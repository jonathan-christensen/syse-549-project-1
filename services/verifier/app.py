"""The Verifier — Figure 3, port block + 2. Partner B.

Owns exactly two things:

  * step 4, the authentication process: does this claimant control the
    authenticator bound to the identifier they claim?
  * step 5, the assertion: telling the Relying Party which subscriber
    identifier was authenticated.

It never serves the protected resource, and it is the only service besides the
CSP that ever sees an authenticator output. The output is compared and
discarded; it is never stored, never returned, and never written to the
transcript.

Endpoints beyond the three the contract requires of every service:

  POST /binding      (CSP -> Verifier, shared token) accept a binding record
  POST /authenticate (Claimant -> Verifier)          step 4, mints an assertion
  POST /introspect   (RP -> Verifier, shared token)  step 5, redeems it once

The assertion is an opaque, single-use handle. It carries no identity of its
own, so a forged one is worthless and the RP cannot decide "authenticated"
without asking the Verifier — see docs/decisions.md.
"""

import secrets
import threading
import time
from typing import Any, Dict

from shared import config
from shared.pwhash import burn_equivalent_work, is_record, verify_secret
from shared.ratelimit import RateLimiter
from shared.service import JsonService, Request, Response
from shared.timeutil import iso_from_epoch
from shared.validate import (
    normalize_identifier,
    valid_authenticator_output,
    valid_handle,
)

# One challenge, used on every 401 this service emits (RFC 9110 section 15.5.2:
# a 401 response must carry a WWW-Authenticate header).
CHALLENGE = 'Lab1-Authenticator realm="lab1-verifier"'

# The single denial body. Wrong authenticator output, unknown identifier and
# malformed-but-well-typed input all produce exactly this, with exactly the
# same status code.
DENIAL: Dict[str, Any] = {"error": "authentication_failed"}

DEFAULT_ASSERTION_TTL = 60
# Failed attempts per client address per window. Deliberately loose: all four
# services run on one host, so every legitimate request arrives from the same
# address as an attacker's would, and a tight limit locks the lab out of itself
# rather than locking an attacker out. See docs/analysis.md — this is a real
# weakness of the deployment, not a well-tuned control.
DEFAULT_MAX_ATTEMPTS = 10
DEFAULT_WINDOW = 60


class Verifier(JsonService):
    name = "verifier"

    def __init__(self) -> None:
        super().__init__()
        self.binding_token = config.require_secret("LAB1_CSP_BINDING_TOKEN")
        self.introspect_token = config.require_secret("LAB1_RP_INTROSPECT_TOKEN")
        self.assertion_ttl = config.int_setting(
            "LAB1_ASSERTION_TTL_SECONDS", DEFAULT_ASSERTION_TTL
        )
        self.limiter = RateLimiter(
            config.int_setting("LAB1_AUTH_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
            config.int_setting("LAB1_AUTH_WINDOW_SECONDS", DEFAULT_WINDOW),
        )
        self._state_lock = threading.Lock()
        self._bindings: Dict[str, Dict[str, Any]] = {}
        self._assertions: Dict[str, Dict[str, Any]] = {}

        self.route("POST", "/binding", self.handle_binding)
        self.route("POST", "/authenticate", self.handle_authenticate)
        self.route("POST", "/introspect", self.handle_introspect)

    def on_reset(self) -> None:
        with self._state_lock:
            self._bindings = {}
            self._assertions = {}
        self.limiter.reset()

    # -- step 2: the CSP hands over the binding record --------------------
    def handle_binding(self, request: Request) -> Response:
        """Accept `identifier -> authenticator verification record` from the CSP.

        The Verifier trusts the CSP for this and only this. The record is a
        salted scrypt digest produced by the CSP; the authenticator secret
        itself does not cross this boundary.
        """
        run_id = request.run_id
        if not self._token_ok(request, "x-lab1-binding-token", self.binding_token):
            self.transcript.record(
                run_id=run_id, step=2, actor="csp", peer="verifier", outcome="denied",
                detail="binding rejected: caller could not present the CSP token",
            )
            return 401, {"error": "unauthorized"}, {"WWW-Authenticate": CHALLENGE}

        identifier = normalize_identifier(request.field("identifier"))
        record = request.field("verifier_record")
        if identifier is None or not is_record(record):
            self.transcript.record(
                run_id=run_id, step=2, actor="csp", peer="verifier", outcome="denied",
                detail="binding rejected: malformed identifier or record",
            )
            return 400, {"error": "invalid_request"}, {}

        with self._state_lock:
            if identifier in self._bindings:
                self.transcript.record(
                    run_id=run_id, step=2, actor="csp", peer="verifier",
                    outcome="denied",
                    detail="binding rejected: identifier already bound",
                )
                return 409, {"error": "already_bound"}, {}
            self._bindings[identifier] = {
                "record": record,
                "bound_at": time.time(),
            }

        self.transcript.record(
            run_id=run_id, step=2, actor="csp", peer="verifier", outcome="success",
            detail="binding record accepted, authenticator bound to subscriber account",
        )
        return 201, {"bound": True, "identifier": identifier}, {}

    # -- step 4: the claimant proves control ------------------------------
    def handle_authenticate(self, request: Request) -> Response:
        """Check the presented authenticator output against the bound record."""
        run_id = request.run_id
        identifier = normalize_identifier(request.field("identifier"))
        output = request.field("authenticator_output")

        allowed, retry_after = self.limiter.check(request.client_ip)
        if not allowed:
            self.transcript.record(
                run_id=run_id, step=4, actor="claimant", peer="verifier",
                outcome="denied",
                detail="denied: too many failed attempts from this client",
            )
            return 429, {"error": "too_many_requests"}, {
                "Retry-After": str(retry_after),
                "WWW-Authenticate": CHALLENGE,
            }

        if identifier is None or not valid_authenticator_output(output):
            # Same body, same status as a wrong secret: a malformed request
            # must not become an oracle either.
            self.transcript.record(
                run_id=run_id, step=4, actor="claimant", peer="verifier",
                outcome="denied", detail="denied: malformed authentication request",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        with self._state_lock:
            binding = self._bindings.get(identifier)

        if binding is None:
            # Unknown identifier: do the same work, return the same answer.
            burn_equivalent_work(output)
            self.transcript.record(
                run_id=run_id, step=4, actor="claimant", peer="verifier",
                outcome="denied", detail="denied: authenticator control not proven",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        if not verify_secret(output, binding["record"]):
            self.transcript.record(
                run_id=run_id, step=4, actor="claimant", peer="verifier",
                outcome="denied", detail="denied: authenticator control not proven",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        self.limiter.forget(request.client_ip)
        handle = secrets.token_urlsafe(32)
        expires_at = time.time() + self.assertion_ttl
        with self._state_lock:
            self._assertions[handle] = {
                "identifier": identifier,
                "run_id": run_id,
                "expires_at": expires_at,
                "redeemed": False,
            }
        self.transcript.record(
            run_id=run_id, step=4, actor="claimant", peer="verifier",
            outcome="success",
            detail="authenticator control proven, single-use assertion issued",
        )
        return 200, {
            "assertion": handle,
            "expires_at": iso_from_epoch(expires_at),
            "run_id": run_id,
        }, {}

    # -- step 5: the RP redeems the assertion -----------------------------
    def handle_introspect(self, request: Request) -> Response:
        """Tell the RP which subscriber identifier an assertion stands for.

        Single use: the handle is consumed here, so a captured assertion cannot
        be redeemed a second time.
        """
        run_id = request.run_id
        if not self._token_ok(request, "x-lab1-introspect-token", self.introspect_token):
            self.transcript.record(
                run_id=run_id, step=5, actor="rp", peer="verifier", outcome="denied",
                detail="introspection rejected: caller is not the relying party",
            )
            return 401, {"error": "unauthorized"}, {"WWW-Authenticate": CHALLENGE}

        handle = request.field("assertion")
        now = time.time()
        with self._state_lock:
            record = self._assertions.get(handle) if valid_handle(handle) else None
            active = bool(
                record and not record["redeemed"] and record["expires_at"] > now
            )
            if active:
                record["redeemed"] = True

        if not active:
            self.transcript.record(
                run_id=run_id, step=5, actor="verifier", peer="rp", outcome="denied",
                detail="assertion not honoured: unknown, expired or already redeemed",
            )
            return 200, {"active": False}, {}

        self.transcript.record(
            run_id=record["run_id"], step=5, actor="verifier", peer="rp",
            outcome="success",
            detail="subscriber identifier asserted to the relying party",
        )
        return 200, {
            "active": True,
            "identifier": record["identifier"],
            "run_id": record["run_id"],
        }, {}

    # -- helpers -----------------------------------------------------------
    def _token_ok(self, request: Request, header: str, expected: str) -> bool:
        return secrets.compare_digest(request.header(header), expected)

    # Test seam: mint an assertion that is already past its expiry, so the
    # expiry path can be tested without sleeping.
    def _mint_assertion(self, identifier: str, run_id: str, *, ttl: float) -> str:
        handle = secrets.token_urlsafe(32)
        with self._state_lock:
            self._assertions[handle] = {
                "identifier": identifier,
                "run_id": run_id,
                "expires_at": time.time() + ttl,
                "redeemed": False,
            }
        return handle


def main() -> None:
    try:
        Verifier().run()
    except config.ConfigError as exc:
        # A configuration problem is an operator error, not a crash: say what to
        # fix in one line rather than printing a traceback.
        raise SystemExit("verifier: %s" % exc)


if __name__ == "__main__":
    main()
