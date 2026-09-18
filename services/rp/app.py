"""The Relying Party — Figure 3, port block + 3. Partner B.

The resource the subject wanted in the first place, and the policy enforcement
point in front of it (SP 800-207 framing: the RP enforces, the Verifier
decides).

  GET  /           public resource, no credential of any kind
  GET  /protected  401 + WWW-Authenticate without a valid session (step 3),
                   200 with one (step 5)
  POST /session    exchange an assertion for a session, by asking the Verifier
  POST /logout     revoke the session

The RP never sees an authenticator secret. It is handed an opaque assertion
handle that means nothing on its own, and the only way it can learn an
identifier is `POST /introspect` on the Verifier. There is deliberately no code
path here that turns a self-asserted identifier into a session — that is the
`skip_verifier` scenario, and it is impossible by construction rather than
rejected by a check.
"""

import secrets
import threading
import time
from typing import Any, Dict, Optional

from shared import config
from shared.httpjson import ServiceUnreachable, post_json
from shared.service import JsonService, Request, Response
from shared.timeutil import iso_from_epoch
from shared.validate import valid_handle

# RFC 9110 section 15.5.2 requires a challenge on every 401. The scheme name is
# ours: this is a non-federated lab, so there is no OAuth bearer token here.
CHALLENGE = 'Lab1-Session realm="lab1-rp"'
AUTH_SCHEME = "lab1-session"

# One denial body for every way of failing to be authenticated.
DENIAL: Dict[str, Any] = {"error": "authentication_required"}

DEFAULT_SESSION_TTL = 600


class RelyingParty(JsonService):
    name = "rp"

    def __init__(self) -> None:
        super().__init__()
        # Introspection stays inside the host; the URL handed to a claimant in
        # the 401 is the public one, because the claimant is not on this host.
        self.verifier_url = config.internal_endpoint_for("verifier")
        self.verifier_public_url = config.endpoint_for("verifier")
        self.introspect_token = config.require_secret("LAB1_RP_INTROSPECT_TOKEN")
        self.session_ttl = config.int_setting(
            "LAB1_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL
        )
        # Pinning a session to the address it was issued to costs a bearer
        # credential most of its value if it is stolen. It is a setting because
        # a client whose address changes mid-session would be logged out.
        self.pin_to_client = config.bool_setting("LAB1_RP_PIN_SESSION_TO_CLIENT", True)
        self._state_lock = threading.Lock()
        self._sessions: Dict[str, Dict[str, Any]] = {}

        self.route("GET", "/", self.handle_public)
        self.route("GET", "/protected", self.handle_protected)
        self.route("POST", "/session", self.handle_session)
        self.route("POST", "/logout", self.handle_logout)

    def on_reset(self) -> None:
        with self._state_lock:
            self._sessions = {}

    # -- the public resource ----------------------------------------------
    def handle_public(self, request: Request) -> Response:
        return 200, {
            "service": self.name,
            "team": self.team,
            "resource": "public",
            "message": "Public page. The subscriber record lives at /protected.",
        }, {}

    # -- steps 3 and 5: the protected resource -----------------------------
    def handle_protected(self, request: Request) -> Response:
        presented = self._presented_credential(request)

        if presented is None:
            # Step 3: the RP demands authentication and says where to get it.
            # The actor is the Subscriber, because the Subscriber is the party
            # making the request; the 401 is what turns them into a Claimant.
            # Recording it that way also makes the Applicant -> Subscriber ->
            # Claimant progression visible across the four transcripts even if
            # no other service happens to write a `subscriber` event (H-ROL).
            self.transcript.record(
                run_id=request.run_id, step=3, actor="subscriber", peer="rp",
                outcome="success",
                detail="no session presented, authentication demanded",
            )
            return 401, dict(DENIAL, authenticate_at=self.verifier_public_url), {
                "WWW-Authenticate": CHALLENGE
            }

        session = self._lookup_session(presented, request.client_ip)
        if session is None:
            # A credential was presented and refused: expired, revoked, forged,
            # or replayed from somewhere else. The transcript is public, so it
            # records the refusal and not which of those it was.
            self.transcript.record(
                run_id=request.run_id, step=5, actor="rp", peer="claimant",
                outcome="denied", detail="session credential refused",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        self.transcript.record(
            run_id=session["run_id"], step=5, actor="rp", peer="subscriber",
            outcome="success",
            detail="protected resource served to an authenticated session",
        )
        return 200, {
            "resource": "protected",
            "subscriber": session["identifier"],
            "content": "Subscriber record for %s: enrolled, authenticator bound."
            % session["identifier"],
            "session_expires_at": iso_from_epoch(session["expires_at"]),
        }, {}

    # -- step 5: turn an assertion into a session ---------------------------
    def handle_session(self, request: Request) -> Response:
        """Establish a session — but only for an assertion the Verifier honours.

        These are the lines that decide "authenticated": the decision is the
        Verifier's `active` flag and the identifier that comes back with it.
        Nothing in the request body can produce an identifier on its own.
        """
        handle = request.field("assertion")
        if not valid_handle(handle):
            self.transcript.record(
                run_id=request.run_id, step=5, actor="rp", peer="claimant",
                outcome="denied",
                detail="session refused: no assertion presented to validate",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        try:
            status, body = post_json(
                self.verifier_url + "/introspect",
                {"assertion": handle, "run_id": request.run_id},
                headers={"X-Lab1-Introspect-Token": self.introspect_token},
            )
        except ServiceUnreachable:
            # Fail closed: an unreachable Verifier means nobody is authenticated.
            self.transcript.record(
                run_id=request.run_id, step=5, actor="rp", peer="verifier",
                outcome="denied",
                detail="session refused: verifier unreachable, failing closed",
            )
            return 503, {"error": "verifier_unavailable"}, {}

        identifier = body.get("identifier")
        if status != 200 or body.get("active") is not True or not isinstance(identifier, str):
            self.transcript.record(
                run_id=request.run_id, step=5, actor="rp", peer="verifier",
                outcome="denied",
                detail="session refused: verifier did not honour the assertion",
            )
            return 401, DENIAL, {"WWW-Authenticate": CHALLENGE}

        run_id = body.get("run_id") or request.run_id
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + self.session_ttl
        with self._state_lock:
            self._sessions[token] = {
                "identifier": identifier,
                "run_id": run_id,
                "expires_at": expires_at,
                "revoked": False,
                "client": request.client_ip,
            }
        self.transcript.record(
            run_id=run_id, step=5, actor="rp", peer="verifier", outcome="success",
            detail="verifier asserted the identifier, session established",
        )
        return 201, {
            "session": token,
            "expires_at": iso_from_epoch(expires_at),
            "identifier": identifier,
        }, {}

    # -- ending a session ----------------------------------------------------
    def handle_logout(self, request: Request) -> Response:
        """Revoke the presented session. Always answers the same way.

        A logout that reported whether the credential was real would be a free
        oracle for testing stolen tokens.
        """
        presented = self._presented_credential(request)
        run_id = request.run_id
        if presented is not None:
            with self._state_lock:
                session = self._sessions.get(presented)
                if session is not None:
                    session["revoked"] = True
                    run_id = session["run_id"]
            if session is not None:
                self.transcript.record(
                    run_id=run_id, step=5, actor="rp", peer="subscriber",
                    outcome="success",
                    detail="session revoked at the subscriber's request",
                )
        return 200, {"revoked": True}, {}

    # -- helpers --------------------------------------------------------------
    def _presented_credential(self, request: Request) -> Optional[str]:
        """Pull the session credential out of the Authorization header or body."""
        header = request.header("authorization")
        if header:
            scheme, _, value = header.partition(" ")
            if scheme.lower() == AUTH_SCHEME and valid_handle(value.strip()):
                return value.strip()
            return None
        candidate = request.field("session")
        return candidate if valid_handle(candidate) else None

    def _lookup_session(self, token: str, client_ip: str) -> Optional[Dict[str, Any]]:
        """The session behind a presented credential, or None if it is no good."""
        with self._state_lock:
            session = self._sessions.get(token)
            if session is None or session["revoked"]:
                return None
            if session["expires_at"] <= time.time():
                return None
            if self.pin_to_client and session["client"] != client_ip:
                return None
            return dict(session)

    # Test seam: mint a session directly, so expiry and client-pinning can be
    # tested without sleeping and without a live Verifier.
    def _mint_session(
        self, identifier: str, run_id: str, *, ttl: float, client: str = "127.0.0.1"
    ) -> str:
        token = secrets.token_urlsafe(32)
        with self._state_lock:
            self._sessions[token] = {
                "identifier": identifier,
                "run_id": run_id,
                "expires_at": time.time() + ttl,
                "revoked": False,
                "client": client,
            }
        return token


def main() -> None:
    try:
        RelyingParty().run()
    except config.ConfigError as exc:
        # A configuration problem is an operator error, not a crash: say what to
        # fix in one line rather than printing a traceback.
        raise SystemExit("rp: %s" % exc)


if __name__ == "__main__":
    main()
