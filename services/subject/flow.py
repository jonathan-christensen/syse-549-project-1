"""The five scenarios the Subject agent drives, as plain Python.

Kept out of the FastAPI handler on purpose: this is the part with the
interesting behaviour, and it is standard library only, so it can be tested
against the real Verifier and Relying Party without a web server in the way.
`POST /run` is then three lines that call `Flow.run(...)`.

The sequence is the one recorded in docs/decisions.md, and the role
transitions are the three named lines PROJECT_WORKFLOW.md section 6 asks for:
one place each where the Applicant becomes a Subscriber and the Subscriber
becomes a Claimant.
"""

import secrets
from typing import Any, Dict, Optional

from shared import config
from shared.httpjson import ServiceUnreachable, get_json, post_json, request_json
from shared.transcript import Transcript

SCENARIOS = (
    "happy_path",
    "wrong_authenticator",
    "unenrolled_claimant",
    "replay",
    "skip_verifier",
)

SESSION_SCHEME = "Lab1-Session"


class Flow:
    """Drives one run from Applicant to authenticated Subscriber, or to a denial."""

    def __init__(
        self,
        transcript: Transcript,
        *,
        csp_url: Optional[str] = None,
        verifier_url: Optional[str] = None,
        rp_url: Optional[str] = None,
    ) -> None:
        self.transcript = transcript
        # Peers are addressed on loopback: all four services run on one host,
        # and the assertion has no business crossing the campus network.
        self.csp_url = csp_url or config.internal_endpoint_for("csp")
        self.verifier_url = verifier_url or config.internal_endpoint_for("verifier")
        self.rp_url = rp_url or config.internal_endpoint_for("rp")

    # -- entry point --------------------------------------------------------
    def run(self, run_id: str, scenario: str, canary: str) -> Dict[str, Any]:
        """Return the `POST /run` response body for one scenario."""
        if scenario not in SCENARIOS:
            return self._result(run_id, scenario, "denied", "unknown scenario")
        identifier = "subject-%s@example.test" % secrets.token_hex(4)
        try:
            return getattr(self, "_" + scenario)(run_id, scenario, identifier, canary)
        except ServiceUnreachable:
            # Fail closed and say so: a peer being down is a denial, not a crash.
            return self._result(run_id, scenario, "denied", "a peer service was unreachable")

    # -- the scenarios ------------------------------------------------------
    def _happy_path(self, run_id, scenario, identifier, canary):
        self._enrol(run_id, identifier, canary)
        if not self._demand_authentication(run_id):
            return self._result(run_id, scenario, "denied",
                                "the relying party did not demand authentication")
        assertion = self._prove_control(run_id, identifier, canary)
        if assertion is None:
            return self._result(run_id, scenario, "denied",
                                "the verifier did not confirm authenticator control")
        session = self._establish_session(run_id, assertion)
        if session is None:
            return self._result(run_id, scenario, "denied",
                                "the relying party refused the assertion")
        if self._read_protected(run_id, session) != 200:
            return self._result(run_id, scenario, "denied",
                                "the protected resource was withheld")
        return self._result(run_id, scenario, "success",
                            "protected resource returned HTTP 200")

    def _wrong_authenticator(self, run_id, scenario, identifier, canary):
        """Enrolled, but the claimant presents the wrong authenticator output."""
        self._enrol(run_id, identifier, canary)
        self._demand_authentication(run_id)
        assertion = self._prove_control(run_id, identifier, "not-the-authenticator")
        if assertion is not None:
            return self._result(run_id, scenario, "success",
                                "the verifier accepted the wrong authenticator")
        return self._result(run_id, scenario, "denied",
                            "the verifier refused the wrong authenticator output")

    def _unenrolled_claimant(self, run_id, scenario, identifier, canary):
        """Never enrolled at all: no account, no binding, no authenticator."""
        self._demand_authentication(run_id)
        assertion = self._prove_control(run_id, identifier, canary)
        if assertion is not None:
            return self._result(run_id, scenario, "success",
                                "the verifier authenticated an unenrolled identifier")
        return self._result(run_id, scenario, "denied",
                            "the verifier refused an identifier it never bound")

    def _replay(self, run_id, scenario, identifier, canary):
        """A valid session, logged out, then the same credential presented again."""
        self._enrol(run_id, identifier, canary)
        self._demand_authentication(run_id)
        assertion = self._prove_control(run_id, identifier, canary)
        if assertion is None:
            return self._result(run_id, scenario, "denied",
                                "the verifier did not confirm authenticator control")
        session = self._establish_session(run_id, assertion)
        if session is None:
            return self._result(run_id, scenario, "denied",
                                "the relying party refused the assertion")
        if self._read_protected(run_id, session) != 200:
            return self._result(run_id, scenario, "denied",
                                "the protected resource was withheld before logout")
        self._logout(run_id, session)
        if self._read_protected(run_id, session) == 200:
            return self._result(run_id, scenario, "success",
                                "the revoked session credential still worked")
        return self._result(run_id, scenario, "denied",
                            "the reused session credential was refused")

    def _skip_verifier(self, run_id, scenario, identifier, canary):
        """Straight to the RP with a self-made assertion. No Verifier involved."""
        self._enrol(run_id, identifier, canary)
        self._demand_authentication(run_id)
        status, body = post_json(
            self.rp_url + "/session",
            {"run_id": run_id, "identifier": identifier,
             "assertion": secrets.token_urlsafe(32)},
        )
        if status == 201 and body.get("session"):
            return self._result(run_id, scenario, "success",
                                "the relying party accepted an unverified identity")
        return self._result(run_id, scenario, "denied",
                            "the relying party refused an assertion no verifier issued")

    # -- steps --------------------------------------------------------------
    def _enrol(self, run_id: str, identifier: str, canary: str) -> None:
        """Steps 1 and 2, at the CSP. The canary is the authenticator secret."""
        # Role: Applicant. Evidence is presented, nothing is proven yet.
        self.transcript.record(
            run_id=run_id, step=1, actor="applicant", peer="csp", outcome="success",
            detail="applicant presents evidence for proofing and enrollment",
        )
        _, body = post_json(
            self.csp_url + "/apply",
            {"run_id": run_id, "email": identifier, "canary": canary},
        )
        token = body.get("token")
        if not token:
            return
        post_json(
            self.csp_url + "/subscribe",
            {"run_id": run_id, "email": identifier, "token": token},
        )

    def _demand_authentication(self, run_id: str) -> bool:
        """Step 3: ask for the protected resource with no session, expect a 401.

        ROLE CHANGE, Subscriber -> Claimant. The 401 is what makes it: up to
        here the subject is an enrolled Subscriber, and from here it is a
        Claimant with something to prove.
        """
        self.transcript.record(
            run_id=run_id, step=3, actor="subscriber", peer="rp", outcome="success",
            detail="subscriber requests the protected resource without a session",
        )
        status, _ = get_json(self.rp_url + "/protected", headers={"X-Run-Id": run_id})
        return status == 401

    def _prove_control(self, run_id: str, identifier: str, output: str) -> Optional[str]:
        """Step 4: present the authenticator output, and get an assertion or nothing."""
        self.transcript.record(
            run_id=run_id, step=4, actor="claimant", peer="verifier", outcome="success",
            detail="claimant presents proof of authenticator control",
        )
        status, body = post_json(
            self.verifier_url + "/authenticate",
            {"run_id": run_id, "identifier": identifier,
             "authenticator_output": output},
        )
        return body.get("assertion") if status == 200 else None

    def _establish_session(self, run_id: str, assertion: str) -> Optional[str]:
        """Step 5: hand the assertion to the RP, which validates it with the Verifier."""
        status, body = post_json(
            self.rp_url + "/session", {"run_id": run_id, "assertion": assertion}
        )
        return body.get("session") if status == 201 else None

    def _read_protected(self, run_id: str, session: str) -> Optional[int]:
        status, _ = get_json(self.rp_url + "/protected", headers=self._auth(run_id, session))
        return status

    def _logout(self, run_id: str, session: str) -> None:
        request_json("POST", self.rp_url + "/logout", {"run_id": run_id},
                     headers=self._auth(run_id, session))

    # -- helpers ------------------------------------------------------------
    def _auth(self, run_id: str, session: str) -> Dict[str, str]:
        return {"Authorization": "%s %s" % (SESSION_SCHEME, session),
                "X-Run-Id": run_id}

    def _result(self, run_id: str, scenario: str, outcome: str, detail: str) -> Dict[str, Any]:
        return {"run_id": run_id, "scenario": scenario,
                "outcome": outcome, "detail": detail}
