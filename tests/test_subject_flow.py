"""The five scenarios, driven against the real Verifier and Relying Party.

The CSP here is a stand-in that implements the enrollment contract in
docs/decisions.md and nothing else: `POST /apply` takes `plaintext` (the
harness's canary, for this scripted flow) and returns a token, `POST
/subscribe` marks the account subscribed and pushes the binding
record to the Verifier. Partner A's CSP is a FastAPI application and cannot be
imported without its dependencies, so what these tests pin down is that the
flow is correct *given* a CSP that meets the contract.
"""

import os
import unittest

from services.subject.flow import Flow
from shared.pwhash import hash_secret
from shared.service import JsonService
from shared.transcript import Transcript
from shared.validate import normalize_identifier
from tests.helpers import Harness, apply_test_env

BINDING_TOKEN = "test-binding-token-0123456789"


class StubCsp(JsonService):
    """The enrollment contract, in about thirty lines."""

    name = "csp"

    def __init__(self, verifier_url: str) -> None:
        super().__init__()
        self.verifier_url = verifier_url
        self.accounts = {}
        self.route("POST", "/apply", self.apply)
        self.route("POST", "/subscribe", self.subscribe)

    def on_reset(self) -> None:
        self.accounts = {}

    def apply(self, request):
        import secrets

        identifier = normalize_identifier(request.field("email"))
        plaintext = request.field("plaintext")
        if identifier is None or not isinstance(plaintext, str) or not plaintext:
            return 400, {"error": "invalid_request"}, {}
        if identifier in self.accounts and self.accounts[identifier]["subscribed"]:
            return 409, {"error": "already_enrolled"}, {}
        token = secrets.token_urlsafe(32)
        # The authenticator secret is hashed here and never stored in the clear.
        self.accounts[identifier] = {
            "token": token,
            "record": hash_secret(plaintext),
            "subscribed": False,
        }
        self.transcript.record(
            run_id=request.run_id, step=1, actor="applicant", peer="csp",
            outcome="success", detail="evidence accepted, subscriber account created",
        )
        return 201, {"token": token}, {}

    def subscribe(self, request):
        from shared.httpjson import ServiceUnreachable, post_json

        identifier = normalize_identifier(request.field("email"))
        account = self.accounts.get(identifier) if identifier else None
        if account is None or account["token"] != request.field("token"):
            return 400, {"error": "invalid_request"}, {}
        account["subscribed"] = True
        try:
            status, _ = post_json(
                self.verifier_url + "/binding",
                {"run_id": request.run_id, "identifier": identifier,
                 "verifier_record": account["record"]},
                headers={"X-Lab1-Binding-Token": BINDING_TOKEN},
            )
        except ServiceUnreachable:
            # A CSP that cannot reach the Verifier has not issued anything.
            # Answering 503 beats an unhandled exception and a 500.
            return 503, {"error": "verifier_unavailable"}, {}
        self.transcript.record(
            run_id=request.run_id, step=2, actor="csp", peer="subscriber",
            outcome="success" if status == 201 else "denied",
            detail="authenticator issued and bound to the subscriber account",
        )
        return 200, {"status": "ok"}, {}


class SubjectFlowTestCase(unittest.TestCase):
    def setUp(self) -> None:
        apply_test_env()
        from services.rp.app import RelyingParty
        from services.verifier.app import Verifier

        self.verifier = Harness(Verifier())
        self.addCleanup(self.verifier.close)
        os.environ["LAB1_VERIFIER_URL"] = self.verifier.url
        self.rp = Harness(RelyingParty())
        self.addCleanup(self.rp.close)
        self.csp = Harness(StubCsp(self.verifier.url))
        self.addCleanup(self.csp.close)

        self.transcript = Transcript()
        self.flow = Flow(
            self.transcript,
            csp_url=self.csp.url,
            verifier_url=self.verifier.url,
            rp_url=self.rp.url,
        )

    def merged(self, run_id):
        """Every service's events for one run, in timestamp order, as the probe reads them."""
        events = (
            self.transcript.events(run_id)
            + self.csp.transcript(run_id)
            + self.verifier.transcript(run_id)
            + self.rp.transcript(run_id)
        )
        return sorted(events, key=lambda e: str(e["ts"]))

    # -- the happy path ----------------------------------------------------
    def test_happy_path_succeeds_and_records_all_five_steps(self):
        result = self.flow.run("probe-happy_path-000001", "happy_path", "CANARY-a1b2c3")
        self.assertEqual(result["outcome"], "success", result)
        self.assertEqual(result["run_id"], "probe-happy_path-000001")
        self.assertEqual(result["scenario"], "happy_path")

        events = self.merged("probe-happy_path-000001")
        steps = [e["step"] for e in events]
        # H-ST1 through H-ST5: every step present, at the service that owns it.
        self.assertEqual(sorted(set(steps)), [1, 2, 3, 4, 5])
        # H-ORD: ascending by timestamp across all four transcripts.
        self.assertEqual(steps, sorted(steps), "steps out of timestamp order: %s" % steps)

    def test_the_role_progression_is_visible_in_order(self):
        # H-ROL: the probe reads Applicant -> Subscriber -> Claimant off the
        # actor field, by first appearance, across every transcript.
        self.flow.run("probe-happy_path-000002", "happy_path", "CANARY-a1b2c3")
        actors = [e["actor"] for e in self.merged("probe-happy_path-000002")]
        self.assertLess(actors.index("applicant"), actors.index("subscriber"))
        self.assertLess(actors.index("subscriber"), actors.index("claimant"))

    def test_each_step_is_recorded_by_the_service_the_probe_asks(self):
        run_id = "probe-happy_path-000003"
        self.flow.run(run_id, "happy_path", "CANARY-a1b2c3")
        csp_steps = {e["step"] for e in self.csp.transcript(run_id)}
        self.assertTrue({1, 2} <= csp_steps, "H-ST1/H-ST2 read the CSP transcript")
        self.assertIn(4, {e["step"] for e in self.verifier.transcript(run_id)})
        rp_steps = {e["step"] for e in self.rp.transcript(run_id)}
        self.assertTrue({3, 5} <= rp_steps, "H-ST3/H-ST5 read the RP transcript")

    def test_the_canary_never_reaches_any_transcript(self):
        # X-CAN: the harness greps every transcript for the secret it supplied.
        canary = "CANARY-d4e5f6"
        self.flow.run("probe-happy_path-000004", "happy_path", canary)
        for source in (self.csp, self.verifier, self.rp):
            self.assertNotIn(canary, source.transcript_text())
        self.assertNotIn(canary, str(self.transcript.events()))

    # -- the four denials --------------------------------------------------
    def assert_denied_without_a_session(self, scenario, run_id):
        result = self.flow.run(run_id, scenario, "CANARY-a1b2c3")
        self.assertEqual(result["outcome"], "denied", result)
        successes = [e for e in self.rp.transcript(run_id)
                     if e["step"] == 5 and e["outcome"] == "success"]
        self.assertEqual(successes, [], "a step 5 succeeded in %s" % scenario)

    def test_denies_a_wrong_authenticator(self):
        # Defends against an attacker who knows a subscriber's identifier but
        # holds none of their authenticators (N-BAD).
        self.assert_denied_without_a_session("wrong_authenticator", "probe-wrong-000005")

    def test_denies_an_unenrolled_claimant(self):
        # Defends against authenticating an identity the CSP never proofed or
        # bound an authenticator to (N-ENR).
        self.assert_denied_without_a_session("unenrolled_claimant", "probe-unenr-000006")

    def test_denies_a_verifier_bypass(self):
        # Defends against the RP accepting a self-asserted identity that no
        # Verifier ever checked (N-SKP) - the failure this architecture exists
        # to make impossible.
        self.assert_denied_without_a_session("skip_verifier", "probe-skip-000007")

    def test_denies_a_replayed_session_credential(self):
        # Defends against reuse of a session credential after logout (N-RPL).
        # A successful step 5 earlier in this run is expected and allowed.
        result = self.flow.run("probe-replay-000008", "replay", "CANARY-a1b2c3")
        self.assertEqual(result["outcome"], "denied", result)
        self.assertIn("reused", result["detail"])

    def test_an_unknown_scenario_is_denied_rather_than_crashing(self):
        # Defends against a malformed run request becoming a 500, which the
        # probe cannot distinguish from a broken service.
        result = self.flow.run("probe-bogus-000009", "not_a_scenario", "CANARY-a1b2c3")
        self.assertEqual(result["outcome"], "denied")

    def test_a_peer_being_down_is_a_denial_not_a_crash(self):
        # Defends against fail-open: if a service cannot be reached, nobody is
        # authenticated, and /run still answers in the contract's shape.
        self.verifier.close()
        result = self.flow.run("probe-down-000010", "happy_path", "CANARY-a1b2c3")
        self.assertEqual(result["outcome"], "denied", result)
        self.addCleanup(lambda: None)


if __name__ == "__main__":
    unittest.main()
