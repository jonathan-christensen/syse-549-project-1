"""Verifier tests — Partner B's service, both directions.

Every test whose name starts with `test_denies_` carries one sentence naming
the attack it defends against, as required by PROJECT_WORKFLOW.md section 8.3.
"""

import unittest

from shared.pwhash import hash_secret
from tests.helpers import Harness, apply_test_env

CANARY = "CANARY-a1b2c3"
RUN_ID = "test-happy_path-000001"
BINDING_HEADER = {"X-Lab1-Binding-Token": "test-binding-token-0123456789"}
INTROSPECT_HEADER = {"X-Lab1-Introspect-Token": "test-introspect-token-0123456789"}


class VerifierTestCase(unittest.TestCase):
    def setUp(self) -> None:
        apply_test_env()
        from services.verifier.app import Verifier

        self.verifier = Harness(Verifier())
        self.addCleanup(self.verifier.close)

    def bind(self, identifier: str = "alice", secret: str = CANARY, **kwargs):
        return self.verifier.request(
            "POST",
            "/binding",
            {
                "run_id": RUN_ID,
                "identifier": identifier,
                "verifier_record": hash_secret(secret),
            },
            headers=kwargs.pop("headers", BINDING_HEADER),
            **kwargs,
        )

    def authenticate(self, identifier: str = "alice", secret: str = CANARY):
        return self.verifier.request(
            "POST",
            "/authenticate",
            {"run_id": RUN_ID, "identifier": identifier, "authenticator_output": secret},
        )

    def introspect(self, handle, headers=None):
        return self.verifier.request(
            "POST",
            "/introspect",
            {"assertion": handle, "run_id": RUN_ID},
            headers=INTROSPECT_HEADER if headers is None else headers,
        )

    # -- does it work ------------------------------------------------------
    def test_health_identifies_the_verifier(self):
        status, body = self.verifier.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "verifier")
        self.assertEqual(body["spec_version"], "1.0")
        self.assertEqual(body["team"], "test-team")

    def test_binding_from_the_csp_is_accepted(self):
        status, body = self.bind()
        self.assertEqual(status, 201)
        self.assertTrue(body["bound"])
        events = self.verifier.transcript(RUN_ID)
        self.assertEqual([e["step"] for e in events], [2])
        self.assertEqual(events[0]["outcome"], "success")
        self.assertEqual(events[0]["step_name"], "authenticator_enrollment_issuance")

    def test_correct_authenticator_output_produces_an_assertion(self):
        self.bind()
        status, body = self.authenticate()
        self.assertEqual(status, 200)
        self.assertTrue(body["assertion"])
        self.assertEqual(body["run_id"], RUN_ID)
        step4 = [e for e in self.verifier.transcript(RUN_ID) if e["step"] == 4]
        self.assertEqual([e["outcome"] for e in step4], ["success"])

    def test_assertion_introspects_once_and_names_the_subscriber(self):
        self.bind()
        _, body = self.authenticate()
        status, introspected = self.introspect(body["assertion"])
        self.assertEqual(status, 200)
        self.assertTrue(introspected["active"])
        self.assertEqual(introspected["identifier"], "alice")
        self.assertEqual(introspected["run_id"], RUN_ID)
        step5 = [e for e in self.verifier.transcript(RUN_ID) if e["step"] == 5]
        self.assertEqual([e["outcome"] for e in step5], ["success"])

    def test_transcript_timestamps_have_sub_second_precision(self):
        self.bind()
        for event in self.verifier.transcript():
            self.assertRegex(event["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$")

    def test_reset_clears_bindings_and_transcript(self):
        self.bind()
        status, _ = self.verifier.request("POST", "/reset")
        self.assertIn(status, (200, 204))
        self.assertEqual(self.verifier.transcript(), [])
        # A half-reset would leave the binding behind and the next run would
        # succeed for the wrong reason.
        self.assertEqual(self.authenticate()[0], 401)

    # -- does it refuse ----------------------------------------------------
    def test_denies_wrong_authenticator_output(self):
        # Defends against online guessing of a subscriber's authenticator.
        self.bind()
        status, body = self.authenticate(secret="not-the-canary")
        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "authentication_failed"})

    def test_denies_unknown_identifier_identically_to_a_wrong_secret(self):
        # Defends against account enumeration: the failure must not reveal
        # whether the account existed.
        self.bind()
        wrong_secret = self.authenticate(secret="not-the-canary")
        unknown_account = self.authenticate(identifier="nobody", secret=CANARY)
        self.assertEqual(wrong_secret, unknown_account)

    def test_denies_unenrolled_claimant(self):
        # Defends against a claimant who was never issued an authenticator
        # authenticating anyway (the unenrolled_claimant scenario).
        status, _ = self.authenticate(identifier="never-enrolled")
        self.assertEqual(status, 401)
        step4 = [e for e in self.verifier.transcript(RUN_ID) if e["step"] == 4]
        self.assertEqual([e["outcome"] for e in step4], ["denied"])

    def test_denies_binding_without_the_csp_token(self):
        # Defends against identity minting: anyone who can bind an authenticator
        # to an identifier can become that subscriber.
        status, _ = self.bind(headers={})
        self.assertEqual(status, 401)
        self.assertEqual(self.authenticate()[0], 401)

    def test_denies_rebinding_an_identifier_that_is_already_bound(self):
        # Defends against account takeover by binding a second authenticator to
        # somebody else's account.
        self.bind()
        status, body = self.bind(secret="attacker-authenticator")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "already_bound")
        # The original authenticator still works; the attacker's does not.
        self.assertEqual(self.authenticate()[0], 200)
        self.assertEqual(self.authenticate(secret="attacker-authenticator")[0], 401)

    def test_denies_introspection_without_the_rp_token(self):
        # Defends against an outsider redeeming or probing assertions, which
        # would leak subscriber identifiers and burn valid assertions.
        self.bind()
        _, body = self.authenticate()
        status, _ = self.introspect(body["assertion"], headers={})
        self.assertEqual(status, 401)
        # The assertion was not consumed by the rejected attempt.
        self.assertTrue(self.introspect(body["assertion"])[1]["active"])

    def test_denies_a_second_redemption_of_the_same_assertion(self):
        # Defends against assertion replay: a captured assertion must be worth
        # at most one session.
        self.bind()
        _, body = self.authenticate()
        self.assertTrue(self.introspect(body["assertion"])[1]["active"])
        self.assertFalse(self.introspect(body["assertion"])[1]["active"])

    def test_denies_an_expired_assertion(self):
        # Defends against an assertion captured now and redeemed later; the
        # credential is minted already expired rather than sleeping in a test.
        handle = self.verifier.service._mint_assertion("alice", RUN_ID, ttl=-1)
        self.assertFalse(self.introspect(handle)[1]["active"])

    def test_denies_a_forged_assertion_handle(self):
        # Defends against an attacker inventing an assertion instead of earning
        # one from step 4.
        self.assertFalse(self.introspect("A" * 43)[1]["active"])
        self.assertFalse(self.introspect("not-a-handle")[1]["active"])

    def test_denies_malformed_requests_without_leaking_internals(self):
        # Defends against error-message probing: a malformed body must produce
        # neither a stack trace nor a different answer from a wrong secret.
        status, headers, raw = self.verifier.raw(
            "POST", "/authenticate", b"{not json", {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 400)
        text = raw.decode("utf-8")
        self.assertNotIn("Traceback", text)
        self.assertNotIn("services/verifier", text)
        self.assertEqual(self.authenticate(identifier="ALICE!!")[1]["error"],
                         "authentication_failed")

    def test_denies_an_oversized_body(self):
        # Defends against memory exhaustion from an unbounded request body.
        payload = b'{"identifier":"alice","authenticator_output":"%s"}' % (b"x" * 32768)
        status, _, _ = self.verifier.raw(
            "POST", "/authenticate", payload, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 400)

    def test_rate_limiting_engages_on_repeated_failures(self):
        # Defends against sustained online guessing from one client.
        self.bind()
        statuses = [self.authenticate(secret="wrong-%d" % i)[0] for i in range(8)]
        self.assertIn(429, statuses)
        self.assertEqual(statuses[0], 401)

    def test_the_authenticator_secret_never_reaches_the_transcript(self):
        # Defends against the canary check X-CAN: a logged secret is a leaked
        # secret, and the harness greps every transcript for it.
        self.bind()
        self.authenticate()
        self.authenticate(secret="wrong-" + CANARY)
        text = self.verifier.transcript_text()
        self.assertNotIn(CANARY, text)
        for banned in ("secret", "password", "authenticator_output"):
            self.assertNotIn(banned, text)

    def test_every_401_carries_a_www_authenticate_header(self):
        # RFC 9110 section 15.5.2: a 401 without a challenge is not a valid
        # denial, and a client cannot tell what to do next.
        self.bind()
        _, headers, _ = self.verifier.raw(
            "POST",
            "/authenticate",
            b'{"identifier":"alice","authenticator_output":"wrong"}',
            {"Content-Type": "application/json"},
        )
        self.assertIn("www-authenticate", headers)


if __name__ == "__main__":
    unittest.main()
