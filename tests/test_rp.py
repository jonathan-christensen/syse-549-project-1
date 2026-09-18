"""Relying Party tests — Partner B's service, both directions.

The RP is tested against a real Verifier on an ephemeral port, because the
question that matters (`skip_verifier`) is about what happens between the two
processes, not inside either one.

Every test whose name starts with `test_denies_` carries one sentence naming
the attack it defends against.
"""

import os
import unittest

from shared.pwhash import hash_secret
from tests.helpers import Harness, apply_test_env

CANARY = "CANARY-a1b2c3"
RUN_ID = "test-happy_path-000002"
BINDING_HEADER = {"X-Lab1-Binding-Token": "test-binding-token-0123456789"}


class RelyingPartyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        apply_test_env()
        from services.rp.app import RelyingParty
        from services.verifier.app import Verifier

        self.verifier = Harness(Verifier())
        self.addCleanup(self.verifier.close)
        # The RP finds the Verifier the same way it does in deployment: through
        # configuration, not through an import.
        os.environ["LAB1_VERIFIER_URL"] = self.verifier.url
        self.rp = Harness(RelyingParty())
        self.addCleanup(self.rp.close)

    def enrol_and_authenticate(self, identifier: str = "alice", secret: str = CANARY):
        """Stand in for Partner A's CSP and Subject agent: bind, then prove control."""
        self.verifier.request(
            "POST",
            "/binding",
            {"run_id": RUN_ID, "identifier": identifier,
             "verifier_record": hash_secret(secret)},
            headers=BINDING_HEADER,
        )
        _, body = self.verifier.request(
            "POST",
            "/authenticate",
            {"run_id": RUN_ID, "identifier": identifier,
             "authenticator_output": secret},
        )
        return body["assertion"]

    def session_headers(self, token: str) -> dict:
        return {"Authorization": "Lab1-Session " + token}

    # -- does it work ------------------------------------------------------
    def test_health_identifies_the_rp(self):
        status, body = self.rp.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "rp")
        self.assertEqual(body["spec_version"], "1.0")

    def test_public_resource_needs_no_credential(self):
        status, headers, raw = self.rp.raw("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn("www-authenticate", headers)
        self.assertNotIn("session", raw.decode("utf-8"))

    def test_protected_without_a_session_is_401_with_a_challenge(self):
        # RFC 9110 section 15.5.2 requires the WWW-Authenticate header on a 401.
        status, headers, raw = self.rp.raw("GET", "/protected",
                                           headers={"X-Run-Id": RUN_ID})
        self.assertEqual(status, 401)
        self.assertIn("www-authenticate", headers)
        self.assertIn("realm=", headers["www-authenticate"])
        self.assertNotIn("Traceback", raw.decode("utf-8"))
        step3 = [e for e in self.rp.transcript(RUN_ID) if e["step"] == 3]
        self.assertEqual([e["outcome"] for e in step3], ["success"])
        self.assertEqual(step3[0]["step_name"], "authentication_request")
        # The probe reads the role progression off the `actor` field
        # (check H-ROL), and this event is the Subscriber half of it.
        self.assertEqual(step3[0]["actor"], "subscriber")

    def test_a_verified_assertion_produces_a_session_and_the_resource(self):
        assertion = self.enrol_and_authenticate()
        status, body = self.rp.request(
            "POST", "/session", {"run_id": RUN_ID, "assertion": assertion}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["identifier"], "alice")

        status, protected = self.rp.request(
            "GET", "/protected", headers=self.session_headers(body["session"])
        )
        self.assertEqual(status, 200)
        self.assertEqual(protected["subscriber"], "alice")
        step5 = [e for e in self.rp.transcript(RUN_ID) if e["step"] == 5]
        self.assertEqual([e["outcome"] for e in step5], ["success", "success"])

    def test_the_run_id_survives_the_hop_through_the_verifier(self):
        # The RP learns the run_id from introspection, not from the caller, so a
        # run stays traceable even if the Subject omits it on this hop.
        assertion = self.enrol_and_authenticate()
        _, body = self.rp.request("POST", "/session", {"assertion": assertion})
        self.assertEqual(body["identifier"], "alice")
        self.assertTrue(
            any(e["run_id"] == RUN_ID for e in self.rp.transcript() if e["step"] == 5)
        )

    def test_transcript_timestamps_have_sub_second_precision(self):
        self.rp.request("GET", "/protected")
        for event in self.rp.transcript():
            self.assertRegex(event["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$")

    def test_reset_clears_sessions_and_transcript(self):
        assertion = self.enrol_and_authenticate()
        _, body = self.rp.request("POST", "/session", {"assertion": assertion})
        token = body["session"]
        status, _ = self.rp.request("POST", "/reset")
        self.assertIn(status, (200, 204))
        self.assertEqual(self.rp.transcript(), [])
        # A session that survived the reset would let the next run pass without
        # authenticating.
        self.assertEqual(
            self.rp.request("GET", "/protected", headers=self.session_headers(token))[0],
            401,
        )

    # -- does it refuse ----------------------------------------------------
    def test_denies_a_self_asserted_identity(self):
        # Defends against the skip_verifier scenario: the RP must not accept a
        # claim about identity that no Verifier ever checked.
        for payload in (
            {"run_id": RUN_ID, "identifier": "alice"},
            {"run_id": RUN_ID, "identifier": "alice", "authenticated": True},
            {"run_id": RUN_ID, "assertion": "A" * 43},
            {"run_id": RUN_ID},
        ):
            status, body = self.rp.request("POST", "/session", payload)
            self.assertEqual(status, 401, payload)
            self.assertNotIn("session", body)
        self.assertFalse(
            [e for e in self.rp.transcript(RUN_ID)
             if e["step"] == 5 and e["outcome"] == "success"]
        )

    def test_denies_a_made_up_session_credential(self):
        # Defends against an attacker guessing or inventing a session token at
        # the protected resource.
        status, body = self.rp.request(
            "GET", "/protected", headers=self.session_headers("Z" * 43)
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "authentication_required"})

    def test_denies_a_session_reused_after_logout(self):
        # Defends against session replay: the replay scenario reuses a credential
        # after the subscriber logged out.
        assertion = self.enrol_and_authenticate()
        _, body = self.rp.request("POST", "/session", {"assertion": assertion})
        token = body["session"]
        self.assertEqual(
            self.rp.request("GET", "/protected",
                            headers=self.session_headers(token))[0], 200
        )
        self.rp.request("POST", "/logout", {"run_id": RUN_ID},
                        headers=self.session_headers(token))
        status, _ = self.rp.request(
            "GET", "/protected", headers=self.session_headers(token)
        )
        self.assertEqual(status, 401)

    def test_denies_an_expired_session(self):
        # Defends against a stolen credential outliving its session; the session
        # is minted already expired rather than sleeping in a test.
        token = self.rp.service._mint_session("alice", RUN_ID, ttl=-1)
        self.assertEqual(
            self.rp.request("GET", "/protected",
                            headers=self.session_headers(token))[0], 401
        )

    def test_denies_a_session_presented_from_a_different_client(self):
        # Defends against a bearer credential lifted from one client and used
        # from another.
        token = self.rp.service._mint_session(
            "alice", RUN_ID, ttl=600, client="10.0.0.9"
        )
        self.assertEqual(
            self.rp.request("GET", "/protected",
                            headers=self.session_headers(token))[0], 401
        )

    def test_denies_an_assertion_the_verifier_has_already_redeemed(self):
        # Defends against assertion replay at the RP: the handle is single-use at
        # the Verifier, so the second exchange finds nothing to validate.
        assertion = self.enrol_and_authenticate()
        self.assertEqual(
            self.rp.request("POST", "/session", {"assertion": assertion})[0], 201
        )
        self.assertEqual(
            self.rp.request("POST", "/session", {"assertion": assertion})[0], 401
        )

    def test_denies_everything_when_the_verifier_is_unreachable(self):
        # Defends against fail-open: if the Verifier cannot be asked, nobody is
        # authenticated.
        assertion = self.enrol_and_authenticate()
        self.verifier.close()
        status, body = self.rp.request("POST", "/session", {"assertion": assertion})
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "verifier_unavailable")
        self.addCleanup(lambda: None)

    def test_denies_malformed_requests_without_leaking_internals(self):
        # Defends against error-message probing for the file layout or framework.
        status, _, raw = self.rp.raw(
            "POST", "/session", b"}{", {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 400)
        text = raw.decode("utf-8")
        self.assertNotIn("Traceback", text)
        self.assertNotIn("services/rp", text)

    def test_logout_answers_the_same_way_for_a_credential_it_never_issued(self):
        # Defends against using logout as an oracle to test stolen credentials.
        real = self.rp.service._mint_session("alice", RUN_ID, ttl=600)
        known = self.rp.request("POST", "/logout", {},
                                headers=self.session_headers(real))
        unknown = self.rp.request("POST", "/logout", {},
                                  headers=self.session_headers("Q" * 43))
        self.assertEqual(known, unknown)

    def test_the_authenticator_secret_never_reaches_the_rp(self):
        # Defends against the architecture's one unforgivable failure: the RP
        # handling an authenticator secret at all (canary check X-CAN).
        assertion = self.enrol_and_authenticate()
        self.rp.request("POST", "/session", {"run_id": RUN_ID, "assertion": assertion})
        text = self.rp.transcript_text()
        self.assertNotIn(CANARY, text)
        for banned in ("secret", "password", "authenticator_output"):
            self.assertNotIn(banned, text)


if __name__ == "__main__":
    unittest.main()


class BasePathTestCase(unittest.TestCase):
    """The RP behind a reverse proxy that keeps the path prefix.

    nginx `proxy_pass` without a trailing slash forwards the whole path, so a
    service reached at /team/rp/ sees /team/rp/health, not /health.
    """

    def setUp(self) -> None:
        apply_test_env()
        os.environ["LAB1_RP_BASE_PATH"] = "/hsundareswaran/rp/"
        self.addCleanup(os.environ.pop, "LAB1_RP_BASE_PATH", None)
        from services.rp.app import RelyingParty

        self.rp = Harness(RelyingParty())
        self.addCleanup(self.rp.close)

    def test_the_contract_endpoints_answer_under_the_prefix(self):
        status, body = self.rp.request("GET", "/hsundareswaran/rp/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "rp")
        # The public resource, with and without the trailing slash.
        self.assertEqual(self.rp.request("GET", "/hsundareswaran/rp/")[0], 200)
        self.assertEqual(self.rp.request("GET", "/hsundareswaran/rp")[0], 200)

    def test_the_protected_resource_still_challenges_under_the_prefix(self):
        # A proxied deployment must not quietly lose the 401: RFC 9110 15.5.2
        # applies to the response the client sees, whatever path it arrived on.
        status, headers, _ = self.rp.raw("GET", "/hsundareswaran/rp/protected")
        self.assertEqual(status, 401)
        self.assertIn("www-authenticate", headers)

    def test_the_unprefixed_path_still_answers_on_loopback(self):
        # Deliberate: the prefix is what the proxy adds for outside callers,
        # while service-to-service calls stay on loopback and address the plain
        # path. Refusing the bare path here would break the RP's own
        # introspection call to the Verifier and every local health check.
        self.assertEqual(self.rp.request("GET", "/health")[1]["service"], "rp")
