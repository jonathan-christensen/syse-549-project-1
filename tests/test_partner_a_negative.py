"""Cross-review: Partner B's negative tests for Partner A's services.

PROJECT_WORKFLOW.md section 13 gives each partner the negative tests for the
*other* partner's two services. These are Partner B's tests for the Subject
agent and the CSP.

They run against live services, because that is the only way to test somebody
else's process. Point them at a deployment and run the same single command:

    LAB1_SUBJECT_URL=http://host:4100 LAB1_CSP_URL=http://host:4101 \\
        python3 -m unittest discover -s tests -t .

With nothing configured and nothing listening, every test here skips with the
reason printed, so the suite still runs from a clean checkout while Partner A's
services are being built.
"""

import os
import secrets
import unittest

from shared import config
from shared.httpjson import ServiceUnreachable, get_json, post_json

CANARY_PREFIX = "CANARY-"
ENROLL_PATH = os.environ.get("LAB1_CSP_ENROLL_PATH", "/enroll")


def live(service: str):
    """Return the base URL of `service` if it answers /health, else None."""
    try:
        url = config.endpoint_for(service)
        status, body = get_json(url + "/health", timeout=2)
    except (ServiceUnreachable, config.ConfigError):
        return None
    return url if status == 200 and body.get("service") == service else None


SUBJECT_URL = live("subject")
CSP_URL = live("csp")

SUBJECT_REASON = "Partner A's Subject agent is not running (set LAB1_SUBJECT_URL)"
CSP_REASON = "Partner A's CSP is not running (set LAB1_CSP_URL)"


def new_run(scenario: str):
    return {
        "run_id": "xreview-%s-%s" % (scenario, secrets.token_hex(3)),
        "scenario": scenario,
        "canary": CANARY_PREFIX + secrets.token_hex(3),
    }


def reset_all():
    for service in ("subject", "csp", "verifier", "rp"):
        url = live(service)
        if url:
            try:
                post_json(url + "/reset", {})
            except ServiceUnreachable:
                pass


@unittest.skipUnless(SUBJECT_URL, SUBJECT_REASON)
class SubjectAgentNegativeTestCase(unittest.TestCase):
    """The four scenarios that must be denied, driven through POST /run."""

    def setUp(self):
        reset_all()

    def run_scenario(self, scenario: str):
        request = new_run(scenario)
        status, body = post_json(SUBJECT_URL + "/run", request, timeout=60)
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("run_id"), request["run_id"])
        self.assertEqual(body.get("scenario"), scenario)
        return request, body

    def transcripts(self, run_id: str):
        events = []
        for service in ("subject", "csp", "verifier", "rp"):
            url = live(service)
            if url:
                _, body = get_json(url + "/transcript", timeout=5)
                events += [e for e in body.get("events", [])
                           if e.get("run_id") == run_id]
        return events

    def assert_denied_with_no_successful_step_five(self, scenario: str):
        request, body = self.run_scenario(scenario)
        self.assertEqual(body.get("outcome"), "denied", body)
        successes = [e for e in self.transcripts(request["run_id"])
                     if e.get("step") == 5 and e.get("outcome") == "success"]
        self.assertEqual(successes, [], "a step 5 succeeded in %s" % scenario)

    def test_denies_a_wrong_authenticator(self):
        # Defends against an attacker who knows a subscriber's identifier but
        # holds none of their authenticators.
        self.assert_denied_with_no_successful_step_five("wrong_authenticator")

    def test_denies_an_unenrolled_claimant(self):
        # Defends against authenticating an identity that was never proofed or
        # enrolled by the CSP.
        self.assert_denied_with_no_successful_step_five("unenrolled_claimant")

    def test_denies_a_verifier_bypass(self):
        # Defends against the RP accepting a self-asserted identity that no
        # Verifier ever checked — the failure this whole architecture exists to
        # prevent.
        self.assert_denied_with_no_successful_step_five("skip_verifier")

    def test_denies_a_replayed_session_credential(self):
        # Defends against reuse of a session credential after logout or expiry.
        request, body = self.run_scenario("replay")
        self.assertEqual(body.get("outcome"), "denied", body)

    def test_the_canary_never_reaches_any_transcript(self):
        # Defends against logging the authenticator secret the harness handed in
        # (conformance check X-CAN).
        request = new_run("happy_path")
        post_json(SUBJECT_URL + "/run", request, timeout=60)
        for service in ("subject", "csp", "verifier", "rp"):
            url = live(service)
            if not url:
                continue
            _, body = get_json(url + "/transcript", timeout=5)
            self.assertNotIn(request["canary"], str(body), "%s logged the canary" % service)

    def test_a_denied_run_leaves_no_usable_session_behind(self):
        # Defends against a failed run leaving the RP in a state where the next
        # request is already authenticated (the persistence half of X-*).
        self.run_scenario("wrong_authenticator")
        rp_url = live("rp")
        if not rp_url:
            self.skipTest("the RP is not running")
        status, _ = get_json(rp_url + "/protected", timeout=5)
        self.assertEqual(status, 401)


@unittest.skipUnless(CSP_URL, CSP_REASON)
class CspNegativeTestCase(unittest.TestCase):
    """Enrollment and binding refusals, tested directly against the CSP."""

    def setUp(self):
        reset_all()
        self.identifier = "xreview-%s" % secrets.token_hex(3)
        self.canary = CANARY_PREFIX + secrets.token_hex(3)

    def enrol(self, identifier: str, **extra):
        payload = {
            "run_id": "xreview-enrol-%s" % secrets.token_hex(3),
            "identifier": identifier,
            "evidence": "self-asserted",
        }
        payload.update(extra)
        status, body = post_json(CSP_URL + ENROLL_PATH, payload, timeout=10)
        if status == 404:
            self.skipTest(
                "the CSP has no %s endpoint; set LAB1_CSP_ENROLL_PATH" % ENROLL_PATH
            )
        return status, body

    def test_denies_a_duplicate_enrollment(self):
        # Defends against one applicant enrolling twice, or an attacker claiming
        # an identifier that already belongs to a subscriber.
        first_status, first_body = self.enrol(self.identifier)
        if first_status not in (200, 201):
            # The enrollment body is Partner A's [C] choice, so a refusal here
            # means the assumed field names are wrong, not that the duplicate
            # check failed. Say which, rather than reporting a false failure.
            self.skipTest(
                "enrollment with the assumed body returned HTTP %s (%s); confirm "
                "the CSP's field names and LAB1_CSP_ENROLL_PATH"
                % (first_status, first_body)
            )
        second_status, second_body = self.enrol(self.identifier)
        self.assertGreaterEqual(second_status, 400, second_body)

    def test_enrollment_never_answers_with_a_server_error(self):
        # Defends against unhandled exceptions on the enrollment path: a 5xx
        # means input reached code that did not expect it, and it is one
        # debug setting away from returning a stack trace with it.
        for body in ({}, {"identifier": None}, {"identifier": "x" * 300}):
            status, response = post_json(
                CSP_URL + ENROLL_PATH, dict(body, run_id="xreview-malformed"), timeout=10
            )
            if status == 404:
                self.skipTest("the CSP has no %s endpoint" % ENROLL_PATH)
            self.assertLess(status, 500, "%r produced HTTP %s: %s"
                            % (body, status, response))

    def test_denies_a_malformed_enrollment_without_leaking_internals(self):
        # Defends against error-message probing for the framework and file layout.
        status, body = self.enrol("NOT A VALID IDENTIFIER!!")
        self.assertGreaterEqual(status, 400)
        self.assertNotIn("Traceback", str(body))
        self.assertNotIn("/services/", str(body))

    def test_the_csp_never_returns_a_stored_authenticator_secret(self):
        # Defends against a CSP that echoes the authenticator back on enrollment
        # or exposes it through a lookup — the secret must leave the CSP only as
        # a salted hash, and only to the Verifier.
        status, body = self.enrol(self.identifier, canary=self.canary)
        if status not in (200, 201):
            self.skipTest("enrollment did not succeed, nothing to inspect")
        self.assertNotIn(self.canary, str(body))
        _, transcript = get_json(CSP_URL + "/transcript", timeout=5)
        self.assertNotIn(self.canary, str(transcript))


if __name__ == "__main__":
    unittest.main()
