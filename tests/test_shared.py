"""Tests for the shared helpers every service depends on."""

import os
import re
import unittest

from shared import config
from shared.pwhash import hash_secret, is_record, verify_secret
from shared.ratelimit import RateLimiter
from shared.timeutil import iso_from_epoch, now_iso
from shared.transcript import STEP_NAMES, Transcript, clean_run_id
from shared.validate import (
    normalize_identifier,
    valid_authenticator_output,
    valid_handle,
    valid_identifier,
)

ISO_US = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


class TimeTestCase(unittest.TestCase):
    def test_timestamps_are_iso8601_utc_with_sub_second_precision(self):
        # Whole-second timestamps collide across four services and the ordering
        # check (H-ORD) then fails for a reason that teaches nothing.
        self.assertRegex(now_iso(), ISO_US)
        self.assertEqual(iso_from_epoch(0), "1970-01-01T00:00:00.000000Z")


class TranscriptTestCase(unittest.TestCase):
    def setUp(self):
        self.transcript = Transcript()

    def record(self, **kwargs):
        base = dict(run_id="r-1", step=1, actor="applicant", peer="csp",
                    outcome="success", detail="evidence accepted")
        base.update(kwargs)
        return self.transcript.record(**base)

    def test_events_are_sequenced_and_contract_shaped(self):
        event = self.record()
        self.assertEqual(
            sorted(event),
            ["actor", "detail", "outcome", "peer", "run_id", "seq", "step",
             "step_name", "ts"],
        )
        self.assertEqual(event["seq"], 1)
        self.assertEqual(self.record()["seq"], 2)
        self.assertEqual(event["step_name"], STEP_NAMES[1])

    def test_rejects_values_outside_the_contract(self):
        # Defends against a transcript that lies: an event outside the contract's
        # vocabulary would make the record unreadable to the grader and could
        # smuggle an authorization-shaped role into an identity-lifecycle field.
        for bad in ({"step": 6}, {"actor": "admin"}, {"peer": "nobody"},
                    {"outcome": "maybe"}):
            with self.assertRaises(ValueError):
                self.record(**bad)

    def test_rejects_a_detail_that_is_not_a_plain_description(self):
        # Details that carry request data are how authenticator secrets end up
        # in a transcript; anything with the shape of interpolated input is
        # refused at the writer.
        with self.assertRaises(ValueError):
            self.record(detail="output={'authenticator': 'CANARY-a1b2c3'}")

    def test_a_malformed_run_id_never_stops_a_denial_from_being_recorded(self):
        # Defends against an attacker suppressing the audit trail by sending a
        # run_id the writer chokes on, so the denial is never recorded.
        self.assertEqual(self.record(run_id="../../etc/passwd")["run_id"],
                         "unattributed")
        self.assertEqual(clean_run_id("probe-happy_path-8f3a1c"),
                         "probe-happy_path-8f3a1c")

    def test_reset_empties_the_log_and_the_sequence(self):
        self.record()
        self.transcript.reset()
        self.assertEqual(self.transcript.events(), [])
        self.assertEqual(self.record()["seq"], 1)


class PasswordHashTestCase(unittest.TestCase):
    def test_a_correct_secret_verifies_and_a_wrong_one_does_not(self):
        record = hash_secret("CANARY-a1b2c3")
        self.assertTrue(verify_secret("CANARY-a1b2c3", record))
        self.assertFalse(verify_secret("CANARY-a1b2c4", record))

    def test_the_record_uses_a_password_hashing_function_and_a_fresh_salt(self):
        # A bare SHA-256 or MD5 store is brute-forceable at speed once stolen.
        first, second = hash_secret("same-secret"), hash_secret("same-secret")
        self.assertEqual(first["alg"], "scrypt")
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["dk"], second["dk"])
        self.assertNotIn("same-secret", str(first))

    def test_malformed_records_are_refused_rather_than_crashing(self):
        # Defends against a forged or downgraded binding record - an "md5" or
        # truncated record must fail verification, never crash into a code path
        # that treats the failure as success.
        for bad in (None, {}, {"alg": "md5"}, dict(hash_secret("x"), salt="zz")):
            self.assertFalse(is_record(bad) and verify_secret("x", bad))


class ValidationTestCase(unittest.TestCase):
    def test_identifiers_must_match_the_allow_list(self):
        # An identifier is a lookup key, not free text: anything outside the
        # pattern is refused before it is used anywhere.
        for good in ("alice", "alice.smith", "user-01", "a1b",
                     "jonathanchristensen123@gmail.com"):
            self.assertTrue(valid_identifier(good), good)
        for bad in ("al", "alice smith", "../etc", "alice';--", None, 7,
                    "a" * 300):
            self.assertFalse(valid_identifier(bad), bad)

    def test_identifiers_are_case_folded_to_one_account(self):
        # Defends against enrolling the spelling the real owner did not take:
        # email is compared case-insensitively in practice, so Alice@x.com and
        # alice@x.com must be one subscriber, not two.
        self.assertEqual(normalize_identifier("  JonathanChristensen123@Gmail.com  "),
                         "jonathanchristensen123@gmail.com")
        self.assertIsNone(normalize_identifier("no spaces allowed"))

    def test_handles_and_outputs_are_shape_checked(self):
        self.assertTrue(valid_handle("A" * 43))
        self.assertFalse(valid_handle("short"))
        self.assertTrue(valid_authenticator_output("CANARY-a1b2c3"))
        self.assertFalse(valid_authenticator_output("x" * 2000))
        self.assertFalse(valid_authenticator_output(""))


class RateLimiterTestCase(unittest.TestCase):
    def test_the_window_engages_and_a_success_clears_it(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        self.assertEqual([limiter.check("ip", now=100)[0] for _ in range(4)],
                         [True, True, True, False])
        limiter.forget("ip")
        self.assertTrue(limiter.check("ip", now=100)[0])

    def test_attempts_age_out_of_the_window(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        limiter.check("ip", now=0)
        limiter.check("ip", now=0)
        self.assertFalse(limiter.check("ip", now=10)[0])
        self.assertTrue(limiter.check("ip", now=200)[0])


class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        # A developer's own .env must not change what the suite asserts, so the
        # settings under test are cleared first. `.env` is read once per
        # process, so popping after that read is enough to keep it out.
        config.load_env_file()
        for key in ("LAB1_PORT_BLOCK", "LAB1_BIND_HOST", "HOST",
                    "LAB1_SUBJECT_PORT", "SUBJECT_PORT",
                    "LAB1_VERIFIER_PORT", "VERIFIER_PORT",
                    "LAB1_RP_PORT", "RP_PORT", "LAB1_CSP_PORT", "CSP_PORT"):
            os.environ.pop(key, None)

    def test_ports_follow_the_claimed_block(self):
        os.environ["LAB1_PORT_BLOCK"] = "4100"
        self.assertEqual(config.port_for("subject"), 4100)
        self.assertEqual(config.port_for("verifier"), 4102)
        self.assertEqual(config.port_for("rp"), 4103)

    def test_partner_a_settings_names_are_read_as_fallbacks(self):
        # One .env drives all four services: the FastAPI services use TEAM,
        # HOST and <SERVICE>_PORT, and the prefixed name wins when both are set.
        os.environ["HOST"] = "0.0.0.0"
        os.environ["VERIFIER_PORT"] = "4202"
        self.assertEqual(config.bind_host(), "0.0.0.0")
        self.assertEqual(config.port_for("verifier"), 4202)
        os.environ["LAB1_VERIFIER_PORT"] = "4302"
        self.assertEqual(config.port_for("verifier"), 4302)

    def test_services_bind_every_interface_by_default(self):
        # Binding 127.0.0.1 works on the server and is invisible from campus.
        self.assertEqual(config.bind_host(), "0.0.0.0")

    def test_a_missing_shared_token_refuses_to_start_the_service(self):
        # Failing closed beats a default token that is readable in the repo.
        os.environ.pop("LAB1_NOT_SET_TOKEN", None)
        with self.assertRaises(config.ConfigError):
            config.require_secret("LAB1_NOT_SET_TOKEN")
        os.environ["LAB1_NOT_SET_TOKEN"] = "too-short"
        with self.assertRaises(config.ConfigError):
            config.require_secret("LAB1_NOT_SET_TOKEN")


if __name__ == "__main__":
    unittest.main()
