"""Input validation, shared by every service.

Everything arriving from the Subject agent is untrusted input. Identifiers and
opaque handles are checked against an allow-list pattern *before* they are used
as dictionary keys, compared, or written anywhere — there is no dynamic query
anywhere in this system, and this is what keeps it that way.
"""

import re
from typing import Any, Optional

# Starts alphanumeric, 3-254 characters, and admits the characters an email
# address needs, because the CSP identifies subscribers by email. Still
# deliberately narrow: an identifier is a lookup key, not free text.
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._+@-]{2,253}$")

# Opaque credentials we mint ourselves: secrets.token_urlsafe output.
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

# NIST SP 800-63B-4 SS3.1.1.2: a password used as the sole authentication
# factor SHALL be at least 15 characters, and verifiers SHOULD permit at
# least 64. This system has no second factor, so every authenticator here is
# single-factor and the 15-character floor applies. scrypt (shared/pwhash.py)
# has no comparable technical ceiling, so the upper bound here is just a
# generous sanity limit, not a hard algorithm constraint.
MIN_OUTPUT_LEN = 15
MAX_OUTPUT_LEN = 1024


def normalize_identifier(value: Any) -> Optional[str]:
    """The canonical form of an identifier, or None if it is not one.

    Case is folded because email addresses are compared case-insensitively in
    practice: without this, `Alice@example.com` and `alice@example.com` are two
    subscriber accounts for one person, and an attacker can enrol the spelling
    the real owner did not take.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if IDENTIFIER_RE.match(candidate) else None


def valid_identifier(value: Any) -> bool:
    return normalize_identifier(value) is not None


def valid_handle(value: Any) -> bool:
    return isinstance(value, str) and bool(HANDLE_RE.match(value))


def valid_authenticator_output(value: Any) -> bool:
    """Shape check only — never a content check, and never logged."""
    return (
        isinstance(value, str)
        and MIN_OUTPUT_LEN <= len(value) <= MAX_OUTPUT_LEN
        and "\x00" not in value
    )
