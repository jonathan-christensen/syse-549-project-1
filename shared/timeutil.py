"""One UTC timestamp helper, used by every service.

Sub-second precision is mandatory: the cross-service ordering check
(conformance check H-ORD) sorts transcript events from four independent
processes by `ts`, and whole-second timestamps collide.

Microseconds, not milliseconds. The probe sorts by the timestamp string and
nothing else, so two events one millisecond apart - the CSP recording step 2
and the Subject recording step 3, say - can tie, and the tie is then broken by
the order the probe happened to collect the transcripts in, which is not
chronological. Measured: at millisecond precision that inversion happens on
most runs. The width is fixed, so the strings still sort chronologically.
"""

from datetime import datetime, timezone


def now_iso() -> str:
    """Current UTC time as ISO 8601 with millisecond precision and a Z suffix.

    >>> now_iso()  # doctest: +SKIP
    '2026-09-14T18:22:03.114259Z'
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def iso_from_epoch(epoch_seconds: float) -> str:
    """Format an epoch timestamp the same way `now_iso` formats the clock."""
    return (
        datetime.fromtimestamp(epoch_seconds, timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
