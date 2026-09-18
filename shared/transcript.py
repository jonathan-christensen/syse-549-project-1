"""The shared transcript writer.

Every service keeps its own ordered transcript and serves it from
`GET /transcript`. The event shape is frozen by the lab contract
(PROJECT_WORKFLOW.md section 5.1) — nine fields, nothing else.

Design rule enforced here: `detail` describes a *decision*, never an *input*.
Nothing that came off the wire is allowed into an event, which is how the
canary check (X-CAN) is passed by construction rather than by luck.
"""

import re
import threading
from typing import Any, Dict, List, Optional

from .timeutil import now_iso

# The five Figure 3 steps. Only the numbers are fixed by the contract; these
# snake_case names are the team's choice and must be identical in all four
# services, so they live here and nowhere else.
STEP_NAMES = {
    1: "identity_proofing_and_enrollment",
    2: "authenticator_enrollment_issuance",
    3: "authentication_request",
    4: "authentication_process",
    5: "authenticated_session",
}

ACTORS = ("applicant", "subscriber", "claimant", "csp", "verifier", "rp")
OUTCOMES = ("success", "denied")

# Used when a request arrives with no run_id to attribute it to — a direct
# curl or a probe check that is not part of a scripted run.
UNATTRIBUTED = "unattributed"

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
DETAIL_RE = re.compile(r"^[A-Za-z0-9 ,.:;/()'\"_-]{0,200}$")


def clean_run_id(value: Any) -> str:
    """Return `value` if it is a well-formed run_id, else UNATTRIBUTED.

    Never raises: a malformed run_id must not be able to stop a service from
    recording that it denied something.
    """
    if isinstance(value, str) and RUN_ID_RE.match(value):
        return value
    return UNATTRIBUTED


class Transcript:
    """Thread-safe, in-memory, ordered event log for one service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: List[Dict[str, Any]] = []
        self._seq = 0

    def record(
        self,
        *,
        run_id: Any,
        step: int,
        actor: str,
        peer: str,
        outcome: str,
        detail: str = "",
    ) -> Dict[str, Any]:
        """Append one contract-shaped event and return it."""
        if step not in STEP_NAMES:
            raise ValueError("step must be 1-5, got %r" % (step,))
        if actor not in ACTORS:
            raise ValueError("actor must be one of %s, got %r" % (ACTORS, actor))
        if peer not in ACTORS:
            raise ValueError("peer must be one of %s, got %r" % (ACTORS, peer))
        if outcome not in OUTCOMES:
            raise ValueError("outcome must be success or denied, got %r" % (outcome,))
        if not DETAIL_RE.match(detail):
            # A detail that fails this pattern is almost always a caller
            # interpolating request data into the transcript, which is how
            # authenticator secrets get logged.
            raise ValueError("detail is not a plain literal description")

        with self._lock:
            self._seq += 1
            event = {
                "seq": self._seq,
                "run_id": clean_run_id(run_id),
                "step": step,
                "step_name": STEP_NAMES[step],
                "actor": actor,
                "peer": peer,
                "outcome": outcome,
                "ts": now_iso(),
                "detail": detail,
            }
            self._events.append(event)
        return event

    def events(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        if run_id is not None:
            events = [e for e in events if e["run_id"] == run_id]
        return events

    def reset(self) -> None:
        with self._lock:
            self._events = []
            self._seq = 0
