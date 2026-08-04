"""Production safety rails.

Three concerns, one package:

  * :mod:`clinkz.safety.destructive` — WHAT must never be sent (the default-deny
    classifier over path, method, field names, and label text).
  * :mod:`clinkz.safety.action_log` — WHAT was actually sent (the per-run record
    an operator reads to answer "what did it do to my app?").
  * :mod:`clinkz.safety.governor` — HOW FAST, HOW MANY AT ONCE, and WHEN TO STOP
    (rate limit, concurrency cap, kill switch, blocking detection).

The governor is installed by the Orchestrator for a real engagement and is
**absent by default**, in which case every hook is a no-op. That is deliberate:
the rails govern an engagement, and a direct methodology invocation (a smoke
test, a replay, a driver script) keeps its existing behaviour exactly.
"""

from clinkz.safety.action_log import ActionLog, ActionRecord
from clinkz.safety.destructive import (
    DestructiveVerdict,
    classify_form_submission,
    classify_request,
    is_state_changing_request,
)
from clinkz.safety.governor import (
    EngagementGovernor,
    EngagementHaltedError,
    TargetBlockingDetectedError,
    get_active_governor,
    set_active_governor,
)

__all__ = [
    "ActionLog",
    "ActionRecord",
    "DestructiveVerdict",
    "EngagementGovernor",
    "EngagementHaltedError",
    "TargetBlockingDetectedError",
    "classify_form_submission",
    "classify_request",
    "get_active_governor",
    "is_state_changing_request",
    "set_active_governor",
]
