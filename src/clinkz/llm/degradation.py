"""Provider degradation — what a fallback costs the run that took one.

Routing v2 makes Anthropic priority 1 for every call on every phase. This
module is the other half of that rule: a fallback is a **disqualifying event**,
not an invisible one.

Why this is not just a log line
-------------------------------

The last instance was found by reading traces after the fact. Gemini had served
6 exploit plans and 6 false-positive cross-checks across 9 engagements — the FP
cross-check being the *suppression* path, so the cheap tier had been deciding
which confirmed findings got demoted — and every one of those reports looked
exactly like a report it had not happened to. The fallback worked. That is the
problem: it produced an answer, the run completed, and nothing in the
deliverable distinguished it from a run served end to end by the model that was
asked for.

So a fallback now has two outcomes and no third:

* **baseline mode** — hard failure. A recorded baseline is only worth the
  comparison it supports, and a ladder served by two models is not a ladder.
  The evidence is not hypothetical: over 1,033 recorded phase-3 calls, the same
  prompt on a byte-identical header observation produced the version-disclosure
  entries 27% of the time under one model and 80% under another. A number
  produced half by one model and half by another is not a measurement of the
  target.
* **client mode** — the run completes, because a client engagement should not
  die because a provider had a bad minute. The report is stamped
  ``provider_degraded`` naming every call site and both models, and the run is
  marked **permanently ineligible as a baseline**.

Ineligibility is one-way on purpose. There is no code path that clears it: the
degraded call already happened and its output is already inside the findings,
so a later clean call cannot un-shape it. :meth:`DegradationRegister.reset` is
for process teardown between runs and tests, never for recovery.

Absent by default, like the governor and the ledger: a directly invoked
methodology, a replay or a driver installs no register and every hook no-ops,
so the black-box floor is byte-identical.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProviderFallback:
    """One call that a provider other than the primary served.

    Attributes:
        agent_role: The role whose call it was (``exploit``, ``scan``, ...).
        method: The ``LLMClient`` method — ``generate_text``, ``reason``,
            ``research``. Together with *agent_role* this is the "call site"
            the report has to name: "exploit fell back" is not actionable,
            "exploit.generate_text fell back" points at the plan.
        asked_provider: The provider the chain led with.
        asked_model: The model that provider would have used.
        served_provider: The provider that actually answered.
        served_model: The model that actually answered. It is this one that
            shaped the output.
        reason: The error class that caused the rotation, when known.
        decision_bearing: Whether this role's answer becomes a conclusion of
            the engagement rather than an observation a later oracle re-derives.
    """

    agent_role: str
    method: str
    asked_provider: str
    asked_model: str
    served_provider: str
    served_model: str
    reason: str = ""
    decision_bearing: bool = False

    @property
    def call_site(self) -> str:
        """``role.method`` — what the report names."""
        return f"{self.agent_role}.{self.method}"

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "call_site": self.call_site,
            "agent_role": self.agent_role,
            "method": self.method,
            "asked_provider": self.asked_provider,
            "asked_model": self.asked_model,
            "served_provider": self.served_provider,
            "served_model": self.served_model,
            "reason": self.reason,
            "decision_bearing": self.decision_bearing,
        }

    def describe(self) -> str:
        """One line for a log or a report row."""
        served = f"{self.served_provider}/{self.served_model}"
        asked = f"{self.asked_provider}/{self.asked_model}"
        tail = f" ({self.reason})" if self.reason else ""
        marker = " [decision-bearing]" if self.decision_bearing else ""
        return f"{self.call_site}: asked {asked}, served by {served}{tail}{marker}"


@dataclass
class DegradationRegister:
    """Every fallback this run took, and the eligibility it cost.

    Thread-safe: phases run concurrently and each has its own client.
    """

    _events: list[ProviderFallback] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, event: ProviderFallback) -> None:
        """Record one fallback. Always loud — this is never a debug line."""
        with self._lock:
            self._events.append(event)
        logger.warning(
            "PROVIDER DEGRADED — %s. This run is permanently ineligible as a baseline.",
            event.describe(),
        )

    def events(self) -> list[ProviderFallback]:
        """Every recorded fallback, in the order it happened."""
        with self._lock:
            return list(self._events)

    @property
    def degraded(self) -> bool:
        """Whether any call was served by a provider other than the primary."""
        with self._lock:
            return bool(self._events)

    @property
    def baseline_eligible(self) -> bool:
        """Whether this run may be used as a baseline.

        One-way. A degraded run does not become eligible again, because the
        degraded answer is already inside the findings.
        """
        return not self.degraded

    def decision_bearing_events(self) -> list[ProviderFallback]:
        """The subset whose answers became conclusions rather than observations."""
        return [event for event in self.events() if event.decision_bearing]

    def summary(self) -> dict[str, Any]:
        """Render for ``report.json``.

        Present even when nothing degraded: "no fallback occurred" is a claim
        the deliverable should make explicitly. A section that appears only on
        failure cannot be distinguished from a section nobody wrote.
        """
        events = self.events()
        served_by: dict[str, int] = {}
        for event in events:
            key = f"{event.served_provider}/{event.served_model}"
            served_by[key] = served_by.get(key, 0) + 1
        return {
            "provider_degraded": bool(events),
            "baseline_eligible": not events,
            "fallback_count": len(events),
            "decision_bearing_fallback_count": len(self.decision_bearing_events()),
            "call_sites": sorted({event.call_site for event in events}),
            "served_by": served_by,
            "events": [event.to_dict() for event in events],
        }

    def reset(self) -> None:
        """Forget every event.

        For process teardown and tests. **Not** a way to recover eligibility:
        the register is per-run, and clearing it mid-run would erase the record
        of a degradation whose output is already in the findings.
        """
        with self._lock:
            self._events.clear()


# ---------------------------------------------------------------------------
# The active register — absent by default
# ---------------------------------------------------------------------------

_active_register: DegradationRegister | None = None


def set_active_degradation_register(register: DegradationRegister | None) -> None:
    """Install (or clear) the run's register.

    Args:
        register: The register, or ``None`` to detach. Arranged exactly like
            :func:`clinkz.safety.governor.get_active_governor`: absent by
            default so a directly invoked methodology, a replay or a driver is
            byte-identical to before this existed.
    """
    global _active_register
    _active_register = register


def get_active_degradation_register() -> DegradationRegister | None:
    """The run's register, or ``None`` when nothing installed one."""
    return _active_register


def record_provider_fallback(event: ProviderFallback) -> None:
    """Record a fallback against the active register, if there is one.

    Never raises and never creates a register: a call made outside an
    engagement has no run to disqualify.
    """
    register = _active_register
    if register is None:
        return
    register.record(event)


def degradation_summary() -> dict[str, Any]:
    """The active register's summary, or the clean shape when none is installed.

    The clean shape rather than ``{}`` so the report always carries the claim.
    A run with no register made no LLM calls through the resilient client, and
    "nothing degraded" is true of it.
    """
    register = _active_register
    if register is None:
        return DegradationRegister().summary()
    return register.summary()


__all__ = [
    "DegradationRegister",
    "ProviderFallback",
    "degradation_summary",
    "get_active_degradation_register",
    "record_provider_fallback",
    "set_active_degradation_register",
]
