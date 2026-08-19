"""What the exploit plan dropped, carried into the deliverable.

Part D's rule, applied to the one bound that was never reported: an operator
must be able to read what the run was allowed to do, and what it did not do,
off the artifact — not off a log line that scrolled past twenty minutes ago.

The rate cap, the concurrency cap, the window, the token cap and the spend cap
are stated before anything is dispatched. The **plan cap** is the sixth bound,
and it is the one that most directly decides what gets tested: candidate
``(class, endpoint)`` pairs are ranked and everything past the cap is dropped.
Four recorded D1 baseline runs each truncated ~1,500 candidates to 150.

That truncation has never been silent — ``_log_plan_truncation`` names every
dropped class, the count, the first omitted endpoint, and separately any
**ranking inversion** — but it has only ever been *loud in the log and the
trace*. The report says nothing, and the report is the artifact that reaches
the client. So a deliverable could say "we tested the target" over a plan that
dropped the one endpoint the class could have confirmed on, and the reader had
no way to know: reading ``trace.jsonl`` is not something a client does.

Two facts, held apart, because they have different fixes
--------------------------------------------------------

* **Truncation** — the cap removed a class's tail. The budget working as
  designed. The fix, if the operator wants those tasks, is a larger cap.
* **Ranking inversion** — a task was dropped from an endpoint where that
  class's *own* attack surface was observed, while lower-relevance tasks
  survived. That is the ordering failing, not the budget, and a larger cap does
  not fix it. It is the defect that cost D1 its weak-session and SQLi findings.

An inversion reads nothing like tail truncation and must not hide inside it —
the same reason the contribution ledger keeps ``DEAD_SEAM`` apart from
``SILENT``. So the summary reports them as separate numbers and the Markdown
renders the inversions with the grade each task was dropped at.

Rendered on a clean run too. "No class was truncated" is a claim; an absent
section is not — a run that fit inside its cap and a run whose truncation
nobody recorded would otherwise produce identical artifacts.

Absent by default, like the governor, the ledger and the scope-refusal log: a
directly invoked methodology, a replay or a driver installs no register, every
hook no-ops, and the black-box floor is byte-identical.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: Most dropped endpoints to retain per class. The COUNT stays exact past this,
#: for the same reason the scope-refusal log keeps its tally exact: a truncated
#: record of a truncation is the failure this module exists to prevent.
MAX_RETAINED_PER_CLASS = 20


@dataclass(frozen=True)
class PlanTruncation:
    """One planning pass's cap outcome.

    Attributes:
        stage: Which pass reported ("deterministic" / "union").
        cap: The task cap in force.
        kept: How many tasks survived it.
        kept_by_class: Per class, HOW MANY of its tasks survived. The total
            above cannot answer the question the class-coverage account asks —
            a class that produced no finding either had every candidate dropped
            (the cap's fault, fixed by a bigger cap) or had tasks in the plan
            and never ran them (the dispatcher's fault, an entirely different
            bug). ``kept`` and ``dropped_by_class`` together leave those two
            indistinguishable, which is the same shape as every other total
            this codebase has had to break down into its parts.
        dropped_total: How many candidates the cap removed.
        dropped_by_class: Per class, the endpoints dropped (bounded by
            :data:`MAX_RETAINED_PER_CLASS`; the count above is exact).
        ranking_inversions: Dropped tasks that sat on an endpoint carrying
            their own class's observed surface. Each is
            ``{"test_method", "endpoint_url", "grade"}``.
    """

    stage: str
    cap: int
    kept: int
    dropped_total: int
    kept_by_class: dict[str, int] = field(default_factory=dict)
    dropped_by_class: dict[str, list[str]] = field(default_factory=dict)
    ranking_inversions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        """Whether the cap removed anything at all."""
        return self.dropped_total > 0

    def to_dict(self) -> dict[str, Any]:
        """Render for ``report.json``."""
        return {
            "stage": self.stage,
            "cap": self.cap,
            "kept": self.kept,
            "kept_by_class": dict(sorted(self.kept_by_class.items())),
            "dropped_total": self.dropped_total,
            "classes_truncated": sorted(self.dropped_by_class),
            "dropped_by_class": {
                name: endpoints[:MAX_RETAINED_PER_CLASS]
                for name, endpoints in sorted(self.dropped_by_class.items())
            },
            "ranking_inversion_count": len(self.ranking_inversions),
            "ranking_inversions": self.ranking_inversions[:MAX_RETAINED_PER_CLASS],
        }


@dataclass
class PlanAlarmRegister:
    """Every planning pass's cap outcome, for the report.

    Thread-safe: the deterministic and union passes can report from different
    tasks.
    """

    _passes: list[PlanTruncation] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, event: PlanTruncation) -> None:
        """Record one pass. A ranking inversion is always logged loudly."""
        with self._lock:
            self._passes.append(event)
        if event.ranking_inversions:
            logger.warning(
                "PLAN RANKING FAILURE recorded for the report — %d dropped task(s) sat on "
                "an endpoint carrying their own class's observed surface (stage=%s cap=%d).",
                len(event.ranking_inversions),
                event.stage,
                event.cap,
            )

    def passes(self) -> list[PlanTruncation]:
        """Every recorded pass, in the order it happened."""
        with self._lock:
            return list(self._passes)

    def summary(self) -> dict[str, Any]:
        """Render for ``report.json``.

        Present even when nothing was truncated, because "the plan fit inside
        its cap" is a claim the deliverable should make explicitly.
        """
        passes = self.passes()
        classes: set[str] = set()
        planned: set[str] = set()
        for event in passes:
            classes.update(event.dropped_by_class)
            planned.update(event.dropped_by_class)
            planned.update(k for k, n in event.kept_by_class.items() if n)
        return {
            "plan_truncated": any(p.truncated for p in passes),
            "passes_recorded": len(passes),
            "dropped_total": sum(p.dropped_total for p in passes),
            "classes_truncated": sorted(classes),
            # Every class the plan held a candidate for, kept or dropped. The
            # class-coverage account reads this to tell "no applicable endpoint
            # existed" from "the plan had one and the class never ran".
            "classes_with_candidates": sorted(planned),
            "ranking_inversion_count": sum(len(p.ranking_inversions) for p in passes),
            "passes": [p.to_dict() for p in passes],
        }

    def reset(self) -> None:
        """Forget every pass. For process teardown and tests."""
        with self._lock:
            self._passes.clear()


# ---------------------------------------------------------------------------
# The active register — absent by default
# ---------------------------------------------------------------------------

_active_register: PlanAlarmRegister | None = None


def set_active_plan_alarms(register: PlanAlarmRegister | None) -> None:
    """Install (or clear) the run's register.

    Args:
        register: The register, or ``None`` to detach.
    """
    global _active_register
    _active_register = register


def get_active_plan_alarms() -> PlanAlarmRegister | None:
    """The run's register, or ``None`` when nothing installed one."""
    return _active_register


def record_plan_truncation(event: PlanTruncation) -> None:
    """Record a planning pass against the active register, if there is one.

    Never raises and never creates a register: a plan built outside an
    engagement — a unit test, a replay — has no report to carry it.
    """
    register = _active_register
    if register is None:
        return
    register.record(event)


def plan_alarm_summary() -> dict[str, Any]:
    """The active register's summary, or the clean shape when none is installed."""
    register = _active_register
    if register is None:
        return PlanAlarmRegister().summary()
    return register.summary()


__all__ = [
    "MAX_RETAINED_PER_CLASS",
    "PlanAlarmRegister",
    "PlanTruncation",
    "get_active_plan_alarms",
    "plan_alarm_summary",
    "record_plan_truncation",
    "set_active_plan_alarms",
]
