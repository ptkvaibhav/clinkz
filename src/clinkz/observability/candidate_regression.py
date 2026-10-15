"""A regression check over two engagement bundles that compares SETS, not counts.

Register R29: on the #145 ride-along, ``kept_by_class`` for
``_test_write_crossing`` went 6 -> 5 and read as noise, and the candidate set
was called "essentially identical". The one endpoint that left the plan was
``/api/Complaints`` — the endpoint carrying the engine's only confirmed
cross-principal write. A total is not evidence about its parts (invariant 72),
and a count of kept tasks is a total.

So the check here is over members. For every ``(test_method, endpoint_url)``
the BASELINE confirmed, the LATER run must have PLANNED that same pair. When it
did not, the regression names which of two things happened, because they have
different fixes:

* ``truncated`` — the pair was a candidate and a cap removed it (a ranking or
  budget defect; R29 was this);
* ``absent`` — the pair was never a candidate (discovery, verb evidence, or
  routing).

A bundle written before the plan-set records existed cannot answer the
question, and is reported :data:`NOT_DETERMINED` — never as a pass. A check
that cannot see is not a check that saw nothing (invariant 80).

Pure: reads ``trace.jsonl`` and ``report_<id>.json`` off disk and nothing else.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

#: ``phase_name`` of the ``plan_coverage`` record carrying the final plan and the
#: candidate pool as sets. Written by ``ExploitAgent._trace_plan_sets``.
PLAN_SETS_PHASE = "plan_sets"

#: ``phase_name`` of the ``plan_coverage`` record attributing one persisted
#: confirmed finding to the task that produced it.
CONFIRMED_FINDING_PHASE = "confirmed_finding"


class PairState(StrEnum):
    """What the later run did with one pair the baseline confirmed."""

    PLANNED = "planned"
    TRUNCATED = "truncated"
    ABSENT = "absent"


class Verdict(StrEnum):
    """The comparison's outcome. Only ``PASS`` licenses "nothing was lost"."""

    PASS = "pass"
    REGRESSION = "regression"
    NOT_DETERMINED = "not_determined"


@dataclass(frozen=True)
class PlanSets:
    """One bundle's plan, candidate pool, and confirmed pairs."""

    planned: frozenset[tuple[str, str]]
    candidates: frozenset[tuple[str, str]]
    confirmed: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class PairOutcome:
    """One baseline-confirmed pair, and what the later run did with it."""

    test_method: str
    endpoint_url: str
    state: PairState


@dataclass
class CandidateSetComparison:
    """The full comparison. ``reason`` is set whenever the verdict is not PASS."""

    verdict: Verdict
    outcomes: list[PairOutcome] = field(default_factory=list)
    reason: str = ""

    @property
    def regressions(self) -> list[PairOutcome]:
        """The confirmed pairs the later run did not plan."""
        return [o for o in self.outcomes if o.state is not PairState.PLANNED]


def _pairs(raw: Iterable[Any]) -> frozenset[tuple[str, str]]:
    return frozenset((str(p[0]), str(p[1])) for p in raw)


def load_plan_sets(bundle_dir: Path) -> PlanSets | None:
    """Read one bundle's plan sets, or ``None`` when the bundle predates them.

    ``None`` is returned only when the trace carries no :data:`PLAN_SETS_PHASE`
    record. A bundle that has one but confirmed nothing returns an empty
    ``confirmed`` — a different fact, and a legitimate baseline.
    """
    trace = bundle_dir / "trace.jsonl"
    if not trace.is_file():
        return None
    plan_record: dict[str, Any] | None = None
    confirmed: set[tuple[str, str]] = set()
    with trace.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            payload = json.loads(line).get("payload") or {}
            if payload.get("skill") != "plan_coverage":
                continue
            phase = payload.get("phase_name")
            if phase == PLAN_SETS_PHASE:
                # The last one wins: a phase re-planned after a retry is the plan
                # that ran.
                plan_record = payload
            elif phase == CONFIRMED_FINDING_PHASE:
                confirmed.add((str(payload["test_method"]), str(payload["endpoint_url"])))
    if plan_record is None:
        return None
    return PlanSets(
        planned=_pairs(plan_record.get("planned", [])),
        candidates=_pairs(plan_record.get("candidates", [])),
        confirmed=frozenset(confirmed),
    )


def compare_plan_sets(baseline: PlanSets | None, later: PlanSets | None) -> CandidateSetComparison:
    """Every pair *baseline* confirmed must be planned by *later*.

    Args:
        baseline: The run whose confirmations are the floor.
        later: The run being checked against it.

    Returns:
        ``NOT_DETERMINED`` when either side predates the plan-set records,
        ``REGRESSION`` naming every lost pair, else ``PASS``.
    """
    if baseline is None or later is None:
        side = "baseline" if baseline is None else "later run"
        return CandidateSetComparison(
            verdict=Verdict.NOT_DETERMINED,
            reason=(
                f"the {side} carries no {PLAN_SETS_PHASE!r} trace record, so its plan "
                "cannot be compared by set; a count comparison is not a substitute"
            ),
        )
    outcomes: list[PairOutcome] = []
    for method, url in sorted(baseline.confirmed):
        if (method, url) in later.planned:
            state = PairState.PLANNED
        elif (method, url) in later.candidates:
            state = PairState.TRUNCATED
        else:
            state = PairState.ABSENT
        outcomes.append(PairOutcome(test_method=method, endpoint_url=url, state=state))
    lost = [o for o in outcomes if o.state is not PairState.PLANNED]
    if lost:
        return CandidateSetComparison(
            verdict=Verdict.REGRESSION,
            outcomes=outcomes,
            reason=f"{len(lost)} baseline-confirmed pair(s) not planned by the later run",
        )
    return CandidateSetComparison(verdict=Verdict.PASS, outcomes=outcomes)


def compare_bundles(baseline_dir: Path, later_dir: Path) -> CandidateSetComparison:
    """:func:`compare_plan_sets` over two ``outputs/<id>/`` directories."""
    return compare_plan_sets(load_plan_sets(baseline_dir), load_plan_sets(later_dir))
