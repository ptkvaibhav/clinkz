"""The plan regression check compares SETS, not counts (register R29).

On the #145 ride-along ``kept_by_class['_test_write_crossing']`` went 6 -> 5 and
read as noise; the one endpoint that left was ``/api/Complaints``, which carried
the engine's only confirmed cross-principal write. These tests pin the check
that would have failed on it, and the producer half that makes it answerable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.observability.candidate_regression import (
    CONFIRMED_FINDING_PHASE,
    PLAN_SETS_PHASE,
    PairState,
    PlanSets,
    Verdict,
    compare_bundles,
    compare_plan_sets,
    load_plan_sets,
)

_ORIGIN = "http://clinkz-juiceshop:3000"
_COMPLAINTS = ("_test_write_crossing", f"{_ORIGIN}/api/Complaints")
_ADDRESSES = ("_test_write_crossing", f"{_ORIGIN}/api/Addresss")
_TWOFA = ("_test_write_crossing", f"{_ORIGIN}/rest/2fa/setup")


def _record(phase: str, **extra: object) -> str:
    payload = {"skill": "plan_coverage", "phase_number": 0, "phase_name": phase, **extra}
    return json.dumps({"stage": "exploit", "category": "methodology_phase", "payload": payload})


def _bundle(
    root: Path,
    name: str,
    *,
    planned: list[tuple[str, str]],
    candidates: list[tuple[str, str]],
    confirmed: list[tuple[str, str]],
    with_plan_sets: bool = True,
) -> Path:
    directory = root / name
    directory.mkdir()
    lines = [
        # A truncation record carrying only COUNTS — exactly what a legacy
        # bundle has, and what the check must not be satisfied by.
        _record("truncation", stage="union", kept_by_class={"_test_write_crossing": 5}),
    ]
    if with_plan_sets:
        lines.append(
            _record(
                PLAN_SETS_PHASE,
                planned=[list(p) for p in planned],
                candidates=[list(p) for p in candidates],
            )
        )
    for method, url in confirmed:
        lines.append(_record(CONFIRMED_FINDING_PHASE, test_method=method, endpoint_url=url))
    (directory / "trace.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory


def test_r29_shape_fails_as_truncated_although_the_class_count_barely_moved(
    tmp_path: Path,
) -> None:
    """Baseline confirmed Complaints; the later run kept 5 write tasks, none of them it."""
    baseline = _bundle(
        tmp_path,
        "base",
        planned=[_COMPLAINTS, _ADDRESSES],
        candidates=[_COMPLAINTS, _ADDRESSES, _TWOFA],
        confirmed=[_COMPLAINTS],
    )
    later = _bundle(
        tmp_path,
        "later",
        planned=[_ADDRESSES, _TWOFA],
        candidates=[_COMPLAINTS, _ADDRESSES, _TWOFA],
        confirmed=[],
    )
    result = compare_bundles(baseline, later)
    assert result.verdict is Verdict.REGRESSION
    assert [(o.test_method, o.endpoint_url, o.state) for o in result.regressions] == [
        (*_COMPLAINTS, PairState.TRUNCATED)
    ]


def test_a_pair_that_was_never_a_candidate_is_absent_not_truncated(tmp_path: Path) -> None:
    """Absent and truncated have different fixes, so they are different states."""
    baseline = _bundle(
        tmp_path, "base", planned=[_COMPLAINTS], candidates=[_COMPLAINTS], confirmed=[_COMPLAINTS]
    )
    later = _bundle(tmp_path, "later", planned=[_ADDRESSES], candidates=[_ADDRESSES], confirmed=[])
    (outcome,) = compare_bundles(baseline, later).regressions
    assert outcome.state is PairState.ABSENT


def test_planned_is_a_pass_even_when_the_later_run_did_not_confirm(tmp_path: Path) -> None:
    """The check is about REACH. Whether the oracle fires again is the oracle's question."""
    baseline = _bundle(
        tmp_path, "base", planned=[_COMPLAINTS], candidates=[_COMPLAINTS], confirmed=[_COMPLAINTS]
    )
    later = _bundle(
        tmp_path, "later", planned=[_COMPLAINTS], candidates=[_COMPLAINTS], confirmed=[]
    )
    result = compare_bundles(baseline, later)
    assert result.verdict is Verdict.PASS
    assert [o.state for o in result.outcomes] == [PairState.PLANNED]


@pytest.mark.parametrize("legacy_side", ["base", "later"])
def test_a_bundle_without_plan_sets_is_not_determined_never_a_pass(
    tmp_path: Path, legacy_side: str
) -> None:
    """A trace carrying only kept_by_class COUNTS cannot answer a set question."""
    sides = {
        name: _bundle(
            tmp_path,
            name,
            planned=[_COMPLAINTS],
            candidates=[_COMPLAINTS],
            confirmed=[_COMPLAINTS],
            with_plan_sets=name != legacy_side,
        )
        for name in ("base", "later")
    }
    result = compare_bundles(sides["base"], sides["later"])
    assert result.verdict is Verdict.NOT_DETERMINED
    assert result.reason


def test_a_missing_trace_is_not_determined(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    assert load_plan_sets(tmp_path / "empty") is None


def test_a_baseline_that_confirmed_nothing_passes_with_no_outcomes() -> None:
    """An empty confirmed set is a measurement, unlike a missing record."""
    empty = PlanSets(planned=frozenset(), candidates=frozenset(), confirmed=frozenset())
    result = compare_plan_sets(empty, empty)
    assert result.verdict is Verdict.PASS
    assert result.outcomes == []


def test_the_driver_exit_code_is_the_verdict(tmp_path: Path) -> None:
    """0 pass · 1 regression · 2 not determined — a CI step can gate on it."""
    import importlib.util

    script = Path(__file__).resolve().parents[2] / "scripts" / "candidate_set_regression.py"
    spec = importlib.util.spec_from_file_location("candidate_set_regression", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    _bundle(tmp_path, "b", planned=[_COMPLAINTS], candidates=[_COMPLAINTS], confirmed=[_COMPLAINTS])
    _bundle(tmp_path, "ok", planned=[_COMPLAINTS], candidates=[_COMPLAINTS], confirmed=[])
    _bundle(tmp_path, "lost", planned=[], candidates=[_COMPLAINTS], confirmed=[])
    _bundle(tmp_path, "old", planned=[], candidates=[], confirmed=[], with_plan_sets=False)
    run = module.main
    assert run(["b", "ok", "--outputs", str(tmp_path)]) == 0
    assert run(["b", "lost", "--outputs", str(tmp_path)]) == 1
    assert run(["b", "old", "--outputs", str(tmp_path)]) == 2


# --------------------------------------------- every run records a plan (item 3)


def _orchestrator_fallback(tmp_path: Path, summary: dict[str, object]) -> Path:
    """Run the orchestrator's end-of-run fallback against a real TraceWriter."""
    from clinkz.observability.trace import TraceWriter
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    writer = TraceWriter("e1", outputs_root=tmp_path)
    OrchestratorAgent._ensure_plan_sets_recorded(object.__new__(OrchestratorAgent), writer, summary)
    writer.close()
    return tmp_path / "e1"


@pytest.mark.parametrize(
    ("summary", "fragment"),
    [
        ({"phases": {}}, "never dispatched"),
        (
            {"phases": {"exploit": {"status": "error", "error": "boom"}}},
            "failed before planning: boom",
        ),
        ({"phases": {"exploit": {"status": "timeout"}}}, "without recording a plan"),
    ],
)
def test_a_run_whose_exploit_phase_never_planned_still_records_a_judgeable_plan(
    tmp_path: Path, summary: dict[str, object], fragment: str
) -> None:
    """An empty plan with its reason is a fact; a missing record is NOT DETERMINED."""
    later = load_plan_sets(_orchestrator_fallback(tmp_path, summary))
    assert later is not None
    assert later.planned == frozenset()
    assert fragment in later.unplanned_reason

    baseline = PlanSets(
        planned=frozenset({_COMPLAINTS}),
        candidates=frozenset({_COMPLAINTS}),
        confirmed=frozenset({_COMPLAINTS}),
    )
    result = compare_plan_sets(baseline, later)
    assert result.verdict is Verdict.REGRESSION
    assert fragment in result.reason


def test_the_fallback_never_overwrites_the_agents_own_record(tmp_path: Path) -> None:
    from clinkz.observability.trace import TraceWriter
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    writer = TraceWriter("e2", outputs_root=tmp_path)
    writer.methodology_phase(
        stage="exploit",
        skill="plan_coverage",
        phase_number=0,
        phase_name=PLAN_SETS_PHASE,
        extra={"planned": [list(_COMPLAINTS)], "candidates": [list(_COMPLAINTS)]},
    )
    OrchestratorAgent._ensure_plan_sets_recorded(
        object.__new__(OrchestratorAgent), writer, {"phases": {}}
    )
    writer.close()
    sets = load_plan_sets(tmp_path / "e2")
    assert sets is not None and sets.planned == frozenset({_COMPLAINTS})
    assert sets.unplanned_reason == ""
