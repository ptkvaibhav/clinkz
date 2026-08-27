"""The registry accounts for every class, and a hole never reads as a pass.

Ranking inversions answered "was the ORDER right among the tasks that existed",
and they saturated — 78/78 and 67/67 across the recorded ladders. They cannot
answer the question that outlives them: **did this class run at all**, and when
it did not, was that correct or a silent hole? Re-grading the recorded DVWA
ladder with the extended account surfaced ``_test_mass_assignment`` never
dispatched at any of the four levels while the plan held twenty candidates for
it — a coverage hole the inversion metric reported nothing about, because
nothing was mis-ORDERED.

The discriminator is the component ledger's, applied to vulnerability classes:
**how far the class's own pipeline got**, read from the run's trace, never a
self-assessment. These tests pin the classification in both directions, because
the failure that matters is the silent one — a hole classified as correct
disappears, and a correct zero classified as a hole becomes the permanent false
alarm that teaches an operator to skim the section.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


@pytest.fixture(scope="module")
def registry() -> ModuleType:
    """Import ``scripts/d1_consistency_runner.py`` by path — not a package.

    ``scripts/`` goes on ``sys.path`` first because the module imports its
    sibling ``_artifact_io`` the way it does when run as a driver.
    """
    added = str(_SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            "d1_consistency_runner", _SCRIPTS / "d1_consistency_runner.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if added:
            sys.path.remove(str(_SCRIPTS))


def _trace(
    tmp_path: Path,
    engagement: str,
    *,
    phases: list[tuple[str, int]],
    dropped: dict[str, list[str]] | None = None,
    kept: dict[str, int] | None = None,
    include_kept: bool = True,
    deterministic_dropped: dict[str, list[str]] | None = None,
    deterministic_kept: dict[str, int] | None = None,
) -> Path:
    """Write a minimal ``trace.jsonl`` carrying only what the account reads.

    ``dropped``/``kept`` describe the UNION stage — the plan that dispatched.
    The ``deterministic_*`` arguments write a second, earlier record so a test
    can prove the account reads the right one.
    """
    directory = tmp_path / engagement
    directory.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for skill, phase in phases:
        lines.append(
            json.dumps({"payload": {"skill": skill, "phase_number": phase, "phase_name": "x"}})
        )
    for stage, stage_dropped, stage_kept in (
        ("deterministic", deterministic_dropped, deterministic_kept),
        ("union", dropped, kept),
    ):
        if stage == "deterministic" and stage_dropped is None and stage_kept is None:
            continue
        record: dict[str, object] = {
            "skill": "plan_coverage",
            "phase_number": 0,
            "phase_name": "truncation",
            "stage": stage,
            "dropped_by_class": stage_dropped or {},
        }
        if include_kept:
            record["kept_by_class"] = stage_kept or {}
        lines.append(json.dumps({"payload": record}))
    (directory / "trace.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory


def _row(coverage: dict, klass: str) -> dict:
    return next(r for r in coverage["rows"] if r["test_method"] == klass)


def test_every_dispatchable_class_gets_exactly_one_verdict(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unaccounted class is the hole, so the account must be total."""
    from clinkz.agents.exploit import _DETERMINISTIC_CATEGORY_ORDER

    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(tmp_path, "eng", phases=[("sqli", 1), ("sqli", 5)])
    coverage = registry.class_coverage("eng")

    assert coverage["classes_accounted"] == len(_DETERMINISTIC_CATEGORY_ORDER)
    assert {r["test_method"] for r in coverage["rows"]} == set(_DETERMINISTIC_CATEGORY_ORDER)
    known = registry.CORRECT_COVERAGE_VERDICTS | registry.ALARM_COVERAGE_VERDICTS
    unknown = {r["verdict"] for r in coverage["rows"]} - known
    assert not unknown, f"verdicts classified as neither correct nor alarm: {sorted(unknown)}"


@pytest.mark.parametrize(
    ("phases", "expected"),
    [
        ([("sqli", 1), ("sqli", 5)], "dispatched_deep"),
        ([("sqli", 1)], "dispatched_applicability_only"),
        ([("sqli", 0)], "dispatched_gate_refused"),
    ],
)
def test_depth_decides_a_dispatched_classs_verdict(
    registry: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phases: list[tuple[str, int]],
    expected: str,
) -> None:
    """How far its own pipeline got — not what it concluded about itself."""
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(tmp_path, "eng", phases=phases)
    assert _row(registry.class_coverage("eng"), "_test_sqli")["verdict"] == expected


def test_a_class_with_surviving_tasks_that_never_ran_is_an_alarm(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ffuf shape at class granularity: the plan reached it, it did not run.

    This is the outcome the registry could not previously see, and it must be
    an ALARM — a fix in the dispatcher, not in the cap.
    """
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(
        tmp_path,
        "eng",
        phases=[("sqli", 5)],
        dropped={"_test_mass_assignment": ["http://t/a"]},
        kept={"_test_mass_assignment": 3},
    )
    row = _row(registry.class_coverage("eng"), "_test_mass_assignment")
    assert row["verdict"] == "no_phase_event_tasks_survived_the_cap"
    assert row["verdict"] in registry.ALARM_COVERAGE_VERDICTS
    assert "3 task(s) survived" in row["reason"]


def test_a_class_whose_every_candidate_the_cap_took_is_a_different_alarm(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coverage lost to the cap. Same silence, different fix, so a different number."""
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(
        tmp_path,
        "eng",
        phases=[("sqli", 5)],
        dropped={"_test_mass_assignment": ["http://t/a", "http://t/b"]},
        kept={"_test_sqli": 4},
    )
    row = _row(registry.class_coverage("eng"), "_test_mass_assignment")
    assert row["verdict"] == "never_dispatched_all_candidates_dropped"
    assert row["verdict"] in registry.ALARM_COVERAGE_VERDICTS


def test_a_class_the_plan_never_had_a_candidate_for_is_correct_not_an_alarm(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Correctly nothing to find" is a fifth fact and it is NOT an alarm.

    A GraphQL discoverer on an app with no GraphQL is the canonical case; a
    class with no applicable endpoint is the same fact. Reported as a defect it
    becomes a permanent false alarm, and a permanent false alarm trains an
    operator to skim the section where a real one will appear.
    """
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(tmp_path, "eng", phases=[("sqli", 5)], dropped={}, kept={"_test_sqli": 2})
    row = _row(registry.class_coverage("eng"), "_test_xxe")
    assert row["verdict"] == "never_dispatched_no_candidates"
    assert row["verdict"] in registry.CORRECT_COVERAGE_VERDICTS
    assert not [a for a in registry.class_coverage("eng")["alarms"] if "_test_xxe" in a]


def test_a_trace_without_kept_by_class_reports_indeterminate_rather_than_guessing(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An answer the evidence cannot support is never rounded to the benign side.

    Runs recorded before ``kept_by_class`` existed cannot separate "the cap took
    them all" from "tasks survived and nothing ran". That gets its own verdict,
    and it is on the ALARM side: an indeterminate coverage answer is a thing the
    operator must see, not a pass.
    """
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(
        tmp_path,
        "eng",
        phases=[("sqli", 5)],
        dropped={"_test_mass_assignment": ["http://t/a"]},
        include_kept=False,
    )
    coverage = registry.class_coverage("eng")
    assert coverage["kept_breakdown_present"] is False
    row = _row(coverage, "_test_mass_assignment")
    assert row["verdict"] == "never_dispatched_kept_breakdown_absent"
    assert row["verdict"] in registry.ALARM_COVERAGE_VERDICTS


def test_a_cross_cutting_skill_is_never_read_as_a_classs_own_dispatch(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``form_safety`` fires under 23 classes, so it is evidence about none.

    Counting it would report every class as dispatched on any run that refused
    a single form — which is every DVWA run — and the account would then be
    incapable of ever reporting a hole.
    """
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(
        tmp_path,
        "eng",
        phases=[("form_safety", 0), ("unproven_lead", 6), ("emission_gate", 3)],
        dropped={"_test_sqli": ["http://t/a"]},
        kept={"_test_sqli": 1},
    )
    coverage = registry.class_coverage("eng")
    assert coverage["reached_an_endpoint"] == 0
    assert _row(coverage, "_test_sqli")["verdict"] == "no_phase_event_tasks_survived_the_cap"


def test_only_the_union_stage_counts_as_the_plan_that_dispatched(
    registry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deterministic stage is the union's SOURCE, not the plan.

    It drops hundreds of candidates by design. A class whose tasks survived
    THERE and were then removed by the union pass never had a task to
    dispatch, so reading the deterministic stage reports a dispatcher bug
    where an ordinary truncation happened — the exact confusion the RANKING
    check already exists to prevent, pointed at a new number.
    """
    monkeypatch.setattr(registry, "OUTPUTS", tmp_path)
    _trace(
        tmp_path,
        "eng",
        phases=[("sqli", 5)],
        deterministic_kept={"_test_mass_assignment": 14},
        deterministic_dropped={"_test_mass_assignment": ["http://t/a"]},
        dropped={"_test_mass_assignment": ["http://t/a", "http://t/b"]},
        kept={"_test_sqli": 3},
    )
    row = _row(registry.class_coverage("eng"), "_test_mass_assignment")
    assert row["verdict"] == "never_dispatched_all_candidates_dropped", (
        "the deterministic stage's kept count was read as the dispatched plan"
    )
    assert row["plan_kept"] == 0
