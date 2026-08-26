"""The benchmark number a client sees must be what testing earned.

Runs 2 and 3 of the Juice Shop variance envelope dispatched **zero** methodology
tasks and still had four challenges marked solved by the target —
``errorHandling``, ``loginAdmin``, ``securityPolicy``, ``weakPassword`` — purely
by authenticating and crawling. Those four are in ``solved_total`` for every run,
including the ones that tested, so run 1's headline "7 of 49" is roughly twice
what this engine's exploitation actually achieved. The honest figure is 3.

The floor is **measured, never declared**. A constant list in the harness would
be a claim about the target that nobody re-derives, going stale the moment Juice
Shop changes what a crawl trips. It is written by a run that observed
``methodology_dispatches == 0`` and carries the engagement id that produced it,
and :func:`record_floor` refuses any other kind of run — a floor taken from a run
that DID test is this engine subtracting its own results from itself.

The live floor file lives under ``outputs/`` and is never committed. The
observation behind it is, in ``tests/fixtures/juiceshop_zero_dispatch_run.json``,
so these assertions run against a real zero-dispatch bundle.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "juiceshop_zero_dispatch_run.json"


@pytest.fixture(scope="module")
def harness() -> Any:
    """``scripts/juiceshop_benchmark_run`` with ``scripts/`` on the path.

    The module imports its siblings by bare name, exactly as
    ``test_class_coverage_account`` does for the same reason.
    """
    added = str(_SCRIPTS) not in sys.path
    if added:
        sys.path.insert(0, str(_SCRIPTS))
    try:
        import juiceshop_benchmark_run

        yield juiceshop_benchmark_run
    finally:
        if added and str(_SCRIPTS) in sys.path:
            sys.path.remove(str(_SCRIPTS))


@pytest.fixture(scope="module")
def observation() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _report_from(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A report shell carrying only the ledger rows the counter reads."""
    return {"component_ledger": {"components": rows}}


class TestTheDispatchCountIsRead:
    """Zero dispatches is the observation the whole mechanism turns on."""

    def test_run_3_dispatched_nothing(self, harness: Any, observation: dict[str, Any]) -> None:
        rows = observation["zero_dispatch_run"]["methodology_ledger_rows"]
        assert rows, "the fixture must carry the ledger rows, not just a total"
        assert harness.methodology_dispatches(_report_from(rows)) == 0

    def test_run_1_dispatched(self, harness: Any, observation: dict[str, Any]) -> None:
        rows = observation["testing_run"]["methodology_ledger_rows"]
        assert harness.methodology_dispatches(_report_from(rows)) > 0

    def test_only_methodology_components_are_counted(self, harness: Any) -> None:
        """``items`` means dispatches on a methodology row and something else elsewhere.

        ``exploit.control_arm`` registers on a KILL and a discoverer's items are
        endpoints; summing the whole ledger would count those as tests.
        """
        report = _report_from(
            [
                {"component": "methodology:_test_sqli", "items_contributed": 3},
                {"component": "exploit.control_arm", "items_contributed": 9},
                {"component": "discovery:openapi", "items_contributed": 40},
            ]
        )
        assert harness.methodology_dispatches(report) == 3

    def test_a_report_with_no_ledger_counts_zero(self, harness: Any) -> None:
        assert harness.methodology_dispatches({}) == 0


class TestTheFloorIsMeasuredNotDeclared:
    """A floor from a run that tested is a subtraction of the engine from itself."""

    @staticmethod
    def _isolate(harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(harness, "RESULTS_DIR", tmp_path)
        monkeypatch.setattr(harness, "FLOOR_PATH", tmp_path / "benchmark_floor.json")

    def test_recording_from_a_zero_dispatch_run_works(
        self,
        harness: Any,
        observation: dict[str, Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._isolate(harness, tmp_path, monkeypatch)
        run = observation["zero_dispatch_run"]
        solved = run["scoreboard_after"]["solved"]
        record = harness.record_floor(
            engagement=run["engagement"],
            solved_keys=solved,
            dispatches=0,
            challenge_index={c["key"]: c for c in run["scoreboard_after"]["newly_solved"]},
        )
        assert record["keys"] == sorted(solved)
        assert record["sources"][0]["engagement"] == run["engagement"]
        assert {c["key"] for c in record["challenges"]} == set(solved)
        assert (tmp_path / "benchmark_floor.json").is_file()

    def test_recording_from_a_testing_run_is_refused(
        self,
        harness: Any,
        observation: dict[str, Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._isolate(harness, tmp_path, monkeypatch)
        rows = observation["testing_run"]["methodology_ledger_rows"]
        dispatches = harness.methodology_dispatches(_report_from(rows))
        with pytest.raises(ValueError, match="methodology task"):
            harness.record_floor(
                engagement=observation["testing_run"]["engagement"],
                solved_keys=["loginAdminChallenge"],
                dispatches=dispatches,
                challenge_index={},
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_a_second_zero_dispatch_run_widens_the_floor(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Union, one-way. A run that trips a challenge the first did not has
        widened what crawling alone reaches; a run that fails to reproduce one is
        evidence about that run's crawl, not about the challenge."""
        self._isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="run-2", solved_keys=["a", "b"], dispatches=0, challenge_index={}
        )
        second = harness.record_floor(
            engagement="run-3", solved_keys=["b", "c"], dispatches=0, challenge_index={}
        )
        assert second["keys"] == ["a", "b", "c"]
        assert [s["engagement"] for s in second["sources"]] == ["run-2", "run-3"]


class TestTheSplitIsReportedSeparately:
    """``solved_total`` stays; ``solved_by_testing`` is the claim about this engine."""

    def test_the_floor_is_subtracted(self, harness: Any) -> None:
        floor = {
            "recorded": True,
            "keys": [
                "errorHandlingChallenge",
                "loginAdminChallenge",
                "securityPolicyChallenge",
                "weakPasswordChallenge",
            ],
            "sources": [{"engagement": "2e21a200"}],
        }
        # Run 1's shape: the four floor challenges plus three the testing earned.
        # Its own scoreboard snapshot was overwritten by the later runs, so the
        # three are named generically - what is under test is the arithmetic and
        # which side of it each key lands on.
        solved = sorted(floor["keys"] + ["earnedA", "earnedB", "earnedC"])
        split = harness.subtract_floor(solved, floor)
        assert split["solved_by_testing_count"] == 3
        assert sorted(split["solved_by_testing"]) == ["earnedA", "earnedB", "earnedC"]
        assert sorted(split["solved_from_floor"]) == sorted(floor["keys"])
        assert len(solved) == 7, "solved_total is unchanged - both numbers are true"

    def test_a_zero_dispatch_run_earns_nothing(
        self, harness: Any, observation: dict[str, Any]
    ) -> None:
        solved = observation["zero_dispatch_run"]["scoreboard_after"]["solved"]
        split = harness.subtract_floor(solved, {"recorded": True, "keys": solved})
        assert split["solved_by_testing"] == []

    def test_an_unmeasured_floor_reports_unknown_not_zero(self, harness: Any) -> None:
        """The distinction the whole section exists to preserve.

        "No floor has been measured" is not "the floor is empty"; defaulting to
        the second silently restores ``solved_by_testing == solved_total``, which
        is the inflated number.
        """
        split = harness.subtract_floor(["a", "b"], {"recorded": False, "keys": []})
        assert split["solved_by_testing"] is None
        assert split["solved_by_testing_count"] is None
        assert "unmeasured" in split["note"]

    def test_reading_an_absent_floor_file_is_not_an_empty_floor(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(harness, "FLOOR_PATH", tmp_path / "nothing-here.json")
        floor = harness.read_floor()
        assert floor["recorded"] is False
        assert harness.subtract_floor(["a"], floor)["solved_by_testing"] is None


class TestTheReconciliationCarriesBothNumbers:
    """Read from the source: the defect would be a missing key, not a wrong value."""

    def test_the_written_reconciliation_declares_the_split(self, harness: Any) -> None:
        source = Path(harness.__file__).read_text(encoding="utf-8")
        for key in (
            '"solved_total"',
            '"solved_by_testing"',
            '"solved_by_testing_count"',
            '"solved_by_testing_in_addressable"',
            '"methodology_dispatches"',
            '"benchmark_floor"',
        ):
            assert key in source, f"reconciliation.json must carry {key}"

    def test_a_zero_dispatch_run_records_the_floor_it_observed(self, harness: Any) -> None:
        """The condition that defines a floor is the condition just observed, so
        recording it in a separate pass would let the two drift."""
        source = Path(harness.__file__).read_text(encoding="utf-8")
        start = source.index("dispatches = methodology_dispatches(report)")
        end = source.index('out = RESULTS_DIR / "reconciliation.json"')
        between = source[start:end]
        assert "if dispatches == 0:" in between
        assert "record_floor(" in between, (
            "a run that dispatched nothing IS a floor observation, and it has to be "
            "recorded before the reconciliation that reads the floor is written"
        )
