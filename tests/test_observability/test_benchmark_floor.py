"""The benchmark number a client sees must be what testing earned.

Runs 2 and 3 of the Juice Shop variance envelope dispatched **zero** methodology
tasks and still had four challenges marked solved by the target —
``errorHandling``, ``loginAdmin``, ``securityPolicy``, ``weakPassword`` — purely
by authenticating and crawling. Those four are in ``solved_total`` for every run,
including the ones that tested, so run 1's headline "7 of 49" is roughly twice
what this engine's exploitation actually achieved.

The floor is **measured, never declared**. A constant list in the harness would
be a claim about the target that nobody re-derives, going stale the moment Juice
Shop changes what a crawl trips. It is written by a run that observed
``methodology_dispatches == 0`` and carries the engagement id that produced it,
and :func:`record_floor` refuses any other kind of run.

"Any other kind of run" is three kinds, and each was found by reading the bundle
the floor on disk was actually taken from:

* **It tested.** A floor from a run that dispatched is this engine subtracting
  its own results from itself.
* **Its dispatch count is unmeasurable.** Per-class methodology components are
  declared at engagement start; a bundle predating that carries none, and a
  counter that sums the rows it finds reports zero for a run with 11 findings.
  An absent population is not a zero — the ledger's own law.
* **An LLM provider outage means its crawl was not a complete crawl.** A run
  whose stamp names an unserved stage dispatches nothing, which from the
  harness's position is indistinguishable from the zero-dispatch run that DEFINES
  the floor. ``2e21a200`` is exactly that run, and it is what the floor on disk
  was measured from.

And a floor is what authenticating and crawling trip **as those principals**, so
it is keyed by the credential set that produced it. Supplying ``jim`` beside
``admin`` adds whatever ``jim``'s own login trips; subtracting an admin-only
floor from that run credits those challenges to testing, which is the inflation
the floor exists to remove, re-entering by the door nobody was watching.

The live floor file lives under ``outputs/`` and is never committed. The
observations behind these assertions are, in
``tests/fixtures/juiceshop_zero_dispatch_run.json``.
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


def _isolate(harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(harness, "FLOOR_PATH", tmp_path / "benchmark_floor.json")


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

    def test_a_report_with_no_ledger_is_unmeasurable_not_zero(self, harness: Any) -> None:
        """The count is read off a population; no population means no reading.

        Reported as zero, it is the strongest possible evidence — "this run
        tested nothing" — manufactured out of an absent key.
        """
        assert harness.methodology_dispatches({}) is None

    def test_a_ledger_without_methodology_components_is_unmeasurable(
        self, harness: Any, observation: dict[str, Any]
    ) -> None:
        """The real shape: 12 components, no methodology row, 11 findings.

        Per-class methodology components are declared at engagement start, so a
        bundle predating that registration carries none. Summing the rows it does
        carry answers a question about a population that is not there.
        """
        pre = observation["ledger_predating_methodology_components"]
        assert pre["findings_emitted"] > 0, "the fixture run plainly tested"
        assert pre["methodology_ledger_rows"] == []
        assert not any(str(c).startswith("methodology:") for c in pre["component_names"])
        report = _report_from(
            [{"component": name, "items_contributed": 0} for name in pre["component_names"]]
        )
        assert harness.methodology_dispatches(report) is None


class TestTheCredentialSetKeysTheFloor:
    """A floor is what THESE principals trip, so it is keyed by them."""

    def test_the_key_is_read_from_the_runs_own_record(self, harness: Any) -> None:
        report = {"authentication": {"roles": ["Jim", "admin"]}}
        assert harness.credential_set_key(report) == "admin+jim"

    def test_the_key_is_order_and_case_independent(self, harness: Any) -> None:
        assert harness.credential_set_key({"authentication": {"roles": ["admin", "jim"]}}) == (
            harness.credential_set_key({"authentication": {"roles": [" JIM ", "Admin"]}})
        )

    def test_a_run_that_authenticated_as_nobody_is_still_a_credential_set(
        self, harness: Any
    ) -> None:
        """An anonymous crawl trips a floor of its own, and it is comparable."""
        key = harness.credential_set_key({"authentication": {"roles": []}})
        assert key == harness.ANONYMOUS_CREDENTIAL_SET
        assert key != harness.UNKNOWN_CREDENTIAL_SET

    def test_a_report_with_no_authentication_block_is_unknown_not_anonymous(
        self, harness: Any
    ) -> None:
        """The distinction the key exists to keep: not knowing is not "nobody"."""
        assert harness.credential_set_key({}) == harness.UNKNOWN_CREDENTIAL_SET
        assert harness.credential_set_key({"authentication": {}}) == harness.UNKNOWN_CREDENTIAL_SET

    def test_the_real_zero_dispatch_bundle_declares_its_credential_set(
        self, harness: Any, observation: dict[str, Any]
    ) -> None:
        run = observation["zero_dispatch_run"]
        assert harness.credential_set_key({"authentication": run["authentication"]}) == "admin"

    def test_a_floor_measured_under_other_principals_is_not_applied(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The defect this keying removes.

        The stored floor was measured under ``admin``. Adding ``jim`` adds
        ``loginJim`` to what a crawl trips, so subtracting the admin-only floor
        would credit ``loginJim`` to testing.
        """
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="floor-admin",
            solved_keys=["loginAdminChallenge", "errorHandlingChallenge"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        split = harness.subtract_floor(
            ["loginAdminChallenge", "loginJimChallenge", "earned"],
            harness.read_floor(),
            credential_set="admin+jim",
        )
        assert split["solved_by_testing"] is None
        assert split["solved_by_testing_count"] is None
        assert split["measured_credential_sets"] == ["admin"]
        assert "'admin'" in split["note"] and "admin+jim" in split["note"]

    def test_the_same_credential_set_is_applied(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="floor-admin",
            solved_keys=["loginAdminChallenge"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        split = harness.subtract_floor(
            ["loginAdminChallenge", "earned"], harness.read_floor(), credential_set="admin"
        )
        assert split["solved_by_testing"] == ["earned"]
        assert split["solved_from_floor"] == ["loginAdminChallenge"]

    def test_two_credential_sets_coexist(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both are true measurements of two different things; neither replaces the other."""
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="floor-admin",
            solved_keys=["loginAdminChallenge"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        harness.record_floor(
            engagement="floor-admin-jim",
            solved_keys=["loginAdminChallenge", "loginJimChallenge"],
            dispatches=0,
            challenge_index={},
            credential_set="admin+jim",
            exhausted_stages=[],
        )
        floor_file = harness.read_floor()
        assert sorted(floor_file["floors"]) == ["admin", "admin+jim"]
        assert harness.floor_for(floor_file, "admin")["keys"] == ["loginAdminChallenge"]
        assert harness.floor_for(floor_file, "admin+jim")["keys"] == [
            "loginAdminChallenge",
            "loginJimChallenge",
        ]

    def test_a_run_that_does_not_say_who_it_was_matches_nothing(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="floor-admin",
            solved_keys=["a"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        split = harness.subtract_floor(
            ["a", "b"], harness.read_floor(), credential_set=harness.UNKNOWN_CREDENTIAL_SET
        )
        assert split["solved_by_testing"] is None

    def test_a_legacy_unkeyed_floor_is_read_and_never_applied(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The floor on disk today. It records no credential set, so "does it match
        this run" is unanswerable, and answering it anyway guesses in the
        direction that inflates ``solved_by_testing``."""
        _isolate(harness, tmp_path, monkeypatch)
        (tmp_path / "benchmark_floor.json").write_text(
            json.dumps(
                {
                    "recorded": True,
                    "keys": ["errorHandlingChallenge", "loginAdminChallenge"],
                    "sources": [{"engagement": "2e21a200-39c1-45bd-bfbd-34986cc0e19f"}],
                }
            ),
            encoding="utf-8",
        )
        floor_file = harness.read_floor()
        assert floor_file["floors"] == {}
        assert floor_file["unkeyed_legacy"]["keys"] == [
            "errorHandlingChallenge",
            "loginAdminChallenge",
        ]
        split = harness.subtract_floor(
            ["errorHandlingChallenge", "earned"], floor_file, credential_set="admin"
        )
        assert split["solved_by_testing"] is None
        assert "unkeyed" in split["note"]

    def test_recording_beside_a_legacy_floor_keeps_it(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It is not applied, but it is not destroyed either — it is the record of
        what the previous number was computed from."""
        _isolate(harness, tmp_path, monkeypatch)
        (tmp_path / "benchmark_floor.json").write_text(
            json.dumps({"recorded": True, "keys": ["old"], "sources": []}), encoding="utf-8"
        )
        harness.record_floor(
            engagement="fresh",
            solved_keys=["new"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        floor_file = harness.read_floor()
        assert floor_file["floors"]["admin"]["keys"] == ["new"]
        assert floor_file["unkeyed_legacy"]["keys"] == ["old"]


class TestTheFloorIsMeasuredNotDeclared:
    """A floor from a run that tested is a subtraction of the engine from itself."""

    def test_recording_from_a_clean_zero_dispatch_run_works(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        solved = ["errorHandlingChallenge", "loginAdminChallenge"]
        record = harness.record_floor(
            engagement="clean-zero-dispatch",
            solved_keys=solved,
            dispatches=0,
            challenge_index={k: {"name": k, "category": "x", "difficulty": 1} for k in solved},
            credential_set="admin",
            exhausted_stages=[],
        )
        assert record["keys"] == sorted(solved)
        assert record["credential_set"] == "admin"
        assert record["sources"][0]["engagement"] == "clean-zero-dispatch"
        assert {c["key"] for c in record["challenges"]} == set(solved)
        assert (tmp_path / "benchmark_floor.json").is_file()

    def test_recording_from_a_testing_run_is_refused(
        self,
        harness: Any,
        observation: dict[str, Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        rows = observation["testing_run"]["methodology_ledger_rows"]
        dispatches = harness.methodology_dispatches(_report_from(rows))
        with pytest.raises(ValueError, match="methodology task"):
            harness.record_floor(
                engagement=observation["testing_run"]["engagement"],
                solved_keys=["loginAdminChallenge"],
                dispatches=dispatches,
                challenge_index={},
                credential_set="admin",
                exhausted_stages=[],
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_recording_from_an_unmeasurable_run_is_refused(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``None`` is not zero, and the whole point is that it must not become one."""
        _isolate(harness, tmp_path, monkeypatch)
        with pytest.raises(ValueError, match="unmeasurable"):
            harness.record_floor(
                engagement="ledger-predates-methodology-components",
                solved_keys=["loginAdminChallenge"],
                dispatches=None,
                challenge_index={},
                credential_set="admin",
                exhausted_stages=[],
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_recording_from_a_provider_starved_run_is_refused(
        self,
        harness: Any,
        observation: dict[str, Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The bundle the floor on disk was actually taken from.

        It dispatched zero because nothing served recon, scan or exploit — not
        because it chose not to test. Its crawl is not a complete crawl, and an
        under-measured floor subtracts too little.
        """
        _isolate(harness, tmp_path, monkeypatch)
        run = observation["zero_dispatch_run"]
        stamp = run["model_stamp"]
        assert {e["provider"] for e in stamp} == {"exhausted"}
        from clinkz.llm.degradation import exhausted_stages

        starved = exhausted_stages(stamp)
        assert starved == ["exploit", "recon", "scan"]
        with pytest.raises(ValueError, match="not a complete crawl"):
            harness.record_floor(
                engagement=run["engagement"],
                solved_keys=run["scoreboard_after"]["solved"],
                dispatches=0,
                challenge_index={},
                credential_set="admin",
                exhausted_stages=starved,
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_a_bundle_with_no_model_stamp_is_refused(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An absent stamp is INDETERMINATE, and the guard used to read it as clean.

        ``exhausted_stages(report.get("model_stamp") or [])`` returns ``[]`` for
        a bundle with no stamp — byte-identical to a run every stage of which was
        served. The absence is not a corner case: a run that dies to a depleted
        balance is exactly the one that may never write a stamp, so the guard's
        own reading defeated the guard on the failure it exists to catch.
        """
        _isolate(harness, tmp_path, monkeypatch)
        with pytest.raises(ValueError, match="INDETERMINATE"):
            harness.record_floor(
                engagement="stampless-bundle",
                solved_keys=["a"],
                dispatches=0,
                challenge_index={},
                credential_set="admin",
                exhausted_stages=None,
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_stamp_exhaustion_separates_absent_empty_and_served(self, harness: Any) -> None:
        """Three inputs, three answers. The middle one is what the fix adds."""
        assert harness.stamp_exhaustion({}) is None, "no key at all"
        assert harness.stamp_exhaustion({"model_stamp": []}) is None, (
            "an empty stamp is written from no llm_call trace events, so it makes no "
            "claim about any stage either"
        )
        assert harness.stamp_exhaustion({"model_stamp": {"a": 1}}) is None, "not a list"
        assert (
            harness.stamp_exhaustion({"model_stamp": [{"stage": "recon", "provider": "anthropic"}]})
            == []
        ), "a stamp that names a serving provider IS a claim that nothing was starved"
        assert harness.stamp_exhaustion(
            {
                "model_stamp": [
                    {"stage": "recon", "provider": "exhausted"},
                    {"stage": "scan", "provider": "anthropic"},
                ]
            }
        ) == ["recon"]

    def test_recording_without_a_credential_set_is_refused(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        with pytest.raises(ValueError, match="who it authenticated as"):
            harness.record_floor(
                engagement="anonymous-bundle",
                solved_keys=["a"],
                dispatches=0,
                challenge_index={},
                credential_set=harness.UNKNOWN_CREDENTIAL_SET,
                exhausted_stages=[],
            )
        assert not (tmp_path / "benchmark_floor.json").exists()

    def test_a_second_zero_dispatch_run_widens_the_floor(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Union, one-way, within a credential set. A run that trips a challenge
        the first did not has widened what crawling alone reaches; a run that
        fails to reproduce one is evidence about that run's crawl, not about
        whether the challenge is reachable without testing."""
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="run-2",
            solved_keys=["a", "b"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        second = harness.record_floor(
            engagement="run-3",
            solved_keys=["b", "c"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        assert second["keys"] == ["a", "b", "c"]
        assert [s["engagement"] for s in second["sources"]] == ["run-2", "run-3"]

    def test_the_union_does_not_cross_credential_sets(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _isolate(harness, tmp_path, monkeypatch)
        harness.record_floor(
            engagement="admin-run",
            solved_keys=["a"],
            dispatches=0,
            challenge_index={},
            credential_set="admin",
            exhausted_stages=[],
        )
        widened = harness.record_floor(
            engagement="admin-jim-run",
            solved_keys=["b"],
            dispatches=0,
            challenge_index={},
            credential_set="admin+jim",
            exhausted_stages=[],
        )
        assert widened["keys"] == ["b"], "an admin floor is not part of an admin+jim floor"
        assert harness.floor_for(harness.read_floor(), "admin")["keys"] == ["a"]


class TestTheSplitIsReportedSeparately:
    """``solved_total`` stays; ``solved_by_testing`` is the claim about this engine."""

    @staticmethod
    def _file(credential_set: str, keys: list[str], sources: list[str]) -> dict[str, Any]:
        return {
            "version": 2,
            "floors": {
                credential_set: {
                    "recorded": True,
                    "credential_set": credential_set,
                    "keys": keys,
                    "sources": [{"engagement": e} for e in sources],
                }
            },
        }

    def test_the_floor_is_subtracted(self, harness: Any) -> None:
        keys = [
            "errorHandlingChallenge",
            "loginAdminChallenge",
            "securityPolicyChallenge",
            "weakPasswordChallenge",
        ]
        floor_file = self._file("admin", keys, ["2e21a200"])
        # Run 1's shape: the four floor challenges plus three the testing earned.
        # Its own scoreboard snapshot was overwritten by the later runs, so the
        # three are named generically - what is under test is the arithmetic and
        # which side of it each key lands on.
        solved = sorted(keys + ["earnedA", "earnedB", "earnedC"])
        split = harness.subtract_floor(solved, floor_file, credential_set="admin")
        assert split["solved_by_testing_count"] == 3
        assert sorted(split["solved_by_testing"]) == ["earnedA", "earnedB", "earnedC"]
        assert sorted(split["solved_from_floor"]) == sorted(keys)
        assert len(solved) == 7, "solved_total is unchanged - both numbers are true"

    def test_a_zero_dispatch_run_earns_nothing(
        self, harness: Any, observation: dict[str, Any]
    ) -> None:
        solved = observation["zero_dispatch_run"]["scoreboard_after"]["solved"]
        split = harness.subtract_floor(
            solved, self._file("admin", solved, ["x"]), credential_set="admin"
        )
        assert split["solved_by_testing"] == []

    def test_an_unmeasured_floor_reports_unknown_not_zero(self, harness: Any) -> None:
        """The distinction the whole section exists to preserve.

        "No floor has been measured" is not "the floor is empty"; defaulting to
        the second silently restores ``solved_by_testing == solved_total``, which
        is the inflated number.
        """
        split = harness.subtract_floor(
            ["a", "b"], {"version": 2, "floors": {}}, credential_set="admin"
        )
        assert split["solved_by_testing"] is None
        assert split["solved_by_testing_count"] is None
        assert "unmeasured" in split["note"]

    def test_reading_an_absent_floor_file_is_not_an_empty_floor(
        self, harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(harness, "FLOOR_PATH", tmp_path / "nothing-here.json")
        floor_file = harness.read_floor()
        assert floor_file["floors"] == {}
        assert (
            harness.subtract_floor(["a"], floor_file, credential_set="admin")["solved_by_testing"]
            is None
        )


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
            # Whether the run is a measurement at all, and of what.
            '"credential_set"',
            '"exhausted_stages"',
        ):
            assert key in source, f"reconciliation.json must carry {key}"

    def test_a_zero_dispatch_run_records_the_floor_it_observed(self, harness: Any) -> None:
        """The condition that defines a floor is the condition just observed, so
        recording it in a separate pass would let the two drift."""
        source = Path(harness.__file__).read_text(encoding="utf-8")
        start = source.index(
            "dispatches = methodology_dispatches(report)", source.index("def main")
        )
        end = source.index('out = RESULTS_DIR / "reconciliation.json"')
        between = source[start:end]
        assert "if dispatches == 0:" in between
        assert "record_floor(" in between, (
            "a run that dispatched nothing IS a floor observation, and it has to be "
            "recorded before the reconciliation that reads the floor is written"
        )
        assert "exhausted_stages=starved" in between, (
            "the refusal has to see the stamp: a provider-starved run dispatches zero "
            "and is otherwise indistinguishable from a floor observation"
        )
