"""The deliverable states the bounds it ran under, in both directions.

Two defects from engagement ``d67835f5``, opposite in sign and identical in
shape — the report describing the run as something other than what it was:

* **A bound that was never enforced.** The CLI assembled a ``SpendLedger`` from
  ``--token-cap`` / ``--spend-cap-usd``, validated it, printed the bounds line
  from it before dispatch, and then constructed the orchestrator without it.
  ``run()`` fell back to ``SpendLedger()`` with ``token_cap=0``, so the caps
  applied to no call in any engagement ever run. ``report.json`` recorded
  ``token_cap: null`` — accurate about the ledger that ran, and the only honest
  party in the exchange. The bounds line was the lie.

* **A capability that was exercised, filed as absent.** Three classes appeared
  under ``no_client_side_oracle`` while P7 executed 40 times, every run returning
  ``executed=False`` with its never-injected control silent — the oracle loading
  each page in a real browser and correctly refusing seven DOM-XSS candidates.
  "We have no way to look" and "we looked and nothing ran" are different
  sentences to a client, and the second one is the product working.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.llm.spend import SpendLedger
from clinkz.models.engagement import AuthorizationRecord
from clinkz.models.report import NotTestedCategory
from clinkz.orchestrator.orchestrator import OrchestratorAgent


class TestTheTokenCapReachesTheEngine:
    """A cap the engine never receives is not a cap, whatever the report says."""

    def test_the_orchestrator_accepts_a_spend_ledger(self) -> None:
        params = inspect.signature(OrchestratorAgent.__init__).parameters
        assert "spend_ledger" in params, (
            "the CLI validates a SpendLedger and prints the bounds from it; without a "
            "way to hand it over, run() builds its own with token_cap=0"
        )

    def test_the_supplied_ledger_survives_the_run_fallback(self) -> None:
        """``run()`` reads ``self._spend_ledger or SpendLedger()``.

        That expression is correct — a direct invocation with no operator budget
        still needs accounting — and it was silently doing all the work, because
        the left operand was always ``None``.
        """
        ledger = SpendLedger(token_cap=400_000, usd_cap=12.5)
        agent = OrchestratorAgent.__new__(OrchestratorAgent)
        agent._spend_ledger = ledger  # type: ignore[attr-defined]
        assert (agent._spend_ledger or SpendLedger()) is ledger  # type: ignore[attr-defined]

        agent._spend_ledger = None  # type: ignore[attr-defined]
        assert (agent._spend_ledger or SpendLedger()).token_cap == 0  # type: ignore[attr-defined]

    def test_the_cli_hands_its_ledger_to_the_orchestrator(self) -> None:
        """Read from the source, because the defect was a call site, not a value.

        Every unit here passed while the cap was enforced on nothing: the ledger
        was correct, the orchestrator was correct, and the one line joining them
        did not exist.
        """
        from pathlib import Path

        source = Path(inspect.getfile(OrchestratorAgent)).parent.parent / "cli.py"
        text = source.read_text(encoding="utf-8")
        assert "spend_ledger=spend_ledger" in text, (
            "cli.py builds a SpendLedger, prints the bounds line from it, and must "
            "pass it to OrchestratorAgent — otherwise --token-cap binds nothing"
        )

    def test_a_zero_cap_still_reports_as_no_cap(self) -> None:
        """``0`` means unbounded, and the summary must not render it as a number."""
        assert SpendLedger(token_cap=0).summary()["token_cap"] is None
        assert SpendLedger(token_cap=400_000).summary()["token_cap"] == 400_000


class TestTheOracleThatRanIsNotAnOracleThatIsMissing:
    """``why_unconfirmed`` must not conflate absence with a negative answer."""

    @staticmethod
    def _not_tested(client_oracle: dict[str, Any]) -> list[Any]:
        agent = ReportAgent.__new__(ReportAgent)
        return ReportAgent._build_not_tested(
            agent,
            engagement_id="00000000-0000-0000-0000-000000000000",
            authorization=None,
            scope_out=[],
            safety={},
            authentication={"authenticated": True, "multi_role": True},
            finding_count=0,
            client_oracle=client_oracle,
        )

    def test_no_oracle_reports_the_absent_capability(self) -> None:
        items = self._not_tested({"resolved": False, "runs": 0, "executions_witnessed": 0})
        categories = {i.category for i in items}
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE in categories
        assert NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING not in categories

    def test_an_oracle_that_ran_reports_the_negative_answer(self) -> None:
        """The portfolio run's numbers: 40 runs, 0 executions witnessed."""
        items = self._not_tested({"resolved": True, "runs": 40, "executions_witnessed": 0})
        categories = {i.category for i in items}
        assert NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING in categories
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE not in categories
        answered = [i for i in items if i.category is NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING]
        assert answered, "the browser classes must still be listed — coverage is still bounded"
        for item in answered:
            assert "40 time(s)" in item.reason
            assert "not because the engine was unable to look" in item.reason

    def test_a_resolved_oracle_that_never_ran_is_still_absent_coverage(self) -> None:
        """Resolving a browser and never reaching it proves nothing about a page."""
        items = self._not_tested({"resolved": True, "runs": 0, "executions_witnessed": 0})
        categories = {i.category for i in items}
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE in categories

    def test_runs_that_reported_nothing_are_not_an_oracle_that_looked(self) -> None:
        """Budget spent is not the same as the browser having answered.

        A runner reply with no verdict used to validate into a default verdict —
        ``executed=False``, control silent — and counted here as a clean
        non-execution. The section then told a client the page was examined in a
        real browser when nothing was observed in either direction, which is the
        very distinction this class holds apart.
        """
        items = self._not_tested(
            {"resolved": True, "runs": 40, "reported": 0, "executions_witnessed": 0}
        )
        categories = {i.category for i in items}
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE in categories
        assert NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING not in categories

    def test_the_claim_names_both_numbers(self) -> None:
        items = self._not_tested(
            {"resolved": True, "runs": 40, "reported": 37, "executions_witnessed": 0}
        )
        answered = [i for i in items if i.category is NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING]
        assert answered
        for item in answered:
            assert "40 time(s)" in item.reason
            assert "37 of them" in item.reason

    def test_a_bundle_predating_the_distinction_renders_as_before(self) -> None:
        """The ABSENCE of ``reported`` separates an old bundle from a new one.

        Same rule as the testing window: an older bundle cannot answer, and
        defaulting it to zero would flip every one of them to "no oracle
        exists" — the misreport this section was built to remove.
        """
        items = self._not_tested({"resolved": True, "runs": 40, "executions_witnessed": 0})
        categories = {i.category for i in items}
        assert NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING in categories
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE not in categories

    def test_missing_information_reads_as_no_oracle(self) -> None:
        """A run that cannot say what it did did not demonstrate that it did anything.

        The conservative direction: an empty dict understates coverage rather
        than claiming a browser ran.
        """
        items = self._not_tested({})
        categories = {i.category for i in items}
        assert NotTestedCategory.NO_CLIENT_SIDE_ORACLE in categories

    @pytest.mark.parametrize(
        "category",
        [NotTestedCategory.NO_CLIENT_SIDE_ORACLE, NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING],
    )
    def test_both_categories_render_under_their_own_heading(
        self, category: NotTestedCategory
    ) -> None:
        """An unrendered category falls through to "Other limitations", which is
        the section's failsafe and not a place a first-class answer belongs."""
        source = inspect.getsource(ReportAgent._render_not_tested)
        assert category.name in source


class TestTheAuthorizationRecordIsUnaffected:
    """Neither change may loosen the gate; a smoke check that it still refuses."""

    def test_a_partial_record_is_still_refused(self) -> None:
        with pytest.raises(Exception):
            AuthorizationRecord(authorizing_party="Someone")
