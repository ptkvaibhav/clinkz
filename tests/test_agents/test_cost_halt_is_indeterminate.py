"""A run the spend cap halted is INDETERMINATE, not a run with N findings.

The spend cap is the engagement's third bound, and it fires differently from the
other two. A depleted provider raises and a phase records ``error``; the wall
clock stops a phase with a ``timeout`` status. The spend cap does neither: the
governor winds the phases down COOPERATIVELY so each one reports ``complete``,
and the run reads as a finished engagement with whatever findings it reached
before the budget line. It is not finished — the classes past that line were
never dispatched, and the count is a floor.

This is the cost twin of the audit / degradation INDETERMINATE state, and it is
built here on origin/main where ``observability/audit.py`` does not yet exist;
its documented template is ``degradation.reconcile_with_model_stamp`` — a verdict
derived from the run's own STORED blocks so a re-render reaches it too, only ever
tightening.

The arms, not the outcome (the acceptance-criterion law): a test that read only
"the report says incomplete" could pass over a verdict reached for the wrong
reason. So each layer is asserted on what it actually saw — the cap FIRED when
driven past it, the governor RECORDED the halt as ``spend_cap``, and only then
the report declared INDETERMINATE — and a halt for a DIFFERENT reason is asserted
NOT to trip the cost verdict, so the verdict is keyed on the cause and not on the
mere fact of a halt.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.report import ReportAgent, _run_completion
from clinkz.llm.spend import (
    HALT_SPEND_CAP,
    SPEND_HALT_INDETERMINATE,
    SPEND_NO_CAP,
    SPEND_WITHIN_BUDGET,
    ModelPrice,
    SpendLedger,
    is_spend_halt,
    set_active_spend_ledger,
    spend_completion_verdict,
)
from clinkz.models.engagement import SafetyPolicy
from clinkz.models.report import PentestReport
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.governor import HALT_KILL_SWITCH, EngagementGovernor
from clinkz.state import StateStore
from tests.test_agents.test_report import MockReportLLM

SCOPE = EngagementScope(
    name="cost-halt",
    targets=[ScopeEntry(value="http://clinkz-target:3000", type=ScopeType.URL)],
)

PRICES = {"claude-sonnet-5": ModelPrice(3.0, 15.0)}

#: A model stamp with every stage served by the primary. Used so the ONLY
#: incompleteness cause in the report tests is the spend halt — an exhausted
#: stage would trip the banner for a different reason and confound the arm.
_CLEAN_STAMP = [
    {"stage": stage, "provider": "anthropic", "model": "claude-sonnet-5", "calls": 3}
    for stage in ("recon", "scan", "exploit", "report")
]


def _maxed_ledger() -> SpendLedger:
    """A ledger driven PAST a $1 cap — the first arm: the cap actually fires."""
    led = SpendLedger(usd_cap=1.0, prices=PRICES)
    assert led.exceeded() == "", "a fresh ledger is under budget"
    # $3/Mtok input × 1M = $3.00, over the $1 cap.
    led.record(
        model="claude-sonnet-5", input_tokens=1_000_000, output_tokens=0, usage_reported=True
    )
    assert "spend cap reached" in led.exceeded(), "the cap must fire when driven past it"
    return led


def _halt_safety() -> dict[str, Any]:
    """The safety block a real run carries after the spend cap halts it.

    Produced by the real governor, not hand-written, so the field names and the
    halt-reason spelling are the ones the engine actually records.
    """
    governor = EngagementGovernor("cost-halt", SafetyPolicy(), outputs_root=tempfile.mkdtemp())
    governor.halt(HALT_SPEND_CAP, "spend cap reached: $3.0000 of $1.00")
    return dict(governor.stats())


# ---------------------------------------------------------------------------
# The three states — none collapses into another
# ---------------------------------------------------------------------------


class TestSpendCompletionVerdict:
    def test_a_halt_on_the_spend_cap_is_indeterminate(self) -> None:
        safety = _halt_safety()
        assert is_spend_halt(safety) is True
        assert spend_completion_verdict({"usd_cap": 1.0}, safety) == SPEND_HALT_INDETERMINATE

    def test_a_cap_that_was_set_and_never_reached_is_within_budget(self) -> None:
        assert (
            spend_completion_verdict({"usd_cap": 5.0, "usd_spent": 0.5}, {}) == SPEND_WITHIN_BUDGET
        )
        assert spend_completion_verdict({"token_cap": 800_000}, {}) == SPEND_WITHIN_BUDGET

    def test_no_cap_installed_is_its_own_state(self) -> None:
        """Not the same claim as 'finished within budget': there was no line."""
        assert spend_completion_verdict({"usd_cap": None, "token_cap": None}, {}) == SPEND_NO_CAP
        assert spend_completion_verdict({}, {}) == SPEND_NO_CAP
        assert spend_completion_verdict(None, None) == SPEND_NO_CAP

    def test_a_halt_for_a_different_reason_is_not_the_cost_verdict(self) -> None:
        """Keyed on the CAUSE, not on the mere fact of a halt: the kill switch
        stops the run, but it is not the spend cap and must not read as one."""
        governor = EngagementGovernor("cost-halt", SafetyPolicy(), outputs_root=tempfile.mkdtemp())
        governor.halt(HALT_KILL_SWITCH, "operator aborted")
        safety = dict(governor.stats())
        assert safety["halted"] is True
        assert is_spend_halt(safety) is False
        # A cap was set, and it was NOT what stopped the run.
        assert spend_completion_verdict({"usd_cap": 1.0}, safety) == SPEND_WITHIN_BUDGET


# ---------------------------------------------------------------------------
# _run_completion sees the halt the phase outcomes hide
# ---------------------------------------------------------------------------


class TestRunCompletionSeesTheCostHalt:
    def test_cooperative_wind_down_still_reads_incomplete(self) -> None:
        """Every phase reports complete — the exact shape that hid the halt."""
        completed, reason = _run_completion(
            phase_outcomes={
                "recon": {"status": "complete"},
                "scan": {"status": "complete"},
                "exploit": {"status": "complete"},
            },
            model_stamp=_CLEAN_STAMP,
            safety=_halt_safety(),
        )
        assert completed is False
        assert "spend cap" in reason
        assert "not tested" in reason
        assert "floor" in reason

    def test_no_halt_and_clean_phases_completes(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={"recon": {"status": "complete"}},
            model_stamp=_CLEAN_STAMP,
            safety={"halted": False},
        )
        assert completed is True
        assert reason == ""

    def test_absent_safety_is_not_a_halt(self) -> None:
        completed, _ = _run_completion(
            phase_outcomes={"recon": {"status": "complete"}},
            model_stamp=_CLEAN_STAMP,
            safety=None,
        )
        assert completed is True


# ---------------------------------------------------------------------------
# The report declares it — the "observed refusing" arm, end to end
# ---------------------------------------------------------------------------


class TestTheReportDeclaresTheCostHalt:
    @staticmethod
    async def _render(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[dict[str, Any], str]:
        import clinkz.agents.report as report_module

        monkeypatch.setattr(report_module, "_active_model_stamp", lambda: list(_CLEAN_STAMP))
        monkeypatch.setattr(report_module, "configured_outputs_root", lambda: tmp_path)
        set_active_spend_ledger(_maxed_ledger())
        try:
            async with StateStore(tmp_path / "state.db") as state:
                engagement_id = await state.create_engagement("cost-halt", SCOPE.model_dump())
                agent = ReportAgent(
                    llm=MockReportLLM(),
                    tools=[],
                    scope=SCOPE,
                    state=state,
                    engagement_id=engagement_id,
                )
                result = await agent.run(
                    {
                        "engagement_name": "cost-halt",
                        # Cooperative wind-down: every phase reports complete.
                        "phase_outcomes": {
                            "recon": {"status": "complete"},
                            "scan": {"status": "complete"},
                            "exploit": {"status": "complete"},
                        },
                        "safety": _halt_safety(),
                    }
                )
        finally:
            set_active_spend_ledger(None)
        markdown = Path(result["markdown_path"]).read_text(encoding="utf-8")
        return result["report"], markdown

    @pytest.mark.asyncio
    async def test_the_executive_summary_says_the_run_did_not_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report, markdown = await self._render(tmp_path, monkeypatch)
        summary = report["executive_summary"]
        assert summary["run_completed"] is False
        assert "spend cap" in summary["incomplete_reason"]
        assert "DID NOT COMPLETE" in summary["overview"]
        assert "THIS RUN DID NOT COMPLETE" in markdown

    @pytest.mark.asyncio
    async def test_no_findings_and_a_halt_rates_not_assessed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """'Informational' is a verdict about the target; a halted run with no
        findings has nothing to have a verdict about."""
        report, _ = await self._render(tmp_path, monkeypatch)
        assert report["executive_summary"]["risk_rating"] == "Not assessed"

    @pytest.mark.asyncio
    async def test_the_spend_section_carries_the_indeterminate_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, markdown = await self._render(tmp_path, monkeypatch)
        assert "Cost-cap verdict: INDETERMINATE" in markdown
        assert "not a baseline" in markdown
        # The client-facing coverage section names the halt as absence-generating.
        assert "stopped early" in markdown
        assert "not tested" in markdown

    @pytest.mark.asyncio
    async def test_the_pdf_carries_the_same_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Three renderers, one source, so they cannot disagree about it."""
        pytest.importorskip("reportlab")
        from clinkz.engagement.artifact_scan import _pdf_text

        await self._render(tmp_path, monkeypatch)
        pdfs = list(tmp_path.rglob("report_*.pdf"))
        assert pdfs, "the engagement must write its PDF deliverable"
        text = _pdf_text(pdfs[0]).replace("\n", " ")
        assert "INDETERMINATE" in text
        assert "did not complete" in text.lower()


# ---------------------------------------------------------------------------
# A stored bundle is re-rendered with the same verdict
# ---------------------------------------------------------------------------


class TestAStoredBundleIsReRenderedHonestly:
    """report-pdf / --resume run over a STORED report; the verdict is derived
    from its own spend and safety blocks, so a re-render reaches it too."""

    def test_the_markdown_renderer_declares_the_stored_halt(self) -> None:
        stored = PentestReport(
            engagement_name="cost-halt",
            test_start=datetime(2026, 9, 19, tzinfo=UTC),
            test_end=datetime(2026, 9, 19, tzinfo=UTC),
            llm_spend={
                "usd_cap": 1.0,
                "token_cap": None,
                "calls": 42,
                "total_tokens": 500_000,
                "input_tokens": 200_000,
                "output_tokens": 300_000,
                "indeterminate_calls": 0,
                "usd_spent": 3.0,
                "usd_is_complete": True,
            },
            safety_summary={
                "halted": True,
                "halt_reason": HALT_SPEND_CAP,
                "halt_detail": "spend cap reached: $3.0000 of $1.00",
            },
        )
        markdown = ReportAgent._render_markdown(stored, stored.findings)
        assert "Cost-cap verdict: INDETERMINATE" in markdown
        assert "not a baseline" in markdown

    def test_a_stored_run_within_budget_is_not_flagged(self) -> None:
        """Precision: a completed run that HAD a cap must not read as halted."""
        stored = PentestReport(
            engagement_name="within-budget",
            test_start=datetime(2026, 9, 19, tzinfo=UTC),
            test_end=datetime(2026, 9, 19, tzinfo=UTC),
            llm_spend={
                "usd_cap": 100.0,
                "calls": 42,
                "total_tokens": 500_000,
                "input_tokens": 200_000,
                "output_tokens": 300_000,
                "indeterminate_calls": 0,
                "usd_spent": 3.0,
                "usd_is_complete": True,
            },
            safety_summary={"halted": False},
        )
        markdown = ReportAgent._render_markdown(stored, stored.findings)
        assert "INDETERMINATE" not in markdown
        assert "finished within its budget" in markdown
