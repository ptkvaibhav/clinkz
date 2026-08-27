"""A report about a run that did not happen must say so.

Engagement ``2e21a200`` failed its recon, scan AND exploit phases with
``All providers exhausted`` and produced this executive summary:

    Penetration test of http://clinkz-juiceshop:3000. 0 findings identified.
    Risk rating: Informational.

That is the strongest claim a pentest report contains — *this target is clean* —
asserted on the strength of testing that did not run. Beside it, in the same
document, sat ``provider_degraded: false, baseline_eligible: true`` while the
run's own ``model_stamp`` recorded ``provider: "exhausted"`` for all three
stages. A document holding both halves of a contradiction and rendering only the
reassuring one is worse than one that just gets it wrong.

The fix has two witnesses because neither covers both instances.
``phase_outcomes`` is what the orchestrator observed and is authoritative live;
``model_stamp`` is written from the run's own trace and is the only one that
survives into a stored bundle. Every assertion here runs against
``tests/fixtures/run3_all_providers_exhausted.json``, which is the artifacts
those runs actually shipped rather than a hand-written approximation of them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.report import ReportAgent, _run_completion
from clinkz.models.report import PentestReport
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from tests.test_agents.test_report import MockReportLLM

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "run3_all_providers_exhausted.json"

SCOPE = EngagementScope(
    name="juiceshop-variance-envelope",
    targets=[ScopeEntry(value="http://clinkz-juiceshop:3000", type=ScopeType.URL)],
)


@pytest.fixture(scope="module")
def run3() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


class TestRunCompletionReadsBothWitnesses:
    """One rule, two inputs, because neither input is always available."""

    def test_a_clean_run_completes(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={"recon": {"status": "complete"}},
            model_stamp=[{"stage": "recon", "provider": "anthropic", "model": "x", "calls": 1}],
        )
        assert completed is True
        assert reason == ""

    def test_a_failed_phase_is_incomplete(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={"scan": {"status": "error", "error": "boom"}},
            model_stamp=[],
        )
        assert completed is False
        assert "scan" in reason

    def test_run_3s_model_stamp_alone_is_enough(self, run3: dict[str, Any]) -> None:
        """The offline case: the process that knew the phase statuses is gone."""
        completed, reason = _run_completion(phase_outcomes={}, model_stamp=run3["model_stamp"])
        assert completed is False
        for stage in ("recon", "scan", "exploit"):
            assert stage in reason
        assert "exhausted" in reason

    def test_run_1s_completed_run_is_not_flagged(self, run3: dict[str, Any]) -> None:
        """Precision matters as much as recall: a false alarm on every healthy run
        is what teaches an operator to stop reading the banner."""
        run1 = run3["run1_smaller_instance"]
        completed, reason = _run_completion(phase_outcomes={}, model_stamp=run1["model_stamp"])
        assert completed is True
        assert reason == ""


class TestTheSynthesizedRun3ReportDeclaresItself:
    """Rebuild run 3's report from run 3's own numbers and read the verdict."""

    @staticmethod
    async def _render(
        tmp_path: Path, run3: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> tuple[dict[str, Any], str]:
        """Run the real ReportAgent with run 3's model stamp installed."""
        import clinkz.agents.report as report_module

        monkeypatch.setattr(report_module, "_active_model_stamp", lambda: list(run3["model_stamp"]))
        monkeypatch.setattr(report_module, "configured_outputs_root", lambda: tmp_path)

        async with StateStore(tmp_path / "state.db") as state:
            engagement_id = await state.create_engagement(
                "juiceshop-variance-envelope", SCOPE.model_dump()
            )
            agent = ReportAgent(
                llm=MockReportLLM(),
                tools=[],
                scope=SCOPE,
                state=state,
                engagement_id=engagement_id,
            )
            result = await agent.run(
                {
                    "engagement_name": "juiceshop-variance-envelope",
                    "phase_outcomes": {
                        "recon": {"status": "error", "error": "All providers exhausted"},
                        "scan": {"status": "error", "error": "All providers exhausted"},
                        "exploit": {"status": "error", "error": "All providers exhausted"},
                    },
                }
            )
        markdown = Path(result["markdown_path"]).read_text(encoding="utf-8")
        return result["report"], markdown

    @pytest.mark.asyncio
    async def test_it_does_not_claim_baseline_eligibility(
        self, tmp_path: Path, run3: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report, markdown = await self._render(tmp_path, run3, monkeypatch)
        degradation = report["provider_degradation"]
        assert degradation["provider_degraded"] is True
        assert degradation["baseline_eligible"] is False
        assert degradation["exhausted_stages"] == ["exploit", "recon", "scan"]
        assert "eligible for use as a baseline" not in markdown
        assert "NOT eligible as a baseline" in markdown

    @pytest.mark.asyncio
    async def test_the_executive_summary_says_the_run_did_not_complete(
        self, tmp_path: Path, run3: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        report, markdown = await self._render(tmp_path, run3, monkeypatch)
        summary = report["executive_summary"]
        assert summary["run_completed"] is False
        assert summary["incomplete_reason"]
        assert "DID NOT COMPLETE" in summary["overview"]
        assert "THIS RUN DID NOT COMPLETE" in markdown

    @pytest.mark.asyncio
    async def test_the_risk_rating_is_not_informational(
        self, tmp_path: Path, run3: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ "Informational" is a verdict about the target.

        With no findings AND no completed run there is nothing to have a verdict
        about, and the shipped report gave one anyway.
        """
        report, _ = await self._render(tmp_path, run3, monkeypatch)
        shipped = run3["executive_summary_as_shipped"]
        assert shipped["risk_rating"] == "Informational", "the fixture must be the defect"
        assert report["executive_summary"]["risk_rating"] == "Not assessed"

    @pytest.mark.asyncio
    async def test_the_pdf_carries_the_same_verdict(
        self, tmp_path: Path, run3: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Three renderers, one source - so they cannot disagree about this."""
        pytest.importorskip("reportlab")
        from clinkz.engagement.artifact_scan import _pdf_text

        report, _ = await self._render(tmp_path, run3, monkeypatch)
        pdfs = list(tmp_path.rglob("report_*.pdf"))
        assert pdfs, "the engagement must write its PDF deliverable"
        text = _pdf_text(pdfs[0]).replace("\n", " ")
        assert "did not complete" in text
        assert "NOT eligible as a baseline" in text


class TestAStoredBundleIsReRenderedHonestly:
    """The rule runs at RENDER time too, not only at build time.

    A bundle written before the reconciliation existed still carries the
    register's half of the disagreement. Re-rendering it - `clinkz report-pdf`,
    `--resume` - must not reproduce the claim its own model stamp contradicts.
    """

    def test_the_markdown_renderer_refuses_the_shipped_clean_claim(
        self, run3: dict[str, Any]
    ) -> None:
        from datetime import UTC, datetime

        stored = PentestReport(
            engagement_name="juiceshop-variance-envelope",
            test_start=datetime(2026, 8, 25, tzinfo=UTC),
            test_end=datetime(2026, 8, 25, tzinfo=UTC),
            model_stamp=run3["model_stamp"],
            provider_degradation=run3["provider_degradation_as_shipped"],
        )
        markdown = ReportAgent._render_markdown(stored, stored.findings)
        assert "eligible for use as a baseline" not in markdown
        assert "NOT eligible as a baseline" in markdown
        assert "`recon`" in markdown, "the starved stages are named, not just counted"
