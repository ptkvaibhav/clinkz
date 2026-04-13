"""Report agent — generates simple pentest reports from engagement data.

Zero LLM calls.  Pulls all findings from the state store and outputs:
  - JSON file with structured finding data
  - Markdown file with human-readable summary

Each finding includes: title, severity, CVSS, endpoint, PoC
(request + response), and a one-line remediation.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase
from clinkz.llm.base import LLMClient
from clinkz.models.finding import Finding, Severity
from clinkz.models.report import ExecutiveSummary, PentestReport
from clinkz.models.scope import EngagementScope
from clinkz.models.target import Host
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "report_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


class ReportAgent(BaseAgent):
    """Simple report agent — zero LLM calls.

    Pulls findings from the state store, formats them into a JSON file
    and a Markdown file.  No executive summary, no attack narrative,
    no multi-pass LLM.  Completes in < 30 seconds.

    Args:
        llm: LLM client (accepted for interface compat but NOT used).
        tools: Unused.
        scope: Engagement scope for display in the report.
        state: SQLite state store to read findings/targets from.
        engagement_id: UUID of the active engagement.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        # Accept and discard outbox/extra kwargs for backward compat
        kwargs.pop("outbox", None)
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            knowledge_base=knowledge_base,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "report"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Entry point — zero LLM calls
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Generate a simple report from engagement state data.

        Pulls all findings from the state store and writes:
        - ``report_<engagement_id>.json`` — structured finding data
        - ``report_<engagement_id>.md`` — human-readable markdown

        No LLM calls.  No executive summary.  No attack narrative.

        Args:
            input_data: Accepts optional ``engagement_id``, ``engagement_name``.

        Returns:
            Dict with ``report`` (PentestReport dict), ``json_path``,
            ``markdown_path``, and ``status``.
        """
        engagement_id = input_data.get("engagement_id", self.engagement_id)
        engagement_name = input_data.get("engagement_name", "Penetration Test")
        scope_values = [str(e.value) for e in self.scope.targets]

        now = datetime.now(UTC)
        test_start_raw = input_data.get("test_start")
        test_end_raw = input_data.get("test_end")
        test_start = datetime.fromisoformat(test_start_raw) if test_start_raw else now
        test_end = datetime.fromisoformat(test_end_raw) if test_end_raw else now

        self._logger.info(
            "ReportAgent starting (simple mode) for '%s' (%s)",
            engagement_name,
            engagement_id,
        )

        # Pull engagement data from state store
        findings_raw = await self.state.get_findings(engagement_id, validated_only=True)
        targets_raw = await self.state.get_targets(engagement_id)

        self._logger.info(
            "Loaded %d validated findings, %d targets",
            len(findings_raw),
            len(targets_raw),
        )

        # Parse Finding models
        finding_models: list[Finding] = []
        for fd in findings_raw:
            try:
                finding_models.append(Finding.model_validate(fd))
            except Exception as exc:
                self._logger.warning("Could not parse finding '%s': %s", fd.get("id"), exc)

        # Parse Host models
        host_models: list[Host] = []
        for td in targets_raw:
            try:
                host_models.append(Host.model_validate(td))
            except Exception as exc:
                self._logger.warning("Could not parse host '%s': %s", td.get("id"), exc)

        # Build severity counts for executive summary (no LLM)
        severity_counts = {s: 0 for s in Severity}
        for f in finding_models:
            severity_counts[f.severity] += 1

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        risk_rating = "Informational"
        for s in severity_order:
            if severity_counts[s] > 0:
                risk_rating = s.value.capitalize()
                break

        exec_summary = ExecutiveSummary(
            overview=(
                f"Penetration test of {', '.join(scope_values)}. "
                f"{len(finding_models)} findings identified."
            ),
            risk_rating=risk_rating,
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
        )

        report = PentestReport(
            engagement_name=engagement_name,
            target_scope=scope_values,
            test_start=test_start,
            test_end=test_end,
            executive_summary=exec_summary,
            hosts=host_models,
            findings=finding_models,
        )

        report_dict = report.model_dump(mode="json")

        # Write JSON output
        json_path = Path(f"report_{engagement_id}.json")
        json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        self._logger.info("JSON report written to %s", json_path)

        # Write Markdown output
        md_path = Path(f"report_{engagement_id}.md")
        md_path.write_text(
            self._render_markdown(report, finding_models),
            encoding="utf-8",
        )
        self._logger.info("Markdown report written to %s", md_path)

        self._logger.info(
            "Report complete: %d findings, risk_rating=%s",
            len(report.findings),
            risk_rating,
        )

        return {
            "report": report_dict,
            "json_path": str(json_path),
            "markdown_path": str(md_path),
            "status": "complete",
        }

    # ------------------------------------------------------------------
    # Markdown renderer — no LLM
    # ------------------------------------------------------------------

    @staticmethod
    def _render_markdown(report: PentestReport, findings: list[Finding]) -> str:
        """Render a simple Markdown report.

        Args:
            report: The assembled PentestReport.
            findings: Parsed Finding models.

        Returns:
            Markdown string.
        """
        lines: list[str] = [
            f"# {report.engagement_name}",
            "",
            f"**Scope:** {', '.join(report.target_scope)}",
            f"**Date:** {report.test_start:%Y-%m-%d} - {report.test_end:%Y-%m-%d}",
            f"**Risk Rating:** {report.executive_summary.risk_rating if report.executive_summary else 'N/A'}",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
        ]

        if not findings:
            lines.append("No validated findings.")
            return "\n".join(lines)

        for i, f in enumerate(findings, 1):
            cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            lines.extend(
                [
                    f"## {i}. {f.title}",
                    "",
                    f"- **Severity:** {f.severity.value.upper()}",
                    f"- **CVSS:** {cvss_str}",
                    f"- **Endpoint:** {f.target}",
                    "",
                ]
            )

            # PoC evidence (request + response)
            if f.evidence:
                lines.append("**PoC:**")
                lines.append("```")
                for ev in f.evidence:
                    lines.append(ev)
                lines.append("```")
                lines.append("")

            # One-line remediation
            lines.append(f"**Remediation:** {f.remediation or 'N/A'}")
            lines.extend(["", "---", ""])

        return "\n".join(lines)
