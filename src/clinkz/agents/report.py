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
from clinkz.models.finding import (
    CrossServiceResearchLead,
    Finding,
    FindingStatus,
    Severity,
    UnprovenExploitLead,
)
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

        Pulls all findings from the state store and writes, under
        ``outputs/<engagement_id>/``:
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
        findings_raw = await self.state.get_findings(engagement_id, validated_only=False)
        targets_raw = await self.state.get_targets(engagement_id)
        # Research-leads live in their OWN table (design §5), read into separate
        # sections — never merged into findings, never counted in coverage. The
        # table holds two structurally different lead types, told apart by the
        # ``lead_kind`` discriminator.
        leads_raw = await self.state.get_research_leads(engagement_id)

        self._logger.info(
            "Loaded %d findings, %d targets, %d research-leads",
            len(findings_raw),
            len(targets_raw),
            len(leads_raw),
        )

        # Parse Finding models. A finding the engagement itself flagged as a
        # suspected false positive is NOT rendered as a finding: the Exploit
        # phase already demotes those to unproven leads (the G10 emission
        # inversion), and this is the second, independent layer at the report
        # chokepoint — so a row written by an older build, a replay, or any
        # future path that sets the status cannot reach ``findings[]`` and be
        # counted in the totals.
        finding_models: list[Finding] = []
        suppressed = 0
        for fd in findings_raw:
            try:
                finding = Finding.model_validate(fd)
            except Exception as exc:
                self._logger.warning("Could not parse finding '%s': %s", fd.get("id"), exc)
                continue
            if finding.status == FindingStatus.FALSE_POSITIVE:
                suppressed += 1
                self._logger.warning(
                    "Excluding finding '%s' (%s) from the report — status=false_positive; "
                    "a finding the engagement believes is a false positive is never emitted",
                    finding.id,
                    finding.title,
                )
                continue
            finding_models.append(finding)
        if suppressed:
            self._logger.info("Report: %d false-positive finding(s) excluded", suppressed)

        # Parse Host models
        host_models: list[Host] = []
        for td in targets_raw:
            try:
                host_models.append(Host.model_validate(td))
            except Exception as exc:
                self._logger.warning("Could not parse host '%s': %s", td.get("id"), exc)

        # Parse the lead models (design §5) — DIFFERENT types than Finding, so they
        # cannot be rendered in the confirmed-findings section. ``lead_kind``
        # discriminates the cross-service chains from the single-service unproven
        # candidates; a row written before the discriminator existed defaults to
        # ``cross_service``.
        lead_models: list[CrossServiceResearchLead] = []
        unproven_models: list[UnprovenExploitLead] = []
        for ld in leads_raw:
            kind = ld.get("lead_kind") or "cross_service"
            try:
                if kind == "unproven_exploit":
                    unproven_models.append(UnprovenExploitLead.model_validate(ld))
                else:
                    lead_models.append(CrossServiceResearchLead.model_validate(ld))
            except Exception as exc:
                self._logger.warning("Could not parse research-lead (kind=%s): %s", kind, exc)

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
            research_leads=lead_models,
            unproven_leads=unproven_models,
        )

        report_dict = report.model_dump(mode="json")

        # Reports live alongside the rest of the engagement artifacts under
        # ``outputs/<engagement_id>/`` (same convention as trace.jsonl and the
        # tool-invocation records). Writing to the cwd would litter the repo
        # root with per-engagement dumps.
        output_dir = Path("outputs") / engagement_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON output
        json_path = output_dir / f"report_{engagement_id}.json"
        json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        self._logger.info("JSON report written to %s", json_path)

        # Write Markdown output
        md_path = output_dir / f"report_{engagement_id}.md"
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
            f"**Risk Rating:** "
            f"{report.executive_summary.risk_rating if report.executive_summary else 'N/A'}",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
        ]

        if not findings:
            lines.append("No validated findings.")
            ReportAgent._render_research_leads(lines, report.research_leads)
            ReportAgent._render_unproven_leads(lines, report.unproven_leads)
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

        ReportAgent._render_research_leads(lines, report.research_leads)
        ReportAgent._render_unproven_leads(lines, report.unproven_leads)
        return "\n".join(lines)

    @staticmethod
    def _render_unproven_leads(lines: list[str], leads: list[UnprovenExploitLead]) -> None:
        """Render the 'Unproven exploitation leads (UNCONFIRMED)' section.

        Structurally separate from the confirmed-findings loop for the same
        reason as :meth:`_render_research_leads`: these are a different type,
        rendered under their own heading, explicitly marked UNCONFIRMED, and
        never counted in the finding totals. Each lead states what WAS observed
        and what was NOT — so a reader can see exactly where the evidence stops.
        """
        if not leads:
            return
        lines.extend(
            [
                "## Unproven exploitation leads (candidates — UNCONFIRMED)",
                "",
                "> These are **reachability observations whose defining security effect "
                "was never witnessed**. They are **NOT findings**, are **not counted** "
                "in the totals above, and no exploitation is claimed. Each states what "
                "was observed and what confirming observation is missing.",
                "",
            ]
        )
        for i, lead in enumerate(leads, 1):
            lines.extend(
                [
                    f"### U{i}. {lead.claim}",
                    "",
                    f"- **Why unconfirmed:** {lead.why_unconfirmed}",
                    f"- **Endpoint:** {lead.endpoint}"
                    + (f"  (parameter: {lead.parameter})" if lead.parameter else ""),
                    f"- **Technique:** {lead.technique}",
                    "",
                    "**Raw evidence:**",
                    "```",
                    f"observed: {lead.raw_observation}",
                    f"missing:  {lead.missing_observation}",
                    "```",
                    "",
                    "---",
                    "",
                ]
            )

    @staticmethod
    def _render_research_leads(lines: list[str], leads: list[CrossServiceResearchLead]) -> None:
        """Render the dedicated 'Cross-service research leads (UNCONFIRMED)' section.

        Kept **structurally separate** from the confirmed-findings loop above
        (design §5): research-leads are a different type, rendered under their own
        heading, explicitly marked UNCONFIRMED and never counted in the finding
        totals. Each lead carries the candidate chain, why it stayed unconfirmed,
        and the RAW null result (the probe that was sent and the null observation)
        so the operator sees exactly what was tried.
        """
        if not leads:
            return
        lines.extend(
            [
                "## Cross-service research leads (candidate chains — UNCONFIRMED)",
                "",
                "> These are **plausible-but-unproven** A→B cross-service chains. They "
                "are **NOT findings**, are **not counted** in the totals above, and were "
                "**not confirmed** by an oracle co-located with service B. Each is an "
                "operator worklist item — investigate with credentials / network access.",
                "",
            ]
        )
        for i, lead in enumerate(leads, 1):
            lines.extend(
                [
                    f"### L{i}. {lead.candidate_chain}",
                    "",
                    f"- **Why unconfirmed:** {lead.why_unconfirmed}",
                    f"- **A endpoint:** {lead.a_endpoint}  (channel: {lead.a_channel})",
                    f"- **B target:** {lead.b_target}",
                    f"- **Topology source:** {lead.topology_source} "
                    f"(grade: {lead.reachability_grade}, conf: {lead.reach_confidence})",
                    "",
                    "**Raw null result:**",
                    "```",
                    f"probe: {lead.raw_probe}",
                    f"observation: {lead.raw_null_observation}",
                    "```",
                    "",
                    "---",
                    "",
                ]
            )
