"""Multi-pass report generator.

Fetches validated findings from the state store, uses the LLM to write
narrative sections, then assembles a PentestReport model.

Two-pass approach:
    Pass 1: Generate executive summary and methodology
    Pass 2: Write detailed description and remediation for each finding
"""

from __future__ import annotations

import logging
from datetime import datetime

from clinkz.llm.base import LLMClient
from clinkz.models.finding import Finding
from clinkz.models.report import ExecutiveSummary, PentestReport
from clinkz.models.scope import EngagementScope
from clinkz.models.target import Host
from clinkz.state import StateStore

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates a PentestReport from engagement state.

    Args:
        llm: LLM client for writing narrative sections.
    """

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    async def generate(
        self,
        engagement_id: str,
        state: StateStore,
        scope: EngagementScope,
        test_start: datetime,
        test_end: datetime,
    ) -> PentestReport:
        """Build a complete PentestReport for a finished engagement.

        Args:
            engagement_id: Engagement UUID.
            state: State store to read targets and findings from.
            scope: Engagement scope.
            test_start: When testing began.
            test_end: When testing ended.

        Returns:
            Fully populated PentestReport ready for rendering.

        TODO:
            - Load hosts from state.get_targets()
            - Load findings from state.get_findings(validated_only=True)
            - Call _write_executive_summary()
            - Call _enrich_finding() for each finding (LLM-written description)
            - Assemble PentestReport
        """
        raise NotImplementedError("ReportGenerator.generate() not yet implemented")

    async def _write_executive_summary(
        self,
        scope: EngagementScope,
        findings: list[Finding],
        hosts: list[Host],
    ) -> ExecutiveSummary:
        """Use LLM to write the executive summary section.

        Args:
            scope: Engagement scope.
            findings: Validated findings.
            hosts: Discovered hosts.

        Returns:
            ExecutiveSummary with LLM-generated overview text.
        """
        prompt = (
            f"Write a concise executive summary (3-4 sentences) for a penetration test of "
            f"'{scope.name}'. "
            f"Findings: {len(findings)} total — "
            f"{sum(1 for f in findings if f.severity.value == 'critical')} critical, "
            f"{sum(1 for f in findings if f.severity.value == 'high')} high. "
            f"Hosts discovered: {len(hosts)}. Focus on business risk, not technical details."
        )
        overview = await self.llm.generate_text(prompt)
        return ExecutiveSummary.from_findings(overview=overview, findings=findings)

    async def _enrich_finding(self, finding: Finding) -> Finding:
        """Use LLM to improve finding description and remediation advice.

        Args:
            finding: Raw finding from the Exploit Agent.

        Returns:
            Finding with improved description and remediation.
        """
        # TODO: call llm.generate_text() to improve description and remediation
        return finding
