"""Report agent — generates professional pentest reports from engagement data.

Multi-pass LLM generation:
  Pass 1: executive summary via llm.generate_text()
  Pass 2: enhanced finding descriptions + remediation per finding
  Pass 3: attack narrative

The agent processes its inbox between passes so that mid-run QUERY messages
from the Orchestrator are incorporated.  It can also send QUERY messages to
the Orchestrator via its outbox when it needs clarification on a finding
before finalising the report.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clinkz.agents.base import BaseAgent
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.llm.base import LLMClient
from clinkz.models.finding import Finding
from clinkz.models.report import ExecutiveSummary, PentestReport
from clinkz.models.scope import EngagementScope
from clinkz.models.target import Host
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "report_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")

_QUERY_TIMEOUT_SECONDS = 30.0


class ReportAgent(BaseAgent):
    """Report generation agent with multi-pass LLM synthesis.

    Does NOT run a ReAct tool loop. Executes three sequential
    ``generate_text()`` passes against engagement state data to assemble
    a :class:`~clinkz.models.report.PentestReport`, optionally sending
    QUERY messages to the Orchestrator for finding clarification.

    Args:
        llm: LLM client (``generate_text()`` must be implemented).
        tools: Unused — report generation is LLM-only.
        scope: Engagement scope for display in the report.
        state: SQLite state store to read findings/targets/actions from.
        engagement_id: UUID of the active engagement.
        outbox: Optional queue for outgoing QUERY messages.  When not
                provided a private queue is created; the caller is
                responsible for draining it if queries need routing.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        outbox: asyncio.Queue[AgentMessage] | None = None,
    ) -> None:
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        self._outbox: asyncio.Queue[AgentMessage] = (
            outbox if outbox is not None else asyncio.Queue()
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
    # Orchestrator query mechanism
    # ------------------------------------------------------------------

    async def _query_orchestrator(
        self,
        question: str,
        finding_id: str | None = None,
    ) -> str:
        """Send a QUERY to the Orchestrator and wait for a RESPONSE.

        Enqueues a query in the outbox (for the lifecycle manager to
        route onto the MessageBus) then blocks on the inbox until a
        RESPONSE arrives or the timeout elapses.

        Args:
            question: The clarification question text.
            finding_id: Optional UUID of the finding the question relates to.

        Returns:
            The Orchestrator's answer string, or a timeout notice.
        """
        query_msg = AgentMessage.query(
            from_agent=self.name,
            to_agent="orchestrator",
            engagement_id=self.engagement_id,
            content={"query": question, "finding_id": finding_id or ""},
        )
        await self._outbox.put(query_msg)
        self._logger.info("Sent query to orchestrator: %s", question)

        try:
            response = await asyncio.wait_for(
                self._inbox.get(), timeout=_QUERY_TIMEOUT_SECONDS
            )
            if response.message_type == MessageType.RESPONSE:
                return str(response.content.get("answer", response.content))
            return str(response.content)
        except asyncio.TimeoutError:
            self._logger.warning("Orchestrator query timed out: %s", question)
            return f"[No response received for: {question}]"

    # ------------------------------------------------------------------
    # Pass 1 — executive summary
    # ------------------------------------------------------------------

    async def _generate_executive_summary(
        self,
        findings: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        scope_values: list[str],
        engagement_name: str,
    ) -> str:
        """Generate an executive summary paragraph via llm.generate_text().

        Args:
            findings: Validated finding dicts from state store.
            targets: Host dicts from state store.
            scope_values: Scope target strings (e.g., ``["example.com"]``).
            engagement_name: Human-readable engagement name.

        Returns:
            Executive summary paragraph (3–5 sentences).
        """
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        findings_list = "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')} "
            f"on {f.get('target', 'unknown')}"
            for f in findings[:20]
        ) or "No validated findings."

        prompt = (
            "You are writing the executive summary for a penetration test report.\n\n"
            f"Engagement: {engagement_name}\n"
            f"Scope: {', '.join(scope_values)}\n"
            f"Hosts discovered: {len(targets)}\n"
            f"Finding severity breakdown: {json.dumps(severity_counts)}\n\n"
            f"Validated findings:\n{findings_list}\n\n"
            "Write a concise executive summary (3–5 sentences) suitable for a "
            "non-technical audience. Describe the overall risk posture and the most "
            "critical issues found. Do not include specific remediation steps here."
        )
        return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Pass 2 — finding enhancement
    # ------------------------------------------------------------------

    async def _enhance_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enhance a single finding's description and remediation text.

        Makes two ``generate_text()`` calls: one for the technical
        description and one for the remediation recommendation.

        Args:
            finding: Finding dict from state store.

        Returns:
            Copy of the finding dict with updated ``description`` and
            ``remediation`` values.
        """
        title = finding.get("title", "Untitled")
        severity = finding.get("severity", "info").upper()
        target = finding.get("target", "unknown")
        evidence_json = json.dumps((finding.get("evidence") or [])[:5])

        desc_prompt = (
            "You are writing the technical description for a pentest finding.\n\n"
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"Target: {target}\n"
            f"Evidence: {evidence_json}\n"
            f"Current description: {finding.get('description', '')}\n\n"
            "Expand this into a clear, technical description (under 200 words) that "
            "explains: (1) what the vulnerability is, (2) how it was discovered, and "
            "(3) the technical impact if exploited. Reference the evidence provided."
        )
        enhanced_desc = await self.llm.generate_text(desc_prompt)

        rem_prompt = (
            "You are writing the remediation recommendation for a pentest finding.\n\n"
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"Current recommendation: {finding.get('remediation', '')}\n\n"
            "Write a concise, actionable remediation recommendation (2–4 sentences). "
            "Be specific: name the exact patch, configuration change, or code fix "
            "required. Reference industry standards (OWASP, CIS, NIST) where applicable."
        )
        enhanced_rem = await self.llm.generate_text(rem_prompt)

        return {**finding, "description": enhanced_desc, "remediation": enhanced_rem}

    # ------------------------------------------------------------------
    # Pass 3 — attack narrative
    # ------------------------------------------------------------------

    async def _generate_narrative(
        self,
        findings: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        actions: list[dict[str, Any]],
    ) -> str:
        """Generate the attack narrative section via llm.generate_text().

        Args:
            findings: Enhanced finding dicts.
            targets: Host dicts from state store.
            actions: Action log dicts from state store.

        Returns:
            Attack narrative text (4–8 sentences, past tense).
        """
        phases = sorted(set(a.get("phase", "unknown") for a in actions))
        tools_used = sorted(set(a.get("tool", "") for a in actions if a.get("tool")))

        findings_list = "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')} "
            f"({f.get('target', 'unknown')})"
            for f in findings
        ) or "No confirmed findings."

        prompt = (
            "You are writing the attack narrative for a penetration test report.\n\n"
            f"Testing phases: {', '.join(phases) or 'unknown'}\n"
            f"Tools used: {', '.join(tools_used) or 'none recorded'}\n"
            f"Hosts discovered: {len(targets)}\n"
            f"Confirmed findings:\n{findings_list}\n\n"
            "Write a 4–8 sentence narrative (in past tense) describing how the testing "
            "progressed: from initial reconnaissance through scanning, exploitation "
            "attempts, and confirmed findings. Highlight any significant attack chains "
            "or notable discoveries. Keep under 300 words."
        )
        return await self.llm.generate_text(prompt)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Generate a PentestReport from engagement state data.

        Pulls all validated findings, targets, and actions from the state
        store, runs three sequential LLM generation passes, then assembles
        a :class:`~clinkz.models.report.PentestReport`.

        The inbox is drained between each pass so that mid-run QUERY
        messages from the Orchestrator are logged.  Use
        :meth:`_query_orchestrator` to proactively request clarification
        on specific findings before finalising the report.

        Args:
            input_data: Accepts the following optional keys:

                - ``engagement_id``: Override engagement UUID (defaults to
                  ``self.engagement_id``).
                - ``engagement_name``: Human-readable name for the report
                  header (default: ``"Penetration Test"``).
                - ``test_start``: ISO 8601 datetime string for testing
                  start timestamp.
                - ``test_end``: ISO 8601 datetime string for testing end
                  timestamp.

        Returns:
            Dict with keys:

            - ``report``: Fully serialised :class:`PentestReport` dict.
            - ``status``: Always ``"complete"`` on success.
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
            "ReportAgent starting for engagement '%s' (%s)",
            engagement_name,
            engagement_id,
        )

        # Pull engagement data from state store
        findings_raw = await self.state.get_findings(engagement_id, validated_only=True)
        targets_raw = await self.state.get_targets(engagement_id)
        actions = await self.state.get_actions(engagement_id)

        self._logger.info(
            "Loaded %d validated findings, %d targets, %d actions",
            len(findings_raw),
            len(targets_raw),
            len(actions),
        )

        # Pass 1: Executive summary
        await self._process_inbox()
        exec_overview = await self._generate_executive_summary(
            findings_raw, targets_raw, scope_values, engagement_name
        )
        self._logger.info("Pass 1 (executive summary) complete")

        # Pass 2: Enhance each finding's description + remediation
        await self._process_inbox()
        enhanced_findings: list[dict[str, Any]] = []
        for finding in findings_raw:
            enhanced = await self._enhance_finding(finding)
            enhanced_findings.append(enhanced)
        self._logger.info(
            "Pass 2 (finding enhancement) complete — %d findings",
            len(enhanced_findings),
        )

        # Pass 3: Attack narrative
        await self._process_inbox()
        narrative = await self._generate_narrative(
            enhanced_findings, targets_raw, actions
        )
        self._logger.info("Pass 3 (attack narrative) complete")

        # Parse Finding models from enhanced dicts
        finding_models: list[Finding] = []
        for fd in enhanced_findings:
            try:
                finding_models.append(Finding.model_validate(fd))
            except Exception as exc:
                self._logger.warning(
                    "Could not parse finding '%s': %s", fd.get("id"), exc
                )

        # Parse Host models from target dicts
        host_models: list[Host] = []
        for td in targets_raw:
            try:
                host_models.append(Host.model_validate(td))
            except Exception as exc:
                self._logger.warning(
                    "Could not parse host '%s': %s", td.get("id"), exc
                )

        # Assemble ExecutiveSummary with severity counts derived from models
        exec_summary = ExecutiveSummary.from_findings(exec_overview, finding_models)

        # Assemble final PentestReport
        report = PentestReport(
            engagement_name=engagement_name,
            target_scope=scope_values,
            test_start=test_start,
            test_end=test_end,
            executive_summary=exec_summary,
            hosts=host_models,
            findings=finding_models,
            methodology=narrative,
        )

        self._logger.info(
            "Report assembled: %d findings, risk_rating=%s",
            len(report.findings),
            report.executive_summary.risk_rating if report.executive_summary else "N/A",
        )

        return {
            "report": report.model_dump(mode="json"),
            "status": "complete",
        }
