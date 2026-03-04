"""Report generation agent — final phase.

Synthesises all findings into a professional penetration test report.
Uses the LLM to write the executive summary, methodology, and remediation advice.
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.agents.base import BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior penetration tester writing a professional pentest report.
Your audience is both technical staff and executive leadership.

You will receive:
- A list of validated findings with evidence
- A list of discovered hosts and services
- Engagement metadata (name, dates, scope)

Write:
1. Executive Summary — clear, non-technical, focused on business risk
2. Methodology — brief description of the testing approach and phases
3. For each finding: clear title, technical description, evidence, severity, remediation steps

Be precise, factual, and professional. Do not embellish or minimise findings.
"""


class ReportAgent(BaseAgent):
    """Report generation agent.

    TODO: Implement run() — call LLM to write narrative sections,
    assemble PentestReport, and hand off to ReportGenerator.
    """

    @property
    def name(self) -> str:
        return "report"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Generate the full report from validated findings.

        Args:
            input_data: {
                "findings": [...],
                "hosts": [...],
                "engagement_name": str,
                "test_start": str,
                "test_end": str,
            }

        Returns:
            {"report": PentestReport.model_dump()}
        """
        raise NotImplementedError("ReportAgent.run() not yet implemented")
