"""Critic agent — validates findings before they enter the report.

Reviews each finding for:
- Evidence completeness (at least one evidence string required for non-info)
- CVSS score presence (required for Critical, High, and Medium findings)
- Non-empty description and remediation
- LLM-assisted quality review (VALID / INVALID verdict)

Confirmed findings are marked validated in the state store.
Rejected findings are returned in the result for the Orchestrator to route
back to the Exploit Agent for re-testing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from clinkz.agents.base import BaseAgent
from clinkz.models.finding import FindingStatus, Severity

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "critic_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")

# Severities that require a CVSS score
_CVSS_REQUIRED = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


class CriticAgent(BaseAgent):
    """Finding validation agent — LLM-driven quality assurance.

    Does NOT use the ReAct tool loop.  Iterates through each submitted
    finding, applies structural checks, then calls ``llm.generate_text()``
    for an LLM-assisted quality review.  Confirmed findings are marked
    validated in the state store; rejected findings are returned to the
    Orchestrator with the rejection reason.

    Args:
        llm: LLM client (``generate_text()`` must be implemented).
        tools: Unused — critic is LLM-only.
        scope: Engagement scope.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
    """

    @property
    def name(self) -> str:
        return "critic"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Validation logic
    # ------------------------------------------------------------------

    async def _validate_finding(
        self, finding: dict[str, Any]
    ) -> tuple[bool, str]:
        """Validate a single finding with structural checks + LLM review.

        Structural checks run first (fast, deterministic).  If they all
        pass, an LLM review is requested for quality assurance.

        Args:
            finding: Finding dict from state store or Orchestrator payload.

        Returns:
            Tuple of ``(is_valid: bool, reason: str)``.
        """
        title = finding.get("title", "Untitled")
        severity_raw = finding.get("severity", "info").lower()
        evidence: list[str] = finding.get("evidence") or []
        cvss_score = finding.get("cvss_score")
        description: str = finding.get("description", "")
        remediation: str = finding.get("remediation", "")

        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.INFO

        # Structural check 1: non-info findings must have evidence
        if severity != Severity.INFO and not evidence:
            return False, (
                f"Finding '{title}' (severity={severity_raw}) has no evidence. "
                "At least one evidence string (request/response snippet, error "
                "message, or screenshot path) is required for non-informational findings."
            )

        # Structural check 2: critical/high/medium require a CVSS score
        if severity in _CVSS_REQUIRED and cvss_score is None:
            return False, (
                f"Finding '{title}' (severity={severity_raw}) is missing a CVSS "
                "score. Critical, High, and Medium findings must include a CVSS "
                "base score (0.0–10.0)."
            )

        # Structural check 3: description must be non-empty
        if not description.strip():
            return False, f"Finding '{title}' has an empty description."

        # Structural check 4: non-info findings require a remediation
        if severity != Severity.INFO and not remediation.strip():
            return False, (
                f"Finding '{title}' (severity={severity_raw}) is missing a "
                "remediation recommendation."
            )

        # LLM-assisted quality review
        llm_verdict = await self._llm_review(finding)
        if not llm_verdict["valid"]:
            return False, llm_verdict["reason"]

        return True, "Finding passes all validation checks."

    async def _llm_review(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Ask the LLM to review a finding for quality and accuracy.

        Sends a structured prompt to ``llm.generate_text()`` and parses
        the ``VALID:`` / ``INVALID:`` prefix from the response.

        Args:
            finding: Finding dict.

        Returns:
            Dict with keys ``valid`` (bool) and ``reason`` (str).
        """
        prompt = (
            "You are a security finding validator reviewing a pentest finding.\n\n"
            "Finding:\n"
            f"- Title: {finding.get('title', 'Untitled')}\n"
            f"- Severity: {finding.get('severity', 'info').upper()}\n"
            f"- CVSS Score: {finding.get('cvss_score', 'not provided')}\n"
            f"- Target: {finding.get('target', 'unknown')}\n"
            f"- Description: {finding.get('description', '')[:500]}\n"
            f"- Evidence: {json.dumps((finding.get('evidence') or [])[:3])}\n"
            f"- Remediation: {finding.get('remediation', '')[:200]}\n\n"
            "Review this finding and respond with EXACTLY one of:\n"
            "VALID: <brief reason>\n"
            "INVALID: <specific rejection reason>\n\n"
            "Reject if: CVSS score is inaccurate for the described severity, evidence "
            "is insufficient to confirm exploitability, or reproduction steps are "
            "absent for a claimed confirmed vulnerability."
        )
        response = (await self.llm.generate_text(prompt)).strip()

        upper = response.upper()
        if upper.startswith("VALID"):
            reason = response[5:].lstrip(":").strip() or "LLM review passed."
            return {"valid": True, "reason": reason}
        if upper.startswith("INVALID"):
            reason = response[7:].lstrip(":").strip() or "LLM review failed."
            return {"valid": False, "reason": reason}

        # Unexpected format — default to valid to avoid false rejections
        self._logger.warning(
            "LLM validator returned unexpected format: %s", response[:100]
        )
        return {"valid": True, "reason": "LLM response format unexpected; defaulting to valid."}

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Validate findings and mark confirmed ones in the state store.

        Args:
            input_data: Accepts the following optional keys:

                - ``findings``: List of finding dicts to validate.  When
                  omitted, all findings for the engagement are pulled from
                  the state store.
                - ``engagement_id``: Override engagement UUID (defaults to
                  ``self.engagement_id``).

        Returns:
            Dict with keys:

            - ``validated``: List of validated finding dicts (with added
              ``"status": "confirmed"`` and ``"validation_reason"`` fields).
            - ``rejected``: List of ``{"finding": dict, "reason": str}``
              dicts for rejected findings.
            - ``status``: Always ``"complete"`` on success.
        """
        engagement_id = input_data.get("engagement_id", self.engagement_id)
        findings_input: list[dict[str, Any]] | None = input_data.get("findings")

        if findings_input is None:
            findings_input = await self.state.get_findings(engagement_id)

        self._logger.info(
            "CriticAgent reviewing %d finding(s) for engagement %s",
            len(findings_input),
            engagement_id,
        )

        validated: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for finding in findings_input:
            finding_id: str = finding.get("id", "")
            title: str = finding.get("title", "Untitled")

            is_valid, reason = await self._validate_finding(finding)

            if is_valid:
                if finding_id:
                    await self.state.mark_finding_validated(finding_id)
                validated.append(
                    {
                        **finding,
                        "status": FindingStatus.CONFIRMED,
                        "validation_reason": reason,
                    }
                )
                self._logger.info("CONFIRMED: '%s' (%s)", title, finding_id)
            else:
                rejected.append(
                    {
                        "finding": {**finding, "status": FindingStatus.NEW},
                        "reason": reason,
                    }
                )
                self._logger.warning(
                    "REJECTED: '%s' (%s) — %s", title, finding_id, reason
                )

        self._logger.info(
            "CriticAgent complete: %d validated, %d rejected",
            len(validated),
            len(rejected),
        )

        return {
            "validated": validated,
            "rejected": rejected,
            "status": "complete",
        }
