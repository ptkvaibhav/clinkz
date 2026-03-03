"""Critic agent — finding validation.

Reviews all raw findings and eliminates false positives before the report.
Does NOT use external tools — only the LLM reasons over the evidence.
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.agents.base import BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a senior penetration tester reviewing findings for accuracy.
Your goal is to eliminate false positives and ensure every finding in the final report
is genuine, well-evidenced, and accurately described.

For each finding, evaluate:
1. Is the evidence conclusive? (request/response pair, PoC output)
2. Is the severity rating appropriate?
3. Is it a duplicate of another finding?
4. Is the description accurate and clearly written?

Return your verdict as: CONFIRMED, FALSE_POSITIVE, or DUPLICATE
with a brief justification for each decision.
"""


class CriticAgent(BaseAgent):
    """Critic / validation phase agent.

    TODO: Implement run() — iterate findings, call _react_loop per finding,
    parse verdict, call state.mark_finding_validated().
    """

    @property
    def name(self) -> str:
        return "critic"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Validate all raw findings and mark confirmed ones.

        Args:
            input_data: {"findings": [Finding.model_dump(), ...]}

        Returns:
            {"confirmed": [...], "false_positives": [...], "duplicates": [...]}
        """
        raise NotImplementedError("CriticAgent.run() not yet implemented")
