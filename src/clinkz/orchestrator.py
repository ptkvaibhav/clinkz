"""Orchestrator agent — high-level strategy and phase transitions.

The Orchestrator decides which phase to run next and when to stop.
It uses the more capable model (GPT-4o / Claude Opus) because it makes
critical strategic decisions across the full engagement lifecycle.

Phase order:
    recon → crawl → exploit → [critic validates] → report

This is a stub. Implement with LangGraph StateGraph or a custom ReAct loop.
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.llm.base import LLMClient
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore

logger = logging.getLogger(__name__)

PHASES = ["recon", "crawl", "exploit", "critic", "report"]


class Orchestrator:
    """Coordinates all phase agents for a full pentest engagement.

    Args:
        llm: LLM client (should use the orchestrator/high-capability model).
        scope: Engagement scope definition.
        state: SQLite state store for the engagement.
        engagement_id: UUID of the active engagement.
    """

    def __init__(
        self,
        llm: LLMClient,
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
    ) -> None:
        self.llm = llm
        self.scope = scope
        self.state = state
        self.engagement_id = engagement_id

    async def run(self) -> dict[str, Any]:
        """Execute the full pentest pipeline from recon to report.

        Returns:
            Summary dict with phase results and finding counts.

        TODO:
            - Instantiate ReconAgent, CrawlAgent, ExploitAgent, CriticAgent, ReportAgent
            - Pass findings between phases via state store
            - Implement LangGraph StateGraph for robust phase management
            - Add conditional phase skipping (e.g., skip exploit if no services found)
        """
        logger.info(
            "Orchestrator starting engagement %s — targets: %s",
            self.engagement_id,
            [t.value for t in self.scope.targets],
        )

        results: dict[str, Any] = {}
        for phase in PHASES:
            logger.info("Phase: %s", phase)
            results[phase] = await self._run_phase(phase)

        await self.state.update_engagement_status(self.engagement_id, "completed")
        return results

    async def _run_phase(self, phase: str) -> dict[str, Any]:
        """Dispatch to the appropriate phase agent.

        Args:
            phase: Phase name from PHASES list.

        Returns:
            Phase result dict (agent-specific).
        """
        # TODO: import and instantiate each phase agent here
        raise NotImplementedError(f"Phase '{phase}' agent not yet implemented")
