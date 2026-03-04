"""Crawling and fuzzing agent — phase 2.

Discovers hidden endpoints, directories, parameters, and API routes.

Tools used: katana, ffuf
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.agents.base import BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert penetration tester running the crawling and fuzzing phase.
Your goal is to discover all accessible endpoints, directories, and parameters.

Use the available tools to:
1. Crawl web applications and follow links (katana)
2. Fuzz directories and files (ffuf)
3. Identify interesting endpoints (admin panels, API docs, backup files)

Focus on coverage — find as many endpoints as possible for the exploitation phase.
Report all discovered URLs, parameters, and interesting findings.
"""


class CrawlAgent(BaseAgent):
    """Crawling and fuzzing phase agent.

    TODO: Implement run() — wire katana and ffuf tools.
    """

    @property
    def name(self) -> str:
        return "crawl"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run crawling against all discovered HTTP services.

        Args:
            input_data: {"hosts": [Host.model_dump(), ...]}

        Returns:
            {"endpoints": [...], "interesting_paths": [...]}
        """
        raise NotImplementedError("CrawlAgent.run() not yet implemented")
