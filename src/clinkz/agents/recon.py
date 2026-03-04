"""Reconnaissance agent — phase 1.

Discovers hosts, open ports, services, subdomains, and web technologies.

Tools used: nmap, subfinder, httpx, whatweb, wafw00f
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.agents.base import BaseAgent

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert penetration tester running the reconnaissance phase.
Your goal is to build a comprehensive picture of the target's attack surface.

Use the available tools to:
1. Enumerate subdomains (subfinder)
2. Probe live hosts and ports (nmap)
3. Fingerprint HTTP services (httpx, whatweb)
4. Detect WAFs (wafw00f)

Always check scope before scanning. Report ALL discovered services, technologies,
and potential entry points. Do not attempt exploitation in this phase.
When you have a complete picture of the target, provide your final answer as a
structured summary of all hosts and services discovered.
"""


class ReconAgent(BaseAgent):
    """Reconnaissance phase agent.

    TODO: Implement run() — wire nmap, subfinder, httpx, whatweb, wafw00f tools.
    """

    @property
    def name(self) -> str:
        return "recon"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run recon against all in-scope targets.

        Args:
            input_data: {"targets": ["example.com", "10.10.10.0/24"]}

        Returns:
            {"hosts": [Host.model_dump(), ...]}
        """
        # TODO: build initial_observation from input_data, call _react_loop,
        #       parse the result into Host models, persist via state.upsert_target
        raise NotImplementedError("ReconAgent.run() not yet implemented")
