"""Research agent — runs concurrently with Scan and Exploit phases.

For each technology discovered during recon, performs multi-angle research:
- CVE + exploit PoC queries
- Bug bounty writeup queries
- Penetration testing technique queries
- Exploit-DB / known vulnerability queries
- Security bypass technique queries

Results are parsed and written to the engagement runbook via
``state.add_runbook_entry()`` so the Exploit Agent can consume them.

The agent runs as a long-lived concurrent task — it keeps researching until
all technologies are covered or the Orchestrator shuts it down.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent
from clinkz.llm.base import LLMClient, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

if TYPE_CHECKING:
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — loaded once at module import from the .md file
# ---------------------------------------------------------------------------

_PROMPT_PATH = Path(__file__).parent / "prompts" / "research_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# Research query templates — one per angle of research
# ---------------------------------------------------------------------------

_RESEARCH_QUERIES: list[str] = [
    "CVE {technology} {version} exploit proof of concept",
    "{technology} {version} HackerOne bug bounty writeup",
    "{technology} {version} penetration testing techniques",
    "{technology} {version} known vulnerabilities exploit-db",
    "{technology} {version} security bypass techniques",
]


class ResearchAgent(BaseAgent):
    """Security research agent that builds an attack playbook.

    For each technology in the input list, the agent performs multiple
    research queries via the LLM's ``research()`` method, then uses the
    ReAct loop to parse findings and write runbook entries.

    The agent exposes two meta-tools to the LLM:
    - ``research_technology``: performs a research query
    - ``write_runbook_entry``: writes a technique to the engagement runbook

    Args:
        llm: LLM client (Claude Opus recommended for deep research).
        tools: Passed to BaseAgent (typically empty — research is LLM-based).
        scope: Engagement scope.
        state: SQLite state store for runbook persistence.
        engagement_id: UUID of the active engagement.
    """

    #: Schema for the research meta-tool.
    _RESEARCH_TECHNOLOGY_SCHEMA: dict[str, Any] = {
        "name": "research_technology",
        "description": (
            "Perform live security research on a technology, service, or version. "
            "Returns detailed findings about CVEs, exploits, attack techniques, "
            "and bug bounty writeups. Use this to gather intelligence before "
            "writing runbook entries."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Research query. Examples: "
                        "'CVE Apache 2.4.25 exploit proof of concept', "
                        "'PHP 7.2 known vulnerabilities exploit-db'."
                    ),
                },
            },
            "required": ["query"],
        },
    }

    #: Schema for writing runbook entries.
    _WRITE_RUNBOOK_ENTRY_SCHEMA: dict[str, Any] = {
        "name": "write_runbook_entry",
        "description": (
            "Write a discovered attack technique to the engagement runbook. "
            "The Exploit Agent reads the runbook to find techniques to apply. "
            "Each entry must include actionable exploitation steps."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "technology": {
                    "type": "string",
                    "description": (
                        "Target technology and version (e.g., 'Apache 2.4.25', "
                        "'PHP 7.2', 'DVWA 1.10')."
                    ),
                },
                "technique_name": {
                    "type": "string",
                    "description": (
                        "Short descriptive name for the technique "
                        "(e.g., 'CVE-2021-41773 Path Traversal')."
                    ),
                },
                "technique_description": {
                    "type": "string",
                    "description": "Detailed description of the technique with context.",
                },
                "steps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered list of exploitation steps.",
                },
                "source_url": {
                    "type": "string",
                    "description": "URL where the technique was found.",
                    "default": "",
                },
                "source_type": {
                    "type": "string",
                    "enum": ["cve", "hackerone", "bugcrowd", "exploit_db", "medium", "reddit", "other"],
                    "description": "Type of source.",
                    "default": "other",
                },
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier if applicable (e.g., 'CVE-2021-41773').",
                    "default": "",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level of the technique.",
                    "default": "info",
                },
            },
            "required": ["technology", "technique_name", "technique_description", "steps"],
        },
    }

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
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            knowledge_base=knowledge_base,
            **kwargs,
        )
        self._runbook_entries_written: int = 0

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "research"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Tool schema override — expose only research + runbook meta-tools
    # ------------------------------------------------------------------

    def _get_tool_schemas(self) -> list[dict[str, Any]]:
        """Return research-specific meta-tool schemas.

        Returns:
            List containing research_technology, write_runbook_entry,
            and shared meta-tools.
        """
        return [
            self._RESEARCH_TECHNOLOGY_SCHEMA,
            self._WRITE_RUNBOOK_ENTRY_SCHEMA,
        ] + self._get_shared_meta_schemas()

    # ------------------------------------------------------------------
    # Tool dispatch override
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_call: ToolCall) -> str:
        """Dispatch tool calls for research meta-tools.

        Args:
            tool_call: ToolCall from the LLM.

        Returns:
            Result string.
        """
        if tool_call.name == "research_technology":
            return await self._do_research(tool_call.arguments)
        if tool_call.name == "write_runbook_entry":
            return await self._do_write_runbook_entry(tool_call.arguments)
        return await super()._execute_tool(tool_call)

    # ------------------------------------------------------------------
    # Meta-tool handlers
    # ------------------------------------------------------------------

    async def _do_research(self, args: dict[str, Any]) -> str:
        """Execute a research query via ``llm.research()``.

        Args:
            args: Must contain ``query`` (str).

        Returns:
            Research result string.
        """
        query: str = args.get("query", "").strip()
        if not query:
            return "Error: 'query' is required for research_technology."
        self._logger.info("Research query: %s", query)
        return await self.llm.research(query)

    async def _do_write_runbook_entry(self, args: dict[str, Any]) -> str:
        """Write a technique to the engagement runbook via the state store.

        Args:
            args: Runbook entry fields.

        Returns:
            Confirmation string with the entry ID.
        """
        technology: str = args.get("technology", "").strip()
        technique_name: str = args.get("technique_name", "").strip()
        technique_description: str = args.get("technique_description", "").strip()
        steps: list[str] = args.get("steps", [])

        if not technology or not technique_name:
            return "Error: 'technology' and 'technique_name' are required."
        if not technique_description:
            return "Error: 'technique_description' is required — provide actionable detail."
        if not steps:
            return "Error: 'steps' must be a non-empty list of exploitation steps."

        entry_id = await self.state.add_runbook_entry(
            engagement_id=self.engagement_id,
            technology=technology,
            technique_name=technique_name,
            technique_description=technique_description,
            source_url=args.get("source_url", ""),
            source_type=args.get("source_type", "other"),
            steps=steps,
            applicable_to=args.get("applicable_to", []),
            cve_id=args.get("cve_id") or None,
            severity=args.get("severity", "info"),
        )

        if entry_id is None:
            return (
                f"Runbook entry '{technique_name}' for '{technology}' already exists — "
                "skipped duplicate."
            )

        self._runbook_entries_written += 1
        self._logger.info(
            "Runbook entry #%d written: %s / %s (severity: %s)",
            self._runbook_entries_written,
            technology,
            technique_name,
            args.get("severity", "info"),
        )
        return (
            f"Runbook entry written: id={entry_id}, "
            f"technology='{technology}', technique='{technique_name}', "
            f"severity={args.get('severity', 'info')}. "
            f"Total entries written: {self._runbook_entries_written}."
        )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run security research for all specified technologies.

        Builds a research plan from the technology list and runs the ReAct
        loop. The LLM calls research_technology for each query angle and
        writes findings to the runbook via write_runbook_entry.

        Args:
            input_data: Accepts:

                - ``technologies``: list of technology strings
                  (e.g., ["Apache 2.4.25", "PHP 7.2", "MySQL 5.7"]).
                - ``task``: optional free-text task description.

        Returns:
            Dict with keys:

            - ``summary``: LLM final_answer string.
            - ``runbook_entries_written``: count of entries added.
            - ``technologies_researched``: input technology list.
            - ``status``: always ``"complete"`` on success.
        """
        self._runbook_entries_written = 0

        technologies: list[str] = [str(t) for t in (input_data.get("technologies") or [])]
        task_text: str = input_data.get("task", "")

        if not technologies:
            self._logger.warning("ResearchAgent called with no technologies — returning early.")
            return {
                "summary": "No technologies provided for research.",
                "runbook_entries_written": 0,
                "technologies_researched": [],
                "status": "complete",
            }

        # Build the initial observation for the LLM
        parts: list[str] = []
        if task_text:
            parts.append(f"Task: {task_text}")

        parts.append(f"Technologies to research ({len(technologies)}):")
        for i, tech in enumerate(technologies, 1):
            parts.append(f"  {i}. {tech}")

        parts.append("\nFor EACH technology, perform these research queries:")
        for template in _RESEARCH_QUERIES:
            parts.append(f"  - {template}")

        parts.append(
            "\nFor each query result, extract actionable techniques and write them "
            "to the runbook using write_runbook_entry. Include specific CVE IDs, "
            "exploitation steps, and severity ratings."
            "\n\nWork through ALL technologies systematically. After researching "
            "all technologies from all angles, return your final_answer with a "
            "summary of what you found."
        )

        initial_observation = "\n".join(parts)

        self._logger.info(
            "ResearchAgent starting — %d technologies: %s",
            len(technologies),
            technologies,
        )

        final_answer = await self._react_loop(initial_observation)

        return {
            "summary": final_answer,
            "runbook_entries_written": self._runbook_entries_written,
            "technologies_researched": technologies,
            "status": "complete",
        }
