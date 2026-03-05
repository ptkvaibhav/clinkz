"""Scan agent — phase 2: attack surface mapping.

Discovers endpoints, hidden paths, parameters, and API routes via dynamic
capability-based tool resolution.  The agent never references tool names
directly; instead it calls ``execute_capability`` and the ToolResolver finds
the best available tool for the requested capability.

Flow
----
1. ``run()`` builds the initial observation from recon results and calls
   ``_react_loop()``.
2. The LLM calls ``execute_capability`` with a capability string
   (e.g., ``"web_crawling"``).
3. ``_execute_tool()`` intercepts the call, queries the ToolResolver, and
   dispatches to the resolved tool.
4. Parsed tool output is returned to the LLM and persisted to the state store.
5. After the LLM returns a final answer, ``run()`` retrieves all persisted
   endpoints/targets and returns them alongside the summary.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from clinkz.agents.base import BaseAgent
from clinkz.llm.base import LLMClient, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — loaded once at module import from the .md file
# ---------------------------------------------------------------------------

_PROMPT_PATH = Path(__file__).parent / "prompts" / "scan_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ScanAgent
# ---------------------------------------------------------------------------


class ScanAgent(BaseAgent):
    """Attack surface mapping phase agent with dynamic tool discovery.

    Instead of holding a fixed set of tools, the ScanAgent exposes a single
    ``execute_capability`` meta-tool to the LLM.  When the LLM calls it, the
    agent queries the ToolResolver for the best available tool that satisfies
    the requested capability, executes it, and returns structured output.

    This ensures:
    - The LLM (and agent code) never hard-codes tool names.
    - The resolver can swap in MCP tools when they become available without
      any agent-side changes.
    - Tests can inject a mock resolver to control tool dispatch precisely.

    Args:
        llm: LLM client (Sonnet-tier recommended for this agent).
        tools: Passed to BaseAgent but not directly exposed to the LLM;
               the ToolResolver handles discovery independently.
        scope: Engagement scope for target validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        resolver: Optional pre-built ToolResolver.  A fresh resolver is
                  created automatically when not provided (production usage).
    """

    #: Schema for the capability meta-tool exposed to the LLM.
    _EXECUTE_CAPABILITY_SCHEMA: dict[str, Any] = {
        "name": "execute_capability",
        "description": (
            "Discover and execute the best scan tool for a given capability. "
            "Always specify the CAPABILITY you need (e.g., 'web_crawling', "
            "'directory_fuzzing', 'parameter_discovery', 'web_fingerprinting'), "
            "never a specific tool name. The system resolves the right tool automatically."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "capability": {
                    "type": "string",
                    "description": (
                        "The scanning capability to exercise. Examples: "
                        "'web_crawling', 'directory_fuzzing', 'parameter_discovery', "
                        "'web_fingerprinting', 'virtual_host_fuzzing', 'api_discovery'."
                    ),
                },
                "arguments": {
                    "type": "object",
                    "description": (
                        "Arguments forwarded to the resolved tool. Common keys: "
                        "'url' for HTTP crawling/fuzzing tools, 'target' for host-level tools. "
                        "Check the capability description for details."
                    ),
                },
            },
            "required": ["capability", "arguments"],
        },
    }

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        resolver: ToolResolver | None = None,
    ) -> None:
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        self._resolver: ToolResolver = resolver if resolver is not None else ToolResolver()
        self._discovered_endpoints: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "scan"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    # ------------------------------------------------------------------
    # Tool schema override — expose only the capability meta-tool
    # ------------------------------------------------------------------

    def _get_tool_schemas(self) -> list[dict[str, Any]]:
        """Return only the execute_capability schema.

        The LLM never sees raw tool names; it only knows how to ask for
        capabilities.  The ToolResolver handles the name-to-tool mapping.

        Returns:
            Single-element list containing the execute_capability schema.
        """
        return [self._EXECUTE_CAPABILITY_SCHEMA]

    # ------------------------------------------------------------------
    # Tool dispatch override — intercept execute_capability calls
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_call: ToolCall) -> str:
        """Dispatch tool calls, intercepting execute_capability for resolution.

        Args:
            tool_call: ToolCall from the LLM.

        Returns:
            JSON-serialised tool output or an error string.
        """
        if tool_call.name == "execute_capability":
            return await self._resolve_and_execute(tool_call.arguments)
        return await super()._execute_tool(tool_call)

    # ------------------------------------------------------------------
    # Capability resolution and execution
    # ------------------------------------------------------------------

    async def _resolve_and_execute(self, args: dict[str, Any]) -> str:
        """Resolve a capability to a tool, execute it, and persist results.

        Queries the ToolResolver for the best available tool, then:
        1. Instantiates the tool with the current scope.
        2. Validates and runs the tool.
        3. Logs the action to the state store.
        4. Persists any discovered endpoints/paths.

        Args:
            args: Must contain ``capability`` (str) and ``arguments`` (dict).

        Returns:
            JSON-serialised ToolOutput, or an error description string.
        """
        capability: str = args.get("capability", "").strip()
        tool_args: dict[str, Any] = args.get("arguments") or {}

        if not capability:
            return "Error: 'capability' is required in execute_capability arguments."

        match = self._resolver.find_tool(capability)
        if match is None:
            return (
                f"No tool is registered for capability '{capability}'. "
                "Try a different capability string or check the available capabilities."
            )
        if not match.available:
            return (
                f"Tool '{match.name}' is registered for capability '{capability}' "
                "but is not installed on this system. Consider an alternative capability."
            )
        if match.tool_class is None:
            return (
                f"Tool '{match.name}' for '{capability}' has no local class "
                "(MCP-only tools are not yet supported in this version)."
            )

        tool = match.tool_class(scope=self.scope)

        action_id = await self.state.log_action(
            engagement_id=self.engagement_id,
            phase=self.name,
            agent=self.__class__.__name__,
            tool=match.name,
            input_data=tool_args,
        )

        try:
            self._logger.info(
                "Resolved '%s' → '%s'; args: %s",
                capability,
                match.name,
                tool_args,
            )
            validated = tool.validate_input(tool_args)
            raw_output = await tool.execute(validated)
            parsed = tool.parse_output(raw_output)

            await self.state.complete_action(action_id, output_data=parsed.model_dump())
            await self._persist_tool_output(parsed)

            return parsed.model_dump_json(indent=2)

        except Exception as exc:
            self._logger.error(
                "Tool '%s' (capability '%s') failed: %s",
                match.name,
                capability,
                exc,
                exc_info=True,
            )
            await self.state.complete_action(
                action_id,
                output_data={"error": str(exc)},
                status="failed",
            )
            return f"Tool '{match.name}' failed with error: {exc}"

    # ------------------------------------------------------------------
    # State persistence helpers
    # ------------------------------------------------------------------

    async def _persist_tool_output(self, parsed: ToolOutput) -> None:
        """Persist discovered endpoints and paths from tool output.

        Inspects the parsed output for known scan fields (``endpoints``,
        ``paths``, ``urls``, ``parameters``) and upserts each discovery into
        the state store as a lightweight target entry tagged for the scan phase.

        Args:
            parsed: The ToolOutput returned by a tool's parse_output().
        """
        # Katana and crawlers return a list of endpoint URL strings
        for field_name in ("endpoints", "urls"):
            if hasattr(parsed, field_name):
                for url in getattr(parsed, field_name):  # type: ignore[attr-defined]
                    endpoint_data: dict[str, Any] = {
                        "ip": str(url),
                        "hostnames": [str(url)],
                        "tags": ["endpoint", "scan"],
                    }
                    target_id = await self.state.upsert_target(
                        self.engagement_id, endpoint_data
                    )
                    self._discovered_endpoints.append({**endpoint_data, "id": target_id})
                    self._logger.info("Persisted endpoint: %s", url)

        # ffuf and directory fuzzers return a list of path strings
        if hasattr(parsed, "paths"):
            for path in parsed.paths:  # type: ignore[attr-defined]
                path_data: dict[str, Any] = {
                    "ip": str(path),
                    "hostnames": [str(path)],
                    "tags": ["path", "scan"],
                }
                target_id = await self.state.upsert_target(
                    self.engagement_id, path_data
                )
                self._discovered_endpoints.append({**path_data, "id": target_id})
                self._logger.info("Persisted path: %s", path)

        # Parameter discovery tools return a list of parameter name strings
        if hasattr(parsed, "parameters"):
            for param in parsed.parameters:  # type: ignore[attr-defined]
                param_data: dict[str, Any] = {
                    "ip": str(param),
                    "hostnames": [str(param)],
                    "tags": ["parameter", "scan"],
                }
                target_id = await self.state.upsert_target(
                    self.engagement_id, param_data
                )
                self._discovered_endpoints.append({**param_data, "id": target_id})
                self._logger.info("Persisted parameter: %s", param)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run attack surface mapping against discovered web services.

        Builds an initial observation from ``input_data``, runs the ReAct
        loop until the LLM signals completion, then retrieves all persisted
        endpoints from the state store.

        Args:
            input_data: Accepts the following optional keys:

                - ``hosts``: list of host dicts from recon (each should have
                  services to identify HTTP/HTTPS ports).
                - ``urls``: list of URL strings to scan directly (overrides
                  host-based URL derivation when provided).
                - ``task``: free-text description of the scan task (e.g.,
                  from the Orchestrator for a focused sub-task).

        Returns:
            Dict with keys:

            - ``summary``: LLM final_answer string.
            - ``endpoints``: list of all persisted endpoint/path dicts.
            - ``status``: always ``"complete"`` on success.
        """
        self._discovered_endpoints = []

        hosts: list[dict[str, Any]] = input_data.get("hosts") or []
        urls: list[str] = [str(u) for u in (input_data.get("urls") or [])]
        task_text: str = input_data.get("task", "")
        scope_values: list[str] = [str(e.value) for e in self.scope.targets]

        # Derive URLs from host data if not explicitly provided
        if not urls:
            for host in hosts:
                for svc in host.get("services") or []:
                    port = svc.get("port")
                    ip = host.get("ip", "")
                    if port == 80:
                        urls.append(f"http://{ip}")
                    elif port == 443:
                        urls.append(f"https://{ip}")
                    elif port and svc.get("name", "").startswith("http"):
                        scheme = "https" if "ssl" in svc.get("name", "") else "http"
                        urls.append(f"{scheme}://{ip}:{port}")

        # Build the initial observation for the LLM
        parts: list[str] = []
        if task_text:
            parts.append(f"Task: {task_text}")
        if urls:
            parts.append(f"Target URLs: {', '.join(urls)}")
        elif hosts:
            parts.append(f"Target hosts: {', '.join(h.get('ip', '') for h in hosts)}")
        parts.append(f"In-scope targets: {', '.join(scope_values)}")
        parts.append(
            "\nUse execute_capability to run scan tools. "
            "Start by crawling (web_crawling) each URL to map the application structure, "
            "then fuzz directories (directory_fuzzing) to find unlisted paths, "
            "then discover parameters (parameter_discovery) on interesting endpoints, "
            "and fingerprint notable endpoints (web_fingerprinting). "
            "When you have thoroughly mapped the attack surface, return your final_answer "
            "with a structured summary of all discovered endpoints, paths, and parameters."
        )
        initial_observation = "\n".join(parts)

        self._logger.info(
            "ScanAgent starting — target URLs: %s",
            urls or [h.get("ip") for h in hosts],
        )

        final_answer = await self._react_loop(initial_observation)
        endpoints_data = await self.state.get_targets(self.engagement_id)

        return {
            "summary": final_answer,
            "endpoints": endpoints_data,
            "status": "complete",
        }
