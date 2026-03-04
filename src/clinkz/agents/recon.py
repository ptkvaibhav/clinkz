"""Reconnaissance agent — phase 1.

Discovers hosts, open ports, services, subdomains, and web technologies via
dynamic capability-based tool resolution.  The agent never references tool
names directly; instead it calls ``execute_capability`` and the ToolResolver
finds the best available tool for the requested capability.

Flow
----
1. ``run()`` builds the initial observation from the task input and calls
   ``_react_loop()``.
2. The LLM calls ``execute_capability`` with a capability string
   (e.g., ``"subdomain_enumeration"``).
3. ``_execute_tool()`` intercepts the call, queries the ToolResolver, and
   dispatches to the resolved tool.
4. Parsed tool output is returned to the LLM and persisted to the state store.
5. After the LLM returns a final answer, ``run()`` retrieves all persisted
   targets and returns them alongside the summary.
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

_PROMPT_PATH = Path(__file__).parent / "prompts" / "recon_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ReconAgent
# ---------------------------------------------------------------------------


class ReconAgent(BaseAgent):
    """Reconnaissance phase agent with dynamic tool discovery.

    Instead of holding a fixed set of tools, the ReconAgent exposes a single
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
            "Discover and execute the best recon tool for a given capability. "
            "Always specify the CAPABILITY you need (e.g., 'subdomain_enumeration', "
            "'port_scanning', 'web_fingerprinting', 'waf_detection', 'http_probing'), "
            "never a specific tool name. The system resolves the right tool automatically."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "capability": {
                    "type": "string",
                    "description": (
                        "The reconnaissance capability to exercise. Examples: "
                        "'subdomain_enumeration', 'port_scanning', 'service_detection', "
                        "'os_fingerprinting', 'http_probing', 'web_fingerprinting', "
                        "'waf_detection', 'dns_enumeration', 'alive_check'."
                    ),
                },
                "arguments": {
                    "type": "object",
                    "description": (
                        "Arguments forwarded to the resolved tool. Common keys: "
                        "'domain' for subdomain/DNS tools, 'target' for network tools, "
                        "'url' for HTTP tools. Check the capability description for details."
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
        self._discovered_hosts: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "recon"

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
        # Fallback to base class dispatch for any other tool name
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
        4. Persists any discovered hosts/subdomains.

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
        """Persist discovered hosts and subdomains from tool output.

        Inspects the parsed output for known fields (``hosts``, ``subdomains``)
        and upserts each discovery into the state store.

        Args:
            parsed: The ToolOutput returned by a tool's parse_output().
        """
        # Nmap and similar tools return a list of Host Pydantic models
        if hasattr(parsed, "hosts"):
            for host in parsed.hosts:  # type: ignore[attr-defined]
                host_data: dict[str, Any] = (
                    host.model_dump() if hasattr(host, "model_dump") else dict(host)
                )
                target_id = await self.state.upsert_target(
                    self.engagement_id, host_data
                )
                self._discovered_hosts.append({**host_data, "id": target_id})
                self._logger.info(
                    "Persisted host: %s", host_data.get("ip", "unknown")
                )

        # Subfinder and similar tools return a list of subdomain strings
        if hasattr(parsed, "subdomains"):
            for subdomain in parsed.subdomains:  # type: ignore[attr-defined]
                host_data = {
                    "ip": subdomain,
                    "hostnames": [subdomain],
                    "tags": ["subdomain"],
                    "is_alive": True,
                }
                target_id = await self.state.upsert_target(
                    self.engagement_id, host_data
                )
                self._discovered_hosts.append({**host_data, "id": target_id})
                self._logger.info("Persisted subdomain: %s", subdomain)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run reconnaissance against all in-scope targets.

        Builds an initial observation from ``input_data``, runs the ReAct
        loop until the LLM signals completion, then retrieves all persisted
        targets from the state store.

        Args:
            input_data: Accepts the following optional keys:

                - ``targets``: list of target strings (domains, IPs, CIDRs).
                - ``task``: free-text description of the recon task (e.g.,
                  from the Orchestrator for a focused sub-task).

        Returns:
            Dict with keys:

            - ``summary``: LLM final_answer string.
            - ``hosts``: list of all persisted host dicts (from state store).
            - ``status``: always ``"complete"`` on success.
        """
        self._discovered_hosts = []

        targets: list[str] = [str(t) for t in (input_data.get("targets") or [])]
        task_text: str = input_data.get("task", "")
        scope_values: list[str] = [str(e.value) for e in self.scope.targets]

        # Build the initial observation for the LLM
        parts: list[str] = []
        if task_text:
            parts.append(f"Task: {task_text}")
        if targets:
            parts.append(f"Primary targets: {', '.join(targets)}")
        parts.append(f"In-scope targets: {', '.join(scope_values)}")
        parts.append(
            "\nUse execute_capability to run recon tools. "
            "Start with passive recon (subdomain_enumeration), then probe live hosts "
            "(http_probing or alive_check), then scan ports (port_scanning), then "
            "fingerprint services (web_fingerprinting, waf_detection). "
            "When you have thoroughly enumerated the targets, return your final_answer "
            "with a structured summary of all discovered hosts, services, and findings."
        )
        initial_observation = "\n".join(parts)

        self._logger.info(
            "ReconAgent starting — primary targets: %s",
            targets or scope_values,
        )

        final_answer = await self._react_loop(initial_observation)
        hosts_data = await self.state.get_targets(self.engagement_id)

        return {
            "summary": final_answer,
            "hosts": hosts_data,
            "status": "complete",
        }
