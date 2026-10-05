"""Base class for the phase agents — shared infrastructure, not a control loop.

Every phase agent inherits from BaseAgent and overrides:
- name       — identifier used in logs and state store
- system_prompt — loaded from agents/prompts/<name>.txt
- run()      — entry point called by the Orchestrator

**What runs is not a ReAct loop.** The v2 phase agents (recon, scan, exploit,
research, report) implement ``run()`` as a fixed sequence of tool calls and
deterministic code, invoking the LLM only at named reasoning checkpoints —
never free-form Observe → Reason → Act → Reflect (CLAUDE.md invariant 1). The
generic ``_react_loop`` that used to live here ran in no v2 agent and was
removed; BaseAgent now provides only the shared services those deterministic
``run()`` methods draw on — tool execution (``_execute_tool``), the skills
loader, state access and step tracing.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager, nullcontext
from typing import TYPE_CHECKING, Any

from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.knowledge.skills_loader import SkillsLoader
from clinkz.llm.base import LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.observability.trace import get_active_trace_writer
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

if TYPE_CHECKING:
    from clinkz.comms.bus import MessageBus
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

# Default iteration limits per agent type.  Agents override via the
# ``max_iterations`` property so each phase gets the budget it needs.
DEFAULT_MAX_ITERATIONS: dict[str, int] = {
    "recon": 20,
    "scan": 20,
    "exploit": 40,
    "research": 10,
    "report": 10,
}

# Fallback when an agent name is not in the map above.
_FALLBACK_MAX_ITERATIONS = 20


class BaseAgent(ABC):
    """Abstract base for all Clinkz phase agents.

    Provides shared services — tool dispatch, the skills loader, state logging
    and step tracing — that each agent's deterministic ``run()`` draws on. It is
    not a control loop: the v2 agents sequence their own steps and invoke the LLM
    at named checkpoints (see the module docstring).
    Concrete agents only need to define their name, prompt, and run() logic.

    Args:
        llm: LLM client (from llm/factory.py — never import SDK directly).
        tools: Tools available to this agent.
        scope: Engagement scope for validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        bus: Optional MessageBus for cross-agent communication (request_help).
    """

    # ------------------------------------------------------------------
    # Shared meta-tool schemas available to ALL agents
    # ------------------------------------------------------------------

    _REQUEST_HELP_SCHEMA: dict[str, Any] = {
        "name": "request_help",
        "description": (
            "Ask another agent or the Orchestrator for information. The message "
            "is routed through the Orchestrator, which decides the best way to "
            "answer — either from its own context or by spinning up the target "
            "agent for a focused sub-task."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": (
                        "The question or request. Be specific about what you need. "
                        "Example: 'What technologies were identified on api.target.com?'"
                    ),
                },
                "target_agent": {
                    "type": "string",
                    "description": (
                        "Which agent should answer: 'recon', 'scan', 'exploit', "
                        "'orchestrator'. The Orchestrator decides whether to spin up "
                        "the target agent or answer from state."
                    ),
                    "default": "orchestrator",
                },
            },
            "required": ["question"],
        },
    }

    _GET_SKILL_REFERENCE_SCHEMA: dict[str, Any] = {
        "name": "get_skill_reference",
        "description": (
            "Retrieve a documented procedure (skill) for performing a specific "
            "pentesting task. Skills contain step-by-step instructions, common "
            "pitfalls, and examples. Always read the relevant skill BEFORE "
            "attempting a task you haven't done in this engagement."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "description": (
                        "Name of the skill to retrieve. Use list_skills() first "
                        "if you don't know what's available. Examples: "
                        "'csrf_token_extraction', 'sqli_column_count', "
                        "'xss_context_analysis', 'lfi_exploitation'"
                    ),
                },
            },
            "required": ["skill_name"],
        },
    }

    _TOOL_INSTALLATION_SCHEMA: dict[str, Any] = {
        "name": "tool_installation",
        "description": (
            "Install a security tool inside the Docker container at runtime. "
            "Use this when research reveals a tool you need but it isn't "
            "installed. After installation, the tool becomes available through "
            "execute_capability."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": (
                        "Name or URL of the tool to install. "
                        "For apt: package name. For pip: package name. "
                        "For go: full module path (e.g., github.com/org/tool/cmd/tool). "
                        "For git: repo URL. For download: direct URL to binary."
                    ),
                },
                "install_method": {
                    "type": "string",
                    "enum": ["apt", "pip", "go", "git", "download"],
                    "description": "Installation method to use.",
                },
            },
            "required": ["tool_name", "install_method"],
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
        bus: MessageBus | None = None,
        persistent_kb: PersistentKnowledgeBase | None = None,
    ) -> None:
        self.llm = llm
        self.tools: dict[str, ToolBase] = {t.name: t for t in tools}
        self.scope = scope
        self.state = state
        self.engagement_id = engagement_id
        self.knowledge_base = knowledge_base
        self._bus: MessageBus | None = bus
        self.persistent_kb: PersistentKnowledgeBase | None = persistent_kb
        self._skills_loader = SkillsLoader()
        self.messages: list[LLMMessage] = []
        self._inbox: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._pending_responses: dict[str, AgentMessage] = {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Iteration limit — per-agent, configurable
    # ------------------------------------------------------------------

    def _record_step(
        self,
        step_name: str,
        *,
        inputs: dict[str, Any] | None = None,
        replay_info: dict[str, Any] | None = None,
    ) -> AbstractContextManager[str]:
        """Wrap a deterministic agent step so it can be replayed in isolation.

        Captures the full input payload to
        ``outputs/<engagement_id>/step_inputs/<step_id>.json`` and emits a
        matching ``agent_step`` trace event on exit. ``replay_info`` should
        carry whatever the :class:`StepReplayer` needs — typically just
        ``{"method_name": "_step_port_scan"}``; the agent class and LLM
        provider are inferred at replay time.

        Returns a context manager yielding the step_id (a UUID). Returns a
        no-op context when no engagement-level TraceWriter is active, so
        agents can call this unconditionally.
        """
        writer = get_active_trace_writer()
        if writer is None:
            return nullcontext("")
        merged_replay = dict(replay_info or {})
        merged_replay.setdefault("agent_class", self.__class__.__name__)
        merged_replay.setdefault("engagement_id", self.engagement_id)
        return writer.step(
            agent=self.name,
            step_name=step_name,
            inputs=inputs,
            replay_info=merged_replay,
        )

    def _trace_step(
        self,
        step_name: str,
        *,
        input_summary: str = "",
        output_summary: str = "",
        duration_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit an agent_step trace event for this agent.

        Used by deterministic v2 agents to mark step boundaries (Step 1 plan,
        Step 2 execute, etc.). No-op when no engagement-level TraceWriter is
        active, so it's safe to call from agent code without checking.
        """
        writer = get_active_trace_writer()
        if writer is None:
            return
        writer.agent_step(
            agent=self.name,
            step_name=step_name,
            input_summary=input_summary,
            output_summary=output_summary,
            duration_ms=duration_ms,
            extra=extra,
        )

    @property
    def max_iterations(self) -> int:
        """Maximum ReAct iterations for this agent.

        Looks up the agent's ``name`` in ``DEFAULT_MAX_ITERATIONS``.
        Subclasses can override this property to set a custom limit.

        Returns:
            Iteration budget for the ReAct loop.
        """
        return DEFAULT_MAX_ITERATIONS.get(self.name, _FALLBACK_MAX_ITERATIONS)

    # ------------------------------------------------------------------
    # Abstract interface — implement in each phase agent
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent identifier (e.g., 'recon', 'exploit')."""
        ...

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Full system prompt text for this agent."""
        ...

    @abstractmethod
    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Execute the agent's phase and return structured results.

        Args:
            input_data: Phase-specific input (e.g., list of targets).

        Returns:
            Phase-specific output (e.g., discovered hosts, findings).
        """
        ...

    # ------------------------------------------------------------------
    # Inbox — mid-run message handling
    # ------------------------------------------------------------------

    def receive_message(self, msg: AgentMessage) -> None:
        """Deliver a message to this agent's inbox for mid-run processing.

        Called by the lifecycle manager (or tests) when routing an incoming
        message to an agent that is already executing its ReAct loop.
        QUERY messages are folded into the LLM conversation at the next
        inter-iteration checkpoint.

        Args:
            msg: The incoming AgentMessage to queue.
        """
        self._inbox.put_nowait(msg)

    def _get_tool_schemas(self) -> list[dict[str, Any]]:
        """Return tool schemas to pass to the LLM for reasoning.

        Subclasses can override this to expose a custom schema set — for
        example, a capability-based meta-tool instead of raw tool schemas.

        The base implementation includes raw tool schemas plus the shared
        meta-tools (request_help, tool_installation).  Subclasses that
        override this should include the shared schemas via
        ``_get_shared_meta_schemas()``.

        Returns:
            List of OpenAI-compatible tool schema dicts.
        """
        return [t.get_schema() for t in self.tools.values()] + self._get_shared_meta_schemas()

    def _get_shared_meta_schemas(self) -> list[dict[str, Any]]:
        """Return the meta-tool schemas shared across ALL agents.

        Includes get_skill_reference, tool_installation, and
        request_help (only if a MessageBus is available).

        Returns:
            List of meta-tool schema dicts.
        """
        schemas: list[dict[str, Any]] = [
            self._GET_SKILL_REFERENCE_SCHEMA,
            self._TOOL_INSTALLATION_SCHEMA,
        ]
        if self._bus is not None:
            schemas.append(self._REQUEST_HELP_SCHEMA)
        return schemas

    async def _process_inbox(self) -> None:
        """Drain the inbox and inject pending messages into the conversation.

        QUERY messages are appended as ``user`` messages so the LLM sees
        them on the next reasoning step.  RESPONSE messages are stored for
        ``_do_request_help()`` to pick up.  Other message types are logged
        and discarded — they are not expected mid-loop for phase agents.
        """
        while True:
            try:
                msg = self._inbox.get_nowait()
            except asyncio.QueueEmpty:
                break

            if msg.message_type == MessageType.QUERY:
                query_text = msg.content.get("query", str(msg.content))
                self._logger.info("Mid-run query from '%s': %s", msg.from_agent, query_text)
                self.messages.append(
                    LLMMessage(
                        role="user",
                        content=f"[Mid-run query from {msg.from_agent}]: {query_text}",
                    )
                )
            elif msg.message_type == MessageType.RESPONSE:
                # Store for _do_request_help() to pick up
                self._pending_responses[msg.parent_message_id or ""] = msg
            else:
                self._logger.debug(
                    "Inbox: ignoring %s message from '%s'",
                    msg.message_type,
                    msg.from_agent,
                )

    # ------------------------------------------------------------------
    # Skill reference: get_skill_reference
    # ------------------------------------------------------------------

    async def _do_get_skill_reference(self, args: dict[str, Any]) -> str:
        """Load a skill document so the LLM can follow the procedure.

        Args:
            args: Must contain ``skill_name`` (str).

        Returns:
            The skill markdown content, or an error message.
        """
        skill_name: str = args.get("skill_name", "").strip()
        if not skill_name:
            available = self._skills_loader.list_skills()
            return f"Error: 'skill_name' is required. Available skills: {available}"

        try:
            content = self._skills_loader.load_skill(skill_name)
            self._logger.info("Loaded skill '%s' (%d chars)", skill_name, len(content))
            return content
        except FileNotFoundError as exc:
            return str(exc)

    # ------------------------------------------------------------------
    # Cross-agent collaboration: request_help
    # ------------------------------------------------------------------

    async def _do_request_help(self, args: dict[str, Any]) -> str:
        """Send a QUERY to the Orchestrator and wait for the RESPONSE.

        The Orchestrator decides whether to answer from state, spin up the
        target agent for a sub-task, or route the question directly.

        Reads directly from the bus queue for this agent's name, because the
        lifecycle manager's bus→inbox bridge is blocked while agent.run() is
        executing.  Non-response messages encountered while waiting are
        forwarded to the agent's inbox for later processing.

        Args:
            args: Must contain ``question`` (str).  Optional: ``target_agent``.

        Returns:
            Response text from the Orchestrator (or target agent via Orchestrator).
        """
        if self._bus is None:
            return (
                "request_help is not available — no MessageBus configured. "
                "Use research_technology for external information."
            )

        question: str = args.get("question", "").strip()
        if not question:
            return "Error: 'question' is required for request_help."

        target_agent: str = args.get("target_agent", "orchestrator").strip()

        # Build and send the QUERY message to the Orchestrator
        query_msg = AgentMessage.query(
            from_agent=self.name,
            to_agent=ORCHESTRATOR,
            engagement_id=self.engagement_id,
            content={
                "query": question,
                "needs_agent": target_agent if target_agent != "orchestrator" else None,
            },
        )

        self._logger.info(
            "request_help: asking '%s' via Orchestrator: %s",
            target_agent,
            question[:200],
        )
        await self._bus.send(query_msg)

        # Wait for RESPONSE with matching parent_message_id.
        # We read from BOTH the bus queue and the agent inbox to avoid the
        # race where the response lands on the bus before anyone bridges it
        # to the inbox.  The lifecycle manager's _run_agent loop is blocked
        # inside agent.run() so it cannot move bus messages to the inbox.
        timeout = 120.0
        poll_interval = 0.25
        elapsed = 0.0

        while elapsed < timeout:
            # 1. Check if _process_inbox already stashed it
            if query_msg.id in self._pending_responses:
                response_msg = self._pending_responses.pop(query_msg.id)
                response_text = response_msg.content.get("response", str(response_msg.content))
                self._logger.info("request_help response received (%d chars)", len(response_text))
                return response_text

            # 2. Drain the agent inbox (messages injected via receive_message)
            try:
                msg = self._inbox.get_nowait()
                if (
                    msg.message_type == MessageType.RESPONSE
                    and msg.parent_message_id == query_msg.id
                ):
                    response_text = msg.content.get("response", str(msg.content))
                    self._logger.info(
                        "request_help response received (%d chars)", len(response_text)
                    )
                    return response_text
                # Not our response — keep it for later
                self._inbox.put_nowait(msg)
            except asyncio.QueueEmpty:
                pass

            # 3. Read directly from the bus queue — this is where the
            #    Orchestrator's response actually lands.
            try:
                bus_msg = await asyncio.wait_for(
                    self._bus.receive(self.name), timeout=poll_interval
                )
                if (
                    bus_msg.message_type == MessageType.RESPONSE
                    and bus_msg.parent_message_id == query_msg.id
                ):
                    response_text = bus_msg.content.get("response", str(bus_msg.content))
                    self._logger.info(
                        "request_help response received (%d chars)", len(response_text)
                    )
                    return response_text
                # Not our response — forward to inbox so _process_inbox
                # picks it up on the next ReAct iteration.
                self._inbox.put_nowait(bus_msg)
            except TimeoutError:
                pass

            elapsed += poll_interval

        self._logger.warning("request_help timed out after %.0fs", timeout)
        return f"request_help timed out after {timeout}s — no response from Orchestrator."

    # ------------------------------------------------------------------
    # Dynamic tool acquisition: tool_installation
    # ------------------------------------------------------------------

    async def _do_tool_installation(self, args: dict[str, Any]) -> str:
        """Install a tool inside the Docker container at runtime.

        Delegates to ``ToolInstallerTool`` from ``tools/installer.py``.

        Args:
            args: Must contain ``tool_name`` and ``install_method``.

        Returns:
            Installation result string.
        """
        from clinkz.tools.installer import ToolInstallerTool

        installer = ToolInstallerTool(scope=self.scope)
        try:
            validated = installer.validate_input(args)
            raw_output = await installer.execute(validated)
            parsed = installer.parse_output(raw_output)
            return parsed.model_dump_json(indent=2)
        except Exception as exc:
            self._logger.error("tool_installation failed: %s", exc, exc_info=True)
            return f"tool_installation failed: {exc}"

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_call: ToolCall) -> str:
        """Dispatch a tool call and return the result as a JSON string.

        Handles shared meta-tools (request_help, tool_installation) first,
        then falls through to registered tools.  Logs the action to the
        state store and handles errors gracefully so a single tool failure
        doesn't crash the whole loop.

        Args:
            tool_call: ToolCall from the LLM.

        Returns:
            Tool output serialised to JSON, or an error message string.
        """
        # Shared meta-tools available to all agents
        if tool_call.name == "get_skill_reference":
            return await self._do_get_skill_reference(tool_call.arguments)
        if tool_call.name == "request_help":
            return await self._do_request_help(tool_call.arguments)
        if tool_call.name == "tool_installation":
            return await self._do_tool_installation(tool_call.arguments)

        if tool_call.name not in self.tools:
            return (
                f"Error: Tool '{tool_call.name}' not available. "
                f"Available tools: {list(self.tools.keys())}"
            )

        tool = self.tools[tool_call.name]
        action_id = await self.state.log_action(
            engagement_id=self.engagement_id,
            phase=self.name,
            agent=self.__class__.__name__,
            tool=tool_call.name,
            input_data=tool_call.arguments,
        )

        try:
            self._logger.info("Calling tool '%s' — args: %s", tool_call.name, tool_call.arguments)
            validated = tool.validate_input(tool_call.arguments)
            raw_output = await tool.execute(validated)
            parsed = tool.parse_output(raw_output)
            output_json = parsed.model_dump_json(indent=2)
            await self.state.complete_action(action_id, output_data=parsed.model_dump())
            self._attach_parsed_output(tool, parsed, succeeded=True)
            return output_json
        except Exception as exc:
            self._logger.error("Tool '%s' failed: %s", tool_call.name, exc, exc_info=True)
            await self.state.complete_action(
                action_id, output_data={"error": str(exc)}, status="failed"
            )
            self._attach_parsed_output(tool, None, succeeded=False)
            return f"Tool '{tool_call.name}' failed: {exc}"

    def _attach_parsed_output(self, tool: ToolBase, parsed: Any, *, succeeded: bool) -> None:
        """Attach the parsed-output payload to the last invocation file.

        Called after :meth:`ToolBase.parse_output` so the full-fidelity
        ``tool_invocations/<seq>_<tool>.json`` file gets the structured
        Pydantic model alongside the raw stdout/stderr already recorded
        at subprocess time. No-op when no engagement-level TraceWriter is
        active or when the tool never recorded a subprocess invocation.
        """
        writer = get_active_trace_writer()
        if writer is None:
            return
        seq = getattr(tool, "last_invocation_seq", -1)
        if seq < 0:
            return
        parsed_dict: dict[str, Any] | None = None
        parsed_type = ""
        try:
            if parsed is not None:
                parsed_type = type(parsed).__name__
                if hasattr(parsed, "model_dump"):
                    parsed_dict = parsed.model_dump(mode="json")
                elif isinstance(parsed, dict):
                    parsed_dict = parsed
                else:
                    parsed_dict = {"value": str(parsed)}
        except Exception as exc:  # noqa: BLE001
            self._logger.debug("Failed to serialise parsed output: %s", exc)
        writer.attach_parsed_output(
            seq,
            parsed_output_type=parsed_type,
            parsed_output=parsed_dict,
            parse_succeeded=succeeded,
        )
