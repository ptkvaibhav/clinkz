"""Base agent class implementing the ReAct (Reasoning + Acting) loop.

Every phase agent inherits from BaseAgent and overrides:
- name       — identifier used in logs and state store
- system_prompt — loaded from agents/prompts/<name>.txt
- run()      — entry point called by the Orchestrator

The core loop is _react_loop():
    1. Observe  — receive initial context
    2. Reason   — call LLM with conversation history + tool schemas
    3. Act      — execute the chosen tool
    4. Reflect  — add tool result to history, repeat from Reason
    5. Done     — LLM returns a final_answer (no tool call)

Between ReAct iterations the agent drains its inbox queue.  The lifecycle
manager (or tests) can inject AgentMessage objects via receive_message()
at any time; QUERY messages are folded into the LLM conversation so the
agent can incorporate them without stopping its current task.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.knowledge.skills_loader import SkillsLoader
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

if TYPE_CHECKING:
    from clinkz.comms.bus import MessageBus
    from clinkz.knowledge.query import KnowledgeBase

logger = logging.getLogger(__name__)

# Default iteration limits per agent type.  Agents override via the
# ``max_iterations`` property so each phase gets the budget it needs.
DEFAULT_MAX_ITERATIONS: dict[str, int] = {
    "recon": 20,
    "scan": 20,
    "exploit": 25,
    "report": 10,
    "critic": 10,
}

# Fallback when an agent name is not in the map above.
_FALLBACK_MAX_ITERATIONS = 20


class BaseAgent(ABC):
    """Abstract base for all Clinkz phase agents.

    Provides the ReAct loop, tool dispatch, and state logging.
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
    ) -> None:
        self.llm = llm
        self.tools: dict[str, ToolBase] = {t.name: t for t in tools}
        self.scope = scope
        self.state = state
        self.engagement_id = engagement_id
        self.knowledge_base = knowledge_base
        self._bus: MessageBus | None = bus
        self._skills_loader = SkillsLoader()
        self.messages: list[LLMMessage] = []
        self._inbox: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._pending_responses: dict[str, AgentMessage] = {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Iteration limit — per-agent, configurable
    # ------------------------------------------------------------------

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

        # Wait for RESPONSE with matching parent_message_id (timeout 120s)
        timeout = 120.0
        poll_interval = 1.0
        elapsed = 0.0

        while elapsed < timeout:
            # Check if the response arrived via _process_inbox
            if query_msg.id in self._pending_responses:
                response_msg = self._pending_responses.pop(query_msg.id)
                response_text = response_msg.content.get(
                    "response", str(response_msg.content)
                )
                self._logger.info("request_help response received (%d chars)", len(response_text))
                return response_text

            # Check inbox directly for new messages
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
                # Not our response — re-queue it
                self._inbox.put_nowait(msg)
            except asyncio.QueueEmpty:
                pass

            await asyncio.sleep(poll_interval)
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
    # ReAct loop
    # ------------------------------------------------------------------

    def _build_system_prompt_with_skills(self) -> str:
        """Append available skill names and reasoning discipline to the system prompt.

        Returns:
            The agent's system prompt with skills summary and reasoning
            discipline instructions appended.
        """
        skills_summary = self._skills_loader.get_skill_names_summary()
        reasoning_block = (
            "\n\n## Reasoning Discipline\n\n"
            "Before executing ANY tool call, you MUST include a structured reasoning "
            "block in your thought. This is mandatory — never skip it.\n\n"
            "```\n"
            "OBSERVATION: What I just learned from the last result\n"
            "HYPOTHESIS: What I think is happening and why\n"
            "NEXT_ACTION: What I will do next and what I expect to see\n"
            "STOP_CONDITION: When I will stop this approach and try something else\n"
            "```\n\n"
            "Follow this structure for every single reasoning step. If you find "
            "yourself acting without stating your hypothesis first, STOP and reason."
        )
        return f"{self.system_prompt}\n\n## Skills\n\n{skills_summary}{reasoning_block}"

    async def _react_loop(self, initial_observation: str) -> str:
        """Run the Observe → Reason → Act → Reflect loop.

        Includes:
        - Reasoning discipline: skills summary and structured reasoning
          instructions are injected into the system prompt.
        - Failure tracking: if the same tool fails 3 consecutive times
          with the same error, a skip message is injected.
        - Repetition detection: if the same tool is called with the same
          arguments 3 times (regardless of success/failure), a nudge is
          injected to try a different approach.

        Args:
            initial_observation: The task description / starting context.

        Returns:
            Final answer text from the LLM.
        """
        self.messages = [
            LLMMessage(role="system", content=self._build_system_prompt_with_skills()),
            LLMMessage(role="user", content=initial_observation),
        ]
        tool_schemas = self._get_tool_schemas()
        limit = self.max_iterations

        # Failure tracking: (tool_name, error_message) → consecutive count
        _last_failure_key: tuple[str, str] | None = None
        _consecutive_failures: int = 0
        _max_consecutive_failures = 3

        # Repetition tracking: (tool_name, args_json) → consecutive count
        _last_call_key: tuple[str, str] | None = None
        _consecutive_same_calls: int = 0
        _max_same_calls = 3

        for iteration in range(limit):
            self._logger.debug("ReAct iteration %d/%d", iteration + 1, limit)

            # Warn the LLM when it's about to hit the iteration limit
            if iteration == limit - 2:
                self._logger.info(
                    "Agent '%s' approaching max iterations — injecting wrap-up prompt",
                    self.name,
                )
                self.messages.append(
                    LLMMessage(
                        role="system",
                        content=(
                            "You have 2 iterations remaining before the hard limit. "
                            "Summarize your findings and return final_answer now. "
                            "Do not start new tool calls."
                        ),
                    )
                )

            # Reason
            action: AgentAction = await self.llm.reason(self.messages, tools=tool_schemas)

            # Done?
            if action.final_answer is not None:
                self._logger.info("Agent '%s' done after %d iteration(s)", self.name, iteration + 1)
                return action.final_answer

            # Act
            if action.tool_call:
                self.messages.append(
                    LLMMessage(
                        role="assistant",
                        content=action.thought,
                        tool_calls=[action.tool_call],
                    )
                )

                # --- Repetition detection (same tool + same args) ---
                call_key = (
                    action.tool_call.name,
                    json.dumps(action.tool_call.arguments, sort_keys=True),
                )
                if call_key == _last_call_key:
                    _consecutive_same_calls += 1
                else:
                    _last_call_key = call_key
                    _consecutive_same_calls = 1

                if _consecutive_same_calls >= _max_same_calls:
                    self._logger.warning(
                        "Agent '%s' repeated '%s' with same args %d times — injecting redirect",
                        self.name,
                        action.tool_call.name,
                        _consecutive_same_calls,
                    )
                    self.messages.append(
                        LLMMessage(
                            role="system",
                            content=(
                                "You are repeating yourself. You have called "
                                f"'{action.tool_call.name}' with the same arguments "
                                f"{_consecutive_same_calls} times. State what you learned "
                                "from previous attempts and try a DIFFERENT approach. "
                                "Use your reasoning discipline:\n"
                                "OBSERVATION: What did the repeated calls tell you?\n"
                                "HYPOTHESIS: Why isn't this working?\n"
                                "NEXT_ACTION: What DIFFERENT action will you try?\n"
                                "STOP_CONDITION: When will you move on entirely?"
                            ),
                        )
                    )
                    _last_call_key = None
                    _consecutive_same_calls = 0

                tool_result = await self._execute_tool(action.tool_call)

                # Track consecutive failures for the same tool+error
                is_failure = (
                    tool_result.startswith(("Error:", "Tool '")) and "failed" in tool_result
                )
                if is_failure:
                    failure_key = (action.tool_call.name, tool_result)
                    if failure_key == _last_failure_key:
                        _consecutive_failures += 1
                    else:
                        _last_failure_key = failure_key
                        _consecutive_failures = 1

                    if _consecutive_failures >= _max_consecutive_failures:
                        self._logger.warning(
                            "Tool '%s' failed %d times with same error — injecting skip directive",
                            action.tool_call.name,
                            _consecutive_failures,
                        )
                        tool_result += (
                            f"\n\n[SYSTEM] Tool '{action.tool_call.name}' has failed "
                            f"{_consecutive_failures} consecutive times with the same error. "
                            "Stop retrying this tool and move on to the next item in your "
                            "checklist. Mark this attempt as failed and proceed."
                        )
                        # Reset so we can detect a new loop on a different tool
                        _last_failure_key = None
                        _consecutive_failures = 0
                else:
                    # Success — reset failure tracking
                    _last_failure_key = None
                    _consecutive_failures = 0

                self.messages.append(
                    LLMMessage(
                        role="tool",
                        content=tool_result,
                        tool_call_id=action.tool_call.id,
                    )
                )
                # Check for incoming messages between ReAct iterations
                await self._process_inbox()
            else:
                # LLM returned a thought with no tool call and no final answer
                self._logger.warning("LLM returned bare thought — treating as final answer")
                return action.thought

        self._logger.warning("Max iterations (%d) reached for agent '%s'", limit, self.name)
        return "Max iterations reached without a final answer."

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
            return output_json
        except Exception as exc:
            self._logger.error("Tool '%s' failed: %s", tool_call.name, exc, exc_info=True)
            await self.state.complete_action(
                action_id, output_data={"error": str(exc)}, status="failed"
            )
            return f"Tool '{tool_call.name}' failed: {exc}"
