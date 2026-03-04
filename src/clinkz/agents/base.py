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
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 20


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
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
    ) -> None:
        self.llm = llm
        self.tools: dict[str, ToolBase] = {t.name: t for t in tools}
        self.scope = scope
        self.state = state
        self.engagement_id = engagement_id
        self.messages: list[LLMMessage] = []
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

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
    # ReAct loop
    # ------------------------------------------------------------------

    async def _react_loop(self, initial_observation: str) -> str:
        """Run the Observe → Reason → Act → Reflect loop.

        Args:
            initial_observation: The task description / starting context.

        Returns:
            Final answer text from the LLM.
        """
        self.messages = [
            LLMMessage(role="system", content=self.system_prompt),
            LLMMessage(role="user", content=initial_observation),
        ]
        tool_schemas = [t.get_schema() for t in self.tools.values()]

        for iteration in range(MAX_ITERATIONS):
            self._logger.debug("ReAct iteration %d/%d", iteration + 1, MAX_ITERATIONS)

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
                tool_result = await self._execute_tool(action.tool_call)
                self.messages.append(
                    LLMMessage(
                        role="tool",
                        content=tool_result,
                        tool_call_id=action.tool_call.id,
                    )
                )
            else:
                # LLM returned a thought with no tool call and no final answer
                self._logger.warning("LLM returned bare thought — treating as final answer")
                return action.thought

        self._logger.warning(
            "Max iterations (%d) reached for agent '%s'", MAX_ITERATIONS, self.name
        )
        return "Max iterations reached without a final answer."

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _execute_tool(self, tool_call: ToolCall) -> str:
        """Dispatch a tool call and return the result as a JSON string.

        Logs the action to the state store and handles errors gracefully
        so a single tool failure doesn't crash the whole loop.

        Args:
            tool_call: ToolCall from the LLM.

        Returns:
            Tool output serialised to JSON, or an error message string.
        """
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
