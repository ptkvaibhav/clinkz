"""OpenAI GPT-4o / GPT-4o-mini LLM client.

This is the primary and most complete provider implementation.
All others follow the same pattern.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion

from clinkz.config import settings
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall

logger = logging.getLogger(__name__)


class OpenAIClient(LLMClient):
    """OpenAI client using GPT-4o for orchestration and GPT-4o-mini for agents.

    Handles:
    - Structured tool calling (function calling API)
    - Automatic retry on transient errors
    - Token usage tracking across all calls
    """

    def __init__(
        self,
        agent_model: str | None = None,
        orchestrator_model: str | None = None,
    ) -> None:
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not set. Add it to your .env file or environment.")
        self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        self._agent_model = agent_model or settings.agent_model
        self._orchestrator_model = orchestrator_model or settings.orchestrator_model
        self._total_tokens: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_openai_messages(self, messages: list[LLMMessage]) -> list[dict[str, Any]]:
        """Convert internal LLMMessage list to OpenAI wire format."""
        result: list[dict[str, Any]] = []
        for msg in messages:
            m: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_call_id:
                m["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                m["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            result.append(m)
        return result

    def _to_openai_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Wrap tool schemas in OpenAI's function-calling envelope."""
        return [{"type": "function", "function": t} for t in tools]

    def _track_usage(self, response: ChatCompletion) -> None:
        if response.usage:
            self._total_tokens += response.usage.total_tokens
            logger.debug(
                "Token usage — request: %d, total session: %d",
                response.usage.total_tokens,
                self._total_tokens,
            )

    # ------------------------------------------------------------------
    # LLMClient interface
    # ------------------------------------------------------------------

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        """Call GPT-4o with optional tool calling and return an AgentAction.

        Args:
            messages: Full conversation history.
            tools: Tool schemas in OpenAI function format.

        Returns:
            AgentAction with thought and optional tool_call or final_answer.
        """
        kwargs: dict[str, Any] = {
            "model": self._agent_model,
            "messages": self._to_openai_messages(messages),
        }
        if tools:
            kwargs["tools"] = self._to_openai_tools(tools)
            kwargs["tool_choice"] = "auto"

        response: ChatCompletion = await self._client.chat.completions.create(**kwargs)
        self._track_usage(response)

        choice = response.choices[0]
        message = choice.message
        thought = message.content or ""

        if message.tool_calls:
            tc = message.tool_calls[0]  # process first tool call per turn
            return AgentAction(
                thought=thought,
                tool_call=ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=json.loads(tc.function.arguments),
                ),
            )

        return AgentAction(thought=thought, final_answer=thought)

    async def research(self, query: str) -> str:
        """Research a security topic using the model's training knowledge.

        Note: Upgrade to GPT-4o with Bing search plugin or Perplexity API
        for live web access if needed.

        Args:
            query: Security-focused research question.

        Returns:
            Research findings as text.
        """
        prompt = (
            "You are an expert penetration tester and vulnerability researcher. "
            "Provide detailed, actionable information on the following topic. "
            "Include: relevant CVEs, affected versions, exploit techniques, PoC availability, "
            "mitigations, and any known bug bounty writeups.\n\n"
            f"Topic: {query}"
        )
        return await self.generate_text(prompt)

    async def generate_text(self, prompt: str) -> str:
        """Generate text from a plain prompt without tool calling.

        Args:
            prompt: The input prompt.

        Returns:
            Generated text content.
        """
        response: ChatCompletion = await self._client.chat.completions.create(
            model=self._agent_model,
            messages=[{"role": "user", "content": prompt}],
        )
        self._track_usage(response)
        return response.choices[0].message.content or ""

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def total_tokens(self) -> int:
        """Cumulative tokens consumed in this session."""
        return self._total_tokens
