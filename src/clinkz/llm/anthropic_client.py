"""Anthropic Claude LLM client (stub — not yet implemented).

Implement after OpenAI client is stable. Claude Sonnet for agents,
Claude Opus for orchestration.
"""

from __future__ import annotations

from typing import Any

from clinkz.llm.base import AgentAction, LLMClient, LLMMessage


class AnthropicClient(LLMClient):
    """Anthropic Claude client (placeholder).

    TODO: Implement using the anthropic SDK.
    Map Claude's tool_use content blocks to ToolCall / AgentAction.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "AnthropicClient is not yet implemented. "
            "Set LLM_PROVIDER=openai in your .env to use the OpenAI client."
        )

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        raise NotImplementedError

    async def generate_text(self, prompt: str) -> str:
        raise NotImplementedError
