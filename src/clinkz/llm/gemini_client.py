"""Google Gemini LLM client (stub — not yet implemented).

Implement after Anthropic client. Gemini Pro has built-in search grounding
which makes it ideal for the research() method.
"""

from __future__ import annotations

from typing import Any

from clinkz.llm.base import AgentAction, LLMClient, LLMMessage


class GeminiClient(LLMClient):
    """Google Gemini client (placeholder).

    TODO: Implement using google-generativeai SDK.
    Use Gemini's native search grounding for the research() method.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "GeminiClient is not yet implemented. "
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
