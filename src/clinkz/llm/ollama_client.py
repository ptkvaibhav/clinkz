"""Ollama local model LLM client (stub — not yet implemented).

Implement last. Useful for air-gapped environments or privacy-sensitive engagements.
Requires Ollama to be running locally with a tool-capable model (e.g., llama3, mistral).
"""

from __future__ import annotations

from typing import Any

from clinkz.llm.base import AgentAction, LLMClient, LLMMessage


class OllamaClient(LLMClient):
    """Ollama local model client (placeholder).

    TODO: Implement using the ollama Python SDK.
    Note: tool calling support varies by model — verify before using.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "OllamaClient is not yet implemented. "
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
