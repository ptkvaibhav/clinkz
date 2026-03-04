"""Abstract base class for all LLM clients.

Defines the interface every provider must implement. Agent code
only ever interacts with LLMClient — never with provider SDKs directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class ToolCall(BaseModel):
    """A tool call requested by the LLM."""

    id: str
    name: str
    arguments: dict[str, Any]


class AgentAction(BaseModel):
    """The output of a single LLM reasoning step.

    Exactly one of ``tool_call`` or ``final_answer`` will be set,
    unless the model returned a bare thought with no further action.
    """

    thought: str
    tool_call: ToolCall | None = None
    final_answer: str | None = None


class LLMMessage(BaseModel):
    """A single message in the conversation history."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: str | None = None  # populated for role="tool" messages
    tool_calls: list[ToolCall] | None = None  # populated for assistant tool-call turns


class LLMClient(ABC):
    """Abstract base class for all LLM provider clients.

    Usage::

        client = get_llm_client()          # from llm/factory.py
        action = await client.reason(messages, tools=tool_schemas)
        text   = await client.generate_text(prompt)
        info   = await client.research("CVE-2024-12345 exploit")
    """

    @abstractmethod
    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        """Run a reasoning step, optionally with tool calling.

        Args:
            messages: Conversation history (system + user + assistant turns).
            tools: JSON schema definitions of available tools in OpenAI function-calling format.

        Returns:
            AgentAction containing a thought and, if applicable, a tool call or final answer.
        """
        ...

    @abstractmethod
    async def research(self, query: str) -> str:
        """Perform web-grounded research on a security topic.

        Args:
            query: Natural-language research question
                   (e.g., "CVE-2024-1234 exploit technique for Apache 2.4.51").

        Returns:
            Research results as a plain string.
        """
        ...

    @abstractmethod
    async def generate_text(self, prompt: str) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: The input prompt.

        Returns:
            Generated text.
        """
        ...
