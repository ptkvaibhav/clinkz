"""OpenAI GPT-4o / GPT-4o-mini LLM client.

This is the primary and most complete provider implementation.
All others follow the same pattern.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion

from clinkz.config import settings
from clinkz.llm.base import (
    AgentAction,
    LLMClient,
    LLMMessage,
    OutputBudget,
    PromptLike,
    RateLimitError,
    ResearchGrounding,
    ServiceUnavailableError,
    ToolCall,
    flatten_prompt,
)

logger = logging.getLogger(__name__)


def _translate_openai_error(exc: Exception) -> Exception:
    """Translate provider-specific errors to Clinkz typed errors."""
    code = getattr(exc, "status_code", None)
    msg = str(exc).lower()
    if code == 429 or "429" in msg or "rate_limit" in msg:
        return RateLimitError(f"OpenAI rate-limited: {exc}")
    if code == 503 or "503" in msg or "overloaded" in msg or "unavailable" in msg:
        return ServiceUnavailableError(f"OpenAI 503: {exc}")
    # A per-call timeout (our asyncio.wait_for ceiling or the SDK's own) is a
    # transient condition — surface it as 503 so the resilient client falls back.
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in msg:
        return ServiceUnavailableError(f"OpenAI timed out: {exc}")
    return exc


class OpenAIClient(LLMClient):
    """OpenAI client using GPT-4o for orchestration and GPT-4o-mini for agents.

    Handles:
    - Structured tool calling (function calling API)
    - Automatic retry on transient errors
    - Token usage tracking across all calls
    """

    #: No search tool is attached on this path.
    RESEARCH_GROUNDING = ResearchGrounding.TRAINING_DATA

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
    # Core API call with a hard per-call timeout
    # ------------------------------------------------------------------

    async def _create(self, **kwargs: Any) -> ChatCompletion:
        """Call chat.completions.create with a hard per-call ceiling.

        Wrapping in asyncio.wait_for bounds a single logical call (including any
        retries the SDK performs internally) so one hung request cannot stall the
        engagement — the safety valve that matters now that the exploit phase has
        no wall-clock deadline.
        """
        return await asyncio.wait_for(
            self._client.chat.completions.create(**kwargs),
            timeout=settings.llm_request_timeout,
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

        try:
            response: ChatCompletion = await self._create(**kwargs)
        except Exception as exc:
            raise _translate_openai_error(exc) from exc
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

    async def generate_text(
        self, prompt: PromptLike, *, budget: OutputBudget = OutputBudget.DEFAULT
    ) -> str:
        """Generate text from a plain prompt without tool calling.

        Args:
            prompt: A plain string, or segments. No explicit cache
                breakpoint here, so segments are flattened and the request
                is byte-identical to the string form.

        Returns:
            Generated text content.
        """
        prompt = flatten_prompt(prompt)
        try:
            response: ChatCompletion = await self._create(
                model=self._agent_model,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:
            raise _translate_openai_error(exc) from exc
        self._track_usage(response)
        return response.choices[0].message.content or ""

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def total_tokens(self) -> int:
        """Cumulative tokens consumed in this session."""
        return self._total_tokens
