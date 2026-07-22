"""Anthropic Claude LLM client.

Uses the anthropic Python SDK with:
- claude-sonnet-5 as default model, configurable via ANTHROPIC_MODEL env var
- Native tool_use content blocks for reason()
- LLM-based research for research() (falls back to Gemini search grounding when available)
- Sliding-window rate limiting
- Exponential backoff on 429 / overloaded errors
- Per-request token usage tracking
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from anthropic import AsyncAnthropic

from clinkz.config import settings
from clinkz.llm.base import (
    AgentAction,
    LLMClient,
    LLMMessage,
    RateLimitError,
    ServiceUnavailableError,
    ToolCall,
)

logger = logging.getLogger(__name__)

_MAX_CALLS_PER_MINUTE: int = 50
_RATE_LIMIT_PERIOD: float = 60.0


class _RateLimiter:
    """Async sliding-window rate limiter."""

    def __init__(self, max_calls: int, period: float) -> None:
        self._max_calls = max_calls
        self._period = period
        self._call_times: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a call slot is available, then claim it."""
        while True:
            async with self._lock:
                now = time.monotonic()
                self._call_times = [t for t in self._call_times if now - t < self._period]
                if len(self._call_times) < self._max_calls:
                    self._call_times.append(time.monotonic())
                    return
                wait = self._period - (now - self._call_times[0])

            logger.debug("Rate limit reached — waiting %.1fs for slot", wait)
            await asyncio.sleep(max(wait, 0.1))


def _is_rate_limit_error(exc: Exception) -> bool:
    """Return True if the exception indicates HTTP 429 / quota exhaustion."""
    msg = str(exc).lower()
    code = getattr(exc, "status_code", None)
    return code == 429 or "429" in msg or "rate_limit" in msg


def _is_service_unavailable_error(exc: Exception) -> bool:
    """Return True if the exception indicates HTTP 503/529 / overloaded."""
    msg = str(exc).lower()
    code = getattr(exc, "status_code", None)
    return code in (503, 529) or "503" in msg or "529" in msg or "overloaded" in msg


def _is_timeout_error(exc: Exception) -> bool:
    """Return True if the exception is a hard per-call timeout.

    Covers both the asyncio.wait_for ceiling we enforce locally and the SDK's
    own httpx timeout, so a single slow call is retried rather than aborting.
    """
    return isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in str(exc).lower()


def _is_retriable_error(exc: Exception) -> bool:
    return _is_rate_limit_error(exc) or _is_service_unavailable_error(exc) or _is_timeout_error(exc)


class AnthropicClient(LLMClient):
    """Anthropic Claude client implementing the LLMClient interface.

    Implements:
    - ``reason()``        — tool/function calling via Claude's tool_use API
    - ``research()``      — LLM-based security research (Gemini fallback for live search)
    - ``generate_text()`` — plain text generation for reports

    Rate limiting and exponential backoff are applied to every API call.
    """

    def __init__(self, model: str | None = None) -> None:
        if not settings.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Add it to your .env file or environment."
            )
        self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._model = model or settings.anthropic_model
        self._rate_limiter = _RateLimiter(_MAX_CALLS_PER_MINUTE, _RATE_LIMIT_PERIOD)
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0

    # ------------------------------------------------------------------
    # Schema / message conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_anthropic_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI-style tool schemas to Anthropic's tool format.

        OpenAI format::

            {"name": "run_nmap", "description": "...", "parameters": {...}}

        Anthropic format::

            {"name": "run_nmap", "description": "...", "input_schema": {...}}
        """
        result: list[dict[str, Any]] = []
        for tool in tools:
            spec = tool.get("function", tool) if "function" in tool else tool
            result.append(
                {
                    "name": spec["name"],
                    "description": spec.get("description", ""),
                    "input_schema": spec.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        return result

    @staticmethod
    def _to_anthropic_messages(
        messages: list[LLMMessage],
    ) -> tuple[str | None, list[dict[str, Any]]]:
        """Convert LLMMessage list to (system_prompt, messages) for Anthropic API.

        - ``system`` role → extracted as the top-level system parameter
        - ``user`` role → {"role": "user", "content": [{"type": "text", ...}]}
        - ``assistant`` role → with optional tool_use blocks
        - ``tool`` role → {"role": "user", "content": [{"type": "tool_result", ...}]}

        Returns:
            Tuple of (system_prompt_string_or_None, list_of_message_dicts).
        """
        system_prompt: str | None = None
        result: list[dict[str, Any]] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
                continue

            if msg.role == "user":
                result.append(
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": msg.content}],
                    }
                )
                continue

            if msg.role == "assistant":
                content: list[dict[str, Any]] = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        content.append(
                            {
                                "type": "tool_use",
                                "id": tc.id,
                                "name": tc.name,
                                "input": tc.arguments,
                            }
                        )
                result.append({"role": "assistant", "content": content})
                continue

            if msg.role == "tool":
                result.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id or "",
                                "content": msg.content,
                            }
                        ],
                    }
                )

        return system_prompt, result

    # ------------------------------------------------------------------
    # Core API call with rate limiting + exponential backoff
    # ------------------------------------------------------------------

    async def _call_with_backoff(self, **kwargs: Any) -> Any:
        """Execute an API call with rate limiting and bounded exponential backoff.

        Retry budget and caps come from ``settings.llm_max_retries`` /
        ``llm_retry_base_delay`` / ``llm_retry_max_delay`` so the resilient
        wrapper can move on quickly when a provider is persistently down.

        Raises:
            RateLimitError: retries exhausted on a 429.
            ServiceUnavailableError: retries exhausted on a 503/529.
        """
        max_retries = max(1, settings.llm_max_retries)
        base_delay = settings.llm_retry_base_delay
        max_delay = settings.llm_retry_max_delay
        last_exc: Exception | None = None

        for attempt in range(max_retries):
            try:
                await self._rate_limiter.acquire()
                # Hard per-call ceiling so a single hung request cannot stall the
                # engagement (the exploit phase no longer has a wall-clock
                # deadline; op-level timeouts are the safety valve).
                return await asyncio.wait_for(
                    self._client.messages.create(**kwargs),
                    timeout=settings.llm_request_timeout,
                )
            except Exception as exc:
                last_exc = exc
                if _is_retriable_error(exc) and attempt < max_retries - 1:
                    wait = min(base_delay * (2**attempt), max_delay)
                    logger.warning(
                        "Retriable error (attempt %d/%d) — retrying in %.0fs: %s",
                        attempt + 1,
                        max_retries,
                        wait,
                        exc,
                    )
                    await asyncio.sleep(wait)
                    continue
                if _is_rate_limit_error(exc):
                    raise RateLimitError(f"Anthropic rate-limited: {exc}") from exc
                if _is_service_unavailable_error(exc):
                    raise ServiceUnavailableError(f"Anthropic 503/529: {exc}") from exc
                raise

        raise RateLimitError(f"Anthropic exhausted retries: {last_exc}")  # pragma: no cover

    def _track_usage(self, response: Any) -> None:
        """Accumulate token counts from an Anthropic response."""
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        inp = getattr(usage, "input_tokens", 0) or 0
        out = getattr(usage, "output_tokens", 0) or 0
        self._total_input_tokens += inp
        self._total_output_tokens += out
        logger.debug(
            "Token usage — input: %d, output: %d | session total in/out: %d/%d",
            inp,
            out,
            self._total_input_tokens,
            self._total_output_tokens,
        )

    # ------------------------------------------------------------------
    # LLMClient interface
    # ------------------------------------------------------------------

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        """Call Claude with optional tool calling and return an AgentAction.

        Converts OpenAI-style tool schemas to Anthropic's tool_use format.
        Processes the response's content blocks to extract text thoughts
        and tool_use calls.

        Args:
            messages: Full conversation history in LLMMessage format.
            tools: Tool schemas in OpenAI function format.

        Returns:
            AgentAction with thought and optional tool_call or final_answer.
        """
        system_prompt, api_messages = self._to_anthropic_messages(messages)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": api_messages,
            "max_tokens": 4096,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = self._to_anthropic_tools(tools)

        response = await self._call_with_backoff(**kwargs)
        self._track_usage(response)

        # Extract thought text and tool_use from content blocks
        thought = ""
        tool_call: ToolCall | None = None

        for block in response.content:
            if block.type == "text":
                thought = block.text
            elif block.type == "tool_use":
                tool_call = ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                )

        if tool_call:
            return AgentAction(thought=thought, tool_call=tool_call)
        return AgentAction(thought=thought, final_answer=thought)

    async def research(self, query: str) -> str:
        """Research a security topic using Claude's knowledge.

        Since Anthropic's API doesn't have built-in web search grounding,
        this uses Claude's training knowledge for research. For live web
        search data, attempts to fall back to Gemini's search grounding
        when a Gemini API key is available.

        Args:
            query: Security-focused research question.

        Returns:
            Research findings as a plain string.
        """
        # Try Gemini search grounding first for live data
        gemini_key = settings.gemini_api_key or settings.google_api_key
        if gemini_key:
            try:
                from clinkz.llm.gemini_client import GeminiClient

                gemini = GeminiClient()
                return await gemini.research(query)
            except Exception as exc:
                logger.debug("Gemini search fallback failed, using Claude: %s", exc)

        # Fall back to Claude's training knowledge
        prompt = (
            "You are an expert penetration tester and vulnerability researcher. "
            "Provide detailed, actionable information on the following topic. "
            "Include: relevant CVEs with IDs and severity, affected versions, "
            "exploit techniques with specific steps, PoC availability, "
            "mitigations, and any known bug bounty writeups.\n\n"
            f"Topic: {query}"
        )
        return await self.generate_text(prompt)

    async def generate_text(self, prompt: str) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: The input prompt.

        Returns:
            Generated text content.
        """
        response = await self._call_with_backoff(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
        )
        self._track_usage(response)

        # Extract all text blocks
        texts: list[str] = []
        for block in response.content:
            if block.type == "text":
                texts.append(block.text)
        return "\n".join(texts)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def total_tokens(self) -> int:
        """Total tokens consumed (input + output) in this session."""
        return self._total_input_tokens + self._total_output_tokens

    @property
    def total_input_tokens(self) -> int:
        """Total input tokens consumed in this session."""
        return self._total_input_tokens

    @property
    def total_output_tokens(self) -> int:
        """Total output tokens consumed in this session."""
        return self._total_output_tokens
