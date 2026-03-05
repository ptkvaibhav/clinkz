"""Google Gemini LLM client.

Uses google-genai SDK with:
- gemini-2.5-flash for all calls
- Native Google Search grounding for research() (live CVE/exploit data)
- Function calling for reason()
- Sliding-window rate limiting (5 req/min, free tier safe)
- Exponential backoff on 429 / quota errors
- Per-request token usage tracking
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from google import genai
from google.genai import types

from clinkz.config import settings
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall

logger = logging.getLogger(__name__)

_MAX_CALLS_PER_MINUTE: int = 5
_RATE_LIMIT_PERIOD: float = 60.0
_MAX_RETRIES: int = 4


class _RateLimiter:
    """Async sliding-window rate limiter.

    Tracks call timestamps and blocks callers when the window is full.
    The lock is released before sleeping so other coroutines can check in.
    """

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
                # Evict timestamps outside the sliding window
                self._call_times = [t for t in self._call_times if now - t < self._period]
                if len(self._call_times) < self._max_calls:
                    self._call_times.append(time.monotonic())
                    return
                # Calculate wait time, then release lock before sleeping
                wait = self._period - (now - self._call_times[0])

            logger.debug("Rate limit reached — waiting %.1fs for slot", wait)
            await asyncio.sleep(max(wait, 0.1))


def _is_rate_limit_error(exc: Exception) -> bool:
    """Return True if the exception indicates a 429 / quota exhaustion."""
    msg = str(exc).lower()
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    return code == 429 or "429" in msg or "resource exhausted" in msg or "quota" in msg


class GeminiClient(LLMClient):
    """Google Gemini client using gemini-2.5-flash.

    Implements the LLMClient interface for all three methods:

    - ``reason()``        — function calling via Gemini's tool API
    - ``research()``      — Google Search grounding for live security intel
    - ``generate_text()`` — plain generation for report narratives

    Rate limiting and exponential backoff are applied transparently to every
    SDK call via ``_call_with_backoff()``.
    """

    def __init__(self, model: str | None = None) -> None:
        api_key = settings.gemini_api_key or settings.google_api_key
        if not api_key:
            raise ValueError(
                "Neither GEMINI_API_KEY nor GOOGLE_API_KEY is set. "
                "Add one to your .env file."
            )
        self._client = genai.Client(api_key=api_key)
        self._model_name = model or settings.gemini_model
        self._rate_limiter = _RateLimiter(_MAX_CALLS_PER_MINUTE, _RATE_LIMIT_PERIOD)
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0

    # ------------------------------------------------------------------
    # Schema / message conversion helpers
    # ------------------------------------------------------------------

    def _to_gemini_tools(self, tools: list[dict[str, Any]]) -> list[types.Tool]:
        """Convert OpenAI-style tool schemas to a Gemini Tool with FunctionDeclarations.

        OpenAI format::

            {"name": "run_nmap", "description": "...", "parameters": {...}}

        All declarations are bundled in a single Tool object.
        """
        declarations = [
            types.FunctionDeclaration(
                name=tool["name"],
                description=tool.get("description", ""),
                parameters=tool.get("parameters", {}),
            )
            for tool in tools
        ]
        return [types.Tool(function_declarations=declarations)]

    def _to_gemini_contents(
        self, messages: list[LLMMessage]
    ) -> tuple[str | None, list[types.Content]]:
        """Convert LLMMessage list to (system_instruction, contents).

        - ``system`` role → extracted as Gemini's system_instruction string
        - ``user``    role → Content(role="user", parts=[Part(text=...)])
        - ``assistant`` role → Content(role="model", parts=[...])
        - ``tool`` role → Content with function_response Part (user role in Gemini)

        Note: ``tool_call_id`` on tool-role messages is expected to be the
        *function name* — the convention used when GeminiClient creates ToolCalls.
        """
        system_instruction: str | None = None
        contents: list[types.Content] = []

        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
                continue

            if msg.role == "user":
                contents.append(
                    types.Content(role="user", parts=[types.Part(text=msg.content)])
                )
                continue

            if msg.role == "assistant":
                parts: list[types.Part] = []
                if msg.content:
                    parts.append(types.Part(text=msg.content))
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append(
                            types.Part(
                                function_call=types.FunctionCall(
                                    name=tc.name, args=tc.arguments
                                )
                            )
                        )
                contents.append(types.Content(role="model", parts=parts))
                continue

            if msg.role == "tool":
                # Gemini expects function results as user-role function_response Parts.
                # tool_call_id stores the function name in GeminiClient convention.
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part(
                                function_response=types.FunctionResponse(
                                    name=msg.tool_call_id or "unknown",
                                    response={"result": msg.content},
                                )
                            )
                        ],
                    )
                )

        return system_instruction, contents

    # ------------------------------------------------------------------
    # Core API call with rate limiting + exponential backoff
    # ------------------------------------------------------------------

    async def _call_with_backoff(
        self,
        coro_factory: Callable[[], Coroutine[Any, Any, Any]],
    ) -> Any:
        """Execute a coroutine factory with rate limiting and exponential backoff.

        Retries up to ``_MAX_RETRIES`` times on 429 / quota errors, waiting
        2^attempt seconds between attempts (1s, 2s, 4s, 8s).

        Args:
            coro_factory: Callable that returns a fresh coroutine each time.
        """
        for attempt in range(_MAX_RETRIES):
            try:
                await self._rate_limiter.acquire()
                return await coro_factory()
            except Exception as exc:
                if _is_rate_limit_error(exc) and attempt < _MAX_RETRIES - 1:
                    wait = 2**attempt
                    logger.warning(
                        "Rate limit hit (attempt %d/%d) — retrying in %ds: %s",
                        attempt + 1,
                        _MAX_RETRIES,
                        wait,
                        exc,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

    def _track_usage(self, response: Any) -> None:
        """Accumulate token counts from a Gemini response and log them."""
        meta = getattr(response, "usage_metadata", None)
        if meta is None:
            return
        inp = getattr(meta, "prompt_token_count", 0) or 0
        out = getattr(meta, "candidates_token_count", 0) or 0
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
        """Call Gemini with optional function calling and return an AgentAction.

        Converts OpenAI-style tool schemas to Gemini FunctionDeclarations.
        Uses the function name as ToolCall.id so that subsequent tool-role
        messages can be mapped back to their function_response correctly.

        Args:
            messages: Full conversation history in LLMMessage format.
            tools: Tool schemas in OpenAI function format (name/description/parameters).

        Returns:
            AgentAction with thought and optional tool_call or final_answer.
        """
        system_instruction, contents = self._to_gemini_contents(messages)

        config_kwargs: dict[str, Any] = {}
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction
        if tools:
            config_kwargs["tools"] = self._to_gemini_tools(tools)

        config = types.GenerateContentConfig(**config_kwargs) if config_kwargs else None

        def _make_coro() -> Coroutine[Any, Any, Any]:
            kwargs: dict[str, Any] = {
                "model": self._model_name,
                "contents": contents,
            }
            if config is not None:
                kwargs["config"] = config
            return self._client.aio.models.generate_content(**kwargs)

        response = await self._call_with_backoff(_make_coro)
        self._track_usage(response)

        candidate = response.candidates[0]
        thought = ""
        tool_call: ToolCall | None = None

        for part in candidate.content.parts:
            text = getattr(part, "text", None)
            if text:
                thought = text
            fc = getattr(part, "function_call", None)
            if fc and getattr(fc, "name", None):
                # Use function name as ID so tool-role responses can reference it
                tool_call = ToolCall(
                    id=fc.name,
                    name=fc.name,
                    arguments=dict(fc.args) if fc.args else {},
                )

        if tool_call:
            return AgentAction(thought=thought, tool_call=tool_call)
        return AgentAction(thought=thought, final_answer=thought)

    async def research(self, query: str) -> str:
        """Research a security topic using Gemini with Google Search grounding.

        Leverages Gemini's native search grounding to retrieve live CVE data,
        exploit techniques, PoC availability, and bug bounty writeups.

        Args:
            query: Security-focused research question.

        Returns:
            Research findings as a plain string.
        """
        system = (
            "You are an expert penetration tester and vulnerability researcher. "
            "Use Google Search to find current, accurate information. "
            "Provide detailed, actionable findings including: relevant CVEs, "
            "affected versions, exploit techniques, PoC availability, mitigations, "
            "and any known bug bounty writeups."
        )
        config = types.GenerateContentConfig(
            tools=[types.Tool(google_search=types.GoogleSearch())],
            system_instruction=system,
        )

        def _make_coro() -> Coroutine[Any, Any, Any]:
            return self._client.aio.models.generate_content(
                model=self._model_name,
                contents=query,
                config=config,
            )

        response = await self._call_with_backoff(_make_coro)
        self._track_usage(response)
        return response.text

    async def generate_text(self, prompt: str) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: The input prompt.

        Returns:
            Generated text content.
        """

        def _make_coro() -> Coroutine[Any, Any, Any]:
            return self._client.aio.models.generate_content(
                model=self._model_name,
                contents=prompt,
            )

        response = await self._call_with_backoff(_make_coro)
        self._track_usage(response)
        return response.text

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def total_tokens(self) -> int:
        """Total tokens consumed (input + output) in this session."""
        return self._total_input_tokens + self._total_output_tokens

    @property
    def total_input_tokens(self) -> int:
        """Total input/prompt tokens consumed in this session."""
        return self._total_input_tokens

    @property
    def total_output_tokens(self) -> int:
        """Total output/completion tokens consumed in this session."""
        return self._total_output_tokens
