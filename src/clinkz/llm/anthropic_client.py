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
    CallStats,
    EmptyResponseError,
    LLMClient,
    LLMMessage,
    PromptLike,
    RateLimitError,
    ServiceUnavailableError,
    ToolCall,
    as_prompt_segments,
)

logger = logging.getLogger(__name__)

_MAX_CALLS_PER_MINUTE: int = 50
_RATE_LIMIT_PERIOD: float = 60.0

#: Minimum cacheable prefix, in tokens, per model family. Below this the API
#: silently declines to cache — no error, ``cache_creation_input_tokens: 0`` —
#: so a breakpoint on a short prefix buys nothing and hides that it bought
#: nothing. The floor is **not monotonic across generations**: it is 512 on the
#: newest models and 4096 on Opus 4.6/4.5 and Haiku 4.5, so it has to be looked
#: up rather than assumed. Prefix match is longest-first.
_CACHE_MIN_PREFIX_TOKENS: tuple[tuple[str, int], ...] = (
    ("claude-opus-4-6", 4096),
    ("claude-opus-4-5", 4096),
    ("claude-haiku-4-5", 4096),
    ("claude-opus-4-7", 2048),
    # Stated rather than left to the default, so the value the run depends on is
    # the documented one for the model we actually ship with rather than a
    # fallback that happens to agree with it today.
    ("claude-sonnet-5", 1024),
    ("claude-sonnet-4-6", 1024),
    ("claude-opus-4-8", 1024),
    ("claude-opus-5", 512),
    ("claude-fable-5", 512),
    ("claude-mythos-5", 512),
)

#: Fallback floor for a model we have no entry for. 1024 is the value for the
#: Opus 4.8 / Sonnet 5 / Sonnet 4.6 generation and is the safe assumption: too
#: high only costs a cache we could have had, while too low would attach
#: breakpoints that never engage and report a hit rate that never materialises.
_CACHE_MIN_PREFIX_TOKENS_DEFAULT: int = 1024

#: Chars per token used only to decide whether a prefix clears the floor. A
#: deliberate underestimate of tokens (4 chars/token) so a borderline prefix is
#: judged too short rather than wrongly marked cacheable.
_CHARS_PER_TOKEN: int = 4


def cache_min_prefix_tokens(model: str) -> int:
    """Return the minimum cacheable prefix, in tokens, for *model*."""
    for prefix, floor in _CACHE_MIN_PREFIX_TOKENS:
        if model.startswith(prefix):
            return floor
    return _CACHE_MIN_PREFIX_TOKENS_DEFAULT


#: Conservative output rate, in tokens/second, used ONLY to derive a timeout
#: floor. Deliberately pessimistic: a thinking-capable model spends part of the
#: allowance reasoning, and the cost of guessing low is a timeout on a request
#: that was about to succeed.
_MIN_OUTPUT_TOKENS_PER_SECOND: float = 30.0

#: Absolute ceiling on the derived floor. Matches the Anthropic SDK's own
#: default client timeout, which is what a non-streaming request is bounded by
#: anyway — deriving something longer would be a number no request can reach.
_MAX_DERIVED_TIMEOUT_SECONDS: float = 600.0


def request_timeout_for(max_output_tokens: int) -> float:
    """Per-call timeout, never shorter than the configured output ceiling needs.

    ``llm_request_timeout`` and ``llm_max_output_tokens`` are separate settings
    that can silently contradict each other, and the default pair did: a
    16000-token non-streaming completion cannot finish inside 120 s, so the
    exploit planner's Anthropic call timed out three times and the chain fell
    through to Gemini — quietly changing which model planned the engagement.
    Measured directly: the same two planning calls that time out at 120 s both
    complete at 600 s.

    So the configured timeout is treated as a floor to raise, not a ceiling to
    respect. The derived value is capped at the SDK's own default client
    timeout, because a non-streaming request is bounded by that regardless.

    Args:
        max_output_tokens: The ``max_tokens`` this request actually carries.

    Returns:
        The timeout, in seconds, to bound this call with.
    """
    configured = float(settings.llm_request_timeout)
    if max_output_tokens <= 0:
        return configured
    needed = min(max_output_tokens / _MIN_OUTPUT_TOKENS_PER_SECOND, _MAX_DERIVED_TIMEOUT_SECONDS)
    if needed <= configured:
        return configured
    logger.info(
        "Raising per-call timeout %.0fs -> %.0fs: max_tokens=%d cannot complete in the "
        "configured window (non-streaming, ~%.0f tok/s floor)",
        configured,
        needed,
        max_output_tokens,
        _MIN_OUTPUT_TOKENS_PER_SECOND,
    )
    return needed


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
        self._total_cache_creation_tokens: int = 0
        self._total_cache_read_tokens: int = 0
        self.last_call_stats: CallStats | None = None

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
                    timeout=request_timeout_for(int(kwargs.get("max_tokens") or 0)),
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

    def _track_usage(self, response: Any) -> CallStats:
        """Accumulate token counts and publish stats for the call just served.

        ``input_tokens`` from the API is the **uncached remainder only**, so it
        is recorded as-is and the cache counters are kept beside it rather than
        folded in — the sum is the real prompt size, and conflating them would
        make a working cache look like a shrinking prompt.
        """
        stats = CallStats(provider="anthropic", model=self._model)
        usage = getattr(response, "usage", None)
        if usage is not None:
            stats.input_tokens = getattr(usage, "input_tokens", 0) or 0
            stats.output_tokens = getattr(usage, "output_tokens", 0) or 0
            stats.cache_creation_input_tokens = (
                getattr(usage, "cache_creation_input_tokens", 0) or 0
            )
            stats.cache_read_input_tokens = getattr(usage, "cache_read_input_tokens", 0) or 0
        stats.stop_reason = getattr(response, "stop_reason", None)

        self._total_input_tokens += stats.input_tokens
        self._total_output_tokens += stats.output_tokens
        self._total_cache_creation_tokens += stats.cache_creation_input_tokens
        self._total_cache_read_tokens += stats.cache_read_input_tokens
        self.last_call_stats = stats

        logger.debug(
            "Token usage — input: %d, output: %d, cache_write: %d, cache_read: %d "
            "| session total in/out: %d/%d",
            stats.input_tokens,
            stats.output_tokens,
            stats.cache_creation_input_tokens,
            stats.cache_read_input_tokens,
            self._total_input_tokens,
            self._total_output_tokens,
        )
        return stats

    # ------------------------------------------------------------------
    # Prompt assembly (incl. the cache breakpoint)
    # ------------------------------------------------------------------

    def _system_blocks_for(self, stable: str) -> list[dict[str, Any]] | None:
        """Render the run-stable prefix as a system block, cached when worthwhile.

        The breakpoint goes on the **last system block**, which is where the
        rendered prompt order (``tools`` → ``system`` → ``messages``) puts the
        boundary between what repeats and what does not.

        A prefix under the model's minimum is still sent — it is real prompt
        content — but carries no ``cache_control``, and says so in the log. An
        unattachable breakpoint is not free: it costs a write premium on a
        cache the API will decline to create, and it invites a hit-rate number
        that was never going to arrive.
        """
        if not stable:
            return None

        block: dict[str, Any] = {"type": "text", "text": stable}
        if not settings.llm_prompt_cache_enabled:
            return [block]

        floor = cache_min_prefix_tokens(self._model)
        approx_tokens = len(stable) // _CHARS_PER_TOKEN
        if approx_tokens < floor:
            logger.info(
                "Prompt cache not attached — stable prefix ~%d tokens is under the "
                "%d-token minimum for %s; the request is unchanged and uncached",
                approx_tokens,
                floor,
                self._model,
            )
            return [block]

        cache_control: dict[str, Any] = {"type": "ephemeral"}
        ttl = settings.llm_prompt_cache_ttl
        if ttl and ttl != "5m":
            cache_control["ttl"] = ttl
        block["cache_control"] = cache_control
        return [block]

    @staticmethod
    def _text_from(response: Any) -> str:
        """Join every text block in a response, ignoring thinking/tool blocks."""
        texts: list[str] = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                texts.append(block.text)
        return "\n".join(texts)

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
            "max_tokens": settings.llm_max_output_tokens,
        }
        if system_prompt:
            # The system prompt is the one span every turn of a ReAct loop
            # repeats verbatim, so it is exactly the prefix worth a breakpoint.
            system_blocks = self._system_blocks_for(system_prompt)
            kwargs["system"] = system_blocks if system_blocks is not None else system_prompt
        if tools:
            kwargs["tools"] = self._to_anthropic_tools(tools)

        response = await self._call_with_backoff(**kwargs)
        stats = self._track_usage(response)

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
        if not thought.strip():
            # No text and no tool call: the turn produced nothing to reason from
            # or act on. Same budget-exhaustion cause as generate_text, and the
            # same reason not to hand it back as a well-formed empty action.
            raise EmptyResponseError(
                f"Anthropic returned neither text nor a tool call (model={self._model}, "
                f"stop_reason={stats.stop_reason}, output_tokens={stats.output_tokens}, "
                f"max_tokens={settings.llm_max_output_tokens})",
                stop_reason=stats.stop_reason,
            )
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

    async def generate_text(self, prompt: PromptLike) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: A plain string, or :class:`PromptSegments` whose ``stable``
                half is sent as a cache-marked system block.

        Returns:
            Generated text content, never empty.

        Raises:
            EmptyResponseError: The response carried no text block. On a
                thinking-capable model this is normally budget exhaustion —
                ``max_tokens`` bounds thinking and text *together*, so a hard
                enough prompt can consume the whole allowance before the first
                visible token. Four DVWA engagements shipped with the exploit
                planner silently receiving ``""`` this way.
        """
        segments = as_prompt_segments(prompt)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "user", "content": segments.volatile or segments.stable}],
            "max_tokens": settings.llm_max_output_tokens,
        }
        system_blocks = self._system_blocks_for(segments.stable if segments.volatile else "")
        if system_blocks is not None:
            kwargs["system"] = system_blocks

        response = await self._call_with_backoff(**kwargs)
        stats = self._track_usage(response)

        text = self._text_from(response)
        if not text.strip():
            raise EmptyResponseError(
                f"Anthropic returned no text block (model={self._model}, "
                f"stop_reason={stats.stop_reason}, output_tokens={stats.output_tokens}, "
                f"max_tokens={settings.llm_max_output_tokens})",
                stop_reason=stats.stop_reason,
            )
        return text

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
