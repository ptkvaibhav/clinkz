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
    OutputBudget,
    PromptLike,
    ProviderAccountError,
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


# ---------------------------------------------------------------------------
# Output ceiling — computed per call, never a constant
# ---------------------------------------------------------------------------

#: ``(context window, max output tokens)`` per model family, longest prefix
#: first. Both halves are needed because the ceiling is the *smaller* of what
#: the model can emit and what is left of the window after the prompt.
#:
#: A constant ceiling is the defect this table exists to remove. 16000 was
#: chosen when the planning prompt was small; the prompt now scales with the
#: discovered attack surface, and a number that clears DVWA says nothing about
#: a target with ten times the endpoints.
_MODEL_LIMITS: tuple[tuple[str, int, int], ...] = (
    ("claude-haiku-4-5", 200_000, 64_000),
    ("claude-sonnet-4-6", 1_000_000, 128_000),
    ("claude-sonnet-5", 1_000_000, 128_000),
    ("claude-opus-4-6", 1_000_000, 128_000),
    ("claude-opus-4-7", 1_000_000, 128_000),
    ("claude-opus-4-8", 1_000_000, 128_000),
    ("claude-opus-5", 1_000_000, 128_000),
    ("claude-fable-5", 1_000_000, 128_000),
    ("claude-mythos-5", 1_000_000, 128_000),
)

#: Limits for a model this table has never heard of. Deliberately the smallest
#: generation still in service: under-reading a window costs a few thousand
#: tokens of headroom, over-reading one costs the call.
_MODEL_LIMITS_DEFAULT: tuple[int, int] = (200_000, 16_000)


def model_limits(model: str) -> tuple[int, int]:
    """Return ``(context_limit, output_ceiling)`` for *model*."""
    for prefix, context, output in _MODEL_LIMITS:
        if model.startswith(prefix):
            return context, output
    return _MODEL_LIMITS_DEFAULT


def resolve_max_output_tokens(model: str, measured_input_tokens: int) -> int:
    """Compute this call's ``max_tokens`` from the model and the actual prompt.

    ``min(model output ceiling, context limit - measured input - margin)``.

    The second term is the one that makes this a computation rather than a
    lookup: a prompt is charged against the same window the answer is written
    into, so a ceiling that ignores the prompt is a ceiling that works until the
    prompt grows. On every model currently in service the first term binds —
    the input would have to reach ~9x the largest planning prompt on record
    before the window did — which is the answer we want and not one to hardcode,
    because it stops being true the moment a bigger target or a smaller model
    turns up.

    Args:
        model: The model that will serve the call.
        measured_input_tokens: Prompt size, measured (``count_tokens``) rather
            than assumed. A conservative over-estimate is safe; an
            under-estimate eats the margin.

    Returns:
        The ``max_tokens`` to send, never below 1.
    """
    context_limit, output_ceiling = model_limits(model)
    margin = max(0, int(settings.llm_context_margin_tokens))
    room_in_window = context_limit - max(0, measured_input_tokens) - margin
    return max(1, min(output_ceiling, room_in_window))


#: Conservative output rate, in tokens/second, used ONLY to derive a timeout
#: floor. Deliberately pessimistic: a thinking-capable model spends part of the
#: allowance reasoning, and the cost of guessing low is a timeout on a request
#: that was about to succeed.
_MIN_OUTPUT_TOKENS_PER_SECOND: float = 30.0

#: Absolute ceiling on the derived floor. Matches the Anthropic SDK's own
#: default client timeout, which is what a non-streaming request is bounded by
#: anyway — deriving something longer would be a number no request can reach.
_MAX_DERIVED_TIMEOUT_SECONDS: float = 600.0

#: Ceiling on the derived floor for a STREAMED request. The ten-minute bound
#: above is the SDK's non-streaming default and does not apply once the response
#: arrives incrementally; a 128000-token ceiling at the pessimistic 30 tok/s
#: floor needs more than ten minutes, and capping it there would hand back the
#: headroom streaming was enabled to obtain.
_MAX_STREAMING_TIMEOUT_SECONDS: float = 3600.0


def request_timeout_for(max_output_tokens: int, *, streaming: bool = False) -> float:
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
        streaming: Whether the request is streamed. A streamed response is not
            bound by the SDK's ten-minute non-streaming ceiling, so the derived
            floor is allowed past it — otherwise raising the cap would buy room
            the timeout immediately takes back.

    Returns:
        The timeout, in seconds, to bound this call with.
    """
    configured = float(settings.llm_request_timeout)
    if max_output_tokens <= 0:
        return configured
    cap = _MAX_STREAMING_TIMEOUT_SECONDS if streaming else _MAX_DERIVED_TIMEOUT_SECONDS
    needed = min(max_output_tokens / _MIN_OUTPUT_TOKENS_PER_SECOND, cap)
    if needed <= configured:
        return configured
    logger.info(
        "Raising per-call timeout %.0fs -> %.0fs: max_tokens=%d cannot complete in the "
        "configured window (%s, ~%.0f tok/s floor)",
        configured,
        needed,
        max_output_tokens,
        "streaming" if streaming else "non-streaming",
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


#: Substrings that identify an ACCOUNT condition rather than a transient fault.
#: Matched against the provider's own error text, which is where the condition
#: is actually stated — the status code is a plain 400 and says nothing.
_ACCOUNT_ERROR_MARKERS: tuple[str, ...] = (
    "credit balance is too low",
    "billing",
    "quota exceeded for your account",
    "invalid x-api-key",
    "authentication_error",
    "permission_error",
)


def _is_account_error(exc: Exception) -> bool:
    """Return True if the provider refused on a durable account condition.

    Deliberately narrow. A false positive here costs the engagement its primary
    provider for the whole run, so the match is on explicit account language and
    never on the bare 400 — plenty of 400s are one malformed request.
    """
    msg = str(exc).lower()
    return any(marker in msg for marker in _ACCOUNT_ERROR_MARKERS)


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
                requested = int(kwargs.get("max_tokens") or 0)
                streaming = requested > int(settings.llm_stream_above_output_tokens)
                return await asyncio.wait_for(
                    self._stream_message(**kwargs)
                    if streaming
                    else self._client.messages.create(**kwargs),
                    timeout=request_timeout_for(requested, streaming=streaming),
                )
            except Exception as exc:
                last_exc = exc
                # An account condition is never retried: retrying spends the
                # backoff budget re-confirming a fact that will not change
                # inside this run.
                if _is_account_error(exc):
                    raise ProviderAccountError(f"Anthropic account condition: {exc}") from exc
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

    async def _stream_message(self, **kwargs: Any) -> Any:
        """Serve one request over the streaming API, returning the final Message.

        Streaming is not a latency preference here — it is what makes a large
        ``max_tokens`` legal at all. The SDK refuses a non-streaming request it
        estimates will exceed ten minutes, and the estimate scales with
        ``max_tokens``, so raising the cap on the non-streaming path converts
        requests that were working into requests that are refused. The final
        message carries the same ``content``/``usage``/``stop_reason`` shape as
        ``messages.create``, so every reader downstream is unchanged.
        """
        async with self._client.messages.stream(**kwargs) as stream:
            return await stream.get_final_message()

    async def _measure_input_tokens(self, **kwargs: Any) -> tuple[int, str]:
        """Measure the prompt this request will send, before sending it.

        Returns ``(tokens, source)`` — ``source`` is ``"count_tokens"`` for the
        API's own count and ``"estimate"`` when that call could not be made.
        The source rides along because the two are not interchangeable: an
        estimate is what the margin exists to cover, and a run that silently
        fell back to one should be able to say so.
        """
        payload = {k: v for k, v in kwargs.items() if k in ("model", "messages", "system")}
        try:
            counted = await self._client.messages.count_tokens(**payload)
            return int(getattr(counted, "input_tokens", 0) or 0), "count_tokens"
        except Exception as exc:
            chars = sum(len(str(part)) for part in payload.values())
            estimate = chars // _CHARS_PER_TOKEN
            logger.warning(
                "count_tokens unavailable (%s) — sizing the ceiling from a %d-char "
                "estimate (~%d tokens); the context margin covers the difference",
                type(exc).__name__,
                chars,
                estimate,
            )
            return estimate, "estimate"

    def _apply_output_budget(self, kwargs: dict[str, Any], measured_input: int, source: str) -> int:
        """Set this request's ``max_tokens`` from the model and the real prompt."""
        ceiling = resolve_max_output_tokens(self._model, measured_input)
        kwargs["max_tokens"] = ceiling
        context_limit, output_ceiling = model_limits(self._model)
        logger.info(
            "Output budget for %s: max_tokens=%d = min(model %d, context %d - input %d "
            "(%s) - margin %d); streamed=%s",
            self._model,
            ceiling,
            output_ceiling,
            context_limit,
            measured_input,
            source,
            settings.llm_context_margin_tokens,
            ceiling > int(settings.llm_stream_above_output_tokens),
        )
        return ceiling

    @staticmethod
    def _report_output_headroom(stats: CallStats) -> None:
        """Say how close the answer came to its ceiling, while there is still room.

        The previous cliff was discovered by reading a traceback from a run that
        had already finished. Headroom is a number the run can watch: at or
        above the alarm ratio it is a near miss and says so, and exhaustion is
        reported as the truncation it is rather than as a completed answer.
        """
        if stats.max_output_tokens <= 0:
            return
        if stats.stop_reason == "max_tokens":
            logger.error(
                "OUTPUT BUDGET EXHAUSTED: %s produced %d tokens against a ceiling of %d and "
                "was CUT OFF (stop_reason=max_tokens). The answer is truncated, not complete.",
                stats.model,
                stats.output_tokens,
                stats.max_output_tokens,
            )
            return
        ratio = float(settings.llm_output_headroom_alarm_ratio)
        if stats.output_utilisation >= ratio:
            logger.warning(
                "OUTPUT BUDGET NEAR MISS: %s produced %d tokens against a ceiling of %d "
                "(%.0f%% of budget, %d left). Raise the ceiling or shrink the ask before "
                "this becomes a truncation.",
                stats.model,
                stats.output_tokens,
                stats.max_output_tokens,
                100 * stats.output_utilisation,
                stats.output_headroom,
            )
        else:
            logger.info(
                "Output headroom: %s used %d/%d tokens (%.0f%%), %d left",
                stats.model,
                stats.output_tokens,
                stats.max_output_tokens,
                100 * stats.output_utilisation,
                stats.output_headroom,
            )

    def _track_usage(self, response: Any, *, requested_max_tokens: int = 0) -> CallStats:
        """Accumulate token counts and publish stats for the call just served.

        ``input_tokens`` from the API is the **uncached remainder only**, so it
        is recorded as-is and the cache counters are kept beside it rather than
        folded in — the sum is the real prompt size, and conflating them would
        make a working cache look like a shrinking prompt.
        """
        stats = CallStats(
            provider="anthropic", model=self._model, max_output_tokens=requested_max_tokens
        )
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

    def _system_blocks(
        self,
        invariant: str,
        engagement_scoped: str = "",
    ) -> list[dict[str, Any]] | None:
        """Render the context as system blocks, with the breakpoint on the
        **invariant** one only.

        The rendered prompt order is ``tools`` → ``system`` → ``messages``, and
        a ``cache_control`` marker caches everything up to and including the
        block that carries it. So block 0 holds the engine-invariant bytes and
        takes the breakpoint; block 1 holds this engagement's observed context
        and is deliberately outside the cached span.

        That placement is the fix for a measured regression, not a preference.
        With the breakpoint after the engagement-scoped block, the cached prefix
        was ~12,500 tokens presented exactly once per run: 96,759 write tokens
        and zero read tokens across 154 recorded engagements, a 1.25x premium
        on an entry nothing ever read. Moving it cuts the exposure by an order
        of magnitude AND puts it on the only span a second call can present
        again byte-for-byte.

        A prefix under the model's minimum is still sent — it is real prompt
        content — but carries no ``cache_control``, and says so in the log. An
        unattachable breakpoint is not free: it costs a write premium on a
        cache the API will decline to create, and it invites a hit-rate number
        that was never going to arrive.
        """
        blocks: list[dict[str, Any]] = []
        if invariant:
            blocks.append(self._cacheable_block(invariant))
        if engagement_scoped:
            blocks.append({"type": "text", "text": engagement_scoped})
        return blocks or None

    def _cacheable_block(self, text: str) -> dict[str, Any]:
        """One system block, cache-marked when the model will honour it."""
        block: dict[str, Any] = {"type": "text", "text": text}
        if not settings.llm_prompt_cache_enabled:
            return block

        floor = cache_min_prefix_tokens(self._model)
        approx_tokens = len(text) // _CHARS_PER_TOKEN
        if approx_tokens < floor:
            logger.info(
                "Prompt cache not attached — invariant prefix ~%d tokens is under the "
                "%d-token minimum for %s; the request is unchanged and uncached",
                approx_tokens,
                floor,
                self._model,
            )
            return block

        cache_control: dict[str, Any] = {"type": "ephemeral"}
        ttl = settings.llm_prompt_cache_ttl
        if ttl and ttl != "5m":
            cache_control["ttl"] = ttl
        block["cache_control"] = cache_control
        return block

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
            # repeats verbatim, so it is exactly the prefix worth a breakpoint —
            # invariant by construction here, with no engagement-scoped half.
            system_blocks = self._system_blocks(system_prompt)
            kwargs["system"] = system_blocks if system_blocks is not None else system_prompt
        if tools:
            kwargs["tools"] = self._to_anthropic_tools(tools)

        response = await self._call_with_backoff(**kwargs)
        stats = self._track_usage(response, requested_max_tokens=int(kwargs["max_tokens"]))
        self._report_output_headroom(stats)

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

        Anthropic's API has no built-in search grounding on this path, so the
        answer comes from Claude's training knowledge. The live-data half of a
        research step is the NVD lookup in
        :mod:`clinkz.research.runtime_research`, which is a structured feed and
        not an LLM call at all — it is unaffected by which model answers here.

        **This method used to hop to Gemini** when a Gemini key was present:
        it imported ``GeminiClient`` directly and returned its answer. That
        routed around the fallback chain completely — a research call the
        resilient client had resolved to Anthropic was served by Gemini anyway,
        and no chain restriction could have seen it, because the substitution
        happened one layer below the layer that picks providers. A provider
        client reaching for another provider is not a fallback; it is a hole in
        the abstraction that made "research runs on Claude" unverifiable from
        the routing layer.

        The capability that went with it is real and is stated rather than
        absorbed: research answers here are no longer grounded in live web
        results. The replacement, if the grounding is wanted back, is Claude's
        own ``web_search`` server tool on this client — grounding without a
        second provider — not the reinstatement of a cross-provider call.

        Args:
            query: Security-focused research question.

        Returns:
            Research findings as a plain string.
        """
        prompt = (
            "You are an expert penetration tester and vulnerability researcher. "
            "Provide detailed, actionable information on the following topic. "
            "Include: relevant CVEs with IDs and severity, affected versions, "
            "exploit techniques with specific steps, PoC availability, "
            "mitigations, and any known bug bounty writeups.\n\n"
            f"Topic: {query}"
        )
        return await self.generate_text(prompt)

    async def generate_text(
        self, prompt: PromptLike, *, budget: OutputBudget = OutputBudget.DEFAULT
    ) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: A plain string, or :class:`PromptSegments` whose ``stable``
                half is sent as a cache-marked system block.
            budget: ``DEFAULT`` keeps the flat configured ceiling — the path
                every call has always taken. ``MAX`` measures the prompt and
                computes the ceiling from it, and is for the calls whose answer
                scales with the target rather than with the question.

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

        # With no ask of its own there is nothing to split around: the whole
        # prompt goes in the message, exactly as a bare string always did.
        content = segments.volatile or segments.flatten()
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "user", "content": content}],
            "max_tokens": settings.llm_max_output_tokens,
        }
        if segments.volatile:
            system_blocks = self._system_blocks(segments.invariant, segments.stable)
            if system_blocks is not None:
                kwargs["system"] = system_blocks

        if budget is OutputBudget.MAX:
            measured, source = await self._measure_input_tokens(**kwargs)
            self._apply_output_budget(kwargs, measured, source)

        response = await self._call_with_backoff(**kwargs)
        stats = self._track_usage(response, requested_max_tokens=int(kwargs["max_tokens"]))
        self._report_output_headroom(stats)

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
