"""Google Gemini LLM client — Gemini 3.x.

Under routing v2 this is a FALLBACK-ONLY provider: Anthropic is priority 1 for
every call on every phase, and reaching this client at all is a disqualifying
event the run has to declare (:mod:`clinkz.llm.fallback`). That fact drives two
decisions recorded below.

Uses the google-genai SDK with:

- The pinned model :data:`clinkz.config.GEMINI_PINNED_MODEL`; per-role pins are
  passed in via the ``model`` argument
- Native Google Search grounding for :meth:`GeminiClient.research`
- Function calling for :meth:`GeminiClient.reason`
- Sliding-window rate limiting (``settings.gemini_max_rpm``)
- Exponential backoff on 429 / 503 / quota errors
- Per-request token usage tracking

Gemini 3.x migration
--------------------

Four generation-config parameters were **removed** in 3.x and are refused here
rather than being passed through to be rejected by the API mid-engagement:
``temperature``, ``top_p``, ``top_k`` and ``candidate_count``
(:data:`_REMOVED_IN_GEMINI_3X`). None of them was in use when this client was
migrated — the guard exists so that re-adding one is a loud test failure rather
than a 400 discovered on the one call path that only runs when the primary
provider is already down.

``thinking_budget`` (an integer) was replaced by ``thinking_level`` (a string
enum). The SDK's ``types.ThinkingLevel`` still offers ``MINIMAL`` and 3.7 Flash
**rejects it** with an API validation error, so the SDK enum is not the
contract: :data:`clinkz.config.GEMINI_THINKING_LEVELS` is, and the value is
validated at config load.

**generateContent (Legacy) is used deliberately, not by inertia.** The
Interactions API is GA and is what Google now recommends, and this client stays
on ``models.generate_content`` anyway for one reason: routing v2 turned this
whole module into a degradation path. Every response reader downstream — the
``candidates[0].content.parts`` walk in :meth:`reason`, ``response.text``,
``usage_metadata`` — is shaped around the generateContent response, and porting
them to a different response shape would put freshly-rewritten, rarely-executed
code on the exact path that only runs when Anthropic is already failing. That is
the worst place in the system to take on untested surface: the first real
exercise would be a live engagement mid-incident. Revisit when either premise
changes — generateContent gets a deprecation date, or Gemini returns to a
primary role and the path is exercised every run. Recorded 2026-08-18.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from google import genai
from google.genai import types

from clinkz.config import GEMINI_THINKING_LEVELS, settings
from clinkz.llm.base import (
    AgentAction,
    LLMClient,
    LLMMessage,
    LLMTimeoutError,
    OutputBudget,
    PromptLike,
    RateLimitError,
    ServiceUnavailableError,
    ToolCall,
    flatten_prompt,
)

logger = logging.getLogger(__name__)

_RATE_LIMIT_PERIOD: float = 60.0
_REQUEST_TIMEOUT: float = 120.0  # Hard timeout for every Gemini API call

#: Generation-config parameters Gemini 3.x removed. Passing any of them earns
#: an API validation error, so they are refused where the config is BUILT — one
#: place, rather than at each of the three call sites that construct one.
#:
#: This is a guard against a future edit, not a fix for a present bug: none of
#: these was set when the client was migrated. It is worth having precisely
#: because of that. Re-adding ``temperature`` is the natural thing to reach for
#: when tuning determinism, it looks harmless, and under routing v2 the code
#: path that would reject it runs only when Anthropic is already down — so the
#: bug would be introduced during a calm afternoon and discovered during an
#: incident.
_REMOVED_IN_GEMINI_3X: frozenset[str] = frozenset(
    {"temperature", "top_p", "top_k", "candidate_count"}
)


class GeminiConfigError(ValueError):
    """A generation config was built with a parameter Gemini 3.x removed."""


def _thinking_config() -> types.ThinkingConfig:
    """Build the 3.x thinking config from the validated configured level.

    ``thinking_level`` replaced the integer ``thinking_budget`` in 3.x. The
    level itself is validated at config load
    (:class:`clinkz.config.Settings`), because ``MINIMAL`` is offered by the
    SDK enum and rejected by the API on 3.7 Flash — a value that type-checks,
    imports cleanly, and fails on the wire.
    """
    level = str(settings.gemini_thinking_level).strip().upper()
    if level not in GEMINI_THINKING_LEVELS:
        raise GeminiConfigError(
            f"gemini_thinking_level={level!r} is not valid on Gemini 3.x "
            f"(valid: {', '.join(sorted(GEMINI_THINKING_LEVELS))})."
        )
    return types.ThinkingConfig(thinking_level=level)


def build_generation_config(**kwargs: Any) -> types.GenerateContentConfig:
    """Build a 3.x-legal ``GenerateContentConfig``.

    THE one place a generation config is constructed, so the 3.x parameter
    removals are enforced once instead of at each call site.

    Args:
        **kwargs: Config fields. ``thinking_config`` is supplied automatically
            unless the caller passes its own.

    Returns:
        A config carrying the validated thinking level.

    Raises:
        GeminiConfigError: A parameter in :data:`_REMOVED_IN_GEMINI_3X` was
            passed. Refused rather than dropped: silently discarding a
            ``temperature`` the caller believed was applied would make the
            request non-reproducible in a way nothing in the artifact records.
    """
    removed = sorted(set(kwargs) & _REMOVED_IN_GEMINI_3X)
    if removed:
        raise GeminiConfigError(
            f"{', '.join(removed)} {'was' if len(removed) == 1 else 'were'} removed in "
            f"Gemini 3.x and cannot be sent to {settings.gemini_model}. Drop the "
            f"parameter; there is no 3.x equivalent to translate it into."
        )
    kwargs.setdefault("thinking_config", _thinking_config())
    return types.GenerateContentConfig(**kwargs)


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
    """Return True if the exception indicates HTTP 429 / quota exhaustion."""
    msg = str(exc).lower()
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    return (
        code == 429
        or "429" in msg
        or "resource exhausted" in msg
        or "quota" in msg
        or "rate limit" in msg
    )


def _is_service_unavailable_error(exc: Exception) -> bool:
    """Return True if the exception indicates HTTP 503 / overloaded."""
    msg = str(exc).lower()
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    return (
        code == 503
        or "503" in msg
        or "unavailable" in msg
        or "high demand" in msg
        or "overloaded" in msg
    )


def _is_retriable_error(exc: Exception) -> bool:
    """Return True for any retriable provider error."""
    return _is_rate_limit_error(exc) or _is_service_unavailable_error(exc)


def _extract_retry_delay(exc: Exception) -> float | None:
    """Extract the server-recommended retry delay from a Gemini 429 error.

    The error details include a ``RetryInfo`` entry like::

        {'@type': '...RetryInfo', 'retryDelay': '46s'}

    Also checks for ``"Please retry in Xs"`` in the error message.
    Returns None if no delay can be extracted.
    """
    import re

    # Try structured details first
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        for entry in details.get("error", {}).get("details", []):
            if "RetryInfo" in str(entry.get("@type", "")):
                delay_str = entry.get("retryDelay", "")
                m = re.search(r"([\d.]+)", delay_str)
                if m:
                    return float(m.group(1)) + 1  # add 1s buffer

    # Fallback: parse from error message
    msg = str(exc)
    m = re.search(r"retry in ([\d.]+)s", msg, re.IGNORECASE)
    if m:
        return float(m.group(1)) + 1
    return None


class GeminiClient(LLMClient):
    """Google Gemini client.

    Implements the LLMClient interface for all three methods:

    - ``reason()``        — function calling via Gemini's tool API
    - ``research()``      — Google Search grounding for live security intel
    - ``generate_text()`` — plain generation for report narratives

    Rate limiting and exponential backoff are applied transparently to every
    SDK call via ``_call_with_backoff()``.

    Args:
        model: Model name. Defaults to ``settings.gemini_model``. Callers pin
            a per-role model here (e.g. Research → ``gemini_research_model``).
        max_rpm: Requests-per-minute ceiling for this client's sliding-window
            limiter. Defaults to ``settings.gemini_max_rpm`` (Tier 1 sized).
    """

    def __init__(self, model: str | None = None, max_rpm: int | None = None) -> None:
        api_key = settings.gemini_api_key or settings.google_api_key
        if not api_key:
            raise ValueError(
                "Neither GEMINI_API_KEY nor GOOGLE_API_KEY is set. Add one to your .env file."
            )
        self._client = genai.Client(
            api_key=api_key,
            # Disable SDK-internal retries — we handle retries ourselves in
            # _call_with_backoff().  The SDK's tenacity retries burn through
            # free-tier daily quota because each retry counts as a request.
            http_options=types.HttpOptions(
                retryOptions=types.HttpRetryOptions(attempts=1),
            ),
        )
        self._model_name = model or settings.gemini_model
        rpm = max_rpm if max_rpm is not None else settings.gemini_max_rpm
        self._rate_limiter = _RateLimiter(int(rpm), _RATE_LIMIT_PERIOD)
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
        declarations = []
        for tool in tools:
            # Support both flat format {"name": ...} and OpenAI wrapper
            # format {"type": "function", "function": {"name": ...}}
            spec = tool.get("function", tool) if "function" in tool else tool
            declarations.append(
                types.FunctionDeclaration(
                    name=spec["name"],
                    description=spec.get("description", ""),
                    parameters=spec.get("parameters", {}),
                )
            )
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
                contents.append(types.Content(role="user", parts=[types.Part(text=msg.content)]))
                continue

            if msg.role == "assistant":
                parts: list[types.Part] = []
                if msg.content:
                    parts.append(types.Part(text=msg.content))
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append(
                            types.Part(
                                function_call=types.FunctionCall(name=tc.name, args=tc.arguments)
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

        Retries up to ``settings.llm_max_retries`` times on retriable errors
        (429, 503, timeout). Honours the server-recommended ``retryDelay``
        when the 429 includes one, otherwise uses exponential backoff capped
        at ``settings.llm_retry_max_delay`` so we fail fast and let the
        resilient wrapper move to the next provider.

        Raises:
            RateLimitError: when retries are exhausted on a 429.
            ServiceUnavailableError: when retries are exhausted on a 503.
            LLMTimeoutError: when all attempts time out.

        Args:
            coro_factory: Callable that returns a fresh coroutine each time.
        """
        max_retries = max(1, settings.llm_max_retries)
        base_delay = settings.llm_retry_base_delay
        max_delay = settings.llm_retry_max_delay
        last_exc: Exception | None = None

        for attempt in range(max_retries):
            try:
                await self._rate_limiter.acquire()
                return await asyncio.wait_for(coro_factory(), timeout=_REQUEST_TIMEOUT)
            except TimeoutError as exc:
                last_exc = exc
                logger.error(
                    "Gemini API call timed out after %.0fs (attempt %d/%d)",
                    _REQUEST_TIMEOUT,
                    attempt + 1,
                    max_retries,
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(min(base_delay * (2**attempt), max_delay))
                    continue
                raise LLMTimeoutError(f"Gemini API timed out after {max_retries} attempts") from exc
            except Exception as exc:
                last_exc = exc
                if _is_retriable_error(exc) and attempt < max_retries - 1:
                    wait = _extract_retry_delay(exc) or min(base_delay * (2**attempt), max_delay)
                    wait = min(wait, max_delay)
                    logger.warning(
                        "Retriable error (attempt %d/%d) — retrying in %.0fs: %s",
                        attempt + 1,
                        max_retries,
                        wait,
                        exc,
                    )
                    await asyncio.sleep(wait)
                    continue
                # Out of retries (or non-retriable) — translate to typed error
                if _is_rate_limit_error(exc):
                    raise RateLimitError(
                        f"Gemini rate-limited: {exc}",
                        retry_after=_extract_retry_delay(exc),
                    ) from exc
                if _is_service_unavailable_error(exc):
                    raise ServiceUnavailableError(f"Gemini 503: {exc}") from exc
                raise

        # Defensive — should be unreachable because the loop always raises.
        raise RateLimitError(f"Gemini exhausted retries: {last_exc}")

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

        # Always built, even with no caller kwargs: 3.x needs the thinking
        # level attached, and the previous ``if config_kwargs else None`` sent
        # a bare request whenever there was no system prompt and no tools.
        config = build_generation_config(**config_kwargs)

        def _make_coro() -> Coroutine[Any, Any, Any]:
            return self._client.aio.models.generate_content(
                model=self._model_name,
                contents=contents,
                config=config,
            )

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
        config = build_generation_config(
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

    async def generate_text(
        self, prompt: PromptLike, *, budget: OutputBudget = OutputBudget.DEFAULT
    ) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: A plain string, or segments. Gemini has no explicit
                cache breakpoint here, so segments are flattened and the
                request is byte-identical to the string form.
            budget: Output-ceiling policy. ``DEFAULT`` applies the flat
                ``settings.llm_max_output_tokens``. ``MAX`` sends **no**
                ``max_output_tokens`` at all, so the model applies its own
                maximum — deliberately not the Anthropic client's computed
                ``min(model ceiling, context - input - margin)``, because that
                arithmetic needs a per-model limits table and inventing numbers
                for a provider we do not measure would produce a ceiling that
                looks derived and is guessed. The provider knows its own limit;
                asking it is the honest form of "as much as you can".

        Returns:
            Generated text content.
        """
        contents = flatten_prompt(prompt)
        config_kwargs: dict[str, Any] = {}
        if budget is OutputBudget.DEFAULT:
            config_kwargs["max_output_tokens"] = int(settings.llm_max_output_tokens)
        config = build_generation_config(**config_kwargs)

        def _make_coro() -> Coroutine[Any, Any, Any]:
            return self._client.aio.models.generate_content(
                model=self._model_name,
                contents=contents,
                config=config,
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
