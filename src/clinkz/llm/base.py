"""Abstract base class for all LLM clients.

Defines the interface every provider must implement. Agent code
only ever interacts with LLMClient — never with provider SDKs directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Typed errors — used by ResilientLLMClient to distinguish retriable failures
# ---------------------------------------------------------------------------


class LLMError(Exception):
    """Base class for all LLM client errors."""


class RateLimitError(LLMError):
    """Provider returned 429 or signalled quota exhaustion."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServiceUnavailableError(LLMError):
    """Provider returned 503 / overloaded / temporarily unavailable."""


class LLMTimeoutError(LLMError):
    """Request to the provider timed out."""


class ProviderAccountError(LLMError):
    """The provider refused on an ACCOUNT condition, not a transient one.

    A depleted credit balance or a revoked key comes back as an HTTP 400 with
    ``invalid_request_error`` — not a 429, not a 503, not a timeout — so none of
    the retry predicates recognise it and it falls through to the generic
    "unexpected error, try the next provider" path. That is nearly right, and
    wrong in one expensive way: the condition is a property of the ACCOUNT and
    will hold for every subsequent call, but the chain re-attempts the same
    provider on the next one. Engagement ``f6a550a4`` made 79 Anthropic
    attempts and 76 of them were the same "credit balance is too low" 400,
    re-discovered from scratch each time.

    Raised as its own type so :class:`~clinkz.llm.fallback.ResilientLLMClient`
    can stop asking — the same thing the Gemini credit pre-flight does at
    engagement start, applied to the condition a pre-flight cannot predict
    because it develops mid-run.
    """


class LLMUnavailableError(LLMError):
    """Every provider in the fallback chain failed."""


class EmptyResponseError(LLMError):
    """The provider answered, but the answer carried no usable text.

    Raised instead of returning ``""``. An empty string is indistinguishable
    from a real answer at every call site — the Exploit planner turned one into
    a single garbage task that reached the target as ``GET /...`` — so the
    empty case is surfaced as a retriable failure the fallback chain can act on
    rather than a value the caller has to think to check.

    The common cause is a thinking-capable model spending the whole
    ``max_tokens`` allowance on reasoning: the budget covers thinking *and*
    response text together, so the turn ends with ``stop_reason="max_tokens"``
    and zero text blocks. ``stop_reason`` is carried so the trace can say which
    it was.
    """

    def __init__(self, message: str, stop_reason: str | None = None) -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


class CallStats(BaseModel):
    """Per-call accounting a provider reports back about one request.

    Populated by whichever client served the call and read at the
    ``ResilientLLMClient`` seam, so cost/cache reporting never requires an
    agent to know which provider ran or to import a provider SDK.

    Cache fields are zero on providers that expose no cache accounting; that is
    a genuine "not reported", not a measured zero, and the trace records the
    provider alongside so the two are never confused.
    """

    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    stop_reason: str | None = None

    @property
    def billed_prompt_tokens(self) -> int:
        """Total prompt tokens the request presented, cached or not.

        ``input_tokens`` is the *uncached remainder* only, so summing the three
        is the only way to recover the true prompt size.
        """
        return self.input_tokens + self.cache_creation_input_tokens + self.cache_read_input_tokens


#: Documented cache-pricing multipliers, relative to the base input rate.
#: Model-independent, so realised savings are reported as a ratio of base-rate
#: input tokens rather than in dollars — a currency figure would bake in a
#: per-model price that drifts, and the ratio is the part that is actually
#: measured.
CACHE_WRITE_MULTIPLIER: dict[str, float] = {"5m": 1.25, "1h": 2.0}
CACHE_READ_MULTIPLIER: float = 0.10


class LLMUsageTotals(BaseModel):
    """Running per-agent totals, aggregated from every :class:`CallStats`.

    Exists so a run can *report* its cache hit rate instead of assuming one.
    """

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def add(self, stats: CallStats) -> None:
        """Fold one call's accounting into the totals."""
        self.calls += 1
        self.input_tokens += stats.input_tokens
        self.output_tokens += stats.output_tokens
        self.cache_creation_input_tokens += stats.cache_creation_input_tokens
        self.cache_read_input_tokens += stats.cache_read_input_tokens

    @property
    def prompt_tokens(self) -> int:
        """Every prompt token presented, cached or not."""
        return self.input_tokens + self.cache_creation_input_tokens + self.cache_read_input_tokens

    @property
    def cache_hit_rate(self) -> float:
        """Share of prompt tokens served from cache. 0.0 when nothing cached."""
        total = self.prompt_tokens
        return (self.cache_read_input_tokens / total) if total else 0.0

    def realised_savings(self, ttl: str = "5m") -> float:
        """Share of base-rate input cost avoided by caching, in [0, 1).

        Negative in principle and clamped at 0 in practice only if every write
        were wasted; a write that is never read costs *more* than not caching,
        which is why this is computed from the counters rather than asserted.
        """
        total = self.prompt_tokens
        if not total:
            return 0.0
        write_mult = CACHE_WRITE_MULTIPLIER.get(ttl, CACHE_WRITE_MULTIPLIER["5m"])
        actual = (
            self.input_tokens
            + self.cache_creation_input_tokens * write_mult
            + self.cache_read_input_tokens * CACHE_READ_MULTIPLIER
        )
        return 1.0 - (actual / total)


class PromptSegments(BaseModel):
    """A prompt split by **how often the bytes repeat**, widest scope first.

    The split is provider-agnostic on purpose. Callers say which bytes repeat
    and over what scope; the client layer alone decides what to do with that —
    an Anthropic cache breakpoint, or nothing at all. No agent imports a
    provider SDK or spells ``cache_control``.

    Three scopes, because two were not enough and the difference cost money:

    * ``invariant`` — bytes that are a property of the ENGINE, identical on
      every call of every engagement forever: the role statement, the
      methodology catalogue, the per-class preconditions, the worked examples.
    * ``stable`` — bytes that are a property of THIS engagement: the observed
      endpoint inventory, the detected technologies, the research runbook.
      Byte-identical across the calls of one run, and different in every run.
    * ``volatile`` — the individual ask.

    Why the middle scope is not the cached one. The breakpoint used to sit
    after ``stable``, which meant the cached prefix was ~12,500 tokens of
    engagement-specific inventory presented **exactly once** — the planning
    call — with the only would-be reader (the plan-repair call) firing solely
    on a parse failure. Across 154 recorded engagements that produced 96,759
    cache-WRITE tokens and **zero** cache-read tokens: a 1.25x premium paid in
    full, every run, for an entry nothing ever read. Caching pays from the
    second presentation onward (``1.25 + 0.10(N-1) < N`` for ``N > 1.28``), and
    the deployment had ``N = 1``.

    So the breakpoint goes at the end of ``invariant``: an order of magnitude
    smaller, which caps the downside of a miss at noise, and the only span in
    the prompt that a second call — a repair, or the next engagement inside the
    TTL — can actually present again byte-for-byte.

    Each segment must be byte-identical across the calls that share it; caching
    is a prefix match, so one interpolated timestamp or one unsorted
    ``json.dumps`` invalidates everything after it.

    Flattening to ``str`` yields exactly what a caller would have passed before
    this type existed, which is what providers without a cache breakpoint send.
    """

    stable: str = ""
    volatile: str = ""
    invariant: str = ""

    @property
    def context(self) -> str:
        """Everything that is not the ask, in rendered order."""
        return "\n\n".join(part for part in (self.invariant, self.stable) if part)

    def flatten(self) -> str:
        """Render every segment as the single prompt string providers see."""
        return "\n\n".join(part for part in (self.invariant, self.stable, self.volatile) if part)


#: What ``generate_text`` accepts. A bare ``str`` is the unchanged path: no
#: breakpoint, no system block, byte-identical request to what shipped before.
PromptLike = str | PromptSegments


def as_prompt_segments(prompt: PromptLike) -> PromptSegments:
    """Normalise a prompt to segments, treating a bare string as all-volatile."""
    if isinstance(prompt, PromptSegments):
        return prompt
    return PromptSegments(stable="", volatile=prompt)


def flatten_prompt(prompt: PromptLike) -> str:
    """Render any accepted prompt shape as the flat string form."""
    return prompt if isinstance(prompt, str) else prompt.flatten()


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

    #: Accounting for the most recent call this client served. ``None`` until
    #: one completes. Read at the ``ResilientLLMClient`` seam for the trace, so
    #: the value is only meaningful immediately after an awaited call returns.
    last_call_stats: CallStats | None = None

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
    async def generate_text(self, prompt: PromptLike) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: Either a plain string, or :class:`PromptSegments` declaring
                which leading bytes repeat across the calls of one engagement.
                A client that cannot exploit the split flattens it and behaves
                exactly as it did for the string form.

        Returns:
            Generated text. Never the empty string — a response carrying no
            text raises :class:`EmptyResponseError` so the failure is visible
            to the fallback chain instead of flowing on as a plausible answer.

        Raises:
            EmptyResponseError: The provider returned no usable text.
        """
        ...
