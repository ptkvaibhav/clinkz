"""Abstract base class for all LLM clients.

Defines the interface every provider must implement. Agent code
only ever interacts with LLMClient — never with provider SDKs directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
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


class ProviderPolicyError(BaseException):
    """A decision-bearing role was about to be served by a forbidden provider.

    **Inherits BaseException, not Exception, and that is the whole mechanism.**

    Every LLM call site in the agents is already wrapped in a broad
    ``except Exception`` that degrades gracefully — the exploit planner falls
    back to its deterministic plan, the research agent skips a technique, the
    methodology checkpoint returns ``""``. Those handlers are correct for what
    they were written for: a provider quirk should not end an engagement. They
    are exactly wrong for this, because "degrade gracefully" is how the run
    continues with the wrong model's answer in it — which is the outcome this
    class exists to prevent.

    Fixing that by re-raising at each of the eight current call sites would
    work today and rot immediately: the ninth call site would re-derive only
    the obvious half. So the refusal is made structurally uncatchable instead,
    the way ``KeyboardInterrupt`` is — a stop, not an error to handle. There is
    no next provider to try and no partial result worth keeping: a plan or a
    suppression verdict written by the wrong model invalidates the run it
    appears in.

    The last instance was found by reading traces after the fact — Gemini had
    served 6 exploit plans and 6 false-positive cross-checks across 9
    engagements, and every one of those reports looked exactly like a report
    that had not happened to it. This raises instead.

    It is deliberately NOT an :class:`LLMError`: the fallback chain rotates on
    those, and rotating is the behaviour being refused.

    **Reserved for the run-mode refusal**, i.e. ``baseline``. The call-purpose
    refusal on an emit/suppress path in ``client`` mode raises
    :class:`DecisionPathFallbackRefused` instead — see that class for why the
    two want opposite catchability.
    """


class DecisionPathFallbackError(BaseException):
    """A call whose answer EMITS or SUPPRESSES a finding may not be served by
    a fallback provider, and only the CALL degrades — never the run.

    The sibling of :class:`ProviderPolicyError`, and the difference between them
    is the intended outcome rather than the severity.

    ``baseline`` mode wants the **run** to fail: a recorded baseline served
    partly by two models measures nothing, so there is no partial result worth
    keeping. ``client`` mode wants only the **call** to fail — the engagement
    should still complete, which is the whole reason client mode degrades.

    **Both inherit BaseException, and that is what changed.** This class used to
    be an :class:`LLMError`, on the reasoning that its two callers already
    degrade correctly under an ordinary ``except Exception`` and therefore
    *should* catch it. They do degrade correctly. What they did not do is
    degrade **visibly**: on the portfolio engagement the false-positive
    cross-check's Anthropic call failed, this refusal was raised in its place,
    and ``except Exception`` turned it into an empty suspect list. An empty
    suspect list is what the cross-check returns when it looked and found
    nothing wrong. Fourteen phantom findings shipped under a signal that said
    the reviewer had cleared them.

    So the two siblings now share the mechanism and differ only in who catches
    them. ``ProviderPolicyError`` is caught by nobody. This one is caught
    **explicitly**, by name, at the two sites where degrading is correct — and
    an explicit handler is a place to log it, record it on the contribution
    ledger, and put it in the deliverable. A broad ``except Exception`` reaches
    neither, which is the entire failure being fixed: the handler that hid this
    was not wrong to degrade, it was wrong to be silent, and a handler nobody
    wrote deliberately cannot be anything else.

    The asymmetry that produced the incident is gone: one sibling was hardened
    against the broad-except pattern and the other was left inside it, so the
    refusal that mattered most — the one on the SUPPRESS path — was the one that
    vanished.

    A new EMIT/SUPPRESS call site that forgets to handle this now fails loudly
    instead of quietly returning the conservative-looking empty answer. That is
    the safe direction for the same reason ``ProviderPolicyError`` is: the
    conservative-looking answer and the real one are indistinguishable
    downstream.

    It is raised from ``_assert_fallback_permitted``, i.e. *before* the request
    leaves, so nothing is bought and nothing is stamped: a degradation the run
    did not take must not appear in the register.

    It does not rotate the chain further. Being raised outside the loop's
    ``try`` in ``_dispatch``, it propagates straight to the caller — every
    remaining provider is a fallback too, so trying the next one asks the same
    forbidden question.
    """


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
    #: The ``max_tokens`` this request actually carried. Recorded because
    #: ``output_tokens`` alone cannot say whether a call finished or was cut
    #: off: 16000 is a complete answer under a 64000 ceiling and a truncation
    #: under a 16000 one. The last cliff was found by reading a traceback,
    #: which is one engagement too late.
    max_output_tokens: int = 0

    @property
    def output_headroom(self) -> int:
        """Tokens left unspent under the ceiling this call carried.

        Negative is impossible; zero means the ceiling bound the answer.
        """
        if self.max_output_tokens <= 0:
            return 0
        return max(0, self.max_output_tokens - self.output_tokens)

    @property
    def output_utilisation(self) -> float:
        """Fraction of the requested ceiling the answer actually consumed."""
        if self.max_output_tokens <= 0:
            return 0.0
        return self.output_tokens / self.max_output_tokens

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

    That move was necessary and not sufficient, and the follow-up measurement
    said so: the smaller span still wrote ~1,566 tokens per run and still read
    back **zero**, because neither would-be second presenter ever arrives. The
    repair call fires only on a parse failure (0 of 13 recorded engagements),
    and the next engagement's planning call lands a whole run later — the
    closest two breakpoint calls on record are 1,692s apart against a 300s TTL.
    ``N`` was 1 before the move and 1 after it. So prompt caching is **off by
    default** (``settings.llm_prompt_cache_enabled``); this split is what a
    deployment that genuinely re-presents a prefix would switch back on, and it
    stays here because the arithmetic — not the machinery — is what failed.

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


class OutputBudget(StrEnum):
    """How a call wants its ``max_tokens`` ceiling chosen.

    A *policy*, never a number: only the client that is about to serve the call
    knows which model will run it, and the ceiling is a function of that model's
    output cap and context window. An agent naming a token count would be
    guessing on behalf of a provider it is not allowed to import.

    * ``DEFAULT`` — ``settings.llm_max_output_tokens``, the flat ceiling every
      call has always carried. Non-streaming-safe by construction.
    * ``MAX`` — computed per call as
      ``min(model output ceiling, context limit - measured input - margin)``.
      For the one call whose answer scales with the discovered attack surface.

    Why ``MAX`` is not simply the default. It costs a ``count_tokens``
    round-trip to measure the input, and it produces a ceiling large enough to
    require streaming. Both are right for a once-per-engagement planning call
    and wrong for the ~5,000 short checkpoint calls a run also makes.
    """

    DEFAULT = "default"
    MAX = "max"


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


class ResearchGrounding(StrEnum):
    """Whether a client's :meth:`LLMClient.research` answer saw the live web.

    Declared by the PRODUCER, like ``ToolOutput.discovered_urls`` and
    ``detected_components()``, and for the same reason: a consumer that guesses
    is a consumer that will be silently wrong the first time a provider changes.

    This is not a preference. A grounded research call reads today's CVE feeds;
    an ungrounded one recites a training corpus with a cutoff, so **every
    vulnerability disclosed after that cutoff is invisible to it** and the
    answer contains no signal that anything is missing. For a security tool
    that is a correctness failure, not a quality one — and an ungrounded
    research answer folded silently into the runbook and persisted to the
    cross-engagement KB is a new unbacked claim that outlives the run.

    So the grounding is stamped wherever the research output goes: the runbook
    and the report. Routing v2 is what made this urgent — Research used to lead
    with Gemini Flash-Lite precisely for native Search Grounding, and Anthropic
    has no equivalent on this path, so the capability was lost with the routing
    change. Stated rather than absorbed.
    """

    #: The provider searched the live web for this answer.
    LIVE_SEARCH = "live_search"
    #: The answer came from the model's training corpus. Bounded by its cutoff.
    TRAINING_DATA = "training_data"
    #: The client never said. Treated as ungrounded everywhere, because
    #: "we do not know whether this saw the web" and "this did not see the web"
    #: license exactly the same claim in a deliverable.
    UNDECLARED = "undeclared"

    @property
    def is_grounded(self) -> bool:
        """Whether output produced under this grounding may be called grounded."""
        return self is ResearchGrounding.LIVE_SEARCH


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

    #: What this client's :meth:`research` answers are grounded in. Every
    #: shipped client overrides it (asserted by
    #: ``tests/test_llm/test_research_grounding.py``); the default is
    #: ``UNDECLARED`` rather than an abstract method so a test double and a
    #: third-party client keep working — and ``UNDECLARED`` is treated as
    #: ungrounded, which is the direction that cannot overstate.
    RESEARCH_GROUNDING: ResearchGrounding = ResearchGrounding.UNDECLARED

    def research_grounding(self) -> ResearchGrounding:
        """What the answer this client would give is grounded in.

        A method rather than a bare attribute read because the resilient client
        overrides it: which provider *served* a research call is only known
        after the chain resolves, and it is the one that served it whose
        grounding the answer actually has.
        """
        return self.RESEARCH_GROUNDING

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
    async def generate_text(
        self, prompt: PromptLike, *, budget: OutputBudget = OutputBudget.DEFAULT
    ) -> str:
        """Generate free-form text from a prompt without tool calling.

        Args:
            prompt: Either a plain string, or :class:`PromptSegments` declaring
                which leading bytes repeat across the calls of one engagement.
                A client that cannot exploit the split flattens it and behaves
                exactly as it did for the string form.
            budget: Which ceiling policy to apply (:class:`OutputBudget`). A
                client with a single fixed ceiling may ignore it; the default
                is the behaviour every call had before the policy existed.

        Returns:
            Generated text. Never the empty string — a response carrying no
            text raises :class:`EmptyResponseError` so the failure is visible
            to the fallback chain instead of flowing on as a plausible answer.

        Raises:
            EmptyResponseError: The provider returned no usable text.
        """
        ...
