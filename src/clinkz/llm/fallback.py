"""Resilient LLM client — automatic provider fallback on failures.

When a provider returns 429, 503, or times out, the next provider in the
profile's fallback chain is tried. Providers without a configured API key
are silently skipped. If every provider fails, raises LLMUnavailableError.

Why this exists
---------------
A single Gemini 503 with 10 retries at exponential backoff is ~40 minutes
of wasted wall time on one provider. With fallback chains we try each
provider up to ``settings.llm_max_retries`` times with a cap of
``settings.llm_retry_max_delay`` seconds, then move on. Worst case across
four providers is a handful of minutes, not tens.

Usage::

    from clinkz.llm.fallback import ResilientLLMClient

    client = ResilientLLMClient(agent_role="research")
    text   = await client.generate_text("...")
"""

from __future__ import annotations

import logging
import os
from typing import Any

from clinkz.config import Settings
from clinkz.config import settings as global_settings
from clinkz.llm.base import (
    AgentAction,
    CallStats,
    DecisionPathFallbackError,
    LLMClient,
    LLMMessage,
    LLMTimeoutError,
    LLMUnavailableError,
    LLMUsageTotals,
    OutputBudget,
    PromptLike,
    ProviderAccountError,
    ProviderPolicyError,
    RateLimitError,
    ResearchGrounding,
    ServiceUnavailableError,
    flatten_prompt,
)
from clinkz.llm.call_purpose import (
    LLMCallPurpose,
    current_call_purpose,
    current_call_site,
)
from clinkz.llm.degradation import (
    DegradationKind,
    ProviderAbsence,
    ProviderFallback,
    record_provider_absence,
    record_provider_fallback,
)
from clinkz.llm.factory import AGENT_PROVIDER_SETTINGS, get_llm_client
from clinkz.llm.spend import HALT_SPEND_CAP, record_spend, spend_cap_exceeded
from clinkz.observability.ledger import (
    ComponentKind,
    declare_component,
    record_contribution,
    record_fallback,
)

logger = logging.getLogger(__name__)


#: Profiles, retained as trace/telemetry labels rather than as different
#: routings. Under routing v2 they no longer disagree about who goes first:
#: ``reasoning`` and ``fast`` both resolve to
#: ``settings.llm_provider_priority``, which is validated to lead with
#: Anthropic, and ``reasoning_pinned`` is Anthropic with no tail at all.
#:
#: ``fast`` used to lead with Gemini Flash, and that was the hole. It was not a
#: rule anybody would defend once stated — "the cheap tier answers first on
#: recon, scan and report" — it was a cost decision that quietly became a
#: routing decision, and the run's own traces are the evidence: Gemini served
#: the exploit stage 12 times across 9 engagements, 6 of them exploit PLANS and
#: 6 of them false-positive cross-checks, i.e. the suppression path.
#:
#: Ollama stays out: the client is a stub, so putting it in a production chain
#: guarantees terminal failure. Add it back once it is implemented.
LLM_PROFILES: frozenset[str] = frozenset({"reasoning", "reasoning_pinned", "fast"})

#: Kept as a module-level name because callers and tests read it. Derived from
#: the DEFAULT priority; :meth:`ResilientLLMClient._build_chain` reads the
#: priority off its own ``config`` so a Settings override is honoured.
LLM_FALLBACK_CHAINS: dict[str, list[str]] = {
    "reasoning": list(global_settings.llm_provider_priority),
    "reasoning_pinned": ["anthropic"],
    "fast": list(global_settings.llm_provider_priority),
}

#: Roles whose output DECIDES something.
#:
#: The distinction is not "important agent" but *what the answer becomes*:
#:
#: * **exploit** — the plan decides which classes are tested against which
#:   endpoints, and the false-positive cross-check decides which findings
#:   survive to the report. Both are the engagement's conclusions.
#: * **research** — the runbook is folded into the exploit plan and persists to
#:   the cross-engagement knowledge base, so a bad answer outlives the run.
#:
#: Recon and scan are deliberately NOT here. They produce observations that a
#: later oracle re-derives from the live target, so a weaker model there costs
#: recall and cannot manufacture a conclusion. That distinction survives
#: routing v2 even though the ROUTING no longer varies by role: v2 made
#: Anthropic priority 1 everywhere, so the question this set answers is no
#: longer "who may serve it" but "how bad is it that something else did".
CLAUDE_ONLY_ROLES: frozenset[str] = frozenset({"exploit", "research"})

#: Maps an agent role to its profile. Every role is ``reasoning`` now, which is
#: to say every role leads with Anthropic. The mapping is kept rather than
#: deleted because it is where a future per-role divergence would be written,
#: and because the trace records the profile a call ran under.
#:
#: Research is the one that cost something real. It led with Gemini Flash-Lite
#: for native Search Grounding, and that capability does not exist on the
#: Anthropic path — the runbook is now assembled without live grounded search.
#: Stated rather than absorbed: the runbook is folded into the exploit plan and
#: persisted to the cross-engagement KB, so a cheap model's answer there
#: outlives the run that produced it, and "cheap model with live search" is not
#: a trade this role is allowed to make on its own.
AGENT_LLM_PROFILE: dict[str, str] = {
    "recon": "reasoning",
    "scan": "reasoning",
    "crawl": "reasoning",
    "report": "reasoning",
    "exploit": "reasoning",
    "research": "reasoning",
}

#: Environment variable that holds the API key for each provider. ``None``
#: means the provider needs no credential (e.g., a local Ollama server).
_API_KEY_ENV: dict[str, str | None] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "ollama": None,
}

#: Providers observed to be in a terminal ACCOUNT state during this process.
#:
#: Process-wide rather than per-client on purpose: a depleted credit balance is
#: a property of the KEY, and every agent in the run shares it. Discovering it
#: once per ``ResilientLLMClient`` would mean discovering it five times.
#:
#: Engagement ``f6a550a4`` is the case. 79 Anthropic attempts, 76 of them the
#: same ``400 … credit balance is too low``, each one a full round-trip to
#: re-learn a fact established by the first. The chain was working exactly as
#: designed — an unexpected error is treated as retriable, because we would
#: rather finish on a backup than halt on a transient quirk — and that is the
#: right rule for a quirk and the wrong one for an account.
_ACCOUNT_DISABLED_PROVIDERS: set[str] = set()


def reset_account_disabled_providers() -> None:
    """Clear the terminal-account set. For tests and for a fresh process."""
    _ACCOUNT_DISABLED_PROVIDERS.clear()


def _provider_client_class(provider: str) -> type[LLMClient] | None:
    """The client CLASS for a provider, imported but not instantiated.

    Used to read a class-level declaration — today only
    :attr:`LLMClient.RESEARCH_GROUNDING` — without building a client. Building
    one requires a key, opens a connection and can raise, none of which a stamp
    should be able to do. Returns ``None`` for an unknown provider, which every
    caller renders as the undeclared/ungrounded value rather than a guess.
    """
    try:
        if provider == "anthropic":
            from clinkz.llm.anthropic_client import AnthropicClient

            return AnthropicClient
        if provider == "gemini":
            from clinkz.llm.gemini_client import GeminiClient

            return GeminiClient
        if provider == "openai":
            from clinkz.llm.openai_client import OpenAIClient

            return OpenAIClient
        if provider == "ollama":
            from clinkz.llm.ollama_client import OllamaClient

            return OllamaClient
    except Exception as exc:  # noqa: BLE001 — a stamp must never fail a run
        logger.warning("Could not import the client class for %s: %s", provider, exc)
    return None


# ---------------------------------------------------------------------------
# ResilientLLMClient
# ---------------------------------------------------------------------------


class ResilientLLMClient(LLMClient):
    """LLMClient wrapper that cycles through a fallback chain on failure.

    Each agent picks its own profile via ``AGENT_LLM_PROFILE`` so the
    reasoning-heavy agents (exploit, research) lead with Claude while the
    high-volume agents (recon, scan, report) lead with Gemini Flash.

    A per-agent override is honoured: setting ``LLM_PROVIDER_<ROLE>`` (for
    example ``LLM_PROVIDER_RESEARCH=anthropic``) bumps that provider to the
    front of the chain; the remaining providers from the profile are kept
    as further fallbacks.

    Args:
        agent_role: One of ``"recon"``, ``"scan"``, ``"exploit"``,
            ``"research"``, ``"report"``. Unknown roles default to the
            ``"fast"`` profile.
        config: Optional Settings override (mainly for tests). Defaults
            to the process-wide ``settings`` singleton.
        override_chain: Optional explicit chain that bypasses the profile.
            Tests use this to inject a deterministic order.
        exclude_providers: Providers to drop from this client's chain for the
            whole engagement (e.g. a Gemini key the credit pre-flight found
            depleted). The drop is skipped if it would empty the chain, so a
            misconfigured exclusion can never strand the agent.
    """

    def __init__(
        self,
        agent_role: str,
        config: Settings | None = None,
        *,
        override_chain: list[str] | None = None,
        exclude_providers: set[str] | None = None,
    ) -> None:
        self.agent_role = agent_role
        self.config = config or global_settings
        self.profile = AGENT_LLM_PROFILE.get(agent_role, "fast")

        if override_chain is not None:
            self.fallback_chain = list(override_chain)
        else:
            self.fallback_chain = self._build_chain(agent_role, self.profile)

        if exclude_providers:
            filtered = [p for p in self.fallback_chain if p not in exclude_providers]
            if filtered:
                self.fallback_chain = filtered
            else:
                logger.warning(
                    "Excluding %s would empty %s's chain %s — keeping it to avoid stranding",
                    exclude_providers,
                    agent_role,
                    self.fallback_chain,
                )

        self._clients: dict[str, LLMClient] = {}
        self._last_used_provider: str | None = None
        #: Cost/cache accounting for every call this agent made, so the run can
        #: report a measured hit rate rather than an assumed one.
        self.run_totals = LLMUsageTotals()
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._logger.info(
            "ResilientLLMClient initialised — role=%s profile=%s chain=%s",
            agent_role,
            self.profile,
            self.fallback_chain,
        )

    def _resolve_model(self, provider: str | None) -> str:
        """Return the configured model name for a provider, for trace tagging."""
        if not provider:
            return ""
        if provider == "anthropic":
            return self.config.anthropic_model
        if provider == "gemini":
            # Per-role gemini model: Exploit and Research pin their own.
            if self.agent_role == "exploit":
                return self.config.gemini_exploit_model
            if self.agent_role == "research":
                return self.config.gemini_research_model
            return self.config.gemini_model
        if provider == "openai":
            return self.config.agent_model
        if provider == "ollama":
            return "ollama"
        return provider

    # ------------------------------------------------------------------
    # LLMClient interface — each method delegates through the chain
    # ------------------------------------------------------------------

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        return await self._dispatch("reason", messages, tools)

    async def research(self, query: str) -> str:
        """Serve one research call through the chain.

        The grounding of the answer is whatever the provider that ANSWERED
        declares, which is only knowable after the chain resolves — see
        :meth:`research_grounding`.
        """
        return await self._dispatch("research", query)

    def research_grounding(self) -> ResearchGrounding:
        """What the last research answer was grounded in — read from who SERVED it.

        The same rule as ``model_stamp``: configuration says who was asked, the
        run's own record says who answered, and it is the one that answered
        whose capability the output actually has. Before any call has run this
        reports the head of the chain, which is what the next call would get.

        Grounding is the one capability routing v2 traded away. Research led
        with Gemini Flash-Lite for native Search Grounding; Anthropic has no
        equivalent on this path. So a chain that resolves to Anthropic answers
        from a training corpus, every CVE published after its cutoff is
        invisible, and nothing in the text says so. This is the seam that lets
        the runbook and the report say it.
        """
        provider = self._last_used_provider or (
            self.fallback_chain[0] if self.fallback_chain else ""
        )
        if not provider:
            return ResearchGrounding.UNDECLARED
        # Read from an ALREADY-BUILT client when there is one, else off the
        # class. Never instantiate: a stamp must not need an API key, must not
        # cost a connection, and must not be the thing that raises. Same shape
        # as _resolve_model, which reads a provider's model without building it.
        existing = self._clients.get(provider)
        if existing is not None:
            return existing.research_grounding()
        client_class = _provider_client_class(provider)
        if client_class is None:
            self._logger.warning(
                "No client class known for provider %s — reporting research grounding as "
                "UNDECLARED, which is treated as ungrounded",
                provider,
            )
            return ResearchGrounding.UNDECLARED
        return client_class.RESEARCH_GROUNDING

    async def generate_text(
        self, prompt: PromptLike, *, budget: OutputBudget = OutputBudget.DEFAULT
    ) -> str:
        """Serve one text generation through the chain, tracing what answered.

        Args:
            prompt: The prompt, plain or segmented.
            budget: Output-ceiling policy, forwarded verbatim to whichever
                provider serves the call. Forwarded rather than resolved here
                because the ceiling is a function of the model, and which model
                runs is exactly what this method is deciding.
        """
        from clinkz.observability.trace import Stopwatch, get_active_trace_writer

        writer = get_active_trace_writer()
        stopwatch = Stopwatch()
        flat = flatten_prompt(prompt)
        try:
            response = await self._dispatch("generate_text", prompt, budget=budget)
        except Exception as exc:
            if writer is not None:
                writer.llm_call(
                    stage=self.agent_role,
                    provider=self._last_used_provider or "exhausted",
                    model=self._resolve_model(self._last_used_provider),
                    prompt_summary=flat,
                    response_summary=f"<error: {type(exc).__name__}: {exc}>",
                    duration_ms=stopwatch.elapsed_ms,
                    extra={"profile": self.profile, "chain": self.fallback_chain},
                )
            raise
        stats = self._collect_call_stats()
        if writer is not None:
            writer.llm_call(
                stage=self.agent_role,
                provider=self._last_used_provider or "unknown",
                model=self._resolve_model(self._last_used_provider),
                prompt_summary=flat,
                response_summary=response,
                duration_ms=stopwatch.elapsed_ms,
                tokens=stats.billed_prompt_tokens + stats.output_tokens if stats else None,
                extra={
                    "profile": self.profile,
                    "chain": self.fallback_chain,
                    **self._cache_trace_fields(stats),
                },
            )
        return response

    # ------------------------------------------------------------------
    # Call accounting (cost + cache)
    # ------------------------------------------------------------------

    def _collect_call_stats(self) -> CallStats | None:
        """Read back what the provider that just served the call reported.

        Folded into the run totals here rather than at each provider, because
        this is the one place that knows *which* provider actually ran after
        the chain resolved.
        """
        provider = self._last_used_provider
        if provider is None:
            return None
        client = self._clients.get(provider)
        stats = getattr(client, "last_call_stats", None)
        if stats is None:
            return None
        self.run_totals.add(stats)
        self._record_cache_economics(stats)
        # Fold into the engagement's spend ledger here, for the same reason the
        # run totals are folded in here: this is the one place that knows WHICH
        # provider actually served the call after the chain resolved, and the
        # cap is meaningless if it is attributed to the model that was asked.
        record_spend(
            model=self._resolve_model(provider),
            input_tokens=stats.billed_prompt_tokens,
            output_tokens=stats.output_tokens,
        )
        return stats

    @staticmethod
    def _record_cache_economics(stats: CallStats) -> None:
        """Report the prompt cache to the ledger as an ordinary component.

        The cache regression is exactly the shape this ledger exists to catch,
        and it went unseen for a week anyway because nothing was reporting it:
        a component invoked on every planning call, succeeding every time,
        contributing **zero**. 96,759 cache-write tokens and zero cache-read
        tokens across 154 recorded engagements, while every run looked healthy.

        So the cache is a ledger component now, and the item it contributes is
        the only thing a cache is for: **tokens actually served from it**. A
        write with no read trips ``SILENT`` in the run log and in
        ``report.json``, next to every other component that produced nothing.

        A call that never carried a breakpoint is not an invocation — the
        capability was not reached for, so recording it would drown the signal
        in every uncached call the run makes. That is also why this component
        vanishes from the ledger entirely once caching is switched off
        (``settings.llm_prompt_cache_enabled``, now the default): nothing is
        written, nothing is read, and a capability the run never reached for is
        not a degradation. It reported SILENT truthfully for as long as it was
        on, which is what got it switched off.
        """
        if not (stats.cache_creation_input_tokens or stats.cache_read_input_tokens):
            return
        record_contribution(
            name=f"llm:{stats.provider or 'unknown'}:prompt_cache",
            kind=ComponentKind.LLM,
            items=stats.cache_read_input_tokens,
            ok=True,
            note=(
                f"write={stats.cache_creation_input_tokens} "
                f"read={stats.cache_read_input_tokens} uncached={stats.input_tokens}"
            ),
        )

    @staticmethod
    def _cache_trace_fields(stats: CallStats | None) -> dict[str, Any]:
        """Trace fields for one call's cache behaviour.

        Recorded per call so a hit rate can be *derived from the trace* after
        the fact instead of asserted. ``cache_read``/``cache_write`` of zero on
        a provider that reports no cache accounting is a "not reported", which
        is why ``provider`` rides along.
        """
        if stats is None:
            return {}
        return {
            "input_tokens": stats.input_tokens,
            "output_tokens": stats.output_tokens,
            "cache_write_tokens": stats.cache_creation_input_tokens,
            "cache_read_tokens": stats.cache_read_input_tokens,
            "stop_reason": stats.stop_reason,
            # The ceiling the call carried, so headroom is derivable from the
            # trace alone. output_tokens without it cannot distinguish a
            # complete answer from a truncated one. ``None`` rather than 0 when
            # the provider that served the call sets no per-request ceiling —
            # zero headroom is what exhaustion looks like, and "not reported"
            # must not read as "exhausted".
            "max_output_tokens": stats.max_output_tokens or None,
            "output_headroom": stats.output_headroom if stats.max_output_tokens else None,
        }

    # ------------------------------------------------------------------
    # Core dispatch with fallback
    # ------------------------------------------------------------------

    async def _dispatch(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke ``method`` on each provider in the chain until one succeeds.

        Retriable errors (``RateLimitError``, ``ServiceUnavailableError``,
        ``LLMTimeoutError``) trigger a jump to the next provider. Any other
        exception is also logged and treated as retriable — we'd rather
        finish the engagement on a backup than halt on a transient provider
        quirk.
        """
        # The spend cap, checked BEFORE the call so the run stops AT the cap
        # rather than one unbounded call past it. A halt rather than an
        # exception: raising here would land in one of the methodology layers'
        # broad handlers and be reported as "that probe failed", while the
        # governor's halt winds the phases down cooperatively and still
        # produces the report — which matters most exactly when the cap fires.
        exceeded = spend_cap_exceeded()
        if exceeded:
            from clinkz.safety.governor import get_active_governor

            governor = get_active_governor()
            if governor is not None and not governor.halted:
                governor.halt(HALT_SPEND_CAP, exceeded)
            raise LLMUnavailableError(f"LLM budget exhausted — {exceeded}")

        last_error: Exception | None = None
        # The provider we actually reached for first. A later provider serving
        # the call is a fallback ACTIVATION, and it is recorded — this is the
        # exact mechanism that absorbed an LLM timeout so completely that the
        # engagement produced an answer and no gate noticed the primary had
        # produced nothing.
        first_attempted: str = ""

        for provider in self.fallback_chain:
            declare_component(name=f"llm:{provider}", kind=ComponentKind.LLM_PROVIDER)
            if provider in _ACCOUNT_DISABLED_PROVIDERS:
                self._logger.debug(
                    "LLM provider %s skipped for agent %s: terminal account condition "
                    "already observed this run",
                    provider,
                    self.agent_role,
                )
                continue
            if not self._has_api_key(provider):
                env_var = _API_KEY_ENV.get(provider) or "<no env var>"
                self._logger.warning(
                    "LLM provider %s skipped for agent %s: %s not set",
                    provider,
                    self.agent_role,
                    env_var,
                )
                continue

            if not first_attempted:
                first_attempted = provider

            # The disqualification gate — the last statement before the
            # request leaves. Placed here and not in `_build_chain` because a
            # chain is a plan and this is the call: `override_chain`, an
            # `exclude_providers` that reshuffled the head, or a future edit to
            # the priority order would each route around a config-time check.
            self._assert_fallback_permitted(provider, primary=self.fallback_chain[0])

            try:
                client = self._get_or_create_client(provider)
            except ProviderPolicyError:
                raise
            except Exception as exc:
                self._logger.warning("Could not instantiate %s: %s", provider, exc)
                last_error = exc
                record_contribution(
                    name=f"llm:{provider}",
                    kind=ComponentKind.LLM_PROVIDER,
                    ok=False,
                    note=f"instantiation failed: {type(exc).__name__}",
                )
                continue

            try:
                fn = getattr(client, method)
                result = await fn(*args, **kwargs)
                self._last_used_provider = provider
                record_contribution(
                    name=f"llm:{provider}",
                    kind=ComponentKind.LLM_PROVIDER,
                    items=1,
                    ok=True,
                    note=f"{self.agent_role}.{method}",
                )
                if provider != first_attempted:
                    reason = type(last_error).__name__ if last_error else "chain rotation"
                    # The ledger alarm fires in EVERY mode. It is the record
                    # that something covered for something else, and it is
                    # independent of what that cost the run.
                    record_fallback(
                        component=f"llm:{first_attempted}",
                        covered_by=f"llm:{provider}",
                        reason=reason,
                    )
                    # The disqualification. Separate from the ledger because it
                    # answers a different question: not "did a fallback happen"
                    # but "may this run's numbers be compared to another's".
                    record_provider_fallback(
                        ProviderFallback(
                            agent_role=self.agent_role,
                            method=method,
                            asked_provider=first_attempted,
                            asked_model=self._resolve_model(first_attempted),
                            served_provider=provider,
                            served_model=self._resolve_model(provider),
                            reason=reason,
                            decision_bearing=self.agent_role in CLAUDE_ONLY_ROLES,
                        )
                    )
                return result
            except ProviderAccountError as exc:
                # Terminal for the rest of the process, not for this call: the
                # chain still falls through to the next provider so the
                # engagement completes, but nobody asks this one again.
                self._logger.error(
                    "LLM provider %s is in a terminal account state — excluding it for the "
                    "remainder of this run (every later call would repeat the same "
                    "refusal): %s",
                    provider,
                    exc,
                )
                _ACCOUNT_DISABLED_PROVIDERS.add(provider)
                last_error = exc
                record_contribution(
                    name=f"llm:{provider}",
                    kind=ComponentKind.LLM_PROVIDER,
                    ok=False,
                    note=f"ProviderAccountError (provider disabled for this run): {exc}",
                )
                # An exclusion is a degradation with no substitution in it. Every
                # LATER call in this engagement runs against a shorter chain than
                # the configured one, and is silent about it at each of those
                # sites — so the disqualification is recorded once, here, where
                # the fact is known.
                record_provider_absence(
                    ProviderAbsence(
                        agent_role=self.agent_role,
                        method=method,
                        kind=DegradationKind.TERMINAL_EXCLUSION,
                        provider=provider,
                        chain=tuple(self.fallback_chain),
                        reason=type(exc).__name__,
                        decision_bearing=self.agent_role in CLAUDE_ONLY_ROLES,
                    )
                )
                continue
            except (RateLimitError, ServiceUnavailableError, LLMTimeoutError) as exc:
                self._logger.warning(
                    "LLM provider %s raised %s — trying next in chain",
                    provider,
                    type(exc).__name__,
                )
                last_error = exc
                record_contribution(
                    name=f"llm:{provider}",
                    kind=ComponentKind.LLM_PROVIDER,
                    ok=False,
                    note=type(exc).__name__,
                )
                continue
            except ProviderPolicyError:
                raise
            except Exception as exc:
                self._logger.error(
                    "LLM provider %s unexpected error (%s) — trying next in chain: %s",
                    provider,
                    type(exc).__name__,
                    exc,
                )
                last_error = exc
                record_contribution(
                    name=f"llm:{provider}",
                    kind=ComponentKind.LLM_PROVIDER,
                    ok=False,
                    note=type(exc).__name__,
                )
                continue

        # The chain ran out. NOTHING answered, so there is no served provider to
        # name and no ProviderFallback that could hold this — which is precisely
        # why it went unrecorded and a run that failed every phase reported
        # itself eligible as a baseline. An absence is the strictly worse
        # degradation: a substituted answer is at least an answer.
        record_provider_absence(
            ProviderAbsence(
                agent_role=self.agent_role,
                method=method,
                kind=DegradationKind.CHAIN_EXHAUSTED,
                chain=tuple(self.fallback_chain),
                reason=type(last_error).__name__ if last_error else "no provider available",
                decision_bearing=self.agent_role in CLAUDE_ONLY_ROLES,
            )
        )
        raise LLMUnavailableError(
            f"All providers exhausted for profile '{self.profile}' "
            f"(chain={self.fallback_chain}): {last_error}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_fallback_permitted(self, provider: str, *, primary: str) -> None:
        """Refuse a fallback that this run, or this call, must not take.

        Called before the request leaves, so the run fails *instead of* buying
        an answer it would have to throw away.

        Two independent refusals, and they answer different questions.

        **The run's mode — comparability.** In ``baseline`` mode nothing but
        the primary may answer, for **every** role and not only the
        decision-bearing ones. ``exploit`` and ``research`` are the roles whose
        answers become conclusions, and a substitution there is a correctness
        problem. But the reason baseline mode exists is comparability, and that
        is broken by any stage: the 27%-vs-80% swing that motivated the model
        stamp was measured on *security-header analysis*, a scan/report-side
        call producing what looks like a pure observation. A ladder number
        produced half by one model and half by another is not a measurement of
        the target, whichever phase did the producing.
        :data:`CLAUDE_ONLY_ROLES` still marks where a fallback is *also* a
        correctness problem, and the register records which kind each event was.

        **The call's purpose — disclosability.** In ``client`` mode a fallback
        is permitted and stamped, because a client engagement should not die
        because a provider had a bad minute and because reduced coverage is a
        thing a stamp can honestly disclose. That reasoning does not extend to a
        call whose answer EMITS a finding or SUPPRESSES one
        (:mod:`clinkz.llm.call_purpose`). A suppressed finding is not in the
        report: there is no row to caveat, no section that names it, and nothing
        distinguishes "the engine did not find it" from "a provider we did not
        choose decided it was not real". Six of the twelve recorded
        Gemini-served exploit calls were false-positive cross-checks — the
        suppression path — so this is the observed failure, not a hypothetical
        one. Refusing is the conservative direction on both paths: the caller's
        existing unreachable-model handling leaves the finding standing and the
        methodology on its deterministic build.

        Args:
            provider: The provider about to be asked.
            primary: The head of this client's chain.

        Raises:
            ProviderPolicyError: The fallback is refused. Deliberately a
                ``BaseException``: every LLM call site is wrapped in a broad
                ``except Exception`` that degrades gracefully, which is the
                behaviour being refused.
        """
        if provider == primary:
            return

        # The run-mode refusal is checked FIRST, and raises the uncatchable
        # error, because a baseline run wants the RUN to stop — on any role and
        # any purpose. The purpose refusal below wants only the CALL to stop.
        if self.config.run_mode == "baseline":
            raise ProviderPolicyError(
                f"Baseline run: refusing to let '{provider}' serve "
                f"'{self.agent_role}' after primary '{primary}' failed "
                f"(chain={self.fallback_chain}). A ladder served by two models is "
                f"not a ladder — the same prompt on a byte-identical observation "
                f"has produced materially different findings across models, so a "
                f"number produced partly by each measures nothing about the target. "
                f"Re-run once the primary is healthy, or set CLINKZ_RUN_MODE=client "
                f"to complete the run with a provider_degraded stamp and no "
                f"baseline eligibility."
            )

        purpose = current_call_purpose()
        if purpose.permits_fallback:
            return
        site = current_call_site() or self.agent_role
        effect = (
            "REMOVES findings from the report"
            if purpose is LLMCallPurpose.SUPPRESS
            else "shapes a finding that reaches the report"
        )
        raise DecisionPathFallbackError(
            f"Refusing to let '{provider}' serve '{site}' after primary "
            f"'{primary}' failed (chain={self.fallback_chain}). This call is "
            f"declared {purpose.value.upper()}: its answer {effect}. The "
            f"provider_degraded stamp can disclose reduced coverage; it cannot "
            f"disclose a finding that was {purpose.value}ed and is therefore not "
            f"in the deliverable. Planning calls still fall back and stamp. This "
            f"call fails instead, and its caller degrades the way it already does "
            f"when a model is unreachable — leaving the finding standing, and the "
            f"methodology on its deterministic build."
        )

    def _build_chain(self, agent_role: str, profile: str) -> list[str]:
        """Compute the effective fallback chain for an agent role.

        ``settings.llm_provider_priority`` is the baseline, and it is validated
        to lead with Anthropic. ``LLM_PROVIDER_<ROLE>`` (or the legacy
        ``<ROLE>_LLM_PROVIDER``) still has an effect, but a **narrowed** one: it
        promotes its provider to the head of the FALLBACK TAIL — position 2 —
        and can no longer displace position 1.

        That narrowing is the point of routing v2 and it is a real behaviour
        change, so it is worth being explicit about what it forbids. Before
        this, ``LLM_PROVIDER_RECON=gemini`` meant "Gemini answers recon", and
        the setting reads exactly like it still should. It now means "if
        Anthropic cannot answer recon, try Gemini before OpenAI". An operator
        who genuinely wants a non-Anthropic provider serving a phase has to
        change the declared priority in config, where the change is one line,
        visible, and validated — rather than reaching it sideways through a
        per-role env var that looks like a preference.
        """
        if profile == "reasoning_pinned":
            return ["anthropic"]

        base = list(self.config.llm_provider_priority)

        setting_name = AGENT_PROVIDER_SETTINGS.get(agent_role)
        configured: str | None = None
        if setting_name is not None:
            configured = getattr(self.config, setting_name, None)

        if configured and configured != base[0]:
            if configured in base:
                base.remove(configured)
            # Position 1, never 0: the head is Anthropic and stays Anthropic.
            base.insert(1, configured)

        return base

    def has_usable_provider(self) -> bool:
        """Return True if at least one provider in the chain has a configured API key.

        Used at engagement start to fail fast when no LLM backend is reachable,
        rather than waiting for the first real request to exhaust the chain.
        """
        return any(self._has_api_key(p) for p in self.fallback_chain)

    def _has_api_key(self, provider: str) -> bool:
        """Return True if the provider has a usable credential or needs none."""
        env_var = _API_KEY_ENV.get(provider)
        if env_var is None:
            return True  # Ollama / local providers need no key
        # Prefer live env (tests monkeypatch os.environ) then config snapshot.
        if os.getenv(env_var):
            return True
        # Special-case Gemini's legacy GOOGLE_API_KEY fallback.
        if provider == "gemini" and os.getenv("GOOGLE_API_KEY"):
            return True
        if provider == "anthropic" and self.config.anthropic_api_key:
            return True
        if provider == "gemini" and (self.config.gemini_api_key or self.config.google_api_key):
            return True
        if provider == "openai" and self.config.openai_api_key:
            return True
        return False

    def _get_or_create_client(self, provider: str) -> LLMClient:
        """Cache one underlying client per provider for the life of this wrapper."""
        if provider not in self._clients:
            self._clients[provider] = get_llm_client(
                provider, model=self._client_model_override(provider)
            )
        return self._clients[provider]

    def _client_model_override(self, provider: str) -> str | None:
        """Construction-time model override for the underlying client.

        Only Research pins a distinct Gemini model (``gemini_research_model`` =
        Flash-Lite); every other role passes ``None`` so the client keeps its
        own default (Recon/Scan/Report → ``gemini_model``). This keeps the
        per-agent model behaviour of the unchanged roles byte-identical.
        """
        if provider == "gemini" and self.agent_role == "research":
            return self.config.gemini_research_model
        return None


# ---------------------------------------------------------------------------
# Engagement-start validation
# ---------------------------------------------------------------------------


async def preflight_provider_available(
    provider: str,
    config: Settings | None = None,
) -> bool:
    """One cheap probe to detect a depleted/unavailable provider at engagement start.

    Run alongside ``ensure_container_ready`` so depletion is caught up front —
    not mid-pipeline after every agent has stormed 429s. The single probe is
    bounded by the underlying client's own retry budget
    (``settings.llm_max_retries`` capped at ``llm_retry_max_delay``), so a
    depleted key fails fast here instead of N times across the engagement.

    Args:
        provider: Provider name to probe (e.g. ``"gemini"``).
        config: Optional Settings override. Defaults to the process-wide settings.

    Returns:
        ``False`` if the probe hit a rate-limit (429 / RESOURCE_EXHAUSTED),
        service-unavailable, timeout, or unavailable error — the signal to
        route the engagement to a fallback provider. ``True`` on success, and
        conservatively ``True`` on any unexpected error so a transient quirk
        never needlessly abandons the cheaper primary provider.
    """
    cfg = config or global_settings
    model = cfg.gemini_model if provider == "gemini" else None
    try:
        client = get_llm_client(provider, model=model)
    except Exception as exc:
        logger.warning(
            "Pre-flight could not instantiate %s (%s) — treating as unavailable",
            provider,
            exc,
        )
        return False

    try:
        await client.generate_text("ping")
        return True
    except (RateLimitError, ServiceUnavailableError, LLMTimeoutError, LLMUnavailableError) as exc:
        logger.warning(
            "Pre-flight probe for %s failed (%s) — provider unavailable for this engagement",
            provider,
            type(exc).__name__,
        )
        return False
    except Exception as exc:  # noqa: BLE001 — be conservative on unknown errors
        logger.warning(
            "Pre-flight probe for %s raised unexpected %s — assuming available",
            provider,
            type(exc).__name__,
        )
        return True


def validate_agent_chains(
    roles: list[str],
    config: Settings | None = None,
) -> None:
    """Verify every agent's fallback chain has at least one provider with an API key.

    Raises ``LLMUnavailableError`` before any agent runs when validation fails —
    better to fail in 2 seconds than waste a full pipeline run hitting an empty
    chain on every LLM call.

    Args:
        roles: Agent roles to check (e.g., ``["recon", "scan", "exploit"]``).
        config: Optional Settings override. Defaults to the process-wide settings.

    Raises:
        LLMUnavailableError: If any role has no usable provider in its chain.
    """
    cfg = config or global_settings
    missing: list[tuple[str, list[str]]] = []
    for role in roles:
        probe = ResilientLLMClient(role, config=cfg)
        if not probe.has_usable_provider():
            missing.append((role, probe.fallback_chain))
    if missing:
        details = "; ".join(f"{role} (chain={chain})" for role, chain in missing)
        raise LLMUnavailableError(
            f"No configured LLM provider for agents: {details}. "
            f"Set at least one of ANTHROPIC_API_KEY, GEMINI_API_KEY, or OPENAI_API_KEY."
        )
