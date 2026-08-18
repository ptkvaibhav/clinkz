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
    ServiceUnavailableError,
    flatten_prompt,
)
from clinkz.llm.factory import AGENT_PROVIDER_SETTINGS, get_llm_client
from clinkz.observability.ledger import (
    ComponentKind,
    declare_component,
    record_contribution,
    record_fallback,
)

logger = logging.getLogger(__name__)


#: Fallback chain per profile. ``reasoning`` prioritises Claude (best for
#: multi-step planning); ``fast`` prioritises Gemini Flash (cheap + high
#: volume). ``reasoning_pinned`` is a single-provider chain — Claude only,
#: no fallback — used by Exploit-Agent methodology checkpoints (character
#: probing, payload synthesis, encoding selection) where switching mid-test
#: from Claude to Gemini changes the deterministic path the test depends on.
#: Ollama is intentionally omitted from the fallback chains: the client is
#: still a stub, so putting it in a production chain guarantees terminal
#: failure. Add it back once the Ollama client is fully implemented.
LLM_FALLBACK_CHAINS: dict[str, list[str]] = {
    "reasoning": ["anthropic", "openai"],
    "reasoning_pinned": ["anthropic"],
    "fast": ["gemini", "anthropic", "openai"],
}

#: Roles whose output DECIDES something, and which therefore may not be served
#: by the cheap tier — not as a primary, and not as a fallback either.
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
#: recall and cannot manufacture a conclusion.
#:
#: The chain was already ``["anthropic", "gemini", "openai"]`` for exploit and
#: Gemini-led for research, and both fired: across 164 recorded traces Gemini
#: served the exploit stage 12 times in 9 engagements — 6 exploit PLANS and 6
#: FP cross-checks. The cross-check is the suppression path, so the cheap tier
#: has already been the thing deciding which confirmed findings were demoted.
CLAUDE_ONLY_ROLES: frozenset[str] = frozenset({"exploit", "research"})

#: Providers that may serve a :data:`CLAUDE_ONLY_ROLES` call.
CLAUDE_PROVIDERS: frozenset[str] = frozenset({"anthropic"})

#: Maps an agent role to the profile whose fallback chain it should use.
AGENT_LLM_PROFILE: dict[str, str] = {
    "recon": "fast",
    "scan": "fast",
    "crawl": "fast",
    "report": "fast",
    "exploit": "reasoning",
    # Research LED with Gemini Flash-Lite for its native Search Grounding, and
    # that is exactly what this now forbids: the runbook decides what the
    # exploit phase reaches for and is written into the persistent KB. The
    # capability cost is real and is stated rather than absorbed — see
    # ``_build_chain`` — but "cheap model with live search" is not a trade this
    # role is allowed to make.
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
        return await self._dispatch("research", query)

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

            # The runtime gate. `_build_chain` already filters these roles, but
            # a chain is a plan and this is the call: `override_chain`, a later
            # edit to a profile, or a role added to CLAUDE_ONLY_ROLES without
            # its chain being revisited would each route around the config-time
            # filter. This is the last statement before the request leaves.
            self._assert_provider_permitted(provider)

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
                    record_fallback(
                        component=f"llm:{first_attempted}",
                        covered_by=f"llm:{provider}",
                        reason=type(last_error).__name__ if last_error else "chain rotation",
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

        raise LLMUnavailableError(
            f"All providers exhausted for profile '{self.profile}' "
            f"(chain={self.fallback_chain}): {last_error}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _assert_provider_permitted(self, provider: str) -> None:
        """Refuse to let a forbidden provider serve a decision-bearing role.

        Args:
            provider: The provider about to be asked.

        Raises:
            ProviderPolicyError: ``self.agent_role`` is in
                :data:`CLAUDE_ONLY_ROLES` and *provider* is not a Claude
                provider. The engagement fails here rather than continuing on
                an answer whose author it would have to caveat.
        """
        if self.agent_role not in CLAUDE_ONLY_ROLES:
            return
        if provider in CLAUDE_PROVIDERS:
            return
        raise ProviderPolicyError(
            f"Refusing to serve decision-bearing role '{self.agent_role}' with provider "
            f"'{provider}' (chain={self.fallback_chain}). Only {sorted(CLAUDE_PROVIDERS)} "
            f"may plan, judge, or research: this role's output decides what gets tested "
            f"and what gets reported, so a substitution here invalidates the engagement "
            f"rather than degrading it."
        )

    def _build_chain(self, agent_role: str, profile: str) -> list[str]:
        """Compute the effective fallback chain for an agent role.

        The profile chain is the baseline. If ``LLM_PROVIDER_<ROLE>`` (or the
        legacy ``<ROLE>_LLM_PROVIDER``) pins a provider, move it to the
        front; the remaining providers keep their relative order.
        """
        base = list(LLM_FALLBACK_CHAINS.get(profile, LLM_FALLBACK_CHAINS["fast"]))

        setting_name = AGENT_PROVIDER_SETTINGS.get(agent_role)
        configured: str | None = None
        if setting_name is not None:
            configured = getattr(self.config, setting_name, None)

        if configured and configured in base:
            base.remove(configured)
            base.insert(0, configured)
        elif configured and configured not in base:
            base.insert(0, configured)

        return self._enforce_claude_only(agent_role, base)

    def _enforce_claude_only(self, agent_role: str, chain: list[str]) -> list[str]:
        """Drop every non-Claude provider from a role whose answer decides something.

        Applied AFTER the ``LLM_PROVIDER_<ROLE>`` override, which is the only
        placement that works: the override inserts its provider at the FRONT of
        the chain, so filtering the profile first would leave
        ``LLM_PROVIDER_EXPLOIT=gemini`` free to put the cheap tier ahead of
        Claude. A configuration switch must not be able to reach a decision this
        rule exists to keep away from it.

        The chain is allowed to become empty and is NOT back-filled. An empty
        chain raises :class:`LLMUnavailableError` on the first call, which is
        the intended outcome: an engagement whose plan or runbook cannot be
        served by Claude has no honest way to continue, and quietly substituting
        a weaker model is precisely the failure this replaces.
        """
        if agent_role not in CLAUDE_ONLY_ROLES:
            return chain
        allowed = [p for p in chain if p in CLAUDE_PROVIDERS]
        dropped = [p for p in chain if p not in CLAUDE_PROVIDERS]
        if dropped:
            # Module logger, not ``self._logger``: this runs from __init__
            # before the per-instance logger exists.
            logger.info(
                "Role %s is decision-bearing: dropped %s from its chain, leaving %s. "
                "A cheaper provider may not plan, judge, or research for this engagement.",
                agent_role,
                dropped,
                allowed,
            )
        return allowed

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
