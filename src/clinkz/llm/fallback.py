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
    PromptLike,
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
    "reasoning": ["anthropic", "gemini", "openai"],
    "reasoning_pinned": ["anthropic"],
    "fast": ["gemini", "anthropic", "openai"],
}

#: Maps an agent role to the profile whose fallback chain it should use.
AGENT_LLM_PROFILE: dict[str, str] = {
    "recon": "fast",
    "scan": "fast",
    "crawl": "fast",
    "report": "fast",
    "exploit": "reasoning",
    # Research now leads with Gemini Flash-Lite (cheap, high-volume, native
    # Search Grounding) → fast profile. Anthropic/OpenAI remain as fallbacks.
    "research": "fast",
}

#: Environment variable that holds the API key for each provider. ``None``
#: means the provider needs no credential (e.g., a local Ollama server).
_API_KEY_ENV: dict[str, str | None] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "ollama": None,
}


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

    async def generate_text(self, prompt: PromptLike) -> str:
        from clinkz.observability.trace import Stopwatch, get_active_trace_writer

        writer = get_active_trace_writer()
        stopwatch = Stopwatch()
        flat = flatten_prompt(prompt)
        try:
            response = await self._dispatch("generate_text", prompt)
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
        return stats

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

            try:
                client = self._get_or_create_client(provider)
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
