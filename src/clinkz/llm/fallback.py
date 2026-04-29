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
    LLMClient,
    LLMMessage,
    LLMTimeoutError,
    LLMUnavailableError,
    RateLimitError,
    ServiceUnavailableError,
)
from clinkz.llm.factory import AGENT_PROVIDER_SETTINGS, get_llm_client

logger = logging.getLogger(__name__)


#: Fallback chain per profile. ``reasoning`` prioritises Claude (best for
#: multi-step planning); ``fast`` prioritises Gemini Flash (cheap + high
#: volume). Ollama is intentionally omitted: the client is still a stub,
#: so putting it in a production chain guarantees terminal failure. Add
#: it back once the Ollama client is fully implemented.
LLM_FALLBACK_CHAINS: dict[str, list[str]] = {
    "reasoning": ["anthropic", "gemini", "openai"],
    "fast": ["gemini", "anthropic", "openai"],
}

#: Maps an agent role to the profile whose fallback chain it should use.
AGENT_LLM_PROFILE: dict[str, str] = {
    "recon": "fast",
    "scan": "fast",
    "crawl": "fast",
    "report": "fast",
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
    """

    def __init__(
        self,
        agent_role: str,
        config: Settings | None = None,
        *,
        override_chain: list[str] | None = None,
    ) -> None:
        self.agent_role = agent_role
        self.config = config or global_settings
        self.profile = AGENT_LLM_PROFILE.get(agent_role, "fast")

        if override_chain is not None:
            self.fallback_chain = list(override_chain)
        else:
            self.fallback_chain = self._build_chain(agent_role, self.profile)

        self._clients: dict[str, LLMClient] = {}
        self._last_used_provider: str | None = None
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
            # Exploit pinning may use a different gemini model
            if self.agent_role == "exploit":
                return self.config.gemini_exploit_model
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

    async def generate_text(self, prompt: str) -> str:
        from clinkz.observability.trace import Stopwatch, get_active_trace_writer

        writer = get_active_trace_writer()
        stopwatch = Stopwatch()
        try:
            response = await self._dispatch("generate_text", prompt)
        except Exception as exc:
            if writer is not None:
                writer.llm_call(
                    stage=self.agent_role,
                    provider=self._last_used_provider or "exhausted",
                    model=self._resolve_model(self._last_used_provider),
                    prompt_summary=prompt,
                    response_summary=f"<error: {type(exc).__name__}: {exc}>",
                    duration_ms=stopwatch.elapsed_ms,
                    extra={"profile": self.profile, "chain": self.fallback_chain},
                )
            raise
        if writer is not None:
            writer.llm_call(
                stage=self.agent_role,
                provider=self._last_used_provider or "unknown",
                model=self._resolve_model(self._last_used_provider),
                prompt_summary=prompt,
                response_summary=response,
                duration_ms=stopwatch.elapsed_ms,
                extra={"profile": self.profile, "chain": self.fallback_chain},
            )
        return response

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

        for provider in self.fallback_chain:
            if not self._has_api_key(provider):
                env_var = _API_KEY_ENV.get(provider) or "<no env var>"
                self._logger.warning(
                    "LLM provider %s skipped for agent %s: %s not set",
                    provider,
                    self.agent_role,
                    env_var,
                )
                continue

            try:
                client = self._get_or_create_client(provider)
            except Exception as exc:
                self._logger.warning("Could not instantiate %s: %s", provider, exc)
                last_error = exc
                continue

            try:
                fn = getattr(client, method)
                result = await fn(*args, **kwargs)
                self._last_used_provider = provider
                return result
            except (RateLimitError, ServiceUnavailableError, LLMTimeoutError) as exc:
                self._logger.warning(
                    "LLM provider %s raised %s — trying next in chain",
                    provider,
                    type(exc).__name__,
                )
                last_error = exc
                continue
            except Exception as exc:
                self._logger.error(
                    "LLM provider %s unexpected error (%s) — trying next in chain: %s",
                    provider,
                    type(exc).__name__,
                    exc,
                )
                last_error = exc
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
            self._clients[provider] = get_llm_client(provider)
        return self._clients[provider]


# ---------------------------------------------------------------------------
# Engagement-start validation
# ---------------------------------------------------------------------------


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
