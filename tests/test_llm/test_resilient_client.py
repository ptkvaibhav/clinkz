"""Tests for ResilientLLMClient — fallback chains and per-agent role routing.

These tests never touch real provider SDKs. Fake LLMClient stand-ins are
registered via the module-level factory so we can verify:

  - the primary provider is used on success;
  - 429 / 503 / timeout on the primary triggers a jump to the next provider;
  - missing API keys are silently skipped;
  - all-providers-failed raises ``LLMUnavailableError``;
  - agent role drives the right profile chain;
  - per-agent env var override bumps a provider to the front.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.llm import fallback as fallback_mod
from clinkz.llm.base import (
    AgentAction,
    LLMClient,
    LLMMessage,
    LLMTimeoutError,
    LLMUnavailableError,
    RateLimitError,
    ServiceUnavailableError,
)
from clinkz.llm.fallback import (
    AGENT_LLM_PROFILE,
    LLM_FALLBACK_CHAINS,
    ResilientLLMClient,
    validate_agent_chains,
)

# ---------------------------------------------------------------------------
# Fake LLM client + registry
# ---------------------------------------------------------------------------


class _FakeLLM(LLMClient):
    """Scripted LLMClient that plays back a list of behaviours per call."""

    def __init__(self, name: str, behaviours: list[Any]) -> None:
        self.name = name
        self._behaviours = list(behaviours)
        self.calls: int = 0

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        return await self._next()

    async def research(self, query: str) -> str:
        return await self._next()

    async def generate_text(self, prompt: str) -> str:
        return await self._next()

    async def _next(self) -> Any:
        self.calls += 1
        if not self._behaviours:
            raise AssertionError(f"{self.name} called more times than scripted")
        nxt = self._behaviours.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _register(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, LLMClient]) -> None:
    """Patch ``get_llm_client`` so ``ResilientLLMClient`` resolves fakes."""

    def fake_factory(provider: str | None = None, *, agent_role: str | None = None) -> LLMClient:
        key = provider or "__default__"
        if key not in mapping:
            raise RuntimeError(f"No fake registered for provider {key!r}")
        return mapping[key]

    monkeypatch.setattr(fallback_mod, "get_llm_client", fake_factory)


def _set_all_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every cloud provider has a usable API key."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)


def _clear_all_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend no cloud provider is configured."""
    for var in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# 1. Primary succeeds — no fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_primary_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    primary = _FakeLLM("anthropic", ["ok-from-anthropic"])
    secondary = _FakeLLM("gemini", ["should-not-be-called"])
    _register(monkeypatch, {"anthropic": primary, "gemini": secondary, "openai": secondary})

    client = ResilientLLMClient(agent_role="research")
    result = await client.generate_text("hi")

    assert result == "ok-from-anthropic"
    assert primary.calls == 1
    assert secondary.calls == 0


# ---------------------------------------------------------------------------
# 2. Fallback on rate-limit (429)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fallback_on_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    primary = _FakeLLM("anthropic", [RateLimitError("429 on anthropic")])
    secondary = _FakeLLM("gemini", ["ok-from-gemini"])
    _register(monkeypatch, {"anthropic": primary, "gemini": secondary, "openai": secondary})

    client = ResilientLLMClient(agent_role="research")
    result = await client.generate_text("hi")

    assert result == "ok-from-gemini"
    assert primary.calls == 1
    assert secondary.calls == 1


# ---------------------------------------------------------------------------
# 3. Fallback on 503
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fallback_on_503(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    primary = _FakeLLM("gemini", [ServiceUnavailableError("503 Service Unavailable")])
    secondary = _FakeLLM("anthropic", ["ok-from-anthropic"])
    _register(monkeypatch, {"gemini": primary, "anthropic": secondary, "openai": secondary})

    # 'recon' → fast profile → gemini first, anthropic second
    client = ResilientLLMClient(agent_role="recon")
    result = await client.generate_text("hi")

    assert result == "ok-from-anthropic"
    assert primary.calls == 1
    assert secondary.calls == 1


# ---------------------------------------------------------------------------
# 4. Fallback on timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fallback_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    primary = _FakeLLM("anthropic", [LLMTimeoutError("request timed out")])
    secondary = _FakeLLM("gemini", ["ok-from-gemini"])
    _register(monkeypatch, {"anthropic": primary, "gemini": secondary, "openai": secondary})

    client = ResilientLLMClient(agent_role="exploit")
    result = await client.generate_text("hi")

    assert result == "ok-from-gemini"
    assert primary.calls == 1


# ---------------------------------------------------------------------------
# 5. All providers exhausted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_providers_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    anthropic = _FakeLLM("anthropic", [RateLimitError("429")])
    gemini = _FakeLLM("gemini", [ServiceUnavailableError("503")])
    openai = _FakeLLM("openai", [LLMTimeoutError("timeout")])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": openai})

    client = ResilientLLMClient(agent_role="research")
    with pytest.raises(LLMUnavailableError):
        await client.generate_text("hi")

    assert anthropic.calls == 1
    assert gemini.calls == 1
    assert openai.calls == 1


# ---------------------------------------------------------------------------
# 6. Skips unconfigured providers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skips_unconfigured_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all_keys(monkeypatch)
    # Only Gemini is configured.
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini")

    anthropic = _FakeLLM("anthropic", ["never-called"])
    gemini = _FakeLLM("gemini", ["ok-from-gemini"])
    openai = _FakeLLM("openai", ["never-called"])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": openai})

    # 'research' → reasoning chain starts with anthropic → should be skipped
    client = ResilientLLMClient(agent_role="research")
    result = await client.generate_text("hi")

    assert result == "ok-from-gemini"
    assert anthropic.calls == 0
    assert openai.calls == 0


# ---------------------------------------------------------------------------
# 7. Agent role selects correct profile
# ---------------------------------------------------------------------------


def test_agent_role_selects_correct_profile() -> None:
    for role in ("exploit", "research"):
        client = ResilientLLMClient(agent_role=role)
        assert client.profile == "reasoning"
        assert client.fallback_chain[0] == "anthropic"

    for role in ("recon", "scan", "report"):
        client = ResilientLLMClient(agent_role=role)
        assert client.profile == "fast"
        assert client.fallback_chain[0] == "gemini"


def test_profile_tables_match_chains() -> None:
    for profile in AGENT_LLM_PROFILE.values():
        assert profile in LLM_FALLBACK_CHAINS


# ---------------------------------------------------------------------------
# 8. Per-agent env var override bumps provider to front of chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_agent_config_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    # Research defaults to anthropic-first. Flip to gemini-first via override.
    monkeypatch.setenv("LLM_PROVIDER_RESEARCH", "gemini")

    # Reload settings so the new env var is picked up.
    from clinkz import config as config_mod

    fresh = config_mod.Settings.from_env()
    assert fresh.research_llm_provider == "gemini"

    anthropic = _FakeLLM("anthropic", ["never-called"])
    gemini = _FakeLLM("gemini", ["ok-from-gemini"])
    _register(monkeypatch, {"gemini": gemini, "anthropic": anthropic, "openai": anthropic})

    client = ResilientLLMClient(agent_role="research", config=fresh)

    # Gemini should now be first in the chain, Anthropic still present as fallback.
    assert client.fallback_chain[0] == "gemini"
    assert "anthropic" in client.fallback_chain

    result = await client.generate_text("hi")
    assert result == "ok-from-gemini"
    assert anthropic.calls == 0


# ---------------------------------------------------------------------------
# 9. Ollama is not in the production fallback chains (stub guard)
# ---------------------------------------------------------------------------


def test_ollama_not_in_fallback_chains() -> None:
    """Ollama client is a stub — it must not appear in any production chain."""
    for profile, chain in LLM_FALLBACK_CHAINS.items():
        assert "ollama" not in chain, f"ollama leaked into '{profile}' chain: {chain}"


# ---------------------------------------------------------------------------
# 10. validate_agent_chains: engagement-start fail-fast when no key is set
# ---------------------------------------------------------------------------


def test_validate_agent_chains_raises_when_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all_keys(monkeypatch)

    # Force the Settings snapshot to have no keys either (covers the config
    # fallback path inside _has_api_key).
    from clinkz import config as config_mod

    fresh = config_mod.Settings.from_env()

    with pytest.raises(LLMUnavailableError) as excinfo:
        validate_agent_chains(
            ["recon", "scan", "exploit", "research", "report"],
            config=fresh,
        )

    msg = str(excinfo.value)
    assert "recon" in msg
    assert "exploit" in msg
    assert "ANTHROPIC_API_KEY" in msg or "GEMINI_API_KEY" in msg or "OPENAI_API_KEY" in msg


def test_validate_agent_chains_passes_with_one_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini")

    # Should not raise — every agent's chain contains gemini as a viable entry.
    validate_agent_chains(["recon", "scan", "exploit", "research", "report"])


# ---------------------------------------------------------------------------
# 11. reasoning_pinned profile — Anthropic only, no fallback
# ---------------------------------------------------------------------------


def test_reasoning_pinned_chain_is_anthropic_only() -> None:
    """The pinned profile is the contract that mid-test the model never swaps.

    Exploit-Agent methodology checkpoints (character probing, payload
    synthesis, encoding selection) require deterministic LLM behaviour. A
    mid-test fallback to Gemini changes which probes get sent and which
    findings emerge, so the pinned profile must be exactly one provider.
    """
    assert LLM_FALLBACK_CHAINS["reasoning_pinned"] == ["anthropic"]


@pytest.mark.asyncio
async def test_reasoning_pinned_does_not_fall_back_on_anthropic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Anthropic raises, the pinned chain must NOT switch to Gemini."""
    _set_all_keys(monkeypatch)
    anthropic = _FakeLLM("anthropic", [ServiceUnavailableError("503")])
    gemini = _FakeLLM("gemini", ["should-never-be-called"])
    openai = _FakeLLM("openai", ["should-never-be-called"])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": openai})

    client = ResilientLLMClient(
        agent_role="exploit",
        override_chain=list(LLM_FALLBACK_CHAINS["reasoning_pinned"]),
    )
    with pytest.raises(LLMUnavailableError):
        await client.generate_text("char probe")

    assert anthropic.calls == 1
    assert gemini.calls == 0
    assert openai.calls == 0


@pytest.mark.asyncio
async def test_exploit_methodology_llm_is_anthropic_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ExploitAgent._methodology_llm must use the Anthropic-only chain.

    This is the integration glue that ties the pinned profile to the
    methodology call sites in the Exploit Agent.
    """
    _set_all_keys(monkeypatch)
    anthropic = _FakeLLM("anthropic", ["pinned-response"])
    gemini = _FakeLLM("gemini", ["never-called"])
    openai = _FakeLLM("openai", ["never-called"])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": openai})

    from unittest.mock import AsyncMock

    from clinkz.agents.exploit import ExploitAgent
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    # A regular reasoning client that would normally cycle through providers.
    top_level_llm = ResilientLLMClient(agent_role="exploit")

    agent = ExploitAgent(
        llm=top_level_llm,
        tools=[],
        scope=EngagementScope(
            name="t",
            targets=[ScopeEntry(value="http://localhost", type=ScopeType.URL)],
        ),
        state=AsyncMock(spec=StateStore),
        engagement_id="t",
        resolver=ToolResolver(),
    )

    # The methodology client should be a separate Resilient client with the
    # pinned single-provider chain.
    assert isinstance(agent._methodology_llm, ResilientLLMClient)
    assert agent._methodology_llm.fallback_chain == ["anthropic"]

    # _llm_analyze must route through the methodology client, not the
    # top-level llm. Verify by counting calls per fake.
    result = await agent._llm_analyze("Is this single quote a SQL error?")
    assert result == "pinned-response"
    assert anthropic.calls == 1
    assert gemini.calls == 0
    assert openai.calls == 0


@pytest.mark.asyncio
async def test_exploit_methodology_swallows_anthropic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Anthropic fails the methodology call returns "" (no silent provider swap).

    The Exploit Agent's _llm_analyze MUST swallow the exception and return
    an empty string so the deterministic _test_* signature checks still run
    — but it must NOT fall through to Gemini, otherwise the test path
    bifurcates based on Anthropic uptime.
    """
    _set_all_keys(monkeypatch)
    anthropic = _FakeLLM("anthropic", [ServiceUnavailableError("503")])
    gemini = _FakeLLM("gemini", ["never-called"])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": gemini})

    from unittest.mock import AsyncMock

    from clinkz.agents.exploit import ExploitAgent
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    agent = ExploitAgent(
        llm=ResilientLLMClient(agent_role="exploit"),
        tools=[],
        scope=EngagementScope(
            name="t",
            targets=[ScopeEntry(value="http://localhost", type=ScopeType.URL)],
        ),
        state=AsyncMock(spec=StateStore),
        engagement_id="t",
        resolver=ToolResolver(),
    )

    result = await agent._llm_analyze("char probe")
    assert result == ""
    assert anthropic.calls == 1
    assert gemini.calls == 0
