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

from clinkz.config import GEMINI_PINNED_MODEL
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
    preflight_provider_available,
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

    async def generate_text(self, prompt: str, **_kw: object) -> str:
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

    def fake_factory(
        provider: str | None = None,
        *,
        agent_role: str | None = None,
        model: str | None = None,
    ) -> LLMClient:
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

    # Exploit leads with Anthropic (reasoning profile) → primary succeeds.
    client = ResilientLLMClient(agent_role="exploit")
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

    # Rotation semantics, shown on RECON: "exploit" is decision-bearing and may
    # not reach Gemini by any route, so the 429 case is exercised where a
    # fallback to Gemini is still a legal outcome.
    client = ResilientLLMClient(agent_role="recon", override_chain=["anthropic", "gemini"])
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
    primary = _FakeLLM("anthropic", [ServiceUnavailableError("503 Service Unavailable")])
    secondary = _FakeLLM("gemini", ["ok-from-gemini"])
    _register(monkeypatch, {"anthropic": primary, "gemini": secondary, "openai": secondary})

    # Routing v2: every role leads with Anthropic, so the 503 is Anthropic's
    # and Gemini is the fallback — the reverse of the pre-v2 arrangement.
    client = ResilientLLMClient(agent_role="recon")
    result = await client.generate_text("hi")

    assert result == "ok-from-gemini"
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

    client = ResilientLLMClient(agent_role="recon", override_chain=["anthropic", "gemini"])
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

    client = ResilientLLMClient(agent_role="recon")
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

    # 'recon' → fast chain leads with gemini (configured) → used directly;
    # anthropic/openai have no key and are skipped. Research used to stand here
    # and no longer can: its chain is Claude-only.
    client = ResilientLLMClient(agent_role="recon")
    result = await client.generate_text("hi")

    assert result == "ok-from-gemini"
    assert anthropic.calls == 0
    assert openai.calls == 0


# ---------------------------------------------------------------------------
# 7. Agent role selects correct profile
# ---------------------------------------------------------------------------


def test_agent_role_selects_correct_profile() -> None:
    """Routing v2: the profile no longer varies who answers first.

    Every role is ``reasoning`` and every chain leads with Anthropic. The
    profile survives as a trace label and as the seam a future per-role
    divergence would be written into. Gemini is still IN the chain — v2
    replaced "the cheap tier may not serve this role" with "if it does, the
    run says so and is disqualified as a baseline" (see
    ``tests/test_llm/test_fallback_disqualification.py``).
    """
    for role in ("exploit", "research", "recon", "scan", "report"):
        client = ResilientLLMClient(agent_role=role)
        assert client.profile == "reasoning"
        assert client.fallback_chain[0] == "anthropic"


def test_profile_tables_match_chains() -> None:
    for profile in AGENT_LLM_PROFILE.values():
        assert profile in LLM_FALLBACK_CHAINS


# ---------------------------------------------------------------------------
# 8. Per-agent env var override bumps provider to front of chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_agent_config_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_all_keys(monkeypatch)
    # Recon defaults to gemini-first. Flip to anthropic-first via the env var to
    # prove the override bumps a non-default provider to the front of the chain.
    # Shown on recon rather than research: research is decision-bearing now, and
    # the override on a gated role is tested below for the opposite property —
    # that it cannot put a cheaper provider anywhere in the chain.
    monkeypatch.setenv("LLM_PROVIDER_RECON", "anthropic")

    # Reload settings so the new env var is picked up.
    from clinkz import config as config_mod

    fresh = config_mod.Settings.from_env()
    assert fresh.recon_llm_provider == "anthropic"

    anthropic = _FakeLLM("anthropic", ["ok-from-anthropic"])
    gemini = _FakeLLM("gemini", ["never-called"])
    _register(monkeypatch, {"gemini": gemini, "anthropic": anthropic, "openai": gemini})

    client = ResilientLLMClient(agent_role="recon", config=fresh)

    # Anthropic should now be first in the chain, Gemini still present as fallback.
    assert client.fallback_chain[0] == "anthropic"
    assert "gemini" in client.fallback_chain

    result = await client.generate_text("hi")
    assert result == "ok-from-anthropic"
    assert gemini.calls == 0


# ---------------------------------------------------------------------------
# 9. Ollama is not in the production fallback chains (stub guard)
# ---------------------------------------------------------------------------


def test_ollama_not_in_fallback_chains() -> None:
    """Ollama client is a stub — it must not appear in any production chain."""
    for profile, chain in LLM_FALLBACK_CHAINS.items():
        assert "ollama" not in chain, f"ollama leaked into '{profile}' chain: {chain}"


# ---------------------------------------------------------------------------
# 9b. Per-role Gemini model: only Research pins Flash-Lite
# ---------------------------------------------------------------------------


def test_research_builds_gemini_client_with_flash_lite_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Research constructs its Gemini client with gemini_research_model
    (the exact pin, never a preview or a floating alias); other roles keep the
    client default."""
    _set_all_keys(monkeypatch)
    captured: list[tuple[str | None, str | None]] = []

    def fake_factory(
        provider: str | None = None,
        *,
        agent_role: str | None = None,
        model: str | None = None,
    ) -> LLMClient:
        captured.append((provider, model))
        return _FakeLLM(provider or "x", ["ok"])

    monkeypatch.setattr(fallback_mod, "get_llm_client", fake_factory)

    research = ResilientLLMClient(agent_role="research")
    research._get_or_create_client("gemini")
    assert captured[-1][0] == "gemini"
    assert captured[-1][1] == GEMINI_PINNED_MODEL
    assert "preview" not in (captured[-1][1] or "")
    assert not (captured[-1][1] or "").endswith("-latest"), "pin the exact string"

    # Scan (also Gemini-led) must NOT get a model override — keeps gemini_model.
    scan = ResilientLLMClient(agent_role="scan")
    scan._get_or_create_client("gemini")
    assert captured[-1] == ("gemini", None)


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
    # ANTHROPIC, not GEMINI. A Gemini key alone no longer satisfies every role:
    # exploit and research have Claude-only chains, so validation fails fast at
    # engagement start rather than discovering it on the first planning call.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic")

    # Should not raise — every agent's chain contains anthropic as a viable entry.
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


# ---------------------------------------------------------------------------
# 12. Credit pre-flight + engagement-wide provider exclusion
# ---------------------------------------------------------------------------


def test_exclude_providers_drops_gemini_from_every_role(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the pre-flight finds Gemini depleted, excluding it leaves each
    role led by its next provider — Anthropic for the fast roles."""
    _set_all_keys(monkeypatch)
    for role in ("recon", "scan", "report", "research"):
        client = ResilientLLMClient(agent_role=role, exclude_providers={"gemini"})
        assert "gemini" not in client.fallback_chain
        assert client.fallback_chain[0] == "anthropic", role


@pytest.mark.asyncio
async def test_excluded_gemini_dispatches_to_anthropic_without_touching_gemini(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fast-profile agent with Gemini excluded must run on Anthropic and
    never instantiate/call the Gemini client (no per-call 429 storm)."""
    _set_all_keys(monkeypatch)
    anthropic = _FakeLLM("anthropic", ["ok-from-anthropic"])
    gemini = _FakeLLM("gemini", [RateLimitError("RESOURCE_EXHAUSTED 429")])
    _register(monkeypatch, {"anthropic": anthropic, "gemini": gemini, "openai": gemini})

    client = ResilientLLMClient(agent_role="recon", exclude_providers={"gemini"})
    result = await client.generate_text("hi")

    assert result == "ok-from-anthropic"
    assert anthropic.calls == 1
    assert gemini.calls == 0, "excluded provider must never be invoked"


def test_exclude_providers_never_empties_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Excluding every provider in the chain is ignored — never strand an agent."""
    _set_all_keys(monkeypatch)
    client = ResilientLLMClient(
        agent_role="recon", exclude_providers={"gemini", "anthropic", "openai"}
    )
    assert client.fallback_chain, "chain must not be emptied by an over-broad exclusion"


@pytest.mark.asyncio
async def test_preflight_returns_false_on_resource_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A depleted Gemini key (429 RESOURCE_EXHAUSTED) → pre-flight reports
    unavailable so the orchestrator routes the engagement to Anthropic."""
    _set_all_keys(monkeypatch)
    gemini = _FakeLLM("gemini", [RateLimitError("429 RESOURCE_EXHAUSTED")])
    _register(monkeypatch, {"gemini": gemini})

    assert await preflight_provider_available("gemini") is False
    assert gemini.calls == 1


@pytest.mark.asyncio
async def test_preflight_returns_true_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A healthy key answers the probe → provider stays primary."""
    _set_all_keys(monkeypatch)
    gemini = _FakeLLM("gemini", ["pong"])
    _register(monkeypatch, {"gemini": gemini})

    assert await preflight_provider_available("gemini") is True


@pytest.mark.asyncio
async def test_preflight_assumes_available_on_unexpected_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-rate-limit error is treated conservatively as available so a
    transient quirk never needlessly abandons the cheaper provider."""
    _set_all_keys(monkeypatch)
    gemini = _FakeLLM("gemini", [ValueError("weird transient parse error")])
    _register(monkeypatch, {"gemini": gemini})

    assert await preflight_provider_available("gemini") is True
