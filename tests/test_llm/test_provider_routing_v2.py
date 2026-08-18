"""Routing v2 — Anthropic is priority 1 for every call on every phase.

These pin the two halves that are one edit away from silently reverting: the
declared priority order, and the fact that no per-role switch can displace its
head. Both failures are invisible in every artifact a run produces except the
report's model stamp, which is read after the engagement is over.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from clinkz.config import GEMINI_PINNED_MODEL, GEMINI_THINKING_LEVELS, Settings
from clinkz.llm.fallback import (
    AGENT_LLM_PROFILE,
    LLM_FALLBACK_CHAINS,
    ResilientLLMClient,
)

#: Every role the orchestrator builds a client for, plus an unknown one.
ALL_ROLES = ("recon", "scan", "crawl", "exploit", "research", "report", "unknown-role")


# ---------------------------------------------------------------------------
# Priority is declared, Anthropic-first, and validated
# ---------------------------------------------------------------------------


def test_default_priority_leads_with_anthropic() -> None:
    assert Settings().llm_provider_priority[0] == "anthropic"


@pytest.mark.parametrize("bad_head", ["gemini", "openai", "ollama"])
def test_a_priority_order_that_does_not_lead_with_anthropic_is_refused(bad_head: str) -> None:
    """The rule is enforced by the model, not by a comment above the field."""
    with pytest.raises(ValidationError, match="must lead with 'anthropic'"):
        Settings(llm_provider_priority=(bad_head, "anthropic"))  # type: ignore[arg-type]


def test_a_repeated_provider_in_the_priority_order_is_refused() -> None:
    with pytest.raises(ValidationError, match="repeated provider"):
        Settings(llm_provider_priority=("anthropic", "gemini", "gemini"))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Every role, every profile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ALL_ROLES)
def test_every_role_leads_with_anthropic(role: str) -> None:
    """'All phases, no exceptions' — asserted per role, not for a sample."""
    assert ResilientLLMClient(role).fallback_chain[0] == "anthropic"


def test_no_profile_leads_with_anything_but_anthropic() -> None:
    for profile, chain in LLM_FALLBACK_CHAINS.items():
        assert chain[0] == "anthropic", f"profile {profile} leads with {chain[0]}"


def test_every_mapped_role_uses_a_known_profile() -> None:
    for role, profile in AGENT_LLM_PROFILE.items():
        assert profile in LLM_FALLBACK_CHAINS, f"{role} maps to unknown profile {profile}"


def test_every_per_agent_provider_default_is_anthropic() -> None:
    """A per-agent default is how priority 1 gets reversed one field at a time."""
    cfg = Settings()
    for field in (
        "recon_llm_provider",
        "scan_llm_provider",
        "report_llm_provider",
        "exploit_llm_provider",
        "research_llm_provider",
        "llm_provider_default",
        "llm_provider",
    ):
        assert getattr(cfg, field) == "anthropic", field


# ---------------------------------------------------------------------------
# The per-role override reorders the TAIL and cannot touch the head
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "role,field", [("recon", "recon_llm_provider"), ("scan", "scan_llm_provider")]
)
def test_a_per_role_override_cannot_displace_anthropic(role: str, field: str) -> None:
    """``LLM_PROVIDER_RECON=gemini`` used to mean "Gemini answers recon"."""
    cfg = Settings(**{field: "gemini"})  # type: ignore[arg-type]
    chain = ResilientLLMClient(role, config=cfg).fallback_chain
    assert chain[0] == "anthropic"
    assert chain[1] == "gemini", "the override should still promote within the tail"


def test_a_per_role_override_promotes_within_the_tail() -> None:
    cfg = Settings(recon_llm_provider="openai")  # type: ignore[arg-type]
    assert ResilientLLMClient("recon", config=cfg).fallback_chain == [
        "anthropic",
        "openai",
        "gemini",
    ]


def test_reasoning_pinned_has_no_fallback_tail() -> None:
    """Methodology checkpoints depend on one deterministic path, not a chain."""
    client = ResilientLLMClient("exploit")
    assert client._build_chain("exploit", "reasoning_pinned") == ["anthropic"]


def test_the_chain_follows_a_reordered_priority_tail() -> None:
    cfg = Settings(llm_provider_priority=("anthropic", "openai", "gemini"))  # type: ignore[arg-type]
    assert ResilientLLMClient("scan", config=cfg).fallback_chain == [
        "anthropic",
        "openai",
        "gemini",
    ]


# ---------------------------------------------------------------------------
# The Gemini pin
# ---------------------------------------------------------------------------


def test_the_gemini_model_is_pinned_to_an_exact_string() -> None:
    assert GEMINI_PINNED_MODEL == "gemini-3.7-flash"
    cfg = Settings()
    assert cfg.gemini_model == GEMINI_PINNED_MODEL
    assert cfg.gemini_exploit_model == GEMINI_PINNED_MODEL
    assert cfg.gemini_research_model == GEMINI_PINNED_MODEL


@pytest.mark.parametrize("alias", ["gemini-flash-latest", "gemini-3.7-flash-latest", "gemini-pro"])
def test_the_pin_is_not_a_floating_alias(alias: str) -> None:
    """A ``-latest`` alias moves under a fixed configuration."""
    assert GEMINI_PINNED_MODEL != alias
    assert not GEMINI_PINNED_MODEL.endswith("-latest")


def test_the_resolved_trace_model_for_gemini_is_the_pin() -> None:
    """The model stamp reads this, so a drifted pin re-baselines every run."""
    for role in ("recon", "scan", "exploit", "research", "report"):
        resolved = ResilientLLMClient(role)._resolve_model("gemini")
        assert resolved == GEMINI_PINNED_MODEL, role


# ---------------------------------------------------------------------------
# Gemini 3.x thinking level
# ---------------------------------------------------------------------------


def test_minimal_thinking_level_is_refused_at_config_time() -> None:
    """The SDK enum offers MINIMAL; 3.7 Flash rejects it on the wire."""
    from google.genai import types

    assert "MINIMAL" in {level.value for level in types.ThinkingLevel}, (
        "premise of this test: the SDK still offers a level the API refuses"
    )
    assert "MINIMAL" not in GEMINI_THINKING_LEVELS
    with pytest.raises(ValidationError, match="not valid on Gemini 3.x"):
        Settings(gemini_thinking_level="MINIMAL")


@pytest.mark.parametrize("level", ["LOW", "MEDIUM", "HIGH"])
def test_the_valid_thinking_levels_are_accepted(level: str) -> None:
    assert Settings(gemini_thinking_level=level).gemini_thinking_level == level
    assert Settings(gemini_thinking_level=level.lower()).gemini_thinking_level == level


def test_thinking_budget_is_not_a_setting_any_more() -> None:
    """3.x replaced the integer budget with the string enum."""
    assert "gemini_thinking_budget" not in Settings.model_fields
