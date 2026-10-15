"""Part 2 pin: ``output_config.effort`` is resolved by the call's PURPOSE.

The effort grid found findings flat across effort while output cost climbed
1.6x-2.4x, so ``llm_effort`` defaults to ``low`` for the paths whose answer the
deliverable can disclose (PLANNING, SUPPRESS). EMIT is the carve-out — it shapes
a finding's verdict and evidence, and lowering it was never isolated in
measurement — so it reads its own ``llm_effort_emit``, left at the provider
default. These tests pin that split, and pin that the level STAMPED on a call is
the level the request carried.
"""

from __future__ import annotations

import pytest

from clinkz.config import Settings, settings
from clinkz.llm.anthropic_client import AnthropicClient
from clinkz.llm.call_purpose import (
    LLMCallPurpose,
    effort_for_purpose,
    llm_call_purpose,
)


def test_resolver_routes_suppress_to_default() -> None:
    assert (
        effort_for_purpose(LLMCallPurpose.SUPPRESS, default="low", emit="", planning="high")
        == "low"
    )


def test_resolver_routes_planning_to_its_own_knob() -> None:
    """PLANNING was split out and raised by the set-level re-grade (§6)."""
    assert (
        effort_for_purpose(LLMCallPurpose.PLANNING, default="low", emit="", planning="high")
        == "high"
    )
    # The SUPPRESS default moving does not move PLANNING.
    assert (
        effort_for_purpose(LLMCallPurpose.PLANNING, default="max", emit="", planning="high")
        == "high"
    )


def test_resolver_routes_emit_to_its_own_knob() -> None:
    # EMIT takes the emit level, NOT the default — that is the whole carve-out.
    assert effort_for_purpose(LLMCallPurpose.EMIT, default="low", emit="", planning="high") == ""
    assert (
        effort_for_purpose(LLMCallPurpose.EMIT, default="low", emit="high", planning="low")
        == "high"
    )
    # And the default moving does not move EMIT.
    assert effort_for_purpose(LLMCallPurpose.EMIT, default="max", emit="", planning="") == ""


def test_each_purpose_reads_exactly_one_knob() -> None:
    """Three purposes, three knobs, no purpose reading another's."""
    read = {
        p: effort_for_purpose(p, default="low", emit="max", planning="high") for p in LLMCallPurpose
    }
    assert read == {
        LLMCallPurpose.SUPPRESS: "low",
        LLMCallPurpose.EMIT: "max",
        LLMCallPurpose.PLANNING: "high",
    }


def test_planning_has_no_default_to_fall_back_on() -> None:
    """A missing planning level is a TypeError, never a silent ``default``."""
    with pytest.raises(TypeError):
        effort_for_purpose(LLMCallPurpose.PLANNING, default="low", emit="")  # type: ignore[call-arg]


def test_config_defaults() -> None:
    fresh = Settings()
    assert fresh.llm_effort == "low", "the grid-justified default for SUPPRESS"
    assert fresh.llm_effort_planning == "high", "raised by the set-level re-grade"
    assert fresh.llm_effort_emit == "", "EMIT left at the provider default until isolated"


def test_from_env_keeps_the_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LLM_EFFORT", "LLM_EFFORT_EMIT", "LLM_EFFORT_PLANNING"):
        monkeypatch.delenv(name, raising=False)
    built = Settings.from_env()
    assert built.llm_effort == "low"
    assert built.llm_effort_planning == "high"
    assert built.llm_effort_emit == ""


@pytest.mark.parametrize("field", ["llm_effort", "llm_effort_emit", "llm_effort_planning"])
def test_every_effort_knob_refuses_an_off_vocabulary_level(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        Settings(**{field: "quick"})


def test_resolved_effort_follows_the_purpose_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_effort", "low")
    monkeypatch.setattr(settings, "llm_effort_emit", "")
    monkeypatch.setattr(settings, "llm_effort_planning", "high")
    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        assert AnthropicClient._resolved_effort() == "high"
    with llm_call_purpose(LLMCallPurpose.SUPPRESS, site="t.suppress"):
        assert AnthropicClient._resolved_effort() == "low"
    with llm_call_purpose(LLMCallPurpose.EMIT, site="t.emit"):
        assert AnthropicClient._resolved_effort() == ""


def test_apply_effort_matches_the_stamp(monkeypatch: pytest.MonkeyPatch) -> None:
    """The request carries exactly the level ``_resolved_effort`` reports — so a
    PLANNING call sends ``output_config`` and an EMIT call (at the provider
    default) omits it, each consistent with its stamp."""
    monkeypatch.setattr(settings, "llm_effort", "low")
    monkeypatch.setattr(settings, "llm_effort_emit", "")
    monkeypatch.setattr(settings, "llm_effort_planning", "high")

    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        kwargs: dict = {}
        AnthropicClient._apply_effort(kwargs)
        assert kwargs["output_config"] == {"effort": "high"}
        assert kwargs["output_config"]["effort"] == AnthropicClient._resolved_effort()

    with llm_call_purpose(LLMCallPurpose.EMIT, site="t.emit"):
        kwargs = {}
        AnthropicClient._apply_effort(kwargs)
        assert "output_config" not in kwargs, "empty effort omits the parameter"
        assert AnthropicClient._resolved_effort() == ""


def test_emit_knob_when_declared_reaches_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_effort", "low")
    monkeypatch.setattr(settings, "llm_effort_emit", "high")
    monkeypatch.setattr(settings, "llm_effort_planning", "medium")
    with llm_call_purpose(LLMCallPurpose.EMIT, site="t.emit"):
        kwargs: dict = {}
        AnthropicClient._apply_effort(kwargs)
        assert kwargs["output_config"] == {"effort": "high"}
    # The same run's PLANNING calls are unaffected — the knobs are independent.
    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        assert AnthropicClient._resolved_effort() == "medium"
