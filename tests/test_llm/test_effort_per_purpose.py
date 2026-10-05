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


def test_resolver_routes_planning_and_suppress_to_default() -> None:
    for purpose in (LLMCallPurpose.PLANNING, LLMCallPurpose.SUPPRESS):
        assert effort_for_purpose(purpose, default="low", emit="") == "low"


def test_resolver_routes_emit_to_its_own_knob() -> None:
    # EMIT takes the emit level, NOT the default — that is the whole carve-out.
    assert effort_for_purpose(LLMCallPurpose.EMIT, default="low", emit="") == ""
    assert effort_for_purpose(LLMCallPurpose.EMIT, default="low", emit="high") == "high"
    # And the default moving does not move EMIT.
    assert effort_for_purpose(LLMCallPurpose.EMIT, default="max", emit="") == ""


def test_emit_is_the_only_purpose_that_diverges() -> None:
    """Only EMIT reads the emit knob; the other two are the default verbatim."""
    diverged = [
        p for p in LLMCallPurpose if effort_for_purpose(p, default="low", emit="high") != "low"
    ]
    assert diverged == [LLMCallPurpose.EMIT]


def test_config_default_is_low_and_emit_is_provider_default() -> None:
    fresh = Settings()
    assert fresh.llm_effort == "low", "the grid-justified default for PLANNING/SUPPRESS"
    assert fresh.llm_effort_emit == "", "EMIT left at the provider default until isolated"


def test_from_env_keeps_the_low_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_EFFORT", raising=False)
    monkeypatch.delenv("LLM_EFFORT_EMIT", raising=False)
    built = Settings.from_env()
    assert built.llm_effort == "low"
    assert built.llm_effort_emit == ""


@pytest.mark.parametrize("field", ["llm_effort", "llm_effort_emit"])
def test_both_effort_knobs_refuse_an_off_vocabulary_level(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        Settings(**{field: "quick"})


def test_resolved_effort_follows_the_purpose_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_effort", "low")
    monkeypatch.setattr(settings, "llm_effort_emit", "")
    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        assert AnthropicClient._resolved_effort() == "low"
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

    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        kwargs: dict = {}
        AnthropicClient._apply_effort(kwargs)
        assert kwargs["output_config"] == {"effort": "low"}
        assert kwargs["output_config"]["effort"] == AnthropicClient._resolved_effort()

    with llm_call_purpose(LLMCallPurpose.EMIT, site="t.emit"):
        kwargs = {}
        AnthropicClient._apply_effort(kwargs)
        assert "output_config" not in kwargs, "empty effort omits the parameter"
        assert AnthropicClient._resolved_effort() == ""


def test_emit_knob_when_declared_reaches_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_effort", "low")
    monkeypatch.setattr(settings, "llm_effort_emit", "high")
    with llm_call_purpose(LLMCallPurpose.EMIT, site="t.emit"):
        kwargs: dict = {}
        AnthropicClient._apply_effort(kwargs)
        assert kwargs["output_config"] == {"effort": "high"}
    # The same run's PLANNING calls are unaffected — the two knobs are independent.
    with llm_call_purpose(LLMCallPurpose.PLANNING, site="t.plan"):
        assert AnthropicClient._resolved_effort() == "low"
