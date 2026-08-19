"""Gemini 3.x removed four generation-config parameters. Pin the refusal.

Under routing v2 the Gemini client is a degradation path: it runs only when
Anthropic could not. So a parameter that 3.x rejects would be introduced on a
calm afternoon and discovered during an incident, on the one code path nothing
exercises. These tests are the exercise.
"""

from __future__ import annotations

import pytest
from google.genai import types

from clinkz.config import GEMINI_THINKING_LEVELS, settings
from clinkz.llm.gemini_client import (
    _REMOVED_IN_GEMINI_3X,
    GeminiConfigError,
    build_generation_config,
)


@pytest.mark.parametrize("removed", sorted(_REMOVED_IN_GEMINI_3X))
def test_each_removed_parameter_is_refused(removed: str) -> None:
    with pytest.raises(GeminiConfigError, match=removed):
        build_generation_config(**{removed: 1})


def test_the_removed_set_is_exactly_the_3x_removals() -> None:
    assert _REMOVED_IN_GEMINI_3X == {"temperature", "top_p", "top_k", "candidate_count"}


def test_every_removed_parameter_is_named_in_one_message() -> None:
    """Fix them in one edit, not one 400 at a time."""
    with pytest.raises(GeminiConfigError) as excinfo:
        build_generation_config(temperature=0.0, top_k=3, candidate_count=1)
    message = str(excinfo.value)
    for name in ("temperature", "top_k", "candidate_count"):
        assert name in message


def test_a_removed_parameter_is_refused_rather_than_dropped() -> None:
    """Silently discarding it makes the request non-reproducible, quietly.

    The caller believes a temperature was applied and nothing in the artifact
    says otherwise — strictly worse than the 400 this replaces.
    """
    with pytest.raises(GeminiConfigError):
        build_generation_config(system_instruction="hi", temperature=0.0)


def test_a_supported_parameter_still_passes_through() -> None:
    config = build_generation_config(system_instruction="be brief", max_output_tokens=256)
    assert config.system_instruction == "be brief"
    assert config.max_output_tokens == 256


# ---------------------------------------------------------------------------
# thinking_level replaces thinking_budget
# ---------------------------------------------------------------------------


def test_the_config_carries_a_thinking_level_and_no_budget() -> None:
    config = build_generation_config()
    assert config.thinking_config is not None
    assert config.thinking_config.thinking_level is not None
    assert config.thinking_config.thinking_budget is None


def test_the_thinking_level_comes_from_settings() -> None:
    assert str(build_generation_config().thinking_config.thinking_level.value) == (
        settings.gemini_thinking_level
    )


def test_a_caller_supplied_thinking_config_is_not_overwritten() -> None:
    explicit = types.ThinkingConfig(thinking_level="HIGH")
    config = build_generation_config(thinking_config=explicit)
    assert config.thinking_config.thinking_level == types.ThinkingLevel.HIGH


def test_minimal_is_offered_by_the_sdk_and_absent_from_ours() -> None:
    """The SDK enum is not the contract — the API is, and it refuses MINIMAL."""
    assert types.ThinkingLevel.MINIMAL.value == "MINIMAL"
    assert "MINIMAL" not in GEMINI_THINKING_LEVELS


def test_an_invalid_level_reaching_the_builder_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config validation is the first gate; this is the second.

    Settings normally rejects MINIMAL, so this simulates a value assigned past
    validation — the builder must not hand it to the API.
    """
    monkeypatch.setattr(settings, "gemini_thinking_level", "MINIMAL", raising=False)
    with pytest.raises(GeminiConfigError, match="not valid on Gemini 3.x"):
        build_generation_config()
