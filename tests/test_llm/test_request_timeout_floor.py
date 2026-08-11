"""The per-call timeout must be able to serve the configured output ceiling.

``llm_request_timeout`` and ``llm_max_output_tokens`` are independent settings,
and the shipped defaults contradicted each other: a 16000-token non-streaming
completion cannot finish inside 120 s. Measured directly against the API with
the exploit planner's real prompt — three consecutive 120 s timeouts, then two
clean completions at 600 s — so the exploit agent's Anthropic call would have
timed out and the fallback chain would have quietly handed the engagement's
planning to Gemini.

The fix treats the configured timeout as a floor to raise rather than a ceiling
to respect, so the two settings cannot silently disagree again.
"""

from __future__ import annotations

import pytest

from clinkz.config import settings
from clinkz.llm.anthropic_client import (
    _MAX_DERIVED_TIMEOUT_SECONDS,
    _MIN_OUTPUT_TOKENS_PER_SECOND,
    request_timeout_for,
)


class TestTimeoutFloor:
    def test_a_small_completion_keeps_the_configured_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "llm_request_timeout", 120.0)
        assert request_timeout_for(1024) == 120.0

    def test_the_shipped_default_pair_no_longer_contradicts_itself(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exact pair that produced the measured timeouts."""
        monkeypatch.setattr(settings, "llm_request_timeout", 120.0)
        assert request_timeout_for(16000) > 120.0

    def test_the_derived_floor_covers_the_output_ceiling(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "llm_request_timeout", 1.0)
        derived = request_timeout_for(9000)
        assert derived == pytest.approx(9000 / _MIN_OUTPUT_TOKENS_PER_SECOND)

    def test_the_floor_is_capped_at_the_sdk_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A derived value beyond the SDK's own ceiling is a number no request reaches."""
        monkeypatch.setattr(settings, "llm_request_timeout", 1.0)
        assert request_timeout_for(10_000_000) == _MAX_DERIVED_TIMEOUT_SECONDS

    def test_a_longer_configured_timeout_is_never_lowered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It is a floor, not a replacement — an operator can still raise it."""
        monkeypatch.setattr(settings, "llm_request_timeout", 900.0)
        assert request_timeout_for(16000) == 900.0

    def test_an_unknown_output_ceiling_changes_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "llm_request_timeout", 120.0)
        assert request_timeout_for(0) == 120.0

    def test_the_raise_is_logged(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(settings, "llm_request_timeout", 120.0)
        with caplog.at_level("INFO", logger="clinkz.llm.anthropic_client"):
            request_timeout_for(16000)
        assert "Raising per-call timeout" in caplog.text


class TestCacheFloorTableCoversTheShippedModel:
    """A floor resting on the fallback is a floor nobody checked."""

    def test_the_configured_model_has_an_explicit_entry(self) -> None:
        from clinkz.llm.anthropic_client import _CACHE_MIN_PREFIX_TOKENS

        model = settings.anthropic_model
        assert any(model.startswith(prefix) for prefix, _ in _CACHE_MIN_PREFIX_TOKENS), (
            f"{model} falls through to the default cache floor; state it explicitly"
        )

    @pytest.mark.parametrize(
        ("model", "expected"),
        [
            ("claude-opus-5", 512),
            ("claude-sonnet-5", 1024),
            ("claude-opus-4-8", 1024),
            ("claude-sonnet-4-6", 1024),
            ("claude-opus-4-7", 2048),
            ("claude-opus-4-6", 4096),
            ("claude-haiku-4-5", 4096),
        ],
    )
    def test_documented_minimums(self, model: str, expected: int) -> None:
        """The floor is not monotonic across generations — it has to be looked up."""
        from clinkz.llm.anthropic_client import cache_min_prefix_tokens

        assert cache_min_prefix_tokens(model) == expected
