"""A response carrying no text must never be handed back as an empty string.

Regression cover for the defect that shipped in the four P7 DVWA engagements
(35511096, 1b23a1ef, 946e7036, f4b0c5c8). In every one of them the exploit
planner's first call to ``generate_text`` returned ``""``. It was not an error,
nothing logged, and the trace recorded an empty ``response_summary`` next to a
32-55 second duration.

The mechanism: ``claude-sonnet-5`` runs adaptive thinking by default, and
``max_tokens`` bounds thinking and response text *together*. With the old
4096-token ceiling a hard planning prompt spent the whole allowance reasoning
and the turn ended ``stop_reason="max_tokens"`` with zero text blocks —
which the old ``generate_text`` dutifully joined into ``""``.

The measured signature across those runs: 12 of 255 Anthropic calls returned
empty, every one of them over 32s, while every non-empty call finished under
46s (median 8.4s). Perfect separation.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.llm.base import AgentAction, EmptyResponseError, LLMClient, LLMMessage

_SETTINGS = SimpleNamespace(
    llm_max_output_tokens=16000,
    llm_prompt_cache_enabled=True,
    llm_prompt_cache_ttl="5m",
    llm_context_margin_tokens=8000,
    llm_stream_above_output_tokens=16000,
    llm_output_headroom_alarm_ratio=0.8,
)


@pytest.fixture(autouse=True)
def _fake_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-fake")


def _client(model: str = "claude-sonnet-5") -> Any:
    from clinkz.llm.anthropic_client import AnthropicClient

    with patch("clinkz.llm.anthropic_client.settings") as fake:
        fake.anthropic_api_key = "k"
        fake.anthropic_model = model
        return AnthropicClient(model=model)


def _thinking_only_response() -> SimpleNamespace:
    """What the API actually returned in those four engagements.

    A thinking block and nothing else, truncated at the token ceiling. Note
    ``generate_text`` collects only ``type == "text"`` blocks, so this joins to
    the empty string.
    """
    return SimpleNamespace(
        content=[SimpleNamespace(type="thinking", thinking="")],
        stop_reason="max_tokens",
        usage=SimpleNamespace(
            input_tokens=4700,
            output_tokens=16000,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        ),
    )


class TestGenerateTextNeverReturnsEmpty:
    @pytest.mark.asyncio
    async def test_thinking_only_response_raises_instead_of_returning_empty(self) -> None:
        client = _client()
        with patch("clinkz.llm.anthropic_client.settings", _SETTINGS):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = _thinking_only_response()
                with pytest.raises(EmptyResponseError) as caught:
                    await client.generate_text("plan the exploit phase")

        # stop_reason is carried so the next occurrence is diagnosable from the
        # exception alone, rather than from a duration histogram.
        assert caught.value.stop_reason == "max_tokens"
        assert "max_tokens" in str(caught.value)

    @pytest.mark.asyncio
    async def test_whitespace_only_text_is_also_empty(self) -> None:
        client = _client()
        response = SimpleNamespace(
            content=[SimpleNamespace(type="text", text="   \n  ")],
            stop_reason="end_turn",
            usage=SimpleNamespace(
                input_tokens=1,
                output_tokens=1,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
            ),
        )
        with patch("clinkz.llm.anthropic_client.settings", _SETTINGS):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = response
                with pytest.raises(EmptyResponseError):
                    await client.generate_text("x")

    @pytest.mark.asyncio
    async def test_real_text_still_comes_back_normally(self) -> None:
        """The guard must not fire on the working path."""
        client = _client()
        response = SimpleNamespace(
            content=[
                SimpleNamespace(type="thinking", thinking=""),
                SimpleNamespace(type="text", text='{"tasks": []}'),
            ],
            stop_reason="end_turn",
            usage=SimpleNamespace(
                input_tokens=10,
                output_tokens=5,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
            ),
        )
        with patch("clinkz.llm.anthropic_client.settings", _SETTINGS):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = response
                assert await client.generate_text("x") == '{"tasks": []}'


class TestReasonNeverReturnsAnEmptyAction:
    @pytest.mark.asyncio
    async def test_no_text_and_no_tool_call_raises(self) -> None:
        client = _client()
        with patch("clinkz.llm.anthropic_client.settings", _SETTINGS):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = _thinking_only_response()
                with pytest.raises(EmptyResponseError):
                    await client.reason([LLMMessage(role="user", content="go")])

    @pytest.mark.asyncio
    async def test_a_tool_call_with_no_preamble_is_not_an_error(self) -> None:
        """A silent tool call is a complete, usable action — not a truncation."""
        client = _client()
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", id="t1", name="run_nmap", input={})],
            stop_reason="tool_use",
            usage=SimpleNamespace(
                input_tokens=10,
                output_tokens=5,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
            ),
        )
        with patch("clinkz.llm.anthropic_client.settings", _SETTINGS):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = response
                action = await client.reason([LLMMessage(role="user", content="go")])

        assert action.tool_call is not None
        assert action.tool_call.name == "run_nmap"


class TestFallbackChainTreatsEmptyAsRetriable:
    """The payoff: an exhausted budget on one provider is no longer silent.

    Before the fix a truncated Anthropic turn produced ``""`` and the chain
    considered the call a success, so Gemini — which would have answered — was
    never reached.
    """

    @pytest.mark.asyncio
    async def test_empty_anthropic_response_falls_through_to_the_next_provider(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from clinkz.llm import fallback as fallback_mod

        class _Truncated(LLMClient):
            async def reason(self, messages: Any, tools: Any = None) -> AgentAction:
                raise AssertionError("not used")

            async def research(self, query: str) -> str:
                raise AssertionError("not used")

            async def generate_text(self, prompt: Any, **_kw: object) -> str:
                raise EmptyResponseError("no text block", stop_reason="max_tokens")

        class _Works(LLMClient):
            async def reason(self, messages: Any, tools: Any = None) -> AgentAction:
                raise AssertionError("not used")

            async def research(self, query: str) -> str:
                raise AssertionError("not used")

            async def generate_text(self, prompt: Any, **_kw: object) -> str:
                return '{"tasks": [{"test_method": "_test_sqli"}]}'

        built = {"anthropic": _Truncated(), "gemini": _Works()}
        monkeypatch.setattr(
            fallback_mod, "get_llm_client", lambda provider, model=None: built[provider]
        )
        for var in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"):
            monkeypatch.setenv(var, "k")

        # Demonstrated on RECON. The rotation semantics under test are
        # role-independent, but the role is not: "exploit" may no longer reach
        # Gemini by any route (see TestDecisionBearingRolesNeverRotateToGemini
        # below), so asserting the rotation there would be asserting a path the
        # engine now refuses.
        client = fallback_mod.ResilientLLMClient("recon", override_chain=["anthropic", "gemini"])
        result = await client.generate_text("analyse these ports")

        assert result == '{"tasks": [{"test_method": "_test_sqli"}]}'
        assert client._last_used_provider == "gemini"
