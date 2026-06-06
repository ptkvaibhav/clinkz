"""Tests for AnthropicClient — message conversion, tool calling, token tracking.

All tests mock the Anthropic SDK so no API key or network is needed.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.llm.base import LLMMessage, ToolCall

# ---------------------------------------------------------------------------
# Fixtures — patch settings so the client can be instantiated without a key
# ---------------------------------------------------------------------------


def _sync_settings_from_env() -> None:
    """Refresh the shared ``config.settings`` object from the environment, in place.

    The llm client modules bind ``settings`` at import time via
    ``from clinkz.config import settings``. Rebinding ``config.settings`` to a
    brand-new object would orphan those module-level references at the stale
    pre-test object — which on a keyless runner carries no API key and makes
    ``AnthropicClient()`` raise ``ANTHROPIC_API_KEY is not set``. Copying a
    fresh ``Settings.from_env()`` onto the existing object keeps every
    import-time reference live.
    """
    from clinkz import config

    fresh = config.Settings.from_env()
    for name in type(config.settings).model_fields:
        setattr(config.settings, name, getattr(fresh, name))


@pytest.fixture(autouse=True)
def _patch_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ANTHROPIC_API_KEY is set for all tests."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-fake")


@pytest.fixture()
def _reload_settings() -> Iterator[None]:
    """Sync settings to the current env in place, restoring originals on teardown."""
    from clinkz import config

    original = {name: getattr(config.settings, name) for name in type(config.settings).model_fields}
    _sync_settings_from_env()
    try:
        yield
    finally:
        for name, value in original.items():
            setattr(config.settings, name, value)


# ---------------------------------------------------------------------------
# Helpers — mock Anthropic API response objects
# ---------------------------------------------------------------------------


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(tool_id: str, name: str, input_data: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=input_data)


def _make_response(
    content: list[Any],
    input_tokens: int = 100,
    output_tokens: int = 50,
) -> SimpleNamespace:
    return SimpleNamespace(
        content=content,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
    )


# ---------------------------------------------------------------------------
# Tests: message conversion
# ---------------------------------------------------------------------------


class TestMessageConversion:
    """Test _to_anthropic_messages() conversion logic."""

    def test_system_message_extracted(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        messages = [
            LLMMessage(role="system", content="You are a pentester."),
            LLMMessage(role="user", content="Scan target."),
        ]
        system, api_msgs = AnthropicClient._to_anthropic_messages(messages)
        assert system == "You are a pentester."
        assert len(api_msgs) == 1
        assert api_msgs[0]["role"] == "user"

    def test_user_message_format(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        messages = [LLMMessage(role="user", content="Hello")]
        _, api_msgs = AnthropicClient._to_anthropic_messages(messages)
        assert api_msgs[0]["content"] == [{"type": "text", "text": "Hello"}]

    def test_assistant_with_tool_calls(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        tc = ToolCall(id="tc_1", name="run_nmap", arguments={"target": "1.2.3.4"})
        messages = [
            LLMMessage(role="assistant", content="I'll scan now.", tool_calls=[tc]),
        ]
        _, api_msgs = AnthropicClient._to_anthropic_messages(messages)
        content = api_msgs[0]["content"]
        assert content[0] == {"type": "text", "text": "I'll scan now."}
        assert content[1]["type"] == "tool_use"
        assert content[1]["name"] == "run_nmap"
        assert content[1]["input"] == {"target": "1.2.3.4"}

    def test_tool_result_message(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        messages = [
            LLMMessage(role="tool", content='{"hosts": []}', tool_call_id="tc_1"),
        ]
        _, api_msgs = AnthropicClient._to_anthropic_messages(messages)
        assert api_msgs[0]["role"] == "user"
        assert api_msgs[0]["content"][0]["type"] == "tool_result"
        assert api_msgs[0]["content"][0]["tool_use_id"] == "tc_1"


# ---------------------------------------------------------------------------
# Tests: tool schema conversion
# ---------------------------------------------------------------------------


class TestToolConversion:
    def test_openai_format_to_anthropic(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        tools = [
            {
                "name": "run_nmap",
                "description": "Scan ports",
                "parameters": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            }
        ]
        result = AnthropicClient._to_anthropic_tools(tools)
        assert len(result) == 1
        assert result[0]["name"] == "run_nmap"
        assert "input_schema" in result[0]
        assert result[0]["input_schema"]["type"] == "object"


# ---------------------------------------------------------------------------
# Tests: reason() with tool calling
# ---------------------------------------------------------------------------


class TestReason:
    @pytest.mark.asyncio
    async def test_reason_returns_tool_call(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        response = _make_response(
            [
                _text_block("I need to scan ports."),
                _tool_use_block("toolu_abc", "run_nmap", {"target": "1.2.3.4"}),
            ]
        )

        with patch.object(
            AnthropicClient, "_call_with_backoff", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = response
            client = AnthropicClient()
            action = await client.reason(
                [LLMMessage(role="user", content="Scan 1.2.3.4")],
                tools=[{"name": "run_nmap", "description": "Scan", "parameters": {}}],
            )

        assert action.tool_call is not None
        assert action.tool_call.name == "run_nmap"
        assert action.tool_call.id == "toolu_abc"
        assert action.tool_call.arguments == {"target": "1.2.3.4"}
        assert action.thought == "I need to scan ports."
        assert action.final_answer is None

    @pytest.mark.asyncio
    async def test_reason_returns_final_answer(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        response = _make_response([_text_block("Scan complete, no issues found.")])

        with patch.object(
            AnthropicClient, "_call_with_backoff", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = response
            client = AnthropicClient()
            action = await client.reason(
                [LLMMessage(role="user", content="Summarize findings")],
            )

        assert action.final_answer == "Scan complete, no issues found."
        assert action.tool_call is None


# ---------------------------------------------------------------------------
# Tests: generate_text()
# ---------------------------------------------------------------------------


class TestGenerateText:
    @pytest.mark.asyncio
    async def test_generate_text_returns_string(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        response = _make_response([_text_block("Generated report text.")])

        with patch.object(
            AnthropicClient, "_call_with_backoff", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = response
            client = AnthropicClient()
            text = await client.generate_text("Write a report.")

        assert text == "Generated report text."


# ---------------------------------------------------------------------------
# Tests: research() fallback behavior
# ---------------------------------------------------------------------------


class TestResearch:
    @pytest.mark.asyncio
    async def test_research_without_gemini_key(
        self, _reload_settings: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without Gemini key, research() uses generate_text()."""
        monkeypatch.setenv("GEMINI_API_KEY", "")
        monkeypatch.setenv("GOOGLE_API_KEY", "")

        _sync_settings_from_env()

        from clinkz.llm.anthropic_client import AnthropicClient

        response = _make_response([_text_block("CVE-2021-41773 affects Apache 2.4.49")])

        with patch.object(
            AnthropicClient, "_call_with_backoff", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = response
            client = AnthropicClient()
            result = await client.research("CVE Apache 2.4.49")

        assert "CVE-2021-41773" in result


# ---------------------------------------------------------------------------
# Tests: token tracking
# ---------------------------------------------------------------------------


class TestTokenTracking:
    @pytest.mark.asyncio
    async def test_tokens_accumulated(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        r1 = _make_response([_text_block("a")], input_tokens=100, output_tokens=50)
        r2 = _make_response([_text_block("b")], input_tokens=200, output_tokens=75)

        with patch.object(
            AnthropicClient, "_call_with_backoff", new_callable=AsyncMock
        ) as mock_call:
            mock_call.side_effect = [r1, r2]
            client = AnthropicClient()
            await client.generate_text("first")
            await client.generate_text("second")

        assert client.total_input_tokens == 300
        assert client.total_output_tokens == 125
        assert client.total_tokens == 425


# ---------------------------------------------------------------------------
# Tests: constructor validation
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_raises_without_api_key(self) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient

        with patch("clinkz.llm.anthropic_client.settings") as mock_settings:
            mock_settings.anthropic_api_key = None
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                AnthropicClient()


# ---------------------------------------------------------------------------
# Tests: factory integration
# ---------------------------------------------------------------------------


class TestFactory:
    def test_factory_returns_anthropic_client(self, _reload_settings: None) -> None:
        from clinkz.llm.anthropic_client import AnthropicClient
        from clinkz.llm.factory import get_llm_client

        client = get_llm_client("anthropic")
        assert isinstance(client, AnthropicClient)


# ---------------------------------------------------------------------------
# Tests: model ID string validation (no API key required)
# ---------------------------------------------------------------------------


# Currently-supported Anthropic model IDs as of the Claude 4.x family.
# Update this list when Anthropic publishes new aliases or retires old ones.
_SUPPORTED_ANTHROPIC_MODEL_IDS: frozenset[str] = frozenset(
    {
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    }
)

# Retired / deprecated IDs that must never appear as defaults.
_RETIRED_ANTHROPIC_MODEL_IDS: frozenset[str] = frozenset(
    {
        "claude-sonnet-4-20250514",
        "claude-3-opus-20240229",
        "claude-3-sonnet-20240229",
        "claude-3-haiku-20240307",
        "claude-3-5-sonnet-20240620",
        "claude-3-5-sonnet-20241022",
    }
)


class TestModelId:
    """Validate the configured model ID is a currently-supported Anthropic ID.

    These tests run in CI without an API key — they're pure string checks
    on the settings defaults. Guards against shipping a retired model ID.
    """

    def test_default_model_is_supported(self, _reload_settings: None) -> None:
        from clinkz.config import settings

        assert settings.anthropic_model in _SUPPORTED_ANTHROPIC_MODEL_IDS, (
            f"settings.anthropic_model={settings.anthropic_model!r} is not in the "
            f"supported set {sorted(_SUPPORTED_ANTHROPIC_MODEL_IDS)}"
        )

    def test_default_model_is_not_retired(self, _reload_settings: None) -> None:
        from clinkz.config import settings

        assert settings.anthropic_model not in _RETIRED_ANTHROPIC_MODEL_IDS, (
            f"settings.anthropic_model={settings.anthropic_model!r} is a retired ID"
        )

    def test_client_uses_configured_model(self, _reload_settings: None) -> None:
        from clinkz.config import settings
        from clinkz.llm.anthropic_client import AnthropicClient

        client = AnthropicClient()
        assert client._model == settings.anthropic_model
        assert client._model in _SUPPORTED_ANTHROPIC_MODEL_IDS

    def test_env_override_threads_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-fake")
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4-7")

        from clinkz import config

        reloaded = config.Settings.from_env()
        assert reloaded.anthropic_model == "claude-opus-4-7"


# ---------------------------------------------------------------------------
# Tests: per-call request timeout (operation-level safety valve)
# ---------------------------------------------------------------------------


class TestRequestTimeout:
    """A single hung messages.create call is bounded by llm_request_timeout.

    This is the operation-level safety valve that matters now that the exploit
    phase has no wall-clock deadline: a stuck call is cancelled after the
    configured timeout instead of stalling the engagement indefinitely.
    """

    @pytest.mark.asyncio
    async def test_hung_call_is_bounded_by_request_timeout(self, _reload_settings: None) -> None:
        from clinkz import config
        from clinkz.llm.anthropic_client import AnthropicClient

        config.settings.llm_request_timeout = 0.05
        config.settings.llm_max_retries = 1

        client = AnthropicClient()

        async def _hang(**_kwargs: Any) -> Any:
            await asyncio.sleep(30)  # would stall forever without the valve

        # Replace the SDK client + rate limiter so no key/network/delay is hit.
        client._client = SimpleNamespace(messages=SimpleNamespace(create=_hang))
        client._rate_limiter = SimpleNamespace(acquire=AsyncMock())

        start = time.monotonic()
        with pytest.raises(TimeoutError):
            await client._call_with_backoff(model="m", messages=[], max_tokens=8)
        elapsed = time.monotonic() - start

        # Bounded by the timeout (×1 retry), nowhere near the 30s sleep.
        assert elapsed < 5.0

    def test_timeout_is_retriable(self) -> None:
        from clinkz.llm.anthropic_client import _is_retriable_error

        # asyncio.TimeoutError is an alias of the builtin on Python 3.11+.
        assert _is_retriable_error(TimeoutError())
