"""Tests for GeminiClient.

All tests mock the google-genai SDK — no real API calls are made.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clinkz.llm.base import AgentAction, LLMMessage, ToolCall


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_settings(api_key: str = "fake-key", model: str = "gemini-2.5-flash") -> MagicMock:
    s = MagicMock()
    s.gemini_api_key = api_key
    s.google_api_key = None
    s.gemini_model = model
    return s


def _make_client(settings_mock: MagicMock | None = None) -> Any:
    """Instantiate GeminiClient with mocked settings and genai.Client."""
    if settings_mock is None:
        settings_mock = _make_settings()
    with (
        patch("clinkz.llm.gemini_client.settings", settings_mock),
        patch("clinkz.llm.gemini_client.genai.Client"),
    ):
        from clinkz.llm.gemini_client import GeminiClient

        return GeminiClient()


# ---------------------------------------------------------------------------
# 1. Schema conversion: OpenAI tool schema → Gemini FunctionDeclarations
# ---------------------------------------------------------------------------

class TestToGeminiTools:
    def test_single_tool_name_and_description(self) -> None:
        client = _make_client()
        tools = [
            {
                "name": "run_nmap",
                "description": "Run nmap port scan",
                "parameters": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            }
        ]
        result = client._to_gemini_tools(tools)
        assert len(result) == 1
        decl = result[0].function_declarations[0]
        assert decl.name == "run_nmap"
        assert decl.description == "Run nmap port scan"

    def test_parameters_schema_has_correct_type(self) -> None:
        """The parameters dict is converted to a Schema object with OBJECT type."""
        from google.genai import types

        client = _make_client()
        params = {
            "type": "object",
            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["host"],
        }
        tools = [{"name": "scan", "description": "scan", "parameters": params}]
        result = client._to_gemini_tools(tools)
        decl = result[0].function_declarations[0]
        # SDK converts dict → Schema; verify it's a Schema with type=OBJECT
        assert isinstance(decl.parameters, types.Schema)
        assert str(decl.parameters.type).upper() in ("OBJECT", "TYPE_OBJECT", "TYPE.OBJECT")

    def test_parameters_properties_are_preserved(self) -> None:
        """Schema properties are preserved after dict→Schema conversion."""
        client = _make_client()
        params = {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        }
        tools = [{"name": "scan", "description": "scan", "parameters": params}]
        result = client._to_gemini_tools(tools)
        schema = result[0].function_declarations[0].parameters
        assert "host" in schema.properties

    def test_multiple_tools_in_single_tool_wrapper(self) -> None:
        client = _make_client()
        tools = [
            {"name": "tool_a", "description": "A", "parameters": {}},
            {"name": "tool_b", "description": "B", "parameters": {}},
        ]
        result = client._to_gemini_tools(tools)
        # All declarations should be in a single Tool object
        assert len(result) == 1
        assert len(result[0].function_declarations) == 2
        names = {d.name for d in result[0].function_declarations}
        assert names == {"tool_a", "tool_b"}

    def test_missing_description_defaults_to_empty_string(self) -> None:
        client = _make_client()
        tools = [{"name": "no_desc", "parameters": {}}]
        result = client._to_gemini_tools(tools)
        assert result[0].function_declarations[0].description == ""


# ---------------------------------------------------------------------------
# 2. Rate limiter logic
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_allows_up_to_max_calls_immediately(self) -> None:
        from clinkz.llm.gemini_client import _RateLimiter

        limiter = _RateLimiter(max_calls=3, period=60.0)

        async def run() -> float:
            start = time.monotonic()
            for _ in range(3):
                await limiter.acquire()
            return time.monotonic() - start

        elapsed = asyncio.run(run())
        # Three calls within the window should return almost instantly
        assert elapsed < 1.0

    def test_blocks_when_window_full(self) -> None:
        """The 3rd call should be delayed when the window (size=2) is full."""
        from clinkz.llm.gemini_client import _RateLimiter

        # Very short period so the test doesn't take long
        limiter = _RateLimiter(max_calls=2, period=0.3)

        async def run() -> float:
            await limiter.acquire()
            await limiter.acquire()
            start = time.monotonic()
            await limiter.acquire()  # must wait for window to slide
            return time.monotonic() - start

        wait_time = asyncio.run(run())
        # Should have waited roughly 0.3 seconds (the period)
        assert wait_time >= 0.25, f"Expected >=0.25s wait, got {wait_time:.3f}s"

    def test_concurrent_callers_respect_limit(self) -> None:
        """Five concurrent callers with limit=2 should all complete without error."""
        from clinkz.llm.gemini_client import _RateLimiter

        limiter = _RateLimiter(max_calls=2, period=0.2)
        results: list[bool] = []

        async def run() -> None:
            async def one_acquire() -> None:
                await limiter.acquire()
                results.append(True)

            await asyncio.gather(*[one_acquire() for _ in range(5)])

        asyncio.run(run())
        assert len(results) == 5  # all completed


# ---------------------------------------------------------------------------
# 3. Exponential backoff on 429 errors
# ---------------------------------------------------------------------------

class TestBackoff:
    @pytest.mark.asyncio
    async def test_retries_on_rate_limit_then_succeeds(self) -> None:
        client = _make_client()
        call_count = 0
        mock_response = MagicMock()
        mock_response.candidates = [MagicMock(content=MagicMock(parts=[]))]
        mock_response.usage_metadata = None

        async def fake_coro() -> Any:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("429 Resource Exhausted quota exceeded")
            return mock_response

        client._rate_limiter.acquire = AsyncMock()

        with patch("clinkz.llm.gemini_client.asyncio.sleep", new_callable=AsyncMock):
            result = await client._call_with_backoff(lambda: fake_coro())

        assert result is mock_response
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self) -> None:
        client = _make_client()

        async def always_fail() -> Any:
            raise Exception("429 quota exhausted")

        client._rate_limiter.acquire = AsyncMock()

        with (
            patch("clinkz.llm.gemini_client.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(Exception, match="429"),
        ):
            await client._call_with_backoff(lambda: always_fail())

    @pytest.mark.asyncio
    async def test_non_rate_limit_error_not_retried(self) -> None:
        client = _make_client()
        call_count = 0

        async def fail_with_other_error() -> Any:
            nonlocal call_count
            call_count += 1
            raise ValueError("Invalid request")

        client._rate_limiter.acquire = AsyncMock()

        with pytest.raises(ValueError, match="Invalid request"):
            await client._call_with_backoff(lambda: fail_with_other_error())

        assert call_count == 1  # no retries

    @pytest.mark.asyncio
    async def test_backoff_sleep_duration_doubles(self) -> None:
        """Verify sleep durations follow 2^attempt (1, 2, 4…)."""
        client = _make_client()
        sleep_calls: list[float] = []
        call_count = 0

        async def fake_sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        mock_response = MagicMock(candidates=[MagicMock(content=MagicMock(parts=[]))], usage_metadata=None)

        async def fail_3_times() -> Any:
            nonlocal call_count
            call_count += 1
            if call_count < 4:
                raise Exception("429 Resource Exhausted")
            return mock_response

        client._rate_limiter.acquire = AsyncMock()

        with patch("clinkz.llm.gemini_client.asyncio.sleep", side_effect=fake_sleep):
            await client._call_with_backoff(lambda: fail_3_times())

        assert sleep_calls == [1, 2, 4]  # 2^0, 2^1, 2^2


# ---------------------------------------------------------------------------
# 4. Factory returns GeminiClient for provider="gemini"
# ---------------------------------------------------------------------------

class TestFactory:
    def test_factory_returns_gemini_client_for_gemini_provider(self) -> None:
        mock_settings = _make_settings()

        with (
            patch("clinkz.llm.factory.settings") as mock_factory_settings,
            patch("clinkz.llm.gemini_client.settings", mock_settings),
            patch("clinkz.llm.gemini_client.genai.Client"),
        ):
            mock_factory_settings.llm_provider = "gemini"
            from clinkz.llm.factory import get_llm_client
            from clinkz.llm.gemini_client import GeminiClient

            client = get_llm_client("gemini")
            assert isinstance(client, GeminiClient)

    def test_factory_raises_for_unknown_provider(self) -> None:
        with patch("clinkz.llm.factory.settings") as mock_settings:
            mock_settings.llm_provider = "unknown"
            from clinkz.llm.factory import get_llm_client

            with pytest.raises(ValueError, match="Unsupported LLM provider"):
                get_llm_client("unknown_provider")

    def test_gemini_client_raises_without_api_key(self) -> None:
        bad_settings = MagicMock()
        bad_settings.gemini_api_key = None
        bad_settings.google_api_key = None
        bad_settings.gemini_model = "gemini-2.5-flash"

        with (
            patch("clinkz.llm.gemini_client.settings", bad_settings),
            pytest.raises(ValueError, match="GEMINI_API_KEY"),
        ):
            from clinkz.llm.gemini_client import GeminiClient

            GeminiClient()


# ---------------------------------------------------------------------------
# 5. Token tracking
# ---------------------------------------------------------------------------

class TestTokenTracking:
    @pytest.mark.asyncio
    async def test_tokens_accumulate_across_calls(self) -> None:
        client = _make_client()

        def _make_response(inp: int, out: int) -> MagicMock:
            r = MagicMock()
            r.candidates = [MagicMock(content=MagicMock(parts=[MagicMock(text="hello", function_call=None)]))]
            r.usage_metadata = MagicMock(prompt_token_count=inp, candidates_token_count=out)
            r.text = "hello"
            return r

        client._rate_limiter.acquire = AsyncMock()

        call_num = 0

        async def fake_generate(**kwargs: Any) -> Any:
            nonlocal call_num
            call_num += 1
            return _make_response(10, 5) if call_num == 1 else _make_response(20, 8)

        client._client.aio.models.generate_content = fake_generate

        await client.generate_text("prompt 1")
        await client.generate_text("prompt 2")

        assert client.total_input_tokens == 30
        assert client.total_output_tokens == 13
        assert client.total_tokens == 43


# ---------------------------------------------------------------------------
# 6. Message conversion
# ---------------------------------------------------------------------------

class TestToGeminiContents:
    def test_system_message_extracted_as_instruction(self) -> None:
        client = _make_client()
        messages = [
            LLMMessage(role="system", content="You are a pentest agent."),
            LLMMessage(role="user", content="Scan example.com"),
        ]
        system, contents = client._to_gemini_contents(messages)
        assert system == "You are a pentest agent."
        assert len(contents) == 1
        assert contents[0].role == "user"

    def test_tool_role_maps_to_function_response(self) -> None:
        client = _make_client()
        messages = [
            LLMMessage(role="tool", content='{"open_ports": [80]}', tool_call_id="run_nmap"),
        ]
        _, contents = client._to_gemini_contents(messages)
        assert contents[0].role == "user"
        part = contents[0].parts[0]
        assert part.function_response is not None
        assert part.function_response.name == "run_nmap"

    def test_assistant_with_tool_calls(self) -> None:
        client = _make_client()
        messages = [
            LLMMessage(
                role="assistant",
                content="",
                tool_calls=[ToolCall(id="run_nmap", name="run_nmap", arguments={"target": "1.2.3.4"})],
            )
        ]
        _, contents = client._to_gemini_contents(messages)
        assert contents[0].role == "model"
        part = contents[0].parts[0]
        assert part.function_call is not None
        assert part.function_call.name == "run_nmap"
        assert part.function_call.args == {"target": "1.2.3.4"}

    def test_no_system_messages_returns_none(self) -> None:
        client = _make_client()
        messages = [LLMMessage(role="user", content="Hello")]
        system, contents = client._to_gemini_contents(messages)
        assert system is None
        assert len(contents) == 1
