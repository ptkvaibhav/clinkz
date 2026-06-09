"""Regression tests: JWT/bearer auth headers propagate the same way cookies do.

Juice Shop authenticates with ``Authorization: Bearer <jwt>`` (no cookie
session). The orchestrator hands the bearer to the Scan/Exploit agents via
``session_headers``; from there it must ride every methodology probe and the
authenticated crawl — exactly the path the session cookies already take.

These tests assert the header reaches the HTTP-client invocation (the
``cookies``-parallel chokepoint), and that the cookie path is unaffected.
"""

from __future__ import annotations

import json
import types
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.agents.scan import ScanAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolMatch, ToolResolver

SCOPE = EngagementScope(
    name="session-headers-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


class _CapturingHTTPTool:
    """Minimal HTTPClientTool stand-in that records the validated args.

    Implements only the ``validate_input`` → ``execute`` → ``parse_output``
    surface the agents use, capturing the args dict so tests can assert on the
    propagated ``headers`` / ``cookies``.
    """

    captured: list[dict[str, Any]] = []

    def __init__(self, scope: Any = None, engagement_id: str | None = None, **_: Any) -> None:
        pass

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        type(self).captured.append(dict(args))
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        return json.dumps(
            {"status_code": 200, "response_body": "<html></html>", "response_headers": {}}
        )

    def parse_output(self, raw_output: str) -> Any:
        data = json.loads(raw_output)
        return types.SimpleNamespace(
            status_code=data["status_code"],
            response_body=data["response_body"],
            response_headers=data["response_headers"],
        )


def _make_exploit_agent() -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="session-headers-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


# ---------------------------------------------------------------------------
# Exploit agent — the methodologies' HTTP probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_get_sends_bearer_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """_http_get attaches the bearer header AND cookies when both are present."""
    _CapturingHTTPTool.captured = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _CapturingHTTPTool)

    agent = _make_exploit_agent()
    agent._session_cookies = {"PHPSESSID": "abc"}
    agent._session_headers = {"Authorization": "Bearer JWT-TOKEN"}

    await agent._http_get("http://example.com/", {"q": "1"})

    assert len(_CapturingHTTPTool.captured) == 1
    args = _CapturingHTTPTool.captured[0]
    assert args["headers"] == {"Authorization": "Bearer JWT-TOKEN"}
    assert args["cookies"] == {"PHPSESSID": "abc"}


@pytest.mark.asyncio
async def test_http_get_omits_headers_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """No session headers → no 'headers' key (DVWA cookie path unchanged)."""
    _CapturingHTTPTool.captured = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _CapturingHTTPTool)

    agent = _make_exploit_agent()
    agent._session_cookies = {"PHPSESSID": "abc"}
    agent._session_headers = {}

    await agent._http_get("http://example.com/", {})

    args = _CapturingHTTPTool.captured[0]
    assert "headers" not in args
    assert args["cookies"] == {"PHPSESSID": "abc"}


@pytest.mark.asyncio
async def test_http_post_merges_bearer_with_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_http_post keeps the form Content-Type and adds the bearer header."""
    _CapturingHTTPTool.captured = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _CapturingHTTPTool)

    agent = _make_exploit_agent()
    agent._session_headers = {"Authorization": "Bearer JWT-TOKEN"}

    await agent._http_post("http://example.com/", {"a": "b"})

    args = _CapturingHTTPTool.captured[0]
    assert args["headers"]["Authorization"] == "Bearer JWT-TOKEN"
    assert args["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


# ---------------------------------------------------------------------------
# Scan agent — the authenticated HTTP-client crawl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_crawl_forwards_bearer_header() -> None:
    """The scan agent's HTTP-client crawl carries the bearer header."""
    _CapturingHTTPTool.captured = []
    resolver = AsyncMock(spec=ToolResolver)
    resolver.find_tool.return_value = ToolMatch(
        name="http_client", source="local", available=True, tool_class=_CapturingHTTPTool
    )

    agent = ScanAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="session-headers-test",
        resolver=resolver,
    )
    agent._session_headers = {"Authorization": "Bearer JWT-TOKEN"}

    await agent._http_crawl_fallback("http://example.com/", max_depth=0, max_pages=1)

    assert _CapturingHTTPTool.captured, "no HTTP request was issued"
    args = _CapturingHTTPTool.captured[0]
    assert args["headers"] == {"Authorization": "Bearer JWT-TOKEN"}
