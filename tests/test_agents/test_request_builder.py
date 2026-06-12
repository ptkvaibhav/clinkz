"""Unit tests for the shared request builder (fix #4).

The injection family no longer hand-rolls request construction: a methodology
says "inject value V into param P", and the builder decides *how* to carry it
based on the param's location (query / json_body / form_body / path). These
tests pin that dispatch and the JSON serialization primitive.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

# asyncio_mode = "auto" (pyproject) auto-detects async tests; no marker needed,
# and this file deliberately mixes sync (pure-function) and async tests.

SCOPE = EngagementScope(
    name="request-builder-test",
    targets=[ScopeEntry(value="t", type=ScopeType.DOMAIN)],
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
    state.add_finding = AsyncMock(return_value="f-1")
    state.log_action = AsyncMock()
    return state


def _make_agent() -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="request-builder-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _stub_transports(agent: ExploitAgent) -> dict[str, AsyncMock]:
    """Replace the three transport primitives with recording mocks."""
    resp = _HTTPResponse(status=200, body="{}", headers={})
    mocks = {
        "_http_get": AsyncMock(return_value=resp),
        "_http_post": AsyncMock(return_value=resp),
        "_http_post_json": AsyncMock(return_value=resp),
    }
    for name, mock in mocks.items():
        setattr(agent, name, mock)
    return mocks


# ---------------------------------------------------------------------------
# _send_probe dispatch
# ---------------------------------------------------------------------------


async def test_send_probe_query_param_uses_get() -> None:
    agent = _make_agent()
    m = _stub_transports(agent)
    page = PageAnalysis(url="http://t/search", body="", status=200, input_params=["q"])

    await agent._send_probe(page, "q", "PAYLOAD")

    m["_http_get"].assert_awaited_once_with("http://t/search", {"q": "PAYLOAD"})
    m["_http_post"].assert_not_awaited()
    m["_http_post_json"].assert_not_awaited()


async def test_send_probe_json_body_param_serializes_json_body() -> None:
    agent = _make_agent()
    m = _stub_transports(agent)
    page = PageAnalysis(
        url="http://t/api/Feedbacks",
        body="",
        status=200,
        input_params=["comment", "rating"],
        request_method="POST",
        content_type="application/json",
        param_locations={
            "comment": ParamLocation.JSON_BODY,
            "rating": ParamLocation.JSON_BODY,
        },
    )

    await agent._send_probe(page, "comment", "<script>alert(1)</script>")

    m["_http_post_json"].assert_awaited_once()
    args, kwargs = m["_http_post_json"].await_args
    assert args[0] == "http://t/api/Feedbacks"
    body = args[1]
    # Payload lands in the probed field; siblings get benign baselines.
    assert body["comment"] == "<script>alert(1)</script>"
    assert body["rating"] == "1"
    assert kwargs.get("method") == "POST"
    m["_http_get"].assert_not_awaited()


async def test_send_probe_path_param_substitutes_in_path() -> None:
    agent = _make_agent()
    m = _stub_transports(agent)
    # Location is inferred from the templated URL — no explicit map needed.
    page = PageAnalysis(url="http://t/rest/basket/:id", body="", status=200, input_params=["id"])
    assert page.param_location("id") is ParamLocation.PATH

    await agent._send_probe(page, "id", "5")

    # Dispatch routes through _http_get; the path substitution itself is
    # exercised by test_build_request_url_path_substitution below.
    m["_http_get"].assert_awaited_once_with("http://t/rest/basket/:id", {"id": "5"})
    m["_http_post_json"].assert_not_awaited()


async def test_send_probe_html_form_posts_full_form() -> None:
    agent = _make_agent()
    m = _stub_transports(agent)
    form = {
        "method": "POST",
        "action": "",
        "fields": [
            {"name": "name", "type": "text", "value": ""},
            {"name": "other", "type": "hidden", "value": "keep"},
        ],
    }
    page = PageAnalysis(
        url="http://t/guestbook", body="", status=200, input_params=["name"], forms=[form]
    )

    await agent._send_probe(page, "name", "INJ")

    m["_http_post"].assert_awaited_once()
    args, _ = m["_http_post"].await_args
    assert args[0] == "http://t/guestbook"
    assert args[1] == {"name": "INJ", "other": "keep"}
    m["_http_post_json"].assert_not_awaited()


# ---------------------------------------------------------------------------
# _http_post_json serialization
# ---------------------------------------------------------------------------


async def test_http_post_json_builds_json_request(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _CapturingHTTP:
        def __init__(self, scope: Any = None, engagement_id: Any = None) -> None:
            pass

        def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
            captured.update(args)
            return args

        async def execute(self, validated: dict[str, Any]) -> dict[str, Any]:
            return {}

        def parse_output(self, raw: Any) -> Any:
            class _Parsed:
                status_code = 201
                response_body = '{"ok":true}'
                response_headers: dict[str, str] = {}

            return _Parsed()

    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _CapturingHTTP)
    agent = _make_agent()
    agent._session_cookies = {"sid": "abc"}
    agent._session_headers = {"Authorization": "Bearer JWT"}

    resp = await agent._http_post_json(
        "http://t/rest/user/login", {"email": "a@b.c", "password": "x"}, method="POST"
    )

    assert resp.status == 201
    assert captured["method"] == "POST"
    assert captured["headers"]["Content-Type"] == "application/json"
    # JWT bearer + cookies are carried through, same as form POSTs.
    assert captured["headers"]["Authorization"] == "Bearer JWT"
    assert captured["cookies"] == {"sid": "abc"}
    assert json.loads(captured["body"]) == {"email": "a@b.c", "password": "x"}


async def test_http_post_json_unknown_method_falls_back_to_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _CapturingHTTP:
        def __init__(self, scope: Any = None, engagement_id: Any = None) -> None:
            pass

        def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
            captured.update(args)
            return args

        async def execute(self, validated: dict[str, Any]) -> dict[str, Any]:
            return {}

        def parse_output(self, raw: Any) -> Any:
            class _Parsed:
                status_code = 200
                response_body = ""
                response_headers: dict[str, str] = {}

            return _Parsed()

    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _CapturingHTTP)
    agent = _make_agent()
    await agent._http_post_json("http://t/x", {"a": "b"}, method="GET")
    assert captured["method"] == "POST"


# ---------------------------------------------------------------------------
# _build_request_url path substitution (the :id work, folded in)
# ---------------------------------------------------------------------------


def test_build_request_url_path_substitution() -> None:
    agent = _make_agent()
    assert (
        agent._build_request_url("http://t/rest/basket/:id", {"id": "5"})
        == "http://t/rest/basket/5"
    )
    # {name} placeholders too, and consumed keys are not re-appended as query.
    assert (
        agent._build_request_url("http://t/api/Users/{id}", {"id": "7"}) == "http://t/api/Users/7"
    )


def test_build_request_url_query_replaces_in_place() -> None:
    agent = _make_agent()
    # A same-named query key is replaced, never duplicated.
    assert agent._build_request_url("http://t/s?q=old", {"q": "new"}) == "http://t/s?q=new"


# ---------------------------------------------------------------------------
# Pseudo-form synthesis + encoding-aware submit
# ---------------------------------------------------------------------------


def test_injectable_forms_synthesizes_json_pseudo_form() -> None:
    agent = _make_agent()
    page = PageAnalysis(
        url="http://t/api/Feedbacks",
        body="",
        status=200,
        input_params=["comment", "rating"],
        request_method="POST",
        param_locations={
            "comment": ParamLocation.JSON_BODY,
            "rating": ParamLocation.JSON_BODY,
        },
    )
    forms = agent._injectable_forms(page)
    assert len(forms) == 1
    pf = forms[0]
    assert pf["encoding"] == "json"
    assert pf["method"] == "POST"
    assert {f["name"] for f in pf["fields"]} == {"comment", "rating"}


def test_injectable_forms_preserves_html_forms_and_adds_none_without_body() -> None:
    agent = _make_agent()
    html_form = {"method": "POST", "action": "", "fields": [{"name": "x", "type": "text"}]}
    page = PageAnalysis(
        url="http://t/p", body="", status=200, input_params=["x"], forms=[html_form]
    )
    # No json_body params → only the HTML form, unchanged (DVWA path intact).
    assert agent._injectable_forms(page) == [html_form]


async def test_submit_form_fields_routes_by_encoding() -> None:
    agent = _make_agent()
    m = _stub_transports(agent)

    json_form = {"method": "POST", "encoding": "json", "fields": []}
    await agent._submit_form_fields("http://t/api/x", json_form, {"a": "1"})
    m["_http_post_json"].assert_awaited_once_with("http://t/api/x", {"a": "1"}, method="POST")

    html_post = {"method": "POST", "fields": []}
    await agent._submit_form_fields("http://t/form", html_post, {"a": "1"})
    m["_http_post"].assert_awaited_once_with("http://t/form", {"a": "1"})

    html_get = {"method": "GET", "fields": []}
    await agent._submit_form_fields("http://t/form", html_get, {"a": "1"})
    m["_http_get"].assert_awaited_once_with("http://t/form", {"a": "1"})


def test_infer_field_type_classifies_credentials() -> None:
    agent = _make_agent()
    assert agent._infer_field_type("password") == "password"
    assert agent._infer_field_type("userPwd") == "password"
    assert agent._infer_field_type("email") == "email"
    assert agent._infer_field_type("comment") == "text"
