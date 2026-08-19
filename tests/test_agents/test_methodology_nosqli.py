"""Unit tests for the adaptive NoSQL-injection methodology phases.

Mirrors the SQLi methodology tests: each phase is exercised in isolation with a
mocked ``_nosql_send_probe`` / ``_http_post_json`` and a silent LLM (so the
deterministic fallbacks drive), plus an end-to-end run and an N/A check on a
SQL/PHP-shaped stack (no false emission).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents import exploit as exploit_module
from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    NoSQLContext,
    NoSQLInjectionType,
    NoSQLPrimitives,
)
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-nosqli-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mocks / fixtures
# ---------------------------------------------------------------------------


class _SilentLLM(LLMClient):
    """LLM whose ``generate_text`` returns "" so deterministic fallbacks drive."""

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


def _make_agent() -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="methodology-nosqli-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _json_body_page(
    url: str = "http://example.com/rest/products/reviews",
    fields: tuple[str, ...] = ("id",),
) -> PageAnalysis:
    return PageAnalysis(
        url=url,
        body="",
        status=200,
        input_params=list(fields),
        request_method="PATCH",
        content_type="application/json",
        param_locations={f: ParamLocation.JSON_BODY for f in fields},
    )


def _query_page(
    url: str = "http://example.com/items?id=1", params: tuple[str, ...] = ("id",)
) -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=list(params))


def _resp(status: int, body: str = "") -> _HTTPResponse:
    return _HTTPResponse(status=status, body=body)


def _modified(n: int) -> str:
    return f'{{"modified": {n}}}'


# ===========================================================================
# Phase 1 — injection-point mapping
# ===========================================================================


@pytest.mark.asyncio
async def test_phase1_no_divergence_not_candidate() -> None:
    """Identical responses for every probe → not a candidate."""
    agent = _make_agent()
    agent._nosql_send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, _modified(0))
    )
    is_candidate, baselines = await agent._nosql_phase1_injection_point(_json_body_page(), "id")
    assert is_candidate is False
    assert len(baselines) == 3


@pytest.mark.asyncio
async def test_phase1_operator_divergence_is_candidate() -> None:
    """An operator-object probe that diverges from benign → candidate."""
    agent = _make_agent()

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        return _resp(200, _modified(99) if isinstance(value, dict) else _modified(0))

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    is_candidate, _ = await agent._nosql_phase1_injection_point(_json_body_page(), "id")
    assert is_candidate is True


# ===========================================================================
# Phase 2 — context + operator fingerprinting
# ===========================================================================


async def _run_phase2(agent: ExploitAgent, page: PageAnalysis, param: str):
    _, baselines = await agent._nosql_phase1_injection_point(page, param)
    return await agent._nosql_phase2_fingerprint(page, param, baselines)


@pytest.mark.asyncio
async def test_phase2_operator_confirmed_by_count_widening() -> None:
    """A JSON-body operator that widens the modified count → JSON_OPERATOR context."""
    agent = _make_agent()

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        if isinstance(value, dict):
            return _resp(200, _modified(99))  # operator widens
        return _resp(200, _modified(0))  # benign / where-break literal

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    context, primitives, _ = await _run_phase2(agent, _json_body_page(), "id")
    assert context is NoSQLContext.JSON_OPERATOR
    assert "$ne" in primitives.operators
    assert primitives.where_string_injectable is False


@pytest.mark.asyncio
async def test_phase2_sql_error_not_confirmed() -> None:
    """SQL errors are not a NoSQL signal — no operators, no $where (DVWA-like)."""
    agent = _make_agent()
    sql_err = "You have an error in your SQL syntax; check the MySQL manual"

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        if isinstance(value, str) and not value.endswith("'"):
            return _resp(200, "<html>items</html>")  # benign
        return _resp(200, sql_err)  # operator bracket + where-break: SQL error

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    context, primitives, _ = await _run_phase2(agent, _query_page(), "id")
    assert context is NoSQLContext.UNKNOWN
    assert primitives.operators == []
    assert primitives.where_string_injectable is False


@pytest.mark.asyncio
async def test_phase2_where_context_on_non_sql_5xx() -> None:
    """A 5xx from a lone quote with no SQL signature → STRING_WHERE context."""
    agent = _make_agent()

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        if isinstance(value, str) and value.endswith("'"):
            return _resp(500, "TypeError: Cannot read properties of undefined")
        return _resp(200, "<html>order</html>")  # benign + operator bracket (ignored)

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    page = _query_page(url="http://example.com/rest/track-order/1")
    context, primitives, _ = await _run_phase2(agent, page, "id")
    assert context is NoSQLContext.STRING_WHERE
    assert primitives.where_string_injectable is True


# ===========================================================================
# Phase 3 — injection-type ranking
# ===========================================================================


@pytest.mark.asyncio
async def test_phase3_na_guard_returns_empty() -> None:
    """No NoSQL signal at all → empty ranking (the N/A gate for a SQL stack)."""
    agent = _make_agent()
    primitives = NoSQLPrimitives(context=NoSQLContext.UNKNOWN)
    ranked = await agent._nosql_phase3_rank_injection_types(NoSQLContext.UNKNOWN, primitives, {})
    assert ranked == []


@pytest.mark.asyncio
async def test_phase3_fallback_json_operator() -> None:
    """JSON-operator context (silent LLM) → operator/auth/boolean ranking."""
    agent = _make_agent()
    primitives = NoSQLPrimitives(context=NoSQLContext.JSON_OPERATOR, operators=["$ne"])
    ranked = await agent._nosql_phase3_rank_injection_types(
        NoSQLContext.JSON_OPERATOR, primitives, {}
    )
    assert ranked[0] is NoSQLInjectionType.OPERATOR_INJECTION
    assert NoSQLInjectionType.AUTH_BYPASS in ranked


@pytest.mark.asyncio
async def test_phase3_fallback_string_where() -> None:
    """String-$where context (silent LLM) → DoS / JS-injection ranking."""
    agent = _make_agent()
    primitives = NoSQLPrimitives(context=NoSQLContext.STRING_WHERE, where_string_injectable=True)
    ranked = await agent._nosql_phase3_rank_injection_types(
        NoSQLContext.STRING_WHERE, primitives, {}
    )
    assert NoSQLInjectionType.NOSQL_DOS in ranked
    assert NoSQLInjectionType.WHERE_JS_INJECTION in ranked


# ===========================================================================
# Phase 4 — payload synthesis
# ===========================================================================


@pytest.mark.asyncio
async def test_phase4_operator_injection_deterministic() -> None:
    """Operator-injection synthesis yields an operator-object probe value."""
    agent = _make_agent()
    primitives = NoSQLPrimitives(context=NoSQLContext.JSON_OPERATOR, operators=["$ne"])
    benign = {"value": "1"}
    synth = await agent._nosql_phase4_synthesize_payload(
        NoSQLInjectionType.OPERATOR_INJECTION, NoSQLContext.JSON_OPERATOR, primitives, benign
    )
    assert synth is not None
    assert isinstance(synth["probe_value"], dict)
    assert "$ne" in synth["probe_value"]
    assert synth["indicator_type"] == "match_widen"


# ===========================================================================
# Phase 5 — verification (evidence-driven, reflection-honest)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase5_operator_widen_confirmed() -> None:
    """A 2xx response whose count exceeds the benign baseline confirms."""
    agent = _make_agent()
    agent._nosql_send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, _modified(99))
    )
    benign = {"body": _modified(0), "status": 200, "value": "1"}
    synth = {"probe_value": {"$ne": -1}, "payload": '{"$ne": -1}'}
    ok, observed = await agent._nosql_phase5_verify(
        _json_body_page(), "id", NoSQLInjectionType.OPERATOR_INJECTION, synth, benign
    )
    assert ok is True
    assert "0 -> 99" in observed


@pytest.mark.asyncio
async def test_phase5_operator_reflection_in_error_rejected() -> None:
    """A marker echoed in a 5xx error response is reflection, not data."""
    agent = _make_agent()
    agent._nosql_send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(500, 'MongoError: {"$ne": -1}')
    )
    benign = {"body": _modified(0), "status": 200, "value": "1"}
    synth = {"probe_value": {"$ne": -1}, "payload": '{"$ne": -1}'}
    ok, _ = await agent._nosql_phase5_verify(
        _json_body_page(), "id", NoSQLInjectionType.OPERATOR_INJECTION, synth, benign
    )
    assert ok is False


@pytest.mark.asyncio
async def test_phase5_operator_sql_error_rejected() -> None:
    """A SQL error in a 2xx response is not a NoSQL signal."""
    agent = _make_agent()
    agent._nosql_send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, "You have an error in your SQL syntax near ... MySQL")
    )
    benign = {"body": _modified(0), "status": 200, "value": "1"}
    synth = {"probe_value": {"$ne": -1}, "payload": '{"$ne": -1}'}
    ok, _ = await agent._nosql_phase5_verify(
        _json_body_page(), "id", NoSQLInjectionType.OPERATOR_INJECTION, synth, benign
    )
    assert ok is False


@pytest.mark.asyncio
async def test_phase5_auth_bypass_confirmed() -> None:
    """Operator-object credentials returning a token (benign did not) confirm."""
    agent = _make_agent()
    agent._http_post_json = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, '{"authentication":{"token":"abc.def.ghi"}}')
    )
    page = _json_body_page(url="http://example.com/rest/user/login", fields=("email", "password"))
    benign = {"body": '{"error":"Invalid email or password"}', "status": 401, "value": "x"}
    synth = {"probe_value": {"$ne": None}, "payload": "{}"}
    ok, _ = await agent._nosql_phase5_verify(
        page, "email", NoSQLInjectionType.AUTH_BYPASS, synth, benign
    )
    assert ok is True


@pytest.mark.asyncio
async def test_phase5_boolean_blind_differential() -> None:
    """A true/false $regex differential confirms; identical bodies do not."""
    agent = _make_agent()

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        # The match-all true probe returns more than the match-none false probe.
        if isinstance(value, dict) and value.get("$regex") == ".*":
            return _resp(200, "A" * 100)
        return _resp(200, "B" * 10)

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    benign = {"body": "", "status": 200, "value": "1"}
    synth = {"probe_value": {"$regex": ".*"}, "control_value": {"$regex": "^zzz$"}, "payload": "x"}
    ok, _ = await agent._nosql_phase5_verify(
        _json_body_page(), "id", NoSQLInjectionType.BOOLEAN_BLIND, synth, benign
    )
    assert ok is True


@pytest.mark.asyncio
async def test_phase5_nosql_dos_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A $where sleep crossing the threshold confirms; a fast response does not."""
    agent = _make_agent()
    monkeypatch.setattr(exploit_module, "_NOSQL_VERIFY_THRESHOLD", 0.05)

    async def slow(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        await asyncio.sleep(0.12)
        return _resp(200, "[]")

    agent._nosql_send_probe = AsyncMock(side_effect=slow)  # type: ignore[method-assign]
    benign = {"body": "[]", "status": 200, "value": "1"}
    synth = {"probe_value": "',sleep(2000),'", "payload": "',sleep(2000),'"}
    page = _query_page(url="http://example.com/rest/track-order/1")
    ok, _ = await agent._nosql_phase5_verify(
        page, "id", NoSQLInjectionType.NOSQL_DOS, synth, benign
    )
    assert ok is True

    async def fast(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        return _resp(200, "[]")

    agent._nosql_send_probe = AsyncMock(side_effect=fast)  # type: ignore[method-assign]
    ok2, _ = await agent._nosql_phase5_verify(
        page, "id", NoSQLInjectionType.NOSQL_DOS, synth, benign
    )
    assert ok2 is False


# ===========================================================================
# End-to-end + N/A contract
# ===========================================================================


@pytest.mark.asyncio
async def test_end_to_end_operator_injection_emits() -> None:
    """A JSON-body operator-injection point is taken end-to-end to a finding."""
    agent = _make_agent()

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        if isinstance(value, dict):
            return _resp(200, _modified(99))  # operator widens all reviews
        return _resp(200, _modified(0))  # benign literal / where-break

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    findings = await agent._test_nosqli(_json_body_page(fields=("id",)))
    assert len(findings) >= 1
    finding = findings[0]
    assert "nosql" in finding.title.lower()
    assert any("phases_completed=" in ev for ev in finding.evidence)
    assert any("injection_type=operator_injection" in ev for ev in finding.evidence)
    assert any("context=json_operator" in ev for ev in finding.evidence)


@pytest.mark.asyncio
async def test_na_on_sql_stack_no_emission() -> None:
    """On a SQL/PHP stack the methodology emits nothing (no NoSQL signal)."""
    agent = _make_agent()
    sql_err = "You have an error in your SQL syntax; check the MySQL manual"

    def probe(page: PageAnalysis, param: str, value: Any) -> _HTTPResponse:
        if isinstance(value, str) and not value.endswith("'"):
            return _resp(200, "<html>items</html>")  # benign
        return _resp(200, sql_err)  # operator bracket + where-break: SQL error

    agent._nosql_send_probe = AsyncMock(side_effect=probe)  # type: ignore[method-assign]
    findings = await agent._test_nosqli(_query_page())
    assert findings == []
