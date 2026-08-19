"""P7 wiring: a lead becomes a finding ONLY on a witnessed execution.

The property under test is directional. P7 is a promotion path and nothing else:
it can raise a candidate whose execution was witnessed, and there is no route by
which it lowers, suppresses, or annotates anything. That matters because the
alternative — an oracle that can also demote — would hand every dropped finding
to whatever made the browser fail that day.

No browser is launched here. A stub oracle returns scripted verdicts, so these
run in the keyless gate and assert the DECISION, which is the part that has to
be right on a machine with no Chromium at all.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.browser.witness import ExecutionWitness, WitnessRefusal, WitnessVerdict
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="p7-promotion",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

DOM_BODY = (
    "<html><body><script>"
    "var q = location.hash.substring(1);"
    "document.getElementById('out').innerHTML = q;"
    "</script></body></html>"
)


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


class _StubOracle:
    """A P7 oracle that returns scripted verdicts without launching anything."""

    def __init__(self, verdict: WitnessVerdict | None, *, raises: bool = False) -> None:
        self._verdict = verdict
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return dict(args)

    async def execute(self, args: dict[str, Any]) -> str:
        self.calls.append(args)
        if self._raises:
            raise RuntimeError("browser crashed")
        return json.dumps({"verdict": (self._verdict or WitnessVerdict()).model_dump(mode="json")})

    def parse_output(self, raw: str) -> Any:
        verdict = WitnessVerdict.model_validate(json.loads(raw)["verdict"])
        return type("Out", (), {"verdict": verdict})()


def _witnessed() -> WitnessVerdict:
    v = WitnessVerdict(
        nonce="aaaaaaaaaaaaaaaa",
        control_nonce="bbbbbbbbbbbbbbbb",
        binding_name="__clinkz_w_1234abcd",
        injected_payload="<script>window.__clinkz_w_1234abcd('aaaaaaaaaaaaaaaa')</script>",
        template_id="inline_script",
        navigated_url="http://example.com/dom#payload",
        witnesses=[ExecutionWitness(value="aaaaaaaaaaaaaaaa", frame_url="http://example.com/dom")],
        policy_in_force="script-src 'self' 'unsafe-inline'",
        policy_source="header",
    )
    v.decide()
    return v


def _not_executed() -> WitnessVerdict:
    v = WitnessVerdict(
        nonce="aaaaaaaaaaaaaaaa",
        control_nonce="bbbbbbbbbbbbbbbb",
        policy_in_force="script-src 'none'",
        policy_source="header",
    )
    v.decide()
    return v


def _control_fired() -> WitnessVerdict:
    v = WitnessVerdict(
        nonce="aaaaaaaaaaaaaaaa",
        control_nonce="bbbbbbbbbbbbbbbb",
        witnesses=[
            ExecutionWitness(value="aaaaaaaaaaaaaaaa"),
            ExecutionWitness(value="bbbbbbbbbbbbbbbb"),
        ],
    )
    v.decide()
    return v


def _make_agent(oracle: Any = None) -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-1")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="p7-promotion",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    agent._client_execution_oracle = oracle

    async def _no_csp(_url: str) -> tuple[list[str], dict[str, str]]:
        return [], {}

    agent._p7_observed_csp_nonces = _no_csp  # type: ignore[method-assign]

    async def _no_gadget(_url: str) -> Any:
        return None

    agent._p7_find_script_gadget = _no_gadget  # type: ignore[method-assign]
    return agent


async def _run_dom(agent: ExploitAgent) -> list[Any]:
    async def fake_get(_url: str, _params: dict[str, str]) -> _HTTPResponse:
        return _HTTPResponse(status=200, body=DOM_BODY)

    agent._http_get = fake_get  # type: ignore[method-assign]
    page = PageAnalysis(url="http://example.com/dom", body=DOM_BODY, status=200, input_params=[])
    return await agent._test_xss_dom(page)


class TestNoOracleIsTheUnchangedFloor:
    @pytest.mark.asyncio
    async def test_without_an_oracle_the_candidate_stays_a_lead(self) -> None:
        agent = _make_agent(oracle=None)
        findings = await _run_dom(agent)
        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1
        lead = agent._unproven_exploit_leads[0]
        assert lead.why_unconfirmed == "execution_not_witnessed_requires_client_side_oracle"
        assert "no client-side execution oracle (P7) was available" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_a_directly_invoked_agent_does_not_resolve_an_oracle_for_itself(self) -> None:
        """The black-box floor must be byte-identical wherever Playwright happens
        to be installed — otherwise the suite reports a different result on a
        developer machine than on CI.

        This is the DIRECT-invocation path, which is what a unit suite, a replay
        and a smoke cell take. A real engagement gets its oracle wired on by the
        orchestrator preflight instead, so the default ``auto`` mode leaves this
        one browser-free while still giving ``clinkz scan`` a browser.
        """
        agent = _make_agent(oracle=None)
        assert agent._p7_oracle() is None


class TestOnlyAWitnessedExecutionPromotes:
    @pytest.mark.asyncio
    async def test_a_witnessed_execution_becomes_a_finding(self) -> None:
        agent = _make_agent(oracle=_StubOracle(_witnessed()))
        findings = await _run_dom(agent)
        assert len(findings) == 1
        assert agent._unproven_exploit_leads == []
        assert "witnessed" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_a_clean_non_execution_keeps_the_lead(self) -> None:
        agent = _make_agent(oracle=_StubOracle(_not_executed()))
        findings = await _run_dom(agent)
        assert findings == []
        lead = agent._unproven_exploit_leads[0]
        assert "rendered in a real browser" in lead.missing_observation
        assert "script-src 'none'" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_an_oracle_failure_keeps_the_lead_and_says_it_is_a_tooling_limit(
        self,
    ) -> None:
        """A browser that could not run is not evidence that the target is safe."""
        verdict = WitnessVerdict(refusal=WitnessRefusal.NAVIGATION_FAILED)
        agent = _make_agent(oracle=_StubOracle(verdict))
        findings = await _run_dom(agent)
        assert findings == []
        lead = agent._unproven_exploit_leads[0]
        assert "NOT evidence that the" in lead.missing_observation

    @pytest.mark.asyncio
    async def test_an_exception_from_the_oracle_keeps_the_lead(self) -> None:
        agent = _make_agent(oracle=_StubOracle(None, raises=True))
        findings = await _run_dom(agent)
        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1

    @pytest.mark.asyncio
    async def test_a_live_control_nonce_can_never_produce_a_finding(self) -> None:
        """Even though the injected nonce came back, the control came back too —
        so the channel is not trustworthy and the positive is inadmissible."""
        agent = _make_agent(oracle=_StubOracle(_control_fired()))
        findings = await _run_dom(agent)
        assert findings == []
        assert len(agent._unproven_exploit_leads) == 1


class TestThePromotedFindingIsRawAuditable:
    @pytest.mark.asyncio
    async def test_evidence_carries_the_nonce_out_and_back_plus_the_control(self) -> None:
        agent = _make_agent(oracle=_StubOracle(_witnessed()))
        finding = (await _run_dom(agent))[0]
        blob = "\n".join(finding.evidence)
        assert "confirmation=P7" in blob
        assert "witness_nonce='aaaaaaaaaaaaaaaa'" in blob
        assert "outbound_probe:" in blob
        assert "bbbbbbbbbbbbbbbb" in blob  # the never-injected control
        assert "control_bore_it=False" in blob

    @pytest.mark.asyncio
    async def test_evidence_records_the_policy_in_force_at_execution(self) -> None:
        agent = _make_agent(oracle=_StubOracle(_witnessed()))
        finding = (await _run_dom(agent))[0]
        blob = "\n".join(finding.evidence)
        assert "csp_in_force_at_execution=" in blob
        assert "bypass_csp_disabled=True" in blob

    @pytest.mark.asyncio
    async def test_the_request_line_is_the_probe_that_was_actually_sent(self) -> None:
        """Rendering the LLM's synthesized payload would print a request the
        engagement never issued."""
        agent = _make_agent(oracle=_StubOracle(_witnessed()))
        finding = (await _run_dom(agent))[0]
        blob = "\n".join(finding.evidence)
        assert "http://example.com/dom#payload" in blob

    @pytest.mark.asyncio
    async def test_target_console_text_is_labelled_as_advisory(self) -> None:
        verdict = _witnessed()
        verdict.console_violations = ["Refused to execute inline script"]
        agent = _make_agent(oracle=_StubOracle(verdict))
        finding = (await _run_dom(agent))[0]
        blob = "\n".join(finding.evidence)
        assert "advisory, not a verdict input" in blob


class TestP7NeverDemotes:
    @pytest.mark.asyncio
    async def test_a_non_executing_verdict_deletes_nothing_from_the_store(self) -> None:
        """P7 is a promotion path only. A run that witnesses nothing must leave
        the engagement's persisted findings entirely alone — otherwise a browser
        that failed on a given day starts deciding which findings survive."""
        agent = _make_agent(oracle=_StubOracle(_not_executed()))
        await _run_dom(agent)
        agent.state.delete_finding.assert_not_called()  # type: ignore[attr-defined]
        agent.state.add_finding.assert_not_called()  # type: ignore[attr-defined]

    def test_no_p7_helper_can_reach_a_suppression_primitive(self) -> None:
        """Structural, not behavioural: the P7 code path contains no call to the
        demotion machinery, so the property holds for inputs no test enumerates."""
        import inspect

        from clinkz.agents import exploit as exploit_mod

        for name, member in inspect.getmembers(exploit_mod.ExploitAgent, inspect.isfunction):
            if not name.startswith("_p7_"):
                continue
            source = inspect.getsource(member)
            for suppressor in ("delete_finding", "_demote", "remove(", "_fp_"):
                assert suppressor not in source, f"{name} can reach {suppressor}"
