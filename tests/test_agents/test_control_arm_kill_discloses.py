"""Every control-arm kill discloses, wherever the kill happens.

The 2026-08-20 DVWA ladder dispatched 31 never-sent control arms. Ten of them
fired, and **zero** of the ten produced any record a client could read: no
finding, no ``UnprovenExploitLead``, no *What was NOT tested* entry. Three DVWA
levels carrying genuine command injection reported silence, and silence in a
pentest report reads as a clean result.

The asymmetry was structural. ``_persist_finding``'s ground 8 catches the same
situation one layer later and writes a lead; a phase-5 kill returned ``continue``
and wrote nothing. One rule, two kill sites, one disclosure between them.

These tests hold the two sites to the same standard, and they hold the lead's
WORDING to it too — a lead saying the target is clean would be a worse artifact
than the silence it replaces, because "we could not prove it" and "it is not
there" are different claims and only the first one is true.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._control_arm import MARKER_ORACLE_CLASSES
from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="control-arm-disclosure-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

_EXPLOIT_SRC = Path(inspect.getfile(ExploitAgent))


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="control-arm-disclosure-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


async def _run_arm(agent: ExploitAgent, *, control_confirms: bool) -> Any:
    """Dispatch one arm whose control answers *control_confirms*."""

    async def oracle(_decoy: str) -> bool:
        return control_confirms

    return await agent._run_control_arm(
        skill="cmdi",
        test_method="_test_cmdi",
        technique="WSTG-INPV-12",
        endpoint="http://example.com/vulnerabilities/exec/",
        parameter="ip",
        confirming_payload="127.0.0.1;echo clinkzcmdi12345",
        confirming_observation="matched output indicator 'clinkzcmdi12345' (status=200)",
        control_label="the benign original value with a decoy appended and no separator",
        oracle_confirms=oracle,
    )


class TestEveryKillDiscloses:
    """A killed candidate that produces no disclosure record fails."""

    @pytest.mark.asyncio
    async def test_kill_records_a_lead(self) -> None:
        agent = _make_agent()
        verdict = await _run_arm(agent, control_confirms=True)

        assert verdict.satisfied is False
        assert agent._control_arm_kills == 1
        assert agent._control_arm_kill_disclosures == 1
        assert len(agent._unproven_exploit_leads) == 1

        lead = agent._unproven_exploit_leads[0]
        assert lead.why_unconfirmed == "never_sent_control_did_not_refuse"
        assert lead.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        assert lead.technique == "WSTG-INPV-12"
        assert lead.endpoint == "http://example.com/vulnerabilities/exec/"
        assert lead.parameter == "ip"

    @pytest.mark.asyncio
    async def test_kills_and_disclosures_stay_equal(self) -> None:
        """The invariant, stated as a count rather than as a convention."""
        agent = _make_agent()
        for _ in range(3):
            await _run_arm(agent, control_confirms=True)
        assert agent._control_arm_kills == 3
        assert agent._control_arm_kill_disclosures == agent._control_arm_kills

    @pytest.mark.asyncio
    async def test_a_refusing_control_discloses_nothing(self) -> None:
        """The arm doing its job is not an event. Only a KILL discloses."""
        agent = _make_agent()
        verdict = await _run_arm(agent, control_confirms=False)
        assert verdict.satisfied is True
        assert agent._control_arm_kills == 0
        assert agent._unproven_exploit_leads == []

    @pytest.mark.asyncio
    async def test_an_undispatchable_control_also_discloses(self) -> None:
        """A control that could not be SENT proves nothing, and says so."""
        agent = _make_agent()

        async def exploding_oracle(_decoy: str) -> bool:
            raise RuntimeError("connection reset")

        verdict = await agent._run_control_arm(
            skill="lfi",
            test_method="_test_lfi",
            technique="WSTG-INPV-11",
            endpoint="http://example.com/vulnerabilities/fi/",
            parameter="page",
            confirming_payload="../../etc/passwd",
            confirming_observation="matched /etc/passwd signature",
            control_label="a benign non-traversal filename",
            oracle_confirms=exploding_oracle,
        )
        assert verdict.dispatched is False
        assert verdict.satisfied is False
        assert agent._control_arm_kill_disclosures == 1


class TestTheLeadSaysWhatIsTrue:
    """ "Could not prove" and "is not there" are different claims."""

    @pytest.mark.asyncio
    async def test_lead_claims_unproven_never_clean(self) -> None:
        agent = _make_agent()
        await _run_arm(agent, control_confirms=True)
        lead = agent._unproven_exploit_leads[0]

        blob = f"{lead.claim} {lead.missing_observation}".lower()
        assert "could not prove" in blob or "could not prove" in lead.claim.lower()
        assert "not a statement that the endpoint is clean" in lead.claim.lower()
        # The honest middle position, stated explicitly: no evidence either way.
        assert "neither proven nor ruled out" in blob

        for forbidden in ("no vulnerability", "target is clean", "not vulnerable"):
            assert forbidden not in blob, f"a control kill must never imply {forbidden!r}"

    @pytest.mark.asyncio
    async def test_lead_carries_both_arms_verbatim(self) -> None:
        """An operator has to be able to re-derive the kill, not take it on trust."""
        agent = _make_agent()
        await _run_arm(agent, control_confirms=True)
        raw = agent._unproven_exploit_leads[0].raw_observation

        assert "127.0.0.1;echo clinkzcmdi12345" in raw
        assert "clinkzcmdi12345" in raw
        assert "confirmed_on_control" in raw
        assert "clinkzdecoycmdi" in raw


class TestDisclosureIsStructural:
    """The disclosure cannot be forgotten, because a caller does not do it."""

    def test_run_control_arm_is_the_only_verdict_producer(self) -> None:
        """Every arm goes through the one method that discloses.

        A second site constructing a ``ControlVerdict`` for a dispatched arm
        would be a second kill path with no disclosure — the exact shape this
        whole change removes. ``_control_arm.py`` also builds verdicts (reading
        them back out of stored evidence), which is not a dispatch and is not in
        this module.
        """
        tree = ast.parse(_EXPLOIT_SRC.read_text(encoding="utf-8"))
        producers = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ControlVerdict"
        ]
        assert len(producers) == 1, (
            "exploit.py must construct ControlVerdict in exactly one place "
            "(_run_control_arm), so every dispatched arm passes the disclosure seam"
        )

    def test_every_call_site_declares_technique_and_observation(self) -> None:
        """Both are needed for the lead to be actionable; neither has a default."""
        tree = ast.parse(_EXPLOIT_SRC.read_text(encoding="utf-8"))
        sites = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_run_control_arm"
        ]
        assert sites, "no _run_control_arm call sites found — the AST probe is broken"
        for site in sites:
            names = {kw.arg for kw in site.keywords}
            assert "technique" in names, f"call at line {site.lineno} omits technique="
            assert "confirming_observation" in names, (
                f"call at line {site.lineno} omits confirming_observation="
            )

    def test_every_marker_oracle_class_has_a_dispatch_site(self) -> None:
        """A marker-bound class with no arm can only ever be refused at emission.

        Refusal at emission does disclose (ground 8 writes a lead), so this is
        not a correctness hole — but a class that never dispatches an arm can
        never CONFIRM either, which is worth failing loudly rather than
        discovering as a permanently empty row in the ladder table.
        """
        tree = ast.parse(_EXPLOIT_SRC.read_text(encoding="utf-8"))
        dispatched: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_run_control_arm"
            ):
                for kw in node.keywords:
                    if kw.arg == "test_method" and isinstance(kw.value, ast.Constant):
                        dispatched.add(str(kw.value.value))
        missing = sorted(MARKER_ORACLE_CLASSES - dispatched)
        assert not missing, f"marker-oracle classes that never dispatch an arm: {missing}"
