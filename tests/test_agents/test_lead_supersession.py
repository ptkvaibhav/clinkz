"""One engagement is one target state, so a lead and a confirmation cannot both stand.

Engagement 908b7130 shipped a report in which ``/vulnerabilities/xss_d/`` was
simultaneously a CONFIRMED DOM-XSS finding and an UNPROVEN lead saying execution
was never witnessed — same endpoint, same parameter, same technique. Both
observations were honestly recorded; they came from two different applications,
because the driver that produced them switched DVWA's security level underneath
a single engagement id. In a client deliverable that reads as the report
contradicting itself.

The rule under test is directional, and it is the same one the rest of the
engine follows: a deterministic observation outranks the absence of one. A
confirmation WITNESSED the defining effect; a lead records only that no witness
was obtained. So a confirmation supersedes a lead for the same surface, and
there is no path by which a lead suppresses a finding.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import Finding, FindingStatus, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="supersession",
    targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
)

ENDPOINT = "http://localhost:8080/vulnerabilities/xss_d/?default=English"
PARAM = "(client-side fragment)"
TECHNIQUE = "WSTG-CLNT-01"


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-1")
    state.add_research_lead = AsyncMock()
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="supersession",
        resolver=ToolResolver(),
        persistent_kb=None,
    )


def _finding(
    *,
    endpoint: str = ENDPOINT,
    param: str = PARAM,
    technique: str = TECHNIQUE,
    status: FindingStatus = FindingStatus.CONFIRMED,
) -> Finding:
    return Finding(
        title="DOM-based XSS - script execution witnessed in a browser",
        description=f"Technique: {technique}. Parameter: {param}.",
        severity=Severity.HIGH,
        status=status,
        target=endpoint,
        evidence=["confirmation=P7"],
    )


def _record_lead(
    agent: ExploitAgent,
    *,
    endpoint: str = ENDPOINT,
    param: str = PARAM,
    technique: str = TECHNIQUE,
) -> None:
    agent._record_unproven_lead(
        claim="Candidate DOM-based XSS via URL fragment / location source",
        why="execution_not_witnessed_requires_client_side_oracle",
        technique=technique,
        endpoint=endpoint,
        parameter=param,
        raw_observation="source->sink",
        missing_observation="nothing executed it",
    )


class TestAConfirmationSupersedesItsLead:
    def test_the_lead_for_the_same_surface_is_dropped(self) -> None:
        agent = _agent()
        _record_lead(agent)
        agent._drop_superseded_leads([_finding()])
        assert agent._unproven_exploit_leads == []

    def test_a_trailing_hash_variant_of_the_same_endpoint_still_matches(self) -> None:
        """Endpoint identity is canonical, exactly as finding-level dedup is."""
        agent = _agent()
        _record_lead(agent, endpoint=ENDPOINT + "#")
        agent._drop_superseded_leads([_finding()])
        assert agent._unproven_exploit_leads == []

    @pytest.mark.asyncio
    async def test_the_superseded_lead_never_reaches_the_state_store(self) -> None:
        """The Report agent reads the table, so dropping it only from memory
        would still render it."""
        agent = _agent()
        _record_lead(agent)
        await agent._persist_research_leads([_finding()])
        agent.state.add_research_lead.assert_not_called()


class TestASupersessionIsNarrow:
    def test_a_lead_on_a_different_parameter_survives(self) -> None:
        """Nothing has been proven about that parameter; it is a different claim."""
        agent = _agent()
        _record_lead(agent, param="name")
        agent._drop_superseded_leads([_finding(param="default")])
        assert len(agent._unproven_exploit_leads) == 1

    def test_a_lead_on_a_different_endpoint_survives(self) -> None:
        agent = _agent()
        _record_lead(agent, endpoint="http://localhost:8080/vulnerabilities/xss_r/")
        agent._drop_superseded_leads([_finding()])
        assert len(agent._unproven_exploit_leads) == 1

    def test_a_lead_for_a_different_technique_survives(self) -> None:
        """Two classes can be true of one endpoint at once."""
        agent = _agent()
        _record_lead(agent, technique="WSTG-CLNT-04")
        agent._drop_superseded_leads([_finding(technique=TECHNIQUE)])
        assert len(agent._unproven_exploit_leads) == 1

    def test_a_lead_survives_when_its_finding_was_demoted(self) -> None:
        """A finding the engagement itself disbelieved supersedes nothing — which
        is why supersession reads the FINAL list, after false-positive demotion."""
        agent = _agent()
        _record_lead(agent)
        agent._drop_superseded_leads([_finding(status=FindingStatus.FALSE_POSITIVE)])
        assert len(agent._unproven_exploit_leads) == 1

    def test_with_no_findings_at_all_every_lead_survives(self) -> None:
        agent = _agent()
        _record_lead(agent)
        agent._drop_superseded_leads([])
        assert len(agent._unproven_exploit_leads) == 1


class TestSupersessionOnlyEverRemovesLeads:
    def test_a_lead_cannot_remove_a_finding(self) -> None:
        """The inverse must be impossible: the direction is the whole point."""
        agent = _agent()
        _record_lead(agent)
        findings = [_finding()]
        agent._drop_superseded_leads(findings)
        assert len(findings) == 1
        assert findings[0].status is FindingStatus.CONFIRMED
