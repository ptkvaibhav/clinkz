"""Cross-service SSRF confirmation + research-lead separation (design §3/§4/§5).

The honesty-critical half of slice B1. Drives ``_confirm_cross_service_reach``
against a REAL collaborator (loopback) and a fake ``_send_probe`` that models A's
egress, proving the co-location gate is deterministic and the research-lead is
structurally separate from a finding:

* **co-located callback → cross-service Finding** (§8b), raw-auditable (P6 pair).
* **generic collaborator NOT co-located with B → research-lead** (§8c, the rung-3
  phantom control): a callback landed, but it proves only "A egresses *somewhere*",
  so the system emits ``egress_confirmed_but_B_reach_not_observed`` and NO finding.
* **no callback → research-lead** ``blind_unconfirmed_within_window``.
* **no healthy collaborator → research-lead** ``B_not_instrumentable``.
* **structural separation** — a ``CrossServiceResearchLead`` is a different TYPE than
  ``Finding``, persisted to a different table, rendered in a different section, and
  never counted in coverage (type-level, not convention).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.config import settings
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import CrossServiceResearchLead, ExploitTask, Finding
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.oob.collaborator import OOBCollaborator
from clinkz.oob.templates import CallbackShape
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

_HTTP_PORT = 18161
_DNS_PORT = 15461

# Scope declares A, B (co-located with the collaborator on loopback), and a generic
# in-scope service that is NOT co-located with the collaborator (the phantom control).
SCOPE = EngagementScope(
    name="xsvc-test",
    targets=[
        ScopeEntry(value="host-a", type=ScopeType.DOMAIN),
        ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ScopeEntry(value="internal-b", type=ScopeType.DOMAIN),
    ],
)
PAGE_A = PageAnalysis(url="http://host-a/fetch", body="", status=200, input_params=["url"])

# B co-located with the collaborator (same loopback address:port the collaborator
# listens on) — arm (b). And a generic in-scope B NOT at the collaborator — arm (c).
B_COLOCATED = f"http://127.0.0.1:{_HTTP_PORT}/internal-admin"
B_GENERIC = "http://internal-b:80/admin"


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-001")
    state.add_research_lead = AsyncMock(return_value="l-001")
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="xsvc-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


@pytest.fixture(autouse=True)
def _short_oob_window() -> Any:
    original = settings.oob_wait_window
    settings.oob_wait_window = 1.5
    yield
    settings.oob_wait_window = original


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _make_collab() -> OOBCollaborator:
    collab = OOBCollaborator(
        zone=f"127.0.0.1:{_HTTP_PORT}",
        callback_shape=CallbackShape.PATH,
        bind_host="127.0.0.1",
        http_port=_HTTP_PORT,
        dns_port=_DNS_PORT,
        advertised_ip="127.0.0.1",
    )
    await collab.start()
    await collab.health_check()
    return collab


async def _deliver(value: str) -> None:
    """Model A fetching the callback URL → a real inbound hit on the collaborator."""
    parsed = urlparse(value)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    writer.write(
        f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.read(64), timeout=5.0)
    writer.close()


def _install_egress(agent: ExploitAgent, *, deliver: bool) -> None:
    """Fake ``_send_probe`` modelling A's egress to the collaborator (at 127.0.0.1).

    The probe value is the CLINKZ-owned callback URL pointing at the collaborator; A
    'fetches' it (deliver=True) or the egress is dropped (deliver=False). This is
    independent of B — in arm (c) the callback still lands, it just is not co-located
    with B.
    """

    async def fake_send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        if urlparse(value).hostname == "127.0.0.1" and deliver:
            await _deliver(value)
        return _HTTPResponse(status=200, body="ok")

    agent._send_probe = fake_send_probe  # type: ignore[method-assign]


def _xsvc_task(b_target: str, source: str = "recon") -> ExploitTask:
    return ExploitTask(
        test_method="_test_ssrf",
        endpoint_url="http://host-a/fetch",
        endpoint_params=["url"],
        tier=1,
        cross_service_target=b_target,
        cross_service_source=source,
    )


# ---------------------------------------------------------------------------
# Arm (b) — co-located collaborator → cross-service Finding, raw-auditable
# ---------------------------------------------------------------------------


def test_colocated_callback_emits_cross_service_finding() -> None:
    async def scenario() -> list[Finding]:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _install_egress(agent, deliver=True)
        try:
            return await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_COLOCATED))
        finally:
            await collab.stop()

    findings = _run(scenario())
    assert len(findings) == 1
    f = findings[0]
    assert "Cross-Service" in f.title
    assert f.severity.value == "high"
    blob = " ".join(f.evidence)
    # Raw-auditable P6 pair: outbound probe carrying the nonce + inbound callback.
    assert "outbound_probe:" in blob
    assert "callback_nonce=" in blob
    assert "inbound callback:" in blob
    # The cross-service dimension is spelled out: A→B + co-located confirmation.
    assert f"B({B_COLOCATED})" in blob
    assert "confirmation=P6" in blob
    assert "REACHES B" in blob


def test_colocated_finding_records_no_research_lead() -> None:
    async def scenario() -> ExploitAgent:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _install_egress(agent, deliver=True)
        try:
            await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_COLOCATED))
        finally:
            await collab.stop()
        return agent

    agent = _run(scenario())
    assert agent._cross_service_research_leads == []  # a confirmed reach is a finding


# ---------------------------------------------------------------------------
# Arm (c) — THE PHANTOM CONTROL: generic collaborator NOT co-located with B
# ---------------------------------------------------------------------------


def test_generic_collaborator_callback_is_a_research_lead_not_a_finding() -> None:
    async def scenario() -> tuple[list[Finding], ExploitAgent]:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _install_egress(agent, deliver=True)  # a callback DOES land (A egresses)
        try:
            findings = await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_GENERIC))
        finally:
            await collab.stop()
        return findings, agent

    findings, agent = _run(scenario())
    # The whole honesty test: a callback landed, but it is NOT co-located with B, so
    # it proves only "A egresses somewhere" — NO cross-service finding.
    assert findings == []
    assert len(agent._cross_service_research_leads) == 1
    lead = agent._cross_service_research_leads[0]
    assert lead.why_unconfirmed == "egress_confirmed_but_B_reach_not_observed"
    assert lead.b_target == B_GENERIC
    assert lead.raw_probe  # the exact probe sent is preserved
    assert "NOT" in lead.raw_null_observation


# ---------------------------------------------------------------------------
# No callback → research-lead blind_unconfirmed_within_window
# ---------------------------------------------------------------------------


def test_no_callback_is_a_blind_unconfirmed_research_lead() -> None:
    async def scenario() -> tuple[list[Finding], ExploitAgent]:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _install_egress(agent, deliver=False)  # probe sent, never arrives
        try:
            findings = await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_COLOCATED))
        finally:
            await collab.stop()
        return findings, agent

    findings, agent = _run(scenario())
    assert findings == []
    assert len(agent._cross_service_research_leads) == 1
    assert (
        agent._cross_service_research_leads[0].why_unconfirmed == "blind_unconfirmed_within_window"
    )


# ---------------------------------------------------------------------------
# No healthy collaborator → research-lead B_not_instrumentable
# ---------------------------------------------------------------------------


def test_no_collaborator_is_b_not_instrumentable_research_lead() -> None:
    async def scenario() -> tuple[list[Finding], ExploitAgent]:
        agent = _make_agent()
        agent._collaborator = None  # cannot co-locate a marker/callback at B
        findings = await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_COLOCATED))
        return findings, agent

    findings, agent = _run(scenario())
    assert findings == []
    assert len(agent._cross_service_research_leads) == 1
    assert agent._cross_service_research_leads[0].why_unconfirmed == "B_not_instrumentable"


# ---------------------------------------------------------------------------
# Structural separation — a research-lead can NEVER be a confirmed finding (§5)
# ---------------------------------------------------------------------------


def test_research_lead_is_not_a_finding_type() -> None:
    lead = CrossServiceResearchLead(candidate_chain="x", why_unconfirmed="topology_prior_only")
    # Type-level: a lead is NOT a Finding, so it cannot be placed in a findings list,
    # persisted via add_finding, or rendered in the confirmed-findings section.
    assert not isinstance(lead, Finding)


def test_execute_task_routes_cross_service_to_the_driver_not_test_ssrf() -> None:
    """A task carrying ``cross_service_target`` is routed to the cross-service driver.

    Routing is load-bearing: without it the cross-service hypothesis would fall to the
    single-service ``_test_ssrf`` param loop and lose the co-location gate + the
    research-lead separation.
    """

    async def scenario() -> tuple[bool, bool]:
        agent = _make_agent()
        called = {"driver": False, "ssrf": False}

        async def fake_fetch_page(*args: Any, **kwargs: Any) -> PageAnalysis:
            return PAGE_A

        async def fake_driver(page: PageAnalysis, task: ExploitTask) -> list[Finding]:
            called["driver"] = True
            return []

        async def fake_ssrf(*args: Any, **kwargs: Any) -> list[Finding]:
            called["ssrf"] = True
            return []

        agent._fetch_page = fake_fetch_page  # type: ignore[method-assign]
        agent._confirm_cross_service_reach = fake_driver  # type: ignore[method-assign]
        agent._test_ssrf = fake_ssrf  # type: ignore[method-assign]
        await agent._execute_task(_xsvc_task(B_COLOCATED), {})
        return called["driver"], called["ssrf"]

    driver_called, ssrf_called = _run(scenario())
    assert driver_called is True
    assert ssrf_called is False  # the single-service path is NOT taken


def test_research_lead_persisted_to_its_own_table_never_findings() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _install_egress(agent, deliver=True)
        try:
            await agent._confirm_cross_service_reach(PAGE_A, _xsvc_task(B_GENERIC))
        finally:
            await collab.stop()
        await agent._persist_research_leads([])
        # A lead is written ONLY via add_research_lead — never add_finding.
        agent.state.add_research_lead.assert_awaited()
        agent.state.add_finding.assert_not_called()

    _run(scenario())
