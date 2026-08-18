"""Cross-service ``reaches`` write-back — YES-only + the abstraction fence (§6, B2).

The exploit-layer half of the learning slice, against a REAL persistent KB:

* **YES-only** (mirrors the capability loop): a CONFIRMED cross-service reach writes
  the abstracted ``reaches`` edge; a research-lead / unconfirmed / refused reach writes
  NO durable edge — proven through the real ``_confirm_cross_service_reach`` driver +
  a live loopback collaborator (the co-located arm writes; the phantom-control arm does
  not).
* **The abstraction fence at the write boundary** (§6.4 — validation #1, exploit-level):
  an un-abstractable B (empty / host-shaped identity) yields NO KB edge while the
  confirmed finding still stands (engagement-local).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.config import settings
from clinkz.discovery.relations import RELATION_REACHES
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import DiscoveryProvenance, ExploitTask, Finding, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.oob.collaborator import OOBCollaborator
from clinkz.oob.templates import CallbackShape
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

_HTTP_PORT = 18173
_DNS_PORT = 15473

SCOPE = EngagementScope(
    name="xsvc-learn",
    targets=[
        ScopeEntry(value="host-a", type=ScopeType.DOMAIN),
        ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ScopeEntry(value="internal-b", type=ScopeType.DOMAIN),
    ],
)
PAGE_A = PageAnalysis(url="http://host-a/fetch", body="", status=200, input_params=["url"])
B_COLOCATED = f"http://127.0.0.1:{_HTTP_PORT}/internal-admin"
B_GENERIC = "http://internal-b:80/admin"


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _short_oob_window() -> Any:
    original = settings.oob_wait_window
    settings.oob_wait_window = 1.5
    yield
    settings.oob_wait_window = original


def _make_agent(kb: PersistentKnowledgeBase) -> ExploitAgent:
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
        engagement_id="xsvc-learn",
        resolver=ToolResolver(),
        persistent_kb=kb,
    )
    agent._methodology_llm = agent.llm
    return agent


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
    parsed = urlparse(value)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    writer.write(
        f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.read(64), timeout=5.0)
    writer.close()


def _install_egress(agent: ExploitAgent, *, deliver: bool) -> None:
    async def fake_send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        if urlparse(value).hostname == "127.0.0.1" and deliver:
            await _deliver(value)
        return _HTTPResponse(status=200, body="ok")

    agent._send_probe = fake_send_probe  # type: ignore[method-assign]


def _xsvc_task(b_target: str, *, a_id: str, b_id: str, source: str = "recon") -> ExploitTask:
    return ExploitTask(
        test_method="_test_ssrf",
        endpoint_url="http://host-a/fetch",
        endpoint_params=["url"],
        tier=1,
        cross_service_target=b_target,
        cross_service_source=source,
        cross_service_a_identity=a_id,
        cross_service_b_identity=b_id,
    )


def _reaches_rows(kb_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in kb_rows if r["relation_type"] == RELATION_REACHES]


# ===========================================================================
# The abstraction fence at the write boundary (exploit-level validation #1)
# ===========================================================================


def test_confirmed_reach_with_abstractable_ends_writes_the_edge() -> None:
    async def scenario() -> list[dict[str, Any]]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            agent = _make_agent(kb)
            finding = Finding(
                title="Cross-Service SSRF",
                description="",
                severity=Severity.HIGH,
                target="http://a/",
            )
            task = _xsvc_task(
                B_COLOCATED, a_id="OWASP Juice Shop", b_id="internal-metadata-service"
            )
            await agent._write_reaches_edge(task, finding)
            return _reaches_rows(await kb.get_technology_relations())
        finally:
            await kb.close()

    rows = _run(scenario())
    assert len(rows) == 1
    assert rows[0]["tech_a"] == "owasp-juice-shop"  # abstracted, never A's URL
    assert rows[0]["tech_b"] == "internal-metadata-service"  # abstracted, never B's URL


@pytest.mark.parametrize("b_identity", ["", "10.0.0.5:6379", "internal-db.corp.local", "node-js"])
def test_unabstractable_b_writes_no_edge_but_keeps_the_finding(b_identity: str) -> None:
    """VALIDATION #1 (exploit-level): a bespoke/host/bare B → engagement-local, no KB row.

    The confirmed finding is unaffected — only the cross-engagement transfer is withheld.
    """

    async def scenario() -> int:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            agent = _make_agent(kb)
            finding = Finding(
                title="Cross-Service SSRF",
                description="",
                severity=Severity.HIGH,
                target="http://a/",
            )
            task = _xsvc_task(B_COLOCATED, a_id="apache-solr", b_id=b_identity)
            await agent._write_reaches_edge(task, finding)
            return len(_reaches_rows(await kb.get_technology_relations()))
        finally:
            await kb.close()

    assert _run(scenario()) == 0  # nothing deployment-specific / over-broad persisted


def test_a_identity_falls_back_to_provenance_but_still_fenced() -> None:
    async def scenario() -> tuple[int, int]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            agent = _make_agent(kb)
            # A specific provenance key transfers; a bare-language one does not.
            good = Finding(
                title="x",
                description="",
                severity=Severity.HIGH,
                target="http://a/",
                discovery_provenance=DiscoveryProvenance(technology_key="geoserver"),
            )
            await agent._write_reaches_edge(
                _xsvc_task(B_COLOCATED, a_id="", b_id="internal-metadata-service"), good
            )
            after_good = len(_reaches_rows(await kb.get_technology_relations()))

            bare = Finding(
                title="x",
                description="",
                severity=Severity.HIGH,
                target="http://a/",
                discovery_provenance=DiscoveryProvenance(technology_key="node-js"),
            )
            await agent._write_reaches_edge(
                _xsvc_task(B_GENERIC, a_id="", b_id="internal-metadata-service"), bare
            )
            after_bare = len(_reaches_rows(await kb.get_technology_relations()))
            return after_good, after_bare
        finally:
            await kb.close()

    good, bare = _run(scenario())
    assert good == 1  # provenance fallback keys the edge on the specific tech
    assert bare == 1  # ...and a bare-language provenance adds nothing (still 1)


# ===========================================================================
# YES-only through the REAL driver (a lead/unconfirmed reach writes no edge)
# ===========================================================================


def test_colocated_confirmed_reach_writes_a_reaches_edge() -> None:
    async def scenario() -> tuple[int, list[dict[str, Any]]]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        collab = await _make_collab()
        agent = _make_agent(kb)
        agent._collaborator = collab
        _install_egress(agent, deliver=True)
        try:
            task = _xsvc_task(B_COLOCATED, a_id="apache-solr", b_id="internal-metadata-service")
            findings = await agent._confirm_cross_service_reach(PAGE_A, task)
        finally:
            await collab.stop()
        rows = _reaches_rows(await kb.get_technology_relations())
        await kb.close()
        return len(findings), rows

    n_findings, rows = _run(scenario())
    assert n_findings == 1  # co-located confirm → a finding
    assert len(rows) == 1  # ...and the YES-only write-back persisted the reaches edge
    assert rows[0]["tech_a"] == "apache-solr"
    assert rows[0]["tech_b"] == "internal-metadata-service"


def test_research_lead_arm_writes_no_reaches_edge() -> None:
    async def scenario() -> tuple[int, int, int]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        collab = await _make_collab()
        agent = _make_agent(kb)
        agent._collaborator = collab
        _install_egress(agent, deliver=True)  # a callback lands, but B is NOT co-located
        try:
            task = _xsvc_task(B_GENERIC, a_id="apache-solr", b_id="internal-metadata-service")
            findings = await agent._confirm_cross_service_reach(PAGE_A, task)
        finally:
            await collab.stop()
        rows = _reaches_rows(await kb.get_technology_relations())
        leads = len(agent._cross_service_research_leads)
        await kb.close()
        return len(findings), leads, len(rows)

    n_findings, n_leads, n_edges = _run(scenario())
    assert n_findings == 0  # the phantom-control arm emits no finding
    assert n_leads == 1  # it is a research-lead
    assert n_edges == 0  # ...and writes NO durable reaches edge (YES-only)
