"""Log4Shell (CVE-2021-44228) — the out-of-band (P6) methodology.

Drives the real ``_test_log4shell`` methodology against a REAL collaborator (bound
on loopback) and a fake ``_send_probe`` that models the target's log4j interpolating
the injected ``${jndi:dns://…}`` and resolving the nonce at the collaborator's DNS
leg. Proves the P6 contracts, reusing the SAME machinery the blind-SSRF path uses:

* **Confirm on a callback** bearing the probe's nonce → a **critical** finding,
  raw-auditable (the outbound ``${jndi:dns://…T…}`` probe AND the inbound callback
  bearing ``T`` are both in the finding evidence), with the never-sent control.
* **Zero-FP** — a probe whose egress is dropped (never reaches the collaborator)
  yields no callback → no finding.
* **collaborator_unavailable** — with no healthy collaborator, Log4Shell (out-of-band
  only) emits NOTHING (never a phantom; the black-box floor).
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.config import settings
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.oob.collaborator import OOBCollaborator, _build_dns_query
from clinkz.oob.templates import CallbackShape
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

_HTTP_PORT = 18161
_DNS_PORT = 15461

SCOPE = EngagementScope(
    name="log4shell-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)
PAGE = PageAnalysis(
    url="http://example.com/solr/admin/cores",
    body="",
    status=200,
    input_params=["action"],
    request_method="GET",
)

_JNDI_DNS_RE = re.compile(r"\$\{jndi:dns://([^/]+)/([a-z0-9]{16,64})\}")


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: Any = None) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-001")
    state.log_action = AsyncMock()
    return state


def _make_agent() -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="log4shell-test",
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


async def _deliver_dns(host: str, port: int, nonce: str) -> None:
    """Simulate log4j's JNDI DNS lookup of *nonce* at the collaborator's DNS leg."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, _build_dns_query(nonce))
        await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=2.0)
    finally:
        sock.close()


def _log_sink_send_probe(agent: ExploitAgent, *, deliver: bool) -> None:
    """Install a ``_send_probe`` modelling a vulnerable log4j log sink.

    A ``${jndi:dns://<authority>/<nonce>}`` value is "logged and interpolated": the
    JNDI DNS lookup resolves ``<nonce>`` at the collaborator's DNS leg
    (``deliver=True``) or is dropped (``deliver=False`` — egress filtered). The HTTP
    response itself is inert (Log4Shell has no in-band signal).
    """

    async def fake_send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        m = _JNDI_DNS_RE.search(value)
        if m and deliver:
            authority, nonce = m.group(1), m.group(2)
            host, _, port = authority.partition(":")
            await _deliver_dns(host, int(port), nonce)
        return _HTTPResponse(status=400, body="Unknown action")

    agent._send_probe = fake_send_probe  # type: ignore[method-assign]


def test_log4shell_confirmed_out_of_band() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _log_sink_send_probe(agent, deliver=True)
        try:
            findings = await agent._test_log4shell(PAGE)
        finally:
            await collab.stop()

        assert len(findings) == 1
        f = findings[0]
        assert "log4shell" in f.title.lower()
        assert f.severity.value == "critical"
        blob = " ".join(f.evidence)
        # Raw-auditable P6 pair: the outbound jndi:dns probe carrying the nonce AND
        # the inbound callback bearing it, plus the never-sent control.
        assert "outbound_probe:" in blob
        assert "jndi:dns://" in blob
        assert "callback_nonce=" in blob
        assert "inbound callback:" in blob
        assert "control_bore_it=False" in blob

    _run(scenario())


def test_same_nonce_leaves_and_returns() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _log_sink_send_probe(agent, deliver=True)
        try:
            findings = await agent._test_log4shell(PAGE)
        finally:
            await collab.stop()
        blob = " ".join(findings[0].evidence)
        out = re.search(r"jndi:dns://[^/]+/([a-z0-9]{16,64})", blob)
        back = re.search(r"confirming_excerpt: inbound callback:.*host=([a-z0-9]{16,64})", blob)
        assert out and back and out.group(1) == back.group(1)

    _run(scenario())


def test_egress_dropped_yields_no_finding() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _log_sink_send_probe(agent, deliver=False)  # probe sent, never calls back
        try:
            findings = await agent._test_log4shell(PAGE)
        finally:
            await collab.stop()
        assert findings == []  # blind_unconfirmed → no finding (zero-FP)

    _run(scenario())


def test_no_collaborator_emits_nothing() -> None:
    async def scenario() -> None:
        agent = _make_agent()
        agent._collaborator = None  # P6 disabled — the black-box floor
        _log_sink_send_probe(agent, deliver=True)
        findings = await agent._test_log4shell(PAGE)
        assert findings == []  # out-of-band only — nothing to confirm, nothing emitted

    _run(scenario())


def test_unhealthy_collaborator_emits_nothing() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        collab._healthy = False  # a dead collaborator must never make a target confirm
        agent = _make_agent()
        agent._collaborator = collab
        _log_sink_send_probe(agent, deliver=True)
        try:
            findings = await agent._test_log4shell(PAGE)
        finally:
            await collab.stop()
        assert findings == []

    _run(scenario())


def test_no_params_is_na_by_construction() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _log_sink_send_probe(agent, deliver=True)
        page = PageAnalysis(url="http://example.com/static", body="", status=200, input_params=[])
        try:
            findings = await agent._test_log4shell(page)
        finally:
            await collab.stop()
        assert findings == []

    _run(scenario())
