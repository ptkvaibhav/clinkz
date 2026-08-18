"""SSRF out-of-band (P6) confirmation — the blind-branch un-pruning.

Drives the real SSRF methodology against a REAL collaborator (bound on loopback)
and a fake ``_send_probe`` that models the target's egress. Proves the four P6
contracts from the design:

* **Confirm on a callback** bearing the probe's nonce → ``BLIND_OOB_CONFIRMED``,
  raw-auditable (the outbound probe carrying the nonce AND the inbound callback
  bearing it are both in the finding evidence).
* **Zero-FP** — a probe whose egress is blocked (never reaches the collaborator)
  yields no callback → ``blind_unconfirmed``, and **no finding**.
* **blind_unconfirmed ≠ not_vulnerable** — silence under a healthy collaborator is
  an inconclusive research-lead, never a clean verdict.
* **collaborator_unavailable ≠ blind_unconfirmed** — with no healthy collaborator
  the blind set is surfaced as "collaborator unavailable", so a dead collaborator
  never makes a target look clean (§P6.7.1).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest

from clinkz.agents.exploit import (
    _SSRF_UNFETCHABLE_HOST,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.config import settings
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.oob.collaborator import OOBCollaborator
from clinkz.oob.templates import CallbackShape
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

_HTTP_PORT = 18151
_DNS_PORT = 15451

SCOPE = EngagementScope(
    name="ssrf-oob-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)
PAGE = PageAnalysis(url="http://example.com/fetch", body="", status=200, input_params=["url"])


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
        engagement_id="ssrf-oob-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


@pytest.fixture(autouse=True)
def _short_oob_window() -> Any:
    """Shrink the shared reap window so the no-callback tests don't wait 20s."""
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
    """Simulate the target fetching *value* (an OOB callback URL) → real inbound hit."""
    parsed = urlparse(value)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    writer.write(
        f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.read(64), timeout=5.0)
    writer.close()


def _blind_fetcher_send_probe(agent: ExploitAgent, *, deliver: bool) -> None:
    """Install a ``_send_probe`` that models a blind fetcher.

    Phase 1 sees a fetch signal (status flip origin-vs-junk, no reflected marker) →
    ``fetch_confirmed`` without ``content_reflected`` (blind). The OOB callback URL
    is either delivered to the real collaborator (``deliver=True``) or dropped
    (``deliver=False`` — egress filtered).
    """

    async def fake_send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
        host = urlparse(value).hostname or ""
        if host == "127.0.0.1":  # an OOB callback URL pointed at the collaborator
            if deliver:
                await _deliver(value)
            return _HTTPResponse(status=200, body="fetched")
        if _SSRF_UNFETCHABLE_HOST in value:  # the phase-1 junk control
            return _HTTPResponse(status=502, body="err")
        return _HTTPResponse(status=200, body="ok body no marker")

    agent._send_probe = fake_send_probe  # type: ignore[method-assign]
    # No ref-marker source → content_reflected stays False (blind).
    agent._http_get = AsyncMock(return_value=_HTTPResponse(status=0, body=""))  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Confirm on a callback → BLIND_OOB_CONFIRMED, raw-auditable
# ---------------------------------------------------------------------------


def test_blind_ssrf_confirmed_out_of_band() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _blind_fetcher_send_probe(agent, deliver=True)
        try:
            findings = await agent._test_ssrf(PAGE)
        finally:
            await collab.stop()

        assert len(findings) == 1
        f = findings[0]
        assert "blind_oob_confirmed" in f.title
        assert f.severity.value == "high"
        blob = " ".join(f.evidence)
        # Raw-auditable P6 pair: BOTH the outbound probe carrying the nonce AND the
        # inbound callback bearing it are present in the finding.
        assert "outbound_probe:" in blob
        assert "callback_nonce=" in blob
        assert "inbound callback:" in blob
        assert "control_bore_it=False" in blob

    _run(scenario())


def test_oob_evidence_pair_is_the_same_nonce_out_and_back() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _blind_fetcher_send_probe(agent, deliver=True)
        try:
            confirmed, evidence, note = await agent._ssrf_oob_confirm(PAGE, "url")
        finally:
            await collab.stop()
        assert confirmed is True
        assert evidence is not None
        assert evidence.primitive == "P6"
        # The nonce that left in the outbound probe is the one that came back.
        assert evidence.confirming_marker in evidence.outbound_probe
        assert evidence.confirming_marker in evidence.confirming_excerpt
        assert evidence.control_confirms is False

    _run(scenario())


# ---------------------------------------------------------------------------
# Zero-FP: egress filtered → no callback → blind_unconfirmed → NO finding
# ---------------------------------------------------------------------------


def test_egress_filtered_yields_blind_unconfirmed_not_a_finding() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _blind_fetcher_send_probe(agent, deliver=False)  # probe sent, never arrives
        try:
            findings = await agent._test_ssrf(PAGE)
        finally:
            await collab.stop()
        # No callback → no finding (zero-FP), and the outcome is the honest
        # inconclusive one — never a phantom.
        assert findings == []

    _run(scenario())


def test_single_shot_blind_unconfirmed_note_is_inconclusive_not_safe() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        _blind_fetcher_send_probe(agent, deliver=False)
        try:
            confirmed, evidence, note = await agent._ssrf_oob_confirm(PAGE, "url")
        finally:
            await collab.stop()
        assert confirmed is False
        assert evidence is None
        assert "blind_unconfirmed" in note
        assert "egress may be filtered" in note

    _run(scenario())


# ---------------------------------------------------------------------------
# collaborator_unavailable ≠ blind_unconfirmed (§P6.7.1)
# ---------------------------------------------------------------------------


def test_no_collaborator_marks_unavailable_never_unconfirmed() -> None:
    """With no collaborator wired, a blind SSRF is 'collaborator unavailable'."""

    async def scenario() -> None:
        agent = _make_agent()
        agent._collaborator = None  # default black-box floor
        _blind_fetcher_send_probe(agent, deliver=False)
        result_holder: list[Any] = []
        # Drive the blind branch directly to inspect the result flags.
        r = await agent._run_ssrf_methodology(PAGE, "url")
        result_holder.append(r)
        assert r.blind_suspected is True
        await agent._ssrf_oob_confirm_batch(PAGE, [("url", r)])
        assert r.collaborator_unavailable is True
        assert r.blind_unconfirmed is False  # a dead/absent collaborator ≠ clean
        assert "collaborator unavailable" in r.oob_note

    _run(scenario())


def test_unhealthy_collaborator_marks_unavailable() -> None:
    async def scenario() -> None:
        # A collaborator that was never started/health-checked is not healthy.
        collab = OOBCollaborator(
            zone=f"127.0.0.1:{_HTTP_PORT}",
            callback_shape=CallbackShape.PATH,
            http_port=_HTTP_PORT,
            dns_port=_DNS_PORT,
        )
        agent = _make_agent()
        agent._collaborator = collab
        r = await agent._run_ssrf_methodology(PAGE, "url")
        # Force the blind path without a live fetcher: mark blind_suspected.
        r.blind_suspected = True
        await agent._ssrf_oob_confirm_batch(PAGE, [("url", r)])
        assert r.collaborator_unavailable is True
        assert r.blind_unconfirmed is False

    _run(scenario())


# ---------------------------------------------------------------------------
# The carrier is used — the outbound payload is nonce+zone only (guardrail)
# ---------------------------------------------------------------------------


def test_oob_send_builds_callback_from_carrier_only() -> None:
    async def scenario() -> None:
        collab = await _make_collab()
        agent = _make_agent()
        agent._collaborator = collab
        captured: list[str] = []

        async def capture(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            captured.append(value)
            return _HTTPResponse(status=200, body="")

        agent._send_probe = capture  # type: ignore[method-assign]
        try:
            outcome = await agent._oob_send(PAGE, "url", "hyp-x")
        finally:
            await collab.stop()
        assert outcome is not None
        nonce, payload, outbound = outcome
        # The payload is exactly the carrier's output: http://<zone>/<nonce>.
        assert payload == f"http://127.0.0.1:{_HTTP_PORT}/{nonce}"
        assert captured == [payload]
        # No target/param string leaked into the callback host.
        assert urlparse(payload).hostname == "127.0.0.1"

    _run(scenario())
