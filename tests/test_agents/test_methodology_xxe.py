"""Unit tests for the adaptive XXE methodology phases.

Mirrors the SQLi/NoSQL/SSTI methodology tests: each phase is exercised in
isolation with a mocked XML-parser carrier (``_xxe_send_probe``) and a silent
LLM (so the deterministic, capability-grounded fallbacks drive), plus an
end-to-end run and an N/A check on a non-XML (HTML) stack — no false emission.

XXE is endpoint-scoped (the whole XML document is the payload), so there is no
parameter loop; the carrier simulators below model an XML parser that resolves
entities and — when *external* — discloses file content **in a 410 body** (the
Juice Shop in-band shape), the channel the verification must honour without
treating the 4xx as a reject signal.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

import clinkz.agents.exploit as exploit_mod
from clinkz.agents.exploit import (
    _XXE_DOS_FANOUT,
    _XXE_DOS_LEVELS,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import XXEExploitationType, XXEParserCapability
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-xxe-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

# A realistic /etc/passwd disclosure as it would appear inside the Juice Shop
# 410 body ("deprecated for security reasons: " + truncated parsed XML).
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_INTERNAL_ENTITY_RE = re.compile(r'<!ENTITY t "(clinkzxxe\d+)"')


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
        engagement_id="methodology-xxe-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _resp(status: int, body: str = "", headers: dict[str, str] | None = None) -> _HTTPResponse:
    return _HTTPResponse(status=status, body=body, headers=headers or {})


def _upload_page(url: str = "http://example.com/file-upload") -> PageAnalysis:
    """An upload-shaped XML sink (Juice Shop's /file-upload, field ``file``)."""
    form = {
        "action": "",
        "method": "POST",
        "fields": [{"name": "file", "type": "file", "value": ""}],
    }
    return PageAnalysis(url=url, body="", status=200, forms=[form])


def _body_page(url: str = "http://example.com/services/orders") -> PageAnalysis:
    """A raw application/xml body sink (no upload form / path)."""
    return PageAnalysis(url=url, body="", status=200, request_method="POST")


def _cap(
    *, external: bool = True, entity: bool = True, parameter: bool = False, inband: bool = True
) -> XXEParserCapability:
    return XXEParserCapability(
        entity_resolution=entity,
        external_entity=external,
        parameter_entity=parameter,
        inband_reflection=inband,
    )


def _vuln_parser(*, external: bool = True):
    """A ``_xxe_send_probe`` side-effect simulating a vulnerable XML parser.

    Resolves internal entities (the marker expands), and — when *external* — a
    SYSTEM entity reading ``/etc/passwd`` discloses the file content inside a
    **410** body (the Juice Shop in-band channel). A malformed document errors.
    """

    async def respond(page: PageAnalysis, xml: str) -> _HTTPResponse:
        if "file:///etc/passwd" in xml:
            if external:
                return _resp(410, f"deprecated for security reasons: <clinkz>{_PASSWD}</clinkz>")
            # External entities disabled: the payload is echoed, nothing disclosed.
            return _resp(410, f"deprecated for security reasons: {xml[:200]}")
        if "<unclosed>" in xml:
            return _resp(500, "XMLSyntaxError: Premature end of data")
        m = _INTERNAL_ENTITY_RE.search(xml)
        if m:  # internal entity expands to the marker
            return _resp(410, f"deprecated for security reasons: <clinkz>{m.group(1)}</clinkz>")
        return _resp(410, "deprecated for security reasons: <clinkz>ok</clinkz>")

    return respond


def _reflect_only():
    """A parser that resolves internal entities but ECHOES external-entity payloads.

    A 410 that reflects the payload literal (``file:///etc/passwd``, ``&xxe;``)
    but discloses no file content — ``external_entity`` must stay False and no
    finding may emit (the reflection-in-error guard, adapted to the 4xx channel).
    """

    async def respond(page: PageAnalysis, xml: str) -> _HTTPResponse:
        if "file:///etc/passwd" in xml:
            return _resp(410, f"deprecated for security reasons: {xml[:400]}")
        if "<unclosed>" in xml:
            return _resp(500, "XMLSyntaxError: Premature end of data")
        m = _INTERNAL_ENTITY_RE.search(xml)
        if m:
            return _resp(410, f"deprecated for security reasons: <clinkz>{m.group(1)}</clinkz>")
        return _resp(410, "deprecated for security reasons: <clinkz>ok</clinkz>")

    return respond


async def _no_xml(page: PageAnalysis, xml: str) -> _HTTPResponse:
    """A non-XML stack (DVWA-shaped): the body is ignored, same HTML every time."""
    return _resp(200, "<html><body>Not an XML endpoint</body></html>")


# ===========================================================================
# Phase 1 — injection-point mapping (does the endpoint parse XML?)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase1_entity_resolution_is_candidate() -> None:
    """An internal entity that expands to the marker → candidate."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_vuln_parser())  # type: ignore[method-assign]
    is_candidate, evidence = await agent._xxe_phase1_injection_point(_upload_page())
    assert is_candidate is True
    assert evidence["entity_resolved"] is True
    assert evidence["inband_reflection"] is True


@pytest.mark.asyncio
async def test_phase1_non_xml_stack_not_candidate() -> None:
    """A non-XML endpoint (no expansion, no parse error, no divergence) → N/A."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_no_xml)  # type: ignore[method-assign]
    is_candidate, evidence = await agent._xxe_phase1_injection_point(_body_page())
    assert is_candidate is False
    assert evidence["entity_resolved"] is False


# ===========================================================================
# Phase 2 — parser-capability fingerprinting
# ===========================================================================


@pytest.mark.asyncio
async def test_phase2_external_entity_confirmed() -> None:
    """A SYSTEM file read that discloses content → external_entity True."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_vuln_parser())  # type: ignore[method-assign]
    _, evidence = await agent._xxe_phase1_injection_point(_upload_page())
    capability, _ = await agent._xxe_phase2_fingerprint(_upload_page(), evidence)
    assert capability.entity_resolution is True
    assert capability.external_entity is True
    assert capability.inband_reflection is True


@pytest.mark.asyncio
async def test_phase2_reflection_only_external_entity_false() -> None:
    """A 410 echoing the payload but no file content → external_entity False."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_reflect_only())  # type: ignore[method-assign]
    _, evidence = await agent._xxe_phase1_injection_point(_upload_page())
    capability, _ = await agent._xxe_phase2_fingerprint(_upload_page(), evidence)
    assert capability.entity_resolution is True  # internal entities still resolve
    assert capability.external_entity is False  # nothing disclosed → not external


# ===========================================================================
# Phase 3 — exploitation-type ranking (+ hard N/A guard)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase3_na_guard_no_entity_resolution() -> None:
    """No entity resolution → no XXE → empty ranking (the non-XML stack)."""
    agent = _make_agent()
    ranked = await agent._xxe_phase3_rank_exploitation_types(_cap(external=False, entity=False), {})
    assert ranked == []


@pytest.mark.asyncio
async def test_phase3_ranks_file_disclosure_first_prunes_oob() -> None:
    """External entity + resolution → file disclosure leads; oob_exfil pruned."""
    agent = _make_agent()
    ranked = await agent._xxe_phase3_rank_exploitation_types(_cap(external=True), {})
    assert ranked[0] == XXEExploitationType.FILE_DISCLOSURE
    assert XXEExploitationType.OOB_EXFIL not in ranked
    assert XXEExploitationType.DOS in ranked


# ===========================================================================
# Phase 4 — capability-conditioned synthesis (incl. SSRF scope safety)
# ===========================================================================


def test_phase4_file_disclosure_grounded_payload() -> None:
    agent = _make_agent()
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.FILE_DISCLOSURE, _cap(external=True), _upload_page()
    )
    assert synth is not None
    assert "file:///etc/passwd" in synth["payload"]
    assert synth["indicator_type"] == "file_content"


def test_phase4_file_disclosure_declines_without_external_entity() -> None:
    agent = _make_agent()
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.FILE_DISCLOSURE, _cap(external=False), _upload_page()
    )
    assert synth is None


def test_phase4_ssrf_only_targets_in_scope_origin() -> None:
    """SSRF synthesis points at the page's in-scope origin; out-of-scope → None."""
    agent = _make_agent()
    in_scope = agent._fallback_synthesis_xxe(
        XXEExploitationType.SSRF, _cap(external=True), _body_page("http://example.com/svc")
    )
    assert in_scope is not None
    assert "example.com" in in_scope["payload"]

    out_of_scope = agent._fallback_synthesis_xxe(
        XXEExploitationType.SSRF, _cap(external=True), _body_page("http://evil.invalid/svc")
    )
    assert out_of_scope is None  # never exfil to an arbitrary external host


def test_payload_in_scope_guard_rejects_external_exfil_target() -> None:
    """Defence-in-depth: an external http SYSTEM target outside scope is rejected.

    The entity URL is fetched server-side, so the HTTP client's scope check on
    the request URL does not cover it — this guard does (e.g. for an LLM-
    suggested exfil host). file:// reads and in-scope http targets are allowed.
    """
    agent = _make_agent()
    assert agent._xxe_payload_in_scope(ExploitAgent._xxe_build_file_payload("file:///etc/passwd"))
    assert agent._xxe_payload_in_scope(ExploitAgent._xxe_build_file_payload("http://example.com/x"))
    assert not agent._xxe_payload_in_scope(
        ExploitAgent._xxe_build_file_payload("http://evil.invalid/collect")
    )
    # A file:// UNC target with a remote host is host control → also scope-checked.
    assert not agent._xxe_payload_in_scope(
        ExploitAgent._xxe_build_file_payload("file://evil.invalid/share")
    )


# ===========================================================================
# Phase 5 — verification (the 410 channel + reflection guard + bounded DoS)
# ===========================================================================


@pytest.mark.asyncio
async def test_phase5_file_disclosure_confirms_on_410_file_content() -> None:
    """File content in a 410 confirms — status is NOT a reject signal for XXE."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_vuln_parser())  # type: ignore[method-assign]
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.FILE_DISCLOSURE, _cap(external=True), _upload_page()
    )
    assert synth is not None
    verified, observed = await agent._xxe_phase5_verify(
        _upload_page(), XXEExploitationType.FILE_DISCLOSURE, synth
    )
    assert verified is True
    assert "410" in observed  # confirmed despite the 4xx channel


@pytest.mark.asyncio
async def test_phase5_file_disclosure_rejects_reflection() -> None:
    """A 410 echoing the payload but no file content → not verified."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_reflect_only())  # type: ignore[method-assign]
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.FILE_DISCLOSURE, _cap(external=True), _upload_page()
    )
    assert synth is not None
    verified, _ = await agent._xxe_phase5_verify(
        _upload_page(), XXEExploitationType.FILE_DISCLOSURE, synth
    )
    assert verified is False


def test_file_signature_guard_rejects_payload_reflection() -> None:
    """The signature guard: file content confirms, a reflected payload does not."""
    payload = ExploitAgent._xxe_build_file_payload("file:///etc/passwd")
    # The payload reflected back (no disclosure) must NOT confirm.
    confirmed, _ = ExploitAgent._xxe_file_signature_in(f"echoed: {payload}", payload)
    assert confirmed is False
    # Actual /etc/passwd content (never in the payload) confirms.
    confirmed, target = ExploitAgent._xxe_file_signature_in(
        f"deprecated for security reasons: {_PASSWD}", payload
    )
    assert confirmed is True
    assert target == "/etc/passwd"


def test_dos_payload_is_bounded() -> None:
    """The DoS probe is a tiny bounded expansion — never a real billion-laughs."""
    payload = ExploitAgent._xxe_build_dos_payload()
    assert "<!DOCTYPE" in payload
    assert f"&a{_XXE_DOS_LEVELS};" in payload
    # The expansion factor is small (4096), orders of magnitude below a DoS.
    assert _XXE_DOS_FANOUT**_XXE_DOS_LEVELS <= 10000
    assert len(payload) < 5000  # the payload string itself is small


@pytest.mark.asyncio
async def test_phase5_dos_confirms_on_timeout_signature() -> None:
    """A 503 timeout response confirms the bounded-expansion DoS."""
    agent = _make_agent()

    async def dos_sim(page: PageAnalysis, xml: str) -> _HTTPResponse:
        if "<!ENTITY a0" in xml:  # the bounded DoS payload
            return _resp(503, "Sorry, we are temporarily not available! Please try again later.")
        return _resp(410, "ok")

    agent._xxe_send_probe = AsyncMock(side_effect=dos_sim)  # type: ignore[method-assign]
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.DOS, _cap(external=False), _upload_page()
    )
    assert synth is not None
    verified, observed = await agent._xxe_phase5_verify(
        _upload_page(), XXEExploitationType.DOS, synth
    )
    assert verified is True
    assert "timeout" in observed


@pytest.mark.asyncio
async def test_phase5_dos_confirms_on_parse_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """A measurable parse-time delta confirms the bounded-expansion DoS."""
    monkeypatch.setattr(exploit_mod, "_XXE_DOS_DELAY_THRESHOLD", 0.02)
    agent = _make_agent()

    async def slow_dos(page: PageAnalysis, xml: str) -> _HTTPResponse:
        if "<!ENTITY a0" in xml:  # the bounded DoS payload parses slowly
            await asyncio.sleep(0.08)
        return _resp(410, "ok")

    agent._xxe_send_probe = AsyncMock(side_effect=slow_dos)  # type: ignore[method-assign]
    synth = agent._fallback_synthesis_xxe(
        XXEExploitationType.DOS, _cap(external=False), _upload_page()
    )
    assert synth is not None
    verified, observed = await agent._xxe_phase5_verify(
        _upload_page(), XXEExploitationType.DOS, synth
    )
    assert verified is True


# ===========================================================================
# Carrier dispatch — multipart upload vs raw application/xml body
# ===========================================================================


@pytest.mark.asyncio
async def test_carrier_upload_uses_multipart() -> None:
    agent = _make_agent()
    agent._http_post_multipart = AsyncMock(return_value=_resp(410, "ok"))  # type: ignore[method-assign]
    agent._http_post_xml = AsyncMock(return_value=_resp(200, "ok"))  # type: ignore[method-assign]
    await agent._xxe_send_probe(_upload_page(), "<clinkz/>")
    agent._http_post_multipart.assert_awaited_once()
    agent._http_post_xml.assert_not_awaited()


@pytest.mark.asyncio
async def test_carrier_body_uses_raw_xml() -> None:
    agent = _make_agent()
    agent._http_post_multipart = AsyncMock(return_value=_resp(410, "ok"))  # type: ignore[method-assign]
    agent._http_post_xml = AsyncMock(return_value=_resp(200, "ok"))  # type: ignore[method-assign]
    await agent._xxe_send_probe(_body_page(), "<clinkz/>")
    agent._http_post_xml.assert_awaited_once()
    agent._http_post_multipart.assert_not_awaited()


# ===========================================================================
# LLM-vocabulary path — phase-3 ranking driven by the actual LLM response
# ===========================================================================


@pytest.mark.asyncio
async def test_phase3_respects_llm_ranking_and_still_prunes_oob() -> None:
    """The live-LLM ranking vocabulary drives phase 3 (not only the fallback).

    LESSONS: a silent-LLM fixture only exercises the deterministic path; feed the
    real JSON shape so the parse + oob-prune chokepoint is proven on LLM output.
    """
    agent = _make_agent()
    agent._llm_analyze = AsyncMock(  # type: ignore[method-assign]
        return_value=(
            '{"ranked": [{"type": "dos", "rationale": "x"}, '
            '{"type": "oob_exfil", "rationale": "y"}, '
            '{"type": "file_disclosure", "rationale": "z"}]}'
        )
    )
    ranked = await agent._xxe_phase3_rank_exploitation_types(_cap(external=True), {})
    assert ranked[0] == XXEExploitationType.DOS  # LLM order respected
    assert XXEExploitationType.FILE_DISCLOSURE in ranked
    assert XXEExploitationType.OOB_EXFIL not in ranked  # pruned regardless of LLM


# ===========================================================================
# End-to-end — vulnerable target emits; reflection-only and non-XML do not
# ===========================================================================


@pytest.mark.asyncio
async def test_end_to_end_file_disclosure_emits() -> None:
    """A vulnerable XML upload sink → a verified XXE file-disclosure finding."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_vuln_parser())  # type: ignore[method-assign]
    findings = await agent._test_xxe(_upload_page())
    assert len(findings) == 1
    finding = findings[0]
    assert "xxe" in finding.title.lower()
    assert any("exploitation_type=file_disclosure" in ev for ev in finding.evidence)
    assert any("phases_completed=" in ev for ev in finding.evidence)


@pytest.mark.asyncio
async def test_end_to_end_carrier_label_recorded() -> None:
    """The synthetic carrier label distinguishes upload (file) from body."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_vuln_parser())  # type: ignore[method-assign]
    upload_result = await agent._run_xxe_methodology(_upload_page())
    assert upload_result.candidate_param == "file"
    body_result = await agent._run_xxe_methodology(_body_page())
    assert body_result.candidate_param == "xml_body"


@pytest.mark.asyncio
async def test_end_to_end_reflection_only_no_emission() -> None:
    """A 410 that echoes the payload but discloses nothing → no finding."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_reflect_only())  # type: ignore[method-assign]
    findings = await agent._test_xxe(_upload_page())
    assert findings == []


@pytest.mark.asyncio
async def test_end_to_end_non_xml_stack_na() -> None:
    """XXE is N/A on a non-XML (HTML) stack — no false emission, no crash."""
    agent = _make_agent()
    agent._xxe_send_probe = AsyncMock(side_effect=_no_xml)  # type: ignore[method-assign]
    findings = await agent._test_xxe(_body_page())
    assert findings == []
