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
from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
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

    async def generate_text(self, prompt: str) -> str:
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
        ranked = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(traversal_sequence="../", wrapper_support=["php://filter"]),
            {},
        )
        assert ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION
        assert ranked[1] == LFIRetrievalType.DIRECT_READ

    @pytest.mark.asyncio
    async def test_fallback_signature_match_prefers_direct_read(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(traversal_sequence="../"),
            {"traversal_signature_match": "../"},
        )
        assert ranked[0] == LFIRetrievalType.DIRECT_READ

    @pytest.mark.asyncio
    async def test_fallback_php_filter_prefers_wrapper(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._lfi_phase3_rank_retrieval_types(
            LFITraversalPrimitives(wrapper_support=["php://filter"]),
            {},
        )
        assert ranked[0] == LFIRetrievalType.WRAPPER_EXTRACTION


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
        synth = await agent._lfi_phase4_synthesize_payload(
            LFIRetrievalType.DIRECT_READ,
            LFITraversalPrimitives(traversal_sequence="../"),
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
        verified, observed = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "passwd" in observed.lower()

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
        verified, observed = await agent._lfi_phase5_verify(_make_page(), "page", synth)
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
        verified, observed = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "decode" in observed.lower()

    @pytest.mark.asyncio
    async def test_error_path_disclosure_matched(self) -> None:
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
        verified, observed = await agent._lfi_phase5_verify(_make_page(), "page", synth)
        assert verified is True
        assert "/var/www" in observed or "/home" in observed

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
        verified, _observed = await agent._lfi_phase5_verify(_make_page(), "page", synth)
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
