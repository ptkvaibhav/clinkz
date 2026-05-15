"""Unit tests for the adaptive file-upload methodology phases.

Each phase is exercised in isolation with mocked HTTP + LLM:

    Phase 1 (upload-point mapping)    — baseline image acceptance
    Phase 2 (restriction fingerprint) — ext / MIME / magic-byte / size /
                                        filename-injection probes
    Phase 3 (execution-type ranking)  — LLM JSON parsing + fallback table
    Phase 4 (payload synthesis)       — LLM JSON parsing + fallback table
    Phase 5 (verification)            — uploaded-URL discovery + execution
    Phase 6 (finding emission)        — evidence chain on the Finding
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    FileUploadExecutionType,
    FileUploadMethodologyResult,
    FileUploadRestrictions,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-upload-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _ScriptedLLM(LLMClient):
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
        engagement_id="methodology-upload-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_upload_form() -> dict[str, Any]:
    return {
        "action": "",
        "method": "POST",
        "fields": [
            {"name": "uploaded", "type": "file", "value": ""},
            {"name": "Upload", "type": "submit", "value": "Upload"},
        ],
    }


def _make_page() -> PageAnalysis:
    return PageAnalysis(
        url="http://example.com/upload",
        body="",
        status=200,
        forms=[_make_upload_form()],
    )


# ===========================================================================
# Phase 1 — Upload point mapping
# ===========================================================================


class TestPhase1UploadPointMapping:
    @pytest.mark.asyncio
    async def test_baseline_image_round_trip(self) -> None:
        agent = _make_agent()
        agent._http_post_multipart = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="image uploaded")
        )
        status, body = await agent._file_upload_phase1_upload_point("http://example.com/upload")
        assert status == 200
        assert "uploaded" in body


# ===========================================================================
# Phase 2 — Restriction fingerprinting
# ===========================================================================


class TestPhase2RestrictionFingerprint:
    @pytest.mark.asyncio
    async def test_unrestricted_accepts_php(self) -> None:
        agent = _make_agent()

        async def fake_post(
            _url: str, filename: str, content: str, content_type: str
        ) -> _HTTPResponse:
            # Permissive server: accepts everything except oversized.
            if len(content) > 1_500_000:
                return _HTTPResponse(status=413, body="too large")
            return _HTTPResponse(status=200, body=f"uploaded {filename}")

        agent._http_post_multipart = fake_post  # type: ignore[method-assign]
        restrictions, _ev = await agent._file_upload_phase2_fingerprint(
            "http://example.com/upload", 200, "uploaded"
        )
        assert ".php" in restrictions.working_extensions
        assert ".phtml" in restrictions.working_extensions
        assert restrictions.content_type_check is False

    @pytest.mark.asyncio
    async def test_extension_blocklist_php_rejected(self) -> None:
        agent = _make_agent()

        async def fake_post(
            _url: str, filename: str, content: str, content_type: str
        ) -> _HTTPResponse:
            if filename.endswith(".php"):
                return _HTTPResponse(status=400, body="error: file type not allowed")
            return _HTTPResponse(status=200, body=f"uploaded {filename}")

        agent._http_post_multipart = fake_post  # type: ignore[method-assign]
        restrictions, _ev = await agent._file_upload_phase2_fingerprint(
            "http://example.com/upload", 200, "uploaded"
        )
        assert ".php" not in restrictions.working_extensions
        # phtml / phar / etc still get through.
        assert ".phtml" in restrictions.working_extensions

    @pytest.mark.asyncio
    async def test_magic_byte_check_detected(self) -> None:
        agent = _make_agent()

        async def fake_post(
            _url: str, filename: str, content: str, content_type: str
        ) -> _HTTPResponse:
            # Reject plain .php script bodies; accept GIF89a-prefixed.
            if filename.endswith(".php") and not content.startswith("GIF89a"):
                return _HTTPResponse(status=400, body="error: invalid file content")
            return _HTTPResponse(status=200, body=f"uploaded {filename}")

        agent._http_post_multipart = fake_post  # type: ignore[method-assign]
        restrictions, _ev = await agent._file_upload_phase2_fingerprint(
            "http://example.com/upload", 200, "uploaded"
        )
        assert restrictions.magic_byte_check is True


# ===========================================================================
# Phase 3 — Execution-type ranking
# ===========================================================================


class TestPhase3ExecutionTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "direct_execution", "rationale": "ext open"},'
                '{"type": "interpreter_misconfig", "rationale": "fallback"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._file_upload_phase3_rank_execution_types(
            FileUploadRestrictions(working_extensions=[".php"]), {}
        )
        assert ranked[0] == FileUploadExecutionType.DIRECT_EXECUTION
        assert ranked[1] == FileUploadExecutionType.INTERPRETER_MISCONFIG

    @pytest.mark.asyncio
    async def test_fallback_php_ranks_direct(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._file_upload_phase3_rank_execution_types(
            FileUploadRestrictions(working_extensions=[".php"]), {}
        )
        assert FileUploadExecutionType.DIRECT_EXECUTION in ranked

    @pytest.mark.asyncio
    async def test_fallback_nothing_accepted_ranks_client_side(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._file_upload_phase3_rank_execution_types(
            FileUploadRestrictions(working_extensions=[]), {}
        )
        assert ranked == [FileUploadExecutionType.CLIENT_SIDE_ONLY]


# ===========================================================================
# Phase 4 — Payload synthesis
# ===========================================================================


class TestPhase4PayloadSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"filename": "shell.php", "content": "<?php phpinfo(); ?>", '
                '"content_type": "application/x-php", "rationale": "direct"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._file_upload_phase4_synthesize(
            FileUploadExecutionType.DIRECT_EXECUTION,
            FileUploadRestrictions(working_extensions=[".php"]),
        )
        assert synth is not None
        assert synth["filename"] == "shell.php"
        assert "phpinfo" in synth["content"]

    @pytest.mark.asyncio
    async def test_fallback_direct_execution(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._file_upload_phase4_synthesize(
            FileUploadExecutionType.DIRECT_EXECUTION,
            FileUploadRestrictions(working_extensions=[".php"]),
        )
        assert synth is not None
        assert synth["filename"].endswith(".php")
        assert "phpinfo" in synth["content"]

    @pytest.mark.asyncio
    async def test_fallback_direct_execution_declines_with_no_working_ext(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._file_upload_phase4_synthesize(
            FileUploadExecutionType.DIRECT_EXECUTION,
            FileUploadRestrictions(working_extensions=[]),
        )
        assert synth is None

    @pytest.mark.asyncio
    async def test_fallback_interpreter_misconfig_uses_svg(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._file_upload_phase4_synthesize(
            FileUploadExecutionType.INTERPRETER_MISCONFIG,
            FileUploadRestrictions(working_extensions=[".svg"]),
        )
        assert synth is not None
        assert synth["filename"].endswith(".svg")
        assert "onload" in synth["content"]


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_upload_accepted_with_canary_executes(self) -> None:
        agent = _make_agent()
        agent._http_post_multipart = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="../../hackable/uploads/shell.php uploaded successfully",
            )
        )
        # When the methodology fetches the uploaded URL, the response
        # mimics PHP execution echoing the canary without source.
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="clinkzupload12345")
        )
        synth = {
            "filename": "shell.php",
            "content": "<?php echo 'clinkzupload12345'; ?>",
            "content_type": "application/x-php",
            "canary": "clinkzupload12345",
        }
        verified, uploaded_url, observed = await agent._file_upload_phase5_verify(
            "http://example.com/upload", synth, FileUploadExecutionType.DIRECT_EXECUTION
        )
        assert verified is True
        assert uploaded_url is not None
        assert observed is not None
        assert "execution" in observed

    @pytest.mark.asyncio
    async def test_upload_rejected(self) -> None:
        agent = _make_agent()
        agent._http_post_multipart = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=400, body="error: rejected")
        )
        synth = {
            "filename": "shell.php",
            "content": "<?php phpinfo(); ?>",
            "content_type": "application/x-php",
        }
        verified, uploaded_url, observed = await agent._file_upload_phase5_verify(
            "http://example.com/upload", synth, FileUploadExecutionType.DIRECT_EXECUTION
        )
        assert verified is False
        assert uploaded_url is None
        assert observed is None


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = FileUploadMethodologyResult(
            phases_completed=6,
            restrictions=FileUploadRestrictions(working_extensions=[".php"]),
            execution_type=FileUploadExecutionType.DIRECT_EXECUTION,
            synthesized_filename="clinkz_pop.php",
            synthesized_content_type="application/x-php",
            uploaded_url="http://example.com/uploads/clinkz_pop.php",
            indicator_observed="execution: canary echoed without source",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._file_upload_phase6_emit("http://example.com/upload", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "execution_type=direct_execution" in joined
        assert "uploaded_url=" in joined
        assert finding.severity.value == "critical"


# ===========================================================================
# Integration — full _test_file_upload driving all six phases
# ===========================================================================


class TestFileUploadMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_low_style_unrestricted_upload(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""] * 8))
        agent._methodology_llm = agent.llm

        stored: dict[str, str] = {}

        async def fake_post(
            _url: str, filename: str, content: str, content_type: str
        ) -> _HTTPResponse:
            stored["last"] = filename
            stored["body"] = content
            if len(content) > 1_500_000:
                return _HTTPResponse(status=413, body="too large")
            return _HTTPResponse(status=200, body=f"uploaded {filename}")

        async def fake_get(url: str, _params: dict[str, str]) -> _HTTPResponse:
            # The methodology probes /uploads/<filename>.
            if stored.get("last") and stored["last"] in url:
                # Pretend the server executed our PHP and echoed canary.
                body = stored.get("body", "")
                # Extract canary from body for the test.
                import re

                m = re.search(r"clinkzupload\d+", body)
                canary = m.group(0) if m else "clinkz"
                return _HTTPResponse(status=200, body=canary)
            return _HTTPResponse(status=404, body="not found")

        agent._http_post_multipart = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page()
        findings = await agent._test_file_upload(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "phases_completed=6" in joined
        assert "execution_type=" in joined
