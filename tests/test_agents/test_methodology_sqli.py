"""Unit tests for the adaptive SQLi methodology phases.

Each phase is exercised in isolation with mocked ``_send_probe`` and LLM:

    Phase 1 (injection-point mapping)   — quote-variant probes vs baseline
    Phase 2 (dialect fingerprinting)    — error signatures + primitive map
    Phase 3 (injection-type ranking)    — LLM JSON parsing + fallback table
    Phase 4 (payload synthesis)         — LLM JSON parsing + fallback table
    Phase 5 (verification)              — indicator-type matching logic

Plus an end-to-end run that drives all six phases through one ``page``.
"""

from __future__ import annotations

import time
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
    InjectionPrimitives,
    InjectionType,
    SQLDialect,
    SQLiMethodologyResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

# NOTE: ``pytest.mark.asyncio`` is applied per-test (only on ``async def``
# tests) rather than module-wide — applying it to sync helpers / classes
# emits a PytestWarning under pytest-asyncio.


SCOPE = EngagementScope(
    name="methodology-sqli-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------


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
        engagement_id="methodology-sqli-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(
    url: str = "http://example.com/q?id=1", params: list[str] | None = None
) -> PageAnalysis:
    return PageAnalysis(
        url=url,
        body="",
        status=200,
        input_params=params or ["id"],
    )


# ===========================================================================
# Phase 1 — Injection-point mapping
# ===========================================================================


class TestPhase1InjectionPointMapping:
    """Quote-variant probes must mark divergent params as candidates."""

    @pytest.mark.asyncio
    async def test_no_divergence_not_a_candidate(self) -> None:
        """All three probes return the exact same response → not a candidate."""
        agent = _make_agent()
        body = "<html><body>Welcome user 1</body></html>"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        page = _make_page()
        is_candidate, baselines = await agent._sqli_phase1_injection_point(page, "id")
        assert is_candidate is False
        assert len(baselines) == 3
        # All three baselines should record the same fingerprint.
        fingerprints = {b["fingerprint"] for b in baselines}
        assert len(fingerprints) == 1

    @pytest.mark.asyncio
    async def test_status_change_marks_candidate(self) -> None:
        """A 500 on the single-quote probe is enough to mark the param."""
        agent = _make_agent()
        responses = {
            "1": _HTTPResponse(status=200, body="<html>ok 1</html>"),
            "1'": _HTTPResponse(status=500, body="<html>error</html>"),
            '1"': _HTTPResponse(status=200, body="<html>ok 1</html>"),
        }

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            return responses.get(value, _HTTPResponse(status=200, body=""))

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, baselines = await agent._sqli_phase1_injection_point(page, "id")
        assert is_candidate is True
        assert baselines[1]["status"] == 500

    @pytest.mark.asyncio
    async def test_length_divergence_marks_candidate(self) -> None:
        """Even with same status, a body-length jump marks the param."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value.endswith("'"):
                return _HTTPResponse(status=200, body="x" * 500)
            return _HTTPResponse(status=200, body="x" * 100)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, _baselines = await agent._sqli_phase1_injection_point(page, "id")
        assert is_candidate is True

    @pytest.mark.asyncio
    async def test_baselines_carry_timing_status_length_fingerprint(self) -> None:
        """Each baseline must record status, length, fingerprint, elapsed."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="content")
        )
        page = _make_page()
        _is_candidate, baselines = await agent._sqli_phase1_injection_point(page, "id")
        for b in baselines:
            assert "status" in b
            assert "length" in b
            assert "fingerprint" in b
            assert "elapsed_seconds" in b
            assert isinstance(b["fingerprint"], str)
            assert len(b["fingerprint"]) == 16  # truncated sha1


# ===========================================================================
# Phase 2 — Dialect classification + primitive enumeration
# ===========================================================================


class TestPhase2DialectClassification:
    """Each dialect's error signature must classify correctly."""

    def test_classify_mysql_from_error(self) -> None:
        agent = _make_agent()
        body = (
            "Error: You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version for the right syntax to use"
        )
        dialect, matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.MYSQL
        assert matched

    def test_classify_postgres_from_error(self) -> None:
        agent = _make_agent()
        body = "PostgreSQL ERROR: syntax error at or near"
        dialect, matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.POSTGRES
        assert "PostgreSQL" in matched

    def test_classify_mssql_from_error(self) -> None:
        agent = _make_agent()
        body = "[Microsoft][ODBC Driver 17 for SQL Server]Unclosed quotation mark"
        dialect, _matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.MSSQL

    def test_classify_sqlite_from_error(self) -> None:
        agent = _make_agent()
        body = (
            'SequelizeDatabaseError SQLITE_ERROR: near "test\'": '
            "syntax error in /api/products/search"
        )
        dialect, _matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.SQLITE

    def test_classify_oracle_from_error(self) -> None:
        agent = _make_agent()
        body = "ORA-00933: SQL command not properly ended"
        dialect, _matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.ORACLE

    def test_unknown_dialect_for_unrelated_error(self) -> None:
        agent = _make_agent()
        body = "Some random server error 502"
        dialect, matched = agent._classify_dialect_from_error(body)
        assert dialect == SQLDialect.UNKNOWN
        assert matched == ""


class TestPhase2PrimitiveExtraction:
    """Quote / comment / concat enumeration."""

    @pytest.mark.asyncio
    async def test_single_quote_primitive_recognised(self) -> None:
        """Single quote diverges → '\\'' confirmed; '"' stays close to baseline."""
        agent = _make_agent()
        baseline_body = "x" * 100
        agent._sqli_body_fingerprint(baseline_body)  # warmup

        # phase-1 baselines: single-quote at 500B (divergent), double-quote
        # equal to original. Both fingerprints computed via the real helper
        # so the re-probe path doesn't mistakenly diverge on hash mismatch.
        original = {
            "variant": "original",
            "value": "1",
            "status": 200,
            "length": 100,
            "fingerprint": agent._sqli_body_fingerprint(baseline_body),
            "elapsed_seconds": 0.05,
            "body": baseline_body,
        }
        baselines = [
            original,
            {
                **original,
                "variant": "single_quote",
                "value": "1'",
                "status": 500,
                "length": 500,
                "fingerprint": agent._sqli_body_fingerprint("y" * 500),
                "body": "y" * 500,
            },
            {**original, "variant": "double_quote", "value": '1"'},
        ]

        # Re-probe stub: ' + " return divergent bodies, anything else echoes
        # baseline (so backtick / comment / concat probes look benign).
        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value.endswith("'"):
                return _HTTPResponse(status=500, body="error" * 100)
            return _HTTPResponse(status=200, body=baseline_body)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        primitives = await agent._sqli_probe_primitives(page, "id", baselines)
        assert "'" in primitives.quote_chars
        assert '"' not in primitives.quote_chars
        assert "`" not in primitives.quote_chars
        # Comment markers parsed cleanly (200 + no errors) in the stub.
        assert "--" in primitives.comment_syntax
        # At least one concat operator should be selected (no errors observed).
        assert primitives.concat_op in {"||", "+", "CONCAT"}

    @pytest.mark.asyncio
    async def test_no_quotes_means_no_comment_no_concat(self) -> None:
        """If no quote is confirmed, comment / concat probes are skipped."""
        agent = _make_agent()
        body = "x" * 100
        original = {
            "variant": "original",
            "value": "1",
            "status": 200,
            "length": 100,
            "fingerprint": agent._sqli_body_fingerprint(body),
            "elapsed_seconds": 0.05,
            "body": body,
        }
        baselines = [
            original,
            {**original, "variant": "single_quote", "value": "1'"},
            {**original, "variant": "double_quote", "value": '1"'},
        ]
        # Every re-probe returns the baseline body → no quote diverges.
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        page = _make_page()
        primitives = await agent._sqli_probe_primitives(page, "id", baselines)
        assert primitives.quote_chars == []
        assert primitives.comment_syntax == []
        assert primitives.concat_op is None


# ===========================================================================
# Phase 3 — Injection-type ranking
# ===========================================================================


class TestPhase3InjectionTypeRanking:
    @pytest.mark.asyncio
    async def test_llm_ranking_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"ranked": ['
                '{"type": "union_based", "rationale": "best yield"},'
                '{"type": "error_based", "rationale": "fast"}'
                "]}"
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"]),
            {"error_match": "SQL syntax MySQL"},
        )
        assert ranked[0] == InjectionType.UNION_BASED
        assert ranked[1] == InjectionType.ERROR_BASED

    @pytest.mark.asyncio
    async def test_fallback_when_dialect_via_error_prefers_error_based(self) -> None:
        """If dialect was classified via an error sig, error-based ranks first."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"]),
            {"error_match": "SQL syntax MySQL"},
        )
        assert ranked[0] == InjectionType.ERROR_BASED

    @pytest.mark.asyncio
    async def test_fallback_when_dialect_via_time_prefers_time_blind(self) -> None:
        """Dialect discovered via time delay → time-blind ranks first."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"]),
            {"time_match": {"guess": "mysql", "elapsed_seconds": 2.1}},
        )
        assert ranked[0] == InjectionType.TIME_BLIND

    @pytest.mark.asyncio
    async def test_fallback_when_unknown_dialect_with_quote_prefers_boolean_blind(
        self,
    ) -> None:
        """Unknown dialect but a quote primitive → boolean-blind ranks first."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.UNKNOWN,
            InjectionPrimitives(quote_chars=["'"]),
            {},
        )
        assert ranked[0] == InjectionType.BOOLEAN_BLIND

    @pytest.mark.asyncio
    async def test_fallback_appends_stacked_for_mssql(self) -> None:
        """Stacked is appended only for MSSQL / PostgreSQL."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        ranked = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.MSSQL,
            InjectionPrimitives(quote_chars=["'"]),
            {"error_match": "[SQL Server]"},
        )
        assert InjectionType.STACKED in ranked
        ranked_sqlite = await agent._sqli_phase3_rank_injection_types(
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"]),
            {"error_match": "SQLITE_ERROR"},
        )
        assert InjectionType.STACKED not in ranked_sqlite


# ===========================================================================
# Phase 4 — Payload synthesis
# ===========================================================================


class TestPhase4PayloadSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "1\' UNION SELECT 1,2-- -", '
                '"control_payload": null, '
                '"expected_indicator": "row_2", '
                '"indicator_type": "union_data", '
                '"rationale": "two-column UNION"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        baseline = {"value": "1", "length": 100}
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.UNION_BASED,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"]),
            baseline,
        )
        assert synth is not None
        assert synth["indicator_type"] == "union_data"
        assert synth["expected_indicator"] == "row_2"
        assert "UNION" in synth["payload"]

    @pytest.mark.asyncio
    async def test_fallback_error_based_uses_dialect_indicator(self) -> None:
        """LLM silent → fallback synthesises a quote-append + dialect indicator."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.ERROR_BASED,
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"]),
            {"value": "1", "length": 100},
        )
        assert synth is not None
        assert synth["indicator_type"] == "error_string"
        assert "SQLITE" in synth["expected_indicator"]
        assert synth["payload"].endswith("'")

    @pytest.mark.asyncio
    async def test_fallback_boolean_blind_provides_control_payload(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.BOOLEAN_BLIND,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"]),
            {"value": "1", "length": 100},
        )
        assert synth is not None
        assert synth["indicator_type"] == "content_diff"
        assert synth["control_payload"] is not None
        assert synth["payload"] != synth["control_payload"]

    @pytest.mark.asyncio
    async def test_fallback_time_blind_uses_dialect_specific_sleep(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth_pg = await agent._sqli_phase4_synthesize_payload(
            InjectionType.TIME_BLIND,
            SQLDialect.POSTGRES,
            InjectionPrimitives(quote_chars=["'"]),
            {"value": "1", "length": 100},
        )
        assert synth_pg is not None
        assert "pg_sleep" in synth_pg["payload"]
        synth_mssql = await agent._sqli_phase4_synthesize_payload(
            InjectionType.TIME_BLIND,
            SQLDialect.MSSQL,
            InjectionPrimitives(quote_chars=["'"]),
            {"value": "1", "length": 100},
        )
        assert synth_mssql is not None
        assert "WAITFOR DELAY" in synth_mssql["payload"]

    @pytest.mark.asyncio
    async def test_fallback_union_based_declines_without_quote(self) -> None:
        """Union-based without confirmed quote primitive declines (returns None)."""
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.UNION_BASED,
            SQLDialect.MYSQL,
            InjectionPrimitives(),
            {"value": "1", "length": 100},
        )
        assert synth is None


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_error_string_indicator_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=500,
                body="You have an error in your SQL syntax — MySQL ...",
            )
        )
        synth = {
            "payload": "1'",
            "indicator_type": "error_string",
            "expected_indicator": "SQL syntax",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is True
        assert "SQL syntax" in observed

    @pytest.mark.asyncio
    async def test_error_string_falls_back_to_pattern_set(self) -> None:
        """If the LLM-supplied indicator doesn't match, the dialect set still does."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=500, body="ORA-00933: bad command")
        )
        synth = {
            "payload": "1'",
            "indicator_type": "error_string",
            "expected_indicator": "totally_wrong_indicator",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is True
        assert "ORA-00933" in observed

    @pytest.mark.asyncio
    async def test_union_data_indicator_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="row: CLINKZUNIONMARKER42")
        )
        synth = {
            "payload": "1' UNION SELECT 'CLINKZUNIONMARKER42',NULL-- -",
            "indicator_type": "union_data",
            "expected_indicator": "CLINKZUNIONMARKER42",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is True
        assert "CLINKZUNIONMARKER42" in observed

    @pytest.mark.asyncio
    async def test_content_diff_paired_payloads(self) -> None:
        """Boolean-blind: true ≈ baseline, false diverges."""
        agent = _make_agent()
        responses = {
            "1' AND '1'='1": _HTTPResponse(status=200, body="x" * 102),  # ≈ baseline
            "1' AND '1'='2": _HTTPResponse(status=200, body="x" * 50),
        }

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            return responses.get(value, _HTTPResponse(status=200, body=""))

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        synth = {
            "payload": "1' AND '1'='1",
            "control_payload": "1' AND '1'='2",
            "indicator_type": "content_diff",
            "expected_indicator": "true ≈ baseline",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is True
        assert "true=" in observed and "false=" in observed

    @pytest.mark.asyncio
    async def test_content_diff_no_difference_rejected(self) -> None:
        """Identical responses for true and false → not verified."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="x" * 100)
        )
        synth = {
            "payload": "1' AND '1'='1",
            "control_payload": "1' AND '1'='2",
            "indicator_type": "content_diff",
            "expected_indicator": "true ≈ baseline",
        }
        verified, _observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_time_delta_above_threshold_verified(self) -> None:
        """Elapsed >= 4s → verified."""
        agent = _make_agent()

        async def slow_probe(_page: PageAnalysis, _param: str, _value: str) -> _HTTPResponse:
            time.sleep(0)  # don't actually sleep — patch monotonic instead
            return _HTTPResponse(status=200, body="")

        agent._send_probe = slow_probe  # type: ignore[method-assign]
        # Monkey-patch monotonic so the verify function thinks 5 seconds passed.
        from clinkz.agents import exploit as exploit_mod

        original_monotonic = exploit_mod.time.monotonic
        clock = iter([0.0, 5.0])
        exploit_mod.time.monotonic = lambda: next(clock)  # type: ignore[assignment]
        try:
            synth = {
                "payload": "1' OR SLEEP(5)-- -",
                "indicator_type": "time_delta",
                "expected_indicator": "elapsed >= 4s",
            }
            verified, observed = await agent._sqli_phase5_verify(
                _make_page(), "id", synth, {"length": 100}
            )
        finally:
            exploit_mod.time.monotonic = original_monotonic  # type: ignore[assignment]
        assert verified is True
        assert "5.00s" in observed

    @pytest.mark.asyncio
    async def test_time_delta_below_threshold_rejected(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="")
        )
        from clinkz.agents import exploit as exploit_mod

        original_monotonic = exploit_mod.time.monotonic
        clock = iter([0.0, 0.5])
        exploit_mod.time.monotonic = lambda: next(clock)  # type: ignore[assignment]
        try:
            synth = {
                "payload": "1' OR SLEEP(5)-- -",
                "indicator_type": "time_delta",
                "expected_indicator": "elapsed >= 4s",
            }
            verified, _observed = await agent._sqli_phase5_verify(
                _make_page(), "id", synth, {"length": 100}
            )
        finally:
            exploit_mod.time.monotonic = original_monotonic  # type: ignore[assignment]
        assert verified is False


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = SQLiMethodologyResult(
            phases_completed=6,
            dialect=SQLDialect.SQLITE,
            primitives=InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"]),
            injection_type=InjectionType.ERROR_BASED,
            synthesized_payload="1'",
            expected_indicator="SQLITE",
            indicator_type="error_string",
            indicator_observed="matched 'SQLITE_ERROR'",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._sqli_phase6_emit("http://x/q?id=1", "id", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "dialect=sqlite" in joined
        assert "injection_type=error_based" in joined
        assert "payload=1'" in joined
        assert "indicator_observed=" in joined
        assert finding.severity.value == "high"
        assert "sql injection" in finding.title.lower()


# ===========================================================================
# Integration — full _test_sqli driving all six phases
# ===========================================================================


class TestSQLiMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_low_style_error_based_finding(self) -> None:
        """End-to-end: single quote returns MySQL error → finding emitted."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))  # silent → fallback path
        agent._methodology_llm = agent.llm

        baseline_body = "<html><body>First name: admin</body></html>"
        error_body = (
            "<html><body>You have an error in your SQL syntax; check the manual "
            "that corresponds to your MySQL server version</body></html>"
        )

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "'" in value or '"' in value:
                return _HTTPResponse(status=200, body=error_body)
            return _HTTPResponse(status=200, body=baseline_body)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://example.com/q?id=1", params=["id"])
        findings = await agent._test_sqli(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "dialect=mysql" in joined
        assert "injection_type=error_based" in joined
        assert "phases_completed=6" in joined

    @pytest.mark.asyncio
    async def test_no_finding_when_param_does_not_diverge(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>safe</html>")
        )
        page = _make_page("http://example.com/q?id=1", params=["id"])
        findings = await agent._test_sqli(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_juiceshop_product_search_breakout_and_columns(self) -> None:
        """Parenthesised context (``((name LIKE '%<v>%' ...))``) on SQLite.

        A bare ``'`` errors; only the ``'))`` closer balances. Phase 2 must
        discover that closer + the 9-column count, and the methodology must
        confirm (the real Juice Shop product-search miss). The mock mirrors
        Juice Shop: ``q=1'`` → 500 SQLITE_ERROR, ``q=1')) ...`` parses.
        """
        agent = _make_agent(_ScriptedLLM(answers=[""]))  # silent → deterministic
        agent._methodology_llm = agent.llm

        products = '{"status":"success","data":[' + '{"id":1},' * 18 + "]}"
        empty = '{"status":"success","data":[]}'
        err = '<html>OWASP Juice Shop<br>SQLITE_ERROR: near "UNION": syntax error</html>'
        marker_body = '{"status":"success","data":[{"id":"CLINKZUNIONMARKER42"}]}'

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            balanced = "'))" in value
            if value == "1":
                return _HTTPResponse(status=200, body=products)
            if balanced and "CLINKZUNIONMARKER42" in value:
                return _HTTPResponse(status=200, body=marker_body)
            if balanced and "OR 1=1" in value:
                return _HTTPResponse(status=200, body=products)
            if balanced and "AND 1=2" in value:
                return _HTTPResponse(status=200, body=empty)
            if balanced and "UNION SELECT" in value:
                # Only the true (9) column count balances; others error.
                return (
                    _HTTPResponse(status=200, body=products)
                    if value.count("NULL") == 9
                    else _HTTPResponse(status=500, body=err)
                )
            if "'" in value:  # any other single-quote-bearing payload → unbalanced
                return _HTTPResponse(status=500, body=err)
            return _HTTPResponse(status=200, body=empty)  # neutral / no-quote probes

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://example.com/rest/products/search?q=1", params=["q"])
        findings = await agent._test_sqli(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "dialect=sqlite" in joined
        # Breakout context + column count were discovered and recorded.
        assert "'))" in joined
        assert "union_columns" in joined


# ===========================================================================
# FIX 1 — breakout-context discovery, column-count, dialect/reflection guards
# ===========================================================================


class TestSQLiBreakoutDiscovery:
    """Phase-2 breakout-context discovery (`break_prefix`)."""

    @pytest.mark.asyncio
    async def test_single_quote_breakout(self) -> None:
        """DVWA-style ``WHERE x='<v>'`` → closer ``'`` balances."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value.startswith("1'") and "OR 1=1" in value:
                return _HTTPResponse(status=200, body="ALL ROWS " * 50)
            if value.startswith("1'") and "AND 1=2" in value:
                return _HTTPResponse(status=200, body="")
            return _HTTPResponse(status=200, body="neutral")  # closer "" → same body

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        bp = await agent._sqli_discover_break_prefix(
            _make_page(), "id", "1", InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"])
        )
        assert bp == "'"

    @pytest.mark.asyncio
    async def test_parenthesised_breakout(self) -> None:
        """Juice-Shop-style ``((name LIKE '%<v>%'))`` → only ``'))`` balances."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "')) OR 1=1" in value:
                return _HTTPResponse(status=200, body="ALL PRODUCTS " * 50)
            if "')) AND 1=2" in value:
                return _HTTPResponse(status=200, body="")
            if value.startswith("1 "):  # closer "" (no quote) → neutral, no diff
                return _HTTPResponse(status=200, body="neutral")
            return _HTTPResponse(status=500, body='SQLITE_ERROR: near "OR": syntax error')

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        bp = await agent._sqli_discover_break_prefix(
            _make_page(), "id", "1", InjectionPrimitives(quote_chars=["'"])
        )
        assert bp == "'))"

    @pytest.mark.asyncio
    async def test_reflected_error_page_is_not_a_breakout(self) -> None:
        """All closers 4xx (reflection in error page) → no breakout (None).

        The /redirect?to= class: every probe is 406'd and reflects the value,
        so bodies differ — but an error response is never a balanced query.
        """
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            return _HTTPResponse(status=406, body=f"Unrecognized target URL: {value}")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        bp = await agent._sqli_discover_break_prefix(
            _make_page(), "to", "/", InjectionPrimitives(quote_chars=["'"])
        )
        assert bp is None

    @pytest.mark.asyncio
    async def test_column_count_enumeration(self) -> None:
        """First NULL-column count that parses cleanly is returned."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if value.count("NULL") == 9:
                return _HTTPResponse(status=200, body="data")
            return _HTTPResponse(
                status=500, body="SQLITE_ERROR: different number of result columns"
            )

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        n = await agent._sqli_count_union_columns(_make_page(), "q", "1", "'))")
        assert n == 9


class TestSQLiDialectConditionedSynthesis:
    """Phase-4 deterministic build from confirmed breakout + column count."""

    @pytest.mark.asyncio
    async def test_union_uses_break_prefix_and_column_count(self) -> None:
        """A known breakout makes synthesis deterministic, ignoring the LLM."""
        # LLM would return a wrong (3-col, bare-quote) payload — must be ignored.
        llm = _ScriptedLLM(answers=['{"payload": "1\' UNION SELECT 1,2,3-- -"}'])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.UNION_BASED,
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"], break_prefix="'))", union_columns=9),
            {"value": "1", "length": 100},
        )
        assert synth is not None
        assert synth["payload"].startswith("1')) UNION SELECT")
        assert "CLINKZUNIONMARKER42" in synth["payload"]
        assert synth["payload"].count("NULL") == 8  # 9 columns: marker + 8 NULL
        assert synth["indicator_type"] == "union_data"
        # The LLM's wrong payload was not consumed.
        assert "1,2,3" not in synth["payload"]

    @pytest.mark.asyncio
    async def test_boolean_uses_break_prefix(self) -> None:
        agent = _make_agent()
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.BOOLEAN_BLIND,
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"], break_prefix="'))"),
            {"value": "1", "length": 100},
        )
        assert synth is not None
        assert synth["payload"] == "1')) AND 1=1-- -"
        assert synth["control_payload"] == "1')) AND 1=2-- -"


class TestSQLiPhase5ReflectionGuard:
    """Phase-5 must reject markers / indicators echoed in error responses."""

    @pytest.mark.asyncio
    async def test_union_marker_in_error_response_rejected(self) -> None:
        """Union marker echoed in a 406 is reflection, not data."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=406, body="Unrecognized target URL: 1' UNION SELECT CLINKZUNIONMARKER42"
            )
        )
        synth = {
            "payload": "1' UNION SELECT 'CLINKZUNIONMARKER42',NULL-- -",
            "indicator_type": "union_data",
            "expected_indicator": "CLINKZUNIONMARKER42",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "to", synth, {"length": 100}
        )
        assert verified is False
        assert "error response" in observed
        assert "status=406" in observed

    @pytest.mark.asyncio
    async def test_reflected_indicator_without_db_error_rejected(self) -> None:
        """An LLM indicator that is just our echoed payload (no DB error) → reject."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=406, body="Unrecognized target URL: 1' UNION SELECT marker"
            )
        )
        synth = {
            "payload": "1' UNION SELECT marker",
            "indicator_type": "error_string",
            "expected_indicator": "UNION SELECT",
        }
        verified, _observed = await agent._sqli_phase5_verify(
            _make_page(), "to", synth, {"length": 100}
        )
        assert verified is False

    @pytest.mark.asyncio
    async def test_real_sqlite_error_500_still_confirms(self) -> None:
        """Juice Shop's real 500 SQLITE_ERROR is a genuine error-based hit."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=500, body='SQLITE_ERROR: near "\'": syntax error')
        )
        synth = {
            "payload": "1'",
            "indicator_type": "error_string",
            "expected_indicator": "anything",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "q", synth, {"length": 100}
        )
        assert verified is True
        assert "SQLITE_ERROR" in observed
        assert "status=500" in observed

    def test_has_db_error_catches_sqlite(self) -> None:
        """`_extract_errors` misses SQLITE_ERROR; the combined check catches it."""
        agent = _make_agent()
        assert agent._extract_errors('SQLITE_ERROR: near "x"') == []
        assert agent._sqli_has_db_error('SQLITE_ERROR: near "x"') is True
        assert agent._sqli_has_db_error("You have an error in your SQL syntax ... MySQL") is True
        assert agent._sqli_has_db_error("a perfectly ordinary page") is False

    @pytest.mark.asyncio
    async def test_union_marker_only_in_echoed_payload_rejected(self) -> None:
        """A 200 endpoint that echoes the submitted value verbatim makes the
        union marker a substring of our own payload — input reflection, not
        extracted data — and must NOT confirm UNION SQLi.

        This is the 1b8101dd / b9dc3627 phantom class: DVWA's
        ``Wrong password for '<input>'`` on csrf/test_credentials.php and the
        xss_r ``Hello <input>`` reflected sink both echo the union payload, so a
        bare ``marker in body`` check trivially (and wrongly) confirmed.
        """
        agent = _make_agent()
        payload = "test' UNION SELECT 'CLINKZUNIONMARKER42',NULL-- -"
        echo_body = f"<pre>Wrong password for '{payload}'</pre>"  # payload echoed verbatim
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=echo_body)
        )
        synth = {
            "payload": payload,
            "indicator_type": "union_data",
            "expected_indicator": "CLINKZUNIONMARKER42",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "username", synth, {"length": 100}
        )
        assert verified is False
        assert "reflection" in observed

    @pytest.mark.asyncio
    async def test_genuine_union_data_row_confirms_despite_echo(self) -> None:
        """DVWA /vulnerabilities/sqli/ echoes the payload in ``ID:`` AND renders
        the executed UNION's first column in ``First name:`` — the marker
        survives the echo strip, so a genuine union still confirms (the
        reflection guard must not over-reject 43aa80a6)."""
        agent = _make_agent()
        payload = "1' UNION SELECT 'CLINKZUNIONMARKER42',NULL-- -"
        # ``ID:`` echoes the raw payload (DVWA low does not escape it); the
        # executed UNION's first column lands in ``First name:`` in data position.
        genuine_body = (
            f"<pre>ID: {payload}<br />First name: CLINKZUNIONMARKER42<br />Surname: </pre>"
        )
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=genuine_body)
        )
        synth = {
            "payload": payload,
            "indicator_type": "union_data",
            "expected_indicator": "CLINKZUNIONMARKER42",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is True
        assert "CLINKZUNIONMARKER42" in observed
