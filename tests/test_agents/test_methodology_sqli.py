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
