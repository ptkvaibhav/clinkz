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
from urllib.parse import quote, unquote

import pytest

from clinkz.agents.exploit import (
    _COOKIE_VECTOR_PREFIX,
    _SESSION_VECTOR_PREFIX,
    _SQLI_UNION_MARKER,
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
from clinkz.models.scan import SessionVector
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
    async def test_union_data_rejects_marker_inside_inline_db_error(self) -> None:
        """DVWA sqli/high renders ``mysqli_error()`` INLINE at status 200; a
        malformed union payload's marker reflected in that error is NOT data.

        This is the a0095af2 session-vector phantom: the marker surfaced only
        inside "near '<marker>'-- -' ... MariaDB" — input reflection in an error
        message, not a UNION row. The 4xx/5xx guard cannot catch it (status is
        200) and the full-payload echo strip misses the partial fragment the
        parser reports, so the DB-error signature is the honest reject signal.
        """
        agent = _make_agent()
        error_body = (
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MariaDB server version for the right syntax "
            "to use near 'CLINKZUNIONMARKER42'-- -' LIMIT 1' at line 1"
        )
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=error_body)
        )
        synth = {
            "payload": "1 UNION SELECT 'CLINKZUNIONMARKER42'-- -",
            "indicator_type": "union_data",
            "expected_indicator": "CLINKZUNIONMARKER42",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100}
        )
        assert verified is False
        assert "DB error" in observed

    @pytest.mark.asyncio
    async def test_content_diff_paired_payloads(self) -> None:
        """Boolean-blind: true ≈ baseline, false diverges — in every repeat.

        G14 made the oracle carry its own control: it re-sends the benign value
        alongside each true/false pair and repeats the whole triple, so the
        baseline the comparison uses is contemporaneous rather than a number
        measured earlier in the phase.
        """
        agent = _make_agent()
        responses = {
            "1": _HTTPResponse(status=200, body="x" * 100),  # the benign baseline
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
            _make_page(), "id", synth, {"length": 100, "value": "1"}
        )
        assert verified is True
        assert "baseline=" in observed and "true=" in observed and "false=" in observed
        assert "identical in every repeat" in observed

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


class TestBreakPrefixEchoRobustness:
    """Phase-2 breakout discovery must not mistake a value-echo for a predicate
    divergence (the DVWA sqli/high ``ID:`` echo, exposed by the session vector)."""

    def test_diverges_beyond_payload_echo_rejects_echo_only(self) -> None:
        """Two bodies that differ ONLY because each echoes its own payload are
        not a real divergence."""
        agent = _make_agent()
        true_body = "<pre>ID: 1 OR 1=1 -- -<br />First name: admin</pre>"
        false_body = "<pre>ID: 1 AND 1=2 -- -<br />First name: admin</pre>"
        assert (
            agent._diverges_beyond_payload_echo(
                true_body, false_body, "1 OR 1=1 -- -", "1 AND 1=2 -- -"
            )
            is False
        )

    def test_diverges_beyond_payload_echo_keeps_real_divergence(self) -> None:
        """A genuine predicate divergence (row vs no row) survives the echo strip."""
        agent = _make_agent()
        true_body = "<pre>ID: 1' OR 1=1 -- -<br />First name: admin</pre>"
        false_body = "<body>Nothing to display.</body>"
        assert (
            agent._diverges_beyond_payload_echo(
                true_body, false_body, "1' OR 1=1 -- -", "1' AND 1=2 -- -"
            )
            is True
        )

    @pytest.mark.asyncio
    async def test_discover_break_prefix_dvwa_high_shape(self) -> None:
        """DVWA sqli/high breakout discovery must find ``'`` — faithfully models
        BOTH root causes the session vector exposed (a0095af2 / 62596e97).

        The mock reproduces ``SELECT ... WHERE user_id = '<value>' LIMIT 1`` with
        an ``ID:`` echo: (1) the integer ``user_id`` coerces ``'1 OR 1=1 -- -'``
        to ``1`` so BOTH empty-closer probes match admin and differ only by the
        echoed payload (the empty closer must be rejected); and (2) a bare ``--``
        does not comment the appended ``' LIMIT 1`` in MySQL, so a ``'`` breakout
        without ``-- `` errors (the genuine closer is found only because the probe
        uses ``-- -``, not the bare confirmed comment)."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            breakout = value.startswith("1'")
            # A ``'`` breakout leaves the appended ``' LIMIT 1`` un-terminated
            # unless a real line comment (``-- `` with trailing whitespace, or
            # ``#``) eats it — otherwise the query is unbalanced and errors.
            if breakout and "-- " not in value and not value.rstrip().endswith("#"):
                return _HTTPResponse(
                    status=200,
                    body="You have an error in your SQL syntax ... MariaDB server version",
                )
            # Balanced ``'`` breakout with a false predicate empties the result
            # set (no row, no ``ID:`` echo).
            if breakout and "AND 1=2" in value:
                return _HTTPResponse(status=200, body="<body>Nothing to display.</body>")
            # Everything else coerces to id=1 → admin row, echoing the raw value.
            return _HTTPResponse(
                status=200,
                body=f"<pre>ID: {value}<br />First name: admin<br />Surname: admin</pre>",
            )

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        # comment_syntax[0] is the bare ``--`` DVWA phase-2 actually confirms; the
        # discover method must still use ``-- -`` internally so ``'`` does not error.
        primitives = InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"])
        closer = await agent._sqli_discover_break_prefix(_make_page(), "id", "1", primitives)
        assert closer == "'"


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
    async def test_error_string_indicator_present_in_baseline_rejected(self) -> None:
        """An over-generic LLM indicator already present in the benign baseline
        (DVWA's left-nav `SQL Injection` chrome on the xss_r page) is static page
        content, not an error the payload provoked — must NOT confirm (the
        b9dc3627 error_string phantom that resurfaced through this branch)."""
        agent = _make_agent()
        # Both the benign baseline and the probe response carry the DVWA nav
        # menu containing "SQL Injection"; only the echoed value differs.
        chrome = "<a href='/vulnerabilities/sqli/'>SQL Injection</a><pre>Hello "
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=chrome + "1'</pre>")
        )
        synth = {
            "payload": "1'",
            "indicator_type": "error_string",
            "expected_indicator": "SQL",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "name", synth, {"length": 100, "body": chrome + "1</pre>"}
        )
        assert verified is False
        assert "no error substring" in observed

    @pytest.mark.asyncio
    async def test_error_string_genuine_indicator_absent_from_baseline_confirms(
        self,
    ) -> None:
        """A real error signature absent from the benign baseline still confirms
        — the baseline-anchor must not over-reject genuine error-based SQLi."""
        agent = _make_agent()
        baseline = "<html><body>First name: admin</body></html>"
        error_body = "You have an error in your SQL syntax; check your MySQL server"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=error_body)
        )
        synth = {
            "payload": "1'",
            "indicator_type": "error_string",
            "expected_indicator": "error in your SQL syntax",
        }
        verified, observed = await agent._sqli_phase5_verify(
            _make_page(), "id", synth, {"length": 100, "body": baseline}
        )
        assert verified is True
        assert "error in your SQL syntax" in observed

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

    @pytest.mark.asyncio
    async def test_union_marker_in_sql_escaped_echo_rejected(self) -> None:
        """FIX 4: a sink that SQL-backslash-escapes the echoed input (DVWA
        xss_s/high mtxMessage, csrf/test_credentials username) turns the
        payload's quotes into \\' so a verbatim replace(payload) misses and the
        alphanumeric marker falsely 'survives'. Normalising body AND payload
        through the same de-escape pipeline blanks the echo, so it is correctly
        recognised as reflection, not extracted data."""
        agent = _make_agent()
        payload = "test' UNION SELECT 'CLINKZUNIONMARKER42',NULL-- -"
        escaped = payload.replace("'", "\\'")  # addslashes / mysqli_real_escape_string
        echo_body = f"<pre>Wrong password for '{escaped}'</pre>"
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

    def test_marker_echo_guard_escaping_robust(self) -> None:
        """Unit-level: the de-escape guard rejects an SQL-escaped echo but lets a
        genuine data-row marker through."""
        payload = "x' UNION SELECT 'CLINKZMARK',NULL-- -"
        marker = "CLINKZMARK"
        escaped_echo = (
            f"<pre>Wrong password for '{payload.replace(chr(39), chr(92) + chr(39))}'</pre>"
        )
        assert ExploitAgent._marker_only_in_payload_echo(escaped_echo, payload, marker) is True
        data_row = f"<pre>ID: {payload}<br />First name: {marker}<br /></pre>"
        assert ExploitAgent._marker_only_in_payload_echo(data_row, payload, marker) is False


# ===========================================================================
# Cookie injection vector (DVWA blind-SQLi ``high``: $id = $_COOKIE['id'])
# ===========================================================================


class TestCookieInjectionVector:
    """The cookie carrier + on-demand harvest, and honesty through the carrier."""

    def test_effective_cookies_overlays_without_mutating_session(self) -> None:
        agent = _make_agent()
        agent._session_cookies = {"PHPSESSID": "abc", "security": "high"}
        eff = agent._effective_cookies({"id": "payload"})
        assert eff == {"PHPSESSID": "abc", "security": "high", "id": "payload"}
        # The ambient jar is never mutated by an override.
        assert "id" not in agent._session_cookies

    @pytest.mark.asyncio
    async def test_cookie_carrier_url_encodes_and_keeps_session_ambient(self) -> None:
        """``_send_probe`` on a cookie-vector param carries the URL-encoded payload
        in one cookie, leaving session/auth cookies ambient."""
        agent = _make_agent()
        agent._session_cookies = {"PHPSESSID": "abc", "security": "high"}
        captured: dict[str, Any] = {}

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            captured["url"] = url
            captured["params"] = params
            captured["cookie_overrides"] = cookie_overrides
            return _HTTPResponse(status=200, body="ok")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page(url="http://example.com/vulnerabilities/sqli_blind/")
        payload = "1' AND 1=1 -- -"
        await agent._send_probe(page, f"{_COOKIE_VECTOR_PREFIX}id", payload)
        assert captured["params"] == {}  # cookie is the sole carrier, no query injected
        assert captured["cookie_overrides"] == {"id": quote(payload, safe="")}
        assert agent._session_cookies == {"PHPSESSID": "abc", "security": "high"}

    @pytest.mark.asyncio
    async def test_harvest_discovers_non_session_cookie_from_setter(self) -> None:
        """A cookie-setter form linked from the page yields its non-session cookie
        name as an injection vector; session cookies are excluded."""
        agent = _make_agent()
        agent._session_cookies = {"PHPSESSID": "abc", "security": "low"}

        setter_form = (
            '<form method="POST" action="#">'
            '<input type="text" name="id">'
            '<input type="submit" name="Submit" value="Submit"></form>'
        )

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            if url.endswith("cookie-input.php"):
                return _HTTPResponse(status=200, body=setter_form)
            return _HTTPResponse(status=200, body="")

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            # Setter sets the app cookie AND re-asserts a session cookie; only the
            # former is injectable.
            return _HTTPResponse(
                status=200, body="ok", headers={"Set-Cookie": "id=clinkz, security=low"}
            )

        agent._http_get = fake_get  # type: ignore[method-assign]
        agent._http_post = fake_post  # type: ignore[method-assign]
        body = '<a href="#" onclick="popUp(\'cookie-input.php\')">change your ID</a>'
        names = await agent._harvest_injectable_cookies(
            "http://example.com/vulnerabilities/sqli_blind/", body
        )
        assert names == ["id"]

    @pytest.mark.asyncio
    async def test_no_cookie_setter_link_yields_no_harvest(self) -> None:
        """A page with no cookie-setter reference triggers no harvest HTTP."""
        agent = _make_agent()
        called = False

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            nonlocal called
            called = True
            return _HTTPResponse(status=200, body="")

        agent._http_get = fake_get  # type: ignore[method-assign]
        names = await agent._harvest_injectable_cookies(
            "http://example.com/x", "<html><body>no setter here</body></html>"
        )
        assert names == []
        assert called is False

    @pytest.mark.asyncio
    async def test_cookie_carrier_confirms_boolean_blind(self) -> None:
        """Phase 5 confirms a boolean-blind cookie injection: TRUE ~ baseline,
        FALSE diverges — carried entirely in the cookie."""
        agent = _make_agent()

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            val = unquote(cookie_overrides["id"]) if cookie_overrides else ""
            if val == "1" or "1=1" in val:  # exists
                return _HTTPResponse(status=200, body="X" * 100)
            return _HTTPResponse(status=200, body="X" * 106)  # missing (diverged)

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page(url="http://example.com/vulnerabilities/sqli_blind/")
        synth = {
            "payload": "1' AND 1=1-- -",
            "control_payload": "1' AND 1=2-- -",
            "indicator_type": "content_diff",
        }
        verified, observed = await agent._sqli_phase5_verify(
            page, f"{_COOKIE_VECTOR_PREFIX}id", synth, {"length": 100, "body": "X" * 100}
        )
        assert verified is True, observed

    @pytest.mark.asyncio
    async def test_reflected_cookie_echo_does_not_confirm(self) -> None:
        """A cookie value merely echoed in the body must NOT confirm SQLi — the
        escaping-robust reflection guard applies unchanged through the carrier."""
        agent = _make_agent()
        marker = "CLINKZUNIONMARKER99"

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            val = unquote(cookie_overrides["id"]) if cookie_overrides else ""
            # 2xx page that reflects the (decoded) cookie value verbatim.
            return _HTTPResponse(status=200, body=f"<p>User ID: {val}</p>")

        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page(url="http://example.com/vulnerabilities/sqli_blind/")
        synth = {
            "payload": f"1' UNION SELECT {marker},NULL-- -",
            "indicator_type": "union_data",
            "expected_indicator": marker,
        }
        verified, observed = await agent._sqli_phase5_verify(
            page, f"{_COOKIE_VECTOR_PREFIX}id", synth, {"length": 12, "body": "<p>User ID: 1</p>"}
        )
        assert verified is False
        assert "reflection" in observed.lower()


# ===========================================================================
# Session-indirection vector (DVWA SQLi high — cross-request inject-and-trigger)
# ===========================================================================


_SETTER = "http://example.com/vulnerabilities/sqli/session-input.php"
_TRIGGER = "http://example.com/vulnerabilities/sqli/"
_SETTER_FORM = (
    '<form action="#" method="POST">Session ID: '
    '<input type="text" name="id">'
    '<input type="submit" name="Submit" value="Submit"></form>'
)


class TestSessionCarrier:
    """The carrier writes via the setter and observes ONLY the trigger."""

    @pytest.mark.asyncio
    async def test_posts_setter_then_returns_trigger_response(self) -> None:
        agent = _make_agent()
        posted: dict[str, Any] = {}

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            posted["url"] = url
            posted["data"] = dict(data)
            # The setter's OWN response echoes the payload — must be discarded.
            return _HTTPResponse(status=200, body="Session ID: SETTER-ECHO-PAYLOAD")

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            return _HTTPResponse(status=200, body="TRIGGER-BODY")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page(url=_TRIGGER, params=[])
        resp = await agent._session_send_probe(page, _SETTER, "id", "PAYLOAD")

        assert posted["url"] == _SETTER
        assert posted["data"]["id"] == "PAYLOAD"
        # The observation point is the trigger, never the setter's self-echo.
        assert resp.body == "TRIGGER-BODY"
        assert "SETTER-ECHO" not in resp.body

    @pytest.mark.asyncio
    async def test_send_probe_dispatches_session_location_to_carrier(self) -> None:
        agent = _make_agent()
        page = _make_page(url=_TRIGGER, params=[])
        page.session_vectors = [SessionVector(setter_url=_SETTER, field="id")]
        seen: dict[str, Any] = {}

        async def fake_carrier(pg, setter_url, field, value):  # type: ignore[no-untyped-def]
            seen.update(setter_url=setter_url, field=field, value=value)
            return _HTTPResponse(status=200, body="T")

        agent._session_send_probe = fake_carrier  # type: ignore[method-assign]
        resp = await agent._send_probe(page, f"{_SESSION_VECTOR_PREFIX}id", "PAYLOAD")
        assert seen == {"setter_url": _SETTER, "field": "id", "value": "PAYLOAD"}
        assert resp.body == "T"

    @pytest.mark.asyncio
    async def test_send_probe_session_without_vector_fetches_trigger_unchanged(self) -> None:
        """A session param with no established vector degrades to a plain GET."""
        agent = _make_agent()
        page = _make_page(url=_TRIGGER, params=[])  # no session_vectors
        got: dict[str, Any] = {}

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            got["url"] = url
            return _HTTPResponse(status=200, body="TRIG")

        agent._http_get = fake_get  # type: ignore[method-assign]
        resp = await agent._send_probe(page, f"{_SESSION_VECTOR_PREFIX}id", "X")
        assert got["url"] == _TRIGGER
        assert resp.body == "TRIG"

    @pytest.mark.asyncio
    async def test_cached_form_carrier_includes_benign_siblings(self) -> None:
        """With the setter form cached (post-discovery), the carrier submits the
        payload field plus benign siblings and returns the trigger response."""
        agent = _make_agent()
        form = {
            "action": "#",
            "method": "POST",
            "fields": [
                {"name": "id", "type": "text"},
                {"name": "Submit", "type": "submit", "value": "Submit"},
            ],
        }
        agent._session_form_cache[_SETTER] = (_SETTER, form)
        posted: dict[str, Any] = {}

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            posted["url"] = url
            posted["data"] = dict(data)
            return _HTTPResponse(status=200, body="Session ID: PWN")

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            return _HTTPResponse(status=200, body="TRIGGER")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = _make_page(url=_TRIGGER, params=[])
        resp = await agent._session_send_probe(page, _SETTER, "id", "PWN")
        assert posted["url"] == _SETTER
        assert posted["data"]["id"] == "PWN"
        assert "Submit" in posted["data"]  # benign sibling carried through
        assert resp.body == "TRIGGER"


class TestSessionLinkGate:
    """The benign-marker link gate proves the setter write reaches the trigger."""

    @pytest.mark.asyncio
    async def test_establishes_vector_when_marker_roundtrips(self) -> None:
        agent = _make_agent()
        state = {"id": "", "trigger": "<pre>ID: </pre>"}

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            if url.endswith("session-input.php"):
                return _HTTPResponse(status=200, body=_SETTER_FORM)
            # Trigger reflects the current session id (the data channel).
            return _HTTPResponse(status=200, body=f"<pre>ID: {state['id']}</pre>")

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            state["id"] = data.get("id", "")
            return _HTTPResponse(status=200, body="ok")

        agent._http_get = fake_get  # type: ignore[method-assign]
        agent._http_post = fake_post  # type: ignore[method-assign]
        vectors = await agent._probe_session_setter(_SETTER, _TRIGGER, "<pre>ID: </pre>")
        assert [v.field for v in vectors] == ["id"]
        assert vectors[0].setter_url == _SETTER
        # The setter's parsed form is cached for the carrier.
        assert _SETTER in agent._session_form_cache

    @pytest.mark.asyncio
    async def test_rejects_when_marker_does_not_reach_trigger(self) -> None:
        """A setter whose write does not feed the trigger yields no vector."""
        agent = _make_agent()

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            if url.endswith("session-input.php"):
                return _HTTPResponse(status=200, body=_SETTER_FORM)
            # Trigger NEVER reflects the marker (no data flow).
            return _HTTPResponse(status=200, body="<pre>ID: static</pre>")

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            return _HTTPResponse(status=200, body="ok")

        agent._http_get = fake_get  # type: ignore[method-assign]
        agent._http_post = fake_post  # type: ignore[method-assign]
        vectors = await agent._probe_session_setter(_SETTER, _TRIGGER, "<pre>ID: static</pre>")
        assert vectors == []

    @pytest.mark.asyncio
    async def test_harvest_end_to_end_on_dvwa_shaped_trigger(self) -> None:
        agent = _make_agent()
        state = {"id": ""}

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            if url.endswith("session-input.php"):
                return _HTTPResponse(status=200, body=_SETTER_FORM)
            return _HTTPResponse(status=200, body=f"<pre>ID: {state['id']}</pre>")

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            state["id"] = data.get("id", "")
            return _HTTPResponse(status=200, body="ok")

        agent._http_get = fake_get  # type: ignore[method-assign]
        agent._http_post = fake_post  # type: ignore[method-assign]
        trigger_body = (
            '<a href="#" onclick="popUp(\'session-input.php\')">change ID</a><pre>ID: 1</pre>'
        )
        vectors = await agent._harvest_session_vectors(_TRIGGER, trigger_body)
        assert [v.field for v in vectors] == ["id"]
        assert vectors[0].setter_url == _SETTER

    @pytest.mark.asyncio
    async def test_establishes_via_divergence_when_echo_is_row_gated(self) -> None:
        """DVWA-high shape: the ``ID:`` echo is inside ``while($row=...)``.

        A non-matching benign value (the random marker) renders NOTHING, so the
        reflection signal can never fire; the benign matching-vs-non-matching
        divergence must still establish the channel. This is the live-verified
        gap the marker-only gate missed on the real target.
        """
        agent = _make_agent()
        state = {"id": ""}

        def render() -> str:
            # Row-gated: only a matching id ('1') renders a result block; any
            # other value (the random marker, a big id) renders no echo at all.
            if state["id"] == "1":
                return "<html><pre>ID: 1<br />First name: admin<br />Surname: admin</pre></html>"
            return "<html><body>Nothing to display</body></html>"

        async def fake_get(url, params, cookie_overrides=None):  # type: ignore[no-untyped-def]
            if url.endswith("session-input.php"):
                return _HTTPResponse(status=200, body=_SETTER_FORM)
            return _HTTPResponse(status=200, body=render())

        async def fake_post(url, data, cookie_overrides=None):  # type: ignore[no-untyped-def]
            state["id"] = data.get("id", "")
            return _HTTPResponse(status=200, body="Session ID: " + state["id"])

        agent._http_get = fake_get  # type: ignore[method-assign]
        agent._http_post = fake_post  # type: ignore[method-assign]
        baseline = "<html><body>Nothing to display</body></html>"
        vectors = await agent._probe_session_setter(_SETTER, _TRIGGER, baseline)
        assert [v.field for v in vectors] == ["id"]
        assert _SETTER in agent._session_form_cache


class TestSessionPhase5OnTrigger:
    """Phase 5 observes the trigger; the ``ID: {payload}`` echo never confirms."""

    @pytest.mark.asyncio
    async def test_union_confirms_on_genuine_trigger_data(self) -> None:
        agent = _make_agent()
        page = _make_page(url=_TRIGGER, params=[])
        payload = f"1' UNION SELECT '{_SQLI_UNION_MARKER}',NULL-- -"
        # Trigger echoes the payload in ID AND returns the marker as query DATA.
        body = f"<pre>ID: {payload}<br />First name: {_SQLI_UNION_MARKER}<br />Surname: x</pre>"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        synth = {
            "payload": payload,
            "indicator_type": "union_data",
            "expected_indicator": _SQLI_UNION_MARKER,
        }
        verified, _obs = await agent._sqli_phase5_verify(
            page,
            f"{_SESSION_VECTOR_PREFIX}id",
            synth,
            {"length": 44, "body": "<pre>ID: 1<br />First name: admin</pre>"},
        )
        assert verified is True

    @pytest.mark.asyncio
    async def test_union_rejected_when_marker_only_in_id_echo(self) -> None:
        """The load-bearing phantom guard: reflection in ID: {payload} is not data."""
        agent = _make_agent()
        page = _make_page(url=_TRIGGER, params=[])
        payload = f"1' UNION SELECT '{_SQLI_UNION_MARKER}',NULL-- -"
        # Trigger reflects the payload (marker appears ONLY inside the ID echo);
        # the query result is unchanged (admin) — no genuine data cell.
        body = f"<pre>ID: {payload}<br />First name: admin<br />Surname: admin</pre>"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        synth = {
            "payload": payload,
            "indicator_type": "union_data",
            "expected_indicator": _SQLI_UNION_MARKER,
        }
        verified, observed = await agent._sqli_phase5_verify(
            page,
            f"{_SESSION_VECTOR_PREFIX}id",
            synth,
            {"length": 44, "body": "<pre>ID: 1<br />First name: admin</pre>"},
        )
        assert verified is False
        assert "reflection" in observed.lower()


class TestSessionMethodologyIntegration:
    """_test_sqli's third loop over page.session_vectors, end to end."""

    @pytest.mark.asyncio
    async def test_cross_request_error_based_confirms_with_session_label(self) -> None:
        """A quote written to the session slot errors the trigger query → finding."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))  # silent → deterministic
        agent._methodology_llm = agent.llm
        agent._run_sqlmap = AsyncMock(return_value=False)  # type: ignore[method-assign]

        async def fake_probe(_page, _param, value):  # type: ignore[no-untyped-def]
            # The trigger reflects the session value and runs the query on it.
            if "'" in value or '"' in value:
                return _HTTPResponse(
                    status=200,
                    body=(
                        f"<pre>ID: {value}</pre>You have an error in your SQL syntax; "
                        "check the manual that corresponds to your MySQL server version"
                    ),
                )
            return _HTTPResponse(
                status=200,
                body=f"<pre>ID: {value}<br />First name: admin<br />Surname: admin</pre>",
            )

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page(url=_TRIGGER, params=[])
        page.input_params = []  # param-less trigger — the session vector is the only path
        page.session_vectors = [SessionVector(setter_url=_SETTER, field="id")]
        findings = await agent._test_sqli(page)
        assert len(findings) == 1
        assert "id (session)" in findings[0].description
        assert "session" in findings[0].title.lower()
        joined = " ".join(findings[0].evidence)
        assert "injection_type=error_based" in joined

    @pytest.mark.asyncio
    async def test_echo_only_trigger_does_not_confirm(self) -> None:
        """A trigger that only reflects ID: {payload} (no query effect) → non-finding."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._run_sqlmap = AsyncMock(return_value=False)  # type: ignore[method-assign]

        async def fake_probe(_page, _param, value):  # type: ignore[no-untyped-def]
            # Reflects the value in ID (so phase 1 sees divergence) but the query
            # result never changes and no DB error surfaces — pure reflection.
            return _HTTPResponse(
                status=200,
                body=f"<pre>ID: {value}<br />First name: admin<br />Surname: admin</pre>",
            )

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page(url=_TRIGGER, params=[])
        page.input_params = []
        page.session_vectors = [SessionVector(setter_url=_SETTER, field="id")]
        findings = await agent._test_sqli(page)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_session_vector_emits_nothing(self) -> None:
        """A param-less trigger with no established vector yields no session finding."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>static</html>")
        )
        page = _make_page(url=_TRIGGER, params=[])
        page.input_params = []  # no params, no session_vectors → nothing to probe
        findings = await agent._test_sqli(page)
        assert findings == []


class TestSessionPhase6Emission:
    def test_finding_carries_clean_session_label(self) -> None:
        agent = _make_agent()
        result = SQLiMethodologyResult(
            phases_completed=6,
            dialect=SQLDialect.MYSQL,
            primitives=InjectionPrimitives(quote_chars=["'"], comment_syntax=["-- -"]),
            injection_type=InjectionType.UNION_BASED,
            synthesized_payload=f"1' UNION SELECT '{_SQLI_UNION_MARKER}',NULL-- -",
            expected_indicator=_SQLI_UNION_MARKER,
            indicator_type="union_data",
            indicator_observed="matched union marker",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._sqli_phase6_emit(_TRIGGER, f"{_SESSION_VECTOR_PREFIX}id", result)
        # The internal sentinel is stripped; the report shows a clean name.
        assert "\x00" not in finding.title
        assert "\x00" not in finding.description
        assert "id (session)" in finding.description
        assert "session value" in finding.title.lower()
        assert finding.severity.value == "high"
