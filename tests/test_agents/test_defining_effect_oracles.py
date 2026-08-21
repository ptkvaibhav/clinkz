"""The three oracles rebuilt on their defining effects.

Specification and live measurements:
:doc:`docs/methodology/defining-effect-oracles`.

Each test here pins the property that made the old oracle fail its own control
arm — never the fix's incidental shape. The distinction matters because all
three failures were on targets that really are vulnerable: a test that merely
asserted "cmdi confirms at DVWA low" passed against every broken version.
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._control_arm import is_minted_marker, strip_shell_separators
from clinkz.agents._methodology_helpers import BaselineProbe
from clinkz.agents.exploit import (
    _CMDI_TIME_MIN_DELTA,
    _CMDI_TIME_REPEATS,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    CMDIExecutionType,
    ShellPrimitives,
    ShellType,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="defining-effect-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="defining-effect-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _baseline(value: str = "127.0.0.1") -> BaselineProbe:
    return BaselineProbe(
        variant="original",
        value=value,
        status=200,
        length=100,
        body_hash="0" * 16,
        time_ms=10.0,
    )


def _page() -> PageAnalysis:
    return PageAnalysis(
        url="http://example.com/vulnerabilities/exec/",
        body="",
        status=200,
        input_params=["ip"],
    )


# ===========================================================================
# 1. CMDI — the marker channel, and a time channel that reads its own baseline
# ===========================================================================


class TestCmdiPrefersTheProvenMarkerChannel:
    """Phase 1 proved the primitive; phase 4 must not ask a model to re-decide."""

    @pytest.mark.asyncio
    async def test_phase4_builds_the_marker_payload_without_the_llm(self) -> None:
        agent = _make_agent()
        agent._llm_analyze = AsyncMock(  # type: ignore[method-assign]
            return_value='{"payload": "x;sleep 5", "expected_indicator": "delay", '
            '"indicator_type": "time_delta", "rationale": "blind"}'
        )
        primitives = ShellPrimitives(separators=[";", "|"], marker_separator="|")

        synth = await agent._cmdi_phase4_synthesize_payload(
            execution_type=CMDIExecutionType.BLIND_TIME,
            shell_type=ShellType.BASH,
            primitives=primitives,
            original_baseline=_baseline(),
        )

        assert synth is not None
        assert synth["indicator_type"] == "stdout_reflection"
        assert synth["payload"].startswith("127.0.0.1|echo clinkzcmdi")
        assert is_minted_marker(synth["expected_indicator"])
        agent._llm_analyze.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_proven_separator_still_asks_the_model(self) -> None:
        """The pre-emption is a floor on evidence, not a removal of the checkpoint."""
        agent = _make_agent()
        agent._llm_analyze = AsyncMock(  # type: ignore[method-assign]
            return_value='{"payload": "x;sleep 5", "expected_indicator": "delay", '
            '"indicator_type": "time_delta", "rationale": "blind"}'
        )
        primitives = ShellPrimitives(separators=[";"], marker_separator=None)
        await agent._cmdi_phase4_synthesize_payload(
            execution_type=CMDIExecutionType.BLIND_TIME,
            shell_type=ShellType.BASH,
            primitives=primitives,
            original_baseline=_baseline(),
        )
        agent._llm_analyze.assert_awaited()


class TestCmdiTimeChannelReadsItsOwnBaseline:
    """An absolute threshold confirmed on DVWA's untouched 4.04s baseline."""

    @pytest.mark.asyncio
    async def test_a_uniformly_slow_endpoint_never_confirms(self) -> None:
        """``ping -c 4`` — every request takes ~4s, payload or not.

        This is the exact shape that produced six control-arm kills: with a 4.0s
        absolute threshold the BASELINE confirmed. A paired differential sees a
        delta near zero and refuses.
        """
        agent = _make_agent()

        async def slow(*_a: object, **_k: object) -> _HTTPResponse:
            return _HTTPResponse(status=200, body="pong")

        agent._send_probe = AsyncMock(side_effect=slow)  # type: ignore[method-assign]
        verified, observed = await agent._cmdi_verify_time_delta(
            _page(),
            "ip",
            "127.0.0.1;sleep 5",
            _baseline(),
        )
        assert verified is False
        assert "not reproduced" in observed
        # Both arms are rendered, so the refusal is auditable.
        assert observed.count("base=") == _CMDI_TIME_REPEATS

    @pytest.mark.asyncio
    async def test_a_real_sleep_confirms_and_shows_every_pair(self) -> None:
        agent = _make_agent()
        calls: list[str] = []

        async def timed(_page: Any, _param: str, value: str, **_k: object) -> _HTTPResponse:
            calls.append(value)
            # Simulated cost: the sleep payload takes materially longer.
            import time as _t

            _t.sleep(0.05 if "sleep" in value else 0.0)
            return _HTTPResponse(status=200, body="pong")

        agent._send_probe = AsyncMock(side_effect=timed)  # type: ignore[method-assign]
        # Pin the margin to the simulated cost rather than the shipped seconds.
        import clinkz.agents.exploit as exploit_mod

        original = exploit_mod._CMDI_TIME_MIN_DELTA
        exploit_mod._CMDI_TIME_MIN_DELTA = 0.02
        try:
            verified, observed = await agent._cmdi_verify_time_delta(
                _page(),
                "ip",
                "127.0.0.1;sleep 5",
                _baseline(),
            )
        finally:
            exploit_mod._CMDI_TIME_MIN_DELTA = original

        assert verified is True
        assert "reproduced" in observed
        # Interleaved: baseline, payload, baseline, payload, ...
        assert len(calls) == _CMDI_TIME_REPEATS * 2
        assert calls[0::2] == ["127.0.0.1"] * _CMDI_TIME_REPEATS
        assert calls[1::2] == ["127.0.0.1;sleep 5"] * _CMDI_TIME_REPEATS

    @pytest.mark.asyncio
    async def test_one_bad_repeat_refuses_the_whole_differential(self) -> None:
        """Reproducible, not large. A single non-reproducing pair is fatal."""
        agent = _make_agent()
        seen = {"n": 0}

        async def flaky(_page: Any, _param: str, value: str, **_k: object) -> _HTTPResponse:
            import time as _t

            seen["n"] += 1
            # Third payload probe (call 6) is fast — the delta collapses.
            if "sleep" in value and seen["n"] < 6:
                _t.sleep(0.05)
            return _HTTPResponse(status=200, body="pong")

        agent._send_probe = AsyncMock(side_effect=flaky)  # type: ignore[method-assign]
        import clinkz.agents.exploit as exploit_mod

        original = exploit_mod._CMDI_TIME_MIN_DELTA
        exploit_mod._CMDI_TIME_MIN_DELTA = 0.02
        try:
            verified, _ = await agent._cmdi_verify_time_delta(
                _page(),
                "ip",
                "127.0.0.1;sleep 5",
                _baseline(),
            )
        finally:
            exploit_mod._CMDI_TIME_MIN_DELTA = original
        assert verified is False

    def test_the_margin_is_below_the_injected_sleep(self) -> None:
        """Jitter must not break a genuine differential, nor rescue a flat one."""
        from clinkz.agents.exploit import _CMDI_CONFIRM_SLEEP

        assert 0 < _CMDI_TIME_MIN_DELTA < _CMDI_CONFIRM_SLEEP


class TestCmdiPhase1ReportsTheProvenSeparator:
    """The measurement has to reach phase 4, or it may as well not exist."""

    @pytest.mark.asyncio
    async def test_the_carrying_separator_is_returned(self) -> None:
        agent = _make_agent()

        async def echo_only_for_pipe(
            _page: Any, _param: str, value: str, **_k: object
        ) -> _HTTPResponse:
            marker = re.search(r"clinkzcmd\d+", value)
            if "|echo " in value and marker:
                # Execution: the marker alone, scaffold consumed.
                return _HTTPResponse(status=200, body=f"<pre>{marker.group(0)}</pre>")
            return _HTTPResponse(status=200, body="<pre>inert</pre>")

        agent._send_probe = AsyncMock(side_effect=echo_only_for_pipe)  # type: ignore[method-assign]
        is_candidate, _baselines, separator = await agent._cmdi_phase1_injection_point(
            _page(), "ip"
        )
        assert is_candidate is True
        assert separator == "|"

    @pytest.mark.asyncio
    async def test_a_reflective_param_reports_no_separator(self) -> None:
        """Whole-payload reflection is not execution, and must not be recorded."""
        agent = _make_agent()

        async def reflect(_page: Any, _param: str, value: str, **_k: object) -> _HTTPResponse:
            return _HTTPResponse(status=200, body=f"you said: {value}")

        agent._send_probe = AsyncMock(side_effect=reflect)  # type: ignore[method-assign]
        _is_candidate, _baselines, separator = await agent._cmdi_phase1_injection_point(
            _page(), "ip"
        )
        assert separator is None

    @pytest.mark.asyncio
    async def test_the_sweep_runs_even_when_a_bare_separator_diverged(self) -> None:
        """It used to be skipped exactly then — which is every DVWA level."""
        agent = _make_agent()
        bodies: list[str] = []

        async def diverging(_page: Any, _param: str, value: str, **_k: object) -> _HTTPResponse:
            bodies.append(value)
            marker = re.search(r"clinkzcmd\d+", value)
            if marker:
                return _HTTPResponse(status=200, body=marker.group(0))
            # Every bare separator variant diverges from the original.
            return _HTTPResponse(status=200, body="x" * (100 + len(value)))

        agent._send_probe = AsyncMock(side_effect=diverging)  # type: ignore[method-assign]
        _is_candidate, _baselines, separator = await agent._cmdi_phase1_injection_point(
            _page(), "ip"
        )
        assert separator is not None
        assert any("echo clinkzcmd" in b for b in bodies)


class TestCmdiControlStaysInert:
    """The control has to keep the shape and lose only the primitive."""

    def test_stripping_separators_leaves_the_scaffold(self) -> None:
        stripped = strip_shell_separators("127.0.0.1|echo clinkzcmdi123")
        assert stripped == "127.0.0.1echo clinkzcmdi123"
        assert "|" not in stripped
        assert "echo clinkzcmdi123" in stripped


# ===========================================================================
# 2. FILE UPLOAD — an indicator the interpreter must COMPUTE
# ===========================================================================


class TestUploadIndicatorIsComputedNotWritten:
    """ "The nonce came back" cannot tell execution from static serving."""

    def test_the_indicator_never_appears_in_the_uploaded_bytes(self) -> None:
        """The whole oracle, in one assertion.

        PHP emits text outside ``<?php ?>`` verbatim, so an indicator written
        into the file comes back from a server that merely SERVES it. Four ladder
        findings died on that. The product of two factors appears only if
        something evaluated them.
        """
        agent = _make_agent()
        for _ in range(50):
            indicator, source = agent._upload_execution_canary({})
            assert indicator not in source, (
                f"indicator {indicator!r} is present in the uploaded source {source!r} — "
                "static serving would reproduce it and the control could not refuse"
            )
            assert is_minted_marker(indicator)

    def test_the_source_computes_exactly_that_indicator(self) -> None:
        agent = _make_agent()
        for _ in range(50):
            indicator, source = agent._upload_execution_canary({})
            factors = re.search(r"\((\d+)\*(\d+)\)", source)
            assert factors, source
            product = int(factors.group(1)) * int(factors.group(2))
            assert indicator == f"clinkzexec{product}"

    def test_the_product_is_parenthesised(self) -> None:
        """``'exec'.554*242`` makes PHP read ``.554`` as a float and fail."""
        agent = _make_agent()
        _indicator, source = agent._upload_execution_canary({})
        assert re.search(r"\.\(\d+\*\d+\)", source), source

    def test_a_caller_supplied_canary_is_honoured_with_an_explicit_source(self) -> None:
        """The control arm's shape: it asks for nothing to be appended."""
        agent = _make_agent()
        indicator, source = agent._upload_execution_canary(
            {"canary": "clinkzexec999", "canary_source": ""}
        )
        assert indicator == "clinkzexec999"
        assert source == ""

    def test_a_bare_canary_is_ignored_and_the_pair_is_minted(self) -> None:
        """The deterministic fallbacks pass one; honouring it re-breaks the oracle.

        ``_direct_execution_synth`` writes ``<?php echo '<canary>'; phpinfo(); ?>``
        and puts that canary in ``synth``. Reading it back as the indicator makes
        the confirming observation a string that IS in the uploaded bytes — the
        exact property the rebuild removed — for every LLM-silent run.
        """
        agent = _make_agent()
        indicator, source = agent._upload_execution_canary({"canary": "clinkzupload12345"})
        assert indicator != "clinkzupload12345"
        assert source, "the computing source must still be appended"
        assert indicator not in source

    def test_two_mintings_do_not_collide(self) -> None:
        agent = _make_agent()
        seen = {agent._upload_execution_canary({})[0] for _ in range(40)}
        assert len(seen) > 20, "indicator entropy is too low to attribute an observation"
