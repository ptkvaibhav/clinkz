"""Unit tests for the adaptive command-injection methodology phases.

Each phase is exercised in isolation with mocked ``_send_probe`` and LLM:

    Phase 1 (injection-point mapping)   — separator-variant probes vs baseline
    Phase 2 (shell fingerprinting)      — OS detection + primitive map
    Phase 3 (execution-type ranking)    — deterministic, on the phase-2 probes
    Phase 4 (payload synthesis)         — LLM JSON parsing + fallback table
    Phase 5 (verification)              — indicator-type matching logic

Plus an end-to-end run that drives all six phases through one ``page``.
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._plan_ranking import attempt_window, rank_cmdi
from clinkz.agents.exploit import (
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import (
    CMDIExecutionType,
    CMDIMethodologyResult,
    ShellPrimitives,
    ShellType,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-cmdi-test",
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
        engagement_id="methodology-cmdi-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _make_page(
    url: str = "http://example.com/exec?cmd=ls", params: list[str] | None = None
) -> PageAnalysis:
    return PageAnalysis(
        url=url,
        body="",
        status=200,
        input_params=params or ["cmd"],
    )


# ===========================================================================
# Phase 1 — Injection-point mapping
# ===========================================================================


class TestPhase1InjectionPointMapping:
    """Separator-variant probes must mark divergent params as candidates."""

    @pytest.mark.asyncio
    async def test_no_divergence_not_a_candidate(self) -> None:
        agent = _make_agent()
        body = "<html><body>output</body></html>"
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body=body)
        )
        page = _make_page()
        is_candidate, baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        assert is_candidate is False
        # 6 separator baselines + 5 echo-canary confirmation probes. The canary
        # sweep now runs UNCONDITIONALLY (it used to be skipped whenever a bare
        # separator diverged — i.e. on every DVWA level, which is where the
        # strongest primitive this class has went unrecorded), and it covers the
        # five separators measured to survive a tightening filter.
        assert len(baselines) == 11

    @pytest.mark.asyncio
    async def test_canary_echo_marks_candidate_when_base_is_inert(self) -> None:
        """DVWA-exec case: bare separators don't change the output (``ping <bad>``
        fails to stderr, which ``shell_exec`` drops), but an injected
        ``;echo <canary>`` reflects — so the echo-canary probe must still mark
        the param a candidate. This is the 76a9ead5 cmdi miss."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            m = re.search(r"echo (\w+)", value)
            if m:  # the injected echo executes — only the canary surfaces
                return _HTTPResponse(status=200, body=f"<pre>{m.group(1)}</pre>")
            return _HTTPResponse(status=200, body="<html>same</html>")  # inert base command

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, _baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        assert is_candidate is True

    @pytest.mark.asyncio
    async def test_pure_reflection_does_not_false_positive(self) -> None:
        """A param that echoes its whole value verbatim (a search box) must NOT
        be flagged by the canary probe: the literal ``echo <canary>`` is present,
        so no command actually ran. Bare separators are collapsed so the canary
        path is the one under test."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            # Strip separators (no divergence) but reflect the rest verbatim, so
            # an `echo <canary>` payload shows up literally in the body.
            collapsed = re.sub(r"[;&|`$()]", "", value)
            return _HTTPResponse(status=200, body=f"<p>you said: {collapsed}</p>")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, _baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        assert is_candidate is False

    @pytest.mark.asyncio
    async def test_separator_changes_response_marks_candidate(self) -> None:
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if ";" in value or "&&" in value or "$()" in value or "`" in value:
                return _HTTPResponse(status=200, body="x" * 500)
            return _HTTPResponse(status=200, body="x" * 100)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        is_candidate, _baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        assert is_candidate is True

    @pytest.mark.asyncio
    async def test_baselines_carry_status_length_hash_time(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="content")
        )
        page = _make_page()
        _is_candidate, baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        for b in baselines:
            assert isinstance(b.status, int)
            assert isinstance(b.length, int)
            assert isinstance(b.body_hash, str) and len(b.body_hash) == 16
            assert isinstance(b.time_ms, float)


# ===========================================================================
# Phase 2 — Shell classification + primitive enumeration
# ===========================================================================


class TestPhase2ShellClassification:
    """Each OS-detection signature must classify correctly."""

    def test_classify_linux_from_uname_output(self) -> None:
        agent = _make_agent()
        body = "test\nLinux\n"
        assert agent._cmdi_classify_shell_from_body(body) == ShellType.BASH

    def test_classify_cmd_from_ver_output(self) -> None:
        agent = _make_agent()
        body = "test\r\nMicrosoft Windows [Version 10.0.19044.1234]\r\n"
        assert agent._cmdi_classify_shell_from_body(body) == ShellType.CMD

    def test_classify_bash_from_id_output(self) -> None:
        agent = _make_agent()
        body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        assert agent._cmdi_classify_shell_from_body(body) == ShellType.BASH

    def test_unknown_for_unrelated_body(self) -> None:
        agent = _make_agent()
        assert agent._cmdi_classify_shell_from_body("totally unrelated") == ShellType.UNKNOWN


class TestPhase2PrimitiveExtraction:
    """Separator / quote / substitution / time-channel enumeration."""

    @pytest.mark.asyncio
    async def test_separator_with_canary_echo_is_recognised(self) -> None:
        """If `;echo <canary>` reflects, the separator is confirmed."""
        agent = _make_agent()

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "Linux" in value:
                # OS detection fails — keep response identical.
                return _HTTPResponse(status=200, body="content")
            # Echo any canary back to the body so separators get confirmed.
            if "echo " in value:
                # Find the canary part after `echo `.
                import re

                m = re.search(r"echo (\w+)", value)
                if m:
                    return _HTTPResponse(status=200, body=f"out: {m.group(1)}")
            return _HTTPResponse(status=200, body="content")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page()
        # Build phase-1 baselines first.
        _candidate, baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        shell, primitives, _evidence = await agent._cmdi_phase2_fingerprint(page, "cmd", baselines)
        # All separators with `echo` payloads should land in `separators`.
        assert ";" in primitives.separators or "&&" in primitives.separators
        # Some substitution form should be confirmed via the canary echo.
        assert "$()" in primitives.substitution or "backtick" in primitives.substitution
        # No time channel was simulated.
        assert primitives.working_time_payload is None
        # Shell type may be UNKNOWN here (no OS-banner match).
        assert isinstance(shell, ShellType)

    @pytest.mark.asyncio
    async def test_no_separator_works_returns_empty(self) -> None:
        agent = _make_agent()
        # Every probe returns the exact same body — nothing diverges.
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="content")
        )
        page = _make_page()
        _candidate, baselines, _separator = await agent._cmdi_phase1_injection_point(page, "cmd")
        _shell, primitives, _evidence = await agent._cmdi_phase2_fingerprint(page, "cmd", baselines)
        assert primitives.separators == []
        assert primitives.substitution == []

    @pytest.mark.asyncio
    async def test_time_channel_detected_when_probe_delays(self) -> None:
        agent = _make_agent()

        # The phase-2 time-probe is the only `_send_probe` call wrapped
        # with a top-level `time.monotonic()` pair (everything else is
        # baselined through `baseline_probe`'s own timer). To make the
        # time-probe see a >=4s delta, we flip a flag inside the fake
        # probe whenever a sleep payload is sent, and have the stub
        # `monotonic()` return 5.0 from that point onward.
        state = {"sleeping": False}

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            if "sleep " in value or "timeout " in value:
                state["sleeping"] = True
            return _HTTPResponse(status=200, body="content")

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        from clinkz.agents import exploit as exploit_mod

        original_monotonic = exploit_mod.time.monotonic

        def fake_monotonic() -> float:
            return 5.0 if state["sleeping"] else 0.0

        exploit_mod.time.monotonic = fake_monotonic  # type: ignore[assignment]
        try:
            page = _make_page()
            _candidate, baselines, _separator = await agent._cmdi_phase1_injection_point(
                page, "cmd"
            )
            _shell, primitives, evidence = await agent._cmdi_phase2_fingerprint(
                page, "cmd", baselines
            )
        finally:
            exploit_mod.time.monotonic = original_monotonic  # type: ignore[assignment]
        assert primitives.working_time_payload is not None
        assert "time_probe" in evidence


# ===========================================================================
# Phase 3 — Execution-type ranking
# ===========================================================================


class TestPhase3ExecutionTypeRanking:
    """Phase 3 is deterministic here too.

    Replayed over the recorded corpus, the model and this ranking already agreed
    on the top-3 set 97.9% of the time and on the leading type 85.8%, and the
    ranking loses none of the 135 recorded command-injection confirmations — so
    inverting removes a variance source and costs nothing measurable.
    """

    def test_observed_command_output_supports_direct_exec(self) -> None:
        ranking = rank_cmdi(
            ShellType.BASH,
            ShellPrimitives(separators=[";"], substitution=["$()"]),
            {"os_probe": {"label": "uname", "classified": "bash"}},
        )
        assert ranking.ranked[0] == CMDIExecutionType.DIRECT_EXEC
        assert ranking.supported == frozenset({CMDIExecutionType.DIRECT_EXEC})

    def test_working_time_payload_supports_blind_time(self) -> None:
        ranking = rank_cmdi(
            ShellType.UNKNOWN,
            ShellPrimitives(separators=[";"], working_time_payload="test;sleep 5"),
            {},
        )
        assert ranking.ranked[0] == CMDIExecutionType.BLIND_TIME
        assert ranking.supported == frozenset({CMDIExecutionType.BLIND_TIME})

    def test_both_probes_support_both_channels(self) -> None:
        ranking = rank_cmdi(
            ShellType.BASH,
            ShellPrimitives(separators=[";"], working_time_payload="test;sleep 5"),
            {"os_probe": {"label": "uname", "classified": "bash"}},
        )
        assert ranking.supported == frozenset(
            {CMDIExecutionType.DIRECT_EXEC, CMDIExecutionType.BLIND_TIME}
        )
        assert list(ranking.ranked[:2]) == [
            CMDIExecutionType.DIRECT_EXEC,
            CMDIExecutionType.BLIND_TIME,
        ]

    def test_error_based_and_oob_are_ranked_but_never_supported(self) -> None:
        """Neither has a phase-2 observation of its own."""
        ranking = rank_cmdi(ShellType.SH, ShellPrimitives(separators=[";"]), {})
        assert CMDIExecutionType.ERROR_BASED in ranking.ranked
        assert CMDIExecutionType.BLIND_OOB in ranking.ranked
        assert ranking.supported == frozenset()

    def test_the_agent_prunes_oob_before_the_window(self) -> None:
        """The ranking states the fingerprint; whether a collaborator is wired
        up is a fact about the agent, so the prune lives at the call site — and
        running it first stops the tail slot being spent on a dropped type."""
        ranking = rank_cmdi(
            ShellType.BASH,
            ShellPrimitives(separators=[";"]),
            {"os_probe": {"label": "uname", "classified": "bash"}},
        )
        in_band = [t for t in ranking.ranked if t is not CMDIExecutionType.BLIND_OOB]
        window = attempt_window(in_band, ranking.supported)
        assert CMDIExecutionType.BLIND_OOB not in window
        assert window[0] == CMDIExecutionType.DIRECT_EXEC
        assert CMDIExecutionType.BLIND_TIME in window

    def test_the_same_fingerprint_always_ranks_the_same_way(self) -> None:
        args = (
            ShellType.BASH,
            ShellPrimitives(separators=[";", "|"], working_time_payload="x;sleep 5"),
            {"os_probe": {"label": "uname", "classified": "bash"}},
        )
        first = rank_cmdi(*args)
        assert all(rank_cmdi(*args) == first for _ in range(25))


# ===========================================================================
# Phase 4 — Payload synthesis
# ===========================================================================


class TestPhase4PayloadSynthesis:
    @pytest.mark.asyncio
    async def test_llm_synthesis_parsed(self) -> None:
        llm = _ScriptedLLM(
            answers=[
                '{"payload": "test;echo CLINKZ123", '
                '"expected_indicator": "CLINKZ123", '
                '"indicator_type": "stdout_reflection", '
                '"rationale": "echo canary"}'
            ]
        )
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        synth = await agent._cmdi_phase4_synthesize_payload(
            CMDIExecutionType.DIRECT_EXEC,
            ShellType.BASH,
            ShellPrimitives(separators=[";"]),
            baseline,
        )
        assert synth is not None
        assert synth["indicator_type"] == "stdout_reflection"
        assert "CLINKZ123" in synth["payload"]

    @pytest.mark.asyncio
    async def test_fallback_direct_exec_uses_canary(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        synth = await agent._cmdi_phase4_synthesize_payload(
            CMDIExecutionType.DIRECT_EXEC,
            ShellType.BASH,
            ShellPrimitives(separators=[";"]),
            baseline,
        )
        assert synth is not None
        assert synth["indicator_type"] == "stdout_reflection"
        assert "echo " in synth["payload"]
        assert synth["expected_indicator"]  # canary set

    @pytest.mark.asyncio
    async def test_fallback_blind_time_reuses_phase2_payload(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        synth = await agent._cmdi_phase4_synthesize_payload(
            CMDIExecutionType.BLIND_TIME,
            ShellType.BASH,
            ShellPrimitives(separators=[";"], working_time_payload="test;sleep 5"),
            baseline,
        )
        assert synth is not None
        assert synth["payload"] == "test;sleep 5"
        assert synth["indicator_type"] == "time_delta"

    @pytest.mark.asyncio
    async def test_fallback_blind_time_for_windows_uses_timeout(self) -> None:
        llm = _ScriptedLLM(answers=[""])
        agent = _make_agent(llm)
        agent._methodology_llm = llm
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        synth = await agent._cmdi_phase4_synthesize_payload(
            CMDIExecutionType.BLIND_TIME,
            ShellType.CMD,
            ShellPrimitives(separators=["&"]),
            baseline,
        )
        assert synth is not None
        assert "timeout" in synth["payload"]


# ===========================================================================
# Phase 5 — Verification
# ===========================================================================


class TestPhase5Verification:
    @pytest.mark.asyncio
    async def test_stdout_reflection_canary_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="output: CLINKZ123 ok")
        )
        synth = {
            "payload": "test;echo CLINKZ123",
            "indicator_type": "stdout_reflection",
            "expected_indicator": "CLINKZ123",
        }
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "cmd", synth, baseline)
        assert verified is True
        assert "CLINKZ123" in observed

    @pytest.mark.asyncio
    async def test_stdout_reflection_falls_back_to_id_pattern(self) -> None:
        """LLM-supplied indicator absent → user-shape regex still matches."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="uid=33(www-data) gid=33(www-data)")
        )
        synth = {
            "payload": "test;id",
            "indicator_type": "stdout_reflection",
            "expected_indicator": "totally_wrong_indicator",
        }
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "cmd", synth, baseline)
        assert verified is True
        assert "id" in observed.lower() or "uid=" in observed

    @pytest.mark.asyncio
    async def test_time_delta_verifies_on_a_delta_over_the_endpoints_own_baseline(
        self,
    ) -> None:
        """The time channel is a PAIRED differential, not an absolute threshold.

        This test used to pin one 5.00s reading against a 4.0s constant. That
        contract is the defect: DVWA's exec page runs ``ping -c 4`` and measures
        4.04s on the untouched baseline, so the oracle confirmed command
        injection on a request carrying no payload, and six ladder findings died
        on their own control arm. The clock is scripted here as interleaved
        pairs — baseline, payload, repeated — because that is what the oracle
        now sends.
        """
        agent = _make_agent()

        async def probe(_page: PageAnalysis, _param: str, _value: str) -> _HTTPResponse:
            return _HTTPResponse(status=200, body="")

        agent._send_probe = probe  # type: ignore[method-assign]
        from clinkz.agents import exploit as exploit_mod

        original_monotonic = exploit_mod.time.monotonic
        # Per repeat: baseline start/end (4.0s — the slow page), then payload
        # start/end (9.0s — the slow page plus our sleep). Delta 5.0s each time.
        ticks: list[float] = []
        for repeat in range(exploit_mod._CMDI_TIME_REPEATS):
            offset = repeat * 100.0
            ticks += [offset, offset + 4.0, offset + 10.0, offset + 19.0]
        clock = iter(ticks)
        exploit_mod.time.monotonic = lambda: next(clock)  # type: ignore[assignment]
        try:
            synth = {
                "payload": "test;sleep 5",
                "indicator_type": "time_delta",
                "expected_indicator": "elapsed exceeds this endpoint's own baseline by ~5s",
            }
            from clinkz.agents._methodology_helpers import BaselineProbe

            baseline = BaselineProbe(
                variant="original",
                value="test",
                status=200,
                length=100,
                body_hash="aaaaaaaaaaaaaaaa",
                time_ms=10.0,
            )
            verified, observed = await agent._cmdi_phase5_verify(
                _make_page(), "cmd", synth, baseline
            )
        finally:
            exploit_mod.time.monotonic = original_monotonic  # type: ignore[assignment]
        assert verified is True
        assert "delta=+5.00s" in observed
        # Both arms of every pair are rendered, so a reader can re-derive it.
        assert observed.count("base=4.00s") == exploit_mod._CMDI_TIME_REPEATS

    @pytest.mark.asyncio
    async def test_a_slow_page_with_no_delta_does_not_verify(self) -> None:
        """The DVWA ``ping -c 4`` shape: 4s+ every time, payload or not."""
        agent = _make_agent()

        async def probe(_page: PageAnalysis, _param: str, _value: str) -> _HTTPResponse:
            return _HTTPResponse(status=200, body="")

        agent._send_probe = probe  # type: ignore[method-assign]
        from clinkz.agents import exploit as exploit_mod

        original_monotonic = exploit_mod.time.monotonic
        ticks: list[float] = []
        for repeat in range(exploit_mod._CMDI_TIME_REPEATS):
            offset = repeat * 100.0
            # Both arms take 4.04s — well over the old absolute threshold.
            ticks += [offset, offset + 4.04, offset + 10.0, offset + 14.04]
        clock = iter(ticks)
        exploit_mod.time.monotonic = lambda: next(clock)  # type: ignore[assignment]
        try:
            from clinkz.agents._methodology_helpers import BaselineProbe

            verified, observed = await agent._cmdi_phase5_verify(
                _make_page(),
                "cmd",
                {
                    "payload": "test;sleep 5",
                    "indicator_type": "time_delta",
                    "expected_indicator": "delay",
                },
                BaselineProbe(
                    variant="original",
                    value="test",
                    status=200,
                    length=100,
                    body_hash="aaaaaaaaaaaaaaaa",
                    time_ms=10.0,
                ),
            )
        finally:
            exploit_mod.time.monotonic = original_monotonic  # type: ignore[assignment]
        assert verified is False
        assert "not reproduced" in observed

    @pytest.mark.asyncio
    async def test_error_string_indicator_matched(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="bash: clinkz_no_such: command not found")
        )
        synth = {
            "payload": "test;clinkz_no_such",
            "indicator_type": "error_string",
            "expected_indicator": "command not found",
        }
        from clinkz.agents._methodology_helpers import BaselineProbe

        baseline = BaselineProbe(
            variant="original",
            value="test",
            status=200,
            length=100,
            body_hash="aaaaaaaaaaaaaaaa",
            time_ms=10.0,
        )
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "cmd", synth, baseline)
        assert verified is True
        assert "bash" in observed.lower()


# ===========================================================================
# Phase 6 — Finding emission
# ===========================================================================


class TestPhase6FindingEmission:
    def test_finding_carries_evidence_chain(self) -> None:
        agent = _make_agent()
        result = CMDIMethodologyResult(
            phases_completed=6,
            shell_type=ShellType.BASH,
            primitives=ShellPrimitives(separators=[";"], substitution=["$()"]),
            execution_type=CMDIExecutionType.DIRECT_EXEC,
            synthesized_payload="test;echo CLINKZ123",
            expected_indicator="CLINKZ123",
            indicator_type="stdout_reflection",
            indicator_observed="matched canary 'CLINKZ123'",
            verified=True,
            verification_strength="verified",
        )
        finding = agent._cmdi_phase6_emit("http://x/exec?cmd=ls", "cmd", result)
        joined = " ".join(finding.evidence)
        assert "phases_completed=6" in joined
        assert "shell=bash" in joined
        assert "execution_type=direct_exec" in joined
        assert "test;echo CLINKZ123" in joined
        assert finding.severity.value == "high"
        assert "command injection" in finding.title.lower()


# ===========================================================================
# Integration — full _test_cmdi driving all six phases
# ===========================================================================


class TestCMDIMethodologyIntegration:
    @pytest.mark.asyncio
    async def test_dvwa_low_style_direct_exec_finding(self) -> None:
        """End-to-end: separator + canary echo → finding emitted."""
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm

        async def fake_probe(_page: PageAnalysis, _param: str, value: str) -> _HTTPResponse:
            # OS detection: `;uname` produces `Linux` in the body.
            if value.endswith(";uname"):
                return _HTTPResponse(status=200, body="ip=test\nLinux\n")
            # Echo the canary back — but only when a SEPARATOR actually starts a
            # second command, which is what a shell does. Without this the fake
            # executes ``testecho <canary>`` as if it were ``test; echo <canary>``,
            # and the never-sent control (the same payload with its separator
            # removed) would come back looking like execution on a target where
            # nothing was injected.
            import re

            sep = r"(?:;|&&|\|\||\||&|\n|%0a|\$\{IFS\}|`|\$\()"
            m = re.search(sep + r"\s*echo (\w+)", value)
            if m:
                return _HTTPResponse(status=200, body=f"out: {m.group(1)}")
            # Status flips on separators (so phase 1 marks candidate).
            if any(sep in value for sep in (";", "&&", "$()", "`", "|")):
                return _HTTPResponse(status=200, body="x" * 500)
            return _HTTPResponse(status=200, body="x" * 100)

        agent._send_probe = fake_probe  # type: ignore[method-assign]
        page = _make_page("http://example.com/exec?cmd=ls", params=["cmd"])
        findings = await agent._test_cmdi(page)
        assert len(findings) == 1
        joined = " ".join(findings[0].evidence)
        assert "shell=" in joined
        assert "execution_type=direct_exec" in joined
        assert "phases_completed=6" in joined

    @pytest.mark.asyncio
    async def test_no_finding_when_param_does_not_diverge(self) -> None:
        agent = _make_agent(_ScriptedLLM(answers=[""]))
        agent._methodology_llm = agent.llm
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>safe</html>")
        )
        page = _make_page("http://example.com/exec?cmd=ls", params=["cmd"])
        findings = await agent._test_cmdi(page)
        assert findings == []


# ===========================================================================
# Regression — phase-5 must accept the LIVE LLM's indicator_type vocabulary,
# not just the deterministic fallback's canonical labels.
#
# Pipeline trace 77031b28: the Anthropic LLM emitted indicator_type
# "output_string" (direct_exec) and "time_delay" (blind_time), neither of which
# the old exact-match normaliser recognised — so verify returned "unknown
# indicator_type" WITHOUT checking the response, even though `test;id` returned
# `uid=33(www-data)` on DVWA-low. The smoke suite passed because its silent LLM
# forces the canonical-label fallback path. These gates exercise the LLM path.
# ===========================================================================


def _baseline() -> Any:
    from clinkz.agents._methodology_helpers import BaselineProbe

    return BaselineProbe(
        variant="original",
        value="test",
        status=200,
        length=100,
        body_hash="aaaaaaaaaaaaaaaa",
        time_ms=10.0,
    )


class TestPhase5LLMVocabulary:
    def test_keyword_classifier_maps_llm_vocabulary(self) -> None:
        assert ExploitAgent._classify_cmdi_indicator("output_string") == "stdout_reflection"
        assert ExploitAgent._classify_cmdi_indicator("time_delay") == "time_delta"
        assert ExploitAgent._classify_cmdi_indicator("error_output_or_response") == "error_string"
        assert ExploitAgent._classify_cmdi_indicator("dns_callback") == "oob_callback"
        assert ExploitAgent._classify_cmdi_indicator(None) == "stdout_reflection"

    @pytest.mark.asyncio
    async def test_output_string_label_verifies_against_id_output(self) -> None:
        """``indicator_type='output_string'`` must verify when the body carries
        genuine ``id`` output (the exact 77031b28 direct_exec miss)."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>"
            )
        )
        synth = {
            "payload": "test;id",
            "expected_indicator": "uid=",
            "indicator_type": "output_string",
        }
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "ip", synth, _baseline())
        assert verified is True
        assert "uid=" in observed

    @pytest.mark.asyncio
    async def test_no_false_positive_on_reflective_non_vuln(self) -> None:
        """A param that merely echoes the payload back (no execution) must NOT
        verify, even though the canary substring is reflected verbatim."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="you searched for: test;echo CLINKZ123 — 0 results"
            )
        )
        synth = {
            "payload": "test;echo CLINKZ123",
            "expected_indicator": "CLINKZ123",
            "indicator_type": "output_string",
        }
        verified, _ = await agent._cmdi_phase5_verify(_make_page(), "q", synth, _baseline())
        assert verified is False

    @pytest.mark.asyncio
    async def test_no_false_positive_on_generic_non_vuln(self) -> None:
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<html>nothing to see here</html>")
        )
        synth = {
            "payload": "test;id",
            "expected_indicator": "uid=",
            "indicator_type": "output_string",
        }
        verified, _ = await agent._cmdi_phase5_verify(_make_page(), "ip", synth, _baseline())
        assert verified is False


class TestPhase5ReflectionInErrorPage:
    """Phase 5 must not confirm an echo canary reflected in an error response.

    The a07df54b Juice Shop run emitted three "high" RCE findings because the
    ``;echo <canary>`` payload string was reflected verbatim in a 500 error body
    (Node, no shell sink). A canary echoed in an error page is input reflection,
    not command output — genuine stdout comes back in a normal (2xx) response in
    command-output position. The error-page gate and the encoding-robust scaffold
    guard close that phantom while preserving genuine command-output confirmation.
    """

    @pytest.mark.asyncio
    async def test_canary_in_500_error_rejected(self) -> None:
        """The exact a07df54b phantom: a 500 body reflects the payload string."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=500,
                body='{"error":"Internal Server Error","message":"bad id test;echo PWNED"}',
            )
        )
        synth = {
            "payload": "test;echo PWNED",
            "expected_indicator": "PWNED",
            "indicator_type": "stdout_reflection",
        }
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "id", synth, _baseline())
        assert verified is False
        assert "error response" in observed

    @pytest.mark.asyncio
    async def test_canary_url_encoded_reflection_in_200_rejected(self) -> None:
        """A 200 that reflects the payload with the space percent-encoded
        (``echo%20PWNED``) is still reflection — the decode guard must catch it."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200, body="you searched for: test;echo%20PWNED — 0 results"
            )
        )
        synth = {
            "payload": "test;echo PWNED",
            "expected_indicator": "PWNED",
            "indicator_type": "stdout_reflection",
        }
        verified, _ = await agent._cmdi_phase5_verify(_make_page(), "q", synth, _baseline())
        assert verified is False

    @pytest.mark.asyncio
    async def test_canary_in_200_command_output_still_confirms(self) -> None:
        """Regression: genuine echo output (canary alone, normal 200 response)
        must still confirm — the error-page gate must not suppress true positives."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="<pre>PWNED</pre>")
        )
        synth = {
            "payload": "test;echo PWNED",
            "expected_indicator": "PWNED",
            "indicator_type": "stdout_reflection",
        }
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "id", synth, _baseline())
        assert verified is True
        assert "PWNED" in observed

    @pytest.mark.asyncio
    async def test_dvwa_id_output_in_200_still_confirms(self) -> None:
        """Regression for the DVWA /exec/ contract: ``;id`` returning
        ``uid=33(www-data)`` in a normal 200 response must still confirm."""
        agent = _make_agent()
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(
                status=200,
                body="<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>",
            )
        )
        synth = {
            "payload": "1;id",
            "expected_indicator": "uid=",
            "indicator_type": "stdout_reflection",
        }
        verified, observed = await agent._cmdi_phase5_verify(_make_page(), "ip", synth, _baseline())
        assert verified is True
        assert "uid=" in observed
