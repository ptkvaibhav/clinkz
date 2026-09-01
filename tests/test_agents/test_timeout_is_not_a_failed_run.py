"""A phase stopped at its own wall clock is not a run that did not happen.

Three identical Juice Shop envelope runs disagreed on the honesty banner: runs 1
and 2 rendered clean, run 3 rendered "THIS RUN DID NOT COMPLETE. The research
phase did not complete." over the same findings. The research phase had overrun
the orchestrator's grace window, which force-kills the agent and discards its
return value, and ``"timeout"`` sat in the same set as ``"error"``.

That banner exists so a bad run cannot hide. A claim that fires on a third of
good runs is one a reader learns to skip, so the two are separated — but on an
engine fact rather than on a list of which phases are allowed to time out. What
a phase HANDED OVER is the fact: ``_phase_stop_result`` carries the agent's
delivered result through a stop, so a timeout with a result is a phase that did
its work and ran out of clock, and a timeout with nothing cannot be told apart
from a phase that never ran.
"""

from __future__ import annotations

from clinkz.agents.report import _run_completion
from clinkz.llm.degradation import EXHAUSTED_PROVIDER


class TestTimeoutClassification:
    def test_a_clean_run_completes(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={"recon": {"status": "complete"}, "scan": {"status": "complete"}},
            model_stamp=[],
        )
        assert completed is True
        assert reason == ""

    def test_a_timeout_that_delivered_a_result_completes(self) -> None:
        """Run 3's shape once research self-returns within its own budget."""
        completed, reason = _run_completion(
            phase_outcomes={
                "scan": {"status": "complete"},
                "research": {"status": "timeout", "result": {"techniques": []}},
            },
            model_stamp=[],
        )
        assert completed is True, "the phase handed its work over and then ran out of clock"
        assert reason == ""

    def test_a_timeout_that_delivered_nothing_still_trips_the_banner(self) -> None:
        """The half that must not be relaxed.

        A phase that handed nothing over is indistinguishable from one that
        never ran, and that is exactly what the banner is for.
        """
        completed, reason = _run_completion(
            phase_outcomes={"research": {"status": "timeout"}},
            model_stamp=[],
        )
        assert completed is False
        assert "research" in reason
        assert "wall clock" in reason
        assert "before delivering any result" in reason

    def test_an_empty_exploit_timeout_cannot_hide(self) -> None:
        """The case the separation must not buy: no findings, nothing ran."""
        completed, reason = _run_completion(
            phase_outcomes={"exploit": {"status": "timeout", "result": {}}},
            model_stamp=[],
        )
        assert completed is False
        assert "exploit" in reason

    def test_an_error_is_still_an_error(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={"exploit": {"status": "error", "result": {"findings": []}}},
            model_stamp=[],
        )
        assert completed is False, "a result does not rescue a phase that BROKE"
        assert "did not complete" in reason

    def test_a_starved_stage_is_unaffected(self) -> None:
        """The model-stamp witness is orthogonal and still fires."""
        completed, reason = _run_completion(
            phase_outcomes={"exploit": {"status": "complete"}},
            model_stamp=[{"stage": "exploit", "model": "", "provider": EXHAUSTED_PROVIDER}],
        )
        assert completed is False
        assert "exploit" in reason

    def test_both_witnesses_are_reported_together(self) -> None:
        completed, reason = _run_completion(
            phase_outcomes={
                "scan": {"status": "error"},
                "research": {"status": "timeout"},
            },
            model_stamp=[],
        )
        assert completed is False
        assert "scan" in reason and "research" in reason
