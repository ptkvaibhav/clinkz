"""The research budget bounds how long the phase takes, not when it may start work.

``_budget_exceeded`` was checked only where a new STEP began, so one in-flight
call answering slowly carried the phase past its own deadline and into the
orchestrator's force-kill — which discards the agent's return value entirely.
That is the trap already documented for the scan phase, reached here by a
different route, and it is why three identical Juice Shop envelope runs did not
agree on the run-completion banner.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from clinkz.agents.research import ResearchAgent


class _Agent:
    """The two attributes ``_within_budget`` reads, without a live agent."""

    _within_budget = ResearchAgent._within_budget
    _budget_remaining = ResearchAgent._budget_remaining

    def __init__(self, deadline: float | None) -> None:
        self._deadline = deadline

        class _Log:
            def warning(self, *_args: object, **_kwargs: object) -> None:
                return None

        self._logger = _Log()


async def _slow(seconds: float) -> str:
    await asyncio.sleep(seconds)
    return "answered"


class TestWithinBudget:
    @pytest.mark.asyncio
    async def test_no_deadline_awaits_normally(self) -> None:
        """A direct invocation or ``research_additional`` arms no budget."""
        agent = _Agent(deadline=None)
        assert await agent._within_budget(_slow(0.0), what="x") == "answered"

    @pytest.mark.asyncio
    async def test_a_call_inside_the_budget_answers(self) -> None:
        agent = _Agent(deadline=time.monotonic() + 5.0)
        assert await agent._within_budget(_slow(0.0), what="x") == "answered"

    @pytest.mark.asyncio
    async def test_a_call_that_overruns_is_cancelled_not_awaited(self) -> None:
        """The whole point: the deadline is real, so the phase self-returns."""
        agent = _Agent(deadline=time.monotonic() + 0.05)
        started = time.monotonic()
        assert await agent._within_budget(_slow(5.0), what="x") is None
        assert time.monotonic() - started < 2.0, "it must not have waited for the call"

    @pytest.mark.asyncio
    async def test_a_spent_budget_never_starts_the_call(self) -> None:
        agent = _Agent(deadline=time.monotonic() - 1.0)
        assert await agent._within_budget(_slow(5.0), what="x") is None

    @pytest.mark.asyncio
    async def test_none_is_what_the_call_sites_already_handle(self) -> None:
        """A cancelled call is an empty answer, which every site falls back from.

        This is the same case as a provider that returned nothing parseable,
        arriving for a different reason — so no new failure path was added.
        """
        agent = _Agent(deadline=time.monotonic() - 1.0)
        response = await agent._within_budget(_slow(5.0), what="x")
        assert (response or "").find("[") == -1
