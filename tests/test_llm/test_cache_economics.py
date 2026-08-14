"""A cache that writes and is never read must SAY so.

This is the whole reason the regression survived a week. The ledger exists
precisely to catch "a component was invoked, succeeded, and contributed
nothing" — and the prompt cache was doing exactly that on every run while not
being a ledger component at all. 96,759 cache-write tokens, zero cache-read
tokens, 154 engagements, every one of them looking healthy.

So the cache reports like anything else, and the item it contributes is the
only thing a cache is for: tokens actually served from it.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.llm.base import CallStats, LLMUsageTotals
from clinkz.observability import ledger as ledger_mod
from clinkz.observability.ledger import ContributionLedger, LedgerAlarm


def _record(stats: CallStats) -> ContributionLedger:
    from clinkz.llm.fallback import ResilientLLMClient

    ledger = ContributionLedger("e")
    ledger_mod.set_active_ledger(ledger)
    try:
        ResilientLLMClient._record_cache_economics(stats)
    finally:
        ledger_mod.set_active_ledger(None)
    return ledger


class TestCacheIsALedgerComponent:
    def test_a_write_that_is_never_read_trips_the_silent_alarm(self) -> None:
        ledger = _record(
            CallStats(provider="anthropic", input_tokens=166, cache_creation_input_tokens=12552)
        )
        (record,) = ledger.records()
        assert record.name == "llm:anthropic:prompt_cache"
        assert record.items_contributed == 0
        assert LedgerAlarm.SILENT in record.alarms

    def test_a_read_is_a_contribution(self) -> None:
        ledger = _record(
            CallStats(provider="anthropic", input_tokens=166, cache_read_input_tokens=12552)
        )
        (record,) = ledger.records()
        assert record.items_contributed == 12552
        assert record.alarms == []

    def test_a_call_with_no_breakpoint_is_not_an_invocation(self) -> None:
        """Otherwise every uncached call drowns the one signal that matters."""
        ledger = _record(CallStats(provider="anthropic", input_tokens=375, output_tokens=299))
        assert ledger.records() == []

    def test_the_note_carries_the_numbers_a_reader_needs(self) -> None:
        ledger = _record(
            CallStats(provider="anthropic", input_tokens=166, cache_creation_input_tokens=1002)
        )
        (record,) = ledger.records()
        assert "write=1002" in record.notes[0]
        assert "read=0" in record.notes[0]

    def test_the_cache_is_not_conflated_with_the_provider(self) -> None:
        """A healthy provider and a wasted cache are different facts."""
        ledger = _record(CallStats(provider="anthropic", cache_creation_input_tokens=1002))
        assert [r.name for r in ledger.records()] == ["llm:anthropic:prompt_cache"]


class TestTheCostArithmeticIsMeasuredNotAsserted:
    def test_the_deployed_shape_is_more_expensive_than_no_caching(self) -> None:
        """One write, no read — the shape actually recorded across 154 runs."""
        totals = LLMUsageTotals()
        totals.add(CallStats(input_tokens=166, cache_creation_input_tokens=12552))
        assert totals.cache_hit_rate == 0.0
        assert totals.realised_savings("5m") < 0

    def test_two_presentations_are_already_worth_caching(self) -> None:
        """Break-even is N > 1.28, so the fix is a reader, not a smaller prefix.

        ``1.25P + 0.10P(N-1) < NP``  =>  ``N > 1.28``. At N=2 caching costs
        1.35P against 2P uncached — a 32.5% saving. The deployment had N=1.
        """
        totals = LLMUsageTotals()
        totals.add(CallStats(cache_creation_input_tokens=1000))
        totals.add(CallStats(cache_read_input_tokens=1000))
        assert totals.realised_savings("5m") == pytest.approx(1 - 1.35 / 2.0)

    def test_the_smaller_prefix_caps_the_downside(self) -> None:
        """Moving the breakpoint is worth it even if a read never arrives.

        Same worst case (write, no read), two prefix sizes: the wasted premium
        falls with the span, which is why the invariant half is the right place
        for it regardless of how often a second call turns up.
        """
        big = LLMUsageTotals()
        big.add(CallStats(input_tokens=166, cache_creation_input_tokens=12552))
        small = LLMUsageTotals()
        small.add(CallStats(input_tokens=11718, cache_creation_input_tokens=1000))

        def wasted(t: LLMUsageTotals) -> float:
            return -t.realised_savings("5m") * t.prompt_tokens

        assert wasted(small) < wasted(big) / 10


@pytest.mark.asyncio
async def test_the_seam_is_inert_without_a_ledger() -> None:
    """Absent by default, like the governor. A driver is byte-identical."""
    from clinkz.llm.fallback import ResilientLLMClient

    ledger_mod.set_active_ledger(None)
    ResilientLLMClient._record_cache_economics(
        CallStats(provider="anthropic", cache_creation_input_tokens=9999)
    )  # must not raise


def test_a_ledger_failure_never_reaches_the_data_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from clinkz.llm.fallback import ResilientLLMClient

    class _Exploding(ContributionLedger):
        def record(self, **kwargs: Any) -> None:
            raise RuntimeError("ledger is broken")

    ledger_mod.set_active_ledger(_Exploding("e"))
    try:
        ResilientLLMClient._record_cache_economics(
            CallStats(provider="anthropic", cache_creation_input_tokens=1)
        )
    finally:
        ledger_mod.set_active_ledger(None)
