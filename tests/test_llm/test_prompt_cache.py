"""Prompt-caching mechanics at the client layer.

Caching is a prefix match: the request either presents byte-identical leading
bytes or it does not cache, and there is no error either way. So these tests
assert on the *request the client builds*, not on a provider's reply — a hit
rate can only be measured against a live API, but whether we ever had a chance
at one is decidable offline, and that is the part that silently regresses.

What this file used to miss, and what it cost. ``TestPrefixStability`` handed
the client the SAME ``PromptSegments`` object twice and asserted the two
requests carried the same prefix bytes. That is a true statement about the
mechanism and says nothing about the deployment: the prefix in production was
the engagement's observed endpoint inventory, presented on exactly ONE call per
run, so it was never re-presented at all — stably or otherwise. Across 154
recorded engagements that produced 96,759 cache-WRITE tokens and zero
cache-read tokens, a 1.25x premium paid every run for an entry nothing read.

A green test over an object reused in the test is not evidence about the object
the caller builds. So the tests below now assert on WHICH SPAN takes the
breakpoint, and the tests at the end assert the property that actually decides
whether caching can ever pay: the same span coming back byte-identical from
independently constructed prompts.

No API key and no network: every test drives ``_call_with_backoff`` through a
mock and inspects the kwargs the client passed it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from clinkz.llm.base import (
    CallStats,
    LLMUsageTotals,
    PromptSegments,
    as_prompt_segments,
    flatten_prompt,
)


@pytest.fixture(autouse=True)
def _fake_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-fake")


def _response(text: str = "ok", **usage: int) -> SimpleNamespace:
    """A minimal Anthropic response object carrying one text block."""
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            cache_creation_input_tokens=usage.get("cache_creation_input_tokens", 0),
            cache_read_input_tokens=usage.get("cache_read_input_tokens", 0),
        ),
    )


def _client(model: str = "claude-sonnet-5") -> Any:
    from clinkz.llm.anthropic_client import AnthropicClient

    with patch("clinkz.llm.anthropic_client.settings") as fake:
        fake.anthropic_api_key = "k"
        fake.anthropic_model = model
        client = AnthropicClient(model=model)
    return client


async def _call(client: Any, prompt: Any, **setting_overrides: Any) -> dict[str, Any]:
    """Run generate_text against a mocked API and return the kwargs it sent."""
    defaults = {
        "llm_max_output_tokens": 16000,
        "llm_prompt_cache_enabled": True,
        "llm_prompt_cache_ttl": "5m",
        "llm_max_retries": 1,
        "llm_retry_base_delay": 0.0,
        "llm_retry_max_delay": 0.0,
        "llm_request_timeout": 30.0,
        "llm_context_margin_tokens": 8000,
        "llm_stream_above_output_tokens": 16000,
        "llm_output_headroom_alarm_ratio": 0.8,
    }
    defaults.update(setting_overrides)
    with patch("clinkz.llm.anthropic_client.settings", SimpleNamespace(**defaults)):
        with patch.object(type(client), "_call_with_backoff", new_callable=AsyncMock) as backoff:
            backoff.return_value = _response()
            await client.generate_text(prompt)
    return backoff.call_args.kwargs


# ---------------------------------------------------------------------------
# The stable/volatile split
# ---------------------------------------------------------------------------


class TestPromptSegments:
    def test_flatten_matches_the_string_a_caller_would_have_written(self) -> None:
        seg = PromptSegments(stable="PREFIX", volatile="ASK")
        assert seg.flatten() == "PREFIX\n\nASK"

    def test_flatten_of_a_bare_string_is_the_identity(self) -> None:
        assert flatten_prompt("just a prompt") == "just a prompt"

    def test_a_bare_string_normalises_to_all_volatile(self) -> None:
        # The unchanged path: nothing is declared stable, so nothing is cached.
        seg = as_prompt_segments("hello")
        assert seg.stable == ""
        assert seg.volatile == "hello"

    def test_empty_half_does_not_introduce_separator_bytes(self) -> None:
        assert PromptSegments(stable="", volatile="ASK").flatten() == "ASK"
        assert PromptSegments(stable="PRE", volatile="").flatten() == "PRE"

    def test_all_three_scopes_render_widest_first(self) -> None:
        seg = PromptSegments(invariant="ENGINE", stable="TARGET", volatile="ASK")
        assert seg.flatten() == "ENGINE\n\nTARGET\n\nASK"
        assert seg.context == "ENGINE\n\nTARGET"

    def test_the_model_sees_the_same_bytes_however_they_are_split(self) -> None:
        """The split is an accounting decision, never a content change."""
        split = PromptSegments(invariant="ENGINE", stable="TARGET", volatile="ASK")
        merged = PromptSegments(stable="ENGINE\n\nTARGET", volatile="ASK")
        assert split.flatten() == merged.flatten()


# ---------------------------------------------------------------------------
# Breakpoint placement
# ---------------------------------------------------------------------------


class TestBreakpointPlacement:
    @pytest.mark.asyncio
    async def test_plain_string_prompt_sends_no_system_block_at_all(self) -> None:
        """The pre-existing path stays byte-identical — no system, no breakpoint."""
        kwargs = await _call(_client(), "a plain prompt")
        assert "system" not in kwargs
        assert kwargs["messages"] == [{"role": "user", "content": "a plain prompt"}]

    @pytest.mark.asyncio
    async def test_stable_prefix_over_the_floor_carries_a_cache_breakpoint(self) -> None:
        stable = "S" * 8000  # ~2000 tokens, over sonnet-5's 1024 floor
        kwargs = await _call(_client(), PromptSegments(invariant=stable, volatile="ASK"))
        assert kwargs["system"] == [
            {"type": "text", "text": stable, "cache_control": {"type": "ephemeral"}}
        ]
        # The volatile half stays in the message, after the breakpoint.
        assert kwargs["messages"] == [{"role": "user", "content": "ASK"}]

    @pytest.mark.asyncio
    async def test_the_engagement_scoped_span_is_sent_outside_the_breakpoint(self) -> None:
        """The regression, pinned.

        The engagement-scoped span is the growing endpoint inventory: ~12,500
        tokens, different in every run, presented once. Caching it bought a
        1.25x premium on an entry nothing ever read. It must be sent — the
        model needs it — and it must sit AFTER the marked block, so it is
        outside the cached prefix.
        """
        invariant = "E" * 8000
        scoped = "T" * 40000
        kwargs = await _call(
            _client(), PromptSegments(invariant=invariant, stable=scoped, volatile="ASK")
        )
        assert kwargs["system"] == [
            {"type": "text", "text": invariant, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": scoped},
        ]

    @pytest.mark.asyncio
    async def test_an_engagement_scoped_span_alone_is_never_cached(self) -> None:
        """No invariant span means no breakpoint — not a breakpoint on the target."""
        kwargs = await _call(_client(), PromptSegments(stable="T" * 40000, volatile="ASK"))
        assert kwargs["system"] == [{"type": "text", "text": "T" * 40000}]

    @pytest.mark.asyncio
    async def test_prefix_under_the_floor_is_sent_but_not_marked(self) -> None:
        """Below the minimum the API silently declines to cache.

        Attaching anyway would buy a write premium on an entry that is never
        created, and would report a hit rate that cannot arrive.
        """
        stable = "S" * 400  # ~100 tokens, under the 1024 floor
        kwargs = await _call(_client(), PromptSegments(invariant=stable, volatile="ASK"))
        assert kwargs["system"] == [{"type": "text", "text": stable}]

    @pytest.mark.asyncio
    async def test_caching_can_be_switched_off_without_changing_the_content(self) -> None:
        stable = "S" * 8000
        kwargs = await _call(
            _client(),
            PromptSegments(invariant=stable, volatile="ASK"),
            llm_prompt_cache_enabled=False,
        )
        assert kwargs["system"] == [{"type": "text", "text": stable}]

    @pytest.mark.asyncio
    async def test_one_hour_ttl_is_passed_through(self) -> None:
        stable = "S" * 8000
        kwargs = await _call(
            _client(),
            PromptSegments(invariant=stable, volatile="ASK"),
            llm_prompt_cache_ttl="1h",
        )
        assert kwargs["system"][0]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}

    @pytest.mark.asyncio
    async def test_max_tokens_comes_from_settings_not_a_literal(self) -> None:
        kwargs = await _call(_client(), "x", llm_max_output_tokens=32000)
        assert kwargs["max_tokens"] == 32000


# ---------------------------------------------------------------------------
# The invariant that makes caching work at all
# ---------------------------------------------------------------------------


class TestPrefixStability:
    @pytest.mark.asyncio
    async def test_changing_the_volatile_half_does_not_disturb_the_prefix(self) -> None:
        """The whole point of the split: a new question is not a new prefix."""
        client = _client()
        stable = "S" * 8000
        first = await _call(client, PromptSegments(invariant=stable, volatile="ask one"))
        second = await _call(
            client, PromptSegments(invariant=stable, volatile="a rather different ask")
        )
        assert first["system"] == second["system"]
        assert first["messages"] != second["messages"]

    @pytest.mark.asyncio
    async def test_changing_the_engagement_span_does_not_disturb_the_prefix(self) -> None:
        """The endpoint inventory GROWS during a run. That must not cost the cache.

        This is the property the old two-call test was reaching for and could
        not reach: it reused one object, so nothing about it could ever change.
        Here the engagement-scoped span really does differ between the calls —
        which is what a live crawl does — and the cached block still matches.
        """
        client = _client()
        invariant = "E" * 8000
        first = await _call(
            client,
            PromptSegments(invariant=invariant, stable='[{"url":"/a"}]', volatile="ask"),
        )
        second = await _call(
            client,
            PromptSegments(
                invariant=invariant,
                stable='[{"url":"/a"},{"url":"/b"},{"url":"/c"}]',
                volatile="ask",
            ),
        )
        assert first["system"][0] == second["system"][0]
        assert first["system"][1] != second["system"][1]

    @pytest.mark.asyncio
    async def test_a_changed_prefix_really_does_change_the_request(self) -> None:
        """Control for the tests above — they must be able to fail."""
        client = _client()
        a = await _call(client, PromptSegments(invariant="A" * 8000, volatile="ask"))
        b = await _call(client, PromptSegments(invariant="B" * 8000, volatile="ask"))
        assert a["system"] != b["system"]


class TestTheInvariantSpanIsActuallyInvariant:
    """The property caching stands or falls on, measured on the REAL builder.

    Not on a fixture and not on a reused object: the planner's own invariant
    prefix, built twice from independently constructed inputs, must come back
    byte-identical. If it does not, every write is a guaranteed miss and the
    breakpoint is pure cost — which is precisely the failure this whole change
    exists to make impossible to ship unnoticed.
    """

    def test_the_planning_invariant_prefix_is_byte_identical_across_engagements(self) -> None:
        from clinkz.agents.exploit import ExploitAgent

        first = ExploitAgent._planning_invariant_prefix()
        second = ExploitAgent._planning_invariant_prefix()
        assert first == second
        assert first, "the invariant prefix is empty — nothing would ever be cached"

    def test_the_invariant_prefix_does_not_move_when_the_target_does(self) -> None:
        """The property that decides everything, tested against real inputs.

        The prefix must not depend on what was observed. A hardcoded URL inside
        a WORKED EXAMPLE is engine content and stays — what may not appear is
        anything derived from this engagement, and the way to check that is to
        vary the engagement and watch the span not move.
        """
        from clinkz.agents.exploit import ExploitAgent
        from clinkz.models.scan import Endpoint

        agent = object.__new__(ExploitAgent)
        empty = ExploitAgent._build_planning_prefix(agent, [], [], [], [], 120)
        busy = ExploitAgent._build_planning_prefix(
            agent,
            [Endpoint(url="http://victim/a", method="GET", params=["id"])],
            ["php", "apache"],
            [{"technique": "x"}],
            [],
            120,
        )
        assert empty != busy, "the engagement span must reflect the engagement"
        # ...and the cached span is untouched by either.
        invariant = ExploitAgent._planning_invariant_prefix()
        assert invariant == ExploitAgent._planning_invariant_prefix()
        assert "victim" not in invariant

    def test_the_invariant_prefix_carries_the_per_class_preconditions(self) -> None:
        """What was moved must actually be there — not silently dropped."""
        from clinkz.agents.exploit import TIER1_TESTS, ExploitAgent

        prefix = ExploitAgent._planning_invariant_prefix()
        assert "Methodology catalogue" in prefix
        assert "Worked examples" in prefix
        for name in TIER1_TESTS:
            assert name in prefix, f"{name} lost its precondition in the split"

    def test_the_engagement_span_carries_the_observations(self) -> None:
        """The negative control: the two halves must not have merged."""
        from clinkz.agents.exploit import ExploitAgent

        agent = object.__new__(ExploitAgent)
        scoped = ExploitAgent._build_planning_prefix(agent, [], [], [], [], 120)
        assert "Endpoint inventory" in scoped
        assert "Methodology catalogue" not in scoped


# ---------------------------------------------------------------------------
# The per-model floor
# ---------------------------------------------------------------------------


class TestCacheFloor:
    @pytest.mark.parametrize(
        ("model", "expected"),
        [
            ("claude-opus-5", 512),
            ("claude-fable-5", 512),
            ("claude-sonnet-5", 1024),
            ("claude-opus-4-8", 1024),
            ("claude-opus-4-7", 2048),
            ("claude-opus-4-6", 4096),
            ("claude-haiku-4-5", 4096),
            ("some-unknown-model", 1024),
        ],
    )
    def test_floor_is_looked_up_per_model_and_is_not_monotonic(
        self, model: str, expected: int
    ) -> None:
        """The floor is 512 on the newest models and 4096 on Opus 4.6 / Haiku 4.5.

        Assuming a single value — in either direction — is how a breakpoint ends
        up attached to a prefix that will never cache.
        """
        from clinkz.llm.anthropic_client import cache_min_prefix_tokens

        assert cache_min_prefix_tokens(model) == expected

    @pytest.mark.asyncio
    async def test_same_prefix_caches_on_opus_5_and_not_on_opus_4_6(self) -> None:
        """One prefix, two models, two answers — because the floors differ 8x."""
        stable = "S" * 3000  # ~750 tokens: over 512, under 4096

        on_opus5 = await _call(
            _client("claude-opus-5"), PromptSegments(invariant=stable, volatile="ASK")
        )
        on_opus46 = await _call(
            _client("claude-opus-4-6"), PromptSegments(invariant=stable, volatile="ASK")
        )

        assert "cache_control" in on_opus5["system"][0]
        assert "cache_control" not in on_opus46["system"][0]


# ---------------------------------------------------------------------------
# Accounting
# ---------------------------------------------------------------------------


class TestUsageAccounting:
    @pytest.mark.asyncio
    async def test_cache_counters_are_read_back_off_the_response(self) -> None:
        client = _client()
        with patch(
            "clinkz.llm.anthropic_client.settings",
            SimpleNamespace(
                llm_max_output_tokens=16000,
                llm_prompt_cache_enabled=True,
                llm_prompt_cache_ttl="5m",
                llm_context_margin_tokens=8000,
                llm_stream_above_output_tokens=16000,
                llm_output_headroom_alarm_ratio=0.8,
            ),
        ):
            with patch.object(
                type(client), "_call_with_backoff", new_callable=AsyncMock
            ) as backoff:
                backoff.return_value = _response(
                    input_tokens=12,
                    output_tokens=34,
                    cache_creation_input_tokens=0,
                    cache_read_input_tokens=4096,
                )
                await client.generate_text("x")

        stats = client.last_call_stats
        assert stats is not None
        assert stats.cache_read_input_tokens == 4096
        assert stats.input_tokens == 12
        # input_tokens is the UNCACHED REMAINDER — the real prompt size is the sum.
        assert stats.billed_prompt_tokens == 12 + 4096

    def test_hit_rate_and_savings_are_derived_from_the_counters(self) -> None:
        totals = LLMUsageTotals()
        # Call 1 writes the cache; calls 2-5 read it.
        totals.add(CallStats(input_tokens=100, cache_creation_input_tokens=4000))
        for _ in range(4):
            totals.add(CallStats(input_tokens=100, cache_read_input_tokens=4000))

        assert totals.calls == 5
        assert totals.prompt_tokens == 500 + 4000 + 16000
        assert totals.cache_hit_rate == pytest.approx(16000 / 20500, rel=1e-4)
        # 500*1.0 + 4000*1.25 + 16000*0.10 = 7100 vs 20500 at base rate.
        assert totals.realised_savings("5m") == pytest.approx(1 - 7100 / 20500, rel=1e-4)

    def test_a_write_that_is_never_read_costs_more_than_not_caching(self) -> None:
        """Savings are computed, not assumed — and can legitimately be negative."""
        totals = LLMUsageTotals()
        totals.add(CallStats(cache_creation_input_tokens=4000))
        assert totals.realised_savings("5m") < 0

    def test_no_cache_activity_reports_a_zero_hit_rate_not_a_crash(self) -> None:
        totals = LLMUsageTotals()
        totals.add(CallStats(input_tokens=500, output_tokens=100))
        assert totals.cache_hit_rate == 0.0
        assert totals.realised_savings("5m") == 0.0

    def test_empty_totals_do_not_divide_by_zero(self) -> None:
        totals = LLMUsageTotals()
        assert totals.cache_hit_rate == 0.0
        assert totals.realised_savings("5m") == 0.0


class TestTheDefaultIsOff:
    """The deployment decision, pinned so it cannot be flipped back silently.

    Caching pays from the second presentation (``1.25 + 0.10(N-1) < N`` for
    ``N > 1.28``). Every trace on disk says ``N = 1``: 13 breakpoint-carrying
    calls across 13 engagements, **zero** of which ever made a second one, and
    104,589 cache-write tokens against 0 cache-read tokens. The cross-run route
    is closed too — no two breakpoint calls on record are closer than 1,692s
    against a 300s TTL, because one run's planning call sits a whole engagement
    away from the next.

    Moving the breakpoint off the engagement-scoped span was necessary and not
    sufficient: it cut the write from ~12,500 tokens to ~1,566 and left the hit
    rate at 0.00%. So the arithmetic, not the machinery, is what failed — the
    flag and the span split stay for a deployment that really re-presents a
    prefix, and the default is off.
    """

    def test_prompt_caching_is_disabled_by_default(self) -> None:
        from clinkz.config import Settings

        assert Settings().llm_prompt_cache_enabled is False

    def test_the_env_var_is_the_opt_in_and_defaults_off(self, monkeypatch) -> None:
        from clinkz.config import Settings

        monkeypatch.delenv("LLM_PROMPT_CACHE_ENABLED", raising=False)
        assert Settings.from_env().llm_prompt_cache_enabled is False
        monkeypatch.setenv("LLM_PROMPT_CACHE_ENABLED", "true")
        assert Settings.from_env().llm_prompt_cache_enabled is True

    def test_a_disabled_cache_reports_no_ledger_component_at_all(self) -> None:
        """Off means the capability is never reached for, not a silent zero.

        A component that is invoked and contributes nothing is a degradation the
        ledger must shout about; a component nobody invoked is not. With caching
        off there is no write and no read, so ``_record_cache_economics``
        returns before recording and the component is absent — which is why
        turning it off CLEARS the alarm rather than pinning it at zero.
        """
        from clinkz.llm.base import CallStats
        from clinkz.llm.fallback import ResilientLLMClient
        from clinkz.observability import ledger as ledger_mod
        from clinkz.observability.ledger import ContributionLedger

        ledger = ContributionLedger("cache-off")
        ledger_mod.set_active_ledger(ledger)
        try:
            # What an uncached call reports: real prompt tokens, no cache activity.
            ResilientLLMClient._record_cache_economics(
                CallStats(provider="anthropic", input_tokens=900)
            )
            # And the control: a call that DID carry a breakpoint is still recorded,
            # so the assertion above is about cache activity and not about a
            # recorder that stopped working.
            ResilientLLMClient._record_cache_economics(
                CallStats(provider="anthropic", cache_creation_input_tokens=1566)
            )
        finally:
            ledger_mod.set_active_ledger(None)

        cache_records = [r for r in ledger.records() if "prompt_cache" in r.name]
        assert len(cache_records) == 1
        assert cache_records[0].invocations == 1
