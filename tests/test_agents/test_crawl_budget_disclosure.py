"""A bound that decides coverage is reported in the DELIVERABLE, not just the log.

`plan_alarms.py` exists because four D1 baseline runs each truncated ~1,500
exploit candidates to 150 in silence. The crawl's enrichment budget is the same
defect one layer earlier, and it survived that fix: on the first non-benchmark
engagement 3,070 crawled URLs reduced to 212 candidates and the budget opened
**80**, so 132 (62%) of the discovered surface was never opened — a number that
existed only at INFO in the run log while `report.json` said nothing at all.

It is strictly upstream of the plan cap: this budget decides which discovered
URLs ever BECOME endpoints, so everything the plan cap can see has already
passed through it. And it silently qualifies the scope-refusal tally, which
counts requests that were REFUSED — a candidate never opened never became a
request, so "75 refusals across 3 hosts" describes the opened slice of the
out-of-scope surface rather than the surface.

Two of the 212 candidates in three spellings were the same link. Reading a URL
out of a JSON-escaped payload without unescaping it leaves the escape in the
path, so `/x`, `/x%5C` and `/x%5C%5C%5C` each consumed a visit.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from clinkz.agents._url_shape import crawl_dedup_key
from clinkz.agents.report import ReportAgent
from clinkz.models.report import PentestReport
from clinkz.observability.plan_alarms import (
    CrawlBudgetTruncation,
    PlanAlarmRegister,
    crawl_budget_summary,
    record_crawl_budget,
    set_active_plan_alarms,
)


def _report(coverage: dict[str, object]) -> PentestReport:
    now = datetime.now(UTC)
    return PentestReport(
        engagement_id="e",
        engagement_name="test",
        target_scope=["t.example"],
        test_start=now,
        test_end=now,
        crawl_coverage=coverage,
    )


def _render(coverage: dict[str, object]) -> str:
    lines: list[str] = []
    ReportAgent._render_crawl_coverage(lines, _report(coverage))
    return chr(10).join(lines)


@pytest.fixture
def register():
    active = PlanAlarmRegister()
    set_active_plan_alarms(active)
    try:
        yield active
    finally:
        set_active_plan_alarms(None)


class TestOneHrefIsOneCandidate:
    """The escape artifact is a spelling, not a route."""

    def test_the_three_spellings_share_one_key(self) -> None:
        spellings = [
            "https://github.com/ptkvaibhav",
            "https://github.com/ptkvaibhav%5C",
            "https://github.com/ptkvaibhav%5C%5C%5C",
        ]
        assert len({crawl_dedup_key(u) for u in spellings}) == 1

    def test_the_clean_spelling_sorts_first(self) -> None:
        """Which is why the caller can keep the smallest without rewriting a URL.

        The clean URL is a strict prefix of every mangled one, so "smallest in
        the group" picks it whenever it was discovered — and when only the
        mangled spelling exists, that one is opened unchanged rather than a URL
        the target never offered.
        """
        group = [
            "https://github.com/ptkvaibhav%5C%5C%5C",
            "https://github.com/ptkvaibhav",
            "https://github.com/ptkvaibhav%5C",
        ]
        assert min(group) == "https://github.com/ptkvaibhav"

    def test_a_lone_mangled_spelling_is_still_a_candidate(self) -> None:
        assert crawl_dedup_key("http://www.w3.org/2000/svg%5C") == "http://www.w3.org/2000/svg"

    def test_the_fragment_and_trailing_slash_still_collapse(self) -> None:
        assert crawl_dedup_key("https://x/a/#top") == crawl_dedup_key("https://x/a")

    def test_a_query_string_is_part_of_the_identity(self) -> None:
        """A parameterised route is the highest-value thing a crawl finds."""
        assert crawl_dedup_key("https://x/a?id=1") != crawl_dedup_key("https://x/a?id=2")


class TestTheBudgetReachesTheReport:
    def test_the_portfolio_shape_renders_its_own_number(self, register: PlanAlarmRegister) -> None:
        record_crawl_budget(
            CrawlBudgetTruncation(
                budget=80,
                candidates=212,
                opened=80,
                duplicates_collapsed=14,
                first_omitted="https://ptkvaibhav.vercel.app/projects/x",
                opened_by_host={"ptkvaibhav.vercel.app": 63, "nextjs.org": 9},
                dropped_by_host={"ptkvaibhav.vercel.app": 100, "www.linkedin.com": 32},
            )
        )
        rendered = _render(crawl_budget_summary())

        assert "## Crawl coverage" in rendered
        assert "**80 of 212 candidate URL(s)**" in rendered
        assert "**132 (62%) were never opened**" in rendered
        assert "14 duplicate spelling(s)" in rendered
        assert "https://ptkvaibhav.vercel.app/projects/x" in rendered

    def test_a_host_never_opened_is_its_own_claim(self, register: PlanAlarmRegister) -> None:
        """A total says how much was missed; only the split says a host was skipped."""
        record_crawl_budget(
            CrawlBudgetTruncation(
                budget=2,
                candidates=5,
                opened=2,
                opened_by_host={"a.example": 2},
                dropped_by_host={"b.example": 3},
            )
        )
        rendered = _render(crawl_budget_summary())
        assert "never opened at all" in rendered
        assert "`b.example`" in rendered
        assert "it is none of them" in rendered

    def test_the_refusal_tally_is_qualified(self, register: PlanAlarmRegister) -> None:
        """A candidate the budget never opened never became a request."""
        record_crawl_budget(CrawlBudgetTruncation(budget=1, candidates=9, opened=1))
        assert "never became a request" in _render(crawl_budget_summary())

    def test_a_clean_crawl_still_makes_the_claim(self, register: PlanAlarmRegister) -> None:
        """A section that appears only on truncation reads like one nobody wrote."""
        record_crawl_budget(CrawlBudgetTruncation(budget=80, candidates=12, opened=12))
        rendered = _render(crawl_budget_summary())
        assert "## Crawl coverage" in rendered
        assert "inside the enrichment budget" in rendered

    def test_no_crawl_renders_nothing(self) -> None:
        """A phase that never ran must not claim coverage it did not measure."""
        assert _render({}) == ""

    def test_the_budget_is_absent_by_default(self) -> None:
        """Like the governor and the ledger: no register, no record, no raise."""
        set_active_plan_alarms(None)
        record_crawl_budget(CrawlBudgetTruncation(budget=1, candidates=2, opened=1))
        assert crawl_budget_summary()["passes_recorded"] == 0


class TestTheScanAgentRecordsIt:
    @pytest.mark.asyncio
    async def test_enrichment_records_the_budget_it_spent(
        self, register: PlanAlarmRegister, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end through the real dedup, priority order and budget."""
        from clinkz.agents import scan as scan_module

        urls = [f"https://t.example/page{i}?id={i}" for i in range(90)]
        # The same link in three spellings must cost one visit, not three.
        urls += [
            "https://t.example/profile",
            "https://t.example/profile%5C",
            "https://t.example/profile%5C%5C%5C",
        ]

        agent = object.__new__(scan_module.ScanAgent)
        import logging

        agent._logger = logging.getLogger("test")
        agent._budget_exhausted = lambda: True  # stop before any request leaves

        await scan_module.ScanAgent._enrich_endpoints_with_params(agent, urls)

        stamp = crawl_budget_summary()
        assert stamp["passes_recorded"] == 1
        assert stamp["candidates"] == 91, "the three spellings collapsed to one candidate"
        assert stamp["duplicates_collapsed"] == 2
        assert stamp["opened"] == 80
        assert stamp["dropped_total"] == 11
        assert stamp["dropped_by_host"] == {"t.example": 11}
        assert stamp["first_omitted"]
