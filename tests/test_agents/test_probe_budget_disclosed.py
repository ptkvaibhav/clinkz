"""The OPTIONS sweep probes application routes first, and says what it dropped.

Pinned on the REAL route shape that produced the defect — 30 Next.js JS chunks,
2 CSS chunks, three `/api/` routes, a root and a handful of static files, which is
the 44-route set of engagement `e4814440` — because the defect was invisible to any
route set that did not include a bundle-heavy SPA. A test written against six tidy
routes passes under lexicographic selection.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.agents._api_schema import (
    MAX_OPTIONS_PROBES,
    RELEVANT_PROBE_GRADES,
    learn_allowed_methods,
)
from clinkz.models.scan import Endpoint
from clinkz.observability.plan_alarms import (
    PlanAlarmRegister,
    ProbeBudgetTruncation,
    probe_budget_summary,
    set_active_plan_alarms,
)

BASE = "http://127.0.0.1:3100"


def _caldiy_routes(chunk_count: int = 30) -> list[str]:
    """The cal.diy route shape, with a tunable number of JS chunks."""
    chunks = [f"{BASE}/_next/static/chunks/{i:02d}abcdefghij.js" for i in range(chunk_count)]
    css = [f"{BASE}/_next/static/chunks/{i:02d}stylesheet.css" for i in range(2)]
    api = [f"{BASE}/api/book/event", f"{BASE}/api/logo", f"{BASE}/api/trpc"]
    static = [
        f"{BASE}/email-clients/gmail.svg",
        f"{BASE}/email-clients/outlook.svg",
        f"{BASE}/email-clients/proton.svg",
        f"{BASE}/email-clients/yahoo.svg",
        f"{BASE}/favicon.ico",
        f"{BASE}/ring.mp3",
        f"{BASE}/safari-pinned-tab.svg",
        f"{BASE}/site.webmanifest",
    ]
    return [f"{BASE}/", *chunks, *css, *api, *static]


def _endpoints(routes: list[str]) -> list[Endpoint]:
    return [Endpoint(url=route, method="GET", params=[]) for route in routes]


class _RecordingProbe:
    """A probe that records what it was asked and answers as cal.diy did.

    Next.js answered `OPTIONS` with `400` and no `Allow` on the routes that carry
    the writes, so this returns the target's real behaviour rather than a
    convenient one — what is asserted here is WHICH routes were asked, which is
    the whole defect.
    """

    def __init__(self) -> None:
        self.asked: list[str] = []

    async def __call__(self, method: str, url: str) -> tuple[int, str, dict[str, str]]:
        assert method in {"GET", "HEAD", "OPTIONS"}, f"unsafe method {method} at a mapping seam"
        self.asked.append(url)
        if "/_next/" in url:
            return 400, "", {"Allow": "HEAD"}
        return 400, "", {}


@pytest.fixture
def register() -> Any:
    reg = PlanAlarmRegister()
    set_active_plan_alarms(reg)
    try:
        yield reg
    finally:
        set_active_plan_alarms(None)


@pytest.mark.asyncio
async def test_api_routes_are_probed_before_bundles(register: PlanAlarmRegister) -> None:
    """The three application routes are asked first, not at sorted index 33."""
    routes = _caldiy_routes()
    assert len(routes) == 44, "the pinned shape must stay the 44-route set that was measured"
    probe = _RecordingProbe()

    await learn_allowed_methods(_endpoints(routes), probe)

    assert len(probe.asked) == MAX_OPTIONS_PROBES
    # The whole fix, in one assertion: the API routes are the first three probes.
    assert probe.asked[:3] == [
        f"{BASE}/api/book/event",
        f"{BASE}/api/logo",
        f"{BASE}/api/trpc",
    ]


@pytest.mark.asyncio
async def test_a_larger_bundle_set_cannot_starve_the_api_routes(
    register: PlanAlarmRegister,
) -> None:
    """The falsifiable prediction the old bound failed.

    cal.com's login page alone references 31 chunks. Under lexicographic
    selection a crawl that found 41 would have spent all 40 probes on bundles and
    returned a clean "no write verb" having asked nothing that could disagree.
    """
    probe = _RecordingProbe()
    await learn_allowed_methods(_endpoints(_caldiy_routes(chunk_count=120)), probe)

    assert len(probe.asked) == MAX_OPTIONS_PROBES
    api_asked = [url for url in probe.asked if "/api/" in url]
    assert len(api_asked) == 3, (
        "a bundle set three times the budget displaced the application routes. Grade 1 "
        f"(is_api_path) must sort ahead of every chunk unconditionally; asked: {probe.asked[:5]}"
    )


@pytest.mark.asyncio
async def test_the_truncation_reaches_the_deliverable(register: PlanAlarmRegister) -> None:
    """A bound that decides coverage is reported, broken down by relevance grade."""
    await learn_allowed_methods(_endpoints(_caldiy_routes()), _RecordingProbe())

    summary = probe_budget_summary()
    assert summary["probe_truncated"] is True
    assert summary["candidates"] == 44
    assert summary["probed"] == 40
    assert summary["dropped_total"] == 4
    # Every dropped route was a static asset, so this is a budget fact and NOT an
    # ordering failure. The two are reported apart because a larger budget fixes
    # only the first.
    assert summary["ordering_failure"] is False
    assert summary["relevant_dropped_count"] == 0
    assert summary["first_omitted"]

    sweep = summary["sweeps"][0]
    assert sweep["sweep"] == "options_methods"
    dropped_grades = {int(g) for g in sweep["dropped_by_grade"]}
    assert dropped_grades and not (dropped_grades & RELEVANT_PROBE_GRADES)


@pytest.mark.asyncio
async def test_a_clean_run_still_records_the_sweep(register: PlanAlarmRegister) -> None:
    """ "Every route was asked" is a claim the report makes, not an absent section."""
    await learn_allowed_methods(_endpoints(_caldiy_routes(chunk_count=5)), _RecordingProbe())

    summary = probe_budget_summary()
    assert summary["sweeps_recorded"] == 1
    assert summary["probe_truncated"] is False
    assert summary["dropped_total"] == 0
    assert summary["first_omitted"] == ""


def test_an_ordering_failure_is_a_separate_number() -> None:
    """A dropped application route is not the same fact as a dropped favicon."""
    benign = ProbeBudgetTruncation(
        sweep="options_methods",
        budget=40,
        candidates=44,
        probed=40,
        dropped_by_grade={5: 4},
    )
    assert benign.truncated is True
    assert benign.ordering_failure is False

    inverted = ProbeBudgetTruncation(
        sweep="options_methods",
        budget=40,
        candidates=44,
        probed=40,
        dropped_by_grade={1: 3, 5: 1},
        relevant_dropped=[f"{BASE}/api/trpc"],
    )
    assert inverted.ordering_failure is True
    rendered = inverted.to_dict()
    assert rendered["ordering_failure"] is True
    assert rendered["relevant_dropped"] == [f"{BASE}/api/trpc"]
    # Grade keys survive the JSON round trip as the same strings.
    assert set(rendered["dropped_by_grade"]) == {"1", "5"}


def test_the_bound_is_absent_outside_an_engagement() -> None:
    """No register installed means no recording and no crash.

    Same contract as the crawl budget and the governor: a sweep run by a driver or
    a unit test has no report to carry it, and must behave identically.
    """
    set_active_plan_alarms(None)
    from clinkz.agents._api_schema import _select_routes

    selected = _select_routes([f"{BASE}/api/x", f"{BASE}/a.css"], 1, sweep="options_methods")
    assert selected == [f"{BASE}/api/x"]
    assert probe_budget_summary()["sweeps_recorded"] == 0
