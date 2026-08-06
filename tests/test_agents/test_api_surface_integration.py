"""The API-surface path end to end, and the two defects that made it moot.

An engagement against a live SPA produced 288 requests, 138 discovered
endpoints and **zero findings**. Neither cause was about JSON bodies:

* the Scan phase overran the orchestrator's generic phase timeout, which
  force-kills the agent and discards its return value, so the Exploit planner
  received ``Endpoints (0 unique) []`` after the scan had mapped 138; and
* with no endpoints, the planner fell back to endpoint URLs the model wrote as
  **paths** (``/rest/user/login``), which are not fetchable — every probe
  returned the transport-failure sentinel, so eighteen methodologies ran in
  twenty milliseconds and each reported a clean non-finding.

These tests pin both, plus the ranking change that keeps a body-carried
injection point from being dropped at the plan cap.
"""

from __future__ import annotations

import time

import pytest

from clinkz.agents._url_shape import crawl_visit_priority, is_api_path
from clinkz.agents.exploit import (
    _endpoint_class_relevance,
    _endpoint_class_sort_key,
    _endpoint_meets_precondition,
)
from clinkz.models.scan import Endpoint, ParamLocation

BASE = "http://target.test"


# ---------------------------------------------------------------------------
# The planner must be able to REACH what it plans
# ---------------------------------------------------------------------------


class _Planner:
    """Just the two URL-resolution helpers, unbound from the agent."""

    def __init__(self) -> None:
        import logging

        self._logger = logging.getLogger("test")

    from clinkz.agents.exploit import ExploitAgent

    _plan_base_origin = staticmethod(ExploitAgent._plan_base_origin)
    _absolutize_planned_url = ExploitAgent._absolutize_planned_url


def test_a_planned_path_is_resolved_against_the_discovered_origin() -> None:
    planner = _Planner()
    endpoints = [Endpoint(url=f"{BASE}/api/a"), Endpoint(url=f"{BASE}/api/b")]
    origin = planner._plan_base_origin(endpoints)
    assert origin == BASE
    assert planner._absolutize_planned_url("/rest/user/login", origin) == f"{BASE}/rest/user/login"
    # Already absolute — untouched.
    assert planner._absolutize_planned_url(f"{BASE}/x", origin) == f"{BASE}/x"


def test_a_relative_url_with_no_known_origin_is_dropped_not_probed_blind() -> None:
    planner = _Planner()
    assert planner._absolutize_planned_url("/rest/user/login", "") == ""


def test_the_plan_origin_is_a_function_of_the_set_not_its_order() -> None:
    """A stray off-origin artifact must not redirect the whole plan, and two
    identical endpoint sets must yield the same origin whatever order they
    arrive in — a concurrent crawler emits a different sequence each run."""
    planner = _Planner()
    endpoints = [
        Endpoint(url=f"{BASE}/api/a"),
        Endpoint(url="http://cdn.other.test/x.js"),
        Endpoint(url=f"{BASE}/api/b"),
    ]
    assert planner._plan_base_origin(endpoints) == BASE
    assert planner._plan_base_origin(list(reversed(endpoints))) == BASE


# ---------------------------------------------------------------------------
# The scan phase must deliver a partial map rather than none
# ---------------------------------------------------------------------------


def test_scan_budget_is_absent_until_a_phase_starts() -> None:
    """Direct invocation (smoke suites, drivers, ``scan_additional``) is
    unbudgeted and byte-identical — the deadline exists only inside ``run()``."""
    from clinkz.agents.scan import ScanAgent

    agent = ScanAgent.__new__(ScanAgent)
    agent._deadline = None
    assert not agent._budget_exhausted()
    assert agent._budget_remaining() == float("inf")


def test_scan_budget_expires_and_is_reported_as_remaining_time() -> None:
    from clinkz.agents.scan import ScanAgent

    agent = ScanAgent.__new__(ScanAgent)
    agent._deadline = time.monotonic() + 60
    assert not agent._budget_exhausted()
    assert 0 < agent._budget_remaining() <= 60
    agent._deadline = time.monotonic() - 1
    assert agent._budget_exhausted()
    assert agent._budget_remaining() == 0.0


def test_a_budget_guard_asks_whether_the_work_will_finish() -> None:
    """The distinction that made two consecutive live runs fail identically.

    "Has the clock run out?" is not the question. Directory fuzzing costs about
    five minutes and logs nothing while it runs; started with 104 seconds left,
    the phase finished 17 seconds after the orchestrator had already given up
    and discarded the entire attack surface. A guard in front of expensive work
    has to know what that work COSTS.
    """
    import logging

    from clinkz.agents.scan import _COST_CRAWL, _COST_EXPANSION_PASS, _COST_FUZZ, ScanAgent

    agent = ScanAgent.__new__(ScanAgent)
    agent._logger = logging.getLogger("test")

    # 104 seconds left — the exact live case.
    agent._deadline = time.monotonic() + 104
    assert not agent._budget_exhausted(), "the old guard would have allowed all of this"
    assert not agent._budget_allows(_COST_FUZZ, "fuzz")
    assert not agent._budget_allows(_COST_EXPANSION_PASS, "expansion")
    assert agent._budget_allows(_COST_CRAWL, "crawl")  # 90s fits in 104s

    # Unbudgeted (direct invocation) allows everything.
    agent._deadline = None
    assert agent._budget_allows(_COST_EXPANSION_PASS, "expansion")

    # Each cost is ordered by how expensive that step actually is.
    assert _COST_CRAWL < _COST_FUZZ < _COST_EXPANSION_PASS


@pytest.mark.parametrize("status", ["timeout", "halted"])
def test_a_stopped_phase_keeps_the_result_it_already_delivered(status: str) -> None:
    """Both stop paths return the partial.

    On the scan phase the difference is total: its return value IS the attack
    surface, so discarding it leaves the Exploit planner with no endpoints and
    every methodology probing an invented URL.
    """
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    delivered = {"endpoints": ["a", "b"]}
    stopped = OrchestratorAgent._phase_stop_result(status, "scan", delivered)
    assert stopped["status"] == status
    assert stopped["agent"] == "scan"
    assert stopped["result"] == delivered

    # Nothing delivered → no empty ``result`` key invented.
    assert "result" not in OrchestratorAgent._phase_stop_result(status, "scan", {})


def test_a_stopped_phase_keeps_its_status_detail_alongside_the_partial() -> None:
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    stopped = OrchestratorAgent._phase_stop_result(
        "halted",
        "exploit",
        {"findings": []},
        halt_reason="kill_switch",
        halt_detail="operator abort",
    )
    assert stopped["halt_reason"] == "kill_switch"
    assert stopped["halt_detail"] == "operator abort"
    # A phase that delivered "no findings" delivered a RESULT; only a phase
    # that delivered nothing at all omits the key.
    assert stopped["result"] == {"findings": []}
    assert "result" not in OrchestratorAgent._phase_stop_result("halted", "exploit", {})


# ---------------------------------------------------------------------------
# Ranking: a body-carried injection point is that class's own surface
# ---------------------------------------------------------------------------


def _json_endpoint(url: str, *fields: str) -> Endpoint:
    return Endpoint(
        url=url,
        method="POST",
        params=list(fields),
        content_type="application/json",
        param_locations=dict.fromkeys(fields, ParamLocation.JSON_BODY),
    )


def test_a_json_body_field_satisfies_the_injection_preconditions() -> None:
    endpoint = _json_endpoint(f"{BASE}/api/x", "note")
    assert _endpoint_meets_precondition("body_param", endpoint, "/api/x")
    plain = Endpoint(url=f"{BASE}/api/x")
    assert not _endpoint_meets_precondition("body_param", plain, "/api/x")


def test_an_api_write_outranks_a_bare_route_for_the_injection_classes() -> None:
    """Without this the class's own surface lands in the same tie bucket as the
    site's static routes and is dropped at the plan cap."""
    injectable = _json_endpoint(f"{BASE}/api/records", "note")
    bare = Endpoint(url=f"{BASE}/api/records")
    for method in ("_test_sqli", "_test_nosqli", "_test_ssti", "_test_cmdi"):
        assert _endpoint_class_relevance(method, injectable) < _endpoint_class_relevance(
            method, bare
        ), method
        assert _endpoint_class_sort_key(method, injectable) < _endpoint_class_sort_key(
            method, bare
        ), method


def test_api_routes_are_visited_before_ordinary_pages() -> None:
    """On an SPA the /api routes ARE the surface — there are no other pages."""
    assert is_api_path("/api/items") and is_api_path("/rest/x") and not is_api_path("/about")
    assert crawl_visit_priority(f"{BASE}/api/items") < crawl_visit_priority(f"{BASE}/about")
    # A parameterised URL still wins outright, and assets still lose.
    assert crawl_visit_priority(f"{BASE}/s?q=1") < crawl_visit_priority(f"{BASE}/api/items")
    assert crawl_visit_priority(f"{BASE}/api/items") < crawl_visit_priority(f"{BASE}/a.css")


def test_server_rendered_targets_keep_their_relative_order() -> None:
    """The DVWA-shaped baseline must not move: a handler page still beats an
    asset, a doc file and a doubled-path crawl artifact, in that order."""
    grades = [
        crawl_visit_priority(f"{BASE}/vulnerabilities/sqli/?id=1"),
        crawl_visit_priority(f"{BASE}/vulnerabilities/sqli/"),
        crawl_visit_priority(f"{BASE}/view_source.php"),
        crawl_visit_priority(f"{BASE}/README.md"),
        crawl_visit_priority(f"{BASE}/style.css"),
        crawl_visit_priority(f"{BASE}/vulnerabilities/vulnerabilities/x"),
    ]
    assert grades == sorted(grades) and len(set(grades)) == len(grades)
