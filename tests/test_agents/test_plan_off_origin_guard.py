"""A planner-authored host is never fetched, and never with the session.

The placeholder defect (``tests/test_agents/test_plan_placeholder_guard.py``)
was survivable only by luck. Engagement 946e7036 sent

    GET http://172.20.0.4/...   ->  404

with the live engagement session cookie attached, because dispatch fetches the
page *before* it resolves ``test_method``. The URL was same-host, so the scope
check passed and the damage was one 404.

Change one byte of the model's output and the same path sends the engagement's
session cookie to a host the model invented. That is the class this file closes,
at both layers that could have stopped it:

1. **The planner** refuses an absolute URL whose origin the scan never
   discovered — an in-memory set comparison, before anything is dispatched and
   before any name is resolved.
2. **The tool layer** refuses an out-of-scope URL in ``validate_input``, which
   runs before ``execute``, so no request is ever built or sent.

Both are asserted, because either alone would have been enough and the point of
a second guard is that it does not depend on the first.
"""

from __future__ import annotations

import logging

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.models.scan import Endpoint
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.http_client import HTTPClientTool

TARGET_ORIGIN = "http://172.20.0.4"
ATTACKER_ORIGIN = "http://evil.example"


def _agent() -> ExploitAgent:
    """An agent with just enough state to parse a plan — no __init__, no IO."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.off-origin-guard")
    return agent


def _endpoints() -> list[Endpoint]:
    return [
        Endpoint(url=f"{TARGET_ORIGIN}/vulnerabilities/sqli/", method="GET", params=["id"]),
        Endpoint(url=f"{TARGET_ORIGIN}/vulnerabilities/xss_r/", method="GET", params=["name"]),
    ]


def _plan_response(url: str, method: str = "_test_sqli") -> str:
    return (
        f'{{"tasks": [{{"test_method": "{method}", "endpoint_url": "{url}", '
        f'"tier": 1, "priority": 0}}]}}'
    )


class TestPlannerRefusesAnUndiscoveredHost:
    @pytest.mark.parametrize(
        "url",
        [
            f"{ATTACKER_ORIGIN}/...",
            f"{ATTACKER_ORIGIN}/vulnerabilities/sqli/",
            "https://evil.example/collect",
            "http://169.254.169.254/latest/meta-data/",
            "http://172.20.0.9/vulnerabilities/sqli/",
            # Every scheme is fenced, not just http/https. Fencing only those
            # two sent these down the relative branch, where ``urljoin``
            # returns a foreign-scheme reference unchanged — the destination
            # survived the check written to refuse it.
            "file:///etc/passwd",
            "ftp://evil.example/x",
            "gopher://evil.example/",
            "ws://evil.example/",
            "sftp://evil.example/x",
            "javascript:fetch('http://evil.example')",
            # Userinfo wearing the target's name in front of the attacker's host.
            f"http://{TARGET_ORIGIN.removeprefix('http://')}@evil.example/x",
        ],
    )
    def test_an_off_origin_absolute_url_yields_no_task(self, url: str) -> None:
        """Including the placeholder shape that actually shipped, re-pointed."""
        plan = _agent()._parse_plan_response(_plan_response(url), _endpoints(), [], [])
        assert plan is None

    def test_the_refusal_is_logged_not_silent(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            _agent()._parse_plan_response(
                _plan_response(f"{ATTACKER_ORIGIN}/..."), _endpoints(), [], []
            )
        assert "outside the discovered origins" in caplog.text
        assert ATTACKER_ORIGIN in caplog.text

    def test_an_in_scope_absolute_url_still_survives(self) -> None:
        """Control: the fence refuses the destination, not absolute URLs."""
        plan = _agent()._parse_plan_response(
            _plan_response(f"{TARGET_ORIGIN}/vulnerabilities/sqli/"), _endpoints(), [], []
        )
        assert plan is not None
        assert plan.tasks[0].endpoint_url == f"{TARGET_ORIGIN}/vulnerabilities/sqli/"

    def test_a_relative_url_still_resolves_against_the_discovered_origin(self) -> None:
        plan = _agent()._parse_plan_response(
            _plan_response("/vulnerabilities/xss_r/"), _endpoints(), [], []
        )
        assert plan is not None
        assert plan.tasks[0].endpoint_url == f"{TARGET_ORIGIN}/vulnerabilities/xss_r/"

    @pytest.mark.parametrize(
        "url",
        [
            f"{TARGET_ORIGIN}:80/vulnerabilities/sqli/",
            f"{TARGET_ORIGIN.upper()}/vulnerabilities/sqli/",
            f"{TARGET_ORIGIN.replace('http://', 'http://172.20.0.4'.upper() and 'HTTP://')}"
            "/vulnerabilities/sqli/",
        ],
    )
    def test_an_equivalent_spelling_of_a_discovered_origin_survives(self, url: str) -> None:
        """Over-refusal costs coverage, so the comparison is on a normalised origin.

        ``http://host:80`` and ``http://host`` are one origin; so are ``HTTP://``
        and ``http://``. A string compare would drop legitimate tasks and call it
        safety.
        """
        plan = _agent()._parse_plan_response(_plan_response(url), _endpoints(), [], [])
        assert plan is not None

    def test_a_second_discovered_host_is_not_collateral(self) -> None:
        """A multi-host engagement plans across every origin the scan found.

        The fence is the discovered *set*, not the single most-frequent origin,
        precisely so tightening the planner does not quietly drop a real host.
        """
        endpoints = [
            *_endpoints(),
            Endpoint(url="http://172.20.0.5/api/orders", method="GET", params=["id"]),
        ]
        plan = _agent()._parse_plan_response(
            _plan_response("http://172.20.0.5/api/orders"), endpoints, [], []
        )
        assert plan is not None
        assert plan.tasks[0].endpoint_url == "http://172.20.0.5/api/orders"

    def test_valid_tasks_survive_alongside_a_refused_one(self) -> None:
        response = (
            '{"tasks": ['
            f'{{"test_method": "_test_sqli", "endpoint_url": "{TARGET_ORIGIN}'
            '/vulnerabilities/sqli/", "tier": 1, "priority": 0},'
            f'{{"test_method": "_test_sqli", "endpoint_url": "{ATTACKER_ORIGIN}/...",'
            ' "tier": 1, "priority": 1}'
            "]}"
        )
        plan = _agent()._parse_plan_response(response, _endpoints(), [], [])
        assert plan is not None
        assert [t.endpoint_url for t in plan.tasks] == [f"{TARGET_ORIGIN}/vulnerabilities/sqli/"]

    def test_no_discovered_endpoints_means_no_absolute_url_is_trusted(self) -> None:
        """An empty discovered set allows nothing, rather than allowing everything.

        A scan that delivered no endpoints is the state in which the planner has
        the least evidence about where the target is, so it is the worst moment
        to accept a destination the model chose.
        """
        plan = _agent()._parse_plan_response(
            _plan_response(f"{TARGET_ORIGIN}/vulnerabilities/sqli/"), [], [], []
        )
        assert plan is None


class TestScopeRefusesBeforeAnyNetworkActivity:
    """The independent second guard, at the one HTTP chokepoint."""

    @staticmethod
    def _scope() -> EngagementScope:
        return EngagementScope(
            name="off-origin-guard",
            targets=[ScopeEntry(type=ScopeType.IP, value="172.20.0.4")],
        )

    def test_validate_input_refuses_an_off_scope_host(self) -> None:
        tool = HTTPClientTool(scope=self._scope())
        with pytest.raises(ValueError, match="outside the engagement scope"):
            tool.validate_input({"method": "GET", "url": f"{ATTACKER_ORIGIN}/..."})

    @pytest.mark.asyncio
    async def test_nothing_is_dispatched_and_no_cookie_is_carried(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refusal happens before a request is built, let alone sent.

        ``_dispatch`` is the single egress seam (curl in docker mode, aiohttp on
        the host). Patching it to explode proves the refusal is not "the request
        went out and the response was discarded".
        """
        tool = HTTPClientTool(scope=self._scope(), engagement_id="off-origin-guard")

        async def _explode(_args: dict[str, object]) -> str:
            raise AssertionError("network egress reached for an out-of-scope host")

        monkeypatch.setattr(HTTPClientTool, "_dispatch", staticmethod(_explode))

        with pytest.raises(ValueError, match="outside the engagement scope"):
            args = tool.validate_input(
                {
                    "method": "GET",
                    "url": f"{ATTACKER_ORIGIN}/...",
                    "cookies": {"PHPSESSID": "the-live-engagement-session"},
                }
            )
            await tool.execute(args)

    def test_the_in_scope_control_validates(self) -> None:
        """Control: the guard refuses the host, not the request shape."""
        tool = HTTPClientTool(scope=self._scope())
        validated = tool.validate_input(
            {
                "method": "GET",
                "url": f"{TARGET_ORIGIN}/vulnerabilities/sqli/",
                "cookies": {"PHPSESSID": "the-live-engagement-session"},
            }
        )
        assert validated["url"] == f"{TARGET_ORIGIN}/vulnerabilities/sqli/"
        assert validated["cookies"] == {"PHPSESSID": "the-live-engagement-session"}
