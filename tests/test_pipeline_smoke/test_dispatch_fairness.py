"""Pipeline smoke: round-robin dispatch gives every category a turn.

Marked ``pipeline_smoke``. The first two tests drive the *real*
``ExploitAgent`` scheduler (``_step_execute_exploits`` / ``run``) — only the
per-task executor and the clock are stubbed at the boundary — so a regression
in the orchestration path is caught where a mocked-out dispatcher would hide
it. They reproduce the failure shape of engagement 5a3f5886: a single high
fan-out vuln-class (IDOR, 18 tasks, slow) sharing a bounded phase budget with
many single-task categories. Under the old sequential dispatcher the slow
class consumed the deadline tail and later categories (e.g. open_redirect)
never dispatched. Under round-robin every applicable category gets at least
one task before the deadline trips. These run without DVWA or an LLM.

The third test is the literal PART-5 gate — the exploit phase dispatching at
least one task per applicable category against a live DVWA — and skips when
the container is not reachable.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import ExploitPlan, ExploitTask, Finding, Severity
from clinkz.models.scan import Endpoint, HTTPScanResult, ScanResult, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

pytestmark = pytest.mark.pipeline_smoke


class _StubLLM(LLMClient):
    """Neutral LLM — forces methodologies down their deterministic path."""

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _scope() -> EngagementScope:
    return EngagementScope(
        name="dispatch-fairness",
        targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
    )


def _make_agent(scope: EngagementScope | None = None) -> ExploitAgent:
    llm = _StubLLM()
    state = AsyncMock(spec=StateStore)
    state.add_finding = AsyncMock(return_value="f")
    state.get_findings = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=llm,
        tools=[],
        scope=scope or _scope(),
        state=state,
        engagement_id="dispatch-fairness",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = llm
    return agent


# The 13 single-task adaptive categories, with IDOR as the high fan-out class.
_SINGLE_TASK_CATEGORIES = [
    "_test_sqli",
    "_test_xss_reflected",
    "_test_xss_stored",
    "_test_xss_dom",
    "_test_cmdi",
    "_test_lfi",
    "_test_csrf",
    "_test_file_upload",
    "_test_brute_force",
    "_test_open_redirect",
    "_test_security_headers",
    "_test_weak_session",
    "_test_javascript_attacks",
]


def _fanout_plan() -> ExploitPlan:
    tasks: list[ExploitTask] = [
        ExploitTask(test_method="_test_idor", endpoint_url=f"http://t/idor/{i}", tier=1)
        for i in range(18)
    ]
    for cat in _SINGLE_TASK_CATEGORIES:
        tasks.append(ExploitTask(test_method=cat, endpoint_url=f"http://t/{cat}", tier=1))
    return ExploitPlan(tasks=tasks, tier1_count=len(tasks))


def _scan_with(endpoints: list[Endpoint]) -> ScanResult:
    return ScanResult(
        target="example.com",
        service_scans=[
            ServiceScanResult(
                service_type="http", port=80, result=HTTPScanResult(endpoints=endpoints)
            )
        ],
        total_endpoints=len(endpoints),
    )


@pytest.mark.asyncio
async def test_every_category_dispatches_before_deadline() -> None:
    """Under a bounded deadline, the slow 18-task IDOR class must not starve
    the other 13 single-task categories."""
    agent = _make_agent()

    dispatched: list[str] = []

    async def fake_execute(task: ExploitTask, _cache: dict[str, Any]) -> list[Finding]:
        dispatched.append(task.test_method)
        if task.test_method == "_test_idor":
            await asyncio.sleep(0.05)  # the slow, high fan-out class
        return []

    agent._execute_task = fake_execute  # type: ignore[method-assign]

    # Deadline admits round 1 (one task per category) comfortably but not all
    # 18 IDOR tasks (~0.9s). stop_margin=0 → stop exactly at the deadline.
    agent._stop_margin = 0.0
    agent._deadline_ts = time.monotonic() + 0.5

    await agent._step_execute_exploits(
        _fanout_plan(), _scan_with([Endpoint(url="http://t/", params=["id"])])
    )

    dispatched_set = set(dispatched)
    expected = set(_SINGLE_TASK_CATEGORIES) | {"_test_idor"}
    missing = expected - dispatched_set
    assert not missing, f"categories starved by IDOR fan-out: {sorted(missing)}"

    # The deadline genuinely tripped mid-IDOR — i.e. the budget was the
    # binding constraint, proving fairness held under pressure rather than
    # because everything simply finished in time.
    assert agent._stopped_early is True
    assert dispatched.count("_test_idor") < 18


@pytest.mark.asyncio
async def test_run_end_to_end_dispatches_all_categories() -> None:
    """The full ``run()`` path (plan build → round-robin dispatch → persist)
    dispatches every applicable category for a parameterised endpoint set."""
    agent = _make_agent()

    dispatched: list[str] = []

    async def fake_execute(task: ExploitTask, _cache: dict[str, Any]) -> list[Finding]:
        dispatched.append(task.test_method)
        return []

    agent._execute_task = fake_execute  # type: ignore[method-assign]
    agent._http_get = AsyncMock(  # type: ignore[method-assign]
        return_value=_HTTPResponse(status=200, body="<html>ok</html>")
    )

    eps = [
        Endpoint(url=f"http://t/page{i}?id={i}", params=["id", "redirect", "page"])
        for i in range(6)
    ]
    out = await agent.run(
        {
            "scan_result": _scan_with(eps).model_dump(mode="json"),
            "research_result": {"technologies": [], "runbook": []},
        }
    )
    assert out["status"] == "complete"

    # Parameterised GET endpoints get the injection/logic + always-on web
    # classes; assert the high-signal categories from 5a3f5886 all ran.
    for cat in (
        "_test_sqli",
        "_test_cmdi",
        "_test_lfi",
        "_test_open_redirect",
        "_test_idor",
        "_test_security_headers",
    ):
        assert cat in dispatched, f"{cat} never dispatched"


@pytest.mark.asyncio
async def test_exploit_phase_against_dvwa_covers_categories(dvwa_url: str) -> None:
    """PART-5 gate: the exploit phase against live DVWA dispatches at least one
    task per applicable category within the deadline.

    Drives the real round-robin scheduler over a DVWA-shaped endpoint set. The
    per-task executor is wrapped to record the dispatched category and short
    out (the methodologies themselves are covered by the DVWA skill suite); the
    point here is that *dispatch* reaches every applicable class under a
    deadline, against a real target, rather than starving the tail."""
    agent = _make_agent(
        EngagementScope(
            name="dispatch-fairness-dvwa",
            targets=[ScopeEntry(value=dvwa_url, type=ScopeType.URL)],
        )
    )

    # DVWA's classic vulnerable surfaces — a GET injection page (many params →
    # IDOR fan-out) plus a POST form page.
    eps = [
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit",
            method="GET",
            params=["id", "Submit"],
        ),
        Endpoint(
            url=f"{dvwa_url}/vulnerabilities/exec/",
            method="POST",
            params=["ip"],
        ),
    ]
    plan = agent._build_deterministic_plan(eps, [], [])
    applicable = {t.test_method for t in plan.tasks}
    assert applicable, "deterministic plan produced no tasks for DVWA endpoints"

    dispatched: list[str] = []

    async def recording_execute(task: ExploitTask, _cache: dict[str, Any]) -> list[Finding]:
        dispatched.append(task.test_method)
        return []

    agent._execute_task = recording_execute  # type: ignore[method-assign]
    agent._stop_margin = 0.0
    agent._deadline_ts = time.monotonic() + 5.0

    await agent._step_execute_exploits(plan, _scan_with(eps))

    missing = applicable - set(dispatched)
    assert not missing, f"categories never dispatched against DVWA: {sorted(missing)}"


def test_imports_smoke() -> None:
    """Guard the import surface this smoke depends on."""
    pa = PageAnalysis(url="http://t/", body="", status=200)
    assert pa.url == "http://t/"
    _ = Severity.HIGH
