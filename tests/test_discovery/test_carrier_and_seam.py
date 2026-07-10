"""Keyless unit gate for the proof-seam carrier fix + plan-union (discovery slice).

Two deterministic behaviours the live GeoServer confirmation depends on:

  1. **Host-alignment carrier constraint (§10 gap #3).** When a page carries the
     ``align_host_with_injected_url_host`` constraint, ``_send_probe`` must set the
     request ``Host`` header to the injected url's host (so a guard comparing the
     two is satisfied). Without the constraint the probe is byte-for-byte
     unchanged — proven by capturing the ``host_override`` reaching the HTTP layer.
  2. **Discovery plan-union (§2.7).** ``_merge_discovery_tasks`` unions discovery
     hypotheses as the third plan source: added when novel, deduped when they
     duplicate an existing task, left untouched when there are none.

No LLM, no container.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.discovery.constants import CARRIER_ALIGN_HOST
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import ExploitPlan, ExploitTask
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="carrier-seam-test",
    targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
)


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None):
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="carrier-seam-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. Host-alignment carrier constraint
# ---------------------------------------------------------------------------


def test_carrier_kwargs_align_host():
    agent = _make_agent()
    page = PageAnalysis(
        url="http://localhost:8080/geoserver/TestWfsPost",
        body="",
        status=200,
        input_params=["url"],
        carrier_constraints=[CARRIER_ALIGN_HOST],
    )
    assert agent._carrier_kwargs(page, "http://127.0.0.1:8080/geoserver/") == {
        "host_override": "127.0.0.1:8080"
    }
    # A non-URL value has no host → no override.
    assert agent._carrier_kwargs(page, "not-a-url") == {}


def test_carrier_kwargs_absent_without_constraint():
    agent = _make_agent()
    page = PageAnalysis(url="http://localhost:8080/x", body="", status=200, input_params=["url"])
    assert agent._carrier_kwargs(page, "http://127.0.0.1:8080/") == {}


def test_send_probe_sets_host_header_when_constrained():
    """The probe's Host header is rewritten to the injected url's host."""
    agent = _make_agent()
    captured: dict[str, Any] = {}

    async def fake_post(url: str, data: dict[str, str], **kwargs: Any) -> _HTTPResponse:
        captured["url"] = url
        captured["host_override"] = kwargs.get("host_override")
        captured["data"] = data
        return _HTTPResponse(status=200, body="ok")

    agent._http_post = fake_post  # type: ignore[method-assign]
    page = PageAnalysis(
        url="http://localhost:8080/geoserver/TestWfsPost",
        body="",
        status=200,
        input_params=["url"],
        param_locations={"url": ParamLocation.FORM_BODY},
        carrier_constraints=[CARRIER_ALIGN_HOST],
    )
    _run(agent._send_probe(page, "url", "http://127.0.0.1:8080/geoserver/"))
    assert captured["host_override"] == "127.0.0.1:8080"
    assert captured["data"]["url"] == "http://127.0.0.1:8080/geoserver/"


def test_send_probe_no_host_override_without_constraint():
    """Without the constraint, no host_override is passed (unchanged behaviour)."""
    agent = _make_agent()
    captured: dict[str, Any] = {"host_override": "SENTINEL"}

    async def fake_post(url: str, data: dict[str, str], **kwargs: Any) -> _HTTPResponse:
        captured["host_override"] = kwargs.get("host_override")
        return _HTTPResponse(status=200, body="ok")

    agent._http_post = fake_post  # type: ignore[method-assign]
    page = PageAnalysis(
        url="http://localhost:8080/geoserver/TestWfsPost",
        body="",
        status=200,
        input_params=["url"],
        param_locations={"url": ParamLocation.FORM_BODY},
    )
    _run(agent._send_probe(page, "url", "http://127.0.0.1:8080/"))
    assert captured["host_override"] is None


# ---------------------------------------------------------------------------
# 2. Discovery plan-union (§2.7)
# ---------------------------------------------------------------------------


def _task(method: str, url: str, params: list[str]) -> ExploitTask:
    return ExploitTask(test_method=method, endpoint_url=url, endpoint_params=params, tier=1)


def test_merge_discovery_tasks_adds_novel_endpoint():
    agent = _make_agent()
    plan = ExploitPlan(tasks=[_task("_test_sqli", "http://localhost:8080/a", ["q"])], tier1_count=1)
    discovery = _task("_test_ssrf", "http://localhost:8080/geoserver/TestWfsPost", ["url"])
    discovery.carrier_constraints = [CARRIER_ALIGN_HOST]
    agent._discovery_tasks = [discovery]

    merged = agent._merge_discovery_tasks(plan)
    assert len(merged.tasks) == 2
    added = merged.tasks[-1]
    assert added.test_method == "_test_ssrf"
    assert added.endpoint_url.endswith("/TestWfsPost")
    assert added.priority == 1  # assigned after the existing task (priority 0)


def test_merge_discovery_tasks_dedups_existing_coverage():
    agent = _make_agent()
    url = "http://localhost:8080/geoserver/TestWfsPost"
    plan = ExploitPlan(tasks=[_task("_test_ssrf", url, ["url"])], tier1_count=1)
    agent._discovery_tasks = [_task("_test_ssrf", url, ["url"])]  # same coverage key
    merged = agent._merge_discovery_tasks(plan)
    assert len(merged.tasks) == 1  # duplicate dropped


def test_merge_discovery_tasks_noop_when_empty():
    agent = _make_agent()
    plan = ExploitPlan(tasks=[_task("_test_sqli", "http://localhost:8080/a", ["q"])], tier1_count=1)
    merged = agent._merge_discovery_tasks(plan)
    assert merged.tasks == plan.tasks
