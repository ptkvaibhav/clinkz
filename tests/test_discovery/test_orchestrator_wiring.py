"""Keyless gate for the Orchestrator ↔ discovery-engine wiring (§4.5).

Slice 1 co-located the four layers into ``DiscoveryEngine.discover()`` and left the
engine driven only by the standalone live driver. Slice 2 wires it into the real
engine: the Orchestrator runs discovery over the engagement source tree BEFORE the
Exploit phase plans and hands the lowered Tier-A hypotheses across the message bus,
where the Exploit agent parses them into ``self._discovery_tasks``. These tests
prove that path deterministically — no LLM, no container:

  * ``_build_discovery_tasks`` produces the Solr ``stream.url`` task from a gray-box
    ``source_dir`` (and is inert without one — the black-box default), and
  * a hypothesis survives the JSON handoff (``model_dump`` → parse) and unions into
    the plan through the unchanged ``_merge_discovery_tasks`` chokepoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clinkz.agents.exploit import ExploitAgent
from clinkz.discovery import DiscoveryEngine
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import ExploitPlan, ExploitTask
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent

SOLR_FIXTURE = str(Path(__file__).parent.parent / "fixtures" / "solr_remote_streaming")
SOLR_BASE = "http://localhost:8983/solr/demo/debug/dump"


class _SilentLLM(LLMClient):
    async def reason(self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None):
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _orchestrator_with_scope(scope: EngagementScope) -> OrchestratorAgent:
    agent = OrchestratorAgent(llm=_SilentLLM())
    agent._scope = scope
    return agent


# --- _build_discovery_tasks -------------------------------------------------


def test_build_discovery_tasks_from_graybox_source():
    """A gray-box ``source_dir`` yields the Solr stream.url SSRF Tier-A task.

    The engine now catalogues a second capability class, so Solr's ``stream.file``
    → ``new File(file)`` local file read *also* surfaces (a legitimate multi-class
    transfer). The SSRF task under test is byte-identical — no regression.
    """
    scope = EngagementScope(
        name="solr-graybox",
        targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
        source_dir=SOLR_FIXTURE,
        discovery_base_url=SOLR_BASE,
    )
    orch = _orchestrator_with_scope(scope)
    tasks = orch._build_discovery_tasks(["Java", "Solr"], "localhost")
    task = next(t for t in tasks if t.test_method == "_test_ssrf")
    assert task.endpoint_url == SOLR_BASE  # operator-supplied reflecting handler
    assert task.endpoint_params == ["stream.url"]
    assert task.param_locations == {"stream.url": ParamLocation.QUERY}
    assert task.carrier_constraints == []  # Solr has no host guard → no carrier
    # The file-read class also transfers to Solr's stream.file (a bonus, not a
    # regression) — same catalog, no Solr-specific entry.
    file_read = next(t for t in tasks if t.test_method == "_test_lfi")
    assert file_read.endpoint_params == ["stream.file"]


def test_build_discovery_tasks_inert_without_source_dir():
    """No ``source_dir`` ⇒ no tasks (the default black-box pipeline is unchanged)."""
    scope = EngagementScope(
        name="blackbox",
        targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
    )
    orch = _orchestrator_with_scope(scope)
    assert orch._build_discovery_tasks(["Java"], "localhost") == []


def test_build_discovery_tasks_missing_source_dir_degrades():
    """A configured but non-existent source tree degrades to black-box, not a crash."""
    scope = EngagementScope(
        name="bad-source",
        targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)],
        source_dir=str(Path(__file__).parent / "does-not-exist"),
    )
    orch = _orchestrator_with_scope(scope)
    assert orch._build_discovery_tasks(["Java"], "localhost") == []


def test_build_discovery_tasks_falls_back_to_primary_target():
    """With no explicit ``discovery_base_url`` the primary target URL is the base."""
    scope = EngagementScope(
        name="geoserver-fallback",
        targets=[ScopeEntry(value="http://localhost:8080/geoserver", type=ScopeType.URL)],
        source_dir=str(Path(__file__).parent.parent / "fixtures" / "geoserver_TestWfsPost.java"),
    )
    orch = _orchestrator_with_scope(scope)
    tasks = orch._build_discovery_tasks(["Java", "GeoServer"], "geoserver")
    assert len(tasks) == 1
    assert tasks[0].endpoint_url == "http://localhost:8080/geoserver/TestWfsPost"


# --- The message-bus handoff round-trip -------------------------------------


def test_parse_discovery_tasks_round_trip_and_union():
    """A serialized hypothesis survives the handoff and unions into the plan.

    Mirrors the real path: the Orchestrator ``model_dump(mode="json")``s each task
    into the exploit message content; the Exploit agent parses them back and merges
    them through the same ``_merge_discovery_tasks`` chokepoint as a direct-drive.
    """
    disc = DiscoveryEngine().discover(SOLR_FIXTURE, ["Java", "Solr"], SOLR_BASE)
    wire = [t.model_dump(mode="json") for t in disc.exploit_tasks()]  # JSON handoff

    parsed = ExploitAgent._parse_discovery_tasks(wire)
    ssrf = next(t for t in parsed if t.test_method == "_test_ssrf")
    assert ssrf.param_locations == {"stream.url": ParamLocation.QUERY}


def test_parse_discovery_tasks_skips_malformed():
    """A malformed entry is skipped; valid ones survive (phase never crashes)."""
    good = ExploitTask(
        test_method="_test_ssrf", endpoint_url=SOLR_BASE, endpoint_params=["stream.url"], tier=1
    ).model_dump(mode="json")
    parsed = ExploitAgent._parse_discovery_tasks([good, {"not": "a task"}, 42])
    assert len(parsed) == 1
    assert parsed[0].endpoint_url == SOLR_BASE


def test_parse_discovery_tasks_passes_through_instances():
    """Already-constructed tasks (direct-drive) pass through unchanged."""
    task = ExploitTask(test_method="_test_ssrf", endpoint_url=SOLR_BASE, tier=1)
    parsed = ExploitAgent._parse_discovery_tasks([task])
    assert parsed == [task]


def test_handoff_unions_into_plan():
    """End-to-end: parsed handoff tasks merge as the third plan source."""
    disc = DiscoveryEngine().discover(SOLR_FIXTURE, ["Java", "Solr"], SOLR_BASE)
    wire = [t.model_dump(mode="json") for t in disc.exploit_tasks()]

    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=EngagementScope(
            name="solr", targets=[ScopeEntry(value="localhost", type=ScopeType.DOMAIN)]
        ),
        state=None,
        engagement_id="solr-wiring",
    )
    agent._discovery_tasks = ExploitAgent._parse_discovery_tasks(wire)
    plan = ExploitPlan(
        tasks=[ExploitTask(test_method="_test_sqli", endpoint_url="http://localhost/a", tier=1)],
        tier1_count=1,
    )
    merged = agent._merge_discovery_tasks(plan)
    # The pre-existing sqli plan task + the two Solr hypotheses (stream.url SSRF and
    # stream.file file read) union in as the third plan source.
    assert len(merged.tasks) == 3
    ssrf = next(t for t in merged.tasks if t.test_method == "_test_ssrf")
    assert ssrf.endpoint_url == SOLR_BASE
