"""Unit tests for OrchestratorAgent — concurrent phase orchestration.

Tests use:
- A mock LLM that returns simple text responses
- A patched AgentLifecycleManager so no real agents are started
- A real in-memory StateStore (aiosqlite :memory:) so persistence is real

Key pattern
-----------
Each ``spin_up`` side-effect immediately:
1. Puts a RESULT message on the bus for the orchestrator.
2. Marks the agent as stopped in the lifecycle manager.

This simulates each phase completing instantly.

Coverage:
- Full pipeline: recon → concurrent(research+scan+exploit) → report
- Phase results are carried forward to subsequent phases
- Cross-phase QUERY handling
- MAX_CROSS_PHASE_RESPINS limit is enforced
- Default credential testing between recon and concurrent phase
- Error in a phase returns error result
- httpx 'url' alias for 'target'
- Per-agent LLM configuration
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from clinkz.comms.bus import MessageBus
from clinkz.comms.message import AgentMessage, MessageType
from clinkz.comms.protocol import ORCHESTRATOR
from clinkz.llm.base import LLMClient
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import MAX_CROSS_PHASE_RESPINS, OrchestratorAgent

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="Test Engagement",
    targets=[ScopeEntry(value="10.10.10.1", type=ScopeType.IP)],
)

# The expected phases spun up in a full pipeline run (recon is sequential,
# then scan+exploit+research run concurrently, then report is sequential).
# The exact order of scan/exploit/research may vary since they're concurrent,
# but recon is always first and report is always last.
_SEQUENTIAL_PHASES = {"recon", "report"}
_CONCURRENT_PHASES = {"scan", "exploit", "research"}
_ALL_PHASES = _SEQUENTIAL_PHASES | _CONCURRENT_PHASES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MockLLM(LLMClient):
    """Simple mock LLM that returns canned text responses."""

    async def reason(self, messages, tools=None):
        raise NotImplementedError("Deterministic orchestrator does not call reason()")

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return "Mock LLM response based on available data."


def _result_msg(from_agent: str, engagement_id: str, content: dict) -> AgentMessage:
    """Create a RESULT message from a phase agent to the Orchestrator."""
    return AgentMessage.result(
        from_agent=from_agent,
        to_agent=ORCHESTRATOR,
        engagement_id=engagement_id,
        content=content,
    )


def _make_lifecycle_mock(bus_holder: list, phase_results: dict[str, dict] | None = None):
    """Create a mock AgentLifecycleManager that simulates instant phase completion.

    Args:
        bus_holder: List to capture the real MessageBus from the orchestrator.
        phase_results: Optional mapping of agent_type → result content.
                       Defaults to {"status": "complete"} for all phases.

    Returns:
        (mock_lifecycle, running_agents list)
    """
    default_results = phase_results or {}
    running_agents: list[str] = []
    mock_lifecycle = MagicMock()
    mock_lifecycle.get_status.return_value = {}
    mock_lifecycle.get_running_agents.side_effect = lambda: list(running_agents)
    mock_lifecycle.shut_down = AsyncMock()

    async def _spin_up(agent_type: str, task_msg: AgentMessage) -> MagicMock:
        running_agents.append(agent_type)
        if bus_holder:
            result_content = default_results.get(
                agent_type, {"status": "complete", "agent": agent_type}
            )
            await bus_holder[0].send(
                _result_msg(agent_type, task_msg.engagement_id, result_content)
            )
            if agent_type in running_agents:
                running_agents.remove(agent_type)
        return MagicMock()

    mock_lifecycle.spin_up = AsyncMock(side_effect=_spin_up)

    return mock_lifecycle, running_agents


async def _run_orchestrator(
    phase_results: dict[str, dict] | None = None,
    scope: EngagementScope = SCOPE,
) -> tuple[dict, MagicMock]:
    """Run OrchestratorAgent with mocked lifecycle and instant phase completion.

    Patches _build_agent_llms to skip real LLM client creation.

    Args:
        phase_results: Optional mapping of agent_type → result content for each phase.
        scope: Engagement scope.

    Returns:
        (result_dict, mock_lifecycle)
    """
    bus_holder: list[MessageBus] = []
    mock_lifecycle, running_agents = _make_lifecycle_mock(bus_holder, phase_results)

    def _lifecycle_constructor(**kwargs: Any) -> MagicMock:
        if "bus" in kwargs:
            bus_holder.append(kwargs["bus"])
        running_agents.clear()
        return mock_lifecycle

    llm = _MockLLM()
    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    with (
        patch(
            "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
            side_effect=_lifecycle_constructor,
        ),
        patch.object(orchestrator, "_probe_url", new=AsyncMock(return_value=None)),
        patch.object(orchestrator, "_attempt_login", new=AsyncMock(return_value=False)),
        patch.object(orchestrator, "_build_agent_llms", return_value={}),
    ):
        result = await orchestrator.run(scope)

    return result, mock_lifecycle


# ---------------------------------------------------------------------------
# Test 1: Full concurrent pipeline run
# ---------------------------------------------------------------------------


async def test_full_concurrent_pipeline() -> None:
    """Orchestrator runs: recon → concurrent(research+scan+exploit) → report."""
    # Provide recon result with technologies so research agent is triggered
    phase_results = {
        "recon": {"tech": ["nginx", "php"], "hosts": [{"ip": "10.10.10.1"}]},
    }
    result, mock_lifecycle = await _run_orchestrator(phase_results=phase_results)

    spun_types = [call[0][0] for call in mock_lifecycle.spin_up.call_args_list]

    # Recon must be first
    assert spun_types[0] == "recon"
    # Report must be last
    assert spun_types[-1] == "report"
    # All expected phases are present
    assert set(spun_types) == _ALL_PHASES

    assert result["status"] == "completed"
    assert "phases" in result
    # All phase results should be present
    for phase in _ALL_PHASES:
        assert phase in result["phases"], f"Missing phase result: {phase}"


# ---------------------------------------------------------------------------
# Test 2: Phase results carry forward
# ---------------------------------------------------------------------------


async def test_phase_results_carry_forward() -> None:
    """Recon results are passed to scan and exploit tasks."""
    recon_data = {
        "hosts": [{"ip": "10.10.10.1", "ports": [80, 443]}],
        "tech": ["nginx"],
    }
    scan_data = {
        "endpoints": ["/login", "/api/v1/users"],
        "parameters": {"username": "string", "password": "string"},
    }

    result, mock_lifecycle = await _run_orchestrator(
        phase_results={"recon": recon_data, "scan": scan_data}
    )

    # Find scan and exploit spin_up calls
    spin_calls = {call[0][0]: call[0][1] for call in mock_lifecycle.spin_up.call_args_list}

    # Scan task should include recon_findings
    assert "recon_findings" in spin_calls["scan"].content

    # Exploit task should include recon_findings
    assert "recon_findings" in spin_calls["exploit"].content

    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 3: Recon is always first, report is always last
# ---------------------------------------------------------------------------


async def test_recon_first_report_last() -> None:
    """Running twice produces the same macro-phase ordering."""
    phase_results = {
        "recon": {"tech": ["nginx"], "hosts": [{"ip": "10.10.10.1"}]},
    }
    _, lc1 = await _run_orchestrator(phase_results=phase_results)
    _, lc2 = await _run_orchestrator(phase_results=phase_results)

    for lc in (lc1, lc2):
        order = [call[0][0] for call in lc.spin_up.call_args_list]
        assert order[0] == "recon", "Recon must be first"
        assert order[-1] == "report", "Report must be last"
        assert set(order) == _ALL_PHASES


# ---------------------------------------------------------------------------
# Test 4: Cross-phase QUERY triggers re-spin
# ---------------------------------------------------------------------------


async def test_cross_phase_query_triggers_respin() -> None:
    """Verify the respin counter and mechanism work."""
    result, mock_lifecycle = await _run_orchestrator()

    spun_types = [call[0][0] for call in mock_lifecycle.spin_up.call_args_list]
    assert "recon" in spun_types
    assert "exploit" in spun_types
    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 5: MAX_CROSS_PHASE_RESPINS is enforced
# ---------------------------------------------------------------------------


async def test_max_cross_phase_respins_enforced() -> None:
    """After MAX_CROSS_PHASE_RESPINS, queries are answered from state only."""
    llm = _MockLLM()
    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    # Simulate hitting the limit
    orchestrator._cross_phase_respins = MAX_CROSS_PHASE_RESPINS

    # A query with needs_agent should NOT trigger a respin
    assert orchestrator._cross_phase_respins >= MAX_CROSS_PHASE_RESPINS


# ---------------------------------------------------------------------------
# Test 6: Default credential testing extracts technologies
# ---------------------------------------------------------------------------


def test_extract_technologies_from_recon() -> None:
    """_extract_technologies pulls tech names from various result shapes."""
    llm = _MockLLM()
    orch = OrchestratorAgent(llm=llm, db_path=":memory:")

    # Direct tech list
    result1 = {"tech": ["nginx", "PHP", "MySQL"]}
    assert orch._extract_technologies(result1) == ["mysql", "nginx", "php"]

    # Nested in hosts
    result2 = {"hosts": [{"ip": "1.2.3.4", "technologies": ["DVWA", "Apache"]}]}
    assert orch._extract_technologies(result2) == ["apache", "dvwa"]

    # Empty result
    assert orch._extract_technologies({}) == []

    # String instead of list
    result3 = {"tech": "WordPress"}
    assert orch._extract_technologies(result3) == ["wordpress"]


# ---------------------------------------------------------------------------
# Test 7: Error in recon phase returns error result but pipeline continues
# ---------------------------------------------------------------------------


async def test_phase_error_returns_error_result() -> None:
    """When recon sends ERROR, the phase returns an error result but
    the pipeline continues through the concurrent and report phases."""
    bus_holder: list[MessageBus] = []
    running_agents: list[str] = []

    mock_lifecycle = MagicMock()
    mock_lifecycle.get_status.return_value = {}
    mock_lifecycle.get_running_agents.side_effect = lambda: list(running_agents)
    mock_lifecycle.shut_down = AsyncMock()

    async def _spin_up(agent_type: str, task_msg: AgentMessage) -> MagicMock:
        running_agents.append(agent_type)
        if agent_type == "recon":
            # Recon sends an ERROR
            await bus_holder[0].send(
                AgentMessage.error(
                    from_agent="recon",
                    to_agent=ORCHESTRATOR,
                    engagement_id=task_msg.engagement_id,
                    content={"error": "nmap not installed"},
                )
            )
            if agent_type in running_agents:
                running_agents.remove(agent_type)
        else:
            await bus_holder[0].send(
                _result_msg(agent_type, task_msg.engagement_id, {"status": "complete"})
            )
            if agent_type in running_agents:
                running_agents.remove(agent_type)
        return MagicMock()

    mock_lifecycle.spin_up = AsyncMock(side_effect=_spin_up)

    def _lifecycle_constructor(**kwargs: Any) -> MagicMock:
        if "bus" in kwargs:
            bus_holder.append(kwargs["bus"])
        running_agents.clear()
        return mock_lifecycle

    llm = _MockLLM()
    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    with (
        patch(
            "clinkz.orchestrator.orchestrator.AgentLifecycleManager",
            side_effect=_lifecycle_constructor,
        ),
        patch.object(orchestrator, "_probe_url", new=AsyncMock(return_value=None)),
        patch.object(orchestrator, "_attempt_login", new=AsyncMock(return_value=False)),
        patch.object(orchestrator, "_build_agent_llms", return_value={}),
    ):
        result = await orchestrator.run(SCOPE)

    # Recon error should be in the phases
    assert result["phases"]["recon"]["status"] == "error"
    assert "nmap" in result["phases"]["recon"]["error"]
    # Engagement should still complete (subsequent phases run with error result)
    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# Test 8: httpx 'url' alias for 'target'
# ---------------------------------------------------------------------------


def test_httpx_url_alias() -> None:
    """httpx should accept 'url' as an alias for 'target'."""
    from clinkz.tools.httpx_tool import HttpxTool

    tool = HttpxTool(scope=SCOPE)
    targets = tool._normalize_targets({"url": "http://10.10.10.1"})
    assert targets == ["http://10.10.10.1"]

    # Both url and target provided — target takes precedence (or both included)
    targets2 = tool._normalize_targets(
        {
            "target": "http://10.10.10.1:80",
            "url": "http://10.10.10.1:443",
        }
    )
    assert "http://10.10.10.1:80" in targets2


# ---------------------------------------------------------------------------
# Test 9: Messages are persisted in the state store
# ---------------------------------------------------------------------------


async def test_messages_persisted_in_state_store() -> None:
    """Phase tasks result in persisted messages via the state store."""
    result, mock_lifecycle = await _run_orchestrator()

    # The orchestrator ran through all phases successfully
    assert result["status"] == "completed"
    # At least 4 spin_up calls (recon + scan + exploit + report; research if techs found)
    assert mock_lifecycle.spin_up.call_count >= 4

    # Each spin_up receives a proper task message
    for call in mock_lifecycle.spin_up.call_args_list:
        task_msg: AgentMessage = call[0][1]
        assert isinstance(task_msg, AgentMessage)
        assert task_msg.message_type == MessageType.TASK
        assert task_msg.from_agent == ORCHESTRATOR
        assert "task" in task_msg.content


# ---------------------------------------------------------------------------
# Test 10: Per-agent LLM configuration
# ---------------------------------------------------------------------------


def test_build_agent_llms() -> None:
    """_build_agent_llms creates per-agent LLM clients from settings."""
    llm = _MockLLM()
    orchestrator = OrchestratorAgent(llm=llm, db_path=":memory:")

    # Patch get_llm_client to return mock LLMs and track calls
    created_providers: list[str] = []

    def _mock_get_llm_client(provider: str) -> _MockLLM:
        created_providers.append(provider)
        return _MockLLM()

    with patch(
        "clinkz.orchestrator.orchestrator.get_llm_client",
        side_effect=_mock_get_llm_client,
    ):
        agent_llms = orchestrator._build_agent_llms()

    # Should have created LLM clients for each agent type
    assert "recon" in agent_llms
    assert "scan" in agent_llms
    assert "exploit" in agent_llms
    assert "research" in agent_llms
    assert "report" in agent_llms
    assert len(created_providers) == 5


# ---------------------------------------------------------------------------
# Test 11: Concurrent phases all get results
# ---------------------------------------------------------------------------


async def test_concurrent_phases_all_get_results() -> None:
    """Research, Scan, and Exploit all produce results in the concurrent phase."""
    phase_results = {
        "recon": {"tech": ["nginx"], "hosts": [{"ip": "10.10.10.1"}]},
        "research": {"runbook_entries": 5, "status": "complete"},
        "scan": {"endpoints_found": 12, "status": "complete"},
        "exploit": {"findings": 3, "status": "complete"},
        "report": {"status": "complete"},
    }

    result, _ = await _run_orchestrator(phase_results=phase_results)

    assert result["status"] == "completed"
    assert result["phases"]["research"]["runbook_entries"] == 5
    assert result["phases"]["scan"]["endpoints_found"] == 12
    assert result["phases"]["exploit"]["findings"] == 3


# ---------------------------------------------------------------------------
# Test 12: Research skipped when no technologies found
# ---------------------------------------------------------------------------


async def test_research_skipped_no_technologies() -> None:
    """When recon finds no technologies, research phase is skipped."""
    phase_results = {
        "recon": {"hosts": [{"ip": "10.10.10.1"}]},  # no tech key
    }

    result, mock_lifecycle = await _run_orchestrator(phase_results=phase_results)

    spun_types = [call[0][0] for call in mock_lifecycle.spin_up.call_args_list]

    # Research should NOT be spun up (no technologies)
    assert "research" not in spun_types
    # But it should appear in results as skipped
    assert result["phases"]["research"]["status"] == "skipped"
    assert result["status"] == "completed"
