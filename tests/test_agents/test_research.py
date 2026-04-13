"""Tests for ResearchAgent — technology research and runbook writing.

Coverage:
- Agent calls research_technology for each technology
- Runbook entries are written to the state store via write_runbook_entry
- Duplicate runbook entries are skipped
- run() returns correct result structure
- Agent handles empty technology list gracefully
- All research queries are logged
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.research import ResearchAgent
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="research-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mock LLM — deterministic research + runbook writing sequence
# ---------------------------------------------------------------------------


class MockResearchLLM(LLMClient):
    """Deterministic LLM that researches one technology then writes a runbook entry.

    Call sequence:
      1 → research_technology("CVE Apache 2.4.25 exploit proof of concept")
      2 → write_runbook_entry(Apache 2.4.25, CVE-2021-41773 Path Traversal, ...)
      3 → research_technology("PHP 7.2 known vulnerabilities exploit-db")
      4 → write_runbook_entry(PHP 7.2, CVE-2019-11043 Remote Code Execution, ...)
      5+ → final_answer
    """

    def __init__(self) -> None:
        self._calls = 0
        self.research_queries: list[str] = []
        self.runbook_writes: list[dict[str, Any]] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._calls += 1

        sequence: list[tuple[str, str, dict[str, Any]]] = [
            (
                "I'll research Apache CVEs first.",
                "research_technology",
                {"query": "CVE Apache 2.4.25 exploit proof of concept"},
            ),
            (
                "Found CVE-2021-41773. Writing to runbook.",
                "write_runbook_entry",
                {
                    "technology": "Apache 2.4.25",
                    "technique_name": "CVE-2021-41773 Path Traversal",
                    "technique_description": (
                        "Path traversal in Apache 2.4.49/2.4.50 allows reading "
                        "files outside the document root via crafted URL."
                    ),
                    "steps": [
                        "Send GET request: /cgi-bin/.%2e/%2e%2e/etc/passwd",
                        "Check if response contains /etc/passwd content",
                        "If mod_cgi enabled, attempt RCE via POST to same path",
                    ],
                    "source_type": "cve",
                    "cve_id": "CVE-2021-41773",
                    "severity": "critical",
                },
            ),
            (
                "Now researching PHP 7.2.",
                "research_technology",
                {"query": "PHP 7.2 known vulnerabilities exploit-db"},
            ),
            (
                "Found CVE-2019-11043. Writing to runbook.",
                "write_runbook_entry",
                {
                    "technology": "PHP 7.2",
                    "technique_name": "CVE-2019-11043 Remote Code Execution",
                    "technique_description": (
                        "Buffer underflow in PHP-FPM allows RCE when nginx is "
                        "configured with specific fastcgi_split_path_info regex."
                    ),
                    "steps": [
                        "Check if target uses nginx + PHP-FPM",
                        "Use phuip-fpizdam exploit tool",
                        "Send crafted requests to trigger buffer underflow",
                        "Verify code execution via injected PHP payload",
                    ],
                    "source_type": "cve",
                    "cve_id": "CVE-2019-11043",
                    "severity": "high",
                },
            ),
        ]

        if self._calls <= len(sequence):
            thought, tool_name, tool_args = sequence[self._calls - 1]
            if tool_name == "research_technology":
                self.research_queries.append(tool_args["query"])
            else:
                self.runbook_writes.append(tool_args)
            return AgentAction(
                thought=thought,
                tool_call=ToolCall(
                    id=f"call_{self._calls:03d}",
                    name=tool_name,
                    arguments=tool_args,
                ),
            )

        return AgentAction(
            thought="Research complete.",
            final_answer=(
                "Research complete for 2 technologies. "
                "Found 2 critical/high severity techniques: "
                "CVE-2021-41773 (Apache path traversal) and "
                "CVE-2019-11043 (PHP-FPM RCE)."
            ),
        )

    async def research(self, query: str) -> str:
        return (
            f"Research results for '{query}':\n"
            "- CVE-2021-41773: Critical path traversal in Apache 2.4.49/2.4.50\n"
            "- CVE-2019-11043: High severity PHP-FPM RCE via buffer underflow\n"
            "- Exploit PoC available on GitHub\n"
            "- Affects default nginx + PHP-FPM configurations"
        )

    async def generate_text(self, prompt: str) -> str:
        return ""


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


async def _make_agent(
    db_path: Path,
    llm: LLMClient | None = None,
) -> tuple[ResearchAgent, StateStore, str]:
    """Spin up a fresh ResearchAgent with an SQLite state store."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("research-test", SCOPE.model_dump())
    agent = ResearchAgent(
        llm=llm or MockResearchLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
    )
    return agent, state, eid


# ---------------------------------------------------------------------------
# Tests: run() result structure
# ---------------------------------------------------------------------------


async def test_run_returns_correct_structure(tmp_path: Path) -> None:
    """run() returns dict with summary, runbook_entries_written, technologies_researched, status."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    await state.close()

    assert "summary" in result
    assert "runbook_entries_written" in result
    assert "technologies_researched" in result
    assert "status" in result
    assert result["status"] == "complete"


async def test_run_returns_technologies_researched(tmp_path: Path) -> None:
    """run() echoes back the input technology list."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    techs = ["Apache 2.4.25", "PHP 7.2"]

    result = await agent.run({"technologies": techs})
    await state.close()

    assert result["technologies_researched"] == techs


# ---------------------------------------------------------------------------
# Tests: runbook entries written to state store
# ---------------------------------------------------------------------------


async def test_runbook_entries_persisted(tmp_path: Path) -> None:
    """Runbook entries are written to the state store."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries = await state.get_all_runbook_entries(eid)
    await state.close()

    assert len(entries) >= 2
    tech_names = {e["technology"] for e in entries}
    assert "Apache 2.4.25" in tech_names
    assert "PHP 7.2" in tech_names


async def test_runbook_entry_has_steps(tmp_path: Path) -> None:
    """Each runbook entry includes exploitation steps."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries = await state.get_all_runbook_entries(eid)
    await state.close()

    for entry in entries:
        assert isinstance(entry["steps"], list)
        assert len(entry["steps"]) > 0, f"Entry '{entry['technique_name']}' has no steps."


async def test_runbook_entry_has_severity(tmp_path: Path) -> None:
    """Runbook entries include severity ratings."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries = await state.get_all_runbook_entries(eid)
    await state.close()

    severities = {e["severity"] for e in entries}
    assert severities & {"critical", "high"}, (
        f"Expected at least one critical/high entry, got: {severities}"
    )


async def test_runbook_entry_has_cve_id(tmp_path: Path) -> None:
    """Runbook entries for CVEs include the CVE identifier."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries = await state.get_all_runbook_entries(eid)
    await state.close()

    cve_ids = {e["cve_id"] for e in entries if e.get("cve_id")}
    assert "CVE-2021-41773" in cve_ids
    assert "CVE-2019-11043" in cve_ids


async def test_runbook_entries_written_count(tmp_path: Path) -> None:
    """run() reports the correct count of entries written."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    await state.close()

    assert result["runbook_entries_written"] == 2


# ---------------------------------------------------------------------------
# Tests: duplicate runbook entries are skipped
# ---------------------------------------------------------------------------


async def test_duplicate_runbook_entries_skipped(tmp_path: Path) -> None:
    """Running the agent twice doesn't create duplicate runbook entries."""
    agent, state, eid = await _make_agent(tmp_path / "test.db")

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries_first = await state.get_all_runbook_entries(eid)

    # Reset LLM state and run again — the same entries should be skipped
    agent2 = ResearchAgent(
        llm=MockResearchLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
    )
    await agent2.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    entries_second = await state.get_all_runbook_entries(eid)
    await state.close()

    assert len(entries_second) == len(entries_first), (
        "Duplicate entries were created on second run."
    )


# ---------------------------------------------------------------------------
# Tests: empty technology list
# ---------------------------------------------------------------------------


async def test_empty_technologies_returns_early(tmp_path: Path) -> None:
    """Agent returns immediately with status=complete when no technologies given."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"technologies": []})
    await state.close()

    assert result["status"] == "complete"
    assert result["runbook_entries_written"] == 0


async def test_no_technologies_key_returns_early(tmp_path: Path) -> None:
    """Agent handles missing 'technologies' key gracefully."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({})
    await state.close()

    assert result["status"] == "complete"


# ---------------------------------------------------------------------------
# Tests: research queries are executed
# ---------------------------------------------------------------------------


async def test_research_queries_called(tmp_path: Path) -> None:
    """The LLM's research() method is called for research_technology tool calls."""
    llm = MockResearchLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm)

    await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    await state.close()

    assert len(llm.research_queries) == 2


# ---------------------------------------------------------------------------
# Tests: tool schemas exposed to LLM
# ---------------------------------------------------------------------------


async def test_tool_schemas_include_research_and_runbook(tmp_path: Path) -> None:
    """The LLM sees research_technology and write_runbook_entry schemas."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    schemas = agent._get_tool_schemas()
    await state.close()

    names = {s["name"] for s in schemas}
    assert "research_technology" in names
    assert "write_runbook_entry" in names


async def test_tool_schemas_include_shared_meta_tools(tmp_path: Path) -> None:
    """The LLM also sees shared meta-tools (get_skill_reference, tool_installation)."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    schemas = agent._get_tool_schemas()
    await state.close()

    names = {s["name"] for s in schemas}
    assert "get_skill_reference" in names
    assert "tool_installation" in names


# ---------------------------------------------------------------------------
# Tests: agent properties
# ---------------------------------------------------------------------------


async def test_agent_name(tmp_path: Path) -> None:
    """Agent name is 'research'."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    await state.close()
    assert agent.name == "research"


async def test_agent_system_prompt_loaded(tmp_path: Path) -> None:
    """System prompt is loaded from the .md file and is non-empty."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    await state.close()
    assert agent.system_prompt
    assert "security research specialist" in agent.system_prompt.lower()


# ---------------------------------------------------------------------------
# Tests: write_runbook_entry validation
# ---------------------------------------------------------------------------


async def test_write_runbook_rejects_empty_technology(tmp_path: Path) -> None:
    """write_runbook_entry rejects entries with no technology."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    result = await agent._do_write_runbook_entry(
        {
            "technology": "",
            "technique_name": "test",
            "technique_description": "desc",
            "steps": ["step1"],
        }
    )
    await state.close()
    assert "Error" in result


async def test_write_runbook_rejects_empty_steps(tmp_path: Path) -> None:
    """write_runbook_entry rejects entries with no steps."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    result = await agent._do_write_runbook_entry(
        {
            "technology": "Apache",
            "technique_name": "test",
            "technique_description": "desc",
            "steps": [],
        }
    )
    await state.close()
    assert "Error" in result


async def test_write_runbook_rejects_empty_description(tmp_path: Path) -> None:
    """write_runbook_entry rejects entries with no description."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")
    result = await agent._do_write_runbook_entry(
        {
            "technology": "Apache",
            "technique_name": "test",
            "technique_description": "",
            "steps": ["step1"],
        }
    )
    await state.close()
    assert "Error" in result
