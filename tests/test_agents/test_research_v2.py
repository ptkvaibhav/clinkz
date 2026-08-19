"""Tests for deterministic ResearchAgent v2 — persistent brain with cross-engagement learning.

Coverage:
- test_research_step_sequence: mock KB + LLM + web search, verify all 7 steps run
- test_research_queries_existing_kb: verify persistent_kb methods called correctly
- test_research_skips_known_technologies: if KB has comprehensive coverage, skip web search
- test_research_persists_new_techniques: verify add_playbook_entry called for new findings
- test_research_adapts_related_techniques: mock related techs, verify adaptation
- test_research_additional_incremental: test the research_additional method
- test_research_result_structure: verify ResearchResult has all fields
- test_research_models: test all Pydantic models serialize/deserialize
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from clinkz.agents.research import ResearchAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.research import (
    AdaptedTechnique,
    ExistingKnowledge,
    NewResearch,
    ResearchResult,
    Technique,
    WebSearchResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="research-v2-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


class MockResearchLLM(LLMClient):
    """Deterministic LLM for research v2 tests.

    generate_text() returns predictable responses based on prompt content.
    reason() is not used by the v2 agent.
    """

    def __init__(self) -> None:
        self.generate_text_calls: list[str] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> Any:
        raise NotImplementedError("v2 ResearchAgent does not use reason()")

    async def research(self, query: str) -> str:
        return "No research results."

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        self.generate_text_calls.append(prompt)

        # Step 2: search query generation
        if "generate 3 search queries" in prompt.lower():
            tech = "Apache 2.4.25" if "apache" in prompt.lower() else "PHP 7.2"
            return json.dumps(
                [
                    f"CVE {tech} exploit PoC",
                    f"{tech} HackerOne writeup",
                    f"{tech} penetration testing",
                ]
            )

        # Step 3: technique synthesis
        if "synthesiz" in prompt.lower():
            return json.dumps(
                [
                    {
                        "name": "CVE-2021-41773 Path Traversal",
                        "description": "Path traversal in Apache 2.4.49/2.4.50",
                        "steps": [
                            "Send GET to /cgi-bin/.%2e/%2e%2e/etc/passwd",
                            "Check response for file content",
                        ],
                        "vuln_class": "path_traversal",
                        "severity": "critical",
                        "source": "NVD",
                        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                    },
                    {
                        "name": "PHP-FPM RCE",
                        "description": "Buffer underflow in PHP-FPM via crafted requests",
                        "steps": [
                            "Identify nginx + PHP-FPM configuration",
                            "Use phuip-fpizdam exploit tool",
                        ],
                        "vuln_class": "rce",
                        "severity": "high",
                        "source": "HackerOne",
                        "source_url": None,
                    },
                ]
            )

        # Step 5: technique adaptation
        if "adapt" in prompt.lower() and "related" in prompt.lower():
            return json.dumps(
                [
                    {
                        "original_name": "Nginx Misconfig Bypass",
                        "original_description": "Bypass path restrictions via double encoding",
                        "original_steps": ["Try double-encoded path", "Check response"],
                        "original_vuln_class": "auth_bypass",
                        "original_severity": "medium",
                        "original_source": "past_engagement",
                        "adaptations": "Use Apache mod_rewrite bypass instead of nginx",
                        "target_technology": "Apache 2.4.25",
                        "confidence": 0.7,
                    }
                ]
            )

        return "LLM analysis complete."


# ---------------------------------------------------------------------------
# Mock RuntimeResearcher
# ---------------------------------------------------------------------------


class MockRuntimeResearcher:
    """Deterministic web researcher that returns predictable findings."""

    def __init__(self) -> None:
        self.research_calls: list[str] = []

    async def research_technology(self, technology: str, version: str = "") -> str:
        self.research_calls.append(technology)
        return (
            "CVE-2021-41773: Critical path traversal in Apache 2.4.49.\n"
            "CVE-2019-11043: PHP-FPM buffer underflow RCE.\n"
            "PoC available on GitHub for both."
        )


# ---------------------------------------------------------------------------
# Mock PersistentKnowledgeBase
# ---------------------------------------------------------------------------


def _make_mock_kb(
    *,
    playbook_entries: list[dict[str, Any]] | None = None,
    past_results: list[dict[str, Any]] | None = None,
    related_technologies: list[dict[str, Any]] | None = None,
) -> MagicMock:
    """Build a mock PersistentKnowledgeBase with configurable responses."""
    kb = AsyncMock()

    kb.get_playbook_for_technology = AsyncMock(return_value=playbook_entries or [])
    kb.get_past_results_for_technology = AsyncMock(return_value=past_results or [])
    kb.get_related_technologies = AsyncMock(return_value=related_technologies or [])
    kb.add_playbook_entry = AsyncMock(return_value=1)

    return kb


# ---------------------------------------------------------------------------
# Test helper
# ---------------------------------------------------------------------------


async def _make_agent(
    db_path: Path,
    llm: LLMClient | None = None,
    kb: Any = None,
    researcher: Any = None,
) -> tuple[ResearchAgent, StateStore, str]:
    """Create a ResearchAgent with mock dependencies."""
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("research-v2-test", SCOPE.model_dump())

    agent = ResearchAgent(
        llm=llm or MockResearchLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
        persistent_kb=kb if kb is not None else _make_mock_kb(),
        runtime_researcher=researcher if researcher is not None else MockRuntimeResearcher(),
    )
    return agent, state, eid


# ---------------------------------------------------------------------------
# Test: step sequence (all 7 steps run in order)
# ---------------------------------------------------------------------------


async def test_research_step_sequence(tmp_path: Path) -> None:
    """All 7 steps execute: KB query, web research, synthesize, related, adapt, persist, build."""
    llm = MockResearchLLM()
    kb = _make_mock_kb()
    researcher = MockRuntimeResearcher()

    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm, kb=kb, researcher=researcher)

    result = await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    await state.close()

    assert result["status"] == "complete"

    # Step 1: KB was queried for each technology
    assert kb.get_playbook_for_technology.call_count >= 2
    assert kb.get_past_results_for_technology.call_count >= 2

    # Step 2: Web research was performed
    assert len(researcher.research_calls) > 0

    # Step 3: LLM was called to synthesize techniques
    synth_calls = [c for c in llm.generate_text_calls if "synthesiz" in c.lower()]
    assert len(synth_calls) >= 1

    # Step 4: Related technologies were queried
    assert kb.get_related_technologies.call_count >= 2

    # Step 7: Result is built
    r = result["result"]
    assert "technologies" in r
    assert "runbook" in r


# ---------------------------------------------------------------------------
# Test: queries existing KB correctly
# ---------------------------------------------------------------------------


async def test_research_queries_existing_kb(tmp_path: Path) -> None:
    """Persistent KB get_playbook_for_technology and get_past_results are called for each tech."""
    kb = _make_mock_kb(
        playbook_entries=[
            {
                "technique_name": "Existing Apache Test",
                "technique_description": "A known test",
                "technology_pattern": "Apache",
                "severity": "high",
                "steps": ["step1"],
                "success_rate": 0.8,
                "source_type": "manual",
                "source_url": None,
                "applicable_vuln_classes": ["rce"],
            }
        ],
        past_results=[
            {"technique_name": "Apache Test", "success": True, "technology_pattern": "Apache"}
        ],
    )

    agent, state, _ = await _make_agent(tmp_path / "test.db", kb=kb)
    result = await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    # Verify KB was queried
    kb.get_playbook_for_technology.assert_called()
    kb.get_past_results_for_technology.assert_called()

    # Verify existing knowledge made it into the result
    r = result["result"]
    assert r["existing_knowledge"]["playbook_entries"]


# ---------------------------------------------------------------------------
# Test: skips known technologies with comprehensive coverage
# ---------------------------------------------------------------------------


async def test_research_skips_known_technologies(tmp_path: Path) -> None:
    """If KB has >= 5 entries with high success rates, skip web research for that tech."""
    # Create comprehensive coverage: 6 entries with high success rates
    comprehensive_entries = [
        {
            "technique_name": f"Known Apache Technique {i}",
            "technique_description": f"Apache technique {i}",
            "technology_pattern": "Apache",
            "severity": "high",
            "success_rate": 0.8,
            "steps": ["step1"],
            "source_type": "manual",
            "source_url": None,
            "applicable_vuln_classes": [],
        }
        for i in range(6)
    ]

    kb = _make_mock_kb(playbook_entries=comprehensive_entries)
    researcher = MockRuntimeResearcher()

    agent, state, _ = await _make_agent(tmp_path / "test.db", kb=kb, researcher=researcher)

    await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    # Web research should have been skipped for Apache since KB is comprehensive
    # The researcher should NOT have been called for Apache
    apache_calls = [c for c in researcher.research_calls if "apache" in c.lower()]
    assert len(apache_calls) == 0, (
        f"Expected no web research for comprehensive tech, got: {researcher.research_calls}"
    )


# ---------------------------------------------------------------------------
# Test: persists new techniques to KB
# ---------------------------------------------------------------------------


async def test_research_persists_new_techniques(tmp_path: Path) -> None:
    """New techniques are persisted to KB via add_playbook_entry with tier=3."""
    kb = _make_mock_kb()

    agent, state, _ = await _make_agent(tmp_path / "test.db", kb=kb)
    await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    # add_playbook_entry should have been called for new techniques
    assert kb.add_playbook_entry.call_count > 0

    # Verify tier=3 was passed
    for call in kb.add_playbook_entry.call_args_list:
        assert call.kwargs.get("tier") == 3 or call.args[0] == 3
        assert call.kwargs.get("source_type") == "research_agent"


# ---------------------------------------------------------------------------
# Test: adapts related techniques
# ---------------------------------------------------------------------------


async def test_research_adapts_related_techniques(tmp_path: Path) -> None:
    """When related technologies have playbook entries, they are adapted."""
    kb = _make_mock_kb(
        related_technologies=[
            {
                "tech_a": "Apache 2.4.25",
                "tech_b": "Apache 2.4.49",
                "relation_type": "similar_stack",
                "similarity_score": 0.9,
            }
        ],
        playbook_entries=[
            {
                "technique_name": "Nginx Misconfig Bypass",
                "technique_description": "Bypass via double encoding",
                "technology_pattern": "nginx",
                "severity": "medium",
                "steps": ["Try double-encoded path"],
                "success_rate": 0.6,
                "source_type": "past_engagement",
                "source_url": None,
                "applicable_vuln_classes": ["auth_bypass"],
            }
        ],
    )

    llm = MockResearchLLM()
    agent, state, _ = await _make_agent(tmp_path / "test.db", llm=llm, kb=kb)
    result = await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    # Verify adaptation LLM call was made
    adapt_calls = [c for c in llm.generate_text_calls if "adapt" in c.lower()]
    assert len(adapt_calls) >= 1

    # Verify adapted techniques are in the result
    r = result["result"]
    assert len(r["adapted_techniques"]) > 0


# ---------------------------------------------------------------------------
# Test: research_additional incremental
# ---------------------------------------------------------------------------


async def test_research_additional_incremental(tmp_path: Path) -> None:
    """research_additional() adds new techniques without re-running full pipeline."""
    kb = _make_mock_kb()
    researcher = MockRuntimeResearcher()

    agent, state, _ = await _make_agent(tmp_path / "test.db", kb=kb, researcher=researcher)

    new_techniques = await agent.research_additional(["MySQL 5.7"])
    await state.close()

    # Should have queried KB and done research
    assert kb.get_playbook_for_technology.call_count >= 1
    assert len(researcher.research_calls) > 0

    # Should return techniques
    assert isinstance(new_techniques, list)


# ---------------------------------------------------------------------------
# Test: result structure
# ---------------------------------------------------------------------------


async def test_research_result_structure(tmp_path: Path) -> None:
    """ResearchResult contains all required fields with correct types."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2"]})
    await state.close()

    r = result["result"]

    # Required top-level fields
    assert isinstance(r["technologies"], list)
    assert len(r["technologies"]) == 2
    assert isinstance(r["existing_knowledge"], dict)
    assert isinstance(r["new_techniques"], list)
    assert isinstance(r["adapted_techniques"], list)
    assert isinstance(r["runbook"], list)
    assert isinstance(r["new_kb_entries_added"], int)
    assert "timestamp" in r

    # ExistingKnowledge structure
    ek = r["existing_knowledge"]
    assert isinstance(ek["playbook_entries"], list)
    assert isinstance(ek["past_results"], list)
    assert isinstance(ek["technologies_covered"], list)

    # Techniques in runbook have required fields
    for entry in r["runbook"]:
        # Each entry is either a Technique dict or an AdaptedTechnique dict
        if "original" in entry:
            # AdaptedTechnique
            assert "adaptations" in entry
            assert "target_technology" in entry
            assert "confidence" in entry
            assert "name" in entry["original"]
        else:
            # Technique
            assert "name" in entry
            assert "description" in entry
            assert "steps" in entry


# ---------------------------------------------------------------------------
# Test: Pydantic model serialization / deserialization
# ---------------------------------------------------------------------------


class TestResearchModels:
    """Test all research Pydantic models serialize and deserialize correctly."""

    def test_existing_knowledge(self) -> None:
        ek = ExistingKnowledge(
            playbook_entries=[{"name": "test", "tier": 2}],
            past_results=[{"success": True}],
            technologies_covered=["Apache 2.4.25"],
        )
        data = ek.model_dump()
        restored = ExistingKnowledge.model_validate(data)
        assert restored.technologies_covered == ["Apache 2.4.25"]
        assert len(restored.playbook_entries) == 1

    def test_web_search_result(self) -> None:
        wsr = WebSearchResult(
            query="CVE Apache 2.4.25",
            results=[{"text": "CVE-2021-41773 found"}],
            source_urls=["https://nvd.nist.gov"],
        )
        data = wsr.model_dump()
        restored = WebSearchResult.model_validate(data)
        assert restored.query == "CVE Apache 2.4.25"
        assert len(restored.source_urls) == 1

    def test_new_research(self) -> None:
        nr = NewResearch(
            findings=[WebSearchResult(query="test", results=[{"text": "found"}], source_urls=[])],
            cves_found=["CVE-2021-41773"],
            technologies_researched=["Apache 2.4.25"],
        )
        data = nr.model_dump()
        restored = NewResearch.model_validate(data)
        assert restored.cves_found == ["CVE-2021-41773"]
        assert len(restored.findings) == 1

    def test_technique(self) -> None:
        t = Technique(
            name="CVE-2021-41773 Path Traversal",
            description="Path traversal in Apache 2.4.49/2.4.50",
            steps=["Send GET request", "Check response"],
            vuln_class="path_traversal",
            severity="critical",
            source="NVD",
            source_url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        )
        data = t.model_dump()
        restored = Technique.model_validate(data)
        assert restored.name == "CVE-2021-41773 Path Traversal"
        assert restored.severity == "critical"
        assert len(restored.steps) == 2
        assert restored.source_url is not None

    def test_technique_minimal(self) -> None:
        t = Technique(name="Test", description="desc")
        data = t.model_dump()
        restored = Technique.model_validate(data)
        assert restored.severity == "info"
        assert restored.source_url is None
        assert restored.steps == []

    def test_adapted_technique(self) -> None:
        original = Technique(
            name="Original Technique",
            description="Original desc",
            steps=["step1", "step2"],
            vuln_class="xss",
            severity="high",
            source="HackerOne",
        )
        at = AdaptedTechnique(
            original=original,
            adaptations="Changed payload for PHP",
            target_technology="PHP 7.2",
            confidence=0.8,
        )
        data = at.model_dump()
        restored = AdaptedTechnique.model_validate(data)
        assert restored.target_technology == "PHP 7.2"
        assert restored.confidence == 0.8
        assert restored.original.name == "Original Technique"
        assert restored.original.severity == "high"

    def test_adapted_technique_confidence_bounds(self) -> None:
        original = Technique(name="Test", description="desc")
        at = AdaptedTechnique(
            original=original,
            target_technology="test",
            confidence=0.0,
        )
        assert at.confidence == 0.0

        at2 = AdaptedTechnique(
            original=original,
            target_technology="test",
            confidence=1.0,
        )
        assert at2.confidence == 1.0

        with pytest.raises(Exception):
            AdaptedTechnique(
                original=original,
                target_technology="test",
                confidence=1.5,
            )

    def test_research_result_full(self) -> None:
        technique = Technique(
            name="Test Technique",
            description="A test",
            steps=["step1"],
            severity="high",
            source="NVD",
        )
        adapted = AdaptedTechnique(
            original=technique,
            adaptations="Adjusted for PHP",
            target_technology="PHP 7.2",
            confidence=0.7,
        )
        result = ResearchResult(
            technologies=["Apache 2.4.25", "PHP 7.2"],
            existing_knowledge=ExistingKnowledge(
                playbook_entries=[{"name": "existing"}],
                technologies_covered=["Apache 2.4.25"],
            ),
            new_techniques=[technique],
            adapted_techniques=[adapted],
            runbook=[technique, adapted],
            new_kb_entries_added=1,
        )
        data = result.model_dump()
        restored = ResearchResult.model_validate(data)

        assert len(restored.technologies) == 2
        assert len(restored.new_techniques) == 1
        assert len(restored.adapted_techniques) == 1
        assert len(restored.runbook) == 2
        assert restored.new_kb_entries_added == 1
        assert isinstance(restored.timestamp, datetime)

    def test_research_result_json_roundtrip(self) -> None:
        result = ResearchResult(
            technologies=["Apache 2.4.25"],
            new_techniques=[Technique(name="Test", description="desc", steps=["step1"])],
            runbook=[Technique(name="Test", description="desc", steps=["step1"])],
            new_kb_entries_added=0,
        )
        json_str = result.model_dump_json()
        restored = ResearchResult.model_validate_json(json_str)
        assert restored.technologies == ["Apache 2.4.25"]
        assert len(restored.runbook) == 1

    def test_research_result_empty(self) -> None:
        result = ResearchResult()
        data = result.model_dump()
        restored = ResearchResult.model_validate(data)
        assert restored.technologies == []
        assert restored.runbook == []
        assert restored.new_kb_entries_added == 0


# ---------------------------------------------------------------------------
# Test: empty technology list
# ---------------------------------------------------------------------------


async def test_empty_technologies_returns_early(tmp_path: Path) -> None:
    """Agent returns immediately with status=complete when no technologies given."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({"technologies": []})
    await state.close()

    assert result["status"] == "complete"
    assert result["result"]["technologies"] == []


async def test_no_technologies_key_returns_early(tmp_path: Path) -> None:
    """Agent handles missing 'technologies' key gracefully."""
    agent, state, _ = await _make_agent(tmp_path / "test.db")

    result = await agent.run({})
    await state.close()

    assert result["status"] == "complete"


# ---------------------------------------------------------------------------
# Test: agent properties
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
    assert "research agent" in agent.system_prompt.lower()


# ---------------------------------------------------------------------------
# Test: no persistent KB still works
# ---------------------------------------------------------------------------


async def test_no_persistent_kb_still_works(tmp_path: Path) -> None:
    """Agent functions without persistent_kb, just skips KB steps."""
    state = StateStore(tmp_path / "test.db")
    await state.connect()
    eid = await state.create_engagement("research-v2-test", SCOPE.model_dump())

    agent = ResearchAgent(
        llm=MockResearchLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id=eid,
        persistent_kb=None,
        runtime_researcher=MockRuntimeResearcher(),
    )

    result = await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    assert result["status"] == "complete"
    assert result["result"]["existing_knowledge"]["playbook_entries"] == []


# ---------------------------------------------------------------------------
# Wall-clock budget + rate-limit resilience
# ---------------------------------------------------------------------------


async def test_research_respects_wall_clock_budget(tmp_path: Path) -> None:
    """A zero budget trips the deadline before step 2, so no web research runs
    and the agent returns a complete (partial) result instead of looping."""
    llm = MockResearchLLM()
    kb = _make_mock_kb()
    researcher = MockRuntimeResearcher()

    agent, state, _ = await _make_agent(
        tmp_path / "budget.db", llm=llm, kb=kb, researcher=researcher
    )
    # Force an immediately-expired deadline.
    agent._research_time_budget = 0.0

    result = await agent.run({"technologies": ["Apache 2.4.25", "PHP 7.2", "nginx 1.24"]})
    await state.close()

    assert result["status"] == "complete"
    # Budget tripped before any grounded web research call was launched.
    assert researcher.research_calls == []


class _Failing503Researcher:
    """RuntimeResearcher that always raises 503 (provider overloaded)."""

    def __init__(self) -> None:
        self.research_calls: list[str] = []

    async def research_technology(self, technology: str, version: str = "") -> str:
        self.research_calls.append(technology)
        from clinkz.llm.base import ServiceUnavailableError

        raise ServiceUnavailableError("503 model overloaded")


async def test_research_returns_partial_on_persistent_503(tmp_path: Path) -> None:
    """When web research raises 503 for every technology, the agent still
    returns a complete (partial) result rather than propagating the error."""
    researcher = _Failing503Researcher()
    agent, state, _ = await _make_agent(tmp_path / "five03.db", researcher=researcher)

    result = await agent.run({"technologies": ["Apache 2.4.25"]})
    await state.close()

    assert result["status"] == "complete"
    assert researcher.research_calls == ["Apache 2.4.25"]  # it tried once (no fan-out)
    assert "runbook" in result["result"]
