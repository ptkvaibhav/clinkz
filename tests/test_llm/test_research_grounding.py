"""Research that did not read the web says so — in the runbook and the report.

Routing v2 made Anthropic priority 1 for every call on every phase. Research
had led with Gemini Flash-Lite for exactly one reason: native Search Grounding,
which the Anthropic path does not have. So the capability was traded away with
the routing, and nothing in any artifact said so.

That is not a thinner report. An ungrounded research answer recites a training
corpus, so **every vulnerability disclosed after that model's cutoff is
invisible to it**, and the text carries no signal that anything is missing — a
CVE list that looks complete and quietly stops. For a security tool that is a
correctness failure, and folding it silently into the runbook (which persists to
the cross-engagement KB) makes it a new unbacked claim that outlives the run.

The stamp is the disclosure. This file pins that:

* every shipped client DECLARES its grounding, the producer-declares rule;
* the resilient client reports the grounding of whoever ANSWERED;
* a mixed phase reports the WEAKEST grounding, which cannot overstate;
* the report renders the caveat, and renders the positive claim too.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.config import Settings
from clinkz.llm.base import LLMClient, ResearchGrounding
from clinkz.llm.fallback import ResilientLLMClient
from clinkz.models.report import PentestReport
from clinkz.models.research import Technique

_SHIPPED_CLIENTS = ("anthropic_client", "gemini_client", "openai_client", "ollama_client")


class TestEveryClientDeclares:
    def test_no_shipped_client_leaves_it_undeclared(self) -> None:
        """The producer declares; a consumer that guesses is silently wrong later."""
        import importlib

        undeclared: list[str] = []
        for module_name in _SHIPPED_CLIENTS:
            module = importlib.import_module(f"clinkz.llm.{module_name}")
            for attr in vars(module).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, LLMClient)
                    and attr is not LLMClient
                    and attr.__module__ == module.__name__
                    and attr.RESEARCH_GROUNDING is ResearchGrounding.UNDECLARED
                ):
                    undeclared.append(f"{module_name}.{attr.__name__}")
        assert not undeclared, (
            "These clients do not declare what their research() answers are "
            f"grounded in, so the report cannot state it: {undeclared}"
        )

    def test_only_gemini_declares_live_search(self) -> None:
        """The fact the trade-off rests on, pinned so it cannot rot silently."""
        from clinkz.llm.anthropic_client import AnthropicClient
        from clinkz.llm.gemini_client import GeminiClient
        from clinkz.llm.openai_client import OpenAIClient

        assert GeminiClient.RESEARCH_GROUNDING is ResearchGrounding.LIVE_SEARCH
        assert AnthropicClient.RESEARCH_GROUNDING is ResearchGrounding.TRAINING_DATA
        assert OpenAIClient.RESEARCH_GROUNDING is ResearchGrounding.TRAINING_DATA

    def test_undeclared_is_not_grounded(self) -> None:
        """'We do not know' licenses the same claim as 'it did not'."""
        assert ResearchGrounding.UNDECLARED.is_grounded is False
        assert ResearchGrounding.TRAINING_DATA.is_grounded is False
        assert ResearchGrounding.LIVE_SEARCH.is_grounded is True

    def test_the_base_default_is_undeclared(self) -> None:
        """A test double or a third-party client keeps working, and is not trusted."""
        assert LLMClient.RESEARCH_GROUNDING is ResearchGrounding.UNDECLARED


class TestTheResilientClientReportsWhoAnswered:
    def test_it_reports_the_head_of_the_chain_before_any_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        client = ResilientLLMClient(
            agent_role="research", config=Settings(), override_chain=["anthropic"]
        )
        assert client.research_grounding() is ResearchGrounding.TRAINING_DATA

    def test_it_reports_the_provider_that_actually_served(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Configuration says who was asked; the run says who answered."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        client = ResilientLLMClient(
            agent_role="research", config=Settings(), override_chain=["anthropic", "gemini"]
        )
        client._last_used_provider = "gemini"
        assert client.research_grounding() is ResearchGrounding.LIVE_SEARCH

    def test_an_unreadable_provider_reports_undeclared_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stamp must never fail a run."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        client = ResilientLLMClient(
            agent_role="research", config=Settings(), override_chain=["anthropic"]
        )
        client._last_used_provider = "a-provider-that-does-not-exist"
        assert client.research_grounding() is ResearchGrounding.UNDECLARED


class TestTheWeakestGroundingWins:
    @staticmethod
    def _agent(seen: set[str]):
        from clinkz.agents.research import ResearchAgent

        agent = ResearchAgent.__new__(ResearchAgent)
        agent._grounding_seen = seen
        return agent

    def test_all_grounded_reports_grounded(self) -> None:
        agent = self._agent({ResearchGrounding.LIVE_SEARCH.value})
        assert agent._effective_grounding() is ResearchGrounding.LIVE_SEARCH

    def test_a_single_fallback_downgrades_the_whole_phase(self) -> None:
        """Some entries saw the web and some did not — the whole is not grounded."""
        agent = self._agent(
            {ResearchGrounding.LIVE_SEARCH.value, ResearchGrounding.TRAINING_DATA.value}
        )
        assert agent._effective_grounding() is ResearchGrounding.TRAINING_DATA

    def test_an_undeclared_call_downgrades_below_training_data(self) -> None:
        agent = self._agent(
            {ResearchGrounding.LIVE_SEARCH.value, ResearchGrounding.UNDECLARED.value}
        )
        assert agent._effective_grounding() is ResearchGrounding.UNDECLARED

    def test_no_research_call_at_all_is_undeclared(self) -> None:
        agent = self._agent(set())
        assert agent._effective_grounding() is ResearchGrounding.UNDECLARED


class TestTheRunbookEntryCarriesIt:
    def test_a_technique_defaults_to_undeclared(self) -> None:
        """The caveat has to outlive the run: a runbook entry persists to the KB."""
        technique = Technique(name="t", description="d")
        assert technique.grounding == ResearchGrounding.UNDECLARED.value
        assert technique.is_grounded is False

    def test_a_grounded_technique_says_so(self) -> None:
        technique = Technique(
            name="t", description="d", grounding=ResearchGrounding.LIVE_SEARCH.value
        )
        assert technique.is_grounded is True


class TestTheReportRendersIt:
    @staticmethod
    def _render(stamp: dict[str, object]) -> str:
        now = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
        report = PentestReport(
            engagement_name="grounding-test",
            test_start=now,
            test_end=now,
            research_grounding=stamp,
        )
        lines: list[str] = []
        ReportAgent._render_research_grounding(lines, report)
        return "\n".join(lines)

    def test_ungrounded_research_is_named_as_such(self) -> None:
        rendered = self._render(
            {
                "grounding": "training_data",
                "is_grounded": False,
                "providers": ["anthropic"],
                "runbook_entries": 7,
            }
        )
        assert "NOT grounded in live web search" in rendered
        assert "training cutoff" in rendered
        assert "7 runbook entr(ies)" in rendered

    def test_it_says_the_findings_are_unaffected(self) -> None:
        """The caveat must not read as doubt about confirmed findings."""
        rendered = self._render(
            {"grounding": "training_data", "is_grounded": False, "runbook_entries": 1}
        )
        assert "does not affect the findings" in rendered
        assert "confirmed by this engine's own oracles" in rendered

    def test_grounded_research_makes_the_positive_claim(self) -> None:
        rendered = self._render(
            {
                "grounding": "live_search",
                "is_grounded": True,
                "providers": ["gemini"],
                "runbook_entries": 3,
            }
        )
        assert "grounded in live web search" in rendered
        assert "NOT grounded" not in rendered

    def test_undeclared_explains_that_it_counts_as_ungrounded(self) -> None:
        rendered = self._render(
            {"grounding": "undeclared", "is_grounded": False, "runbook_entries": 0}
        )
        assert "did not declare" in rendered
        assert "same as ungrounded" in rendered

    def test_a_phase_that_never_reported_is_not_a_phase_that_found_nothing(self) -> None:
        """``Runbook entries produced: 0`` was rendered for both.

        ``grounding: undeclared`` carries a partial signal that something is
        missing. The COUNT carries none — a phase that errored and a phase that
        ran and produced no technique were the same zero — so it is withheld and
        the absence is stated instead.
        """
        rendered = self._render(
            {
                "grounding": "undeclared",
                "is_grounded": False,
                "research_reported": False,
                "providers": None,
                "runbook_entries": None,
            }
        )
        assert "produced no record for this run" in rendered
        assert "not the same as a research phase that ran and found nothing" in rendered
        assert "whose count this run did not record" in rendered
        assert "0 runbook entr(ies)" not in rendered
        assert "not recorded" in rendered, "the provider list is absent too, not empty"

    def test_a_phase_that_ran_and_produced_nothing_still_says_zero(self) -> None:
        """The other side of the same distinction: 0 IS a measurement."""
        rendered = self._render(
            {
                "grounding": "training_data",
                "is_grounded": False,
                "research_reported": True,
                "providers": ["anthropic"],
                "runbook_entries": 0,
            }
        )
        assert "the 0 runbook entr(ies)" in rendered
        assert "produced no record for this run" not in rendered

    def test_an_empty_stamp_renders_nothing(self) -> None:
        """A directly invoked ReportAgent has no research phase to describe."""
        assert self._render({}) == ""


class TestTheOrchestratorSummary:
    @staticmethod
    def _summary(phase: dict[str, object]) -> dict[str, object]:
        from clinkz.orchestrator.orchestrator import OrchestratorAgent

        return OrchestratorAgent._research_grounding_summary(phase)

    def test_it_reads_the_phase_result_not_configuration(self) -> None:
        summary = self._summary(
            {
                "result": {
                    "grounding": "live_search",
                    "grounding_providers": ["gemini"],
                    "runbook": [{}, {}],
                }
            }
        )
        assert summary["is_grounded"] is True
        assert summary["providers"] == ["gemini"]
        assert summary["runbook_entries"] == 2

    def test_a_research_phase_that_did_not_run_is_undeclared(self) -> None:
        for phase in ({}, {"status": "skipped"}, {"status": "error", "error": "boom"}):
            summary = self._summary(phase)
            assert summary["grounding"] == ResearchGrounding.UNDECLARED.value
            assert summary["is_grounded"] is False

    def test_a_phase_that_did_not_run_reports_no_count(self) -> None:
        """The producer's half of item 7: no result means no count, not zero.

        ``grounding: undeclared`` already said something was missing. The COUNT
        said nothing — a phase that errored and a phase that ran and produced no
        technique were the same ``0`` — so it is withheld and the absence is
        stated in ``research_reported``.
        """
        for phase in ({}, {"status": "error"}, {"result": None}):
            summary = self._summary(phase)
            assert summary["research_reported"] is False, phase
            assert summary["runbook_entries"] is None, phase
            assert summary["providers"] is None, phase
            assert summary["is_grounded"] is False, phase

    def test_a_phase_that_ran_reports_its_count_even_when_zero(self) -> None:
        """The other half: ``0`` from a phase that ran IS a measurement."""
        summary = self._summary({"result": {"grounding": "training_data", "runbook": []}})
        assert summary["research_reported"] is True
        assert summary["runbook_entries"] == 0
        assert summary["providers"] == []
