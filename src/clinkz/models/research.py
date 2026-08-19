"""Research-phase data models for the deterministic research agent (v2).

These models represent structured output from each step of the
research pipeline: existing KB knowledge, web search results,
synthesized techniques, adapted techniques, and the final research result.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from clinkz.llm.base import ResearchGrounding


class ExistingKnowledge(BaseModel):
    """Knowledge already in the persistent KB for requested technologies."""

    playbook_entries: list[dict[str, Any]] = Field(default_factory=list)
    past_results: list[dict[str, Any]] = Field(default_factory=list)
    technologies_covered: list[str] = Field(default_factory=list)


class WebSearchResult(BaseModel):
    """A single web search query and its results."""

    query: str
    results: list[dict[str, Any]] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)


class NewResearch(BaseModel):
    """Aggregated results from web research across technologies."""

    findings: list[WebSearchResult] = Field(default_factory=list)
    cves_found: list[str] = Field(default_factory=list)
    technologies_researched: list[str] = Field(default_factory=list)


class Technique(BaseModel):
    """An actionable exploitation technique synthesized by the LLM.

    ``grounding`` is what the research this technique came from actually saw.
    It travels with the technique rather than sitting only on the result,
    because a runbook entry is persisted to the cross-engagement KB and read
    back by later engagements: the claim outlives the run that made it, so the
    caveat has to outlive it too.
    """

    name: str
    description: str
    steps: list[str] = Field(default_factory=list)
    vuln_class: str = ""
    severity: str = "info"
    source: str = ""
    source_url: str | None = None
    #: ``live_search`` / ``training_data`` / ``undeclared``. Anything other than
    #: ``live_search`` means this entry cannot know about a CVE published after
    #: the serving model's cutoff, and nothing in its text would say so.
    grounding: str = ResearchGrounding.UNDECLARED.value

    @property
    def is_grounded(self) -> bool:
        """Whether this entry came from research that read the live web."""
        return self.grounding == ResearchGrounding.LIVE_SEARCH.value


class AdaptedTechnique(BaseModel):
    """A technique adapted from a related technology for the current target."""

    original: Technique
    adaptations: str = ""
    target_technology: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class ResearchResult(BaseModel):
    """Final output of the deterministic research agent.

    Consumed by the Orchestrator and the Exploit Agent.
    """

    #: What the research calls this result was built from actually read.
    #: ``live_search`` only when the provider that SERVED them declares native
    #: search grounding; anything else means the runbook below is a recollection
    #: of a training corpus with a cutoff, and every vulnerability disclosed
    #: after that cutoff is invisible to it — with no signal in the text that
    #: anything is missing. For a security tool that is a correctness failure,
    #: so it is stamped here, on every runbook entry, and in the report.
    grounding: str = ResearchGrounding.UNDECLARED.value
    #: Which providers served the research calls, in the order first seen. A
    #: fallback mid-phase can change the grounding under a single result, and
    #: :attr:`grounding` is then the WEAKEST of them — the honest reading of a
    #: runbook where some entries saw the web and some did not.
    grounding_providers: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    existing_knowledge: ExistingKnowledge = Field(default_factory=ExistingKnowledge)
    new_techniques: list[Technique] = Field(default_factory=list)
    adapted_techniques: list[AdaptedTechnique] = Field(default_factory=list)
    runbook: list[Technique | AdaptedTechnique] = Field(default_factory=list)
    new_kb_entries_added: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
