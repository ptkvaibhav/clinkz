"""Research-phase data models for the deterministic research agent (v2).

These models represent structured output from each step of the
research pipeline: existing KB knowledge, web search results,
synthesized techniques, adapted techniques, and the final research result.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


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
    """An actionable exploitation technique synthesized by the LLM."""

    name: str
    description: str
    steps: list[str] = Field(default_factory=list)
    vuln_class: str = ""
    severity: str = "info"
    source: str = ""
    source_url: str | None = None


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

    technologies: list[str] = Field(default_factory=list)
    existing_knowledge: ExistingKnowledge = Field(default_factory=ExistingKnowledge)
    new_techniques: list[Technique] = Field(default_factory=list)
    adapted_techniques: list[AdaptedTechnique] = Field(default_factory=list)
    runbook: list[Technique | AdaptedTechnique] = Field(default_factory=list)
    new_kb_entries_added: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
