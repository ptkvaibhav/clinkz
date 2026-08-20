"""Report data models.

PentestReport aggregates all findings, targets, and metadata into
a structure that the ReportGenerator can render to HTML/PDF/JSON.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from clinkz.models.engagement import AuthorizationRecord, EngagementWindow
from clinkz.models.finding import (
    ChainResearchLead,
    CrossServiceResearchLead,
    Finding,
    Severity,
    UnprovenExploitLead,
)
from clinkz.models.target import Host


class ReportFormat(StrEnum):
    """Supported output formats for the report renderer."""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"


class ExecutiveSummary(BaseModel):
    """High-level summary written for a non-technical audience.

    Attributes:
        overview: 2–4 sentence description of the engagement and overall risk.
        risk_rating: Overall risk rating (Critical / High / Medium / Low).
        critical_count: Number of critical findings.
        high_count: Number of high severity findings.
        medium_count: Number of medium severity findings.
        low_count: Number of low severity findings.
        info_count: Number of informational findings.
        key_findings: Bullet-point list of the most important discoveries.
        recommendations: Prioritised remediation recommendations.
    """

    overview: str
    risk_rating: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    key_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, overview: str, findings: list[Finding]) -> ExecutiveSummary:
        """Compute severity counts from a list of findings.

        Args:
            overview: Pre-written overview paragraph.
            findings: Validated findings list.

        Returns:
            ExecutiveSummary with counts populated.
        """
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in severity_order:
            if counts[s] > 0:
                risk_rating = s.value.capitalize()
                break
        else:
            risk_rating = "Informational"

        return cls(
            overview=overview,
            risk_rating=risk_rating,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
        )


class NotTestedCategory(StrEnum):
    """Why something was not tested.

    Attributes:
        OUT_OF_SCOPE: Explicitly excluded by the client.
        NOT_PERMITTED: Outside the authorized permitted-technique list.
        NO_CLIENT_SIDE_ORACLE: The defining effect happens in a browser and this
            engine had no client-side execution oracle for this run. A capability
            that was ABSENT.
        CLIENT_ORACLE_FOUND_NOTHING: The defining effect happens in a browser,
            the client-side oracle RAN, and it witnessed no execution. A
            capability that was EXERCISED — a different fact, and the stronger
            one. These were filed together until engagement ``d67835f5`` listed
            three classes as having no oracle while P7 executed 40 times and
            correctly refused every candidate: the product's best behaviour,
            reported as a gap in the product.
        NOT_IMPLEMENTED: No methodology exists for the class.
        DESTRUCTIVE_REFUSED: The safety rails refused the action.
        ENGAGEMENT_HALTED: The engagement stopped before coverage completed.
        UNAUTHENTICATED: The class needed a session (or a second role) that the
            engagement did not have.
        SOURCE_NOT_INGESTED: A source tree was supplied for gray-box discovery
            and could not be read, so the engagement ran black-box. Its own
            category because the failure is invisible otherwise: a gray-box run
            that fell back produces exactly the artifacts of a black-box run.
    """

    OUT_OF_SCOPE = "out_of_scope"
    NOT_PERMITTED = "not_permitted"
    NO_CLIENT_SIDE_ORACLE = "no_client_side_oracle"
    CLIENT_ORACLE_FOUND_NOTHING = "client_oracle_found_nothing"
    NOT_IMPLEMENTED = "not_implemented"
    DESTRUCTIVE_REFUSED = "destructive_refused"
    ENGAGEMENT_HALTED = "engagement_halted"
    UNAUTHENTICATED = "unauthenticated"
    SOURCE_NOT_INGESTED = "source_not_ingested"


class NotTestedItem(BaseModel):
    """One thing the engagement did NOT test, and why.

    The section this feeds is what separates a professional deliverable from an
    automated scan dump. A client reading "no findings" is entitled to know
    whether that means "we looked and it is sound" or "we could not look".

    Attributes:
        item: What was not tested — a class label, a host, an action category.
        category: Why, as a machine-readable reason.
        reason: The same thing as a sentence a client can act on.
    """

    item: str
    category: NotTestedCategory
    reason: str


class PentestReport(BaseModel):
    """Complete penetration test report.

    This is the final output of a pentest engagement.
    Passed to the ReportRenderer to produce HTML/PDF.

    Attributes:
        id: Auto-generated UUID.
        engagement_name: Name of the engagement.
        target_scope: List of scope strings for display.
        test_start: When testing began.
        test_end: When testing concluded.
        generated_at: Timestamp of report generation.
        executive_summary: High-level summary (populated by ReportAgent).
        hosts: All discovered hosts.
        findings: The engagement's confirmed findings. Emitted through
            ``_persist_finding``, which is the only gate they pass: the
            CriticAgent that this line used to name is archived, having run
            0 times across 2,774 recorded agent steps.
        methodology: Narrative describing the testing approach.
        appendices: Optional extra sections keyed by title.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_name: str
    target_scope: list[str] = Field(default_factory=list)
    test_start: datetime
    test_end: datetime
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executive_summary: ExecutiveSummary | None = None
    hosts: list[Host] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    # Cross-service research-leads (design §5): plausible-but-unproven A→B chains.
    # A DIFFERENT type than :class:`Finding`, held in a SEPARATE field, so it is
    # structurally impossible to render one as a confirmed finding or count it in
    # ``finding_counts`` — the type-system + storage-level separation the design
    # requires (§5 the hard line).
    research_leads: list[CrossServiceResearchLead] = Field(default_factory=list)
    # Single-service unproven leads — same separation, same guarantee: a candidate
    # whose defining effect was never witnessed is a different TYPE than a finding.
    unproven_leads: list[UnprovenExploitLead] = Field(default_factory=list)
    # Compositions that were worth carrying and could not be PROVEN — most often
    # because an equivalently-shaped decoy was accepted too. Third lead type,
    # third separate field, same guarantee.
    chain_leads: list[ChainResearchLead] = Field(default_factory=list)
    #: The link-by-link view of every CONFIRMED chain. Each chain is ALSO in
    #: ``findings`` — it was emitted through the same chokepoint as everything
    #: else — so this field renders the composition and is never counted again.
    #: ``finding_counts`` reads ``findings`` alone, which is what keeps a chain
    #: from inflating the totals it is built out of.
    confirmed_chains: list[dict[str, object]] = Field(default_factory=list)
    methodology: str = ""
    appendices: dict[str, str] = Field(default_factory=dict)

    # ---- Client-ready header (productization P1 · part D) ------------------
    # The authorization record is reproduced verbatim in the report header: a
    # deliverable that cannot say who authorized the test is not a deliverable.
    authorization: AuthorizationRecord | None = None
    engagement_window: EngagementWindow | None = None
    rules_of_engagement: list[str] = Field(default_factory=list)
    #: Explicitly excluded targets. Rendered as prominently as the in-scope list
    #: — "we did not touch X" is a statement the client is paying for.
    excluded_scope: list[str] = Field(default_factory=list)
    #: Everything the engagement did NOT test, and why. Never empty in practice:
    #: at minimum it carries the classes with no oracle and no methodology.
    not_tested: list[NotTestedItem] = Field(default_factory=list)
    #: Safety-rail outcome — rate, refusals, halts, action-log location.
    safety_summary: dict[str, object] = Field(default_factory=dict)
    #: Authentication outcome — mechanism, roles, and the assertion that proved
    #: the session (or the absence of one).
    authentication: dict[str, object] = Field(default_factory=dict)
    #: Per-component contribution ledger — what each component was asked to do
    #: and how many items it actually contributed. Carries the run's silent
    #: components and fallback activations, so a deliverable can never again
    #: report a healthy total over a component that produced nothing.
    component_ledger: dict[str, object] = Field(default_factory=dict)
    #: Which model actually served each LLM stage of this run, and how many calls
    #: it took. Sourced from the run's own ``llm_call`` trace events, so it
    #: reflects what ANSWERED rather than what was configured — a rate-limit
    #: fallback makes those two different, and it is the one that answered which
    #: shaped the output. Present so that any number this run contributes to a
    #: benchmark baseline carries the model that produced it: the same prompt on
    #: a byte-identical header observation yielded its findings 27% of the time
    #: under one model and 80% under its predecessor, so a model bump silently
    #: re-baselines every comparison drawn against an earlier run.
    model_stamp: list[dict[str, str | int]] = Field(default_factory=list)
    #: Whether any LLM call was served by a provider other than the one routing
    #: v2 asked for, and what that cost. Anthropic is priority 1 for every call
    #: on every phase; everything else is fallback only, and a fallback is a
    #: disqualifying event rather than an invisible one. Carries
    #: ``provider_degraded``, ``baseline_eligible``, the call sites and both
    #: models per event.
    #:
    #: Populated even on a clean run, because "no fallback occurred" is a claim
    #: the deliverable should make: a section that appears only on failure
    #: cannot be told apart from a section nobody wrote. The eligibility flag is
    #: one-way — a degraded answer is already inside the findings, so no later
    #: clean call un-shapes it.
    provider_degradation: dict[str, object] = Field(default_factory=dict)
    #: Every out-of-scope target the engagement reached for and refused. THE
    #: control on an external engagement: a real application links out, the
    #: crawler follows links, and this is the evidence that the ones leaving
    #: the authorised host were stopped. Rendered even when empty, because
    #: otherwise a run that enforced scope perfectly and one that never had a
    #: link to follow produce identical artifacts.
    scope_refusals: dict[str, object] = Field(default_factory=dict)
    #: What the run consumed from the LLM providers, and the caps it ran under.
    #: ``usd_spent`` is a LOWER BOUND whenever ``usd_is_complete`` is false —
    #: clinkz ships no default rate card, so a model with no declared price
    #: contributes tokens and no dollars rather than a guess.
    llm_spend: dict[str, object] = Field(default_factory=dict)
    #: What the Research phase actually READ. ``is_grounded`` is true only when
    #: the provider that SERVED the research calls declares native live search.
    #: Anything else means the runbook is a recollection of a training corpus
    #: with a cutoff — every vulnerability disclosed after it is invisible, and
    #: nothing in the research text signals the absence. Routing v2 is what made
    #: this reachable: Research led with Gemini Flash-Lite precisely for native
    #: Search Grounding, and the Anthropic path has no equivalent. Stated in the
    #: deliverable rather than absorbed, because an ungrounded CVE claim in a
    #: security report is a new unbacked claim, not merely a thinner one.
    research_grounding: dict[str, object] = Field(default_factory=dict)
    #: What the exploit plan's task cap dropped, and whether the ordering held.
    #: The plan cap is the bound that most directly decides what gets TESTED,
    #: and it was the one bound reported only in the log and the trace — neither
    #: of which reaches a client. Two numbers kept apart because they have
    #: different fixes: ``dropped_total`` is the budget working, while
    #: ``ranking_inversion_count`` is a task dropped from an endpoint carrying
    #: its own class's observed surface while lower-relevance tasks survived,
    #: which a larger cap does not fix. Rendered even when the plan fit.
    plan_coverage: dict[str, object] = Field(default_factory=dict)
    crawl_coverage: dict[str, object] = Field(default_factory=dict)

    @property
    def finding_counts(self) -> dict[str, int]:
        """Return a dict of severity → count for all findings."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
