"""Vulnerability finding model.

A Finding is the primary output of the pentest. The Critic Agent
validates each finding before it reaches the report.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from clinkz.models.scan import ParamLocation


class Severity(StrEnum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Lifecycle state of a finding."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class Finding(BaseModel):
    """A single vulnerability finding discovered during a pentest.

    Attributes:
        id: Auto-generated UUID.
        title: Short, descriptive title (e.g., "SQL Injection in /api/users").
        description: Detailed technical description of the vulnerability.
        severity: CVSS-aligned severity level.
        status: Validation state (new → confirmed or false_positive).
        target: Affected host/URL.
        evidence: List of evidence strings (request/response snippets, screenshots paths).
        cvss_score: Optional CVSS base score (0.0 – 10.0).
        cve_ids: Associated CVE identifiers, if any.
        references: URLs to CVE entries, writeups, or documentation.
        remediation: Recommended fix.
        discovered_at: Timestamp when the finding was created.
        validated_at: Timestamp when the Critic Agent validated it.
        discovery_provenance: Capability-learning provenance when this finding came
            from a discovery-engine hypothesis (stamped from its
            :class:`ExploitTask` at the ``_execute_task`` seam). ``None`` for
            LLM/deterministic/black-box findings — those write no capability fact
            (design §S1.5).
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.NEW
    target: str
    evidence: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cve_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    remediation: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    validated_at: datetime | None = None
    discovery_provenance: DiscoveryProvenance | None = None


# ---------------------------------------------------------------------------
# Exploit Agent v2 models
# ---------------------------------------------------------------------------


class DiscoveryProvenance(BaseModel):
    """Capability-learning provenance a discovery-originated task/finding carries.

    Threaded hypothesis → :class:`ExploitTask` → :class:`Finding` (and onto the
    exploit ``PageAnalysis`` for the non-confirming ledger path) so the Layer-2
    write-back can key a ``capability_fact`` and build a ``capability_observation``
    without new plumbing (design §S1.3). ``None`` on every LLM-planned,
    deterministic-coverage, and black-box task — so a black-box finding writes no
    capability fact (the deprecate-replace end-state).

    The enum-valued fields are carried as their plain ``str`` values (StrEnum
    ``.value``): this model lives in the leaf ``models.finding`` so
    ``discovery.models`` (which imports :class:`ExploitTask`) can reference the
    provenance without a circular import, and the Layer-2 DB columns are TEXT.

    Attributes:
        technology_key: Normalized TECH identity the fact is keyed on — the
            carrying dependency (e.g. ``log4j-core``) or a normalized fingerprint.
            Never a target host/URL (§5.3).
        observed_version: EXACT observed point version (e.g. ``2.14.1``); ``""``
            when no manifest/banner version is observable (→ predicate ``*``).
        sink_shape_id: Fixed recognizer-vocabulary sink id
            (``java.url_openconnection`` / ``java.file_sink`` / ``log4j.log_sink``).
        primitive_class: Layer-1 :class:`PrimitiveClass` value
            (``egress_fetch`` / ``file_read`` / ``log_interpolation`` / …).
        primitive_id: The catalog :class:`CapabilityPrimitive` id.
        confirmation_primitive: The P-id(s) the obligation reduces to (``P6``, ``P3``).
        reachability_grade: The :class:`SoundnessGrade` value the reaching edge carried.
        gating_config: The config flag that would subtract this capability from Δ
            (for the ``failed_gated`` refine), or ``None``.
    """

    technology_key: str = ""
    observed_version: str = ""
    sink_shape_id: str = ""
    primitive_class: str = ""
    primitive_id: str = ""
    confirmation_primitive: str = ""
    reachability_grade: str = ""
    gating_config: str | None = None


class ComponentCVEContext(BaseModel):
    """The known-CVE match a plan task was queued FOR — context, never proof.

    Threaded hypothesis-style: ``ComponentCVEMatch`` → :class:`ExploitTask` →
    the :class:`Finding` its own oracle emitted, so a reader of the deliverable
    can see both what was observed and **how strong that observation was**.

    ``version_provenance`` is the field that matters and the reason this model
    exists rather than a bare ``cve_id`` string. A template scanner reports "the
    banner says 2.4.49, CVE-2021-41773 affects 2.4.49" and stops; the difference
    here is that the CVE never emits anything — an oracle does — and that the
    strength of the version claim travels with the result instead of being
    flattened into "a version matched". A finding backed by a lockfile entry and
    one backed by a ``Server:`` header are different claims, and the report says
    which one this is.

    Attributes:
        cve_id: The published identifier.
        title: Human summary, as catalogued.
        observed_component: Product name as the fingerprinter reported it.
        observed_version: Version string exactly as observed.
        version_provenance: :class:`~clinkz.models.recon.VersionProvenance`
            value — how that version was obtained.
        observation_source: The observing tool plus evidence kind
            (``nmap:service``), so the provenance claim is checkable.
        affected: The published affected-version predicate.
        reference: Where the affected range came from.
    """

    cve_id: str
    title: str = ""
    observed_component: str = ""
    observed_version: str = ""
    version_provenance: str = ""
    observation_source: str = ""
    affected: str = ""
    reference: str = ""


class ExploitTask(BaseModel):
    """A single exploit task planned by the LLM.

    Attributes:
        test_method: Name of the _test_* method to call (e.g. "_test_sqli").
        endpoint_url: URL of the endpoint to test.
        endpoint_params: Parameter names on the endpoint.
        endpoint_method: HTTP method the endpoint expects (GET/POST/PUT/...).
        endpoint_content_type: Request content-type for body-bearing
            endpoints (e.g. ``application/json``), or None.
        param_locations: Per-param injection location (query/json_body/
            form_body/path). A name absent from this map defaults to
            ``query`` (or ``path`` when the URL templates it). Sourced from
            the discovered :class:`~clinkz.models.scan.Endpoint`, never from
            LLM JSON, so it cannot drift.
        tier: 1 (universal), 2 (tech-matched), 3 (experimental/research).
        playbook_entry_id: FK to persistent KB playbook_entries (tier 2/3).
        technique_name: Human-readable technique name.
        technique_steps: Steps from research runbook (tier 3).
        priority: Execution priority (lower = run first).
        carrier_constraints: Per-instance probe-carrier constraints from a
            discovery-engine proof obligation (e.g. ``align_host_with_injected_
            url_host``). Threaded onto the ``PageAnalysis`` so the shared request
            builder honours them; empty for LLM/deterministic-planned tasks
            (unchanged behaviour). Sourced from the hypothesis, never LLM JSON.
    """

    test_method: str
    endpoint_url: str
    endpoint_params: list[str] = Field(default_factory=list)
    endpoint_method: str = "GET"
    endpoint_content_type: str | None = None
    param_locations: dict[str, ParamLocation] = Field(default_factory=dict)
    tier: int = Field(ge=1, le=3)
    playbook_entry_id: int | None = None
    technique_name: str = ""
    technique_steps: list[str] = Field(default_factory=list)
    priority: int = 0
    carrier_constraints: list[str] = Field(default_factory=list)
    discovery_provenance: DiscoveryProvenance | None = None
    # Cross-service reachability (design §3): B's in-scope INTERNAL URL — the
    # confirmation target of a cross-service SSRF hypothesis (an ``EGRESS_FETCH`` Δ
    # whose reaching edge crossed the A→B boundary). Set ONLY on a cross-service
    # discovery task; empty on every single-service / black-box task, so the normal
    # ``_test_ssrf`` dispatch is unchanged. Its presence is what routes the task to
    # the cross-service confirmation driver (co-location gate + research-lead), which
    # reuses the P6 machinery — no new oracle, no new ``_test_*`` method.
    cross_service_target: str = ""
    # How the A→B boundary hop was discovered (``source`` / ``recon`` / ``catalog``,
    # design §2) — carried onto the finding/research-lead for provenance. Empty for
    # non-cross-service. ``catalog`` = a learned ``reaches`` topology prior (slice B2).
    cross_service_source: str = ""
    # A's + B's abstracted role/tech-class (slice B2 §6.4), recon-derived — the two
    # ends of the ``reaches`` edge written back on a CONFIRMED reach. NEVER a URL/host,
    # so a deployment-specific identifier cannot enter the cross-engagement KB. A's is
    # the SPECIFIC service role (``owasp-juice-shop``), distinct from the capability
    # fact key. Empty (either end) ⇒ un-abstractable ⇒ the confirmed reach stays
    # engagement-local (no durable edge).
    cross_service_a_identity: str = ""
    cross_service_b_identity: str = ""
    # Discovery-hypothesis ranking metadata, for the §6.2 "gets smarter" trace.
    # ``prior_source`` is ``capability_recall`` when a Layer-2 recall boosted/seeded
    # the hypothesis, else ``cold_derivation``; ``rank_score`` is the hypothesis
    # rank. Defaults suit every non-discovery (LLM / deterministic / black-box) task.
    # Ranking metadata only — never an emission gate (emission stays the proof, §5).
    prior_source: str = "cold_derivation"
    rank_score: float = 0.0
    # The dependency→known-CVE match this task was queued FOR (the fourth plan
    # source). ``None`` on every LLM-planned, deterministic-coverage, discovery
    # and black-box task. Carried so the finding this task's own oracle emits can
    # state the CVE as CONTEXT and — the part a template scanner has no answer to
    # — say how strong the version observation behind it was.
    component_cve: ComponentCVEContext | None = None


class ExploitPlan(BaseModel):
    """Ordered plan of exploit tasks grouped by tier.

    Attributes:
        tasks: All planned exploit tasks in priority order.
        tier1_count: Number of universal (always-run) tasks.
        tier2_count: Number of technology-matched tasks.
        tier3_count: Number of experimental/research tasks.
    """

    tasks: list[ExploitTask] = Field(default_factory=list)
    tier1_count: int = 0
    tier2_count: int = 0
    tier3_count: int = 0


class ExploitAnalysis(BaseModel):
    """LLM analysis of exploit results — identifies retries and chaining.

    Attributes:
        false_positive_suspects: Findings the LLM thinks may be false positives.
            Each entry is a ``{"id": <finding-id>, "reason": <why>}`` dict. The
            live LLM emits these as structured objects (not bare id strings), so
            the field is typed ``list[dict]`` — the same str-vs-dict drift that
            previously broke ``chaining_opportunities`` / ``finding_ids``. A
            ``before`` validator coerces a legacy ``list[str]`` (bare ids) into
            this shape so both variants parse.
        retry_targets: Tasks to retry with adapted payloads.
        chaining_opportunities: Descriptions of how findings can be chained.
            Each entry is heterogeneous — e.g. a ``description`` string plus a
            ``finding_ids`` list — so values are typed ``Any`` rather than
            ``str`` (the LLM legitimately emits a list for ``finding_ids``).
        coverage_summary: Human-readable summary of test coverage.
        cross_check_ran: Whether the reviewing call actually produced an answer.
            An empty ``false_positive_suspects`` has two readings — the reviewer
            looked and cleared everything, or the reviewer never answered — and
            the portfolio engagement shipped fourteen phantoms under the second
            one wearing the first one's clothes. Defaults to ``False`` so an
            analysis nobody filled in cannot claim a review it did not get.
    """

    false_positive_suspects: list[dict[str, Any]] = Field(default_factory=list)
    retry_targets: list[ExploitTask] = Field(default_factory=list)
    chaining_opportunities: list[dict[str, Any]] = Field(default_factory=list)
    coverage_summary: str = ""
    cross_check_ran: bool = False

    @field_validator("false_positive_suspects", mode="before")
    @classmethod
    def _coerce_fp_suspects(cls, value: Any) -> list[dict[str, Any]]:
        """Normalise false-positive suspects to ``[{"id", "reason"}, ...]``.

        Accepts the two shapes the LLM produces in the wild:

          * ``["id1", "id2"]``           — bare finding-id strings (legacy)
          * ``[{"id": ..., "reason": ...}]`` — structured objects (current)

        Both are mapped to ``{"id": str, "reason": str}`` dicts. ``finding_id``
        is accepted as an alias for ``id``. Entries without a usable id are
        dropped rather than raising, so a single malformed element can never
        void the whole post-run analysis.
        """
        if not isinstance(value, list):
            return []
        coerced: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, str):
                if item:
                    coerced.append({"id": item, "reason": ""})
            elif isinstance(item, dict):
                fid = item.get("id") or item.get("finding_id") or item.get("finding")
                if fid:
                    coerced.append({"id": str(fid), "reason": str(item.get("reason") or "")})
        return coerced


class CrossServiceResearchLead(BaseModel):
    """A plausible-but-unproven cross-service A→B chain (design §5).

    The first-class, **structurally distinct** home for every cross-service chain
    that could not be *proven* by an unchanged zero-FP oracle co-located with B.
    It is deliberately **NOT** a :class:`Finding` and holds **no** path to
    ``_persist_finding``: emission stays the P1–P6 proof on the live target, so a
    topology prior can only ever surface a lead here, never manufacture a finding
    (§4/§7). Because it is a different *type* than :class:`Finding`, "never rendered
    as a confirmed finding / never counted in coverage" is a type-system property,
    not a convention — the report renderer takes ``list[CrossServiceResearchLead]``
    in a separate argument and renders it in a dedicated section.

    The hard line (§5): a research-lead is never a finding, never counted in
    coverage, never marked confirmed, never rendered in the confirmed-findings
    section, never written to the capability KB as a positive fact.

    Attributes:
        candidate_chain: Human-readable ``channel(A) → egress(A) → A→B edge →
            (impact at B)`` description of the unproven chain.
        why_unconfirmed: WHY it stayed a lead — one of
            :data:`CROSS_SERVICE_WHY_UNCONFIRMED` (e.g.
            ``egress_confirmed_but_B_reach_not_observed`` — the rung-3 trap: a
            callback landed at a collaborator NOT co-located with B, proving only
            "A egresses somewhere", never "A reaches B").
        a_endpoint: A's endpoint URL the probe was sent to.
        a_channel: A's egress channel param the probe rode.
        b_target: B's in-scope internal URL the chain was hypothesised to reach.
        topology_source: How the A→B edge was discovered (``source`` / ``recon``).
        reachability_grade: The composed edge grade (always
            ``cross_service_topology``).
        reach_confidence: The composed edge's ``reach_confidence`` (ranking only).
        raw_probe: The exact probe sent from A (carrying the nonce / B's URL) — the
            raw null-result half so the operator sees exactly what was tried.
        raw_null_observation: The null observation (no B-marker / no co-located
            callback) — the other half of the raw null result.
        discovered_at: When the lead was recorded.
    """

    candidate_chain: str
    why_unconfirmed: str
    a_endpoint: str = ""
    a_channel: str = ""
    b_target: str = ""
    topology_source: str = ""
    reachability_grade: str = "cross_service_topology"
    reach_confidence: float = 0.0
    raw_probe: str = ""
    raw_null_observation: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Discriminator for the shared ``research_leads`` table, which now holds two
    # structurally different lead types. Defaulted so rows written before the
    # second type existed still validate.
    lead_kind: str = "cross_service"


class UnprovenExploitLead(BaseModel):
    """A vulnerability whose DEFINING effect was never witnessed (the general form).

    The single-service sibling of :class:`CrossServiceResearchLead`, and the same
    hard line: it is **NOT** a :class:`Finding` and holds **no** path to
    ``_persist_finding``. "Never rendered as confirmed, never counted in
    coverage" is a property of the *type*, not a convention — the report renderer
    takes these in a separate argument and renders them under their own heading.

    This is where a methodology puts a *reachability* observation that stops
    short of exploitation. The motivating case is DOM-XSS: static analysis can
    prove an attacker-controlled DOM source flows into a dangerous sink, but
    confirming that the payload *executes* needs a client-side execution oracle
    (a headless browser) the engine does not yet have. Engagement ``913fecee``
    emitted that observation as a ``high``/``confirmed`` finding whose evidence
    string asserted "payload executed by client-side JS" — an observation nobody
    made. The honest shape is a lead: the reachability evidence is real and
    worth an operator's time, the exploitation claim is not made at all.

    Attributes:
        claim: What would be true IF the lead were proven — the candidate
            vulnerability, stated as a candidate.
        why_unconfirmed: WHY it stayed a lead — one of
            :data:`UNPROVEN_WHY_UNCONFIRMED`.
        technique: The WSTG / technique id the lead belongs to.
        endpoint: The endpoint the observation was made on.
        parameter: The parameter / channel involved, when there is one.
        raw_observation: What WAS actually observed, verbatim (e.g. the
            source→sink pair and the script excerpt) — the auditable half.
        missing_observation: What was NOT observed and would be required to
            confirm — stated so the gap is explicit rather than implied.
        discovered_at: When the lead was recorded.
    """

    claim: str
    why_unconfirmed: str
    technique: str = ""
    endpoint: str = ""
    parameter: str = ""
    raw_observation: str = ""
    missing_observation: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lead_kind: str = "unproven_exploit"


# The closed vocabulary of WHY a single-service candidate stayed a lead. Kept
# closed for the same reason as :data:`CROSS_SERVICE_WHY_UNCONFIRMED`: a free-text
# reason drifts into a justification, and a justification reads like a finding.
UNPROVEN_WHY_UNCONFIRMED: frozenset[str] = frozenset(
    {
        # Reachability proven statically; execution never witnessed because the
        # engine has no client-side execution oracle (a headless browser).
        "execution_not_witnessed_requires_client_side_oracle",
        # The effect is only observable out-of-band and no callback landed.
        "blind_unconfirmed_within_window",
        # The confirming observation needs credentials/access we do not hold.
        "not_instrumentable",
        # The post-run analysis flagged the candidate as a false positive and no
        # deterministic signal contradicted it. The system does not believe its
        # own claim, so the claim is demoted here rather than emitted with a
        # caveat attached (the G10 emission inversion).
        "suspected_false_positive_no_deterministic_signal",
        # The candidate's only "observation" restates the rationale it was derived
        # from: it describes a MECHANISM and never demonstrates the effect. Caught
        # at the emission chokepoint rather than left to a post-run reviewer to
        # notice, because whether it is demoted must not depend on whether an LLM
        # happened to flag it.
        "observation_restates_rationale_mechanism_not_effect",
        # A client-side security control was DESCRIBED (a hidden field computed
        # by the page's own JS, a validation gate) but the server was never
        # observed accepting a value that control alone was holding back.
        # Describing the mechanism is reachability; acceptance is the effect.
        "client_side_control_described_server_acceptance_not_witnessed",
        # The methodology's own ``verification_strength`` says the defining
        # effect was not witnessed ("likely"), while every ``_make_finding``
        # stamps CONFIRMED — so the candidate contradicted itself in its own
        # evidence. Held at the emission chokepoint so the rule is a property of
        # the engine rather than something each class must remember.
        "verification_strength_below_confirmation",
        # The remaining deterministic emission grounds. Every one of these is a
        # pure function of the candidate's own evidence, and all nine now run
        # unconditionally at ``_persist_finding`` — so each needs its own entry
        # here or the lead lands under a reason that is not what happened.
        #
        # Two of them (attribution, the never-sent control) shipped without one
        # and were silently normalised to ``not_instrumentable``, which tells a
        # client "the confirming observation needs access we do not hold". The
        # truth was the opposite: the observation was made, and it refuted
        # itself. A lead's reason is the only thing an operator can act on, so a
        # wrong one is worse than a vague one.
        #
        # The recorded character map proves a character the emitted payload
        # needs did not survive the filter.
        "character_map_blocks_the_payload",
        # The evidence contradicts itself: the request line assigns the tested
        # parameter twice, or carries ``verified=False`` under a confirmed status.
        "evidence_internally_inconsistent",
        # The execution claim is conditional on a downstream transform nobody
        # observed ("if a later layer decodes this, it executes"), and phase 5
        # did not witness the payload landing literally in an executable position.
        "execution_claim_is_conditional",
        # The confirming observation sits in a 4xx/5xx response or inside a
        # framework error block: reflection into an error page is reachability,
        # not an executable context.
        "observation_landed_in_an_error_response",
        # The observation names something the payload cannot have produced — a
        # command channel it never invoked, or a marker other than the one minted
        # for this attempt. The evidence refutes itself on its face.
        "observation_not_attributable_to_the_payload",
        # A marker-oracle class reached emission without a never-sent control arm
        # that refused. An oracle that never tried to refuse has not
        # distinguished the vulnerability from a page that merely contains the
        # string.
        "never_sent_control_did_not_refuse",
        # The upload store accepted the artifact and served it back, but no
        # restriction was observed to be BYPASSED: no script/interpreter
        # extension was accepted and no filename injection survived. Accepted
        # and retrievable is the feature working; a validation gap needs a gap.
        "upload_accepted_but_no_restriction_bypass_observed",
        # An upload branch whose claimed effect this engine has no oracle for was
        # attempted, and only the upload feature working was seen. The chain
        # branch asserts a CONSUMER SINK composes with the upload — nothing here
        # reaches for a consumer, so a direct GET of the artifact is not that
        # observation; the client-side branch is the same gap that makes every
        # DOM-XSS result a lead. Both used to verify on ``status == 200``.
        "upload_inclusion_chain_effect_not_witnessed",
        "upload_client_side_only_effect_not_witnessed",
        # The execution branches, attempted and not proven: the artifact was
        # stored but came back as source (or re-encoded), so no interpreter ran.
        "upload_direct_execution_effect_not_witnessed",
        "upload_interpreter_misconfig_effect_not_witnessed",
        # An external tool (sqlmap) reported the vulnerability while this
        # engine's own oracle did not confirm it. The tool is probably right,
        # but its verdict is not an observation we made and cannot be
        # re-derived from the evidence we recorded, so it is a lead.
        "effect_asserted_by_external_tool_not_witnessed_in_band",
        # A fingerprinted component reports a version inside a published CVE's
        # affected range, and this engine has NO oracle for that CVE's defining
        # effect. A version number is not an exploit: the banner may be wrong,
        # the fix may be back-ported, and the vulnerable code path may be
        # unreachable. The version match is real and worth an operator's time;
        # the exploitation claim is not made at all.
        "version_match_only_no_oracle_for_this_cve",
        # Same version match, and this engine HAS the oracle — it cannot deliver
        # the CVE's input to it. A component-derived task carries its probe as a
        # PARAMETER VALUE and nothing else, so a CVE reached through the URL
        # path, a request header or a whole-body document is never actually
        # sent. Split out from the reason above because the two have different
        # fixes and only one of them is a gap in a class we already claim: the
        # first waits on a new confirmation primitive, this one waits on a
        # carrier. Both Apache traversal rows spent a reserved plan slot under
        # the WRONG reason for two releases — the run reported "the oracle ran
        # and did not confirm" about three query-parameter probes that never
        # touched the path the CVE traverses.
        "version_match_vector_not_carried_by_this_engine",
        # Same version match, and nothing capable of NAMING that component is
        # what reported it. ``nmap -sV`` and ``whatweb`` fingerprint servers, so
        # a row reading ``ejs 3.1.6`` at banner strength is a mis-parse of
        # something else rather than a weak sighting of ejs. Not a statement
        # about evidence strength — provenance still never gates a test — but
        # about whether there is an observation of this component at all.
        "version_match_provenance_cannot_identify_this_component",
        # An access-control class proved everything EXCEPT ownership. The
        # response differs from the caller's own object, from a never-issued
        # reference of the same shape, and from what an anonymous caller is
        # served — three negatives that a shared record behind a login satisfies
        # exactly as well as another principal's record does. Positive
        # attribution needs a SECOND authenticated principal's own authorized
        # read of the same object, and a single-role engagement cannot dispatch
        # that arm. Declared by the producer
        # (:class:`~clinkz.models.vuln_classes.MultiPrincipalRequirement`) and
        # enforced at the emission chokepoint, so the class cannot confirm by
        # forgetting to check.
        "single_role_cannot_attribute",
        # The run held enough principals to attribute the object, and could not
        # say which of them outranks the other. A crossing arm is evidence of a
        # broken boundary only while no role the CALLER holds authorizes the
        # read: dispatched from an administrator, "I was served a customer's
        # record" is the application working. The rank is the operator's to
        # declare (``privilege`` on the role credential) because a role label is
        # free text and no response can be asked about a hierarchy — so an
        # undeclared order costs the confirmation rather than producing one in
        # the direction that cannot be told apart from a feature.
        "privilege_order_undeclared_crossing_may_be_authorized",
        # The access-control class could not establish which reference belongs
        # to the CALLER. The self arm used to carry whatever value the crawl
        # observed in the parameter — a fact about the crawler's session, not
        # about the identity the arms are dispatched as — and on engagement
        # 20fad9dc the crawl saw 1, the caller was user 2, and the increment
        # landed on the caller's own record: the self arm read the other
        # principal's object and the crossing arm read the caller's. Every arm
        # downstream is a comparison and a comparison does not know which side
        # it is standing on, so an unanchored crossing is refused rather than
        # graded. Also carries the loud arms-inverted refusal, which is the same
        # missing fact caught one step later.
        "self_reference_not_anchored_to_the_caller",
        # The anonymous arm — the one that establishes the object is not simply
        # public — was never sent. An arm that was not dispatched refused
        # nothing, the same rule every control arm is held to.
        "anonymous_control_arm_not_dispatched",
        # The crossing response names no owning principal other than the
        # caller. An IDOR claim rests on the OBJECT saying whom it belongs to
        # (``UserId``, ``email``, ``author``); a response that names nobody is a
        # public catalogue record, and "differs from mine, from a never-issued
        # reference and from what anonymous is served" is three negatives a
        # shared record behind a login satisfies exactly as well.
        "crossing_response_names_no_owning_principal",
        # Same version match, and this engine DOES have an oracle — which ran
        # against the live target and did not witness the effect. Recorded so
        # the difference between "we could not test this" and "we tested it and
        # saw nothing" is visible in the deliverable, because they call for
        # opposite follow-up. A version match never rescues a failed
        # confirmation.
        "version_match_oracle_ran_and_did_not_confirm",
    }
)


class ChainResearchLead(BaseModel):
    """A composition that could not be PROVEN — the chaining lead type.

    The third structurally-distinct lead, and the same hard line as the other
    two: not a :class:`Finding`, no path to ``_persist_finding``, never counted
    in coverage, rendered under its own heading.

    It exists because chaining's failure mode is the one most likely to
    manufacture a finding. Two confirmed findings sit next to each other in a
    result list and a narrative connecting them writes itself — "SQL injection
    disclosed the password hashes, therefore account takeover". The composition
    itself is what needs evidence, and when the decoy-substitution control did
    not run, or ran and did not discriminate, or one link rests on inference,
    the honest artifact is this: the operator gets the chain that was worth
    trying and the exact link that stopped it.

    Attributes:
        candidate_chain: The composition, as an ordered human-readable chain.
        why_unconfirmed: One of :data:`CHAIN_WHY_UNCONFIRMED`.
        unconfirmed_link: WHICH link stopped it, named — the field that makes
            this lead actionable rather than a shrug. "Link 2 (carriage of a
            credential at /rest/user/login) is not confirmed: an
            equivalently-shaped decoy was accepted too."
        chain_kind: The composition shape that was attempted.
        carried_artifact_kind: What the chain intended to carry.
        carried_artifact_fingerprint: Salted fingerprint of the carried value —
            correlates the lead with the finding that produced the artifact and
            replays nowhere. NEVER the value itself: a chain carries exactly the
            material a report must not reproduce.
        links: One line per link, with its confirmation state.
        raw_observation: What WAS observed, verbatim and bounded.
        missing_observation: What was NOT observed and would be required.
        discovered_at: When the lead was recorded.
    """

    candidate_chain: str
    why_unconfirmed: str
    unconfirmed_link: str = ""
    chain_kind: str = ""
    carried_artifact_kind: str = ""
    carried_artifact_fingerprint: str = ""
    links: list[str] = Field(default_factory=list)
    raw_observation: str = ""
    missing_observation: str = ""
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lead_kind: str = "chain"


#: The closed vocabulary of WHY a chain stayed a lead. Closed for the same reason
#: as the other two: a free-text reason drifts into a justification, and a
#: justification reads like a finding.
CHAIN_WHY_UNCONFIRMED: frozenset[str] = frozenset(
    {
        # The artifact was presented at the next step and was NOT accepted. The
        # two findings are both real; they simply do not compose.
        "carried_artifact_not_accepted",
        # The artifact was accepted AND so was an equivalently-shaped decoy the
        # target never issued. The endpoint accepts the SHAPE, so its acceptance
        # is not evidence about the value we recovered. This is the control that
        # keeps chaining from manufacturing findings, and it is the reason a
        # chain lead is common rather than exceptional.
        "decoy_also_accepted_composition_not_discriminating",
        # A link rests on inference rather than on a P1–P7 oracle, so the chain
        # cannot be confirmed however well the composition carried.
        "link_not_independently_confirmed",
        # The composition would have required a request the safety rails refuse
        # (a destructive verb, an identity change) and no benchmark profile
        # permitted it.
        "carriage_refused_by_safety_rails",
        # Planned but never carried — the phase ran out of budget, or the
        # carriage surface (a login endpoint, a session-discriminating URL) was
        # never discovered.
        "carriage_not_attempted",
        # Nothing carriable came out of the head link: the class declares a yield
        # but this particular finding's evidence held no artifact of that kind.
        "no_artifact_recovered",
    }
)


# The closed vocabulary of WHY a cross-service chain stayed a research-lead (§5).
# ``egress_confirmed_but_B_reach_not_observed`` is the rung-3 trap (a callback at a
# collaborator NOT co-located with B); the others cover "cannot instrument B",
# "OOB sent, no callback in window", and "topology prior only, never probed".
CROSS_SERVICE_WHY_UNCONFIRMED: frozenset[str] = frozenset(
    {
        "egress_confirmed_but_B_reach_not_observed",
        "B_not_instrumentable",
        "blind_unconfirmed_within_window",
        "topology_prior_only",
    }
)


class ExploitResult(BaseModel):
    """Final output of the v2 exploit agent.

    Consumed by the Orchestrator, Critic Agent, and Report Agent.

    Attributes:
        findings: All vulnerability findings discovered.
        plan: The exploit plan that was executed.
        analysis: LLM analysis of the results.
        total_tests_run: Number of _test_* invocations.
        total_findings: Number of findings discovered.
        by_severity: Finding counts by severity level.
        kb_results_recorded: Number of technique results written to persistent KB.
        stopped_early: True when the phase stopped dispatching new tasks at the
            cooperative deadline before exhausting its plan. Findings are
            persisted incrementally, so an early stop still yields a complete,
            queryable result in the state store.
        timestamp: When the exploit phase completed.
    """

    findings: list[Finding] = Field(default_factory=list)
    plan: ExploitPlan = Field(default_factory=ExploitPlan)
    analysis: ExploitAnalysis = Field(default_factory=ExploitAnalysis)
    total_tests_run: int = 0
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    kb_results_recorded: int = 0
    stopped_early: bool = False
    # Cross-service research-leads (design §5): plausible-but-unproven A→B chains.
    # NOT findings — never counted in ``total_findings`` / ``by_severity`` / coverage;
    # surfaced in the report's dedicated "Cross-service research leads (UNCONFIRMED)"
    # section, structurally separate from ``findings``.
    research_leads: list[CrossServiceResearchLead] = Field(default_factory=list)
    # Single-service unproven leads — a candidate whose DEFINING effect was never
    # witnessed (today: DOM-XSS reachability without a client-side execution
    # oracle). Same hard line as ``research_leads``: never a finding, never counted.
    unproven_leads: list[UnprovenExploitLead] = Field(default_factory=list)
    # Compositions that were worth carrying and could not be PROVEN — most often
    # because an equivalently-shaped decoy was accepted too, which is the control
    # that keeps chaining from turning two adjacent findings into a story. Same
    # hard line again: a different TYPE, a separate field, never counted.
    chain_leads: list[ChainResearchLead] = Field(default_factory=list)
    # Chains every link of which is independently confirmed AND whose composition
    # survived the decoy control. Each is also emitted as a Finding through the
    # normal chokepoint; this field carries the structured form for the report.
    confirmed_chains: list[dict[str, Any]] = Field(default_factory=list)
    # What the P7 client-side execution oracle actually DID this run: whether one
    # was resolved, how many times it ran, and how many of those witnessed script
    # execution. Carried so the report can tell "this engine has no client-side
    # oracle" apart from "the oracle ran N times and did not witness execution".
    # The portfolio run filed the second as the first: three classes listed under
    # ``no_client_side_oracle`` while P7 executed 40 times and correctly refused
    # every candidate. That refusal is the product working, and it was reported
    # as a gap in the product.
    client_oracle: dict[str, Any] = Field(default_factory=dict)
    # How far the emission and control-arm paths actually got. Carried so the
    # component ledger can answer "this seam never registered" with the
    # engagement condition rather than an alarm: a run where nothing reached the
    # emission chokepoint and one where the chokepoint is broken are opposite
    # facts that look identical from a zero. Counted at the seams themselves,
    # never derived from finding/lead totals — a lead can be written by paths
    # that never reach ``_persist_finding``, and deriving one from the other is
    # how a healthy run manufactures a permanent false alarm.
    emission_candidates: int = 0
    control_arm_kills: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
