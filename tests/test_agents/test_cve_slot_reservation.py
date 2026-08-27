"""The dependency→CVE plan source's slot reservation, and what it costs.

The fourth plan source could not queue a task on any engagement ever run. Not
because it was ranked low — because the arithmetic ahead of it left nothing:
``_interleave_by_relevance_band`` fills the plan to ``exploit_max_plan_tasks``,
so by the time ``_merge_component_cve_tasks`` ran, ``len(merged) >= cap`` was
already true and every confirmable match took the "the plan cap was reached"
branch. The tier-2/3 research source, one function up, was blocked by the same
sum: ``tier23[: cap - len(tasks)]`` is ``tier23[:0]``.

Two properties are pinned here, and the second is the one that makes the first
safe to ship:

* **The reservation is spent by provenance, not by arrival.** A ``Server:``
  banner is a string the target chose and a back-ported fix defeats it; a
  lockfile entry is not. Reserving slots without ordering them would make the
  fourth plan source the one part of the engine immune to ranking, and would
  spend its scarce slots on the weakest evidence in the system. So when the
  ceiling bites, banner-derived matches are what fall out.
* **A run that matched nothing plans exactly what it planned before.** The
  reservation is ``min(16, dispatchable)``, and ``dispatchable`` is zero on
  every target with no CVE hit — which is nearly all of them. A reservation that
  cost coverage on runs it does nothing for would be a worse defect than the one
  it fixes, so the no-match plan is asserted byte-identical rather than
  "similar".
"""

from __future__ import annotations

import logging
from typing import Any

from clinkz.agents.exploit import (
    _MAX_COMPONENT_CVE_MATCHES,
    ExploitAgent,
)
from clinkz.knowledge.component_cves import (
    ComponentCVEMatch,
    KnownComponentCVE,
    match_components,
)
from clinkz.models.recon import DetectedComponent, VersionProvenance
from clinkz.models.scan import Endpoint, HTTPScanResult, ScanResult, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

SCOPE = EngagementScope(
    name="reservation-test",
    targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.test")],
)

# A catalogue with one confirmable entry, so a match's fate turns on the
# observation behind it rather than on which CVE it happened to hit.
_CATALOG: tuple[KnownComponentCVE, ...] = (
    KnownComponentCVE(
        cve_id="CVE-9999-0001",
        component=r"^widget$",
        affected="=1.0.0",
        title="Widget log-injection to JNDI lookup",
        severity="medium",
        # A class the deterministic Tier-1 buckets never produce, so a queued CVE
        # task is visible instead of colliding with a task the class floor
        # already planned for the same endpoint.
        confirming_test_method="_test_log4shell",
        proving_observation="an out-of-band callback carrying our nonce",
        reference="https://example.invalid/CVE-9999-0001",
    ),
    KnownComponentCVE(
        cve_id="CVE-9999-0002",
        component=r"^gadget$",
        affected="=2.0.0",
        title="Gadget remote file inclusion",
        severity="critical",
        confirming_test_method="_test_lfi",
        proving_observation="file content the application should not serve",
        reference="https://example.invalid/CVE-9999-0002",
    ),
)


def _agent(max_plan_tasks: int = 10) -> ExploitAgent:
    """A bare agent — no LLM, no network, no state store."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.scope = SCOPE
    agent._logger = logging.getLogger("test.reservation")
    agent._unproven_exploit_leads = []
    agent._component_cve_pending = {}
    agent._max_plan_tasks = max_plan_tasks
    agent.engagement_id = "reservation-test"
    return agent


def _endpoints(count: int) -> list[Endpoint]:
    """A surface big enough that the Tier-1 interleave saturates any small cap."""
    return [
        Endpoint(url=f"https://app.test/page{i}", method="GET", params=["id", "file"])
        for i in range(count)
    ]


def _scan(endpoints: list[Endpoint]) -> ScanResult:
    return ScanResult(
        target="https://app.test",
        service_scans=[
            ServiceScanResult(
                port=443,
                service_type="http",
                result=HTTPScanResult(base_url="https://app.test/", endpoints=endpoints),
            )
        ],
    )


def _recon(*components: DetectedComponent) -> dict[str, Any]:
    return {"components": [c.model_dump(mode="json") for c in components]}


# ---------------------------------------------------------------------------
# Provenance decides which matches get the reserved slots
# ---------------------------------------------------------------------------


def test_a_lockfile_match_outranks_a_banner_match_of_higher_severity() -> None:
    """Provenance sits ahead of published severity, deliberately.

    A CRITICAL resting on a banner and a MEDIUM resting on a lockfile are not
    the same claim. Ranking by severity first spends the reserved slots on the
    evidence a back-port defeats, and calls it prioritisation.
    """
    matches = match_components(
        [
            DetectedComponent(
                name="gadget",
                version="2.0.0",
                source="nmap:service",
                provenance=VersionProvenance.BANNER,
            ),
            DetectedComponent(
                name="widget",
                version="1.0.0",
                source="lockfile",
                provenance=VersionProvenance.LOCKFILE,
            ),
        ],
        catalog=_CATALOG,
    )
    assert [m.cve.cve_id for m in matches] == ["CVE-9999-0001", "CVE-9999-0002"], (
        "the lockfile-backed MEDIUM must precede the banner-backed CRITICAL — "
        f"got {[(m.cve.cve_id, m.provenance.value, m.cve.severity) for m in matches]}"
    )


def test_confirmability_still_outranks_provenance() -> None:
    """A match with no oracle cannot become a task, so it never displaces one.

    Provenance orders the matches that can claim a slot; it does not promote a
    lead past them. Otherwise a strongly-evidenced lead would push a weakly-
    evidenced *testable* match out of the ceiling, trading a test for a note.
    """
    catalog = (
        _CATALOG[0],
        KnownComponentCVE(
            cve_id="CVE-9999-0003",
            component=r"^gadget$",
            affected="=2.0.0",
            title="Gadget deserialization",
            severity="critical",
            confirming_test_method="",
            proving_observation="code execution on the host",
        ),
    )
    matches = match_components(
        [
            DetectedComponent(
                name="gadget",
                version="2.0.0",
                source="lockfile",
                provenance=VersionProvenance.LOCKFILE,
            ),
            DetectedComponent(
                name="widget",
                version="1.0.0",
                source="whatweb:plugin",
                provenance=VersionProvenance.BANNER,
            ),
        ],
        catalog=catalog,
    )
    assert [m.cve.cve_id for m in matches] == ["CVE-9999-0001", "CVE-9999-0003"]
    assert matches[0].is_confirmable and not matches[1].is_confirmable


def test_the_matched_on_string_states_the_provenance() -> None:
    """The lead a match becomes must carry how strong its version claim was.

    ``matched_on`` is rendered verbatim into the lead's raw observation, so this
    is the only place the reader of an UNCONFIRMED entry learns whether a
    back-port could have defeated the version.
    """
    matches = match_components(
        [
            DetectedComponent(
                name="widget",
                version="1.0.0",
                source="nmap:service",
                provenance=VersionProvenance.BANNER,
            )
        ],
        catalog=_CATALOG,
    )
    assert "version provenance: banner" in matches[0].matched_on


def test_an_undeclared_provenance_ranks_last() -> None:
    """Silence is not strength — the same rule research grounding follows."""
    matches = match_components(
        [
            DetectedComponent(name="gadget", version="2.0.0", source="mystery"),
            DetectedComponent(
                name="widget",
                version="1.0.0",
                source="whatweb:plugin",
                provenance=VersionProvenance.BANNER,
            ),
        ],
        catalog=_CATALOG,
    )
    assert [m.provenance for m in matches] == [
        VersionProvenance.BANNER,
        VersionProvenance.UNDECLARED,
    ]


# ---------------------------------------------------------------------------
# The reservation
# ---------------------------------------------------------------------------


def test_a_confirmable_match_now_wins_a_slot_on_a_saturated_plan() -> None:
    """The blocked path, unblocked — with the surface that used to block it."""
    endpoints = _endpoints(40)
    scan = _scan(endpoints)
    recon = _recon(
        DetectedComponent(
            name="widget",
            version="1.0.0",
            source="lockfile",
            provenance=VersionProvenance.LOCKFILE,
        )
    )
    agent = _agent(max_plan_tasks=10)
    agent._component_cve_matches = match_components(
        [DetectedComponent(name="widget", version="1.0.0", provenance=VersionProvenance.LOCKFILE)],
        catalog=_CATALOG,
    )
    agent._component_cve_reserved = 1

    plan = agent._build_deterministic_plan(endpoints, [], [])
    assert len(plan.tasks) == 9, (
        "the Tier-1 passes must give up exactly the reserved slot — "
        f"got {len(plan.tasks)} of a cap of 10 with 1 reserved"
    )

    merged = agent._merge_component_cve_tasks(plan, recon, scan)
    cve_tasks = [t for t in merged.tasks if t.component_cve is not None]
    assert len(cve_tasks) == 1, "the reserved slot must actually be spendable"
    assert cve_tasks[0].test_method == "_test_log4shell"
    assert cve_tasks[0].component_cve is not None
    assert cve_tasks[0].component_cve.cve_id == "CVE-9999-0001"
    assert cve_tasks[0].component_cve.version_provenance == "lockfile"
    assert len(merged.tasks) == 10, "the plan must land exactly on the configured cap"


def test_an_unspent_reservation_returns_to_the_tier1_fill() -> None:
    """A slot held for a task that was never queued is coverage paid for and not got.

    The reservation is sized before the plan exists, so a match can still be
    deduped away against a task another source already planned. When that
    happens the slot goes back rather than shrinking the plan silently.
    """
    endpoints = _endpoints(40)
    scan = _scan(endpoints)
    agent = _agent(max_plan_tasks=10)
    # Reserve two slots against a match set that can only ever queue one, which
    # is exactly the shape a dedup produces.
    agent._component_cve_matches = match_components(
        [DetectedComponent(name="widget", version="1.0.0", provenance=VersionProvenance.LOCKFILE)],
        catalog=_CATALOG,
    )
    agent._component_cve_reserved = 2

    plan = agent._build_deterministic_plan(endpoints, [], [])
    assert len(plan.tasks) == 8
    merged = agent._merge_component_cve_tasks(
        plan,
        _recon(DetectedComponent(name="widget", version="1.0.0")),
        scan,
    )
    assert len(merged.tasks) == 10, (
        "one reserved slot was spent and one was not; the unspent one must return "
        f"to the Tier-1 fill — plan is {len(merged.tasks)} of 10"
    )
    assert sum(1 for t in merged.tasks if t.component_cve is not None) == 1


def test_the_reservation_ceiling_is_the_declared_constant() -> None:
    """Sized to ``_MAX_COMPONENT_CVE_MATCHES``, which is the slice the union takes.

    A reservation larger than the slice would hold slots for matches the union
    never looks at; a smaller one would starve matches it does.
    """
    components = [
        DetectedComponent(
            name="widget",
            version="1.0.0",
            source=f"lockfile:{i}",
            port=i + 1,
            provenance=VersionProvenance.LOCKFILE,
        )
        for i in range(_MAX_COMPONENT_CVE_MATCHES + 5)
    ]
    endpoints = _endpoints(40)
    agent = _agent(max_plan_tasks=200)
    agent._harvest_components = staticmethod(lambda _: components)  # type: ignore[method-assign]

    def _matches(_: list[DetectedComponent]) -> list[ComponentCVEMatch]:
        return match_components(components, catalog=_CATALOG)

    agent._resolve_component_cve_reservation(
        {"components": [c.model_dump(mode="json") for c in components]},
        _scan(endpoints),
    )
    assert agent._component_cve_reserved <= _MAX_COMPONENT_CVE_MATCHES


# ---------------------------------------------------------------------------
# The no-match case: byte-identical, not merely similar
# ---------------------------------------------------------------------------


def test_a_run_with_no_cve_match_plans_byte_identically() -> None:
    """The pinning test the reservation had to earn.

    Nearly every engagement matches no CVE. If the reservation cost those runs a
    single Tier-1 task, it would be a coverage regression paid on every target to
    benefit a handful — so the plan is compared field for field, not by length.
    """
    endpoints = _endpoints(40)
    scan = _scan(endpoints)

    baseline = _agent(max_plan_tasks=25)
    baseline_plan = baseline._build_deterministic_plan(endpoints, [], [])
    baseline_merged = baseline._merge_component_cve_tasks(baseline_plan, None, scan)

    # The same agent, having actually gone through the reservation step against
    # an inventory that matches nothing in the catalogue.
    reserved = _agent(max_plan_tasks=25)
    reserved._resolve_component_cve_reservation(
        _recon(
            DetectedComponent(
                name="nothing-in-the-catalogue",
                version="9.9.9",
                source="nmap:service",
                provenance=VersionProvenance.BANNER,
            )
        ),
        scan,
    )
    assert reserved._component_cve_reserved == 0, (
        "an inventory with no catalogue hit must reserve nothing — "
        f"reserved {reserved._component_cve_reserved}"
    )
    reserved_plan = reserved._build_deterministic_plan(endpoints, [], [])
    reserved_merged = reserved._merge_component_cve_tasks(
        reserved_plan,
        _recon(DetectedComponent(name="nothing-in-the-catalogue", version="9.9.9")),
        scan,
    )

    assert reserved_merged.model_dump(mode="json") == baseline_merged.model_dump(mode="json"), (
        "a run that matched no CVE must plan exactly what it planned before the reservation existed"
    )


def test_an_empty_inventory_reserves_nothing() -> None:
    """No components at all is the commonest shape and must cost nothing."""
    agent = _agent(max_plan_tasks=25)
    agent._resolve_component_cve_reservation(None, _scan(_endpoints(5)))
    assert agent._component_cve_reserved == 0
    assert agent._tier1_plan_task_cap() == agent._max_plan_task_cap()


def test_a_match_with_no_discovered_surface_reserves_nothing() -> None:
    """A match that can only ever become a lead costs no plan slot.

    A lead is not a task. Reserving for one would shrink the Tier-1 fill to hold
    a slot nothing can be queued into.
    """
    agent = _agent(max_plan_tasks=25)
    agent._resolve_component_cve_reservation(
        _recon(
            DetectedComponent(
                name="widget",
                version="1.0.0",
                source="lockfile",
                provenance=VersionProvenance.LOCKFILE,
            )
        ),
        _scan([]),
    )
    assert agent._component_cve_reserved == 0


# ---------------------------------------------------------------------------
# The second blocked path: the tier-2/3 research source
# ---------------------------------------------------------------------------


def test_the_research_source_is_computed_even_when_the_cap_leaves_no_room() -> None:
    """It used to not even be CALLED, which is why its silence was unreadable.

    ``if len(tasks) < cap`` guarded the whole branch and the interleave above it
    fills to ``cap``, so on any saturating target ``_build_tier23_tasks`` never
    ran. A plan source contributing nothing then looked exactly like research
    having produced no techniques — the same conflation the contribution ledger
    exists to end, one layer up.
    """
    endpoints = _endpoints(40)
    agent = _agent(max_plan_tasks=10)
    runbook = [_Technique(name="Some published technique", steps=["step one"])]

    recorded: list[Any] = []
    agent._log_plan_truncation = (  # type: ignore[method-assign]
        lambda stage, buckets, kept, cap, by_key=None: recorded.append((stage, buckets, kept))
    )
    agent._build_deterministic_plan(endpoints, [], runbook)

    assert recorded, "the truncation report must still run"
    _stage, buckets, _kept = recorded[0]
    assert "_test_tier3_technique" in buckets, (
        "the research source's candidates must reach the truncation buckets so the "
        "report can say the cap refused them — otherwise the source is invisible, "
        f"and the plan only knows about {sorted(buckets)}"
    )


def test_the_research_source_still_takes_whatever_room_the_cap_leaves() -> None:
    """The fill is unchanged — only the silence was the defect.

    Handing this source a reservation would cost the client's target a real
    request (the dispatcher fetches the endpoint before calling the handler) and
    a Tier-1 class a real task, to run two methods registered NOT_IMPLEMENTED
    that construct no Finding. So on a target the cap does not saturate it takes
    room exactly as it always did, and on one that saturates it is DISCLOSED
    rather than skipped.
    """
    agent = _agent(max_plan_tasks=50)
    plan = agent._build_deterministic_plan(_endpoints(1), [], [_Technique(name="T", steps=["s"])])
    assert [t.tier for t in plan.tasks if t.tier == 3], (
        "a small surface leaves room, and the research source must still use it — "
        f"plan holds {[(t.test_method, t.tier) for t in plan.tasks]}"
    )


class _Technique:
    """A minimal research-runbook entry (duck-typed by ``_build_tier23_tasks``)."""

    def __init__(self, name: str, steps: list[str]) -> None:
        self.name = name
        self.steps = steps


# ---------------------------------------------------------------------------
# Provenance reaches the finding, not just the planner
# ---------------------------------------------------------------------------


def test_the_cve_context_lands_on_the_finding_its_own_oracle_emitted() -> None:
    from clinkz.models.finding import ComponentCVEContext, Finding, Severity

    finding = Finding(
        title="Path traversal in /download",
        description="oracle-confirmed",
        severity=Severity.HIGH,
        target="https://app.test/download",
        evidence=["Request: GET /download", "phases_completed=6 verified=True strength=verified"],
    )
    ExploitAgent._stamp_component_cve_context(
        [finding],
        ComponentCVEContext(
            cve_id="CVE-9999-0001",
            title="Widget path traversal",
            observed_component="widget",
            observed_version="1.0.0",
            version_provenance="lockfile",
            observation_source="package-lock.json",
            affected="=1.0.0",
            reference="https://example.invalid/CVE-9999-0001",
        ),
    )
    assert finding.cve_ids == ["CVE-9999-0001"]
    assert "https://example.invalid/CVE-9999-0001" in finding.references
    context_line = next(e for e in finding.evidence if e.startswith("Known-CVE context:"))
    assert "version provenance: lockfile" in context_line
    assert "package-lock.json" in context_line
    assert "this engine's own oracle did" in context_line


def test_the_context_line_can_never_be_read_as_an_engine_verdict() -> None:
    """Prose by construction, so the structured-evidence readers skip it.

    ``_evidence_strength`` and the deterministic grounds read only entries whose
    EVERY token is ``key=value``. A context line carrying target-derived text
    (a product name, a version) must not be able to reach them — a suppression
    primitive handed to the host under test is worse than the phantom a guard
    prevents.
    """
    from clinkz.agents.exploit import _evidence_strength
    from clinkz.models.finding import ComponentCVEContext, Finding, Severity

    finding = Finding(
        title="Path traversal in /download",
        description="oracle-confirmed",
        severity=Severity.HIGH,
        target="https://app.test/download",
        evidence=["phases_completed=6 verified=True strength=verified"],
    )
    ExploitAgent._stamp_component_cve_context(
        [finding],
        ComponentCVEContext(
            cve_id="CVE-9999-0001",
            # A product name the TARGET chose, spelled to look like a verdict.
            observed_component="strength=likely",
            observed_version="1.0.0",
            version_provenance="banner",
        ),
    )
    assert _evidence_strength(finding.evidence) == "verified", (
        "a component name echoed from the target must not be able to restate the "
        "engine's own verification strength"
    )


def test_stamping_is_idempotent_and_never_creates_a_finding() -> None:
    from clinkz.models.finding import ComponentCVEContext, Finding, Severity

    context = ComponentCVEContext(cve_id="CVE-9999-0001", version_provenance="banner")
    findings: list[Finding] = []
    ExploitAgent._stamp_component_cve_context(findings, context)
    assert findings == [], "a version match must never produce a finding"

    finding = Finding(title="t", description="d", severity=Severity.LOW, target="https://app.test")
    ExploitAgent._stamp_component_cve_context([finding], context)
    ExploitAgent._stamp_component_cve_context([finding], context)
    assert finding.cve_ids == ["CVE-9999-0001"]
    assert sum(1 for e in finding.evidence if e.startswith("Known-CVE context:")) == 1
