"""fingerprint → component+version → known CVE → test.

The rung that did not exist. Every piece was already there — fingerprinting
named products, ``-sV`` resolved versions, ``version_satisfies`` compared them,
and seven oracles were sitting downstream — but nothing joined the halves, so no
engagement ever tested a dependency against a published CVE.

**The emission rule is what these tests are mostly about.** A CVE match on a
version string is a LEAD, never a finding — the same rule that correctly demoted
the sqlmap-only SQLi, for the same reason: it is somebody else's conclusion about
what is installed, not an effect this engine observed. A banner can lie, a distro
can back-port a fix without moving the version, and the vulnerable code path may
be unreachable from any request. So the refusal half is tested at least as hard
as the confirm half.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS, ExploitAgent
from clinkz.discovery.versions import parse_version, version_satisfies
from clinkz.knowledge.component_cves import (
    BACKPORT_CAVEAT,
    BACKPORT_DEFEASIBLE_PROVENANCE,
    BAND_C_VECTORS,
    CARRIABLE_VECTORS,
    KNOWN_COMPONENT_CVES,
    LEAD_NO_ORACLE,
    LEAD_UNIDENTIFIABLE,
    LEAD_VECTOR_NOT_CARRIED,
    ComponentCVEMatch,
    CVEVector,
    KnownComponentCVE,
    MatchDisposition,
    match_components,
)
from clinkz.models.finding import (
    UNPROVEN_WHY_UNCONFIRMED,
    ExploitPlan,
    ExploitTask,
    Finding,
    Severity,
)
from clinkz.models.recon import (
    DetectedComponent,
    ReconResult,
    VersionProvenance,
    dedupe_components,
)
from clinkz.models.scan import Endpoint, HTTPScanResult, ScanResult, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.ledger import (
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)
from clinkz.tools.nmap import NmapOutput
from clinkz.tools.whatweb import WhatWebOutput, WhatWebScanResult

SCOPE = EngagementScope(
    name="cve-path",
    targets=[ScopeEntry(type=ScopeType.IP, value="10.0.0.1")],
)


def _agent() -> ExploitAgent:
    """A bare agent — no LLM, no network, no state store."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.scope = SCOPE
    agent._logger = logging.getLogger("test.cve")
    agent._unproven_exploit_leads = []
    agent._component_cve_pending = {}
    agent.engagement_id = "cve-test"
    return agent


def _plan(*tasks: ExploitTask) -> ExploitPlan:
    return ExploitPlan(
        tasks=list(tasks),
        tier1_count=sum(1 for t in tasks if t.tier == 1),
        tier2_count=sum(1 for t in tasks if t.tier == 2),
        tier3_count=sum(1 for t in tasks if t.tier == 3),
    )


def _scan(*urls: str, params: list[str] | None = None, port: int = 80) -> ScanResult:
    """A ScanResult with real endpoints, reached the way the agent reaches them.

    Endpoints live under ``service_scans[].result.endpoints``, not on
    ``ScanResult`` itself — building the real nesting keeps this test honest
    about the shape the production code actually walks.

    ``params`` defaults to one query parameter on every endpoint because the
    endpoint choice now REQUIRES a parameterised surface: every ``_test_*`` the
    CVE source dispatches to carries its probe as a parameter value, so a
    parameter-less endpoint is one the oracle sends nothing to. A fixture
    without params would make every row look unreservable and would be testing
    the fixture.
    """
    names = ["q"] if params is None else params
    return ScanResult(
        target="10.0.0.1",
        service_scans=[
            ServiceScanResult(
                port=port,
                service_type="http",
                result=HTTPScanResult(
                    base_url="http://10.0.0.1/",
                    endpoints=[Endpoint(url=u, params=list(names)) for u in urls],
                ),
            )
        ],
    )


# ---------------------------------------------------------------------------
# The inventory: fingerprinters carry versions all the way through
# ---------------------------------------------------------------------------


def test_nmap_service_banners_become_versioned_components() -> None:
    """``-sV`` is the richest version source and it now reaches the inventory."""
    from clinkz.models.target import Host, Service

    out = NmapOutput(
        tool_name="nmap",
        success=True,
        hosts=[
            Host(
                ip="10.0.0.1",
                services=[
                    Service(port=80, name="http", product="Apache httpd", version="2.4.49"),
                    Service(port=22, name="ssh", product="OpenSSH", version="8.9p1"),
                ],
            )
        ],
    )
    components = out.detected_components()
    assert {(c.name, c.version, c.port) for c in components} == {
        ("Apache httpd", "2.4.49", 80),
        ("OpenSSH", "8.9p1", 22),
    }
    assert all(c.source == "nmap:service" for c in components)


def test_whatweb_versions_finally_reach_a_consumer() -> None:
    """``WhatWebScanResult.versions`` was parsed for years and read by nothing."""
    out = WhatWebOutput(
        tool_name="whatweb",
        success=True,
        results=[
            WhatWebScanResult(
                target="http://10.0.0.1/",
                technologies=["nginx", "jQuery"],
                versions={"nginx": "1.24.0", "jQuery": "3.4.1"},
            )
        ],
    )
    assert {(c.name, c.version) for c in out.detected_components()} == {
        ("nginx", "1.24.0"),
        ("jQuery", "3.4.1"),
    }


def test_dedupe_prefers_the_observer_that_had_a_version() -> None:
    """Two tools naming one product is normal; only one usually knows the version."""
    merged = dedupe_components(
        [
            DetectedComponent(name="nginx", source="whatweb:plugin"),
            DetectedComponent(name="nginx", version="1.24.0", source="nmap:service"),
        ]
    )
    assert len(merged) == 1
    assert merged[0].version == "1.24.0"


# ---------------------------------------------------------------------------
# Matching: the honesty rules live here
# ---------------------------------------------------------------------------


def test_an_affected_version_matches() -> None:
    matches = match_components([DetectedComponent(name="Apache", version="2.4.49", port=80)])
    assert "CVE-2021-41773" in {m.cve.cve_id for m in matches}


def test_a_patched_version_does_not_match() -> None:
    """The control. A matcher that fires on the fixed version is not a matcher."""
    matches = match_components([DetectedComponent(name="Apache", version="2.4.58", port=80)])
    assert "CVE-2021-41773" not in {m.cve.cve_id for m in matches}


def test_an_unversioned_component_matches_no_version_bounded_cve() -> None:
    """The deliberate recall loss, asserted so nobody "fixes" it later.

    Without a version there is no evidence the host is in the affected range.
    Reporting a CVE anyway would be the exact fabrication this module refuses —
    so an unversioned ``Apache`` matches nothing version-bounded, even though it
    may well be vulnerable.
    """
    matches = match_components([DetectedComponent(name="Apache", version="", port=80)])
    assert all(m.cve.affected == "*" for m in matches), [
        (m.cve.cve_id, m.cve.affected) for m in matches
    ]


def test_matches_are_ordered_confirmable_first_and_deterministically() -> None:
    """Plan order must not depend on inventory order — two runs, one worklist."""
    components = [
        DetectedComponent(name="lodash", version="4.17.4"),
        DetectedComponent(name="Apache", version="2.4.49", port=80),
        DetectedComponent(name="jquery", version="3.3.1"),
    ]
    forward = [(m.cve.cve_id, m.component.name) for m in match_components(components)]
    reversed_order = [
        (m.cve.cve_id, m.component.name) for m in match_components(list(reversed(components)))
    ]
    assert forward == reversed_order
    confirmable = [m.is_confirmable for m in match_components(components)]
    assert confirmable == sorted(confirmable, reverse=True), "confirmable matches must sort first"


def test_every_catalogue_entry_naming_a_method_names_a_real_one() -> None:
    """A catalogue claiming an oracle we do not have is a back door to emission."""
    dispatchable = set(DISPATCHABLE_TEST_METHODS)
    for entry in KNOWN_COMPONENT_CVES:
        if entry.confirming_test_method:
            assert entry.confirming_test_method in dispatchable, (
                f"{entry.cve_id} names {entry.confirming_test_method}, which the Exploit "
                "Agent does not dispatch"
            )


def test_an_unbounded_entry_must_name_a_specific_component() -> None:
    """An entry that matches unconditionally carries no information.

    ``affected="*"`` means "every version", so the only thing bounding the match
    is the component pattern. Combine ``*`` with a broad alternation of generic
    server names — which is exactly how a protocol-level CVE like HTTP/2 Rapid
    Reset wants to be written — and the entry matches every host in the world.
    A lead equally true of every target is the version-match form of a phantom:
    it fills the worklist and distinguishes nothing.
    """
    for entry in KNOWN_COMPONENT_CVES:
        if entry.affected != "*":
            continue
        assert "|" not in entry.component, (
            f"{entry.cve_id} is unbounded (affected='*') AND matches an alternation of "
            f"components ({entry.component!r}). It would fire on every engagement without "
            "saying anything about the target."
        )


def test_no_catalogue_entry_matches_an_arbitrary_component() -> None:
    """The end-to-end form of the rule above, over the real catalogue."""
    noise = [
        DetectedComponent(name="nginx", version="1.99.0"),
        DetectedComponent(name="Apache httpd", version="2.4.62"),
        DetectedComponent(name="Express", version="4.21.0"),
    ]
    assert match_components(noise) == [], (
        "a fully-patched, ordinary stack must produce no CVE match at all — "
        f"got {[m.cve.cve_id for m in match_components(noise)]}"
    )


#: Bounded entries allowed a CLOSED upper bound, each with the reason its
#: advisory genuinely names a last-affected version rather than a fixed one.
#: Empty on purpose: every entry in the catalogue today is derived from an
#: advisory that states the version the fix landed in.
_CLOSED_UPPER_BOUND_ALLOWED: dict[str, str] = {}


def test_every_bounded_entry_uses_a_half_open_upper_bound() -> None:
    """The decrement-by-one guard, over a domain computed from the catalogue.

    A closed upper bound obliges its author to name the last version released
    before the fix — a fact the advisory does not state. Guess it low and the
    predicate under-matches, which produces a MISSED finding: silent, and
    unreachable by every control arm this engine has. The half-open form is
    derived from the one number the advisory does give.

    This is why ``[1.2.0,3.4.9]`` (jQuery CVE-2020-11022, advisory ``< 3.5.0``)
    is gone: it silently excluded ``3.4.95``.
    """
    for entry in KNOWN_COMPONENT_CVES:
        if not entry.affected.startswith(("[", "(")):
            continue
        if entry.cve_id in _CLOSED_UPPER_BOUND_ALLOWED:
            assert _CLOSED_UPPER_BOUND_ALLOWED[entry.cve_id].strip(), (
                f"{entry.cve_id} is allow-listed with no reason"
            )
            continue
        assert entry.affected.endswith(")"), (
            f"{entry.cve_id} has a CLOSED upper bound ({entry.affected!r}). Write it as "
            "[introduced,fixed) — the advisory's own form — or allow-list it with the "
            "reason its advisory names a last-affected version."
        )


def test_a_version_between_the_last_release_and_the_fix_is_still_in_range() -> None:
    """The property that a hand-decremented upper bound breaks, on real entries.

    For every half-open entry, a version below the fix with a patch number no
    author would have guessed must still match. jQuery ``3.4.95`` is the case
    the old ``[1.2.0,3.4.9]`` silently dropped.
    """
    for entry in KNOWN_COMPONENT_CVES:
        if not (entry.affected.startswith("[") and entry.affected.endswith(")")):
            continue
        low, high = entry.affected[1:-1].split(",", 1)
        major, minor, patch = parse_version(high.strip()) or (0, 0, 0)
        below = f"{major}.{minor}.{patch - 1}" if patch else f"{major}.{minor - 1}.95"
        if not version_satisfies(below, f"[{low.strip()},{high.strip()})"):
            continue  # below the introduced bound — nothing to assert for this entry
        assert version_satisfies(below, entry.affected), (
            f"{entry.cve_id}: {below} is inside {entry.affected} by construction"
        )
        assert not version_satisfies(high.strip(), entry.affected), (
            f"{entry.cve_id}: the fixed version {high.strip()} must be OUT of {entry.affected}"
        )


def test_the_apache_entries_still_match_exactly_what_they_matched_before() -> None:
    """The single-point entries moved to half-open form and did not drift.

    ``=2.4.49`` became ``[2.4.49,2.4.50)``: 2.4.49 still hits, 2.4.67 still
    misses, and the distribution spelling — which the exact form could not
    match — now does.
    """

    def _hits(version: str) -> set[str]:
        return {
            m.cve.cve_id
            for m in match_components([DetectedComponent(name="Apache", version=version, port=80)])
        }

    assert _hits("2.4.49") == {"CVE-2021-41773"}
    assert _hits("2.4.50") == {"CVE-2021-42013"}
    assert _hits("2.4.67") == set()
    assert _hits("2.4.48") == set()
    assert _hits("2.4.51") == set()
    assert _hits("2.4.49-1ubuntu3.2") == {"CVE-2021-41773"}


# ---------------------------------------------------------------------------
# Back-ports: provenance gates the CLAIM, never the TEST
# ---------------------------------------------------------------------------


def test_a_banner_derived_match_is_still_dispatched() -> None:
    """The decision, recorded. A back-ported host gets TESTED, not skipped.

    Refusing to dispatch below lockfile-grade provenance would delete this
    engine's only published-CVE coverage of the component class it most often
    observes by banner, and buy nothing: the oracle is the gate, so a patched
    host in the affected range is tested, observed to do nothing, and stays a
    lead. The honesty rule lives at ``_persist_finding``, not here.

    The fixture is Solr rather than Apache httpd, and the swap is the point of
    a different rule: the Apache rows are ``URL_PATH`` CVEs and no longer
    dispatch at all, so asserting this claim on one would have quietly become an
    assertion about the vector instead of about provenance. Solr 8.0.0 is
    banner-observable and its Velocity SSTI arrives in a request parameter, so
    the only thing this test can now be failing on is the provenance rule.
    """
    match = match_components(
        [
            DetectedComponent(
                name="Apache Solr",
                version="8.0.0",
                port=8983,
                source="nmap",
                provenance=VersionProvenance.BANNER,
            )
        ]
    )[0]
    assert match.backport_defeasible is True
    assert match.disposition is MatchDisposition.DISPATCH


def test_an_oracle_we_have_but_cannot_reach_is_a_lead_that_says_which() -> None:
    """The measured gap, pinned: an oracle exists and the vector is not carried.

    ``_test_lfi`` iterates ``page.input_params`` and sends its probe as a
    parameter VALUE — three requests, none of them mutating the URL path. The
    Apache traversal is reached by traversing an aliased directory IN the path.
    So the row keeps its oracle (it is the right oracle) and stops dispatching,
    and the lead says the vector was never carried rather than that the oracle
    ran and saw nothing.
    """
    match = match_components(
        [DetectedComponent(name="Apache", version="2.4.49", port=80, source="nmap")]
    )[0]
    assert match.cve.cve_id == "CVE-2021-41773"
    assert match.is_confirmable is True, "the file-read oracle genuinely proves this effect"
    assert match.vector_is_carriable is False, "and this plan source cannot deliver a URL path"
    assert match.can_dispatch is False
    assert match.disposition is MatchDisposition.LEAD
    assert match.lead_reason == LEAD_VECTOR_NOT_CARRIED
    assert match.lead_reason in UNPROVEN_WHY_UNCONFIRMED


def test_a_component_no_producer_can_name_is_not_a_weak_sighting() -> None:
    """``identifiable_by`` is an observability claim, never a policy gate.

    ejs runs on the server, so nothing that reads a banner can report it. A row
    reading ``ejs 3.1.6`` at banner strength is a mis-parse of something else,
    and there is no observation of ejs to test — which is a different fact from
    "the evidence is weak", and it gets a different reason.
    """
    lockfile = match_components(
        [
            DetectedComponent(
                name="ejs",
                version="3.1.6",
                source="package-lock.json",
                provenance=VersionProvenance.LOCKFILE,
            )
        ]
    )[0]
    assert lockfile.can_dispatch is True
    assert lockfile.disposition is MatchDisposition.DISPATCH

    banner = match_components(
        [
            DetectedComponent(
                name="ejs",
                version="3.1.6",
                source="whatweb",
                provenance=VersionProvenance.BANNER,
            )
        ]
    )[0]
    assert banner.component_is_identifiable is False
    assert banner.can_dispatch is False
    assert banner.lead_reason == LEAD_UNIDENTIFIABLE
    assert banner.lead_reason in UNPROVEN_WHY_UNCONFIRMED


def test_every_entry_naming_an_oracle_states_the_effect_that_oracle_proves() -> None:
    """A named method without a stated effect cannot be checked against it.

    The pairing is what went wrong on the Apache rows and the only durable guard
    is that the row has to SAY what it expects the oracle to witness — a
    sentence a reader can hold against ``_control_arm``'s partition without
    opening the methodology.
    """
    for entry in KNOWN_COMPONENT_CVES:
        if not entry.confirming_test_method:
            continue
        assert entry.defining_effect.strip(), (
            f"{entry.cve_id} names {entry.confirming_test_method} and does not say what "
            "that oracle is expected to witness"
        )


def test_only_a_carriable_vector_may_dispatch_over_the_whole_catalogue() -> None:
    """The guard-domain law over a domain COMPUTED from the catalogue.

    Not a list of rows to check — every row, every time. An entry naming an
    oracle whose vector this plan source cannot carry must not be dispatchable,
    because a dispatch is a claim that the work was attempted.
    """
    for entry in KNOWN_COMPONENT_CVES:
        match = ComponentCVEMatch(
            component=DetectedComponent(name="probe", version="1.0.0"), cve=entry
        )
        if entry.vector not in CARRIABLE_VECTORS:
            assert match.can_dispatch is False, (
                f"{entry.cve_id} declares vector {entry.vector.value}, which no "
                "component-derived task carries, yet it dispatches"
            )


def test_the_carriable_set_is_exactly_what_a_component_task_can_send() -> None:
    """Widening this set is a code change plus a live proof, never a row edit.

    A component-derived ``ExploitTask`` is built with an endpoint, that
    endpoint's params and its request shape. It carries no ``carrier_constraints``
    and no ``ParamLocation.PATH`` substitution, so the parameter value is the
    only channel it has. Pinned so that adding ``URL_PATH`` here without
    building the carrier fails loudly.
    """
    assert CARRIABLE_VECTORS == {CVEVector.REQUEST_PARAM}
    assert BAND_C_VECTORS == {CVEVector.ENVIRONMENTAL}
    assert not (CARRIABLE_VECTORS & BAND_C_VECTORS), (
        "a vector cannot be both the one channel we can send and permanently unprovable"
    )


def test_a_defeasible_match_says_so_in_the_observation_a_client_reads() -> None:
    """Where provenance DOES decide: the wording of the claim."""
    banner = match_components(
        [
            DetectedComponent(
                name="jquery",
                version="3.4.1",
                source="whatweb",
                provenance=VersionProvenance.BANNER,
            )
        ]
    )[0]
    assert banner.disposition is MatchDisposition.LEAD
    assert BACKPORT_CAVEAT in banner.matched_on

    lockfile = match_components(
        [
            DetectedComponent(
                name="jquery",
                version="3.4.1",
                source="package-lock.json",
                provenance=VersionProvenance.LOCKFILE,
            )
        ]
    )[0]
    assert lockfile.backport_defeasible is False
    assert BACKPORT_CAVEAT not in lockfile.matched_on


def test_the_defeasible_set_is_exactly_the_target_composed_provenances() -> None:
    """A provenance added later must be classified deliberately, not by default."""
    resolved = {
        VersionProvenance.LOCKFILE,
        VersionProvenance.ARTIFACT_HASH,
        VersionProvenance.MANIFEST,
    }
    assert BACKPORT_DEFEASIBLE_PROVENANCE == set(VersionProvenance) - resolved


def test_disposition_is_a_closed_vocabulary_of_two() -> None:
    """A third outcome does not exist: a match is a task or it is a lead.

    The two outcomes are unchanged; what decides between them is not. It used to
    be ``confirming_test_method`` alone, which answered only whether an oracle
    exists — the Apache rows named one and could not be reached by it. The
    predicate is now ``can_dispatch``, and the reasons a match landed on LEAD
    are carried separately by :attr:`lead_reason` rather than by inventing a
    third disposition for each of them.
    """
    assert {d.value for d in MatchDisposition} == {"dispatch", "lead"}
    for entry in KNOWN_COMPONENT_CVES:
        # Probed at the strongest provenance the row declares itself observable
        # at. Probing everything at the default UNDECLARED would make every
        # ``identifiable_by`` row a lead and the assertion would be measuring
        # the fixture's provenance rather than the disposition rule.
        allowed = entry.identifiable_by
        provenance = VersionProvenance.LOCKFILE if allowed is None else sorted(allowed)[0]
        component = DetectedComponent(name="x", version="1.0.0", provenance=provenance)
        match = ComponentCVEMatch(component=component, cve=entry)
        expected = (
            MatchDisposition.DISPATCH
            if (
                entry.confirming_test_method
                and entry.vector in CARRIABLE_VECTORS
                and match.component_is_identifiable
            )
            else MatchDisposition.LEAD
        )
        assert match.disposition is expected, entry.cve_id


def test_every_lead_reason_is_in_the_closed_vocabulary_over_the_catalogue() -> None:
    """Domain computed from the catalogue, classification hand-maintained.

    A row whose ``lead_reason`` is not in ``UNPROVEN_WHY_UNCONFIRMED`` records a
    lead under a reason the report cannot render, which is the silent half of
    the same defect: the operator gets a lead with no actionable reason on it.
    """
    for entry in KNOWN_COMPONENT_CVES:
        for provenance in VersionProvenance:
            match = ComponentCVEMatch(
                component=DetectedComponent(name="probe", version="1.0.0", provenance=provenance),
                cve=entry,
            )
            assert match.lead_reason in UNPROVEN_WHY_UNCONFIRMED, (
                f"{entry.cve_id} at {provenance.value} produces {match.lead_reason!r}, "
                "which the report has no sentence for"
            )


def test_every_catalogue_entry_states_its_proving_observation() -> None:
    """A lead that cannot say what would prove it is not an actionable lead."""
    for entry in KNOWN_COMPONENT_CVES:
        assert entry.proving_observation.strip(), f"{entry.cve_id} has no proving_observation"
        assert entry.cve_id.startswith("CVE-")


def test_every_lead_reason_has_a_sentence_the_dispatcher_can_render() -> None:
    """The other half of the closed vocabulary: the reason must have prose.

    ``_merge_component_cve_tasks`` looks the reason up in
    ``_COMPONENT_CVE_LEAD_MISSING`` with a bare subscript, so a reason added to
    the vocabulary and not to the table raises inside the plan seam. The
    subscript is deliberate — a ``.get(reason, "")`` would emit a lead with an
    empty ``missing_observation``, which is a lead an operator cannot act on
    and the silent version of the same defect. This asserts both directions.
    """
    from clinkz.agents.exploit import _COMPONENT_CVE_LEAD_MISSING

    reasons = {LEAD_NO_ORACLE, LEAD_UNIDENTIFIABLE, LEAD_VECTOR_NOT_CARRIED}
    assert set(_COMPONENT_CVE_LEAD_MISSING) == reasons, (
        "every lead reason needs a client-facing sentence, and every sentence a reason"
    )
    for reason, sentence in _COMPONENT_CVE_LEAD_MISSING.items():
        assert reason in UNPROVEN_WHY_UNCONFIRMED, reason
        assert sentence.strip(), reason


def test_a_band_c_entry_says_it_is_permanent_rather_than_pending() -> None:
    """The default vector is ENVIRONMENTAL, so the classification must be MEANT.

    ``ENVIRONMENTAL`` is the model's default precisely so an unclassified row
    cannot dispatch — the fail-safe direction. That makes it the value a row
    also lands on by ACCIDENT, and the two readings are opposite: "no remote
    oracle can ever prove this" versus "nobody got round to classifying it". A
    Band C row therefore has to say ``permanently lead-only`` in the sentence a
    client reads, which is a claim an author cannot make by forgetting.
    """
    band_c = [e for e in KNOWN_COMPONENT_CVES if e.vector in BAND_C_VECTORS]
    assert band_c, "the catalogue carries Band C entries and the report renders them"
    for entry in band_c:
        assert "permanently lead-only" in entry.proving_observation.lower(), (
            f"{entry.cve_id} is Band C. Say why it can never be proven remotely, or "
            "give it the vector it actually has"
        )
        assert not entry.confirming_test_method, (
            f"{entry.cve_id} is Band C and names an oracle. If an oracle can witness "
            "it, it is not permanently unprovable"
        )


def test_the_band_c_product_property_reaches_the_deliverable() -> None:
    """Part 4: the client is TOLD what a version match can become, on every run.

    Rendered from the catalogue rather than written down, so the numbers cannot
    drift from the rows they describe. Gated on an inventory existing — with
    nothing fingerprinted there is nothing for the matcher to read and nothing
    to say about it.
    """
    from datetime import UTC, datetime

    from clinkz.agents.report import ReportAgent
    from clinkz.models.report import PentestReport

    now = datetime.now(UTC)
    report = PentestReport(
        engagement_id="band-c",
        engagement_name="band-c",
        target="10.0.0.1",
        test_start=now,
        test_end=now,
        component_inventory={
            "total": 1,
            "versioned": 1,
            "components": [{"name": "Apache", "version": "2.4.67", "provenance": "banner"}],
        },
    )
    lines: list[str] = []
    ReportAgent._render_version_match_disposition(lines, report)
    rendered = "\n".join(lines)
    assert "## What a version match can become" in rendered
    assert "never becomes a finding on the strength of a version number" in rendered
    assert "Band C" in rendered and "permanently lead-only" in rendered
    testable = sum(
        1
        for e in KNOWN_COMPONENT_CVES
        if e.confirming_test_method and e.vector in CARRIABLE_VECTORS
    )
    assert f"**{testable} are testable**" in rendered, "the count must come off the catalogue"

    # And it says nothing at all when nothing was fingerprinted.
    empty: list[str] = []
    ReportAgent._render_version_match_disposition(
        empty,
        PentestReport(
            engagement_id="e",
            engagement_name="e",
            target="t",
            test_start=now,
            test_end=now,
        ),
    )
    assert empty == []


# ---------------------------------------------------------------------------
# The plan seam: task where we have an oracle, lead where we do not
# ---------------------------------------------------------------------------


def _recon(*components: DetectedComponent) -> ReconResult:
    from clinkz.models.recon import PortScanResult, ServiceScanResult, TechStack

    return ReconResult(
        target="10.0.0.1",
        ports=PortScanResult(),
        services=ServiceScanResult(),
        tech_stack=TechStack(),
        components=list(components),
    )


def test_a_confirmable_cve_becomes_a_task_for_our_own_oracle() -> None:
    """A row whose oracle exists AND whose vector we carry becomes a real task.

    The fixture is Solr, not Apache httpd, and that is the correction rather
    than a convenience: the Apache traversal rows name the right oracle and
    arrive in the URL path, which no component-derived task sends, so they are
    leads now. Solr's Velocity SSTI arrives in a request parameter — the one
    channel this source has — so it is what a dispatch claim can honestly be
    asserted on.
    """
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache Solr", version="8.0.0", port=80)),
        _scan("http://10.0.0.1/deep/page", "http://10.0.0.1/app"),
    )
    # Solr 8.0.0 genuinely sits inside TWO published ranges — the Velocity SSTI
    # and the ReplicationHandler SSRF — and both are real, so both are queued.
    assert {t.test_method for t in plan.tasks} == {"_test_ssti", "_test_ssrf"}
    assert {t.technique_name.split(" ")[0] for t in plan.tasks} == {
        "CVE-2019-17558",
        "CVE-2021-27905",
    }
    for task in plan.tasks:
        assert task.endpoint_url == "http://10.0.0.1/app", (
            "the shortest-path PARAMETERISED endpoint, deterministically, never crawl order"
        )
        assert task.endpoint_params == ["q"], (
            "the endpoint's own params ride along; without them the methodology sends nothing"
        )
    assert not agent._unproven_exploit_leads, "a queued task is not also a lead"


def test_a_url_path_cve_is_a_lead_at_the_plan_seam_and_costs_no_slot() -> None:
    """The other half of the same fixture change, asserted end to end."""
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache httpd", version="2.4.49", port=80)),
        _scan("http://10.0.0.1/", "http://10.0.0.1/app"),
    )
    assert plan.tasks == [], "a vector we cannot carry must not spend a plan slot"
    assert len(agent._unproven_exploit_leads) == 1
    lead = agent._unproven_exploit_leads[0]
    assert lead.why_unconfirmed == LEAD_VECTOR_NOT_CARRIED
    assert "HAS an oracle" in lead.missing_observation
    assert "not a statement that the host is clean" in lead.missing_observation


def test_a_parameterless_surface_is_a_lead_not_a_task_that_sends_nothing() -> None:
    """Nowhere to carry the vector is a stated outcome, not an inert task.

    Measured: ``_test_ssti`` and every sibling iterate ``page.input_params``, so
    against a parameter-less root they issue zero requests and return. Queuing
    that task would report a class as tested on an endpoint it never probed.
    """
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache Solr", version="8.0.0", port=80)),
        _scan("http://10.0.0.1/", params=[]),
    )
    assert plan.tasks == []
    leads = agent._unproven_exploit_leads
    assert leads and all(x.why_unconfirmed == LEAD_VECTOR_NOT_CARRIED for x in leads)
    assert "no parameterised surface" in leads[0].missing_observation


def test_an_unconfirmable_cve_becomes_a_lead_and_never_a_task() -> None:
    """The honesty half: no oracle ⇒ no claim, and the lead says which."""
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="lodash", version="4.17.4")),
        _scan("http://10.0.0.1/"),
    )
    assert plan.tasks == [], "a CVE we cannot confirm must never plan a task"
    # lodash 4.17.4 genuinely sits inside two published ranges (<4.17.21 and
    # <4.17.5). Both are real; both get their own lead.
    claims = {lead.claim for lead in agent._unproven_exploit_leads}
    assert {"CVE-2021-23337", "CVE-2018-3721"} <= {c.split(" ")[0] for c in claims}
    for lead in agent._unproven_exploit_leads:
        assert lead.why_unconfirmed == "version_match_only_no_oracle_for_this_cve"
        assert "4.17.4" in lead.raw_observation
        assert "no oracle" in lead.missing_observation.lower()


def test_a_version_match_alone_never_produces_a_finding() -> None:
    """The whole rule, stated as one assertion over the whole seam."""
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(
            DetectedComponent(name="Apache", version="2.4.49", port=80),
            DetectedComponent(name="lodash", version="4.17.4"),
            DetectedComponent(name="jquery", version="3.3.1"),
        ),
        _scan("http://10.0.0.1/"),
    )
    assert all(isinstance(t, ExploitTask) for t in plan.tasks)
    assert all(
        lead.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED for lead in agent._unproven_exploit_leads
    )
    # Nothing on this seam constructs a Finding at all.
    assert not any(isinstance(x, Finding) for x in plan.tasks)


def test_an_empty_inventory_leaves_the_plan_untouched() -> None:
    agent = _agent()
    original = _plan(ExploitTask(test_method="_test_sqli", endpoint_url="http://10.0.0.1/", tier=1))
    scan = _scan("http://10.0.0.1/")
    assert agent._merge_component_cve_tasks(original, _recon(), scan) is original
    assert agent._merge_component_cve_tasks(original, None, scan) is original


def test_no_discovered_surface_becomes_a_lead_not_a_guessed_url() -> None:
    """With nowhere to point the methodology, we say so rather than invent a URL."""
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache Solr", version="8.0.0", port=80)),
        _scan(),
    )
    assert plan.tasks == []
    leads = agent._unproven_exploit_leads
    assert leads, "an unpointable match must still be reported"
    assert all(x.why_unconfirmed == LEAD_VECTOR_NOT_CARRIED for x in leads)
    assert "no parameterised surface" in leads[0].missing_observation


# ---------------------------------------------------------------------------
# After execution: "we tested and saw nothing" ≠ "we never looked"
# ---------------------------------------------------------------------------


def test_an_oracle_that_ran_and_saw_nothing_says_exactly_that() -> None:
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache Solr", version="8.0.0", port=80)),
        _scan("http://10.0.0.1/app"),
    )
    assert agent._component_cve_pending, "the queued match must be remembered"

    agent._record_unconfirmed_component_cves([])  # the methodology confirmed nothing

    # Both Solr rows queued, so both report back — a queued match that goes
    # quiet is the outcome this lead exists to make visible.
    assert len(agent._unproven_exploit_leads) == 2
    for lead in agent._unproven_exploit_leads:
        assert lead.why_unconfirmed == "version_match_oracle_ran_and_did_not_confirm"
        assert "RAN" in lead.missing_observation
        assert "version match stands; the exploitation does not" in lead.missing_observation


def test_a_confirmed_finding_leaves_the_cve_as_context_with_no_lead() -> None:
    """A finding on that endpoint means the CVE rode along on a proven result."""
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache Solr", version="8.0.0", port=80)),
        _scan("http://10.0.0.1/app"),
    )
    agent._record_unconfirmed_component_cves(
        [
            Finding(
                title="Server-side template injection",
                description="",
                severity=Severity.HIGH,
                target="http://10.0.0.1/app",
                evidence=["Request: ...", "Response: 49"],
            )
        ]
    )
    assert agent._unproven_exploit_leads == []


@pytest.mark.parametrize(
    "why",
    ["version_match_only_no_oracle_for_this_cve", "version_match_oracle_ran_and_did_not_confirm"],
)
def test_both_reasons_are_in_the_closed_vocabulary(why: str) -> None:
    """A free-text reason drifts into a justification, and a justification reads
    like a finding."""
    assert why in UNPROVEN_WHY_UNCONFIRMED


def test_a_malformed_catalogue_entry_cannot_break_a_run() -> None:
    """The target's banner is attacker-influenced; a bad regex must not raise."""
    bad = (
        KnownComponentCVE(
            cve_id="CVE-0000-0000",
            component=r"([unclosed",
            affected="*",
            title="malformed",
            proving_observation="n/a",
        ),
    )
    assert match_components([DetectedComponent(name="anything", version="1.0")], bad) == []


def _unused(*_: Any) -> None:  # pragma: no cover - keeps ``Any`` import honest
    return None


# ---------------------------------------------------------------------------
# The alarm blind spot: registration must not be gated by what it observes
# ---------------------------------------------------------------------------


class TestTheSeamIsObservableWhenItContributesNothing:
    """``record_contribution`` sat BELOW ``if not components: return plan``.

    An empty inventory took the early return, so the ledger was never told this
    component exists and the starved seam reached none of the four alarm
    classes: not SILENT (that needs a recorded invocation), not DEAD_SEAM, not
    ALL_FAILED, and not declared-but-never-invoked — nothing declares it, and
    ``declare_component`` is called in exactly one place in the whole engine,
    for LLM providers.

    The inventory was empty on every engagement ever run, because the
    orchestrator handed Exploit the recon phase envelope. So the alarm built to
    catch a component contributing nothing was, for this component, structurally
    incapable of reporting the one thing that was wrong with it.
    """

    @staticmethod
    def _record(recon: Any) -> ContributionLedger:
        agent = _agent()
        agent._logger = logging.getLogger("test.cve.ledger")
        ledger = ContributionLedger(engagement_id="ledger-test")
        set_active_ledger(ledger)
        try:
            agent._merge_component_cve_tasks(_plan(), recon, None)
        finally:
            set_active_ledger(None)
        return ledger

    def test_an_empty_inventory_still_registers_the_component(self) -> None:
        ledger = self._record(None)
        names = {rec.name for rec in ledger.records()}
        assert "exploit.component_cve_match" in names, (
            "a starved seam that never registers is unobservable by construction — "
            f"the ledger only knows about {sorted(names)}"
        )

    def test_an_empty_inventory_is_correctly_empty_with_a_stated_reason(self) -> None:
        """Recon named nothing, so there was nothing of this component's kind to read.

        That is the NOT-APPLICABLE fact, not an alarm: reported as a defect it
        would fire on every target with no fingerprintable banner, and a
        permanent false alarm trains an operator to skim the section a real one
        appears in.
        """
        ledger = self._record(None)
        rec = next(r for r in ledger.records() if r.name == "exploit.component_cve_match")
        assert rec.invocations == 1
        assert rec.items_contributed == 0
        assert rec.not_applicable == 1, "the zero must carry the reason it is a zero"
        assert rec.correctly_empty
        assert rec.alarms == []

    def test_an_inventory_that_matched_nothing_stays_an_ordinary_zero(self) -> None:
        """Components were READ. That is a different sentence, and it stays loud.

        A fully-patched stack and a component-name parser that mangles every
        name both produce zero matches here, and only one of them is fine. No
        reason string can tell them apart, so this zero is not talked away — it
        is the ffuf shape at the granularity of this seam.
        """
        ledger = self._record(
            {"components": [DetectedComponent(name="nginx", version="1.99.0").model_dump()]}
        )
        rec = next(r for r in ledger.records() if r.name == "exploit.component_cve_match")
        assert rec.invocations == 1
        assert rec.items_contributed == 0
        assert rec.not_applicable == 0
        assert rec.alarms == [LedgerAlarm.SILENT]
        assert any("1 component(s) inventoried" in n for n in rec.notes)
