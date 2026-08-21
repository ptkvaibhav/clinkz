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
from clinkz.knowledge.component_cves import (
    KNOWN_COMPONENT_CVES,
    KnownComponentCVE,
    match_components,
)
from clinkz.models.finding import (
    UNPROVEN_WHY_UNCONFIRMED,
    ExploitPlan,
    ExploitTask,
    Finding,
    Severity,
)
from clinkz.models.recon import DetectedComponent, ReconResult, dedupe_components
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


def _scan(*urls: str) -> ScanResult:
    """A ScanResult with real endpoints, reached the way the agent reaches them.

    Endpoints live under ``service_scans[].result.endpoints``, not on
    ``ScanResult`` itself — building the real nesting keeps this test honest
    about the shape the production code actually walks.
    """
    return ScanResult(
        target="10.0.0.1",
        service_scans=[
            ServiceScanResult(
                port=80,
                service_type="http",
                result=HTTPScanResult(
                    base_url="http://10.0.0.1/",
                    endpoints=[Endpoint(url=u) for u in urls],
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


def test_every_catalogue_entry_states_its_proving_observation() -> None:
    """A lead that cannot say what would prove it is not an actionable lead."""
    for entry in KNOWN_COMPONENT_CVES:
        assert entry.proving_observation.strip(), f"{entry.cve_id} has no proving_observation"
        assert entry.cve_id.startswith("CVE-")


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
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    plan = agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache httpd", version="2.4.49", port=80)),
        _scan("http://10.0.0.1/", "http://10.0.0.1/deep/page"),
    )
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.test_method == "_test_lfi", "the CVE's effect is a file read — use that oracle"
    assert task.endpoint_url == "http://10.0.0.1/", "a server-level defect targets the ORIGIN"
    assert "CVE-2021-41773" in task.technique_name
    assert not agent._unproven_exploit_leads, "a queued task is not also a lead"


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
        _recon(DetectedComponent(name="Apache", version="2.4.49", port=80)),
        _scan(),
    )
    assert plan.tasks == []
    assert len(agent._unproven_exploit_leads) == 1
    assert "no surface" in agent._unproven_exploit_leads[0].missing_observation.lower()


# ---------------------------------------------------------------------------
# After execution: "we tested and saw nothing" ≠ "we never looked"
# ---------------------------------------------------------------------------


def test_an_oracle_that_ran_and_saw_nothing_says_exactly_that() -> None:
    agent = _agent()
    agent._max_plan_task_cap = lambda: 50  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
    agent._merge_component_cve_tasks(
        _plan(),
        _recon(DetectedComponent(name="Apache", version="2.4.49", port=80)),
        _scan("http://10.0.0.1/"),
    )
    assert agent._component_cve_pending, "the queued match must be remembered"

    agent._record_unconfirmed_component_cves([])  # the methodology confirmed nothing

    assert len(agent._unproven_exploit_leads) == 1
    lead = agent._unproven_exploit_leads[0]
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
        _recon(DetectedComponent(name="Apache", version="2.4.49", port=80)),
        _scan("http://10.0.0.1/"),
    )
    agent._record_unconfirmed_component_cves(
        [
            Finding(
                title="Local File Inclusion in path",
                description="",
                severity=Severity.HIGH,
                target="http://10.0.0.1/",
                evidence=["Request: ...", "Response: root:x:0:0:"],
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
