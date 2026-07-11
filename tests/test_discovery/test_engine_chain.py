"""Keyless unit gate for capability → intent → reachability → hypothesis (slice 1).

Drives the whole deterministic discovery chain over the real GeoServer
``TestWfsPost.java`` fixture and asserts it produces the SSRF hypothesis the
walkthrough (§10) predicts — most importantly that **Intent does not collapse Δ**
by mis-scoring the bypassable host guard as a real guard (§10 gap #2 / OQ #7), and
that the hypothesis carries the Host-alignment carrier constraint (§10 gap #3).

The second half proves the adjudication the other way: a genuinely-constraining
guard yields *no* Δ (SANCTIONED), so the exposure verdict is a real decision, not
a rubber stamp.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery import (
    CARRIER_ALIGN_HOST,
    DiscoveryEngine,
    compute_delta,
    match_primitives,
)
from clinkz.discovery.models import (
    CallSite,
    DeltaGrade,
    Guard,
    ParamLocation,
    PrimitiveClass,
    SoundnessGrade,
    SourceModel,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "geoserver_TestWfsPost.java"
BASE_URL = "http://localhost:8080/geoserver"


@pytest.fixture(scope="module")
def result():
    return DiscoveryEngine().discover(str(FIXTURE), ["Java", "GeoServer"], BASE_URL)


def test_active_primitive_is_egress_fetch(result):
    ids = {p.id for p in result.active_primitives}
    assert "egress_fetch.java_openconnection" in ids
    prim = result.active_primitives[0]
    assert prim.primitive_class == PrimitiveClass.EGRESS_FETCH
    assert prim.proof_obligation.test_method == "_test_ssrf"
    assert {"P3", "P1"}.issubset(set(prim.proof_obligation.confirmation_primitives))


def test_intent_keeps_delta_exposed_bypassable_guard(result):
    """The crux: Intent must NOT score the url-host-vs-Host-header check as real."""
    assert len(result.deltas) == 1
    delta = result.deltas[0]
    assert delta.delta_grade == DeltaGrade.EXPOSED
    assert delta.delta_confidence >= 0.85
    assert delta.gated_by is None  # ProxyBaseUrl unset by default ⇒ stays in Δ
    ev = delta.intent_evidence.lower()
    assert "attacker-controlled" in ev
    assert "proxybaseurl" in ev


def test_reachability_intra_function_static_confirmed(result):
    assert len(result.edges) == 1
    edge = result.edges[0]
    assert edge.channel_param == "url"
    assert edge.soundness_grade == SoundnessGrade.STATIC_CONFIRMED
    assert edge.channel_location == ParamLocation.FORM_BODY  # POST servlet body
    assert edge.reach_confidence >= 0.85


def test_hypothesis_binds_test_ssrf_with_host_carrier(result):
    assert len(result.hypotheses) == 1
    hyp = result.hypotheses[0]
    assert hyp.target_url == "http://localhost:8080/geoserver/TestWfsPost"
    assert hyp.obligation.test_method == "_test_ssrf"
    # The per-instance carrier constraint the concrete guard surfaced (gap #3).
    assert CARRIER_ALIGN_HOST in hyp.obligation.carrier_constraints
    assert hyp.rank_score > 0.7


def test_hypothesis_lowers_to_tier_a_exploit_task(result):
    task = result.hypotheses[0].to_exploit_task()
    assert task.test_method == "_test_ssrf"
    assert task.endpoint_url == "http://localhost:8080/geoserver/TestWfsPost"
    assert task.endpoint_method == "POST"
    assert task.endpoint_params == ["url"]
    assert task.param_locations == {"url": ParamLocation.FORM_BODY}
    assert CARRIER_ALIGN_HOST in task.carrier_constraints
    assert task.tier == 1


def test_real_guard_yields_no_delta():
    """Adjudication the other way: a guard that fixes an operand is SANCTIONED.

    A host check against a config-fixed value (not attacker-controlled) is a real
    guard, so the capability is not exposed and produces no Δ — proving the
    EXPOSED verdict above is a decision, not a rubber stamp.
    """
    call_site = CallSite(
        primitive_class=PrimitiveClass.EGRESS_FETCH,
        symbol="openConnection",
        tainted_by="url",
        guard_symbol="validateURL",
    )
    real_guard = Guard(
        symbol="validateURL",
        kind="host_match",
        operands=["url.getHost()", "allowlistHost"],
        attacker_controlled_operands=[],  # only one operand attacker-controlled ⇒ real
        gating_config=None,
        bypassable_by_default=False,
    )
    model = SourceModel(call_sites=[call_site], guards=[real_guard])
    primitives = [
        p for p in DiscoveryEngine().discover(str(FIXTURE), ["Java"], BASE_URL).active_primitives
    ]
    deltas = compute_delta(model, primitives)
    assert deltas == []


def test_match_primitives_na_without_egress_source():
    """No EGRESS_FETCH call site in source ⇒ the primitive is not active (N/A)."""
    empty = SourceModel()
    assert match_primitives(empty, ["Java"]) == []
