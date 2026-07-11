"""Capability catalog (seeded) — the transfer key (§3, first vertical slice).

The general Capability Agent (re-scoped Research, CVE/CWE/source ingestion to grow
a cross-engagement catalog) is out of scope for this slice. Here we **seed one
primitive** — a Java ``openConnection`` server-side fetch — payload-free and
technology-invariant, so the same catalog entry would transfer to any Java target
with an HTTP-fetch sink (the point of primitive-not-payload, §3.1). Its
``proof_obligation`` reduces to confirmation primitives Clinkz already has
(P3 content-we-never-sent / P1 differential), so a hypothesis built from it
inherits zero-FP by construction (§6.1).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from clinkz.discovery.models import (
    CapabilityPrimitive,
    PrimitiveClass,
    ProofObligation,
    SourceModel,
)

# The single seeded primitive for this slice. Note the deliberate absence of any
# GeoServer-, endpoint-, or payload-specificity: this is the generic SSRF-egress
# capability that already underpins the existing ``_test_ssrf`` methodology.
EGRESS_FETCH_JAVA_OPENCONNECTION = CapabilityPrimitive(
    id="egress_fetch.java_openconnection",
    technology_pattern=r"(?i)\bjava\b|servlet",
    name="java-http-fetch-openconnection",
    primitive_class=PrimitiveClass.EGRESS_FETCH,
    trigger_shape=(
        "a request-derived string becomes the target of a server-side "
        "java.net.URL.openConnection() fetch whose response may return in-band"
    ),
    input_carriers=["query", "body_field", "path", "header"],
    effect_class="outbound_network",
    proof_obligation=ProofObligation(
        test_method="_test_ssrf",
        # Reduces to built confirmation primitives — the zero-FP boundary (§6.1).
        confirmation_primitives=["P3", "P1"],
        # Base obligation carries no carrier constraint; the Hypothesis layer adds
        # the Host-alignment constraint per-instance when the reaching guard is a
        # host-match guard (§10 gap #3 — discoverable only from the concrete guard).
        carrier_constraints=[],
        description=(
            "in-band SSRF: confirm by reflecting internal-only content the payload "
            "never contained (P3) or an open-vs-closed reachability differential (P1)"
        ),
    ),
    gating_config="ProxyBaseUrl",
    cwe_refs=["CWE-918"],
    provenance=["framework-source: URL.openConnection sink", "CVE-2021-40822"],
    evidence_grade="bootstrapped-from-source",
)

CATALOG: list[CapabilityPrimitive] = [EGRESS_FETCH_JAVA_OPENCONNECTION]


def match_primitives(
    source_model: SourceModel, fingerprint: Iterable[str]
) -> list[CapabilityPrimitive]:
    """Active primitive set: catalogued primitives whose class is present in the
    ingested source AND whose ``technology_pattern`` matches the stack (§2.3).

    This is the raw ``Capability(tech)`` term the Intent layer subtracts from —
    the catalog primitives that actually apply to the fingerprinted target.
    """
    present_classes = {c.primitive_class for c in source_model.call_sites}
    tech_blob = " ".join([*fingerprint, *source_model.technologies])
    active: list[CapabilityPrimitive] = []
    for primitive in CATALOG:
        if primitive.primitive_class not in present_classes:
            continue
        if re.search(primitive.technology_pattern, tech_blob):
            active.append(primitive)
    return active


def primitive_by_class(
    primitives: Iterable[CapabilityPrimitive], primitive_class: PrimitiveClass
) -> CapabilityPrimitive | None:
    """First active primitive of *primitive_class*, or ``None``."""
    return next((p for p in primitives if p.primitive_class == primitive_class), None)
