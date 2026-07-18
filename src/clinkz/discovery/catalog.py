"""Capability catalog (seeded) — the transfer key (§3).

The general Capability Agent (re-scoped Research, CVE/CWE/source ingestion to grow
a cross-engagement catalog) is out of scope. Here we **seed primitives** — each
payload-free and technology-invariant, so the same catalog entry transfers to any
Java target with the matching sink shape (the point of primitive-not-payload,
§3.1). Each ``proof_obligation`` reduces to confirmation primitives Clinkz already
has (P3 content-we-never-sent / P1 differential), so a hypothesis built from a
primitive inherits zero-FP by construction (§6.1).

Two capability classes are catalogued, and the catalog is **class-generic**: the
matcher, intent, reachability, hypothesis and proof-reduction layers are keyed on
:class:`PrimitiveClass`, never on any one class. Adding the second class was a
single catalog entry (this file) + the class-specific *source idiom* (the file-read
sink) and *carrier* (path-segment traversal) — the abstraction extends, it does not
fork per class:

* ``EGRESS_FETCH`` — a Java ``URL.openConnection()`` server-side fetch → SSRF,
  proven by ``_test_ssrf`` (GeoServer CVE-2021-40822; Solr RemoteStreaming).
* ``FILE_READ`` — a request-tainted path into a ``java.io.File`` / ``Files`` /
  ``FileInputStream`` read sink with no basename-strip/canonicalize guard →
  arbitrary file read, proven by ``_test_lfi`` (Flink CVE-2020-17519). The proof
  reduces to the **same** P3 file-content oracle the black-box LFI methodology
  already uses — zero new proof code.
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

# The second capability class — the first multi-class test of the catalog
# abstraction. Same schema, different sink shape: a request-tainted path reaching
# a filesystem-read sink (``new File(dir, name)`` / ``Files.read*`` /
# ``new FileInputStream``) with no basename-strip/canonicalize guard. Deliberately
# free of any Flink-, route-, or payload-specificity — the generic path-traversal
# file-read capability the existing ``_test_lfi`` methodology confirms. Its
# obligation reduces to the built P3 file-content oracle (an /etc/passwd signature
# reflected in-band — content the payload never carried), so the hypothesis is
# zero-FP by construction. The Host-alignment carrier is EGRESS-specific; FILE_READ
# instead carries the path-segment-traversal constraint, attached per-instance by
# the Hypothesis layer when the reaching channel is a URL path parameter (§10 gap
# #3 — the encoding of the traversal is discoverable only from the concrete channel
# location, exactly like the Host carrier is discoverable only from the guard).
FILE_READ_JAVA_FILE_SINK = CapabilityPrimitive(
    id="file_read.java_file_sink",
    technology_pattern=r"(?i)\bjava\b|servlet",
    name="java-tainted-path-file-read",
    primitive_class=PrimitiveClass.FILE_READ,
    trigger_shape=(
        "a request-derived path (query/form/path parameter) becomes the name of a "
        "java.io.File / Files.read* / FileInputStream read whose bytes may return "
        "in-band, with no basename-strip (.getName()) or canonicalization guard"
    ),
    input_carriers=["path", "query", "body_field"],
    effect_class="filesystem_read",
    proof_obligation=ProofObligation(
        test_method="_test_lfi",
        # Reduces to the SAME built P3 file-content oracle the black-box LFI
        # methodology uses — content the payload never contained (§6.1). Zero new
        # proof code: the hypothesis rides the existing ``_test_lfi`` plan-union.
        confirmation_primitives=["P3"],
        # Base obligation carries no carrier constraint; the Hypothesis layer adds
        # the path-segment-traversal carrier per-instance when the reaching channel
        # is a URL path parameter (the encoding is a property of the concrete
        # channel, not the primitive).
        carrier_constraints=[],
        description=(
            "in-band arbitrary file read: confirm by an /etc/passwd (or other "
            "well-known file) content signature reflected in the response — content "
            "the traversal payload never carried (P3)"
        ),
    ),
    gating_config=None,
    cwe_refs=["CWE-22", "CWE-98"],
    provenance=["framework-source: new File(dir, pathParam) sink", "CVE-2020-17519"],
    evidence_grade="bootstrapped-from-source",
)

CATALOG: list[CapabilityPrimitive] = [
    EGRESS_FETCH_JAVA_OPENCONNECTION,
    FILE_READ_JAVA_FILE_SINK,
]


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
