"""Capability catalog (seeded) — the transfer key (§3).

The general Capability Agent (re-scoped Research, CVE/CWE/source ingestion to grow
a cross-engagement catalog) is out of scope. Here we **seed primitives** — each
payload-free and technology-invariant, so the same catalog entry transfers to any
target with the matching sink shape (the point of primitive-not-payload, §3.1). The
class-agnostic ``EGRESS_FETCH`` / ``FILE_READ`` primitives are also *language*-agnostic
(discovery slice A1): their ``technology_pattern`` matches Node/JS as well as Java, so a
JS sink shape the ``JsSourceIngestor`` surfaces activates the same primitive as its Java
twin. Each ``proof_obligation`` reduces to confirmation primitives Clinkz already has
(P3 content-we-never-sent / P1 differential), so a hypothesis built from a primitive
inherits zero-FP by construction (§6.1).

Three capability classes are catalogued, and the catalog is **class-generic**: the
matcher, intent, reachability, hypothesis and proof-reduction layers are keyed on
:class:`PrimitiveClass`, never on any one class. Each new class was a single catalog
entry (this file) + its class-specific *source idiom* and (where the channel needs
one) a *carrier* — the abstraction extends, it does not fork per class:

* ``EGRESS_FETCH`` — a Java ``URL.openConnection()`` server-side fetch → SSRF,
  proven by ``_test_ssrf`` (GeoServer CVE-2021-40822; Solr RemoteStreaming).
* ``FILE_READ`` — a request-tainted path into a ``java.io.File`` / ``Files`` /
  ``FileInputStream`` read sink with no basename-strip/canonicalize guard →
  arbitrary file read, proven by ``_test_lfi`` (Flink CVE-2020-17519). The proof
  reduces to the **same** P3 file-content oracle the black-box LFI methodology
  already uses — zero new proof code.
* ``LOG_INTERPOLATION`` — a request-derived string reaching an SLF4J/Log4j logging
  call whose vulnerable ``log4j-core`` interpolates a ``${jndi:…}`` message lookup
  → blind egress (Log4Shell, CVE-2021-44228), proven by ``_test_log4shell``. The
  flagship, and the first class whose proof reduces to the **out-of-band** primitive
  (P6) — a JNDI/DNS callback bearing a fresh nonce — rather than an in-band oracle;
  it also brings the first **heuristic, cross-function** reachability and a
  **manifest-version-gated** capability. Zero new proof code: it rides the same P6
  mint→build→send→reap→ConfirmationEvidence machinery the blind-SSRF path uses.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from clinkz.discovery.constants import LOG4J_VULNERABLE_TOKEN
from clinkz.discovery.models import (
    CapabilityPrimitive,
    PrimitiveClass,
    ProofObligation,
    SourceModel,
)

# Language-generalized stack match for the class-agnostic EGRESS_FETCH (SSRF) and
# FILE_READ (path-traversal) primitives — discovery slice A1. These two capabilities
# are language-AGNOSTIC: the sink shape differs per language (Java
# ``URL.openConnection`` / JS ``axios.get``; Java ``new File`` / JS ``fs.readFile``)
# but the capability, its Δ-adjudication, its reachability and its proof oracle are the
# same, and each ingestor surfaces the sink as the *same* ``PrimitiveClass``. The
# original Java-only gate (``\bjava\b|servlet``) wrongly made these primitives N/A on a
# Node/Express target that genuinely has them, so the match is widened to the JS/TS
# stack. This is the ONE Layer-1 touch slice A1 makes: it adds no PrimitiveClass,
# oracle or proof — it only lets an EXISTING primitive apply to a new language.
# ``LOG_INTERPOLATION`` is deliberately NOT widened — Log4Shell is a Java/log4j-core
# property, manifest-version-gated, and a JS log-injection would be a different class.
_MULTILANG_FETCH_FILE_TECH = (
    r"(?i)\bjava\b|servlet|\bnode\b|node\.?js|express|javascript|typescript"
)

# The single seeded primitive for this slice. Note the deliberate absence of any
# GeoServer-, endpoint-, or payload-specificity: this is the generic SSRF-egress
# capability that already underpins the existing ``_test_ssrf`` methodology.
EGRESS_FETCH_JAVA_OPENCONNECTION = CapabilityPrimitive(
    id="egress_fetch.java_openconnection",
    technology_pattern=_MULTILANG_FETCH_FILE_TECH,
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
    technology_pattern=_MULTILANG_FETCH_FILE_TECH,
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

# The third capability class — the flagship, and the first class whose proof
# reduces to the out-of-band primitive (P6) rather than an in-band oracle. Same
# schema, a fundamentally different sink shape: a request-derived string reaches a
# **logging call** whose library (vulnerable ``log4j-core``) interpolates
# ``${jndi:…}`` message lookups into an outbound egress (Log4Shell, CVE-2021-44228).
# Deliberately free of any Solr-, route- or payload-specificity — the generic
# log-sink egress capability. Three things make this class distinct from EGRESS_FETCH,
# and all three are why it is its own class, not an EGRESS_FETCH variant:
#
#   * **Manifest-derived, version-gated.** The capability is present only when a
#     vulnerable ``log4j-core`` (< 2.15) is declared in a build manifest / shipped
#     jar; the ingestor emits ``LOG4J_VULNERABLE_TOKEN`` in that case, and this
#     ``technology_pattern`` matches it. A patched target (≥ 2.15 / JndiLookup
#     removed) emits no token ⇒ not active ⇒ N/A by construction (design §P6.5.2).
#   * **Heuristic, cross-function reachability.** The channel→sink path is NOT
#     intra-function (``action`` flows request→dispatch→a deep logging call); the
#     reachability layer grades it ``STATIC_HEURISTIC`` — a loose prior ("a request
#     param plausibly reaches a logging call"), and P6 is the precise confirmation
#     (reachability-as-prior, §4.3).
#   * **Out-of-band proof (P6), no in-band signal.** There is no reflected content,
#     so the obligation reduces to P6 or NOTHING (§8.1): a JNDI/DNS callback bearing
#     a fresh nonce reaches the Clinkz collaborator ⇒ zero-FP by construction. The
#     JNDI payload is a CLINKZ-OWNED, nonce-only template (the §P6.7.4 exfil
#     guardrail holds — no target data in the lookup). Zero new proof code: the
#     hypothesis rides the same P6 mint→build→send→reap→ConfirmationEvidence
#     machinery the blind-SSRF path already uses, via ``_test_log4shell``.
LOG4J_INTERPOLATION_JNDI = CapabilityPrimitive(
    id="log_interpolation.log4j_jndi",
    # Gated on the manifest-derived vulnerable-log4j verdict, NOT a bare "java"
    # match — so a Java target on a patched log4j never activates this primitive.
    technology_pattern=rf"(?i){re.escape(LOG4J_VULNERABLE_TOKEN)}",
    name="log4j-message-lookup-jndi-egress",
    primitive_class=PrimitiveClass.LOG_INTERPOLATION,
    trigger_shape=(
        "a request-derived string reaches an SLF4J/Log4j logging call "
        "(logger.info/warn/error/…) whose vulnerable log4j-core interpolates a "
        "${jndi:…} message lookup, performing an outbound JNDI/LDAP/DNS fetch"
    ),
    input_carriers=["query", "body_field", "path", "header"],
    effect_class="outbound_network",
    proof_obligation=ProofObligation(
        test_method="_test_log4shell",
        # Reduces to the built out-of-band primitive (P6) ONLY — there is no in-band
        # signal, so it is P6 or nothing (§8.1). Zero new proof code.
        confirmation_primitives=["P6"],
        # No per-instance carrier: the JNDI string rides as the param VALUE via the
        # shared string carrier (like SSRF), so no Host / path-segment carrier.
        carrier_constraints=[],
        description=(
            "blind egress via a log sink: confirm by a JNDI/DNS callback bearing a "
            "fresh single-use nonce reaching the Clinkz collaborator (P6) — the "
            "target executed the interpolated lookup; unforgeable ⇒ zero-FP"
        ),
    ),
    # Setting this config disables the lookup egress (subtracts from Δ): the 2.14.1
    # default leaves it unset ⇒ EXPOSED. Version ≥ 2.16 / JndiLookup removal is
    # handled upstream by the manifest gate (no token ⇒ primitive not active).
    gating_config="log4j2.formatMsgNoLookups",
    cwe_refs=["CWE-917", "CWE-502"],
    provenance=["framework-source: log4j-core JndiLookup/StrSubstitutor", "CVE-2021-44228"],
    evidence_grade="bootstrapped-from-source",
)

CATALOG: list[CapabilityPrimitive] = [
    EGRESS_FETCH_JAVA_OPENCONNECTION,
    FILE_READ_JAVA_FILE_SINK,
    LOG4J_INTERPOLATION_JNDI,
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
