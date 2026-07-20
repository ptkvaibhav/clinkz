"""Discovery-engine constants shared with the proof engine.

Deliberately a **leaf module** (no intra-package imports) so
``agents/exploit.py`` can import the carrier-constraint identifier without
pulling in the whole discovery package — keeping the proof engine free of any
discovery import cycle.
"""

from __future__ import annotations

# Per-instance carrier constraint an SSRF proof obligation may carry, telling the
# probe to rewrite the request ``Host`` header to the host of the injected ``url``
# value. Required by targets whose fetch guard compares the ``url`` host to the
# request ``Host`` header (GeoServer TestWfsPost / CVE-2021-40822): both are
# attacker-controlled, so aligning them satisfies a bypassable guard. Opt-in
# (empty ``carrier_constraints`` ⇒ unchanged behaviour) so it never fires where a
# host rewrite would break routing.
CARRIER_ALIGN_HOST: str = "align_host_with_injected_url_host"

# Manifest-derived capability token the source ingestor emits into
# ``SourceModel.technologies`` when a vulnerable ``log4j-core`` (< 2.15.0, JNDI
# message-lookups un-gated) is declared in a build manifest / shipped jar. The
# LOG_INTERPOLATION catalog primitive's ``technology_pattern`` matches this token,
# so a patched target (≥ 2.15, or JndiLookup removed) never emits it ⇒ the Log4Shell
# primitive is not active ⇒ N/A by construction (design §P6.5.2 version-gating). The
# specific version is learned from the manifest; only the derived verdict is a token.
LOG4J_VULNERABLE_TOKEN: str = "log4j-jndi-lookup-exposed"

# Per-instance carrier constraint a FILE_READ (path-traversal) proof obligation
# carries when its channel is a URL *path* parameter (the whole ``:filename``
# segment is attacker-controlled). It tells the probe carrier to inject the
# traversal payload into the path segment **verbatim** — the generic path carrier
# ``quote(safe="")``-re-encodes the value (so an already-encoded ``..%252f`` token
# becomes ``..%25252f`` and the traversal is defeated) — and to normalise every
# literal ``/`` left in the payload (the target's ``etc/passwd`` separators) to the
# payload's own encoded-slash token so the whole payload stays ONE opaque path
# segment routed to the file handler (Apache Flink CVE-2020-17519 routes a literal
# ``/`` to a different handler). Opt-in, so IDOR's encoded ``:id`` value carrier
# and every query/form probe are byte-for-byte unchanged.
CARRIER_PATH_TRAVERSAL: str = "carry_path_segment_traversal_raw"
