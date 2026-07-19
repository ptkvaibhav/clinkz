"""Reachability layer — untrusted channel ⇒ Δ-capability (§2.5).

For each Δ-capability, decide whether an untrusted channel reaches it and with
what soundness grade (§4.2). Two grades are produced:

* **``STATIC_CONFIRMED`` (intra-function)** — the source ingestor already proved
  the taint (``CallSite.tainted_by`` names the entrypoint parameter whose value
  reaches the sink inside the same handler), so reachability is a direct lookup:
  no call-graph walk, high prior. The GeoServer ``url`` → ``openConnection`` and
  Flink ``filename`` → ``new File`` paths are exactly this shape.
* **``STATIC_HEURISTIC`` (cross-function, the log-sink channel)** — the Log4Shell
  class (design §P6.5.3): the channel→sink path is NOT intra-function (``action``
  flows request → core-admin dispatch → a logging call deep in the tree, and the
  interpolation happens inside log4j-core). log4j interpolates *any* logged string,
  so the honest prior is loose — "an untrusted request param plausibly reaches a
  logging call" — and P6 (the callback) is the precise confirmation
  (reachability-as-prior, §4.3: the prior ranks, P6 proves). This is the first
  heuristic / cross-function reachability; it deliberately over-approximates, and
  the zero-FP OOB oracle downstream is what keeps that honest.

Cross-service / sequence reachability remain out of scope.
"""

from __future__ import annotations

from clinkz.discovery.models import (
    CapabilityDelta,
    Entrypoint,
    PrimitiveClass,
    ReachabilityEdge,
    SoundnessGrade,
    SourceModel,
)
from clinkz.models.scan import ParamLocation

# Cap on the number of untrusted channels wired to the log sink by the heuristic
# prior — a loose "any logged param" prior must stay bounded, and P6 proves which of
# the ranked candidates actually reach the logger (the rest defer, never false-emit).
_MAX_LOG_SINK_CHANNELS = 8
# Heuristic reachability prior — deliberately below the intra-function 0.9 so a
# log-sink hypothesis ranks under a confirmed-taint one; the callback is the proof.
_LOG_SINK_REACH_CONFIDENCE = 0.5


def _entrypoint_for_param(param: str, entrypoints: list[Entrypoint]) -> Entrypoint | None:
    """The entrypoint that reads *param* (the channel carrying the taint)."""
    return next((e for e in entrypoints if param in e.params), None)


def _channel_location(entrypoint: Entrypoint, param: str) -> ParamLocation:
    """Where the channel param rides: URL path segment, form body, or query.

    A typed path parameter (Flink's ``:filename``) rides in the URL *path* itself,
    so the probe is carried as a path segment — the file-read class's channel. A
    servlet's ``getParameter`` reads both query and form-body params, so for a POST
    entrypoint we carry the probe in the form body (the SSRF shape), else the query
    string.
    """
    if param in entrypoint.path_params:
        return ParamLocation.PATH
    if "POST" in {m.upper() for m in entrypoint.http_methods}:
        return ParamLocation.FORM_BODY
    return ParamLocation.QUERY


def compute_reachability(
    source_model: SourceModel, deltas: list[CapabilityDelta]
) -> list[ReachabilityEdge]:
    """Build reachability edges from Δ-capabilities to the channels that reach them.

    An intra-function taint the ingestor already confirmed is graded
    ``STATIC_CONFIRMED`` with a high prior. A ``LOG_INTERPOLATION`` Δ (Log4Shell)
    has no intra-function taint — the log sink logs a request-derived value reached
    across functions — so it is graded ``STATIC_HEURISTIC`` and wired to the
    untrusted entrypoint params by the loose prior "any logged param plausibly
    reaches the sink"; P6 proves which actually do (§4.3). A Δ whose call site has
    no channel at all is simply not edged — never dropped into a false claim.
    """
    edges: list[ReachabilityEdge] = []
    log_deltas: list[CapabilityDelta] = []
    for delta in deltas:
        if delta.call_site.primitive_class is PrimitiveClass.LOG_INTERPOLATION:
            log_deltas.append(delta)
            continue
        param = delta.call_site.tainted_by
        if not param:
            continue  # no channel identified for this Δ
        entrypoint = _entrypoint_for_param(param, source_model.entrypoints)
        if entrypoint is None:
            continue
        edges.append(
            ReachabilityEdge(
                channel_param=param,
                channel_location=_channel_location(entrypoint, param),
                primitive_id=delta.primitive_id,
                entrypoint_route=entrypoint.route,
                entrypoint_methods=entrypoint.http_methods,
                path_evidence=(
                    f"intra-function: request param {param!r} → "
                    f"{delta.call_site.symbol}() sink in {entrypoint.handler_symbol} "
                    f"({delta.call_site.file}:{delta.call_site.line})"
                ),
                soundness_grade=SoundnessGrade.STATIC_CONFIRMED,
                reach_confidence=0.9,
            )
        )
    edges.extend(_log_sink_edges(source_model, log_deltas))
    return edges


def _log_sink_edges(
    source_model: SourceModel, log_deltas: list[CapabilityDelta]
) -> list[ReachabilityEdge]:
    """Heuristic cross-function edges: untrusted params → a log sink (Log4Shell).

    log4j interpolates *any* logged string, so the channel is not a single proven
    param but "an untrusted request param the handler tree may log". We wire each
    untrusted entrypoint param (bounded, first-seen order so the CVE's canonical
    ``action`` leads) to a single representative log sink at ``STATIC_HEURISTIC``.
    Each edge is a ranked prior; the P6 callback confirms which params actually
    reach the logger (the rest defer as ``blind_unconfirmed`` — never false-emit).
    """
    if not log_deltas:
        return []
    # One representative sink per primitive (the prior is "the request reaches A
    # logger", not each individual call), preferring a coarse whole-request sink.
    sink = next(
        (
            d
            for d in log_deltas
            if d.call_site.tainted_by and d.call_site.tainted_by.startswith("*")
        ),
        log_deltas[0],
    )
    primitive_id = sink.primitive_id
    edges: list[ReachabilityEdge] = []
    seen: set[str] = set()
    for entrypoint in source_model.entrypoints:
        for param in entrypoint.params:
            if param in seen:
                continue
            seen.add(param)
            edges.append(
                ReachabilityEdge(
                    channel_param=param,
                    channel_location=_channel_location(entrypoint, param),
                    primitive_id=primitive_id,
                    entrypoint_route=entrypoint.route,
                    entrypoint_methods=entrypoint.http_methods,
                    path_evidence=(
                        f"heuristic cross-function: untrusted param {param!r} on "
                        f"{entrypoint.http_methods} {entrypoint.route or '/'} plausibly reaches "
                        f"log sink {sink.call_site.symbol}() "
                        f"({sink.call_site.file}:{sink.call_site.line}) — log4j interpolates any "
                        "logged string; the P6 callback is the precise confirmation"
                    ),
                    soundness_grade=SoundnessGrade.STATIC_HEURISTIC,
                    reach_confidence=_LOG_SINK_REACH_CONFIDENCE,
                )
            )
            if len(edges) >= _MAX_LOG_SINK_CHANNELS:
                return edges
    return edges
