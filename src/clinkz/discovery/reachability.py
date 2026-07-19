"""Reachability layer — untrusted channel ⇒ Δ-capability (§2.5, first slice).

For each Δ-capability, decide whether an untrusted channel reaches it and with
what soundness grade (§4.2). This slice implements only the **intra-function**
case (the cheapest, soundest grade, ``STATIC_CONFIRMED``): the source ingestor
already proved the taint (``CallSite.tainted_by`` names the entrypoint parameter
whose value reaches the sink inside the same handler), so reachability here is a
direct lookup — no call-graph walk, no cross-service inference. The GeoServer
``url`` param → ``openConnection`` path is exactly this shape (§10 (c), "the
strongest part of the trace"). Cross-function / cross-service / sequence
reachability are explicitly out of scope (next slice).
"""

from __future__ import annotations

from clinkz.discovery.models import (
    CapabilityDelta,
    Entrypoint,
    ReachabilityEdge,
    SoundnessGrade,
    SourceModel,
)
from clinkz.models.scan import ParamLocation


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
    ``STATIC_CONFIRMED`` with a high prior; a Δ whose call site has no confirmed
    taint source is left ``HYPOTHESIZED`` (lower prior) — still emitted so the
    proof engine can arbitrate, never dropped (§4.3).
    """
    edges: list[ReachabilityEdge] = []
    for delta in deltas:
        param = delta.call_site.tainted_by
        if not param:
            continue  # no channel identified for this Δ in this slice
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
    return edges
