"""Intent layer — computes Δ = Capability − Intent (§2.4, first vertical slice).

For each active capability primitive present in the source, decide whether the
call site is **sanctioned** (a real guard constrains it), **gated** (a config flag
disables it), or **exposed** (present, un-gated, no real guard). Δ is the exposed
set.

The load-bearing decision — and the sharpest failure risk in the whole GeoServer
walkthrough (§10 gap #2 / open-question #7) — is the guard adjudication: a naive
reader sees *a host check exists* and scores it a real guard, so Δ collapses and
the vuln is never hypothesised. The correct reading is that the default host check
compares **two attacker-controlled values** (the ``url`` host vs the request
``Host`` header) and is therefore **bypassable**; the real guard is gated on
``ProxyBaseUrl``, which is unset by default. This slice implements that as a
deterministic rule over the ingested :class:`Guard` facts; generalising the
adjudication to an LLM checkpoint is the next slice.
"""

from __future__ import annotations

from clinkz.discovery.models import (
    CallSite,
    CapabilityDelta,
    CapabilityPrimitive,
    DeltaGrade,
    Guard,
    SourceModel,
)


def _guard_for(call_site: CallSite, guards: list[Guard]) -> Guard | None:
    """The guard invoked before *call_site*, matched by symbol."""
    if not call_site.guard_symbol:
        return None
    return next((g for g in guards if g.symbol == call_site.guard_symbol), None)


def _adjudicate(
    call_site: CallSite, guard: Guard | None
) -> tuple[DeltaGrade, float, str, str | None]:
    """Return ``(delta_grade, confidence, evidence, gated_by)`` for one call site.

    * No guard at all → the intent-gap: present but nobody wired an intent around
      it (highest Δ, the Log4Shell shape).
    * A guard that is **bypassable by default** (both operands attacker-controlled;
      the real branch gated on an unset config) → EXPOSED. This is the GeoServer
      case — the guard exists but does not constrain the attacker.
    * A guard that is a genuine, unconditional constraint → SANCTIONED (Δ removed).
    """
    if guard is None:
        return (
            DeltaGrade.EXPOSED,
            0.75,
            "no guard on the capability call site — present but unconstrained (intent-gap)",
            None,
        )
    if guard.bypassable_by_default:
        gate = guard.gating_config
        evidence = (
            f"guard {guard.symbol!r} ({guard.kind}) compares two attacker-controlled "
            f"values {guard.operands} — a real guard would fix at least one operand. "
            + (
                f"The genuine guard is gated on {gate!r}, unset by default, so the "
                "bypassable branch is active."
                if gate
                else "No config fixes an operand, so it never constrains the attacker."
            )
        )
        # gated_by stays None: the config that WOULD gate it is unset by default,
        # so the primitive remains in Δ (config set ⇒ it would move to GATED).
        return DeltaGrade.EXPOSED, 0.9, evidence, None
    return (
        DeltaGrade.SANCTIONED,
        0.6,
        f"guard {guard.symbol!r} fixes at least one operand — a real constraint",
        None,
    )


def compute_delta(
    source_model: SourceModel, primitives: list[CapabilityPrimitive]
) -> list[CapabilityDelta]:
    """Compute the Δ-set: exposed capability call sites, each with a confidence.

    Only call sites whose primitive class is in the active primitive set are
    considered (Capability), and only EXPOSED ones become Δ (Capability − Intent).
    """
    active_classes = {p.primitive_class for p in primitives}
    primitive_id_by_class = {p.primitive_class: p.id for p in primitives}
    deltas: list[CapabilityDelta] = []
    for call_site in source_model.call_sites:
        if call_site.primitive_class not in active_classes:
            continue
        guard = _guard_for(call_site, source_model.guards)
        grade, confidence, evidence, gated_by = _adjudicate(call_site, guard)
        if grade != DeltaGrade.EXPOSED:
            continue  # sanctioned / gated capabilities are not attack surface
        deltas.append(
            CapabilityDelta(
                primitive_id=primitive_id_by_class[call_site.primitive_class],
                call_site=call_site,
                present=True,
                delta_grade=grade,
                delta_confidence=confidence,
                gated_by=gated_by,
                intent_evidence=evidence,
            )
        )
    return deltas
