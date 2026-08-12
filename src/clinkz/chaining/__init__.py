"""Chaining — composing confirmed steps into a demonstrated-impact chain.

A chain is an ordered composition of confirmed steps where step N's OUTPUT
becomes step N+1's INPUT or precondition. It is a first-class capability, not a
post-processing narrative over a finding list: the composition ITSELF carries an
oracle, because two confirmed findings do not imply the chain between them.

The four modules divide as the honesty rule does:

* :mod:`~clinkz.chaining.vocabulary` — what each methodology class YIELDS and
  what it REQUIRES. The substrate: without a declared vocabulary a "chain
  planner" is a story generator.
* :mod:`~clinkz.chaining.models` — the carried artifact, the links, the
  composition evidence, the confirmed chain.
* :mod:`~clinkz.chaining.composition` — the oracle. A chain confirms only when
  the carried artifact was ACCEPTED at step N+1 **and** an equivalently-shaped
  decoy was REJECTED. Everything else is a lead naming the unconfirmed link.
* :mod:`~clinkz.chaining.planner` — which candidate chains exist, in an order
  that is a function of the finding SET rather than of execution order.
* :mod:`~clinkz.chaining.impact` — the point of chaining: a fetch that reaches
  an internal service is a different severity than a fetch, and the escalation
  is stated from what was demonstrated, never asserted.
"""

from __future__ import annotations

from clinkz.chaining.composition import (
    CompositionVerdict,
    credentials_in,
    decoy_for,
    evaluate_composition,
    grade_chain,
    links_independently_confirmed,
)
from clinkz.chaining.harvest import harvest_artifacts, is_internal_address
from clinkz.chaining.impact import ImpactEscalation, escalate
from clinkz.chaining.models import (
    ChainArtifact,
    ChainCandidate,
    ChainKind,
    ChainLink,
    CompositionEvidence,
    ConfirmedChain,
    LinkKind,
)
from clinkz.chaining.planner import (
    ACCEPTANCE_SIGNAL,
    CarriageSurface,
    ConfirmedStep,
    plan_chains,
)
from clinkz.chaining.vocabulary import (
    CLASS_CONFIRMATION_PRIMITIVES,
    CLASS_REQUIRES,
    CLASS_YIELDS,
    NO_YIELD_REASON,
    ArtifactKind,
    confirmation_primitives_of,
    requires_of,
    yields_of,
)

__all__ = [
    "ACCEPTANCE_SIGNAL",
    "CLASS_CONFIRMATION_PRIMITIVES",
    "CLASS_REQUIRES",
    "CLASS_YIELDS",
    "NO_YIELD_REASON",
    "ArtifactKind",
    "CarriageSurface",
    "ChainArtifact",
    "ChainCandidate",
    "ChainKind",
    "ChainLink",
    "CompositionEvidence",
    "CompositionVerdict",
    "ConfirmedChain",
    "ConfirmedStep",
    "ImpactEscalation",
    "LinkKind",
    "confirmation_primitives_of",
    "credentials_in",
    "decoy_for",
    "escalate",
    "evaluate_composition",
    "grade_chain",
    "harvest_artifacts",
    "is_internal_address",
    "links_independently_confirmed",
    "plan_chains",
    "requires_of",
    "yields_of",
]
