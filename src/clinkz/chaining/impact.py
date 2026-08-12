"""Impact escalation — the point of chaining, stated from what was demonstrated.

Every SSRF this engine has confirmed proves the FETCH and stops there: the target
was loopback-self or a collaborator we mounted ourselves. That is a real finding
and a modest one, because "the server fetches a URL I choose" is a primitive, not
an incident. What makes it an incident is what the fetch REACHES — and that is a
second observation, not an adjective.

So escalation here is a function of a CONFIRMED composition and nothing else. It
takes the chain's demonstrated effect and states the severity that effect
carries, together with the sentence a reader can check it against. It never
escalates a candidate, never escalates on the strength of a chain kind alone, and
never lowers a severity a single link already earned — the component findings are
left exactly as their own oracles graded them, and the chain is emitted alongside
them rather than rewriting them.
"""

from __future__ import annotations

from pydantic import BaseModel

from clinkz.chaining.models import ChainKind, ConfirmedChain, LinkKind

#: Severity ordering, strongest first. Local to this module and deliberately
#: string-keyed: the chain layer never constructs a
#: :class:`~clinkz.models.finding.Severity`, it hands a label to the emit site.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

#: The severity a CONFIRMED chain of each kind carries, and the effect that
#: earns it. The sentence is not decoration — it is what the report prints, and
#: it has to describe an observation the evidence supports.
_ESCALATION: dict[ChainKind, tuple[str, str]] = {
    ChainKind.CREDENTIAL_TO_ACCESS: (
        "critical",
        "a credential the application disclosed was accepted as authentication, so the "
        "disclosure is not a readable value but working access to the account it belongs to",
    ),
    ChainKind.FILE_READ_TO_CREDENTIAL: (
        "critical",
        "a credential parsed out of a file the application let us read was accepted as "
        "authentication, so the file read composes into working access rather than "
        "stopping at disclosure",
    ),
    ChainKind.TOKEN_TO_IMPERSONATION: (
        "high",
        "a session token obtained without the account's credentials was accepted, and the "
        "application served that principal's own view — so the weakness is impersonation, "
        "not token hygiene",
    ),
    ChainKind.FETCH_TO_INTERNAL_REACH: (
        "high",
        "the server-side fetch reached an internal address and returned content from it, so "
        "the primitive is not 'the server fetches a URL we choose' but access to a service "
        "the network places out of our reach",
    ),
}


class ImpactEscalation(BaseModel):
    """What a confirmed chain demonstrated, and the severity that earns.

    Attributes:
        severity: The chain's severity.
        base_severity: The strongest single link's severity, kept so the
            escalation reads as a delta a reviewer can check rather than a number
            that appeared.
        escalated: Whether the chain raised the severity above its strongest link.
        statement: The demonstrated effect, in one sentence.
    """

    severity: str
    base_severity: str
    escalated: bool = False
    statement: str = ""


def escalate(chain: ConfirmedChain, *, base_severity: str) -> ImpactEscalation:
    """Compute the severity a CONFIRMED chain has demonstrated.

    Args:
        chain: The chain. Must have every link confirmed — a candidate has
            demonstrated nothing, and escalating one would be the assertion this
            module exists to avoid.
        base_severity: Severity of the strongest single link.

    Returns:
        The escalation. When *chain* is not fully confirmed, the base severity is
        returned unchanged with a statement saying so.
    """
    base = (base_severity or "medium").lower()
    if base not in _SEVERITY_RANK:
        base = "medium"

    if not chain.links or not all(link.confirmed for link in chain.links):
        return ImpactEscalation(
            severity=base,
            base_severity=base,
            statement=(
                "not escalated: at least one link is unconfirmed, so the composition "
                "demonstrated nothing beyond its individual steps"
            ),
        )
    if not any(link.kind is LinkKind.CARRIAGE for link in chain.links):
        return ImpactEscalation(
            severity=base,
            base_severity=base,
            statement=(
                "not escalated: the chain carries no composition link, so nothing was "
                "shown to compose"
            ),
        )

    escalated_severity, statement = _ESCALATION.get(
        chain.chain_kind,
        (base, "no escalation is declared for this composition"),
    )
    # max() over the rank: a chain never LOWERS what a single link already
    # earned. A confirmed critical SQLi composed into a credential chain is still
    # critical, and the composition adds impact rather than re-grading the step.
    winner = min((base, escalated_severity), key=lambda s: _SEVERITY_RANK[s])
    return ImpactEscalation(
        severity=winner,
        base_severity=base,
        escalated=_SEVERITY_RANK[winner] < _SEVERITY_RANK[base],
        statement=statement,
    )


__all__ = ["ImpactEscalation", "escalate"]
