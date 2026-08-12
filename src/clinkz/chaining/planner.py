"""Which chains exist, and in what order — a function of the finding SET.

The planner composes confirmed steps into candidate chains by matching what each
step YIELDS against what the next step REQUIRES, and it does so *before anything
is carried*: a candidate names the artifact it intends to present and the
acceptance signal it intends to look for. That ordering is deliberate. A chain
whose acceptance signal is chosen after the response arrives is a chain graded on
its own result, which is how "the second request returned 200" becomes "account
takeover".

Ranking is a function of the confirmed-finding SET, never of the order the
findings happened to be produced in — the same rule the exploit plan follows.
Findings arrive from a concurrent phase, so any tie broken by arrival order would
make the engagement non-reproducible.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from clinkz.chaining.composition import credentials_in
from clinkz.chaining.harvest import is_internal_address
from clinkz.chaining.models import (
    ChainArtifact,
    ChainCandidate,
    ChainKind,
    ChainLink,
    LinkKind,
)
from clinkz.chaining.vocabulary import ArtifactKind, confirmation_primitives_of
from clinkz.discovery.models import SoundnessGrade

#: Never plan more than this many chains. Each candidate costs two live requests
#: (the carriage and its decoy control) against the client's application, and a
#: chain is a targeted composition rather than a sweep.
MAX_CHAIN_CANDIDATES = 8

#: Impact rank per chain kind — lower runs first. Ordered by what the chain
#: DEMONSTRATES if it confirms, not by how interesting it sounds: reaching an
#: internal service and authenticating as somebody else are the two that turn a
#: primitive into an incident.
_CHAIN_RANK: dict[ChainKind, int] = {
    ChainKind.CREDENTIAL_TO_ACCESS: 0,
    ChainKind.FETCH_TO_INTERNAL_REACH: 1,
    ChainKind.TOKEN_TO_IMPERSONATION: 2,
    ChainKind.FILE_READ_TO_CREDENTIAL: 3,
}

#: What "accepted" means, per chain kind. Fixed here — before any request — so a
#: verdict cannot be graded against a signal picked to fit the response.
ACCEPTANCE_SIGNAL: dict[ChainKind, str] = {
    ChainKind.CREDENTIAL_TO_ACCESS: (
        "the authenticated-state boundary discriminator flips: a login redirect, "
        "status class, login form, session marker or identity echo that the "
        "anonymous control does not show"
    ),
    ChainKind.FILE_READ_TO_CREDENTIAL: (
        "the authenticated-state boundary discriminator flips for a credential "
        "parsed out of the recovered content"
    ),
    ChainKind.TOKEN_TO_IMPERSONATION: (
        "the application serves a principal's own view to a request carrying the "
        "recovered token, and refuses the same request carrying the decoy"
    ),
    ChainKind.FETCH_TO_INTERNAL_REACH: (
        "content the internal address serves comes back through the fetch channel, "
        "and the equivalently-shaped non-resolving decoy address returns none of it"
    ),
}

#: Content artifacts worth re-parsing for credentials — the FILE_READ_TO_CREDENTIAL
#: head. Any recovered body can carry a credential; these are the kinds whose
#: content is the *target's*, not ours.
_CONTENT_KINDS: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.FILE_CONTENT,
        ArtifactKind.DB_RECORD,
        ArtifactKind.COMMAND_OUTPUT,
        ArtifactKind.INTERNAL_RESPONSE,
    }
)


class ConfirmedStep(BaseModel):
    """One confirmed finding, as the planner needs it.

    A deliberately narrow projection of :class:`~clinkz.models.finding.Finding`
    so the planner is testable without constructing findings, and so a field the
    planner does not need cannot leak into a chain.

    Attributes:
        finding_id: The confirmed finding's id.
        test_method: The class that produced it.
        endpoint: Where it was confirmed.
        title: For the chain's description.
        severity: The single-step severity, for the escalation delta.
        parameter: The channel it was confirmed on, when there is one.
        confirmation_primitive: Overrides the class default when the methodology
            recorded one (a discovery-originated finding does).
    """

    finding_id: str
    test_method: str
    endpoint: str = ""
    title: str = ""
    severity: str = "medium"
    parameter: str = ""
    confirmation_primitive: str = ""

    def to_link(self, ordinal: int, produced: ArtifactKind | None) -> ChainLink:
        """Lower this step to an exploit link."""
        primitive = self.confirmation_primitive or confirmation_primitives_of(self.test_method)
        return ChainLink(
            ordinal=ordinal,
            kind=LinkKind.EXPLOIT,
            test_method=self.test_method,
            endpoint=self.endpoint,
            finding_id=self.finding_id,
            confirmation_primitive=primitive,
            soundness=SoundnessGrade.STATIC_CONFIRMED,
            produced=produced,
            confirmed=bool(primitive),
            why_unconfirmed=(
                "" if primitive else f"{self.test_method} declares no P1–P7 confirmation primitive"
            ),
            description=self.title or self.test_method,
        )


class CarriageSurface(BaseModel):
    """Where a carried artifact can be presented.

    The planner never invents a destination. Every field here comes from the
    engagement's own discovered surface, so a chain cannot be planned against a
    host the client did not authorise.

    Attributes:
        login_endpoints: URLs that authenticate — where a recovered credential
            is presented.
        session_probe_urls: URLs that behave differently with and without a
            session — where a recovered token is presented.
        fetch_channels: ``(endpoint_url, parameter)`` pairs a confirmed SSRF
            proved the server fetches from.
        internal_targets: In-scope internal addresses a fetch could reach.
    """

    login_endpoints: list[str] = Field(default_factory=list)
    session_probe_urls: list[str] = Field(default_factory=list)
    fetch_channels: list[tuple[str, str]] = Field(default_factory=list)
    internal_targets: list[str] = Field(default_factory=list)


def _identity_of(candidate: ChainCandidate) -> str:
    """A stable structural identity, for the final tie-break."""
    return "|".join(
        [
            candidate.chain_kind.value,
            candidate.carriage_target,
            *(f"{link.test_method}@{link.endpoint}" for link in candidate.links),
        ]
    )


def _carriage_link(
    ordinal: int,
    chain_kind: ChainKind,
    artifact: ChainArtifact,
    target: str,
) -> ChainLink:
    """The unproven carriage link a candidate carries until the oracle runs.

    Its ``soundness`` starts at :attr:`SoundnessGrade.HYPOTHESIZED` and its
    ``confirmed`` at ``False``: until the decoy control has run, the composition
    is exactly an inference, and a candidate that never reaches the oracle must
    grade as one rather than inherit its neighbours' grades.
    """
    return ChainLink(
        ordinal=ordinal,
        kind=LinkKind.CARRIAGE,
        test_method=f"carriage:{chain_kind.value}",
        endpoint=target,
        confirmation_primitive="P4",
        soundness=SoundnessGrade.HYPOTHESIZED,
        consumed=artifact.kind,
        confirmed=False,
        why_unconfirmed="the decoy-substitution control has not run",
        description=(
            f"present the {artifact.kind.value} recovered at step {ordinal - 1} "
            f"at {target}, alongside an equivalently-shaped decoy"
        ),
    )


def plan_chains(
    *,
    steps: list[ConfirmedStep],
    artifacts: list[ChainArtifact],
    surface: CarriageSurface,
) -> list[ChainCandidate]:
    """Compose confirmed steps into candidate chains.

    Args:
        steps: Every confirmed finding, projected.
        artifacts: Artifacts harvested from those findings.
        surface: Where a carried artifact may be presented.

    Returns:
        Up to :data:`MAX_CHAIN_CANDIDATES` candidates, ranked by impact class,
        then by link count (a shorter chain is a stronger claim), then by a
        structural identity — never by the order findings arrived in.
    """
    by_finding = {step.finding_id: step for step in steps}
    candidates: list[ChainCandidate] = []

    def source_step(artifact: ChainArtifact) -> ConfirmedStep | None:
        return by_finding.get(artifact.source_finding_id)

    for artifact in artifacts:
        step = source_step(artifact)
        if step is None:
            continue

        if artifact.kind is ArtifactKind.CREDENTIAL and surface.login_endpoints:
            target = surface.login_endpoints[0]
            head = step.to_link(1, ArtifactKind.CREDENTIAL)
            candidates.append(
                ChainCandidate(
                    chain_kind=ChainKind.CREDENTIAL_TO_ACCESS,
                    links=[
                        head,
                        _carriage_link(2, ChainKind.CREDENTIAL_TO_ACCESS, artifact, target),
                    ],
                    artifact=artifact,
                    carriage_target=target,
                    base_severity=step.severity,
                    rationale=(
                        f"{step.title or step.test_method} recovered a credential "
                        f"({artifact.obtained_by}); if the application accepts it at "
                        f"{target} while refusing an equivalently-shaped decoy, the "
                        "disclosure is authenticated access rather than a readable value"
                    ),
                )
            )

        elif artifact.kind is ArtifactKind.SESSION_TOKEN and surface.session_probe_urls:
            target = surface.session_probe_urls[0]
            head = step.to_link(1, ArtifactKind.SESSION_TOKEN)
            candidates.append(
                ChainCandidate(
                    chain_kind=ChainKind.TOKEN_TO_IMPERSONATION,
                    links=[
                        head,
                        _carriage_link(2, ChainKind.TOKEN_TO_IMPERSONATION, artifact, target),
                    ],
                    artifact=artifact,
                    carriage_target=target,
                    base_severity=step.severity,
                    rationale=(
                        f"{step.title or step.test_method} put a session token in our "
                        f"hands; presenting it at {target} distinguishes 'the token is "
                        "weak' from 'the token is another principal's session'"
                    ),
                )
            )

        elif artifact.kind in _CONTENT_KINDS and surface.login_endpoints:
            # The recovered CONTENT is not itself carriable — what makes it a
            # chain is a credential parsed out of it, which is a second, derived
            # artifact with its own provenance back to the same finding.
            for cred in credentials_in(artifact.value):
                derived = ChainArtifact(
                    kind=ArtifactKind.CREDENTIAL,
                    value=cred.secret,
                    principal=cred.identity,
                    label=(
                        f"credential for {cred.identity or 'an unnamed principal'}, "
                        f"parsed out of content recovered by {step.title or step.test_method}"
                    ),
                    source_finding_id=artifact.source_finding_id,
                    source_test_method=artifact.source_test_method,
                    obtained_by=cred.how,
                )
                target = surface.login_endpoints[0]
                head = step.to_link(1, artifact.kind)
                candidates.append(
                    ChainCandidate(
                        chain_kind=ChainKind.FILE_READ_TO_CREDENTIAL,
                        links=[
                            head,
                            _carriage_link(2, ChainKind.FILE_READ_TO_CREDENTIAL, derived, target),
                        ],
                        artifact=derived,
                        carriage_target=target,
                        base_severity=step.severity,
                        rationale=(
                            f"{step.title or step.test_method} recovered content carrying "
                            f"{cred.how}; the read is proven, and whether that credential "
                            f"WORKS is the difference between a file disclosure and access"
                        ),
                    )
                )

    # A confirmed fetch primitive composes with an internal address rather than
    # with an artifact it recovered: what the chain carries is the ADDRESS, and
    # the decoy is an equivalently-shaped address that resolves nowhere.
    fetch_steps = [
        step
        for step in steps
        if step.test_method in ("_test_ssrf", "_test_log4shell") and step.finding_id
    ]
    for step in fetch_steps:
        channel = next(
            ((url, param) for url, param in surface.fetch_channels if url == step.endpoint),
            None,
        )
        if channel is None:
            continue
        for internal in surface.internal_targets:
            if not is_internal_address(internal):
                continue
            artifact = ChainArtifact(
                kind=ArtifactKind.INTERNAL_ENDPOINT,
                value=internal,
                label=f"internal address reachable through {channel[1]!r} on {channel[0]}",
                source_finding_id=step.finding_id,
                source_test_method=step.test_method,
                obtained_by="an in-scope internal address in the engagement's own surface",
            )
            head = step.to_link(1, ArtifactKind.INTERNAL_RESPONSE)
            candidates.append(
                ChainCandidate(
                    chain_kind=ChainKind.FETCH_TO_INTERNAL_REACH,
                    links=[
                        head,
                        _carriage_link(2, ChainKind.FETCH_TO_INTERNAL_REACH, artifact, channel[0]),
                    ],
                    artifact=artifact,
                    carriage_target=channel[0],
                    carriage_parameter=channel[1],
                    base_severity=step.severity,
                    rationale=(
                        f"{step.title or step.test_method} proved the server fetches a URL "
                        f"we choose. Every confirmed fetch so far has stopped at that: "
                        f"pointing the same channel at {internal} is what turns 'it fetches' "
                        "into 'it reaches an internal service'"
                    ),
                )
            )

    for candidate in candidates:
        candidate.rank = _CHAIN_RANK.get(candidate.chain_kind, 99)
    candidates.sort(key=lambda c: (c.rank, len(c.links), _identity_of(c)))
    return candidates[:MAX_CHAIN_CANDIDATES]


__all__ = [
    "ACCEPTANCE_SIGNAL",
    "MAX_CHAIN_CANDIDATES",
    "CarriageSurface",
    "ConfirmedStep",
    "plan_chains",
]
