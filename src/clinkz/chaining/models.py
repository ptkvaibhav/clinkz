"""The shapes a chain is made of — artifact, link, composition evidence, chain.

The load-bearing decision in this module is that :class:`ChainArtifact` keeps the
carried value **out of everything a human reads**. A chain's whole point is
carrying material the application should not have given us — a password, a
session token, key material — and a chain finding that quoted it would be the
report becoming the disclosure. So the value lives in one field nothing renders,
and the evidence quotes a shape description and a salted fingerprint instead.
That is the same discipline :mod:`clinkz.engagement.credential_shapes` applies to
captured tokens, applied at the point where a chain would otherwise re-introduce
the leak the redactor was written to prevent.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from clinkz.chaining.vocabulary import ArtifactKind
from clinkz.discovery.models import SoundnessGrade


class LinkKind(StrEnum):
    """What kind of step a link is.

    Attributes:
        EXPLOIT: A confirmed ``_test_*`` finding. Its proof is the finding's own
            P1–P7 oracle; chaining re-uses that verdict and never re-derives it.
        CARRIAGE: The composition itself — the artifact from the previous link
            presented where it should not be accepted. Its proof is the
            decoy-substitution control, and it is the only link kind chaining
            introduces new evidence for.
    """

    EXPLOIT = "exploit"
    CARRIAGE = "carriage"


class ChainKind(StrEnum):
    """The composition shapes this engine can carry AND falsify.

    Each names a (carried artifact, acceptance oracle, decoy construction)
    triple. A composition with no entry here is not planned at all — a chain we
    could carry but not disprove is a narrative.

    Attributes:
        CREDENTIAL_TO_ACCESS: A recovered credential used to authenticate.
            Accepted ⇒ the boundary discriminator flips; decoy ⇒ it does not.
        TOKEN_TO_IMPERSONATION: A recovered or predicted session token presented
            as ours. Accepted ⇒ the application serves a principal's view.
        FETCH_TO_INTERNAL_REACH: A confirmed server-side fetch pointed at an
            internal address. Accepted ⇒ content we never sent comes back.
        FILE_READ_TO_CREDENTIAL: File content recovered, credential material
            parsed out of it. Its own proof is the NEXT link's carriage — this
            kind never confirms alone.
    """

    CREDENTIAL_TO_ACCESS = "credential_to_access"
    TOKEN_TO_IMPERSONATION = "token_to_impersonation"
    FETCH_TO_INTERNAL_REACH = "fetch_to_internal_reach"
    FILE_READ_TO_CREDENTIAL = "file_read_to_credential"


class ChainArtifact(BaseModel):
    """A thing carried from one link to the next.

    Attributes:
        kind: What sort of artifact this is — the routing label.
        value: The artifact itself. **Never rendered.** Nothing in the report,
            the trace, the action log or a finding's evidence reads this field;
            :meth:`describe` is what a human sees. Excluded from
            ``model_dump()`` so a caller cannot leak it by serialising the model
            wholesale.
        label: A non-secret name for the artifact ("the password field of the
            row returned by the UNION probe").
        principal: WHO the artifact belongs to, when the source named one — the
            username or email a credential was found beside. Carried as its own
            field rather than parsed back out of ``label`` at the carriage, so
            the login body is built from what the source actually said. Not a
            secret: an identity is what a report names, and it is what makes
            "we authenticated as X" a sentence rather than a claim.
        source_finding_id: The confirmed finding this came out of.
        source_test_method: The class that produced it.
        obtained_by: One sentence on HOW it was obtained, for the evidence.
    """

    kind: ArtifactKind
    value: str = Field(exclude=True)
    label: str = ""
    principal: str = ""
    source_finding_id: str = ""
    source_test_method: str = ""
    obtained_by: str = ""

    def fingerprint(self, salt: str = "") -> str:
        """A salted, non-reversible fingerprint of the carried value.

        Correlates the same artifact across links of one chain — "the value
        accepted at step 2 is the value recovered at step 1" — while replaying
        nowhere. Salted per engagement so a fingerprint cannot be matched against
        a precomputed table of common passwords, which an unsalted digest of a
        weak credential would be trivially vulnerable to.

        Args:
            salt: Engagement-local salt.

        Returns:
            A 12-hex-character prefix of the salted digest.
        """
        digest = hashlib.sha256(f"{salt}\x00{self.value}".encode()).hexdigest()
        return digest[:12]

    def describe(self, salt: str = "") -> str:
        """The renderable description — shape and fingerprint, never the value."""
        return (
            f"{self.kind.value} ({len(self.value)} chars, "
            f"fingerprint {self.fingerprint(salt)}): {self.label or 'unnamed'}"
        )


class CompositionEvidence(BaseModel):
    """The decoy-substitution control that proves a carriage was real.

    Two confirmed findings do not imply the chain between them, and neither does
    a successful second request: an endpoint that accepts everything accepts our
    carried credential too. So a carriage is proven the way every other oracle in
    this engine is — against a control. The control is an **equivalently-shaped
    decoy**: same length, same alphabet, same structure, a value the target never
    issued. The chain confirms only when the real artifact is accepted and the
    decoy is refused, which is precisely the observation an accept-everything
    endpoint cannot produce.

    Attributes:
        carried_kind: The artifact kind that was carried.
        carried_fingerprint: Salted fingerprint of the real artifact.
        decoy_fingerprint: Salted fingerprint of the decoy.
        decoy_shape: How the decoy matched the real artifact's shape, in words —
            what makes it a control rather than a different request.
        acceptance_signal: The observation that means "accepted" for this chain
            kind (a boundary discriminator, a content signature we never sent).
        real_accepted: Whether the real artifact was accepted.
        real_status: HTTP status of the carriage response.
        real_excerpt: Bounded excerpt of the accepting response.
        decoy_accepted: Whether the DECOY was also accepted. For a genuine chain
            this MUST be ``False``.
        decoy_status: HTTP status of the decoy response.
        decoy_excerpt: Bounded excerpt of the decoy response.
    """

    carried_kind: ArtifactKind
    carried_fingerprint: str = ""
    decoy_fingerprint: str = ""
    decoy_shape: str = ""
    acceptance_signal: str = ""
    real_accepted: bool = False
    real_status: int | None = None
    real_excerpt: str = ""
    decoy_accepted: bool = False
    decoy_status: int | None = None
    decoy_excerpt: str = ""


class ChainLink(BaseModel):
    """One step of a chain.

    Attributes:
        ordinal: 1-based position.
        kind: :class:`LinkKind`.
        test_method: The class this link is (an ``EXPLOIT`` link) or is carrying
            into (a ``CARRIAGE`` link).
        endpoint: Where the step happened.
        finding_id: The confirmed finding backing an ``EXPLOIT`` link; empty for
            a carriage, whose proof is its :class:`CompositionEvidence`.
        confirmation_primitive: Which of P1–P7 proved this link.
        soundness: This link's grade. A chain's grade is the weakest link's.
        consumed: Artifact kind this link took in, if any.
        produced: Artifact kind this link put out, if any.
        confirmed: Whether the link is independently proven.
        why_unconfirmed: Populated only when ``confirmed`` is ``False``.
        composition: The decoy control, on a carriage link.
        description: One sentence for the report.
    """

    ordinal: int
    kind: LinkKind
    test_method: str = ""
    endpoint: str = ""
    finding_id: str = ""
    confirmation_primitive: str = ""
    soundness: SoundnessGrade = SoundnessGrade.STATIC_CONFIRMED
    consumed: ArtifactKind | None = None
    produced: ArtifactKind | None = None
    confirmed: bool = False
    why_unconfirmed: str = ""
    composition: CompositionEvidence | None = None
    description: str = ""


class ChainCandidate(BaseModel):
    """A planned, not-yet-carried chain.

    The planner's output. Every candidate is a hypothesis about a composition,
    which is why it names the artifact it intends to carry and the acceptance
    signal it intends to look for BEFORE anything is sent — a chain whose
    acceptance signal is decided after seeing the response is a chain graded on
    its own result.

    Attributes:
        id: Stable identifier.
        chain_kind: Which composition this is.
        links: The exploit links already confirmed, in order.
        artifact: What will be carried.
        carriage_target: Where the artifact will be presented.
        carriage_parameter: The parameter it rides in, where the carriage is a
            parameter (the fetch channel a confirmed SSRF proved). Empty when the
            artifact is carried in a body or a header.
        base_severity: The head link's own severity — what the chain escalates
            FROM. Carried here so the escalation can be stated as a delta against
            a number the head finding actually earned, rather than a default.
        rank: Planner rank — impact class first, then link count, then a
            structural identity. A function of the finding SET, never of the
            order findings happened to be produced in.
        rationale: Why this composition is worth carrying.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_kind: ChainKind
    links: list[ChainLink] = Field(default_factory=list)
    artifact: ChainArtifact
    carriage_target: str = ""
    carriage_parameter: str = ""
    base_severity: str = "medium"
    rank: int = 0
    rationale: str = ""


class ConfirmedChain(BaseModel):
    """A chain every link of which is independently proven.

    Attributes:
        id: Stable identifier.
        chain_kind: Which composition this is.
        links: Every link, in order, each ``confirmed``.
        composed_grade: The WEAKEST link's grade
            (:func:`~clinkz.discovery.models.compose_soundness`).
        severity: The escalated severity — from what the chain DEMONSTRATED.
        impact_statement: What the chain proved, in one sentence.
        base_severity: The severity of the strongest single link, kept so the
            escalation can be read as a delta rather than asserted.
        confirmed_at: When the carriage was proven.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_kind: ChainKind
    links: list[ChainLink] = Field(default_factory=list)
    composed_grade: SoundnessGrade = SoundnessGrade.STATIC_CONFIRMED
    severity: str = "medium"
    impact_statement: str = ""
    base_severity: str = "medium"
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def link_summary(self) -> str:
        """``sqli → carriage(credential) → authenticated access``, for a title."""
        return " → ".join(
            link.test_method.removeprefix("_test_")
            if link.kind is LinkKind.EXPLOIT
            else f"carriage({link.consumed.value if link.consumed else 'artifact'})"
            for link in self.links
        )


__all__ = [
    "ChainArtifact",
    "ChainCandidate",
    "ChainKind",
    "ChainLink",
    "CompositionEvidence",
    "ConfirmedChain",
    "LinkKind",
]
