"""The write-crossing oracle, as pure functions.

Successor to the four-arm READ oracle (:mod:`clinkz.agents._idor_oracle`), not a
variant of it. That one proves *A was served B's object*. This proves *A wrote an
object that is B's* — a different defining effect, different arms, a different
destructive category and a different dispatch class.

Three things about this class are not true of the read oracle, and every design
decision in this module falls out of one of them.

**The write cannot be taken back.** A read arm that proves nothing costs a
request. A write arm that proves nothing costs a row in somebody else's data
that this engine has no permission to delete — ``CATEGORY_DELETION`` is refused
by the client-safe default, so the engine *cannot* clean up even where it wanted
to. Everything that could fail is therefore checked BEFORE the first payload —
the write must be locatable in a subsequent read, the records must name an
owner, and ``ref(B)`` must have been discovered by probing as B — and a
precondition that does not hold is an ABSTAIN with nothing sent, never a
degradation to a lead.

**The status code is not the effect.** ``201 Created`` proves a record was
created and says nothing about what the record claims to belong to; every
framework that silently discards an unbound field returns the same 201 as one
that honours it. Nor is the write's own response body: an echo of the submitted
owner value proves the handler reflects its input, and frameworks reflect before
discarding. Only a SEPARATE read of the persisted object is evidence, which is
why :class:`WriteObservation` carries the read-back body under
``persisted_body`` and the write's own answer only as a status.

**Attribution is a relation, not a property.** Whose object this is comes off
the OWNING FIELD, through :func:`~clinkz.agents._idor_oracle.owner_claim`,
reused verbatim rather than re-derived — same two routes, same strength order,
same names-and-fingerprints rendering. An object naming no owner cannot be
crossed into, for the identical reason a public catalogue record cannot be
crossed into on the read side: there is nobody it belongs to.

See :doc:`/methodology/write-crossings` for the arms, the fixture and the
decision order this module implements.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from clinkz.agents._idor_oracle import (
    OWNING_FIELD_NAMES_PRINCIPAL,
    OWNING_FIELD_NOT_CALLER,
    OwnerClaim,
    owner_claim,
    owning_fields,
    stable_fields,
)
from clinkz.agents._json_body import leaf_name

__all__ = [
    "ANONYMOUS_ARM_NOT_DISPATCHED",
    "ANONYMOUS_WRITE_SUCCEEDED",
    "ARM_DISPATCH_ORDER",
    "CONTROL_ABSENT_NOT_DISPATCHED",
    "CONTROL_ABSENT_LANDED",
    "CONTROL_SELF_DID_NOT_ATTRIBUTE",
    "NOT_READABLE_BACK",
    "OBJECT_NAMES_NO_OWNER",
    "REFERENCE_NOT_OWNED",
    "REQUIRES_SECOND_PRINCIPAL",
    "WRITE_CROSSING_WHY_UNCONFIRMED",
    "ControlArmNotDispatchedError",
    "CreatedObject",
    "WriteArm",
    "WriteArmRecorder",
    "WriteCrossingVerdict",
    "WriteObservation",
    "benign_value_like",
    "crossing_body",
    "decide_write_crossing",
    "locate_created_object",
    "object_identifier",
    "owner_field_key",
    "owning_field_of",
    "owner_reference_of",
    "verified_owner_reference_of",
    "reference_format",
    "residual_note",
    "shaped_self_reference",
]


class WriteArm(StrEnum):
    """The five dispatched arms, named as the methodology doc names them."""

    #: Arm 5. B's own authorized read of B's own object. Not a control — it is
    #: the ATTRIBUTION SOURCE, and the arm a single-role engagement cannot send.
    OWNER_READ = "owner_read"
    #: §2(a)+(b) — not an arm, and named separately for that reason. An ordinary
    #: object created as A with the owning field OMITTED, so the SERVER assigns
    #: the owner. It answers three preconditions at once: the write is locatable
    #: in a subsequent read, the records name an owner, and the owner the server
    #: named for A is ``ref(A)`` in the application's own spelling. Taking
    #: ``ref(A)`` from A's identity tokens instead would be a guess — an email
    #: address is not the reference a collection keyed on a numeric id issues.
    SELF_ANCHOR = "self_anchor"
    #: Arm 1. As A, owner field = ``ref(A)``. The liveness control: does this
    #: endpoint honour the owning field at all, from this principal, in this
    #: shape?
    CONTROL_SELF = "control_self"
    #: Arm 2. As A, owner field = ``ref(∅)``. The never-issued control.
    CONTROL_ABSENT = "control_absent"
    #: Arm 4. No session, owner field = ``ref(B)``. Disqualifying if it works.
    ANONYMOUS = "anonymous"
    #: Arm 3. As A, owner field = ``ref(B)``. The payload.
    CROSSING = "crossing"


#: The order the arms are DISPATCHED in — 5, 1, 2, 4, then 3.
#:
#: Two orderings are folded into one tuple here, and both are load-bearing:
#:
#: * **The control precedes the payload** (``control_absent`` and
#:   ``control_self`` before ``crossing``). A control dispatched after a write
#:   whose effect outlives the request is observed through a collection the
#:   payload has already grown, and on the modify arm through an object the
#:   payload has already changed — so the same oracle that just said yes to the
#:   payload says yes to the control, and the true positive is killed by its own
#:   proof. The seam (``_run_control_arm_first``) owns that half.
#: * **The attribution source precedes the payload** (``owner_read`` before
#:   ``crossing``). ``owner_read`` is B's read of B's own collection, and it is
#:   where ``ref(B)`` comes from. Run after the crossing it would be reading a
#:   collection this class had just written an object into, so the reference the
#:   claim rests on would be attributed against contaminated data — the payload
#:   grading its own evidence, one layer up from the control-order defect.
ARM_DISPATCH_ORDER: tuple[WriteArm, ...] = (
    WriteArm.OWNER_READ,
    WriteArm.SELF_ANCHOR,
    WriteArm.CONTROL_SELF,
    WriteArm.CONTROL_ABSENT,
    WriteArm.ANONYMOUS,
    WriteArm.CROSSING,
)


#: The write cannot be read back, so it cannot be attributed. Established before
#: the first payload by writing an ordinary self-attributed object and locating
#: it in a subsequent read.
NOT_READABLE_BACK = "write_crossing_not_readable_back"

#: The created object carries no owning field. Nobody it belongs to, so nothing
#: to cross into — the write side of the read oracle's public-record abstain.
OBJECT_NAMES_NO_OWNER = "write_crossing_object_names_no_owner"

#: ``ref(B)`` was not discovered by probing AS B. The mirror of the read
#: oracle's ``ref(A)`` anchor: reads need the SELF arm anchored, writes need the
#: PAYLOAD's owner value discovered, and both are the same law — a reference the
#: caller owns, or abstain.
REFERENCE_NOT_OWNED = "write_crossing_reference_not_owned"

#: Fewer than two principals. Arm 5 cannot be dispatched at all, so nothing can
#: attribute the object and nothing can source ``ref(B)``.
REQUIRES_SECOND_PRINCIPAL = "write_crossing_requires_second_principal"

#: The never-issued control could not be SENT. An un-sent control licenses
#: nothing, and this class's payload is irreversible, so the payload is skipped.
CONTROL_ABSENT_NOT_DISPATCHED = "write_crossing_control_arm_not_dispatched"

#: The never-issued control LANDED, attributed to a principal that does not
#: exist. The handler is storing an opaque string, not honouring an owner field,
#: and the "crossing" is that same string storage.
CONTROL_ABSENT_LANDED = "write_crossing_absent_reference_was_honoured"

#: The liveness control did not attribute A's own object to A. The endpoint does
#: not honour the owning field from this principal in this shape, so arm 3
#: attributing one to B would be a coincidence rather than a crossing.
CONTROL_SELF_DID_NOT_ATTRIBUTE = "write_crossing_endpoint_does_not_honour_owner_field"

#: The anonymous arm was never sent. An arm that was not dispatched refused
#: nothing — the same rule every control arm in this engine is held to.
ANONYMOUS_ARM_NOT_DISPATCHED = "write_crossing_anonymous_arm_not_dispatched"

#: The anonymous arm SUCCEEDED. A's session was not what crossed anything: the
#: endpoint is simply open, which is a different finding with a different
#: remediation.
ANONYMOUS_WRITE_SUCCEEDED = "write_crossing_endpoint_accepts_unauthenticated_writes"


#: Every reason this class can decline, as a set, so the registry sync test and
#: :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED` can be checked against
#: one another rather than against a hand-copied list.
WRITE_CROSSING_WHY_UNCONFIRMED: frozenset[str] = frozenset(
    {
        NOT_READABLE_BACK,
        OBJECT_NAMES_NO_OWNER,
        REFERENCE_NOT_OWNED,
        REQUIRES_SECOND_PRINCIPAL,
        CONTROL_ABSENT_NOT_DISPATCHED,
        CONTROL_ABSENT_LANDED,
        CONTROL_SELF_DID_NOT_ATTRIBUTE,
        ANONYMOUS_ARM_NOT_DISPATCHED,
        ANONYMOUS_WRITE_SUCCEEDED,
    }
)


#: Field names an API uses for an object's own identifier, in preference order.
#: Used only to NAME what a run left behind so the operator can find and delete
#: it — never to decide anything about a verdict.
_IDENTIFIER_FIELDS: tuple[str, ...] = ("id", "_id", "uuid", "identifier", "key", "pk", "ref")


@dataclass(frozen=True)
class CreatedObject:
    """One object this class wrote, located in a SEPARATE read of the collection.

    Attributes:
        located: Whether the object was found in the read-back at all. ``False``
            is an unobserved outcome, never a negative one: the write may have
            landed somewhere this engine did not look.
        identifier: The object's own id, as the application named it. Reported to
            the operator so they can remove the row; it is a value WE caused to
            exist, not one the target was keeping.
        body: The persisted object, verbatim, as the read-back served it. This
            and nothing else is what attribution reads.
        marker: The engine-minted value that identified this object in the
            collection — one attempt's own token, so a located object is
            attributable to the write that made it.
    """

    located: bool
    identifier: str = ""
    body: str = ""
    marker: str = ""


@dataclass(frozen=True)
class WriteObservation:
    """What one dispatched arm sent, and what a later read found.

    ``status`` is the write's own answer and is recorded because an operator
    reading the evidence wants it — it decides nothing. ``persisted_body`` is
    the read-back, and it is the only field any verdict branch consults.

    Attributes:
        arm: Which arm this is.
        dispatched: Whether the request actually went out. An arm that was not
            sent proves nothing and is never read as a refusal.
        status: The write's HTTP status, or 0 when nothing came back.
        owner_value_sent: The value this arm put in the owning field.
        created: The object a later read located, if any.
        principal: Label of the identity it was sent as, or ``anonymous``.
    """

    arm: WriteArm
    dispatched: bool
    status: int
    owner_value_sent: str
    created: CreatedObject
    principal: str

    @property
    def persisted_body(self) -> str:
        """The read-back body — the ONE channel attribution may be read from."""
        return self.created.body if self.created.located else ""

    def landed(self) -> bool:
        """Whether this arm's write was located in a subsequent read."""
        return self.dispatched and self.created.located


@dataclass
class WriteArmRecorder:
    """Accumulates the arms as they are dispatched, in dispatch order.

    A mutable collector rather than five locals, for the reason
    :class:`~clinkz.agents._idor_oracle.ArmRecorder` is one: every arm the oracle
    grades is an arm that was recorded here, and an absent one is visibly
    ``None`` rather than quietly defaulted.

    :attr:`sequence` is what the acceptance criterion reads. Per invariant 35, a
    test that asks only whether the verdict was right cannot detect an oracle
    that reached the right verdict by the wrong arm — so the ORDER the arms went
    out in is recorded as a fact about the run, not reconstructed from a log.
    """

    observations: dict[WriteArm, WriteObservation] = field(default_factory=dict)
    sequence: list[WriteArm] = field(default_factory=list)

    def record(self, obs: WriteObservation) -> WriteObservation:
        self.observations[obs.arm] = obs
        self.sequence.append(obs.arm)
        return obs

    def get(self, arm: WriteArm) -> WriteObservation | None:
        return self.observations.get(arm)

    def dispatch_order_holds(self) -> bool:
        """Whether the arms went out in :data:`ARM_DISPATCH_ORDER`.

        Compares the SUBSEQUENCE actually dispatched against the declared order,
        so an arm that legitimately never ran (a precondition abstained before
        it) does not read as an inversion — only two arms in the wrong relative
        order do.
        """
        ranks = [ARM_DISPATCH_ORDER.index(a) for a in self.sequence if a in ARM_DISPATCH_ORDER]
        return ranks == sorted(ranks)


@dataclass(frozen=True)
class WriteCrossingVerdict:
    """The oracle's answer, and why.

    Attributes:
        confirmed: Whether every arm cleared. Only ever True in the multi-role
            tier — the registry declares the requirement and the code reads it.
        tier: ``"multi_role"`` or ``"single_role"``.
        attribution: The owning-field route that attributed the PERSISTED object
            to B (:data:`~clinkz.agents._idor_oracle.OWNING_FIELD_NAMES_PRINCIPAL`
            / :data:`~clinkz.agents._idor_oracle.OWNING_FIELD_NOT_CALLER`), or
            ``""``. This is the claim.
        attributing_fields: The field that did it, as
            ``field=<name> owner_fp=<hash> caller_fp=<hash|absent>``. Names and
            salted fingerprints only — never a value from the target.
        owning_field: Schema path of the field naming the owner.
        why_unconfirmed: The closed-vocabulary reason, or ``""``.
        detail: One sentence for the trace, the lead and the evidence.
        arms_detail: Per-arm one-liners, so a reviewer can re-derive the verdict.
        arms_inverted: The arms went out in the wrong order. A loud refusal,
            never a quiet abstain: a crossing graded against a collection its own
            owner_read had not yet read is the defect this class was built after.
        corroborated: Whether B's OWN authorized read, taken after the write,
            is served the object we filed in B's name. This is a second
            principal observing the crossed object rather than a restatement of
            our own reference — the check that ``ref(B)`` came from B's snapshot
            would be true by construction, since that snapshot is where it came
            from, and a check that cannot fail is not evidence. Load-bearing in
            the ``OWNING_FIELD_NOT_CALLER`` branch, which is the weaker
            attribution route and the one the methodology doc requires arm 5 to
            corroborate.
    """

    confirmed: bool
    tier: str
    attribution: str = ""
    attributing_fields: tuple[str, ...] = ()
    owning_field: str = ""
    why_unconfirmed: str = ""
    detail: str = ""
    arms_detail: tuple[str, ...] = ()
    arms_inverted: bool = False
    corroborated: bool = False


def object_identifier(record: dict[str, Any]) -> str:
    """The application's own id for *record*, or ``""``.

    Read only to NAME what a run left behind. Nothing about a verdict consults
    it: an identifier is how the operator finds the row to delete, and reading it
    as evidence would be the status-code mistake wearing a different hat.
    """
    for name in _IDENTIFIER_FIELDS:
        for key, value in record.items():
            if key.lower() == name and value not in (None, "", []):
                return str(value)
    return ""


def locate_created_object(
    records: list[dict[str, Any]],
    marker: str,
) -> CreatedObject:
    """Find the object this attempt created, in a SEPARATE read of the collection.

    The whole point of the function is that the caller hands it the read-back
    rather than the write's own response. A create's answer echoes what it was
    sent; only the collection says what was stored.

    *marker* is a value this engine minted for this one attempt, so a located
    object is attributable to the write that made it — the same rule every
    marker oracle in this engine follows, applied to a record instead of a
    response body. Matching on "the newest row" instead would attribute whatever
    another client happened to write while we were looking.

    Args:
        records: The collection's own representation, as records.
        marker: The engine-minted token the write carried.

    Returns:
        The located object, or ``CreatedObject(located=False)`` — an UNOBSERVED
        outcome, never a negative one.
    """
    if not marker:
        return CreatedObject(located=False)
    for record in records:
        if marker in json.dumps(record, sort_keys=True, default=str):
            return CreatedObject(
                located=True,
                identifier=object_identifier(record),
                body=json.dumps(record, sort_keys=True, default=str),
                marker=marker,
            )
    return CreatedObject(located=False, marker=marker)


def owner_reference_of(body: str, principal_values: frozenset[str]) -> tuple[str, str]:
    """The owning ``(field, value)`` *body* names, preferring one we can verify.

    Used twice, and the asymmetry between the two uses is the point:

    * over the object A wrote for itself, to learn WHICH field this endpoint
      names an owner with (precondition (b));
    * over B's own authorized read, to learn ``ref(B)`` — the value the payload
      will carry (precondition (c)).

    In the second use the field's value must be B's, which is why the caller
    passes B's identity tokens as *principal_values*: a value checkable against
    an identity we HOLD beats one admitted on the strength of its field name
    alone, so those are offered first.

    Returns:
        ``(field_path, value)``, or ``("", "")`` when the body names no owner.
    """
    owners = owning_fields(body, principal_values=principal_values)
    if not owners:
        return "", ""
    known = {v.strip() for v in principal_values if v.strip()}
    for path, value in sorted(owners.items()):
        if value in known:
            return path, value
    path, value = sorted(owners.items())[0]
    return path, value


#: The filler a synthesised sibling value is built from. Deliberately recognisable
#: — an operator reading the row this test left behind should be able to tell at a
#: glance that it is ours.
_BENIGN_FILLER = "clinkz"


def benign_value_like(observed: Any) -> Any:
    """A value of *observed*'s TYPE and SHAPE that reproduces none of its content.

    Sibling fields exist to get the request past the handler's own validation
    and no further: every arm sends the same ones, so they cancel out of the
    differential entirely. What they must not do is fail validation for a reason
    that has nothing to do with the claim — a request the handler rejects never
    reaches the code path this class is asking about, and the class would then
    report that this endpoint's writes cannot be read back, which is a statement
    about our own body rather than about the target. Juice Shop's
    ``/api/Addresss`` refuses exactly that way: ``Validation min on mobileNum``,
    ``Validation len on zipCode``.

    So the SHAPE is copied — a string's length, a number's magnitude — and the
    CONTENT is not. Copying the observed value would satisfy the same validators
    and would write another principal's real address into a new row, which is a
    worse thing to leave behind than a placeholder. Same trade
    :func:`~clinkz.agents._idor_oracle.synthesize_absent_reference` makes for a
    reference: keep everything the handler round-trips on, change what it says.
    """
    if isinstance(observed, bool):
        return False
    if isinstance(observed, int):
        # Same number of digits, so a ``min``/``max`` bound written for real data
        # is satisfied by construction. Never the observed number itself.
        digits = len(str(abs(observed))) or 1
        return int("1" + "0" * (digits - 1))
    if isinstance(observed, float):
        return 1.0
    if isinstance(observed, str):
        length = len(observed)
        if length <= 0:
            return _BENIGN_FILLER
        repeated = (_BENIGN_FILLER * (length // len(_BENIGN_FILLER) + 1))[:length]
        return repeated
    return _BENIGN_FILLER


def verified_owner_reference_of(body: str, principal_values: frozenset[str]) -> tuple[str, str]:
    """The owning ``(field, value)`` *body* names that is VERIFIABLY a held identity.

    The strict half of :func:`owner_reference_of`, and the difference is what the
    caller may conclude. That function falls back to the first owning field it
    finds, which is correct when the value came from a write the SERVER
    attributed — the server said whose it was, so the value is that principal's by
    construction. It is not correct when the value came out of a collection read:
    a collection shows every principal's records, and "the first owning value in
    the list" belongs to whoever happens to sort first.

    So this route requires the value to be one of *principal_values* — read from
    session material WE hold
    (:meth:`~clinkz.agents._principal.Principal.identity_tokens`, which decodes
    the bearer's own identity claims) and never from a response. A target cannot
    nominate one of its records as ours.

    Returns:
        ``(field_path, value)``, or ``("", "")`` when nothing in *body* carries an
        identity we hold — an abstain, never a guess at which record is whose.
    """
    known = {v.strip() for v in principal_values if v.strip()}
    if not known:
        return "", ""
    for path, value in sorted(owning_fields(body, principal_values=frozenset(known)).items()):
        if value.strip() in known:
            return path, value.strip()
    return "", ""


def owner_field_key(path: str) -> str:
    """The owning field as a REQUEST BODY KEY — its leaf name, never its path.

    Every route that discovers the owning field discovers it by reading
    something, and where it read decides the spelling: a single created object
    gives ``UserId`` and a collection gives ``[9].UserId``. Both name the same
    field. Only one of them is a key a handler has.

    Measured twice on Juice Shop's ``/api/Complaints``, once per discovery
    route: every arm went out carrying ``"[0].UserId"`` / ``"[9].UserId"``, the
    server ignored an unknown field, all four objects came back unattributed,
    and the class reported that the collection's records name no owner while its
    own snapshot carried one. Normalising at each discovery site is what let it
    happen twice, so it is normalised HERE — at the one seam the field crosses on
    its way to becoming a body key — and each route calls this rather than
    remembering the rule.

    An index is where a value was observed. It is not part of the field's name.
    """
    return leaf_name(path)


def owning_field_of(snapshot: str) -> str:
    """The field this COLLECTION names its records' owner with, or ``""``.

    Read from the collection rather than from one object, because the object a
    create returns may carry the field EMPTY — Juice Shop's ``/api/Complaints``
    answers a create with ``UserId: null``, and an empty value names nobody, so
    :func:`owning_fields` correctly declines to admit it. The collection's other
    records carry the same field populated, and the field is a property of the
    schema rather than of any one row.

    Returns the LEAF name, via :func:`owner_field_key` — see the rule there.
    """
    for path in sorted(owning_fields(snapshot)):
        return owner_field_key(path)
    return ""


def shaped_self_reference(caller_identity: frozenset[str], observed_values: tuple[str, ...]) -> str:
    """``ref(A)`` from A's OWN session claims, matched by shape to the owner field.

    The third and last tier, and the one that reaches the endpoints this class
    exists for. The first two read ``ref(A)`` off an object the server
    attributed; an application that assigns **no** owner at all — the shape a
    cross-principal write is possible on — gives neither, so the reference has to
    come from somewhere else or the class abstains on exactly the targets worth
    testing.

    It comes from A's own identity claims: the username the operator supplied and
    the identity claims of the session token the target issued US
    (:meth:`~clinkz.agents._principal.Principal.identity_tokens`). Those are read
    from session material we hold and never from a response, which is the same
    source the read oracle's ``caller_identity`` comes from — a target cannot
    nominate one of its values as ours.

    The SHAPE filter is what makes it a candidate rather than a guess: a
    collection keyed on a numeric ``UserId`` is not named by an email address, so
    only a claim shaped like the values that field is observed to carry is
    offered. And it is still only a candidate — **arm 1 is what proves it**. If
    the endpoint does not read back an object attributed to this value, the class
    abstains rather than treating the guess as established.

    Args:
        caller_identity: A's identity values, from A's own session.
        observed_values: The values the owning field was seen to carry.

    Returns:
        The reference, or ``""`` when no claim matches the field's shape.
    """
    shapes = {reference_format(v) for v in observed_values if v.strip()}
    if not shapes:
        return ""
    for value in sorted(v.strip() for v in caller_identity if v.strip()):
        if reference_format(value) in shapes:
            return value
    return ""


def crossing_body(
    base: dict[str, Any],
    owner_field: str,
    owner_value: str,
    marker_field: str,
    marker: str,
) -> dict[str, Any]:
    """One arm's request body: the base object, this arm's owner value, our marker.

    Every arm sends the SAME shape and differs only in *owner_value* — that is
    what makes the four write arms a differential rather than four unrelated
    requests. The marker rides in a field the collection's own representation
    already carries, so the read-back can attribute the located row to this
    attempt without adding a field the application never offered (which would be
    a mass-assignment probe, a different class with a different claim).

    An empty *owner_field* OMITS the field entirely rather than sending it blank
    — that is the anchoring probe's whole shape, and invariant 16's rule besides:
    a field the methodology did not intend to set is omitted, never sent
    empty-but-present, because a blank owner is a value we chose and the server
    assigning one is the observation being sought.
    """
    body = dict(base)
    if marker_field:
        body[marker_field] = marker
    if owner_field:
        body[owner_field] = owner_value
    return body


def residual_note(collection: str, identifier: str, arm: WriteArm) -> str:
    """The instruction the client-facing document gives the operator.

    Written as an instruction rather than a description because this is the one
    row in a deliverable where the action is something the operator must do
    BECAUSE we ran the test. It names the collection and the identifier so they
    can find the row rather than take the claim on trust.
    """
    where = f"{collection} (object id {identifier})" if identifier else collection
    return (
        f"Delete the object this test created at {where}. It was written by the "
        f"{arm.value!r} arm of the write-crossing test and this engine cannot remove it: "
        "deleting an application record is a destructive action the client-safe default "
        "refuses, so no request it is permitted to send would undo the write. Removal is "
        "manual."
    )


#: What each arm's body carried in the owning field, named rather than
#: rendered: the VALUES are principal identifiers and never reach an artifact.
_ARM_OWNER_CARRIED: dict[WriteArm, str] = {
    WriteArm.OWNER_READ: "(a read — no body)",
    WriteArm.SELF_ANCHOR: "(omitted — the server assigned the owner)",
    WriteArm.CONTROL_SELF: "ref(A)",
    WriteArm.CONTROL_ABSENT: "ref(0) — a reference nobody owns",
    WriteArm.ANONYMOUS: "ref(B)",
    WriteArm.CROSSING: "ref(B)",
}


def _arm_line(obs: WriteObservation | None, arm: WriteArm) -> str:
    if obs is None:
        return f"{arm.value}: not dispatched"
    return (
        f"{obs.arm.value}: as {obs.principal} "
        f"owner_field_carried={_ARM_OWNER_CARRIED[arm]} "
        f"write_status={obs.status} landed={obs.landed()} "
        f"object_id={obs.created.identifier or '-'}"
    )


def decide_write_crossing(
    *,
    owner_read: WriteObservation | None,
    corroborating_body: str,
    control_self: WriteObservation | None,
    control_absent: WriteObservation | None,
    anonymous: WriteObservation | None,
    crossing: WriteObservation | None,
    recorder: WriteArmRecorder,
    caller_identity: frozenset[str],
    held_identities: dict[str, frozenset[str]],
    principals_available: int,
    principals_required: int,
    tier: str,
    absent_reference: str,
) -> WriteCrossingVerdict:
    """Grade the five arms, in the decision order the methodology doc declares.

    Nothing here reads a status code as an effect and nothing reads a write's own
    response. Every branch that consults a body consults
    :attr:`WriteObservation.persisted_body` — the read-back — and the crossing's
    attribution is taken from that body through
    :func:`~clinkz.agents._idor_oracle.owner_claim`, unchanged.

    Args:
        owner_read: Arm 5 — B's authorized read taken BEFORE any write. The
            attribution source, and where ``ref(B)`` was discovered.
        corroborating_body: B's own read of the collection taken AFTER the
            crossing. A read contaminates nothing, and B being served the object
            we filed in its name is a second principal's observation of the
            effect rather than a restatement of our own reference.
        control_self: Arm 1 — the liveness control.
        control_absent: Arm 2 — the never-issued control.
        anonymous: Arm 4 — the sessionless write.
        crossing: Arm 3 — the payload.
        recorder: The arms as dispatched, for the order assertion and the lines.
        caller_identity: A's identity values, from A's own session.
        held_identities: Every OTHER principal's identity values, by label.
        principals_available: How many principals the run holds.
        principals_required: How many the registry says this class needs.
        tier: ``multi_role`` / ``single_role``, as the run counted it.
        absent_reference: ``ref(∅)``, so the control's landing can be checked
            against the value it actually carried.

    Returns:
        The verdict. ``confirmed`` is only ever True with every arm dispatched,
        both controls refusing, the anonymous arm failing, and the persisted
        crossing object attributed to a principal that is not the caller.
    """
    lines = tuple(_arm_line(recorder.get(arm), arm) for arm in ARM_DISPATCH_ORDER)

    def refuse(detail: str, *, why: str = "", inverted: bool = False) -> WriteCrossingVerdict:
        return WriteCrossingVerdict(
            confirmed=False,
            tier=tier,
            why_unconfirmed=why,
            detail=detail,
            arms_detail=lines,
            arms_inverted=inverted,
        )

    # 0. The arms went out in the declared order. Asserted on what was RECORDED,
    #    not on what the caller meant, for the reason the read oracle re-asserts
    #    its references on what was sent: a class that can get the order wrong
    #    eventually does, and the artifact of getting it wrong looks exactly like
    #    the artifact of getting it right.
    if not recorder.dispatch_order_holds():
        return refuse(
            "ARMS INVERTED: the arms were dispatched in the order "
            f"{[a.value for a in recorder.sequence]}, and this oracle requires "
            f"{[a.value for a in ARM_DISPATCH_ORDER]} — the attribution source and both "
            "controls must precede a write whose effect outlives the request",
            why=REFERENCE_NOT_OWNED,
            inverted=True,
        )

    # 1. An un-sent control cannot license an irreversible write.
    if control_absent is None or not control_absent.dispatched:
        return refuse(
            "the never-issued control could not be dispatched, so nothing licensed the "
            "payload — an arm that was not sent refused nothing",
            why=CONTROL_ABSENT_NOT_DISPATCHED,
        )

    # 2. The never-issued control landed ATTRIBUTED TO NOBODY ⇒ refuse. The
    #    handler is storing an opaque string; the crossing is that same storage.
    if control_absent.landed():
        absent_owner = stable_fields(control_absent.persisted_body)
        if any(v.strip() == absent_reference.strip() for v in absent_owner.values()):
            return refuse(
                "the never-issued control landed carrying a reference nobody owns, so the "
                "handler is storing the owner field as an opaque string rather than "
                "honouring it — the crossing arm would be that same string storage",
                why=CONTROL_ABSENT_LANDED,
            )

    # 3. The liveness control must attribute A's own object to A.
    if control_self is None or not control_self.landed():
        return refuse(
            "the liveness control did not land an object attributed to the caller, so this "
            "endpoint was never shown to honour the owning field from this principal in "
            "this shape — an object attributed to another principal would be a coincidence",
            why=CONTROL_SELF_DID_NOT_ATTRIBUTE,
        )
    mine = {v.strip() for v in caller_identity if v.strip()}
    self_owner = owning_fields(control_self.persisted_body, principal_values=frozenset(mine))
    if not self_owner:
        return refuse(
            "the object the caller wrote for itself names no owner, so this endpoint's "
            "records cannot be attributed to anybody",
            why=OBJECT_NAMES_NO_OWNER,
        )
    if not any(value in mine for value in self_owner.values()):
        if control_self.owner_value_sent.strip() not in {v.strip() for v in self_owner.values()}:
            return refuse(
                "the liveness control landed, and the persisted object does not carry the "
                "owner value the caller sent — the endpoint accepted the field and did not "
                "honour it, which is the server correctly overriding a client-supplied owner",
                why=CONTROL_SELF_DID_NOT_ATTRIBUTE,
            )

    # 4. The anonymous arm. Never dispatched ⇒ abstain; succeeded ⇒ disqualify.
    if anonymous is None or not anonymous.dispatched:
        return refuse(
            "the anonymous arm was never sent, so nothing established that this endpoint "
            "requires a session at all — an arm that was not dispatched refused nothing",
            why=ANONYMOUS_ARM_NOT_DISPATCHED,
        )
    if anonymous.landed():
        return refuse(
            "an unauthenticated request created an object attributed to the other "
            "principal, so the caller's session was not what crossed anything — this "
            "endpoint is open, which is a different finding with a different remediation",
            why=ANONYMOUS_WRITE_SUCCEEDED,
        )

    # 5. The crossing, read back and attributed off the PERSISTED object.
    if crossing is None or not crossing.landed():
        return refuse(
            "the crossing write was not located in a subsequent read of the collection, so "
            "there is no persisted object to attribute — an unobserved outcome, not a "
            "negative one",
            why=NOT_READABLE_BACK,
        )
    claim: OwnerClaim | None = owner_claim(
        crossing_body=crossing.persisted_body,
        self_body=control_self.persisted_body,
        caller_identity=caller_identity,
        held_identities=held_identities,
    )
    if claim is None:
        return refuse(
            "the persisted crossing object names no owner other than the caller, so the "
            "write was not attributed to anybody else",
            why=OBJECT_NAMES_NO_OWNER,
        )

    # B's own authorized read of the object we filed in B's name. Keyed on the
    # marker this attempt minted, so what corroborates is THIS write rather than
    # any row that happens to carry the same owner value.
    corroborated = bool(
        owner_read is not None
        and owner_read.dispatched
        and crossing.created.marker
        and crossing.created.marker in (corroborating_body or "")
    )

    if principals_available < principals_required:
        return refuse(
            f"the write landed attributed to another principal via {claim.field}, and this "
            f"run holds {principals_available} of the {principals_required} principals the "
            "registry requires to attribute it",
            why=REQUIRES_SECOND_PRINCIPAL,
        )

    # OWNING_FIELD_NOT_CALLER is the weaker route: it says the value is not the
    # caller's and differs from the caller's own record, which a shared or
    # sequence-allocated value satisfies too. The doc requires arm 5 to
    # corroborate before it may confirm; without corroboration it is a lead.
    if claim.route == OWNING_FIELD_NOT_CALLER and not corroborated:
        return refuse(
            f"the persisted object's owning field {claim.field} carries a value that is "
            "neither the caller's nor what the caller's own object carries, and B's own "
            "authorized read did not corroborate that the value is B's",
            why=REQUIRES_SECOND_PRINCIPAL,
        )

    return WriteCrossingVerdict(
        confirmed=True,
        tier=tier,
        attribution=claim.route,
        attributing_fields=(claim.evidence,) if claim.evidence else (),
        owning_field=claim.field,
        detail=(
            f"a write dispatched as the least-privileged principal created an object that a "
            f"SEPARATE read of the collection attributes to "
            f"{claim.principal or 'a principal that is not the caller'} through the owning "
            f"field {claim.field}"
            + (
                " (route: the owning value is an identity this engagement holds)"
                if claim.route == OWNING_FIELD_NAMES_PRINCIPAL
                else " (route: the owning value is neither the caller's nor what the "
                "caller's own object carries, corroborated by the owner's authorized read)"
            )
        ),
        arms_detail=lines,
        corroborated=corroborated,
    )


def reference_format(value: str) -> str:
    """Classify a reference's SHAPE, for :func:`synthesize_absent_reference`.

    The read oracle gets this from its phase-2 fingerprint, which this class has
    no equivalent of: it never sweeps a parameter, it reads one value off an
    object the application served. So the shape is classified from the value
    itself — and only the shape, because that is all
    ``synthesize_absent_reference`` needs in order to build a control that
    round-trips exactly as the real reference does and differs only in
    ownership.

    Returns:
        ``numeric`` / ``uuid`` / ``opaque``, using the same vocabulary
        :func:`~clinkz.agents._idor_oracle.synthesize_absent_reference` reads.
    """
    stripped = (value or "").strip()
    if stripped.isdigit():
        return "numeric"
    if len(stripped) == 36 and stripped.count("-") == 4:
        return "uuid"
    return "opaque"


class ControlArmNotDispatchedError(RuntimeError):
    """This class's own never-issued control probe never reached the target.

    Raised out of the class's ``oracle_confirms`` callback so
    ``_dispatch_control_probe`` records ``dispatched=False`` — which is what
    makes ``_run_control_arm_first`` skip the confirming half.

    It exists because the carrier does not raise: ``_http_post_json`` catches its
    own transport failures and returns ``status=0``, so a control that never went
    out would otherwise reach the seam as an arm that was sent and simply did not
    land — i.e. as a control that REFUSED, licensing a payload nothing licensed.
    An un-sent control and a control the server rejected are opposite facts, and
    for this class the difference is an irreversible write into another
    principal's data.
    """
