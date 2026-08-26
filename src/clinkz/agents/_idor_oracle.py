"""The four-arm IDOR oracle — pure logic, offline-testable.

An IDOR confirmation is a claim that **principal A read an object belonging to
principal B**. Everything that is hard about proving it is in the word
*belonging*: a response that differs from A's own is not evidence, because a
public catalogue record differs from A's own too, and so does an error page, and
so does the next row of a table anyone may read.

**What was here before, and why 92% of the corpus died on it.** The old phase 5
opened with a precondition: phase 2 sent an out-of-allotment reference
(``id=99999999`` / the all-zero UUID) and required the target to REFUSE it,
otherwise "the endpoint returns whatever reference it is given — a public lookup,
nothing to bypass". Over 2,955 recorded engagements that gate consumed **616 of
668 phase-5 refusals**, and phase 2 recorded ``authz_check_present`` False on
**1,226 of 1,256** fingerprints. The gate is not merely strict, it is backwards:
an application that answers 404 for an id nobody owns and 200 for a neighbour's
record is *discriminating perfectly* — it is the textbook IDOR — and that is
precisely the shape the precondition reads as "no boundary exists".

**The inversion.** ``ref(∅)`` stops being the precondition and becomes the
CONTROL. Four arms, dispatched:

===============  =================  ==========================================
arm              carried as         what it must show
===============  =================  ==========================================
``self``         A, ``ref(A)``      A's own object — the identity values that
                                    must NOT be what the crossing arm returned
``crossing``     A, ``ref(B)``      an object positively attributable to B
``nonexistent``  A, ``ref(∅)``      must differ materially from ``crossing``
``anonymous``    no session,        must NOT return it — if it does, the object
                 ``ref(B)``         is public and there is no boundary
===============  =================  ==========================================

``ref(B)`` is made attributable by a fifth observation that is not a control:
**B's own authorized read** of the same reference. That is what "belonging" means
operationally, and it is why the class cannot confirm with one principal.

**The decoy must round-trip like the payload.** ``ref(∅)`` is compared against
``ref(B)`` through the same handler, the same encoder and the same template. A
bare marker (``clinkzdecoyidor48211``) is encoding-invariant: it fails to parse
as an identifier, takes the target's generic error path, differs from everything,
and would therefore pass this control on a vulnerable target and a phantom alike.
So ``ref(∅)`` is synthesized in the reference's OWN shape — numeric far outside
the issued range, a fresh v4 for a UUID, the same length and character classes
for an opaque token — and the only thing that distinguishes it from ``ref(B)`` is
that nobody owns it.

Nothing in this module performs I/O. It takes what the arms observed and returns
a verdict, so the whole decision table is testable against recorded response
pairs from stored bundles.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "ATTRIBUTION_IDENTICAL_RENDERING",
    "ATTRIBUTION_STABLE_FIELDS",
    "MIN_ATTRIBUTING_FIELDS",
    "TIER_MULTI_ROLE",
    "TIER_SINGLE_ROLE",
    "ArmObservation",
    "ArmRecorder",
    "IDORArm",
    "IDORVerdict",
    "attribution_between",
    "decide_idor",
    "idor_body_fingerprint",
    "idor_normalise_body",
    "materially_differs",
    "reflection_explains",
    "stable_fields",
    "synthesize_absent_reference",
]


class IDORArm(StrEnum):
    """The arms, named once so the trace, the evidence and the tests agree."""

    #: As A, ``ref(A)``. The owned object. Harvests A's own identity values.
    SELF = "self"
    #: As A, ``ref(B)``. The candidate crossing.
    CROSSING = "crossing"
    #: As A, ``ref(∅)``. The never-issued reference — the control.
    NONEXISTENT = "nonexistent"
    #: No session at all, ``ref(B)``. Proves the object is not simply public.
    ANONYMOUS = "anonymous"
    #: As B, ``ref(B)``. Not a control: the attribution source. This is the arm
    #: a single-role engagement cannot dispatch, and therefore the reason a
    #: single-role engagement may not confirm.
    OWNER_READ = "owner_read"


#: The crossing arm returned the same record B's own read returned, rendered the
#: same way. The strongest attribution available in band, and the ordinary shape
#: when both principals reach one object through one handler.
ATTRIBUTION_IDENTICAL_RENDERING = "identical_rendering"

#: The renderings differ (an envelope naming the caller, a nav bar carrying A's
#: name) but B's own field VALUES are present in what A was served, and they are
#: not values A's own record carries.
ATTRIBUTION_STABLE_FIELDS = "stable_fields"

#: How many attributing field values a stable-field match needs.
#:
#: One is not attribution. Two records rendered by one template share ``"Male"``,
#: ``"active"``, a currency symbol and every label on the page; a single shared
#: value is a property of the template, not of the principal. Two distinct values
#: that B's record carries, A's does not, and A was nevertheless served is a
#: claim about the object rather than about the page.
MIN_ATTRIBUTING_FIELDS = 2

#: Values too short or too generic to attribute anything. Length alone is not
#: enough — ``"1"`` is short and ``"true"`` is not — so both are excluded.
_MIN_ATTRIBUTING_VALUE_LEN = 3
_GENERIC_VALUES: frozenset[str] = frozenset(
    {
        "true",
        "false",
        "null",
        "none",
        "yes",
        "no",
        "male",
        "female",
        "other",
        "active",
        "inactive",
        "enabled",
        "disabled",
        "pending",
        "user",
        "admin",
        "guest",
        "default",
        "unknown",
        "n/a",
        "na",
    }
)

#: ``Label: value`` pairs in an HTML/text rendering. Bounded on both sides so a
#: paragraph of prose does not become a hundred spurious "fields".
_LABEL_VALUE_RE: re.Pattern[str] = re.compile(
    r"([A-Za-z][A-Za-z0-9 _-]{0,30}?)\s*:\s*([^<>\n\r|]{1,120}?)\s*(?:<|\n|\r|\||$)"
)

#: An HTML tag, stripped before text-pair extraction.
_TAG_RE: re.Pattern[str] = re.compile(r"<[^>]+>")


def idor_normalise_body(body: str) -> str:
    """Fold everything about a body that varies between two reads of one record.

    Long hex/alnum runs (CSRF tokens, session ids, ETags, hashes) go first, then
    every remaining digit run, then whitespace, then case. Two renders of the
    same record therefore normalise equal even when a timestamp, a counter or a
    per-request token differs, while two different records — different WORDS — do
    not.

    Digits are folded deliberately and it costs nothing here: the identifier
    under test is carried by the arm, not read back out of the body, and two
    records that differ only in a number differ in nothing this oracle is
    entitled to call attribution.
    """
    normalized = re.sub(r"[0-9a-fA-F]{16,}", "0", body)
    normalized = re.sub(r"\d+", "0", normalized)
    return re.sub(r"\s+", " ", normalized).strip().lower()


def idor_body_fingerprint(body: str) -> str:
    """Stable short hash of :func:`idor_normalise_body`.

    The engine's ONE body-shape rule for access-control comparisons. It lived on
    the Exploit Agent as ``_idor_body_fingerprint``; the agent now calls this, so
    the arms and the tests fold the same things.
    """
    return hashlib.sha1(  # noqa: S324  # non-crypto shape fingerprint, not a security control
        idor_normalise_body(body).encode("utf-8", errors="replace"), usedforsecurity=False
    ).hexdigest()[:16]


def _json_leaves(node: Any, prefix: str, out: dict[str, str]) -> None:
    """Flatten JSON leaves into ``path -> value``, containers excluded.

    Only leaves, for the same reason ``set_json_path`` only writes leaves: a
    container's "value" is the object holding the fields under test, so matching
    on one would call an entire response body a single attributing field.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            _json_leaves(value, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _json_leaves(value, f"{prefix}[{index}]", out)
    elif node is not None:
        out[prefix or "(root)"] = str(node)


def stable_fields(body: str) -> dict[str, str]:
    """The identity-bearing ``field -> value`` pairs a body renders.

    JSON is flattened to leaf paths. Anything else is read for ``Label: value``
    pairs after tags are stripped, which is what a server-rendered record
    actually looks like — DVWA's ``First name: admin``, a profile table, a
    receipt.

    Values are returned verbatim, NOT normalised: normalisation exists to make
    two renders of one record compare equal, and applying it here would fold the
    account numbers and reference ids that are the most attributing values on the
    page. Volatility is handled by requiring the value to be absent from A's own
    record, which a per-request token cannot satisfy twice in a row.
    """
    trimmed = (body or "").strip()
    if trimmed[:1] in ("{", "["):
        try:
            parsed = json.loads(trimmed)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if parsed is not None:
            out: dict[str, str] = {}
            _json_leaves(parsed, "", out)
            return out

    text = _TAG_RE.sub("\n", body or "")
    pairs: dict[str, str] = {}
    for label, value in _LABEL_VALUE_RE.findall(text):
        key = label.strip().lower()
        val = value.strip()
        if key and val and key not in pairs:
            pairs[key] = val
    return pairs


def _attributing(value: str) -> bool:
    """Whether *value* is specific enough to attribute a record to a principal."""
    stripped = value.strip()
    if len(stripped) < _MIN_ATTRIBUTING_VALUE_LEN:
        return False
    return stripped.lower() not in _GENERIC_VALUES


def attribution_between(
    *,
    owner_body: str,
    crossing_body: str,
    self_body: str,
) -> tuple[str, tuple[str, ...]]:
    """How, if at all, *crossing_body* is attributable to the owner of *owner_body*.

    Two routes, in strength order:

    1. **Identical rendering.** The crossing arm and B's own authorized read
       normalise to the same fingerprint. One handler served one record to two
       principals; the only difference is who asked.
    2. **Stable fields.** The renderings differ — an API envelope naming the
       caller, a page whose chrome carries A's own name — but values B's record
       carries, and A's does not, came back to A. Requires
       :data:`MIN_ATTRIBUTING_FIELDS` distinct such values.

    Subtracting A's own record is the load-bearing half of route 2 and the reason
    it is not just "the bodies overlap": every field the template renders for
    everybody is in A's record too, so the residue is what is specific to B.

    Args:
        owner_body: What B's own authorized read returned.
        crossing_body: What A was served for ``ref(B)``.
        self_body: What A was served for ``ref(A)``.

    Returns:
        ``(route, attributing_values)``. ``("", ())`` when the crossing response
        is not attributable to B at all — which is not a weaker finding, it is a
        different response, and the caller moves on.
    """
    if not owner_body or not crossing_body:
        return "", ()

    if idor_body_fingerprint(owner_body) == idor_body_fingerprint(crossing_body):
        return ATTRIBUTION_IDENTICAL_RENDERING, ()

    owner = stable_fields(owner_body)
    crossing = stable_fields(crossing_body)
    mine = {v.strip() for v in stable_fields(self_body).values()}

    matched: list[str] = []
    for key, value in owner.items():
        if not _attributing(value):
            continue
        if value.strip() in mine:
            continue
        if crossing.get(key, "").strip() == value.strip():
            matched.append(f"{key}={value.strip()}")
    if len(matched) < MIN_ATTRIBUTING_FIELDS:
        return "", ()
    return ATTRIBUTION_STABLE_FIELDS, tuple(sorted(matched))


def reflection_explains(crossing: ArmObservation, self_arm: ArmObservation) -> bool:
    """Whether the crossing arm's divergence is just our own reference echoed back.

    ``Welcome longreference123 to your dashboard`` differs from
    ``Welcome x to your dashboard`` and is not a different OBJECT — the parameter
    is a reflection sink, and the only thing that changed is the value we sent.

    Phase 1 already excludes a pure reflection sink before any of this runs. This
    is the case phase 1 cannot see: a parameter that reflects SOME inputs and
    selects a resource for others, where the reflection is what the crossing arm
    happened to land on. It matters more here than it did under the old oracle,
    because a reflection sink defeats every other arm at once — a never-issued
    reference is reflected too (so the control refuses, correctly, on a
    *different* string) and the owner's read of the same reference reflects the
    same string back (so it looks like an identical rendering). Three arms
    agreeing on an artifact of one substitution is not three pieces of evidence.

    Substituting A's own reference back in for the echoed one and comparing
    normalised bodies is the same test ``_idor_reflection_only_divergence``
    makes in phase 1, and the echo guard the injection classes make on their own
    payloads.
    """
    if not crossing.reference or not self_arm.reference:
        return False
    if not crossing.body or not self_arm.body:
        return False
    if crossing.reference not in crossing.body:
        return False
    reconstructed = crossing.body.replace(crossing.reference, self_arm.reference)
    return idor_body_fingerprint(reconstructed) == idor_body_fingerprint(self_arm.body)


def materially_differs(left: ArmObservation, right: ArmObservation) -> bool:
    """Whether two arms saw meaningfully different things.

    Status class first, then the normalised fingerprint. Length is deliberately
    NOT a criterion: two records of the same shape are routinely the same length,
    and a length delta is a correlate of difference rather than difference — the
    same reason ``assert_authenticated`` refuses a body-length delta as a
    boundary discriminator.
    """
    if left.status != right.status:
        return True
    return left.fingerprint() != right.fingerprint()


@dataclass(frozen=True)
class ArmObservation:
    """What one dispatched arm saw.

    Attributes:
        arm: Which arm this is.
        dispatched: Whether the request actually went out. An arm that was not
            sent proves nothing and is never read as a refusal — the same rule as
            :class:`~clinkz.agents._control_arm.ControlVerdict`.
        status: HTTP status, or 0 when nothing came back.
        body: The response body, verbatim.
        reference: The reference value this arm carried.
        principal: Label of the identity it was sent as, or
            :data:`~clinkz.agents._principal.ANONYMOUS`.
    """

    arm: IDORArm
    dispatched: bool
    status: int
    body: str
    reference: str
    principal: str

    def resolves(self) -> bool:
        """Whether this arm was served a resource at all."""
        return self.dispatched and self.status in (200, 201, 202, 206) and bool(self.body)

    def fingerprint(self) -> str:
        return idor_body_fingerprint(self.body or "")


@dataclass(frozen=True)
class IDORVerdict:
    """The oracle's answer, and why.

    Attributes:
        confirmed: Whether every arm cleared. Only ever True in the multi-role
            tier — see :attr:`tier`.
        tier: ``"multi_role"`` or ``"single_role"``. Declared by the registry
            (:class:`~clinkz.models.vuln_classes.MultiPrincipalRequirement`), not
            decided here; this records which one the run was in.
        attribution: Which route attributed the crossing response to B, or ``""``.
        attributing_values: The specific ``field=value`` pairs that did it.
        why_unconfirmed: The closed-vocabulary lead reason, or ``""``.
        detail: One sentence for the trace, the lead, and the evidence.
        arms_detail: Per-arm one-liners, rendered into the finding so a reviewer
            can re-derive the verdict rather than take it on trust.
    """

    confirmed: bool
    tier: str
    attribution: str = ""
    attributing_values: tuple[str, ...] = ()
    why_unconfirmed: str = ""
    detail: str = ""
    arms_detail: tuple[str, ...] = ()
    control_refused: bool = False
    object_is_public: bool = False


#: The tier names, so the registry, the agent and the tests spell them once.
TIER_MULTI_ROLE = "multi_role"
TIER_SINGLE_ROLE = "single_role"


def _arm_line(obs: ArmObservation | None, arm: IDORArm) -> str:
    if obs is None:
        return f"{arm.value}: not dispatched"
    return (
        f"{obs.arm.value}: as {obs.principal} ref={obs.reference!r} "
        f"status={obs.status} len={len(obs.body or '')} fp={obs.fingerprint()}"
    )


def decide_idor(
    *,
    self_arm: ArmObservation,
    crossing: ArmObservation,
    nonexistent: ArmObservation,
    anonymous: ArmObservation,
    owner_read: ArmObservation | None,
    principals_available: int,
    principals_required: int,
    single_role_why: str,
) -> IDORVerdict:
    """Grade the arms.

    The order below is the order a reviewer would ask the questions in, and each
    step is a different fact about the target:

    1. Did the crossing arm resolve at all? No ⇒ nothing happened.
    2. Is the object PUBLIC (the anonymous arm was served it)? Yes ⇒ there is no
       authorization boundary here, and this is not-applicable rather than
       unproven — a lead per public endpoint would be a permanent false alarm.
    3. Did the control refuse (``ref(∅)`` differs materially from ``ref(B)``)?
       No ⇒ the endpoint answers the same for any reference and the crossing
       response was never evidence. This is a control-arm KILL and discloses.
    4. Is the crossing response A's own object? Yes ⇒ we re-read A's record.
       And is the difference from A's own just our reference echoed back? A
       reflection sink defeats every other arm at once, so it gets its own step.
    5. Is it positively attributable to B? Needs B's own authorized read, which
       needs a second principal. Without one the answer is a LEAD, never a
       finding: "not A's" is satisfied identically by a public catalogue record.

    Args:
        self_arm: As A, ``ref(A)``.
        crossing: As A, ``ref(B)``.
        nonexistent: As A, ``ref(∅)``.
        anonymous: No session, ``ref(B)``.
        owner_read: As B, ``ref(B)``. ``None`` in the single-role tier.
        principals_available: How many authenticated principals the run holds.
        principals_required: How many the registry says confirming needs.
        single_role_why: The registry's declared lead reason for having fewer.

    Returns:
        The verdict. ``confirmed`` is only ever True with every arm cleared AND
        ``principals_available >= principals_required``.
    """
    tier = TIER_MULTI_ROLE if principals_available >= principals_required else TIER_SINGLE_ROLE
    arms = tuple(
        _arm_line(obs, arm)
        for obs, arm in (
            (self_arm, IDORArm.SELF),
            (crossing, IDORArm.CROSSING),
            (nonexistent, IDORArm.NONEXISTENT),
            (anonymous, IDORArm.ANONYMOUS),
            (owner_read, IDORArm.OWNER_READ),
        )
    )

    def verdict(**kwargs: Any) -> IDORVerdict:
        return IDORVerdict(tier=tier, arms_detail=arms, **kwargs)

    if not crossing.resolves():
        return verdict(
            confirmed=False,
            detail=(
                f"the crossing arm was not served a resource (dispatched="
                f"{crossing.dispatched} status={crossing.status}) — nothing was crossed"
            ),
        )

    # 2. Public object. The anonymous arm carries NO session material at all, so
    #    being served the same record means the target hands it to anyone. There
    #    is no boundary to cross, and saying so is a statement about the endpoint
    #    rather than about our coverage.
    if anonymous.resolves() and not materially_differs(anonymous, crossing):
        return verdict(
            confirmed=False,
            object_is_public=True,
            detail=(
                "the anonymous arm — no session material at all — was served the same "
                f"resource (status={anonymous.status}), so the object is public and "
                "there is no authorization boundary to cross"
            ),
        )

    # 3. The control. ``ref(∅)`` is a reference of the same shape that nobody
    #    owns; if the endpoint answers it the same way it answered ``ref(B)``,
    #    the response is a property of the handler and not of the reference.
    control_refused = materially_differs(nonexistent, crossing)
    if not control_refused:
        return verdict(
            confirmed=False,
            why_unconfirmed="never_sent_control_did_not_refuse",
            detail=(
                f"the never-issued reference {nonexistent.reference!r} produced the same "
                f"response as {crossing.reference!r} (status={nonexistent.status}, same "
                "normalised body) — the endpoint answers identically for a reference "
                "nobody owns, so the crossing response is not evidence of access"
            ),
        )

    # 4. A's own object, read back.
    if self_arm.resolves() and not materially_differs(self_arm, crossing):
        return verdict(
            confirmed=False,
            control_refused=True,
            detail=(
                f"the crossing arm returned the same resource as {self_arm.reference!r}, "
                "which is A's own object — no boundary was crossed"
            ),
        )

    # 4b. Reflection. The crossing body differs from A's only by the reference
    #     we injected, so the parameter echoed us rather than selecting an
    #     object. Not a lead — this is not an access-control candidate at all,
    #     the same verdict phase 1 gives a pure reflection sink.
    if reflection_explains(crossing, self_arm):
        return verdict(
            confirmed=False,
            control_refused=control_refused,
            detail=(
                f"the crossing response differs from {self_arm.reference!r}'s only by the "
                f"reference {crossing.reference!r} echoed back into it — the parameter is a "
                "reflection sink, not an object reference"
            ),
        )

    # 5. Attribution. Everything above is "not A's, not nobody's, not
    #    everybody's" — three negatives that a shared record behind a login
    #    satisfies exactly as well as another principal's record does.
    if tier == TIER_SINGLE_ROLE or owner_read is None or not owner_read.resolves():
        return verdict(
            confirmed=False,
            control_refused=True,
            why_unconfirmed=single_role_why,
            detail=(
                f"{principals_available} authenticated principal(s) available, "
                f"{principals_required} required: the response differs from A's own, from a "
                "never-issued reference and from what an anonymous caller is served — but "
                "with no second principal's authorized read of the same object there is "
                "nothing to attribute it TO, and a shared record behind a login satisfies "
                "all three of those the same way another principal's record does"
            ),
        )

    route, values = attribution_between(
        owner_body=owner_read.body or "",
        crossing_body=crossing.body or "",
        self_body=self_arm.body or "",
    )
    if not route:
        return verdict(
            confirmed=False,
            control_refused=True,
            detail=(
                f"the crossing response is not attributable to {owner_read.principal}: it "
                "matches neither that principal's own authorized read of the same reference "
                "nor enough of its field values to identify the record"
            ),
        )

    return verdict(
        confirmed=True,
        control_refused=True,
        attribution=route,
        attributing_values=values,
        detail=(
            f"as {self_arm.principal}, reference {crossing.reference!r} returned the record "
            f"{owner_read.principal} is served by its own authorized read ({route}"
            + (f": {', '.join(values[:4])}" if values else "")
            + f"); the never-issued reference {nonexistent.reference!r} did not return it "
            f"(status={nonexistent.status}) and neither did an anonymous caller "
            f"(status={anonymous.status})"
        ),
    )


# ---------------------------------------------------------------------------
# ref(∅) — the never-issued reference, in the reference's own shape
# ---------------------------------------------------------------------------

_HEX_LOWER = "0123456789abcdef"
_HEX_UPPER = "0123456789ABCDEF"

#: How far past the largest identifier we have seen a numeric ``ref(∅)`` sits.
#:
#: Far enough that it cannot plausibly have been issued, near enough that it
#: stays the same KIND of value: a bare integer in the same parameter, encoded
#: byte-for-byte the way the real reference is. The old constant ``99999999``
#: is a plausible primary key on any system with eight-figure ids.
_ABSENT_NUMERIC_OFFSET = 900_000_000


def _looks_hex(template: str) -> bool:
    """Whether the WHOLE value is a hex string (dashes allowed).

    Asked of the value rather than of each character, because ``A`` is a hex
    digit and also a letter. Deciding per character made the hex pool — which
    contains digits — apply to the ``A`` in an opaque token like ``AB12-cd34``,
    so a letter could be replaced by a digit and the control stopped matching
    the real reference's character classes.
    """
    stripped = template.replace("-", "")
    return bool(stripped) and all(c in _HEX_LOWER or c in _HEX_UPPER for c in stripped)


def _perturb_char(char: str, rng: random.Random, *, hexish: bool = False) -> str:
    """A different character of the same class as *char*.

    Class-preserving is what makes the decoy round-trip: a value the target
    percent-encodes, upper-cases, or validates as hex must still be
    percent-encoded, upper-cased and valid hex after substitution, or the two
    arms differ in their ENCODING as well as in their ownership and the control
    stops being a control.

    Args:
        char: The character to replace.
        rng: Seeded RNG, so a replay re-derives the same control.
        hexish: Whether the value this character came from is hex throughout —
            see :func:`_looks_hex`. Only then may a letter become a digit.
    """
    if hexish and (char in _HEX_LOWER or char in _HEX_UPPER):
        pool = _HEX_UPPER if char.isupper() else _HEX_LOWER
    elif char.isdigit():
        pool = "0123456789"
    elif char.islower():
        pool = "abcdefghijklmnopqrstuvwxyz"
    elif char.isupper():
        pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    else:
        # Structural punctuation (a UUID's dashes, an id's separators) is part of
        # the SHAPE and is preserved exactly.
        return char
    alternatives = pool.replace(char, "")
    return rng.choice(alternatives) if alternatives else char


def synthesize_absent_reference(
    *,
    id_format: str,
    observed_values: tuple[str, ...],
    nonce: int,
    template: str = "",
) -> str:
    """A reference of the same shape as the real ones that nobody owns.

    This is the never-sent control's marker, and it obeys the same rule as every
    other control in the engine: it must differ from the confirming arm in the
    PRIMITIVE and in nothing else. For an object reference the primitive is
    ownership, so the shape, the length, the character classes and therefore the
    on-the-wire encoding all have to survive.

    Args:
        id_format: ``numeric`` / ``uuid`` / ``hashed`` / ``opaque`` / ``unknown``,
            as phase 2 classified it.
        observed_values: Every reference this endpoint was seen to accept —
            the issued range, as far as we know it.
        nonce: Caller-supplied randomness. The caller owns the RNG so this stays
            pure and the unit suite can pin it.
        template: The reference whose SHAPE the control must copy — the one the
            crossing arm carried. Passed explicitly rather than taken as
            ``observed_values[0]``, because the issued range is a SET and its
            order is an artifact of how the probes were collected: on a
            parameter whose baseline value was ``x`` and whose crossing
            reference was ``longreference123``, the first observed value
            produced a ONE-character control for a sixteen-character reference,
            which no longer round-trips the way the confirming arm did. Defaults
            to the first observed value when the caller has nothing better.

    Returns:
        A reference that is not any of *observed_values*.
    """
    rng = random.Random(nonce)  # noqa: S311  # shape synthesis, not a security control
    seen = {v for v in observed_values if v}

    if id_format == "numeric":
        highest = 0
        for value in seen:
            try:
                highest = max(highest, abs(int(value)))
            except (TypeError, ValueError):
                continue
        candidate = str(highest + _ABSENT_NUMERIC_OFFSET + rng.randint(1, 99_999))
        while candidate in seen:
            candidate = str(int(candidate) + 1)
        return candidate

    if id_format == "uuid":
        # A fresh v4: version nibble 4, variant nibble in 8-b. Built from the
        # seeded RNG rather than uuid4() so a replay of the same run synthesises
        # the same control and the trace can be re-graded offline.
        raw = [rng.choice(_HEX_LOWER) for _ in range(32)]
        raw[12] = "4"
        raw[16] = rng.choice("89ab")
        hexed = "".join(raw)
        candidate = f"{hexed[:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:]}"
        while candidate in seen:
            raw[0] = _perturb_char(raw[0], rng, hexish=True)
            hexed = "".join(raw)
            candidate = f"{hexed[:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:]}"
        return candidate

    # hashed / opaque / unknown: keep the template's own length and character
    # classes, change what it says.
    shape = template or next((v for v in observed_values if v), "") or "0000000000000000"
    hexish = _looks_hex(shape)
    for _ in range(8):
        candidate = "".join(_perturb_char(c, rng, hexish=hexish) for c in shape)
        if candidate not in seen and candidate != shape:
            return candidate
    # Every perturbation collided (a one-character alphabet, a value made
    # entirely of punctuation). Extending the shape changes its length, which
    # weakens the round-trip — so it is the LAST resort, and it is still a value
    # nobody issued.
    return shape + rng.choice("0123456789abcdef")


@dataclass
class ArmRecorder:
    """Accumulates the arms as they are dispatched, in one place.

    A mutable collector rather than five locals, so the caller cannot dispatch an
    arm and forget to pass it to :func:`decide_idor` — every arm the oracle grades
    is an arm that was recorded here, and an absent one is visibly ``None``.
    """

    observations: dict[IDORArm, ArmObservation] = field(default_factory=dict)

    def record(self, obs: ArmObservation) -> ArmObservation:
        self.observations[obs.arm] = obs
        return obs

    def get(self, arm: IDORArm) -> ArmObservation | None:
        return self.observations.get(arm)
