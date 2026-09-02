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
``self``         A, ``ref(A)``      A's own object, ANCHORED to A's identity —
                                    never the value the crawl happened to see
``crossing``     A, ``ref(B)``      an object positively attributable to B
``nonexistent``  A, ``ref(∅)``      must differ materially from ``crossing``
``anonymous``    no session,        must NOT return it — if it does, the object
                 ``ref(B)``         is public and there is no boundary
===============  =================  ==========================================

``ref(B)`` is made attributable by a fifth observation that is not a control:
**B's own authorized read** of the same reference. That is what "belonging" means
operationally, and it is why the class cannot confirm with one principal.

**Which identity is A is the other half of the claim.** Every arm above is
satisfied by an administrator being served a customer's record, and in most
applications that is the feature rather than the flaw. So A is the LEAST
privileged identity the engagement holds, from the operator's own declared rank
(:func:`~clinkz.agents._principal.privilege_order`) — dispatched that way there
is no role the caller holds that authorizes the read. An undeclared rank is
reported as undeclared and the crossing becomes a lead: guessing the hierarchy
out of a role LABEL would manufacture exactly the false positive this rule
exists to prevent, on the commonest client engagement there is — one supplied
admin or service account.

**``ref(A)`` is A's, or there is no crossing to grade.** The self arm used to
carry whatever value the CRAWL observed in the parameter, and phase 3 produced
``ref(B)`` by incrementing it. On the 2026-08-31 Juice Shop envelope the crawl
saw ``1``, A was ``jim`` — who is user **2** — and the increment landed on
``2``: the self arm read admin's basket and the crossing arm read A's own. Every
downstream arm then cleared, because they are all comparisons and a comparison
does not know which side it is standing on. A crawl-observed value is a fact
about the CRAWLER's session, not about A, and the only reference this oracle may
call ``ref(A)`` is one A is observed to own from A's own session
(:func:`anchor_self_reference`). **Unanchorable ⇒ the class abstains**: a
crossing you cannot anchor is not a crossing, and the arms are asserted distinct
and correctly attributed before the verdict is read.

**Attribution comes off the OBJECT, not off a comparison of two renderings.**
``identical_rendering`` — the crossing response fingerprinting equal to B's own
authorized read — was the ground truth, and it is vacuous in the direction the
direction rule requires. A is the LEAST privileged identity and B therefore
outranks it; an administrator reading A's record returns A's record, so
"identical to B's read" is satisfied by *B can also read this*, which is the
feature. Both halves of the spec cannot hold at once, and it was the attribution
half that was wrong. The claim now rests on an **owning field** — a field the
application itself uses to name a record's owner (``UserId``, ``email``,
``author``), carrying a value that is not the caller's
(:func:`owner_claim`). ``UserId: 1`` in a body served to user 2 is unforgeable
in a way a fingerprint comparison is not. B's own read is kept, dispatched and
reported, as **corroboration**. **No owning field ⇒ abstain**, which is also
what retires the public-catalogue shape without a decoration-tolerant differ: a
public record has no owning principal to name.

**An anonymous 200 on ``ref(B)`` is disqualifying, full stop.** It used to be
one input to :func:`materially_differs`, so a per-caller ``"liked":true``
decoration on the same review — 13 bytes, same ``_id`` — made the anonymous arm
"differ" and the crossing confirmed against a record anyone may read. If an
anonymous caller is served the resource there is no boundary to cross, whatever
else the bytes do. An anonymous arm that was never DISPATCHED proves nothing in
either direction and abstains, the same rule
:class:`~clinkz.agents._control_arm.ControlVerdict` applies to every other arm.

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

from clinkz.agents._principal import PRIVILEGE_ORDER_UNDECLARED
from clinkz.engagement.credential_shapes import fingerprint

__all__ = [
    "ANCHOR_NOT_ESTABLISHED",
    "ANONYMOUS_ARM_NOT_DISPATCHED",
    "ATTRIBUTION_IDENTICAL_RENDERING",
    "ATTRIBUTION_STABLE_FIELDS",
    "MIN_ATTRIBUTING_FIELDS",
    "NO_OWNING_FIELD",
    "OWNER_FIELD_NAME_TOKENS",
    "OWNING_FIELD_NAMES_PRINCIPAL",
    "OWNING_FIELD_NOT_CALLER",
    "TIER_MULTI_ROLE",
    "TIER_SINGLE_ROLE",
    "ArmObservation",
    "ArmRecorder",
    "IDORArm",
    "IDORVerdict",
    "OwnerClaim",
    "SelfAnchor",
    "anchor_self_reference",
    "attribution_between",
    "decide_idor",
    "idor_body_fingerprint",
    "idor_normalise_body",
    "materially_differs",
    "names_the_caller",
    "owner_claim",
    "owning_fields",
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
            # A key carrying a ``.`` is bracketed, because otherwise the joined
            # path cannot be split back into segments — and one of those segments
            # may be an identifier the evidence must not reproduce. A map keyed
            # by ``victim@corp.example`` would split into ``victim@corp`` and
            # ``example``, and fingerprinting the first leaves the second in the
            # deliverable. Bracket notation is what a JSON path already uses for
            # a key that is not a bare name.
            name = str(key)
            segment = f"[{name}]" if "." in name else name
            _json_leaves(value, f"{prefix}.{segment}" if prefix else segment, out)
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
        ``(route, attributing_fields)``. ``("", ())`` when the crossing response
        is not attributable to B at all — which is not a weaker finding, it is a
        different response, and the caller moves on.

        Each attributing field is rendered as
        ``field=<name> owner_fp=<hash> caller_fp=<hash|absent>`` — the field NAME
        and a salted fingerprint, never the value. The value is the one piece of
        the target's own data an IDOR finding has ever carried, and on a client
        engagement it is a real customer's email or postal address in a document
        that gets emailed. Bounding it to 80 characters bounded volume, not
        sensitivity. The claim the values were carrying is *this field came back
        identical to B's own read and differs from A's*, and two fingerprints
        make exactly that claim — the same trade
        :attr:`~clinkz.agents._auth_bypass.AuthArtifact.principal` already makes
        for a captured credential.
    """
    if not owner_body or not crossing_body:
        return "", ()

    if idor_body_fingerprint(owner_body) == idor_body_fingerprint(crossing_body):
        return ATTRIBUTION_IDENTICAL_RENDERING, ()

    owner = stable_fields(owner_body)
    crossing = stable_fields(crossing_body)
    caller = stable_fields(self_body)
    mine = {v.strip() for v in caller.values()}

    matched: list[str] = []
    for key, value in owner.items():
        if not _attributing(value):
            continue
        if value.strip() in mine:
            continue
        if crossing.get(key, "").strip() == value.strip():
            matched.append(_attributing_field_line(key, value.strip(), caller.get(key)))
    if len(matched) < MIN_ATTRIBUTING_FIELDS:
        return "", ()
    return ATTRIBUTION_STABLE_FIELDS, tuple(sorted(matched))


def _attributing_field_line(field: str, owner_value: str, caller_value: str | None) -> str:
    """One attributing field as names and fingerprints, carrying no target data.

    ``caller_fp`` is deliberately part of the line rather than left implicit:
    "the owner's value came back" is only half the claim, and the half that makes
    it a BOUNDARY crossing is that the caller's own record holds something else —
    or holds nothing under that field at all, which is ``absent``.

    The field NAME survives because it is schema, not data: ``billing.email`` is
    the application's own vocabulary and is what a remediation has to name. The
    fingerprint is per-process salted, so two lines in one bundle can be compared
    and nothing in it can be replayed or reversed.

    A path segment is only schema while the object it indexes is a RECORD. An
    API that returns a **map keyed by the record's own identifier** —
    ``{"accounts": {"victim@corp.example": {...}}}`` — puts the identifier in the
    path, so fingerprinting the values alone still reproduced a victim's email
    verbatim. Identifier-shaped segments are therefore fingerprinted too; see
    :func:`_schema_path`.
    """
    caller = (caller_value or "").strip()
    caller_fp = fingerprint(caller) if caller else "absent"
    return f"field={_schema_path(field)} owner_fp={fingerprint(owner_value)} caller_fp={caller_fp}"


#: A path segment that is DATA rather than schema. Each alternative is an
#: identifier shape a field name does not have: an address (``@``), a UUID, a
#: bare number, a long hex run, or any run of five or more digits — which is an
#: account number or an order reference, and is not ``line1``, ``address2``,
#: ``sha256`` or ``oauth2``.
_IDENTIFIER_SEGMENT: re.Pattern[str] = re.compile(
    r"^[^\s]*@[^\s]*$"
    r"|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    r"|^\d+$"
    r"|^[0-9a-fA-F]{12,}$"
    r"|\d{5,}"
)


def _schema_path(path: str) -> str:
    """*path* with any identifier-shaped segment replaced by a fingerprint.

    The dot-joined leaf path is the application's vocabulary right up until the
    application keys a map by the record's identifier, at which point one segment
    of it is the very data this evidence must not reproduce. Fingerprinting that
    segment keeps the path readable as a shape (``accounts.<id:a3f…>.iban`` still
    names the field a remediation has to fix) and keeps the correlation — the
    same identifier fingerprints the same way inside one bundle.

    List indices (``items[0].sku``) are positions, not identifiers, and are left
    alone.
    """
    segments = _path_segments(path)
    if not any(_IDENTIFIER_SEGMENT.search(segment) for segment in segments):
        return path
    return ".".join(
        f"<id:{fingerprint(segment.strip('[]'))}>"
        if _IDENTIFIER_SEGMENT.search(segment)
        else segment
        for segment in segments
    )


def _path_segments(path: str) -> list[str]:
    """Split a leaf path on the dots that SEPARATE segments, not the ones inside one.

    ``str.split(".")`` cannot do this: ``_json_leaves`` brackets a key containing
    a dot precisely so the path stays splittable, and a naive split would tear
    ``[victim@corp.example]`` in half — leaving the domain in the deliverable
    after the local part had been fingerprinted.
    """
    segments: list[str] = []
    current: list[str] = []
    depth = 0
    for char in path:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char == "." and depth == 0:
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
    segments.append("".join(current))
    return segments


# ---------------------------------------------------------------------------
# The owning field — who does the OBJECT say it belongs to?
# ---------------------------------------------------------------------------

#: Substrings that make a field name the application's own way of saying WHO
#: OWNS a record.
#:
#: This is a field-SELECTION vocabulary and nothing more: it decides which of a
#: body's fields is worth reading, never whether a crossing happened. That is
#: what makes a hand-maintained list safe here, against the guard-domain law's
#: usual objection — every direction it can be wrong in costs coverage. A name
#: it does not know is a field that is not read, so the endpoint ABSTAINS; a
#: name it knows that turns out to be uninteresting still has to carry a value
#: differing from the caller's own record before it says anything. An omission
#: can never license a confirmation, only withhold one.
#:
#: ``role`` and ``group`` are deliberately absent. They name what a principal
#: IS, not which principal a record belongs to, and Juice Shop's user records
#: carry ``role: "customer"`` on every customer — a value that differs from an
#: admin caller's and identifies nobody.
OWNER_FIELD_NAME_TOKENS: tuple[str, ...] = (
    "userid",
    "user_id",
    "user",
    "ownerid",
    "owner_id",
    "owner",
    "accountid",
    "account_id",
    "customerid",
    "customer_id",
    "author",
    "createdby",
    "created_by",
    "submittedby",
    "submitted_by",
    "email",
    "username",
    "principal",
    "subject",
)

#: Everything that is not a letter or a digit in a field name, so ``UserId``,
#: ``user_id`` and ``user-id`` are one name.
_FIELD_NAME_NOISE: re.Pattern[str] = re.compile(r"[^a-z0-9]+")


def _field_owns(path: str) -> bool:
    """Whether *path*'s LEAF name is one an application uses to name an owner.

    The leaf only. Matching the joined path would let a container called
    ``user`` make every leaf beneath it an owning field, so ``user.createdAt``
    would name an owner and carry a timestamp.
    """
    segments = [seg for seg in _path_segments(path) if seg]
    if not segments:
        return False
    leaf = _FIELD_NAME_NOISE.sub("", segments[-1].strip("[]").lower())
    # A list index (``[0]``) is a position, not a name; step back to the field
    # it indexes, which is what ``data[0].author`` is really called.
    if leaf.isdigit() and len(segments) > 1:
        leaf = _FIELD_NAME_NOISE.sub("", segments[-2].strip("[]").lower())
    if not leaf:
        return False
    return any(token.replace("_", "") in leaf for token in OWNER_FIELD_NAME_TOKENS)


def owning_fields(
    body: str,
    *,
    principal_values: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """The ``field -> value`` pairs by which *body* names its record's owner.

    Two admissions, and the second is the one that does not depend on a
    vocabulary at all:

    1. **The field NAME is one an application uses to name an owner**
       (:data:`OWNER_FIELD_NAME_TOKENS`). ``UserId: 1`` qualifies on its name,
       which is why a single-digit value is not filtered out here: an
       identifier is short and that is what identifiers are.
    2. **The field VALUE is an identity WE hold.** ``First name: bob`` on a
       target with no owner-shaped field anywhere names bob if bob is a
       principal of this engagement — and nothing about the field's name was
       needed to know it. This route is the one that cannot be wrong in the
       dangerous direction, because the comparison is against
       :meth:`~clinkz.agents._principal.Principal.identity_tokens`, read from
       session material we hold rather than from the response.

    Route 2 keeps a minimum length so a one-character value cannot name a
    principal by coincidence, and deliberately does NOT apply
    :data:`_GENERIC_VALUES`: ``admin`` is on that list and is also the username
    of the principal every second engagement supplies. Genericness is a guess
    about whether a value identifies anybody; an exact match against an identity
    we hold is not a guess.

    Args:
        body: The response body, verbatim.
        principal_values: Identity values of principals this engagement holds —
            the caller's when anchoring, everyone's when attributing.

    Returns:
        Owning fields keyed by leaf path. **Empty when the body names no
        owner**, which is the answer for a public catalogue record and is why a
        public record cannot be crossed into: there is nobody it belongs to.
    """
    known = {v.strip() for v in principal_values if v.strip()}
    owners: dict[str, str] = {}
    for path, raw in stable_fields(body).items():
        value = raw.strip()
        if not value:
            continue
        if _field_owns(path):
            owners[path] = value
        elif value in known and len(value) >= _MIN_ATTRIBUTING_VALUE_LEN:
            owners[path] = value
    return owners


#: The owning field's value IS a principal this engagement holds a session for,
#: and it is not the caller. The strongest form available: the engine knows its
#: own identities, so nothing the target sends can manufacture this.
OWNING_FIELD_NAMES_PRINCIPAL = "owning_field_names_principal"

#: The owning field carries a value that is none of the caller's identity values
#: and is not what the caller's OWN anchored record carries under that same
#: field. The object names an owner and the owner is not us.
OWNING_FIELD_NOT_CALLER = "owning_field_not_caller"


@dataclass(frozen=True)
class OwnerClaim:
    """Who the crossing response says its record belongs to.

    Attributes:
        route: :data:`OWNING_FIELD_NAMES_PRINCIPAL` or
            :data:`OWNING_FIELD_NOT_CALLER`.
        field: Schema path of the owning field, identifier segments
            fingerprinted (:func:`_schema_path`).
        principal: The held principal the value names, under
            :data:`OWNING_FIELD_NAMES_PRINCIPAL`. Empty otherwise — an owner we
            hold no session for is still an owner.
        evidence: The rendered ``field=… owner_fp=… caller_fp=…`` line. Names
            and salted fingerprints only, never a value.
    """

    route: str
    field: str
    principal: str = ""
    evidence: str = ""


def owner_claim(
    *,
    crossing_body: str,
    self_body: str,
    caller_identity: frozenset[str],
    held_identities: dict[str, frozenset[str]],
) -> OwnerClaim | None:
    """Read the owning principal off the crossing RESPONSE, or return ``None``.

    This is the ground truth an IDOR confirmation now rests on. It replaced
    ``identical_rendering`` — the crossing response fingerprinting equal to B's
    own authorized read — which is vacuous exactly where the direction rule puts
    us: A is the least-privileged identity, B therefore outranks it, and B
    reading A's record returns A's record. "Matches B's read" then proves *B can
    also read this*, which in most applications is what B is for. Direction
    needs A least-privileged and attribution-by-owner_read needs B not to
    outrank A; both cannot hold, and it was the attribution half that was wrong.

    Two routes, in strength order:

    1. :data:`OWNING_FIELD_NAMES_PRINCIPAL` — the owning value is an identity
       this engagement holds and it is not the caller's
       (``email: admin@juice-sh.op`` in a body served to jim). Unforgeable: the
       comparison is against what WE hold, so no response can satisfy it by
       choosing its own bytes.
    2. :data:`OWNING_FIELD_NOT_CALLER` — the owning value is none of the
       caller's identity values AND differs from what the caller's own anchored
       record carries under the same field (``UserId: 1`` where the caller's own
       record says ``UserId: 2``). The caller's record is the reference point,
       which is why the self arm must be ANCHORED before this may be asked.

    Args:
        crossing_body: What A was served for ``ref(B)``.
        self_body: What A was served for its OWN anchored reference.
        caller_identity: A's identity values, read from A's own session
            (:meth:`~clinkz.agents._principal.Principal.identity_tokens`).
        held_identities: Every OTHER principal's identity values, by label.

    Returns:
        The claim, or ``None`` when the body names no owner other than the
        caller — an abstain, not a weaker finding.
    """
    everyone: set[str] = {v.strip() for v in caller_identity if v.strip()}
    for tokens in held_identities.values():
        everyone.update(v.strip() for v in tokens if v.strip())
    owners = owning_fields(crossing_body, principal_values=frozenset(everyone))
    if not owners:
        return None
    mine = {v.strip() for v in caller_identity if v.strip()}
    caller_record = stable_fields(self_body)

    # Route 1 first: a value checkable against our OWN identities beats one
    # checkable only against the caller's record.
    for path, value in sorted(owners.items()):
        if value in mine:
            continue
        for label, tokens in sorted(held_identities.items()):
            if value in tokens:
                return OwnerClaim(
                    route=OWNING_FIELD_NAMES_PRINCIPAL,
                    field=_schema_path(path),
                    principal=label,
                    evidence=_attributing_field_line(path, value, caller_record.get(path)),
                )

    for path, value in sorted(owners.items()):
        if value in mine:
            continue
        # Route 2 needs the application's OWN owner vocabulary. A field admitted
        # only because its value named some principal has already been offered to
        # route 1 and declined, so grading it here would be attribution by
        # difference — which is ``stable_fields`` again, and is what the
        # ``identical_rendering`` defect was.
        if not _field_owns(path):
            continue
        # The caller's OWN record under the same field. ABSENT is not evidence:
        # a field the caller's record does not carry says nothing about whom the
        # crossing record belongs to, and reading absence as difference is how
        # an envelope key present only on populated records would confirm.
        ours = caller_record.get(path, "").strip()
        if not ours or ours == value:
            continue
        return OwnerClaim(
            route=OWNING_FIELD_NOT_CALLER,
            field=_schema_path(path),
            evidence=_attributing_field_line(path, value, ours),
        )
    return None


def names_the_caller(body: str, caller_identity: frozenset[str]) -> str:
    """The owning field by which *body* says it belongs to the CALLER, or ``""``.

    The other half of :func:`owner_claim`, and the reason it is a separate
    function: "is this my own record?" and "whose is it?" are the same question
    asked in two directions, and the first one has to be answered **before** the
    normalised fingerprint is consulted.

    :func:`idor_normalise_body` folds every digit run to ``0``, which was
    deliberate and cost nothing while attribution was a comparison of
    renderings. It is not free any more: the commonest owning field there is is
    a NUMBER (``UserId: 1``), so two records differing only in whose they are
    normalise equal, and the "we just re-read A's own object" step would refuse
    a genuine crossing. Asking the owner first fixes that without weakening the
    fingerprint, which still does the job it is good at — telling one rendering
    of a record from another.

    Args:
        body: The response body, verbatim.
        caller_identity: The caller's identity values, from its own session.

    Returns:
        The schema path of the owning field carrying one of the caller's
        identity values, or ``""``.
    """
    mine = {v.strip() for v in caller_identity if v.strip()}
    if not mine:
        return ""
    for path, value in sorted(owning_fields(body, principal_values=frozenset(mine)).items()):
        if value in mine:
            return _schema_path(path)
    return ""


# ---------------------------------------------------------------------------
# ref(A) — the reference A actually owns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SelfAnchor:
    """Which reference is A's own, and how that was established.

    Attributes:
        anchored: Whether A's own reference was established at all. ``False``
            means the class ABSTAINS: the self arm would otherwise carry a value
            observed under somebody else's session, and every arm downstream is
            a comparison that cannot tell which side it is standing on.
        reference: The anchored ``ref(A)``.
        field: The owning field that carried A's identity, for the evidence.
        why: One sentence, for the trace and the lead.
    """

    anchored: bool
    reference: str = ""
    field: str = ""
    why: str = ""


def anchor_self_reference(
    *,
    candidates: tuple[tuple[str, str], ...],
    caller_identity: frozenset[str],
) -> SelfAnchor:
    """Pick the reference A OWNS out of references probed AS A.

    A record is A's when it names A as its owner — the same owning-field
    vocabulary the crossing arm is graded on, pointed at the caller instead. The
    comparison is against A's identity values, which come from A's own session
    material and never from a response, so a target cannot nominate one of its
    records as ours.

    Args:
        candidates: ``(reference, body)`` for each reference probed AS A, in
            preference order. Only bodies A was actually served belong here: a
            404's body names no owner and would anchor nothing anyway.
        caller_identity: A's identity values.

    Returns:
        The anchor. ``anchored`` is False when no candidate names A — the honest
        answer for a reference that is not user-owned at all (a product id), for
        an endpoint whose records do not name their owner, and for a session
        whose identity we cannot read (an opaque cookie and no username).
    """
    mine = {v.strip() for v in caller_identity if v.strip()}
    if not mine:
        return SelfAnchor(
            anchored=False,
            why=(
                "the caller's own identity is unreadable from the session material we hold "
                "(no supplied username, no identity claim in a bearer token), so no "
                "reference can be shown to be the caller's"
            ),
        )
    for reference, body in candidates:
        if not reference or not body:
            continue
        for path, value in sorted(owning_fields(body, principal_values=frozenset(mine)).items()):
            if value in mine:
                return SelfAnchor(
                    anchored=True,
                    reference=reference,
                    field=_schema_path(path),
                    why=(
                        f"reference {reference!r} returned a record naming the caller as its "
                        f"owner under {_schema_path(path)}"
                    ),
                )
    probed = len([c for c in candidates if c[1]])
    return SelfAnchor(
        anchored=False,
        why=(
            f"none of the {probed} reference(s) probed as the caller returned a record "
            "naming the caller as its owner, so the caller's own reference could not be "
            "established — a crossing that cannot be anchored is not a crossing"
        ),
    )


#: Shortest reference :func:`reflection_explains` will accept as evidence of an
#: echo. Four characters is long enough that a body containing it plausibly
#: echoed it, and short enough to keep every opaque token and UUID in scope.
_MIN_ECHOABLE_REFERENCE_LEN = 4


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

    **A SHORT reference cannot establish an echo**, and that is not a
    refinement. Substitution is global: with ``ref(A)="2"`` and
    ``ref(B)="1"``, rewriting every ``1`` in ``{"id":1,"UserId":1}`` produces
    ``{"id":2,"UserId":2}`` — which IS A's record, byte for byte, so the guard
    fires on the textbook sequential-integer crossing and calls the whole class
    a reflection sink. What the test needs is a value distinctive enough that
    finding it in the body means the body echoed it, and a one- or two-character
    identifier is not that. :data:`_MIN_ECHOABLE_REFERENCE_LEN` is the floor;
    below it the guard abstains, which costs nothing — a reflection sink whose
    parameter takes a two-character value is caught by phase 1's dedicated
    canary probe, which uses a minted token precisely so this cannot happen.
    """
    if not crossing.reference or not self_arm.reference:
        return False
    if len(crossing.reference) < _MIN_ECHOABLE_REFERENCE_LEN:
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
        attribution: The OWNING-FIELD route that attributed the crossing
            response to somebody other than the caller
            (:data:`OWNING_FIELD_NAMES_PRINCIPAL` /
            :data:`OWNING_FIELD_NOT_CALLER`), or ``""``. This is the claim.
        attributing_fields: The fields that did it, as
            ``field=<name> owner_fp=<hash> caller_fp=<hash|absent>``. Names and
            salted fingerprints only — see :func:`_attributing_field_line`.
        why_unconfirmed: The closed-vocabulary lead reason, or ``""``.
        detail: One sentence for the trace, the lead, and the evidence.
        arms_detail: Per-arm one-liners, rendered into the finding so a reviewer
            can re-derive the verdict rather than take it on trust.
        anchored: Whether ``ref(A)`` was established from A's own identity
            rather than taken from the crawl.
        anchor_detail: How, or why not.
        owning_field: The schema path of the field naming the owner.
        corroboration: What B's own authorized read added
            (:data:`ATTRIBUTION_IDENTICAL_RENDERING` /
            :data:`ATTRIBUTION_STABLE_FIELDS`), or ``""``. **Never the ground
            truth** — recorded because a second principal agreeing is worth
            reporting, and load-bearing in no branch.
        arms_inverted: The dispatch assertion failed — the self arm and the
            crossing arm carried the same reference, or the self arm carried
            something other than the anchored ``ref(A)``. A loud refusal, never
            a quiet abstain: it means the run asked the wrong question.
    """

    confirmed: bool
    tier: str
    attribution: str = ""
    attributing_fields: tuple[str, ...] = ()
    why_unconfirmed: str = ""
    detail: str = ""
    arms_detail: tuple[str, ...] = ()
    control_refused: bool = False
    object_is_public: bool = False
    anchored: bool = False
    anchor_detail: str = ""
    owning_field: str = ""
    corroboration: str = ""
    arms_inverted: bool = False


#: The tier names, so the registry, the agent and the tests spell them once.
TIER_MULTI_ROLE = "multi_role"
TIER_SINGLE_ROLE = "single_role"

#: ``ref(A)`` could not be shown to be A's own. Registered in
#: :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED`.
ANCHOR_NOT_ESTABLISHED = "self_reference_not_anchored_to_the_caller"

#: The anonymous arm was never sent, so it refused nothing. An arm that was not
#: dispatched proves nothing in either direction — the same rule
#: :class:`~clinkz.agents._control_arm.ControlVerdict` applies to every control.
ANONYMOUS_ARM_NOT_DISPATCHED = "anonymous_control_arm_not_dispatched"

#: The crossing response names no owner other than the caller.
NO_OWNING_FIELD = "crossing_response_names_no_owning_principal"


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
    anchor: SelfAnchor,
    caller_identity: frozenset[str],
    held_identities: dict[str, frozenset[str]],
    principals_available: int,
    principals_required: int,
    single_role_why: str,
    privilege_order_known: bool = True,
    privilege_why: str = "",
) -> IDORVerdict:
    """Grade the arms.

    The order below is the order a reviewer would ask the questions in, and each
    step is a different fact about the target:

    0. Is ``ref(A)`` A's? An unanchored self arm carries whatever the CRAWL saw
       under somebody else's session, and every step after this is a comparison
       that cannot tell which side it is standing on. Unanchored ⇒ abstain. Then
       the dispatch assertion: the self and crossing arms must carry DIFFERENT
       references and the self arm must carry the anchored one. A violation is a
       loud refusal, because it means the run asked the wrong question.
    1. Did the crossing arm resolve at all? No ⇒ nothing happened.
    2. Is the object PUBLIC? An anonymous caller — no session material at all —
       being served the resource is DISQUALIFYING, full stop: if anonymous gets
       it there is no boundary to cross, whatever else the bytes do. This used
       to be one input to :func:`materially_differs`, so a per-caller
       ``"liked":true`` decoration on the same review made the anonymous arm
       "differ" and the crossing confirmed against a public record. An anonymous
       arm that was never DISPATCHED refused nothing and abstains.
    3. Did the control refuse (``ref(∅)`` differs materially from ``ref(B)``)?
       No ⇒ the endpoint answers the same for any reference and the crossing
       response was never evidence. This is a control-arm KILL and discloses.
    4. Is the crossing response A's own object? Yes ⇒ we re-read A's record.
       And is the difference from A's own just our reference echoed back? A
       reflection sink defeats every other arm at once, so it gets its own step.
    5. Does the OBJECT name an owner, and is that owner somebody other than the
       caller? This is the claim (:func:`owner_claim`). No owning field ⇒
       abstain: three negatives ("not A's, not nobody's, not everybody's") are
       satisfied by a shared record behind a login exactly as well as by another
       principal's record.
    6. Which DIRECTION did the arm run in? Every step above is satisfied by an
       administrator reading a customer's record, which is the application
       working. A crossing is evidence only when the caller holds no role that
       authorizes the read, so the arm must be dispatched from an identity that
       does not outrank the owner — a fact about the operator's declared
       hierarchy, not about the response.

    **The tier rule sits between 5 and 6** and is unchanged: the registry
    declares how many principals confirming needs, and a run holding fewer may
    only lead. B's own authorized read is still dispatched, and is now
    CORROBORATION rather than the ground truth — see :func:`owner_claim` for why
    the two halves of the old spec could not both hold.

    Args:
        self_arm: As A, the ANCHORED ``ref(A)``.
        crossing: As A, ``ref(B)``.
        nonexistent: As A, ``ref(∅)``.
        anonymous: No session, ``ref(B)``.
        owner_read: As B, ``ref(B)``. ``None`` in the single-role tier. B is a
            principal the engagement HOLDS that A does not outrank — it is a
            CANDIDATE owner, and on any run where ``ref(B)`` was reached by
            incrementing the anchor it is generally not the actual owner. So
            what this arm establishes is that a SECOND principal is served the
            same record, which rules out a per-caller decoration; it is not the
            owner's own read and the detail sentence does not call it one.
        anchor: How ``ref(A)`` was established (:func:`anchor_self_reference`).
        caller_identity: A's identity values, from A's own session.
        held_identities: Every other principal's identity values, by label.
        principals_available: How many authenticated principals the run holds.
        principals_required: How many the registry says confirming needs.
        single_role_why: The registry's declared lead reason for having fewer.
        privilege_order_known: Whether the operator declared a rank for every
            principal that could take part, so the caller is known not to
            outrank the owner (:func:`~clinkz.agents._principal.privilege_order`).
            Defaults True, which is the honest answer for the callers that hold
            fewer than two principals and therefore have no pair to order — and
            those callers are refused one step earlier anyway.
        privilege_why: What was undeclared, for the lead.

    Returns:
        The verdict. ``confirmed`` is only ever True with ``ref(A)`` anchored,
        every arm cleared, an owning field naming somebody other than the
        caller, ``principals_available >= principals_required`` AND a known
        direction.
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
        kwargs.setdefault("anchored", anchor.anchored)
        kwargs.setdefault("anchor_detail", anchor.why)
        return IDORVerdict(tier=tier, arms_detail=arms, **kwargs)

    # 0. The anchor. ``ref(A)`` must be a reference A OWNS, established from A's
    #    own session — not the value the crawl happened to see under whichever
    #    identity was crawling. Without it the self arm is another principal's
    #    record and the "crossing" arm may be A's own, which is exactly what
    #    engagement 20fad9dc shipped five times.
    if not anchor.anchored:
        return verdict(
            confirmed=False,
            why_unconfirmed=ANCHOR_NOT_ESTABLISHED,
            detail=(
                "the caller's own reference could not be established, so no arm can be "
                f"attributed: {anchor.why}"
            ),
        )

    # 0b. The dispatch assertion, re-derived here rather than trusted. If the
    #     self arm is not carrying the anchored reference, or the two arms carry
    #     the same one, the arms are inverted or collapsed and the run asked a
    #     different question from the one it is about to answer.
    if self_arm.reference != anchor.reference or self_arm.reference == crossing.reference:
        return verdict(
            confirmed=False,
            arms_inverted=True,
            why_unconfirmed=ANCHOR_NOT_ESTABLISHED,
            detail=(
                f"ARMS INVERTED: the self arm carried {self_arm.reference!r} and the "
                f"crossing arm {crossing.reference!r}, while the caller's own anchored "
                f"reference is {anchor.reference!r} — the arms do not answer the question "
                "this oracle grades and the result is refused"
            ),
        )

    if not crossing.resolves():
        return verdict(
            confirmed=False,
            detail=(
                f"the crossing arm was not served a resource (dispatched="
                f"{crossing.dispatched} status={crossing.status}) — nothing was crossed"
            ),
        )

    # 2. Public object. DISQUALIFYING rather than one input to a difference
    #    test: on ``/rest/products/2/reviews`` an anonymous caller was served
    #    the same review — same ``_id`` — decorated with a per-caller
    #    ``"liked":true``, 13 bytes that made ``materially_differs`` True and
    #    let a public record confirm. If anonymous gets it there is no boundary.
    if not anonymous.dispatched:
        return verdict(
            confirmed=False,
            why_unconfirmed=ANONYMOUS_ARM_NOT_DISPATCHED,
            detail=(
                "the anonymous arm was never dispatched, so nothing established that the "
                "resource is not simply public — an arm that was not sent refused nothing"
            ),
        )
    if anonymous.resolves():
        return verdict(
            confirmed=False,
            object_is_public=True,
            detail=(
                "the anonymous arm — no session material at all — was served the resource "
                f"(status={anonymous.status}, {len(anonymous.body or '')} bytes), so the "
                "object is public and there is no authorization boundary to cross"
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

    # 4. A's own object, read back. The OWNING FIELD is asked first and the
    #    fingerprint only when the body names no owner, because
    #    ``idor_normalise_body`` folds digit runs and the commonest owning field
    #    is a number: ``{"id":1,"UserId":1}`` and ``{"id":2,"UserId":2}``
    #    normalise to the same string, so a fingerprint-only test refuses the
    #    textbook crossing as "we re-read our own record". The folding stays —
    #    it is what makes two renderings of ONE record compare equal — and the
    #    question it cannot answer is asked of the owner instead.
    caller_owns = names_the_caller(crossing.body or "", caller_identity)
    if caller_owns:
        return verdict(
            confirmed=False,
            control_refused=True,
            detail=(
                f"the record returned for {crossing.reference!r} names the caller as its "
                f"owner under {caller_owns} — it is A's own object and no boundary was "
                "crossed"
            ),
        )
    if (
        not owning_fields(crossing.body or "", principal_values=caller_identity)
        and self_arm.resolves()
        and not materially_differs(self_arm, crossing)
    ):
        return verdict(
            confirmed=False,
            control_refused=True,
            detail=(
                f"the crossing arm returned the same resource as {self_arm.reference!r}, "
                "which is A's own object — no boundary was crossed"
            ),
        )

    # 5. The owning field. The claim rests HERE — on what the object says about
    #    itself — and not on a comparison with B's read, which an outranking B
    #    satisfies by being allowed to read A's records.
    claim = owner_claim(
        crossing_body=crossing.body or "",
        self_body=self_arm.body or "",
        caller_identity=caller_identity,
        held_identities=held_identities,
    )

    # 4b. Reflection, asked only of a body that names NO owner. The crossing
    #     body differs from A's only by the reference we injected, so the
    #     parameter echoed us rather than selecting an object. Not a lead — this
    #     is not an access-control candidate at all, the same verdict phase 1
    #     gives a pure reflection sink. A response carrying an owning field is a
    #     RECORD by the same reading that attributes it, and asking whether a
    #     record is an echo of its own identifier is a question with a
    #     misleading answer: substitution is global, so rewriting the owner's id
    #     into the caller's turns the owner's record into the caller's.
    if claim is None and reflection_explains(crossing, self_arm):
        return verdict(
            confirmed=False,
            control_refused=control_refused,
            detail=(
                f"the crossing response differs from {self_arm.reference!r}'s only by the "
                f"reference {crossing.reference!r} echoed back into it — the parameter is a "
                "reflection sink, not an object reference"
            ),
        )

    if claim is None:
        return verdict(
            confirmed=False,
            control_refused=True,
            why_unconfirmed=NO_OWNING_FIELD,
            detail=(
                f"the response to {crossing.reference!r} differs from the caller's own "
                "record, from a never-issued reference of the same shape and from what an "
                "anonymous caller is served — but it names no owning principal other than "
                "the caller, so there is nobody it can be said to belong to; three "
                "negatives are satisfied by a shared record behind a login exactly as well "
                "as by another principal's record"
            ),
        )

    # B's own authorized read. CORROBORATION only: it is dispatched, recorded
    # and reported, and no branch below turns on it.
    corroboration = ""
    if owner_read is not None and owner_read.resolves():
        corroboration, _ = attribution_between(
            owner_body=owner_read.body or "",
            crossing_body=crossing.body or "",
            self_body=self_arm.body or "",
        )

    fields = (claim.evidence,) if claim.evidence else ()

    # The tier rule. Declared by the registry, counted here.
    if tier == TIER_SINGLE_ROLE:
        return verdict(
            confirmed=False,
            control_refused=True,
            attribution=claim.route,
            attributing_fields=fields,
            owning_field=claim.field,
            corroboration=corroboration,
            why_unconfirmed=single_role_why,
            detail=(
                f"{principals_available} authenticated principal(s) available, "
                f"{principals_required} required: reference {crossing.reference!r} returned "
                f"a record naming {claim.field} as its owner, which is not the caller — but "
                "with a single role there is no second authorized read to corroborate it "
                "against, and this tier may only lead"
            ),
        )

    # 6. Direction.
    if not privilege_order_known:
        return verdict(
            confirmed=False,
            control_refused=True,
            attribution=claim.route,
            attributing_fields=fields,
            owning_field=claim.field,
            corroboration=corroboration,
            why_unconfirmed=PRIVILEGE_ORDER_UNDECLARED,
            detail=(
                f"as {self_arm.principal}, reference {crossing.reference!r} returned a "
                f"record naming an owner other than the caller under {claim.field} "
                f"({claim.route}) — but {privilege_why or 'the privilege order was not declared'}, "
                "so this cannot be told apart from a more privileged caller legitimately "
                "reading a less privileged one's record"
            ),
        )

    named = f" ({claim.principal})" if claim.principal else ""
    return verdict(
        confirmed=True,
        control_refused=True,
        attribution=claim.route,
        attributing_fields=fields,
        owning_field=claim.field,
        corroboration=corroboration,
        detail=(
            f"as {self_arm.principal}, whose own anchored reference is "
            f"{anchor.reference!r}, reference {crossing.reference!r} returned a record "
            f"naming a different owner under {claim.field}{named} ({claim.route}); the "
            f"never-issued reference {nonexistent.reference!r} did not return it "
            f"(status={nonexistent.status}) and neither did an anonymous caller "
            f"(status={anonymous.status}); "
            + (
                # NOT "the owner's own read". The arm is dispatched as B, and B is
                # a principal the engagement HOLDS that A does not outrank —
                # while ref(B) comes from incrementing the anchored ref(A), so the
                # record it lands on belongs to whoever owns it. On engagement
                # aba713f1 all three crossings named user 3 under the owning field
                # while this arm ran as admin. What it shows is that a second
                # principal is served the same record, which rules out a
                # per-caller decoration; naming that principal the owner claimed
                # something the run's own arms contradict.
                f"a second principal's authorized read of the same reference "
                f"({owner_read.principal if owner_read is not None else 'B'}) returns "
                f"the same record ({corroboration})"
                if corroboration
                else "a second principal's authorized read did not corroborate it, "
                "which the claim does not rest on"
            )
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
