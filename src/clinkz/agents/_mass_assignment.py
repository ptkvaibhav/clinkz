"""Mass assignment: a field the client never offers, honoured by the server.

Distinct from IDOR, which tests object ACCESS — whether principal A can read
principal B's record. This tests object CREATION and MODIFICATION: whether a
request may set a property the application never exposes, because the handler
binds the whole request body onto its model.

**The defining effect is the read-back, not the status code.** A ``201 Created``
proves the record was created; it says nothing about whether the extra field was
stored or silently dropped, and almost every framework drops it silently. So the
confirmation is: create with the field, read the object back, and see the value
we chose. And that read-back needs its own control, because a field appearing in
a response might be a default the server always sets — so the SAME create is
repeated **omitting** the field, and the control must come back without it (or
with a different value). Two records, one difference, one field.

That is three requests to confirm one field, and it is three requests because a
cheaper shape confirms something else:

  * status-only: proves the endpoint exists;
  * echo-in-response: proves the handler reflects its input, which many do
    before discarding it;
  * read-back without a control: proves the field has that value, not that WE
    set it.

**This class writes to the target**, which nothing else in the surface-mapping
path does. It is gated at :func:`clinkz.safety.destructive.classify_form_submission`
like every other submission, the created records are ordinary application
records (never a credential or account mutation), and every request is
state-changing and therefore lands in the action log. The engagement can answer
"what did it do to my app?" with the exact list.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

#: Field names whose value is an authorization or accounting decision — the ones
#: worth testing, because setting them from the request IS the vulnerability.
#:
#: These are the nouns an API uses for "who is this" and "what is it worth", not
#: any application's vocabulary. A name here is only a CANDIDATE: it is tested
#: only when the client never offers it, and it confirms only on a read-back
#: differential.
_PRIVILEGED_FIELD_TOKENS: frozenset[str] = frozenset(
    {
        # Authorization
        "role", "roles", "admin", "isadmin", "is_admin", "superuser", "privilege",
        "privileges", "permission", "permissions", "scope", "scopes", "group",
        "groups", "authority", "authorities", "level", "accesslevel", "usertype",
        # Ownership / identity binding
        "owner", "ownerid", "userid", "user_id", "accountid", "account_id",
        "tenant", "tenantid", "organization", "orgid", "createdby", "author",
        # Accounting / state a client must not choose
        "price", "amount", "total", "cost", "discount", "balance", "credit",
        "quantity", "status", "state", "verified", "isverified", "approved",
        "active", "enabled", "deleted", "confirmed", "paid",
    }
)  # fmt: skip

#: Values to attempt per field family. Chosen to be unmistakable on read-back and
#: harmless if honoured: a role of ``clinkz-probe-admin`` grants nothing on any
#: real system, and a price of ``0.01`` is a value the app's own schema accepts.
#: A payload that would grant real privilege is not needed to prove the binding.
_PROBE_VALUES: tuple[tuple[frozenset[str], str], ...] = (
    (
        frozenset({"role", "roles", "usertype", "authority", "authorities", "group", "groups"}),
        "clinkz-probe-role",
    ),
    (
        frozenset(
            {"admin", "isadmin", "is_admin", "superuser", "verified", "isverified",
             "approved", "active", "enabled", "confirmed", "paid"}
        ),
        "true",
    ),
    (
        frozenset({"price", "amount", "total", "cost", "discount", "balance", "credit"}),
        "0.01",
    ),
    (frozenset({"quantity"}), "1"),
    (frozenset({"status", "state", "level", "accesslevel", "privilege"}), "clinkz-probe-state"),
)  # fmt: skip

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _normalise(name: str) -> str:
    """``is_Admin`` / ``is-admin`` / ``isAdmin`` → ``isadmin``."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name or "")
    return "".join(_TOKEN_SPLIT_RE.split(spaced.lower()))


class AssignmentCandidate(BaseModel):
    """One field worth attempting, and the value to attempt it with.

    Attributes:
        field: The field name to add to the request, spelled as the API would.
        value: The probe value — unmistakable on read-back, harmless if honoured.
        why: Why this field is a candidate, for the evidence.
    """

    field: str
    value: str
    why: str = ""


def probe_value_for(field: str) -> str:
    """The value to attempt for *field*."""
    normalised = _normalise(field)
    for names, value in _PROBE_VALUES:
        if normalised in names:
            return value
    return "clinkz-probe-value"


def candidate_fields(
    *,
    client_offered: list[str],
    observed_object_fields: list[str],
) -> list[AssignmentCandidate]:
    """Fields the SERVER's own object shows but the CLIENT never offers.

    The two-sided derivation is what keeps this general and keeps it honest.
    The candidate set is not a guess about what the application might call its
    role field — it is read from the application's own representation of the
    object (a ``GET`` of the collection, which the schema learner already
    fetches). Subtracting what the client offers is what makes the field
    *unofferable*, which is the whole claim: a field the form already has is not
    mass assignment, it is the form.

    A field the server never shows is not proposed at all. Guessing field names
    would send writes that cannot be confirmed either way — and a write that
    cannot be confirmed is target state changed for nothing.

    Args:
        client_offered: Field names the client actually offers — form inputs,
            the documented request body, the fields a create form posts.
        observed_object_fields: Field names present in the server's own
            representation of this object type.

    Returns:
        Candidates in deterministic order (privileged-token match first, then
        alphabetical), so two runs plan the same probes.
    """
    offered = {_normalise(name) for name in client_offered if name}
    candidates: list[AssignmentCandidate] = []
    for raw in observed_object_fields:
        name = (raw or "").strip()
        if not name:
            continue
        normalised = _normalise(name)
        if not normalised or normalised in offered:
            continue
        if normalised not in _PRIVILEGED_FIELD_TOKENS:
            continue
        candidates.append(
            AssignmentCandidate(
                field=name,
                value=probe_value_for(name),
                why=(
                    f"the server's own representation of this object carries {name!r}, "
                    f"and the client offers no way to set it"
                ),
            )
        )
    candidates.sort(key=lambda c: c.field.lower())
    return candidates


class ReadBackVerdict(BaseModel):
    """Whether the read-back proves WE set the field.

    Attributes:
        honoured: The probe object carries our value AND the control does not.
            The only state that may confirm.
        probe_value_present: Our value came back on the probe object.
        control_value_present: Our value came back on the CONTROL object too —
            which means the server sets it regardless of us, so the probe proves
            nothing about our request.
        detail: One sentence for the evidence.
    """

    honoured: bool = False
    probe_value_present: bool = False
    control_value_present: bool = False
    detail: str = ""


def evaluate_read_back(
    *,
    field: str,
    probe_value: str,
    probe_object: dict | None,
    control_object: dict | None,
) -> ReadBackVerdict:
    """Compare the probe read-back against the control read-back.

    Args:
        field: The field under test.
        probe_value: The value the probe request tried to set.
        probe_object: The created object, read back, from the request that
            CARRIED the field.
        control_object: The created object, read back, from an otherwise
            identical request that OMITTED it.

    Returns:
        A verdict that is ``honoured`` only when the probe object carries our
        value and the control object does not.
    """
    if not probe_object:
        return ReadBackVerdict(detail="the created object could not be read back")

    probe_present = _field_equals(probe_object, field, probe_value)
    control_present = _field_equals(control_object or {}, field, probe_value)

    if not probe_present:
        return ReadBackVerdict(
            probe_value_present=False,
            control_value_present=control_present,
            detail=(
                f"the object was created but {field!r} did not come back as "
                f"{probe_value!r} — the server dropped the field, which is the "
                f"binding working correctly"
            ),
        )
    if control_present:
        return ReadBackVerdict(
            probe_value_present=True,
            control_value_present=True,
            detail=(
                f"{field!r} came back as {probe_value!r} on the probe AND on the "
                f"control that never sent it, so the server sets this value "
                f"itself — our request is not what put it there"
            ),
        )
    return ReadBackVerdict(
        honoured=True,
        probe_value_present=True,
        control_value_present=False,
        detail=(
            f"{field!r} came back as {probe_value!r} on the object created by the "
            f"request that carried it, and did NOT come back on the control "
            f"created by an otherwise identical request that omitted it"
        ),
    )


def _field_equals(obj: dict, field: str, value: str) -> bool:
    """Whether *obj* carries *field* with *value*, comparing loosely on type.

    The server round-trips ``"true"`` as a boolean and ``"0.01"`` as a float, so
    a strict string compare would miss every honoured probe. Compared as
    lowercased strings after normalising the field name, since an API may return
    ``isAdmin`` for a field it accepted as ``is_admin``.
    """
    if not obj:
        return False
    wanted = _normalise(field)
    target = str(value).strip().lower()
    for key, raw in obj.items():
        if _normalise(str(key)) != wanted:
            continue
        got = str(raw).strip().lower()
        if got == target:
            return True
        # Numeric equality: 0.01 == "0.01" == 0.010
        try:
            if float(got) == float(target):
                return True
        except (TypeError, ValueError):
            pass
    return False


__all__ = [
    "AssignmentCandidate",
    "ReadBackVerdict",
    "candidate_fields",
    "evaluate_read_back",
    "probe_value_for",
]
