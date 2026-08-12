"""A constraint the application declares, and the server accepting a value that breaks it.

The Juice Shop ``NO_CLASS`` cluster — empty registration, mismatched password
repeat, out-of-range rating, oversized upload — is one class, not four. In each
case the application **declares** a rule (an HTML ``required``/``min``/``max``, a
``pattern``, a schema type) and the server does not enforce it, because the rule
lives only in the client.

**The defining effect: the server ACCEPTED a value it declares invalid.** Not
"the field had no server-side check we could see" and not "the response was
200" — accepted, meaning the request that violated the declared constraint was
processed.

**The control is what makes that meaningful, and it is the whole design.** A 200
proves acceptance only if this endpoint is capable of rejecting anything. An
endpoint that returns 200 to every request — a SPA shell, a route that does not
exist, a handler that swallows errors — would otherwise confirm on every field
of every form, forever. So each probe carries a control: a request of the SAME
shape carrying a value that is invalid in a way the server MUST reject
(a required field omitted entirely, a wrong-typed value where a number is
declared). If the control is also accepted, the endpoint demonstrates no
validation at all, we have learned nothing about this constraint, and the result
is a lead rather than a finding.

That asymmetry is deliberate: this class can only confirm on an endpoint that
has *proven it validates*, which is exactly the endpoint where "it accepted my
invalid value" is a real statement.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

#: Constraint kinds this module can both READ from a declaration and VIOLATE
#: with a concrete value. A declared constraint we cannot violate concretely is
#: not tested — proposing a probe we cannot construct would produce a request
#: whose outcome means nothing.
_SUPPORTED_KINDS: frozenset[str] = frozenset(
    {"required", "minlength", "maxlength", "min", "max", "pattern", "type"}
)


class DeclaredConstraint(BaseModel):
    """A rule the application states about one field.

    Attributes:
        field: The field the rule governs.
        kind: One of :data:`_SUPPORTED_KINDS`.
        declared: The declared bound, verbatim as the application wrote it
            (``"5"``, ``"email"``, ``"[0-9]{4}"``). Quoted into the evidence so a
            reader sees the application's own words.
        source: Where the declaration was read (``"html:input[min]"``,
            ``"openapi:schema"``). A constraint is only as good as its
            provenance.
    """

    field: str
    kind: str
    declared: str
    source: str = ""


class ConstraintProbe(BaseModel):
    """A value that violates a declared constraint, plus the control.

    Attributes:
        constraint: The rule being tested.
        violating_value: A value the application's own declaration forbids.
        control_value: A value invalid in a way any functioning handler must
            reject, used to prove this endpoint validates at all. ``None`` when
            the violation IS omission (the required-field case), where the
            control is instead a wrong-typed value supplied by the caller.
        expectation: What the server should do, for the evidence.
    """

    constraint: DeclaredConstraint
    violating_value: str
    control_value: str | None = None
    expectation: str = ""


#: The control value: a wrong-typed, structurally nonsensical payload that any
#: handler doing input validation rejects. Deliberately not an injection payload
#: — the control must be refused for being malformed, not for being hostile, or
#: a WAF answers the question instead of the handler.
CONTROL_VALUE = "clinkz-control-not-a-valid-value"


def _violating_value(constraint: DeclaredConstraint) -> str | None:
    """A concrete value that breaks *constraint*, or ``None`` if we cannot build one."""
    kind = constraint.kind.lower()
    declared = (constraint.declared or "").strip()

    if kind == "required":
        return ""  # the empty submission — Juice Shop's empty-registration shape
    if kind == "minlength":
        try:
            return "a" * max(0, int(declared) - 1)
        except ValueError:
            return None
    if kind == "maxlength":
        try:
            return "a" * (int(declared) + 1)
        except ValueError:
            return None
    if kind == "min":
        try:
            return str(float(declared) - 1).rstrip("0").rstrip(".") or "-1"
        except ValueError:
            return None
    if kind == "max":
        try:
            return str(float(declared) + 1).rstrip("0").rstrip(".")
        except ValueError:
            return None
    if kind == "type":
        # A declared type is violated by a value of a different type.
        return {
            "number": "clinkz-not-a-number",
            "email": "clinkz-not-an-email",
            "url": "not a url",
        }.get(declared.lower())
    if kind == "pattern":
        # A value that matches no non-trivial pattern. Not derived from the
        # pattern itself: constructing a guaranteed non-match from an arbitrary
        # regex is not decidable in general, and a wrong construction would send
        # a VALID value and read the acceptance as a finding.
        return "clinkz probe value" if declared else None
    return None


def build_probes(constraints: list[DeclaredConstraint]) -> list[ConstraintProbe]:
    """Turn declared constraints into violating probes, each with its control.

    Args:
        constraints: What the application declared about its own fields.

    Returns:
        One probe per constraint we can concretely violate, in deterministic
        order (field then kind). A constraint we cannot violate concretely is
        skipped rather than approximated — a probe whose value might be valid
        would read acceptance as a finding.
    """
    probes: list[ConstraintProbe] = []
    for constraint in constraints:
        if constraint.kind.lower() not in _SUPPORTED_KINDS:
            continue
        value = _violating_value(constraint)
        if value is None:
            continue
        probes.append(
            ConstraintProbe(
                constraint=constraint,
                violating_value=value,
                control_value=CONTROL_VALUE,
                expectation=(
                    f"the application declares {constraint.field!r} "
                    f"{constraint.kind}={constraint.declared!r}, so this value must be rejected"
                ),
            )
        )
    probes.sort(key=lambda p: (p.constraint.field.lower(), p.constraint.kind))
    return probes


class ValidationVerdict(BaseModel):
    """Whether the server accepted a value it declares invalid.

    Attributes:
        confirmed: The probe was accepted AND the control was rejected. The only
            state that may emit.
        probe_accepted: The violating value was processed.
        control_rejected: The endpoint proved it rejects something, so its
            acceptance of the probe is a statement about this constraint.
        detail: One sentence for the evidence.
    """

    confirmed: bool = False
    probe_accepted: bool = False
    control_rejected: bool = False
    detail: str = ""


def response_accepted(status: int, body: str) -> bool:
    """Whether a response represents the request being ACCEPTED.

    Status alone is not the answer and never has been: an API that returns 200
    with ``{"error": "..."}`` has rejected the request, and a form that
    re-renders itself with a validation message is a 200 that rejected. So a 2xx
    additionally has to be free of a rejection signature.

    Args:
        status: HTTP status.
        body: Response body.

    Returns:
        ``True`` only for a 2xx carrying no rejection signature.
    """
    if not 200 <= status < 300:
        return False
    lowered = (body or "").lower()
    rejection_markers = (
        '"error"',
        "'error'",
        "validationerror",
        "validation error",
        "is required",
        "must be",
        "invalid",
        "not allowed",
        '<div class="error',
        "field is required",
    )
    return not any(marker in lowered for marker in rejection_markers)


def evaluate(
    *,
    probe: ConstraintProbe,
    probe_status: int,
    probe_body: str,
    control_status: int,
    control_body: str,
) -> ValidationVerdict:
    """Decide whether a declared constraint is unenforced, with the control.

    Returns:
        A verdict that is ``confirmed`` only when the violating value was
        accepted and the control was rejected. If the control was ALSO accepted,
        the endpoint validates nothing observable, so the probe's acceptance
        says nothing about this constraint — that is the phantom this class
        would otherwise emit on every field of every SPA route.
    """
    probe_accepted = response_accepted(probe_status, probe_body)
    control_accepted = response_accepted(control_status, control_body)
    constraint = probe.constraint

    if not probe_accepted:
        return ValidationVerdict(
            probe_accepted=False,
            control_rejected=not control_accepted,
            detail=(
                f"the server rejected {constraint.field!r}={probe.violating_value!r} "
                f"(status {probe_status}), so it enforces its declared "
                f"{constraint.kind}={constraint.declared!r}"
            ),
        )
    if control_accepted:
        return ValidationVerdict(
            probe_accepted=True,
            control_rejected=False,
            detail=(
                f"the server accepted the violating value (status {probe_status}) but ALSO "
                f"accepted the malformed control (status {control_status}), so this endpoint "
                f"demonstrates no validation at all — its acceptance is not evidence about "
                f"{constraint.kind}={constraint.declared!r}"
            ),
        )
    return ValidationVerdict(
        confirmed=True,
        probe_accepted=True,
        control_rejected=True,
        detail=(
            f"the application declares {constraint.field!r} "
            f"{constraint.kind}={constraint.declared!r} ({constraint.source}); the server "
            f"ACCEPTED {probe.violating_value!r} (status {probe_status}) while REJECTING the "
            f"malformed control (status {control_status}), so the endpoint validates and this "
            f"constraint is not among the rules it enforces"
        ),
    )


#: HTML validation attributes, mapped to the constraint kind they declare.
#: These ARE the application's declaration — quoting them into a finding quotes
#: the application's own words about its own field, which is what makes "the
#: server accepted a value it declares invalid" a statement rather than a
#: judgement of ours.
_HTML_CONSTRAINT_ATTRS: dict[str, str] = {
    "required": "required",
    "minlength": "minlength",
    "maxlength": "maxlength",
    "min": "min",
    "max": "max",
    "pattern": "pattern",
}

_INPUT_TAG_RE = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""([a-zA-Z-]+)\s*(?:=\s*("[^"]*"|'[^']*'|[^\s>]+))?""")

#: Input types that declare a value SHAPE the server should re-check. ``text``
#: and ``password`` declare nothing, so they are not constraints.
_TYPED_INPUTS: frozenset[str] = frozenset({"number", "email", "url"})


def declared_constraints_from_html(body: str, source_url: str = "") -> list[DeclaredConstraint]:
    """Read the constraints an HTML form declares about its own fields.

    Deliberately the *page's own* attributes rather than a vocabulary of ours: a
    finding here quotes the application saying what it considers valid, and then
    shows the server disagreeing with it. A rule we invented would make the
    finding an argument about what the field ought to accept.

    Args:
        body: The page HTML.
        source_url: Recorded on each constraint's provenance.

    Returns:
        Constraints in document order, deduplicated on ``(field, kind)``.
    """
    if not body:
        return []
    constraints: list[DeclaredConstraint] = []
    seen: set[tuple[str, str]] = set()
    for tag in _INPUT_TAG_RE.finditer(body):
        attrs: dict[str, str] = {}
        for attr in _ATTR_RE.finditer(tag.group(1)):
            key = attr.group(1).lower()
            raw = attr.group(2) or ""
            attrs[key] = raw.strip("\"'")
        field = attrs.get("name") or attrs.get("id") or ""
        if not field:
            continue
        for attr_name, kind in _HTML_CONSTRAINT_ATTRS.items():
            if attr_name not in attrs:
                continue
            declared = attrs[attr_name] or "true"
            key = (field, kind)
            if key in seen:
                continue
            seen.add(key)
            constraints.append(
                DeclaredConstraint(
                    field=field,
                    kind=kind,
                    declared=declared,
                    source=f"html:{tag.group(0)[:1]}input[{attr_name}] on {source_url}".strip(),
                )
            )
        declared_type = (attrs.get("type") or "").lower()
        if declared_type in _TYPED_INPUTS and (field, "type") not in seen:
            seen.add((field, "type"))
            constraints.append(
                DeclaredConstraint(
                    field=field,
                    kind="type",
                    declared=declared_type,
                    source=f"html:input[type] on {source_url}".strip(),
                )
            )
    return constraints


__all__ = [
    "CONTROL_VALUE",
    "ConstraintProbe",
    "DeclaredConstraint",
    "ValidationVerdict",
    "build_probes",
    "declared_constraints_from_html",
    "evaluate",
    "response_accepted",
]
