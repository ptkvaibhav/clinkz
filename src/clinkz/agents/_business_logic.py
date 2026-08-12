"""Business logic — where capability exceeds what the application declares it is for.

Δ = Capability(technology) − Intent(developer), applied to the layer where the
developer's intent is *the application itself*. An API that exposes a checkout, a
discount, a quantity and a state transition has declared what it is for. The flaw
is where the capability exceeds that declaration.

**This is the class a tool most easily hallucinates.** Unusual-but-intended
behaviour looks exactly like a business-logic flaw from the outside: a
subscription that lets you set a negative balance may be a credit note; an order
that can be shipped before payment may be an invoiced customer. So the honesty
rule here is stricter than anywhere else in the engine, and it is structural:

  **Intent must be EVIDENCED from the application's own surface.** Not from what
  an application "should" do — from a field in the server's own representation of
  its own objects, from the range of values that representation actually shows,
  or from the application's own words when it rejects something. Where intent
  cannot be evidenced, the result is a research lead, never a finding. This is
  the same rule :mod:`clinkz.agents._input_validation` follows one rung down,
  where the declaration is an HTML ``min=`` and the finding quotes it verbatim.

  **Every finding states three things**: the inferred intent, the EVIDENCE for
  that inference from the app's own surface, and the observation showing
  capability exceeded it. :meth:`BusinessLogicVerdict.evidence_lines` builds all
  three, so an emit site cannot ship two of them.

The three classes built here each carry a defining effect and a control:

===========================  ==================================  ==============================
class                        defining effect                     control
===========================  ==================================  ==============================
state-sequence bypass        a terminal state reached with the   the same request in correct
                             prerequisite skipped, read back     sequence, plus a malformed
                                                                 request the endpoint refuses
constraint violation         a persisted record carrying a       the boundary value the app
                             value the app's own surface         declares valid, plus a
                             forbids                             malformed request it refuses
repeatability                a single-use action applied twice,  the app's own refusal of an
                             the SECOND effect observed          invalid instance
===========================  ==================================  ==============================
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Intent — inferred from the application's own surface, with evidence
# ---------------------------------------------------------------------------


class IntentFacet(StrEnum):
    """A dimension of what an application declares it is for.

    Attributes:
        ENTITY_TYPE: A kind of object the API manages.
        STATE_TRANSITION: A field whose values name the stages of a workflow.
        ORDERING_CONSTRAINT: One stage the application says must precede another.
        QUANTITY_BOUND: A numeric field whose observed values stay within a range
            the application evidently intends.
        OWNERSHIP_RELATION: A field binding an object to a principal.
        SINGLE_USE_ACTION: An action the application says may happen once.
    """

    ENTITY_TYPE = "entity_type"
    STATE_TRANSITION = "state_transition"
    ORDERING_CONSTRAINT = "ordering_constraint"
    QUANTITY_BOUND = "quantity_bound"
    OWNERSHIP_RELATION = "ownership_relation"
    SINGLE_USE_ACTION = "single_use_action"


class IntentAssertion(BaseModel):
    """One thing the application declares about itself, and how we know.

    Attributes:
        facet: Which dimension.
        subject: What it is about — an entity name, a field name, a route.
        statement: The inferred intent, as a sentence a client would recognise.
        evidence: What in the application's OWN surface supports it. **An
            assertion with no evidence is not usable**: :meth:`is_evidenced` is
            checked at every emit site, and an unevidenced intent downgrades a
            result to a lead rather than being quietly assumed.
        evidence_source: Where the evidence came from — ``"representation"`` (the
            server's own object), ``"rejection"`` (the application's own words
            refusing something), ``"surface"`` (the route structure).
        observed_values: The values the surface actually showed, when the
            evidence is a value range. Quoted into the finding so a reader can
            re-derive the inference.
    """

    facet: IntentFacet
    subject: str
    statement: str
    evidence: str = ""
    evidence_source: str = ""
    observed_values: list[str] = Field(default_factory=list)

    @property
    def is_evidenced(self) -> bool:
        """Whether this assertion rests on the application's own surface."""
        return bool(self.evidence.strip() and self.evidence_source.strip())


#: Field names that carry a workflow stage. General workflow vocabulary — the
#: words an API uses for "where in its lifecycle this object is" — not any
#: application's own. The vocabulary only PROPOSES; the observed values are what
#: evidence the assertion.
_STATE_FIELD_TOKENS: frozenset[str] = frozenset(
    {"status", "state", "stage", "phase", "step", "workflow", "lifecycle"}
)

#: Stage labels that read as terminal, and as initial. Used only to ORDER two
#: values the application itself emitted — never to assert that a stage exists.
_TERMINAL_STATE_TOKENS: frozenset[str] = frozenset(
    {
        "complete",
        "completed",
        "delivered",
        "shipped",
        "paid",
        "closed",
        "approved",
        "fulfilled",
        "confirmed",
        "settled",
        "published",
        "active",
    }
)
_INITIAL_STATE_TOKENS: frozenset[str] = frozenset(
    {"pending", "new", "created", "draft", "open", "unpaid", "awaiting", "initiated", "submitted"}
)

#: Numeric field names whose value range is an intent statement.
_QUANTITY_FIELD_TOKENS: frozenset[str] = frozenset(
    {"quantity", "qty", "amount", "count", "total", "price", "cost", "balance", "units", "stock"}
)

#: Fields that bind an object to a principal.
_OWNERSHIP_FIELD_TOKENS: frozenset[str] = frozenset(
    {"userid", "user", "ownerid", "owner", "accountid", "account", "customerid", "customer"}
)

#: Fields marking that a one-time thing has been used up.
_SINGLE_USE_FIELD_TOKENS: frozenset[str] = frozenset(
    {"used", "redeemed", "consumed", "applied", "claimed", "spent", "activated"}
)

#: The application's own words for "this may only happen once" and "you skipped a
#: step". These are read out of a REJECTION the application produced, which makes
#: them the application declaring its own rule — the strongest evidence available
#: from a black-box surface, and the same kind of evidence an HTML ``min=`` is.
_SINGLE_USE_REJECTION_RE = re.compile(
    r"already (?:been )?(?:used|redeemed|claimed|applied|submitted|processed)"
    r"|has (?:already )?expired"
    r"|(?:coupon|code|token|voucher|invite)\s+(?:is\s+)?(?:no longer valid|invalid|expired)"
    r"|one[- ]time (?:only|use)"
    r"|cannot be (?:re-?used|used again|redeemed again)",
    re.IGNORECASE,
)

_ORDERING_REJECTION_RE = re.compile(
    r"must be (?P<prereq>[a-z][a-z _-]{2,30}?) (?:first|before)"
    r"|(?:not|isn't|is not) (?P<prereq2>[a-z][a-z _-]{2,30}?) yet"
    r"|requires? (?:the )?(?P<prereq3>[a-z][a-z _-]{2,30}?) (?:step|stage|state)"
    r"|cannot .{0,40} (?:before|until) (?:it is |the )?(?P<prereq4>[a-z][a-z _-]{2,30})",
    re.IGNORECASE,
)

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _normalise(name: str) -> str:
    """``orderStatus`` / ``order_status`` / ``Order-Status`` → ``orderstatus``."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name or "")
    return "".join(_TOKEN_SPLIT_RE.split(spaced.lower()))


def _name_tokens(name: str) -> set[str]:
    """The word tokens of a field name, for vocabulary matching."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name or "")
    return {tok for tok in _TOKEN_SPLIT_RE.split(spaced.lower()) if tok}


def _numeric(value: Any) -> float | None:
    """*value* as a float, or ``None`` when it is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except (TypeError, ValueError):
            return None
    return None


#: Below this many observed records a value range is not an intent statement —
#: one order with quantity 1 says nothing about whether 0 is intended. Kept low
#: because a black-box crawl of a collection rarely returns many, and stated
#: rather than tuned silently: the number IS the strength of the inference.
MIN_RECORDS_FOR_RANGE = 3


def infer_intent(
    *,
    entity: str,
    representation: list[dict[str, Any]],
    routes: list[str] | None = None,
    rejections: list[str] | None = None,
) -> list[IntentAssertion]:
    """Infer what an application is FOR, from its own surface.

    Args:
        entity: The entity name (the collection this representation came from).
        representation: The server's OWN representation of its objects — records
            read back from a ``GET`` of the collection. This is the evidence
            base: every assertion either quotes a field it carries or a range of
            values it showed.
        routes: Route paths discovered on this API, for the entity/action shape.
        rejections: Response bodies in which the application REFUSED something.
            The richest evidence available from a black box: an application
            saying "this coupon has already been used" has declared the rule.

    Returns:
        Assertions in a deterministic order (facet, then subject). Only assertions
        the surface evidences are returned — an unevidenced guess is not an
        assertion with a weak confidence, it is absent.
    """
    assertions: list[IntentAssertion] = []
    records = [r for r in representation if isinstance(r, dict)]
    routes = routes or []
    rejections = rejections or []

    if records:
        assertions.append(
            IntentAssertion(
                facet=IntentFacet.ENTITY_TYPE,
                subject=entity,
                statement=f"the API manages {entity!r} objects",
                evidence=(
                    f"the server's own representation of {entity!r} returned {len(records)} "
                    f"record(s) carrying the fields "
                    f"{sorted({k for r in records for k in r})[:12]}"
                ),
                evidence_source="representation",
            )
        )

    field_names = sorted({str(k) for record in records for k in record})

    for field in field_names:
        tokens = _name_tokens(field)

        # --- state transition + ordering ---------------------------------
        if tokens & _STATE_FIELD_TOKENS:
            values = sorted(
                {str(r[field]) for r in records if r.get(field) not in (None, "")},
                key=str.lower,
            )
            if len(values) >= 2:
                assertions.append(
                    IntentAssertion(
                        facet=IntentFacet.STATE_TRANSITION,
                        subject=field,
                        statement=(
                            f"{entity!r} objects move through a workflow recorded in {field!r}"
                        ),
                        evidence=(
                            f"the server's own representation of {entity!r} showed "
                            f"{len(values)} distinct {field!r} values across "
                            f"{len(records)} records"
                        ),
                        evidence_source="representation",
                        observed_values=values,
                    )
                )
                terminal = [v for v in values if _name_tokens(v) & _TERMINAL_STATE_TOKENS]
                initial = [v for v in values if _name_tokens(v) & _INITIAL_STATE_TOKENS]
                if terminal and initial:
                    assertions.append(
                        IntentAssertion(
                            facet=IntentFacet.ORDERING_CONSTRAINT,
                            subject=field,
                            statement=(
                                f"{entity!r} objects reach {terminal[0]!r} after "
                                f"{initial[0]!r}, not instead of it"
                            ),
                            evidence=(
                                f"the application's own records carry both {initial[0]!r} "
                                f"and {terminal[0]!r} in {field!r}, so both stages exist "
                                f"in its workflow"
                            ),
                            evidence_source="representation",
                            observed_values=[initial[0], terminal[0]],
                        )
                    )

        # --- quantity bound ----------------------------------------------
        if tokens & _QUANTITY_FIELD_TOKENS:
            numbers = [n for r in records if (n := _numeric(r.get(field))) is not None]
            if len(numbers) >= MIN_RECORDS_FOR_RANGE:
                low, high = min(numbers), max(numbers)
                assertions.append(
                    IntentAssertion(
                        facet=IntentFacet.QUANTITY_BOUND,
                        subject=field,
                        statement=(
                            f"{field!r} on a {entity!r} object is intended to be at least {low:g}"
                        ),
                        evidence=(
                            f"across {len(numbers)} records the application's own "
                            f"representation never showed {field!r} below {low:g} "
                            f"(observed range {low:g}–{high:g})"
                        ),
                        evidence_source="representation",
                        observed_values=[f"{low:g}", f"{high:g}"],
                    )
                )

        # --- ownership ----------------------------------------------------
        if _normalise(field) in _OWNERSHIP_FIELD_TOKENS or tokens & _OWNERSHIP_FIELD_TOKENS:
            assertions.append(
                IntentAssertion(
                    facet=IntentFacet.OWNERSHIP_RELATION,
                    subject=field,
                    statement=f"a {entity!r} object belongs to the principal named in {field!r}",
                    evidence=(
                        f"the server's own representation of {entity!r} carries {field!r} on "
                        f"{sum(1 for r in records if field in r)} of {len(records)} records"
                    ),
                    evidence_source="representation",
                )
            )

        # --- single use (field form) ---------------------------------------
        if tokens & _SINGLE_USE_FIELD_TOKENS:
            assertions.append(
                IntentAssertion(
                    facet=IntentFacet.SINGLE_USE_ACTION,
                    subject=field,
                    statement=f"a {entity!r} object is consumed once, recorded in {field!r}",
                    evidence=(
                        f"the server's own representation of {entity!r} carries a "
                        f"{field!r} marker, which exists to record that the thing has "
                        f"been used up"
                    ),
                    evidence_source="representation",
                )
            )

    # --- single use / ordering (the application's own words) ----------------
    for body in rejections:
        if not body:
            continue
        single_use = _SINGLE_USE_REJECTION_RE.search(body)
        if single_use:
            assertions.append(
                IntentAssertion(
                    facet=IntentFacet.SINGLE_USE_ACTION,
                    subject=entity,
                    statement=f"the application treats this {entity!r} action as single-use",
                    evidence=(
                        f"the application itself refused a repeat with {single_use.group(0)!r}"
                    ),
                    evidence_source="rejection",
                )
            )
        ordering = _ORDERING_REJECTION_RE.search(body)
        if ordering:
            prereq = next(
                (g for g in ordering.groups() if g),
                "",
            ).strip()
            assertions.append(
                IntentAssertion(
                    facet=IntentFacet.ORDERING_CONSTRAINT,
                    subject=entity,
                    statement=(
                        f"the application requires {prereq!r} before this {entity!r} action"
                    ),
                    evidence=(
                        f"the application itself refused with {ordering.group(0)!r}, which "
                        f"is it declaring its own ordering rule"
                    ),
                    evidence_source="rejection",
                    observed_values=[prereq] if prereq else [],
                )
            )

    seen: set[tuple[str, str, str]] = set()
    unique: list[IntentAssertion] = []
    for assertion in assertions:
        key = (assertion.facet.value, assertion.subject, assertion.statement)
        if key in seen:
            continue
        seen.add(key)
        unique.append(assertion)
    unique.sort(key=lambda a: (a.facet.value, a.subject.lower(), a.statement))
    return unique


def verify_proposed_intent(
    proposed: list[dict[str, Any]],
    *,
    representation: list[dict[str, Any]],
    routes: list[str] | None = None,
) -> tuple[list[IntentAssertion], list[str]]:
    """Keep only LLM-proposed intent an observation actually backs.

    The LLM checkpoint is genuinely valuable here — reading an API surface and
    saying what the application is FOR is what a good model is strong at, and it
    sees relations the vocabularies above cannot name. What it must not do is
    decide. So a proposal is kept only when the code can VERIFY its subject
    against the surface: the field it names has to exist in the server's own
    representation, or the route it names has to exist on the discovered surface.

    This is the same direction as everywhere else in the engine — a deterministic
    observation gates the model's list, not just its verdict. A proposal about a
    field the application does not have is not a weak signal; it is about a
    different application.

    Args:
        proposed: Raw LLM output — ``{"facet", "subject", "statement"}`` dicts.
        representation: The server's own object representation.
        routes: Discovered route paths.

    Returns:
        ``(kept, dropped_reasons)``. Every dropped proposal is reported, so the
        gate's work is visible in the trace rather than silent.
    """
    known_fields = {
        _normalise(str(key))
        for record in representation
        if isinstance(record, dict)
        for key in record
    }
    known_routes = {(r or "").lower() for r in (routes or [])}
    kept: list[IntentAssertion] = []
    dropped: list[str] = []

    for item in proposed:
        if not isinstance(item, dict):
            dropped.append(f"non-object proposal {item!r}")
            continue
        raw_facet = str(item.get("facet") or "").strip().lower()
        subject = str(item.get("subject") or "").strip()
        statement = str(item.get("statement") or "").strip()
        if not subject or not statement:
            dropped.append(f"proposal missing subject or statement: {item!r}")
            continue
        try:
            facet = IntentFacet(raw_facet)
        except ValueError:
            dropped.append(f"{subject!r}: unknown facet {raw_facet!r}")
            continue

        normalised = _normalise(subject)
        if normalised in known_fields:
            evidence = (
                f"the server's own representation carries {subject!r}, so this assertion "
                f"is about a field the application actually has"
            )
            source = "representation"
        elif subject.lower() in known_routes:
            evidence = f"{subject!r} is a route the scan discovered on this application"
            source = "surface"
        else:
            dropped.append(
                f"{subject!r}: named neither a field in the server's own representation "
                f"nor a discovered route — unverifiable against this application"
            )
            continue

        kept.append(
            IntentAssertion(
                facet=facet,
                subject=subject,
                statement=statement,
                evidence=evidence,
                evidence_source=source,
            )
        )

    kept.sort(key=lambda a: (a.facet.value, a.subject.lower(), a.statement))
    return kept, dropped


# ---------------------------------------------------------------------------
# The shared verdict shape
# ---------------------------------------------------------------------------


class BusinessLogicVerdict(BaseModel):
    """Whether capability was shown to exceed an evidenced intent.

    Attributes:
        confirmed: Every half held. The only state that may emit.
        why_unconfirmed: Which half did not, when it did not.
        intent: The intent assertion under test. ``None`` when none was
            evidenced, which is itself a reason to stay a lead.
        observation: What was actually observed — the capability side.
        control_detail: What the control showed, and what that proves.
        detail: One sentence summarising the verdict.
    """

    confirmed: bool = False
    why_unconfirmed: str = ""
    intent: IntentAssertion | None = None
    observation: str = ""
    control_detail: str = ""
    detail: str = ""

    def evidence_lines(self) -> list[str]:
        """The three statements a business-logic result must carry.

        Built here rather than at each emit site, because "state the inferred
        intent, its evidence, and the observation" is the honesty rule for this
        whole family and a rule each of three classes has to remember is a rule
        that will be forgotten by the fourth.
        """
        intent = self.intent
        no_evidence = "the application surface declared nothing about this"
        return [
            f"Inferred intent: {intent.statement if intent else 'none could be evidenced'}",
            f"Evidence for that intent ({intent.evidence_source if intent else 'none'}): "
            f"{intent.evidence if intent else no_evidence}",
            f"Observation showing capability exceeded it: {self.observation or 'none'}",
            f"Control: {self.control_detail or 'none'}",
        ]


def _unevidenced(observation: str) -> BusinessLogicVerdict:
    """The verdict for "we saw something, and the application never said it was wrong"."""
    return BusinessLogicVerdict(
        why_unconfirmed="intent_not_evidenced_from_application_surface",
        observation=observation,
        detail=(
            "the application's own surface evidences no rule this behaviour breaks, so "
            "the behaviour is unusual rather than demonstrably unintended — reported as a "
            "lead, because inferring what an application SHOULD do is not an observation"
        ),
    )


# ---------------------------------------------------------------------------
# State-sequence bypass
# ---------------------------------------------------------------------------


def evaluate_state_sequence(
    *,
    intent: IntentAssertion | None,
    terminal_state: str,
    skipped_prerequisite: str,
    out_of_sequence_accepted: bool,
    read_back_state: str | None,
    in_sequence_accepted: bool,
    malformed_control_rejected: bool,
) -> BusinessLogicVerdict:
    """Did the application let a terminal state be reached out of sequence?

    **Defining effect**: the resource is IN the terminal state after a request
    that skipped a prerequisite the application's own surface declares. A status
    code is not the effect — plenty of APIs answer 200 and discard — so the
    read-back is required.

    **Controls, both required and each proving a different thing**:

    * the same request in CORRECT sequence is accepted. Without it, a refusal of
      the out-of-sequence request would be indistinguishable from an endpoint
      that refuses this action to us entirely.
    * a malformed request to the same endpoint is refused. Without it, an
      endpoint that accepts everything confirms — the same asymmetry
      :mod:`clinkz.agents._input_validation` is built on.

    Args:
        intent: The evidenced ordering constraint.
        terminal_state: The stage that was reached.
        skipped_prerequisite: The stage that was skipped.
        out_of_sequence_accepted: Whether the skipping request was accepted.
        read_back_state: The resource's state when read back, or ``None`` when
            the read-back could not be performed.
        in_sequence_accepted: Whether the correct-sequence control was accepted.
        malformed_control_rejected: Whether the malformed control was refused.

    Returns:
        A verdict confirmed only when every half held.
    """
    observation = (
        f"a request reaching {terminal_state!r} while skipping {skipped_prerequisite!r} "
        f"was {'accepted' if out_of_sequence_accepted else 'refused'}; the resource read "
        f"back as {read_back_state!r}"
        if read_back_state is not None
        else (
            f"a request reaching {terminal_state!r} while skipping "
            f"{skipped_prerequisite!r} was "
            f"{'accepted' if out_of_sequence_accepted else 'refused'}; the resource could "
            f"not be read back"
        )
    )
    if intent is None or not intent.is_evidenced:
        return _unevidenced(observation)

    control_detail = (
        f"the same action in correct sequence was "
        f"{'accepted' if in_sequence_accepted else 'refused'}, and a malformed request to "
        f"the same endpoint was "
        f"{'refused' if malformed_control_rejected else 'accepted'}"
    )

    if not out_of_sequence_accepted:
        return BusinessLogicVerdict(
            why_unconfirmed="out_of_sequence_request_refused",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the application refused the request that skipped "
                f"{skipped_prerequisite!r}, so it enforces the ordering it declares"
            ),
        )
    if read_back_state is None:
        return BusinessLogicVerdict(
            why_unconfirmed="terminal_state_not_read_back",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the out-of-sequence request was accepted but the resource could not be "
                "read back, so whether it actually reached the terminal state was never "
                "observed — an acceptance status is not a state change"
            ),
        )
    if _normalise(read_back_state) != _normalise(terminal_state):
        return BusinessLogicVerdict(
            why_unconfirmed="terminal_state_not_reached",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the request was accepted but the resource read back as "
                f"{read_back_state!r}, not {terminal_state!r} — the application accepted "
                f"the call and did not perform the transition"
            ),
        )
    if not malformed_control_rejected:
        return BusinessLogicVerdict(
            why_unconfirmed="endpoint_accepts_malformed_control",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the endpoint accepted a malformed control too, so it demonstrates no "
                "request validation at all and its acceptance of the out-of-sequence "
                "request is not evidence about the ordering"
            ),
        )
    if not in_sequence_accepted:
        return BusinessLogicVerdict(
            why_unconfirmed="in_sequence_control_refused",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the correct-sequence control was refused, so this endpoint's behaviour "
                "is not explained by the ordering — something else decides its answer and "
                "the comparison is not about sequence"
            ),
        )
    return BusinessLogicVerdict(
        confirmed=True,
        intent=intent,
        observation=observation,
        control_detail=control_detail,
        detail=(
            f"the application declares that {terminal_state!r} follows "
            f"{skipped_prerequisite!r} ({intent.evidence}); a request that skipped "
            f"{skipped_prerequisite!r} was accepted and the resource READ BACK in "
            f"{terminal_state!r}, while the same endpoint refused a malformed control — "
            f"so the ordering is declared and not enforced"
        ),
    )


# ---------------------------------------------------------------------------
# Constraint violation
# ---------------------------------------------------------------------------


def evaluate_constraint_violation(
    *,
    intent: IntentAssertion | None,
    field: str,
    violating_value: str,
    boundary_value: str,
    violating_accepted: bool,
    read_back_value: str | None,
    boundary_accepted: bool,
    malformed_control_rejected: bool,
) -> BusinessLogicVerdict:
    """Did the application persist a value its own surface forbids?

    **Defining effect**: the persisted record carries the violating value. Not a
    2xx — a record. An API that returns 201 and clamps the value to 1 has
    behaved correctly, and a status-only oracle would call that a finding.

    **Controls**: the boundary value the application declares valid must be
    ACCEPTED (proving the field is writable at all and this endpoint serves us),
    and a malformed request must be REFUSED (proving the endpoint validates
    something).

    Args:
        intent: The evidenced quantity bound.
        field: The field under test.
        violating_value: The value that breaks the evidenced bound.
        boundary_value: The lowest value the application's own records showed.
        violating_accepted: Whether the violating write was accepted.
        read_back_value: The field's value on the persisted record, or ``None``.
        boundary_accepted: Whether the boundary control was accepted.
        malformed_control_rejected: Whether the malformed control was refused.

    Returns:
        A verdict confirmed only when every half held.
    """
    observation = (
        f"{field!r}={violating_value!r} was "
        f"{'accepted' if violating_accepted else 'refused'}; the record read back with "
        f"{field!r}={read_back_value!r}"
        if read_back_value is not None
        else (
            f"{field!r}={violating_value!r} was "
            f"{'accepted' if violating_accepted else 'refused'}; the record could not be "
            f"read back"
        )
    )
    if intent is None or not intent.is_evidenced:
        return _unevidenced(observation)

    control_detail = (
        f"the boundary value {field!r}={boundary_value!r} — the lowest the application's "
        f"own records show — was {'accepted' if boundary_accepted else 'refused'}, and a "
        f"malformed request to the same endpoint was "
        f"{'refused' if malformed_control_rejected else 'accepted'}"
    )

    if not violating_accepted:
        return BusinessLogicVerdict(
            why_unconfirmed="violating_value_refused",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the application refused {field!r}={violating_value!r}, so it enforces "
                f"the bound its own records imply"
            ),
        )
    if read_back_value is None:
        return BusinessLogicVerdict(
            why_unconfirmed="value_not_read_back",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the write was accepted but the record could not be read back, so whether "
                "the violating value PERSISTED was never observed — and an API that "
                "accepts and then clamps is the feature working"
            ),
        )
    if _numeric(read_back_value) != _numeric(violating_value):
        return BusinessLogicVerdict(
            why_unconfirmed="violating_value_not_persisted",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the write was accepted but the record read back with "
                f"{field!r}={read_back_value!r}, not {violating_value!r} — the "
                f"application normalised the value, which is the constraint being enforced"
            ),
        )
    if not malformed_control_rejected:
        return BusinessLogicVerdict(
            why_unconfirmed="endpoint_accepts_malformed_control",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the endpoint accepted a malformed control too, so it demonstrates no "
                "validation at all and its acceptance says nothing about this bound"
            ),
        )
    if not boundary_accepted:
        return BusinessLogicVerdict(
            why_unconfirmed="boundary_control_refused",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the application refused {field!r}={boundary_value!r}, a value its own "
                f"records show as normal, so this endpoint is not behaving as the "
                f"representation describes and the comparison is not about the bound"
            ),
        )
    return BusinessLogicVerdict(
        confirmed=True,
        intent=intent,
        observation=observation,
        control_detail=control_detail,
        detail=(
            f"the application's own records never show {field!r} below "
            f"{boundary_value!r} ({intent.evidence}); it ACCEPTED "
            f"{field!r}={violating_value!r} and the record READ BACK carrying that value, "
            f"while the same endpoint accepted the valid boundary and refused a malformed "
            f"control — so the bound is a property of the data, not of the handler"
        ),
    )


# ---------------------------------------------------------------------------
# Repeatability
# ---------------------------------------------------------------------------


def evaluate_repeatability(
    *,
    intent: IntentAssertion | None,
    action: str,
    second_application_accepted: bool,
    first_effect: str | None,
    second_effect: str | None,
    invalid_control_rejected: bool,
) -> BusinessLogicVerdict:
    """Was a single-use action applied a second time, with the SECOND effect seen?

    **Defining effect**: the effect applied twice. Not "the second request
    returned 200" — an idempotent handler returns 200 to a replay and changes
    nothing, and that is correct behaviour. So the two effects are compared, and
    confirmation needs them to DIFFER in the direction of cumulative application.

    **Control**: the endpoint refuses an invalid instance of the same action,
    proving it validates the action at all.

    Args:
        intent: The evidenced single-use rule.
        action: What was applied, for the evidence.
        second_application_accepted: Whether the replay was accepted.
        first_effect: The observed effect after the first application (a
            read-back value), or ``None`` when it could not be observed.
        second_effect: The observed effect after the second.
        invalid_control_rejected: Whether an invalid instance was refused.

    Returns:
        A verdict confirmed only when the second effect was actually observed.
    """
    observation = (
        f"{action} applied a second time was "
        f"{'accepted' if second_application_accepted else 'refused'}; the observed effect "
        f"went from {first_effect!r} to {second_effect!r}"
    )
    if intent is None or not intent.is_evidenced:
        return _unevidenced(observation)

    control_detail = (
        f"an invalid instance of the same action was "
        f"{'refused' if invalid_control_rejected else 'accepted'}"
    )

    if not second_application_accepted:
        return BusinessLogicVerdict(
            why_unconfirmed="second_application_refused",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the application refused the second application of {action}, so it "
                f"enforces the single-use rule it declares"
            ),
        )
    if first_effect is None or second_effect is None:
        return BusinessLogicVerdict(
            why_unconfirmed="repeat_effect_not_observed",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the second application was accepted but its EFFECT was never observed. "
                "An idempotent handler answers 200 to a replay and changes nothing, which "
                "is correct behaviour, so acceptance alone cannot tell the two apart"
            ),
        )
    if _normalise(str(first_effect)) == _normalise(str(second_effect)):
        return BusinessLogicVerdict(
            why_unconfirmed="repeat_had_no_cumulative_effect",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                f"the second application was accepted but the observed effect is unchanged "
                f"({first_effect!r}), so the handler is idempotent — it accepted the replay "
                f"and applied nothing, which is the rule being honoured"
            ),
        )
    if not invalid_control_rejected:
        return BusinessLogicVerdict(
            why_unconfirmed="endpoint_accepts_invalid_control",
            intent=intent,
            observation=observation,
            control_detail=control_detail,
            detail=(
                "the endpoint accepted an invalid instance of the action too, so it "
                "validates nothing observable and its acceptance of the replay is not "
                "evidence about single use"
            ),
        )
    return BusinessLogicVerdict(
        confirmed=True,
        intent=intent,
        observation=observation,
        control_detail=control_detail,
        detail=(
            f"the application declares {action} single-use ({intent.evidence}); applying "
            f"it a second time was accepted AND the observed effect moved from "
            f"{first_effect!r} to {second_effect!r}, so the effect accumulated rather than "
            f"being replayed idempotently — while the same endpoint refused an invalid "
            f"instance"
        ),
    )


#: Why a business-logic result stayed a lead. Closed vocabulary, same discipline
#: as the finding-level ones: every entry names a specific missing half so the
#: operator knows what to check by hand, and no entry is a shrug.
BUSINESS_LOGIC_WHY_UNCONFIRMED: frozenset[str] = frozenset(
    {
        "intent_not_evidenced_from_application_surface",
        "out_of_sequence_request_refused",
        "terminal_state_not_read_back",
        "terminal_state_not_reached",
        "in_sequence_control_refused",
        "violating_value_refused",
        "value_not_read_back",
        "violating_value_not_persisted",
        "boundary_control_refused",
        "second_application_refused",
        "repeat_effect_not_observed",
        "repeat_had_no_cumulative_effect",
        "endpoint_accepts_malformed_control",
        "endpoint_accepts_invalid_control",
    }
)


__all__ = [
    "BUSINESS_LOGIC_WHY_UNCONFIRMED",
    "MIN_RECORDS_FOR_RANGE",
    "BusinessLogicVerdict",
    "IntentAssertion",
    "IntentFacet",
    "evaluate_constraint_violation",
    "evaluate_repeatability",
    "evaluate_state_sequence",
    "infer_intent",
    "verify_proposed_intent",
]
