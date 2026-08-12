"""Business logic — the confirm, and (mostly) the refusal.

Business logic is where a tool most easily hallucinates a vulnerability out of
unusual-but-intended behaviour, so this file is weighted the way that risk is:
every class gets a confirm test and several refusals, and each refusal is the
*specific* near-miss that would fool a naive implementation rather than an empty
input.

The one that carries the most weight is
:func:`test_unusual_behaviour_the_application_never_declared_a_rule_about`. An
API that accepts a negative balance may be issuing a credit note; an order that
ships before payment may belong to an invoiced customer. Neither is a finding,
and the only thing that separates them from a real flaw is whether the
application's own surface says otherwise.
"""

from __future__ import annotations

import pytest

from clinkz.agents._business_logic import (
    BUSINESS_LOGIC_WHY_UNCONFIRMED,
    BusinessLogicVerdict,
    IntentAssertion,
    IntentFacet,
    evaluate_constraint_violation,
    evaluate_repeatability,
    evaluate_state_sequence,
    infer_intent,
    verify_proposed_intent,
)

# ---------------------------------------------------------------------------
# Intent inference — from the application's own surface, or not at all
# ---------------------------------------------------------------------------

_ORDERS = [
    {"id": 1, "status": "pending", "quantity": 2, "userId": 7, "total": 19.99},
    {"id": 2, "status": "delivered", "quantity": 1, "userId": 7, "total": 4.50},
    {"id": 3, "status": "pending", "quantity": 5, "userId": 9, "total": 55.00},
]


class TestIntentInference:
    def test_a_workflow_field_with_two_observed_values_evidences_a_transition(self) -> None:
        assertions = infer_intent(entity="Orders", representation=_ORDERS)
        transitions = [a for a in assertions if a.facet is IntentFacet.STATE_TRANSITION]
        assert transitions
        assert transitions[0].subject == "status"
        assert transitions[0].evidence_source == "representation"
        assert set(transitions[0].observed_values) == {"pending", "delivered"}

    def test_an_ordering_is_inferred_only_when_the_app_shows_both_stages(self) -> None:
        assertions = infer_intent(entity="Orders", representation=_ORDERS)
        ordering = [a for a in assertions if a.facet is IntentFacet.ORDERING_CONSTRAINT]
        assert ordering
        assert ordering[0].observed_values == ["pending", "delivered"]
        assert "own records carry both" in ordering[0].evidence

    def test_a_single_stage_is_not_an_ordering(self) -> None:
        """One value is a field, not a workflow — nothing to skip."""
        records = [{"status": "pending"}, {"status": "pending"}, {"status": "pending"}]
        assertions = infer_intent(entity="Orders", representation=records)
        assert not [a for a in assertions if a.facet is IntentFacet.ORDERING_CONSTRAINT]

    def test_a_quantity_bound_quotes_the_range_the_app_actually_showed(self) -> None:
        assertions = infer_intent(entity="Orders", representation=_ORDERS)
        bounds = [a for a in assertions if a.facet is IntentFacet.QUANTITY_BOUND]
        subjects = {a.subject for a in bounds}
        assert "quantity" in subjects
        quantity = next(a for a in bounds if a.subject == "quantity")
        assert quantity.observed_values == ["1", "5"]
        assert "never showed 'quantity' below 1" in quantity.evidence

    def test_too_few_records_is_not_a_range(self) -> None:
        """One order with quantity 1 says nothing about whether 0 is intended."""
        assertions = infer_intent(entity="Orders", representation=[{"quantity": 1}])
        assert not [a for a in assertions if a.facet is IntentFacet.QUANTITY_BOUND]

    def test_the_applications_own_refusal_is_the_strongest_evidence(self) -> None:
        assertions = infer_intent(
            entity="Coupons",
            representation=[],
            rejections=['{"error": "This coupon has already been used."}'],
        )
        single_use = [a for a in assertions if a.facet is IntentFacet.SINGLE_USE_ACTION]
        assert single_use
        assert single_use[0].evidence_source == "rejection"
        assert "already been used" in single_use[0].evidence

    def test_an_empty_surface_evidences_nothing_at_all(self) -> None:
        assert infer_intent(entity="Orders", representation=[]) == []

    def test_inference_is_deterministic(self) -> None:
        first = infer_intent(entity="Orders", representation=_ORDERS)
        second = infer_intent(entity="Orders", representation=list(reversed(_ORDERS)))
        assert [(a.facet, a.subject) for a in first] == [(a.facet, a.subject) for a in second]


class TestLLMIntentGate:
    """A deterministic observation gates the model's LIST, not just its verdict."""

    def test_a_proposal_about_a_field_the_application_has_is_kept(self) -> None:
        kept, dropped = verify_proposed_intent(
            [
                {
                    "facet": "ownership_relation",
                    "subject": "userId",
                    "statement": "an order belongs to the user named in userId",
                }
            ],
            representation=_ORDERS,
        )
        assert len(kept) == 1
        assert kept[0].evidence_source == "representation"
        assert not dropped

    def test_a_proposal_about_a_field_the_application_does_not_have_is_dropped(self) -> None:
        """Not a weak signal — it is about a different application."""
        kept, dropped = verify_proposed_intent(
            [
                {
                    "facet": "quantity_bound",
                    "subject": "loyaltyPoints",
                    "statement": "loyalty points cannot go negative",
                }
            ],
            representation=_ORDERS,
        )
        assert kept == []
        assert dropped and "unverifiable" in dropped[0]

    def test_an_unknown_facet_is_dropped_rather_than_coerced(self) -> None:
        kept, dropped = verify_proposed_intent(
            [{"facet": "vibes", "subject": "status", "statement": "..."}],
            representation=_ORDERS,
        )
        assert kept == []
        assert dropped

    def test_garbage_never_raises(self) -> None:
        kept, dropped = verify_proposed_intent(
            ["not an object", {}, {"subject": "status"}], representation=_ORDERS
        )
        assert kept == []
        assert len(dropped) == 3


# ---------------------------------------------------------------------------
# The refusal that matters most
# ---------------------------------------------------------------------------


def test_unusual_behaviour_the_application_never_declared_a_rule_about() -> None:
    """THE refusal. Unusual is not unintended, and the difference is evidence.

    An API that accepts a negative balance may be issuing a credit note. Without
    the application's own surface saying otherwise, calling that a finding is
    this engine asserting how somebody else's business ought to work.
    """
    verdict = evaluate_constraint_violation(
        intent=None,
        field="balance",
        violating_value="-100",
        boundary_value="0",
        violating_accepted=True,
        read_back_value="-100",
        boundary_accepted=True,
        malformed_control_rejected=True,
    )
    assert not verdict.confirmed
    assert verdict.why_unconfirmed == "intent_not_evidenced_from_application_surface"
    assert verdict.why_unconfirmed in BUSINESS_LOGIC_WHY_UNCONFIRMED
    assert "unusual rather than demonstrably unintended" in verdict.detail


def test_an_intent_assertion_with_no_evidence_is_not_usable() -> None:
    unevidenced = IntentAssertion(
        facet=IntentFacet.QUANTITY_BOUND,
        subject="quantity",
        statement="quantity should be at least 1",
    )
    assert not unevidenced.is_evidenced
    verdict = evaluate_constraint_violation(
        intent=unevidenced,
        field="quantity",
        violating_value="-1",
        boundary_value="1",
        violating_accepted=True,
        read_back_value="-1",
        boundary_accepted=True,
        malformed_control_rejected=True,
    )
    assert not verdict.confirmed
    assert verdict.why_unconfirmed == "intent_not_evidenced_from_application_surface"


# ---------------------------------------------------------------------------
# Constraint violation
# ---------------------------------------------------------------------------


def _quantity_intent() -> IntentAssertion:
    return next(
        a
        for a in infer_intent(entity="Orders", representation=_ORDERS)
        if a.facet is IntentFacet.QUANTITY_BOUND and a.subject == "quantity"
    )


class TestConstraintViolation:
    def test_it_confirms_when_the_violating_value_persists(self) -> None:
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="0",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="0",
            boundary_accepted=True,
            malformed_control_rejected=True,
        )
        assert verdict.confirmed
        assert "READ BACK carrying that value" in verdict.detail

    def test_an_api_that_clamps_the_value_has_enforced_the_constraint(self) -> None:
        """201 Created is not the effect — the persisted record is."""
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="-5",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="1",
            boundary_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "violating_value_not_persisted"

    def test_an_unreadable_record_is_an_unobserved_outcome_not_a_finding(self) -> None:
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="-5",
            boundary_value="1",
            violating_accepted=True,
            read_back_value=None,
            boundary_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "value_not_read_back"

    def test_an_endpoint_that_accepts_the_malformed_control_proves_nothing(self) -> None:
        """The accept-everything endpoint, which would otherwise confirm on every field."""
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="-5",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="-5",
            boundary_accepted=True,
            malformed_control_rejected=False,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "endpoint_accepts_malformed_control"

    def test_a_refused_boundary_means_the_comparison_is_not_about_the_bound(self) -> None:
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="-5",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="-5",
            boundary_accepted=False,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "boundary_control_refused"

    def test_an_enforced_constraint_is_reported_as_enforced(self) -> None:
        verdict = evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="-5",
            boundary_value="1",
            violating_accepted=False,
            read_back_value=None,
            boundary_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "violating_value_refused"
        assert "it enforces the bound" in verdict.detail


# ---------------------------------------------------------------------------
# State-sequence bypass
# ---------------------------------------------------------------------------


def _ordering_intent() -> IntentAssertion:
    return next(
        a
        for a in infer_intent(entity="Orders", representation=_ORDERS)
        if a.facet is IntentFacet.ORDERING_CONSTRAINT
    )


class TestStateSequence:
    def test_it_confirms_when_the_resource_reads_back_in_the_terminal_state(self) -> None:
        verdict = evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=True,
            read_back_state="delivered",
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        )
        assert verdict.confirmed
        assert "READ BACK" in verdict.detail

    def test_an_accepted_call_that_performed_no_transition_is_not_a_bypass(self) -> None:
        """Many APIs answer 200 and discard. The read-back is the effect."""
        verdict = evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=True,
            read_back_state="pending",
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "terminal_state_not_reached"

    def test_an_unreadable_resource_is_not_a_state_change(self) -> None:
        verdict = evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=True,
            read_back_state=None,
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "terminal_state_not_read_back"

    def test_a_refused_in_sequence_control_means_something_else_decides(self) -> None:
        verdict = evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=True,
            read_back_state="delivered",
            in_sequence_accepted=False,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "in_sequence_control_refused"

    def test_an_enforced_ordering_is_reported_as_enforced(self) -> None:
        verdict = evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=False,
            read_back_state=None,
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "out_of_sequence_request_refused"


# ---------------------------------------------------------------------------
# Repeatability
# ---------------------------------------------------------------------------


def _single_use_intent() -> IntentAssertion:
    return next(
        a
        for a in infer_intent(
            entity="Coupons",
            representation=[],
            rejections=["This coupon has already been used."],
        )
        if a.facet is IntentFacet.SINGLE_USE_ACTION
    )


class TestRepeatability:
    def test_it_confirms_when_the_second_effect_accumulates(self) -> None:
        verdict = evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=True,
            first_effect='{"discount": 10}',
            second_effect='{"discount": 20}',
            invalid_control_rejected=True,
        )
        assert verdict.confirmed
        assert "accumulated" in verdict.detail

    def test_an_idempotent_handler_is_the_rule_being_honoured(self) -> None:
        """200 to a replay with no change is correct behaviour, not a flaw."""
        verdict = evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=True,
            first_effect='{"discount": 10}',
            second_effect='{"discount": 10}',
            invalid_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "repeat_had_no_cumulative_effect"
        assert "idempotent" in verdict.detail

    def test_an_unobserved_effect_cannot_tell_the_two_apart(self) -> None:
        verdict = evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=True,
            first_effect=None,
            second_effect=None,
            invalid_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "repeat_effect_not_observed"

    def test_an_endpoint_that_accepts_an_invalid_instance_proves_nothing(self) -> None:
        verdict = evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=True,
            first_effect='{"discount": 10}',
            second_effect='{"discount": 20}',
            invalid_control_rejected=False,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "endpoint_accepts_invalid_control"

    def test_an_enforced_single_use_rule_is_reported_as_enforced(self) -> None:
        verdict = evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=False,
            first_effect='{"discount": 10}',
            second_effect=None,
            invalid_control_rejected=True,
        )
        assert not verdict.confirmed
        assert verdict.why_unconfirmed == "second_application_refused"


# ---------------------------------------------------------------------------
# The emission-honesty contract, checked once for the whole family
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verdict",
    [
        evaluate_constraint_violation(
            intent=_quantity_intent(),
            field="quantity",
            violating_value="0",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="0",
            boundary_accepted=True,
            malformed_control_rejected=True,
        ),
        evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=True,
            read_back_state="delivered",
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        ),
        evaluate_repeatability(
            intent=_single_use_intent(),
            action="the /redeem action",
            second_application_accepted=True,
            first_effect='{"discount": 10}',
            second_effect='{"discount": 20}',
            invalid_control_rejected=True,
        ),
    ],
    ids=["constraint", "sequence", "repeatability"],
)
def test_every_confirmed_verdict_states_intent_evidence_and_observation(
    verdict: BusinessLogicVerdict,
) -> None:
    """The three statements are built at one seam, so no class can ship two of them."""
    assert verdict.confirmed
    lines = verdict.evidence_lines()
    assert len(lines) == 4
    assert lines[0].startswith("Inferred intent: ")
    assert "none could be evidenced" not in lines[0]
    # The source is either the server's own representation or the application's
    # own refusal wording — both are the application speaking, and neither is us.
    assert lines[1].startswith("Evidence for that intent (representation") or lines[1].startswith(
        "Evidence for that intent (rejection"
    )
    assert "declared nothing" not in lines[1]
    assert lines[2].startswith("Observation showing capability exceeded it: ")
    assert lines[2] != "Observation showing capability exceeded it: none"
    assert lines[3].startswith("Control: ")
    assert lines[3] != "Control: none"


def test_every_why_unconfirmed_is_in_the_closed_vocabulary() -> None:
    """A free-text reason drifts into a justification, and a justification reads
    like a finding."""
    produced = {
        evaluate_constraint_violation(
            intent=None,
            field="q",
            violating_value="0",
            boundary_value="1",
            violating_accepted=True,
            read_back_value="0",
            boundary_accepted=True,
            malformed_control_rejected=True,
        ).why_unconfirmed,
        evaluate_state_sequence(
            intent=_ordering_intent(),
            terminal_state="delivered",
            skipped_prerequisite="pending",
            out_of_sequence_accepted=False,
            read_back_state=None,
            in_sequence_accepted=True,
            malformed_control_rejected=True,
        ).why_unconfirmed,
        evaluate_repeatability(
            intent=_single_use_intent(),
            action="x",
            second_application_accepted=True,
            first_effect="a",
            second_effect="a",
            invalid_control_rejected=True,
        ).why_unconfirmed,
    }
    assert produced <= BUSINESS_LOGIC_WHY_UNCONFIRMED
