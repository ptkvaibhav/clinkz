"""The write-crossing oracle: the arms, the order, the residue, the refusals.

Per invariant 35, an acceptance criterion that reads only a verdict cannot detect
an oracle that reached the right answer by the wrong arm — so what is asserted
here is **which request went out, as whom, carrying what, and in what order**.
The verdict is checked too, but it is never the only thing checked.

The negative fixture at the bottom is the one that matters most: a run where the
crossing arm precedes the never-issued control must FAIL, even though every other
observation in it is identical to a sound run's and an external grader would mark
the challenge solved either way.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinkz.agents._idor_oracle import (
    OWNING_FIELD_NAMES_PRINCIPAL,
    TIER_MULTI_ROLE,
)
from clinkz.agents._write_crossing import (
    ANONYMOUS_ARM_NOT_DISPATCHED,
    ANONYMOUS_WRITE_SUCCEEDED,
    ARM_DISPATCH_ORDER,
    CONTROL_ABSENT_LANDED,
    CONTROL_ABSENT_NOT_DISPATCHED,
    CONTROL_SELF_DID_NOT_ATTRIBUTE,
    NOT_READABLE_BACK,
    OBJECT_NAMES_NO_OWNER,
    REFERENCE_NOT_OWNED,
    REQUIRES_SECOND_PRINCIPAL,
    WRITE_CROSSING_WHY_UNCONFIRMED,
    CreatedObject,
    WriteArm,
    WriteArmRecorder,
    WriteObservation,
    benign_value_like,
    crossing_body,
    decide_write_crossing,
    locate_created_object,
    object_identifier,
    owner_field_key,
    owner_reference_of,
    owning_field_of,
    reference_format,
    residual_note,
    shaped_self_reference,
    verified_owner_reference_of,
)
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED

# A is the least-privileged principal; B outranks it. Their identity values are
# what the engine HOLDS, so nothing the target sends can manufacture attribution.
A_IDENTITY = frozenset({"jim@t.test", "2"})
B_IDENTITY = frozenset({"admin@t.test", "1"})
HELD = {"admin": B_IDENTITY}

ABSENT = "874211"


def _created(**fields: Any) -> CreatedObject:
    return CreatedObject(
        located=True,
        identifier=str(fields.get("id", "9")),
        body=json.dumps(fields, sort_keys=True),
        marker="clinkzdecoywritecrossing11111",
    )


def _obs(
    arm: WriteArm,
    *,
    owner_value: str,
    landed: bool = True,
    dispatched: bool = True,
    status: int = 201,
    principal: str = "customer",
    **fields: Any,
) -> WriteObservation:
    return WriteObservation(
        arm=arm,
        dispatched=dispatched,
        status=status,
        owner_value_sent=owner_value,
        created=_created(**fields) if landed else CreatedObject(located=False),
        principal=principal,
    )


def _sound_arms(**overrides: Any) -> dict[str, Any]:
    """Five arms as a real crossing produces them, dispatched in order."""
    recorder = WriteArmRecorder()
    owner_read = WriteObservation(
        arm=WriteArm.OWNER_READ,
        dispatched=True,
        status=200,
        owner_value_sent="",
        created=CreatedObject(
            located=True, identifier="", body=json.dumps([{"id": 3, "UserId": "1"}])
        ),
        principal="admin",
    )
    self_anchor = _obs(
        WriteArm.SELF_ANCHOR, owner_value="", id=6, UserId="2", comment="clinkz-comment"
    )
    control_self = _obs(
        WriteArm.CONTROL_SELF, owner_value="2", id=7, UserId="2", comment="clinkz-comment"
    )
    control_absent = _obs(
        WriteArm.CONTROL_ABSENT,
        owner_value=ABSENT,
        # The server refused a reference nobody owns: the write did not land.
        landed=False,
        status=422,
    )
    anonymous = _obs(
        WriteArm.ANONYMOUS,
        owner_value="1",
        landed=False,
        status=401,
        principal="anonymous",
    )
    crossing = _obs(WriteArm.CROSSING, owner_value="1", id=9, UserId="1", comment="clinkz-comment")
    arms = {
        "owner_read": owner_read,
        "self_anchor": self_anchor,
        "control_self": control_self,
        "control_absent": control_absent,
        "anonymous": anonymous,
        "crossing": crossing,
    }
    arms.update({k: v for k, v in overrides.items() if k in arms})
    for arm in ARM_DISPATCH_ORDER:
        observation = arms[arm.value]
        if observation is not None:
            recorder.record(observation)
    return {
        **{k: v for k, v in arms.items() if k != "self_anchor"},
        "recorder": overrides.get("recorder", recorder),
        "corroborating_body": overrides.get(
            "corroborating_body", json.dumps([{"id": 9, "comment": crossing.created.marker}])
        ),
        "caller_identity": overrides.get("caller_identity", A_IDENTITY),
        "held_identities": overrides.get("held_identities", HELD),
        "principals_available": overrides.get("principals_available", 2),
        "principals_required": overrides.get("principals_required", 2),
        "tier": overrides.get("tier", TIER_MULTI_ROLE),
        "absent_reference": overrides.get("absent_reference", ABSENT),
    }


class TestTheSoundCrossingConfirms:
    def test_it_confirms_and_names_the_route(self) -> None:
        verdict = decide_write_crossing(**_sound_arms())
        assert verdict.confirmed is True
        assert verdict.attribution == OWNING_FIELD_NAMES_PRINCIPAL
        assert verdict.owning_field
        assert verdict.tier == TIER_MULTI_ROLE

    def test_the_attribution_reproduces_no_value_from_the_target(self) -> None:
        """Names and salted fingerprints only — invariant 13, on the write side."""
        verdict = decide_write_crossing(**_sound_arms())
        rendered = " ".join(verdict.attributing_fields)
        assert rendered, "a confirmation with no attributing field renders no claim"
        assert "admin@t.test" not in rendered
        assert "owner_fp=" in rendered

    def test_every_arm_is_named_in_the_evidence_lines(self) -> None:
        verdict = decide_write_crossing(**_sound_arms())
        rendered = " | ".join(verdict.arms_detail)
        for arm in ARM_DISPATCH_ORDER:
            assert arm.value in rendered


class TestTheStatusCodeIsNeverTheEffect:
    def test_a_201_with_nothing_read_back_does_not_confirm(self) -> None:
        """The identical error mass assignment already refuses to make.

        Every framework that silently discards an unbound field returns the same
        201 as one that honours it, so a crossing whose object was never located
        in a separate read proves nothing.
        """
        verdict = decide_write_crossing(
            **_sound_arms(
                crossing=_obs(WriteArm.CROSSING, owner_value="1", landed=False, status=201)
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == NOT_READABLE_BACK

    def test_the_persisted_body_is_the_only_channel_read(self) -> None:
        """A crossing whose PERSISTED object names only the caller does not confirm."""
        verdict = decide_write_crossing(
            **_sound_arms(
                crossing=_obs(
                    WriteArm.CROSSING, owner_value="1", id=9, UserId="2", comment="clinkz"
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == OBJECT_NAMES_NO_OWNER


class TestTheControlsRefuseBeforeAnythingConfirms:
    def test_an_undispatched_control_abstains(self) -> None:
        verdict = decide_write_crossing(
            **_sound_arms(
                control_absent=_obs(
                    WriteArm.CONTROL_ABSENT,
                    owner_value=ABSENT,
                    dispatched=False,
                    landed=False,
                    status=0,
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == CONTROL_ABSENT_NOT_DISPATCHED

    def test_a_never_issued_reference_that_landed_kills_the_finding(self) -> None:
        """Opaque string storage, not attribution — and the crossing is that storage."""
        verdict = decide_write_crossing(
            **_sound_arms(
                control_absent=_obs(
                    WriteArm.CONTROL_ABSENT, owner_value=ABSENT, id=8, UserId=ABSENT
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == CONTROL_ABSENT_LANDED

    def test_a_liveness_control_that_did_not_land_abstains(self) -> None:
        verdict = decide_write_crossing(
            **_sound_arms(
                control_self=_obs(WriteArm.CONTROL_SELF, owner_value="2", landed=False, status=201)
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == CONTROL_SELF_DID_NOT_ATTRIBUTE

    def test_an_endpoint_that_overrides_the_owner_field_abstains(self) -> None:
        """The server correctly setting the owner itself is not a crossing.

        Without arm 1 this is indistinguishable from a real one: the object comes
        back attributed to somebody, and which somebody is not the question.
        """
        verdict = decide_write_crossing(
            **_sound_arms(
                control_self=_obs(
                    WriteArm.CONTROL_SELF, owner_value="2", id=7, UserId="99", comment="clinkz"
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == CONTROL_SELF_DID_NOT_ATTRIBUTE


class TestTheAnonymousArm:
    def test_an_arm_never_dispatched_abstains(self) -> None:
        verdict = decide_write_crossing(
            **_sound_arms(
                anonymous=_obs(
                    WriteArm.ANONYMOUS,
                    owner_value="1",
                    dispatched=False,
                    landed=False,
                    status=0,
                    principal="anonymous",
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == ANONYMOUS_ARM_NOT_DISPATCHED

    def test_an_anonymous_write_that_landed_is_disqualifying(self) -> None:
        """The endpoint is open, which is a different finding — invariant 34."""
        verdict = decide_write_crossing(
            **_sound_arms(
                anonymous=_obs(
                    WriteArm.ANONYMOUS,
                    owner_value="1",
                    id=11,
                    UserId="1",
                    principal="anonymous",
                )
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == ANONYMOUS_WRITE_SUCCEEDED


class TestTheMultiPrincipalRequirement:
    def test_a_single_role_run_may_only_lead(self) -> None:
        verdict = decide_write_crossing(**_sound_arms(principals_available=1, tier="single_role"))
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == REQUIRES_SECOND_PRINCIPAL

    def test_every_reason_is_registered_vocabulary(self) -> None:
        """A reason the oracle can produce and the vocabulary does not know is a leak."""
        assert WRITE_CROSSING_WHY_UNCONFIRMED <= UNPROVEN_WHY_UNCONFIRMED, sorted(
            WRITE_CROSSING_WHY_UNCONFIRMED - UNPROVEN_WHY_UNCONFIRMED
        )


class TestTheArmOrderIsTheClaim:
    """Invariant 35: assert the ARMS, not the grader's verdict.

    The negative fixture. Every observation below is byte-identical to the sound
    run's — same statuses, same persisted bodies, same attribution — and the only
    difference is that the crossing went out before the never-issued control. An
    external grader would mark the challenge solved either way. The oracle must
    refuse.
    """

    def test_the_declared_order_puts_the_attribution_source_and_controls_first(self) -> None:
        order = [a.value for a in ARM_DISPATCH_ORDER]
        assert order.index("owner_read") < order.index("crossing")
        assert order.index("control_self") < order.index("crossing")
        assert order.index("control_absent") < order.index("crossing")
        assert order.index("anonymous") < order.index("crossing")
        assert order[-1] == "crossing"

    def test_a_crossing_before_the_control_fails_despite_identical_observations(self) -> None:
        sound = _sound_arms()
        inverted = WriteArmRecorder()
        # Arm 3 first, then the control that was supposed to license it.
        for arm in (
            WriteArm.OWNER_READ,
            WriteArm.CONTROL_SELF,
            WriteArm.CROSSING,
            WriteArm.CONTROL_ABSENT,
            WriteArm.ANONYMOUS,
        ):
            inverted.record(sound[arm.value])  # type: ignore[index]

        verdict = decide_write_crossing(**{**sound, "recorder": inverted})
        assert verdict.confirmed is False, (
            "the arms went out with the payload ahead of its own control and the "
            "oracle confirmed anyway — every observation it graded was made through a "
            "collection the payload had already grown"
        )
        assert verdict.arms_inverted is True
        assert verdict.why_unconfirmed == REFERENCE_NOT_OWNED

    def test_the_same_observations_in_the_declared_order_do_confirm(self) -> None:
        """The control for the test above: the inversion is the only difference."""
        assert decide_write_crossing(**_sound_arms()).confirmed is True

    def test_owner_read_after_the_crossing_is_an_inversion_too(self) -> None:
        """Arm 5 reads the collection arm 3 wrote into — the payload grading itself."""
        sound = _sound_arms()
        inverted = WriteArmRecorder()
        for arm in (
            WriteArm.CONTROL_SELF,
            WriteArm.CONTROL_ABSENT,
            WriteArm.ANONYMOUS,
            WriteArm.CROSSING,
            WriteArm.OWNER_READ,
        ):
            inverted.record(sound[arm.value])
        verdict = decide_write_crossing(**{**sound, "recorder": inverted})
        assert verdict.confirmed is False
        assert verdict.arms_inverted is True

    def test_a_missing_arm_is_not_read_as_an_inversion(self) -> None:
        """A precondition that abstained before an arm ran is not the wrong ORDER."""
        recorder = WriteArmRecorder()
        sound = _sound_arms()
        recorder.record(sound["owner_read"])
        recorder.record(sound["control_self"])
        assert recorder.dispatch_order_holds() is True


class TestTheHelpers:
    def test_a_located_object_is_attributed_to_our_own_marker(self) -> None:
        records = [{"id": 1, "comment": "somebody else's"}, {"id": 2, "comment": "mark-42"}]
        located = locate_created_object(records, "mark-42")
        assert located.located is True
        assert located.identifier == "2"

    def test_an_unmarked_read_locates_nothing(self) -> None:
        """Never "the newest row": that attributes whatever another client wrote."""
        records = [{"id": 1, "comment": "a"}, {"id": 2, "comment": "b"}]
        assert locate_created_object(records, "mark-42").located is False
        assert locate_created_object(records, "").located is False

    def test_the_identifier_is_read_for_the_operator_not_for_the_verdict(self) -> None:
        assert object_identifier({"id": 4, "UserId": 1}) == "4"
        assert object_identifier({"UserId": 1}) == ""

    def test_the_owner_reference_prefers_a_value_we_hold(self) -> None:
        body = json.dumps([{"id": 3, "UserId": "1", "author": "someone"}])
        field_path, value = owner_reference_of(body, B_IDENTITY)
        assert value == "1"
        assert "UserId" in field_path

    def test_every_arm_sends_one_shape_differing_only_in_the_owner(self) -> None:
        base = {"comment": "clinkz-comment", "rating": "clinkz-rating"}
        left = crossing_body(base, "UserId", "1", "comment", "mark")
        right = crossing_body(base, "UserId", "2", "comment", "mark")
        assert set(left) == set(right)
        assert {k: v for k, v in left.items() if k != "UserId"} == {
            k: v for k, v in right.items() if k != "UserId"
        }
        assert left["comment"] == "mark"
        assert base == {"comment": "clinkz-comment", "rating": "clinkz-rating"}, (
            "the caller's base object must not be mutated — every arm builds from it"
        )

    def test_no_sibling_field_is_sent_empty_but_present(self) -> None:
        """Invariant 16: a field the methodology did not intend to set is omitted."""
        body = crossing_body({"comment": "clinkz-comment"}, "UserId", "1", "comment", "mark")
        assert all(str(v).strip() for v in body.values())

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("42", "numeric"),
            ("3f2504e0-4f89-41d3-9a0c-0305e82c3301", "uuid"),
            ("aXbYcZ", "opaque"),
        ],
    )
    def test_the_reference_shape_is_classified_from_the_value(
        self, value: str, expected: str
    ) -> None:
        assert reference_format(value) == expected

    def test_the_residual_note_names_the_collection_and_the_identifier(self) -> None:
        note = residual_note("https://app.test/api/Feedbacks", "42", WriteArm.CROSSING)
        assert "https://app.test/api/Feedbacks" in note
        assert "42" in note
        assert "manual" in note.lower()
        assert "crossing" in note


class TestWhatTheLiveRunsFound:
    """Three defects the unit fixtures could not have produced, pinned.

    Each was found by dispatching every arm against a running Juice Shop, and
    each has the same shape: the class did the right thing and reported the
    opposite, because a value it built was wrong in a way no synthetic fixture
    would reproduce. A test suite whose objects are all hand-written cannot see
    any of them — which is the argument for the live loop, and the reason they
    are written down here rather than fixed and forgotten.
    """

    def test_an_owning_field_read_from_a_collection_is_a_leaf_name(self) -> None:
        """``[9].UserId`` is not a key any handler has.

        Found twice, once per discovery route: every arm went out carrying an
        indexed path, the server ignored an unknown field, all four objects came
        back unattributed, and the class reported that the collection's records
        name no owner while its own snapshot carried one.
        """
        assert owner_field_key("[9].UserId") == "UserId"
        assert owner_field_key("UserId") == "UserId"
        assert owning_field_of(json.dumps([{"UserId": 3, "id": 1}])) == "UserId"

    def test_the_owning_field_survives_a_single_object_too(self) -> None:
        """The other spelling, so the normalisation cannot regress one way only."""
        assert owning_field_of(json.dumps({"UserId": 3, "id": 1})) == "UserId"

    @pytest.mark.parametrize(
        ("observed", "expected_type"),
        [(523423432, int), ("1701", str), (3.5, float), (True, bool), (None, str)],
    )
    def test_a_sibling_value_keeps_the_type_the_server_uses(
        self, observed: Any, expected_type: type
    ) -> None:
        """A typed API rejects ``clinkz-mobileNum`` in a numeric column.

        Juice Shop's ``/api/Addresss`` answers ``Validation min on mobileNum``
        and ``Validation len on zipCode`` — a 400 that says nothing about the
        claim, which the class then reported as "this endpoint's writes cannot be
        read back".
        """
        assert isinstance(benign_value_like(observed), expected_type)

    def test_a_sibling_value_keeps_the_shape_and_none_of_the_content(self) -> None:
        """Copying the observed value would satisfy the validator and leak a row.

        Writing another principal's real address into a new object is a worse
        thing to leave behind than a placeholder, so the length and magnitude are
        copied and the content is not.
        """
        assert len(benign_value_like("1701")) == len("1701")
        assert benign_value_like("1701") != "1701"
        assert len(str(benign_value_like(523423432))) == len("523423432")
        assert benign_value_like(523423432) != 523423432

    def test_ref_a_falls_back_to_the_callers_own_session_claims(self) -> None:
        """An application that assigns NO owner is the shape this class is for.

        Juice Shop stores ``UserId: null`` on a create that omits the field, so
        neither the anchored object nor the caller's own records yield ``ref(A)``
        — and abstaining there would abstain on exactly the targets worth
        testing. The last tier reads it from the caller's own identity claims,
        filtered to the shape the field is observed to carry.
        """
        assert shaped_self_reference(frozenset({"2", "jim@t.test"}), ("3",)) == "2"

    def test_a_claim_of_the_wrong_shape_is_not_offered(self) -> None:
        """A collection keyed on a numeric id is not named by an email address."""
        assert shaped_self_reference(frozenset({"jim@t.test"}), ("3",)) == ""

    def test_a_reference_read_from_a_collection_is_never_taken_on_trust(self) -> None:
        """A collection shows everyone's records; the first one is nobody's in particular."""
        snapshot = json.dumps([{"UserId": "7", "id": 1}, {"UserId": "2", "id": 2}])
        assert verified_owner_reference_of(snapshot, frozenset({"2"}))[1] == "2"
        assert verified_owner_reference_of(snapshot, frozenset({"9"})) == ("", "")
        # The permissive route DOES fall back — which is why it is only used on an
        # object the SERVER attributed, where the value is that principal's by
        # construction.
        assert owner_reference_of(snapshot, frozenset({"9"}))[1] == "7"
