"""The four-arm IDOR oracle, offline.

Two halves, deliberately separate:

* :mod:`clinkz.agents._idor_oracle` is pure — arms in, verdict out — so the whole
  decision table is exercised against recorded response bodies with no network,
  no LLM and no agent.
* The agent-level tests drive ``_idor_phase5_verify`` through a scripted target
  that answers by ``(reference, principal)``, which is the only way to tell the
  four arms apart: a mock returning one body for every request cannot
  distinguish "A read B's record" from "this endpoint returns the same page to
  everybody", and that is precisely the confusion the oracle exists to resolve.

The record bodies come from ``tests/fixtures/idor_recorded_records.json`` — real
bytes a DVWA install actually sent, header block removed and checked against the
engagement's own credential-shape vocabulary. The corpus holds exactly one clean
per-principal read across 271,169 recorded HTTP invocations, so the peer and
owner renderings vary that recording's record FIELDS while every byte of chrome,
token and whitespace stays what the target sent.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._idor_oracle import (
    ANCHOR_NOT_ESTABLISHED,
    ANONYMOUS_ARM_NOT_DISPATCHED,
    ATTRIBUTION_IDENTICAL_RENDERING,
    ATTRIBUTION_STABLE_FIELDS,
    NO_OWNING_FIELD,
    OWNING_FIELD_NAMES_PRINCIPAL,
    OWNING_FIELD_NOT_CALLER,
    TIER_MULTI_ROLE,
    TIER_SINGLE_ROLE,
    ArmObservation,
    IDORArm,
    IDORVerdict,
    SelfAnchor,
    anchor_self_reference,
    attribution_between,
    decide_idor,
    idor_body_fingerprint,
    materially_differs,
    owner_claim,
    owning_fields,
    stable_fields,
    synthesize_absent_reference,
)
from clinkz.agents._principal import (
    ANONYMOUS,
    PRIVILEGE_ORDER_UNDECLARED,
    Principal,
    parse_role_sessions,
    privilege_order,
)
from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED, Finding
from clinkz.models.methodology import IDORPrimitives
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.vuln_classes import for_method, multi_principal_requirement
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

_FIXTURE = json.loads(
    (pathlib.Path(__file__).parents[1] / "fixtures" / "idor_recorded_records.json").read_text(
        encoding="utf-8"
    )
)
#: The real recorded rendering, principal ``admin admin`` at ``id=1``.
OWNER_RECORD: str = _FIXTURE["owner_record"]

SCOPE = EngagementScope(
    name="idor-four-arm-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


def _record_for(first: str, surname: str, reference: str) -> str:
    """The recorded rendering with this principal's fields substituted in."""
    body = OWNER_RECORD.replace("First name: admin", f"First name: {first}")
    body = body.replace("Surname: admin", f"Surname: {surname}")
    return re.sub(r"<pre>ID: [^<]*", f"<pre>ID: {reference}", body)


A_RECORD = _record_for("alice", "anders", "1")
B_RECORD = _record_for("bob", "bergman", "2")
NOT_FOUND = OWNER_RECORD.replace(
    "<pre>ID: 1<br />First name: admin<br />Surname: admin</pre>", "<pre></pre>"
)


def _arm(
    arm: IDORArm,
    body: str,
    *,
    status: int = 200,
    reference: str = "",
    principal: str = "alice",
    dispatched: bool = True,
) -> ArmObservation:
    return ArmObservation(
        arm=arm,
        dispatched=dispatched,
        status=status,
        body=body,
        reference=reference,
        principal=principal,
    )


#: Alice is the CALLER. Her identity values come from the session material the
#: engagement holds, never from a response — see
#: :meth:`~clinkz.agents._principal.Principal.identity_tokens`.
ALICE_IDENTITY = frozenset({"alice"})
HELD_IDENTITIES = {"bob": frozenset({"bob"})}

#: ``ref(A)`` established from alice's own record, which is what every arm is
#: graded relative to. Never the value the crawl happened to see.
ANCHOR_A = SelfAnchor(
    anchored=True, reference="1", field="first name", why="record 1 names alice as its owner"
)


def _four_arms(**overrides: Any) -> dict[str, Any]:
    """The arms of a genuine, fully-cleared IDOR. Override one to break it."""
    base = {
        "self_arm": _arm(IDORArm.SELF, A_RECORD, reference="1"),
        "crossing": _arm(IDORArm.CROSSING, B_RECORD, reference="2"),
        "nonexistent": _arm(IDORArm.NONEXISTENT, NOT_FOUND, status=404, reference="900012345"),
        "anonymous": _arm(IDORArm.ANONYMOUS, "", status=302, reference="2", principal=ANONYMOUS),
        "owner_read": _arm(IDORArm.OWNER_READ, B_RECORD, reference="2", principal="bob"),
        "anchor": ANCHOR_A,
        "caller_identity": ALICE_IDENTITY,
        "held_identities": HELD_IDENTITIES,
        "principals_available": 2,
        "principals_required": 2,
        "single_role_why": "single_role_cannot_attribute",
    }
    base.update(overrides)
    return base


# ===========================================================================
# The pure decision table
# ===========================================================================


class TestTheFourArmsMustAllClear:
    def test_a_genuine_crossing_confirms(self) -> None:
        verdict = decide_idor(**_four_arms())
        assert verdict.confirmed is True
        assert verdict.tier == TIER_MULTI_ROLE
        # The CLAIM is the owning field, not a fingerprint comparison: the
        # record served to alice names bob, an identity this engagement holds.
        assert verdict.attribution == OWNING_FIELD_NAMES_PRINCIPAL
        assert verdict.owning_field
        assert verdict.anchored is True
        assert verdict.control_refused is True
        assert verdict.why_unconfirmed == ""
        # B's own read agrees, and is reported as what it is.
        assert verdict.corroboration == ATTRIBUTION_IDENTICAL_RENDERING

    def test_an_unanchored_self_arm_abstains(self) -> None:
        """PART 1. The defect that shipped five findings on engagement 20fad9dc.

        Every arm below the anchor is a comparison, and a comparison does not
        know which side it is standing on. Without a reference shown to be the
        CALLER's, the whole table is ungraded rather than graded wrongly.
        """
        verdict = decide_idor(
            **_four_arms(anchor=SelfAnchor(anchored=False, why="no record named alice"))
        )
        assert verdict.confirmed is False
        assert verdict.anchored is False
        assert verdict.why_unconfirmed == ANCHOR_NOT_ESTABLISHED
        assert "could not be established" in verdict.detail

    def test_inverted_arms_are_refused_loudly(self) -> None:
        """The self arm carrying anything but the anchored reference is refused.

        This is the run-3 shape exactly: the crawl saw ``1``, the caller owned
        ``2``, and the arms ran backwards. It is not an abstain with a shrug —
        ``arms_inverted`` says the run asked the wrong question.
        """
        verdict = decide_idor(
            **_four_arms(
                anchor=SelfAnchor(anchored=True, reference="2", why="record 2 names alice"),
                self_arm=_arm(IDORArm.SELF, B_RECORD, reference="1"),
            )
        )
        assert verdict.confirmed is False
        assert verdict.arms_inverted is True
        assert verdict.why_unconfirmed == ANCHOR_NOT_ESTABLISHED
        assert "ARMS INVERTED" in verdict.detail

    def test_the_self_and_crossing_arms_may_not_be_the_same_reference(self) -> None:
        verdict = decide_idor(
            **_four_arms(crossing=_arm(IDORArm.CROSSING, B_RECORD, reference="1"))
        )
        assert verdict.confirmed is False
        assert verdict.arms_inverted is True

    def test_the_control_not_refusing_kills_it(self) -> None:
        """``ref(∅)`` answering like ``ref(B)`` means the handler answers anything."""
        verdict = decide_idor(
            **_four_arms(
                nonexistent=_arm(IDORArm.NONEXISTENT, B_RECORD, reference="900012345"),
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == "never_sent_control_did_not_refuse"
        assert "nobody owns" in verdict.detail

    def test_a_public_object_is_not_a_boundary_crossing(self) -> None:
        """The anonymous arm being served it means there is no boundary at all."""
        verdict = decide_idor(
            **_four_arms(
                anonymous=_arm(IDORArm.ANONYMOUS, B_RECORD, reference="2", principal=ANONYMOUS),
            )
        )
        assert verdict.confirmed is False
        assert verdict.object_is_public is True
        # NOT a lead: a permanent per-public-endpoint alarm is the false alarm
        # the ledger's ``correctly_empty`` category exists to prevent.
        assert verdict.why_unconfirmed == ""

    def test_an_anonymous_200_disqualifies_however_the_bytes_differ(self) -> None:
        """PART 3. ``/rest/products/2/reviews``, byte for byte.

        The anonymous caller was served the SAME review — same ``_id`` — with a
        per-caller ``"liked":true`` decoration, 13 bytes that made
        :func:`materially_differs` True and let a public record confirm. An
        anonymous 200 on the crossing reference is disqualifying, full stop:
        if anonymous gets it there is no boundary to cross, whatever else the
        bytes do.
        """
        review = (
            '{"status":"success","data":[{"message":"m","author":"bob","_id":"t2Dz7onX2hLE7tiB8"}]}'
        )
        decorated = review.replace('"_id"', '"liked":true,"_id"')
        verdict = decide_idor(
            **_four_arms(
                crossing=_arm(IDORArm.CROSSING, review, reference="2"),
                owner_read=_arm(IDORArm.OWNER_READ, review, reference="2", principal="bob"),
                anonymous=_arm(IDORArm.ANONYMOUS, decorated, reference="2", principal=ANONYMOUS),
            )
        )
        assert materially_differs(
            _arm(IDORArm.ANONYMOUS, decorated, reference="2"),
            _arm(IDORArm.CROSSING, review, reference="2"),
        ), "the 13-byte decoration really does make the old test pass — that was the defect"
        assert verdict.confirmed is False
        assert verdict.object_is_public is True

    def test_an_anonymous_arm_that_was_never_sent_refused_nothing(self) -> None:
        """An arm that was not dispatched proves nothing in either direction."""
        verdict = decide_idor(
            **_four_arms(
                anonymous=_arm(
                    IDORArm.ANONYMOUS,
                    "",
                    status=0,
                    reference="2",
                    principal=ANONYMOUS,
                    dispatched=False,
                ),
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == ANONYMOUS_ARM_NOT_DISPATCHED

    def test_reading_our_own_object_back_is_not_a_crossing(self) -> None:
        verdict = decide_idor(
            **_four_arms(crossing=_arm(IDORArm.CROSSING, A_RECORD, reference="2"))
        )
        assert verdict.confirmed is False
        assert "A's own object" in verdict.detail

    def test_a_crossing_that_never_resolved_is_nothing(self) -> None:
        verdict = decide_idor(
            **_four_arms(
                crossing=_arm(IDORArm.CROSSING, "", status=404, reference="2"),
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == ""

    def test_a_reflection_sink_is_not_an_object_reference(self) -> None:
        """The reflection guard, on the pure table where an anchor can be given.

        A parameter that echoes its input defeats every other arm at once: the
        never-issued reference is echoed too (so the control refuses, on a
        DIFFERENT string), and the owner's read of the same reference echoes the
        same string back (so the corroboration reads as an identical rendering).
        Three arms agreeing on an artifact of one substitution is not three
        pieces of evidence.

        The agent-level version of this now refuses one step earlier — a
        reflection sink names no owner, so it does not anchor — which is the
        more honest refusal. This keeps the guard itself covered, on the pure
        table where the anchor is supplied.

        The guard runs only on a body naming NO owner, and deliberately: a
        response carrying an owning field is a RECORD, and asking whether a
        record echoes its own identifier has a misleading answer, because
        substitution is global. Rewriting ``1`` into ``2`` across
        ``{"id":1,"UserId":1}`` yields the caller's own record exactly, so the
        guard would fire on the textbook sequential-integer crossing.
        """
        echoed = "note: Welcome longref123 to your dashboard\n"
        mine = "note: Welcome 1 to your dashboard\n"
        verdict = decide_idor(
            **_four_arms(
                self_arm=_arm(IDORArm.SELF, mine, reference="1"),
                crossing=_arm(IDORArm.CROSSING, echoed, reference="longref123"),
                owner_read=_arm(
                    IDORArm.OWNER_READ, echoed, reference="longref123", principal="bob"
                ),
            )
        )
        assert verdict.confirmed is False
        assert "reflection sink" in verdict.detail

    def test_a_short_reference_cannot_establish_an_echo(self) -> None:
        """The sequential-integer crossing is not a reflection sink.

        Substitution is global. ``ref(B)="1"`` rewritten to ``ref(A)="2"``
        across ``{"id":1,"UserId":1}`` produces ``{"id":2,"UserId":2}`` — the
        caller's own record byte for byte — so a guard with no length floor
        calls every numeric IDOR an echo. Below
        ``_MIN_ECHOABLE_REFERENCE_LEN`` the guard abstains; phase 1's canary
        probe covers the short-reference sink with a MINTED token, which is
        distinctive by construction.
        """
        from clinkz.agents._idor_oracle import reflection_explains

        owner = '{"id":1,"UserId":1}'
        caller = '{"id":2,"UserId":2}'
        assert (
            reflection_explains(
                _arm(IDORArm.CROSSING, owner, reference="1"),
                _arm(IDORArm.SELF, caller, reference="2"),
            )
            is False
        )

    def test_a_record_naming_an_owner_is_never_read_as_an_echo(self) -> None:
        """The same defect one layer up: the guard is not even asked."""
        verdict = decide_idor(
            **_four_arms(
                self_arm=_arm(IDORArm.SELF, '{"id":2,"UserId":2}', reference="2"),
                crossing=_arm(IDORArm.CROSSING, '{"id":1,"UserId":1}', reference="1"),
                nonexistent=_arm(IDORArm.NONEXISTENT, '{"data":null}', reference="900012345"),
                anonymous=_arm(
                    IDORArm.ANONYMOUS, "", status=401, reference="1", principal=ANONYMOUS
                ),
                owner_read=_arm(
                    IDORArm.OWNER_READ, '{"id":1,"UserId":1}', reference="1", principal="bob"
                ),
                anchor=SelfAnchor(
                    anchored=True, reference="2", field="UserId", why="record 2 names alice"
                ),
                caller_identity=frozenset({"2"}),
                held_identities={"bob": frozenset({"1"})},
            )
        )
        assert verdict.confirmed is True, verdict.detail
        assert verdict.attribution == OWNING_FIELD_NAMES_PRINCIPAL

    def test_the_owners_own_read_is_corroboration_not_the_claim(self) -> None:
        """PART 2, stated as a test.

        ``identical_rendering`` used to BE the attribution, and it is vacuous
        whenever B outranks A: an admin B reads A's records too, so matching B's
        read proves *B can also read this*. The claim rests on the owning field,
        so B failing to read it costs the corroboration and not the finding.
        """
        verdict = decide_idor(
            **_four_arms(
                owner_read=_arm(IDORArm.OWNER_READ, "", status=403, reference="2", principal="bob"),
            )
        )
        assert verdict.confirmed is True, verdict.detail
        assert verdict.attribution == OWNING_FIELD_NAMES_PRINCIPAL
        assert verdict.corroboration == ""
        assert "did not corroborate" in verdict.detail

    def test_a_record_naming_no_owner_abstains(self) -> None:
        """A public catalogue record has no owning principal, so there is nobody
        it can be said to belong to — three negatives are not a positive."""
        catalogue = '{"sku": "AJ-1000", "name": "Apple Juice", "price": "1.99"}'
        mine = '{"sku": "OJ-1000", "name": "Orange Juice", "price": "2.99"}'
        verdict = decide_idor(
            **_four_arms(
                self_arm=_arm(IDORArm.SELF, mine, reference="1"),
                crossing=_arm(IDORArm.CROSSING, catalogue, reference="2"),
                owner_read=_arm(IDORArm.OWNER_READ, catalogue, reference="2", principal="bob"),
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == NO_OWNING_FIELD


class TestTheCorroboratingArmIsNotTheOwnersRead:
    """B is a CANDIDATE owner, and the sentence must not call it the owner.

    Found live on engagement ``aba713f1`` (2026-09-02). All three confirmed
    crossings rendered "the owner's own authorized read corroborates it" while
    the arm ran as ``admin`` and the owning field named user ``3`` — a principal
    that engagement held no credential for.

    It is structural, not a coincidence of that run. ``ref(B)`` is reached by
    phase 3 INCREMENTING the anchored ``ref(A)``, so it lands on whoever owns
    that reference; and B is drawn from the principals the engagement HOLDS that
    A does not outrank, which for the commonest supply — one admin beside one
    customer — is the admin. The two have no reason to coincide.

    The verdict never turned on it (``corroboration`` is load-bearing in no
    branch), which is exactly why it survived: the only thing wrong was the
    sentence, and the sentence is what a client reads.
    """

    def test_the_sentence_names_a_second_principal_not_the_owner(self) -> None:
        """The observation is unchanged; only the claim about whose read it was."""
        verdict = decide_idor(**_four_arms())
        assert verdict.confirmed is True
        assert verdict.corroboration == ATTRIBUTION_IDENTICAL_RENDERING
        assert "second principal's authorized read" in verdict.detail
        assert "the owner's own authorized read" not in verdict.detail

    def test_the_principal_that_actually_ran_the_arm_is_named(self) -> None:
        """A reader can check it against the ``Arm owner_read:`` line."""
        verdict = decide_idor(
            **_four_arms(
                owner_read=_arm(
                    IDORArm.OWNER_READ, B_RECORD, reference="2", principal="admin@example.test"
                )
            )
        )
        assert "admin@example.test" in verdict.detail

    def test_the_negative_sentence_drops_the_claim_too(self) -> None:
        """B failing to corroborate costs the corroboration, not the finding —
        and says so without calling B the owner."""
        verdict = decide_idor(
            **_four_arms(
                owner_read=_arm(IDORArm.OWNER_READ, "", status=403, reference="2", principal="bob"),
            )
        )
        assert verdict.confirmed is True
        assert verdict.corroboration == ""
        assert "second principal's authorized read did not corroborate" in verdict.detail
        assert "the owner's own authorized read" not in verdict.detail

    def test_it_stays_corroboration_and_decides_nothing(self) -> None:
        """The whole reason the label could be wrong for this long."""
        with_arm = decide_idor(**_four_arms())
        without = decide_idor(
            **_four_arms(
                owner_read=_arm(IDORArm.OWNER_READ, "", status=403, reference="2", principal="bob")
            )
        )
        assert with_arm.confirmed == without.confirmed is True
        assert with_arm.attribution == without.attribution


class TestTheTwoTiers:
    def test_a_single_role_run_may_only_lead(self) -> None:
        """Every control cleared and it is STILL not a finding. PART 3's whole rule."""
        verdict = decide_idor(
            **_four_arms(owner_read=None, principals_available=1, principals_required=2)
        )
        assert verdict.confirmed is False
        assert verdict.tier == TIER_SINGLE_ROLE
        assert verdict.why_unconfirmed == "single_role_cannot_attribute"
        assert "no second authorized read to corroborate it against" in verdict.detail

    def test_no_principals_at_all_is_the_single_role_tier(self) -> None:
        """A direct methodology invocation cannot attribute either. Not an exemption."""
        verdict = decide_idor(
            **_four_arms(owner_read=None, principals_available=0, principals_required=2)
        )
        assert verdict.confirmed is False
        assert verdict.tier == TIER_SINGLE_ROLE

    def test_the_lead_reason_is_registered_vocabulary(self) -> None:
        from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED

        assert "single_role_cannot_attribute" in UNPROVEN_WHY_UNCONFIRMED

    def test_the_registry_is_what_declares_the_requirement(self) -> None:
        requirement = multi_principal_requirement("_test_idor")
        assert requirement.principals_required == 2
        assert requirement.why_unconfirmed == "single_role_cannot_attribute"
        assert requirement.reason.strip()

    def test_every_other_class_needs_exactly_one_principal(self) -> None:
        """The new rule must not quietly widen to classes that never needed it."""
        from clinkz.agents.exploit import DISPATCHABLE_TEST_METHODS

        widened = sorted(
            name
            for name in DISPATCHABLE_TEST_METHODS
            if name != "_test_idor" and multi_principal_requirement(name).principals_required > 1
        )
        assert widened == [], widened


class TestAttribution:
    def test_an_identical_rendering_attributes(self) -> None:
        route, values = attribution_between(
            owner_body=B_RECORD, crossing_body=B_RECORD, self_body=A_RECORD
        )
        assert route == ATTRIBUTION_IDENTICAL_RENDERING
        assert values == ()

    def test_a_map_keyed_by_the_record_identifier_does_not_leak_it(self) -> None:
        """A path segment is schema only while the object it indexes is a RECORD.

        ``{"accounts": {"victim@corp.example": {...}}}`` puts the identifier in
        the leaf PATH, so fingerprinting the values alone still reproduced a
        victim's email verbatim in the evidence — the exact disclosure moving off
        values was meant to remove.
        """
        body = '{"caller": "%s", "accounts": {"%s": {"iban": "GB29ABCD1234", "bal": "41902.55"}}}'
        route, values = attribution_between(
            owner_body=body % ("victim", "victim@corp.example"),
            crossing_body=body % ("tester", "victim@corp.example"),
            self_body='{"caller": "tester", "accounts": {"tester@corp.example": '
            '{"iban": "GB77WXYZ9999", "bal": "12.00"}}}',
        )
        assert route == ATTRIBUTION_STABLE_FIELDS
        blob = " ".join(values)
        for leaked in ("victim@corp.example", "victim", "corp.example", "GB29ABCD1234"):
            assert leaked not in blob, f"{leaked!r} reached the evidence through the path"
        assert "<id:" in blob, "the identifier segment is fingerprinted, not dropped"
        assert "accounts." in blob and ".iban" in blob, (
            "the surrounding path is schema and must survive - it is what a remediation has to name"
        )

    def test_field_values_attribute_across_different_renderings(self) -> None:
        """An envelope naming the caller changes the page and not the record."""
        owner = json.dumps(
            {"viewer": "bob", "record": {"first": "bob", "surname": "bergman", "iban": "GB29ABCD"}}
        )
        crossing = json.dumps(
            {
                "viewer": "alice",
                "record": {"first": "bob", "surname": "bergman", "iban": "GB29ABCD"},
            }
        )
        mine = json.dumps(
            {
                "viewer": "alice",
                "record": {"first": "alice", "surname": "anders", "iban": "GB77WXYZ"},
            }
        )
        route, values = attribution_between(
            owner_body=owner, crossing_body=crossing, self_body=mine
        )
        assert route == ATTRIBUTION_STABLE_FIELDS
        # The attributing FIELDS are named; their values are not. An attributing
        # value is a real customer's surname, IBAN or address on a client
        # engagement, and this is the first target data an IDOR finding has
        # carried into a document that gets emailed. The claim survives on two
        # fingerprints: equal to the owner's own read, different from A's.
        assert any("field=record.surname" in v for v in values)
        assert any("field=record.iban" in v for v in values)
        blob = " ".join(values)
        for value in ("bergman", "GB29ABCD", "bob"):
            assert value not in blob, f"{value!r} is the target's data and must not be reproduced"
        for line in values:
            assert "owner_fp=" in line and "caller_fp=" in line
        assert "caller_fp=absent" not in blob, (
            "the caller's own record carries all three fields, so each has a differing "
            "fingerprint rather than an absence"
        )

    def test_values_the_callers_own_record_carries_do_not_attribute(self) -> None:
        """Subtracting A's record is the load-bearing half; without it the template wins."""
        shared = json.dumps({"currency": "GBP", "status": "active", "role": "user"})
        route, values = attribution_between(
            owner_body=shared, crossing_body=shared[:-1] + " ", self_body=shared
        )
        assert route == ""
        assert values == ()

    def test_one_matching_field_is_not_attribution(self) -> None:
        owner = json.dumps({"first": "bob", "colour": "blue"})
        crossing = json.dumps({"first": "bob", "colour": "green"})
        mine = json.dumps({"first": "alice", "colour": "green"})
        route, _ = attribution_between(owner_body=owner, crossing_body=crossing, self_body=mine)
        assert route == ""

    def test_stable_fields_reads_a_real_recorded_rendering(self) -> None:
        fields = stable_fields(A_RECORD)
        assert fields, "the recorded DVWA rendering yielded no field pairs"
        assert any(v == "alice" for v in fields.values())


# ===========================================================================
# The anchor and the owning field, against the bytes engagement 20fad9dc sent
# ===========================================================================

#: Real response bodies from ``outputs/20fad9dc-…``, trimmed of the product
#: lists. A is jim, who is user 2; the crawl saw ``id=1``, which is admin's.
JS_BASKET_1 = '{"status":"success","data":{"id":1,"coupon":null,"UserId":1}}'
JS_BASKET_2 = '{"status":"success","data":{"id":2,"coupon":null,"UserId":2}}'
JS_USER_1 = (
    '{"status":"success","data":{"id":1,"username":"","email":"admin@juice-sh.op",'
    '"role":"admin","isActive":true}}'
)
JS_USER_2 = (
    '{"status":"success","data":{"id":2,"username":"","email":"jim@juice-sh.op",'
    '"role":"customer","isActive":true}}'
)
JS_REVIEWS_1 = (
    '{"status":"success","data":[{"message":"One of my favorites!",'
    '"author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],'
    '"_id":"b6vJFxErvT2NfHSxY"}]}'
)
JS_REVIEWS_2 = (
    '{"status":"success","data":[{"message":"y0ur f1r3wall needs m0r3 musc13",'
    '"author":"uvogin@juice-sh.op","product":2,"likesCount":0,"likedBy":[],'
    '"_id":"t2Dz7onX2hLE7tiB8"}]}'
)

#: jim's identity, as ``identity_tokens()`` reads it out of the bearer token the
#: target issued US: ``data.id`` 2 and ``data.email``. Never off a response.
JIM = frozenset({"2", "jim@juice-sh.op"})
ADMIN = frozenset({"1", "admin@juice-sh.op"})


class TestTheAnchor:
    def test_the_crawls_value_is_not_the_callers_reference(self) -> None:
        """The 2026-08-31 defect, pinned to the bytes that produced it.

        The crawl saw ``id=1``. jim is user **2**. Anchoring picks 2 — and the
        run that shipped five findings used 1 as the self arm and 2 as the
        crossing, so its "crossing" was jim reading jim's own basket.
        """
        anchor = anchor_self_reference(
            candidates=(("1", JS_BASKET_1), ("2", JS_BASKET_2)), caller_identity=JIM
        )
        assert anchor.anchored is True
        assert anchor.reference == "2", "the crawl's 1 is admin's basket, not jim's"
        assert anchor.field == "data.UserId"

    def test_a_reference_that_is_not_user_owned_anchors_nothing(self) -> None:
        """``/rest/products/:id/reviews`` — the id is a PRODUCT, not a record of
        jim's. No candidate names the caller, so the class abstains rather than
        grading a comparison it cannot orient."""
        anchor = anchor_self_reference(
            candidates=(("1", JS_REVIEWS_1), ("2", JS_REVIEWS_2)), caller_identity=JIM
        )
        assert anchor.anchored is False
        assert "could not be established" in anchor.why

    def test_an_unreadable_caller_identity_anchors_nothing(self) -> None:
        """An opaque cookie asserts no identity we can read. Abstain, not guess."""
        anchor = anchor_self_reference(
            candidates=(("2", JS_BASKET_2),), caller_identity=frozenset()
        )
        assert anchor.anchored is False
        assert "unreadable" in anchor.why


class TestTheOwningField:
    def test_a_record_naming_a_principal_we_hold_is_the_strongest_route(self) -> None:
        """``/api/Users/1`` served to jim carries ``email: admin@juice-sh.op``.

        Checked against an identity the ENGINE holds, so no response can satisfy
        it by choosing its own bytes.
        """
        claim = owner_claim(
            crossing_body=JS_USER_1,
            self_body=JS_USER_2,
            caller_identity=JIM,
            held_identities={"admin": ADMIN},
        )
        assert claim is not None
        assert claim.route == OWNING_FIELD_NAMES_PRINCIPAL
        assert claim.principal == "admin"
        assert "admin@juice-sh.op" not in claim.evidence, (
            "the owning VALUE is a real identity and never reaches the deliverable"
        )
        assert "owner_fp=" in claim.evidence and "caller_fp=" in claim.evidence

    def test_an_owner_field_differing_from_the_callers_own_record(self) -> None:
        """``UserId: 1`` where the caller's own basket says ``UserId: 2``.

        Route 2 stands on its own: hold no session for the owner and the claim
        is unchanged, which is the case on every real engagement where the
        neighbouring record belongs to somebody who is not a supplied role.
        """
        claim = owner_claim(
            crossing_body=JS_BASKET_1,
            self_body=JS_BASKET_2,
            caller_identity=JIM,
            held_identities={},
        )
        assert claim is not None
        assert claim.route == OWNING_FIELD_NOT_CALLER
        assert claim.field == "data.UserId"

    def test_the_run_three_crossing_was_the_callers_own_record(self) -> None:
        """Graded the way run 3 dispatched it, the claim evaporates.

        ``crossing`` carried ``2``, which is jim's own basket, and ``self``
        carried admin's. Nothing in that response names an owner other than the
        caller, because the caller IS the owner.
        """
        claim = owner_claim(
            crossing_body=JS_BASKET_2,
            self_body=JS_BASKET_1,
            caller_identity=JIM,
            held_identities={"admin": ADMIN},
        )
        assert claim is None

    def test_a_review_names_an_author_and_still_never_reaches_a_claim(self) -> None:
        """The reviews endpoint is not killed by the owning field — it has one.

        ``author`` is an owner-shaped name and a review really does have an
        author. It dies twice over and neither is here: no review names JIM, so
        the anchor fails (Part 1), and an anonymous caller is served the record,
        so the public gate disqualifies it (Part 3). Stating that plainly
        matters — a rule that appeared to kill this case for the wrong reason
        would be trusted on a target where the reason does not hold.
        """
        assert owning_fields(JS_REVIEWS_2, principal_values=JIM) == {
            "data[0].author": "uvogin@juice-sh.op"
        }
        assert not anchor_self_reference(
            candidates=(("1", JS_REVIEWS_1), ("2", JS_REVIEWS_2)), caller_identity=JIM
        ).anchored

    def test_a_catalogue_record_names_nobody_at_all(self) -> None:
        assert owning_fields('{"sku":"AJ-1000","name":"Apple Juice","price":"1.99"}') == {}

    def test_role_is_not_an_owning_field(self) -> None:
        """``role: customer`` says what a principal IS, not whose record this is —
        and it differs from an admin caller's while identifying nobody."""
        assert "data.role" not in owning_fields(JS_USER_2)

    def test_a_container_named_user_does_not_make_its_leaves_owning(self) -> None:
        """The LEAF decides. Matching the joined path would make
        ``user.createdAt`` an owning field carrying a timestamp."""
        fields = owning_fields('{"user": {"id": 7, "createdAt": "2026-01-01T00:00:00Z"}}')
        assert "user.createdAt" not in fields

    def test_a_value_naming_a_principal_needs_no_owner_shaped_name(self) -> None:
        """DVWA renders ``First name: bob`` and has no ``UserId`` anywhere.

        The value route needs no vocabulary at all: bob is a principal this
        engagement holds, so a record served to alice naming bob is attributed
        on what we know rather than on what the field is called.
        """
        claim = owner_claim(
            crossing_body=B_RECORD,
            self_body=A_RECORD,
            caller_identity=frozenset({"alice"}),
            held_identities={"bob": frozenset({"bob"})},
        )
        assert claim is not None
        assert claim.route == OWNING_FIELD_NAMES_PRINCIPAL

    def test_a_difference_alone_never_attributes(self) -> None:
        """Attribution by difference is ``stable_fields``, which is what the
        vacuous ``identical_rendering`` route amounted to. A field with no
        owner-shaped name and no principal-valued content says nothing."""
        claim = owner_claim(
            crossing_body='{"note": "some other text", "qty": "9"}',
            self_body='{"note": "my text", "qty": "3"}',
            caller_identity=JIM,
            held_identities={"admin": ADMIN},
        )
        assert claim is None


class TestNormalisation:
    def test_a_per_request_token_does_not_make_two_reads_differ(self) -> None:
        """DVWA re-issues a 32-char ``user_token`` on every GET of the same page.

        Two reads of one record must still compare equal, or every token-bearing
        page looks like a different resource on every request.
        """
        token = '<input type="hidden" name="user_token" value="{}">'
        first = A_RECORD.replace("</body>", token.format("a" * 32) + "</body>")
        second = A_RECORD.replace("</body>", token.format("9f3c" * 8) + "</body>")
        assert first != second
        assert idor_body_fingerprint(first) == idor_body_fingerprint(second)

    def test_two_different_records_fingerprint_differently(self) -> None:
        assert idor_body_fingerprint(A_RECORD) != idor_body_fingerprint(B_RECORD)

    def test_a_length_delta_alone_is_not_a_difference(self) -> None:
        """``materially_differs`` refuses length as a discriminator, like auth_state."""
        padded = A_RECORD + "   \n\n  "
        left = _arm(IDORArm.SELF, A_RECORD)
        right = _arm(IDORArm.CROSSING, padded)
        assert len(padded) != len(A_RECORD)
        assert materially_differs(left, right) is False

    def test_a_status_change_is_a_difference(self) -> None:
        assert materially_differs(
            _arm(IDORArm.NONEXISTENT, A_RECORD, status=404),
            _arm(IDORArm.CROSSING, A_RECORD, status=200),
        )

    def test_the_agent_delegates_to_the_one_rule(self) -> None:
        """Two copies of a normalisation rule are two rules that will disagree."""
        assert ExploitAgent._idor_body_fingerprint(A_RECORD) == idor_body_fingerprint(A_RECORD)


class TestTheAbsentReferenceRoundTrips:
    def test_numeric_lands_outside_the_issued_range(self) -> None:
        absent = synthesize_absent_reference(
            id_format="numeric", observed_values=("1", "2", "12"), nonce=7
        )
        assert absent.isdigit()
        assert int(absent) > 12

    def test_numeric_is_never_one_of_the_observed_values(self) -> None:
        for nonce in range(25):
            absent = synthesize_absent_reference(
                id_format="numeric", observed_values=("1", "2", "3"), nonce=nonce
            )
            assert absent not in ("1", "2", "3")

    def test_a_uuid_control_is_a_well_formed_v4(self) -> None:
        import uuid

        absent = synthesize_absent_reference(
            id_format="uuid",
            observed_values=("3f2504e0-4f89-41d3-9a0c-0305e82c3301",),
            nonce=11,
        )
        parsed = uuid.UUID(absent)
        assert parsed.version == 4
        assert len(absent) == 36

    def test_an_opaque_control_keeps_length_and_character_classes(self) -> None:
        """Same on the wire, so only ownership differs — never a bare marker.

        Per-character class preservation, for a token whose letters run outside
        the hex alphabet: a value the target validates as ``[A-Za-z0-9_-]`` must
        still validate, or the control takes a parse-error path the confirming
        arm never took and stops being a control.
        """
        template = "sTz9-Kq4w-Xm2P"
        absent = synthesize_absent_reference(
            id_format="opaque", observed_values=(template,), nonce=3
        )
        assert absent != template
        assert len(absent) == len(template)
        for got, want in zip(absent, template, strict=True):
            assert got.isdigit() == want.isdigit()
            assert got.isalpha() == want.isalpha()
            assert got.isupper() == want.isupper()
            assert (got == "-") == (want == "-")

    def test_an_all_hex_value_stays_in_the_hex_charset(self) -> None:
        """For a hex value the CHARSET is the class — a letter may become a digit.

        Asked of the whole value, not per character, because ``A`` is both a
        letter and a hex digit. Deciding per character applied the hex pool
        (which contains digits) to the ``A`` of a mixed token, so an opaque
        letter could turn into a digit and the round-trip broke.
        """
        template = "AB12-cd34-EF56"
        absent = synthesize_absent_reference(
            id_format="opaque", observed_values=(template,), nonce=3
        )
        assert absent != template
        assert len(absent) == len(template)
        for got, want in zip(absent, template, strict=True):
            assert (got == "-") == (want == "-")
            if want != "-":
                assert got in "0123456789abcdefABCDEF"

    def test_a_hashed_control_stays_hex(self) -> None:
        template = "deadbeefcafe1234"
        absent = synthesize_absent_reference(
            id_format="hashed", observed_values=(template,), nonce=5
        )
        assert absent != template
        assert len(absent) == len(template)
        assert all(c in "0123456789abcdef" for c in absent)

    def test_the_control_is_never_a_clinkz_marker(self) -> None:
        """A minted marker is encoding-invariant and would pass on any target."""
        for id_format in ("numeric", "uuid", "hashed", "opaque"):
            absent = synthesize_absent_reference(
                id_format=id_format, observed_values=("abc123",), nonce=1
            )
            assert "clinkz" not in absent.lower()

    def test_the_same_nonce_synthesises_the_same_control(self) -> None:
        """A replay must re-derive the control, or a stored trace cannot be re-graded."""
        args = {"id_format": "uuid", "observed_values": ("a",), "nonce": 99}
        assert synthesize_absent_reference(**args) == synthesize_absent_reference(**args)


# ===========================================================================
# The agent, driven through a target that answers per (reference, principal)
# ===========================================================================


class _ScriptedLLM(LLMClient):
    def __init__(self, answers: list[str] | None = None) -> None:
        self.prompts: list[str] = []
        self.answers = list(answers or [])

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""


class _ScriptedTarget:
    """A target that serves records by ``(reference, who is asking)``.

    The single-return mock every previous phase-5 test used cannot express what
    the four arms measure — an endpoint that returns one body to everyone is a
    public lookup, and one that returns B's record only to B is not vulnerable —
    so the whole point of this harness is that it answers differently per
    principal.
    """

    def __init__(
        self,
        owned: dict[str, str],
        *,
        public: bool = False,
        enforces: bool = True,
        anonymous_ok: bool = False,
        not_found: str = NOT_FOUND,
        not_found_status: int = 404,
    ) -> None:
        self.owned = owned  # reference -> owning principal role
        self.public = public
        self.enforces = enforces
        self.anonymous_ok = anonymous_ok
        self.not_found = not_found
        self.not_found_status = not_found_status
        self.requests: list[tuple[str, str]] = []

    def bind(self, agent: ExploitAgent) -> ExploitAgent:
        async def _send_probe(page: PageAnalysis, param: str, value: str) -> _HTTPResponse:
            who = ANONYMOUS
            if agent._principal_isolation:
                who = agent._active_principal.role if agent._active_principal else ANONYMOUS
            elif agent._principals:
                who = next((p.role for p in agent._principals if p.primary), "alice")
            else:
                who = "alice"
            self.requests.append((value, who))

            owner = self.owned.get(value)
            if owner is None:
                return _HTTPResponse(status=self.not_found_status, body=self.not_found, headers={})
            if who == ANONYMOUS and not (self.public or self.anonymous_ok):
                return _HTTPResponse(status=302, body="", headers={})
            if self.enforces and not self.public and who != owner and who != ANONYMOUS:
                # A target that actually enforces: only the owner is served.
                return _HTTPResponse(status=403, body="forbidden", headers={})
            body = _record_for(owner, f"{owner}son", value)
            return _HTTPResponse(status=200, body=body, headers={})

        agent._send_probe = _send_probe  # type: ignore[method-assign]
        return agent


def _make_agent(principals: tuple[Principal, ...] = ()) -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_ScriptedLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="idor-four-arm-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    agent._principals = principals
    return agent


def _idor_finding() -> Finding:
    """A confirmed IDOR finding, for the emission-chokepoint grounds."""
    return Finding(
        title="Insecure Direct Object Reference via id parameter",
        severity="high",
        target="http://example.com/account",
        description="Technique: WSTG-ATHZ-04. Parameter: id.",
    )


def _page(url: str = "http://example.com/account?id=1") -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=["id"])


# Ranked as peers: neither holds a role that authorizes reading the other's
# record, which is the direction that makes a crossing arm evidence. An
# undeclared rank is a lead, not a confirmation — asserted separately in
# ``TestTheCrossingRunsUphill``.
TWO_ROLES = (
    Principal(role="alice", username="alice", cookies={"sid": "a"}, primary=True, privilege=0),
    Principal(role="bob", username="bob", cookies={"sid": "b"}, privilege=0),
)
ONE_ROLE = (Principal(role="alice", username="alice", cookies={"sid": "a"}, primary=True),)


async def _verify(
    agent: ExploitAgent,
    synth: dict[str, Any],
    *,
    primitives: IDORPrimitives | None = None,
    page: PageAnalysis | None = None,
    original_value: str = "1",
) -> tuple[Any, Any, Any]:
    """Anchor ``ref(A)`` through the real sweep, then run phase 5.

    Every agent-level test goes through here rather than calling phase 5 with a
    hand-made anchor, because the anchor is now part of what phase 5 is: the
    2026-08-31 defect was not in the grading, it was in which reference each arm
    carried, and a test that supplies the answer cannot see that.
    """
    page = page or _page()
    prims = primitives or IDORPrimitives(id_format="numeric")
    anchor = await agent._idor_anchor(page, "id", original_value, prims)
    return await agent._idor_phase5_verify(
        page,
        "id",
        synth,
        {"baseline_status": 200, "baseline_body": A_RECORD},
        prims,
        anchor.reference,
        anchor=anchor,
    )


class TestPhase5FourArm:
    @pytest.mark.asyncio
    async def test_a_real_crossing_confirms_with_two_principals(self) -> None:
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, arms, control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric", authz_check_present=False),
        )
        assert verdict.confirmed is True, verdict.detail
        assert verdict.tier == TIER_MULTI_ROLE
        assert control is not None and control.satisfied
        assert arms.get(IDORArm.OWNER_READ) is not None

    @pytest.mark.asyncio
    async def test_the_same_target_with_one_principal_only_leads(self) -> None:
        agent = _make_agent(ONE_ROLE)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, _arms, _control = await _verify(agent, {"reference": "2", "rationale": "peer"})
        assert verdict.confirmed is False
        assert verdict.tier == TIER_SINGLE_ROLE
        # A single-role run holds no OTHER identity to recognise an owner by, so
        # bob's record names nobody it can check against and the class abstains
        # one step earlier than the tier gate. Both are refusals and the reason
        # differs: this one is what the run actually lacked. The tier gate
        # itself is asserted on the pure table, where the harness can hold an
        # owning field and a single principal at the same time.
        assert verdict.why_unconfirmed in (
            "single_role_cannot_attribute",
            NO_OWNING_FIELD,
        )

    @pytest.mark.asyncio
    async def test_a_public_lookup_does_not_confirm_and_leaves_no_lead(self) -> None:
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, public=True).bind(agent)
        verdict, _arms, _control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert verdict.object_is_public is True
        assert verdict.why_unconfirmed == ""

    @pytest.mark.asyncio
    async def test_an_endpoint_that_answers_anything_is_killed_by_the_control(self) -> None:
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False)
        # Every unknown reference renders the same record — the handler answers
        # whatever it is handed, which is what the control is for.
        target.not_found = _record_for("bob", "bobson", "2")
        target.not_found_status = 200
        target.bind(agent)
        verdict, _arms, control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert control is not None and not control.satisfied
        assert verdict.why_unconfirmed == "never_sent_control_did_not_refuse"

    @pytest.mark.asyncio
    async def test_a_target_that_enforces_does_not_confirm(self) -> None:
        """The negative control for the whole class: authorization actually works."""
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=True).bind(agent)
        verdict, _arms, _control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False

    @pytest.mark.asyncio
    async def test_the_authz_precondition_no_longer_gates(self) -> None:
        """The inversion, stated as a test.

        ``authz_check_present=False`` used to return before anything was graded
        and consumed 616 of 668 recorded phase-5 refusals. The same probe is now
        the control, and a genuine crossing confirms with the flag False.
        """
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, _arms, _control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric", authz_check_present=False),
        )
        assert verdict.confirmed is True, verdict.detail

    @pytest.mark.asyncio
    async def test_every_arm_is_carried_as_the_right_principal(self) -> None:
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False)
        target.bind(agent)
        await _verify(agent, {"reference": "2", "rationale": "peer"})
        sent = target.requests
        assert ("1", "alice") in sent, sent
        assert ("2", "alice") in sent, sent
        assert ("2", ANONYMOUS) in sent, sent
        assert ("2", "bob") in sent, sent
        absent = [ref for ref, _who in sent if ref not in ("1", "2")]
        assert absent, "the never-issued reference was never dispatched"
        assert all(ref.isdigit() and int(ref) > 2 for ref in absent), absent

    @pytest.mark.asyncio
    async def test_a_reference_equal_to_the_anchored_one_is_refused(self) -> None:
        """The crossing arm may not ask for the caller's OWN record.

        The guard used to compare against the crawl's observed value, which is
        a fact about whichever session was crawling. It compares against the
        ANCHORED reference now — and nothing is dispatched past the anchor
        sweep, so the arms never go out.
        """
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "alice"})
        target.bind(agent)
        verdict, _arms, control = await _verify(agent, {"reference": "1"})
        assert verdict.confirmed is False
        assert control is None
        assert "the caller's own anchored reference" in verdict.detail
        # Only the anchor sweep's own probes, all carried as the caller.
        assert {who for _ref, who in target.requests} == {"alice"}, target.requests


class TestTheHandoff:
    def test_only_established_sessions_become_principals(self) -> None:
        parsed = parse_role_sessions(
            [
                {"role": "a", "established": True, "cookies": {"s": "1"}, "primary": True},
                {"role": "b", "established": False, "cookies": {"s": "2"}},
            ]
        )
        assert [p.role for p in parsed] == ["a"]

    def test_a_principal_with_no_session_material_is_dropped(self) -> None:
        parsed = parse_role_sessions([{"role": "a", "established": True}])
        assert parsed == ()

    def test_the_primary_comes_first(self) -> None:
        parsed = parse_role_sessions(
            [
                {"role": "b", "established": True, "cookies": {"s": "2"}},
                {"role": "a", "established": True, "cookies": {"s": "1"}, "primary": True},
            ]
        )
        assert [p.role for p in parsed] == ["a", "b"]

    def test_a_duplicate_role_name_is_dropped(self) -> None:
        parsed = parse_role_sessions(
            [
                {"role": "a", "established": True, "cookies": {"s": "1"}},
                {"role": "a", "established": True, "cookies": {"s": "9"}},
            ]
        )
        assert len(parsed) == 1
        assert parsed[0].cookies == {"s": "1"}

    def test_a_malformed_handoff_degrades_to_single_role(self) -> None:
        for raw in (None, {}, "roles", [1, 2], [{"nope": True}]):
            assert parse_role_sessions(raw) == ()

    def test_the_agent_parses_the_handoff_into_principals(self) -> None:
        """A ranked handoff crosses UPHILL: the low role reads the admin's object.

        This assertion used to read ``_idor_principal_a() is None`` — the ambient
        session IS A — and the ambient session is the primary role, which on the
        ordinary client engagement is the administrator. That direction grades
        "the admin was served a customer's record" as a boundary crossing, which
        is what most applications authorize an admin to do.
        """
        agent = _make_agent()
        agent._principals = parse_role_sessions(
            [
                {
                    "role": "admin",
                    "username": "admin",
                    "established": True,
                    "cookies": {"PHPSESSID": "x"},
                    "primary": True,
                    "privilege": 10,
                },
                {
                    "role": "user_b",
                    "username": "gordonb",
                    "established": True,
                    "headers": {"Authorization": "Bearer y"},
                    "privilege": 0,
                },
            ]
        )
        assert agent._idor_tier() == TIER_MULTI_ROLE
        principal_a = agent._idor_principal_a()
        assert principal_a is not None
        assert principal_a.role == "user_b"
        assert [p.role for p in agent._idor_principals_b()] == ["admin"]


class TestTheCrossingRunsUphill:
    """Which identity the crossing is dispatched FROM decides whether it is one.

    Every arm in the four-arm table is satisfied by an administrator being served
    a customer's record, and in most applications that is the feature. So A is
    the least privileged identity the engagement holds, and where the operator
    declared no hierarchy the engine says so rather than picking one: the
    commonest engagement in the field supplies a single admin or service account,
    and that is exactly the run a name-based guess would produce a false positive
    on.
    """

    def test_a_declared_rank_orders_least_privileged_first(self) -> None:
        order = privilege_order(
            (
                Principal(role="admin", cookies={"s": "1"}, primary=True, privilege=10),
                Principal(role="customer", cookies={"s": "2"}, privilege=0),
            )
        )
        assert order.known is True
        assert order.least_privileged is not None
        assert order.least_privileged.role == "customer"
        assert [p.role for p in order.crossing_candidates()] == ["admin"]

    def test_a_candidate_ranked_below_a_is_not_a_crossing(self) -> None:
        """Downhill is where an entitlement lives, so it is not dispatched as one."""
        order = privilege_order(
            (
                Principal(role="mid", cookies={"s": "1"}, privilege=5),
                Principal(role="admin", cookies={"s": "2"}, privilege=10),
                Principal(role="low", cookies={"s": "3"}, privilege=0),
            )
        )
        assert order.least_privileged is not None
        assert order.least_privileged.role == "low"
        assert [p.role for p in order.crossing_candidates()] == ["mid", "admin"]

    def test_peers_cross_each_other(self) -> None:
        """Equal rank is the cleanest crossing: no role authorizes either read."""
        order = privilege_order(
            (
                Principal(role="alice", cookies={"s": "1"}, privilege=0),
                Principal(role="bob", cookies={"s": "2"}, privilege=0),
            )
        )
        assert order.known is True
        assert order.least_privileged is not None
        assert order.least_privileged.role == "alice"
        assert [p.role for p in order.crossing_candidates()] == ["bob"]

    def test_the_order_is_a_function_of_the_set_not_the_handoff(self) -> None:
        """Ties break on role name, so two handoff orders rank identically.

        A run whose arms depend on dict ordering cannot be compared against its
        own baseline - the same reason the exploit plan refuses to break a tie on
        the crawler's emission sequence.
        """
        a = Principal(role="alice", cookies={"s": "1"}, privilege=0)
        b = Principal(role="bob", cookies={"s": "2"}, privilege=0)
        assert [p.role for p in privilege_order((a, b)).ordered] == [
            p.role for p in privilege_order((b, a)).ordered
        ]

    def test_one_undeclared_rank_makes_the_whole_order_unknown(self) -> None:
        order = privilege_order(
            (
                Principal(role="admin", cookies={"s": "1"}, primary=True, privilege=10),
                Principal(role="customer", cookies={"s": "2"}),
            )
        )
        assert order.known is False
        assert "customer" in order.why_unknown
        # The arms still dispatch: what an unknown order costs is the
        # confirmation, not the observation.
        assert [p.role for p in order.crossing_candidates()] == ["customer"]

    def test_fewer_than_two_principals_is_vacuously_ordered(self) -> None:
        """There is no pair, so there is no order to get wrong.

        The single-role tier refuses to confirm for its own, more specific
        reason; reporting the direction as unknown here as well would demote
        under a reason naming the wrong missing observation.
        """
        assert privilege_order(()).known is True
        assert privilege_order((Principal(role="solo", cookies={"s": "1"}),)).known is True

    def test_a_boolean_is_not_a_rank(self) -> None:
        """A ``privilege: true`` typo is undeclared: ``bool`` is an ``int`` here."""
        parsed = parse_role_sessions(
            [
                {"role": "a", "established": True, "cookies": {"s": "1"}, "privilege": True},
                {"role": "b", "established": True, "cookies": {"s": "2"}, "privilege": 0},
            ]
        )
        assert [p.privilege for p in parsed] == [None, 0]
        assert privilege_order(parsed).known is False

    def test_the_handoff_carries_the_declared_rank(self) -> None:
        parsed = parse_role_sessions(
            [
                {"role": "a", "established": True, "cookies": {"s": "1"}, "privilege": 7},
                {"role": "b", "established": True, "cookies": {"s": "2"}, "privilege": -1},
            ]
        )
        assert {p.role: p.privilege for p in parsed} == {"a": 7, "b": -1}

    @pytest.mark.asyncio
    async def test_the_arms_are_dispatched_from_the_low_principal(self) -> None:
        """The crossing is sent as the customer, not as the primary admin."""
        agent = _make_agent(
            (
                Principal(
                    role="admin",
                    username="admin",
                    cookies={"sid": "a"},
                    primary=True,
                    privilege=10,
                ),
                Principal(role="customer", username="customer", cookies={"sid": "b"}, privilege=0),
            )
        )
        target = _ScriptedTarget({"1": "customer", "2": "admin"}, enforces=False)
        target.bind(agent)
        verdict, _arms, _control = await _verify(
            agent, {"reference": "2", "rationale": "the admin's record"}
        )
        crossing_callers = [who for ref, who in target.requests if ref == "2"]
        assert "customer" in crossing_callers
        assert verdict.confirmed is True, verdict.detail

    @pytest.mark.asyncio
    async def test_an_undeclared_order_leads_instead_of_confirming(self) -> None:
        """Same target, same arms, ranks removed: a lead with an actionable reason."""
        agent = _make_agent(
            (
                Principal(role="alice", username="alice", cookies={"sid": "a"}, primary=True),
                Principal(role="bob", username="bob", cookies={"sid": "b"}),
            )
        )
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, _arms, _control = await _verify(
            agent,
            {"reference": "2", "rationale": "peer"},
            primitives=IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == PRIVILEGE_ORDER_UNDECLARED
        assert verdict.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        # The attribution SUCCEEDED and is reported. What is missing is the
        # direction, and the lead has to say which of the two it is.
        assert verdict.attribution == OWNING_FIELD_NAMES_PRINCIPAL
        assert "privilege rank" in verdict.detail

    def test_the_emission_chokepoint_refuses_an_unranked_confirmation(self) -> None:
        """Ground 10: the rule holds even if a future class forgets to check.

        Both halves are engine facts - a registry declaration and the run's own
        principal list - so nothing the target sends reaches this ground in
        either direction.
        """
        agent = _make_agent(
            (
                Principal(role="alice", cookies={"sid": "a"}, primary=True),
                Principal(role="bob", cookies={"sid": "b"}),
            )
        )
        ground = agent._fp_ground_undeclared_privilege_order(_idor_finding())
        assert ground is not None
        assert "outrank" in ground

    def test_ground_ten_stands_down_for_a_ranked_run(self) -> None:
        agent = _make_agent(
            (
                Principal(role="alice", cookies={"sid": "a"}, primary=True, privilege=0),
                Principal(role="bob", cookies={"sid": "b"}, privilege=0),
            )
        )
        assert agent._fp_ground_undeclared_privilege_order(_idor_finding()) is None

    def test_ground_ten_defers_to_ground_nine_on_a_single_role_run(self) -> None:
        """Two grounds, two missing observations - the lead names the right one."""
        agent = _make_agent((Principal(role="alice", cookies={"sid": "a"}, primary=True),))
        assert agent._fp_ground_undeclared_privilege_order(_idor_finding()) is None
        assert agent._fp_ground_insufficient_principals(_idor_finding()) is not None

    def test_a_class_needing_one_principal_is_untouched(self) -> None:
        agent = _make_agent(
            (
                Principal(role="alice", cookies={"sid": "a"}, primary=True),
                Principal(role="bob", cookies={"sid": "b"}),
            )
        )
        finding = Finding(
            title="SQL Injection via id parameter",
            severity="high",
            target="http://example.com/account",
            description="Technique: WSTG-INPV-05. Parameter: id.",
        )
        assert agent._fp_ground_undeclared_privilege_order(finding) is None

    def test_the_registry_tells_a_client_the_ranking_is_needed(self) -> None:
        """A rule the code enforces and the report does not mention is a trap."""
        limitation = for_method("_test_idor").limitation
        assert "privilege" in limitation
        assert "least privileged" in limitation


# ===========================================================================
# The acceptance criterion — asserted on the ARMS, never on an outcome
# ===========================================================================


#: The five claims a confirmed IDOR must be able to make about its own arms.
#:
#: This is the acceptance criterion restated in the form
#: ``.claude/skills/clinkz-dev/SKILL.md`` requires — the acceptance-criterion
#: law. The one it replaces was "a target-confirmed scoreboard solve plus an
#: emitted finding of the matching class", which passed three runs running over
#: an oracle whose arms were inverted: the scoreboard grades the OUTCOME and the
#: oracle grades the REASONING, and nothing compared them. Juice Shop marked
#: ``basketAccess`` solved because our traffic really did fetch basket 1; the
#: finding said we had crossed into basket 2, which is the caller's own.
IDOR_ACCEPTANCE_CLAIMS: tuple[str, ...] = (
    "ref(A) was anchored to the caller's own identity, not to a crawled value",
    "ref(self) != ref(crossing), and ref(self) is the anchored reference",
    "the crossing response names an owning principal that is not the caller",
    "the anonymous arm was dispatched against ref(B) and was not served it",
    "the never-issued control was dispatched and refused",
)


def idor_acceptance_failures(verdict: Any, arms: dict[IDORArm, ArmObservation]) -> list[str]:
    """Which acceptance claims a confirmed verdict cannot make about its arms.

    Reads only ENGINE facts — what each arm carried, as whom, and what the
    oracle concluded — never an external grader. A scoreboard solve satisfies
    none of these and is reported beside them, never instead of them.
    """
    failures: list[str] = []
    self_arm = arms.get(IDORArm.SELF)
    crossing = arms.get(IDORArm.CROSSING)
    anonymous = arms.get(IDORArm.ANONYMOUS)
    nonexistent = arms.get(IDORArm.NONEXISTENT)

    if not verdict.anchored:
        failures.append(IDOR_ACCEPTANCE_CLAIMS[0])
    if (
        self_arm is None
        or crossing is None
        or self_arm.reference == crossing.reference
        or verdict.arms_inverted
    ):
        failures.append(IDOR_ACCEPTANCE_CLAIMS[1])
    if verdict.attribution not in (OWNING_FIELD_NAMES_PRINCIPAL, OWNING_FIELD_NOT_CALLER):
        failures.append(IDOR_ACCEPTANCE_CLAIMS[2])
    if anonymous is None or not anonymous.dispatched or anonymous.resolves():
        failures.append(IDOR_ACCEPTANCE_CLAIMS[3])
    if nonexistent is None or not nonexistent.dispatched or not verdict.control_refused:
        failures.append(IDOR_ACCEPTANCE_CLAIMS[4])
    return failures


class TestTheAcceptanceCriterion:
    @pytest.mark.asyncio
    async def test_a_confirmation_can_make_every_claim_about_its_own_arms(self) -> None:
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, arms, _control = await _verify(agent, {"reference": "2", "rationale": "peer"})
        assert verdict.confirmed is True, verdict.detail
        assert idor_acceptance_failures(verdict, arms.observations) == []

    @pytest.mark.asyncio
    async def test_the_run_three_shape_fails_the_criterion(self) -> None:
        """The regression the old criterion could not see, driven end to end.

        The scripted target is the Juice Shop shape: the crawl's value is
        ``1`` and it belongs to the OTHER principal, while the caller owns
        ``2``. Under the old arms this confirmed; under the anchored ones the
        crossing is re-pointed at ``1`` and the caller's own record is no longer
        mistaken for a neighbour's.
        """
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "bob", "2": "alice"}, enforces=False)
        target.bind(agent)
        verdict, arms, _control = await _verify(agent, {"reference": "2", "rationale": "peer"})
        # ``2`` is the CALLER's own record here, so the synthesised crossing is
        # the anchored reference and phase 5 refuses before it dispatches an arm.
        assert verdict.confirmed is False
        assert "the caller's own anchored reference" in verdict.detail
        assert idor_acceptance_failures(verdict, arms.observations)

    def test_an_external_grader_satisfies_no_claim(self) -> None:
        """The law, stated as a test.

        A verdict carrying every outcome signal there is — a scoreboard solve, a
        matching class, a 200 on somebody else's reference — and no anchored
        arms behind it fails every claim. That is the whole difference between
        the criterion this replaces and this one.
        """
        verdict = IDORVerdict(confirmed=True, tier=TIER_MULTI_ROLE)
        assert idor_acceptance_failures(verdict, {}) == list(IDOR_ACCEPTANCE_CLAIMS)
