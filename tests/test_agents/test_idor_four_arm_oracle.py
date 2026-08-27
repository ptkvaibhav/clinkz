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
    ATTRIBUTION_IDENTICAL_RENDERING,
    ATTRIBUTION_STABLE_FIELDS,
    TIER_MULTI_ROLE,
    TIER_SINGLE_ROLE,
    ArmObservation,
    IDORArm,
    attribution_between,
    decide_idor,
    idor_body_fingerprint,
    materially_differs,
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


def _four_arms(**overrides: Any) -> dict[str, Any]:
    """The arms of a genuine, fully-cleared IDOR. Override one to break it."""
    base = {
        "self_arm": _arm(IDORArm.SELF, A_RECORD, reference="1"),
        "crossing": _arm(IDORArm.CROSSING, B_RECORD, reference="2"),
        "nonexistent": _arm(IDORArm.NONEXISTENT, NOT_FOUND, status=404, reference="900012345"),
        "anonymous": _arm(IDORArm.ANONYMOUS, "", status=302, reference="2", principal=ANONYMOUS),
        "owner_read": _arm(IDORArm.OWNER_READ, B_RECORD, reference="2", principal="bob"),
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
        assert verdict.attribution == ATTRIBUTION_IDENTICAL_RENDERING
        assert verdict.control_refused is True
        assert verdict.why_unconfirmed == ""

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

    def test_an_unattributable_record_does_not_confirm(self) -> None:
        """B cannot read it either, so it is not B's — try the next ranked type."""
        verdict = decide_idor(
            **_four_arms(
                owner_read=_arm(IDORArm.OWNER_READ, "", status=403, reference="2", principal="bob"),
            )
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == "single_role_cannot_attribute"


class TestTheTwoTiers:
    def test_a_single_role_run_may_only_lead(self) -> None:
        """Every control cleared and it is STILL not a finding. PART 3's whole rule."""
        verdict = decide_idor(
            **_four_arms(owner_read=None, principals_available=1, principals_required=2)
        )
        assert verdict.confirmed is False
        assert verdict.tier == TIER_SINGLE_ROLE
        assert verdict.why_unconfirmed == "single_role_cannot_attribute"
        assert "shared record behind a login" in verdict.detail

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


class TestPhase5FourArm:
    @pytest.mark.asyncio
    async def test_a_real_crossing_confirms_with_two_principals(self) -> None:
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, arms, control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric", authz_check_present=False),
        )
        assert verdict.confirmed is True, verdict.detail
        assert verdict.tier == TIER_MULTI_ROLE
        assert control is not None and control.satisfied
        assert arms.get(IDORArm.OWNER_READ) is not None

    @pytest.mark.asyncio
    async def test_the_same_target_with_one_principal_only_leads(self) -> None:
        agent = _make_agent(ONE_ROLE)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False).bind(agent)
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert verdict.tier == TIER_SINGLE_ROLE
        assert verdict.why_unconfirmed == "single_role_cannot_attribute"

    @pytest.mark.asyncio
    async def test_a_public_lookup_does_not_confirm_and_leaves_no_lead(self) -> None:
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, public=True).bind(agent)
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
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
        verdict, _arms, control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert control is not None and not control.satisfied
        assert verdict.why_unconfirmed == "never_sent_control_did_not_refuse"

    @pytest.mark.asyncio
    async def test_a_target_that_enforces_does_not_confirm(self) -> None:
        """The negative control for the whole class: authorization actually works."""
        agent = _make_agent(TWO_ROLES)
        _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=True).bind(agent)
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
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
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric", authz_check_present=False),
        )
        assert verdict.confirmed is True, verdict.detail

    @pytest.mark.asyncio
    async def test_every_arm_is_carried_as_the_right_principal(self) -> None:
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "alice", "2": "bob"}, enforces=False)
        target.bind(agent)
        await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
            original_value="1",
        )
        sent = target.requests
        assert ("1", "alice") in sent, sent
        assert ("2", "alice") in sent, sent
        assert ("2", ANONYMOUS) in sent, sent
        assert ("2", "bob") in sent, sent
        absent = [ref for ref, _who in sent if ref not in ("1", "2")]
        assert absent, "the never-issued reference was never dispatched"
        assert all(ref.isdigit() and int(ref) > 2 for ref in absent), absent

    @pytest.mark.asyncio
    async def test_a_reference_equal_to_the_original_is_refused(self) -> None:
        agent = _make_agent(TWO_ROLES)
        target = _ScriptedTarget({"1": "alice"})
        target.bind(agent)
        verdict, _arms, control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "1"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
            original_value="1",
        )
        assert verdict.confirmed is False
        assert control is None
        assert target.requests == []


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
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "the admin's record"},
            {"baseline_status": 200, "baseline_body": _record_for("customer", "customerson", "1")},
            IDORPrimitives(id_format="numeric"),
            original_value="1",
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
        verdict, _arms, _control = await agent._idor_phase5_verify(
            _page(),
            "id",
            {"reference": "2", "rationale": "peer"},
            {"baseline_status": 200, "baseline_body": A_RECORD},
            IDORPrimitives(id_format="numeric"),
        )
        assert verdict.confirmed is False
        assert verdict.why_unconfirmed == PRIVILEGE_ORDER_UNDECLARED
        assert verdict.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED
        # The attribution SUCCEEDED and is reported. What is missing is the
        # direction, and the lead has to say which of the two it is.
        assert verdict.attribution == ATTRIBUTION_IDENTICAL_RENDERING
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
