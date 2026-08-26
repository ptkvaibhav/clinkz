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
from clinkz.agents._principal import ANONYMOUS, Principal, parse_role_sessions
from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import IDORPrimitives
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.models.vuln_classes import multi_principal_requirement
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
        assert any("bergman" in v for v in values)

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


def _page(url: str = "http://example.com/account?id=1") -> PageAnalysis:
    return PageAnalysis(url=url, body="", status=200, input_params=["id"])


TWO_ROLES = (
    Principal(role="alice", username="alice", cookies={"sid": "a"}, primary=True),
    Principal(role="bob", username="bob", cookies={"sid": "b"}),
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
        agent = _make_agent()
        agent._principals = parse_role_sessions(
            [
                {
                    "role": "admin",
                    "username": "admin",
                    "established": True,
                    "cookies": {"PHPSESSID": "x"},
                    "primary": True,
                },
                {
                    "role": "user_b",
                    "username": "gordonb",
                    "established": True,
                    "headers": {"Authorization": "Bearer y"},
                },
            ]
        )
        assert agent._idor_tier() == TIER_MULTI_ROLE
        assert [p.role for p in agent._idor_principals_b()] == ["user_b"]
        assert agent._idor_principal_a() is None  # the ambient session IS A
