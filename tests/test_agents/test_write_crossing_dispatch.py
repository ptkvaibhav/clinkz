"""``_test_write_crossing`` driven end to end against a stub application.

The oracle's unit suite grades verdicts from constructed arms. This one asserts
what actually goes on the wire: which requests were dispatched, as whom, carrying
what, and in what order — the half of invariant 35 that a verdict test cannot
reach.

Four properties, each of which fails in a way the artifacts would not show:

* **The arms go out 5, 1, 2, 4, 3.** The attribution source and both controls
  before the payload.
* **Every landed write is disclosed**, whether or not a finding emitted.
* **A control that could not be sent stops the payload.** For this class that is
  not an efficiency: "anyway" means an object written into another principal's
  data that no finding can come out of.
* **One dispatch per (collection, principal-pair) per run.** Terminal ordering
  orders classes, not tasks, and the plan legitimately holds several tasks for
  one collection.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from clinkz.agents._origin import OriginIdentity
from clinkz.agents._principal import Principal
from clinkz.agents._write_crossing import ARM_DISPATCH_ORDER
from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

COLLECTION = "https://app.test/api/Feedbacks"

A = Principal(role="customer", username="jim@t.test", privilege=0, cookies={"s": "a"})
B = Principal(role="admin", username="admin@t.test", privilege=10, primary=True, cookies={"s": "b"})


class StubApp:
    """A feedback collection that honours a client-supplied ``UserId``.

    Deliberately minimal, and deliberately NOT a model of the oracle: it stores
    what it is given and serves it back. Everything the class claims has to be
    derived from that, which is the point — a stub that encoded "this is a
    crossing" would be a test that can only pass against a fiction.
    """

    def __init__(
        self,
        *,
        honour_owner: bool = True,
        accept_anonymous: bool = False,
        accept_unknown_owner: bool = False,
    ) -> None:
        self.rows: list[dict[str, Any]] = [
            {"id": 1, "comment": "seeded", "UserId": "1"},
            {"id": 2, "comment": "seeded", "UserId": "2"},
        ]
        self.honour_owner = honour_owner
        self.accept_anonymous = accept_anonymous
        self.accept_unknown_owner = accept_unknown_owner
        self.known_owners = {"1", "2"}
        self.writes: list[dict[str, Any]] = []
        self.reads: list[str] = []
        self.next_id = 3

    #: Which owner reference each session is issued — the application's own
    #: spelling, which is deliberately NOT the identity value the engagement
    #: holds. That gap is the reason ``ref(A)`` has to be discovered from a write
    #: the server attributed rather than taken from A's username.
    OWNER_OF = {"customer (jim@t.test)": "2", "admin (admin@t.test)": "1"}

    def post(self, body: dict[str, Any], principal: str) -> _HTTPResponse:
        self.writes.append({"body": dict(body), "as": principal})
        if principal == "anonymous" and not self.accept_anonymous:
            return _HTTPResponse(status=401, body="", headers={})
        # The owning field OMITTED is the ordinary create: the server assigns the
        # owner from the session, which is what every sound handler does.
        if "UserId" not in body:
            owner = self.OWNER_OF.get(principal, "2")
        else:
            owner = str(body["UserId"])
            if owner not in self.known_owners and not self.accept_unknown_owner:
                return _HTTPResponse(status=422, body="", headers={})
        row = {
            "id": self.next_id,
            "comment": body.get("comment", ""),
            "UserId": owner if self.honour_owner else self.OWNER_OF.get(principal, "2"),
        }
        self.next_id += 1
        self.rows.append(row)
        # The create echoes the record — which is exactly the channel the oracle
        # must not read, so a stub that reflects is the honest stub.
        return _HTTPResponse(status=201, body=json.dumps(row), headers={})

    def get(self, principal: str) -> _HTTPResponse:
        self.reads.append(principal)
        return _HTTPResponse(status=200, body=json.dumps(self.rows), headers={})


def _agent(app: StubApp, *, principals: tuple[Principal, ...] = (A, B)) -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.scope = EngagementScope(
        name="write-crossing", targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.test")]
    )
    agent.engagement_id = "write-crossing-test"
    agent._logger = logging.getLogger("test.exploit.write_crossing")
    agent._session_cookies = {}
    agent._session_headers = {}
    agent._active_principal = None
    agent._principal_isolation = False
    agent._authenticated_as = "jim@t.test"
    agent._principals = principals
    agent._unproven_exploit_leads = []
    agent._residual_mutations = []
    agent._control_arms = {}
    agent._control_arm_kills = 0
    agent._control_arm_kill_disclosures = 0
    agent._write_crossing_dispatched = set()
    agent._origin_identity = OriginIdentity()
    agent._findings = []
    agent._business_logic_rejections = []
    agent._traced: list[dict[str, Any]] = []

    def _trace(**kwargs: Any) -> None:
        agent._traced.append(kwargs)

    agent._trace_methodology_phase = _trace  # type: ignore[method-assign]
    agent._strip_empty_fragment = lambda url: url  # type: ignore[method-assign]
    agent._truncate = lambda text, n: text[:n]  # type: ignore[method-assign]

    async def _post_json(url: str, body: dict[str, Any], method: str = "POST") -> _HTTPResponse:
        del url, method
        return app.post(body, agent._current_label())

    async def _get(url: str, params: dict[str, str]) -> _HTTPResponse:
        del url, params
        return app.get(agent._current_label())

    agent._current_label = lambda: (  # type: ignore[attr-defined]
        "anonymous"
        if agent._principal_isolation and agent._active_principal is None
        else (agent._active_principal.label() if agent._active_principal is not None else "ambient")
    )
    agent._http_post_json = _post_json  # type: ignore[method-assign]
    agent._http_get = _get  # type: ignore[method-assign]
    return agent


def _page() -> PageAnalysis:
    return PageAnalysis(
        url=COLLECTION,
        body="",
        status=200,
        input_params=["comment", "UserId"],
        request_method="POST",
        content_type="application/json",
    )


def _arms_dispatched(agent: ExploitAgent) -> list[str]:
    """The arms, in the order the methodology traced them going out."""
    return [
        entry["extra"]["arm"]
        for entry in agent._traced
        if entry.get("phase_name", "").startswith("arm_")
    ]


# ---------------------------------------------------------------------------
# 2a — the arm order, on the wire
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_arms_go_out_in_the_declared_order() -> None:
    app = StubApp()
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())

    write_arms = _arms_dispatched(agent)
    assert write_arms == [
        "self_anchor",
        "control_self",
        "control_absent",
        "anonymous",
        "crossing",
    ], write_arms
    # Arm 5 is a READ, so it is traced under its own phase — and it precedes
    # every write, which is the ordering 2a exists for.
    phases = [e.get("phase_name") for e in agent._traced]
    assert phases.index("owner_snapshot_taken") < phases.index("arm_self_anchor")
    assert phases.index("owner_snapshot_taken") < phases.index("arm_crossing")
    assert [a.value for a in ARM_DISPATCH_ORDER][0] == "owner_read"
    assert findings, "a stub that honours a client-supplied UserId is a crossing"


@pytest.mark.asyncio
async def test_the_crossing_carries_a_reference_discovered_by_probing_as_b() -> None:
    """``ref(B)`` is DISCOVERED, never synthesised or incremented off A's."""
    app = StubApp()
    agent = _agent(app)
    await agent._test_write_crossing(_page())

    crossing = [w for w in app.writes if w["as"] == A.label()][-1]
    assert crossing["body"]["UserId"] == "1", "the crossing must carry B's own reference"
    # And B's snapshot was taken BEFORE this class wrote anything, so the
    # reference the payload carries is one the application issued rather than
    # one this run put there.
    phases = [e.get("phase_name") for e in agent._traced]
    assert phases.index("owner_snapshot_taken") < phases.index("arm_self_anchor")
    assert B.label() in app.reads
    # The anchoring write omits the owner field entirely — the server assigns it,
    # which is where ref(A) comes from.
    anchor = [w for w in app.writes if w["as"] == A.label()][0]
    assert "UserId" not in anchor["body"], anchor


@pytest.mark.asyncio
async def test_the_attribution_comes_from_a_read_that_did_not_carry_the_write() -> None:
    app = StubApp()
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())
    assert findings
    evidence = " ".join(findings[0].evidence)
    assert "SEPARATE read" in evidence
    assert "never on the create's status code" in evidence
    # One collection read per write arm, plus B's own — the read-back is real.
    assert len(app.reads) >= len(app.writes)


# ---------------------------------------------------------------------------
# 2c — every landed write is disclosed, on the witnessed effect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_landed_write_enters_the_residual_ledger() -> None:
    app = StubApp()
    agent = _agent(app)
    await agent._test_write_crossing(_page())

    landed = [
        w
        for w in app.writes
        if w["as"] != "anonymous" and str(w["body"].get("UserId", "2")) in {"1", "2"}
    ]
    assert len(agent._residual_mutations) == len(landed), (
        f"{len(landed)} writes landed and {len(agent._residual_mutations)} were disclosed"
    )
    for mutation in agent._residual_mutations:
        assert mutation.test_method == "_test_write_crossing"
        assert mutation.witnessed is True
        assert mutation.endpoint == COLLECTION
        assert mutation.key, "a disclosure the operator cannot act on names nothing"
        assert "manual" in mutation.remediation.lower()


@pytest.mark.asyncio
async def test_a_refused_finding_still_discloses_what_it_wrote() -> None:
    """The disclosure is on the WITNESSED EFFECT, never on emission.

    An endpoint that accepts a reference nobody owns kills the finding — and the
    two objects the run already wrote are in the client's data either way. A
    disclosure that only fires when we also got a finding out of it is a
    disclosure that serves us.
    """
    app = StubApp(accept_unknown_owner=True)
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())

    assert findings == [], "a handler storing an unowned reference is not honouring the field"
    assert agent._residual_mutations, "the writes landed and nothing disclosed them"
    arms = {m.mechanism.split("'")[1] for m in agent._residual_mutations}
    assert "control_absent" in arms, (
        "the never-issued control's own object is one this run created and cannot "
        f"delete — disclosed arms were {sorted(arms)}"
    )


# ---------------------------------------------------------------------------
# 2d — a control that could not be sent stops the payload, for THIS class
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_control_that_could_not_be_dispatched_never_sends_the_crossing() -> None:
    """Asserted for this class explicitly, not inherited on trust.

    The seam owns the rule. What this pins is that this class actually goes
    through the seam — and the failure mode it prevents here is worse than the
    pollution class's: an object written into another principal's data that no
    finding can ever come out of.
    """
    app = StubApp()
    agent = _agent(app)
    original = agent._http_post_json
    calls: list[dict[str, Any]] = []

    async def _post(url: str, body: dict[str, Any], method: str = "POST") -> _HTTPResponse:
        calls.append(dict(body))
        # The never-issued control is the one that cannot be sent. Everything
        # else — the anchoring write, which omits the field — goes through.
        if "UserId" in body and str(body["UserId"]) not in {"1", "2"}:
            raise OSError("connection refused")
        return await original(url, body, method)

    agent._http_post_json = _post  # type: ignore[method-assign]
    findings = await agent._test_write_crossing(_page())

    assert findings == []
    arms = _arms_dispatched(agent)
    assert "crossing" not in arms, (
        "the payload was dispatched after a control that never went out — for this "
        f"class that is an irreversible write no finding can come out of. Arms: {arms}"
    )
    assert "anonymous" not in arms, "the whole confirming half must be skipped"
    assert agent._unproven_exploit_leads, "an un-dispatched arm disclosed nothing"


# ---------------------------------------------------------------------------
# 2b — one dispatch per (collection, principal-pair) per run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_second_task_on_the_same_collection_writes_nothing() -> None:
    app = StubApp()
    agent = _agent(app)
    await agent._test_write_crossing(_page())
    writes_after_first = len(app.writes)

    # The same collection, spelled by a second discoverer as an item route.
    second = PageAnalysis(
        url=f"{COLLECTION}/:id",
        body="",
        status=200,
        input_params=["comment", "UserId"],
        request_method="POST",
        content_type="application/json",
    )
    findings = await agent._test_write_crossing(second)

    assert findings == []
    assert len(app.writes) == writes_after_first, (
        "a second task on the same collection wrote more objects into another "
        "principal's data to re-answer a question this run had answered"
    )
    assert any(e.get("phase_name") == "duplicate_dispatch_suppressed" for e in agent._traced), (
        "the suppression must be visible in the trace, not silent"
    )


# ---------------------------------------------------------------------------
# The abstentions send nothing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_single_role_run_writes_nothing_at_all() -> None:
    app = StubApp()
    agent = _agent(app, principals=(A,))
    findings = await agent._test_write_crossing(_page())

    assert findings == []
    assert app.writes == [], "a class that cannot confirm must not write to the target"
    assert agent._residual_mutations == []


@pytest.mark.asyncio
async def test_an_endpoint_that_accepts_and_overrides_sends_no_crossing() -> None:
    """The control shows the override, and the payload is never dispatched.

    A server that takes the field and then sets the owner from the session is
    the application working. Arm 1 cannot show it — an honoured ``ref(A)`` and an
    overridden one produce the same object — so the tell is a reference NOBODY
    owns coming back attributed to the caller. Once that is seen, nothing arm 3
    could return would confirm, and for this class an arm that cannot confirm is
    an irreversible write into the other principal's namespace.
    """
    app = StubApp(honour_owner=False, accept_unknown_owner=True)
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())

    assert findings == []
    arms = _arms_dispatched(agent)
    assert "control_absent" in arms, arms
    assert "crossing" not in arms, (
        "the override was already visible in the control, and the crossing arm was "
        f"dispatched into B's namespace anyway: {arms}"
    )
    assert agent._unproven_exploit_leads, "the abstain must be named, never silent"
    assert not any(m.mechanism.split("'")[1] == "crossing" for m in agent._residual_mutations), (
        "nothing should have been written in the other principal's name"
    )


@pytest.mark.asyncio
async def test_an_endpoint_that_validates_and_overrides_refuses_at_attribution() -> None:
    """The other override shape, and the honest cost of telling them apart.

    A server that REJECTS a reference nobody owns and then overrides a valid one
    is indistinguishable from one that honours the field until the crossing comes
    back. So the crossing IS dispatched, it lands attributed to the caller, and
    the class refuses — having written an object into its own name rather than
    B's, which is the outcome the arm order buys.
    """
    app = StubApp(honour_owner=False)
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())

    assert findings == []
    assert "crossing" in _arms_dispatched(agent)
    crossing_rows = [r for r in app.rows if r["comment"].startswith("clinkzdecoy")]
    assert all(r["UserId"] == "2" for r in crossing_rows), (
        "the server overrode every owner to the caller's, so nothing landed in B's "
        f"name: {crossing_rows}"
    )
    assert agent._unproven_exploit_leads, "the refusal must be named, never silent"


# ---------------------------------------------------------------------------
# The read-back must be able to FIND our row, and must look where it can land
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_read_back_finds_a_row_past_the_representation_cap() -> None:
    """A collection lists oldest first; the row we just created is LAST.

    ``_observed_records`` truncates to five, which is the right bound for "what
    does this object type look like" and the wrong one for "is our row in this
    list". Measured against Juice Shop's ``/api/Addresss``: three arms landed,
    the read-back read five records, every one of them reported
    ``landed=False``, and the class reported that this endpoint's writes could
    not be read back — the exact opposite of what happened, while disclosing none
    of the three objects it had left behind.
    """
    app = StubApp()
    app.rows = [
        {"id": i, "comment": f"filler-{i}", "UserId": "1" if i % 2 else "2"} for i in range(1, 40)
    ]
    app.next_id = 40
    agent = _agent(app)
    await agent._test_write_crossing(_page())

    landed = [
        e
        for e in agent._traced
        if e.get("phase_name", "").startswith("arm_") and e["extra"]["landed"]
    ]
    assert landed, (
        "every arm reported landed=False against a collection 39 rows deep — the "
        "read-back is reading a truncated representation instead of searching for "
        "its own marker"
    )
    assert agent._residual_mutations, "rows landed and nothing disclosed them"


@pytest.mark.asyncio
async def test_a_row_only_the_owner_can_see_is_still_located() -> None:
    """The crossing's whole point is that the object left the caller's scope.

    On a per-principal collection an object that genuinely crossed is no longer
    in A's read. Reading only as A would report that a real crossing "did not
    land" — the one outcome this class exists to catch, misread as the endpoint
    refusing the write.
    """
    app = StubApp()
    visible_to = {A.label(): "2", B.label(): "1"}

    def scoped(principal: str) -> _HTTPResponse:
        """A per-principal collection: you are served your own rows and no others."""
        owner = visible_to.get(principal)
        rows = [r for r in app.rows if owner is not None and str(r["UserId"]) == owner]
        app.reads.append(principal)
        return _HTTPResponse(status=200, body=json.dumps(rows), headers={})

    app.get = scoped  # type: ignore[method-assign]
    agent = _agent(app)
    findings = await agent._test_write_crossing(_page())

    crossing = [e for e in agent._traced if e.get("phase_name") == "arm_crossing"]
    assert crossing, "the crossing arm never ran"
    assert crossing[0]["extra"]["landed"] is True, (
        "the crossing landed in the OWNER's scope and the read-back only looked in "
        "the caller's, so a real crossing was reported as a write that did not land"
    )
    assert findings, "a located, attributed crossing must emit"
