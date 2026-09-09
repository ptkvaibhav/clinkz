"""The per-account credential budget, and the stop the target itself declares.

The measurement this exists for, taken against the Meridian container on
2026-09-06 by counting credential-bearing POSTs at the transport:

===================================  ================  ==============
one ``authenticate()`` call           docker (curl)     local (aiohttp)
===================================  ================  ==============
credential that WORKS                        2                2
credential that does NOT                    16               18
===================================  ================  ==============

and the client-facing action log for the whole two-role engagement recorded
**two** entries, both reading ``POST mutates target state``. The governor —
which owns the rate limit, the concurrency cap, the kill switch and that log —
took one slot per ``authenticate()`` call, so the only component that could have
bounded a brute-force we did not intend to perform could not see one.

Two halves fix it and they fail in opposite directions, which is why there are
two:

* the **budget** is an assumption we make in advance. It cannot know where a
  particular application's lockout trips, so it is declarable and defaults low.
* the **stop** is an observation the target hands us. It knows exactly, and it
  arrives too late to prevent the attempt that produced it — which is precisely
  why acting on it must stop the ones after it.
"""

from __future__ import annotations

import pytest

from clinkz.models.engagement import SafetyPolicy
from clinkz.safety.action_log import CATEGORY_CREDENTIAL_ATTEMPT, OUTCOME_REFUSED, OUTCOME_SENT
from clinkz.safety.governor import (
    REFUSED_CREDENTIAL_BUDGET,
    REFUSED_CREDENTIAL_STOPPED,
    EngagementGovernor,
)
from clinkz.safety.lockout import LockoutKind, classify_lockout

_LOGIN = "http://target.test/login"
_OTHER_ROUTE = "http://target.test/api/auth/login"
_OTHER_ORIGIN = "http://other.test/login"


def _governor(tmp_path, budget: int = 3, reserve: int = 0) -> EngagementGovernor:
    """A governor whose whole allowance is the deterministic pass's, by default.

    ``reserve=0`` because every test in this module below was written about the
    per-account BUDGET and measures the share the login flow may spend. The
    adaptive-auth reserve splits that allowance in two
    (:attr:`SafetyPolicy.adaptive_auth_credential_reserve`), and letting the
    production default apply here would silently re-scale every number in the
    file — which is the "changed the instrument, kept the readings" mistake.
    :class:`TestTheAdaptiveAuthReserve` exercises the split explicitly instead.
    """
    return EngagementGovernor(
        "budget-test",
        SafetyPolicy(
            max_requests_per_second=1000.0,
            max_credential_attempts_per_account=budget,
            adaptive_auth_credential_reserve=reserve,
        ),
        outputs_root=tmp_path,
    )


async def _attempt(governor: EngagementGovernor, url: str, account: str):
    decision = await governor.authorize(
        "POST", url, body="username=x&password=y", stage="auth", account=account
    )
    if decision.allowed:
        governor.release()
    return decision


# ---------------------------------------------------------------------------
# The budget
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_budget_is_spent_across_routes_not_per_route(tmp_path) -> None:
    """The JSON arm walks eight routes on one host offering the same password.

    A per-URL counter would hand each route a fresh budget and bound nothing,
    which is how 16 attempts fitted inside a nominal limit of two.
    """
    governor = _governor(tmp_path, budget=3)

    assert (await _attempt(governor, _LOGIN, "admin")).allowed
    assert (await _attempt(governor, _OTHER_ROUTE, "admin")).allowed
    assert (await _attempt(governor, _LOGIN, "admin")).allowed

    refused = await _attempt(governor, _OTHER_ROUTE, "admin")
    assert not refused.allowed
    assert refused.category == REFUSED_CREDENTIAL_BUDGET
    assert "budget is 3" in refused.reason


@pytest.mark.asyncio
async def test_the_budget_is_per_account_and_per_origin(tmp_path) -> None:
    """A spent budget for one account says nothing about another."""
    governor = _governor(tmp_path, budget=1)

    assert (await _attempt(governor, _LOGIN, "admin")).allowed
    assert not (await _attempt(governor, _LOGIN, "admin")).allowed
    # A different account on the same origin, and the same account on a
    # different origin, are different accounts to lock.
    assert (await _attempt(governor, _LOGIN, "root")).allowed
    assert (await _attempt(governor, _OTHER_ORIGIN, "admin")).allowed


@pytest.mark.asyncio
async def test_a_request_that_names_no_account_is_unbounded_as_before(tmp_path) -> None:
    """Every other request in the engagement is byte-identical to before."""
    governor = _governor(tmp_path, budget=1)
    for _ in range(5):
        decision = await governor.authorize("GET", "http://target.test/page", stage="scan")
        assert decision.allowed
        governor.release()


@pytest.mark.asyncio
async def test_a_zero_budget_disables_the_bound(tmp_path) -> None:
    """``0`` is "no bound", not "no attempts" — the same convention as the action ceiling."""
    governor = _governor(tmp_path, budget=0)
    for _ in range(12):
        assert (await _attempt(governor, _LOGIN, "admin")).allowed


@pytest.mark.asyncio
async def test_a_refused_attempt_costs_no_slot_and_no_token(tmp_path) -> None:
    """A refusal that consumed a concurrency slot would deadlock the next one."""
    governor = _governor(tmp_path, budget=1)
    assert (await _attempt(governor, _LOGIN, "admin")).allowed
    before = governor.credential_attempts(_LOGIN, "admin")
    assert not (await _attempt(governor, _LOGIN, "admin")).allowed
    # The refusal did not count as an attempt either — an attempt is a request
    # the target received, and this one never left.
    assert governor.credential_attempts(_LOGIN, "admin") == before
    # The semaphore is intact: a permitted request still goes through.
    assert (await _attempt(governor, _LOGIN, "root")).allowed


# ---------------------------------------------------------------------------
# The stop the target declares
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "headers", "body", "kind", "marker"),
    [
        (429, {}, "", LockoutKind.RATE_LIMIT, "429"),
        (200, {"Retry-After": "60"}, "", LockoutKind.RATE_LIMIT, "Retry-After: 60"),
        (
            200,
            {"X-RateLimit-Remaining": "0"},
            "",
            LockoutKind.RATE_LIMIT,
            "X-RateLimit-Remaining: 0",
        ),
        (200, {}, "Your account has been locked.", LockoutKind.LOCKOUT, "account has been locked"),
        (200, {}, "Please solve the captcha to continue", LockoutKind.CAPTCHA, "solve the captcha"),
        (200, {}, "Too many failed sign-in attempts", LockoutKind.LOCKOUT, "too many failed"),
    ],
)
def test_the_vocabulary_classifies_what_it_claims_to(
    status: int, headers: dict[str, str], body: str, kind: LockoutKind, marker: str
) -> None:
    signal = classify_lockout(status, headers, body)
    assert signal.kind is kind
    assert signal.marker == marker


def test_a_budget_with_room_left_is_not_a_refusal() -> None:
    """``X-RateLimit-Remaining: 7`` is the server saying we may continue."""
    assert not classify_lockout(200, {"X-RateLimit-Remaining": "7"}, "")


def test_an_ordinary_refusal_carries_no_stop_signal() -> None:
    """A wrong password is not a lockout, and must not stop the run."""
    assert not classify_lockout(401, {}, "<html>Invalid credentials</html>")


@pytest.mark.asyncio
async def test_an_observed_lockout_refuses_every_later_attempt(tmp_path) -> None:
    """The captcha case, which is the one that was silently wrong.

    A captcha is a refusal the application made WITHOUT evaluating the
    credential. Read as "that password was wrong", it produced N-1 further
    attempts on evidence we already had.
    """
    governor = _governor(tmp_path, budget=50)
    assert (await _attempt(governor, _LOGIN, "admin")).allowed

    signal = governor.observe_credential_response(
        url=_LOGIN,
        account="admin",
        status=200,
        headers={},
        body="<html>Please solve the captcha to continue</html>",
    )
    assert signal.kind is LockoutKind.CAPTCHA

    refused = await _attempt(governor, _LOGIN, "admin")
    assert not refused.allowed
    assert refused.category == REFUSED_CREDENTIAL_STOPPED
    assert "captcha" in refused.reason
    # It is a statement about the login, not about the password.
    assert "wrong" not in refused.reason.lower()


@pytest.mark.asyncio
async def test_the_stop_beats_a_budget_that_still_has_room(tmp_path) -> None:
    """An observation about the target outranks an assumption about it."""
    governor = _governor(tmp_path, budget=50)
    governor.observe_credential_response(
        url=_LOGIN, account="admin", status=429, headers={}, body=""
    )
    refused = await _attempt(governor, _LOGIN, "admin")
    assert refused.category == REFUSED_CREDENTIAL_STOPPED


@pytest.mark.asyncio
async def test_only_the_first_stop_is_kept(tmp_path) -> None:
    """The observation that stopped us is the one the operator needs to see."""
    governor = _governor(tmp_path)
    governor.observe_credential_response(
        url=_LOGIN, account="admin", status=200, headers={}, body="Account has been locked"
    )
    governor.observe_credential_response(
        url=_LOGIN, account="admin", status=429, headers={}, body=""
    )
    assert governor.credential_stop(_LOGIN, "admin").kind is LockoutKind.LOCKOUT


@pytest.mark.asyncio
async def test_the_sweep_asks_for_the_first_stop_on_any_account(tmp_path) -> None:
    """An engine that stops guessing admin's password and starts on root's learned nothing."""
    governor = _governor(tmp_path)
    assert governor.first_credential_stop() == ("", governor.credential_stop(_LOGIN, "nobody"))
    governor.observe_credential_response(
        url=_LOGIN, account="admin", status=429, headers={}, body=""
    )
    account, signal = governor.first_credential_stop()
    assert account == "admin"
    assert signal.kind is LockoutKind.RATE_LIMIT


# ---------------------------------------------------------------------------
# The client-facing record
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_attempt_and_every_refusal_reaches_the_action_log(tmp_path) -> None:
    """ "How many times did you try my admin password" is answerable from the log.

    It was not: one ``authenticate()`` produced at most ONE entry saying "POST
    mutates target state", while the JSON arm — riding the HTTP chokepoint —
    logged its seven-to-twenty-four individually. Two accounting regimes inside
    one call meant the log's meaning depended on which transport ran.
    """
    import json

    governor = _governor(tmp_path, budget=2)
    await _attempt(governor, _LOGIN, "admin")
    await _attempt(governor, _LOGIN, "admin")
    await _attempt(governor, _LOGIN, "admin")  # refused

    records = [
        json.loads(line)
        for line in governor.action_log.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    attempts = [r for r in records if r["category"] == CATEGORY_CREDENTIAL_ATTEMPT]
    assert len(attempts) == 2, f"expected two sent attempts in the log, got {records}"
    assert all(r["outcome"] == OUTCOME_SENT for r in attempts)
    # Each one names the account and where it is in the budget.
    assert attempts[0]["signal"] == "admin"
    assert "credential attempt 1 of 2 for account 'admin'" in attempts[0]["reason"]
    assert "credential attempt 2 of 2 for account 'admin'" in attempts[1]["reason"]

    refusals = [r for r in records if r["category"] == REFUSED_CREDENTIAL_BUDGET]
    assert len(refusals) == 1
    assert refusals[0]["outcome"] == OUTCOME_REFUSED


@pytest.mark.asyncio
async def test_the_stats_report_per_account_rather_than_a_total(tmp_path) -> None:
    """A total is not evidence about its parts (invariant 72).

    24 attempts across six accounts and 24 against one are the same number and a
    different engagement.
    """
    governor = _governor(tmp_path, budget=10)
    await _attempt(governor, _LOGIN, "admin")
    await _attempt(governor, _LOGIN, "admin")
    await _attempt(governor, _LOGIN, "root")
    governor.observe_credential_response(
        url=_LOGIN, account="admin", status=429, headers={}, body=""
    )

    stats = governor.stats()
    assert stats["max_credential_attempts_per_account"] == 10
    assert stats["credential_attempts"] == {
        "admin @ http://target.test": 2,
        "root @ http://target.test": 1,
    }
    assert stats["credential_stops"] == {"admin @ http://target.test": "rate_limit: 429"}


@pytest.mark.asyncio
async def test_the_password_never_reaches_the_log(tmp_path) -> None:
    """The body is excerpted into the action log, so the secret must be registered."""
    import json

    from clinkz.engagement.secrets import clear_secrets, register_secret

    register_secret("hunter2-the-real-one")
    try:
        governor = _governor(tmp_path, budget=5)
        decision = await governor.authorize(
            "POST",
            _LOGIN,
            body="account=admin&password=hunter2-the-real-one",
            stage="auth",
            account="admin",
            # What every credential-bearing caller declares. Without it the
            # destructive classifier reads ``account`` as a mutation qualifier
            # and refuses the login as a credential CHANGE — see the note at
            # the authorize() call in http_client.
            field_names=["username", "password"],
        )
        assert decision.allowed
        governor.release()
    finally:
        clear_secrets()

    raw = governor.action_log.path.read_text(encoding="utf-8")
    assert "hunter2-the-real-one" not in raw
    # The FIELD NAME survives — it is schema, not data.
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert "password" in records[-1]["body_excerpt"]


# ---------------------------------------------------------------------------
# The pre-flight accessor, and the one property it must have
# ---------------------------------------------------------------------------


class TestCredentialAttemptsRemaining:
    """A caller that must DECIDE before dispatching gets the same answer as the gate.

    The adaptive-auth loop asks this before proposing a credential POST, because
    proposing one it cannot afford spends a turn and teaches nothing. That makes
    it a second place the budget is read, and a second reader is a second answer
    unless the two are held together — which is exactly the shape that produced
    ``ceiling_is_our_budget`` (invariant 93): a flag read where it could not take
    its other value.
    """

    @pytest.mark.asyncio
    async def test_it_counts_down_with_each_dispatched_attempt(self, tmp_path) -> None:
        governor = _governor(tmp_path, budget=3)
        assert governor.credential_attempts_remaining(_LOGIN, "admin") == 3
        for expected in (2, 1, 0):
            assert (await _attempt(governor, _LOGIN, "admin")).allowed
            assert governor.credential_attempts_remaining(_LOGIN, "admin") == expected

    @pytest.mark.asyncio
    async def test_zero_remaining_and_the_gate_refusing_are_the_same_moment(self, tmp_path) -> None:
        """The property that matters: the pre-flight never disagrees with the gate.

        A pre-flight that said "one left" where ``authorize`` refuses would send a
        caller into a refusal it had just been told it could avoid, and the
        transcript would record a rails refusal where a budget check belonged.
        """
        governor = _governor(tmp_path, budget=2)
        for _ in range(4):
            remaining = governor.credential_attempts_remaining(_LOGIN, "admin")
            decision = await _attempt(governor, _LOGIN, "admin")
            assert decision.allowed == (remaining != 0), (
                f"pre-flight said {remaining} remaining and the gate said "
                f"allowed={decision.allowed}"
            )

    def test_a_recorded_stop_returns_zero_ahead_of_the_arithmetic(self, tmp_path) -> None:
        """The target's answer outranks the budget we assumed (invariant 92).

        Arithmetically there are attempts left. Operationally there are none: the
        account is locked and ``_credential_decision`` refuses regardless.
        Answering "seven remaining" here would be true and useless.
        """
        governor = _governor(tmp_path, budget=8)
        governor.observe_credential_response(
            url=_LOGIN,
            account="admin",
            status=200,
            headers={},
            body="Your account has been locked",
        )
        assert governor.credential_attempts_remaining(_LOGIN, "admin") == 0

    def test_an_unconfigured_bound_is_none_and_not_a_number(self, tmp_path) -> None:
        """``0`` already means unbounded to ``_credential_decision``.

        So this must not return ``0`` for it: a caller branching on "is there a
        bound" would read the unbounded case as the spent case and refuse every
        attempt. ``None`` is the only value that cannot be mistaken for a count.
        """
        governor = _governor(tmp_path, budget=0)
        assert governor.credential_attempts_remaining(_LOGIN, "admin") is None

    def test_it_is_keyed_on_origin_and_account_like_the_budget_itself(self, tmp_path) -> None:
        """Same key, or the two readings are of different things."""
        governor = _governor(tmp_path, budget=4)
        governor._credential_attempts[governor._credential_key(_LOGIN, "admin")] = 3
        assert governor.credential_attempts_remaining(_OTHER_ROUTE, "admin") == 1
        assert governor.credential_attempts_remaining(_LOGIN, "other") == 4
        assert governor.credential_attempts_remaining(_OTHER_ORIGIN, "admin") == 4


# ---------------------------------------------------------------------------
# The adaptive-auth reserve
# ---------------------------------------------------------------------------


class TestTheAdaptiveAuthReserve:
    """Being last is what starves a consumer, so it RESERVES (invariant 88's shape).

    Measured on cal.diy, the target the adaptive layer was built for: the
    deterministic pass spent **8 of 8** — two form attempts, then the JSON arm
    walking its route list with two identity-key shapes each — and the adaptive
    layer, which runs only after that pass has failed, recorded NOT_ATTEMPTED
    with the whole allowance gone. Every one of those eight was a correct thing
    to try. A budget a first consumer may exhaust is not a shared budget; it is a
    first-come one, and the consumer that runs second never gets a turn.

    The reserve costs the deterministic pass nothing it was going to use: its
    remaining attempts differ from its earlier ones in route and field NAME, not
    in anything that learns from the last answer.
    """

    @pytest.mark.asyncio
    async def test_the_deterministic_pass_is_bounded_by_the_unreserved_share(
        self, tmp_path
    ) -> None:
        governor = _governor(tmp_path, budget=8, reserve=3)
        allowed = 0
        for _ in range(10):
            if (await _attempt(governor, _LOGIN, "admin")).allowed:
                allowed += 1
        assert allowed == 5, "the login flow may spend 8 - 3"

    @pytest.mark.asyncio
    async def test_the_reserve_survives_for_the_caller_that_claims_it(self, tmp_path) -> None:
        """The property the whole thing exists for.

        With the unreserved share exhausted, an unreserved caller is refused and
        a reserved one is not — and the reserved one gets exactly the reserve.
        """
        governor = _governor(tmp_path, budget=8, reserve=3)
        for _ in range(10):
            await _attempt(governor, _LOGIN, "admin")

        assert not (await _attempt(governor, _LOGIN, "admin")).allowed
        assert governor.credential_attempts_remaining(_LOGIN, "admin") == 0
        assert governor.credential_attempts_remaining(_LOGIN, "admin", reserved=True) == 3

        for expected in (2, 1, 0):
            decision = await governor.authorize(
                "POST", _LOGIN, account="admin", credential_reserve=True
            )
            assert decision.allowed
            governor.release()
            assert (
                governor.credential_attempts_remaining(_LOGIN, "admin", reserved=True) == expected
            )
        refused = await governor.authorize("POST", _LOGIN, account="admin", credential_reserve=True)
        assert not refused.allowed, "the reserve is a share, not an exemption"

    @pytest.mark.asyncio
    async def test_a_zero_reserve_is_byte_identical_to_before(self, tmp_path) -> None:
        """The pre-existing behaviour is still reachable, and is what ``0`` means."""
        governor = _governor(tmp_path, budget=3, reserve=0)
        allowed = 0
        for _ in range(5):
            if (await _attempt(governor, _LOGIN, "admin")).allowed:
                allowed += 1
        assert allowed == 3

    def test_a_reserve_larger_than_the_budget_cannot_starve_the_login_flow(self, tmp_path) -> None:
        """The same defect pointing the other way, clamped rather than trusted.

        A reserve of 10 against a budget of 3 would leave the deterministic pass
        zero attempts — an engine that cannot log in at all, in service of a
        layer that only runs when logging in failed.
        """
        governor = _governor(tmp_path, budget=3, reserve=10)
        assert governor._reserve() == 2
        assert governor._budget_for(reserved=False) == 1
        assert governor._budget_for(reserved=True) == 3

    def test_an_unbounded_allowance_has_no_share_to_divide(self, tmp_path) -> None:
        """``0`` budget means unbounded, so a reserve against it invents a bound."""
        governor = _governor(tmp_path, budget=0, reserve=3)
        assert governor._reserve() == 0
        assert governor.credential_attempts_remaining(_LOGIN, "admin") is None
        assert governor.credential_attempts_remaining(_LOGIN, "admin", reserved=True) is None

    def test_the_split_is_stated_in_the_client_facing_summary(self, tmp_path) -> None:
        """Two allowances, stated apart.

        A run where the login flow hit ITS bound is not a run that exhausted the
        client's account, and a single total cannot tell an operator which
        happened.
        """
        stats = _governor(tmp_path, budget=8, reserve=3).stats()
        assert stats["max_credential_attempts_per_account"] == 8
        assert stats["adaptive_auth_credential_reserve"] == 3

    @pytest.mark.asyncio
    async def test_the_refusal_names_why_the_share_is_smaller_than_the_budget(
        self, tmp_path
    ) -> None:
        """An operator reading "budget is 5" against a policy of 8 needs the reason."""
        governor = _governor(tmp_path, budget=8, reserve=3)
        for _ in range(6):
            decision = await _attempt(governor, _LOGIN, "admin")
        assert not decision.allowed
        assert "held back for the adaptive layer" in decision.reason
