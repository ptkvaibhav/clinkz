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


def _governor(tmp_path, budget: int = 3) -> EngagementGovernor:
    return EngagementGovernor(
        "budget-test",
        SafetyPolicy(
            max_requests_per_second=1000.0,
            max_credential_attempts_per_account=budget,
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
