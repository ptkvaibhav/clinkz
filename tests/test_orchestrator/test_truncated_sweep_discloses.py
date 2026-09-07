"""A default-credential sweep the target stopped says so, and names the remainder.

The stop itself is invariant 92's and is not in question here: once the login has
answered with a lockout, a rate limit or a captcha, every further guess is an
attempt on evidence we already hold, and on a lockout it extends the lock. What
this pins is what the stop LEAVES BEHIND.

Before: a log line at ERROR, and a deliverable in which the engagement reports no
default credentials. That sentence is a claim about every pair in the catalogue,
and after a stop it is a claim about pairs that were never dispatched — an
absence read as a measurement, in the one document a client acts on.

The fix is structural rather than a message change. The sweep now builds its
whole candidate list BEFORE the first attempt: a loop that seeds the next
technology only after finishing the previous one cannot name its own remainder
at the moment it stops, because it does not yet know what it was going to do.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.safety.lockout import NO_LOCKOUT, LockoutKind, LockoutSignal

SCOPE = EngagementScope(
    name="sweep-truncation-test",
    targets=[ScopeEntry(value="http://app:80", type=ScopeType.URL)],
)
LOGIN = "http://app:80/login.php"


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _cred(cred_id: str, username: str, password: str) -> Any:
    return SimpleNamespace(id=cred_id, username=username, password=password, valid=None)


class _Store:
    """The credential store, reduced to what the sweep asks of it."""

    def __init__(self, by_tech: dict[str, list[Any]]) -> None:
        self._by_tech = by_tech
        self.marked_invalid: list[str] = []

    async def seed_defaults(self, _engagement: str, technology: str) -> list[str]:
        return [c.id for c in self._by_tech.get(technology, [])]

    async def get(self, _engagement: str, technology: str = "") -> list[Any]:
        return list(self._by_tech.get(technology, []))

    async def mark_invalid(self, cred_id: str) -> None:
        self.marked_invalid.append(cred_id)


def _agent(by_tech: dict[str, list[Any]]) -> OrchestratorAgent:
    agent = OrchestratorAgent(llm=_SilentLLM())
    agent._scope = SCOPE
    agent._engagement_id = "00000000-0000-0000-0000-000000000000"
    agent._cred_store = _Store(by_tech)  # type: ignore[assignment]
    # The sweep asserts the state store is open before it plans; nothing in
    # the path under test reads it.
    agent._state = object()  # type: ignore[assignment]
    agent._extract_technologies = lambda _r: list(by_tech)  # type: ignore[method-assign]
    agent._find_login_url = AsyncMock(return_value=LOGIN)  # type: ignore[method-assign]
    agent._attempt_login = AsyncMock(return_value=False)  # type: ignore[method-assign]
    return agent


def _stop_after(n: int, signal: LockoutSignal) -> Any:
    """Report no stop for the first *n* checks, then the target's refusal."""
    calls = {"n": 0}

    def _evidence() -> tuple[str, LockoutSignal]:
        calls["n"] += 1
        if calls["n"] <= n:
            return ("", NO_LOCKOUT)
        return ("admin", signal)

    return _evidence


LOCKOUT = LockoutSignal(LockoutKind.LOCKOUT, "account has been locked", "response body")


@pytest.mark.asyncio
async def test_a_truncated_sweep_records_that_it_stopped() -> None:
    agent = _agent(
        {
            "dvwa": [_cred("c1", "admin", "password"), _cred("c2", "gordonb", "abc123")],
            "mysql": [_cred("c3", "root", "root")],
            "tomcat": [_cred("c4", "tomcat", "tomcat")],
        }
    )
    agent._credential_stop_evidence = _stop_after(2, LOCKOUT)  # type: ignore[method-assign]

    await agent._try_default_credentials({})

    sweep = agent._credential_sweep
    assert sweep["stopped"] is True
    assert sweep["stop_kind"] == LockoutKind.LOCKOUT.value
    assert sweep["stop_marker"] == "account has been locked"
    assert sweep["stopped_for_account"] == "admin"
    assert sweep["login_url"] == LOGIN
    assert sweep["attempted"] == 2
    assert sweep["planned"] == 4


@pytest.mark.asyncio
async def test_the_remainder_is_named_by_account_and_technology() -> None:
    """And never by password — the untried ones were never registered.

    ``_attempt_login`` calls ``register_secret`` on a guess as it offers it, so
    a pair the sweep never sent is outside the redaction gate entirely. Writing
    its password into the deliverable would put an unregistered secret past the
    one thing that exists to catch them.
    """
    agent = _agent(
        {
            "dvwa": [_cred("c1", "admin", "password")],
            "mysql": [_cred("c2", "root", "hunter2")],
            "tomcat": [_cred("c3", "tomcat", "s3cr3t")],
        }
    )
    agent._credential_stop_evidence = _stop_after(1, LOCKOUT)  # type: ignore[method-assign]

    await agent._try_default_credentials({})

    untried = agent._credential_sweep["untried"]
    assert untried == ["root (mysql)", "tomcat (tomcat)"]
    joined = " ".join(untried)
    for password in ("hunter2", "s3cr3t"):
        assert password not in joined


@pytest.mark.asyncio
async def test_the_stop_still_stops_it() -> None:
    """The disclosure is added; the refusal is unchanged."""
    agent = _agent({"dvwa": [_cred(f"c{i}", f"user{i}", "pw") for i in range(6)]})
    agent._credential_stop_evidence = _stop_after(2, LOCKOUT)  # type: ignore[method-assign]

    await agent._try_default_credentials({})

    assert agent._attempt_login.call_count == 2  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_a_sweep_that_finished_records_that_too() -> None:
    """ "The sweep completed" and "no sweep ran" are different states.

    Both leave ``untried`` empty, so the report reads ``stopped`` rather than the
    emptiness — but the orchestrator has to be able to tell them apart at all,
    which it cannot from an absent field.
    """
    agent = _agent({"dvwa": [_cred("c1", "admin", "password"), _cred("c2", "gordonb", "abc123")]})
    agent._credential_stop_evidence = lambda: ("", NO_LOCKOUT)  # type: ignore[method-assign]

    await agent._try_default_credentials({})

    sweep = agent._credential_sweep
    assert sweep["stopped"] is False
    assert sweep["attempted"] == 2
    assert sweep["planned"] == 2
    assert sweep["untried"] == []


@pytest.mark.asyncio
async def test_a_run_with_no_login_surface_records_nothing() -> None:
    """No sweep, no claim to qualify."""
    agent = _agent({"dvwa": [_cred("c1", "admin", "password")]})
    agent._find_login_url = AsyncMock(return_value="")  # type: ignore[method-assign]

    await agent._try_default_credentials({})

    assert agent._credential_sweep == {}
