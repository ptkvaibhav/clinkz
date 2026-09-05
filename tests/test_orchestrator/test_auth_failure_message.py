"""The abort message may not assert a negative about a comparison never made.

Three different failures wore one message, and on a live run all three of its
remedies were wrong at once. The credentials had never been offered to the
application; the assertion had never run — ``attempted`` was empty — and the
message nonetheless said:

    the application has no URL that behaves differently when authenticated
    among the ones tried

Nothing had been tried. An operator acting on that would have gone looking for a
protected URL to declare, for a session that failed three steps earlier.

These tests pin the split: which of the three things happened decides what the
message is allowed to say, and the remedies are filtered the same way.
"""

from __future__ import annotations

from typing import Any

from clinkz.engagement.auth_state import AuthAssertion, AuthMechanism
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent

SCOPE = EngagementScope(
    name="auth-failure-message",
    targets=[ScopeEntry(value="http://app:8090", type=ScopeType.URL)],
)

#: The sentence that may only appear when a comparison actually happened.
_NEGATIVE_ABOUT_A_COMPARISON = "behaves differently when authenticated"


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


class _Detection:
    mechanism = AuthMechanism.UNKNOWN
    login_url = ""


def _message(sessions: dict[str, dict[str, Any]]) -> str:
    agent = OrchestratorAgent(llm=_SilentLLM())
    agent._scope = SCOPE
    agent._role_sessions = sessions
    return agent._auth_failure_message("http://app:8090", _Detection())


def test_nothing_dispatched_says_so_and_claims_no_comparison() -> None:
    """The live defect: no credential ever left the engine."""
    message = _message(
        {
            "operator": {
                "established": False,
                "username": "acct-4417",
                "login_url": "http://app:8090/portal/gateway",
                "posted_to": "",
                "assertion": AuthAssertion(
                    established=False,
                    why_unproven="no login surface was proven under http://app:8090",
                ),
            }
        }
    )
    assert "NO credential was ever offered to the application" in message
    assert "before any login request was dispatched" in message
    assert _NEGATIVE_ABOUT_A_COMPARISON not in message, (
        "the message asserted a negative about a comparison that never ran:\n" + message
    )
    # It should instead point at the declarations that would fix discovery.
    assert "login_api_url" in message
    assert "login_field" in message
    assert "login_content_type" in message


def test_a_dispatched_and_refused_post_names_where_it_went() -> None:
    """A form ``action`` sends the credentials somewhere the operator never named."""
    message = _message(
        {
            "operator": {
                "established": False,
                "username": "acct-4417",
                "login_url": "http://app:8090/portal/gateway",
                "posted_to": "http://app:8090/portal/v3/session-open",
                "assertion": AuthAssertion(
                    established=False,
                    why_unproven=(
                        "credential POST to http://app:8090/portal/v3/session-open "
                        "returned 401 with no session material"
                    ),
                ),
            }
        }
    )
    assert "a credential POST WAS dispatched" in message
    assert "the assertion was never reached" in message
    assert "posted to: http://app:8090/portal/v3/session-open" in message
    # The distinction an operator cannot make from "login failed at <login page>".
    assert "that is not http://app:8090/portal/gateway" in message
    assert _NEGATIVE_ABOUT_A_COMPARISON not in message
    # Wrong credentials IS a live possibility here, and only here.
    assert "the credentials are wrong" in message


def test_only_a_run_that_reached_the_assertion_may_blame_the_urls() -> None:
    """The one case in which "no URL behaved differently" is about an observation."""
    message = _message(
        {
            "operator": {
                "established": False,
                "username": "acct-4417",
                "login_url": "http://app:8090/portal/gateway",
                "posted_to": "http://app:8090/portal/v3/session-open",
                "assertion": AuthAssertion(
                    established=False,
                    why_unproven="no candidate URL behaved differently",
                    attempted=[
                        "http://app:8090/api/users: authenticated=404 anonymous=404",
                        "http://app:8090/me: authenticated=404 anonymous=404",
                    ],
                ),
            }
        }
    )
    assert "the assertion RAN" in message
    assert _NEGATIVE_ABOUT_A_COMPARISON in message
    assert "assert_url" in message
    # And the comparison itself is listed, with both statuses per URL.
    assert "http://app:8090/api/users: authenticated=404 anonymous=404" in message
    assert "http://app:8090/me: authenticated=404 anonymous=404" in message


def test_a_long_comparison_is_truncated_but_says_how_much() -> None:
    """A bound that hides evidence announces itself."""
    attempted = [f"http://app:8090/p{i}: authenticated=404 anonymous=404" for i in range(14)]
    message = _message(
        {
            "operator": {
                "established": False,
                "username": "u",
                "login_url": "http://app:8090/login",
                "posted_to": "http://app:8090/login",
                "assertion": AuthAssertion(
                    established=False, why_unproven="nothing discriminated", attempted=attempted
                ),
            }
        }
    )
    assert "and 6 more" in message


def test_roles_are_reported_independently() -> None:
    """Two roles failing for two reasons get two diagnoses, not one verdict."""
    message = _message(
        {
            "admin": {
                "established": False,
                "username": "a",
                "login_url": "http://app:8090/login",
                "posted_to": "",
                "assertion": AuthAssertion(established=False, why_unproven="no login surface"),
            },
            "customer": {
                "established": False,
                "username": "c",
                "login_url": "http://app:8090/login",
                "posted_to": "http://app:8090/login",
                "assertion": AuthAssertion(
                    established=False,
                    why_unproven="nothing discriminated",
                    attempted=["http://app:8090/me: authenticated=200 anonymous=200"],
                ),
            },
        }
    )
    assert "[admin] NO credential was ever offered" in message
    assert "[customer] the session was established and the assertion RAN" in message
    # One role reached the assertion, so the remedy is offered — once.
    assert message.count("assert_url") == 1
