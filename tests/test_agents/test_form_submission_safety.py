"""Regression tests for the destructive-form-submission guard (gap G8).

The engagement that motivated this: per-parameter fuzzing submitted DVWA's
password-change form ~25 times per run and left ``admin``'s hash as
``md5("")``. Two independent defects combined —

  1. :meth:`ExploitAgent._build_form_data` sent every non-probed field
     EMPTY BUT PRESENT, so a handler comparing ``new == confirm`` saw two empty
     strings agree; and
  2. the state-change guard covered navigation (``is_state_changing_url``) but
     not form SUBMISSION, so nothing refused the request in the first place.

Both are covered here: the builder must never blank a field it was not asked to
set, and the submit chokepoint must refuse a credential/account-mutating form
outright.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._url_safety import is_destructive_form_submission
from clinkz.agents.exploit import ExploitAgent, PageAnalysis, _HTTPResponse
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="form-safety-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=None,  # type: ignore[arg-type]
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="form-safety-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    return agent


def _password_change_form() -> dict[str, Any]:
    """DVWA's password-change form, verbatim in shape."""
    return {
        "action": "#",
        "method": "POST",
        "fields": [
            {"name": "password_new", "type": "password", "value": ""},
            {"name": "password_conf", "type": "password", "value": ""},
            {"name": "Change", "type": "submit", "value": "Change"},
        ],
    }


def _guestbook_form() -> dict[str, Any]:
    """A benign stored-content form — must stay fully fuzzable."""
    return {
        "action": "#",
        "method": "POST",
        "fields": [
            {"name": "txtName", "type": "text", "value": ""},
            {"name": "mtxMessage", "type": "textarea", "value": ""},
            {"name": "btnSign", "type": "submit", "value": "Sign Guestbook"},
        ],
    }


def _login_form() -> dict[str, Any]:
    return {
        "action": "",
        "method": "POST",
        "fields": [
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
            {"name": "Login", "type": "submit", "value": "Login"},
        ],
    }


# ===========================================================================
# The predicate
# ===========================================================================


class TestIsDestructiveFormSubmission:
    def test_password_change_form_is_destructive(self) -> None:
        assert is_destructive_form_submission(
            _password_change_form(), "http://example.com/vulnerabilities/csrf/"
        )

    def test_password_change_with_current_field_is_destructive(self) -> None:
        form = {
            "action": "",
            "method": "POST",
            "fields": [
                {"name": "password_current", "type": "password", "value": ""},
                {"name": "password_new", "type": "password", "value": ""},
            ],
        }
        assert is_destructive_form_submission(form, "http://example.com/pw")

    def test_json_change_password_api_is_destructive_by_path(self) -> None:
        """A JSON pseudo-form carries its sensitivity in the path, not the action."""
        form = {
            "action": "",
            "method": "POST",
            "encoding": "json",
            "fields": [
                {"name": "current", "type": "text", "value": ""},
                {"name": "new", "type": "text", "value": ""},
            ],
        }
        assert is_destructive_form_submission(form, "http://example.com/rest/user/change-password")

    def test_delete_method_is_destructive(self) -> None:
        form = {"action": "", "method": "DELETE", "fields": [{"name": "id", "type": "text"}]}
        assert is_destructive_form_submission(form, "http://example.com/api/items/1")

    def test_destructive_verb_in_path_is_destructive(self) -> None:
        form = {"action": "", "method": "POST", "fields": [{"name": "id", "type": "text"}]}
        assert is_destructive_form_submission(form, "http://example.com/account/delete")

    def test_login_form_is_not_destructive(self) -> None:
        """Brute-force testing depends on login forms staying submittable."""
        assert not is_destructive_form_submission(_login_form(), "http://example.com/login.php")

    def test_registration_form_is_not_destructive(self) -> None:
        """Creating an account destroys nothing — no mutation qualifier present."""
        form = {
            "action": "",
            "method": "POST",
            "encoding": "json",
            "fields": [
                {"name": "email", "type": "email", "value": ""},
                {"name": "password", "type": "password", "value": ""},
                {"name": "passwordRepeat", "type": "password", "value": ""},
            ],
        }
        assert not is_destructive_form_submission(form, "http://example.com/api/Users")

    def test_guestbook_form_is_not_destructive(self) -> None:
        assert not is_destructive_form_submission(
            _guestbook_form(), "http://example.com/vulnerabilities/xss_s/"
        )

    def test_search_form_is_not_destructive(self) -> None:
        form = {
            "action": "",
            "method": "GET",
            "fields": [{"name": "q", "type": "text", "value": ""}],
        }
        assert not is_destructive_form_submission(form, "http://example.com/search")


# ===========================================================================
# The body builder — never empty-but-present
# ===========================================================================


class TestBuildFormDataNeverBlanks:
    def test_unset_valueless_fields_are_omitted_not_blanked(self) -> None:
        agent = _make_agent()
        data = agent._build_form_data(_password_change_form(), {"password_new": "PAYLOAD"})
        assert data["password_new"] == "PAYLOAD"
        # THE regression: password_conf must not be transmitted at all. Sent as
        # "" it equals an empty password_new on a baseline probe, and the
        # handler agrees the two match.
        assert "password_conf" not in data

    def test_declared_values_are_preserved(self) -> None:
        """A submit button's value gates the server-side handler — keep it."""
        agent = _make_agent()
        data = agent._build_form_data(_guestbook_form(), {"txtName": "PAYLOAD"})
        assert data["txtName"] == "PAYLOAD"
        assert data["btnSign"] == "Sign Guestbook"
        assert "mtxMessage" not in data

    def test_baseline_probe_sends_only_declared_values(self) -> None:
        """The empty-override case is what actually set the password to md5("")."""
        agent = _make_agent()
        data = agent._build_form_data(_password_change_form(), {})
        assert data == {"Change": "Change"}


# ===========================================================================
# The submit chokepoint — refusal
# ===========================================================================


class TestSubmitChokepointRefusal:
    @pytest.mark.asyncio
    async def test_destructive_form_is_never_submitted(self) -> None:
        agent = _make_agent()
        posted: list[tuple[str, dict[str, str]]] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append((url, data))
            return _HTTPResponse(status=200, body="changed")

        agent._http_post = fake_post  # type: ignore[method-assign]
        resp = await agent._submit_form_fields(
            "http://example.com/vulnerabilities/csrf/",
            _password_change_form(),
            {"password_new": "x", "password_conf": "x"},
        )
        assert posted == [], "a credential-mutating form was submitted"
        # The refusal returns the same no-response sentinel a transport failure
        # does, so callers degrade to "no signal" — never to a fabricated one.
        assert resp.status == 0
        assert resp.body == ""

    @pytest.mark.asyncio
    async def test_benign_form_still_submits(self) -> None:
        agent = _make_agent()
        posted: list[tuple[str, dict[str, str]]] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append((url, data))
            return _HTTPResponse(status=200, body="signed")

        agent._http_post = fake_post  # type: ignore[method-assign]
        resp = await agent._submit_form_fields(
            "http://example.com/vulnerabilities/xss_s/",
            _guestbook_form(),
            {"txtName": "PAYLOAD", "btnSign": "Sign Guestbook"},
        )
        assert len(posted) == 1
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_per_parameter_probe_never_reaches_a_credential_form(self) -> None:
        """End-to-end for the real carrier: ``_send_probe`` on a password field.

        This is the exact path that fired ~25 times per engagement.
        """
        agent = _make_agent()
        posted: list[dict[str, str]] = []
        got: list[str] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append(data)
            return _HTTPResponse(status=200, body="ok")

        async def fake_get(url: str, params: dict[str, str], **_kw: Any) -> _HTTPResponse:
            got.append(url)
            return _HTTPResponse(status=200, body="ok")

        agent._http_post = fake_post  # type: ignore[method-assign]
        agent._http_get = fake_get  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/csrf/",
            body="",
            status=200,
            input_params=["password_new", "password_conf"],
            forms=[_password_change_form()],
        )
        for param in page.input_params:
            resp = await agent._send_probe(page, param, "' OR 1=1-- -")
            assert resp.status == 0
        assert posted == [], "the password-change form was submitted by a probe"
        assert got == [], "the password-change form was submitted by a probe"


# ===========================================================================
# The carriers that route AROUND a form-shaped guard
#
# Found by the gate-3 security review of the first G8 fix: three submission
# paths did not pass through ``_submit_form_fields``, so the guard did not
# cover them. Each is the same destructive shape by a different carrier.
# ===========================================================================


class TestNonFormCarriersAreGuarded:
    @pytest.mark.asyncio
    async def test_weak_session_never_submits_a_credential_form(self) -> None:
        """Phase 1 accepts ANY generic POST form, and phase 2 submits it 8x.

        Unguarded, that is eight live password changes — worse than the
        per-parameter fuzzer that motivated the guard.
        """
        agent = _make_agent()
        posted: list[dict[str, str]] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append(data)
            return _HTTPResponse(status=200, body="", headers={"Set-Cookie": "sid=1"})

        agent._http_post = fake_post  # type: ignore[method-assign]
        samples, _flags = await agent._weak_session_phase2_observation(
            "http://example.com/vulnerabilities/csrf/", _password_change_form()
        )
        assert posted == [], "weak-session probing submitted a credential form"
        assert samples == {}

    @pytest.mark.asyncio
    async def test_weak_session_still_probes_a_benign_generator_form(self) -> None:
        agent = _make_agent()
        posted: list[dict[str, str]] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append(data)
            return _HTTPResponse(status=200, body="", headers={"Set-Cookie": "dvwaSession=1"})

        agent._http_post = fake_post  # type: ignore[method-assign]
        form = {
            "action": "",
            "method": "POST",
            "fields": [{"name": "Generate", "type": "submit", "value": "Generate"}],
        }
        samples, _flags = await agent._weak_session_phase2_observation(
            "http://example.com/vulnerabilities/weak_id/", form
        )
        assert len(posted) == 8
        assert posted[0] == {"Generate": "Generate"}
        assert samples["dvwaSession"]

    @pytest.mark.asyncio
    async def test_json_body_probe_never_reaches_a_change_password_api(self) -> None:
        """A JSON API has no parsed <form>, so the form guard cannot see it."""
        agent = _make_agent()
        sent: list[dict[str, Any]] = []

        async def fake_post_json(
            url: str, obj: dict[str, Any], method: str = "POST"
        ) -> _HTTPResponse:
            sent.append(obj)
            return _HTTPResponse(status=200, body="ok")

        agent._http_post_json = fake_post_json  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/rest/user/change-password",
            body="",
            status=200,
            input_params=["current", "new", "repeat"],
            request_method="POST",
            content_type="application/json",
            param_locations={
                "current": ParamLocation.JSON_BODY,
                "new": ParamLocation.JSON_BODY,
                "repeat": ParamLocation.JSON_BODY,
            },
        )
        resp = await agent._send_probe(page, "new", "PAYLOAD")
        assert sent == [], "a change-password JSON API was fuzzed"
        assert resp.status == 0

    @pytest.mark.asyncio
    async def test_json_body_probe_still_reaches_a_benign_api(self) -> None:
        agent = _make_agent()
        sent: list[dict[str, Any]] = []

        async def fake_post_json(
            url: str, obj: dict[str, Any], method: str = "POST"
        ) -> _HTTPResponse:
            sent.append(obj)
            return _HTTPResponse(status=201, body="ok")

        agent._http_post_json = fake_post_json  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/api/Feedbacks",
            body="",
            status=200,
            input_params=["comment", "rating"],
            request_method="POST",
            content_type="application/json",
            param_locations={
                "comment": ParamLocation.JSON_BODY,
                "rating": ParamLocation.JSON_BODY,
            },
        )
        resp = await agent._send_probe(page, "comment", "PAYLOAD")
        assert len(sent) == 1
        assert sent[0]["comment"] == "PAYLOAD"
        assert resp.status == 201

    @pytest.mark.asyncio
    async def test_form_body_probe_is_guarded(self) -> None:
        agent = _make_agent()
        posted: list[dict[str, str]] = []

        async def fake_post(url: str, data: dict[str, str], **_kw: Any) -> _HTTPResponse:
            posted.append(data)
            return _HTTPResponse(status=200, body="ok")

        agent._http_post = fake_post  # type: ignore[method-assign]
        page = PageAnalysis(
            url="http://example.com/account/password/update",
            body="",
            status=200,
            input_params=["password"],
            request_method="POST",
            param_locations={"password": ParamLocation.FORM_BODY},
        )
        resp = await agent._send_probe(page, "password", "PAYLOAD")
        assert posted == []
        assert resp.status == 0
