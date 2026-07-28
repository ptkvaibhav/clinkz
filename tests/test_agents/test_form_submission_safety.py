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


def _exploding_http_client(*_args: Any, **_kwargs: Any) -> Any:
    """Stand-in for ``HTTPClientTool`` that fails loudly if anything builds it.

    A refused request and a failed request both surface as ``status=0``, so
    asserting on the status alone cannot distinguish "guard fired" from "request
    went out and errored". Constructing the transport at all is the observable
    that actually separates them.
    """
    raise AssertionError("transport was reached — the request was NOT refused")


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


# ===========================================================================
# The GET-method credential form (engagement cb54495c — the live failure)
#
# The form-shaped guard refused 66 submissions and the run STILL set admin's
# hash to md5(""). DVWA's password-change form is `<form action="#"
# method="GET">`, so its fields are ordinary query parameters — and
# `low.php` gates only on `isset($_GET['Change'])`, taking password_new and
# password_conf as NULL when absent:
#
#     GET /vulnerabilities/csrf/?Change=CLNKZmclhqf   →  NULL == NULL  →  md5("")
#
# One unparameterised-looking probe of the submit button. It never touched
# `_submit_form_fields`: methodologies hand-roll query probes, and the NoSQL
# carrier sends bracket-notation query params directly. The guard therefore
# has to bind to the ENDPOINT and be enforced in the _http_* helpers — the
# only layer every carrier passes through.
# ===========================================================================


class TestDestructiveEndpointRegistry:
    def _register(self, agent: ExploitAgent, url: str, form: dict[str, Any]) -> None:
        agent._register_destructive_endpoint(url, [form], [f["name"] for f in form["fields"]])

    def test_get_method_credential_form_registers_the_endpoint(self) -> None:
        agent = _make_agent()
        form = {**_password_change_form(), "method": "GET"}
        self._register(agent, "http://example.com/vulnerabilities/csrf/", form)
        assert agent._destructive_endpoints == {"http://example.com/vulnerabilities/csrf"}

    @pytest.mark.asyncio
    async def test_query_carrier_cannot_reach_a_registered_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE regression: `?Change=x` on a GET-method credential form.

        The transport is booby-trapped rather than mocked: a mock returning a
        response, or a real request failing, both look like ``status=0``, so
        only "the HTTP client was never even constructed" actually proves the
        request was not transmitted.
        """
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        self._register(
            agent,
            "http://example.com/vulnerabilities/csrf/",
            {**_password_change_form(), "method": "GET"},
        )
        page = PageAnalysis(
            url="http://example.com/vulnerabilities/csrf/",
            body="",
            status=200,
            input_params=["password_new", "password_conf", "Change"],
            forms=[{**_password_change_form(), "method": "GET"}],
        )
        for param in ("Change", "password_new", "password_conf"):
            resp = await agent._send_probe(page, param, "CLNKZprobe")
            assert resp.status == 0, f"probe of {param} was transmitted"

    @pytest.mark.asyncio
    async def test_nosql_bracket_query_carrier_is_also_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`?Change[$ne]=-1` — a carrier that never touches _submit_form_fields."""
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        self._register(
            agent,
            "http://example.com/vulnerabilities/csrf/",
            {**_password_change_form(), "method": "GET"},
        )
        resp = await agent._http_get(
            "http://example.com/vulnerabilities/csrf/", {"Change[$ne]": "-1"}
        )
        assert resp.status == 0

    @pytest.mark.asyncio
    async def test_a_benign_endpoint_still_reaches_the_transport(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Proves the booby-trap above is load-bearing, not vacuous."""
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        self._register(
            agent,
            "http://example.com/vulnerabilities/csrf/",
            {**_password_change_form(), "method": "GET"},
        )
        with pytest.raises(AssertionError, match="transport was reached"):
            await agent._http_get("http://example.com/vulnerabilities/sqli/", {"id": "1"})

    @pytest.mark.asyncio
    async def test_unparameterised_fetch_is_still_allowed(self) -> None:
        """CSRF analysis must still be able to READ the form it evaluates."""
        agent = _make_agent()
        fetched: list[str] = []

        async def fake_exec(url: str, params: dict[str, str], **_kw: Any) -> _HTTPResponse:
            fetched.append(url)
            return _HTTPResponse(status=200, body="<form>...</form>")

        self._register(
            agent,
            "http://example.com/vulnerabilities/csrf/",
            {**_password_change_form(), "method": "GET"},
        )
        # A no-parameter GET is a read, not a submission — it must pass the
        # guard. Verified by the guard predicate directly, so no transport is
        # needed.
        assert not agent._is_destructive_request(
            "http://example.com/vulnerabilities/csrf/", has_params=False
        )
        assert agent._is_destructive_request(
            "http://example.com/vulnerabilities/csrf/", has_params=True
        )
        assert not fetched

    def test_unrelated_endpoints_are_unaffected(self) -> None:
        agent = _make_agent()
        self._register(
            agent,
            "http://example.com/vulnerabilities/csrf/",
            {**_password_change_form(), "method": "GET"},
        )
        assert not agent._is_destructive_request(
            "http://example.com/vulnerabilities/sqli/?id=1", has_params=True
        )

    def test_endpoint_key_ignores_query_and_trailing_slash(self) -> None:
        agent = _make_agent()
        key = agent._endpoint_key("http://EXAMPLE.com/a/b/?x=1#frag")
        assert key == "http://example.com/a/b"
        assert agent._endpoint_key("http://example.com/a/b") == key

    @pytest.mark.asyncio
    async def test_multipart_carrier_cannot_reach_a_registered_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The FOURTH carrier — found by the gate-3 review of D1 batch 2.

        ``_http_post_multipart`` builds its own ``HTTPClientTool`` and never
        asked the endpoint guard, so an upload point that also mutates
        credentials would still have been submitted to — and phase-2 upload
        fingerprinting drives ~20 probes through this carrier per upload point.
        Same class as the three closed in f8ce94d.
        """
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        self._register(
            agent,
            "http://example.com/vulnerabilities/upload/",
            _password_change_form(),
        )
        resp = await agent._http_post_multipart(
            "http://example.com/vulnerabilities/upload/",
            filename="clinkz_probe.php",
            content="<?php echo 1; ?>",
            content_type="image/jpeg",
        )
        assert resp.status == 0

    @pytest.mark.asyncio
    async def test_xml_body_carrier_cannot_reach_a_registered_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The FIFTH carrier: the XXE raw-XML body helper had no guard either."""
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        self._register(
            agent,
            "http://example.com/services/import",
            _password_change_form(),
        )
        resp = await agent._http_post_xml(
            "http://example.com/services/import",
            xml="<?xml version='1.0'?><x/>",
        )
        assert resp.status == 0

    @pytest.mark.asyncio
    async def test_the_boobytrap_fires_on_an_unregistered_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The proof above is not vacuous: on a benign endpoint both carriers
        DO construct the transport, so ``status=0`` there means "guard fired",
        not "this code path never sends anything"."""
        agent = _make_agent()
        monkeypatch.setattr(
            "clinkz.tools.http_client.HTTPClientTool",
            _exploding_http_client,
        )
        with pytest.raises(AssertionError, match="transport was reached"):
            await agent._http_post_multipart(
                "http://example.com/vulnerabilities/upload/",
                filename="a.txt",
                content="x",
                content_type="text/plain",
            )
        with pytest.raises(AssertionError, match="transport was reached"):
            await agent._http_post_xml(
                "http://example.com/services/import",
                xml="<x/>",
            )
