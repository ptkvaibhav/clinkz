"""Tests for WebAuthenticator — deterministic login with CSRF handling."""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import (
    AuthOutput,
    AuthResult,
    WebAuthenticator,
    _EncodingOrder,
    _parse_form_fields,
)

# ---------------------------------------------------------------------------
# HTML form parsing tests
# ---------------------------------------------------------------------------


class TestFormFieldParser:
    """Test the HTML form field parser."""

    def test_extracts_hidden_fields(self) -> None:
        html = """
        <form method="POST" action="/login">
            <input type="hidden" name="user_token" value="abc123" />
            <input type="hidden" name="csrf_token" value="xyz789" />
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        """
        form = _parse_form_fields(html)
        assert form.hidden_fields == {"user_token": "abc123", "csrf_token": "xyz789"}
        assert form.username_field == "username"
        assert form.password_field == "password"
        assert form.form_action == "/login"

    def test_auto_detects_username_variants(self) -> None:
        for field_name in ("username", "user", "login_name", "email", "user_name"):
            html = f'<input type="text" name="{field_name}" />'
            form = _parse_form_fields(html)
            assert form.username_field == field_name, f"Failed to detect: {field_name}"

    def test_detects_password_field(self) -> None:
        html = '<input type="password" name="pass" />'
        form = _parse_form_fields(html)
        assert form.password_field == "pass"

    def test_no_form_action(self) -> None:
        html = '<form><input type="text" name="user" /></form>'
        form = _parse_form_fields(html)
        assert form.form_action == ""

    def test_empty_html(self) -> None:
        form = _parse_form_fields("")
        assert form.hidden_fields == {}
        assert form.username_field == ""
        assert form.password_field == ""

    def test_dvwa_login_form(self) -> None:
        """Parse a DVWA-style login page."""
        html = """
        <html>
        <body>
        <form action="login.php" method="post">
            <input type="text" name="username" /><br />
            <input type="password" name="password" autocomplete="off" /><br />
            <input type="submit" name="Login" value="Login" /><br />
            <input type="hidden" name="user_token" value="d4f1e8a2b3c4d5e6f7a8b9c0" />
        </form>
        </body>
        </html>
        """
        form = _parse_form_fields(html)
        assert form.hidden_fields == {"user_token": "d4f1e8a2b3c4d5e6f7a8b9c0"}
        assert form.username_field == "username"
        assert form.password_field == "password"
        assert form.form_action == "login.php"

    def test_multiple_hidden_fields(self) -> None:
        html = """
        <form method="POST">
            <input type="hidden" name="csrf" value="token1" />
            <input type="hidden" name="nonce" value="token2" />
            <input type="hidden" name="redirect_to" value="/dashboard" />
        </form>
        """
        form = _parse_form_fields(html)
        assert len(form.hidden_fields) == 3
        assert form.hidden_fields["csrf"] == "token1"
        assert form.hidden_fields["nonce"] == "token2"
        assert form.hidden_fields["redirect_to"] == "/dashboard"


# ---------------------------------------------------------------------------
# Login success heuristic tests
# ---------------------------------------------------------------------------


class TestLoginSuccessHeuristics:
    """Test _check_login_success heuristics."""

    def test_success_logout_in_body(self) -> None:
        assert WebAuthenticator._check_login_success(
            response_body="<html><a href='/logout'>Logout</a></html>",
            status_code=200,
            final_url="http://target/index.php",
            login_url="http://target/login.php",
            redirect_chain=[],
        )

    def test_success_redirected_away(self) -> None:
        assert WebAuthenticator._check_login_success(
            response_body="<html>Dashboard</html>",
            status_code=200,
            final_url="http://target/dashboard",
            login_url="http://target/login",
            redirect_chain=["http://target/dashboard"],
        )

    def test_failure_invalid_in_body(self) -> None:
        assert not WebAuthenticator._check_login_success(
            response_body="<html>Invalid credentials</html>",
            status_code=200,
            final_url="http://target/login",
            login_url="http://target/login",
            redirect_chain=[],
        )

    def test_failure_incorrect_password(self) -> None:
        assert not WebAuthenticator._check_login_success(
            response_body="<html>incorrect password</html>",
            status_code=200,
            final_url="http://target/login",
            login_url="http://target/login",
            redirect_chain=[],
        )

    def test_failure_login_failed(self) -> None:
        assert not WebAuthenticator._check_login_success(
            response_body="<html>Login failed. Try again.</html>",
            status_code=200,
            final_url="http://target/login",
            login_url="http://target/login",
            redirect_chain=[],
        )

    def test_success_302_redirect(self) -> None:
        assert WebAuthenticator._check_login_success(
            response_body="",
            status_code=302,
            final_url="http://target/home",
            login_url="http://target/login",
            redirect_chain=["http://target/home"],
        )


# ---------------------------------------------------------------------------
# Tool interface tests
# ---------------------------------------------------------------------------


class TestWebAuthenticatorTool:
    """Test the ToolBase interface of WebAuthenticator."""

    @pytest.fixture()
    def scope(self) -> EngagementScope:
        return EngagementScope(
            name="test",
            targets=[ScopeEntry(type=ScopeType.DOMAIN, value="target.local")],
        )

    @pytest.fixture()
    def auth(self, scope: EngagementScope) -> WebAuthenticator:
        return WebAuthenticator(scope=scope, engagement_id="test-engagement")

    def test_name_and_description(self, auth: WebAuthenticator) -> None:
        assert auth.name == "web_authenticator"
        assert "login" in auth.description.lower()

    def test_capabilities(self) -> None:
        assert "web_authentication" in WebAuthenticator.capabilities
        assert WebAuthenticator.category == "utility"

    def test_get_schema(self, auth: WebAuthenticator) -> None:
        schema = auth.get_schema()
        assert schema["name"] == "web_authenticator"
        params = schema["parameters"]
        assert "login_url" in params["properties"]
        assert "username" in params["properties"]
        assert "password" in params["properties"]
        assert set(params["required"]) == {"login_url", "username", "password"}

    def test_validate_input_valid(self, auth: WebAuthenticator) -> None:
        result = auth.validate_input(
            {
                "login_url": "http://target.local/login",
                "username": "admin",
                "password": "password",
            }
        )
        assert result["login_url"] == "http://target.local/login"
        assert result["username"] == "admin"
        assert result["password"] == "password"

    def test_validate_input_missing_url(self, auth: WebAuthenticator) -> None:
        with pytest.raises(ValueError, match="login_url"):
            auth.validate_input({"username": "admin", "password": "pass"})

    def test_validate_input_invalid_url(self, auth: WebAuthenticator) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            auth.validate_input(
                {
                    "login_url": "not-a-url",
                    "username": "admin",
                    "password": "pass",
                }
            )

    def test_validate_input_out_of_scope(self, auth: WebAuthenticator) -> None:
        with pytest.raises(ValueError, match="outside"):
            auth.validate_input(
                {
                    "login_url": "http://evil.com/login",
                    "username": "admin",
                    "password": "pass",
                }
            )

    def test_parse_output_success(self, auth: WebAuthenticator) -> None:
        raw = json.dumps(
            {
                "success": True,
                "session_cookies": {"PHPSESSID": "abc123"},
                "redirect_url": "http://target.local/index.php",
                "login_url": "http://target.local/login.php",
                "username": "admin",
                "status_code": 200,
            }
        )
        parsed = auth.parse_output(raw)
        assert isinstance(parsed, AuthOutput)
        assert parsed.success is True
        assert parsed.auth_result.session_cookies == {"PHPSESSID": "abc123"}

    def test_parse_output_failure(self, auth: WebAuthenticator) -> None:
        raw = json.dumps(
            {
                "success": False,
                "session_cookies": {},
                "error": "Invalid credentials",
            }
        )
        parsed = auth.parse_output(raw)
        assert parsed.auth_result.success is False

    def test_parse_output_empty(self, auth: WebAuthenticator) -> None:
        parsed = auth.parse_output("")
        assert parsed.success is False
        assert "Empty" in parsed.error

    def test_parse_output_bad_json(self, auth: WebAuthenticator) -> None:
        parsed = auth.parse_output("not json")
        assert parsed.success is False
        assert "JSON" in parsed.error


# ---------------------------------------------------------------------------
# Execution-mode routing
# ---------------------------------------------------------------------------


class TestExecutionModeRouting:
    """WebAuthenticator routes via curl in docker mode, aiohttp otherwise.

    Mirrors HTTPClientTool's single-flag gate. The previous hostname
    whitelist excluded container aliases (e.g. ``clinkz-dvwa``) produced
    by target_resolver, which silently broke default-cred testing in the
    full /run-dvwa pipeline.
    """

    @pytest.fixture()
    def auth(self) -> WebAuthenticator:
        scope = EngagementScope(
            name="test",
            targets=[
                ScopeEntry(type=ScopeType.DOMAIN, value="clinkz-dvwa"),
                ScopeEntry(type=ScopeType.DOMAIN, value="localhost"),
            ],
        )
        return WebAuthenticator(scope=scope, engagement_id="test-engagement")

    @pytest.mark.asyncio
    async def test_docker_mode_uses_curl_for_container_alias(
        self,
        auth: WebAuthenticator,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        called = {"curl": False, "aiohttp": False}

        async def fake_curl(args: dict[str, Any]) -> str:
            called["curl"] = True
            return "{}"

        async def fake_aiohttp(args: dict[str, Any]) -> str:
            called["aiohttp"] = True
            return "{}"

        monkeypatch.setattr(auth, "_execute_curl", fake_curl)
        monkeypatch.setattr(auth, "_execute_aiohttp", fake_aiohttp)

        await auth.execute(
            {
                "login_url": "http://clinkz-dvwa:80/login.php",
                "username": "admin",
                "password": "password",
            }
        )
        assert called["curl"] is True
        assert called["aiohttp"] is False

    @pytest.mark.asyncio
    async def test_local_mode_uses_aiohttp(
        self,
        auth: WebAuthenticator,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "local")
        called = {"curl": False, "aiohttp": False}

        async def fake_curl(args: dict[str, Any]) -> str:
            called["curl"] = True
            return "{}"

        async def fake_aiohttp(args: dict[str, Any]) -> str:
            called["aiohttp"] = True
            return "{}"

        monkeypatch.setattr(auth, "_execute_curl", fake_curl)
        monkeypatch.setattr(auth, "_execute_aiohttp", fake_aiohttp)

        await auth.execute(
            {
                "login_url": "http://localhost:8080/login.php",
                "username": "admin",
                "password": "password",
            }
        )
        assert called["aiohttp"] is True
        assert called["curl"] is False


# ---------------------------------------------------------------------------
# JSON / API (JWT bearer) authentication
# ---------------------------------------------------------------------------


class TestTokenExtraction:
    """``_extract_token`` pulls a token from common JSON login-response shapes."""

    def test_juice_shop_shape(self) -> None:
        body = json.dumps({"authentication": {"token": "JWT123", "umail": "a@b.c"}})
        assert WebAuthenticator._extract_token(body) == "JWT123"

    def test_flat_token(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps({"token": "abc"})) == "abc"

    def test_access_token(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps({"access_token": "xyz"})) == "xyz"

    def test_nested_data_token(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps({"data": {"token": "ddd"}})) == "ddd"

    def test_absent_token(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps({"foo": "bar"})) == ""

    def test_empty_token_ignored(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps({"token": "   "})) == ""

    def test_non_json_body(self) -> None:
        assert WebAuthenticator._extract_token("<html>not json</html>") == ""

    def test_non_object_json(self) -> None:
        assert WebAuthenticator._extract_token(json.dumps(["a", "b"])) == ""


class TestJsonApiAuth:
    """``authenticate()`` falls back to JSON/API auth when the form flow fails."""

    @pytest.fixture()
    def auth(self, monkeypatch: pytest.MonkeyPatch) -> WebAuthenticator:
        scope = EngagementScope(
            name="test",
            targets=[ScopeEntry(type=ScopeType.DOMAIN, value="localhost")],
        )
        authenticator = WebAuthenticator(scope=scope, engagement_id="test-engagement")

        # The encoding-order probe reads the login page over HTTP, and there is
        # no server here. Stub it to the verdict a target with nothing
        # observable about it produces — form first, which is the order every
        # assertion below was written against.
        async def form_first(login_url: str, **_kw: Any) -> _EncodingOrder:
            return _EncodingOrder(("form", "json"), "stubbed for the unit test")

        monkeypatch.setattr(authenticator, "_encoding_order", form_first)
        return authenticator

    @staticmethod
    def _form_failure(args: dict[str, Any]) -> str:
        return json.dumps(
            {
                "success": False,
                "session_cookies": {},
                "login_url": args.get("login_url", ""),
                "username": args.get("username", ""),
                "status_code": 200,
            }
        )

    @pytest.mark.asyncio
    async def test_falls_back_to_api_on_form_failure(
        self, auth: WebAuthenticator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Form auth fails → JSON auth against /rest/user/login returns a JWT."""

        async def fake_execute(args: dict[str, Any]) -> str:
            return self._form_failure(args)

        calls: list[tuple[str, dict[str, str]]] = []

        async def fake_api_post(
            url: str, payload: dict[str, str]
        ) -> tuple[int, str, dict[str, str]]:
            calls.append((url, payload))
            if url.endswith("/rest/user/login"):
                return 200, json.dumps({"authentication": {"token": "JWT-OK"}}), {}
            return 404, "", {}

        monkeypatch.setattr(auth, "execute", fake_execute)
        monkeypatch.setattr(auth, "_api_post_json", fake_api_post)

        result = await auth.authenticate("http://localhost:3000/", "admin@juice-sh.op", "admin123")

        assert result.success is True
        assert result.bearer_token == "JWT-OK"
        assert result.session_cookies == {}
        # The Juice Shop route was actually exercised, against the right origin.
        assert any(u == "http://localhost:3000/rest/user/login" for u, _ in calls)
        # Email identifier → only the email-keyed body is sent.
        assert all("email" in p for _, p in calls)

    @pytest.mark.asyncio
    async def test_form_success_skips_api(
        self, auth: WebAuthenticator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DVWA no-regression: a successful form login never triggers API auth."""

        async def fake_execute(args: dict[str, Any]) -> str:
            return json.dumps(
                {
                    "success": True,
                    "session_cookies": {"PHPSESSID": "abc"},
                    "login_url": args.get("login_url", ""),
                    "username": args.get("username", ""),
                    "status_code": 200,
                }
            )

        api_called = {"v": False}

        async def fake_api_post(
            url: str, payload: dict[str, str]
        ) -> tuple[int, str, dict[str, str]]:
            api_called["v"] = True
            return 200, json.dumps({"token": "should-not-be-used"}), {}

        monkeypatch.setattr(auth, "execute", fake_execute)
        monkeypatch.setattr(auth, "_api_post_json", fake_api_post)

        result = await auth.authenticate("http://localhost:8080/login.php", "admin", "password")

        assert result.success is True
        assert result.session_cookies == {"PHPSESSID": "abc"}
        assert result.bearer_token == ""
        assert api_called["v"] is False

    @pytest.mark.asyncio
    async def test_username_body_tried_for_non_email(
        self, auth: WebAuthenticator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-email identifier also gets a username-keyed body shape."""
        seen: list[dict[str, str]] = []

        async def fake_api_post(
            url: str, payload: dict[str, str]
        ) -> tuple[int, str, dict[str, str]]:
            seen.append(payload)
            if "username" in payload:
                return 200, json.dumps({"token": "T"}), {}
            return 401, "", {}

        monkeypatch.setattr(auth, "execute", self._form_failure_async())
        monkeypatch.setattr(auth, "_api_post_json", fake_api_post)

        result = await auth.authenticate("http://localhost:3000/", "admin", "pass")

        assert result.success is True
        assert result.bearer_token == "T"
        assert any("username" in p for p in seen)

    @pytest.mark.asyncio
    async def test_returns_form_failure_when_both_fail(
        self, auth: WebAuthenticator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both paths fail → the (richer) form-auth failure is surfaced."""

        async def fake_execute(args: dict[str, Any]) -> str:
            return self._form_failure(args)

        async def fake_api_post(
            url: str, payload: dict[str, str]
        ) -> tuple[int, str, dict[str, str]]:
            return 404, "", {}

        monkeypatch.setattr(auth, "execute", fake_execute)
        monkeypatch.setattr(auth, "_api_post_json", fake_api_post)

        result = await auth.authenticate("http://localhost:3000/", "admin", "pass")

        assert result.success is False
        assert result.bearer_token == ""

    def _form_failure_async(self) -> Any:
        async def _inner(args: dict[str, Any]) -> str:
            return self._form_failure(args)

        return _inner


# ---------------------------------------------------------------------------
# A 415 is not a success, and a success carries a session
# ---------------------------------------------------------------------------


class TestSuccessRequiresPositiveEvidence:
    """The defect that made a **415** a proven session.

    ``_check_login_success`` returned True because ``final_url`` differed from
    ``login_url``: a form whose ``action`` points at another path satisfies
    "redirected away → success" with no redirect having occurred at all. The
    server had answered 415 — the clearest possible statement that it accepted
    nothing — and the engine recorded an authenticated session, then handed
    ``cookies={}`` to an assertion three layers away.
    """

    def test_415_at_a_different_path_is_not_success(self) -> None:
        """The defect verbatim, with Meridian's own URLs."""
        assert not WebAuthenticator._check_login_success(
            response_body=json.dumps(
                {"status": "error", "expects": {"content_type": "application/json"}}
            ),
            status_code=415,
            final_url="http://target/portal/v3/session-open",
            login_url="http://target/portal/gateway",
            redirect_chain=[],
            session_evidence={},
        )

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 415, 422, 500, 503])
    def test_no_4xx_or_5xx_is_ever_success(self, status: int) -> None:
        """Not even one carrying every success keyword and a cookie."""
        assert not WebAuthenticator._check_login_success(
            response_body="<html>Welcome to your dashboard — logout</html>",
            status_code=status,
            final_url="http://target/dashboard",
            login_url="http://target/login",
            redirect_chain=["http://target/dashboard"],
            session_evidence={"SESSION": "abc"},
        )

    def test_a_different_final_path_alone_is_not_a_redirect(self) -> None:
        """An empty redirect chain means no redirect happened. Nothing else."""
        assert not WebAuthenticator._check_login_success(
            response_body="<html>ok</html>",
            status_code=200,
            final_url="http://target/somewhere/else",
            login_url="http://target/login",
            redirect_chain=[],
            session_evidence={},
        )

    def test_a_session_cookie_is_positive_evidence(self) -> None:
        assert WebAuthenticator._check_login_success(
            response_body=json.dumps({"status": "ok"}),
            status_code=200,
            final_url="http://target/portal/v3/session-open",
            login_url="http://target/portal/gateway",
            redirect_chain=[],
            session_evidence={"meridian_portal": "abc"},
        )

    def test_a_body_token_is_positive_evidence(self) -> None:
        assert WebAuthenticator._check_login_success(
            response_body=json.dumps({"authentication": {"token": "JWT"}}),
            status_code=200,
            final_url="http://target/rest/user/login",
            login_url="http://target/login",
            redirect_chain=[],
            session_evidence={},
        )

    def test_a_real_redirect_away_from_login_is_positive_evidence(self) -> None:
        """DVWA's shape, unchanged: the chain is non-empty because it redirected."""
        assert WebAuthenticator._check_login_success(
            response_body="",
            status_code=200,
            final_url="http://target/index.php",
            login_url="http://target/login.php",
            redirect_chain=["http://target/index.php"],
            session_evidence={},
        )


class TestNegotiatingA415:
    """A 415 states the media type it wanted, and the engine now reads it."""

    def test_the_body_names_the_content_type(self) -> None:
        assert (
            WebAuthenticator._negotiated_content_type(
                415,
                {},
                json.dumps({"expects": {"content_type": "application/json"}}),
            )
            == "application/json"
        )

    def test_the_accept_post_header_names_it(self) -> None:
        assert (
            WebAuthenticator._negotiated_content_type(
                415, {"Accept-Post": "application/json; charset=utf-8"}, ""
            )
            == "application/json"
        )

    def test_a_type_we_cannot_encode_is_not_retried(self) -> None:
        """Reported, not guessed at. We cannot produce it, and say so."""
        assert (
            WebAuthenticator._negotiated_content_type(415, {"Accept-Post": "application/xml"}, "")
            == ""
        )

    @pytest.mark.parametrize("status", [200, 400, 401, 422, 500])
    def test_only_a_415_negotiates(self, status: int) -> None:
        """No other status carries this instruction; reading one into them
        would be parsing prose the target controls."""
        assert (
            WebAuthenticator._negotiated_content_type(
                status, {"Accept-Post": "application/json"}, ""
            )
            == ""
        )

    def test_prose_is_never_parsed(self) -> None:
        """A body that merely mentions a type states nothing machine-readable."""
        assert (
            WebAuthenticator._negotiated_content_type(
                415, {}, "please send application/json next time"
            )
            == ""
        )


class TestASuccessMustCarryASession:
    """A success holding neither cookie nor token contradicts itself."""

    def test_the_contradiction_is_refused_at_the_seam(self) -> None:
        scope = EngagementScope(
            name="test", targets=[ScopeEntry(type=ScopeType.DOMAIN, value="target")]
        )
        auth = WebAuthenticator(scope=scope)
        claimed = AuthResult(
            success=True,
            status_code=415,
            login_url="http://target/portal/gateway",
            posted_to="http://target/portal/v3/session-open",
        )
        refused = auth._require_session_material(claimed)
        assert refused.success is False
        assert "no session material" in refused.error
        # The reason names the URL the credentials actually went to, which is
        # not the login URL whenever a form action redirected them.
        assert "session-open" in refused.failure_stage

    def test_a_genuine_session_passes_through_unchanged(self) -> None:
        scope = EngagementScope(
            name="test", targets=[ScopeEntry(type=ScopeType.DOMAIN, value="target")]
        )
        auth = WebAuthenticator(scope=scope)
        real = AuthResult(success=True, session_cookies={"SESSION": "x"}, status_code=200)
        assert auth._require_session_material(real) is real
