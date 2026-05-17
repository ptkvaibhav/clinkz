"""Tests for WebAuthenticator — deterministic login with CSRF handling."""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import (
    AuthOutput,
    WebAuthenticator,
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
