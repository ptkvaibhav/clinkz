"""The curl (docker) path parses the bytes curl actually writes.

The two execution modes must reach the same verdict about the same target: an
application that authenticates under ``TOOL_EXEC_MODE=local`` and not under
``docker`` is a defect the mode hides rather than a property of the application.
The curl path's 415 renegotiation is therefore the same rule as the aiohttp
path's, and it stands on :meth:`WebAuthenticator._parse_curl_exchange`, which is
what these fixtures exercise.

Every fixture in ``tests/fixtures/auth/`` was captured from a real
``curl -s -S -D - -X POST -L`` against a running Meridian — the bytes curl
writes, not a plausible transcript of them. Two volatile values are pinned so
the files are reproducible: the ``Date`` headers, and the ephemeral session id
in the 200 response (a local throwaway server's token for a published test
credential, replaced by a fixed 32-hex constant of the same shape).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.tools.auth import WebAuthenticator

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "auth"


def _fixture(name: str) -> str:
    path = FIXTURES / name
    assert path.is_file(), f"missing curl fixture: {path}"
    return path.read_text(encoding="utf-8")


class TestParsingWhatCurlWrites:
    def test_a_single_block_yields_status_body_and_headers(self) -> None:
        status, body, headers = WebAuthenticator._parse_curl_exchange(
            _fixture("meridian_login_415_curl.txt")
        )
        assert status == 415
        assert headers["Content-Type"] == "application/json"
        assert '"content_type": "application/json"' in body

    def test_the_415_body_names_the_encoding_through_the_real_bytes(self) -> None:
        """End to end over the fixture: bytes -> parse -> negotiated type."""
        status, body, headers = WebAuthenticator._parse_curl_exchange(
            _fixture("meridian_login_415_curl.txt")
        )
        assert (
            WebAuthenticator._negotiated_content_type(status, headers, body) == "application/json"
        )

    def test_the_415_is_not_read_as_a_successful_login(self) -> None:
        """The defect, over the real bytes and at the real form-action URL."""
        status, body, _headers = WebAuthenticator._parse_curl_exchange(
            _fixture("meridian_login_415_curl.txt")
        )
        assert not WebAuthenticator._check_login_success(
            response_body=body,
            status_code=status,
            final_url="http://target/portal/v3/session-open",
            login_url="http://target/portal/gateway",
            redirect_chain=[],
            session_cookies={},
        )

    def test_the_200_yields_the_session_cookie_and_a_success(self) -> None:
        raw = _fixture("meridian_login_200_curl.txt")
        status, body, _headers = WebAuthenticator._parse_curl_exchange(raw)
        cookies = WebAuthenticator._parse_set_cookies(raw)
        assert status == 200
        assert "meridian_portal" in cookies
        assert WebAuthenticator._check_login_success(
            response_body=body,
            status_code=status,
            final_url="http://target/portal/v3/session-open",
            login_url="http://target/portal/gateway",
            redirect_chain=[],
            session_cookies=cookies,
        )

    def test_a_multi_block_dump_reports_the_block_that_answered(self) -> None:
        """Several blocks in one dump; the answer is the last one.

        A fixture captured under ``-L``, or — now that no credential exchange
        uses ``-L`` — the per-hop dumps the authenticator joins. Reading the
        FIRST block's status here would report 302 for a request that ended at
        200, and reading the last block's headers is what makes ``Accept-Post``
        on a 415 findable at all.

        The ``Location`` values in this dump are deliberately NOT read back as a
        redirect chain. They are raw header text — ``/portal/gateway?next=…``,
        unresolved — and that was the curl arm's ``redirect_chain`` while the
        aiohttp arm filled the same field with absolute URLs. One field, two
        meanings, read by the success oracle.
        """
        status, body, headers = WebAuthenticator._parse_curl_exchange(
            _fixture("meridian_redirect_chain_curl.txt")
        )
        assert status == 200, "the final block answered, not the 302 that led to it"
        assert headers["Content-Type"].startswith("text/html")
        assert "<input type=password" in body

    @pytest.mark.parametrize("raw", ["", "   ", "not an http response at all"])
    def test_unparseable_output_is_data_not_a_crash(self, raw: str) -> None:
        status, body, headers = WebAuthenticator._parse_curl_exchange(raw)
        assert status == 0
        assert body == ""
        assert headers == {}


class TestTheFormActionIsScopeChecked:
    """The credential POST goes where the TARGET said, so scope must gate it.

    ``validate_input`` scope-checks the login URL. It cannot check the form's
    ``action``: that is an attribute of a page the target served, read after the
    check, and the POST that follows carries the engagement's plaintext
    credentials over aiohttp/curl directly rather than through the
    scope-enforcing HTTP client. A page serving
    ``<form action="https://attacker.tld/collect">`` received them.

    The 415 renegotiation makes it worse rather than better: an attacker
    endpoint answering 415 with a named media type earns a SECOND copy of the
    credentials in a different encoding.
    """

    @staticmethod
    def _authenticator() -> WebAuthenticator:
        from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

        return WebAuthenticator(
            scope=EngagementScope(
                name="scoped",
                targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.example.com")],
            )
        )

    def test_an_absolute_off_scope_action_is_refused(self) -> None:
        auth = self._authenticator()
        with pytest.raises(ValueError, match="outside the engagement scope"):
            auth._resolve_post_url("http://app.example.com/login", "https://attacker.tld/collect")

    def test_an_absolute_in_scope_action_is_allowed(self) -> None:
        auth = self._authenticator()
        assert (
            auth._resolve_post_url("http://app.example.com/login", "http://app.example.com/session")
            == "http://app.example.com/session"
        )

    @pytest.mark.parametrize(
        ("login_url", "action", "expected"),
        [
            # Meridian's shape: an absolute-path action on the same origin.
            (
                "http://app.example.com/portal/gateway",
                "/portal/v3/session-open",
                "http://app.example.com/portal/v3/session-open",
            ),
            # DVWA's shape: a relative action beside the login page.
            (
                "http://app.example.com/login.php",
                "login.php",
                "http://app.example.com/login.php",
            ),
            # No action at all — the POST goes back to the login page.
            ("http://app.example.com/login", "", "http://app.example.com/login"),
        ],
    )
    def test_a_relative_action_resolves_to_the_same_origin(
        self, login_url: str, action: str, expected: str
    ) -> None:
        """In scope by construction — it cannot leave the origin, so it is not
        re-checked and the existing targets keep working unchanged."""
        assert self._authenticator()._resolve_post_url(login_url, action) == expected
