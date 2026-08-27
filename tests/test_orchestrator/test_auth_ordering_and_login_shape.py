"""Two authentication defects a client would see in their own logs.

**D — a login URL is proven by SHAPE, never by a status code.** A single-page
application serves its shell for every path it does not recognise, so
``/login.php`` answers 200 with 9903 bytes of Angular on a Node target that has
never had a PHP file. The probe accepted any ``status < 400``, so it "found" a
login page there and six credential POSTs followed.

**E — the credential the client gave us goes first.** The default-credential
sweep ran unconditionally ahead of the supplied credential: 52 requests of
admin/admin, root/root, admin/password and test/test across six routes, landing
in the client's authentication logs as credential stuffing, from an authorized
test, before that test did the thing it was authorized to do.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.engagement import CredentialSet, RoleCredential
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent

SCOPE = EngagementScope(
    name="auth-ordering-test",
    targets=[ScopeEntry(value="http://app:3000", type=ScopeType.URL)],
)

#: What a framework target serves for EVERY unrecognised path. No form, no
#: password input — the whole application is rendered from the bundle.
SPA_SHELL = (
    "<!doctype html><html><head><title>App</title>"
    '<script src="/main-ABC123.js" type="module"></script></head>'
    "<body><app-root></app-root></body></html>"
)

#: A real server-rendered login page (DVWA's shape).
LOGIN_PAGE = (
    "<html><body><form action='login.php' method='post'>"
    "<input type='text' name='username'>"
    "<input type='password' AUTOCOMPLETE='off' name='password'>"
    "<input type='submit' value='Login'></form></body></html>"
)


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _orchestrator(credentials: CredentialSet | None = None) -> OrchestratorAgent:
    agent = OrchestratorAgent(llm=_SilentLLM(), credentials=credentials)
    agent._scope = SCOPE
    return agent


def _serve(bodies: dict[str, str]) -> Any:
    """Patch the login-shape probe's transport: path -> served body.

    Anything not named is served the SPA shell at 200, which is exactly what a
    catch-all does and is the condition under test.
    """

    async def _probe(self: OrchestratorAgent, url: str) -> bool:
        from urllib.parse import urlparse

        body = bodies.get(urlparse(url).path, SPA_SHELL)
        return OrchestratorAgent._login_shape_of(body)

    return _probe


# ---------------------------------------------------------------------------
# D — shape, not status
# ---------------------------------------------------------------------------


class TestLoginUrlIsProvenByShape:
    async def test_spa_catch_all_is_not_a_login_page(self, monkeypatch: Any) -> None:
        """The defect verbatim: 200 + a body, and still not a login surface."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _serve({}), raising=True)
        found = await agent._find_login_url({}, "")
        assert found is None, (
            f"a catch-all shell was accepted as a login page at {found} — "
            "this is the /login.php-on-a-Node-app defect"
        )

    async def test_a_real_login_page_is_still_found(self, monkeypatch: Any) -> None:
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(
            OrchestratorAgent,
            "_serves_a_login_form",
            _serve({"/login.php": LOGIN_PAGE}),
            raising=True,
        )
        found = await agent._find_login_url({}, "")
        assert found is not None and found.endswith("/login.php")

    async def test_no_login_surface_yields_none_not_the_root_url(self, monkeypatch: Any) -> None:
        """The removed sixth strategy. A root URL is not a login page; it is
        where a credential POST lands when nobody proved anything."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _serve({}), raising=True)
        assert await agent._find_login_url({}, "") is None

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            (SPA_SHELL, False),
            (LOGIN_PAGE, True),
            ("<html><input type='password' name='new'></html>", False),
            ("<html><form><input name='q' type='text'></form></html>", False),
            ("", False),
        ],
    )
    def test_shape_predicate(self, body: str, expected: bool) -> None:
        """A password field ALONE is a password-change form, not a login: the
        identity field beside it is what makes the pair."""
        assert OrchestratorAgent._login_shape_of(body) is expected


# ---------------------------------------------------------------------------
# E — supplied credentials first
# ---------------------------------------------------------------------------


class TestSuppliedCredentialsGoFirst:
    async def test_sweep_is_skipped_when_the_operator_supplied_a_credential(self) -> None:
        creds = CredentialSet(
            credentials=[RoleCredential(role="admin", username="a@example.com", password="pw")]
        )
        agent = _orchestrator(creds)
        agent._try_default_credentials = AsyncMock()  # type: ignore[method-assign]
        assert agent._should_sweep_default_credentials() is False

    async def test_sweep_runs_when_no_credential_was_supplied(self) -> None:
        agent = _orchestrator(CredentialSet())
        assert agent._should_sweep_default_credentials() is True

    def test_the_sweep_is_unreachable_after_a_supplied_credential_fails(self) -> None:
        """There is deliberately no "…or they failed" branch.

        Supplied-and-failed ABORTS (``AuthStateError`` out of
        ``_establish_authenticated_state``), because scanning an authenticated
        application anonymously produces an empty report that reads like a clean
        bill of health. So the sweep is not merely deferred past a failure, it is
        unreachable after one — which is the stricter reading, and the right one:
        falling back to guessing passwords the moment the client's own credential
        is rejected is the same log entry this change exists to remove.
        """
        import inspect

        source = inspect.getsource(OrchestratorAgent.run)
        # The CALL sites, not the prose about them — the comment explaining this
        # rule names ``_establish_authenticated_state`` several lines above the
        # sweep, and matching that would invert the assertion.
        sweep = source.index("await self._try_default_credentials(")
        establish = source.index("await self._establish_authenticated_state(")
        assert sweep < establish, "the sweep must be decided before authentication runs"
        assert "self._should_sweep_default_credentials()" in source
