"""Meridian Portal — the third auth shape, wired into the suite as a fixture.

DVWA is form + cookie. Juice Shop is JSON + bearer. Both the authenticator and
the authenticated-state assertion were built against exactly those two, and
every defect this module pins was invisible until a target combined them
differently:

* a JSON login route reached only through an HTML form's ``action``,
* an identity field called ``account``,
* a session **cookie** on a **JSON** response, with no token anywhere,
* protected routes that deny anonymously with **302 to the login page** rather
  than 401/403 — the commonest shape in production and the one a status-class
  oracle cannot see,
* a login page at ``/portal/gateway``, which no list of login path names
  contains.

The load-bearing test here is
:func:`test_the_login_page_spelling_does_not_change_the_verdict`. Meridian runs
the same application at ``/portal/gateway`` and at ``/login``; the ONLY
difference is the name. Anything less than an equality assertion between the two
verdicts re-admits a name-based oracle, because a name oracle passes every test
that only ever spells the login page the way it expects.

The server is standard library only and binds an ephemeral port in a thread, so
this runs anywhere pytest does — no container, no network beyond loopback.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from clinkz.engagement.auth_state import (
    AuthAssertion,
    ProbeResponse,
    _return_parameter_naming,
    assert_authenticated,
)
from clinkz.models.engagement import RoleCredential
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.auth import WebAuthenticator

#: Loopback only. Meridian is a test target, not a fixture that reaches out.
_HOST = "127.0.0.1"

#: Credentials Meridian ships with. ``acct-4417`` is the lower-privileged one.
_ACCOUNT = "acct-4417"
_PASSWORD = "s3cure-passphrase"  # noqa: S105 — a test target's published credential

#: The two spellings of the same login page. The whole point of the file.
_GATEWAY_SPELLING = "/portal/gateway"
_LOGIN_SPELLING = "/login"


def _load_meridian() -> Any:
    """Import ``docker/meridian/app.py`` by path.

    It is a target, not a package, and it deliberately has no ``__init__.py``:
    it must run as a bare script inside its container. Loading it by path is how
    the fixture uses the SAME file the container does, rather than a copy that
    can drift from it.
    """
    root = Path(__file__).resolve().parents[2]
    app_path = root / "docker" / "meridian" / "app.py"
    if not app_path.is_file():  # pragma: no cover — the tree is checked in
        pytest.skip(f"Meridian target not present at {app_path}")
    spec = importlib.util.spec_from_file_location("clinkz_test_meridian", app_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def meridian() -> Iterator[tuple[str, Any]]:
    """A running Meridian on an ephemeral port. Yields ``(base_url, module)``."""
    module = _load_meridian()
    os.environ.setdefault("MERIDIAN_ACCESS_LOG", "0")
    server: ThreadingHTTPServer = module.build_server(0, _HOST)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{_HOST}:{server.server_address[1]}", module
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def login_path(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Serve the login page at the requested spelling.

    ``MERIDIAN_LOGIN_PATH`` is read per request by the target, so a spelling
    change needs no restart — which is what lets one test compare both.
    """
    spelling = getattr(request, "param", _GATEWAY_SPELLING)
    monkeypatch.setenv("MERIDIAN_LOGIN_PATH", spelling)
    return spelling


@pytest.fixture()
def scope() -> EngagementScope:
    return EngagementScope(name="meridian", targets=[ScopeEntry(type=ScopeType.IP, value=_HOST)])


@pytest.fixture(autouse=True)
def local_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the in-process HTTP path; there is no tools container here."""
    from clinkz.config import settings

    monkeypatch.setattr(settings, "tool_exec_mode", "local")


class _Probe:
    """A minimal :class:`~clinkz.engagement.auth_state.HttpProbe` over aiohttp.

    Deliberately not the orchestrator's ``_ToolHttpProbe``: that one needs an
    engagement, a governor and a state store, and none of them is what these
    tests are about. What it MUST reproduce faithfully is the one property the
    assertion depends on — ``follow_redirects=False``, and an anonymous control
    that carries nothing.
    """

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bool]] = []

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> ProbeResponse:
        import aiohttp

        self.requests.append(("GET", url, bool(cookies or headers)))
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ) as session:
                async with session.get(
                    url,
                    headers=headers or {},
                    cookies=cookies or {},
                    allow_redirects=follow_redirects,
                ) as resp:
                    return ProbeResponse(
                        status=resp.status,
                        headers={k: v for k, v in resp.headers.items()},
                        body=await resp.text(errors="replace"),
                    )
        except Exception as exc:  # pragma: no cover — loopback
            return ProbeResponse(error=str(exc))

    async def post_json(self, url: str, payload: dict[str, str]) -> ProbeResponse:
        import aiohttp

        self.requests.append(("POST", url, False))
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload, allow_redirects=False) as resp:
                    return ProbeResponse(
                        status=resp.status,
                        headers={k: v for k, v in resp.headers.items()},
                        body=await resp.text(errors="replace"),
                    )
        except Exception as exc:  # pragma: no cover — loopback
            return ProbeResponse(error=str(exc))


async def _login_and_assert(
    base_url: str, spelling: str, scope: EngagementScope
) -> tuple[Any, AuthAssertion]:
    """Log in at *spelling* and prove the session, exactly as the engine does."""
    authenticator = WebAuthenticator(scope=scope, engagement_id="")
    result = await authenticator.authenticate(f"{base_url}{spelling}", _ACCOUNT, _PASSWORD)
    if not result.success:
        return result, AuthAssertion(established=False, why_unproven="login failed")

    headers = {"Authorization": f"Bearer {result.bearer_token}"} if result.bearer_token else {}
    assertion = await assert_authenticated(
        _Probe(),
        [f"{base_url}/api/orders", f"{base_url}/dashboard", f"{base_url}/account"],
        cookies=result.session_cookies,
        headers=headers,
        username=_ACCOUNT,
    )
    return result, assertion


# ---------------------------------------------------------------------------
# Part 6 — the equality that is the test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_login_page_spelling_does_not_change_the_verdict(
    meridian: tuple[str, Any], scope: EngagementScope, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same application at two paths must reach the same verdict.

    This is the regression for the whole class. Before it, ``/login`` proved a
    session in one request and ``/portal/gateway`` could not prove one at all —
    the redirect discriminator matched seven substrings, and the destination's
    NAME was the gate. Nothing about the application differed.

    Both halves are asserted: the session is established either way, and it is
    established by the SAME discriminator. Equality on ``established`` alone
    would pass if one spelling proved the session by a lucky body marker while
    the redirect boundary stayed blind.
    """
    base_url, _module = meridian
    verdicts: dict[str, tuple[bool, str, int, int]] = {}

    for spelling in (_GATEWAY_SPELLING, _LOGIN_SPELLING):
        monkeypatch.setenv("MERIDIAN_LOGIN_PATH", spelling)
        result, assertion = await _login_and_assert(base_url, spelling, scope)
        assert result.success, f"login failed at {spelling}: {result.error}"
        verdicts[spelling] = (
            assertion.established,
            assertion.discriminator,
            assertion.authenticated_status,
            assertion.anonymous_status,
        )

    gateway = verdicts[_GATEWAY_SPELLING]
    login = verdicts[_LOGIN_SPELLING]
    assert gateway[0] is True, f"the /portal/gateway spelling proved nothing: {gateway}"
    assert gateway == login, (
        "the login page's NAME changed the verdict — "
        f"{_GATEWAY_SPELLING} -> {gateway}, {_LOGIN_SPELLING} -> {login}. "
        "That is a name oracle, whatever else it gets right."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("login_path", [_GATEWAY_SPELLING, _LOGIN_SPELLING], indirect=True)
async def test_the_redirect_boundary_is_proven_under_either_spelling(
    meridian: tuple[str, Any], scope: EngagementScope, login_path: str
) -> None:
    """A 302 to the login page is the boundary, whatever the page is called."""
    base_url, _module = meridian
    _result, assertion = await _login_and_assert(base_url, login_path, scope)
    assert assertion.established is True
    assert assertion.discriminator == "login_redirect"
    assert assertion.anonymous_status == 302
    assert 200 <= assertion.authenticated_status < 300


# ---------------------------------------------------------------------------
# Part 1 — 415 is not success, and the 415 is USED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("login_path", [_GATEWAY_SPELLING], indirect=True)
async def test_the_415_is_read_as_a_content_type_negotiation(
    meridian: tuple[str, Any], scope: EngagementScope, login_path: str
) -> None:
    """The form POST is refused with 415; the retry under the named type wins.

    Meridian's login page is a real HTML form whose ``action`` is a JSON-only
    API. Posting it form-encoded earns a 415 that names
    ``application/json`` — the application stating its own contract. The field
    names come from the form's HTML and the encoding from the server's answer,
    so neither half of the successful request was guessed.
    """
    base_url, _module = meridian
    authenticator = WebAuthenticator(scope=scope, engagement_id="")
    result = await authenticator.authenticate(f"{base_url}{login_path}", _ACCOUNT, _PASSWORD)

    assert result.success is True
    assert result.status_code == 200, "the 415 should have been renegotiated, not accepted"
    assert result.negotiated_content_type == "application/json"
    assert result.session_cookies, "a JSON login whose session is a cookie must yield it"
    assert "meridian_portal" in result.session_cookies
    # The credentials went to the form's ACTION, which is not the login page.
    assert result.posted_to.endswith("/portal/v3/session-open")


@pytest.mark.asyncio
@pytest.mark.parametrize("login_path", [_GATEWAY_SPELLING], indirect=True)
async def test_wrong_credentials_do_not_authenticate(
    meridian: tuple[str, Any], scope: EngagementScope, login_path: str
) -> None:
    """The negotiation must not turn a refusal into a session."""
    base_url, _module = meridian
    authenticator = WebAuthenticator(scope=scope, engagement_id="")
    result = await authenticator.authenticate(
        f"{base_url}{login_path}", _ACCOUNT, "not-the-password"
    )
    assert result.success is False
    assert result.status_code == 401
    assert not result.session_cookies


@pytest.mark.asyncio
@pytest.mark.parametrize("login_path", [_GATEWAY_SPELLING], indirect=True)
async def test_a_public_path_yields_no_discriminator(
    meridian: tuple[str, Any], scope: EngagementScope, login_path: str
) -> None:
    """Meridian's two public paths are byte-identical either way.

    A discriminator that fires here is firing on page chrome. The assertion must
    report ``established=False`` rather than prove a session from a page anyone
    can read — this is the control on the control.
    """
    base_url, _module = meridian
    authenticator = WebAuthenticator(scope=scope, engagement_id="")
    result = await authenticator.authenticate(f"{base_url}{login_path}", _ACCOUNT, _PASSWORD)
    assert result.success is True

    assertion = await assert_authenticated(
        _Probe(),
        [f"{base_url}/", f"{base_url}/pricing"],
        cookies=result.session_cookies,
        username=_ACCOUNT,
    )
    assert assertion.established is False
    assert assertion.attempted, "the comparison must be reported even when it found nothing"


# ---------------------------------------------------------------------------
# Part 4 — the declarations reach the authenticator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("login_path", [_GATEWAY_SPELLING], indirect=True)
async def test_declarations_override_discovery(
    meridian: tuple[str, Any], scope: EngagementScope, login_path: str, module_free: None = None
) -> None:
    """An operator naming the JSON route, field and content type is obeyed.

    The JSON arm used to take the login URL, keep only its origin, and iterate
    six canned routes — so the one thing the operator actually knew was the one
    thing the engine discarded. Here the login PAGE is never fetched: the
    declared route, field and content type are enough on their own.
    """
    base_url, module = meridian
    cred = RoleCredential(
        role="operator",
        username=_ACCOUNT,
        password=_PASSWORD,
        login_url=f"{base_url}{login_path}",
        login_api_url=f"{base_url}{module.LOGIN_API_PATH}",
        login_field=module.IDENTITY_FIELD,
        login_content_type="application/json",
    )
    assert cred.login_field == "account"

    authenticator = WebAuthenticator(scope=scope, engagement_id="")
    result = await authenticator._try_api_login(
        cred.login_url,
        cred.username,
        cred.secret(),
        api_login_url=cred.login_api_url,
        identity_field=cred.login_field,
    )
    assert result.success is True
    assert result.posted_to == cred.login_api_url
    assert result.auth_body_fields == [module.IDENTITY_FIELD, "password"]
    assert "meridian_portal" in result.session_cookies


# ---------------------------------------------------------------------------
# The return-parameter corroboration, on Meridian's own redirect
# ---------------------------------------------------------------------------


def test_the_return_parameter_is_read_by_value_not_by_name() -> None:
    """``?next=%2Fapi%2Forders`` names the path we asked for, whatever it is called.

    The parameter's own name is deliberately not consulted: ``next``,
    ``return_to``, ``r`` and ``ReturnUrl`` are the same idea, and matching on the
    VALUE reads the application instead of a list we would have to maintain —
    which is the defect this whole change exists to remove.
    """
    for parameter in ("next", "ReturnUrl", "r", "come_back_to"):
        location = f"/portal/gateway?{parameter}=%2Fapi%2Forders"
        assert _return_parameter_naming(location, "http://target/api/orders") == parameter

    # A parameter naming something else is not a return parameter.
    assert _return_parameter_naming("/portal/gateway?next=%2Fhome", "http://t/api/orders") == ""
    # No query at all.
    assert _return_parameter_naming("/portal/gateway", "http://t/api/orders") == ""


def test_meridian_is_reachable_as_a_module() -> None:
    """The fixture loads the same file the container runs, not a copy."""
    module = _load_meridian()
    assert module.IDENTITY_FIELD == "account"
    assert module.LOGIN_API_PATH == "/portal/v3/session-open"
    assert module.SESSION_COOKIE == "meridian_portal"
    assert asyncio is not None  # the module is importable without a running loop
