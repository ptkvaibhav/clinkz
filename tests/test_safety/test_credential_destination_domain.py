"""Where a credential may GO — every destination-choosing site, computed and classified.

A credential is sent only to a destination something OBSERVED to be a login:

* a form the target RENDERED with a password input (its ``action``);
* a route the operator DECLARED (``login_url`` / ``login_api_url``);
* a route the adaptive layer PROVED (gated, then decided by
  ``assert_authenticated``).

There used to be two more. ``_establish_authenticated_state`` ended its default
with ``or base_url``, so the site root received the credential whenever nothing
was found; and both ``tools/auth.py`` and ``engagement/auth_state.py`` carried a
six-entry route list led by ``/rest/user/login`` — a benchmark constant in
production code. On the separate-origin IdP fixture (``docker/spa-keycloak``)
they spent five credential POSTs per account on destinations nothing had shown
to be a login: three to the root, two to Juice Shop's route.

The DOMAIN here is computed, twice:

1. **Call sites.** The credential senders are the GOVERNED/EXEMPT members of
   ``test_credential_sender_domain``'s two tables (themselves asserted equal to
   their computed domains). Every sender whose signature takes a URL chooses or
   receives a destination; every CALL to one, anywhere under ``src/clinkz``, is a
   site that hands it one. Homonyms are kept, not filtered: a ``_dispatch`` that
   is the LLM fallback's is classified as not a credential destination, in the
   table, with its reason, rather than silently skipped.
2. **Route literals.** Every non-docstring string constant spelling a
   login-shaped absolute path. None may live in a sender, and each that lives
   elsewhere states why it is not a credential destination.

The CLASSIFICATION is the hand-maintained half, and both directions are asserted.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.test_safety.test_credential_sender_domain import (
    DECLARED,
    DECLARED_CALL_SENDERS,
    _Sender,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"

URL_PARAM = re.compile(r"(^|_)url$")


class _Dest:
    """Where a site's credential destination comes from."""

    #: The action of a form the target rendered with a password input; an
    #: undeclared page that renders none receives nothing (``no_login_surface``).
    RENDERED_FORM = "rendered_form"
    #: A URL the operator declared on the role.
    DECLARED = "declared"
    #: A proposal the adaptive layer's gate admitted, decided by the assertion.
    ADAPTIVE_PROVEN = "adaptive_proven"
    #: Passes the destination its own caller chose, unchanged; the caller is
    #: itself a member of this domain and classified on its own row.
    INHERITS = "inherits"
    #: A homonym, or a request that carries no credential.
    NOT_A_CREDENTIAL_DESTINATION = "not_a_credential_destination"


#: ``"file::caller -> callee" -> (provenance, reason)``.
DECLARED_SITES: dict[str, tuple[str, str]] = {
    "agents/exploit.py::_run_brute_force_methodology -> _brute_force_phase2_observation": (
        _Dest.RENDERED_FORM,
        "phase 1 admits only a login-SHAPED form (identity plus password field) the "
        "crawl observed or a discovery source declared; a path that merely spells "
        "login no longer qualifies",
    ),
    "engagement/auth_agent.py::run -> post_credentials": (
        _Dest.ADAPTIVE_PROVEN,
        "the model proposes, eleven deterministic refusals gate the proposal including "
        "scope, and assert_authenticated decides whether the destination seated anything",
    ),
    "llm/fallback.py::generate_text -> _dispatch": (
        _Dest.NOT_A_CREDENTIAL_DESTINATION,
        "a homonym: the provider-routing dispatcher sends a prompt to an LLM API, never "
        "a credential to the target",
    ),
    "llm/fallback.py::reason -> _dispatch": (
        _Dest.NOT_A_CREDENTIAL_DESTINATION,
        "the same provider-routing homonym, reached from the reasoning entry point",
    ),
    "llm/fallback.py::research -> _dispatch": (
        _Dest.NOT_A_CREDENTIAL_DESTINATION,
        "the same provider-routing homonym, reached from the research entry point",
    ),
    "orchestrator/orchestrator.py::_attempt_login -> authenticate": (
        _Dest.RENDERED_FORM,
        "the sweep's URL comes from _find_login_url, which returns only a page whose "
        "served body is a password form, and the call declares nothing",
    ),
    "orchestrator/orchestrator.py::_authenticate_role -> _adaptive_auth": (
        _Dest.ADAPTIVE_PROVEN,
        "hands over the page that was READ; the adaptive layer chooses its own "
        "destinations, each gated and asserted",
    ),
    "orchestrator/orchestrator.py::_authenticate_role -> authenticate": (
        _Dest.DECLARED,
        "passes login_url_declared only when the role declared login_url; otherwise the "
        "page is the observed login or the root, and either receives a credential only "
        "if it renders a password form",
    ),
    "orchestrator/orchestrator.py::_establish_authenticated_state -> _verify_and_refresh_session": (
        _Dest.RENDERED_FORM,
        "the discovered or detected login URL, or the empty string; the conventional "
        "/login fallback that used to follow is gone",
    ),
    "orchestrator/orchestrator.py::_reauthenticate_under_lock -> authenticate": (
        _Dest.DECLARED,
        "re-sends the first login's declarations unchanged, so a re-login goes where "
        "the first one was allowed to go and nowhere else",
    ),
    "orchestrator/orchestrator.py::_try_default_credentials -> _attempt_login": (
        _Dest.RENDERED_FORM,
        "the sweep refuses to start without a login URL _find_login_url proved by the "
        "served password form",
    ),
    "orchestrator/orchestrator.py::_verify_and_refresh_session -> authenticate": (
        _Dest.RENDERED_FORM,
        "re-authenticates a swept credential only when a login URL was observed; an "
        "empty one leaves the expired session expired",
    ),
    "tools/auth.py::_dispatch -> _governed_request": (
        _Dest.INHERITS,
        "a redirect hop inside a credential exchange, walked only after its destination "
        "is scope-checked; the exchange's own destination is the arm's",
    ),
    "tools/auth.py::_execute_aiohttp -> _governed_request": (
        _Dest.RENDERED_FORM,
        "the aiohttp form arm POSTs only to the action of a form rendering a password "
        "input, or to a declared login_url",
    ),
    "tools/auth.py::_execute_curl -> _governed_request": (
        _Dest.RENDERED_FORM,
        "the curl form arm applies the same destination gate as the aiohttp arm, "
        "asserted below on both transports",
    ),
    "tools/auth.py::_get_login_page -> _governed_request": (
        _Dest.NOT_A_CREDENTIAL_DESTINATION,
        "the login-page GET carries no credential; it is the read that decides whether "
        "a form was rendered at all",
    ),
    "tools/auth.py::_post -> _governed_request": (
        _Dest.INHERITS,
        "the credential POST closure inside the form arms; it receives the post_url the "
        "arm resolved after the destination gate",
    ),
    "tools/auth.py::_try_api_login -> _api_post_json": (
        _Dest.DECLARED,
        "the JSON arm's routes are api_login_url and a DECLARED login_url, and nothing "
        "else; the canned route list is deleted",
    ),
    "tools/auth.py::authenticate -> _run_form_arm": (
        _Dest.INHERITS,
        "forwards login_url and login_url_declared unchanged to the form arm, whose gate decides",
    ),
    "tools/auth.py::authenticate -> _try_api_login": (
        _Dest.INHERITS,
        "forwards the declarations unchanged to the JSON arm, which posts to declared routes only",
    ),
    "tools/auth.py::execute -> _dispatch": (
        _Dest.INHERITS,
        "the tool's execute dispatches to the transport-specific form arm with the "
        "validated arguments, login_url_declared among them",
    ),
    "tools/http_client.py::execute -> _dispatch": (
        _Dest.INHERITS,
        "the HTTP client's chokepoint sends where its caller pointed it; the JSON arm "
        "and the adaptive dispatcher are the callers, each classified here",
    ),
}


#: ``"file::owner" -> reason`` for each holder of a login-shaped path literal.
#: Not one of them may be a credential destination.
DECLARED_ROUTE_LITERALS: dict[str, str] = {
    "agents/exploit.py::<module>": (
        "_LOGIN_PATH_HINTS and the JWKS paths order and select candidates for GET-only "
        "probes and planning; the brute-force class no longer qualifies a destination "
        "on a path name"
    ),
    "engagement/auth_state.py::<module>": (
        "_FORM_LOGIN_PATHS are GET-only detection probes; a path becomes a login URL only "
        "when its served body carries a password input"
    ),
    "orchestrator/orchestrator.py::_find_login_url": (
        "conventional paths and name hints ORDER the shape probing and never gate it; "
        "the shape test on the served body decides, and only a GET is sent"
    ),
    "tools/auth.py::_cookie_jar_path": (
        "a local cookie-jar file path inside the tools container that the pattern "
        "matches on the word auth; it is not a URL at all"
    ),
}


def _senders() -> set[str]:
    merged = {**DECLARED, **DECLARED_CALL_SENDERS}
    return {k for k, (c, _r) in merged.items() if c != _Sender.NO_DISPATCH}


def _trees() -> list[tuple[str, ast.Module]]:
    out = []
    for path in sorted(SRC.rglob("*.py")):
        out.append(
            (
                path.relative_to(SRC).as_posix(),
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path)),
            )
        )
    return out


def _destination_callees() -> set[str]:
    """Names of senders whose signature takes a URL — they receive a destination."""
    senders = _senders()
    names: set[str] = set()
    for rel, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if f"{rel}::{node.name}" not in senders:
                continue
            args = node.args
            params = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
            if any(URL_PARAM.search(p) for p in params):
                names.add(node.name)
    return names


def _site_domain() -> set[str]:
    callees = _destination_callees()
    sites: set[str] = set()
    for rel, tree in _trees():
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for sub in ast.walk(fn):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                name = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else ""
                )
                if name in callees:
                    sites.add(f"{rel}::{fn.name} -> {name}")
    return sites


LOGIN_PATH = re.compile(
    r"^/[\w./~-]*(login|signin|sign-in|sign_in|logon|auth|session)[\w./~-]*$", re.IGNORECASE
)


def _route_literal_domain() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for rel, tree in _trees():
        docstrings: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                body = node.body
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                ):
                    docstrings.add(id(body[0].value))
        owner: dict[int, str] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                for sub in ast.walk(fn):
                    owner.setdefault(id(sub), fn.name)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and LOGIN_PATH.match(node.value)
            ):
                found.setdefault(f"{rel}::{owner.get(id(node), '<module>')}", []).append(node.value)
    return found


# ---------------------------------------------------------------------------
# The two domains, both directions
# ---------------------------------------------------------------------------


def test_every_destination_site_is_classified() -> None:
    missing = _site_domain() - set(DECLARED_SITES)
    assert not missing, (
        "a site hands a credential sender a destination and nobody has said where it "
        f"comes from: {sorted(missing)}"
    )


def test_no_classification_outlived_its_site() -> None:
    stale = set(DECLARED_SITES) - _site_domain()
    assert not stale, f"classified sites that no longer exist: {sorted(stale)}"


@pytest.mark.parametrize("site", sorted(DECLARED_SITES))
def test_each_site_states_its_reason(site: str) -> None:
    provenance, reason = DECLARED_SITES[site]
    assert provenance in {v for k, v in vars(_Dest).items() if k.isupper()}
    assert len(reason.split()) >= 6, f"{site}: a classification needs its reason"


def test_the_site_domain_is_not_vacuous() -> None:
    """Positive control: the computed domain sees the sites this change rewrote."""
    domain = _site_domain()
    assert "orchestrator/orchestrator.py::_authenticate_role -> authenticate" in domain
    assert "tools/auth.py::_try_api_login -> _api_post_json" in domain
    assert "engagement/auth_agent.py::run -> post_credentials" in domain


def test_every_route_literal_holder_is_classified() -> None:
    domain = _route_literal_domain()
    assert set(domain) == set(DECLARED_ROUTE_LITERALS), (
        f"unclassified: {sorted(set(domain) - set(DECLARED_ROUTE_LITERALS))}; "
        f"stale: {sorted(set(DECLARED_ROUTE_LITERALS) - set(domain))}"
    )


def test_no_credential_sender_holds_a_route_literal() -> None:
    senders = _senders()
    holders = {k for k in _route_literal_domain() if k in senders}
    assert not holders, f"a credential sender spells a login route: {sorted(holders)}"


def test_the_benchmark_route_is_gone_from_production_code() -> None:
    """``/rest/user/login`` is Juice Shop's route. It has no place outside prose."""
    spelled = [
        f"{holder}: {value}"
        for holder, values in _route_literal_domain().items()
        for value in values
        if value == "/rest/user/login"
    ]
    assert not spelled


# ---------------------------------------------------------------------------
# Behaviour: the gate refuses, and the declaration licenses
# ---------------------------------------------------------------------------


# The form-arm half of the gate is held on BOTH transports by the scenarios
# ``undeclared_page_without_a_password_form_receives_nothing`` and
# ``declared_page_without_a_password_form_is_a_destination`` in
# ``tests/test_tools/test_auth_transport_equivalence.py``.

_SHELL = '<html><body><div id="root"></div><script src="/app.js"></script></body></html>'


@pytest.mark.asyncio
async def test_the_json_arm_posts_to_declared_routes_only(monkeypatch) -> None:
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.tools.auth import WebAuthenticator

    sent: list[str] = []

    async def _fake_post(self: Any, url: str, payload: dict[str, str], **_kw: Any):
        sent.append(url)
        return 404, "", []

    monkeypatch.setattr(WebAuthenticator, "_api_post_json", _fake_post)
    scope = EngagementScope(
        name="dest-gate", targets=[ScopeEntry(type=ScopeType.DOMAIN, value="app.test")]
    )
    auth = WebAuthenticator(scope=scope, engagement_id="dest-gate")

    undeclared = await auth._try_api_login("http://app.test/", "alice", "x")
    assert sent == []
    assert "dispatched nothing" in undeclared.failure_stage

    await auth._try_api_login(
        "http://app.test/", "alice", "x", api_login_url="http://app.test/api/v2/session"
    )
    assert sent and all(url == "http://app.test/api/v2/session" for url in sent)


def test_detection_names_no_root_and_probes_no_json_route() -> None:
    """The cookie branch names a mechanism, never the root as a login URL."""
    import asyncio

    from clinkz.engagement.auth_state import ProbeResponse, detect_auth_mechanism

    posted: list[str] = []

    class _Probe:
        async def get(self, url: str, **_kw: Any) -> ProbeResponse:
            headers = (
                {"Set-Cookie": "sid=1; Path=/"} if url.rstrip("/") == "http://app.test" else {}
            )
            return ProbeResponse(status=200, body=_SHELL, headers=headers)

        async def post_json(self, url: str, payload: dict[str, str]) -> ProbeResponse:
            posted.append(url)
            return ProbeResponse(status=401, body=json.dumps({}))

    detection = asyncio.run(detect_auth_mechanism(_Probe(), "http://app.test"))
    assert posted == []
    assert detection.login_url == ""
