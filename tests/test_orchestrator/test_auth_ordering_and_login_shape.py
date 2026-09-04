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
        found = await agent._find_login_url({})
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
        found = await agent._find_login_url({})
        assert found is not None and found.endswith("/login.php")

    async def test_no_login_surface_yields_none_not_the_root_url(self, monkeypatch: Any) -> None:
        """The removed sixth strategy. A root URL is not a login page; it is
        where a credential POST lands when nobody proved anything."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _serve({}), raising=True)
        assert await agent._find_login_url({}) is None

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


# ---------------------------------------------------------------------------
# The crawler linked it, and six path names hid it
# ---------------------------------------------------------------------------

#: A login page at a path no list of login names contains. Meridian's, verbatim.
UNCONVENTIONAL_LOGIN_PATH = "/portal/gateway"


def _links(urls: list[str]) -> Any:
    """Patch the landing-page reader: the anchors the application serves.

    This is the source that ACTUALLY produces at authentication time. These
    tests used to feed a ``scan_result`` parameter instead, which was ``None``
    at both call sites because the scan phase starts after authentication ends —
    so the property below was pinned against a producer that had never run, in
    the one method whose entire history is a name filter that hid a login page.
    """

    async def _linked(self: OrchestratorAgent, base: str) -> list[str]:
        return list(urls)

    return _linked


class TestLoginUrlIsRankedByShapeNotName:
    """``_find_login_url`` used six path names as an ELIGIBILITY filter.

    A URL that matched none of ``("/login", "/admin", "/wp-login", "/manager",
    "/signin", "/auth")`` was discarded before its shape was ever read — so an
    application could link its own login page from its landing page, hand it to
    this method, and still come back "no login surface proven". Renaming the
    same page ``/login`` found it instantly.

    Path names still order the work, because each shape test costs a request.
    They no longer decide what is allowed to be tested.
    """

    async def test_a_linked_login_page_with_an_unconventional_path_is_found(
        self, monkeypatch: Any
    ) -> None:
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(
            OrchestratorAgent,
            "_serves_a_login_form",
            _serve({UNCONVENTIONAL_LOGIN_PATH: LOGIN_PAGE}),
            raising=True,
        )
        # Exactly what a landing page hands over: itself, a public page, and the
        # login page — none of whose names contain a login hint.
        monkeypatch.setattr(
            OrchestratorAgent,
            "_linked_urls",
            _links(
                [
                    "http://app:3000/",
                    "http://app:3000/pricing",
                    f"http://app:3000{UNCONVENTIONAL_LOGIN_PATH}",
                ]
            ),
            raising=True,
        )
        found = await agent._find_login_url({})
        assert found == f"http://app:3000{UNCONVENTIONAL_LOGIN_PATH}", (
            "the application linked its login page and a list of six path names "
            f"discarded it — got {found!r}"
        )

    async def test_the_same_page_named_login_is_still_found(self, monkeypatch: Any) -> None:
        """The control: only the NAME differs, and the verdict must not."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(
            OrchestratorAgent,
            "_serves_a_login_form",
            _serve({"/login": LOGIN_PAGE}),
            raising=True,
        )
        monkeypatch.setattr(
            OrchestratorAgent, "_linked_urls", _links(["http://app:3000/login"]), raising=True
        )
        found = await agent._find_login_url({})
        assert found == "http://app:3000/login"

    async def test_a_login_shaped_name_is_tried_before_an_unconventional_one(
        self, monkeypatch: Any
    ) -> None:
        """Names order the work; they do not gate it. Each test is a request."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        order: list[str] = []

        async def _probe(self: OrchestratorAgent, url: str) -> bool:
            order.append(url)
            return False

        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _probe, raising=True)
        monkeypatch.setattr(
            OrchestratorAgent,
            "_linked_urls",
            _links(["http://app:3000/portal/gateway", "http://app:3000/signin"]),
            raising=True,
        )
        await agent._find_login_url({})
        assert order.index("http://app:3000/signin") < order.index("http://app:3000/portal/gateway")

    async def test_a_shapeless_link_set_still_yields_none(self, monkeypatch: Any) -> None:
        """Collecting every URL must not become "return the first one"."""
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _serve({}), raising=True)
        monkeypatch.setattr(
            OrchestratorAgent,
            "_linked_urls",
            _links([f"http://app:3000/p{i}" for i in range(5)]),
            raising=True,
        )
        assert await agent._find_login_url({}) is None

    async def test_recons_own_summary_is_still_a_candidate_source(self, monkeypatch: Any) -> None:
        """The one collection branch with a live producer at this point in the run.

        Recon emits ``summary`` — its synthesis LLM's prose — and a URL inside it
        is weak evidence that still faces the same shape test as every other
        candidate. It is kept for exactly that reason, while the branches whose
        producers had not run were deleted.
        """
        agent = _orchestrator()
        agent._login_shape_cache = {}
        monkeypatch.setattr(
            OrchestratorAgent,
            "_serves_a_login_form",
            _serve({UNCONVENTIONAL_LOGIN_PATH: LOGIN_PAGE}),
            raising=True,
        )
        monkeypatch.setattr(OrchestratorAgent, "_linked_urls", _links([]), raising=True)
        found = await agent._find_login_url(
            {
                "summary": (
                    "The host serves a portal; the operator console is at "
                    f"http://app:3000{UNCONVENTIONAL_LOGIN_PATH} behind a login."
                )
            }
        )
        assert found == f"http://app:3000{UNCONVENTIONAL_LOGIN_PATH}"


class TestLoginDiscoveryReadsOnlyProducersThatHaveRun:
    """A dead branch in the auth path is where a name filter comes back.

    ``_find_login_url`` read five sources that had never produced anything: a
    ``login_urls`` map no producer writes, four structured URL keys absent from
    a v2 ``ReconResult`` at every nesting level, a ``scan_result`` parameter that
    was ``None`` at both call sites, and ``state.get_endpoints()``. Nothing
    exercised them, so nothing would have caught a filter reintroduced inside
    one — and the tests above were written against the ``scan_result`` one,
    which made them read as coverage of a path that could not execute.

    The domain here is COMPUTED rather than asserted: the ordering comes from
    ``run()``'s own call sequence and the endpoint table's writer set comes from
    the tree, so this cannot become documentation of a wish.
    """

    @staticmethod
    def _orchestrator_source() -> str:
        import inspect

        from clinkz.orchestrator import orchestrator as module

        return inspect.getsource(module)

    def test_authentication_runs_before_the_phase_that_writes_endpoints(self) -> None:
        """The ordering is the reason, so it is read rather than believed."""
        import ast

        tree = ast.parse(self._orchestrator_source())
        run = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run"
        )
        calls = [
            node.func.attr
            for node in ast.walk(run)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]
        assert "_establish_authenticated_state" in calls
        assert "_run_concurrent_phase" in calls
        assert calls.index("_establish_authenticated_state") < calls.index(
            "_run_concurrent_phase"
        ), (
            "authentication no longer precedes the concurrent phase — if that is "
            "deliberate, the dead-source reasoning below has to be redone, not "
            "this assertion relaxed"
        )

    def test_the_endpoint_table_is_written_only_by_the_scan_agent(self) -> None:
        """The producer set, from the tree — not from a comment about it."""
        from pathlib import Path

        src = Path(__file__).resolve().parents[2] / "src" / "clinkz"
        writers = {
            path.relative_to(src).as_posix()
            for path in src.rglob("*.py")
            if ".add_endpoint(" in path.read_text(encoding="utf-8")
        }
        assert writers == {"agents/scan.py"}, (
            f"another producer writes endpoints now: {sorted(writers)}. If it runs "
            "before authentication, login discovery may read it."
        )

    def test_login_discovery_takes_no_scan_result_and_reads_no_endpoint_table(self) -> None:
        import ast
        import inspect
        import textwrap

        assert "scan_result" not in inspect.signature(OrchestratorAgent._find_login_url).parameters

        source = textwrap.dedent(inspect.getsource(OrchestratorAgent._find_login_url))
        called = {
            node.func.attr
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "get_endpoints" not in called, (
            "login discovery reads the endpoint table again; the Scan agent — its "
            "only writer — has not run when this is called"
        )


class TestTheLandingPageNamesTheLoginPage:
    """Removing the name filter was necessary and not sufficient.

    The authentication phase runs BEFORE the scan phase, so ``scan_result`` is
    ``None`` at the call site that matters and there is no crawl to rank. An
    application whose login page sits at an unconventional path therefore had no
    candidate to rank at all, and a live run aborted having POSTed the
    credentials at the site root (405).

    The application says where its login is, in an anchor. Reading that is an
    observation of the same kind as reading a form's ``action``.
    """

    #: Meridian's landing page, verbatim in shape: it links its own login page.
    LANDING = (
        "<!doctype html><html><body><h1>Meridian</h1>"
        "<p><a href=/pricing>Pricing</a> · "
        '<a href="/portal/gateway">Portal</a></p></body></html>'
    )

    async def test_a_linked_login_page_is_discovered_before_the_crawl_exists(
        self, monkeypatch: Any
    ) -> None:
        agent = _orchestrator()
        agent._login_shape_cache = {}

        async def _linked(self: OrchestratorAgent, base: str) -> list[str]:
            return ["http://app:3000/pricing", "http://app:3000/portal/gateway"]

        monkeypatch.setattr(OrchestratorAgent, "_linked_urls", _linked, raising=True)
        monkeypatch.setattr(
            OrchestratorAgent,
            "_serves_a_login_form",
            _serve({UNCONVENTIONAL_LOGIN_PATH: LOGIN_PAGE}),
            raising=True,
        )
        # scan_result=None — exactly how _establish_authenticated_state calls it.
        found = await agent._find_login_url({})
        assert found == "http://app:3000/portal/gateway", (
            f"the landing page linked the login page and discovery still missed it — got {found!r}"
        )

    async def test_off_origin_and_non_navigational_links_are_not_collected(self) -> None:
        """A page linking off-site links to somebody else's login page.

        The scope check downstream would refuse it anyway; not collecting it
        keeps the shape budget for candidates that could be right.
        """
        agent = _orchestrator()
        agent._login_shape_cache = {}
        body = (
            '<a href="https://evil.example/login">Login</a>'
            '<a href="/portal/gateway">Portal</a>'
            '<a href="mailto:x@y.z">Mail</a><a href="#top">Top</a>'
            '<a href="javascript:void(0)">JS</a>'
        )
        assert await self._extract(agent, body, "http://app:3000") == [
            "http://app:3000/portal/gateway"
        ]

    @staticmethod
    async def _extract(agent: OrchestratorAgent, body: str, base: str) -> list[str]:
        """Drive ``_linked_urls`` with a served body, through the real parser."""
        from unittest.mock import patch

        class _Parsed:
            status_code = 200
            response_body = body

        class _Http:
            def __init__(self, **_kw: Any) -> None: ...
            def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
                return args

            async def execute(self, _args: dict[str, Any]) -> str:
                return ""

            def parse_output(self, _raw: str) -> Any:
                return _Parsed()

        with patch("clinkz.tools.http_client.HTTPClientTool", _Http):
            return await agent._linked_urls(base)

    async def test_a_landing_page_with_no_login_link_yields_none(self, monkeypatch: Any) -> None:
        """Collecting links must not become "return the first link"."""
        agent = _orchestrator()
        agent._login_shape_cache = {}

        async def _linked(self: OrchestratorAgent, base: str) -> list[str]:
            return ["http://app:3000/pricing", "http://app:3000/about"]

        monkeypatch.setattr(OrchestratorAgent, "_linked_urls", _linked, raising=True)
        monkeypatch.setattr(OrchestratorAgent, "_serves_a_login_form", _serve({}), raising=True)
        assert await agent._find_login_url({}) is None
