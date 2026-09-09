"""The adaptive layer never engages on a login the parser could already read.

This is the acceptance criterion the capability claim rests on, and it is a
NEGATIVE, so it needs the same care as any other negative in this codebase: an
absence measured by a broken instrument is indistinguishable from an absence.
Three layers, each catching what the others cannot.

**Structurally**, ``_adaptive_auth`` is called from exactly two places, both
inside ``_authenticate_role``, and each is dominated by a test for the session
NOT being established. A third call site added anywhere else fails
``test_the_adaptive_layer_has_exactly_two_call_sites`` — because "we only call
it on failure" is a property of the call graph, not of a comment.

**Behaviourally**, the pass is driven with an LLM that RAISES on contact. A run
whose login succeeds must complete without touching it; a run whose login fails
must reach it. An LLM that merely counted calls would let a zero pass for the
wrong reason — a fake that is never wired up also records zero.

**On the shapes themselves**, the property that makes the adaptive layer
unnecessary on DVWA and Meridian is asserted directly: their login forms declare
an ``action``, so the credential POST is ADDRESSED rather than defaulted and the
deterministic path has somewhere to send it. The contrast case — a form that
declares nothing, which is the condition this agent exists for — is asserted
beside them. Tying the negative to that property rather than to a target NAME is
what keeps this file meaningful when a fifth target arrives.

What is deliberately NOT claimed here is a live run. The live proof that the
deterministic path seats Meridian's session unaided is
``tests/test_engagement/test_meridian_auth.py``, which runs the real target
in-process; DVWA and Juice Shop are proven live by the container gate. A second
copy of those fixtures in this file would be a second thing to keep in step, and
the claim it would support is one they already support.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from clinkz.engagement.auth_agent import AuthAgentOutcome

_ORCHESTRATOR = (
    pathlib.Path(__file__).resolve().parents[2]
    / "src"
    / "clinkz"
    / "orchestrator"
    / "orchestrator.py"
)


def _tree() -> ast.Module:
    return ast.parse(_ORCHESTRATOR.read_text(encoding="utf-8"))


def _calls_to(tree: ast.Module, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
    ]


def _enclosing_function(tree: ast.Module, node: ast.AST) -> str:
    best = ("", 10**9)
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        start, end = candidate.lineno, candidate.end_lineno or candidate.lineno
        if start <= node.lineno <= end and (end - start) < best[1]:
            best = (candidate.name, end - start)
    return best[0]


class TestTheCallGraph:
    def test_the_adaptive_layer_has_exactly_two_call_sites(self) -> None:
        """Both in ``_authenticate_role``, and there are no others.

        A third call site is how "deterministic first" would quietly stop being
        true: somebody adds a re-authentication path, or a default-credential
        path, that reaches the model on a target whose login parses fine.
        """
        tree = _tree()
        calls = _calls_to(tree, "_adaptive_auth")
        assert len(calls) == 2, f"expected 2 call sites, found {len(calls)}"
        enclosing = {_enclosing_function(tree, call) for call in calls}
        assert enclosing == {"_authenticate_role"}, (
            "the adaptive layer is reachable from somewhere other than the role "
            f"authentication path: {sorted(enclosing)}"
        )

    def test_each_call_site_is_guarded_by_a_not_established_test(self) -> None:
        """Each call is dominated by a check that no session was seated.

        Read off the source rather than asserted in prose: the first site is in
        the ``if not result.success`` branch, the second in ``if not
        assertion.established``. A call site that drifted out of its guard would
        make the layer engage on a working login, which is the one thing this
        module exists to rule out.
        """
        source = _ORCHESTRATOR.read_text(encoding="utf-8")
        guards = [
            ("if not result.success:", "await self._adaptive_auth(cred, result, login_url)"),
            (
                "if not assertion.established:",
                "await self._adaptive_auth(cred, result, login_url)",
            ),
        ]
        for guard, call in guards:
            guard_at = source.find(guard)
            assert guard_at != -1, f"the guard {guard!r} is gone"
            call_at = source.find(call, guard_at)
            assert call_at != -1, f"no adaptive call follows {guard!r}"
            # Nothing between the guard and the call may seat a session.
            between = source[guard_at:call_at]
            assert "established=True" not in between


class _ExplodingLLM:
    """Raises on contact. A call count of zero must not be achievable by accident."""

    def __init__(self) -> None:
        self.touched = False

    async def generate_text(self, prompt, **_kwargs):  # noqa: ANN001, ANN202
        self.touched = True
        raise AssertionError(
            "the adaptive-auth layer consulted a model on a login the deterministic "
            "path had already read"
        )


@pytest.mark.asyncio
class TestItDoesNotEngageOnAWorkingLogin:
    async def test_a_seated_session_produces_a_not_engaged_transcript_and_no_llm_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole criterion, in one assertion pair.

        ``_authenticate_role`` is driven with an authenticator that succeeds and
        an assertion that proves — which is what DVWA, Juice Shop and Meridian
        all do — and the LLM raises if touched. The transcript that comes out
        says NOT_ENGAGED with zero turns, which is the record a reader gets on
        every ordinary engagement.
        """
        from clinkz.engagement.auth_state import AuthAssertion
        from clinkz.models.engagement import RoleCredential
        from clinkz.orchestrator import orchestrator as orch_module
        from clinkz.tools.auth import AuthResult, LoginVerdict

        agent = orch_module.OrchestratorAgent.__new__(orch_module.OrchestratorAgent)
        agent._auth_transcripts = []
        agent._role_sessions = {}
        agent._session_material_source = ""
        agent._proven_login = None
        agent._reauth_credential = None
        agent._reauth_login_url = ""
        agent._credentials = _Credentials()
        agent._scope = None
        agent._engagement_id = "test"
        agent._llm = _ExplodingLLM()
        agent._logger = orch_module.logging.getLogger("test")

        result = AuthResult(
            success=True,
            session_cookies={"PHPSESSID": "abc"},
            login_url="http://t.test/login.php",
            posted_to="http://t.test/login.php",
            username="admin",
            status_code=302,
            verdict=LoginVerdict.PROVEN,
            verdict_evidence="the POST set PHPSESSID",
        )

        class _Auth:
            def __init__(self, **_kwargs) -> None:
                pass

            async def authenticate(self, *_args, **_kwargs) -> AuthResult:
                return result

        monkeypatch.setattr("clinkz.tools.auth.WebAuthenticator", _Auth)

        async def _assert_role_session(_cred, _cookies, _headers, _login_url):  # noqa: ANN001
            return AuthAssertion(
                established=True,
                url="http://t.test/index.php",
                discriminator="login_redirect",
                authenticated_status=200,
                anonymous_status=302,
            )

        agent._assert_role_session = _assert_role_session

        cred = RoleCredential(role="admin", username="admin", password="password")
        await orch_module.OrchestratorAgent._authenticate_role(
            agent, cred, "http://t.test/login.php"
        )

        assert not agent._llm.touched, "a model was consulted on a working login"
        assert len(agent._auth_transcripts) == 1
        transcript = agent._auth_transcripts[0]
        assert transcript.outcome is AuthAgentOutcome.NOT_ENGAGED
        assert transcript.llm_turns == 0
        assert not transcript.attempts
        assert not transcript.engaged
        assert agent._role_sessions["admin"]["established"]
        assert agent._role_sessions["admin"].get("seated_by") is None

    async def test_a_failed_login_does_reach_the_layer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The positive control for the negative above.

        A test that only asserted "no LLM call on success" would pass against a
        layer that is wired to nothing at all. So the same harness, with a login
        that fails, must reach the model — and the exploding LLM turning that
        into a NOT_ATTEMPTED outcome is the proof it was reached.
        """
        from clinkz.models.engagement import RoleCredential
        from clinkz.orchestrator import orchestrator as orch_module
        from clinkz.tools.auth import AuthResult, LoginVerdict

        agent = orch_module.OrchestratorAgent.__new__(orch_module.OrchestratorAgent)
        agent._auth_transcripts = []
        agent._role_sessions = {}
        agent._session_material_source = ""
        agent._recon_component_labels = []
        agent._package_identity_coverage_note = ""
        agent._scope = _Scope()
        agent._engagement_id = "test"
        agent._llm = _ExplodingLLM()
        agent._logger = orch_module.logging.getLogger("test")
        agent._primary_target_url = lambda: "http://t.test"

        failed = AuthResult(
            success=False,
            login_url="http://t.test/login",
            posted_to="http://t.test/login",
            username="u@t.test",
            status_code=200,
            form_action_declared=False,
            form_field_names=["csrfToken", "email", "password"],
            csrf_fields_without_cookie=["csrfToken"],
            framework_fingerprint="X-Powered-By: SomeFramework",
            post_changed_nothing=True,
            verdict=LoginVerdict.REFUSED,
            verdict_evidence="the POST set no cookie and returned no token",
            failure_stage="the credential POST changed nothing",
        )

        class _Auth:
            def __init__(self, **_kwargs) -> None:
                pass

            async def authenticate(self, *_args, **_kwargs) -> AuthResult:
                return failed

        monkeypatch.setattr("clinkz.tools.auth.WebAuthenticator", _Auth)

        cred = RoleCredential(role="admin", username="u@t.test", password="s")
        await orch_module.OrchestratorAgent._authenticate_role(agent, cred, "http://t.test/login")

        assert agent._llm.touched, "the adaptive layer was never reached on a failed login"
        transcript = agent._auth_transcripts[0]
        assert transcript.outcome is AuthAgentOutcome.NOT_ATTEMPTED
        assert transcript.engaged


class _Credentials:
    def primary(self):  # noqa: ANN201
        from clinkz.models.engagement import RoleCredential

        return RoleCredential(role="admin", username="admin", password="password")

    def for_role(self, _role):  # noqa: ANN001, ANN201
        return self.primary()


class _Scope:
    def contains(self, _url: str) -> bool:
        return True


# ---------------------------------------------------------------------------
# The three targets, on their own recorded bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "html", "headers", "expected"),
    [
        (
            "dvwa-form-and-cookie",
            '<form action="login.php" method="post">'
            '<input name="username"><input type="password" name="password">'
            '<input type="hidden" name="user_token" value="t">'
            '<input type="submit" name="Login" value="Login"></form>',
            {"X-Powered-By": "PHP/8.5.6", "Set-Cookie": "PHPSESSID=abc; Path=/"},
            "action",
        ),
        (
            "meridian-json-behind-a-form",
            '<form action="/portal/v3/session-open" method="post">'
            '<input name="account"><input type="password" name="password">'
            '<input type="submit" name="submit" value="Sign in"></form>',
            {"Server": "Meridian/1.0"},
            "action",
        ),
    ],
)
def test_the_targets_the_parser_can_read_declare_a_destination(
    name: str, html: str, headers: dict[str, str], expected: str
) -> None:
    """Why the adaptive layer is unnecessary on these, stated as a property.

    Both declare a form ``action``, so the credential POST is ADDRESSED rather
    than defaulted, and the deterministic path has somewhere to send it. That is
    the fact that separates them from the target this agent was built for, whose
    form declares nothing — and tying the negative to that property rather than
    to a target name is what keeps this test meaningful when a fourth target
    arrives.
    """
    from clinkz.tools.auth import _framework_fingerprint, _parse_form_fields

    form = _parse_form_fields(html)
    assert expected == "action"
    assert form.form_action.strip(), f"{name}: the form declares no action"
    assert form.password_field, f"{name}: no password input was found"
    assert _framework_fingerprint(headers), f"{name}: nothing named the stack"


def test_the_target_the_agent_exists_for_declares_nothing() -> None:
    """The contrast case, from the corpus: a form with no action at all.

    Recorded shape, reduced to its load-bearing parts. Every fact the
    deterministic path can read is present and none of them says where the
    credential goes — which is the condition under which proposing is the only
    remaining move.
    """
    from clinkz.tools.auth import (
        _csrf_fields_without_cookie,
        _framework_fingerprint,
        _parse_form_fields,
    )

    html = (
        "<form>"
        '<input name="email"><input type="password" name="password">'
        '<input type="hidden" name="csrfToken" value="x">'
        "</form>"
    )
    form = _parse_form_fields(html)
    assert form.from_form, "the page DID serve a form"
    assert not form.form_action.strip(), "and it declared no destination"
    assert _csrf_fields_without_cookie(form.hidden_fields, {}) == ["csrfToken"]
    assert _framework_fingerprint(
        {"X-Powered-By": "Next.js", "Vary": "rsc, next-router-state-tree"}
    )
