"""Carrying a probe as a NAMED principal without poisoning the engagement session.

Three session modes exist at the HTTP chokepoint and they are not
interchangeable:

* ``ambient``  — the shared jar is read and written. Every ordinary probe.
* ``isolated`` — the jar is untouched in both directions; the explicit cookies
  and headers are the only session material. What a role-B probe needs.
* ``none``     — no session material at all. The anonymous control.

``isolated`` is the one that did not exist, and the two that did are both wrong
for a cross-principal arm. Under ``ambient`` curl still passes ``-c <jar>``, so
role B's ``Set-Cookie`` overwrites the engagement's own session and every later
probe silently becomes B. Under ``none`` the explicit cookies are dropped, so the
request carries no principal at all. An access-control oracle cannot survive
either, and neither failure is visible in a response.
"""

from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents._principal import ANONYMOUS, Principal
from clinkz.agents.exploit import ExploitAgent
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.http_client import (
    SESSION_AMBIENT,
    SESSION_ISOLATED,
    SESSION_MODES,
    SESSION_NONE,
    HTTPClientTool,
)
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="principal-carrier-test",
    targets=[ScopeEntry(value="app.test", type=ScopeType.DOMAIN)],
)


class _NullLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_NullLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="principal-carrier-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._session_cookies = {"PHPSESSID": "engagement-session"}
    agent._session_headers = {"Authorization": "Bearer engagement-token"}
    return agent


class TestTheChokepointResolvesOneMode:
    def test_the_default_is_ambient(self) -> None:
        args = HTTPClientTool(scope=SCOPE).validate_input({"url": "http://app.test/x"})
        assert args["session_mode"] == SESSION_AMBIENT
        assert args["no_session"] is False

    def test_no_session_is_shorthand_for_none(self) -> None:
        args = HTTPClientTool(scope=SCOPE).validate_input(
            {"url": "http://app.test/x", "no_session": True}
        )
        assert args["session_mode"] == SESSION_NONE
        assert args["no_session"] is True

    def test_no_session_is_derived_not_independently_supplied(self) -> None:
        """Two booleans that must agree is how the session-link leak happened."""
        args = HTTPClientTool(scope=SCOPE).validate_input(
            {"url": "http://app.test/x", "session_mode": SESSION_ISOLATED}
        )
        assert args["no_session"] is False
        assert args["session_mode"] == SESSION_ISOLATED

    def test_a_contradictory_pair_raises_rather_than_picking_one(self) -> None:
        with pytest.raises(ValueError, match="contradictory session material"):
            HTTPClientTool(scope=SCOPE).validate_input(
                {
                    "url": "http://app.test/x",
                    "no_session": True,
                    "session_mode": SESSION_AMBIENT,
                }
            )

    def test_an_unknown_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid session_mode"):
            HTTPClientTool(scope=SCOPE).validate_input(
                {"url": "http://app.test/x", "session_mode": "borrowed"}
            )

    def test_the_schema_advertises_every_mode(self) -> None:
        schema = HTTPClientTool(scope=SCOPE).get_schema()
        declared = schema["parameters"]["properties"]["session_mode"]["enum"]
        assert set(declared) == set(SESSION_MODES)


class TestTheCurlCarrierHonoursTheMode:
    """``-c`` writes the shared jar and ``-b <jar>`` reads it. They separate."""

    @staticmethod
    def _cmd(mode: str, cookies: dict[str, str] | None = None) -> list[str]:
        tool = HTTPClientTool(scope=SCOPE, engagement_id="eng-1")
        captured: dict[str, Any] = {}

        async def _fake(cmd: list[str]) -> tuple[str, str, int]:
            captured["cmd"] = cmd
            return "HTTP/1.1 200 OK\n\nbody", "", 0

        tool._run_subprocess = _fake  # type: ignore[method-assign]
        import asyncio

        args = tool.validate_input(
            {"url": "http://app.test/x", "session_mode": mode, "cookies": cookies or {}}
        )
        asyncio.run(tool._execute_curl(args))
        return captured["cmd"]

    def test_ambient_reads_and_writes_the_jar(self) -> None:
        cmd = self._cmd(SESSION_AMBIENT, {"sid": "a"})
        assert "-c" in cmd
        assert "sid=a" in cmd

    def test_ambient_with_no_explicit_cookies_reads_the_jar(self) -> None:
        cmd = self._cmd(SESSION_AMBIENT)
        assert "-c" in cmd
        jar = cmd[cmd.index("-c") + 1]
        assert cmd[cmd.index("-b") + 1] == jar

    def test_isolated_sends_the_cookies_and_touches_no_jar(self) -> None:
        cmd = self._cmd(SESSION_ISOLATED, {"sid": "role-b"})
        assert "-c" not in cmd, "isolated must not WRITE the shared jar"
        assert "sid=role-b" in cmd
        jar_args = [a for a in cmd if a.endswith("_cookies.txt")]
        assert jar_args == [], f"isolated must not READ the shared jar: {jar_args}"

    def test_none_sends_nothing_and_touches_no_jar(self) -> None:
        cmd = self._cmd(SESSION_NONE, {"sid": "a"})
        assert "-c" not in cmd
        assert "-b" not in cmd
        assert "sid=a" not in cmd


class TestOnlyAnAmbientResponseIsEvidenceAboutTheSession:
    def test_isolated_is_not_session_bearing(self) -> None:
        """A role-B 401 is B lacking the object, not our session expiring."""
        observed: list[bool] = []

        class _Gov:
            def observe_response(self, **kw: Any) -> None:
                observed.append(bool(kw.get("session_bearing")))

        for mode, expected in (
            (SESSION_AMBIENT, True),
            (SESSION_ISOLATED, False),
            (SESSION_NONE, False),
        ):
            observed.clear()
            HTTPClientTool._observe(
                _Gov(),
                '{"status_code": 401, "response_headers": {}, "response_body": ""}',
                session_bearing=mode == SESSION_AMBIENT,
            )
            assert observed == [expected], mode

    def test_a_request_that_got_no_response_is_not_observed_at_all(self) -> None:
        """An absence entering the session oracle as a measurement.

        The status was ``int(data.get("status_code") or 0)``, so a transport
        failure (whose envelope carries ``status_code: 0``) and a truncated
        envelope both arrived as 0. Neither ``_looks_blocked`` nor
        ``looks_unauthenticated`` matches 0, so both were fed in as CLEAN
        responses and RESET two streaks: the governor's consecutive-block count
        and the sentinel's consecutive-loss count. Both counters exist to
        accumulate across exactly the conditions under which transport failures
        cluster.
        """
        seen: list[dict[str, Any]] = []

        class _Gov:
            def observe_response(self, **kw: Any) -> None:
                seen.append(kw)

        for raw in (
            '{"response_headers": {}, "response_body": ""}',
            '{"status_code": 0, "response_body": "", "error": "connection refused"}',
            '{"status_code": null}',
            '{"status_code": "200"}',
        ):
            HTTPClientTool._observe(_Gov(), raw)
        assert seen == [], "a request with no response status must make no observation"

        HTTPClientTool._observe(
            _Gov(), '{"status_code": 200, "response_headers": {}, "response_body": "x"}'
        )
        assert [s["status"] for s in seen] == [200], "a real status is still observed"


class TestTheAgentCarrier:
    @pytest.mark.asyncio
    async def test_a_named_principal_swaps_the_session_and_declares_isolation(self) -> None:
        agent = _agent()
        bob = Principal(role="bob", username="bob", cookies={"PHPSESSID": "bobs"})
        async with agent._as_principal(bob):
            assert agent._session_cookies == {"PHPSESSID": "bobs"}
            assert agent._session_headers == {}
            assert agent._session_isolation_args() == {"session_mode": SESSION_ISOLATED}
        assert agent._session_cookies == {"PHPSESSID": "engagement-session"}
        assert agent._session_headers == {"Authorization": "Bearer engagement-token"}
        assert agent._session_isolation_args() == {}

    @pytest.mark.asyncio
    async def test_the_anonymous_arm_declares_none_not_an_empty_cookie_dict(self) -> None:
        """An empty dict under ``ambient`` still makes curl fall back to the jar."""
        agent = _agent()
        async with agent._as_principal(None):
            assert agent._session_cookies == {}
            assert agent._session_headers == {}
            assert agent._session_isolation_args() == {"session_mode": SESSION_NONE}

    @pytest.mark.asyncio
    async def test_the_session_is_restored_even_when_the_body_raises(self) -> None:
        agent = _agent()
        bob = Principal(role="bob", cookies={"PHPSESSID": "bobs"})
        with pytest.raises(RuntimeError, match="probe blew up"):
            async with agent._as_principal(bob):
                raise RuntimeError("probe blew up")
        assert agent._session_cookies == {"PHPSESSID": "engagement-session"}
        assert agent._principal_isolation is False
        assert agent._active_principal is None

    @pytest.mark.asyncio
    async def test_nesting_is_refused_rather_than_interleaved(self) -> None:
        """Concurrent use would send one principal's session under another's label."""
        agent = _agent()
        a = Principal(role="a", cookies={"s": "1"})
        b = Principal(role="b", cookies={"s": "2"})
        async with agent._as_principal(a):
            with pytest.raises(RuntimeError, match="not re-entrant"):
                async with agent._as_principal(b):
                    pass
        assert agent._active_principal is None

    def test_a_principal_with_no_session_material_is_not_an_identity(self) -> None:
        assert Principal(role="ghost").carries_session is False
        assert Principal(role="bob", cookies={"s": "1"}).carries_session is True
        assert Principal(role="bob", headers={"Authorization": "x"}).carries_session is True

    def test_the_label_names_the_role_and_the_user(self) -> None:
        assert Principal(role="bob", username="gordonb").label() == "bob (gordonb)"
        assert Principal(role="bob", username="bob").label() == "bob"
        assert Principal(role="").label() == "(unnamed principal)"

    def test_anonymous_is_not_a_role_name_a_target_could_supply(self) -> None:
        assert ANONYMOUS == "anonymous"


class TestEverySessionCarryingBuilderHonoursTheOverlay:
    """The guard-domain law: the domain is COMPUTED, not listed here.

    Every arg dict in the Exploit Agent that reads the ambient session material
    and hands it to :class:`HTTPClientTool` must also carry
    ``**self._session_isolation_args()``. One that does not would send role B's
    cookies while still writing the shared jar — silently, and only in docker
    mode, which is the mode a real engagement runs in.
    """

    @staticmethod
    def _session_reading_dicts() -> tuple[list[str], list[str]]:
        """Every session-reading arg dict in the agent, split by whose tool it is.

        The domain is COMPUTED from the HTTP tool's OWN schema rather than
        listed here: a dict whose keys all belong to
        ``HTTPClientTool.get_schema()`` and which carries ``url`` and ``cookies``
        is an HTTP argument builder. Anything with keys the schema has never
        heard of belongs to a different tool, and is returned separately so the
        exclusion is visible rather than silent.

        Returns:
            ``(http_builders, other_tools)`` — each a list of rendered dicts.
        """
        import ast
        import pathlib

        http_keys = set(HTTPClientTool(scope=SCOPE).get_schema()["parameters"]["properties"])
        source = pathlib.Path(inspect.getfile(ExploitAgent)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        http_builders: list[str] = []
        other: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if "cookies" not in keys or "url" not in keys:
                continue
            rendered = ast.unparse(node)
            if "_session_cookies" not in rendered and "_effective_cookies" not in rendered:
                continue
            entry = f"line {node.lineno}: {rendered}"
            (http_builders if keys <= http_keys else other).append(entry)
        return http_builders, other

    def test_no_builder_reads_the_session_without_declaring_its_mode(self) -> None:
        http_builders, _other = self._session_reading_dicts()
        assert http_builders, "the AST probe found no HTTP argument builders — it is broken"
        offenders = [b[:140] for b in http_builders if "_session_isolation_args" not in b]
        assert offenders == [], (
            "these HTTP argument builders read the ambient session but declare no "
            f"session_mode, so an isolated principal probe would write the shared jar: {offenders}"
        )

    def test_the_excluded_builders_belong_to_another_tool(self) -> None:
        """What the domain leaves out, named — a silent skip is how guards rot.

        The P7 browser oracle takes ``cookies`` too and has no ``session_mode``:
        it is a different tool with a different schema. It is not reached from
        inside ``_as_principal`` — no access-control class invokes P7 — so it
        carries the engagement's own session, which is what it is for.
        """
        _http, other = self._session_reading_dicts()
        for entry in other:
            assert "injection" in entry or "template_id" in entry, (
                f"an excluded session-reading arg dict that is NOT the browser oracle: {entry}"
            )

    def test_the_anonymous_helpers_declare_none(self) -> None:
        """They are the pre-existing statement of the same property."""
        import ast
        import pathlib

        source = pathlib.Path(inspect.getfile(ExploitAgent)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        declared = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            rendered = ast.unparse(node)
            if "'no_session': True" in rendered or "SESSION_NONE" in rendered:
                declared += 1
        assert declared >= 3, f"expected the anonymous carriers to declare none: {declared}"
