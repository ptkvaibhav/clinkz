"""Where the P7 browser runs, and the rails it carries when it runs there.

No browser is launched in this file. What is under test is the seam that makes
the oracle reachable from a real engagement at all — the runtime choice, the
transport into the tools container, the projection of the safety rails into a
process that cannot import Clinkz, and the action-log record every navigation
leaves. All of that has to be right on a machine with no Chromium, which is why
it is asserted in the keyless gate rather than behind the ``p7_browser`` mark.

The bug these cover: P7 was validated only through a driver that ran the browser
in-process against ``http://localhost:8080``. A real engagement runs in docker
tool-mode, where the scope target has been rewritten to a container-network
alias — so the oracle was, in effect, unreachable from ``clinkz scan``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinkz.browser import _container_runner
from clinkz.browser._container_runner import RESULT_SENTINEL, request_refusal, same_origin
from clinkz.browser.oracle import (
    RUNTIME_CONTAINER,
    RUNTIME_IN_PROCESS,
    PlaywrightExecutionOracle,
)
from clinkz.browser.witness import WitnessRefusal
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.action_log import CATEGORY_BROWSER_NAVIGATION, OUTCOME_REFUSED, OUTCOME_SENT
from clinkz.safety.destructive import subresource_guard_spec

SCOPE = EngagementScope(
    name="p7-runtime",
    targets=[ScopeEntry(value="clinkz-dvwa", type=ScopeType.DOMAIN)],
)

TARGET = "http://clinkz-dvwa/vulnerabilities/xss_d/"
GUARD = {"allowed_hosts": ["clinkz-dvwa"], **subresource_guard_spec()}


def _oracle(runtime: str = RUNTIME_CONTAINER, **kw: Any) -> PlaywrightExecutionOracle:
    return PlaywrightExecutionOracle(scope=SCOPE, runtime=runtime, **kw)


class TestTheRuntimeFollowsWhereToolsExecute:
    """The target address is a consequence of ``TOOL_EXEC_MODE``, so the runtime is too."""

    def test_docker_exec_mode_runs_the_browser_in_the_container(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.tool_exec_mode", "docker")
        assert PlaywrightExecutionOracle.default_runtime() == RUNTIME_CONTAINER

    def test_local_exec_mode_runs_the_browser_in_process(self, monkeypatch) -> None:
        monkeypatch.setattr("clinkz.config.settings.tool_exec_mode", "local")
        assert PlaywrightExecutionOracle.default_runtime() == RUNTIME_IN_PROCESS

    def test_the_container_runtime_gets_the_flags_it_cannot_launch_without(self) -> None:
        """Chromium's sandbox cannot initialise as root in a container, and
        /dev/shm is 64 MB there. Omitting these is a browser that never starts."""
        job = _oracle(RUNTIME_CONTAINER)._build_job(_verdict(), TARGET, "GET", "", {})
        assert "--no-sandbox" in job["launch_args"]
        assert "--disable-dev-shm-usage" in job["launch_args"]

    def test_the_in_process_runtime_is_given_no_extra_flags(self) -> None:
        job = _oracle(RUNTIME_IN_PROCESS)._build_job(_verdict(), TARGET, "GET", "", {})
        assert job["launch_args"] == []


def _verdict():
    from clinkz.browser.witness import WitnessVerdict

    return WitnessVerdict(binding_name="__clinkz_w_deadbeefdeadbeef")


class TestTheRailsTravelWithTheJob:
    """The browser may run where Clinkz cannot be imported, so the rails ship as data."""

    def test_the_job_carries_the_scope_as_an_explicit_host_allowlist(self) -> None:
        job = _oracle()._build_job(_verdict(), TARGET, "GET", "", {})
        assert "clinkz-dvwa" in job["guard"]["allowed_hosts"]

    def test_the_job_carries_the_destructive_vocabulary(self) -> None:
        job = _oracle()._build_job(_verdict(), TARGET, "GET", "", {})
        assert "logout" in job["guard"]["blocked_path_tokens"]
        assert "phpids" in job["guard"]["blocked_query_keys"]

    def test_the_allowlist_is_derived_from_scope_not_only_the_target(self) -> None:
        scope = EngagementScope(
            name="two",
            targets=[
                ScopeEntry(value="http://a.example:8080", type=ScopeType.DOMAIN),
                ScopeEntry(value="b.example", type=ScopeType.DOMAIN),
            ],
        )
        oracle = PlaywrightExecutionOracle(scope=scope, runtime=RUNTIME_CONTAINER)
        hosts = oracle._scope_hosts("http://a.example:8080/x")
        assert {"a.example", "b.example"} <= set(hosts)


class TestTheInBrowserRequestRail:
    """What a rendered page is allowed to make the browser do."""

    def test_a_same_origin_asset_is_allowed(self) -> None:
        assert request_refusal("http://clinkz-dvwa/dvwa/css/main.css", "GET", TARGET, GUARD) == ""

    def test_an_in_scope_cross_origin_asset_is_allowed(self) -> None:
        guard = {"allowed_hosts": ["clinkz-dvwa", "cdn.internal"], **subresource_guard_spec()}
        assert request_refusal("http://cdn.internal/x.js", "GET", TARGET, guard) == ""

    def test_an_out_of_scope_host_is_refused(self) -> None:
        refusal = request_refusal("http://offsite.invalid/pixel.png", "GET", TARGET, GUARD)
        assert "outside the engagement scope" in refusal

    def test_a_page_initiated_mutation_is_refused(self) -> None:
        """A blocked navigation is not enough: fetch('/x', {method:'DELETE'})
        reaches the target as a subresource request, not a navigation."""
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            refusal = request_refusal("http://clinkz-dvwa/api/x", method, TARGET, GUARD)
            assert "would mutate target state" in refusal

    def test_a_get_that_destroys_the_session_is_refused(self) -> None:
        """<img src="/logout"> is a GET, and it ends the engagement's session."""
        refusal = request_refusal("http://clinkz-dvwa/logout.php", "GET", TARGET, GUARD)
        assert "state-changing token" in refusal and "logout" in refusal

    def test_a_get_that_flips_a_security_control_is_refused(self) -> None:
        refusal = request_refusal(
            "http://clinkz-dvwa/security.php?phpids=off", "GET", TARGET, GUARD
        )
        assert "state-changing" in refusal

    def test_a_destructive_verb_in_the_path_is_refused(self) -> None:
        refusal = request_refusal("http://clinkz-dvwa/users/5/delete", "GET", TARGET, GUARD)
        assert "delete" in refusal

    def test_matching_is_on_tokens_not_substrings(self) -> None:
        """``undeleted`` is not ``delete``; a substring rule would refuse the web."""
        assert request_refusal("http://clinkz-dvwa/undeleted.css", "GET", TARGET, GUARD) == ""

    def test_same_origin_defaults_the_port_by_scheme(self) -> None:
        assert same_origin("http://h/a", "http://h:80/b") is True
        assert same_origin("https://h/a", "https://h:443/b") is True
        assert same_origin("http://h:8080/a", "http://h/b") is False


class TestTheContainerTransport:
    """Reading a verdict back out of a process that also hosts a browser."""

    async def test_a_delimited_result_is_parsed_out_of_noisy_output(self, monkeypatch) -> None:
        payload = {**_container_runner._blank_result(), "final_url": "http://clinkz-dvwa/x"}
        noise = "Fontconfig warning: ignoring UTF-8\nlibva error: something\n"

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return (f"{noise}{RESULT_SENTINEL}{json.dumps(payload)}\n", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        result = await _oracle()._run_in_container({"url": TARGET})
        assert result["final_url"] == "http://clinkz-dvwa/x"

    async def test_the_job_reaches_the_container_and_the_runner_source_is_the_program(
        self, monkeypatch
    ) -> None:
        seen: dict[str, Any] = {}

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            seen["cmd"] = cmd
            seen["stdin"] = stdin_data
            return (f"{RESULT_SENTINEL}{json.dumps(_container_runner._blank_result())}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        await _oracle()._run_in_container({"url": TARGET, "marker": "carried"})

        assert seen["cmd"][:2] == ["python3", "-"]
        assert "def run_witness" in seen["stdin"]
        import base64

        assert json.loads(base64.b64decode(seen["cmd"][2]))["marker"] == "carried"

    async def test_session_cookies_never_reach_the_recorded_command(self, monkeypatch) -> None:
        """The job carries the engagement's session cookies, and base64 hides
        them from the redaction chokepoint entirely — an encoded blob has no
        shape for a cookie rule to match. A live run wrote a real PHPSESSID into
        ``tool_invocations/`` this way while the disclosure gate reported zero
        credential shapes, truthfully answering the wrong question."""
        import base64

        seen: dict[str, Any] = {}

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            seen["cmd"] = cmd
            seen["trace_cmd"] = trace_cmd
            return (f"{RESULT_SENTINEL}{json.dumps(_container_runner._blank_result())}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle()
        args = oracle.validate_input(
            {
                "url": TARGET,
                "param": "q",
                "cookies": {"PHPSESSID": "s3cr3tvalue", "security": "low"},
            }
        )
        await oracle.execute(args)

        executed = json.loads(base64.b64decode(seen["cmd"][2]))
        recorded = json.loads(base64.b64decode(seen["trace_cmd"][2]))

        # The browser still receives the real session, or it browses anonymously.
        assert executed["cookies"]["PHPSESSID"] == "s3cr3tvalue"
        # The artifact keeps the NAMES and loses the VALUES.
        assert set(recorded["cookies"]) == {"PHPSESSID", "security"}
        assert "s3cr3tvalue" not in json.dumps(recorded)
        assert "s3cr3tvalue" not in seen["trace_cmd"][2]

    async def test_a_missing_playwright_reads_as_unavailable_not_as_a_clean_result(
        self, monkeypatch
    ) -> None:
        """The distinction the whole primitive rests on: a broken oracle is a
        coverage gap, never evidence that the target is safe."""

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return ("", "ModuleNotFoundError: No module named 'playwright'", 1)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        result = await _oracle()._run_in_container({"url": TARGET})
        assert result["unavailable"] is True

    async def test_unparseable_output_is_an_error_not_a_silent_empty_verdict(
        self, monkeypatch
    ) -> None:
        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return (f"{RESULT_SENTINEL}{{not json", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        result = await _oracle()._run_in_container({"url": TARGET})
        assert result["error"]


class TestEveryNavigationIsInTheActionLog:
    """ "What did it do to my app" must include handing a page to a real engine."""

    @pytest.fixture
    def governor(self, tmp_path, monkeypatch):
        from clinkz.models.engagement import SafetyPolicy
        from clinkz.safety.governor import EngagementGovernor, set_active_governor

        gov = EngagementGovernor("nav-log-test", SafetyPolicy(), outputs_root=tmp_path)
        set_active_governor(gov)
        yield gov
        set_active_governor(None)

    async def test_an_authorized_navigation_is_recorded_as_sent(
        self, governor, monkeypatch
    ) -> None:
        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return (f"{RESULT_SENTINEL}{json.dumps(_container_runner._blank_result())}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle(engagement_id="nav-log-test")
        await oracle.execute(oracle.validate_input({"url": TARGET, "param": "q"}))

        records = _read_log(governor)
        navs = [r for r in records if r["category"] == CATEGORY_BROWSER_NAVIGATION]
        assert len(navs) == 1
        assert navs[0]["outcome"] == OUTCOME_SENT
        assert navs[0]["method"] == "GET"

    async def test_a_refused_navigation_is_recorded_and_no_browser_runs(
        self, governor, monkeypatch
    ) -> None:
        async def explode(self, cmd, stdin_data, trace_cmd=None):
            raise AssertionError("a refused navigation must not reach the browser")

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", explode)
        oracle = _oracle(engagement_id="nav-log-test")
        raw = await oracle.execute(
            oracle.validate_input({"url": "http://clinkz-dvwa/logout.php", "param": "q"})
        )

        assert json.loads(raw)["verdict"]["refusal"] == WitnessRefusal.STATE_CHANGING_URL.value
        records = _read_log(governor)
        assert any(r["outcome"] == OUTCOME_REFUSED for r in records)

    async def test_a_get_navigation_does_not_inflate_the_state_changing_tally(
        self, governor, monkeypatch
    ) -> None:
        """The two numbers answer different questions and must not be summed."""

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return (f"{RESULT_SENTINEL}{json.dumps(_container_runner._blank_result())}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle(engagement_id="nav-log-test")
        await oracle.execute(oracle.validate_input({"url": TARGET, "param": "q"}))

        stats = governor.stats()
        assert stats["state_changing_sent"] == 0
        assert stats["browser_navigations"] == 1

    async def test_an_unavailable_browser_logs_no_navigation(self, governor, monkeypatch) -> None:
        """Nothing reached the target, so nothing may appear in the log that
        answers "what did it do to my app"."""

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return ("", "ModuleNotFoundError: No module named 'playwright'", 1)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle(engagement_id="nav-log-test")
        raw = await oracle.execute(oracle.validate_input({"url": TARGET, "param": "q"}))

        assert json.loads(raw)["verdict"]["refusal"] == WitnessRefusal.ORACLE_UNAVAILABLE.value
        assert _read_log(governor) == []

    async def test_a_crashed_renderer_still_logs_the_navigation(
        self, governor, monkeypatch
    ) -> None:
        """The page WAS handed to an engine — that is the fact being recorded."""

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            payload = {**_container_runner._blank_result(), "error": "Target page crashed"}
            return (f"{RESULT_SENTINEL}{json.dumps(payload)}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle(engagement_id="nav-log-test")
        raw = await oracle.execute(oracle.validate_input({"url": TARGET, "param": "q"}))

        assert json.loads(raw)["verdict"]["refusal"] == WitnessRefusal.NAVIGATION_FAILED.value
        assert [r["outcome"] for r in _read_log(governor)] == [OUTCOME_SENT]

    async def test_no_governor_means_no_log_and_no_crash(self, monkeypatch) -> None:
        """Outside an engagement the rails are absent and the oracle is unchanged."""
        from clinkz.safety.governor import set_active_governor

        set_active_governor(None)

        async def fake(self, cmd, stdin_data, trace_cmd=None):
            return (f"{RESULT_SENTINEL}{json.dumps(_container_runner._blank_result())}", "", 0)

        monkeypatch.setattr(PlaywrightExecutionOracle, "_run_subprocess_stdin", fake)
        oracle = _oracle()
        raw = await oracle.execute(oracle.validate_input({"url": TARGET, "param": "q"}))
        assert json.loads(raw)["verdict"]["refusal"] == WitnessRefusal.NOT_EXECUTED.value


def _read_log(governor) -> list[dict[str, Any]]:
    path = governor.action_log.path
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
