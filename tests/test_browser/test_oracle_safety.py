"""The P7 rails, asserted without a browser.

A headless browser is a genuinely new destructive surface: it fetches
subresources, follows redirects, and executes code the target wrote. These
tests pin the refusals that keep it from becoming one, and they run in the
keyless gate because none of them needs a browser to be installed.
"""

from __future__ import annotations

import json

import pytest

from clinkz.browser.oracle import PlaywrightExecutionOracle
from clinkz.browser.witness import WitnessRefusal
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

SCOPE = EngagementScope(
    name="p7",
    targets=[
        ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
    ],
)


def _oracle() -> PlaywrightExecutionOracle:
    return PlaywrightExecutionOracle(scope=SCOPE)


def _verdict(raw: str) -> dict:
    return json.loads(raw)["verdict"]


class TestScopeIsCheckedBeforeAnyNavigation:
    def test_out_of_scope_host_is_refused_at_validation(self) -> None:
        with pytest.raises(ValueError, match="outside the engagement scope"):
            _oracle().validate_input({"url": "http://not-in-scope.example/x"})

    def test_in_scope_host_validates(self) -> None:
        args = _oracle().validate_input({"url": "http://127.0.0.1:8080/a"})
        assert args["url"] == "http://127.0.0.1:8080/a"

    @pytest.mark.parametrize("url", ["", "ftp://127.0.0.1/x", "file:///etc/passwd", "not a url"])
    def test_non_http_urls_are_refused(self, url: str) -> None:
        with pytest.raises(ValueError):
            _oracle().validate_input({"url": url})

    def test_unknown_injection_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="injection channel"):
            _oracle().validate_input({"url": "http://127.0.0.1/a", "injection": "header"})

    def test_unknown_template_is_refused(self) -> None:
        with pytest.raises(ValueError, match="witness template"):
            _oracle().validate_input({"url": "http://127.0.0.1/a", "template_id": "custom"})

    def test_caller_cannot_supply_a_payload_string(self) -> None:
        """The schema exposes a template SELECTION, never a payload."""
        props = _oracle().get_schema()["parameters"]["properties"]
        assert "payload" not in props
        assert "script" not in props
        assert "template_id" in props


class TestStateChangingNavigationIsRefused:
    async def test_logout_url_is_refused_before_the_browser_launches(self) -> None:
        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1:8080/logout.php"})
        verdict = _verdict(await oracle.execute(args))
        assert verdict["refusal"] == WitnessRefusal.STATE_CHANGING_URL.value
        assert verdict["executed"] is False

    async def test_a_refusal_is_not_a_statement_about_the_target(self) -> None:
        from clinkz.browser.witness import WitnessVerdict

        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1:8080/logout.php"})
        verdict = WitnessVerdict.model_validate(_verdict(await oracle.execute(args)))
        assert verdict.is_target_statement is False


class TestGovernorDecides:
    async def test_a_governor_refusal_becomes_a_refusal_verdict(self, monkeypatch) -> None:
        from clinkz.safety.governor import RequestDecision

        navigations: list[dict] = []

        class _Refusing:
            def __init__(self) -> None:
                self.released = 0

            async def authorize(self, *a, **k):
                return RequestDecision(allowed=False, category="halted", reason="engagement halted")

            def release(self) -> None:
                self.released += 1

            def observe_response(self, **k) -> None:
                pass

            def record_navigation(self, **k) -> None:
                navigations.append(k)

        gov = _Refusing()
        monkeypatch.setattr("clinkz.safety.governor.get_active_governor", lambda: gov)
        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1:8080/reflect"})
        verdict = _verdict(await oracle.execute(args))
        assert verdict["refusal"] == WitnessRefusal.SAFETY_REFUSED.value
        assert "engagement halted" in verdict["refusal_detail"]
        # The refusal is auditable: a navigation the rails stopped is recorded
        # as such, not simply absent from the log.
        assert [n["outcome"] for n in navigations] == ["refused"]

    async def test_a_refused_navigation_costs_no_concurrency_slot(self, monkeypatch) -> None:
        """A refusal acquires nothing, so it must release nothing — releasing a
        slot never taken would corrupt the semaphore for every other phase."""
        from clinkz.safety.governor import RequestDecision

        released: list[int] = []
        navigations: list[dict] = []

        class _Refusing:
            async def authorize(self, *a, **k):
                return RequestDecision(allowed=False, category="halted", reason="no")

            def release(self) -> None:
                released.append(1)

            def observe_response(self, **k) -> None:
                pass

            def record_navigation(self, **k) -> None:
                navigations.append(k)

        monkeypatch.setattr("clinkz.safety.governor.get_active_governor", lambda: _Refusing())
        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1:8080/reflect"})
        await oracle.execute(args)
        assert released == []

    async def test_body_injection_is_authorized_as_a_post(self, monkeypatch) -> None:
        """A POST navigation must reach the action log as a POST, or 'what did it
        do to my app' answers wrongly."""
        seen: dict[str, object] = {}
        navigations: list[dict] = []
        from clinkz.safety.governor import RequestDecision

        class _Recording:
            async def authorize(self, method, url, **k):
                seen["method"] = method
                seen["url"] = url
                seen["body"] = k.get("body")
                return RequestDecision(allowed=False, category="x", reason="stop here")

            def release(self) -> None:
                pass

            def observe_response(self, **k) -> None:
                pass

            def record_navigation(self, **k) -> None:
                navigations.append(k)

        monkeypatch.setattr("clinkz.safety.governor.get_active_governor", lambda: _Recording())
        oracle = _oracle()
        args = oracle.validate_input(
            {"url": "http://127.0.0.1:8080/csp/", "injection": "body", "param": "include"}
        )
        await oracle.execute(args)
        assert seen["method"] == "POST"
        assert "include=" in str(seen["body"])


class TestPayloadPlacement:
    def test_query_injection_sets_the_parameter_without_over_encoding(self) -> None:
        """The payload is placed with MINIMAL encoding, because a ``decodeURI``
        sink cannot recover the reserved set: a fully percent-encoded ``</script>``
        arrives as ``%3C%2Fscript%3E`` and stays inert. The browser encodes what
        it must, and ``decodeURI`` reverses exactly that."""
        oracle = _oracle()
        args = oracle.validate_input(
            {"url": "http://127.0.0.1/a?keep=1", "injection": "query", "param": "q"}
        )
        url, body = oracle._build_request(args, "<script>x</script>")
        assert "keep=1" in url
        assert "q=<script>x</script>" in url
        assert "%2F" not in url  # the reserved character decodeURI would not restore
        assert body == ""

    def test_a_payload_containing_an_ampersand_is_escaped_in_the_query(self) -> None:
        """Minimal is not none: an unescaped ``&`` would start a new parameter."""
        oracle = _oracle()
        args = oracle.validate_input(
            {"url": "http://127.0.0.1/a", "injection": "query", "param": "q"}
        )
        url, _ = oracle._build_request(args, "a&b#c")
        assert "%26" in url and "%23" in url

    def test_fragment_injection_never_reaches_the_query(self) -> None:
        """The fragment is the vector precisely because the server never sees it."""
        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1/a", "injection": "fragment"})
        url, body = oracle._build_request(args, "<script>x</script>")
        assert "#" in url
        assert url.split("#")[0].endswith("/a")
        assert body == ""

    def test_body_injection_produces_a_form_encoded_body(self) -> None:
        oracle = _oracle()
        args = oracle.validate_input(
            {"url": "http://127.0.0.1/a", "injection": "body", "param": "include"}
        )
        url, body = oracle._build_request(args, "<script>x</script>")
        assert url == "http://127.0.0.1/a"
        assert body.startswith("include=")


class TestMissingOracleIsACoverageGapNotAVerdict:
    async def test_absent_playwright_yields_oracle_unavailable(self, monkeypatch) -> None:
        import builtins

        real_import = builtins.__import__

        def _no_playwright(name, *a, **k):
            if name.startswith("playwright"):
                raise ImportError("no playwright here")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _no_playwright)
        oracle = _oracle()
        args = oracle.validate_input({"url": "http://127.0.0.1:8080/reflect"})
        verdict = _verdict(await oracle.execute(args))
        assert verdict["refusal"] == WitnessRefusal.ORACLE_UNAVAILABLE.value
        assert verdict["executed"] is False

    def test_availability_is_answered_not_assumed(self) -> None:
        """The resolver's binary check is the wrong question for a Python-native
        tool; the tool answers it itself."""
        assert PlaywrightExecutionOracle.native_availability() in (True, False)

    def test_resolver_finds_the_oracle_by_capability_never_by_name(self) -> None:
        from clinkz.tools.resolver import TOOL_CHAINS, ToolResolver

        match = ToolResolver().find_tool("client_side_execution")
        assert match is not None
        assert match.tool_class is PlaywrightExecutionOracle
        assert TOOL_CHAINS["client_side_execution"][0] == "playwright_chromium"
        assert len(TOOL_CHAINS["client_side_execution"]) > 1


class TestParseOutput:
    def test_malformed_output_is_an_error_not_a_confirmation(self) -> None:
        out = _oracle().parse_output("not json")
        assert out.success is False
        assert out.verdict.executed is False

    def test_a_refusal_is_not_success(self) -> None:
        raw = json.dumps(
            {"verdict": {"executed": False, "refusal": WitnessRefusal.NAVIGATION_FAILED.value}}
        )
        assert _oracle().parse_output(raw).success is False

    def test_a_clean_non_execution_is_success(self) -> None:
        raw = json.dumps(
            {"verdict": {"executed": False, "refusal": WitnessRefusal.NOT_EXECUTED.value}}
        )
        assert _oracle().parse_output(raw).success is True
