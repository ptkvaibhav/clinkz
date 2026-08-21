"""Tier 1 — the two mechanical migrations, and the guards that keep them.

Eleven classes read the target through one of two abstractions that already
existed in the tree, and three classes already used. What made the other eight
invisible on a framework target was not a missing capability, it was the shape
of the accessor:

* ``page.forms`` is ``_http_get`` plus ``_FormParser().feed(body)``, so it is
  ``[]`` on any React/Angular/Vue target — the form exists, it is just rendered
  after the bytes we parsed. ``_injectable_forms`` is the same list plus the
  pseudo-forms this agent synthesizes for body-bearing API endpoints.
* ``_http_get(page.url, {param: value})`` puts every probe in the query string.
  ``_send_probe`` is the shape-aware chokepoint that already knew about JSON
  bodies, path segments, cookies and forms.

The guards below are computed from the source rather than hand-listed, per the
guard-domain law: a new hand-rolled probe fails the build without anyone
remembering to add it to a table here.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Any
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.exploit import (
    _AUTH_ROUTE_SEGMENTS,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.scan import ParamLocation
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="tier1-migration-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

_EXPLOIT_SOURCE = pathlib.Path(__file__).resolve().parents[2] / "src/clinkz/agents/exploit.py"


class _SilentLLM(LLMClient):
    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_agent() -> ExploitAgent:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=state,
        engagement_id="tier1-migration-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


# ===========================================================================
# B — the probe carrier is a chokepoint, and the domain is the source
# ===========================================================================

#: Call sites that legitimately build a parameterised GET without going through
#: ``_send_probe``. Each entry states WHY, and the shared reason is the same
#: one: ``_send_probe`` injects into *the page under test*, and none of these is
#: probing the page under test.
_DELIBERATE_DIRECT_PROBES: dict[str, str] = {
    "_send_probe": (
        "is the chokepoint itself — the query branch every other carrier falls "
        "through to when the parameter lives in the query string"
    ),
    "_present_artifact": (
        "carries a harvested chain artifact at a DIFFERENT endpoint from any "
        "page under test; there is no PageAnalysis in a chain carriage, only "
        "the artifact and the target it is being presented to"
    ),
    "_p7_find_script_gadget": (
        "sweeps OTHER paths on the same origin looking for a JSONP wrapper, so "
        "each probe URL is constructed per candidate path rather than injected "
        "into the page the methodology is testing"
    ),
}


def _direct_parameter_probes() -> dict[int, str]:
    """Every ``self._http_get(<url>, {<key>: ...})`` in the exploit agent.

    The DOMAIN is the module's own AST, so a methodology that hand-rolls a new
    query probe fails this test without anyone editing a list — which is the
    whole point, since the eight classes that needed migrating are exactly the
    ones a hand-maintained domain would have forgotten.
    """
    tree = ast.parse(_EXPLOIT_SOURCE.read_text(encoding="utf-8"))
    found: dict[int, str] = {}
    stack: list[str] = []

    def walk(node: ast.AST) -> None:
        pushed = False
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            stack.append(node.name)
            pushed = True
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "_http_get"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Dict)
                and node.args[1].keys
            ):
                found[node.lineno] = stack[-1] if stack else "<module>"
        for child in ast.iter_child_nodes(node):
            walk(child)
        if pushed:
            stack.pop()

    walk(tree)
    return found


class TestProbeCarrierIsTheChokepoint:
    def test_no_methodology_hand_rolls_a_query_probe(self) -> None:
        offenders = {
            f"{name} (exploit.py:{line})"
            for line, name in _direct_parameter_probes().items()
            if name not in _DELIBERATE_DIRECT_PROBES
        }
        assert not offenders, (
            "These build a parameterised GET directly instead of going through "
            f"_send_probe, so the probe rides the query string whatever the "
            f"parameter's declared location is: {sorted(offenders)}. Either use "
            "_send_probe or add an entry to _DELIBERATE_DIRECT_PROBES with the "
            "reason it cannot."
        )

    def test_every_exemption_is_still_real(self) -> None:
        """``declared - computed`` — an exemption that outlived its call site."""
        live = set(_direct_parameter_probes().values())
        stale = set(_DELIBERATE_DIRECT_PROBES) - live
        assert not stale, (
            f"These no longer build a direct parameter probe: {sorted(stale)}. "
            "Remove the exemption rather than leaving documentation of a wish."
        )

    @pytest.mark.parametrize("reason", _DELIBERATE_DIRECT_PROBES.values())
    def test_exemptions_carry_a_substantive_reason(self, reason: str) -> None:
        assert len(reason.split()) >= 6, f"not a reason: {reason!r}"


class TestSendProbeCarriesAJsonBodyReference:
    """The concrete gain: a reference that lives in the body goes in the body."""

    async def test_idor_reference_rides_the_json_body_not_the_query(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(
            url="http://api/orders",
            body="{}",
            status=200,
            input_params=["orderId"],
            request_method="POST",
            content_type="application/json",
            param_locations={"orderId": ParamLocation.JSON_BODY},
        )
        posted: list[tuple[str, dict[str, Any], str]] = []

        async def _capture(url: str, body: dict[str, Any], method: str = "POST") -> _HTTPResponse:
            posted.append((url, body, method))
            return _HTTPResponse(status=200, body="{}")

        agent._http_post_json = _capture  # type: ignore[method-assign]
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="{}")
        )

        await agent._send_probe(page, "orderId", "2")

        assert posted, "the reference never reached a JSON body — it went to the query"
        url, body, method = posted[0]
        assert body["orderId"] == "2"
        assert method == "POST"
        assert "orderId=" not in url
        agent._http_get.assert_not_awaited()

    async def test_path_segment_reference_is_substituted_not_appended(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(
            url="http://api/api/Users/:id",
            body="{}",
            status=200,
            input_params=["id"],
            param_locations={"id": ParamLocation.PATH},
        )
        agent._http_get = AsyncMock(  # type: ignore[method-assign]
            return_value=_HTTPResponse(status=200, body="{}")
        )
        await agent._send_probe(page, "id", "2")

        # ``_send_probe`` hands the reference to ``_http_get`` keyed by name;
        # the segment substitution itself lives one layer deeper, in
        # ``_build_request_url`` -> ``_resolve_path_params``. Assert both halves,
        # because either one alone would pass against a version that appends
        # ``?id=2`` to an unresolved ``:id`` template.
        url, params = agent._http_get.await_args.args[:2]
        assert params == {"id": "2"}
        resolved = agent._build_request_url(url, dict(params))
        assert resolved.endswith("/api/Users/2"), resolved
        assert "id=" not in resolved


# ===========================================================================
# A — the form-shaped classes read _injectable_forms
# ===========================================================================


def _multipart_page(params: list[str], ctype: str = "multipart/form-data") -> PageAnalysis:
    """A discovered upload endpoint with NO parsed HTML form.

    The shape of every framework target: the control is rendered in JavaScript,
    so ``_FormParser`` finds nothing, while ``_js_api_mining`` read the field
    names straight off the frontend's own ``new FormData()`` builder.
    """
    return PageAnalysis(
        url="http://app/file-upload",
        body='{"ok":true}',
        status=200,
        input_params=params,
        request_method="POST",
        content_type=ctype,
        param_locations=dict.fromkeys(params, ParamLocation.FORM_BODY),
    )


class TestUploadPseudoForm:
    def test_declared_multipart_with_a_file_part_yields_a_pseudo_form(self) -> None:
        agent = _make_agent()
        form = agent._upload_pseudo_form(_multipart_page(["file", "caption"]))
        assert form is not None
        assert form["encoding"] == "multipart"
        assert form["method"] == "POST"
        types = {f["name"]: f["type"] for f in form["fields"]}
        assert types["file"] == "file"
        assert types["caption"] != "file"

    def test_multipart_without_a_file_part_yields_nothing(self) -> None:
        """A multipart form with no file part has nothing for an upload test."""
        agent = _make_agent()
        assert agent._upload_pseudo_form(_multipart_page(["title", "body"])) is None

    def test_a_json_endpoint_is_not_an_upload_point(self) -> None:
        agent = _make_agent()
        page = _multipart_page(["file"], ctype="application/json")
        assert agent._upload_pseudo_form(page) is None

    def test_html_forms_are_returned_first_and_unchanged(self) -> None:
        agent = _make_agent()
        page = _multipart_page(["file"])
        html_form = {"action": "/u", "method": "POST", "fields": []}
        page.forms = [html_form]
        forms = agent._injectable_forms(page)
        assert forms[0] is html_form


class TestFileUploadReachesAFormlessTarget:
    async def test_upload_point_selected_without_a_parsed_form(self) -> None:
        agent = _make_agent()
        page = _multipart_page(["file", "caption"])
        assert page.forms == [], "precondition: the framework target parses to zero forms"

        seen: list[dict[str, Any]] = []

        async def _run(_page: PageAnalysis, form: dict[str, Any]) -> Any:
            seen.append(form)
            raise AssertionError("stop after selection")

        agent._run_file_upload_methodology = _run  # type: ignore[method-assign]
        with pytest.raises(AssertionError, match="stop after selection"):
            await agent._test_file_upload(page)
        assert seen and seen[0]["encoding"] == "multipart"

    async def test_the_pre_migration_accessor_would_have_found_nothing(self) -> None:
        """The defect itself, pinned: ``page.forms`` is empty on this target."""
        page = _multipart_page(["file"])
        assert not [
            f for f in page.forms if any(x.get("type") == "file" for x in f.get("fields", []))
        ]


class TestWeakSessionReachesAFormlessTarget:
    def test_pseudo_form_qualifies_on_an_observed_set_cookie(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(
            url="http://app/rest/session",
            body="{}",
            status=200,
            input_params=["email"],
            request_method="POST",
            param_locations={"email": ParamLocation.JSON_BODY},
            response_headers={"Set-Cookie": "sid=abc; Path=/"},
        )
        pseudo = agent._injectable_forms(page)[-1]
        assert pseudo["encoding"] == "json"
        ok, evidence = agent._weak_session_phase1_hypothesis(page, pseudo)
        assert ok is True
        assert evidence["pseudo_form_set_cookie"] is True

    def test_pseudo_form_without_a_set_cookie_is_refused(self) -> None:
        """No protocol artifact, no hypothesis — a body-bearing endpoint is not
        a session mint just because it accepts a POST."""
        agent = _make_agent()
        page = PageAnalysis(
            url="http://app/rest/search",
            body="{}",
            status=200,
            input_params=["q"],
            request_method="POST",
            param_locations={"q": ParamLocation.JSON_BODY},
        )
        pseudo = agent._injectable_forms(page)[-1]
        ok, _evidence = agent._weak_session_phase1_hypothesis(page, pseudo)
        assert ok is False

    def test_html_form_judgement_is_unchanged_by_the_cookie_signal(self) -> None:
        """The DVWA path: an HTML form is judged on its submit label, and never
        reaches the Set-Cookie branch — so a cookie-setting page cannot promote
        a form that phase 1 already declined."""
        agent = _make_agent()
        page = PageAnalysis(
            url="http://app/search",
            body="",
            status=200,
            response_headers={"Set-Cookie": "sid=abc"},
        )
        html_form = {
            "method": "POST",
            "action": "/search",
            "fields": [{"name": "q", "type": "text"}],
        }
        ok, evidence = agent._weak_session_phase1_hypothesis(page, html_form)
        assert ok is False
        assert "pseudo_form_set_cookie" not in evidence


class TestJavascriptAttacksCannotMigrate:
    """``_test_javascript_attacks`` is the one that does NOT migrate.

    Its phase-1 hypothesis is a CONJUNCTION — a form AND an inline ``<script>``
    block — and its only confirming path needs a hidden field of that form to be
    written by that script. A synthesized pseudo-form has no ``hidden`` field by
    construction (``_infer_field_type`` returns password/email/text), and the
    body it is synthesized from is a JSON response with no script in it. So
    swapping the accessor would buy zero confirmations and cost an LLM call per
    endpoint, each one recording a lead the class can never promote.

    Reaching a framework target's client-side security logic means reading its
    bundle, which is a new oracle. That is out of Tier 1's scope, and this test
    exists so the reason is in the tree rather than in a commit message.
    """

    def test_a_pseudo_form_has_no_hidden_field_to_forge(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(
            url="http://app/api/profile",
            body='{"ok":true}',
            status=200,
            input_params=["token", "name"],
            request_method="POST",
            param_locations={
                "token": ParamLocation.JSON_BODY,
                "name": ParamLocation.JSON_BODY,
            },
        )
        pseudo = agent._injectable_forms(page)[-1]
        assert not [f for f in pseudo["fields"] if f.get("type") == "hidden"]

    async def test_the_class_still_declines_a_formless_json_endpoint(self) -> None:
        agent = _make_agent()
        page = PageAnalysis(
            url="http://app/api/profile",
            body='{"ok":true}',
            status=200,
            input_params=["token"],
            request_method="POST",
            param_locations={"token": ParamLocation.JSON_BODY},
        )
        assert await agent._test_javascript_attacks(page) == []


# ===========================================================================
# D — the auth-route signal is a shape, not our two targets' paths
# ===========================================================================


class TestAuthRouteSignalIsAShape:
    @pytest.mark.parametrize(
        "path",
        [
            "/login",
            "/login.php",
            "/signin",
            "/api/login",
            "/rest/user/login",
            "/account/login",
            "/users/login",
            "/auth",
        ],
    )
    def test_generic_auth_routes_match(self, path: str) -> None:
        stems = [seg.rsplit(".", 1)[0] for seg in path.lower().split("/") if seg]
        assert any(stem in _AUTH_ROUTE_SEGMENTS for stem in stems), path

    @pytest.mark.parametrize("path", ["/brute", "/vulnerabilities/brute/", "/search", "/products"])
    def test_a_benchmark_module_name_is_not_an_auth_route(self, path: str) -> None:
        stems = [seg.rsplit(".", 1)[0] for seg in path.lower().split("/") if seg]
        assert not any(stem in _AUTH_ROUTE_SEGMENTS for stem in stems), path

    def test_the_table_names_no_target(self) -> None:
        """The generality law, as an assertion: the signal describes what an
        auth route IS. ``brute`` is a DVWA module and ``rest`` a Juice Shop
        prefix; neither is a word that means "authenticate"."""
        assert not ({"brute", "rest", "dvwa", "juice", "vulnerabilities"} & _AUTH_ROUTE_SEGMENTS)
