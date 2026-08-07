"""P7 end-to-end against a real browser and a local fixture site.

Marked ``p7_browser`` and excluded from the keyless gate, for the same reason
``dvwa_smoke`` is: they need a system dependency (a downloaded Chromium) that a
bare CI runner does not have. Everything that can be asserted *without* a
browser lives in the keyless suites next door — this file only holds claims that
genuinely require an execution engine, because those are exactly the claims P7
exists to make.

Run with::

    pip install -e '.[browser]' && playwright install chromium
    pytest tests/test_browser -m p7_browser
"""

from __future__ import annotations

import json

import pytest

from clinkz.browser.oracle import PlaywrightExecutionOracle
from clinkz.browser.templates import ClientWitnessTemplateId as T
from clinkz.browser.witness import WitnessRefusal, WitnessVerdict
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

from .conftest import STATIC_NONCE

pytestmark = [
    pytest.mark.p7_browser,
    pytest.mark.skipif(
        not PlaywrightExecutionOracle.native_availability(),
        reason=(
            "P7 oracle not installed (pip install -e '.[browser]' && playwright install chromium)"
        ),
    ),
]

SCOPE = EngagementScope(
    name="p7-browser",
    targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
)


async def _run(url: str, **kw) -> WitnessVerdict:
    oracle = PlaywrightExecutionOracle(scope=SCOPE)
    args = oracle.validate_input({"url": url, **kw})
    raw = await oracle.execute(args)
    return WitnessVerdict.model_validate(json.loads(raw)["verdict"])


class TestTheWitnessConfirmsOnlyExecution:
    async def test_a_raw_reflection_executes_and_confirms(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/reflect", param="q")
        assert v.executed is True
        assert v.refusal is WitnessRefusal.NONE
        assert any(w.value == v.nonce for w in v.witnesses)

    async def test_an_escaped_reflection_is_present_but_refuses(self, fixture_site: str) -> None:
        """The payload is in the DOM, byte for byte, and nothing runs it. This is
        the confounder that made every previous DOM-XSS confirmation a phantom."""
        v = await _run(f"{fixture_site}/escaped", param="q")
        assert v.executed is False
        assert v.refusal is WitnessRefusal.NOT_EXECUTED
        assert v.is_target_statement is True

    async def test_a_text_node_landing_refuses(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/textnode", param="q")
        assert v.executed is False
        assert v.refusal is WitnessRefusal.NOT_EXECUTED

    async def test_a_dom_sink_fed_from_the_fragment_confirms(self, fixture_site: str) -> None:
        """The fragment never reaches the server, so no server-side observation
        could ever have witnessed this."""
        v = await _run(f"{fixture_site}/dom-fragment", injection="fragment")
        assert v.executed is True

    async def test_a_decodeuri_fragment_sink_confirms(self, fixture_site: str) -> None:
        """``decodeURI`` does not decode the reserved set, so a fully
        percent-encoded probe reaches this sink with ``%2F`` intact and
        ``</script>`` never reforms. Measured on a live target: the class reported
        'not exploitable' at every security level of a page that executes at
        three of them."""
        v = await _run(f"{fixture_site}/dom-fragment-decodeuri", injection="fragment")
        assert v.executed is True

    async def test_a_decodeuri_query_sink_confirms(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/dom-query-decodeuri", param="q", injection="query")
        assert v.executed is True

    async def test_other_query_parameters_survive_the_injection(self, fixture_site: str) -> None:
        """Placing the payload minimally must not drop the URL's own parameters."""
        oracle = PlaywrightExecutionOracle(scope=SCOPE)
        args = oracle.validate_input(
            {"url": f"{fixture_site}/reflect?keep=1&other=2", "param": "q", "injection": "query"}
        )
        url, _ = oracle._build_request(args, "<script>x</script>")
        assert "keep=1" in url and "other=2" in url and "q=" in url

    async def test_an_event_handler_shape_confirms(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/reflect", param="q", template_id=T.IMG_ONERROR.value)
        assert v.executed is True


class TestTheNeverExecutedControl:
    async def test_control_is_minted_distinct_and_stays_silent_on_a_confirm(
        self, fixture_site: str
    ) -> None:
        v = await _run(f"{fixture_site}/reflect", param="q")
        assert v.executed is True
        assert v.control_nonce and v.control_nonce != v.nonce
        assert v.control_silent is True
        assert all(w.value != v.control_nonce for w in v.witnesses)

    async def test_the_control_never_appears_in_the_payload(self, fixture_site: str) -> None:
        """It is a control precisely because it is injected nowhere."""
        v = await _run(f"{fixture_site}/reflect", param="q")
        assert v.control_nonce not in v.injected_payload
        assert v.control_nonce not in v.navigated_url

    async def test_control_stays_silent_on_a_refusal_too(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/escaped", param="q")
        assert v.control_silent is True


class TestCSPIsRecordedAndObeyed:
    async def test_a_blocking_policy_refuses_and_records_the_policy(
        self, fixture_site: str
    ) -> None:
        v = await _run(f"{fixture_site}/csp-none", param="q")
        assert v.executed is False
        assert v.refusal is WitnessRefusal.NOT_EXECUTED
        assert "script-src 'none'" in v.policy_in_force
        assert v.policy_source == "header"
        assert v.bypass_csp_disabled is True

    async def test_csp_is_never_bypassed(self, fixture_site: str) -> None:
        """An oracle that disabled CSP would confirm every policy ever written."""
        v = await _run(f"{fixture_site}/csp-none", param="q")
        assert v.bypass_csp_disabled is True

    async def test_a_meta_policy_is_recorded_when_no_header_carried_one(
        self, fixture_site: str
    ) -> None:
        v = await _run(f"{fixture_site}/csp-meta", param="q")
        assert v.policy_source == "meta"
        assert "script-src 'none'" in v.policy_in_force

    async def test_plain_inline_is_blocked_when_a_nonce_is_published(
        self, fixture_site: str
    ) -> None:
        """A nonce makes 'unsafe-inline' inert — the branch that decides which
        shape is worth sending."""
        v = await _run(f"{fixture_site}/csp-static-nonce", param="q")
        assert v.executed is False
        assert "unsafe-inline" in v.policy_in_force

    async def test_a_reused_nonce_is_not_a_control(self, fixture_site: str) -> None:
        """The static-nonce finding, end to end: the policy publishes a constant,
        so an injected script carrying it executes under that very policy."""
        v = await _run(
            f"{fixture_site}/csp-static-nonce",
            param="q",
            template_id=T.NONCED_INLINE_SCRIPT.value,
            csp_nonce=STATIC_NONCE,
        )
        assert v.executed is True
        assert STATIC_NONCE in v.policy_in_force
        assert v.template_id == T.NONCED_INLINE_SCRIPT.value

    async def test_a_wrong_nonce_does_not_execute(self, fixture_site: str) -> None:
        v = await _run(
            f"{fixture_site}/csp-static-nonce",
            param="q",
            template_id=T.NONCED_INLINE_SCRIPT.value,
            csp_nonce="bm90LXRoZS1yaWdodC1vbmU=",
        )
        assert v.executed is False


class TestTheBrowserIsNotASteerableSurface:
    async def test_a_page_cannot_navigate_the_oracle_away(self, fixture_site: str) -> None:
        """The page assigns `location.href`. The oracle refuses, and RECORDS the
        refusal — a blocked navigation leaves Chromium on an internal error page,
        so without that record the run would read as a failed load."""
        v = await _run(f"{fixture_site}/second-navigation", param="q")
        assert v.blocked_navigations, "the page's navigation attempt was not recorded"
        assert any("q=moved" in u for u in v.blocked_navigations)
        assert "q=moved" not in v.final_url
        assert "attempted to navigate away" in v.final_url

    async def test_an_offsite_subresource_is_refused_and_recorded(self, fixture_site: str) -> None:
        """The offsite image is aborted at the interception seam; the page still
        renders and the verdict is still produced."""
        v = await _run(f"{fixture_site}/offsite-subresource", param="q")
        assert v.executed is True
        assert v.is_target_statement is True
        assert any("offsite.invalid" in u for u in v.blocked_subresources)


class TestPOSTNavigationSeesTheRealResponse:
    async def test_a_body_injection_renders_the_servers_own_response(
        self, fixture_site: str
    ) -> None:
        """Rendering the HTML with set_content would apply no policy and confirm
        every level — so the payload has to ride a real POST navigation."""
        v = await _run(f"{fixture_site}/post-reflect", injection="body", param="include")
        assert v.executed is True


class TestEvidenceIsAuditable:
    async def test_a_confirm_carries_the_nonce_out_and_back(self, fixture_site: str) -> None:
        v = await _run(f"{fixture_site}/reflect", param="q")
        summary = v.evidence_summary()
        assert f"nonce_injected='{v.nonce}'" in summary
        assert f"nonce_returned='{v.nonce}'" in summary
        assert v.nonce in v.injected_payload
        assert "control_silent=True" in summary
