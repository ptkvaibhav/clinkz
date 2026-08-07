"""Reading a served policy, and choosing what to try under it.

The two branches with live evidence behind them are the nonce-beats-unsafe-inline
rule and the static-nonce rule; both are asserted here against the exact policy
strings DVWA serves, because those are the shapes that were measured.
"""

from __future__ import annotations

import pytest

from clinkz.browser.csp_policy import (
    nonce_is_static,
    parse_csp,
    same_origin,
    select_bypass_route,
)
from clinkz.browser.templates import ClientWitnessTemplateId as T

# The four policies observed live on the DVWA csp module, verbatim.
POLICY_LOW = (
    "script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com "
    "code.jquery.com https://ssl.google-analytics.com unpkg.com cdn.jsdelivr.net digi.ninja ;"
)
POLICY_MEDIUM = "script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';"
POLICY_HIGH = "script-src 'self';"


def _hdr(policy: str) -> dict[str, str]:
    return {"Content-Security-Policy": policy}


class TestParsing:
    def test_no_policy_is_absent_not_permissive(self) -> None:
        p = parse_csp({})
        assert p.present is False
        assert p.raw == ""

    def test_header_name_is_case_insensitive(self) -> None:
        assert parse_csp({"content-security-policy": POLICY_HIGH}).present is True
        assert parse_csp({"Content-Security-Policy": POLICY_HIGH}).present is True

    def test_report_only_enforces_nothing_and_is_ignored(self) -> None:
        """Treating a report-only policy as a control would report a policy as
        blocking while the browser happily executes."""
        p = parse_csp({"Content-Security-Policy-Report-Only": "script-src 'none'"})
        assert p.present is False

    def test_script_src_wins_over_default_src(self) -> None:
        p = parse_csp(_hdr("default-src 'none'; script-src 'self'"))
        assert p.effective_directive == "script-src"
        assert p.allows_self is True

    def test_default_src_governs_when_script_src_is_absent(self) -> None:
        p = parse_csp(_hdr("default-src 'self'"))
        assert p.effective_directive == "default-src"
        assert p.allows_self is True

    def test_meta_policy_is_read_when_no_header_carried_one(self) -> None:
        p = parse_csp({}, meta_policies=["script-src 'self'"])
        assert p.present is True
        assert p.source == "meta"

    def test_policy_governing_no_script_directive_is_not_present(self) -> None:
        p = parse_csp(_hdr("img-src 'none'; style-src 'self'"))
        assert p.present is False


class TestNonceDefeatsUnsafeInline:
    """Measured live: with both present, a bare inline script was refused."""

    def test_unsafe_inline_alone_allows_inline(self) -> None:
        assert parse_csp(_hdr("script-src 'unsafe-inline'")).allows_inline is True

    def test_a_nonce_makes_unsafe_inline_inert(self) -> None:
        p = parse_csp(_hdr(POLICY_MEDIUM))
        assert "'unsafe-inline'" in " ".join(p.sources)
        assert p.allows_inline is False
        assert p.nonces == ("TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=",)

    def test_a_hash_makes_unsafe_inline_inert(self) -> None:
        p = parse_csp(_hdr("script-src 'unsafe-inline' 'sha256-abc123='"))
        assert p.allows_inline is False
        assert p.hashes == ("sha256-abc123=",)


class TestMultiplePoliciesIntersect:
    def test_all_policies_must_permit_inline(self) -> None:
        p = parse_csp(
            {"Content-Security-Policy": "script-src 'unsafe-inline'"},
            meta_policies=["script-src 'self'"],
        )
        assert p.allows_inline is False


class TestStaticNonce:
    def test_one_observation_proves_nothing(self) -> None:
        """A per-response nonce looks identical to a static one when seen once."""
        assert nonce_is_static(["abc"]) is False

    def test_two_identical_observations_prove_reuse(self) -> None:
        assert nonce_is_static(["abc", "abc"]) is True

    def test_a_rotating_nonce_is_not_static(self) -> None:
        assert nonce_is_static(["abc", "def"]) is False

    def test_no_observations_is_not_static(self) -> None:
        assert nonce_is_static([]) is False


class TestRouteSelection:
    def test_no_policy_routes_to_plain_inline(self) -> None:
        route = select_bypass_route(parse_csp({}))
        assert route.template_id is T.INLINE_SCRIPT

    def test_unsafe_inline_routes_to_plain_inline(self) -> None:
        route = select_bypass_route(parse_csp(_hdr("script-src 'unsafe-inline'")))
        assert route.template_id is T.INLINE_SCRIPT

    def test_static_nonce_routes_to_the_nonced_shape(self) -> None:
        nonce = "TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA="
        route = select_bypass_route(parse_csp(_hdr(POLICY_MEDIUM)), observed_nonces=[nonce, nonce])
        assert route.template_id is T.NONCED_INLINE_SCRIPT
        assert route.csp_nonce == nonce

    def test_a_rotating_nonce_yields_no_inline_route(self) -> None:
        route = select_bypass_route(
            parse_csp(_hdr("script-src 'nonce-aaa'")), observed_nonces=["aaa", "bbb"]
        )
        assert route.template_id is None
        assert "per-response nonce" in route.unreachable_note

    def test_self_plus_a_gadget_routes_to_the_gadget(self) -> None:
        route = select_bypass_route(parse_csp(_hdr(POLICY_HIGH)), gadget_available=True)
        assert route.template_id is T.SAME_ORIGIN_SCRIPT_GADGET
        assert route.requires_gadget is True

    def test_self_without_a_gadget_has_no_route_and_says_so(self) -> None:
        route = select_bypass_route(parse_csp(_hdr(POLICY_HIGH)), gadget_available=False)
        assert route.template_id is None
        assert "Not tested" in route.unreachable_note

    def test_strict_dynamic_disables_the_gadget_route(self) -> None:
        """'strict-dynamic' makes host and 'self' sources inert for script loads,
        so a same-origin include is no longer permitted by the policy."""
        route = select_bypass_route(
            parse_csp(_hdr("script-src 'self' 'strict-dynamic' 'nonce-x'")),
            gadget_available=True,
        )
        assert route.template_id is None

    def test_no_route_never_reads_as_a_clean_policy(self) -> None:
        route = select_bypass_route(parse_csp(_hdr("script-src 'none'")))
        assert route.template_id is None
        assert route.unreachable_note
        assert "not a proof" in route.unreachable_note

    def test_dvwa_low_policy_permits_no_inline_shape(self) -> None:
        """Low allows external hosts and 'self' but not inline — so the inline
        shapes are correctly not chosen."""
        route = select_bypass_route(parse_csp(_hdr(POLICY_LOW)), gadget_available=False)
        assert route.template_id is None


class TestSameOrigin:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("http://h:80/a", "http://h:80/b", True),
            ("http://h/a", "https://h/a", False),
            ("http://h:8080/a", "http://h:3000/a", False),
            ("http://a/x", "http://b/x", False),
        ],
    )
    def test_origin_comparison(self, a: str, b: str, expected: bool) -> None:
        assert same_origin(a, b) is expected
