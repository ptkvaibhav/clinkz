"""The P7 carrier's guardrail: a witness payload is built, never authored.

These mirror ``tests/test_oob/test_templates.py``. The P6 versions exist because
an OOB template that could interpolate arbitrary data would be an exfiltration
channel. P7's channel does not leave the machine, so the property being defended
here is different and narrower: a payload must be *the shape the verdict claims
it was*, and a target-derived token must never break out of its own syntactic
slot into script.
"""

from __future__ import annotations

import pytest

from clinkz.browser.templates import (
    ClientWitnessTemplateId,
    MarkupBreakout,
    build_witness_expression,
    build_witness_payload,
    is_valid_binding,
    mint_binding_name,
)
from clinkz.oob.templates import is_valid_nonce, mint_nonce

NONCE = "abcdefghij234567"
BINDING = "__clinkz_w_deadbeef"


def _every_template_kwargs(tid: ClientWitnessTemplateId) -> dict[str, str]:
    if tid is ClientWitnessTemplateId.NONCED_INLINE_SCRIPT:
        return {"csp_nonce": "TmV2ZXJnb25uYQ=="}
    if tid in (
        ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
        ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET_URL,
    ):
        return {"gadget_path": "/api/jsonp.php", "gadget_param": "callback"}
    return {}


class TestNonceMachineryIsShared:
    """P7 reuses P6's nonce, rather than inventing a second scheme."""

    def test_minted_binding_is_a_valid_identifier(self) -> None:
        for _ in range(20):
            assert is_valid_binding(mint_binding_name())

    def test_binding_names_are_per_load_random(self) -> None:
        names = {mint_binding_name() for _ in range(50)}
        assert len(names) == 50

    def test_witness_expression_carries_exactly_the_nonce(self) -> None:
        assert build_witness_expression(BINDING, NONCE) == f"window.{BINDING}('{NONCE}')"

    def test_oob_minted_nonce_is_accepted(self) -> None:
        nonce = mint_nonce()
        assert is_valid_nonce(nonce)
        assert nonce in build_witness_expression(BINDING, nonce)


class TestEveryTemplateCarriesTheNonce:
    @pytest.mark.parametrize("tid", list(ClientWitnessTemplateId))
    def test_payload_contains_nonce_and_binding(self, tid: ClientWitnessTemplateId) -> None:
        payload = build_witness_payload(tid, NONCE, BINDING, **_every_template_kwargs(tid))
        assert BINDING in payload
        # The gadget shape URL-encodes its callback, so compare on the decoded form.
        from urllib.parse import unquote

        assert NONCE in unquote(payload)

    @pytest.mark.parametrize("tid", list(ClientWitnessTemplateId))
    def test_payload_reads_nothing_and_connects_nowhere(self, tid: ClientWitnessTemplateId) -> None:
        """The executable surface is one call — no DOM read, no storage, no fetch."""
        payload = build_witness_payload(tid, NONCE, BINDING, **_every_template_kwargs(tid))
        lowered = payload.lower()
        for forbidden in (
            "document.cookie",
            "localstorage",
            "sessionstorage",
            "fetch(",
            "xmlhttprequest",
            "navigator.sendbeacon",
            "innerhtml",
        ):
            assert forbidden not in lowered


class TestGuardrailRejectsNonNonceData:
    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "short",
            "../../etc/passwd",
            "${env:AWS_SECRET}",
            "abc'; alert(1); //",
            "UPPERCASE1234567",
            "with.dot.1234567",
        ],
    )
    def test_non_nonce_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="nonce"):
            build_witness_payload(ClientWitnessTemplateId.INLINE_SCRIPT, bad, BINDING)

    @pytest.mark.parametrize(
        "bad",
        ["", "x", "has-dash", "1startsWithDigit", "with space", "quote'name"],
    )
    def test_non_identifier_binding_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="binding"):
            build_witness_payload(ClientWitnessTemplateId.INLINE_SCRIPT, NONCE, bad)

    @pytest.mark.parametrize(
        "bad",
        ['"><script>alert(1)</script>', "has space", "has'quote", "a" * 200],
    )
    def test_csp_nonce_that_could_break_its_attribute_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="csp_nonce"):
            build_witness_payload(
                ClientWitnessTemplateId.NONCED_INLINE_SCRIPT, NONCE, BINDING, csp_nonce=bad
            )

    def test_nonced_template_without_a_nonce_refuses_rather_than_degrading(self) -> None:
        """A silent fallback to the plain shape would make the verdict describe a
        probe that was never sent."""
        with pytest.raises(ValueError, match="csp_nonce"):
            build_witness_payload(ClientWitnessTemplateId.NONCED_INLINE_SCRIPT, NONCE, BINDING)


class TestGadgetPathCannotLeaveTheOrigin:
    """The one shape that could turn a same-origin include into an off-origin one."""

    @pytest.mark.parametrize(
        "bad",
        [
            "//evil.tld/x.js",
            "https://evil.tld/x.js",
            "http://evil.tld/x.js",
            "/ok/but'quote",
            '/ok/but"quote',
            "/ok/but<script>",
            "/ok/but space",
            "relative/no/root.js",
            "",
        ],
    )
    def test_off_origin_or_breaking_path_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError):
            build_witness_payload(
                ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
                NONCE,
                BINDING,
                gadget_path=bad,
                gadget_param="callback",
            )

    def test_protocol_relative_names_its_own_reason(self) -> None:
        with pytest.raises(ValueError, match="OFF-ORIGIN"):
            build_witness_payload(
                ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
                NONCE,
                BINDING,
                gadget_path="//evil.tld/x.js",
                gadget_param="callback",
            )

    @pytest.mark.parametrize("bad", ["", "has space", "has'quote", "-leading"])
    def test_bad_param_name_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="gadget_param"):
            build_witness_payload(
                ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
                NONCE,
                BINDING,
                gadget_path="/api/jsonp.php",
                gadget_param=bad,
            )

    def test_existing_query_string_is_appended_to_not_clobbered(self) -> None:
        payload = build_witness_payload(
            ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
            NONCE,
            BINDING,
            gadget_path="/api/jsonp.php?v=2",
            gadget_param="callback",
        )
        assert "/api/jsonp.php?v=2&callback=" in payload


class TestBreakoutVocabularyIsClosed:
    @pytest.mark.parametrize("breakout", list(MarkupBreakout))
    def test_every_member_builds(self, breakout: MarkupBreakout) -> None:
        payload = build_witness_payload(
            ClientWitnessTemplateId.INLINE_SCRIPT, NONCE, BINDING, breakout=breakout
        )
        assert payload.endswith(f"<script>window.{BINDING}('{NONCE}')</script>")

    def test_unknown_breakout_is_refused(self) -> None:
        with pytest.raises(ValueError):
            build_witness_payload(
                ClientWitnessTemplateId.INLINE_SCRIPT,
                NONCE,
                BINDING,
                breakout="</option>",  # type: ignore[arg-type]
            )

    def test_no_page_string_can_reach_a_payload(self) -> None:
        """There is no parameter through which response text could ride."""
        import inspect

        params = set(inspect.signature(build_witness_payload).parameters)
        assert params == {
            "template_id",
            "nonce",
            "binding",
            "breakout",
            "csp_nonce",
            "gadget_path",
            "gadget_param",
        }
