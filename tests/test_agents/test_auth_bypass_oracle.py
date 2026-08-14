"""The authentication-bypass oracle, and the phantoms it must refuse (D8).

The gap: forty SQL-injection payloads landed in a login form's email field, the
target graded the challenge solved, and ``_test_sqli`` emitted nothing —
correctly, because a DB error, a boolean row-set delta and a UNION row are the
only effects its oracle could see, and an auth bypass produces none of them.

The danger in closing it: the naive indicator is "200 and a cookie came back",
which confirms on every application that issues an anonymous session. So the
tests below are written in two halves — the effect is DEMONSTRATED, and every
cheaper observation that resembles it is REFUSED.

Pure: three observations in, a verdict out. No network, no target, no LLM.
"""

from __future__ import annotations

import base64
import json

import pytest

from clinkz.agents._auth_bypass import (
    AuthArtifactKind,
    AuthObservation,
    body_carries_auth_artifact,
    decide_auth_bypass,
    read_auth_artifact,
)


def _jwt(payload: dict) -> str:
    """A structurally real JWT — the header is what makes it decodable."""

    def seg(obj: dict) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.c2lnbmF0dXJl"


# ---------------------------------------------------------------------------
# read_auth_artifact — what counts as authenticated state
# ---------------------------------------------------------------------------


class TestReadAuthArtifact:
    def test_a_plain_200_is_not_authentication(self) -> None:
        """ "The request succeeded" is not the effect."""
        assert read_auth_artifact(200, {}, '{"status":"ok"}') is None

    def test_an_empty_response_is_not_authentication(self) -> None:
        assert read_auth_artifact(200, {}, "") is None

    def test_a_jwt_in_the_body_is_an_artifact(self) -> None:
        token = _jwt({"data": {"id": 1, "email": "admin@juice-sh.op"}})
        artifact = read_auth_artifact(200, {}, json.dumps({"authentication": {"token": token}}))
        assert artifact is not None
        assert artifact.kind is AuthArtifactKind.BODY_TOKEN
        assert artifact.principal == "admin@juice-sh.op"

    def test_a_jwt_artifact_never_carries_the_token_value(self) -> None:
        """A bypass finding is made of what a report must not reproduce."""
        token = _jwt({"sub": "admin", "password": "$2a$hashed"})
        artifact = read_auth_artifact(200, {}, json.dumps({"token": token}))
        assert artifact is not None
        rendered = artifact.describe()
        assert token not in rendered
        assert "$2a$hashed" not in rendered
        assert artifact.fingerprint

    def test_claim_names_survive_but_claim_values_do_not(self) -> None:
        token = _jwt({"sub": "admin", "password": "$2a$hashed", "totpSecret": "ABC"})
        artifact = read_auth_artifact(200, {}, json.dumps({"token": token}))
        assert artifact is not None
        assert "password" in artifact.claim_names
        assert "$2a$hashed" not in " ".join(artifact.claim_names)

    def test_a_session_cookie_is_an_artifact(self) -> None:
        artifact = read_auth_artifact(
            200, {"Set-Cookie": "connect.sid=s%3Aabcdef123456; Path=/; HttpOnly"}, ""
        )
        assert artifact is not None
        assert artifact.kind is AuthArtifactKind.SESSION_COOKIE
        assert "connect.sid" in artifact.where

    def test_a_non_session_cookie_is_not_an_artifact(self) -> None:
        """The whole point of not confirming on 'a cookie came back'."""
        assert read_auth_artifact(200, {"Set-Cookie": "csrftoken_x=abc; Path=/"}, "") is not None
        assert read_auth_artifact(200, {"Set-Cookie": "locale=en-GB; Path=/"}, "") is None
        assert read_auth_artifact(200, {"Set-Cookie": "cookie_consent=1; Path=/"}, "") is None

    def test_a_redirect_to_login_is_not_authentication(self) -> None:
        assert read_auth_artifact(302, {"Location": "/login.php?error=1"}, "") is None

    def test_a_redirect_away_from_login_is_an_artifact(self) -> None:
        artifact = read_auth_artifact(302, {"Location": "/index.php"}, "")
        assert artifact is not None
        assert artifact.kind is AuthArtifactKind.AUTHENTICATED_REDIRECT

    def test_a_placeholder_token_value_is_not_an_artifact(self) -> None:
        assert read_auth_artifact(200, {}, '{"token":"n/a"}') is None

    def test_body_only_helper_agrees_with_the_full_reader(self) -> None:
        token = _jwt({"sub": "someone"})
        assert body_carries_auth_artifact(json.dumps({"token": token})) is True
        assert body_carries_auth_artifact('{"error":"Invalid email or password"}') is False


# ---------------------------------------------------------------------------
# decide_auth_bypass — the three-arm differential
# ---------------------------------------------------------------------------


def _authenticated(label: str, principal: str = "admin@juice-sh.op") -> AuthObservation:
    token = _jwt({"data": {"email": principal}})
    return AuthObservation(
        label=label,
        status=200,
        artifact=read_auth_artifact(200, {}, json.dumps({"authentication": {"token": token}})),
    )


def _refused(label: str, status: int = 401) -> AuthObservation:
    return AuthObservation(label=label, status=status, artifact=None)


SUPPLIED = ["clinkz-probe@example.com", "Clinkz-Probe-1!"]


class TestDecideAuthBypass:
    def test_the_effect_confirms(self) -> None:
        verdict = decide_auth_bypass(
            probe=_authenticated("probe"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is True
        assert verdict.principal_is_foreign is True
        assert "admin@juice-sh.op" in verdict.reason

    def test_no_artifact_on_the_probe_confirms_nothing(self) -> None:
        verdict = decide_auth_bypass(
            probe=_refused("probe"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False
        assert verdict.reason == "no_auth_artifact_returned"

    def test_an_accept_everything_endpoint_confirms_nothing(self) -> None:
        """The control is the same shape with the boolean inverted.

        If it authenticates too, the endpoint is reacting to the SHAPE of the
        value, not evaluating it — a WAF returning a canned 200, a handler that
        errors into a token. This is the observation a naive oracle would have
        called a critical finding.
        """
        verdict = decide_auth_bypass(
            probe=_authenticated("probe"),
            control=_authenticated("control"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False
        assert verdict.reason == "shape_matched_control_also_authenticated"

    def test_an_endpoint_that_authenticates_anyone_confirms_nothing(self) -> None:
        verdict = decide_auth_bypass(
            probe=_authenticated("probe"),
            control=_refused("control"),
            benign=_authenticated("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False
        assert verdict.reason == "benign_credentials_also_authenticated"

    def test_a_token_naming_our_own_identity_confirms_nothing(self) -> None:
        """The probe rides the engagement's session; an echo is not a bypass."""
        verdict = decide_auth_bypass(
            probe=_authenticated("probe", principal="clinkz-probe@example.com"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False
        assert verdict.reason == "principal_is_an_identity_we_supplied"

    def test_a_partial_identity_match_still_counts_as_ours(self) -> None:
        verdict = decide_auth_bypass(
            probe=_authenticated("probe", principal="clinkz-probe"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False

    def test_a_one_character_supplied_value_does_not_suppress_a_real_finding(self) -> None:
        """The benign param value defaults to ``"1"``.

        A two-way substring test against it judges ``admin1@corp.example`` to be
        an identity we supplied and refuses a genuine bypass. This guard runs in
        the suppress-a-real-finding direction, so a false positive in it is the
        expensive kind.
        """
        verdict = decide_auth_bypass(
            probe=_authenticated("probe", principal="admin1@corp.example"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=["1", *SUPPLIED],
        )
        assert verdict.confirmed is True

    def test_an_exact_match_counts_however_short(self) -> None:
        """Short values still match exactly — only CONTAINMENT needs length."""
        verdict = decide_auth_bypass(
            probe=_authenticated("probe", principal="1"),
            control=_refused("control"),
            benign=_refused("benign"),
            supplied_identities=["1"],
        )
        assert verdict.confirmed is False

    def test_an_opaque_artifact_still_confirms_on_the_differential(self) -> None:
        """A session cookie names nobody; requirement (c) cannot apply to it."""
        probe = AuthObservation(
            label="probe",
            status=302,
            artifact=read_auth_artifact(
                302, {"Set-Cookie": "PHPSESSID=abcdef1234; Path=/", "Location": "/index.php"}, ""
            ),
        )
        verdict = decide_auth_bypass(
            probe=probe,
            control=_refused("control", status=302),
            benign=_refused("benign", status=302),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is True
        assert verdict.principal_is_foreign is False

    def test_the_observation_names_all_three_arms(self) -> None:
        """The evidence must let a reader re-derive the verdict."""
        verdict = decide_auth_bypass(
            probe=_authenticated("probe(tautology)"),
            control=_refused("control(contradiction)"),
            benign=_refused("benign"),
            supplied_identities=SUPPLIED,
        )
        for arm in ("probe(tautology)", "control(contradiction)", "benign"):
            assert arm in verdict.observed

    @pytest.mark.parametrize(
        ("control_auth", "benign_auth"),
        [(True, True), (True, False), (False, True)],
    )
    def test_any_uncooperative_control_blocks_confirmation(
        self, control_auth: bool, benign_auth: bool
    ) -> None:
        verdict = decide_auth_bypass(
            probe=_authenticated("probe"),
            control=_authenticated("control") if control_auth else _refused("control"),
            benign=_authenticated("benign") if benign_auth else _refused("benign"),
            supplied_identities=SUPPLIED,
        )
        assert verdict.confirmed is False


# ---------------------------------------------------------------------------
# The deterministic applicability gate — never the LLM's call
# ---------------------------------------------------------------------------


def _agent():
    from tests.test_agents.test_methodology_sqli import _make_agent  # type: ignore

    return _make_agent()


class TestApplicabilityGate:
    def test_a_search_box_is_not_a_login(self) -> None:
        from clinkz.agents.exploit import PageAnalysis

        agent = _agent()
        page = PageAnalysis(url="http://t/search", body="", status=200, input_params=["q"])
        applicable, reason = agent._sqli_auth_bypass_applicable(page, "q")
        assert applicable is False
        assert "password-shaped field" in reason

    def test_an_identity_field_beside_a_password_field_is_a_login(self) -> None:
        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.scan import ParamLocation

        agent = _agent()
        page = PageAnalysis(
            url="http://t/rest/user/login",
            body="",
            status=200,
            input_params=["email", "password"],
            param_locations={
                "email": ParamLocation.JSON_BODY,
                "password": ParamLocation.JSON_BODY,
            },
        )
        applicable, _ = agent._sqli_auth_bypass_applicable(page, "email")
        assert applicable is True

    def test_the_password_field_itself_is_not_the_identity_field(self) -> None:
        from clinkz.agents.exploit import PageAnalysis

        agent = _agent()
        page = PageAnalysis(
            url="http://t/login", body="", status=200, input_params=["email", "password"]
        )
        applicable, reason = agent._sqli_auth_bypass_applicable(page, "password")
        assert applicable is False
        assert "identity-shaped" in reason

    def test_an_html_login_form_is_recognised(self) -> None:
        from clinkz.agents.exploit import PageAnalysis

        agent = _agent()
        page = PageAnalysis(
            url="http://t/login.php",
            body="",
            status=200,
            input_params=["username", "password"],
            forms=[
                {
                    "action": "login.php",
                    "method": "POST",
                    "fields": [
                        {"name": "username", "type": "text", "value": ""},
                        {"name": "password", "type": "password", "value": ""},
                    ],
                }
            ],
        )
        applicable, _ = agent._sqli_auth_bypass_applicable(page, "username")
        assert applicable is True

    def test_the_gate_removes_the_type_the_llm_invented(self) -> None:
        """Applicability is deterministic in BOTH directions."""
        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.methodology import InjectionType

        agent = _agent()
        page = PageAnalysis(url="http://t/search", body="", status=200, input_params=["q"])
        ranked = agent._sqli_apply_auth_bypass_gate(
            page, "q", [InjectionType.AUTH_BYPASS, InjectionType.ERROR_BASED]
        )
        assert ranked == [InjectionType.ERROR_BASED]

    def test_the_gate_adds_the_type_the_llm_omitted(self) -> None:
        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.methodology import InjectionType

        agent = _agent()
        page = PageAnalysis(
            url="http://t/login", body="", status=200, input_params=["email", "password"]
        )
        ranked = agent._sqli_apply_auth_bypass_gate(page, "email", [InjectionType.ERROR_BASED])
        assert ranked[0] is InjectionType.AUTH_BYPASS
        assert InjectionType.ERROR_BASED in ranked


# ---------------------------------------------------------------------------
# Synthesis — the pair must differ by the boolean and nothing else
# ---------------------------------------------------------------------------


class TestSynthesis:
    def test_probe_and_control_differ_only_in_the_boolean(self) -> None:
        from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect

        agent = _agent()
        synth = agent._fallback_synthesis_sqli(
            InjectionType.AUTH_BYPASS,
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"], break_prefix="'"),
            {"value": "1"},
        )
        assert synth is not None
        probe, control = synth["payload"], synth["control_payload"]
        assert len(probe) == len(control)
        differing = [i for i, (a, b) in enumerate(zip(probe, control)) if a != b]
        assert len(differing) == 1, f"{probe!r} vs {control!r}"
        assert synth["indicator_type"] == "auth_bypass"

    def test_the_pair_uses_the_confirmed_breakout(self) -> None:
        from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect

        agent = _agent()
        synth = agent._fallback_synthesis_sqli(
            InjectionType.AUTH_BYPASS,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["#"], break_prefix="')"),
            {"value": "1"},
        )
        assert synth is not None
        assert synth["payload"].startswith("1')")
        assert synth["payload"].endswith("#")
