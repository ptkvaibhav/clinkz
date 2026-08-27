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


class TestTheArmsAreSessionless:
    """A class claiming "authenticated without a credential" must not start
    the request already authenticated.

    Found by the live run, not by a unit test. On DVWA the login form sits
    inside an app the engagement is logged into and the server re-issues
    PHPSESSID on every request, so all three arms came back carrying an auth
    artifact and the differential was structurally unobservable: six refusals
    with `shape_matched_control_also_authenticated`. The refusal was correct —
    a control that also authenticates proves nothing — but the cause was our
    own session rather than the target.
    """

    @pytest.mark.asyncio
    async def test_the_anonymous_helper_declares_no_session(self) -> None:
        """An empty cookies dict is NOT enough — the jar is ambient."""
        from unittest.mock import AsyncMock, patch

        agent = _agent()
        with patch("clinkz.tools.http_client.HTTPClientTool") as tool_cls:
            tool = tool_cls.return_value
            tool.validate_input.side_effect = lambda a: a
            tool.execute = AsyncMock(return_value="{}")
            tool.parse_output.return_value = type(
                "P", (), {"status_code": 200, "response_body": "", "response_headers": {}}
            )()
            await agent._http_send_anonymous("POST", "http://t/login", form_data={"u": "a"})

        args = tool.validate_input.call_args.args[0]
        assert args["no_session"] is True
        assert args["cookies"] == {}

    @pytest.mark.asyncio
    async def test_form_data_is_encoded_into_the_body(self) -> None:
        """The client takes a body STRING; a dict would be silently dropped."""
        from unittest.mock import AsyncMock, patch

        agent = _agent()
        with patch("clinkz.tools.http_client.HTTPClientTool") as tool_cls:
            tool = tool_cls.return_value
            tool.validate_input.side_effect = lambda a: a
            tool.execute = AsyncMock(return_value="{}")
            tool.parse_output.return_value = type(
                "P", (), {"status_code": 200, "response_body": "", "response_headers": {}}
            )()
            await agent._http_send_anonymous(
                "POST", "http://t/login", form_data={"username": "a b", "password": "p"}
            )

        args = tool.validate_input.call_args.args[0]
        assert args["body"] == "username=a+b&password=p"
        assert args["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    @pytest.mark.asyncio
    async def test_a_target_authored_mutating_verb_is_clamped(self) -> None:
        """The verb can come from a `<form method=...>` the TARGET wrote.

        The session-carrying path clamps to POST/PUT/PATCH; a carrier that did
        not would send an anonymous DELETE from a probe whose whole job is to
        observe a login.
        """
        from unittest.mock import AsyncMock, patch

        agent = _agent()
        with patch("clinkz.tools.http_client.HTTPClientTool") as tool_cls:
            tool = tool_cls.return_value
            tool.validate_input.side_effect = lambda a: a
            tool.execute = AsyncMock(return_value="{}")
            tool.parse_output.return_value = type(
                "P", (), {"status_code": 200, "response_body": "", "response_headers": {}}
            )()
            await agent._http_send_anonymous("DELETE", "http://t/login", json_body={"a": 1})

        assert tool.validate_input.call_args.args[0]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_every_arm_goes_through_the_sessionless_carrier(self) -> None:
        """All three arms, not just the probe — a session on any one of them
        reintroduces the confound."""
        from unittest.mock import AsyncMock

        from clinkz.agents.exploit import PageAnalysis, _AuthBypassCarrier, _HTTPResponse

        agent = _agent()
        page = PageAnalysis(
            url="http://t/login", body="", status=200, input_params=["email", "password"]
        )
        agent._auth_bypass_send_probe = AsyncMock(  # type: ignore[method-assign]
            return_value=(
                _HTTPResponse(status=401, body="{}", headers={}),
                _AuthBypassCarrier(
                    label="arm", sent=True, submitted={}, session_free=True, note=""
                ),
            )
        )
        agent._send_probe = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("an arm used the session-carrying probe")
        )
        agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]
        agent._authenticated_as = ""

        ok, _ = await agent._sqli_verify_auth_bypass(
            page, "email", "1' OR '1'='1'-- -", "1' OR '1'='2'-- -", {"value": "1"}
        )
        assert ok is False
        assert agent._auth_bypass_send_probe.await_count == 3


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


# ---------------------------------------------------------------------------
# FIX A — the LLM synthesizer is structurally unreachable for AUTH_BYPASS
# ---------------------------------------------------------------------------


class TestTheLLMNeverSynthesizesAnAuthBypassPair:
    """Not a preference for the deterministic build — an exclusion.

    The phase-4 prompt has no auth_bypass vocabulary and the ``indicator_type``
    enum it asks for excludes the value, so every pair a model could return here
    is either rejected at phase 5 as an unknown indicator or routed to a
    row-set/error/timing oracle that cannot see the effect — the wrong oracle,
    running against a live login handler. There is no state in which that path
    helps, so the assertion below is about the CALL, not about the result: a
    behavioural test that only checks the returned pair passes just as happily
    against a version that consults the model first and discards its answer.
    """

    @staticmethod
    def _spy(agent) -> object:
        from unittest.mock import AsyncMock

        spy = AsyncMock(side_effect=AssertionError("the LLM synthesizer was called"))
        agent._llm_analyze = spy  # type: ignore[method-assign]
        return spy

    @pytest.mark.asyncio
    async def test_it_is_not_called_even_without_a_confirmed_breakout(self) -> None:
        """``break_prefix is None`` is the state that used to fall through."""
        from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect

        agent = _agent()
        spy = self._spy(agent)
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.AUTH_BYPASS,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"], break_prefix=None),
            {"value": "1"},
        )
        assert spy.await_count == 0
        assert synth is not None
        assert synth["indicator_type"] == "auth_bypass"

    @pytest.mark.asyncio
    async def test_it_is_not_called_when_the_deterministic_table_declines(self) -> None:
        """Declining ABSTAINS. The refactor-proof half of the same rule: one
        `return None` away from the old behaviour, the class would resume asking
        a model that cannot answer."""
        from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect

        agent = _agent()
        spy = self._spy(agent)
        agent._fallback_synthesis_sqli = lambda *a, **kw: None  # type: ignore[method-assign]
        traced: list[dict] = []
        agent._trace_methodology_phase = lambda **kw: traced.append(kw)  # type: ignore[method-assign]

        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.AUTH_BYPASS,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=[], comment_syntax=[], break_prefix=None),
            {"value": "1"},
        )
        assert synth is None
        assert spy.await_count == 0
        assert [t for t in traced if t.get("phase_name") == "auth_bypass_abstained"], (
            "an abstention that leaves no trace reads exactly like a class that was never ranked"
        )

    @pytest.mark.asyncio
    async def test_other_types_still_reach_the_llm_checkpoint(self) -> None:
        """The exclusion is scoped to the one type whose oracle the model cannot
        address — it is not a general retreat from the phase-4 checkpoint."""
        from unittest.mock import AsyncMock

        from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect

        agent = _agent()
        called = AsyncMock(return_value='{"payload": "x", "indicator_type": "error_string"}')
        agent._llm_analyze = called  # type: ignore[method-assign]
        await agent._sqli_phase4_synthesize_payload(
            InjectionType.ERROR_BASED,
            SQLDialect.MYSQL,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"], break_prefix=None),
            {"value": "1"},
        )
        assert called.await_count == 1


# ---------------------------------------------------------------------------
# FIX B — the suppression is keyed on credential possession, not on identity
# ---------------------------------------------------------------------------

#: A token naming the account a `' OR 1=1 --` returns on an application whose
#: first row is the administrator. This is the shape that made the old key
#: wrong: the name is real, the request carried no password for it.
ADMIN = "admin@juice-sh.op"


def _login_page():
    from clinkz.agents.exploit import PageAnalysis

    return PageAnalysis(
        url="http://t/rest/user/login", body="", status=200, input_params=["email", "password"]
    )


def _drive(
    agent,
    *,
    probe_body: str,
    session_free: bool = True,
    submitted: dict[str, str] | None = None,
) -> None:
    """Wire the three arms: probe authenticates, control and benign refuse."""
    from clinkz.agents.exploit import _AuthBypassCarrier, _HTTPResponse

    async def _send(page, param, value, *, label="arm"):
        authenticating = label.startswith("probe")
        return (
            _HTTPResponse(
                status=200 if authenticating else 401, body=probe_body if authenticating else "{}"
            ),
            _AuthBypassCarrier(
                label=label,
                sent=True,
                submitted=dict(submitted or {}),
                session_free=session_free,
                note="" if session_free else "auth-carrying headers ['Cookie']",
            ),
        )

    agent._auth_bypass_send_probe = _send  # type: ignore[method-assign]
    agent._trace_methodology_phase = lambda **kw: None  # type: ignore[method-assign]


class TestTheSuppressionKeyIsCredentialPossession:
    """What the suppression must catch is "we authenticated legitimately and the
    endpoint told us who we are" — which has two routes, a session for the
    principal or a valid credential for it. Identity coincidence proxies that
    badly in both directions, and the expensive direction is the strict one: it
    refuses ``admin@juice-sh.op'--``, a real bypass carrying no password.
    """

    @pytest.mark.asyncio
    async def test_a_real_bypass_naming_the_engagement_identity_confirms(self) -> None:
        agent = _agent()
        agent._authenticated_as = ADMIN
        _drive(
            agent,
            probe_body=json.dumps({"authentication": {"token": _jwt({"email": ADMIN})}}),
            submitted={"email": f"{ADMIN}'-- ", "password": "Clinkz-Probe-1!"},
        )
        ok, observed = await agent._sqli_verify_auth_bypass(
            _login_page(), "email", f"{ADMIN}'-- ", f"{ADMIN}'and'1'='2'-- ", {"value": "1"}
        )
        assert ok is True, observed
        assert "carrier assertion PASSED" in observed

    @pytest.mark.asyncio
    async def test_a_failed_carrier_assertion_keeps_the_engagement_identity(self) -> None:
        """Fail SAFE. The guard may only relax on an arm it checked, so a carrier
        that cannot state it was sessionless returns the class to its stricter
        behaviour rather than inheriting the looser one."""
        agent = _agent()
        agent._authenticated_as = ADMIN
        _drive(
            agent,
            probe_body=json.dumps({"authentication": {"token": _jwt({"email": ADMIN})}}),
            session_free=False,
        )
        ok, observed = await agent._sqli_verify_auth_bypass(
            _login_page(), "email", f"{ADMIN}'-- ", f"{ADMIN}'and'1'='2'-- ", {"value": "1"}
        )
        assert ok is False
        assert "principal_is_an_identity_we_supplied" in observed
        assert "carrier assertion FAILED" in observed

    @pytest.mark.asyncio
    async def test_an_arm_that_submitted_a_valid_credential_is_suppressed(self) -> None:
        """The B-control, as a unit: a sessionless arm that hands over a password
        we hold and know works has LOGGED IN, and a token naming that account
        afterwards demonstrates nothing. Note ``_authenticated_as`` is empty —
        this must be caught by possession alone."""
        from clinkz.engagement.credential_shapes import fingerprint

        agent = _agent()
        agent._authenticated_as = ""
        agent._known_valid_credentials = {ADMIN: fingerprint("admin123")}
        _drive(
            agent,
            probe_body=json.dumps({"authentication": {"token": _jwt({"email": ADMIN})}}),
            submitted={"email": ADMIN, "password": "admin123"},
        )
        ok, observed = await agent._sqli_verify_auth_bypass(
            _login_page(), "email", ADMIN, f"{ADMIN}x", {"value": "1"}
        )
        assert ok is False
        assert "principal_is_an_identity_we_supplied" in observed

    @pytest.mark.asyncio
    async def test_the_same_identity_beside_a_probe_password_is_not_possession(self) -> None:
        """The other direction of the same key: holding a credential for an
        account is not submitting it."""
        from clinkz.engagement.credential_shapes import fingerprint

        agent = _agent()
        agent._authenticated_as = ADMIN
        agent._known_valid_credentials = {ADMIN: fingerprint("admin123")}
        _drive(
            agent,
            probe_body=json.dumps({"authentication": {"token": _jwt({"email": ADMIN})}}),
            submitted={"email": ADMIN, "password": "Clinkz-Probe-1!"},
        )
        ok, observed = await agent._sqli_verify_auth_bypass(
            _login_page(), "email", f"{ADMIN}'-- ", f"{ADMIN}'and'1'='2'-- ", {"value": "1"}
        )
        assert ok is True, observed

    @pytest.mark.asyncio
    async def test_a_wider_supplied_set_does_not_suppress_a_real_bypass(self) -> None:
        """Two held credentials, and the tautology submits neither password.

        The first engagement carrying two credentials is the first real test of
        this keying under a wider supplied set, and the failure mode it guards is
        a silent regression to identity MATCHING: a bypass payload naming the
        admin would be suppressed on every application whose first row is the
        admin, exactly because the engagement happens to hold that account's
        credential. Possession is per-request, so holding two changes nothing —
        neither password rode this request.
        """
        from clinkz.engagement.credential_shapes import fingerprint

        agent = _agent()
        agent._authenticated_as = ADMIN
        agent._known_valid_credentials = {
            ADMIN: fingerprint("admin123"),
            "jim@t": fingerprint("ncc-1701"),
        }
        _drive(
            agent,
            probe_body=json.dumps({"authentication": {"token": _jwt({"email": ADMIN})}}),
            submitted={"email": ADMIN, "password": "Clinkz-Probe-1!"},
        )
        ok, observed = await agent._sqli_verify_auth_bypass(
            _login_page(), "email", f"{ADMIN}'-- ", f"{ADMIN}'and'1'='2'-- ", {"value": "1"}
        )
        assert ok is True, observed

    def test_both_halves_must_ride_the_same_request(self) -> None:
        from clinkz.engagement.credential_shapes import fingerprint

        agent = _agent()
        agent._known_valid_credentials = {
            ADMIN: fingerprint("admin123"),
            "user@t": fingerprint("p"),
        }
        # Identity of one entry, password of another.
        assert agent._identities_authenticated_by({"email": ADMIN, "password": "p"}) == []
        assert agent._identities_authenticated_by({"email": ADMIN, "password": "admin123"}) == [
            ADMIN
        ]

    def test_a_password_shaped_field_is_what_carries_a_credential(self) -> None:
        """The value has to arrive in a password field. An application echoing a
        known password into a display field is not a login attempt."""
        from clinkz.engagement.credential_shapes import fingerprint

        agent = _agent()
        agent._known_valid_credentials = {ADMIN: fingerprint("admin123")}
        assert agent._identities_authenticated_by({"email": ADMIN, "note": "admin123"}) == []

    def test_the_handoff_is_reduced_to_fingerprints_on_the_way_in(self) -> None:
        """The CredentialSet is structurally off this agent and this must not be
        the exception that puts it back."""
        agent = _agent()
        harvested = agent._harvest_known_valid_credentials(
            [
                {"username": ADMIN, "password": "admin123"},
                {"username": "", "password": "x"},
                {"username": "u", "password": ""},
                "not a dict",
            ]
        )
        assert set(harvested) == {ADMIN}
        assert "admin123" not in harvested.values()
        assert agent._harvest_known_valid_credentials(None) == {}


class TestTheCarrierAssertionReadsTheDispatchedRequest:
    """ "Sessionless" is a property of the request that went out. Asserting it
    from the branch that built the request is the assumption this guard exists
    to stop making."""

    def test_an_unrecorded_request_is_not_session_free(self) -> None:
        agent = _agent()
        ok, note = agent._auth_bypass_assert_session_free({})
        assert ok is False
        assert "no dispatched request" in note

    def test_the_ambient_jar_counts(self) -> None:
        agent = _agent()
        ok, note = agent._auth_bypass_assert_session_free(
            {"no_session": False, "cookies": {}, "headers": {}}
        )
        assert ok is False
        assert "no_session" in note

    @pytest.mark.parametrize("header", ["Cookie", "authorization", "X-Auth-Token"])
    def test_an_auth_carrying_header_counts(self, header: str) -> None:
        agent = _agent()
        ok, note = agent._auth_bypass_assert_session_free(
            {"no_session": True, "cookies": {}, "headers": {header: "v"}}
        )
        assert ok is False
        assert header in note
        assert "v" not in note.replace(header, "")

    def test_this_engagements_own_session_header_counts(self) -> None:
        """A target-specific auth header the static vocabulary has never seen is
        still this engagement's session."""
        agent = _agent()
        agent._session_headers = {"X-Juice-Token": "..."}
        ok, _ = agent._auth_bypass_assert_session_free(
            {"no_session": True, "cookies": {}, "headers": {"x-juice-token": "v"}}
        )
        assert ok is False

    def test_an_explicit_cookie_dict_counts(self) -> None:
        agent = _agent()
        ok, note = agent._auth_bypass_assert_session_free(
            {"no_session": True, "cookies": {"PHPSESSID": "x"}, "headers": {}}
        )
        assert ok is False
        assert "PHPSESSID" in note

    def test_a_clean_request_passes(self) -> None:
        agent = _agent()
        ok, note = agent._auth_bypass_assert_session_free(
            {
                "no_session": True,
                "cookies": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            }
        )
        assert (ok, note) == (True, "")

    @pytest.mark.asyncio
    async def test_the_live_carrier_records_what_it_sent_and_passes(self) -> None:
        """End to end through the real builder + the real chokepoint arguments."""
        from unittest.mock import AsyncMock, patch

        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.scan import ParamLocation

        agent = _agent()
        page = PageAnalysis(
            url="http://t/login",
            body="",
            status=200,
            input_params=["email", "password"],
            param_locations={
                "email": ParamLocation.FORM_BODY,
                "password": ParamLocation.FORM_BODY,
            },
        )
        with patch("clinkz.tools.http_client.HTTPClientTool") as tool_cls:
            tool = tool_cls.return_value
            tool.validate_input.side_effect = lambda a: a
            tool.execute = AsyncMock(return_value="{}")
            tool.parse_output.return_value = type(
                "P", (), {"status_code": 401, "response_body": "{}", "response_headers": {}}
            )()
            _resp, carrier = await agent._auth_bypass_send_probe(
                page, "email", "x' OR '1'='1'-- ", label="probe(tautology)"
            )

        assert carrier.sent is True
        assert carrier.session_free is True, carrier.note
        assert carrier.submitted["email"] == "x' OR '1'='1'-- "
        assert carrier.submitted["password"] == agent._benign_param_value("password")

    @pytest.mark.asyncio
    async def test_a_refused_arm_sends_nothing_and_is_not_session_free(self) -> None:
        """Nothing sent is not a sessionless observation — it is no observation,
        and it must not be read as licence to relax the suppression."""
        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.scan import ParamLocation

        agent = _agent()
        page = PageAnalysis(
            url="http://t/register",
            body="",
            status=200,
            input_params=["email", "password"],
            param_locations={
                "email": ParamLocation.FORM_BODY,
                "password": ParamLocation.FORM_BODY,
            },
        )
        agent._body_submission_is_destructive = lambda p: True  # type: ignore[method-assign]
        _resp, carrier = await agent._auth_bypass_send_probe(page, "email", "x", label="benign")
        assert carrier.sent is False
        assert carrier.session_free is False
