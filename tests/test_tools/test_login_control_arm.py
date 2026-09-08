"""The login verdict has a control arm, and the deterministic pass says what it saw.

Three defects, one run. The engine held the login-page GET and the credential
POST of the same URL, identical byte length, and compared nothing:

* a failure keyword present in a page that carries it **whatever we send** was
  read as "the application refused this credential";
* that keyword rule ran BEFORE the session-evidence rule, so a POST that came
  back setting a session cookie was refused because the page contained a word;
* three facts the deterministic pass had already read — the form declared no
  action, a CSRF field arrived with no matching cookie, the headers name the
  framework — never reached the operator, who was instead offered two remedies
  that were both false.
"""

from __future__ import annotations

from clinkz.safety.lockout import LockoutKind, classify_lockout
from clinkz.tools.auth import (
    AuthResult,
    LoginVerdict,
    WebAuthenticator,
    _csrf_fields_without_cookie,
    _framework_fingerprint,
    _parse_form_fields,
)

_LOGIN_PAGE = (
    "<html><body><form method='post'>"
    "<input type='text' name='username'><input type='password' name='password'>"
    "<p>Enter your credentials. An invalid entry will be rejected.</p>"
    "</form></body></html>"
)


def _verdict(body: str, **kwargs: object):
    defaults: dict[str, object] = {
        "status_code": 200,
        "final_url": "https://app.test/login",
        "login_url": "https://app.test/login",
        "redirect_chain": [],
        "session_evidence": None,
        "carried_session": None,
        "control_body": "",
    }
    defaults.update(kwargs)
    return WebAuthenticator._login_verdict(
        body,
        defaults["status_code"],
        defaults["final_url"],
        defaults["login_url"],
        defaults["redirect_chain"],
        defaults["session_evidence"],
        defaults["carried_session"],
        control_body=defaults["control_body"],
    )


# ---------------------------------------------------------------------------
# The control arm
# ---------------------------------------------------------------------------


def test_a_marker_the_control_also_carries_is_discarded() -> None:
    """The page says "invalid" whether or not a credential was ever sent."""
    judgement = _verdict(
        _LOGIN_PAGE + "<!-- one byte more -->",
        control_body=_LOGIN_PAGE,
    )
    # Not the verdict-carrying phrasing — the discard phrasing.
    assert "the response body carries the refusal marker" not in judgement.evidence
    assert "discarded" in judgement.evidence
    assert "'invalid'" in judgement.evidence


def test_a_marker_only_the_payload_response_carries_still_refuses() -> None:
    """A control arm is not a suppression primitive. A real refusal still refuses."""
    judgement = _verdict(
        "<html><body>Login failed: bad credentials.</body></html>",
        control_body=_LOGIN_PAGE,
    )
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "refusal marker" in judgement.evidence
    assert "which the login page served without credentials does not" in judgement.evidence


def test_with_no_control_the_rule_behaves_exactly_as_it_did() -> None:
    """A caller holding no control gets the old answer, not a worse one."""
    judgement = _verdict("<html>Invalid username or password</html>")
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "refusal marker" in judgement.evidence


def test_session_evidence_outranks_the_keyword() -> None:
    """A POST that set a session cookie is not refused because a page has a word."""
    judgement = _verdict(
        "<html>Welcome. Report an invalid listing here.</html>",
        session_evidence={"PHPSESSID": "abc"},
    )
    assert judgement.verdict is LoginVerdict.PROVEN
    assert "PHPSESSID" in judgement.evidence


def test_a_token_in_the_body_outranks_the_keyword_too() -> None:
    judgement = _verdict(
        '{"token": "aaa.bbb.ccc", "notice": "invalid coupons are ignored"}',
        control_body=_LOGIN_PAGE,
    )
    assert judgement.verdict is LoginVerdict.PROVEN


# ---------------------------------------------------------------------------
# Identical byte length is its own verdict
# ---------------------------------------------------------------------------


def test_a_byte_identical_response_says_the_post_did_nothing() -> None:
    judgement = _verdict(_LOGIN_PAGE, control_body=_LOGIN_PAGE)
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "byte-identical" in judgement.evidence
    assert "changed nothing" in judgement.evidence
    assert str(len(_LOGIN_PAGE)) in judgement.evidence


def test_the_same_length_but_different_bytes_says_so_precisely() -> None:
    """Same length is the observation; byte-identical is a stronger one."""
    other = "X" * len(_LOGIN_PAGE)
    judgement = _verdict(other, control_body=_LOGIN_PAGE)
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "the same length as" in judgement.evidence
    assert "byte-identical" not in judgement.evidence


def test_the_no_effect_rule_runs_ahead_of_the_deferral() -> None:
    """A response that IS the login page leaves nothing to defer WITH.

    The INDETERMINATE branch exists for a framework that promoted its pre-login
    session in place — which still renders a DIFFERENT page once that session is
    authenticated. A byte-identical one is the login page again.
    """
    judgement = _verdict(
        _LOGIN_PAGE,
        control_body=_LOGIN_PAGE,
        carried_session={"sessionid": "pre-login"},
    )
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "changed nothing" in judgement.evidence


def test_a_promoted_session_still_defers() -> None:
    """The shape the third value exists for is untouched by any of this."""
    judgement = _verdict(
        "<html><body>Your dashboard</body></html>",
        control_body=_LOGIN_PAGE,
        carried_session={"sessionid": "pre-login"},
    )
    assert judgement.verdict is LoginVerdict.INDETERMINATE


def test_a_4xx_is_still_never_a_success() -> None:
    judgement = _verdict("", status_code=401, control_body=_LOGIN_PAGE)
    assert judgement.verdict is LoginVerdict.REFUSED
    assert "401" in judgement.evidence


# ---------------------------------------------------------------------------
# The same treatment for the classifier that STOPS the run
# ---------------------------------------------------------------------------


def test_a_lockout_phrase_the_control_carries_does_not_stop_the_run() -> None:
    nav = "<nav><a href='/vulnerabilities/captcha'>Insecure CAPTCHA</a></nav>"
    signal = classify_lockout(200, {}, nav + "<p>Login failed</p>", nav)
    assert not signal
    assert signal.discarded == ("invalid captcha",) or not signal.discarded


def test_a_real_lockout_still_stops_the_run() -> None:
    signal = classify_lockout(
        200, {}, "<p>Your account has been locked.</p>", "<p>Please sign in.</p>"
    )
    assert signal.kind is LockoutKind.LOCKOUT
    assert signal.marker == "account has been locked"


def test_a_header_signal_is_not_control_compared() -> None:
    """A Retry-After is the server naming a wait; it cannot be page furniture."""
    signal = classify_lockout(200, {"Retry-After": "60"}, "body", "body")
    assert signal.kind is LockoutKind.RATE_LIMIT


def test_without_a_control_lockout_classification_is_unchanged() -> None:
    signal = classify_lockout(200, {}, "<p>too many attempts</p>")
    assert signal.kind is LockoutKind.LOCKOUT


# ---------------------------------------------------------------------------
# Part 3 — what the deterministic pass already knows
# ---------------------------------------------------------------------------


def test_a_form_with_no_action_is_recorded_as_declaring_no_destination() -> None:
    form = _parse_form_fields(_LOGIN_PAGE)
    assert form.from_form is True
    assert form.form_action == ""


def test_inputs_outside_any_form_are_a_different_fact() -> None:
    loose = _parse_form_fields("<input type='text' name='user'><input type='password' name='pw'>")
    assert loose.from_form is False


def test_a_csrf_field_with_no_matching_cookie_is_named() -> None:
    assert _csrf_fields_without_cookie({"csrfToken": "abc"}, {}) == ["csrfToken"]
    assert (
        _csrf_fields_without_cookie({"csrfToken": "abc"}, {"next-auth.csrf-token": "abc|def"}) == []
    )
    # A session cookie is not a CSRF cookie; half a double-submit is still half.
    assert _csrf_fields_without_cookie({"csrfToken": "abc"}, {"PHPSESSID": "x"}) == ["csrfToken"]
    # Nothing CSRF-shaped in the form: nothing to report.
    assert _csrf_fields_without_cookie({"return_to": "/"}, {}) == []


def test_the_framework_is_read_off_protocol_artifacts() -> None:
    assert "Next.js" in _framework_fingerprint({"X-Powered-By": "Next.js"})
    rsc = _framework_fingerprint({"Vary": "RSC, Next-Router-State-Tree, Accept-Encoding"})
    assert "React Server Components" in rsc
    assert "rsc" in rsc
    # Nothing named a stack: the honest answer is nothing, never a guess.
    assert _framework_fingerprint({"Content-Type": "text/html"}) == ""
    assert _framework_fingerprint(None) == ""


def test_the_three_true_statements_replace_the_two_false_remedies() -> None:
    """The sentence the operator is owed, assembled from what was observed."""
    result = AuthResult(
        login_url="https://cal.diy/auth/login",
        posted_to="https://cal.diy/auth/login",
        form_action_declared=False,
        page_declared_a_form=True,
        post_changed_nothing=True,
        csrf_fields_without_cookie=["csrfToken"],
        framework_fingerprint="X-Powered-By: Next.js",
    )
    facts = result.deterministic_observations()
    joined = " | ".join(facts)
    assert "declared no action" in joined
    assert "changed nothing" in joined
    assert "csrfToken" in joined
    assert "Next.js" in joined
    assert len(facts) == 4


def test_a_clean_login_page_states_nothing_it_did_not_observe() -> None:
    """A result that observed nothing unusual must not manufacture a complaint."""
    assert AuthResult().deterministic_observations() == []


def test_a_discard_is_reported_so_a_consumer_can_still_stop_on_it() -> None:
    """The control decides the CLAIM; each consumer decides its own STOP.

    ``_test_brute_force`` breaks on ``signal.discarded`` as well as on a signal,
    because a login page already displaying a lockout notice is the case where
    continuing is worst and a shorter series is cheap. The governor does not,
    because a stop there halts the engagement and asserts the client account is
    locked — bounded instead by max_credential_attempts_per_account.
    """
    nav = "<p>Subject to our rate limit policy.</p>"
    signal = classify_lockout(200, {}, nav + "<p>Wrong password</p>", nav)
    assert not signal, "the CLAIM must not survive a phrase the control carries"
    assert signal.discarded, "the discard has to be visible or no consumer can stop on it"
