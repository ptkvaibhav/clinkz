"""Redaction by provenance, not by substring (register R30).

Engagement ``e7bd146a`` ran DVWA as ``admin``/``password`` with the intake
refusal disabled. The disclosure gate said CLEAN and the bundle was damaged:
``password_new`` cited as ``[REDACTED]_new`` in the client-facing CSRF evidence,
218 captured pages with ``type="[REDACTED]"``, and the brute-force probe
``wrongpassword0`` recorded as ``wrong[REDACTED]0``. These tests pin each rule
of :mod:`clinkz.engagement.secret_provenance` on the exact strings that run
wrote, and the positive control that keeps the rule honest: an ECHO of the
secret — a unit the target never served without the credential — stays
redacted, and goes red when the control rule is removed.
"""

from __future__ import annotations

import pytest

from clinkz.engagement import secret_provenance
from clinkz.engagement.artifact_scan import scan_integrity
from clinkz.engagement.secrets import (
    clear_secrets,
    observe_control,
    redact,
    redact_structure,
    register_secret,
)

#: DVWA's login form, as the anonymous GET serves it.
DVWA_LOGIN_GET = (
    '<input type="text" class="loginInput" size="20" name="username">'
    '<input type="password" class="loginInput" AUTOCOMPLETE="off" size="20" name="password">'
)


@pytest.fixture(autouse=True)
def _dvwa_engagement() -> None:
    clear_secrets()
    register_secret("password")
    observe_control(DVWA_LOGIN_GET, request_text="http://dvwa/login.php")
    yield
    clear_secrets()


# --------------------------------------------------------------- vocabulary kept


@pytest.mark.parametrize(
    "text",
    [
        # The CSRF evidence the client read.
        "form fields=['step', 'password_new', 'password_conf', 'Change']",
        '<input type="password" AUTOCOMPLETE="off" name="password_new">',
        # The replay corpus's login form, raw and inside a JSON envelope.
        '<input type="password" class="loginInput" name="password">',
        '<input type=\\"password\\" class=\\"loginInput\\" name=\\"password\\">',
        "<input type='password' AUTOCOMPLETE='off' name='password'>",
        # The brute-force class's own probe value.
        "username=admin&password=wrongpassword0&Login=Login",
        # Target prose that NAMES the field.
        "(using password: YES)",
        "mysql_native_password",
        # The engine's own remediation sentence.
        "Require re-authentication for sensitive actions such as changing a password, "
        "an email address",
        "/auth/forgot-password",
    ],
)
def test_vocabulary_survives(text: str) -> None:
    assert redact(text) == text
    assert not scan_integrity(redact(text))


# --------------------------------------------------------------- secret removed


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Bodies the engine CONSTRUCTED: the value of a credential field.
        (
            "username=admin&password=password&Login=Login",
            "username=admin&password=[REDACTED]&Login=Login",
        ),
        (
            '{"username":"admin","password":"password"}',
            '{"username":"admin","password":"[REDACTED]"}',
        ),
        ('{\\"password\\":\\"password\\"}', '{\\"password\\":\\"[REDACTED]\\"}'),
        # Exact value under any name: the default is the secret.
        ('"pw":"password"', '"pw":"[REDACTED]"'),
        ("password", "[REDACTED]"),
        # An echo behind an encoded separator is still an echo.
        ("q=%22password%22", "q=%22[REDACTED]%22"),
        ("\\npassword\\n", "\\n[REDACTED]\\n"),
    ],
)
def test_the_secret_is_removed_where_it_was_placed(text: str, expected: str) -> None:
    assert redact(text) == expected
    assert not scan_integrity(redact(text)), "a correct redaction is not structural damage"


def test_a_structured_credential_field_is_redacted_and_its_key_kept() -> None:
    out = redact_structure({"password": "password", "probe": "wrongpassword0"})
    assert set(out) == {"password", "probe"}
    assert out["password"].startswith("[REDACTED")
    assert out["probe"] == "wrongpassword0"


# ---------------------------------------------------------------- the echo case

#: Units the anonymous login page never served — a reflected credential.
ECHOES = [
    "<td>password</td>",
    '<input name="pw2" value="password">',
    "Hello password, welcome back",
]


@pytest.mark.parametrize("echo", ECHOES)
def test_an_echo_the_anonymous_target_never_served_stays_redacted(echo: str) -> None:
    assert "password" not in redact(echo).replace("pw2", "")


def test_the_echo_control_goes_red_without_the_control_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive control: remove rule 4's fail-closed default and the echoes leak.

    Replaces ``is_secret_occurrence`` with the rule set minus its default — keep
    everything no rule claimed — and asserts the echo case then FAILS. A test
    that cannot fail is not testing the rule.
    """

    def permissive(text: str, start: int, secret: str, controls: frozenset[str]) -> bool:
        return False

    monkeypatch.setattr("clinkz.engagement.secrets.is_secret_occurrence", permissive)
    leaked = [echo for echo in ECHOES if "password" in redact(echo).replace("pw2", "")]
    assert leaked == ECHOES


def test_a_strong_password_is_redacted_in_every_position() -> None:
    """None of the vocabulary rules can claim a value nobody's schema spells."""
    clear_secrets()
    register_secret("Quartz-Meadow-2291")
    for text, expected in [
        ("Quartz-Meadow-2291: too short", "[REDACTED]: too short"),
        ("pw=Quartz-Meadow-2291", "pw=[REDACTED]"),
        ('{"Quartz-Meadow-2291": 1}', '{"[REDACTED]": 1}'),
        ("<b>Quartz-Meadow-2291</b>", "<b>[REDACTED]</b>"),
    ]:
        assert redact(text) == expected


def test_a_request_that_carried_the_secret_teaches_nothing() -> None:
    """A credential POST's response may echo it; it is not a control."""
    clear_secrets()
    register_secret("password")
    learned = observe_control(
        "<td>password</td>", request_text="POST /login username=admin&password=password"
    )
    assert learned == 0
    assert redact("<td>password</td>") == "<td>[REDACTED]</td>"


def test_a_declared_field_name_is_learned_only_from_name_attributes() -> None:
    controls = frozenset(secret_provenance.control_units("<label>password</label>", "password"))
    assert secret_provenance.DECLARED_FIELD + "password" not in controls
    controls = frozenset(secret_provenance.control_units('<input name="password">', "password"))
    assert secret_provenance.DECLARED_FIELD + "password" in controls
