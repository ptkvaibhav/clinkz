"""The destructive classifier must refuse production harm without refusing us.

Two failure modes, opposite directions, both fatal:

  * **Too loose** — a probe deletes a production record, changes a password, or
    takes a payment. That is the incident this module exists to prevent.
  * **Too tight** — the classifier reads our OWN payloads as destructive
    semantics and refuses them, quietly reducing an authorized engagement to a
    crawler while every phase still reports success.

The second is the subtle one, so it gets the most cases here.
"""

from __future__ import annotations

import pytest

from clinkz.agents._url_safety import is_destructive_form_submission, is_state_changing_url
from clinkz.safety.destructive import (
    CATEGORY_BULK_MESSAGING,
    CATEGORY_CANCELLATION,
    CATEGORY_CREDENTIAL_CHANGE,
    CATEGORY_DATA_RESET,
    CATEGORY_DELETION,
    CATEGORY_IDENTITY_CHANGE,
    CATEGORY_KEY_REVOCATION,
    CATEGORY_PAYMENT,
    CATEGORY_SECURITY_CONTROL,
    CATEGORY_SESSION_DESTRUCTION,
    CATEGORY_UNSAFE_METHOD,
    classify_form_submission,
    classify_request,
)

# ---------------------------------------------------------------------------
# The categories the engagement contract names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "url", "category"),
    [
        ("DELETE", "https://app.test/api/anything", CATEGORY_UNSAFE_METHOD),
        ("GET", "https://app.test/admin/users/5/delete", CATEGORY_DELETION),
        ("GET", "https://app.test/posts/9?action=delete", CATEGORY_DELETION),
        ("POST", "https://app.test/records/1/purge", CATEGORY_DELETION),
        ("POST", "https://app.test/account/change-password", CATEGORY_CREDENTIAL_CHANGE),
        ("POST", "https://app.test/settings/email", CATEGORY_IDENTITY_CHANGE),
        ("POST", "https://app.test/rest/basket/1/checkout", CATEGORY_PAYMENT),
        ("POST", "https://app.test/billing/invoice/2/refund", CATEGORY_PAYMENT),
        ("POST", "https://app.test/wallet/withdraw", CATEGORY_PAYMENT),
        ("POST", "https://app.test/subscription/cancel", CATEGORY_CANCELLATION),
        ("POST", "https://app.test/account/terminate", CATEGORY_CANCELLATION),
        ("POST", "https://app.test/api/keys/7/revoke", CATEGORY_KEY_REVOCATION),
        ("POST", "https://app.test/newsletter", CATEGORY_BULK_MESSAGING),
        ("POST", "https://app.test/notify?scope=all", CATEGORY_BULK_MESSAGING),
        ("POST", "https://app.test/admin/database/reset", CATEGORY_DATA_RESET),
        ("GET", "https://app.test/logout", CATEGORY_SESSION_DESTRUCTION),
        ("GET", "https://app.test/security.php?phpids=on", CATEGORY_SECURITY_CONTROL),
        ("PUT", "https://app.test/api/Users/1", CATEGORY_UNSAFE_METHOD),
        ("PATCH", "https://app.test/api/orders/3", CATEGORY_UNSAFE_METHOD),
    ],
)
def test_destructive_requests_are_refused_with_the_right_category(
    method: str, url: str, category: str
) -> None:
    verdict = classify_request(method, url)
    assert verdict.refused, f"{method} {url} was NOT refused"
    assert verdict.category == category
    assert verdict.reason, "a refusal must carry a reason an operator can read"
    assert verdict.signal, "a refusal must name the signal that decided it"


# ---------------------------------------------------------------------------
# The engine's own traffic must survive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        # Injection payloads carry the exact vocabulary this module refuses on.
        # Reading a VALUE as semantics would refuse our own probes and reduce an
        # authorized engagement to a crawler, silently.
        "http://t/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
        "http://t/vulnerabilities/sqli/?id=1'; DROP TABLE users--",
        "http://t/vulnerabilities/sqli/?id=1 UNION SELECT 1,2,3--",
        "http://t/vulnerabilities/exec/?ip=127.0.0.1;rm -rf /tmp/x",
        "http://t/vulnerabilities/exec/?ip=127.0.0.1|cat /etc/passwd",
        "http://t/vulnerabilities/fi/?page=../../../../etc/passwd",
        "http://t/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
        "http://t/search?q=%3Cimg%20src%3Dx%20onerror%3Ddelete%3E",
        "http://t/redirect?url=http://evil.example/logout",
    ],
)
def test_our_own_payloads_are_not_read_as_destructive_semantics(url: str) -> None:
    assert not classify_request("GET", url).refused, (
        "the classifier read an injection payload as an application action; "
        "this silently disables the engine against an authorized target"
    )


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", "http://t/vulnerabilities/csrf/"),
        ("GET", "http://t/vulnerabilities/upload/"),
        ("GET", "http://t/vulnerabilities/brute/?username=admin&password=p&Login=Login"),
        ("GET", "http://t/view_source.php?id=fi&security=low"),
        ("GET", "http://t/setup.php"),
        ("POST", "http://t/login.php"),
        ("POST", "http://t/rest/user/login"),
        ("POST", "http://t/api/Users"),
        ("GET", "http://t/rest/track-order/1234"),
        ("GET", "http://t/api/BasketItems"),
        ("POST", "http://t/api/Feedbacks"),
    ],
)
def test_benchmark_surface_stays_reachable(method: str, url: str) -> None:
    assert not classify_request(method, url).refused


def test_csrf_endpoint_is_plannable_but_the_password_change_url_is_not() -> None:
    """The distinction the DVWA regression depends on.

    The bare endpoint must stay crawlable and plannable, or the CSRF class loses
    its target entirely. Only the fully-parameterised password-change URL — the
    one that actually mutates on visit — is refused.
    """
    assert not is_state_changing_url("http://t/vulnerabilities/csrf/")
    assert is_state_changing_url(
        "http://t/vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change"
    )


# ---------------------------------------------------------------------------
# Form submission — the predecessor's rules, preserved
# ---------------------------------------------------------------------------


def _form(method: str, fields: list[dict[str, str]], action: str = "#") -> dict:
    return {"method": method, "action": action, "fields": fields}


def test_login_and_registration_forms_are_still_submittable() -> None:
    login = _form(
        "POST",
        [
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
            {"name": "Login", "type": "submit", "value": "Login"},
        ],
    )
    registration = _form(
        "POST",
        [
            {"name": "email", "type": "email", "value": ""},
            {"name": "password", "type": "password", "value": ""},
            {"name": "passwordRepeat", "type": "password", "value": ""},
        ],
    )
    assert not is_destructive_form_submission(login, "http://t/login.php")
    assert not is_destructive_form_submission(registration, "http://t/api/Users")


def test_password_change_form_is_still_refused() -> None:
    """The incident that produced the predecessor guard, still caught."""
    form = _form(
        "GET",
        [
            {"name": "password_new", "type": "password", "value": ""},
            {"name": "password_conf", "type": "password", "value": ""},
            {"name": "Change", "type": "submit", "value": "Change"},
        ],
    )
    verdict = classify_form_submission(form, "http://t/vulnerabilities/csrf/")
    assert verdict.refused
    assert verdict.category == CATEGORY_CREDENTIAL_CHANGE


def test_button_label_alone_can_refuse_a_form() -> None:
    """A form whose semantics live only in its submit-button text.

    ``{"name": "confirm"}`` says nothing; ``value="Delete my account"`` says
    everything. Reading labels is what the predecessor guard could not do.
    """
    form = _form("POST", [{"name": "confirm", "type": "submit", "value": "Delete my account"}])
    verdict = classify_form_submission(form, "http://t/account")
    assert verdict.refused
    assert verdict.category == CATEGORY_DELETION


def test_database_reset_button_is_refused() -> None:
    form = _form(
        "POST", [{"name": "create_db", "type": "submit", "value": "Create / Reset Database"}]
    )
    assert classify_form_submission(form, "http://t/setup.php").refused


def test_classifier_can_only_refuse_more_than_its_predecessor() -> None:
    """Every predecessor refusal survives; the new categories are additive."""
    legacy_refused = [
        _form("DELETE", [{"name": "id", "type": "hidden", "value": "1"}]),
        _form("POST", [{"name": "delete_user", "type": "submit", "value": "Go"}]),
        _form(
            "POST",
            [
                {"name": "password_current", "type": "password", "value": ""},
                {"name": "password_new", "type": "password", "value": ""},
            ],
        ),
        _form("POST", [{"name": "new_email", "type": "text", "value": ""}]),
    ]
    for form in legacy_refused:
        assert is_destructive_form_submission(form, "http://t/x"), form
