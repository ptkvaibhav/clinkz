"""The session token is found by the response's STRUCTURE, never by a path list.

D4 / item 4: the adaptive layer reached Juice Shop's login route cold and could
not carry ``{"authentication": {"token": <JWT>}}``, because it read top-level
keys only. The deterministic arm found the same token through a key-path list
whose first entry was commented ``# Juice Shop``. One structural locator now
serves both, and no benchmark nesting appears in any list.
"""

from __future__ import annotations

import base64
import json

import pytest

from clinkz.engagement.auth_agent import DispatchResponse
from clinkz.engagement.token_locator import is_jwt, locate_token
from clinkz.tools.auth import WebAuthenticator


def _jwt(claims: dict[str, object]) -> str:
    def seg(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(claims)}.c2lnbmF0dXJlLXZhbHVl"


JWT = _jwt({"status": "success", "data": {"id": 1}})
JUICE_SHOP_LOGIN = json.dumps({"authentication": {"token": JWT, "bid": 1, "umail": "a@b.c"}})


def test_the_juice_shop_nesting_is_found_by_structure() -> None:
    assert locate_token(JUICE_SHOP_LOGIN) == (JWT, "authentication.token")


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"token": "abc"}, "abc"),
        ({"access_token": "xyz"}, "xyz"),
        ({"data": {"token": "ddd"}}, "ddd"),
        ({"result": {"session": {"accessToken": "deep"}}}, "deep"),
        ({"payload": [{"jwt": JWT}]}, JWT),
        ({"unnamed": JWT}, JWT),
    ],
)
def test_any_nesting_any_spelling(body: dict[str, object], expected: str) -> None:
    assert locate_token(json.dumps(body))[0] == expected


def test_a_jwt_under_a_token_name_outranks_an_opaque_one() -> None:
    body = {"token": "opaque", "auth": {"id_token": JWT}}
    assert locate_token(json.dumps(body))[0] == JWT


def test_a_refresh_token_is_never_the_bearer() -> None:
    assert locate_token(json.dumps({"refresh_token": JWT})) == ("", "")
    assert locate_token(json.dumps({"refreshToken": JWT, "accessToken": "a1"}))[0] == "a1"


@pytest.mark.parametrize("body", ['{"foo": "bar"}', '{"token": "   "}', "<html>x</html>", '["a"]'])
def test_no_token_is_no_token(body: str) -> None:
    assert locate_token(body) == ("", "")


def test_is_jwt_reads_the_header_not_the_dots() -> None:
    assert is_jwt(JWT)
    assert not is_jwt("version.1.2")
    assert not is_jwt("aaaaaaaaaa.bbbbbbbbbb.cccc")


def test_the_adaptive_layer_carries_a_nested_token() -> None:
    """The defect itself: a response that issued a token read as "no token"."""
    response = DispatchResponse(status=200, body=JUICE_SHOP_LOGIN)
    assert response.credential_session_material
    assert response.session_headers() == {"Authorization": f"Bearer {JWT}"}
    assert JWT not in response.redacted_body_excerpt(10_000)


def test_the_deterministic_arm_uses_the_same_locator() -> None:
    assert WebAuthenticator._extract_token(JUICE_SHOP_LOGIN) == JWT


def test_no_benchmark_nesting_survives_in_a_constant() -> None:
    """``("authentication", "token")`` was a Juice Shop constant in a list."""
    import clinkz.tools.auth as auth

    assert not hasattr(auth, "_TOKEN_JSON_PATHS")
