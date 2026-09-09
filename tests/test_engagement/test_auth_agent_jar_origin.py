"""The episode jar never carries one origin's cookies to another."""

from __future__ import annotations

import json
from typing import Any

import pytest

from clinkz.engagement.auth_agent_dispatch import HttpToolDispatcher, _origin


class _FakeHTTP:
    """Records the cookies each request carried, and issues one per origin."""

    sent: list[tuple[str, dict[str, str]]] = []

    def __init__(self, **_kwargs) -> None:
        self.credential_account = ""
        self.credential_control_body = ""
        self.credential_reserve = False

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        return args

    async def execute(self, args: dict[str, Any]) -> str:
        _FakeHTTP.sent.append((args["url"], dict(args.get("cookies") or {})))
        host = _origin(args["url"]).replace("://", "-").replace(":", "-")
        return json.dumps(
            {
                "status_code": 200,
                "response_headers": {},
                "response_body": "",
                "set_cookie": [f"sid-{host}=secret-for-{host}; Path=/"],
            }
        )

    def parse_output(self, raw: str):  # noqa: ANN201
        from clinkz.tools.http_client import HTTPClientOutput

        return HTTPClientOutput(tool_name="http_client", success=True, **json.loads(raw))


@pytest.mark.asyncio
async def test_a_cookie_one_origin_issued_is_never_sent_to_another(monkeypatch) -> None:
    _FakeHTTP.sent = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _FakeHTTP)

    d = HttpToolDispatcher(scope=None, engagement_id="jar-test")
    await d.read("http://a.test/token", "GET")
    await d.read("http://b.test/anything", "GET")
    await d.post_credentials(
        "http://b.test/session",
        content_type="application/json",
        fields={"u": "x", "p": "y"},
        account="x",
    )

    by_url = dict(_FakeHTTP.sent)
    assert by_url["http://a.test/token"] == {}
    assert by_url["http://b.test/anything"] == {}, "a.test's cookie must not reach b.test"
    carried = by_url["http://b.test/session"]
    assert list(carried) == ["sid-http-b.test"], f"leaked across origins: {carried}"


@pytest.mark.asyncio
async def test_the_same_origin_token_still_rides_the_credential_post(monkeypatch) -> None:
    """The capability this must not cost: a token fetched on turn 1, presented on turn 2."""
    _FakeHTTP.sent = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _FakeHTTP)

    d = HttpToolDispatcher(scope=None, engagement_id="jar-test")
    await d.read("http://a.test/csrf", "GET")
    await d.post_credentials(
        "http://a.test/session",
        content_type="application/json",
        fields={"u": "x", "p": "y"},
        account="x",
    )
    carried = dict(_FakeHTTP.sent)["http://a.test/session"]
    assert carried == {"sid-http-a.test": "secret-for-http-a.test"}


@pytest.mark.asyncio
async def test_the_asserter_gets_the_credential_origins_jar_only(monkeypatch) -> None:
    """A union would hand the assertion material the credential never reached."""
    _FakeHTTP.sent = []
    monkeypatch.setattr("clinkz.tools.http_client.HTTPClientTool", _FakeHTTP)

    d = HttpToolDispatcher(scope=None, engagement_id="jar-test")
    await d.read("http://a.test/x", "GET")
    await d.post_credentials(
        "http://b.test/session",
        content_type="application/json",
        fields={"u": "x", "p": "y"},
        account="x",
    )
    assert list(d.jar) == ["sid-http-b.test"]


def test_scheme_is_part_of_the_origin() -> None:
    """https and http on one host are two origins; a cookie must not downgrade."""
    assert _origin("https://a.test/x") != _origin("http://a.test/x")
    assert _origin("http://a.test:8080/x") != _origin("http://a.test/x")
    assert _origin("not a url") == ""
