"""Unit tests for API schema learning (keyless — fake probe, no network).

Two properties carry the weight here:

* **safety** — surface mapping must not write to the target. The learners are
  only ever handed a safe-method probe, and the sweeps must not try to use it
  for anything else; and
* **not inventing surface** — a permissive CORS header and a status envelope
  both *look* like schema information and are not, and both produced concrete
  fabrications against a live target before these rules existed.
"""

from __future__ import annotations

from clinkz.agents._api_schema import (
    field_names_from_error,
    is_server_managed,
    learn_allowed_methods,
    learn_body_schema_from_representation,
    record_field_names,
)
from clinkz.models.scan import Endpoint, ParamLocation

BASE = "http://target.test"


def _probe(responses: dict[tuple[str, str], tuple[int, str, dict[str, str]]], sent: list):
    async def probe(method: str, url: str):
        sent.append((method, url))
        return responses.get((method, url.rstrip("/")))

    return probe


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------


async def test_allow_header_yields_the_write_methods_it_names() -> None:
    sent: list = []
    probe = _probe({("OPTIONS", f"{BASE}/api/items"): (204, "", {"allow": "GET, POST, PUT"})}, sent)
    found = await learn_allowed_methods([Endpoint(url=f"{BASE}/api/items")], probe)
    assert sorted(e.method for e in found) == ["POST", "PUT"]
    assert all(m == "OPTIONS" for m, _ in sent)


async def test_cors_wildcard_is_not_a_route_inventory() -> None:
    """``Access-Control-Allow-Methods`` is a policy, not the resource's ``Allow``.

    Middleware emits one blanket CORS value for every path on the origin.
    Reading it as an inventory manufactured 105 write endpoints out of a single
    header against a live target — a hundred endpoints never shown to exist,
    competing for plan budget with the ones that do.
    """
    sent: list = []
    probe = _probe(
        {
            ("OPTIONS", f"{BASE}/api/items"): (
                204,
                "",
                {"access-control-allow-methods": "GET,HEAD,PUT,PATCH,POST,DELETE"},
            )
        },
        sent,
    )
    assert await learn_allowed_methods([Endpoint(url=f"{BASE}/api/items")], probe) == []


async def test_options_sweep_order_is_deterministic_and_budgeted() -> None:
    sent: list = []
    probe = _probe({}, sent)
    endpoints = [Endpoint(url=f"{BASE}/api/r{i}") for i in range(9, -1, -1)]
    await learn_allowed_methods(endpoints, probe, max_probes=3)
    assert [u for _, u in sent] == sorted(u for _, u in sent)
    assert len(sent) == 3


# ---------------------------------------------------------------------------
# Representation
# ---------------------------------------------------------------------------


async def test_collection_records_become_the_write_body_schema() -> None:
    sent: list = []
    body = '{"status":"ok","data":[{"id":1,"comment":"a","rating":5,"createdAt":"t"}]}'
    probe = _probe(
        {("GET", f"{BASE}/api/notes"): (200, body, {"content-type": "application/json"})}, sent
    )
    post = Endpoint(url=f"{BASE}/api/notes", method="POST")
    assert await learn_body_schema_from_representation([post], probe) == 1
    assert set(post.params) == {"comment", "rating"}  # id/createdAt are server-managed
    assert post.param_locations["comment"] is ParamLocation.JSON_BODY
    assert post.content_type == "application/json"


async def test_a_status_envelope_is_not_a_record() -> None:
    """A bare object response is overwhelmingly a status envelope.

    Reading ``{"status": ..., "body": ...}`` as a record proposed ``status`` and
    ``body`` as request fields the endpoint has never accepted.
    """
    sent: list = []
    probe = _probe(
        {
            ("GET", f"{BASE}/rest/health"): (
                200,
                '{"status":"ok","body":"running"}',
                {"content-type": "application/json"},
            )
        },
        sent,
    )
    post = Endpoint(url=f"{BASE}/rest/health", method="POST")
    assert await learn_body_schema_from_representation([post], probe) == 0
    assert post.params == []


async def test_a_shape_read_from_source_is_never_overwritten() -> None:
    """A body read from the frontend's own code beats one inferred from records."""
    sent: list = []
    probe = _probe(
        {
            ("GET", f"{BASE}/api/notes"): (
                200,
                '{"data":[{"other":1}]}',
                {"content-type": "application/json"},
            )
        },
        sent,
    )
    post = Endpoint(
        url=f"{BASE}/api/notes",
        method="POST",
        params=["precise"],
        param_locations={"precise": ParamLocation.JSON_BODY},
    )
    assert await learn_body_schema_from_representation([post], probe) == 0
    assert post.params == ["precise"]


async def test_an_error_response_that_names_a_field_is_still_read() -> None:
    """The weaker source, used only where the stronger one produced nothing.

    The response has already arrived; reading it provokes nothing. This is what
    a `{}`-POST probe was supposed to buy, without creating records to get it.
    """
    sent: list = []
    probe = _probe(
        {
            ("GET", f"{BASE}/api/notes"): (
                500,
                'Error: WHERE parameter "captchaId" has invalid "undefined" value',
                {"content-type": "text/html"},
            )
        },
        sent,
    )
    post = Endpoint(url=f"{BASE}/api/notes", method="POST")
    assert await learn_body_schema_from_representation([post], probe) == 1
    assert "captchaId" in post.params
    assert [m for m, _ in sent] == ["GET"]  # no extra request was made


async def test_representation_sweep_only_uses_get() -> None:
    sent: list = []
    probe = _probe({}, sent)
    await learn_body_schema_from_representation(
        [Endpoint(url=f"{BASE}/api/notes", method="POST")], probe
    )
    assert {m for m, _ in sent} <= {"GET"}


def test_nested_record_fields_are_dotted_paths() -> None:
    payload = {"data": [{"id": 1, "owner": {"email": "a", "id": 2}}]}
    assert record_field_names(payload) == ["owner", "owner.email"]


def test_server_managed_fields_are_recognised_generically() -> None:
    for name in ("id", "_id", "createdAt", "updated_on", "deletedAt", "__v", "uuid"):
        assert is_server_managed(name), name
    for name in ("comment", "email", "identifier", "created_by"):
        assert not is_server_managed(name), name


# ---------------------------------------------------------------------------
# Error responses — read, never provoked
# ---------------------------------------------------------------------------


def test_field_names_are_read_from_validator_phrasings() -> None:
    assert "comment" in field_names_from_error(
        "SequelizeValidationError: notNull Violation: Feedback.comment cannot be null"
    )
    assert "email" in field_names_from_error("should have required property 'email'")
    assert "token" in field_names_from_error('{"errors":[{"param":"token","msg":"required"}]}')


def test_prose_without_a_named_field_teaches_nothing() -> None:
    assert field_names_from_error("Internal Server Error") == []
    assert field_names_from_error("") == []
    assert field_names_from_error("<html><body>Something went wrong</body></html>") == []
