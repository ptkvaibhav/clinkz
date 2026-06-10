"""Backward-compatibility tests for param-location modelling (fix #4).

``ParamLocation`` plus the new ``Endpoint.content_type`` /
``Endpoint.param_locations`` and ``ExploitTask`` body fields must be purely
*additive*: an endpoint or task constructed the old way (no location data)
behaves exactly as before, and the new fields round-trip through JSON as plain
strings (``ParamLocation`` is a ``StrEnum``).
"""

from __future__ import annotations

from clinkz.models.finding import ExploitTask
from clinkz.models.scan import Endpoint, ParamLocation


def test_endpoint_defaults_are_backward_compatible() -> None:
    """A query-only endpoint built the old way carries no location data."""
    ep = Endpoint(url="http://t/vulnerabilities/sqli/", params=["id"], method="GET")
    assert ep.content_type is None
    assert ep.param_locations == {}
    # params is still the flat name list every existing consumer reads.
    assert ep.params == ["id"]


def test_endpoint_carries_json_body_locations() -> None:
    """A JSON POST endpoint records its content-type and per-param locations."""
    ep = Endpoint(
        url="http://t/api/Feedbacks",
        method="POST",
        params=["comment", "rating"],
        content_type="application/json",
        param_locations={
            "comment": ParamLocation.JSON_BODY,
            "rating": ParamLocation.JSON_BODY,
        },
    )
    assert ep.param_locations["comment"] is ParamLocation.JSON_BODY
    # StrEnum members are plain strings — JSON round-trip yields raw values.
    dumped = ep.model_dump(mode="json")
    assert dumped["content_type"] == "application/json"
    assert dumped["param_locations"] == {"comment": "json_body", "rating": "json_body"}
    assert Endpoint.model_validate(dumped) == ep


def test_param_location_string_values() -> None:
    """The four locations expose the wire strings the builder dispatches on."""
    assert ParamLocation.QUERY == "query"
    assert ParamLocation.JSON_BODY == "json_body"
    assert ParamLocation.FORM_BODY == "form_body"
    assert ParamLocation.PATH == "path"


def test_exploit_task_body_fields_default_safely() -> None:
    """An ExploitTask built the old way defaults to a GET/query shape."""
    task = ExploitTask(test_method="_test_sqli", endpoint_url="http://t/x", tier=1)
    assert task.endpoint_method == "GET"
    assert task.endpoint_content_type is None
    assert task.param_locations == {}


def test_exploit_task_accepts_location_metadata() -> None:
    """An ExploitTask threads the endpoint's method/content-type/locations."""
    task = ExploitTask(
        test_method="_test_xss_stored",
        endpoint_url="http://t/api/Feedbacks",
        endpoint_params=["comment", "rating"],
        endpoint_method="POST",
        endpoint_content_type="application/json",
        param_locations={"comment": ParamLocation.JSON_BODY},
        tier=1,
    )
    assert task.endpoint_method == "POST"
    assert task.endpoint_content_type == "application/json"
    assert task.param_locations["comment"] is ParamLocation.JSON_BODY
