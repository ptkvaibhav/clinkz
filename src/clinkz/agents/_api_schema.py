"""Learn an API endpoint's methods and body schema from what the target serves.

The JS call-site reader (:mod:`clinkz.agents._js_api_mining`) recovers a body
shape only where the frontend's own code touches the body's fields. On a great
deal of real code it does not — ``save(payload) { return http.post(url, payload) }``
names nothing. This module fills that gap from the **live target**, using only
requests that cannot change its state:

* :func:`learn_allowed_methods` — ``OPTIONS`` is defined by RFC 9110 as a safe
  method whose whole purpose is to report the communication options for a
  resource. ``Allow`` / ``Access-Control-Allow-Methods`` is the target telling
  us which verbs its route accepts.
* :func:`learn_body_schema_from_representation` — for a REST collection, the
  fields of ``POST /api/X`` are the fields of the records ``GET /api/X``
  returns. Reading a resource's own representation is a GET.

**What this module deliberately does not do.** The obvious way to learn a
required-field list is to POST an empty body and read the validation error back.
Measured against a live target, that is not a read: two of six endpoints
answered ``201 Created`` and the probe *created records* — an account and an
answer row — during what is supposed to be surface mapping. A discovery step
that registers users is precisely the failure the crawl-safety invariant exists
to prevent, and the return was one field name on one endpoint. Field names read
out of an error response are still used when one arrives — from a request some
methodology was going to send anyway (:func:`field_names_from_error`) — but
nothing here provokes one.

Server-managed fields are stripped from a learned schema: an identifier or a
timestamp the server assigns is not an input, and injecting into one tests the
database's clock rather than the application.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from clinkz.models.scan import Endpoint, ParamLocation

logger = logging.getLogger(__name__)

# --- Bounds ----------------------------------------------------------------
MAX_OPTIONS_PROBES = 40  # routes an OPTIONS sweep may touch
MAX_REPRESENTATION_PROBES = 40  # collections whose representation we read
_MAX_RECORDS_READ = 5  # records sampled from one collection
_MAX_SCHEMA_FIELDS = 40  # field names kept from one representation
_MAX_BODY_BYTES = 2_000_000  # response body parsed as JSON

_WRITE_METHODS = ("POST", "PUT", "PATCH")
_ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

# Fields a server assigns rather than accepts. Generic persistence vocabulary
# (ORM timestamps, soft-delete markers, surrogate keys) — no application names.
_SERVER_MANAGED_RE = re.compile(
    r"^(?:id|_id|uuid|guid|"
    r"created(?:_?at|_?on|_?date)?|updated(?:_?at|_?on|_?date)?|"
    r"deleted(?:_?at|_?on|_?date)?|modified(?:_?at|_?on)?|"
    r"timestamp|version|__v|etag|rev|_rev|href|self|links?)$",
    re.IGNORECASE,
)

# Field names quoted inside a validation error. Covers the phrasings ORMs and
# validators actually emit; every one requires the name to be quoted or
# explicitly labelled, so prose is never mistaken for a schema.
_ERROR_FIELD_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Sequelize: `notNull Violation: Model.field cannot be null`
    re.compile(r"""Violation:\s*[\w.]*?\.?(\w+)\s+cannot be null""", re.IGNORECASE),
    # Generic: `"field" is required` / `'field' cannot be empty`
    re.compile(
        r"""["'`](\w{1,64})["'`]\s+(?:is|was|are)?\s*(?:required|missing|cannot|must)""",
        re.IGNORECASE,
    ),
    # JSON Schema / ajv: `should have required property 'field'`
    re.compile(r"""required property\s+["'`](\w{1,64})["'`]""", re.IGNORECASE),
    # Express/Mongoose: `Path `field` is required`
    re.compile(r"""Path\s+[`"'](\w{1,64})[`"']\s+is required""", re.IGNORECASE),
    # Parameter-named errors: `WHERE parameter "field" has invalid ...`
    re.compile(r"""parameter\s+["'`&][^"'`]*?(\w{1,64})[^"'`]*?["'`&;]""", re.IGNORECASE),
    # `Missing required field: field`
    re.compile(
        r"""(?:missing|unknown|invalid)\s+(?:required\s+)?"""
        r"""(?:field|parameter|argument)s?[:\s]+["'`]?(\w{1,64})""",
        re.IGNORECASE,
    ),
)

# A safe (state-preserving) fetch of an absolute URL with an explicit method.
# Returns ``(status, body, headers)`` or ``None`` on any failure.
ProbeFn = Callable[[str, str], Awaitable["tuple[int, str, dict[str, str]] | None"]]


def _route_key(url: str) -> str:
    """scheme://host/path identity, ignoring query and fragment."""
    parsed = urlsplit(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def is_server_managed(name: str) -> bool:
    """Whether *name* is a field the server assigns rather than accepts."""
    return bool(_SERVER_MANAGED_RE.match((name or "").strip()))


# ---------------------------------------------------------------------------
# OPTIONS — the target's own statement of which methods a route accepts
# ---------------------------------------------------------------------------


def _parse_allowed_methods(headers: dict[str, str]) -> list[str]:
    """HTTP methods the resource itself declares it accepts, from ``Allow``.

    ``Access-Control-Allow-Methods`` is deliberately NOT read as an inventory.
    It is a **CORS policy**, usually one blanket value emitted by middleware for
    every path on the origin; ``Allow`` is the individual resource answering for
    itself. Reading the CORS header as a route inventory against a live target
    manufactured 105 endpoints out of one wildcard header — a hundred write
    endpoints that were never shown to exist, competing for the plan budget with
    the ones that do. A permissive CORS configuration is a finding about the
    origin, not a list of its routes.
    """
    raw = headers.get("allow") or headers.get("Allow") or ""
    out: list[str] = []
    for token in raw.split(","):
        method = token.strip().upper()
        if method in _ALL_METHODS and method not in out:
            out.append(method)
    return out


async def learn_allowed_methods(
    endpoints: list[Endpoint],
    probe: ProbeFn,
    max_probes: int = MAX_OPTIONS_PROBES,
) -> list[Endpoint]:
    """Emit endpoints for methods a route accepts that we had not discovered.

    One ``OPTIONS`` per distinct route, capped. A route whose accepted methods
    include a write verb we have no endpoint for gets one — carrying the same
    param structure the known twin had, since a REST collection's ``PUT`` takes
    what its ``POST`` takes.

    Args:
        endpoints: The endpoints discovered so far.
        probe: Safe-method fetch, ``(method, url) -> (status, body, headers)``.
        max_probes: Maximum routes to probe.

    Returns:
        New endpoints only (never duplicates of the input).
    """
    by_route: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        by_route.setdefault(_route_key(ep.url), []).append(ep)

    # Deterministic order: a concurrent crawl emits a different sequence each
    # run, and which routes fit inside the probe budget must not depend on it.
    routes = sorted(by_route)[:max_probes]
    if len(by_route) > max_probes:
        logger.info(
            "OPTIONS sweep: %d of %d route(s) exceed the %d-probe budget and were not probed",
            len(by_route) - max_probes,
            len(by_route),
            max_probes,
        )

    discovered: list[Endpoint] = []
    for route in routes:
        result = await probe("OPTIONS", route)
        if result is None:
            continue
        status, _body, headers = result
        if status <= 0 or status >= 500:
            continue
        allowed = _parse_allowed_methods(headers)
        if not allowed:
            continue
        known = {(ep.method or "GET").upper() for ep in by_route[route]}
        template = max(by_route[route], key=lambda e: (len(e.param_locations), len(e.params)))
        for method in allowed:
            if method in known or method not in _WRITE_METHODS:
                continue
            discovered.append(
                Endpoint(
                    url=template.url,
                    method=method,
                    params=list(template.params),
                    content_type=template.content_type,
                    param_locations=dict(template.param_locations),
                )
            )
            known.add(method)
    if discovered:
        logger.info("OPTIONS sweep: %d additional method endpoint(s)", len(discovered))
    return discovered


# ---------------------------------------------------------------------------
# Representation — a collection's records name the fields its writes accept
# ---------------------------------------------------------------------------


def record_field_names(payload: Any, _depth: int = 0, _unwrapped: bool = False) -> list[str]:
    """Field names of the **records** in a parsed JSON response body.

    Unwraps the envelope shapes APIs actually use (``{"data": [...]}``,
    ``{"items": [...]}``) and returns the union of the top-level keys of the
    records found, with nested object fields as dotted paths. Server-managed
    fields are excluded.

    A record is required to come from a **collection** — a JSON array of
    objects, or an object reached by unwrapping a named envelope. A bare object
    at the top level is not treated as a record, because the overwhelmingly
    common bare-object response is a *status envelope*
    (``{"status": "...", "body": "..."}``), and reading one as a schema
    proposes ``status`` and ``body`` as request fields the endpoint has never
    accepted.
    """
    if _depth > 3:
        return []
    if isinstance(payload, dict):
        for envelope in ("data", "items", "results", "records", "rows", "content"):
            if envelope in payload:
                return record_field_names(payload[envelope], _depth + 1, _unwrapped=True)
        return _object_field_names(payload) if _unwrapped else []
    if isinstance(payload, list):
        out: list[str] = []
        for record in payload[:_MAX_RECORDS_READ]:
            if not isinstance(record, dict):
                continue
            for name in record_field_names(record, _depth + 1, _unwrapped=True):
                if name not in out:
                    out.append(name)
        return out[:_MAX_SCHEMA_FIELDS]
    return []


def _object_field_names(obj: dict[str, Any], prefix: str = "", _depth: int = 0) -> list[str]:
    """Writable field names of one record object, nested as dotted paths."""
    out: list[str] = []
    for key, value in obj.items():
        if not isinstance(key, str) or not key:
            continue
        if is_server_managed(key):
            continue
        path = f"{prefix}{key}"
        out.append(path)
        if isinstance(value, dict) and _depth < 2:
            out.extend(_object_field_names(value, f"{path}.", _depth + 1))
        if len(out) >= _MAX_SCHEMA_FIELDS:
            break
    return out[:_MAX_SCHEMA_FIELDS]


async def learn_body_schema_from_representation(
    endpoints: list[Endpoint],
    probe: ProbeFn,
    max_probes: int = MAX_REPRESENTATION_PROBES,
) -> int:
    """Fill in missing body schemas from each collection's own representation.

    A write endpoint (``POST``/``PUT``/``PATCH``) with no body params is an
    injection point we cannot reach. When the same route answers a GET with
    JSON records, those records' field names are the schema — that is what REST
    means by a collection. Mutates the matching endpoints **in place** (adding
    ``json_body`` params and a JSON content type) and returns how many were
    filled.

    Only endpoints that have no body params already are touched: a shape read
    from the frontend's own source is more precise than one inferred from a
    representation, and never gets overwritten by it.
    """
    by_route: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        by_route.setdefault(_route_key(ep.url), []).append(ep)

    needy: list[str] = sorted(
        route
        for route, eps in by_route.items()
        if any(
            (ep.method or "GET").upper() in _WRITE_METHODS and not _has_body_params(ep)
            for ep in eps
        )
    )
    probed = needy[:max_probes]
    if len(needy) > max_probes:
        logger.info(
            "Representation sweep: %d of %d route(s) exceed the %d-probe budget",
            len(needy) - max_probes,
            len(needy),
            max_probes,
        )

    filled = 0
    for route in probed:
        result = await probe("GET", route)
        if result is None:
            continue
        status, body, headers = result
        if status < 200 or status >= 300 or not body:
            continue
        content_type = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        if "json" not in content_type and body.lstrip()[:1] not in ("{", "["):
            continue
        if len(body) > _MAX_BODY_BYTES:
            continue
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            continue
        names = [n for n in record_field_names(payload) if n]
        if not names:
            continue
        for ep in by_route[route]:
            if (ep.method or "GET").upper() not in _WRITE_METHODS or _has_body_params(ep):
                continue
            for name in names:
                if name in ep.param_locations:
                    continue
                ep.params.append(name)
                ep.param_locations[name] = ParamLocation.JSON_BODY
            ep.content_type = ep.content_type or "application/json"
            filled += 1
            logger.info(
                "Body schema for %s %s learned from its own representation: %s",
                ep.method,
                ep.url,
                ", ".join(names[:8]),
            )
    return filled


def _has_body_params(endpoint: Endpoint) -> bool:
    """Whether *endpoint* already declares a request-body parameter."""
    return any(
        location in (ParamLocation.JSON_BODY, ParamLocation.FORM_BODY)
        for location in endpoint.param_locations.values()
    )


# ---------------------------------------------------------------------------
# Error responses — read when one arrives, never provoked
# ---------------------------------------------------------------------------


def field_names_from_error(body: str) -> list[str]:
    """Field names an error response names as expected, missing or invalid.

    Applied to responses the engagement already received. Returns ``[]`` for a
    body that names nothing — an error page with no field in it teaches nothing,
    and a plausible-looking word from its prose is not a schema.
    """
    text = (body or "")[:_MAX_BODY_BYTES]
    if not text:
        return []
    out: list[str] = []

    # A structured validator response is the reliable shape; read it as data.
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            payload = None
        if payload is not None:
            out.extend(_structured_error_fields(payload))

    for pattern in _ERROR_FIELD_PATTERNS:
        for match in pattern.finditer(text):
            name = (match.group(1) or "").strip()
            if name and not is_server_managed(name) and name not in out:
                out.append(name)
            if len(out) >= _MAX_SCHEMA_FIELDS:
                return out
    return out[:_MAX_SCHEMA_FIELDS]


def _structured_error_fields(payload: Any, _depth: int = 0) -> list[str]:
    """Field names from a structured validation-error document."""
    if _depth > 4:
        return []
    out: list[str] = []
    if isinstance(payload, dict):
        for key in ("param", "field", "path", "property", "name", "instancePath"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                candidate = value.strip().lstrip("/").replace("/", ".")
                if candidate and not is_server_managed(candidate):
                    out.append(candidate)
        for value in payload.values():
            if isinstance(value, dict | list):
                out.extend(_structured_error_fields(value, _depth + 1))
    elif isinstance(payload, list):
        for item in payload[:_MAX_SCHEMA_FIELDS]:
            out.extend(_structured_error_fields(item, _depth + 1))
    return list(dict.fromkeys(out))[:_MAX_SCHEMA_FIELDS]
