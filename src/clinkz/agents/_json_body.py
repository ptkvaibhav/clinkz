"""Addressing a field *inside* a structured request or response body.

A query parameter is a name. A JSON body field is a **path**: ``comment``,
``user.email``, ``items[0].sku``. Both sides of a methodology need that path —
the request builder, to put a payload on one leaf while leaving the rest of the
body exactly as the application expects it; and the oracle, to say where in the
response structure the value came back.

Everything here is pure and total: no exception escapes, an unresolvable path
yields ``None`` rather than raising, and depth/size are bounded so a hostile
response cannot drive unbounded recursion.

Path grammar (the subset real APIs need, nothing more):

    field
    parent.child
    list[0]
    parent.list[2].child

A path is only ever produced by discovery from a shape the target itself
served, so this never has to parse anything a payload could control.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_MAX_DEPTH = 8  # nesting levels walked in a structure
_MAX_LOCATE_NODES = 20_000  # nodes visited when locating a value
_MAX_INDEX = 64  # largest array index a path may address

_SEGMENT_RE = re.compile(r"([^.\[\]]+)|\[(\d{1,3})\]")

# JSON string escapes a response may apply to a payload before echoing it.
_JSON_UNICODE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def parse_path(path: str) -> list[str | int]:
    """Split a body path into its segments — ``a.b[2].c`` → ``["a","b",2,"c"]``.

    Returns ``[]`` for an empty or malformed path, and clamps array indices to
    :data:`_MAX_INDEX` so a discovered path can never ask for element 900000.
    """
    text = (path or "").strip()
    if not text:
        return []
    segments: list[str | int] = []
    position = 0
    for match in _SEGMENT_RE.finditer(text):
        if match.start() > position and text[position : match.start()] not in (".", ""):
            return []
        position = match.end()
        name, index = match.group(1), match.group(2)
        if index is not None:
            segments.append(min(int(index), _MAX_INDEX))
        elif name:
            segments.append(name)
    if position != len(text):
        return []
    return segments[:_MAX_DEPTH]


def is_nested(path: str) -> bool:
    """Whether *path* addresses something below the top level."""
    return len(parse_path(path)) > 1


def leaf_name(path: str) -> str:
    """The final named segment of *path* — ``user.email`` → ``email``.

    Used to pick a benign sibling value: the *name* of a field is what says
    what a plausible value looks like, and that is the last name in the path.
    """
    for segment in reversed(parse_path(path)):
        if isinstance(segment, str):
            return segment
    return path or ""


def get_json_path(body: Any, path: str) -> Any:
    """Value at *path* inside *body*, or ``None`` when it does not resolve."""
    cursor = body
    for segment in parse_path(path):
        if isinstance(segment, int):
            if not isinstance(cursor, list) or segment >= len(cursor):
                return None
            cursor = cursor[segment]
        else:
            if not isinstance(cursor, dict) or segment not in cursor:
                return None
            cursor = cursor[segment]
    return cursor


def set_json_path(body: dict[str, Any], path: str, value: Any) -> bool:
    """Set *path* inside *body* to *value*, creating containers as needed.

    Everything already in *body* survives: this writes ONE leaf and does not
    touch its siblings, which is the whole point — an endpoint that validates
    its input rejects a body whose unrelated fields were dropped or blanked,
    and the probe then never reaches the injection point at all.

    Returns ``True`` when the write happened. A path that collides with an
    existing value of an incompatible kind (addressing ``a.b`` where ``a`` is a
    string) returns ``False`` rather than silently destroying it.
    """
    segments = parse_path(path)
    if not segments:
        return False
    cursor: Any = body
    for depth, segment in enumerate(segments[:-1]):
        nxt = segments[depth + 1]
        want_list = isinstance(nxt, int)
        if isinstance(segment, int):
            if not isinstance(cursor, list):
                return False
            while len(cursor) <= segment:
                cursor.append([] if want_list else {})
            if not isinstance(cursor[segment], dict | list):
                cursor[segment] = [] if want_list else {}
            cursor = cursor[segment]
            continue
        if not isinstance(cursor, dict):
            return False
        existing = cursor.get(segment)
        if not isinstance(existing, dict | list):
            cursor[segment] = [] if want_list else {}
        cursor = cursor[segment]

    last = segments[-1]
    if isinstance(last, int):
        if not isinstance(cursor, list):
            return False
        while len(cursor) <= last:
            cursor.append(None)
        cursor[last] = value
        return True
    if not isinstance(cursor, dict):
        return False
    cursor[last] = value
    return True


def leaf_paths(paths: list[str]) -> list[str]:
    """Drop paths that merely name a container of another path.

    Discovery reports a nested schema as every level it saw
    (``config``, ``config.app``, ``config.app.name``). Writing a payload to
    ``config`` would replace the whole object the endpoint expects; the field
    to write is the leaf. Order-stable.
    """
    kept: list[str] = []
    for path in paths:
        prefix = path + "."
        if any(other != path and other.startswith(prefix) for other in paths):
            continue
        kept.append(path)
    return kept


# ---------------------------------------------------------------------------
# Response side
# ---------------------------------------------------------------------------


def json_unescape(text: str) -> str:
    """Undo the escaping a JSON encoder applies to a string it emits.

    ``\\u003c`` → ``<``, ``\\/`` → ``/``, ``\\"`` → ``"``. A JSON API that
    echoes a payload escapes it on the way out, and a substring test against
    the raw payload then misses its own reflection — the response-side twin of
    the HTML-entity and SQL-backslash cases the echo comparison already undoes.
    """
    if not text:
        return ""
    decoded = _JSON_UNICODE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return decoded.replace("\\/", "/")


def parse_json_body(body: str, max_bytes: int = 4_000_000) -> Any:
    """Parse a response body as JSON, or ``None`` if it is not JSON."""
    text = (body or "").strip()
    if not text or len(text) > max_bytes or text[:1] not in ("{", "["):
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def locate_value(payload: Any, needle: str, max_hits: int = 8) -> list[str]:
    """Paths inside *payload* whose string value contains *needle*.

    This is what lets an oracle say **where** a value came back rather than
    only that it appears somewhere in the bytes. Position inside a structure is
    the JSON analogue of "in an executable context": a marker echoed at
    ``errors[0].message`` is the API quoting our input back, while the same
    marker at ``data[0].comment`` is the record the application stored.
    """
    if not needle:
        return []
    hits: list[str] = []
    visited = 0

    def walk(node: Any, path: str, depth: int) -> None:
        nonlocal visited
        if depth > _MAX_DEPTH or len(hits) >= max_hits or visited >= _MAX_LOCATE_NODES:
            return
        visited += 1
        if isinstance(node, str):
            if needle in node or needle in json_unescape(node):
                hits.append(path or "$")
            return
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}" if path else str(key), depth + 1)
        elif isinstance(node, list):
            for index, value in enumerate(node[: _MAX_INDEX + 1]):
                walk(value, f"{path}[{index}]", depth + 1)

    walk(payload, "", 0)
    return hits


def locate_in_body(body: str, needle: str, max_hits: int = 8) -> list[str]:
    """:func:`locate_value` over a raw response body; ``[]`` if it is not JSON."""
    payload = parse_json_body(body)
    if payload is None:
        return []
    return locate_value(payload, needle, max_hits=max_hits)
