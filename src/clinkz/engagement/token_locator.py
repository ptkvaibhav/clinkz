"""Where is the session token in this login response? Found by STRUCTURE.

Register D4 / item 4. The adaptive layer reached Juice Shop's ``/rest/user/login``
cold and could not carry what came back, because the response nests its token —
``{"authentication": {"token": "<JWT>", …}}`` — and the reader looked at
top-level keys only. The deterministic arm had the opposite defect: it found the
token through a list of key PATHS whose first entry was commented
``# Juice Shop``, which is a benchmark constant in a list, and a target that
nests one level differently gets nothing.

Both now ask the response's own structure. A value is a session token when:

1. it is **JWT-shaped** — three base64url segments whose first decodes to a JSON
   object naming an ``alg`` — wherever it sits in the tree; or
2. it sits under a key that NAMES a token (``token``, ``access_token``,
   ``jwt``, ``id_token`` and their camel/kebab spellings), at any depth.

A key naming a REFRESH token is never the bearer: it is presented to the token
endpoint, not to the API, and carrying it as ``Authorization`` would prove
nothing. Among candidates the order is: JWT under a token-naming key, JWT
anywhere, opaque value under a token-naming key; ties break on the shallower
path, then the path's spelling, so the answer is a function of the document and
never of dict ordering.

**No model reads the body** — this is the deliberate half of D4. The adaptive
loop shows its model a READ's SHAPE (status, content type, key names), never the
target's text, because the model's answer chooses where a credential is sent: a
body the target authored, in that prompt, would let the target steer the
destination. Locating the token is a parsing problem with a structural answer,
so it is solved here, deterministically, and the model is never asked.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Final

#: Key spellings that name a bearer token, compared after lower-casing and
#: dropping ``_`` and ``-`` — so ``accessToken``, ``access_token`` and
#: ``access-token`` are one name.
TOKEN_KEY_NAMES: Final = frozenset(
    {"token", "accesstoken", "jwt", "idtoken", "authtoken", "bearer"}
)

#: A key naming a refresh token is never the bearer (module docstring).
_REFRESH: Final = "refresh"

#: Three base64url segments, the signature segment allowed empty (``alg: none``).
_JWT_RE: Final = re.compile(r"\A[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\Z")

#: How deep the walk goes. A login response that buries its token deeper than
#: this is not one this engine has seen; the bound keeps a hostile body cheap.
_MAX_DEPTH: Final = 6


def _normalise(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")


def is_jwt(value: str) -> bool:
    """Whether *value* is a JWT by form: its header decodes and names ``alg``."""
    if not _JWT_RE.match(value):
        return False
    head = value.split(".", 1)[0]
    try:
        decoded = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except (ValueError, TypeError):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


def _walk(
    node: Any, path: tuple[str, ...], depth: int, out: list[tuple[tuple[str, ...], str]]
) -> None:
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _walk(value, (*path, str(key)), depth + 1, out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk(value, (*path, f"[{index}]"), depth + 1, out)
    elif isinstance(node, str) and node.strip():
        out.append((path, node.strip()))


def locate_token(body: str) -> tuple[str, str]:
    """The session token a JSON login response carries, and the path it sat at.

    Args:
        body: The raw response body.

    Returns:
        ``(token, dotted_path)``, or ``("", "")`` when the body is not JSON or
        carries no token by either rule. The path is a key path (schema), safe
        to log; the token is session material and is the caller's to protect.
    """
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return "", ""
    leaves: list[tuple[tuple[str, ...], str]] = []
    _walk(parsed, (), 0, leaves)
    ranked: list[tuple[int, int, str, str]] = []
    for path, value in leaves:
        names = [_normalise(part) for part in path if not part.startswith("[")]
        if any(_REFRESH in name for name in names):
            continue
        named = bool(names) and names[-1] in TOKEN_KEY_NAMES
        jwt = is_jwt(value)
        if jwt and named:
            rank = 0
        elif jwt:
            rank = 1
        elif named:
            rank = 2
        else:
            continue
        ranked.append((rank, len(path), ".".join(path), value))
    if not ranked:
        return "", ""
    _, _, where, token = min(ranked)
    return token, where
