"""Driver artifact writes, routed through the engine's redaction chokepoint.

**This module contains no redaction logic of its own.** It calls
:func:`clinkz.engagement.secrets.redact_structure` — the same function the trace
writer, the action log, the state store and the report call — and then
serialises. There is one redactor in this codebase and this is a call site of
it, not a second one.

Why it exists
-------------
The engine's guarantee holds only where the engine writes. A validation driver
is a hand-written script that reaches *around* the writers: it tees the HTTP
chokepoint to capture raw exchanges, then serialises them itself. So the
guarantee simply did not apply, and
``outputs/d8_auth_bypass_live_validation.json`` shipped a complete RS256 session
JWT — signature included, payload decoding to the account record — plus the lab
password in plaintext in three request bodies. The engine was not at fault:
``report.json`` from the same run was clean and the oracle's own ``observed``
field carried a salted fingerprint and claim names only. The driver wrote past
all of it.

Redaction does not cost a driver its evidence. A driver proves *which* token was
accepted where another was refused; a fingerprint answers that and replays
nowhere, which is the whole design of
:mod:`clinkz.engagement.credential_shapes`. ``[REDACTED]`` in a request body
still shows that the field was populated, which is what a control arm asserts.

Hardcoded lab credentials
-------------------------
Shape redaction is always on, but a plaintext password has no shape — it is
removed only because it was *registered*. :mod:`clinkz.engagement.secrets` says
intake is the two functions that read an operator's credential file. A driver
with ``ADMIN_PASSWORD = "admin123"`` at module scope is a third intake route, so
it registers on the way in, exactly like the other two.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:  # a driver may be run before the package is installed
    sys.path.insert(0, str(_SRC))

from clinkz.engagement.secrets import redact, redact_structure, register_secret  # noqa: E402


def register_lab_credential(*values: str) -> None:
    """Register a credential the driver itself hardcodes.

    Args:
        *values: Plaintext secrets. Blank entries are ignored; anything shorter
            than the substring-redaction floor is accepted and reported by
            :mod:`clinkz.engagement.secrets` rather than silently skipped.
    """
    for value in values:
        if value and not register_secret(value):
            print(
                f"  WARNING: a lab credential of length {len(value)} is too short to be "
                "substring-redacted from artifacts; it will appear in this driver's output.",
                file=sys.stderr,
            )


def write_redacted_json(path: Path | str, obj: Any, *, indent: int = 2) -> Path:
    """Serialise *obj* to *path* with every string redacted first.

    Args:
        path: Destination file. Parent directories are created.
        obj: Any JSON-ish structure. Walked by
            :func:`~clinkz.engagement.secrets.redact_structure`, which is
            key-aware, so a ``Set-Cookie`` value is caught by its key even
            though the target chose it and it has no intrinsic shape.
        indent: ``json.dumps`` indent.

    Returns:
        The path written.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Redact the STRUCTURE, not the serialised blob: flattening to text first
    # would lose the keys, and a Set-Cookie value is identified by nothing else.
    payload = json.dumps(redact_structure(obj), indent=indent, default=str)
    out.write_text(payload, encoding="utf-8")
    return out


def write_redacted_text(path: Path | str, text: str) -> Path:
    """Write *text* to *path* with credential shapes and registered values removed.

    For captured stdout and other blobs that were never a structure. Key-aware
    redaction is unavailable here by construction — there are no keys — so this
    catches shapes and registered values only.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(redact(text), encoding="utf-8")
    return out


def redacted(value: Any) -> Any:
    """Redact a value for printing, without writing it anywhere.

    Console output is not a durable artifact, but a driver run under ``tee``
    produces one, and ``outputs/`` already holds three such logs.
    """
    return redact(value) if isinstance(value, str) else redact_structure(value)


__all__ = [
    "redacted",
    "register_lab_credential",
    "write_redacted_json",
    "write_redacted_text",
]
