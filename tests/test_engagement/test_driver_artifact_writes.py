"""Validation drivers write through the engine's redaction chokepoint.

The engine's redaction guarantee holds where the engine writes. A driver in
``scripts/`` is a hand-written harness that reaches *around* the writers — it
tees :meth:`HTTPClientTool.execute` to capture raw exchanges and then serialises
them itself — so the guarantee did not apply to it, and nobody noticed for as
long as the drivers have existed.

What it cost: ``outputs/d8_auth_bypass_live_validation.json`` shipped a complete
RS256 session JWT (signature included, payload decoding to the account record)
plus the lab password in plaintext in three request bodies. The engine was not
at fault. ``report.json`` from that same run was clean, and the auth-bypass
oracle's own ``observed`` field carried a salted fingerprint and claim names
only. The driver wrote past all of it.

Two assertions, and the second is the one with a future:

  * the shared write path really removes credential material — a guard not
    observed working is not a guard;
  * **no driver writes into ``outputs/`` any other way**, checked against the
    source. The first assertion protects the drivers that exist; only the second
    protects the one somebody writes next month, and a driver is exactly the
    kind of file a ``src/``-and-``tests/`` grep misses.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from clinkz.engagement.artifact_scan import scan_text
from clinkz.engagement.credential_shapes import reset_fingerprint_salt
from clinkz.engagement.secrets import clear_secrets

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

#: Write calls that put bytes on disk. ``scripts/`` is not a package, so this is
#: read from the source rather than imported.
_WRITE_METHODS = frozenset({"write_text", "write_bytes"})

#: The sanctioned write path.
_REDACTING_WRITERS = frozenset({"write_redacted_json", "write_redacted_text"})

#: Raw writes that are deliberately NOT routed, each with the reason it cannot
#: carry credential material. An entry here is a claim a reader can check; an
#: empty allow-list is the goal, not a requirement.
_ALLOWED_RAW_WRITES: dict[str, str] = {
    "_artifact_io.py": "the chokepoint itself — it is what every other driver routes through",
    "lockfile.py": (
        "not a driver and touches no engagement: it writes requirements-ci.lock at the "
        "repo root from pip's own resolver report — package names and version strings, "
        "no target, no session, no response body. Routing it through the redactor would "
        "claim it handles engagement data, which is the opposite of true."
    ),
}


@pytest.fixture(autouse=True)
def _clean_registry_and_salt():
    clear_secrets()
    reset_fingerprint_salt()
    yield
    clear_secrets()


def _load_artifact_io() -> ModuleType:
    """Import ``scripts/_artifact_io.py`` by path — ``scripts/`` is not a package."""
    spec = importlib.util.spec_from_file_location("_artifact_io", _SCRIPTS / "_artifact_io.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jwt() -> str:
    """A session token shaped like the one the d8 driver actually leaked."""

    def seg(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = seg({"typ": "JWT", "alg": "RS256"})
    body = seg({"iat": 1770000000, "bid": 1, "data": {"email": "admin@juice-sh.op"}})
    return f"{header}.{body}.{'s' * 342}"


# ---------------------------------------------------------------------------
# The write path removes what it is there to remove
# ---------------------------------------------------------------------------


def test_a_teed_exchange_reaches_disk_without_its_session_token(tmp_path: Path) -> None:
    """The exact structure the d8 driver serialises, through the new write path."""
    artifact_io = _load_artifact_io()
    token = _jwt()
    results = {
        "main": {
            "exchanges": [
                {
                    "request": {"url": "http://localhost:3000/rest/user/login", "body": "{}"},
                    "raw_response": json.dumps({"authentication": {"token": token}}),
                }
            ]
        }
    }

    out = artifact_io.write_redacted_json(tmp_path / "d8.json", results)
    written = out.read_text(encoding="utf-8")

    findings, _ = scan_text(written, path="d8.json")
    assert findings == [], "a session token reached the driver's artifact"
    assert token not in written


def test_a_hardcoded_lab_password_is_registered_and_removed(tmp_path: Path) -> None:
    """A driver with ``ADMIN_PASSWORD = "admin123"`` is a third intake route.

    Shape redaction would never catch this: a plaintext password has no shape.
    It is removed only because the driver registers it the way the credential
    loader does.
    """
    artifact_io = _load_artifact_io()
    password = "admin123"
    body = {"exchanges": [{"request": {"body": json.dumps({"password": password})}}]}

    unregistered = artifact_io.write_redacted_json(tmp_path / "before.json", body)
    assert password in unregistered.read_text(encoding="utf-8"), (
        "this test would pass for the wrong reason if shapes already caught it"
    )

    artifact_io.register_lab_credential(password)
    after = artifact_io.write_redacted_json(tmp_path / "after.json", body)
    assert password not in after.read_text(encoding="utf-8")


def test_redaction_leaves_the_driver_its_evidence(tmp_path: Path) -> None:
    """A control arm asserts a field was POPULATED and which token came back.

    If redaction destroyed either, a driver would have a reason to write raw.
    """
    artifact_io = _load_artifact_io()
    accepted, refused = _jwt(), _jwt().replace("s" * 342, "t" * 342)
    out = artifact_io.write_redacted_json(
        tmp_path / "arms.json",
        {"probe": {"token": accepted}, "control": {"token": refused}, "echo": {"token": accepted}},
    )
    written = json.loads(out.read_text(encoding="utf-8"))

    probe = written["probe"]["token"]
    assert probe != written["control"]["token"], "two distinct tokens became indistinguishable"
    assert probe == written["echo"]["token"], "the same token got two different fingerprints"
    assert "sha256=" in probe


# ---------------------------------------------------------------------------
# No driver writes into outputs/ any other way
# ---------------------------------------------------------------------------


def _raw_writes(source: str) -> list[tuple[int, str]]:
    """Every ``x.write_text(...)`` / ``x.write_bytes(...)`` call, with its line."""
    tree = ast.parse(source)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _WRITE_METHODS
        ):
            found.append((node.lineno, node.func.attr))
    return found


@pytest.mark.parametrize("script", sorted(p for p in _SCRIPTS.glob("*.py")), ids=lambda p: p.name)
def test_no_driver_writes_an_artifact_outside_the_chokepoint(script: Path) -> None:
    """Read from the source, so a driver added later is covered without edits."""
    reason = _ALLOWED_RAW_WRITES.get(script.name)
    raw = _raw_writes(script.read_text(encoding="utf-8"))

    if reason:
        assert raw, (
            f"{script.name} is allow-listed for a raw write it no longer has — "
            "delete the entry rather than leaving a stale exemption"
        )
        return

    assert not raw, (
        f"{script.name} writes to disk directly at line(s) "
        f"{', '.join(str(line) for line, _ in raw)}. Driver artifacts go through "
        f"{' / '.join(sorted(_REDACTING_WRITERS))} in scripts/_artifact_io.py, or the "
        f"engine's redaction does not apply to them — which is how a live session "
        f"JWT reached outputs/d8_auth_bypass_live_validation.json. Add an entry to "
        f"_ALLOWED_RAW_WRITES with a reason if this write genuinely cannot carry "
        f"credential material."
    )


def test_every_allow_list_entry_names_a_script_that_exists() -> None:
    """A stale exemption is an exemption nobody re-examines."""
    for name in _ALLOWED_RAW_WRITES:
        assert (_SCRIPTS / name).is_file(), f"_ALLOWED_RAW_WRITES names a missing script: {name}"
