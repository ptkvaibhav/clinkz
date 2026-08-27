"""A recon component that RAISED must not look like a target with nothing to find.

Recon is where the component inventory comes from, and the inventory is the
whole input to the published-CVE path: fingerprint → component+version → known
CVE → one of this engine's own oracles. When a recon step raises, that inventory
is empty — and an empty inventory has two causes that are indistinguishable from
every downstream position:

* the target genuinely exposes no versioned component, or
* a parser raised on the tool's real bytes.

Only the component's own failure record separates them. That is not
hypothetical: ``whatweb --log-json=-`` interleaves its human log with the JSON
array, whole-blob ``json.loads`` raised on every run for years, a complete
Apache/PHP fingerprint was discarded every time, and nothing anywhere recorded
that it had happened.

The fingerprinter's handler was fixed in isolation. Its two siblings in the same
file had the identical shape and were not — including ``_step_service_scan``,
the RICHER source of the two, because ``nmap -sV`` resolves a banner to a product
AND a version through nmap's own signature database, already split, which is why
its provenance outranks a ``Server:`` header.

So the domain is COMPUTED (guard-domain law): every ``except`` handler inside a
method that returns a component-bearing model. Only the CLASSIFICATION is
hand-maintained, and an exemption is an entry with a reason rather than a silent
skip. A hand-listed domain is what let two of three handlers sit outside the
check that exists to find them.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_RECON = pathlib.Path(__file__).resolve().parents[2] / "src" / "clinkz" / "agents" / "recon.py"

#: Methods whose return value carries the component inventory (or the header set
#: and body fingerprints that feed it). Computed against the file so a renamed
#: method fails here rather than silently leaving the domain.
_COMPONENT_BEARING_METHODS: frozenset[str] = frozenset({"_step_service_scan", "_step_web_recon"})

_LEDGER_CALLS: frozenset[str] = frozenset(
    {"record_contribution", "record_dead_seam", "record_fallback"}
)

#: Handlers that legitimately record nothing, keyed by a token that appears in
#: the HANDLER's own source (never the try body it guards), with the reason. An
#: exemption is an entry with a reason; there is no silent skip.
_EXEMPT_HANDLERS: dict[str, str] = {
    "WAF detection on": (
        "WAF detection contributes no component and no version - it sets "
        "waf_detected/waf_name, which are not inputs to the CVE path. Its failure "
        "costs a posture note, not an inventory."
    ),
}


def _handler_exemption(handler: ast.ExceptHandler, source: str) -> str:
    """The reason this handler is allowed to record nothing, or ``""``."""
    segment = ast.get_source_segment(source, handler) or ""
    for token, reason in _EXEMPT_HANDLERS.items():
        if token in segment:
            return reason
    return ""


def _records_to_the_ledger(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name in _LEDGER_CALLS:
            return True
    return False


def _component_bearing_handlers() -> list[tuple[str, ast.ExceptHandler]]:
    """The COMPUTED domain: every handler inside a component-bearing method."""
    source = _RECON.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found: list[tuple[str, ast.ExceptHandler]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        if node.name not in _COMPONENT_BEARING_METHODS:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.ExceptHandler):
                found.append((node.name, inner))
    return found


def test_the_domain_is_not_empty() -> None:
    """A walk that finds nothing passes vacuously, which is how this got missed."""
    source = _RECON.read_text(encoding="utf-8")
    tree = ast.parse(source)
    method_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
    }
    missing = _COMPONENT_BEARING_METHODS - method_names
    assert not missing, (
        f"these methods were renamed or removed and this guard's domain silently "
        f"shrank with them: {sorted(missing)}"
    )
    handlers = _component_bearing_handlers()
    assert len(handlers) >= 3, (
        f"expected the three component-bearing handlers this rule is about, found {len(handlers)}"
    )


@pytest.mark.parametrize("method", sorted(_COMPONENT_BEARING_METHODS))
def test_every_component_bearing_handler_reaches_the_ledger(method: str) -> None:
    source = _RECON.read_text(encoding="utf-8")
    unrecorded = [
        handler
        for name, handler in _component_bearing_handlers()
        if name == method
        and not _records_to_the_ledger(handler)
        and not _handler_exemption(handler, source)
    ]
    assert not unrecorded, (
        f"{method} swallows an exception at line(s) "
        f"{[h.lineno for h in unrecorded]} without recording anything. A failed "
        f"component source produces an empty inventory, which is byte-identical to a "
        f"target that has nothing to inventory - and only the component's own "
        f"failure record tells the two apart. Either record it, or add it to "
        f"_EXEMPT_HANDLERS with the reason it contributes nothing."
    )


def test_every_exemption_still_matches_a_handler() -> None:
    """``declared - computed``: an exemption that outlived the code it excused.

    The other half of the guard-domain law. An exemption nobody can reach reads
    as coverage and is not.
    """
    source = _RECON.read_text(encoding="utf-8")
    segments = [
        ast.get_source_segment(source, handler) or ""
        for _, handler in _component_bearing_handlers()
    ]
    stale = [
        token for token in _EXEMPT_HANDLERS if not any(token in segment for segment in segments)
    ]
    assert not stale, (
        f"these handlers are exempted but no longer exist in a component-bearing method: {stale}"
    )


def test_the_failure_note_does_not_reproduce_an_unbounded_tool_message() -> None:
    """A tool error can carry the argv that produced it.

    ``add_note`` redacts, but bounding what reaches the redactor is cheaper than
    trusting it with an unbounded blob of somebody else's process output.
    """
    source = _RECON.read_text(encoding="utf-8")
    assert "str(exc)[:200]" in source
    assert 'f"{exc}"' not in source or source.count("str(exc)[:200]") >= 3
