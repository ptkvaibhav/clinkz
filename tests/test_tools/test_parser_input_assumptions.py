"""Every ``parse_output`` accounted for by what it assumes about its input.

The whatweb defect (D1) was not a coding slip — it was an *assumption* nobody
had written down: that a tool invoked with ``--log-json=-`` gives the JSON log
sole ownership of stdout. whatweb does not. It keeps writing its brief
human-readable log to the same stream, the two interleave, ``json.loads`` on
the blob raises, and 100% of a successful fingerprint was discarded on every
run for the life of the wrapper. The unit suite passed throughout, because the
committed fixture was a hand-authored clean JSON array — the shape we assumed,
not the shape the tool emits.

So the assumption is now a declared, tested property. Each wrapper is listed
with the input shape its parser is built for and *why that is safe for that
tool*, and the test fails when a new wrapper appears without an entry. The
point is not to forbid whole-blob parsing — it is correct for a parser reading
JSON the wrapper itself produced — but to make choosing it a decision someone
made rather than one that got made by default.

No network, no container: the classification is read out of the source.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "clinkz" / "tools"

#: tool module -> (input shape the parser assumes, why that assumption holds).
#:
#: ``self_produced`` is the one case where whole-blob ``json.loads`` is
#: unimpeachable: the bytes were serialised by this wrapper's own ``execute``,
#: so there is no foreign writer to interleave with.
#: ``foreign_stream`` means the bytes come from a third-party process's stdout,
#: where any assumption of sole ownership has to be earned.
PARSER_INPUT_ASSUMPTIONS: dict[str, tuple[str, str]] = {
    "whatweb.py": (
        "foreign_stream",
        "whatweb writes its brief human-readable log to the SAME stdout as "
        "--log-json=-, so the blob is not valid JSON. Whole-blob parse is the "
        "fast path only; a balanced-object scanner recovers each element when "
        "it fails. This is the D1 defect, fixed.",
    ),
    "ffuf.py": (
        "foreign_stream",
        "ffuf prints a banner before its single JSON object. Bounded extract "
        "(first '{' .. last '}') rather than whole-blob, so leading and "
        "trailing prose are already tolerated.",
    ),
    "nuclei.py": (
        "foreign_stream",
        "NDJSON — parsed per line, so a banner or progress line is skipped "
        "rather than poisoning the whole parse. Structurally immune to the "
        "interleaving that broke whatweb.",
    ),
    "httpx_tool.py": (
        "foreign_stream",
        "NDJSON — parsed per line, same structural immunity as nuclei: an "
        "unparseable line costs that line and nothing else.",
    ),
    "katana.py": (
        "foreign_stream",
        "Plain text, one URL per line, filtered on an http prefix. Nothing is "
        "assumed about the surrounding stream at all.",
    ),
    "subfinder.py": (
        "foreign_stream",
        "Plain text, one subdomain per line. No document-level structure to "
        "assume, so there is nothing an interleaved writer could break.",
    ),
    "sqlmap.py": (
        "foreign_stream",
        "Plain text log scanned line by line for its own markers; sqlmap "
        "interleaves progress with results by design and the parser expects it.",
    ),
    "wafw00f.py": (
        "foreign_stream",
        "Plain text report scanned line by line; the banner is part of normal "
        "output and is skipped rather than assumed absent.",
    ),
    "nmap.py": (
        "foreign_stream",
        "XML, extracted between the outermost <nmaprun> bounds before parsing, "
        "so the human-readable summary nmap also prints cannot reach the "
        "parser.",
    ),
    "nikto.py": (
        "foreign_stream",
        "XML, same bounded extract as nmap: the document is cut out of the "
        "stream rather than assumed to be the whole of it.",
    ),
    "installer.py": (
        "foreign_stream",
        "Plain text from a package manager, matched on substrings; no "
        "document structure is assumed, so extra output is inert.",
    ),
    "auth.py": (
        "self_produced",
        "execute() serialises its OWN result dict with json.dumps and "
        "parse_output reads it straight back. No foreign writer shares the "
        "string, so whole-blob json.loads cannot be interleaved with.",
    ),
    "http_client.py": (
        "self_produced",
        "Same shape as auth.py: the wrapper serialises the response itself.",
    ),
}

#: Modules under tools/ that define no ``parse_output`` and so need no entry.
_NO_PARSER = {
    "__init__.py",
    "base.py",
    "binary_identity.py",
    "component_names.py",
    "docker_preflight.py",
    "mcp_client.py",
    "resolver.py",
}


def _modules_defining_parse_output() -> set[str]:
    """Every tools/ module that defines a ``parse_output`` method."""
    found: set[str] = set()
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "parse_output" and path.name != "base.py":
                    found.add(path.name)
    return found


def test_every_parser_declares_what_it_assumes_about_its_input() -> None:
    """A new wrapper cannot inherit the whatweb assumption silently."""
    defined = _modules_defining_parse_output()
    undeclared = defined - set(PARSER_INPUT_ASSUMPTIONS)
    assert not undeclared, (
        f"tools/ modules define parse_output with no input-shape entry: "
        f"{sorted(undeclared)}. Add one, stating whether the bytes are "
        f"self-produced or come from a foreign process's stdout."
    )
    stale = set(PARSER_INPUT_ASSUMPTIONS) - defined - _NO_PARSER
    assert not stale, f"entries for modules that no longer parse: {sorted(stale)}"


def test_every_reason_is_substantive() -> None:
    """A one-word reason is a box tick, not a decision."""
    for module, (shape, reason) in PARSER_INPUT_ASSUMPTIONS.items():
        assert shape in ("self_produced", "foreign_stream"), module
        assert len(reason) > 40, f"{module}: reason is too thin to be a decision"


@pytest.mark.parametrize(
    "module",
    sorted(m for m, (shape, _) in PARSER_INPUT_ASSUMPTIONS.items() if shape == "self_produced"),
)
def test_a_self_produced_claim_is_verified_against_the_source(module: str) -> None:
    """The claim must hold in the code, not only in this table.

    A wrapper claiming ``self_produced`` must actually serialise its own output
    — otherwise the entry documents a wish, and whole-blob parsing on a foreign
    stream is exactly the defect this file exists to prevent.
    """
    source = (TOOLS_DIR / module).read_text(encoding="utf-8")
    assert "json.dumps(" in source, (
        f"{module} claims self_produced but never serialises its own output"
    )


@pytest.mark.parametrize(
    "module",
    sorted(m for m, (shape, _) in PARSER_INPUT_ASSUMPTIONS.items() if shape == "foreign_stream"),
)
def test_no_foreign_stream_parser_parses_the_whole_blob_unguarded(module: str) -> None:
    """A foreign stdout may carry a second writer's output. Assume nothing.

    Bare ``json.loads(raw_output)`` with no per-line split, no bounded extract
    and no object scan is the whatweb shape. Anything reaching for it must
    justify itself here first.
    """
    import clinkz.tools as tools_pkg

    module_name = f"{tools_pkg.__name__}.{module[:-3]}"
    mod = __import__(module_name, fromlist=["*"])
    sources = [
        inspect.getsource(obj.parse_output)
        for obj in vars(mod).values()
        if inspect.isclass(obj) and "parse_output" in vars(obj)
    ]
    for src in sources:
        if "json.loads" not in src:
            continue
        guarded = any(
            marker in src
            for marker in (
                "_top_level_json_objects",  # object scan (whatweb)
                "splitlines",  # NDJSON
                "for line in",  # NDJSON
                "rfind(",  # bounded extract (ffuf)
            )
        )
        assert guarded, (
            f"{module} calls json.loads on a foreign stdout with no per-line "
            f"split, bounded extract, or object scan — the whatweb assumption"
        )


def test_the_recorded_corpus_agrees_that_whatweb_parses_now() -> None:
    """The committed baseline is the evidence, not a claim in a docstring.

    Before the fix, 114 of the 115 baselined whatweb records read
    ``success: false, "JSON parse error"``. The gate was faithfully locking in
    a 99%-failure parser, which is why a green corpus replay never surfaced it.
    """
    baseline = Path(__file__).resolve().parents[1] / "fixtures" / "corpus_replay_baseline.json"
    entries = json.loads(baseline.read_text(encoding="utf-8"))["entries"]
    whatweb = [v for k, v in entries.items() if k.startswith("whatweb:")]
    assert whatweb, "the corpus carries no whatweb records to check"
    failed = [v for v in whatweb if not v.get("success")]
    assert not failed, f"{len(failed)}/{len(whatweb)} recorded whatweb outputs still fail to parse"

    versioned = {
        (tech, version)
        for record in whatweb
        for result in record.get("results", [])
        for tech, version in (result.get("versions") or {}).items()
    }
    # The point of parsing whatweb at all: a component WITH a version is what
    # the published-CVE path matches against. Names alone match nothing
    # version-bounded.
    assert versioned, "whatweb parses but recovers no versioned component"
