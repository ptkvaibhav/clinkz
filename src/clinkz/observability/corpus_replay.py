"""Offline regression gate over the recorded tool-invocation corpus.

What this is
------------
Every engagement writes ``outputs/<id>/tool_invocations/<seq>_<tool>.json``
carrying the exact command, the exact ``stdout``, and the exit code. Across the
four P7 DVWA engagements that is 6,657 records — 6,582 of them real HTTP
responses from a live target, plus nmap XML, katana crawl output, whatweb and
wafw00f. It is a large, free corpus of real tool output that the parsers are
supposed to understand.

This module re-runs the **parsers** over that recorded output and compares the
result against a committed baseline. No network, no container, no target.

What it deliberately is NOT
--------------------------
``clinkz tool-invoke --replay`` was the obvious starting point and is the wrong
tool for this job. Read it: it calls ``asyncio.create_subprocess_exec`` on the
recorded command, so it re-executes ``docker exec clinkz-tools curl …
http://172.20.0.4/…`` against the live target. It needs the container up and
the target reachable, it re-sends traffic to the client's host, it prints a
diff rather than returning a verdict, and it exits 0 whether or not the output
matched. It is an excellent *interactive debugging* tool and cannot be a gate.

Limits — state these, do not let a green run imply more
-------------------------------------------------------
The corpus is a record of probes that were **already sent**. So this gate
catches a parser or model regression against traffic we have seen, and nothing
else:

* **A new probe shape is not in the corpus.** A methodology that starts sending
  a request nobody has sent before has no recorded response to parse, so a
  green replay says nothing about it. Genuinely new methodology still needs
  live confirmation at the Phase-5 gate.
* **It cannot see the target's behaviour change.** The bytes are frozen at the
  moment they were recorded.
* **It cannot validate the request side** — what we chose to send, and whether
  we should have. Only what we did with the answer.
* **Coverage is whatever the corpus happens to contain.** 98.9% of these
  records are ``http_client``; nmap has 8. A green run is not uniform evidence.

A green replay is never a substitute for a live proof.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clinkz.config import outputs_root as configured_outputs_root

logger = logging.getLogger(__name__)

#: Baseline digest committed alongside the harness. The corpus itself lives
#: under ``outputs/``, which is local-only by policy and never committed, so the
#: digest is the part that travels.
DEFAULT_BASELINE = Path("tests/fixtures/corpus_replay_baseline.json")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InvocationRecord:
    """One recorded tool invocation, read off disk.

    ``exit_code`` is ``int | None`` because a record can be truncated. It was
    read as ``int(data.get("exit_code") or 0)``, and ``0`` is *the tool
    succeeded* — the strongest reading available, manufactured out of a key a
    half-written file never got to. Nothing consults it today, which is exactly
    why the type is the place to fix it: the first consumer that does would
    inherit the wrong answer silently, and the baseline diff would then lock the
    parse of a record that never finished being written.

    ``seq`` and ``duration_ms`` coalesce the same way and are deliberately left
    alone: neither decides anything. ``seq`` is unread, and ``duration_ms``
    reaches only ``_parse_curl_output``'s ``response_time_ms``, which the
    baseline digest does not carry — and curl's own ``__CURL_TIMING__`` marker
    overrides it whenever the recorded stdout has one.
    """

    path: Path
    engagement: str
    seq: int
    tool_name: str
    stdout: str
    exit_code: int | None
    duration_ms: float

    @property
    def stdout_sha(self) -> str:
        """Content address for the recorded output.

        The key into the baseline is ``(tool, stdout_sha)``, not the file path:
        a corpus is re-recorded whenever someone runs the pipeline, and keying
        on paths would make the baseline churn on every run while still missing
        the case where identical bytes start parsing differently.
        """
        return hashlib.sha256(self.stdout.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def key(self) -> str:
        return f"{self.tool_name}:{self.stdout_sha}"


def load_corpus(
    outputs_root: Path | None = None,
    *,
    engagements: list[str] | None = None,
) -> Iterator[InvocationRecord]:
    """Yield every recorded invocation under *outputs_root*.

    Malformed records are skipped with a warning rather than aborting the walk —
    a half-written file from an interrupted run should not take the gate down.
    """
    outputs_root = Path(outputs_root or configured_outputs_root())
    if not outputs_root.exists():
        return
    for engagement_dir in sorted(outputs_root.iterdir()):
        if not engagement_dir.is_dir():
            continue
        if engagements and engagement_dir.name not in engagements:
            continue
        invocations = engagement_dir / "tool_invocations"
        if not invocations.is_dir():
            continue
        for path in sorted(invocations.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping unreadable invocation %s: %s", path, exc)
                continue
            stdout = data.get("stdout")
            if not isinstance(stdout, str):
                continue
            recorded_exit = data.get("exit_code")
            yield InvocationRecord(
                path=path,
                engagement=engagement_dir.name,
                seq=int(data.get("seq") or 0),
                tool_name=str(data.get("tool_name") or ""),
                stdout=stdout,
                # ``None`` when the record does not carry one. NOT zero: zero is
                # "the tool exited successfully", and a truncated record has
                # made no claim about how the tool exited.
                exit_code=int(recorded_exit) if isinstance(recorded_exit, int) else None,
                duration_ms=float(data.get("duration_ms") or 0.0),
            )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _replay_scope() -> Any:
    """A throwaway in-scope target for constructing a tool.

    Replay never sends anything — the scope only has to satisfy the tool's
    constructor. It is deliberately not the corpus's real target, so a replay
    can never be mistaken for, or turn into, traffic.
    """
    from clinkz.models.scope import EngagementScope, ScopeEntry

    return EngagementScope(
        name="corpus-replay",
        targets=[ScopeEntry(value="example.com", type="domain")],
    )


def _parse_http_client(record: InvocationRecord) -> dict[str, Any]:
    """Run the full curl-stdout → HTTPClientOutput pipeline.

    Two stages, because that is what the live path does: ``_parse_curl_output``
    turns raw curl output into the tool's JSON envelope, and ``parse_output``
    turns that envelope into the Pydantic model the agents consume. Replaying
    only the second stage would miss every header/redirect/timing defect.
    """
    from clinkz.tools.http_client import HTTPClientTool

    tool = HTTPClientTool(scope=_replay_scope())
    envelope = tool._parse_curl_output(record.stdout, record.duration_ms)
    parsed = tool.parse_output(envelope)
    return {
        "status_code": parsed.status_code,
        "success": parsed.success,
        "error": parsed.error,
        # Header NAMES only. A value can be a Set-Cookie, and the baseline is a
        # committed artifact — the redaction chokepoint exists precisely so an
        # artifact writer does not have to be trusted to remember.
        "header_names": sorted(parsed.response_headers or {}),
        "body_len": len(parsed.response_body or ""),
        "body_sha": hashlib.sha256(
            (parsed.response_body or "").encode("utf-8", "replace")
        ).hexdigest()[:16],
        "redirect_chain_len": len(parsed.redirect_chain or []),
    }


#: Fields a parse *mints* rather than *reads*. A model that assigns a fresh
#: ``uuid4`` per parsed host differs from itself on every run, so leaving these
#: in would make the gate fail 100% of the time and teach everyone to ignore it.
#: The baseline compares what the parse means, not the identity it stamped.
_NON_DETERMINISTIC_FIELDS: frozenset[str] = frozenset(
    {"id", "uuid", "timestamp", "created_at", "generated_at", "scan_time", "elapsed_ms"}
)


def _canonical(value: Any) -> Any:
    """Strip minted identity and timing so two parses of the same bytes compare."""
    if isinstance(value, dict):
        return {
            k: _canonical(v) for k, v in sorted(value.items()) if k not in _NON_DETERMINISTIC_FIELDS
        }
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def _parse_via_tool(tool_factory: Any) -> Any:
    """Build a replay function for a tool whose parse_output takes raw stdout."""

    def _run(record: InvocationRecord) -> dict[str, Any]:
        parsed = tool_factory().parse_output(record.stdout)
        dumped = parsed.model_dump(mode="json")
        # raw_output is the input, not a parse result; keeping it would make the
        # baseline a copy of the corpus and hide real drift in the noise.
        dumped.pop("raw_output", None)
        return _canonical(dumped)

    return _run


def _nmap_tool() -> Any:
    from clinkz.tools.nmap import NmapTool

    return NmapTool(scope=_replay_scope())


def _katana_tool() -> Any:
    from clinkz.tools.katana import KatanaTool

    return KatanaTool(scope=_replay_scope())


def _whatweb_tool() -> Any:
    from clinkz.tools.whatweb import WhatWebTool

    return WhatWebTool(scope=_replay_scope())


def _wafw00f_tool() -> Any:
    from clinkz.tools.wafw00f import Wafw00fTool

    return Wafw00fTool(scope=_replay_scope())


def _parse_ffuf(record: InvocationRecord) -> dict[str, Any]:
    """Summarise an ffuf parse, ending at the contract the consumer reads.

    Deliberately a summary rather than a full ``model_dump``. Two reasons, and
    the second is the important one:

    * a dump of every hit's nine fields across 300 recorded fuzz runs makes the
      committed baseline ~20 MB, which is a corpus copy rather than a digest;
    * the assertion that matters is ``discovered_urls()`` — the declared
      contract the consumption seam reads. A baseline that captured every field
      *except* that one would go green while the exact defect this gate exists
      to catch reappeared.

    ``command_line`` is excluded: it carries the session ``Cookie:`` header and
    is an input, not a parse result.
    """
    from clinkz.tools.ffuf import FfufTool

    parsed = FfufTool(scope=_replay_scope()).parse_output(record.stdout)
    return {
        "success": parsed.success,
        "error": parsed.error,
        "hits": len(parsed.results),
        # The contract, not just the rows behind it.
        "discovered_urls": sorted(parsed.discovered_urls()),
        "statuses": sorted({r.status for r in parsed.results}),
    }


def _parse_httpx(record: InvocationRecord) -> dict[str, Any]:
    """Summarise an httpx parse, ending at the same declared contract."""
    from clinkz.tools.httpx_tool import HttpxTool

    parsed = HttpxTool(scope=_replay_scope()).parse_output(record.stdout)
    return {
        "success": parsed.success,
        "error": parsed.error,
        "hits": len(parsed.results),
        "discovered_urls": sorted(parsed.discovered_urls()),
        "statuses": sorted({r.status_code for r in parsed.results}),
    }


#: tool_name → a pure function from a record to a canonical parse summary.
#: A tool absent from this map is counted as unreplayable and reported, never
#: silently passed — an unreplayable record is missing coverage, not a success.
PARSERS: dict[str, Any] = {
    "http_client": _parse_http_client,
    "nmap": _parse_via_tool(_nmap_tool),
    "katana": _parse_via_tool(_katana_tool),
    "whatweb": _parse_via_tool(_whatweb_tool),
    "wafw00f": _parse_via_tool(_wafw00f_tool),
    # ffuf was missing here, and the omission rhymes with the defect that
    # motivated it: 304 recorded ffuf invocations sat in the corpus reported as
    # `no-parser`, so the parser regression gate had a hole at exactly the tool
    # whose consumption seam was dead. A gate that does not cover a parser
    # cannot notice that parser breaking.
    "ffuf": _parse_ffuf,
    "httpx": _parse_httpx,
}


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


@dataclass
class ReplayReport:
    """Outcome of replaying a corpus against a baseline."""

    checked: int = 0
    matched: int = 0
    mismatched: list[dict[str, Any]] = field(default_factory=list)
    errored: list[dict[str, Any]] = field(default_factory=list)
    unreplayable: dict[str, int] = field(default_factory=dict)
    new_keys: int = 0

    @property
    def ok(self) -> bool:
        """A parse that changed or started throwing is a failure. New keys are not.

        A corpus recorded after the baseline legitimately contains responses the
        baseline never saw; those are reported as ``new_keys`` and do not fail
        the gate. Only a key that *was* in the baseline and now parses
        differently — or crashes — is a regression.
        """
        return not self.mismatched and not self.errored

    def summary(self) -> str:
        parts = [
            f"checked={self.checked}",
            f"matched={self.matched}",
            f"mismatched={len(self.mismatched)}",
            f"errored={len(self.errored)}",
            f"new={self.new_keys}",
        ]
        if self.unreplayable:
            unreplayable = ", ".join(
                f"{tool}x{count}" for tool, count in sorted(self.unreplayable.items())
            )
            parts.append(f"no-parser=[{unreplayable}]")
        return " ".join(parts)


#: A redaction fingerprint's salted hash prefix. Deliberately unstable across
#: processes — that is what makes a fingerprint correlate inside one bundle and
#: replay nowhere — so it cannot be part of a comparison key.
_FINGERPRINT_RE = re.compile(r"(sha256=)[0-9a-f]{6,}")


def _stabilise(value: Any) -> Any:
    """Blank the salt out of any redaction fingerprint, recursively.

    The corpus gate asks one question: does this recorded stdout still parse to
    the same structure? A salted hash answers a different question, and answers
    it differently every process — so comparing it turns a parser gate into a
    coin flip. Both sides are normalised, so parser drift is still caught while
    the deliberately-unstable part is ignored.
    """
    if isinstance(value, str):
        return _FINGERPRINT_RE.sub(r"\1<salted>", value)
    if isinstance(value, dict):
        return {k: _stabilise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stabilise(v) for v in value]
    return value


def parse_record(record: InvocationRecord) -> dict[str, Any] | None:
    """Parse one record, or return ``None`` when no parser covers its tool."""
    parser = PARSERS.get(record.tool_name)
    if parser is None:
        return None
    return parser(record)


def build_baseline(
    outputs_root: Path | None = None,
    *,
    engagements: list[str] | None = None,
    per_tool_cap: int = 400,
) -> dict[str, Any]:
    """Derive a fresh baseline from the corpus.

    Bounded per tool and selected by sorted content hash, so the sample is
    deterministic and reviewable rather than "whatever the walk hit first" —
    two people regenerating the baseline from the same corpus get the same file.
    """
    by_key: dict[str, dict[str, Any]] = {}
    per_tool: dict[str, list[InvocationRecord]] = {}
    for record in load_corpus(outputs_root, engagements=engagements):
        if record.tool_name not in PARSERS:
            continue
        per_tool.setdefault(record.tool_name, []).append(record)

    for tool, records in sorted(per_tool.items()):
        # Deduplicate identical outputs, then take a deterministic slice.
        unique: dict[str, InvocationRecord] = {}
        for record in records:
            unique.setdefault(record.stdout_sha, record)
        for _sha, record in sorted(unique.items())[:per_tool_cap]:
            try:
                parsed = parse_record(record)
            except Exception as exc:  # noqa: BLE001 — a throwing parser is data
                logger.warning("Parser raised on %s: %s", record.path, exc)
                continue
            if parsed is not None:
                by_key[record.key] = parsed
        logger.info("Baseline: %s → %d unique records", tool, len(unique))

    # The baseline is a committed artifact derived from a real engagement's
    # traffic, so it goes through the same redaction chokepoint every other
    # artifact writer uses. Today's corpus is a benchmark target; the next one
    # regenerated from a client engagement must not depend on someone
    # remembering that.
    from clinkz.engagement.secrets import redact_structure

    return {
        "version": 1,
        "note": (
            "Derived from outputs/<id>/tool_invocations/ by "
            "clinkz.observability.corpus_replay.build_baseline. Keys are "
            "tool:sha256(stdout)[:16]. Regenerate with `clinkz corpus-replay "
            "--rebuild`."
        ),
        "entries": redact_structure(dict(sorted(by_key.items()))),
    }


def replay_corpus(
    baseline: dict[str, Any],
    outputs_root: Path | None = None,
    *,
    engagements: list[str] | None = None,
) -> ReplayReport:
    """Re-parse the corpus and compare against *baseline*.

    Both sides are redacted before comparison. The baseline is a committed
    artifact so it is written through the redaction chokepoint — but the live
    re-parse was compared raw, which makes the gate compare a redacted value
    against an unredacted one and report a parser regression that is really an
    asymmetry in the harness.

    It stayed latent only because no covered parser's output happened to carry
    credential-shaped material; adding ffuf (whose ``command_line`` includes the
    session ``Cookie:`` header) turned every single ffuf record into a false
    mismatch. Redacting the actual keeps the committed baseline safe AND makes
    the comparison like-for-like.
    """
    from clinkz.engagement.secrets import redact_structure

    entries: dict[str, Any] = baseline.get("entries", {})
    report = ReplayReport()
    seen: set[str] = set()

    for record in load_corpus(outputs_root, engagements=engagements):
        parser = PARSERS.get(record.tool_name)
        if parser is None:
            report.unreplayable[record.tool_name] = report.unreplayable.get(record.tool_name, 0) + 1
            continue
        if record.key in seen:
            continue
        seen.add(record.key)

        expected = _stabilise(entries.get(record.key))
        if expected is None:
            report.new_keys += 1
            continue

        report.checked += 1
        try:
            actual = _stabilise(redact_structure(parser(record)))
        except Exception as exc:  # noqa: BLE001 — a throwing parser is the regression
            report.errored.append(
                {
                    "key": record.key,
                    "path": str(record.path),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        if actual == expected:
            report.matched += 1
        else:
            report.mismatched.append(
                {
                    "key": record.key,
                    "path": str(record.path),
                    "expected": expected,
                    "actual": actual,
                }
            )

    return report


def load_baseline(path: Path = DEFAULT_BASELINE) -> dict[str, Any] | None:
    """Read the committed baseline, or ``None`` when it is absent."""
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
