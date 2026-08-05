"""The disclosure gate — does this bundle still carry credential material?

Everything under ``outputs/<engagement_id>/`` is the deliverable. The report is
the document a client reads, but the trace, the action log, the tool-invocation
records and the step inputs travel with it, and an operator who zips the
directory has handed over all of it. So the contract this module enforces is
stated in one sentence:

    **An artifact handed to a client must never carry a usable session token.**

Not "should not". The engagement's own redaction is supposed to guarantee it —
:mod:`clinkz.engagement.secrets` removes registered values and
:mod:`clinkz.engagement.credential_shapes` removes credential shapes at every
writer. This module exists because that guarantee had already been believed
once while being false. A run against a live target wrote five session JWTs into
its trace, and the check in place at the time reported zero leaks — because the
check searched for the credential values the operator had CONFIGURED, and a
token the target issued is not one of those. The lesson is not "add a pattern".
It is that **a guarantee asserted by the same logic that produces it is not
checked at all**: the scanner has to look at the bytes on disk, with its own
eyes, after everything has been written.

**Two severities, and only one of them fails the gate.**

  * ``credential`` — a definite shape from the shared vocabulary: a JWT whose
    header decodes, an ``Authorization`` value, a cookie value, a vendor API
    key, a PEM private-key block. These fail the run loudly.
  * ``suspicious`` — the entropy heuristic: a long, high-entropy, mixed-charset
    string that no shape rule claimed. Reported, never fatal. This is a
    penetration-testing tool whose evidence is *made of* alarming-looking
    strings — payloads, extracted hashes, base64 from an XXE response — and a
    gate that cried wolf on those would be silenced within a week, which is the
    same as not having one. It is listed so a human can look, not so a machine
    can block.

**The scan report never contains what it found.** A finding carries the kind,
the line and column, the length and a salted fingerprint — never the value, not
even a prefix. A leak report that reproduces the leak is a new artifact with the
same defect.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from pathlib import Path
from typing import Final

from pydantic import BaseModel, Field

from clinkz.engagement.credential_shapes import ShapeHit, find_shapes, fingerprint

logger = logging.getLogger(__name__)

#: Filename the gate writes its own result to, inside the engagement directory.
#: Excluded from scanning so a re-scan is idempotent.
SCAN_REPORT_FILENAME: Final = "artifact_scan.json"

#: Severity meaning "this is credential material" — fails the gate.
SEVERITY_CREDENTIAL: Final = "credential"

#: Severity meaning "this looks like a secret but matched no shape" — advisory.
SEVERITY_SUSPICIOUS: Final = "suspicious"

#: Files never worth scanning as text.
_BINARY_SUFFIXES: Final = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".db", ".sqlite", ".ico"}
)

#: Cap per file. An artifact larger than this is pathological, and the scan must
#: not be the reason a run appears to hang. Truncation is REPORTED, never silent.
_MAX_FILE_BYTES: Final = 64 * 1024 * 1024

#: Candidate tokens for the entropy heuristic.
_ENTROPY_CANDIDATE_RE: Final = re.compile(r"[A-Za-z0-9+/=_-]{32,}")

#: Minimum Shannon entropy, in bits per character, for a candidate to be worth
#: a human's attention. Below this it is a path, an identifier, or English.
_MIN_ENTROPY: Final = 4.2

#: A UUID — engagement ids, step ids, finding ids. Structural, not secret.
_UUID_RE: Final = re.compile(r"\A[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")

#: Pure hex up to a digest length — our own fingerprints, OOB nonces, canaries,
#: content hashes. Reporting every sha256 in the trace would bury the signal.
_HEX_DIGEST_RE: Final = re.compile(r"\A[0-9a-fA-F]{32,64}\Z")

#: How many hits a human-readable rendering lists before summarising the rest.
#: The persisted report is never truncated.
_RENDER_LIMIT: Final = 50


class ArtifactFinding(BaseModel):
    """One credential shape located inside a written artifact.

    Attributes:
        path: Path relative to the scanned root.
        line: 1-indexed line number.
        column: 1-indexed column of the match.
        kind: Shape identifier (``jwt``, ``cookie``, ``entropy``, ...).
        detail: Non-secret description — scheme, cookie name, claim NAMES.
        fingerprint: Salted hash prefix; correlates occurrences, reveals nothing.
        length: Length of the matched value.
        severity: :data:`SEVERITY_CREDENTIAL` or :data:`SEVERITY_SUSPICIOUS`.
    """

    path: str
    line: int
    column: int
    kind: str
    detail: str = ""
    fingerprint: str = ""
    length: int = 0
    severity: str = SEVERITY_CREDENTIAL


class ArtifactScanReport(BaseModel):
    """The gate's verdict over one engagement's artifact directory.

    Attributes:
        engagement_id: Engagement the bundle belongs to.
        root: Absolute path scanned.
        files_scanned: How many files were read.
        bytes_scanned: Total bytes read.
        files_truncated: Files that exceeded the size cap and were read partially.
        findings: Credential-severity hits. Non-empty means the gate FAILED.
        suspicions: Entropy-severity hits. Advisory; never fails the gate.
        errors: Files that could not be read, with the reason.
    """

    engagement_id: str = ""
    root: str = ""
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_truncated: list[str] = Field(default_factory=list)
    findings: list[ArtifactFinding] = Field(default_factory=list)
    suspicions: list[ArtifactFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def clean(self) -> bool:
        """Whether the bundle may be handed over."""
        return not self.findings

    def summary_line(self) -> str:
        """One line for a log, the run summary, or a CLI.

        ASCII only, like every other operator-facing string in the CLI: a
        Windows console on the default code page raised on a U+2192 once and
        killed the command that printed it. A release check must not be the
        thing that crashes.
        """
        if self.clean:
            return (
                f"ARTIFACT SCAN CLEAN - {self.files_scanned} file(s), "
                f"{self.bytes_scanned} bytes, 0 credential shapes"
                + (f", {len(self.suspicions)} advisory" if self.suspicions else "")
            )
        kinds = Counter(f.kind for f in self.findings)
        breakdown = ", ".join(f"{n}x {kind}" for kind, n in sorted(kinds.items()))
        return (
            f"ARTIFACT SCAN FAILED - {len(self.findings)} credential shape(s) "
            f"in {len({f.path for f in self.findings})} file(s): {breakdown}"
        )

    def render(self) -> str:
        """Full human-readable rendering, safe to print anywhere. ASCII only."""
        lines = [self.summary_line()]
        if self.findings:
            lines.append("")
            lines.append("CREDENTIAL MATERIAL (this bundle must not be handed over):")
            for finding in self.findings[:_RENDER_LIMIT]:
                lines.append(
                    f"  {finding.path}:{finding.line}:{finding.column}  "
                    f"{finding.kind}  {finding.detail}  "
                    f"(len={finding.length} sha256={finding.fingerprint})"
                )
            if len(self.findings) > _RENDER_LIMIT:
                # Truncating the RENDERING is fine; truncating the report is
                # not. The full list is in artifact_scan.json either way.
                lines.append(
                    f"  ... and {len(self.findings) - _RENDER_LIMIT} more "
                    f"(full list in {SCAN_REPORT_FILENAME})"
                )
        if self.suspicions:
            lines.append("")
            lines.append("ADVISORY - high-entropy strings matching no known shape:")
            for finding in self.suspicions[:_RENDER_LIMIT]:
                lines.append(
                    f"  {finding.path}:{finding.line}:{finding.column}  "
                    f"len={finding.length} sha256={finding.fingerprint}"
                )
            if len(self.suspicions) > _RENDER_LIMIT:
                lines.append(f"  ... and {len(self.suspicions) - _RENDER_LIMIT} more")
        if self.files_truncated:
            lines.append("")
            lines.append("NOT FULLY SCANNED (exceeded the size cap):")
            lines.extend(f"  {path}" for path in self.files_truncated)
        if self.errors:
            lines.append("")
            lines.append("UNREADABLE:")
            lines.extend(f"  {err}" for err in self.errors)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entropy heuristic
# ---------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character in *value*."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_entropy_candidate(token: str) -> bool:
    """Whether a high-entropy token is worth a human's attention.

    Excludes the structural identifiers this system generates by the thousand —
    UUIDs and hex digests — and anything without the mixed charset a real key
    has. Without these exclusions the advisory list is longer than the trace.
    """
    if _UUID_RE.match(token) or _HEX_DIGEST_RE.match(token):
        return False
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_digit = any(c.isdigit() for c in token)
    if not (has_lower and has_upper and has_digit):
        return False
    return shannon_entropy(token) >= _MIN_ENTROPY


def _entropy_hits(text: str, shape_hits: list[ShapeHit]) -> list[ShapeHit]:
    """Entropy-heuristic hits, excluding regions already claimed by a shape.

    Takes the shape hits rather than recomputing them: the caller has already
    paid for that pass, and these files run to tens of megabytes.
    """
    claimed: list[tuple[int, int]] = [(hit.start, hit.start + hit.length) for hit in shape_hits]
    hits: list[ShapeHit] = []
    for match in _ENTROPY_CANDIDATE_RE.finditer(text):
        start, end = match.start(), match.end()
        if any(start < c_end and end > c_start for c_start, c_end in claimed):
            continue
        token = match.group(0)
        if not _is_entropy_candidate(token):
            continue
        hits.append(
            ShapeHit(
                kind="entropy",
                detail=f"entropy={shannon_entropy(token):.2f} bits/char",
                fingerprint=fingerprint(token),
                start=start,
                length=len(token),
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    """Translate a character offset into 1-indexed line and column."""
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def scan_text(
    text: str, *, path: str = "<text>"
) -> tuple[list[ArtifactFinding], list[ArtifactFinding]]:
    """Scan one blob. Returns ``(credential findings, entropy suspicions)``."""
    shape_hits = find_shapes(text)
    findings: list[ArtifactFinding] = []
    for hit in shape_hits:
        line, column = _line_and_column(text, hit.start)
        findings.append(
            ArtifactFinding(
                path=path,
                line=line,
                column=column,
                kind=hit.kind,
                detail=hit.detail,
                fingerprint=hit.fingerprint,
                length=hit.length,
                severity=SEVERITY_CREDENTIAL,
            )
        )
    suspicions: list[ArtifactFinding] = []
    for hit in _entropy_hits(text, shape_hits):
        line, column = _line_and_column(text, hit.start)
        suspicions.append(
            ArtifactFinding(
                path=path,
                line=line,
                column=column,
                kind=hit.kind,
                detail=hit.detail,
                fingerprint=hit.fingerprint,
                length=hit.length,
                severity=SEVERITY_SUSPICIOUS,
            )
        )
    return findings, suspicions


def scan_artifact_tree(root: Path | str, *, engagement_id: str = "") -> ArtifactScanReport:
    """Scan every file under *root* for credential material.

    Args:
        root: The engagement's artifact directory (``outputs/<engagement_id>``).
        engagement_id: Recorded on the report.

    Returns:
        An :class:`ArtifactScanReport`. ``clean`` is ``False`` when any
        credential-severity shape was found.
    """
    root_path = Path(root)
    report = ArtifactScanReport(engagement_id=engagement_id, root=str(root_path.resolve()))
    if not root_path.is_dir():
        report.errors.append(f"{root_path}: not a directory")
        return report

    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if path.name == SCAN_REPORT_FILENAME:
            continue
        if path.suffix.lower() in _BINARY_SUFFIXES:
            continue
        relative = path.relative_to(root_path).as_posix()
        try:
            size = path.stat().st_size
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(_MAX_FILE_BYTES)
        except OSError as exc:
            report.errors.append(f"{relative}: {exc}")
            continue
        if size > _MAX_FILE_BYTES:
            report.files_truncated.append(relative)
        report.files_scanned += 1
        report.bytes_scanned += len(text)
        findings, suspicions = scan_text(text, path=relative)
        report.findings.extend(findings)
        report.suspicions.extend(suspicions)

    return report


def write_scan_report(report: ArtifactScanReport, root: Path | str) -> Path:
    """Persist the scan result beside the artifacts it scanned."""
    path = Path(root) / SCAN_REPORT_FILENAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    except OSError as exc:  # pragma: no cover — unwritable outputs dir
        logger.warning("Could not write %s: %s", path, exc)
    return path


def run_disclosure_gate(root: Path | str, *, engagement_id: str = "") -> ArtifactScanReport:
    """Scan the bundle, persist the result, and say so at the right volume.

    A clean result is logged at INFO — an operator should be able to see that
    the check ran, because a gate nobody notices is a gate nobody trusts. A
    failure is logged at ERROR with every location, because the bundle must not
    be handed over until it is resolved.

    Args:
        root: The engagement's artifact directory.
        engagement_id: Recorded on the report.

    Returns:
        The :class:`ArtifactScanReport`.
    """
    report = scan_artifact_tree(root, engagement_id=engagement_id)
    write_scan_report(report, root)
    if report.clean:
        logger.info("%s", report.summary_line())
    else:
        logger.error(
            "ARTIFACT DISCLOSURE GATE FAILED — this bundle carries credential "
            "material and must NOT be handed to a client:\n%s",
            report.render(),
        )
    return report


def load_scan_report(root: Path | str) -> ArtifactScanReport | None:
    """Read back a previously written scan report, or ``None``."""
    path = Path(root) / SCAN_REPORT_FILENAME
    if not path.is_file():
        return None
    try:
        return ArtifactScanReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


__all__ = [
    "SCAN_REPORT_FILENAME",
    "SEVERITY_CREDENTIAL",
    "SEVERITY_SUSPICIOUS",
    "ArtifactFinding",
    "ArtifactScanReport",
    "load_scan_report",
    "run_disclosure_gate",
    "scan_artifact_tree",
    "scan_text",
    "shannon_entropy",
    "write_scan_report",
]
