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

**Two regions, because the first one was too small.** The gate reported CLEAN
over 3,123 files while a live JWT sat one directory up, in
``outputs/d8_auth_bypass_live_validation.json`` — a companion artifact written
by a validation driver, outside every engagement's root and therefore outside
every scan. The verdict was true and useless: it answered a question about a
region chosen so as to exclude where the leak landed, which is the same defect
shape as a tree-scanning leak guard that cannot see a pull request's own text.

So a run scans two regions and returns ONE verdict:

  * :data:`REGION_BUNDLE` — ``outputs/<engagement_id>/``, this engagement's
    deliverable.
  * :data:`REGION_COMPANION` — everything else under the outputs root that no
    engagement's gate will ever cover: loose files, driver output directories,
    anything a hand-written script dropped beside the bundles.

They are one verdict because the operator's question is "may I share what is in
this directory", and two regions because "your bundle is clean, the directory
around it is not" is a different instruction from "your bundle leaked". Every
finding carries its :attr:`~ArtifactFinding.region` and the rendering keeps them
apart.

A directory whose name is an engagement id belongs to some other engagement's
bundle, so it is not swept into this one's verdict — a run must not be told to
answer for a leak it did not write.

**Every file this gate does not read is named, and an unexplained one FAILS.**
The region gap above was the second guard in a month to report CLEAN over
somewhere it never looked, and a silently skipped file is the mechanism every
time: the verdict is true about the bytes examined and is read as a statement
about the directory. So the skip list is inverted. :data:`_SKIP_ALLOWED` is an
allow-list keyed by suffix, each entry carrying *the reason that suffix is not
read*, and anything skipped without an entry — an unreadable file, a format no
extractor handles, a file over the size cap — is recorded with an empty reason
and makes :attr:`~ArtifactScanReport.clean` ``False``. The counts are in
:meth:`~ArtifactScanReport.summary_line` next to the scanned ones, because a
coverage number that omits what it declined to look at is the same defect one
level down.

Note what the allow reasons do NOT claim. ``.db`` is skipped because this gate
has no SQLite reader, not because a SQLite file is safe — its ``TEXT`` columns
sit in page data in plaintext. The reason strings say so. An allowed skip is a
disclosed hole, never an absolution.

**A PDF is read through two channels, because each is blind to the other.**
Page text lives in Flate-compressed content streams and document metadata in a
separate ``/Info`` dictionary; a byte scan of the file sees neither, and an
extractor that reads only pages misses a token pasted into ``/Title`` (and the
reverse). Both are pulled — via :mod:`pypdf`, the one dependency here with a
consumer — into a single blob with ``[metadata]`` / ``[page N]`` markers, so a
reported line number still tells an operator where to look. A PDF that cannot
be parsed is an unexplained skip, not a clean file.
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

#: Region: inside the engagement's own artifact directory.
REGION_BUNDLE: Final = "bundle"

#: Region: elsewhere under the outputs root — a companion artifact no
#: engagement's gate covers. See the module docstring.
REGION_COMPANION: Final = "companion"

#: A directory under the outputs root whose name is an engagement id. Ids are
#: minted with :func:`uuid.uuid4`, so the shape identifies them, and a directory
#: matching it is some engagement's bundle rather than a companion artifact.
_ENGAGEMENT_DIR_RE: Final = re.compile(r"\A[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")

#: Reason recorded for the gate's own output file. Excluded so a re-scan is
#: idempotent rather than a report of itself.
SKIP_SELF: Final = "this gate's own output; excluded so a re-scan is idempotent"

#: The ONLY skips that do not fail the gate, each with the reason it is allowed.
#: A suffix absent from this table is read; a file that cannot be read despite
#: being absent from it is recorded with an empty reason and fails.
#:
#: The reasons are deliberately narrow. Three of these formats can carry text —
#: a SQLite ``TEXT`` column and an archive member are both plaintext on disk —
#: and say so, because an allow-list whose entries read as safety assessments
#: would relaunch the failure this table exists to close. What is allowed here
#: is a hole this gate DISCLOSES, not one it dismisses.
_SKIP_ALLOWED: Final[dict[str, str]] = {
    ".png": "raster image; carries no extractable text",
    ".jpg": "raster image; carries no extractable text",
    ".jpeg": "raster image; carries no extractable text",
    ".gif": "raster image; carries no extractable text",
    ".ico": "raster image; carries no extractable text",
    ".db": "SQLite; no reader here, and its TEXT columns are NOT covered by this verdict",
    ".sqlite": "SQLite; no reader here, and its TEXT columns are NOT covered by this verdict",
    ".zip": "archive; members are NOT covered by this verdict",
    ".gz": "archive; members are NOT covered by this verdict",
    ".tar": "archive; members are NOT covered by this verdict",
}

#: Suffix read through :mod:`pypdf` rather than as text. Absent from
#: :data:`_SKIP_ALLOWED` on purpose: it used to be there, which made every PDF
#: in a bundle a region the gate certified without reading.
_PDF_SUFFIX: Final = ".pdf"

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
        region: :data:`REGION_BUNDLE` or :data:`REGION_COMPANION` — whether this
            landed inside the engagement's own directory or beside it.
    """

    path: str
    line: int
    column: int
    kind: str
    detail: str = ""
    fingerprint: str = ""
    length: int = 0
    severity: str = SEVERITY_CREDENTIAL
    region: str = REGION_BUNDLE


class SkippedFile(BaseModel):
    """One file the gate did not read, and whether that was allowed.

    Attributes:
        path: Path relative to the scanned root.
        reason: Why it was not read. An entry from :data:`_SKIP_ALLOWED` or
            :data:`SKIP_SELF` when the skip is allowed, and **empty when it is
            not** — an unreadable file, an unparseable PDF, a file over the size
            cap. An empty reason fails the gate: the verdict cannot cover bytes
            nobody looked at, and saying so is the whole job.
        detail: Non-secret elaboration — the OSError text, the parser message.
        region: :data:`REGION_BUNDLE` or :data:`REGION_COMPANION`.
    """

    path: str
    reason: str = ""
    detail: str = ""
    region: str = REGION_BUNDLE

    @property
    def allowed(self) -> bool:
        """Whether this skip carries an explicit allow reason."""
        return bool(self.reason)


class ArtifactScanReport(BaseModel):
    """The gate's verdict over one engagement's artifact directory.

    Attributes:
        engagement_id: Engagement the bundle belongs to.
        root: Absolute path scanned.
        files_scanned: How many files were read.
        bytes_scanned: Total bytes read.
        files_truncated: Files that exceeded the size cap and were read partially.
        files_skipped: Every file not read, with the reason. An entry whose
            reason is empty was skipped with no allow reason and FAILS the gate.
        findings: Credential-severity hits. Non-empty means the gate FAILED.
        suspicions: Entropy-severity hits. Advisory; never fails the gate.
        errors: Files that could not be read, with the reason.
        companion_root: Outputs root whose companion artifacts were also
            scanned, or ``""`` when the verdict covers the bundle alone.
        companion_files_scanned: Files read in the companion region. Counted
            separately so "3,123 files, clean" can never again be a statement
            about a region that excluded the leak.
    """

    engagement_id: str = ""
    root: str = ""
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_truncated: list[str] = Field(default_factory=list)
    files_skipped: list[SkippedFile] = Field(default_factory=list)
    findings: list[ArtifactFinding] = Field(default_factory=list)
    suspicions: list[ArtifactFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    companion_root: str = ""
    companion_files_scanned: int = 0

    @property
    def unexplained_skips(self) -> list[SkippedFile]:
        """Files not read, for no reason this gate is willing to stand behind."""
        return [s for s in self.files_skipped if not s.allowed]

    @property
    def clean(self) -> bool:
        """Whether the bundle may be handed over.

        Two ways to fail, and the second one is the newer half: a credential
        shape was found, OR a file was skipped with no allow reason. A verdict
        that passes over something it could not read is not a verdict about the
        directory, and every guard in this repository that got caught reporting
        CLEAN over the wrong region did it through a file nobody read.
        """
        return not self.findings and not self.unexplained_skips

    def region_findings(self, region: str) -> list[ArtifactFinding]:
        """Credential-severity findings from one region."""
        return [f for f in self.findings if f.region == region]

    def absorb_companion(self, companions: ArtifactScanReport) -> None:
        """Fold a companion-region scan into this verdict.

        One verdict over two regions, so the merge lives here rather than at
        each caller. It used to be written out twice — in
        :func:`run_disclosure_gate` and again in the ``artifact-scan`` command —
        which is precisely how a newly added field ends up counted in one place
        and dropped in the other.
        """
        self.companion_root = companions.root
        self.companion_files_scanned = companions.files_scanned
        self.bytes_scanned += companions.bytes_scanned
        self.files_truncated.extend(companions.files_truncated)
        self.files_skipped.extend(companions.files_skipped)
        self.findings.extend(companions.findings)
        self.suspicions.extend(companions.suspicions)
        self.errors.extend(companions.errors)

    def _skip_clause(self) -> str:
        """The skipped-file half of the coverage statement, or ``""``.

        Rendered next to the scanned count rather than below it: an operator
        reads one line, and "12 files, clean" beside "3 files never opened" is a
        different sentence from "12 files, clean".
        """
        if not self.files_skipped:
            return ""
        unexplained = len(self.unexplained_skips)
        allowed = len(self.files_skipped) - unexplained
        parts = []
        if allowed:
            parts.append(f"{allowed} skipped (allowed)")
        if unexplained:
            parts.append(f"{unexplained} skipped with NO allow reason")
        return ", " + ", ".join(parts)

    def _coverage(self) -> str:
        """What the verdict actually covered, in one clause."""
        if not self.companion_root:
            scanned = f"{self.files_scanned} file(s), {self.bytes_scanned} bytes"
        else:
            scanned = (
                f"{self.files_scanned} bundle file(s) + "
                f"{self.companion_files_scanned} companion file(s), "
                f"{self.bytes_scanned} bytes"
            )
        return scanned + self._skip_clause()

    def summary_line(self) -> str:
        """One line for a log, the run summary, or a CLI.

        Always names the coverage, clean or not. A gate that says CLEAN without
        saying what it looked at is how a true statement about 3,123 files got
        read as a guarantee about a directory that held a live token.

        ASCII only, like every other operator-facing string in the CLI: a
        Windows console on the default code page raised on a U+2192 once and
        killed the command that printed it. A release check must not be the
        thing that crashes.
        """
        if self.clean:
            return f"ARTIFACT SCAN CLEAN - {self._coverage()}, 0 credential shapes" + (
                f", {len(self.suspicions)} advisory" if self.suspicions else ""
            )
        if not self.findings:
            # Failing on coverage alone. Saying "0 credential shapes" here would
            # be true and would read as a pass, so the reason leads instead.
            return (
                f"ARTIFACT SCAN FAILED - {len(self.unexplained_skips)} file(s) could not be "
                f"read and carry no allow reason, so this verdict does not cover them; "
                f"of {self._coverage()}"
            )
        kinds = Counter(f.kind for f in self.findings)
        breakdown = ", ".join(f"{n}x {kind}" for kind, n in sorted(kinds.items()))
        companion = len(self.region_findings(REGION_COMPANION))
        where = f" ({companion} beside the bundle)" if companion else ""
        return (
            f"ARTIFACT SCAN FAILED - {len(self.findings)} credential shape(s){where} "
            f"in {len({f.path for f in self.findings})} file(s) "
            f"of {self._coverage()}: {breakdown}"
        )

    def _render_findings(self, findings: list[ArtifactFinding], heading: str) -> list[str]:
        """One heading and its located findings, capped for readability."""
        if not findings:
            return []
        lines = ["", heading]
        for finding in findings[:_RENDER_LIMIT]:
            lines.append(
                f"  {finding.path}:{finding.line}:{finding.column}  "
                f"{finding.kind}  {finding.detail}  "
                f"(len={finding.length} sha256={finding.fingerprint})"
            )
        if len(findings) > _RENDER_LIMIT:
            # Truncating the RENDERING is fine; truncating the report is
            # not. The full list is in artifact_scan.json either way.
            lines.append(
                f"  ... and {len(findings) - _RENDER_LIMIT} more "
                f"(full list in {SCAN_REPORT_FILENAME})"
            )
        return lines

    def render(self) -> str:
        """Full human-readable rendering, safe to print anywhere. ASCII only.

        The two regions are rendered apart because they call for different
        actions: a hit in the bundle means this engagement's deliverable leaked,
        a hit beside it means the outputs directory holds credential material
        somebody else's run left there.
        """
        lines = [self.summary_line()]
        lines.extend(
            self._render_findings(
                self.region_findings(REGION_BUNDLE),
                "CREDENTIAL MATERIAL (this bundle must not be handed over):",
            )
        )
        lines.extend(
            self._render_findings(
                self.region_findings(REGION_COMPANION),
                f"CREDENTIAL MATERIAL BESIDE THE BUNDLE, under {self.companion_root} "
                "(not written by this engagement, and not shareable either):",
            )
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
        unexplained = self.unexplained_skips
        if unexplained:
            lines.append("")
            lines.append("NOT READ, WITH NO ALLOW REASON (this verdict does not cover them):")
            for skip in unexplained[:_RENDER_LIMIT]:
                detail = f"  {skip.detail}" if skip.detail else ""
                lines.append(f"  {skip.path}{detail}")
            if len(unexplained) > _RENDER_LIMIT:
                lines.append(f"  ... and {len(unexplained) - _RENDER_LIMIT} more")
        allowed = [s for s in self.files_skipped if s.allowed]
        if allowed:
            # Grouped by reason: the operator needs to know a hole exists and
            # what shape it is, not to read the same sentence once per file.
            lines.append("")
            lines.append("NOT READ, ALLOWED (a disclosed gap in coverage, not a clean bill):")
            by_reason = Counter(s.reason for s in allowed)
            for reason, count in sorted(by_reason.items()):
                lines.append(f"  {count}x {reason}")
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
    text: str, *, path: str = "<text>", region: str = REGION_BUNDLE
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
                region=region,
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


def is_engagement_dir(path: Path) -> bool:
    """Whether *path* is some engagement's artifact directory.

    Used to hold other engagements' bundles out of the companion region: each
    is covered by its own gate, and a run must not be made to answer for a leak
    it did not write.
    """
    return path.is_dir() and bool(_ENGAGEMENT_DIR_RE.match(path.name))


class _UnreadableError(Exception):
    """A file this gate must cover and could not read. Never swallowed."""


def _pdf_text(path: Path) -> str:
    """Both of a PDF's text channels, as one blob with located markers.

    A PDF holds text in two places that do not overlap, and an extractor that
    reads one is blind to the other:

      * **page content streams**, Flate-compressed, which is why a byte scan of
        the file finds nothing however carefully it is written;
      * the **document information dictionary** (``/Info``) — ``/Title``,
        ``/Author``, ``/Subject``, ``/Keywords``, and any custom key a producer
        added — which never appears in page text.

    Both go into one blob, prefixed ``[metadata]`` and ``[page N]``, so the line
    number on a finding still points an operator at the channel to look in.

    Raises:
        _UnreadableError: The file could not be parsed. The caller records an
            unexplained skip and the gate fails — an unparseable PDF is a region
            nobody read, and this module exists because that was once reported
            as clean.
    """
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover — pypdf is a declared dependency
        raise _UnreadableError(f"no PDF extractor available: {exc}") from exc

    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted:
            # Permissions-only encryption uses an empty user password and is
            # common in generated documents. A real password is not guessed:
            # the file stays unread and the gate says so.
            if reader.decrypt("") == 0:
                raise _UnreadableError("encrypted; no empty-password decryption")
        lines: list[str] = []
        for key, value in (reader.metadata or {}).items():
            lines.append(f"[metadata] {key}: {value}")
        for number, page in enumerate(reader.pages, start=1):
            lines.append(f"[page {number}] {page.extract_text() or ''}")
    except _UnreadableError:
        raise
    except Exception as exc:
        # Deliberately broad, and the opposite of the swallowed-exception
        # failure this repository has been bitten by: pypdf raises a wide and
        # undocumented set on a malformed document, and every one of them means
        # the same thing here. Nothing is absorbed — it converts to a skip with
        # no allow reason, which FAILS the gate.
        raise _UnreadableError(f"{type(exc).__name__}: {exc}") from exc
    return "\n".join(lines)


def _scan_one_file(path: Path, relative: str, report: ArtifactScanReport, *, region: str) -> None:
    """Read one file into *report*, honouring the size cap.

    Reads unbounded when the file fits under the cap, and only asks for a bounded
    read when it does not. ``TextIOWrapper.read(n)`` allocates in proportion to
    *n*, so passing the 64 MB cap unconditionally cost ~24 ms per file whatever
    its size — about 75 seconds of pure allocation on a 3,000-file bundle, paid
    at the end of every engagement. The cap still applies; it is just no longer
    charged to the files that do not need it.
    """
    try:
        size = path.stat().st_size
        if path.suffix.lower() == _PDF_SUFFIX:
            if size > _MAX_FILE_BYTES:
                # Unlike a text file, a PDF has no useful partial read: the
                # first N bytes of a compressed container are not the first N
                # bytes of its content. So this is a hole, and it is declared as
                # one rather than filed under "truncated" beside files that WERE
                # substantially read.
                raise _UnreadableError(f"{size} bytes exceeds the {_MAX_FILE_BYTES}-byte cap")
            text = _pdf_text(path)
        else:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                text = handle.read() if size <= _MAX_FILE_BYTES else handle.read(_MAX_FILE_BYTES)
            if size > _MAX_FILE_BYTES:
                report.files_truncated.append(relative)
    except (OSError, _UnreadableError) as exc:
        report.errors.append(f"{relative}: {exc}")
        # Also an unexplained skip, which is what actually fails the gate. The
        # two lists have different jobs: `errors` carries the message a human
        # reads, `files_skipped` carries the verdict. A file that could not be
        # read is not a file that was found clean.
        report.files_skipped.append(
            SkippedFile(path=relative, reason="", detail=str(exc), region=region)
        )
        return
    report.bytes_scanned += len(text)
    findings, suspicions = scan_text(text, path=relative, region=region)
    report.findings.extend(findings)
    report.suspicions.extend(suspicions)


def skip_reason(path: Path) -> str | None:
    """The allow reason for not reading *path*, or ``None`` when it must be read.

    The allow-list is the whole contract: a suffix with an entry is a declared
    gap, and anything else is read or fails.
    """
    if path.name == SCAN_REPORT_FILENAME:
        return SKIP_SELF
    return _SKIP_ALLOWED.get(path.suffix.lower())


def _visit(path: Path, relative: str, report: ArtifactScanReport, *, region: str) -> None:
    """Read one path into *report*, or record why it was not read.

    The single place a file is accounted for. Both region walks call it, so
    "scanned" and "skipped" cannot diverge between them.
    """
    if not path.is_file():
        return
    reason = skip_reason(path)
    if reason is not None:
        report.files_skipped.append(SkippedFile(path=relative, reason=reason, region=region))
        return
    report.files_scanned += 1
    _scan_one_file(path, relative, report, region=region)


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
        _visit(path, path.relative_to(root_path).as_posix(), report, region=REGION_BUNDLE)

    return report


def scan_companion_artifacts(
    outputs_root: Path | str, *, bundle_root: Path | str | None = None
) -> ArtifactScanReport:
    """Scan everything under *outputs_root* that no engagement's gate covers.

    The companion region is the outputs root minus every engagement directory:
    loose files a driver wrote, named result directories
    (``outputs/_juiceshop_benchmark/``, ``outputs/cross-service-b1/``), anything
    a hand-written script dropped beside the bundles. It exists because a
    validation driver wrote a live session JWT to
    ``outputs/d8_auth_bypass_live_validation.json`` and no scan was ever pointed
    at it — the file sat one directory above the only root anyone looked in.

    Args:
        outputs_root: The directory holding the engagement bundles.
        bundle_root: An engagement directory to exclude explicitly, for the
            caller whose own id is not UUID-shaped. Ids are uuid4 in production,
            so :func:`is_engagement_dir` covers the real case; this covers the
            test and the hand-made id.

    Returns:
        An :class:`ArtifactScanReport` whose findings all carry
        :data:`REGION_COMPANION`.
    """
    root_path = Path(outputs_root)
    report = ArtifactScanReport(root=str(root_path.resolve()))
    if not root_path.is_dir():
        report.errors.append(f"{root_path}: not a directory")
        return report

    excluded = Path(bundle_root).resolve() if bundle_root is not None else None
    for entry in sorted(root_path.iterdir()):
        if is_engagement_dir(entry):
            continue
        if excluded is not None and entry.resolve() == excluded:
            continue
        candidates = sorted(entry.rglob("*")) if entry.is_dir() else [entry]
        for path in candidates:
            _visit(path, path.relative_to(root_path).as_posix(), report, region=REGION_COMPANION)

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


def run_disclosure_gate(
    root: Path | str,
    *,
    engagement_id: str = "",
    companion_root: Path | str | None = None,
) -> ArtifactScanReport:
    """Scan the bundle and its companions, persist the result, and say so.

    A clean result is logged at INFO — an operator should be able to see that
    the check ran, because a gate nobody notices is a gate nobody trusts. A
    failure is logged at ERROR with every location, because the bundle must not
    be handed over until it is resolved.

    Args:
        root: The engagement's artifact directory.
        engagement_id: Recorded on the report.
        companion_root: The outputs root. When given, everything under it that
            no engagement's gate covers is scanned too and folded into the same
            verdict, tagged :data:`REGION_COMPANION`. Omitted, the verdict
            covers the bundle alone and :meth:`ArtifactScanReport.summary_line`
            says so — the point of the coverage clause is that a CLEAN can never
            again be read as a claim about a region it did not look at.

    Returns:
        The :class:`ArtifactScanReport`. One verdict over both regions.
    """
    report = scan_artifact_tree(root, engagement_id=engagement_id)
    if companion_root is not None:
        report.absorb_companion(scan_companion_artifacts(companion_root, bundle_root=root))
    write_scan_report(report, root)
    if report.clean:
        logger.info("%s", report.summary_line())
    else:
        logger.error(
            "ARTIFACT DISCLOSURE GATE FAILED — credential material is present "
            "and this must NOT be handed to a client:\n%s",
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
    "REGION_BUNDLE",
    "REGION_COMPANION",
    "SCAN_REPORT_FILENAME",
    "SEVERITY_CREDENTIAL",
    "SEVERITY_SUSPICIOUS",
    "SKIP_SELF",
    "ArtifactFinding",
    "ArtifactScanReport",
    "SkippedFile",
    "is_engagement_dir",
    "load_scan_report",
    "run_disclosure_gate",
    "scan_artifact_tree",
    "scan_companion_artifacts",
    "scan_text",
    "shannon_entropy",
    "skip_reason",
    "write_scan_report",
]
