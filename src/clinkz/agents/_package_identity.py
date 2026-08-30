"""Package identity — the producer the dependency→CVE path never had.

:mod:`clinkz.knowledge.component_cves` has carried five entries against three
npm packages (``lodash`` ×2, ``jquery`` ×2, ``express-fileupload``) since it was
written, and **nothing in this engine could ever produce a component they match**.
The two fingerprinters that feed ``ReconResult.components`` name SERVERS:
``nmap -sV`` resolves a service banner through its signature database, and
``whatweb`` reads response headers and page markers. Neither has ever emitted a
row whose name is ``lodash``. Those five entries were unreachable catalogue, and
the honest reading of the zeros they produced is not "no target shipped a
vulnerable lodash" — it is "the question was never asked".

This module asks it. It is the third component source, and it is deliberately
**pure**: every function takes bytes or a path and returns
:class:`~clinkz.models.recon.DetectedComponent` rows, so the whole producer is
offline-testable and the recon agent supplies the I/O.

Sources, in the provenance order the enum already declares
--------------------------------------------------------
``LOCKFILE`` — a resolved dependency graph from the gray-box source tree
    (``package-lock.json``, ``yarn.lock``). This names the version that was
    actually installed. The target does not choose it and cannot edit it from a
    config file, which is why it outranks everything below.

``MANIFEST`` — a ``package.json`` dependency pinned to an EXACT version. A pin
    is a resolved answer by construction. A RANGE (``^4.17.20``, ``~1.2``,
    ``>=3``) is deliberately **not** read: a range names what was asked for, not
    what arrived, and turning ``^4.17.20`` into an observation of ``4.17.20``
    would be the fabrication this whole path exists to refuse. The recall loss
    is real and it is the correct trade.

``ARTIFACT_STRING`` — a version string embedded in a bundle the target actually
    served (``/*! jQuery v3.4.1 | (c) JS Foundation */``, ``@license lodash
    4.17.20``, an ``pkg@1.2.3`` coordinate). Baked in at build time, naming the
    package's own release rather than a distribution's repackaging. Weaker than
    a resolved dependency, stronger than a header one ``ServerTokens`` line can
    erase.

``BANNER`` — unchanged, and still where ``whatweb`` and ``nmap`` sit.

There is deliberately **no bundle-hash route**. A digest identifies a package
only against a catalogue of known digests, and this engine has none; computing
a SHA-256 of a served bundle and reporting it as identity would be a number with
nothing to compare it to. See ``docs/methodology/sca-catalogue-breadth.md``.

What this module refuses to do
------------------------------
It never *infers* a package from a framework name, a path fragment, or a
technology the LLM listed. Every row it emits is a literal ``(name, version)``
pair read out of a file the engagement was handed or bytes the target served,
and the ``source`` field says which — so the provenance claim riding into a
report is checkable against the observation that produced it.

It also carries no application's vocabulary. The bundle patterns are the
license-banner and npm-coordinate shapes every published JS package ships; the
tree readers are the npm ecosystem's own file formats. Nothing here reports the
same package whether or not the target has it, which is the line between
discovery and recall.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field

from clinkz.models.recon import (
    DetectedComponent,
    VersionProvenance,
    version_provenance_rank,
)
from clinkz.tools.base import ToolOutput

logger = logging.getLogger(__name__)

#: Bundles read per engagement. The walk is breadth-first from the shell's own
#: ``<script src>`` tags; a SPA puts its vendor chunk there, and a bound is what
#: keeps a code-split application from turning recon into a crawl.
MAX_BUNDLES = 8

#: Bytes read from any one bundle. A vendor chunk is megabytes and every banner
#: comment this reads is in the first few kilobytes of its own segment, so the
#: cap costs the tail of a minified body and nothing else. Stated rather than
#: silent: a bundle truncated here can under-report, never over-report.
MAX_BUNDLE_BYTES = 2_000_000

#: Manifest/lockfile files read from a supplied source tree, and the depth the
#: walk goes to. A monorepo has one per workspace; a vendored ``node_modules``
#: has thousands, and reading those would inventory the DEPENDENCIES' own
#: dependencies as though the application shipped them.
MAX_TREE_FILES = 64
MAX_TREE_DEPTH = 4
MAX_TREE_FILE_BYTES = 8_000_000

#: Directories never descended into. ``node_modules`` is the important one: the
#: installed tree is what the lockfile already describes, and walking it would
#: replace one resolved answer with thousands of transitive ones.
_SKIP_DIRS = frozenset(
    {"node_modules", ".git", ".hg", ".svn", "dist", "build", "coverage", "__pycache__", ".venv"}
)

#: An npm package name: optional ``@scope/``, then the registry's own charset.
#: Anchored in every pattern below so a bare English word cannot become a
#: package identity.
_PKG = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"

#: A dotted numeric version, optionally with a pre-release/build tail. The tail
#: is captured and kept: ``2.4.62-1~deb12u2`` is a real observation and
#: discarding the suffix would silently upgrade a back-ported build into the
#: upstream release it is not.
_VER = r"\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.~-]+)?"

#: ``/*! jQuery v3.4.1 | (c) JS Foundation`` and ``@license lodash 4.17.20``.
#: The two shapes essentially every published UMD/minified bundle ships. ``v``
#: is optional because half the ecosystem omits it.
_BANNER_VERSION_RE = re.compile(
    r"(?:@license\s+|/\*!\s*|\*\s+)(?P<name>" + _PKG + r")\s+v?(?P<version>" + _VER + r")\b",
    re.IGNORECASE,
)

#: An npm coordinate: ``lodash@4.17.20``. Appears in license headers, sourcemap
#: comments and webpack module ids. Guarded on the left so an email address or a
#: scoped path fragment cannot match.
_COORDINATE_RE = re.compile(
    r"(?<![\w@/.-])(?P<name>" + _PKG + r")@(?P<version>" + _VER + r")(?![\w.-])"
)

#: Words that are package-name-shaped but are never a package in this position.
#: A minified bundle is full of ``t@1.2.3``-looking noise; requiring three
#: characters and excluding the handful of English words that collide keeps the
#: emitted rows to things a registry could actually resolve.
_NAME_STOPWORDS = frozenset(
    {
        "version",
        "license",
        "copyright",
        "released",
        "build",
        "chunk",
        "module",
        "bundle",
        "webpack",
        "sourcemappingurl",
        "https",
        "http",
        "www",
    }
)


def _plausible_package_name(name: str) -> bool:
    """Whether *name* could be a package identity rather than minifier noise.

    Deliberately conservative in one direction only. A false positive here costs
    a catalogue lookup that matches nothing (every dependency entry is name-
    anchored, so ``chunk 4.17.20`` matches no CVE); a false NEGATIVE costs a
    real observation. The bar is therefore low — length and a stopword list —
    rather than an allow-list of packages, which would make this a recall table
    and reintroduce exactly the "reports the same surface whether or not the
    target has it" defect the route discoverers were built to avoid.
    """
    bare = name.rsplit("/", 1)[-1].lower()
    if len(bare) < 3:
        return False
    return bare not in _NAME_STOPWORDS


@dataclass
class PackageInventoryReport:
    """How far this producer's own pipeline got, so a zero can be READ.

    The same three counters — and the same reasoning —
    :class:`~clinkz.agents._route_discovery.DiscoveryReport` carries, kept as a
    separate type because the noun differs (components, not endpoints) and a
    shared class whose field is called ``endpoints_emitted`` would be the
    consumer-assumption shape this repo has paid for before.

    * ``inputs_examined == 0`` — no lockfile, manifest or served bundle existed
      to read. Correct-for-target: a black-box engagement against a PHP app has
      no package identity to find.
    * ``candidates_seen == 0`` with inputs read — real input was parsed and
      contained no ``(name, version)`` pair. Also correct.
    * ``candidates_seen > 0`` and ``components_emitted == 0`` — input was found
      and every candidate was discarded on the way out. That is the ffuf shape.
      It stays an alarm and no reason string may talk it away.
    """

    inputs_examined: int = 0
    candidates_seen: int = 0
    components_emitted: int = 0
    detail: str = ""

    @property
    def correctly_empty_reason(self) -> str:
        """Why emitting nothing was CORRECT, or ``""`` when it was not."""
        if self.components_emitted > 0:
            return ""
        if self.inputs_examined == 0:
            return (
                "no lockfile, manifest or served JavaScript bundle was available to read "
                f"({self.detail or 'no input'})"
            )
        if self.candidates_seen == 0:
            return (
                f"read {self.inputs_examined} input(s) carrying no package/version pair "
                f"({self.detail or 'no candidates'})"
            )
        return ""


class PackageIdentityOutput(ToolOutput):
    """The producer's declaration, read through the fingerprint contract.

    This is a :class:`~clinkz.tools.base.ToolOutput` subclass and not a bare
    dataclass for one reason: it makes package identity a **second inventory
    path that the consumer reads exactly like the first**. The recon agent's
    fingerprint seam already asks ``declares_components()`` and then
    ``detected_components()``; giving this producer the same contract means the
    seam gains a source without gaining a branch, and a future producer that
    forgets to declare is a loud dead seam rather than a silent empty list.

    That matters here more than anywhere. The seam this replaces was
    ``hasattr(r, "technologies")`` then ``hasattr(r, "tech")`` — two spellings
    because two wrappers differed, and a third would have contributed nothing
    with nothing said about it. A new inventory path is that seam again, and it
    is answered the same way: the producer declares.

    Attributes:
        components: What was identified, already deduplicated and provenance-
            stamped by :func:`build_inventory`.
        report: How far the pipeline got, for the ledger.
    """

    components: list[DetectedComponent] = Field(default_factory=list)
    report: PackageInventoryReport = Field(default_factory=PackageInventoryReport)

    def detected_components(self) -> list[DetectedComponent]:
        """The declared fingerprint contract — the ONE way a consumer reads this."""
        return list(self.components)


# ---------------------------------------------------------------------------
# Source-tree readers: LOCKFILE and MANIFEST
# ---------------------------------------------------------------------------


def packages_from_package_lock(
    text: str, *, path_label: str = "package-lock.json"
) -> list[DetectedComponent]:
    """Resolved dependencies from an npm ``package-lock.json``.

    Handles both layouts the file has had, because a real engagement's tree may
    carry either: lockfile v1 nests a ``dependencies`` map, v2/v3 carries a flat
    ``packages`` map keyed by install path. v2 carries BOTH, and the flat map is
    read first because it is the one npm itself treats as authoritative.

    The root entry (``packages[""]``) is skipped: it describes the application
    under test, not a dependency, and its ``version`` is the app's own.

    Args:
        text: File contents.
        path_label: What to name in ``source``, so a monorepo's several
            lockfiles stay distinguishable in the inventory.

    Returns:
        One ``LOCKFILE`` row per dependency that names a version.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[DetectedComponent] = []
    seen: set[tuple[str, str]] = set()

    def _emit(name: str, version: object) -> None:
        if not isinstance(version, str) or not version.strip():
            return
        clean = name.strip()
        if not clean or not _plausible_package_name(clean):
            return
        key = (clean.lower(), version.strip())
        if key in seen:
            return
        seen.add(key)
        out.append(
            DetectedComponent(
                name=clean,
                version=version.strip(),
                source=f"package_identity:{path_label}",
                provenance=VersionProvenance.LOCKFILE,
            )
        )

    packages = data.get("packages")
    if isinstance(packages, dict):
        for install_path, entry in packages.items():
            if not install_path or not isinstance(entry, dict):
                continue  # "" is the application itself, not a dependency
            # "node_modules/@scope/name" -> "@scope/name"; the LAST occurrence
            # is the package, because a nested install path repeats the segment.
            name = install_path.split("node_modules/")[-1]
            _emit(name, entry.get("version"))

    def _walk_v1(node: object, depth: int = 0) -> None:
        if depth > 8 or not isinstance(node, dict):
            return
        for name, entry in node.items():
            if not isinstance(entry, dict):
                continue
            _emit(name, entry.get("version"))
            _walk_v1(entry.get("dependencies"), depth + 1)

    _walk_v1(data.get("dependencies"))
    return out


#: ``  version "4.17.20"`` — the resolved version line under a yarn.lock entry.
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"?(?P<version>' + _VER + r')"?\s*$')
#: ``lodash@^4.17.0, lodash@~4.17.15:`` — the descriptor header line. Several
#: descriptors can share one resolution, and they all name the same package.
_YARN_HEADER_RE = re.compile(r'^"?(?P<name>' + _PKG + r")@")


def packages_from_yarn_lock(text: str, *, path_label: str = "yarn.lock") -> list[DetectedComponent]:
    """Resolved dependencies from a ``yarn.lock`` (v1 text format).

    Parsed line-wise rather than with a YAML reader on purpose: yarn v1's format
    is not YAML, and yarn v2+ writes a YAML file whose entries carry the same
    ``version:`` key at the same nesting, so the line reader handles both
    without claiming to implement either grammar.

    A header names one or more descriptors for one resolution; the version line
    that follows is that resolution. A header with no following version line
    contributes nothing — an unresolved descriptor is a range, and a range is
    not an observation.
    """
    out: list[DetectedComponent] = []
    seen: set[tuple[str, str]] = set()
    pending: list[str] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line[:1].isspace():
            pending = []
            for descriptor in raw_line.rstrip(":").split(","):
                header = _YARN_HEADER_RE.match(descriptor.strip())
                if header:
                    pending.append(header.group("name"))
            continue
        version_line = _YARN_VERSION_RE.match(raw_line)
        if version_line is None or not pending:
            continue
        version = version_line.group("version")
        for name in pending:
            if not _plausible_package_name(name):
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                DetectedComponent(
                    name=name,
                    version=version,
                    source=f"package_identity:{path_label}",
                    provenance=VersionProvenance.LOCKFILE,
                )
            )
        pending = []
    return out


#: A ``package.json`` value that is an EXACT pin: a bare version, optionally
#: with a leading ``=`` or ``v``. Anything carrying ``^ ~ > < | * x -`` or a
#: URL/tag is a range or a non-registry source and is not an observation.
_EXACT_PIN_RE = re.compile(r"^[=v]?(?P<version>" + _VER + r")$")


def packages_from_package_json(
    text: str, *, path_label: str = "package.json"
) -> list[DetectedComponent]:
    """EXACT dependency pins from a ``package.json``.

    Only exact pins. ``^4.17.20`` says the build accepts 4.17.20 through 4.999
    and npm will have installed whatever was newest at install time — reporting
    the floor of a range as the observed version would manufacture a CVE match
    against a version that may never have been on the host. A range is skipped
    silently here and shows up as a candidate that emitted nothing, which is the
    honest accounting: the file was read, the entry was seen, it was not an
    observation.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[DetectedComponent] = []
    seen: set[tuple[str, str]] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            pin = _EXACT_PIN_RE.match(spec.strip())
            if pin is None or not _plausible_package_name(str(name)):
                continue
            key = (str(name).lower(), pin.group("version"))
            if key in seen:
                continue
            seen.add(key)
            out.append(
                DetectedComponent(
                    name=str(name),
                    version=pin.group("version"),
                    source=f"package_identity:{path_label}#{section}",
                    provenance=VersionProvenance.MANIFEST,
                )
            )
    return out


#: Filename → the reader that understands it. The dispatch is by exact filename
#: because these formats are named by their ecosystem, not guessed at.
_TREE_READERS = {
    "package-lock.json": packages_from_package_lock,
    "npm-shrinkwrap.json": packages_from_package_lock,
    "yarn.lock": packages_from_yarn_lock,
    "package.json": packages_from_package_json,
}


def packages_from_source_tree(
    root: Path | str | None,
) -> tuple[list[DetectedComponent], PackageInventoryReport]:
    """Walk a supplied source tree for lockfiles and manifests.

    Bounded in three dimensions (:data:`MAX_TREE_DEPTH`, :data:`MAX_TREE_FILES`,
    :data:`MAX_TREE_FILE_BYTES`) and blind to :data:`_SKIP_DIRS`. The important
    exclusion is ``node_modules``: the installed tree is what the lockfile
    already resolved, and walking it would report every transitive dependency's
    own manifest as though the application declared it.

    Deliberately npm-only today. That is not an oversight and it is stated
    rather than absorbed: every dependency entry in the CVE catalogue is an npm
    package, so an npm reader is exactly what makes the unreachable half of the
    catalogue reachable. A Python or Java reader is the same shape and adds
    entries this catalogue does not yet carry —
    ``docs/methodology/sca-catalogue-breadth.md`` reports what that would cost.

    Args:
        root: ``EngagementScope.source_dir``, or ``None`` on a black-box run.

    Returns:
        The rows found, and the report describing how far the walk got. A
        ``None``/missing root yields ``inputs_examined=0``, which reads as
        correct-for-target rather than as a defect.
    """
    report = PackageInventoryReport()
    if not root:
        report.detail = "no source tree was supplied (black-box engagement)"
        return [], report
    base = Path(root)
    if not base.is_dir():
        report.detail = f"source path is not a directory: {base}"
        return [], report

    found: list[DetectedComponent] = []
    files_read = 0
    candidates = 0
    for path in sorted(base.rglob("*")):
        if files_read >= MAX_TREE_FILES:
            break
        if path.name not in _TREE_READERS or not path.is_file():
            continue
        try:
            relative = path.relative_to(base)
        except ValueError:  # pragma: no cover - rglob results are always under base
            continue
        if len(relative.parts) - 1 > MAX_TREE_DEPTH:
            continue
        if _SKIP_DIRS.intersection(relative.parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_TREE_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Package identity could not read %s: %s", path, exc)
            continue
        files_read += 1
        rows = _TREE_READERS[path.name](text, path_label=relative.as_posix())
        candidates += len(rows)
        found.extend(rows)

    report.inputs_examined = files_read
    report.candidates_seen = candidates
    report.components_emitted = len(found)
    report.detail = f"{files_read} lockfile/manifest file(s) under {base}"
    return found, report


# ---------------------------------------------------------------------------
# Served-bundle reader: ARTIFACT_STRING
# ---------------------------------------------------------------------------


def packages_from_bundle(js: str, url: str = "") -> list[DetectedComponent]:
    """Package identities embedded in the bytes a target actually served.

    Two shapes, both of them the JavaScript ecosystem's own conventions rather
    than any application's vocabulary:

    * the license/banner comment a published UMD build ships
      (``/*! jQuery v3.4.1 | (c) JS Foundation``, ``@license lodash 4.17.20``);
    * an npm coordinate (``lodash@4.17.20``) as it appears in license headers,
      sourcemap comments and module ids.

    Both are ``ARTIFACT_STRING``: baked into the artifact at build time, naming
    the package's own release. Neither survives a back-port, which is why the
    rank sits below every resolved-dependency source.

    Args:
        js: Bundle body, already truncated by the caller.
        url: Bundle URL, recorded in ``source`` so the claim is checkable.

    Returns:
        Deduplicated rows in first-appearance order.
    """
    label = url or "bundle"
    out: list[DetectedComponent] = []
    seen: set[tuple[str, str]] = set()
    for pattern in (_BANNER_VERSION_RE, _COORDINATE_RE):
        for match in pattern.finditer(js):
            name = match.group("name")
            version = match.group("version")
            if not _plausible_package_name(name):
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                DetectedComponent(
                    name=name,
                    version=version,
                    source=f"package_identity:{label}",
                    provenance=VersionProvenance.ARTIFACT_STRING,
                )
            )
    return out


def bundle_candidate_count(js: str) -> int:
    """Raw ``(name, version)`` matches in *js*, BEFORE the plausibility filter.

    The ledger's discriminator needs ``candidates_seen`` to mean "input of this
    shape was found", not "input this producer chose to keep". Counting after
    the filter would let a reader that discards 100% of what it finds report
    itself as correctly-empty — the exact self-assessment the report shape
    exists to refuse.
    """
    return sum(len(pattern.findall(js)) for pattern in (_BANNER_VERSION_RE, _COORDINATE_RE))


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_inventory(
    *,
    tree_components: list[DetectedComponent],
    tree_report: PackageInventoryReport,
    bundle_bodies: list[tuple[str, str]],
) -> PackageIdentityOutput:
    """Merge the tree and bundle sources into one declared output.

    Args:
        tree_components: Rows from :func:`packages_from_source_tree`.
        tree_report: That walk's own report.
        bundle_bodies: ``(url, body)`` for every bundle the caller fetched. An
            entry with an empty body still counts as an input examined —
            fetching it is what proves the target serves bundles — and
            contributes no candidates.

    Returns:
        A :class:`PackageIdentityOutput` whose ``detected_components()`` is the
        deduplicated union, strongest provenance winning per ``(name, version)``.
    """
    components = list(tree_components)
    bundle_candidates = 0
    bundle_emitted = 0
    for url, body in bundle_bodies:
        if not body:
            continue
        bundle_candidates += bundle_candidate_count(body)
        rows = packages_from_bundle(body, url)
        bundle_emitted += len(rows)
        components.extend(rows)

    merged = _merge(components)
    report = PackageInventoryReport(
        inputs_examined=tree_report.inputs_examined + len(bundle_bodies),
        candidates_seen=tree_report.candidates_seen + bundle_candidates,
        components_emitted=len(merged),
        detail=(
            f"{tree_report.inputs_examined} tree file(s), {len(bundle_bodies)} served bundle(s); "
            f"{tree_report.components_emitted} from lockfile/manifest, "
            f"{bundle_emitted} from artifact strings"
        ),
    )
    return PackageIdentityOutput(
        tool_name="package_identity",
        success=True,
        components=merged,
        report=report,
    )


def _merge(components: list[DetectedComponent]) -> list[DetectedComponent]:
    """One row per ``(name, version)``, keeping the strongest provenance.

    Not :func:`~clinkz.models.recon.dedupe_components`: that one keys on
    ``(name, port)`` and is answering "which observer's version do we believe
    for this service". Here two sources can honestly disagree about the version
    of the SAME package — a lockfile says ``4.17.21`` while a stale served
    bundle's banner still says ``4.17.20`` — and both are true observations of
    different things. Collapsing them would discard the one the CVE catalogue
    matches. They are kept apart, and the seam that merges this into the recon
    inventory applies the port-keyed rule afterwards.
    """
    by_key: dict[tuple[str, str], DetectedComponent] = {}
    order: list[tuple[str, str]] = []
    for component in components:
        key = component.identity()
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = component
            order.append(key)
            continue
        if version_provenance_rank(component.provenance) < version_provenance_rank(
            existing.provenance
        ):
            by_key[key] = component
    return [by_key[key] for key in order]


__all__ = [
    "MAX_BUNDLES",
    "MAX_BUNDLE_BYTES",
    "PackageIdentityOutput",
    "PackageInventoryReport",
    "build_inventory",
    "bundle_candidate_count",
    "packages_from_bundle",
    "packages_from_package_json",
    "packages_from_package_lock",
    "packages_from_source_tree",
    "packages_from_yarn_lock",
]
