"""Offline replay: what the dependency→CVE slot reservation would have cost.

Sends nothing. Reads only ``outputs/<id>/report_<id>.json`` and, where the
bundle kept one, ``outputs/<id>/trace.jsonl``.

The question
------------
``_resolve_component_cve_reservation`` takes ``min(_MAX_COMPONENT_CVE_MATCHES,
dispatchable)`` slots off the top of ``exploit_max_plan_tasks`` and hands the
remainder to the Tier-1 interleave. Two things have to be true before that is
safe to ship, and both are measurable against bundles already on disk:

* **A run that matched nothing plans byte-identically.** The reservation is a
  reduction of a shared cap, so a run it does nothing for must not lose a single
  task to it. This is the same shape as the never-sent control: prove the change
  is inert where it should not apply.
* **Where it does apply, the cost is stated.** Every reserved slot comes out of
  the Tier-1 fill on a saturated plan, so it displaces exactly one Tier-1
  candidate. That number belongs in a report, not in a footnote.

THE STORED-BUNDLE RECOVERY CEILING (read this before writing another replay)
---------------------------------------------------------------------------
Every offline replay over ``outputs/`` inherits this, not just this one. The
measurement, taken 2026-08-30 over 4,151 stored report bundles:

* **70 bundles carry ``plan_coverage``** — the population any plan-shaped replay
  can use at all.
* **``hosts[].services`` is empty on all 70.** It is NOT empty everywhere: 30
  bundles elsewhere in the corpus carry a populated service list. The two
  populations do not overlap, so the strongest recovery route exists in the
  corpus and never on a bundle a replay can use. Checking "does any bundle carry
  this?" and concluding the route is available is therefore wrong, and it is the
  mistake this paragraph exists to prevent.
* **Only 20 of the 70 kept a ``trace.jsonl`` at all.** The other 50 are
  unreachable by every trace-based route by construction.
* **``trace.jsonl`` truncates every ``data_summary`` at 500 characters**, so the
  recon→orchestrator handoff — the exact value ``_harvest_components`` reads —
  is cut off mid-``raw_output`` on every bundle whose recon actually found
  anything. It parses only for runs that scanned nothing.

Net: 11 of 70 bundles yield an inventory, all of them by re-running the real
parsers over recorded tool stdout. **A component this engine did not fingerprint
with a recorded tool cannot be recovered from any stored bundle** — which now
includes everything ``agents/_package_identity.py`` produces, since no bundle
stores a served bundle body or a supplied lockfile. See ``apply_package_control``
below for how a control is written when the corpus cannot carry the observation.

The forward fix is shipped and does not help these bundles: ``report.json`` now
carries ``component_inventory`` — name, version, provenance and observing source
— so a replay written against bundles produced from 2026-08-30 onward reads the
inventory directly instead of reconstructing it.

What this replay can and cannot recover
---------------------------------------
The reservation is a function of the recon **component inventory** and the scan
**endpoint set**, and given the ceiling above neither is stored whole on the
bundles in scope. So the inventory is recovered from the strongest route that
survives, and the route is REPORTED beside the number, because a count whose
provenance is not stated is the defect this whole feature exists to fix. A
bundle no route reaches is ``UNRECOVERABLE`` — never ``0 components``. An
unmeasurable inventory and an empty one produce identical arithmetic here and
are not the same fact, and recording the second when only the first is known is
how a replay certifies a region it never read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from clinkz.agents.exploit import _MAX_COMPONENT_CVE_MATCHES  # noqa: E402
from clinkz.knowledge.component_cves import ComponentCVEMatch, match_components  # noqa: E402
from clinkz.models.recon import (  # noqa: E402
    DetectedComponent,
    VersionProvenance,
)
from clinkz.models.scan import Endpoint  # noqa: E402
from clinkz.tools.nmap import NmapTool  # noqa: E402
from clinkz.tools.whatweb import WhatWebTool  # noqa: E402

#: Inventory recovery routes, strongest first. The order is the order they are
#: tried, and the winner's name is printed beside every number derived from it.
ROUTE_REPORT_INVENTORY = "report:component_inventory"
ROUTE_REPORT_HOSTS = "report:hosts.services"
ROUTE_TRACE_HANDOFF = "trace:recon_handoff"
ROUTE_TRACE_TOOL_STDOUT = "trace:tool_stdout"
ROUTE_UNRECOVERABLE = "UNRECOVERABLE"

#: Marker the trace writer leaves when it cuts a payload short. Its presence is
#: the difference between "the tool reported this" and "the tool reported this
#: and more we cannot see".
_TRUNCATION_MARKER = "...[truncated "


@dataclass
class BundleReplay:
    """One stored bundle, replayed against the reservation arithmetic."""

    engagement_id: str
    has_trace: bool
    passes_recorded: int = 0
    cap: int = 0
    kept: int = 0
    dropped_total: int = 0
    saturated: bool = False
    route: str = ROUTE_UNRECOVERABLE
    truncated_source: bool = False
    components: list[DetectedComponent] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    matches: list[ComponentCVEMatch] = field(default_factory=list)
    confirmable: list[ComponentCVEMatch] = field(default_factory=list)
    reserved: int = 0
    displaced: int = 0
    identical: bool | None = None
    note: str = ""

    @property
    def baseline_measurable(self) -> bool:
        """Whether the planner recorded a pass at all.

        ``passes_recorded == 0`` means no pass reached the register, so this
        bundle says nothing about the cap, what was kept, or the headroom the
        reservation would come out of. Rendering those as ``0`` would be the
        defect the register itself exists to prevent: an absent measurement read
        as a measurement of zero.
        """
        return self.passes_recorded > 0 and self.cap > 0

    @property
    def headroom(self) -> int:
        """Plan slots the Tier-1 fill left unspent — what the CVE source could win today."""
        return max(0, self.cap - self.kept)

    @property
    def measurable(self) -> bool:
        return self.route != ROUTE_UNRECOVERABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "passes_recorded": self.passes_recorded,
            "baseline_measurable": self.baseline_measurable,
            "cap": self.cap if self.baseline_measurable else None,
            "kept": self.kept if self.baseline_measurable else None,
            "headroom": self.headroom if self.baseline_measurable else None,
            "dropped_total": self.dropped_total,
            "saturated": self.saturated if self.baseline_measurable else None,
            "inventory_route": self.route,
            "inventory_source_truncated": self.truncated_source,
            "components": [
                {"name": c.name, "version": c.version, "provenance": c.provenance.value}
                for c in self.components
            ],
            "endpoints_recovered": len(self.endpoints),
            "cve_matches": len(self.matches),
            "cve_matches_confirmable": len(self.confirmable),
            "reserved": self.reserved,
            "tier1_displaced": self.displaced,
            "plan_byte_identical": self.identical,
            "note": self.note,
        }


def _iter_trace(path: Path) -> Iterator[dict[str, Any]]:
    """Trace records, skipping anything that does not parse.

    A malformed line is skipped rather than fatal: this reads bundles written by
    every version of the writer that has ever run.
    """
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _components_from_inventory(report: dict[str, Any]) -> list[DetectedComponent]:
    """The inventory the deliverable states about ITSELF — the only route with
    no reconstruction and no provenance guessing in it.

    Written by ``ReportAgent`` from recon's own rows as of 2026-08-30, carrying
    the ``VersionProvenance`` each producer declared. Absent on every bundle
    written before that, which is exactly the ceiling documented above: this
    route is the fix, and it is a fix for the NEXT corpus, not this one.
    """
    inventory = report.get("component_inventory") or {}
    rows = inventory.get("components") if isinstance(inventory, dict) else None
    if not isinstance(rows, list):
        return []
    components: list[DetectedComponent] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            components.append(
                DetectedComponent(
                    name=str(row.get("name") or ""),
                    version=str(row.get("version") or ""),
                    source=str(row.get("source") or ""),
                    port=int(row.get("port") or 0),
                    provenance=row.get("provenance") or VersionProvenance.UNDECLARED,
                )
            )
        except Exception:  # noqa: BLE001 - a malformed row is dropped, never fatal
            continue
    return [c for c in components if c.name]


def _components_from_report(report: dict[str, Any]) -> list[DetectedComponent]:
    """The inventory the deliverable itself carries, if any.

    Empty on every bundle written so far — ``hosts[].services`` has been an
    empty list on all of them — but it is tried first because a report that DOES
    carry the inventory is the only route with no reconstruction in it.
    """
    components: list[DetectedComponent] = []
    for host in report.get("hosts") or []:
        for service in host.get("services") or []:
            name = (service.get("product") or service.get("service_name") or "").strip()
            if not name:
                continue
            components.append(
                DetectedComponent(
                    name=name,
                    version=(service.get("version") or "").strip(),
                    source="report:hosts",
                    port=service.get("port") or 0,
                )
            )
    return components


def _components_from_handoff(records: list[dict[str, Any]]) -> list[DetectedComponent]:
    """The inventory off the recon→orchestrator handoff, when it survived truncation.

    This is the exact value ``_harvest_components`` reads, so when it parses
    there is no reconstruction at all. It parses only for runs whose recon
    result was under the trace writer's 500-character summary cap — in practice
    the ones that scanned nothing.
    """
    for record in records:
        payload = record.get("payload") or {}
        if record.get("category") != "data_handoff" or payload.get("from_agent") != "recon":
            continue
        raw = payload.get("data_summary") or ""
        if _TRUNCATION_MARKER in raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        result = parsed.get("result", parsed)
        if not isinstance(result, dict):
            continue
        harvested: list[DetectedComponent] = []
        for entry in result.get("components") or []:
            if isinstance(entry, dict):
                try:
                    harvested.append(DetectedComponent.model_validate(entry))
                except Exception:  # noqa: BLE001 — a malformed row is dropped, never fatal
                    continue
        return harvested
    return []


def _components_from_tool_stdout(
    records: list[dict[str, Any]],
) -> tuple[list[DetectedComponent], bool]:
    """The inventory rebuilt by running the REAL parsers over recorded stdout.

    The fingerprinters' own output is in the trace's ``tool_call`` records, so
    the reconstruction runs ``WhatWebTool.parse_output`` /
    ``NmapTool.parse_output`` and reads ``detected_components()`` — the producer's
    own declaration, never a regex of this script's invention. A consumer
    guessing at a producer's field names is the defect this repo has paid for
    more than once.

    Returns:
        The recovered inventory, and whether any stdout it was built from was
        truncated by the trace writer. A truncated source makes the inventory a
        LOWER BOUND, which is stated rather than absorbed.
    """
    whatweb = WhatWebTool.__new__(WhatWebTool)
    nmap = NmapTool.__new__(NmapTool)
    parsers = {"whatweb": whatweb.parse_output, "nmap": nmap.parse_output}

    recovered: list[DetectedComponent] = []
    truncated = False
    for record in records:
        if record.get("category") != "tool_call":
            continue
        payload = record.get("payload") or {}
        tool = str(payload.get("tool") or "")
        parse = parsers.get(tool)
        if parse is None:
            continue
        stdout = payload.get("stdout_summary") or ""
        if not stdout:
            continue
        if _TRUNCATION_MARKER in stdout:
            truncated = True
            stdout = stdout.split(_TRUNCATION_MARKER)[0]
        try:
            parsed = parse(stdout)
            recovered.extend(parsed.detected_components())
        except Exception:  # noqa: BLE001 — a parser raising on a truncated tail is expected
            continue

    seen: set[tuple[str, str, int]] = set()
    deduped: list[DetectedComponent] = []
    for component in recovered:
        key = (component.name.lower(), component.version, component.port or 0)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(component)
    return deduped, truncated


def _endpoints_from_bundle(report: dict[str, Any], records: list[dict[str, Any]]) -> list[Endpoint]:
    """Every target URL the bundle still evidences — a LOWER BOUND on the scan's set.

    The scan handoff is truncated like the recon one, so the endpoint set is
    rebuilt from URLs the run demonstrably touched: the findings and leads in the
    report, and the target the trace recorded resolving. It can only be smaller
    than what the scan actually discovered, and a smaller set can only make
    ``_component_cve_target_url`` return ``""`` where the real run would have
    found a URL — so every ``reserved`` below is a floor, never an overstatement.
    """
    urls: set[str] = set()
    for key in ("findings", "unproven_leads", "research_leads", "chain_leads"):
        for item in report.get(key) or []:
            for field_name in ("affected_url", "endpoint_url", "url", "location"):
                value = item.get(field_name)
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    urls.add(value)
    for record in records:
        payload = record.get("payload") or {}
        if payload.get("step_name") == "target_resolution":
            resolved = payload.get("resolved_target")
            if isinstance(resolved, str) and resolved.startswith(("http://", "https://")):
                urls.add(resolved)
        cmd = payload.get("cmd")
        if isinstance(cmd, str):
            urls.update(re.findall(r"https?://[^\s'\"]+", cmd))
    return [Endpoint(url=url, method="GET") for url in sorted(urls)]


def _target_url_for(match: ComponentCVEMatch, endpoints: list[Endpoint]) -> str:
    """``ExploitAgent._component_cve_target_url``, replayed verbatim.

    Kept in step with the agent by construction: the same port constraint, the
    same root preference, the same deterministic tie-break. A replay that scored
    by a rule of its own would be measuring this script.
    """
    if not endpoints:
        return ""
    candidates = list(endpoints)
    if match.component.port:
        on_port = [
            ep
            for ep in candidates
            if (urlparse(ep.url).port or (443 if urlparse(ep.url).scheme == "https" else 80))
            == match.component.port
        ]
        if on_port:
            candidates = on_port
    roots = [ep for ep in candidates if urlparse(ep.url).path in ("", "/")]
    pool = roots or candidates
    return min(pool, key=lambda ep: (len(urlparse(ep.url).path), ep.url)).url


#: The control observation. A published CVE in this engine's own catalogue whose
#: effect one of its own oracles can witness, chosen so a hit is unambiguous:
#: ``=2.4.49`` is a single-point range, so nothing near it matches by accident.
_CONTROL_NAME = "Apache"
_CONTROL_VERSION = "2.4.49"


def apply_positive_control(replay: BundleReplay) -> BundleReplay | None:
    """Re-run one bundle with a version the catalogue is known to match.

    Every measurable bundle in the corpus reserves **zero**, which is the right
    answer — no stored engagement observed a component inside a published
    affected range. But a zero produced by a matcher that cannot fire and a zero
    produced by a matcher that fired and found nothing are the same number, and
    only one of them is a measurement. So the observed inventory is re-run with
    the version substituted for one the catalogue does match, on the SAME bundle,
    through the SAME code.

    This is the never-sent control's shape, one level up: the corpus result is
    evidence only once the instrument has been shown to register a hit.

    Returns:
        The controlled replay, or ``None`` when this bundle observed nothing to
        substitute — a bundle with no Apache observation cannot carry this
        control, and inventing an observation it never made would be measuring
        this script.
    """
    if not replay.measurable:
        return None
    substituted: list[DetectedComponent] = []
    hit = False
    for component in replay.components:
        if component.name.lower() == _CONTROL_NAME.lower() and component.version:
            substituted.append(component.model_copy(update={"version": _CONTROL_VERSION}))
            hit = True
        else:
            substituted.append(component)
    if not hit:
        return None

    controlled = BundleReplay(
        engagement_id=replay.engagement_id,
        has_trace=replay.has_trace,
        passes_recorded=replay.passes_recorded,
        cap=replay.cap,
        kept=replay.kept,
        dropped_total=replay.dropped_total,
        saturated=replay.saturated,
        route=replay.route + "+control",
        truncated_source=replay.truncated_source,
        components=substituted,
        endpoints=replay.endpoints,
    )
    controlled.matches = match_components(substituted)
    controlled.confirmable = [m for m in controlled.matches if m.is_confirmable]
    dispatchable = [
        m
        for m in controlled.matches[:_MAX_COMPONENT_CVE_MATCHES]
        if m.is_confirmable and _target_url_for(m, controlled.endpoints)
    ]
    controlled.reserved = len(dispatchable)
    controlled.displaced = max(0, controlled.reserved - controlled.headroom)
    controlled.identical = controlled.reserved == 0
    return controlled


#: The package-identity control observations.
#:
#: Two of them, because the SCA half of the catalogue has two distinct outcomes
#: and a control that exercised only one would leave the other unverified:
#:
#: * ``lodash 4.17.20`` matches CVE-2021-23337, which this engine has **no
#:   oracle for**. It must produce a MATCH and reserve **nothing** — the honest
#:   behaviour, and the one a reader measuring ``reserved`` after the ingestion
#:   change would otherwise read as a dead producer.
#: * ``log4j-core 2.14.0`` matches CVE-2021-44228, which ``_test_log4shell``
#:   confirms through P6. It must reserve a slot, which is what proves a
#:   package-sourced observation reaches the reservation arithmetic at all.
#:
#: Both carry ``LOCKFILE`` provenance, so the pair also exercises the ordering
#: that decides which match spends a scarce slot.
_PACKAGE_CONTROL_LEAD_ONLY = ("lodash", "4.17.20")
_PACKAGE_CONTROL_CONFIRMABLE = ("log4j-core", "2.14.0")


def apply_package_control(replay: BundleReplay) -> BundleReplay | None:
    """Re-run one bundle with package identities INJECTED into its inventory.

    This control is a step weaker than :func:`apply_positive_control` and the
    difference is stated rather than blurred, because the two are not the same
    kind of evidence:

    * the Apache control **substitutes** a version into an observation the
      bundle really made — it changes one field of a real row;
    * this control **injects** rows the bundle never observed, because **no
      stored bundle can observe a package at all**. Package identity is read
      from served bundle bodies and supplied lockfiles, and nothing in
      ``outputs/`` stores either. There is no observation to substitute into.

    Inventing an observation is normally exactly what this replay refuses. It is
    admissible here for one reason, and only for that reason: the question being
    asked is about the *instrument*, not about the bundle. "Does a
    package-provenance component reach the matcher and the reservation
    arithmetic?" is answered by the code path, and the recorded endpoint set —
    the part that decides whether a confirmable match can be pointed anywhere —
    is the bundle's own. Every number this produces is labelled ``+pkg`` so it
    can never be read as something a stored engagement observed.

    Returns:
        The controlled replay, or ``None`` when the bundle is unmeasurable.
    """
    if not replay.measurable:
        return None

    # Start from the Apache substitution where the bundle can carry it. Without
    # it the injected log4j row is the ONLY confirmable match, and an ordering
    # assertion over a one-element list passes having compared nothing — the
    # vacuous-guard shape this repo has shipped more than once. With it there
    # are two confirmable matches of DIFFERENT provenance, which is the
    # comparison the claim is actually about.
    banner_arm = apply_positive_control(replay)
    injected = list(banner_arm.components if banner_arm is not None else replay.components)
    for name, version in (_PACKAGE_CONTROL_LEAD_ONLY, _PACKAGE_CONTROL_CONFIRMABLE):
        injected.append(
            DetectedComponent(
                name=name,
                version=version,
                source="package_identity:CONTROL (injected, never observed)",
                provenance=VersionProvenance.LOCKFILE,
            )
        )

    controlled = BundleReplay(
        engagement_id=replay.engagement_id,
        has_trace=replay.has_trace,
        passes_recorded=replay.passes_recorded,
        cap=replay.cap,
        kept=replay.kept,
        dropped_total=replay.dropped_total,
        saturated=replay.saturated,
        route=replay.route + "+pkg",
        truncated_source=replay.truncated_source,
        components=injected,
        endpoints=replay.endpoints,
    )
    controlled.matches = match_components(injected)
    controlled.confirmable = [m for m in controlled.matches if m.is_confirmable]
    dispatchable = [
        m
        for m in controlled.matches[:_MAX_COMPONENT_CVE_MATCHES]
        if m.is_confirmable and _target_url_for(m, controlled.endpoints)
    ]
    controlled.reserved = len(dispatchable)
    controlled.displaced = max(0, controlled.reserved - controlled.headroom)
    controlled.identical = controlled.reserved == 0
    return controlled


def package_control_verdicts(controlled: BundleReplay) -> dict[str, bool]:
    """The three claims the package control has to earn, each as a boolean.

    Kept apart rather than summed into one pass/fail, because they fail for
    different reasons and a single boolean would send the next reader to the
    wrong file:

    ``ingestion_reaches_the_matcher``
        A ``LOCKFILE``-provenance package produced a CVE match. False means the
        catalogue's name patterns and the producer's names do not meet — the
        ingestion path is built and joined to nothing.
    ``lead_only_reserves_nothing``
        The lead-only package matched and still claimed no plan slot. False
        means a match with no oracle is taking a reserved slot, which would
        starve a confirmable one for a lead.
    ``package_provenance_outranks_banner``
        Among confirmable matches, every ``LOCKFILE`` one sorts ahead of every
        ``BANNER`` one. This is the ordering that decides which match is
        TESTED when the ceiling bites, and it is asserted here rather than
        assumed because it is the whole point of carrying provenance at all.
    """
    lead_name = _PACKAGE_CONTROL_LEAD_ONLY[0].lower()
    confirmable_name = _PACKAGE_CONTROL_CONFIRMABLE[0].lower()

    matched_names = {m.component.name.lower() for m in controlled.matches}
    reserved_names = {
        m.component.name.lower()
        for m in controlled.matches[:_MAX_COMPONENT_CVE_MATCHES]
        if m.is_confirmable and _target_url_for(m, controlled.endpoints)
    }

    # Asserted LITERALLY, against the two provenance values by name, and NOT by
    # checking that the list is sorted by ``version_provenance_rank``. The
    # second was the first attempt and it is a tautology: ``match_components``
    # sorts on exactly that key, so the check re-derives its expectation from
    # the thing under test and passes even with the rank table inverted —
    # verified by inverting it. What the claim is actually about is that a
    # resolved dependency is tested before a string the target chose, so that
    # is what is written down.
    ordering_holds = True
    seen_banner = False
    for match in controlled.confirmable:
        if match.provenance == VersionProvenance.BANNER:
            seen_banner = True
        elif match.provenance == VersionProvenance.LOCKFILE and seen_banner:
            ordering_holds = False
            break

    return {
        "ingestion_reaches_the_matcher": lead_name in matched_names
        or confirmable_name in matched_names,
        "lead_only_reserves_nothing": lead_name not in reserved_names,
        "package_provenance_outranks_banner": ordering_holds,
    }


def package_control_exercised_ordering(controlled: BundleReplay) -> bool:
    """Whether this bundle's confirmable set could FALSIFY the ordering claim.

    The claim compares a ``LOCKFILE`` match against a ``BANNER`` one, so a
    confirmable set missing either provenance compares nothing and passes. That is not a
    weaker pass — it is no measurement at all, and reporting it beside the real
    ones is how a green guard becomes documentation of a wish. The run-level
    check below refuses a corpus where no bundle exercised it.
    """
    provenances = {m.provenance for m in controlled.confirmable}
    return VersionProvenance.LOCKFILE in provenances and VersionProvenance.BANNER in provenances


def replay_bundle(report_path: Path) -> BundleReplay | None:
    """Replay one stored bundle. ``None`` when it carries no ``plan_coverage``."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    coverage = report.get("plan_coverage")
    if not coverage:
        return None

    bundle_dir = report_path.parent
    trace_path = bundle_dir / "trace.jsonl"
    records = list(_iter_trace(trace_path)) if trace_path.exists() else []
    replay = BundleReplay(engagement_id=bundle_dir.name, has_trace=trace_path.exists())

    passes = coverage.get("passes") or []
    replay.passes_recorded = len(passes)
    deterministic = next((p for p in passes if p.get("stage") == "deterministic"), None)
    chosen = deterministic or (passes[0] if passes else {})
    replay.cap = int(chosen.get("cap") or 0)
    replay.kept = int(chosen.get("kept") or 0)
    replay.dropped_total = int(coverage.get("dropped_total") or 0)
    replay.saturated = bool(replay.cap) and replay.kept >= replay.cap

    components = _components_from_inventory(report)
    if components:
        replay.route = ROUTE_REPORT_INVENTORY
    else:
        components = _components_from_report(report)
    if components and replay.route == ROUTE_UNRECOVERABLE:
        replay.route = ROUTE_REPORT_HOSTS
    if not components and records:
        components = _components_from_handoff(records)
        if components:
            replay.route = ROUTE_TRACE_HANDOFF
        else:
            components, truncated = _components_from_tool_stdout(records)
            replay.truncated_source = truncated
            if components:
                replay.route = ROUTE_TRACE_TOOL_STDOUT
    replay.components = components

    if not replay.measurable:
        replay.note = (
            "no route reaches this bundle's component inventory - "
            + ("the trace truncates the recon handoff" if records else "no trace was kept")
            + "; reserved is NOT measurable and is not reported as zero"
        )
        return replay

    replay.endpoints = _endpoints_from_bundle(report, records)
    replay.matches = match_components(replay.components)
    replay.confirmable = [m for m in replay.matches if m.is_confirmable]
    dispatchable = [
        m
        for m in replay.matches[:_MAX_COMPONENT_CVE_MATCHES]
        if m.is_confirmable and _target_url_for(m, replay.endpoints)
    ]
    replay.reserved = len(dispatchable)
    # On a saturated plan every reserved slot is one the Tier-1 fill had taken,
    # so displacement is the reservation itself. On an unsaturated plan the
    # reservation is absorbed by the headroom first.
    replay.displaced = max(0, replay.reserved - replay.headroom)
    replay.identical = replay.reserved == 0
    if replay.reserved == 0:
        replay.note = "no dispatchable CVE match -> reservation 0 -> plan byte-identical"
    elif replay.truncated_source:
        replay.note = "inventory rebuilt from TRUNCATED stdout - reserved is a lower bound"
    return replay


def replay_corpus(outputs_root: Path) -> list[BundleReplay]:
    """Every stored bundle carrying ``plan_coverage``, oldest path order."""
    results: list[BundleReplay] = []
    for report_path in sorted(outputs_root.glob("*/report_*.json")):
        replayed = replay_bundle(report_path)
        if replayed is not None:
            results.append(replayed)
    return results


def _render(results: list[BundleReplay]) -> str:
    lines: list[str] = []
    lines.append(f"Bundles carrying plan_coverage: {len(results)}")
    with_baseline = [r for r in results if r.baseline_measurable]
    lines.append(f"  with a recorded planner pass (a measurable baseline): {len(with_baseline)}")
    lines.append(
        f"  with passes_recorded == 0 (baseline UNMEASURABLE, not zero): "
        f"{len(results) - len(with_baseline)}"
    )
    saturated = [r for r in with_baseline if r.saturated]
    caps = sorted({r.cap for r in saturated})
    lines.append(
        f"Saturated at their cap (zero headroom today): {len(saturated)}/{len(with_baseline)}"
        + (f" - every one at cap={caps[0]}" if len(caps) == 1 else "")
    )
    void = [r for r in with_baseline if r.kept == 0]
    if void:
        lines.append(
            "Recorded a pass but kept nothing (the plan never filled): "
            + ", ".join(r.engagement_id[:8] for r in void)
        )
    measurable = [r for r in results if r.measurable]
    lines.append(f"Inventory recoverable: {len(measurable)}/{len(results)}")
    lines.append("")
    header = (
        f"{'engagement':10} {'cap':>4} {'kept':>5} {'head':>5} "
        f"{'inv':>4} {'cve':>4} {'rsv':>4} {'disp':>5}  route / note"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        inv = "n/a" if not r.measurable else str(len(r.components))
        cve = "n/a" if not r.measurable else str(len(r.matches))
        rsv = "n/a" if not r.measurable else str(r.reserved)
        disp = "n/a" if not r.measurable else str(r.displaced)
        cap = str(r.cap) if r.baseline_measurable else "n/a"
        kept = str(r.kept) if r.baseline_measurable else "n/a"
        head = str(r.headroom) if r.baseline_measurable else "n/a"
        note = r.note
        if not r.baseline_measurable:
            note = "passes_recorded=0; no plan baseline stored" + (f"; {note}" if note else "")
        lines.append(
            f"{r.engagement_id[:8]:10} {cap:>4} {kept:>5} {head:>5} "
            f"{inv:>4} {cve:>4} {rsv:>4} {disp:>5}  {r.route}" + (f" - {note}" if note else "")
        )
    lines.append("")

    identical = [r for r in measurable if r.identical]
    lines.append(
        f"BYTE-IDENTICAL (reserved == 0 -> Tier-1 cap unchanged): "
        f"{len(identical)}/{len(measurable)} measurable bundles"
    )
    spending = [r for r in measurable if r.reserved]
    if spending:
        lines.append(f"Bundles that would spend reserved slots: {len(spending)}")
        for r in spending:
            names = ", ".join(f"{m.cve.cve_id} ({m.provenance.value})" for m in r.confirmable[:5])
            lines.append(
                f"  {r.engagement_id[:8]}  reserved={r.reserved} displaced={r.displaced}  {names}"
            )
    else:
        lines.append("Bundles that would spend reserved slots: 0")
    lines.append("")
    lines.append("POSITIVE CONTROL - the same bundles, with the observed Apache version")
    lines.append(f"substituted for {_CONTROL_VERSION} (CVE-2021-41773, confirmable via _test_lfi).")
    lines.append("A zero above is a measurement only if these are non-zero.")
    controls = [c for c in (apply_positive_control(r) for r in measurable) if c is not None]
    if not controls:
        lines.append("  NO BUNDLE COULD CARRY THE CONTROL - the corpus zero is UNVERIFIED.")
    for c in controls:
        lines.append(
            f"  {c.engagement_id[:8]}  matches={len(c.matches)} confirmable={len(c.confirmable)} "
            f"reserved={c.reserved} tier1_displaced={c.displaced} "
            f"(tier1 cap {c.cap} -> {c.cap - c.reserved})"
        )
    lines.append("")
    lines.append("PACKAGE-IDENTITY CONTROL - the same bundles with a lockfile-provenance")
    lines.append(
        f"{_PACKAGE_CONTROL_LEAD_ONLY[0]} {_PACKAGE_CONTROL_LEAD_ONLY[1]} (no oracle -> lead) and "
        f"{_PACKAGE_CONTROL_CONFIRMABLE[0]} {_PACKAGE_CONTROL_CONFIRMABLE[1]} "
        "(CVE-2021-44228, confirmable via _test_log4shell) INJECTED."
    )
    lines.append("INJECTED, not substituted: no stored bundle records a served bundle body or a")
    lines.append("supplied lockfile, so there is no package observation to substitute into. These")
    lines.append("numbers measure the instrument, never what a stored engagement observed.")
    pkg_controls = [c for c in (apply_package_control(r) for r in measurable) if c is not None]
    if not pkg_controls:
        lines.append("  NO MEASURABLE BUNDLE - the package-identity path is UNVERIFIED here.")
    for c in pkg_controls[:5]:
        verdicts = package_control_verdicts(c)
        lines.append(
            f"  {c.engagement_id[:8]}  matches={len(c.matches)} "
            f"confirmable={len(c.confirmable)} reserved={c.reserved} "
            f"tier1_displaced={c.displaced}"
        )
        exercised = package_control_exercised_ordering(c)
        lines.append(
            "      "
            + "  ".join(f"{name}={'PASS' if held else 'FAIL'}" for name, held in verdicts.items())
            + ("  [ordering EXERCISED]" if exercised else "  [ordering not exercised here]")
        )
    if len(pkg_controls) > 5:
        lines.append(f"  ({len(pkg_controls) - 5} further controlled bundle(s) not listed)")
    if pkg_controls:
        exercised_n = sum(1 for c in pkg_controls if package_control_exercised_ordering(c))
        lines.append(
            f"  Ordering claim exercised on {exercised_n}/{len(pkg_controls)} controlled "
            "bundle(s) - i.e. carried both a lockfile- and a banner-provenance confirmable "
            "match, so a wrong order could have been observed."
        )

    unmeasurable = [r for r in results if not r.measurable]
    if unmeasurable:
        lines.append("")
        lines.append(
            f"UNMEASURABLE: {len(unmeasurable)} bundle(s) carry no recoverable inventory. "
            "Not counted as no-match - the question was never answerable from what was stored."
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--outputs-root", default=str(REPO_ROOT / "outputs"))
    parser.add_argument("--json", action="store_true", help="emit the per-bundle rows as JSON")
    args = parser.parse_args()

    outputs_root = Path(args.outputs_root)
    if not outputs_root.is_dir():
        print(f"outputs root not found: {outputs_root}", file=sys.stderr)
        return 2

    results = replay_corpus(outputs_root)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print(_render(results))

    # A measurable bundle whose reservation is non-zero and whose plan was NOT
    # saturated should have been absorbed by headroom; anything else is a
    # regression in the arithmetic this replay exists to check.
    for r in results:
        if r.measurable and r.reserved == 0 and r.identical is not True:
            print(
                f"INCONSISTENT: {r.engagement_id} reserved 0 but not byte-identical",
                file=sys.stderr,
            )
            return 1

    # A corpus of zeros is evidence only if the instrument can register a hit.
    # A control that reserves nothing means the matcher, the endpoint recovery or
    # the reservation arithmetic is dead, and every zero above is uninterpretable.
    measurable = [r for r in results if r.measurable]
    controls = [c for c in (apply_positive_control(r) for r in measurable) if c is not None]
    if measurable and not any(c.reserved for c in controls):
        print(
            "POSITIVE CONTROL FAILED: no bundle reserved a slot even with a "
            "known-affected version substituted - the corpus zeros prove nothing",
            file=sys.stderr,
        )
        return 1

    # The same discipline for the ingestion path. A zero from a matcher with no
    # package input is indistinguishable from a zero from a matcher that works,
    # and after this change EVERY stored bundle is the first case: none of them
    # can carry a package observation at all. So the ingestion path is verified
    # against injected identities or it is not verified.
    pkg_controls = [c for c in (apply_package_control(r) for r in measurable) if c is not None]
    if measurable and not pkg_controls:
        print(
            "PACKAGE CONTROL FAILED: no measurable bundle could carry the control, "
            "so nothing here says whether package identity reaches the matcher",
            file=sys.stderr,
        )
        return 1
    for controlled in pkg_controls:
        for claim, held in package_control_verdicts(controlled).items():
            if not held:
                print(
                    f"PACKAGE CONTROL FAILED on {controlled.engagement_id}: {claim}",
                    file=sys.stderr,
                )
                return 1
    if pkg_controls and not any(package_control_exercised_ordering(c) for c in pkg_controls):
        print(
            "PACKAGE CONTROL FAILED: no controlled bundle carried both a lockfile- and a "
            "banner-provenance confirmable match, so package_provenance_outranks_banner "
            "passed without comparing anything - it is not a measurement",
            file=sys.stderr,
        )
        return 1
    if pkg_controls and not any(c.reserved for c in pkg_controls):
        print(
            "PACKAGE CONTROL FAILED: a confirmable lockfile-provenance match reserved "
            "no slot on any bundle - package identity reaches the matcher but not the "
            "reservation, so the fourth plan source cannot spend what ingestion finds",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
