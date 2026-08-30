"""Package identity: the producer that made the dependency-SCA catalogue reachable.

Every test here is offline. The module takes bytes or a path and returns
:class:`DetectedComponent` rows, which is the whole point of keeping the I/O in
the recon agent: the thing that decides what a CVE match rests on is testable
without a target.

The load-bearing tests are the two that are about what this module REFUSES to
do — a version range is not an observation, and a plausible-looking name is not
an allow-listed one — because the failure mode this producer could introduce is
manufacturing an inventory, and a manufactured inventory feeds a CVE matcher
that then reports leads about software the host never ran.
"""

from __future__ import annotations

import json

import pytest

from clinkz.agents._package_identity import (
    PackageIdentityOutput,
    PackageInventoryReport,
    build_inventory,
    bundle_candidate_count,
    packages_from_bundle,
    packages_from_package_json,
    packages_from_package_lock,
    packages_from_source_tree,
    packages_from_yarn_lock,
)
from clinkz.knowledge.component_cves import match_components
from clinkz.models.recon import (
    DetectedComponent,
    VersionProvenance,
    dedupe_components,
    inventory_summary,
    version_provenance_rank,
)
from clinkz.tools.base import ToolOutput

# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_the_producer_declares_the_fingerprint_contract() -> None:
    """A second inventory path is the Part-1 seam again, answered the same way.

    The recon seam used to read ``hasattr(r, "technologies")`` then
    ``hasattr(r, "tech")`` — two spellings because two wrappers differed, and a
    third would have contributed nothing silently. A new component source must
    therefore DECLARE, not be guessed at.
    """
    assert issubclass(PackageIdentityOutput, ToolOutput)
    assert PackageIdentityOutput.declares_components()


def test_a_failed_producer_is_distinguishable_from_an_empty_one() -> None:
    """``success=False`` with no rows is not the same fact as no packages."""
    failed = PackageIdentityOutput(tool_name="package_identity", success=False)
    assert failed.detected_components() == []
    assert failed.success is False


# ---------------------------------------------------------------------------
# Lockfiles: LOCKFILE provenance
# ---------------------------------------------------------------------------


def test_package_lock_v3_flat_packages_map() -> None:
    text = json.dumps(
        {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "9.9.9"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/widget": {"version": "2.1.0"},
            },
        }
    )
    rows = packages_from_package_lock(text)
    assert {(c.name, c.version) for c in rows} == {
        ("lodash", "4.17.20"),
        ("@scope/widget", "2.1.0"),
    }
    assert all(c.provenance is VersionProvenance.LOCKFILE for c in rows)


def test_the_root_package_entry_is_not_a_dependency() -> None:
    """``packages[""]`` describes the application under test, not something it ships.

    Emitting it would put the CLIENT'S OWN version into the dependency
    inventory, where a catalogue entry could match it — a CVE lead about the
    application from its own package name.
    """
    text = json.dumps({"packages": {"": {"name": "juice-shop", "version": "1.2.3"}}})
    assert packages_from_package_lock(text) == []


def test_package_lock_v1_nested_dependencies() -> None:
    """The older layout is read too — a real tree may carry either."""
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.20", "dependencies": {"tiny-dep": {"version": "1.0.0"}}}
            },
        }
    )
    rows = packages_from_package_lock(text)
    assert {(c.name, c.version) for c in rows} == {("lodash", "4.17.20"), ("tiny-dep", "1.0.0")}


def test_a_malformed_lockfile_yields_nothing_and_does_not_raise() -> None:
    assert packages_from_package_lock("{not json") == []
    assert packages_from_package_lock("[]") == []


def test_yarn_lock_reads_the_resolution_not_the_descriptor() -> None:
    """Several descriptors share one resolution; the resolution is the observation."""
    text = """# yarn lockfile v1

lodash@^4.17.0, lodash@~4.17.15:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"""
    rows = packages_from_yarn_lock(text)
    assert [(c.name, c.version) for c in rows] == [("lodash", "4.17.21")]
    assert rows[0].provenance is VersionProvenance.LOCKFILE


def test_a_yarn_descriptor_with_no_resolution_contributes_nothing() -> None:
    """An unresolved descriptor is a RANGE, and a range is not an observation."""
    assert packages_from_yarn_lock('lodash@^4.17.0:\n  resolved "https://x"\n') == []


# ---------------------------------------------------------------------------
# Manifests: MANIFEST provenance, and the range refusal
# ---------------------------------------------------------------------------


def test_only_an_exact_pin_is_an_observation() -> None:
    """``^4.17.20`` says what was ASKED FOR, not what arrived.

    This is the fabrication the module exists to refuse. Reading the floor of a
    range as the installed version would manufacture a CVE match against a
    version that may never have been on the host, from a file that does not
    claim it.
    """
    text = json.dumps(
        {
            "dependencies": {
                "pinned": "4.17.20",
                "caret": "^4.17.20",
                "tilde": "~4.17.20",
                "gte": ">=4.17.20",
                "star": "*",
                "range": "1.0.0 - 2.0.0",
                "tag": "latest",
                "url": "git+https://example.invalid/x.git",
            }
        }
    )
    rows = packages_from_package_json(text)
    assert [(c.name, c.version) for c in rows] == [("pinned", "4.17.20")]
    assert rows[0].provenance is VersionProvenance.MANIFEST


def test_a_manifest_pin_may_carry_a_leading_marker() -> None:
    text = json.dumps({"dependencies": {"alpha": "=1.2.3", "beta": "v4.5.6"}})
    assert {(c.name, c.version) for c in packages_from_package_json(text)} == {
        ("alpha", "1.2.3"),
        ("beta", "4.5.6"),
    }


# ---------------------------------------------------------------------------
# Served bundles: ARTIFACT_STRING provenance
# ---------------------------------------------------------------------------


def test_a_license_banner_is_an_artifact_string() -> None:
    js = "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors */"
    rows = packages_from_bundle(js, "http://target/main.js")
    assert [(c.name, c.version) for c in rows] == [("jQuery", "3.4.1")]
    assert rows[0].provenance is VersionProvenance.ARTIFACT_STRING
    assert "http://target/main.js" in rows[0].source


def test_an_npm_coordinate_is_an_artifact_string() -> None:
    rows = packages_from_bundle("/* bundled from lodash@4.17.20 */")
    assert [(c.name, c.version) for c in rows] == [("lodash", "4.17.20")]


def test_a_bundle_with_no_version_string_yields_nothing() -> None:
    assert packages_from_bundle("var a=1;function b(){return 2}") == []


def test_minifier_noise_is_not_a_package_identity() -> None:
    """A one- or two-character name is a minified symbol, not a registry entry."""
    assert packages_from_bundle("x@1.2.3 t@4.5.6") == []


def test_the_candidate_count_is_taken_before_the_filter() -> None:
    """A reader that discards everything must not report itself correctly-empty.

    ``candidates_seen`` means "input of this shape was found", not "input this
    producer chose to keep". Counting after the filter is what would let the
    ffuf shape — found input, emitted nothing — grade itself as a target with
    nothing to find.
    """
    js = "x@1.2.3 t@4.5.6"
    assert bundle_candidate_count(js) == 2
    assert packages_from_bundle(js) == []


# ---------------------------------------------------------------------------
# The tree walk
# ---------------------------------------------------------------------------


def test_no_source_tree_is_correctly_empty_not_a_defect(tmp_path) -> None:
    rows, report = packages_from_source_tree(None)
    assert rows == []
    assert report.inputs_examined == 0
    assert "no source tree" in report.correctly_empty_reason


def test_node_modules_is_never_walked(tmp_path) -> None:
    """The installed tree is what the lockfile already resolved.

    Walking it would inventory every transitive dependency's own manifest as
    though the application declared it — thousands of rows, and a CVE worklist
    that describes npm rather than the target.
    """
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"kept": "1.0.0"}}), encoding="utf-8"
    )
    nested = tmp_path / "node_modules" / "buried"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text(
        json.dumps({"dependencies": {"dropped": "2.0.0"}}), encoding="utf-8"
    )
    rows, report = packages_from_source_tree(tmp_path)
    assert {c.name for c in rows} == {"kept"}
    assert report.inputs_examined == 1


def test_a_missing_directory_is_reported_not_raised(tmp_path) -> None:
    rows, report = packages_from_source_tree(tmp_path / "does-not-exist")
    assert rows == []
    assert "not a directory" in report.detail


# ---------------------------------------------------------------------------
# The inventory report — how far the pipeline got
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("report", "expect_reason"),
    [
        (PackageInventoryReport(inputs_examined=0, candidates_seen=0, components_emitted=0), True),
        (PackageInventoryReport(inputs_examined=3, candidates_seen=0, components_emitted=0), True),
        # Found candidates, emitted none: the ffuf shape. NOT correctly empty,
        # and no reason string may talk it away.
        (PackageInventoryReport(inputs_examined=3, candidates_seen=7, components_emitted=0), False),
        (PackageInventoryReport(inputs_examined=3, candidates_seen=7, components_emitted=2), False),
    ],
)
def test_only_two_shapes_of_zero_are_correct(
    report: PackageInventoryReport, expect_reason: bool
) -> None:
    assert bool(report.correctly_empty_reason) is expect_reason


def test_an_empty_bundle_still_counts_as_an_input_examined() -> None:
    """Fetching it is what proves the target serves bundles.

    Dropping it would make a target that serves nothing indistinguishable from
    one that was never asked — which is the whole distinction the report exists
    to make.
    """
    out = build_inventory(
        tree_components=[],
        tree_report=PackageInventoryReport(),
        bundle_bodies=[("http://t/a.js", "")],
    )
    assert out.report.inputs_examined == 1
    assert out.report.candidates_seen == 0
    assert "no input of this kind" not in out.report.correctly_empty_reason


# ---------------------------------------------------------------------------
# Provenance is what this is for
# ---------------------------------------------------------------------------


def test_a_lockfile_entry_outranks_a_banner_for_the_same_product() -> None:
    """``dedupe_components`` stopped being a no-op when this producer arrived."""
    merged = dedupe_components(
        [
            DetectedComponent(
                name="express",
                version="4.17.1",
                source="whatweb",
                provenance=VersionProvenance.BANNER,
            ),
            DetectedComponent(
                name="express",
                version="4.18.2",
                source="package_identity:package-lock.json",
                provenance=VersionProvenance.LOCKFILE,
            ),
        ]
    )
    assert [(c.version, c.provenance) for c in merged] == [("4.18.2", VersionProvenance.LOCKFILE)]


def test_the_artifact_string_rank_sits_between_manifest_and_banner() -> None:
    """A bundle's own banner comment is not a ``Server:`` header.

    Both are defeated by a back-port, but one is baked into the shipped bytes
    and the other is one ``ServerTokens`` line from saying nothing.
    """
    assert (
        version_provenance_rank(VersionProvenance.MANIFEST)
        < version_provenance_rank(VersionProvenance.ARTIFACT_STRING)
        < version_provenance_rank(VersionProvenance.BANNER)
    )


def test_the_catalogue_half_that_could_never_fire_now_can() -> None:
    """Five entries against three npm packages had no possible producer.

    ``whatweb`` and ``nmap`` fingerprint SERVERS. Their zeros were never an
    observation about a target — the question was never asked. This is the test
    that says it now is.
    """
    rows, report = packages_from_source_tree(None)
    assert rows == []  # black-box: still nothing, and that is honest

    out = build_inventory(
        tree_components=packages_from_package_lock(
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}})
        ),
        tree_report=PackageInventoryReport(inputs_examined=1, candidates_seen=1),
        bundle_bodies=[("http://t/v.js", "/*! jQuery v3.4.1 */")],
    )
    matches = match_components(out.detected_components())
    assert {m.cve.cve_id for m in matches} == {"CVE-2021-23337", "CVE-2020-11022"}
    # Neither is confirmable: this engine has no prototype-pollution oracle and
    # declines to claim its XSS oracle for a library-version match. So package
    # identity produces LEADS and reserves no plan slot, by construction.
    assert not any(m.is_confirmable for m in matches)


def test_the_inventory_summary_is_a_view_not_a_second_population() -> None:
    """Its counts sum to its rows, so a consumer can never read it as separate."""
    components = [
        DetectedComponent(name="Apache", version="2.4.67", provenance=VersionProvenance.BANNER),
        DetectedComponent(name="lodash", version="4.17.20", provenance=VersionProvenance.LOCKFILE),
        DetectedComponent(name="nginx", version="", provenance=VersionProvenance.UNDECLARED),
    ]
    summary = inventory_summary(components)
    assert summary["total"] == len(summary["components"]) == 3
    assert summary["versioned"] == 2
    assert sum(summary["by_provenance"].values()) == summary["total"]
    # Strongest provenance first: that IS the order reserved slots are spent in.
    assert [row["name"] for row in summary["components"]] == ["lodash", "Apache", "nginx"]


def test_an_empty_inventory_renders_nothing_rather_than_an_empty_table() -> None:
    assert inventory_summary([]) == {}
