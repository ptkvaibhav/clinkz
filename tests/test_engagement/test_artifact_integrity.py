"""The disclosure gate claims only what it checks (register R30).

``CLEAN`` means no credential escaped. It never meant the bundle is still the
record of the run, and engagement ``e7bd146a`` showed the difference: CLEAN, 25
findings, and 1,134 sites where redaction had rewritten schema or target
vocabulary. The integrity check is a second verdict beside the leak check; a
CORRUPTED bundle is not certifiable whatever the leak check says.

The excerpts below are verbatim from ``e7bd146a`` (outputs are never committed,
so the bundle itself cannot be the fixture). DVWA's public markup only — the
bundle's secret is already a marker in every one of them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.engagement.artifact_scan import scan_artifact_tree, scan_integrity

E7BD146A_EXCERPTS = {
    "identifier_rewritten": [
        "form fields=['step', '[REDACTED]_new', '[REDACTED]_conf', 'Change']",
        'f\\" name=\\"[REDACTED]_new\\"><br />',
        "TIFIED WITH mysql_native_[REDACTED] BY 'p@ssw0rd';",
    ],
    "protocol_keyword_rewritten": [
        '>\\r\\n\\t\\t\\t<input type=\\"[REDACTED]\\" AUTOCOMPLETE=\\"of',
        "br />\\n<input type='[REDACTED]' id='[REDACTED]' na",
    ],
    "name_rewritten": [
        '":\\"tony\\",\\"level\\":0,\\"[REDACTED]\\":\\"5f4dcc3b',
    ],
}


@pytest.mark.parametrize(
    ("kind", "excerpt"),
    [(kind, excerpt) for kind, excerpts in E7BD146A_EXCERPTS.items() for excerpt in excerpts],
)
def test_every_e7bd146a_damage_shape_is_detected(kind: str, excerpt: str) -> None:
    assert kind in {f.kind for f in scan_integrity(excerpt)}


@pytest.mark.parametrize(
    "text",
    [
        "password=[REDACTED]&Login=Login",
        '{"pw":"[REDACTED]"}',
        "\\n[REDACTED]\\n",
        "%22[REDACTED]%22",
        "\\u0022[REDACTED]\\u0022",
        "Default [REDACTED] = <code>[REDACTED]</code>",
        "[REDACTED:JWT sha256=ab12 alg=HS256 claims=[sub]]tail",
        "admin:[REDACTED]@host",
    ],
)
def test_a_value_removed_from_a_value_position_is_not_damage(text: str) -> None:
    assert scan_integrity(text) == []


def test_e7bd146a_is_clean_and_corrupted_and_not_certifiable(tmp_path: Path) -> None:
    """The positive control: a leak-clean bundle that must still fail."""
    trace = "\n".join(e for excerpts in E7BD146A_EXCERPTS.values() for e in excerpts)
    (tmp_path / "trace.jsonl").write_text(trace, encoding="utf-8")
    report = scan_artifact_tree(tmp_path, engagement_id="e7bd146a")
    assert report.clean, "no credential shape is present — the leak check passes"
    assert report.corrupted
    assert not report.certifiable
    line = report.summary_line()
    assert "ARTIFACT SCAN CLEAN" in line and "INTEGRITY CORRUPTED" in line
    assert "NOT CERTIFIABLE" in line


def test_an_intact_bundle_says_so(tmp_path: Path) -> None:
    (tmp_path / "trace.jsonl").write_text('{"body": "password=[REDACTED]"}', encoding="utf-8")
    report = scan_artifact_tree(tmp_path)
    assert report.certifiable
    assert "INTEGRITY INTACT" in report.summary_line()
