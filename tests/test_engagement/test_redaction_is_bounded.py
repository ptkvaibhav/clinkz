"""A redaction removes a value, never the document after it (register R21).

The failure
-----------

``PRIVATE_KEY_RE`` ended ``(?:<END-banner>|\\Z)`` under ``re.DOTALL``. A BEGIN
banner with no END after it matched to end-of-string, and the post-render
``redact()`` pass over the Markdown replaced everything after the banner —
*What was NOT tested*, the component ledger, the run audit — with one marker. A
response body is quoted verbatim into the PoC block, so the target chose where
the document ended by serving one line. Invariant 55: a guard that hands the
target a suppression primitive is worse than the leak it prevents.

And the disclosure gate graded that document INTACT: the R30 integrity patterns
look at what surrounds a marker, and a marker with nothing after it is a
well-formed marker. Deletion is corruption too, so the gate now reads what a
report must CONTAIN (``scan_report_completeness``).

Every bundle assertion here reads a file the real ``ReportAgent.run`` wrote,
because the redaction that deleted the sections runs at the producer.

The PEM banners are assembled at runtime: the commit guard refuses the literal in
any tracked file, correctly, so the fixture bends.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from re import _constants as sre_c  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from types import ModuleType
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.engagement import (
    credential_shapes,
    render_safety,
    secret_provenance,
    secrets,
)
from clinkz.engagement.artifact_scan import (
    REPORT_END_SENTINEL,
    REPORT_REQUIRED_SECTIONS,
    scan_artifact_tree,
    scan_report_completeness,
)
from clinkz.engagement.credential_shapes import (
    PRIVATE_KEY_UNTERMINATED_LABEL,
    redact_shapes,
)
from clinkz.models.finding import Finding, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from tests.authorization_fixtures import TEST_AUTHORIZATION

_DASHES = "-" * 5
_BEGIN = f"{_DASHES}BEGIN RSA PRIVATE KEY{_DASHES}"
_END = f"{_DASHES}END RSA PRIVATE KEY{_DASHES}"

#: Key material that must not survive, and evidence after it that must.
_KEY_BODY = "MIIEpAIBAAKCAQEAzvKEYBODYzz"
_TAIL = "TAILSURVIVESxq"

#: A response body carrying a bare BEGIN banner: the body that follows it, then
#: a line that is not base64 and is evidence, not key.
_BARE_BANNER_EVIDENCE = f"Response: 200 OK\n{_BEGIN}\n{_KEY_BODY}\n{_KEY_BODY}\nServer: {_TAIL}"

#: The same banner with a line break inside it, in an INLINE field. The per-field
#: pass does not see a banner (it needs a space after BEGIN); render_safety then
#: collapses the line break to a space, and the post-render ``redact()`` over the
#: whole Markdown does. That is the path that deleted the sections — the
#: block-path banner above is truncated per field before the renderer runs.
_SPLIT_BANNER_TARGET = (
    f"https://app.test/k?v={_DASHES}BEGIN\nRSA PRIVATE KEY{_DASHES}\n{_KEY_BODY}\nnext: {_TAIL}"
)

#: The pattern as it stood before R21, rebuilt here with the ``end`` group the
#: current replacement reads. Semantically identical: ``(?:END|\\Z)``.
_LEGACY_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:(?P<end>-----END [A-Z0-9 ]*PRIVATE KEY-----)|\Z)",
    re.DOTALL,
)


def _scope() -> EngagementScope:
    return EngagementScope(
        name="Acme Q3",
        targets=[ScopeEntry(value="https://app.test", type=ScopeType.URL)],
        authorization=TEST_AUTHORIZATION,
    )


async def _bundle(
    engagement_id: str,
    evidence: list[str],
    *,
    target: str = "https://app.test/config",
    with_finding: bool = True,
) -> dict[str, object]:
    """Run the real report agent over one finding; return its result."""
    finding = Finding(
        title="Sensitive file disclosure",
        description="The server returned a configuration file.",
        severity=Severity.HIGH,
        target=target,
        evidence=evidence,
    )
    state = AsyncMock()
    state.get_findings.return_value = [finding.model_dump(mode="json")] if with_finding else []
    state.get_targets.return_value = []
    state.get_research_leads.return_value = []
    agent = ReportAgent(
        llm=AsyncMock(), tools=[], scope=_scope(), state=state, engagement_id=engagement_id
    )
    return await agent.run(
        {
            "engagement_id": engagement_id,
            "engagement_name": "Acme Q3",
            "authorization": TEST_AUTHORIZATION.model_dump(mode="json"),
        }
    )


def _pdf_text(path: Path) -> str:
    pypdf = pytest.importorskip("pypdf")
    return "\n".join(page.extract_text() or "" for page in pypdf.PdfReader(str(path)).pages)


# ---------------------------------------------------------------------------
# The observed failure — a bare banner, rendered through all three documents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_banner_the_renderer_assembles_deletes_no_section(tmp_path: Path) -> None:
    """The observed failure: red before the fix — every section after the
    finding was gone from the Markdown, and the PDF lost the rest of the field.
    """
    result = await _bundle("eng-r21-inline", ["Response: 200"], target=_SPLIT_BANNER_TARGET)
    markdown = Path(str(result["markdown_path"])).read_text(encoding="utf-8")

    missing = [h for h in REPORT_REQUIRED_SECTIONS if h not in markdown.splitlines()]
    assert not missing, f"sections deleted after a target-served banner: {missing}"
    assert markdown.rstrip().endswith(REPORT_END_SENTINEL)
    assert _TAIL in markdown
    assert _KEY_BODY not in markdown
    assert PRIVATE_KEY_UNTERMINATED_LABEL in markdown

    if result["pdf_path"]:
        pdf = _pdf_text(Path(str(result["pdf_path"])))
        assert _TAIL in pdf, "pdf: the rest of the field after the banner was deleted"
        assert _KEY_BODY not in pdf


@pytest.mark.asyncio
async def test_a_bare_begin_banner_deletes_no_evidence_after_the_key(tmp_path: Path) -> None:
    """The block path: red before the fix in all three documents.

    The per-field pass truncated the evidence entry at the banner, so the line
    after the key body — evidence, not key — was gone from JSON, Markdown and
    PDF alike. The key body itself must still be gone from every one of them.
    """
    result = await _bundle("eng-r21", [_BARE_BANNER_EVIDENCE])
    markdown = Path(str(result["markdown_path"])).read_text(encoding="utf-8")
    raw_json = Path(str(result["json_path"])).read_text(encoding="utf-8")

    assert not scan_report_completeness(markdown)
    for name, text in (("markdown", markdown), ("json", raw_json)):
        assert _TAIL in text, f"{name}: evidence after the key body was deleted"
        assert _KEY_BODY not in text, f"{name}: the key body survived redaction"
        assert PRIVATE_KEY_UNTERMINATED_LABEL in text, (
            f"{name}: a bounded redaction must say the block had no END banner"
        )
    evidence = json.loads(raw_json)["findings"][0]["evidence"][0]
    assert evidence.startswith("Response: 200 OK\n")

    if result["pdf_path"]:
        pdf = _pdf_text(Path(str(result["pdf_path"])))
        assert _TAIL in pdf, "pdf: evidence after the key body was deleted"
        assert _KEY_BODY not in pdf


@pytest.mark.asyncio
async def test_a_banner_pair_across_responses_deletes_no_finding(tmp_path: Path) -> None:
    """The bounded-match half: BEGIN in one response, END in a later one.

    A lazy ``.*?`` to the END banner would remove everything between — the
    engine's own lines included. Prose between two banners is not a key line.
    """
    result = await _bundle(
        "eng-r21-pair",
        [f"Response: 200\n{_BEGIN}\n{_KEY_BODY}", f"Middle: {_TAIL} engine line", f"x\n{_END}"],
    )
    markdown = Path(str(result["markdown_path"])).read_text(encoding="utf-8")
    assert _TAIL in markdown
    assert _KEY_BODY not in markdown
    assert not scan_report_completeness(markdown)


# ---------------------------------------------------------------------------
# The gate must grade the pre-fix document CORRUPTED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_pre_fix_output_is_graded_corrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The legacy pattern reproduces the deletion, and the gate catches it.

    Both halves are asserted, so this cannot pass by the legacy pattern failing
    to reproduce: the sections ARE gone, and the bundle is NOT certifiable.
    """
    monkeypatch.setattr(credential_shapes, "PRIVATE_KEY_RE", _LEGACY_PRIVATE_KEY_RE)
    result = await _bundle("eng-r21-legacy", ["Response: 200"], target=_SPLIT_BANNER_TARGET)
    markdown_path = Path(str(result["markdown_path"]))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "## What was NOT tested" not in markdown, "the legacy pattern must reproduce R21"

    report = scan_artifact_tree(markdown_path.parent, engagement_id="eng-r21-legacy")
    kinds = {f.kind for f in report.integrity_findings}
    assert {"report_truncated", "report_section_missing"} <= kinds
    assert report.clean, "nothing leaked — the leak check alone would have passed it"
    assert report.corrupted and not report.certifiable


@pytest.mark.asyncio
async def test_the_fixed_output_is_graded_intact(tmp_path: Path) -> None:
    """The control: the same bundle under the bounded pattern is certifiable."""
    result = await _bundle("eng-r21-fixed", ["Response: 200"], target=_SPLIT_BANNER_TARGET)
    root = Path(str(result["markdown_path"])).parent
    report = scan_artifact_tree(root, engagement_id="eng-r21-fixed")
    assert report.integrity_findings == []
    assert report.certifiable


def test_findings_cut_from_the_middle_are_a_count_mismatch() -> None:
    sections = "\n\n".join(REPORT_REQUIRED_SECTIONS)
    document = sections.replace(
        "## Findings", "- **Confirmed findings:** 3\n\n## Findings\n\n## 1. a\n\n## 3. c"
    )
    document += f"\n\n{REPORT_END_SENTINEL}\n"
    kinds = {f.kind for f in scan_report_completeness(document)}
    assert kinds == {"report_finding_count_mismatch"}


def test_a_heading_inside_a_fence_is_not_the_documents() -> None:
    """Target bytes in a PoC block cannot satisfy, or break, the check."""
    fenced = "```\n" + "\n".join(REPORT_REQUIRED_SECTIONS) + f"\n{REPORT_END_SENTINEL}\n```\n"
    kinds = {f.kind for f in scan_report_completeness(fenced)}
    assert kinds == {"report_truncated", "report_section_missing"}


# ---------------------------------------------------------------------------
# The required-section list is the renderer's, in both directions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_required_sections_are_exactly_the_unconditional_headings(tmp_path: Path) -> None:
    """Computed from the renderer: the headings EVERY variant writes, in order.

    A required heading some run omits would grade a good report CORRUPTED — a
    permanent false alarm (invariant 77). An unconditional heading missing from
    the list is a section whose deletion the gate cannot see.
    """
    variants: list[list[str]] = []
    # With evidence, without, and the no-finding path, which returns early.
    for engagement_id, evidence, with_finding in (
        ("eng-r21-a", ["a"], True),
        ("eng-r21-b", [], True),
        ("eng-r21-c", [], False),
    ):
        result = await _bundle(engagement_id, evidence, with_finding=with_finding)
        lines = Path(str(result["markdown_path"])).read_text(encoding="utf-8").splitlines()
        variants.append([line for line in lines if line.startswith("## ")])
    common = [h for h in variants[0] if all(h in v for v in variants[1:])]
    common = [h for h in common if not re.match(r"^## \d+\. ", h)]
    assert tuple(common) == REPORT_REQUIRED_SECTIONS


# ---------------------------------------------------------------------------
# The computed domain — every pattern that can match to end of input
# ---------------------------------------------------------------------------

#: The modules that hold the redaction vocabulary, plus the render pass that
#: transforms the same structure. The domain is computed over their globals.
_VOCABULARY_MODULES: tuple[ModuleType, ...] = (
    credential_shapes,
    secrets,
    secret_provenance,
    render_safety,
)

#: Every pattern in the domain, with why its unbounded span cannot reach the
#: end of a document. Hand-maintained; the domain is not.
_CLASSIFIED: dict[str, str] = {
    "credential_shapes.PRIVATE_KEY_RE": (
        "each repetition consumes one line that is WHOLLY a key token (base64 or a "
        "PEM encapsulated header); the first line that is not stops the match — "
        "pinned by test_a_banner_the_renderer_assembles_deletes_no_section"
    ),
    "credential_shapes.AUTH_VALUE_RE": (
        "anchored ^...$ without MULTILINE over a standalone header VALUE the "
        "structure walker separated from its key: the whole string is the value, "
        "so the match cannot reach past it into a document"
    ),
}


def _patterns() -> Iterator[tuple[str, re.Pattern[str]]]:
    def walk(name: str, value: object) -> Iterator[tuple[str, re.Pattern[str]]]:
        if isinstance(value, re.Pattern):
            yield name, value
        elif isinstance(value, (tuple, list)):
            for index, item in enumerate(value):
                yield from walk(f"{name}[{index}]", item)

    for module in _VOCABULARY_MODULES:
        short = module.__name__.rsplit(".", 1)[-1]
        for attr, value in vars(module).items():
            yield from walk(f"{short}.{attr}", value)


def _matches_newline(items: object, flags: int) -> bool:
    """Whether any item in a parsed sub-pattern can consume a line break."""
    for op, av in items:  # type: ignore[attr-defined]
        if op is sre_c.ANY and flags & re.DOTALL:
            return True
        if op is sre_c.LITERAL and av == 10:
            return True
        if op is sre_c.NOT_LITERAL and av != 10:
            return True
        if op is sre_c.IN and _set_has_newline(av):
            return True
        if op is sre_c.SUBPATTERN and _matches_newline(av[3], flags | av[1]):
            return True
        if op is sre_c.BRANCH and any(_matches_newline(b, flags) for b in av[1]):
            return True
        if op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT):
            if _matches_newline(av[2], flags):
                return True
        if op is sre_c.ATOMIC_GROUP and _matches_newline(av, flags):
            return True
    return False


def _set_has_newline(members: list[tuple[object, object]]) -> bool:
    negate = bool(members) and members[0][0] is sre_c.NEGATE
    hit = False
    for op, av in members:
        if (op is sre_c.LITERAL and av == 10) or (
            op is sre_c.RANGE and av[0] <= 10 <= av[1]  # type: ignore[index,operator]
        ):
            hit = True
        if op is sre_c.CATEGORY and av in (
            sre_c.CATEGORY_SPACE,
            sre_c.CATEGORY_NOT_DIGIT,
            sre_c.CATEGORY_NOT_WORD,
            sre_c.CATEGORY_LINEBREAK,
        ):
            hit = True
    return hit != negate


def _reaches_end(items: object, flags: int) -> list[str]:
    """Why a parsed pattern can consume to the end of input, or ``[]``.

    Two shapes: an explicit ``\\Z`` in a consuming position, and an unbounded
    repeat whose body can cross a line break. Lookarounds consume nothing and
    are not descended into.
    """
    reasons: list[str] = []
    for op, av in items:  # type: ignore[attr-defined]
        if op is sre_c.AT and av is sre_c.AT_END_STRING:
            reasons.append("\\Z")
        elif op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT):
            _low, high, body = av
            if high == sre_c.MAXREPEAT and _matches_newline(body, flags):
                reasons.append("unbounded repeat across line breaks")
            reasons.extend(_reaches_end(body, flags))
        elif op is sre_c.SUBPATTERN:
            reasons.extend(_reaches_end(av[3], flags | av[1]))
        elif op is sre_c.BRANCH:
            for branch in av[1]:
                reasons.extend(_reaches_end(branch, flags))
        elif op is sre_c.ATOMIC_GROUP:
            reasons.extend(_reaches_end(av, flags))
    return reasons


def _domain() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, pattern in _patterns():
        reasons = _reaches_end(sre_parse.parse(pattern.pattern, pattern.flags), pattern.flags)
        if reasons:
            out[name] = sorted(set(reasons))
    return out


def test_the_analysis_flags_the_legacy_pattern() -> None:
    """Positive control: the detector sees the shape R21 was."""
    parsed = sre_parse.parse(_LEGACY_PRIVATE_KEY_RE.pattern, _LEGACY_PRIVATE_KEY_RE.flags)
    reasons = set(_reaches_end(parsed, _LEGACY_PRIVATE_KEY_RE.flags))
    assert reasons == {"\\Z", "unbounded repeat across line breaks"}


def test_the_domain_is_nonempty_and_covers_every_module() -> None:
    """A domain computed over nothing passes everything."""
    names = [name for name, _ in _patterns()]
    for module in _VOCABULARY_MODULES:
        short = module.__name__.rsplit(".", 1)[-1]
        assert any(n.startswith(f"{short}.") for n in names), f"no pattern found in {short}"


def test_every_pattern_that_can_reach_end_of_input_is_classified() -> None:
    """Both directions: every member classified, every classification a member."""
    domain = _domain()
    unclassified = sorted(set(domain) - set(_CLASSIFIED))
    stale = sorted(set(_CLASSIFIED) - set(domain))
    assert not unclassified, f"unbounded redaction pattern(s) with no reason: {unclassified}"
    assert not stale, f"classification for a pattern no longer in the domain: {stale}"
    assert all("\\Z" not in reasons for reasons in domain.values()), domain
    assert all(reason.strip() for reason in _CLASSIFIED.values())


def test_redaction_of_an_unterminated_block_is_bounded_and_announced() -> None:
    text = f"x {_BEGIN}\n{_KEY_BODY}\n\n## What was NOT tested\nNone"
    out = redact_shapes(text)
    assert out == f"x {PRIVATE_KEY_UNTERMINATED_LABEL}\n\n## What was NOT tested\nNone"


def test_a_key_inside_a_json_string_is_still_removed_whole() -> None:
    """The escaped-newline form a leaked config file carries."""
    text = f'{{"private_key": "{_BEGIN}\\n{_KEY_BODY}\\n{_END}\\n", "next": 1}}'
    out = redact_shapes(text)
    assert _KEY_BODY not in out and _END not in out
    assert out.endswith('[REDACTED:PRIVATE_KEY]\\n", "next": 1}')
