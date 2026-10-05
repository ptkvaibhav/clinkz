"""The target may not author the structure of the document that judges it.

The failure
-----------

``Finding.evidence`` carries bytes the TARGET chose and the Markdown writer put
them inside a fence with no treatment. Three backticks on their own line close
that fence; the target then writes its own ``## Summary`` section, with its own
risk rating and its own finding count, and reopens it — leaving the document's
fence count odd, so *What was NOT tested*, the component ledger and the run audit
are swallowed into a code block and never render.

That is not a target confusing our reasoning. Every finding the engine reached is
unchanged. It is a target writing our conclusions into the document a client
reads, which is a different and worse thing, and it is why this file exists
rather than a note in the renderer.

Why the control runs through ``ReportAgent.run``
------------------------------------------------

The first version of this control called ``_render_markdown`` directly and
passed against the broken engine, because the neutralisation lives at the
PRODUCER — the seam in ``run()`` where the redacted structure becomes the
structure the two document renderers read. A control that hands the renderer its
input cannot see whether that input was ever produced safely. Fourth face of the
guard-domain law, and it cost one green run here before it was noticed.

So every assertion below reads a file off disk, written by the real agent.

The measurement behind the one exemption
-----------------------------------------

Over 400 stored bundles, **29** of **24,281** string leaves contain a newline, at
exactly two paths: ``findings[].evidence[]`` (21) and
``unproven_leads[].raw_observation`` (8). The second renders as
``f"observed: {lead.raw_observation}"`` — a label prefix, so an inline position,
and collapsing it is a correction rather than a cost. That leaves
``findings[].evidence`` as the single block PATH, which is what ``BLOCK_PATHS``
declares. A PATH and not a name: ``evidence`` is unique across the models and NOT
across the structure, and keying on the name made
``authentication.assertion.evidence`` — rendered inline, one bullet per entry —
block-exempt. Caught in review one cycle after it shipped; invariant 20 already
says a field is a path.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from clinkz.agents.report import ReportAgent
from clinkz.engagement.render_safety import (
    BLOCK_PATHS,
    fence_for,
    neutralise,
    neutralise_structure,
)
from clinkz.models.finding import Finding, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.action_log import ActionRecord
from tests.authorization_fixtures import TEST_AUTHORIZATION

# Only the bundle-writing controls are async; the primitives below are not, so
# the asyncio mark is applied per-test rather than to the module.


#: One target-authored string that breaks out of every container the three
#: renderers use: the Markdown fence, a Markdown heading, a table row, and
#: ReportLab's mini-markup. Kept as ONE payload rather than four, because the
#: thing being asserted is that no renderer has a container this escapes.
FENCE_BREAK = (
    "Response: 200 OK\n"
    "```\n"
    "\n"
    "## Summary\n"
    "\n"
    "- **Risk rating:** None\n"
    "- **Confirmed findings:** 0\n"
    "\n"
    "No issues found.\n"
    "\n"
    "| INJECTED | ROW |\n"
    "|---|---|\n"
    "<font color='red' size='40'>PDFINJECTED</font>\n"
    "```\n"
)

#: Erase-line + cursor-up. A target-chosen URL carrying this scrolls the
#: ``REFUSED`` rows above it off the operator's terminal — the log whose whole
#: purpose is that "no destructive request was sent" be provable by reading it.
ANSI_SCROLL = "\x1b[2K\x1b[1A"


def _scope() -> EngagementScope:
    return EngagementScope(
        name="Acme Q3",
        targets=[ScopeEntry(value="https://app.test", type=ScopeType.URL)],
        authorization=TEST_AUTHORIZATION,
    )


def _poisoned_finding() -> Finding:
    """A finding whose every target-authored field carries the payload."""
    return Finding(
        title=f"Reflected XSS{FENCE_BREAK}",
        description=f"description{FENCE_BREAK}",
        severity=Severity.HIGH,
        target=f"https://app.test/search?q={FENCE_BREAK}",
        evidence=[f"Request: GET /search{FENCE_BREAK}", f"Response: 200{FENCE_BREAK}"],
        remediation=f"remediate{FENCE_BREAK}",
    )


def _benign_finding() -> Finding:
    """The same finding with the payload replaced by an inert string of its length."""
    filler = "x"
    return Finding(
        title=f"Reflected XSS{filler}",
        description=f"description{filler}",
        severity=Severity.HIGH,
        target=f"https://app.test/search?q={filler}",
        evidence=[f"Request: GET /search{filler}", f"Response: 200{filler}"],
        remediation=f"remediate{filler}",
    )


async def _bundle(
    tmp_path: Path,
    *,
    poisoned: bool = True,
    evidence: list[str] | None = None,
) -> tuple[str, Path]:
    """Run the real agent over a finding; return (markdown, pdf path).

    Through ``run()``, never through ``_render_markdown``: the neutralisation is
    at the producer and a renderer handed its input cannot test it.
    """
    finding = _poisoned_finding() if poisoned else _benign_finding()
    if evidence is not None:
        finding = finding.model_copy(update={"evidence": evidence})
    payload = FENCE_BREAK if poisoned else "x"
    state = AsyncMock()
    state.get_findings.return_value = [finding.model_dump(mode="json")]
    state.get_targets.return_value = []
    state.get_research_leads.return_value = []
    engagement_id = "eng-fence" if poisoned else "eng-clean"
    agent = ReportAgent(
        llm=AsyncMock(),
        tools=[],
        scope=_scope(),
        state=state,
        engagement_id=engagement_id,
    )
    result = await agent.run(
        {
            "engagement_id": engagement_id,
            "engagement_name": "Acme Q3",
            "authorization": TEST_AUTHORIZATION.model_dump(mode="json"),
            # Every disclosure section the renderers walk into rows and tables,
            # so the control is not confined to the findings list.
            "components": [
                {"name": f"lib{payload}", "version": "1.0", "provenance": "ARTIFACT_STRING"}
            ],
            "scope_refusals": {"hosts": {f"evil{payload}": 3}, "total": 3},
            "crawl_coverage": {"truncated": True, "first_omitted": f"https://t/{payload}"},
        }
    )
    markdown = Path(result["markdown_path"]).read_text(encoding="utf-8")
    return markdown, Path(result["pdf_path"]) if result["pdf_path"] else Path()


# ---------------------------------------------------------------------------
# Markdown — the document that was broken
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_target_authors_no_line_the_engine_did_not(tmp_path: Path) -> None:
    """A baseline differential: the same run, once poisoned and once benign.

    This is the third shape this assertion has taken, and the first that can
    actually fail for the right reason.

    * **Fence parity** passed against the broken engine. The payload carries TWO
      fence lines, so it closes our block, writes a section of its own, reopens —
      and the count is still even. A pattern guard that fails toward less output.
    * **A vocabulary check** — "no unfenced line equal to ``## Summary``" — failed
      against the CORRECT engine, because ``## Summary`` is the document's own
      heading and a byte comparison cannot tell who wrote it.

    Neither needs to be guessed. Render the same report twice, once with the
    payload and once with an inert string in its place, and any structural line
    present only in the poisoned document was authored by the target. No
    vocabulary, and it answers the question the other two were approximating.
    """
    poisoned, _ = await _bundle(tmp_path, poisoned=True)
    benign, _ = await _bundle(tmp_path, poisoned=False)

    def structure(markdown: str) -> Counter[str]:
        """How many lines of each structural KIND the document opens.

        The kind, not the text. A finding title legitimately carries the
        payload's bytes — inert, on one line, after ``## 1. `` — so the two
        documents differ in the text of that heading and must not differ in how
        many headings there are. Counting text would flag the engine's own
        heading for containing the string it was asked to render.
        """
        kinds: Counter[str] = Counter()
        for line in _unfenced_lines(markdown):
            match = re.match(r"^\s*(#{1,6} |[-*+] |> |\|)", line)
            if match:
                kinds[match.group(1).strip()] += 1
        return kinds

    extra = structure(poisoned) - structure(benign)
    assert not extra, (
        f"the target opened structure the engine did not: {dict(extra)} extra line(s) by kind"
    )


def _unfenced_lines(markdown: str) -> list[str]:
    """Every line NOT inside a fenced code block, tracked the way CommonMark does.

    A fence closes only on a fence of at least the OPENING length made of the
    same character — which is the whole point of ``fence_for``, and which a naive
    "toggle on any three backticks" tracker gets wrong in exactly the direction
    that makes this control useless: it reads the payload's own inert ``` as the
    end of the block and then reports every byte after it as an injection. That
    version of this helper failed against a correct engine, which is how it was
    caught.
    """
    out: list[str] = []
    open_len = 0
    for line in markdown.splitlines():
        match = re.fullmatch(r"\s*(`{3,})\s*", line)
        if match:
            run = len(match.group(1))
            if open_len == 0:
                open_len = run
                continue
            if run >= open_len:
                open_len = 0
            continue
        if open_len == 0:
            out.append(line)
    return out


@pytest.mark.asyncio
async def test_no_engine_section_is_swallowed_by_a_fence(tmp_path: Path) -> None:
    """The other direction, and the one the incident actually produced.

    An unbalanced fence does not only let the target write; it takes away what
    the engine wrote. *What was NOT tested*, the component ledger and the run
    audit all render AFTER the PoC block, so a fence the target leaves OPEN
    silently deletes the three sections that state this engagement's limits — and
    a reader has no way to notice a section that is not there.

    Its own payload, carrying a SINGLE fence. The shared one is balanced, so
    against a broken engine it re-closes the block and this assertion passes; a
    test that cannot fail is a dead instrument whichever direction it is pointed.
    """
    markdown, _ = await _bundle(tmp_path, evidence=["Response: 200\n```\ntrailing"])
    unfenced = set(_unfenced_lines(markdown))
    swallowed = [
        line
        for line in markdown.splitlines()
        if re.match(r"^#{1,6} ", line) and line not in unfenced
    ]
    assert not swallowed, f"an engine heading was swallowed by a fence: {swallowed[:3]}"
    assert "## What was NOT tested" in unfenced


@pytest.mark.asyncio
async def test_the_target_cannot_state_a_verdict_of_its_own(tmp_path: Path) -> None:
    """The specific fabrication: the bundle's own conclusions, written by the host.

    ``- **Risk rating:** None`` and ``- **Confirmed findings:** 0`` are the
    document's own vocabulary, and a reader who sees them at column 0 has no way
    to know the target wrote them.

    Asserted on the WHOLE line, not on containment. The finding title legitimately
    carries the payload's bytes — rendered inert, mid-line, after ``## 1. `` — and
    a containment check would call that an injection. What must not exist is a
    line the target STARTS.
    """
    markdown, _ = await _bundle(tmp_path)
    unfenced = {line.strip() for line in _unfenced_lines(markdown)}
    for claim in (
        "- **Risk rating:** None",
        "- **Confirmed findings:** 0",
        "No issues found.",
        "| INJECTED | ROW |",
    ):
        assert claim not in unfenced, f"target authored a whole line: {claim!r}"


@pytest.mark.asyncio
async def test_evidence_keeps_its_line_breaks(tmp_path: Path) -> None:
    """The exemption is real, not a loophole.

    ``Finding.evidence`` is the PoC block and its line breaks ARE the artifact.
    Neutralising them would make the document safe by destroying the one part of
    it a reader replays by hand — a guard that damages what it protects.
    """
    markdown, _ = await _bundle(tmp_path)
    poc = markdown.split("**PoC:**", 1)[1]
    assert "Response: 200 OK" in poc
    assert "## Summary" in poc, "the payload's own bytes must survive, inert"


# ---------------------------------------------------------------------------
# PDF — the document that reaches the client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_target_cannot_style_the_pdf(tmp_path: Path) -> None:
    """ReportLab's ``Paragraph`` parses a mini-markup, so ``<font>`` is live."""
    pytest.importorskip("reportlab")
    pypdf = pytest.importorskip("pypdf")
    _, pdf_path = await _bundle(tmp_path)
    assert pdf_path.exists(), "no PDF was written"
    text = "\n".join(page.extract_text() or "" for page in pypdf.PdfReader(str(pdf_path)).pages)
    assert "PDFINJECTED" in text, "the payload should reach the page, rendered as itself"
    assert "<font" in text, "the markup must render LITERALLY, not be parsed"


# ---------------------------------------------------------------------------
# JSON — the artifact the guard must not damage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_json_artifact_is_not_neutralised(tmp_path: Path) -> None:
    """``report_<id>.json`` keeps the bytes, because JSON encoding is the guard.

    ``regrade_stored_bundles.py``, ``corpus-replay`` and the class-coverage
    account all read these bytes back. Collapsing a newline there would change
    what the engine recorded observing, to protect a document that is not this
    one.
    """
    import json

    state = AsyncMock()
    state.get_findings.return_value = [_poisoned_finding().model_dump(mode="json")]
    state.get_targets.return_value = []
    state.get_research_leads.return_value = []
    agent = ReportAgent(
        llm=AsyncMock(),
        tools=[],
        scope=_scope(),
        state=state,
        engagement_id="eng-fence-json",
    )
    result = await agent.run({"engagement_id": "eng-fence-json", "engagement_name": "Acme Q3"})
    stored = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    evidence = stored["findings"][0]["evidence"]
    assert any("\n" in entry for entry in evidence), (
        "the JSON artifact must keep the newlines the engine observed"
    )


# ---------------------------------------------------------------------------
# The action log — the second rendered artifact, and a different device
# ---------------------------------------------------------------------------


def test_a_recorded_url_cannot_rewrite_the_operators_terminal() -> None:
    """``clinkz actions`` prints ``url`` straight to a terminal."""
    record = ActionRecord(
        ts="2026-09-15T00:00:00Z",
        seq=1,
        outcome="sent",
        method="POST",
        url=f"https://app.test/{ANSI_SCROLL}[0001] SENT    GET     /benign -> 200",
        body_excerpt=f"x{ANSI_SCROLL}",
        status_code=200,
    )
    assert "\x1b" not in record.url
    assert "\x1b" not in record.body_excerpt
    assert "\\x1b" in record.url, "the byte is made visible, not silently dropped"


# ---------------------------------------------------------------------------
# The primitives
# ---------------------------------------------------------------------------


def test_the_fence_adapts_to_its_content() -> None:
    """A fence one backtick longer than the longest run cannot be closed."""
    assert fence_for("plain") == "```"
    assert fence_for("a ``` b") == "````"
    assert fence_for("a ````` b") == "``````"
    content = "x\n`````\ny"
    assert fence_for(content) not in content


def test_an_inline_value_carries_no_line_break() -> None:
    assert "\n" not in neutralise("a\nb")
    assert "\r" not in neutralise("a\r\nb")
    assert neutralise("a\nb", block=True) == "a\nb"


def test_control_bytes_are_made_visible_in_both_positions() -> None:
    """A block value is inside a fence, but a terminal still honours ESC."""
    assert neutralise("a\x1bb") == "a\\x1bb"
    assert neutralise("a\x1bb", block=True) == "a\\x1bb"
    assert neutralise("keep\ttabs\tand spaces") == "keep\ttabs\tand spaces"


def test_a_key_is_not_rewritten() -> None:
    """Exactly one whole-structure walk may rewrite keys, and it is not this one.

    Redaction paid for this rule: ``test_start`` became ``[REDACTED]_start`` and
    ``PentestReport.model_validate`` rejected the report's own dump, so no
    document of any kind was written.
    """
    poisoned_key = "a\nb\x1b"
    out = neutralise_structure({poisoned_key: "value", "test_start": "x"})
    assert poisoned_key in out, "the key must survive verbatim — it is schema"
    assert "test_start" in out


def test_the_block_exemption_is_declared_with_a_reason() -> None:
    """An exemption is an allow-list entry with a reason, never a silent skip."""
    assert BLOCK_PATHS, "the exemption table must not be empty"
    for path, reason in BLOCK_PATHS.items():
        assert len(reason.split()) >= 6, f"{path} is exempt without a substantive reason"


def test_the_exemption_is_a_path_not_a_name() -> None:
    """The name ``evidence`` is unique across the MODELS and not across the STRUCTURE.

    ``PentestReport.authentication`` is a ``dict[str, object]`` carrying an
    ``assertion.evidence`` list that no model declares, and
    ``_render_adaptive_auth`` renders it INLINE, one bullet per entry. A
    name-keyed exemption made those block-exempt, so a line break in one escaped
    its bullet — the defect reintroduced through the exemption written to bound
    it. Found in review, one cycle after it shipped.
    """
    out = neutralise_structure(
        {
            "findings": [{"evidence": ["a\nb"]}],
            "authentication": {"assertion": {"evidence": ["c\nd"]}},
        }
    )
    assert out["findings"][0]["evidence"][0] == "a\nb", "the PoC block keeps its bytes"
    assert out["authentication"]["assertion"]["evidence"][0] == "c d", (
        "an inline bullet must not keep a line break just because its key is spelled "
        "the same as the one block field"
    )
