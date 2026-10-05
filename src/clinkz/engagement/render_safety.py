"""The target may not author the structure of the document that judges it.

Redaction, next door in :mod:`clinkz.engagement.secrets`, asks what a value
*is*. This module asks what a value *renders as*, which is a different question
with the same answer shape: a whole-structure transformation applied once at the
producer, so that no renderer — and no renderer written later — has to remember.

The failure
-----------

``Finding.evidence`` carries a response snippet the TARGET chose, and the
Markdown writer put it inside a fence with no treatment at all::

    **PoC:**
    ```
    Response: 200
    ```

    ## Summary

    - **Risk rating:** None
    - **Confirmed findings:** 0

    No issues found.
    ```

Three backticks on their own line close our fence; the target then writes its
own ``## Summary`` section carrying its own risk rating and finding count, and
reopens the fence. The document's fence count is now odd, so *What was NOT
tested*, the component ledger and the run audit are swallowed into a code block
and never render. That is not a target confusing our reasoning — the engine's
findings are unchanged — it is a target writing our conclusions into the
deliverable a client reads.

Measured on the tree this landed against: **180** interpolation sites in
``agents/report.py`` can carry a value the target chose, and **not one** of them
neutralised anything. The PDF held, because ``_report_pdf._text`` escapes at the
sink — but that is a convention, not a guard: ``_para`` and ``_grid`` take raw
markup and trust every caller, so the PDF's safety is a property of ~170 call
sites rather than of one seam. A sink-side fix is a guard whose domain is every
future sink.

The rule
--------

    **A value the target chose may not begin a line in a rendered document, and
    may not carry a byte that means something to the device rendering it.**

Two consequences, and which applies is a property of the SITE, not the value:

* An **inline** value — a finding title, an endpoint, a table cell, a label
  prefix — is interpolated into a line somebody else opened. A newline is the
  whole attack: whatever follows it is at column 0 and is structural. So an
  inline value carries no line breaks.
* A **block** value renders inside a fence, where nothing is structural except
  a fence that closes it. So a block value keeps its newlines and the FENCE
  adapts: opened with one more backtick than the longest run in the content,
  which no content can then close.

Why the exemption is one field
------------------------------

Measured over 400 stored bundles: **29** of **24,281** string leaves contain a
newline at all, at exactly two paths — ``findings[].evidence[]`` (21) and
``unproven_leads[].raw_observation`` (8). The second renders as
``f"observed: {lead.raw_observation}"``, a label prefix, so it is an inline
position and collapsing it is a correction rather than a cost: a newline there
already broke the ``observed:``/``missing:`` alignment it was pretending to
keep. That leaves ``findings[].evidence`` as the single block PATH, and
:data:`BLOCK_PATHS` names it with its reason.

What this module does NOT touch
-------------------------------

* **Keys.** A key is schema — the rule :mod:`~clinkz.engagement.secrets` paid
  for when ``test_start`` became ``[REDACTED]_start`` and took the whole report
  with it. Exactly one whole-structure walk in this tree may rewrite keys and it
  is not this one.
* **The JSON artifact.** ``report_<id>.json`` is written from the *unneutralised*
  structure, because JSON encoding is already structural neutralisation and
  because ``regrade_stored_bundles.py``, ``corpus-replay`` and the class-coverage
  account all read those bytes back. A guard that damages the artifact it
  protects protects nothing.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "BLOCK_PATHS",
    "fence_for",
    "neutralise",
    "neutralise_structure",
]


#: The PATHS whose value renders inside a fence, so the fence neutralises it and
#: its line breaks are content rather than structure. One entry, with the reason
#: it is the only one; every other string leaf is inline by default, which is the
#: fail-closed direction.
#:
#: **A path, not a name** — invariant 20's rule, and it was keyed on the bare name
#: ``evidence`` for exactly one review cycle before that cost something. The name
#: is unique across the MODELS, which is what was checked; it is not unique across
#: the STRUCTURE, because ``PentestReport.authentication`` is a
#: ``dict[str, object]`` carrying an ``assertion.evidence`` list that no model
#: declares and that ``_render_adaptive_auth`` renders INLINE, one bullet per
#: entry. A name-keyed exemption made those block-exempt, so a line break in one
#: would have escaped its bullet — the whole defect, reintroduced through the
#: exemption written to bound it.
BLOCK_PATHS: dict[str, str] = {
    "findings[].evidence": (
        "the PoC block: raw request and response bytes rendered inside a fence, where "
        "the line breaks ARE the artifact and collapsing them would destroy the one "
        "part of the document a reader replays by hand. Safe to keep because "
        "_render_markdown opens that block with fence_for(), which no content can close"
    ),
}

#: C0 controls and DEL, minus the three whitespace characters a document may
#: legitimately carry. ESC is the one that matters: ``clinkz actions`` prints a
#: recorded URL straight to a terminal, and ``\x1b[2K\x1b[1A`` clears the line
#: and moves the cursor up, so a target-chosen URL can scroll the REFUSED rows
#: above it off the operator's screen.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_LINE_BREAK = re.compile(r"\r\n|\r|\n")

_BACKTICK_RUN = re.compile(r"`+")


def fence_for(content: str) -> str:
    """The opening fence for a block that must contain *content*.

    CommonMark closes a fenced block only on a fence of at least the opening
    length made of the same character, so a fence one backtick longer than the
    longest run in the content cannot be closed from inside it. The content's
    bytes are unchanged — this is the neutralisation that costs the deliverable
    nothing, which is why the block case gets it rather than an escaping rule.

    Args:
        content: Everything that will sit between the fences.

    Returns:
        A fence of at least three backticks.
    """
    longest = max((len(run) for run in _BACKTICK_RUN.findall(content)), default=0)
    return "`" * max(3, longest + 1)


def neutralise(value: str, *, block: bool = False) -> str:
    """One string on its way into a rendered document.

    Args:
        value: The string as the engine recorded it.
        block: True when this value renders inside a fence, so its line breaks
            are content. Defaults to False, which is the fail-closed direction:
            a value whose position nobody declared is treated as inline, and an
            inline value that keeps a newline is the whole defect.

    Returns:
        The same string with control bytes made visible and, unless *block*,
        line breaks collapsed.
    """
    text = _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", value)
    if block:
        return text
    return _LINE_BREAK.sub(" ", text)


def _is_block_path(path: str) -> bool:
    """Whether a leaf at *path* renders inside a fence.

    ``findings[].evidence[]`` is under the declared ``findings[].evidence``;
    ``authentication.assertion.evidence[]`` is not, and that separation is the
    whole point of keying on the path.
    """
    return any(
        path == declared or path.startswith(f"{declared}[") or path.startswith(f"{declared}.")
        for declared in BLOCK_PATHS
    )


def neutralise_structure(obj: Any, *, _path: str = "") -> Any:
    """Recursively neutralise every string leaf of a document structure.

    Mirrors :func:`clinkz.engagement.secrets.redact_structure` in shape and
    differs from it in exactly one way that matters: **keys are passed through
    untouched**. A key is the structure's own vocabulary, and rewriting one is
    how redaction cost this engine an entire deliverable.

    Each leaf is decided by its PATH — dict keys joined with ``.``, every list,
    tuple and set collapsing to ``[]`` — so the exemption names a position in the
    document rather than a word that may appear in several.

    Args:
        obj: A JSON-ish structure, already redacted.
        _path: Internal. The normalised path of *obj* within the document.

    Returns:
        The same shape, renderable without the target authoring any of it.
    """
    if isinstance(obj, str):
        return neutralise(obj, block=_is_block_path(_path))
    if isinstance(obj, dict):
        return {
            key: neutralise_structure(
                value,
                _path=f"{_path}.{key}" if _path else str(key),
            )
            for key, value in obj.items()
        }
    if isinstance(obj, (list, tuple, set)):
        items = [neutralise_structure(item, _path=f"{_path}[]") for item in obj]
        if isinstance(obj, tuple):
            return tuple(items)
        if isinstance(obj, set):
            return set(items)
        return items
    return obj
