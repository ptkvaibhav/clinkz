"""Methodology models — structured intermediate results for adaptive skill phases.

Adaptive ``_test_*`` methods (XSS-reflected, SQLi, etc.) emit per-phase
intermediate results that are persisted in the execution trace and attached
to the resulting Finding's evidence. This module is the single source of
truth for those intermediate-result schemas so phase implementations and
trace inspectors stay in lockstep.

The schema is shared across vuln classes — XSS reflection contexts, SQLi
parser-state contexts, and command-injection escape contexts all fit the
same ``ReflectionPoint`` / ``CharacterMap`` / ``SynthesizedPayload`` shape.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ReflectionContext(StrEnum):
    """The HTML / JS / URL context where a probe token reflects.

    The set of contexts covers everything a payload-synthesis step needs to
    decide which XSS form (tag injection, attribute breakout, JS string
    breakout, etc.) has any chance of executing. Anything that doesn't fit
    is ``NONE`` — meaning the reflection won't render.
    """

    HTML_BODY = "html_body"
    HTML_ATTRIBUTE_VALUE = "html_attribute_value"
    HTML_ATTRIBUTE_NAME = "html_attribute_name"
    JS_STRING_SINGLE = "js_string_single"
    JS_STRING_DOUBLE = "js_string_double"
    JS_CODE = "js_code"
    CSS = "css"
    URL = "url"
    COMMENT = "comment"
    NONE = "none"


class FilterBehavior(StrEnum):
    """How the server transformed a probed character on its way back.

    ``SURVIVED`` is the only outcome that means the character is usable as-is
    in a payload. The other values describe each transformation a sanitizer
    might apply, so payload synthesis can reason about the bypass surface.
    """

    SURVIVED = "survived"
    HTML_ENCODED = "html_encoded"
    URL_ENCODED = "url_encoded"
    BACKSLASH_ESCAPED = "backslash_escaped"
    STRIPPED = "stripped"
    REPLACED = "replaced"
    SERVER_ERROR = "server_error"
    BLOCKED = "blocked"


class ReflectionPoint(BaseModel):
    """A single occurrence of the probe token in the response.

    Attributes:
        location: Coarse pointer to where the reflection was found
            (e.g. byte offset, ``"body[1234]"``, attribute path). Used for
            human debugging — exact format is not load-bearing.
        context: Parser context the reflection lives in. Drives payload form.
        surrounding_snippet: Short slice of HTML around the reflection. Kept
            for evidence / debugging — not parsed downstream.
    """

    location: str
    context: ReflectionContext
    surrounding_snippet: str


class CharacterMap(BaseModel):
    """Per-character filter behavior across the probed character set.

    ``per_char`` keys are single characters (or short Unicode escapes like
    ``"\\u003c"`` and full-width variants) — whatever was probed by the
    fingerprinting phase. ``probe_summary`` is a human-readable summary the
    LLM can be shown without serializing the whole dict.
    """

    per_char: dict[str, FilterBehavior] = Field(default_factory=dict)
    probe_summary: str = ""


class SynthesizedPayload(BaseModel):
    """An LLM-produced payload tailored to the observed reflection + char map.

    Attributes:
        payload: The candidate string to send.
        rationale: One-paragraph explanation of why this form should execute
            given the context and the surviving character set. Stored on the
            Finding so a reviewer can audit the synthesis decision.
        expected_execution: Free-text description of what executing the payload
            should look like (alert dialog, console log, etc.). Used by the
            verification phase as a hint, not a strict assertion.
    """

    payload: str
    rationale: str
    expected_execution: str


class MethodologyResult(BaseModel):
    """Roll-up of every phase's output for one ``_test_*`` invocation.

    Attached to the resulting Finding's evidence so the report has a complete
    audit trail of how the vuln was discovered. ``phases_completed`` is the
    highest 1-indexed phase that finished — useful for triaging methodology
    failures (e.g. phase 2 always failing means fingerprinting is broken).
    """

    phases_completed: int = 0
    character_map: CharacterMap = Field(default_factory=CharacterMap)
    reflections: list[ReflectionPoint] = Field(default_factory=list)
    synthesized_payload: SynthesizedPayload | None = None
    bypass_attempts: list[str] = Field(default_factory=list)
    verified: bool = False


__all__ = [
    "CharacterMap",
    "FilterBehavior",
    "MethodologyResult",
    "ReflectionContext",
    "ReflectionPoint",
    "SynthesizedPayload",
]
