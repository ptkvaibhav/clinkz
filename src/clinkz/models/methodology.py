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
    JS_DOM = "js_dom"
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
    # ``verified`` means the methodology emitted a finding. ``verification_strength``
    # qualifies how strong that confirmation is. ``"verified"`` = the payload
    # was observed landing in an executable position on the server; ``"likely"``
    # = the methodology has strong static evidence (e.g. SPA shell + fragment
    # route + JS sink reachable via static analysis) but cannot run the JS to
    # observe execution without a headless browser.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# SQLi methodology types
# ---------------------------------------------------------------------------


class SQLDialect(StrEnum):
    """Backend SQL dialect classified during phase-2 fingerprinting.

    Drives payload synthesis: the operators, comment markers, and built-in
    functions that work in MySQL are different from PostgreSQL or MSSQL,
    and a wrong dialect guess produces a payload that won't trigger.
    ``UNKNOWN`` is reserved for the case where every dialect probe came back
    indistinguishable from baseline — synthesis can still try a portable
    payload, but verification confidence is lower.
    """

    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


class InjectionType(StrEnum):
    """The shape of the SQL injection that the synthesis phase will target.

    Selected by the LLM checkpoint at phase 3 given dialect + observed
    primitives. Each value implies a different verification rule:

    - ``ERROR_BASED``: parse for an expected error substring.
    - ``UNION_BASED``: check for extracted data appearing in the response.
    - ``BOOLEAN_BLIND``: compare body length / hash between true / false
      payloads sharing the same shape.
    - ``TIME_BLIND``: measure response time delta vs baseline.
    - ``STACKED``: only meaningful on dialects that allow multi-statement
      execution (MSSQL, PostgreSQL with semicolon separator, etc.).
    """

    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    STACKED = "stacked"


class InjectionPrimitives(BaseModel):
    """Operators, quote chars, and comment syntax confirmed available.

    Populated during phase-2 fingerprinting. Phase-4 payload synthesis
    constrains itself to these primitives — synthesizing with characters
    that didn't survive the round-trip produces a payload the server will
    sanitise away. Empty lists / ``None`` mean the corresponding probe came
    back inconclusive (or the character is filtered).

    Attributes:
        quote_chars: Quote characters whose use produced a distinguishable
            response from baseline (``'``, ``"``, backtick).
        comment_syntax: Comment markers that successfully terminated a
            tail-of-statement injection (``--``, ``#``, ``/* */``).
        concat_op: First string-concatenation operator that was observed to
            work — ``"||"`` (PG/Oracle/SQLite), ``"+"`` (MSSQL), or
            ``"CONCAT"`` (MySQL function form). ``None`` if none worked.
    """

    quote_chars: list[str] = Field(default_factory=list)
    comment_syntax: list[str] = Field(default_factory=list)
    concat_op: str | None = None


class SQLiMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one SQLi ``_test_*`` invocation.

    Mirrors :class:`MethodologyResult` but with SQLi-specific fields. Stored
    on the resulting Finding's evidence so the report has a complete audit
    trail of dialect classification, primitive enumeration, the LLM-picked
    injection type, the synthesized payload, and the verification outcome.

    ``phases_completed`` is the highest 1-indexed phase that finished —
    useful for triaging methodology failures (e.g. phase 2 always producing
    ``UNKNOWN`` means dialect fingerprinting needs work).
    """

    phases_completed: int = 0
    dialect: SQLDialect = SQLDialect.UNKNOWN
    primitives: InjectionPrimitives = Field(default_factory=InjectionPrimitives)
    injection_type: InjectionType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding. ``verification_strength``
    # qualifies how strong that confirmation is. ``"verified"`` = the indicator
    # for the chosen injection type was directly observed (error string seen,
    # union row in body, boolean diff matching, or time delta beyond threshold).
    # ``"likely"`` = sqlmap fallback flagged the param injectable but our
    # in-process verification did not match the indicator type cleanly.
    verification_strength: str = "verified"


__all__ = [
    "CharacterMap",
    "FilterBehavior",
    "InjectionPrimitives",
    "InjectionType",
    "MethodologyResult",
    "ReflectionContext",
    "ReflectionPoint",
    "SQLDialect",
    "SQLiMethodologyResult",
    "SynthesizedPayload",
]
