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


# ---------------------------------------------------------------------------
# Command-injection methodology types
# ---------------------------------------------------------------------------


class ShellType(StrEnum):
    """The shell context inferred during command-injection fingerprinting.

    Drives payload synthesis: bash / sh accept ``$IFS``, backticks, and the
    full ``;|&&||`` separator set; CMD accepts ``&`` and ``|`` but neither
    backticks nor ``$()``; PowerShell parses ``;`` plus its own substitution
    syntax. ``UNKNOWN`` means the OS-detection probes were inconclusive and
    payload synthesis must rely on portable primitives.
    """

    BASH = "bash"
    SH = "sh"
    CMD = "cmd"
    POWERSHELL = "powershell"
    UNKNOWN = "unknown"


class CMDIExecutionType(StrEnum):
    """The shape of the command injection that the synthesis phase will target.

    Selected by the LLM checkpoint at phase 3 given OS + confirmed
    primitives. Each value implies a different verification rule:

    - ``DIRECT_EXEC``: response body reflects command output (whoami →
      user-shaped string, ``id`` → ``uid=``).
    - ``BLIND_TIME``: response time delta vs baseline beyond a sleep
      threshold.
    - ``BLIND_OOB``: out-of-band callback observed (DNS/HTTP) — skipped
      when no oast collaborator is available.
    - ``ERROR_BASED``: malformed command produces a shell error string in
      the response body.
    """

    DIRECT_EXEC = "direct_exec"
    BLIND_TIME = "blind_time"
    BLIND_OOB = "blind_oob"
    ERROR_BASED = "error_based"


class ShellPrimitives(BaseModel):
    """Operators, separators, and quoting forms confirmed available.

    Populated during phase-2 fingerprinting. Phase-4 payload synthesis
    constrains itself to these primitives — synthesizing with a separator
    that didn't survive the round-trip produces a payload that runs nothing.

    Attributes:
        separators: Command-chaining tokens whose use produced a
            distinguishable response from baseline (``";"``, ``"&&"``,
            ``"||"``, ``"|"``, ``"&"``, ``"%0a"``, ``"$IFS"``, ...).
        quotes: Quoting forms whose presence around a payload survived the
            server's parsing (``"single"``, ``"double"``, ``"none"``).
        substitution: Command-substitution forms confirmed available
            (``"$()"``, ``"backtick"``, ``"%COMMAND%"``).
        working_time_payload: First time-based probe payload that actually
            produced a measurable delay during phase-2 confirmation. ``None``
            if the time channel hasn't been confirmed.
    """

    separators: list[str] = Field(default_factory=list)
    quotes: list[str] = Field(default_factory=list)
    substitution: list[str] = Field(default_factory=list)
    working_time_payload: str | None = None


class CMDIMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one CMDI ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` but with CMDI-specific fields.
    Stored on the resulting Finding's evidence so the report has a complete
    audit trail of OS classification, primitive enumeration, the LLM-picked
    execution type, the synthesized payload, and the verification outcome.
    """

    phases_completed: int = 0
    shell_type: ShellType = ShellType.UNKNOWN
    primitives: ShellPrimitives = Field(default_factory=ShellPrimitives)
    execution_type: CMDIExecutionType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies how strong that confirmation is.
    # ``"verified"`` = the indicator for the chosen execution type was
    # directly observed (canary echoed, time delta beyond threshold, shell
    # error string seen). ``"likely"`` = secondary signal (e.g. status flip
    # alone) without a clean indicator match.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# LFI methodology types
# ---------------------------------------------------------------------------


class LFIRetrievalType(StrEnum):
    """The shape of the LFI primitive that the synthesis phase will target.

    Selected by the LLM checkpoint at phase 3 given the traversal primitives
    confirmed during fingerprinting. Each value implies a different
    verification rule:

    - ``DIRECT_READ``: file content reflected in the response body (look
      for known file signatures — ``root:x:0:0:`` etc.).
    - ``WRAPPER_EXTRACTION``: ``php://filter/convert.base64-encode/...``
      returns a base64 blob that decodes to a recognised file signature.
    - ``ERROR_BASED_PATH``: the absolute filesystem path leaks in an error
      message (path-disclosure, useful but not directly content-disclosing).
    - ``SOURCE_DISCLOSURE``: PHP source returned via ``php://filter`` —
      same indicator family as ``WRAPPER_EXTRACTION``, just aimed at code
      rather than data.
    """

    DIRECT_READ = "direct_read"
    WRAPPER_EXTRACTION = "wrapper_extraction"
    ERROR_BASED_PATH = "error_based_path"
    SOURCE_DISCLOSURE = "source_disclosure"


class LFITraversalPrimitives(BaseModel):
    """Path-handling primitives confirmed during phase-2 fingerprinting.

    Phase-4 payload synthesis constrains itself to these primitives —
    synthesizing with a traversal sequence that the server normalises away
    produces a payload that resolves back to the application's directory.

    Attributes:
        traversal_sequence: First traversal token whose use produced a
            distinguishable response from baseline (``"../"``, ``"..\\"``,
            ``"....//"``, ``"%2e%2e%2f"``, ...). ``None`` when no traversal
            shape worked.
        wrapper_support: PHP / similar wrappers whose use produced a
            response distinguishable from a generic 404 (``"php://filter"``,
            ``"php://input"``, ``"file://"``, ``"data://"``, ...).
        prefix_required: ``True`` when the server rejects relative paths
            and only an absolute path-prefixed payload (``"/etc/passwd"``)
            triggers a recognisable response.
        suffix_handling: How the server treats trailing input. ``"none"``
            = no suffix manipulation observed; ``"appends_extension"`` =
            the server appended ``.php`` / ``.txt``; ``"truncatable_nul"``
            = a legacy-PHP nul byte truncation works to defeat the suffix.
    """

    traversal_sequence: str | None = None
    wrapper_support: list[str] = Field(default_factory=list)
    prefix_required: bool = False
    suffix_handling: str = "none"


class LFIMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one LFI ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` but with LFI-specific fields.
    Stored on the resulting Finding's evidence so the report has a complete
    audit trail of traversal-sequence selection, wrapper-support fingerprint,
    the LLM-picked retrieval type, the synthesized payload, and the
    verification outcome.
    """

    phases_completed: int = 0
    primitives: LFITraversalPrimitives = Field(default_factory=LFITraversalPrimitives)
    retrieval_type: LFIRetrievalType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies how strong that confirmation is.
    # ``"verified"`` = the indicator for the chosen retrieval type was
    # directly observed (file signature in body, base64 decoding to file
    # signature, full path in error). ``"likely"`` = secondary signal (e.g.
    # status flip + length divergence) without a clean indicator match.
    verification_strength: str = "verified"


__all__ = [
    "CMDIExecutionType",
    "CMDIMethodologyResult",
    "CharacterMap",
    "FilterBehavior",
    "InjectionPrimitives",
    "InjectionType",
    "LFIMethodologyResult",
    "LFIRetrievalType",
    "LFITraversalPrimitives",
    "MethodologyResult",
    "ReflectionContext",
    "ReflectionPoint",
    "SQLDialect",
    "SQLiMethodologyResult",
    "ShellPrimitives",
    "ShellType",
    "SynthesizedPayload",
]
