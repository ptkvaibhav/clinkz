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
        break_prefix: The closing context that balances the surrounding query
            so an injected clause parses — e.g. ``"'"`` for ``WHERE x='<v>'``
            or ``"'))"`` for ``WHERE ((name LIKE '%<v>%' ...))``. Empty string
            means the value is already in statement position (no quoting).
            ``None`` when no breakout was confirmed. Discovered in phase 2 via a
            paired boolean tautology and used by every phase-4 payload so the
            clause isn't left inside unbalanced parentheses.
        union_columns: Number of columns the front query selects, discovered by
            ``UNION SELECT NULL,...`` enumeration. ``None`` when not determined.
            A UNION payload whose column count differs from this triggers a
            "different number of result columns" error and never confirms.
    """

    quote_chars: list[str] = Field(default_factory=list)
    comment_syntax: list[str] = Field(default_factory=list)
    concat_op: str | None = None
    break_prefix: str | None = None
    union_columns: int | None = None


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
# NoSQL-injection methodology types
# ---------------------------------------------------------------------------


class NoSQLContext(StrEnum):
    """The injection carrier classified during phase-2 fingerprinting.

    NoSQL injection reaches the backend through three structurally different
    carriers, and payload synthesis must know which one it is:

    - ``JSON_OPERATOR``: the value sits in a JSON request-body field that the
      backend feeds straight into a query document, so a nested operator
      object (``{"$ne": null}``, ``{"$gt": ""}``) is interpreted as a query
      operator rather than a literal string. Juice Shop's ``PATCH
      /rest/products/reviews`` "NoSQL Manipulation" case.
    - ``QUERY_BRACKET``: a query-string parameter the server parses into a
      nested object (Express ``qs``: ``p[$ne]=`` becomes ``{p: {$ne: ""}}``),
      so operator injection rides bracket notation.
    - ``STRING_WHERE``: the value is string-concatenated into a server-side
      JavaScript ``$where`` clause (``$where: "this.x === '<v>'"``), so a
      quote-break injects JS — the track-order / ``sleep(N)`` DoS surface.
    - ``UNKNOWN``: no NoSQL-specific behaviour distinguished from baseline
      (e.g. a SQL/PHP stack like DVWA — synthesis declines, nothing emits).
    """

    JSON_OPERATOR = "json_operator"
    QUERY_BRACKET = "query_bracket"
    STRING_WHERE = "string_where"
    UNKNOWN = "unknown"


class NoSQLInjectionType(StrEnum):
    """The shape of the NoSQL injection that the synthesis phase will target.

    Selected by the phase-3 LLM checkpoint given context + confirmed
    operators. Each value implies a different verification rule:

    - ``AUTH_BYPASS``: operator objects in both credential fields
      (``{"$ne": null}``) authenticate without a valid password — confirmed
      by an authenticated / different-principal response. (N/A on a
      SQL-backed login such as Juice Shop's — correctly a non-finding.)
    - ``OPERATOR_INJECTION``: an operator object widens the query's match set
      (data manipulation / over-broad read) — confirmed when the affected or
      returned record count exceeds the benign baseline (the ``$ne:-1``
      multi-review update).
    - ``BOOLEAN_BLIND``: an anchored ``$regex`` probe yields a true/false
      response differential — confirmed extraction channel.
    - ``WHERE_JS_INJECTION``: a string-context ``$where`` break injects
      JavaScript that alters the result set.
    - ``NOSQL_DOS``: a ``$where`` / ``sleep(N)`` injection produces a
      measurable server delay — confirmed by a time delta beyond threshold.
    """

    AUTH_BYPASS = "auth_bypass"
    OPERATOR_INJECTION = "operator_injection"
    BOOLEAN_BLIND = "boolean_blind"
    WHERE_JS_INJECTION = "where_js_injection"
    NOSQL_DOS = "nosql_dos"


class NoSQLPrimitives(BaseModel):
    """Operators and context confirmed available during phase-2 fingerprinting.

    Phase-4 synthesis constrains itself to these — synthesizing a ``$regex``
    extraction when only ``$ne`` was interpreted produces a payload the
    backend ignores.

    Attributes:
        operators: MongoDB query operators whose injection produced a response
            distinguishable from the benign baseline (``$ne``, ``$gt``,
            ``$regex``, ``$where``, ...).
        context: The carrier classified for this parameter.
        where_string_injectable: ``True`` when a quote-break in a string
            ``$where`` context parsed cleanly (JS injection reachable) —
            drives the DoS / JS-injection types.
        error_signatures: NoSQL-specific error strings observed (MongoError,
            CastError, marsdb, ``$where`` SyntaxError). Evidence, and a hint
            that input reached the query engine.
    """

    operators: list[str] = Field(default_factory=list)
    context: NoSQLContext = NoSQLContext.UNKNOWN
    where_string_injectable: bool = False
    error_signatures: list[str] = Field(default_factory=list)


class NoSQLMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one NoSQL ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` with NoSQL-specific fields. Stored
    on the resulting Finding's evidence so the report has a complete audit
    trail of context classification, operator enumeration, the LLM-picked
    injection type, the synthesized payload, and the verification outcome.

    ``synthesized_payload`` is stored as a string (JSON-serialised for an
    operator-object carrier) so the evidence/trace is human-readable; the
    structured value used to send the probe lives inside the phase.
    """

    phases_completed: int = 0
    context: NoSQLContext = NoSQLContext.UNKNOWN
    primitives: NoSQLPrimitives = Field(default_factory=NoSQLPrimitives)
    injection_type: NoSQLInjectionType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies it: ``"verified"`` = the indicator
    # for the chosen injection type was directly observed (match-set widened,
    # authenticated response, regex differential, or time delta beyond
    # threshold); ``"likely"`` = divergence was clear but no clean indicator
    # surfaced.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# SSTI (server-side template injection) methodology types
# ---------------------------------------------------------------------------


class SSTITemplateEngine(StrEnum):
    """Backend template engine classified during phase-2 fingerprinting.

    SSTI's equivalent of :class:`SQLDialect`: different engines evaluate
    different syntax and reach RCE through different gadgets, so a wrong-engine
    guess produces a payload that won't evaluate. The set leans toward the JS
    engines because the modern-SPA targets are Node (Juice Shop is Pug):

    - ``PUG`` — Pug/Jade interpolation (``#{7*7}``); Juice Shop's
      ``views/userProfile.pug`` username case. Node RCE via
      ``global.process.mainModule.require('child_process')``.
    - ``EJS`` — embedded JS (``<%= 7*7 %>``). Node RCE same family.
    - ``NUNJUCKS`` — ``{{7*7}}`` evaluates; distinguished from Jinja2 because
      ``{{7*'7'}}`` is ``49`` (JS coercion) not ``7777777`` (Python repeat).
    - ``HANDLEBARS`` — logic-less: ``{{7*7}}`` does NOT evaluate, so an
      evaluating ``{{}}`` rules Handlebars out.
    - ``JINJA2`` / ``TWIG`` — Python / PHP ``{{}}`` engines (``{{7*'7'}}`` is
      ``7777777`` in Jinja2, an error in Twig).
    - ``FREEMARKER`` / ``VELOCITY`` — JVM ``${...}`` / ``#set`` engines.
    - ``ERB`` — Ruby ``<%= %>``.
    - ``UNKNOWN`` — an arithmetic probe evaluated but no engine probe
      distinguished which; synthesis can still try a portable eval payload but
      RCE confidence is lower.
    """

    JINJA2 = "jinja2"
    TWIG = "twig"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    ERB = "erb"
    EJS = "ejs"
    PUG = "pug"
    HANDLEBARS = "handlebars"
    NUNJUCKS = "nunjucks"
    UNKNOWN = "unknown"


class SSTIExploitationType(StrEnum):
    """The shape of the SSTI exploitation that the synthesis phase will target.

    Selected by the phase-3 LLM checkpoint given engine + confirmed
    primitives, ranked by what the fingerprinted engine supports. Each value
    implies a different verification rule:

    - ``EXPRESSION_EVAL``: the engine evaluates an arithmetic expression and
      the result renders in a normal response (the ``7*7 -> 49`` proof). The
      universal, lowest-risk confirmation — high severity (data/expression
      leak).
    - ``SANDBOX_ESCAPE``: an engine with a sandbox (e.g. a restricted Twig /
      Nunjucks) where a gadget reaches outside the allowed object graph;
      verified the same way as the downstream effect it unlocks.
    - ``RCE``: an engine-specific gadget reaches OS command execution
      (Pug/EJS/Nunjucks ``child_process``; Jinja2 ``__class__`` chain;
      Freemarker ``Execute``) — confirmed by an ``echo`` canary landing in
      command-output position in a non-error response. Critical severity.
    """

    EXPRESSION_EVAL = "expression_eval"
    SANDBOX_ESCAPE = "sandbox_escape"
    RCE = "rce"


class SSTIPrimitives(BaseModel):
    """Engine + evaluating syntaxes confirmed during phase-2 fingerprinting.

    Phase-4 synthesis constrains itself to these — synthesizing a Pug ``#{}``
    payload when only ``<%= %>`` evaluated produces a payload the engine
    renders as literal text.

    Attributes:
        engine: The template engine classified for this parameter.
        evaluating_syntaxes: Polyglot wrapper labels whose arithmetic probe
            evaluated (``"{{}}"``, ``"${}"``, ``"#{}"``, ``"<%= %>"``,
            ``"{}"``). The carrier(s) synthesis must use.
        rce_gadget_supported: ``True`` when the fingerprinted engine has a
            known RCE gadget in :data:`SSTI_RCE_CAPABLE_ENGINES` — drives
            whether phase-3 ranks ``RCE`` at all.
        error_signatures: Template-engine error strings observed (pug/jade
            SyntaxError, nunjucks, jinja2, Twig, freemarker). Evidence, and a
            hint that input reached the template compiler.
    """

    engine: SSTITemplateEngine = SSTITemplateEngine.UNKNOWN
    evaluating_syntaxes: list[str] = Field(default_factory=list)
    rce_gadget_supported: bool = False
    error_signatures: list[str] = Field(default_factory=list)


class SSTIMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one SSTI ``_test_*`` invocation.

    Mirrors :class:`NoSQLMethodologyResult` with SSTI-specific fields. Stored
    on the resulting Finding's evidence so the report has a complete audit
    trail of engine classification, the evaluating syntaxes, the LLM-picked
    exploitation type, the synthesized payload, and the verification outcome.

    N/A by construction on a non-template / literal-reflection stack (DVWA's
    PHP/MySQL): no arithmetic probe evaluates, so phase 3 returns no candidate
    type and nothing is emitted.
    """

    phases_completed: int = 0
    engine: SSTITemplateEngine = SSTITemplateEngine.UNKNOWN
    primitives: SSTIPrimitives = Field(default_factory=SSTIPrimitives)
    exploitation_type: SSTIExploitationType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies it: ``"verified"`` = the indicator
    # for the chosen exploitation type was directly observed (arithmetic
    # result rendered in a non-error response, or an ``echo`` canary in
    # command-output position); ``"likely"`` = an arithmetic probe evaluated
    # but the engine-specific escalation could not be cleanly confirmed.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# XXE (XML external entity injection) methodology types
# ---------------------------------------------------------------------------


class XXEExploitationType(StrEnum):
    """The shape of the XXE exploitation that the synthesis phase will target.

    Selected by the phase-3 LLM checkpoint given the confirmed parser
    capabilities, ranked by what phase 2 proved the parser supports. Each value
    implies a different verification rule:

    - ``FILE_DISCLOSURE``: an external ``SYSTEM`` entity reads a local file
      (``file:///etc/passwd``) whose content reflects in-band — confirmed by a
      file-content signature in the response (NOT the payload reflected). The
      canonical, cleanest proof. High severity.
    - ``SSRF``: an external ``SYSTEM`` entity makes the *server* fetch a URL
      (``http://internal``) — confirmed by in-scope fetch evidence. Restricted
      to in-scope targets via the scope-validated client. High severity.
    - ``OOB_EXFIL``: blind exfiltration via parameter entities + an external DTD
      callback — confirmed only by a received out-of-band callback. Without OOB
      collaborator infrastructure this degrades to the in-band path and the
      limitation is noted (like the SSRF-callback limitation).
    - ``DOS``: entity-expansion denial of service — confirmed by a *bounded*
      expansion producing a measurable parse-time delta (or the target's
      timeout signature). Never a real billion-laughs. Medium severity.
    """

    FILE_DISCLOSURE = "file_disclosure"
    SSRF = "ssrf"
    OOB_EXFIL = "oob_exfil"
    DOS = "dos"


class XXEParserCapability(BaseModel):
    """XML-parser capabilities confirmed during phase-2 fingerprinting.

    XXE's equivalent of :class:`SQLDialect` / :class:`SSTITemplateEngine`, but a
    *capability vector* rather than a single discrete class — the parser either
    resolves entities or it does not, supports external entities or not, etc.,
    and the combination gates which exploitation types phase 3 may rank. With no
    ``entity_resolution`` there is no XXE (justified non-finding — the DVWA
    path, where no endpoint parses XML at all).

    Attributes:
        entity_resolution: ``True`` when a benign *internal* entity
            (``<!ENTITY t "MARKER">`` then ``&t;``) expands to its value in the
            response — the baseline proof that the parser resolves entities.
        external_entity: ``True`` when a ``SYSTEM`` external entity is resolved
            (file content / fetch reached) rather than ignored or rejected —
            drives FILE_DISCLOSURE / SSRF.
        parameter_entity: ``True`` when a parameter entity (``<!ENTITY % p ...>``)
            is accepted — drives the OOB external-DTD exfil technique.
        inband_reflection: ``True`` when expanded entity content is echoed back
            in the response body (including a 4xx body — Juice Shop's 410
            deprecation message carries the truncated parsed XML), so file
            disclosure is verifiable in-band without a collaborator.
        error_signatures: XML-parser error / deprecation strings observed
            (libxml/SAX parse errors, "deprecated for security reasons").
            Evidence, and a hint that input reached the XML parser.
    """

    entity_resolution: bool = False
    external_entity: bool = False
    parameter_entity: bool = False
    inband_reflection: bool = False
    error_signatures: list[str] = Field(default_factory=list)


class XXEMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one XXE ``_test_*`` invocation.

    Mirrors :class:`SSTIMethodologyResult` with XXE-specific fields. Stored on
    the resulting Finding's evidence so the report has a complete audit trail of
    the parser-capability fingerprint, the LLM-picked exploitation type, the
    synthesized entity payload, and the verification outcome.

    ``candidate_param`` is a synthetic carrier label (``"file"`` for a multipart
    XML upload, ``"xml_body"`` for a raw ``application/xml`` body) rather than a
    request parameter — XXE is endpoint-scoped, the whole XML document is the
    payload, so there is no injectable named parameter (unlike the SQLi/NoSQL/
    SSTI parameter loop).

    N/A by construction on a non-XML stack (DVWA's PHP/MySQL HTML endpoints): no
    endpoint parses XML, so phase 1 finds no candidate and nothing is emitted.
    """

    phases_completed: int = 0
    capability: XXEParserCapability = Field(default_factory=XXEParserCapability)
    exploitation_type: XXEExploitationType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies it: ``"verified"`` = the indicator for
    # the chosen exploitation type was directly observed (a file-content
    # signature in the response, an in-scope SSRF fetch, or a bounded parse-time
    # delta / timeout); ``"likely"`` = the parser resolved entities but the
    # specific escalation could not be cleanly confirmed in-band.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# JWT (JSON Web Token) attack methodology types
# ---------------------------------------------------------------------------


class JWTAlgorithm(StrEnum):
    """The ``alg`` header value classified during phase-2 fingerprinting.

    JWT's equivalent of :class:`SQLDialect` / :class:`SSTITemplateEngine`, but
    cryptographic rather than injection: the algorithm gates which attacks apply.
    ``alg:none`` acceptance only matters for a currently-*signed* token;
    RS256→HS256 confusion only for an asymmetric (``RS*`` / ``ES*`` / ``PS*``)
    algorithm; weak-secret brute-force only for an HMAC (``HS*``) algorithm.

    Enum *values* are the literal ``alg`` strings so ``JWTAlgorithm(value)``
    round-trips a decoded header. ``NONE`` is the unsigned ``"none"`` algorithm
    (case-folded during fingerprinting so ``None`` / ``NONE`` map here too).
    ``UNKNOWN`` is reserved for an unrecognised / unparseable ``alg``.
    """

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    PS256 = "PS256"
    NONE = "none"
    UNKNOWN = "unknown"


class JWTAttackType(StrEnum):
    """The shape of the JWT attack that the synthesis phase will target.

    Selected by the phase-3 LLM checkpoint given the token fingerprint, ranked by
    what the fingerprint supports. Each value implies a different forge + a fully
    in-band verification rule (the server *accepts* a token we forged/tampered):

    - ``ALG_NONE``: strip the signature and set ``alg`` to ``none`` — confirmed
      when the unsigned token is accepted on an endpoint that rejects a
      broken-signature token. Forgery / full auth bypass — critical.
    - ``ALGORITHM_CONFUSION``: an ``RS256`` token re-signed ``HS256`` using the
      *public* key as the HMAC secret — confirmed when accepted. Needs the public
      key (a bounded in-scope JWKS probe); declines otherwise. Critical.
    - ``WEAK_SECRET``: an ``HS*`` token whose signing secret is in a bounded
      common/default list — proven by a *local* signature verification, then
      confirmed by re-signing a tampered token the server accepts. Critical.
    - ``KID_INJECTION``: a ``kid`` header steered (path traversal / predictable
      key) to a key the attacker controls — confirmed when the resulting token is
      accepted. Critical.
    - ``CLAIM_TAMPERING``: a privileged claim (``role`` / ``admin`` / ...) flipped
      and the token re-signed via an available signing bypass — confirmed by an
      elevated-access response. Privilege escalation / horizontal access — high.
    - ``EXPIRED_ACCEPTANCE``: an expired (or back-dated) token replayed —
      confirmed when ``exp`` is not enforced. High.
    """

    ALG_NONE = "alg_none"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    WEAK_SECRET = "weak_secret"
    KID_INJECTION = "kid_injection"
    CLAIM_TAMPERING = "claim_tampering"
    EXPIRED_ACCEPTANCE = "expired_acceptance"


class JWTFingerprint(BaseModel):
    """Decoded-token characteristics confirmed during phase-2 fingerprinting.

    JWT's equivalent of :class:`InjectionPrimitives` / :class:`XXEParserCapability`
    — the combination gates which attacks phase 3 may rank. **Redaction-safe by
    construction**: it stores claim *names* and header-parameter *names*, never
    their values (a JWT payload routinely carries email / role / session data),
    so the fingerprint can be logged and attached to evidence without leaking.

    Attributes:
        algorithm: The ``alg`` header value (:class:`JWTAlgorithm`). Drives the
            applicable attack set.
        kid_present: ``True`` when a ``kid`` (key-id) header is present — the
            precondition for the kid-injection attack.
        header_params: Names of JOSE header parameters observed (``alg``, ``typ``,
            ``kid``, ``jku``, ``x5u``, ``jwk``, ...). ``jku`` / ``x5u`` / ``jwk``
            presence widens the key-injection surface.
        claim_names: Names of the payload claims (``sub``, ``iat``, ``exp``,
            ``iss``, ...) — names only, never values.
        privileged_claim_names: Subset of ``claim_names`` whose name suggests an
            authorization decision (``role``, ``admin``, ``isAdmin``, ``scope``,
            ``groups``, ``permissions``) — the claim-tampering target set.
        has_expiry: ``True`` when an ``exp`` claim is present (drives
            expired-acceptance ranking).
        expired: ``True`` when the present ``exp`` is already in the past.
        signature_present: ``True`` when the third (signature) segment is
            non-empty — i.e. the token is currently signed (the precondition for
            ``alg:none`` to be a *bypass* rather than the status quo).
        error_signatures: Token-parse / decode error strings observed. Evidence,
            and a hint that the value reached a JWT verifier.
    """

    algorithm: JWTAlgorithm = JWTAlgorithm.UNKNOWN
    kid_present: bool = False
    header_params: list[str] = Field(default_factory=list)
    claim_names: list[str] = Field(default_factory=list)
    privileged_claim_names: list[str] = Field(default_factory=list)
    has_expiry: bool = False
    expired: bool = False
    signature_present: bool = False
    error_signatures: list[str] = Field(default_factory=list)


class JWTMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one JWT ``_test_*`` invocation.

    Mirrors :class:`XXEMethodologyResult` with JWT-specific fields. Stored on the
    resulting Finding's evidence so the report has a complete audit trail of the
    token fingerprint, the LLM-picked attack type, the (redacted) original and
    forged tokens, and the in-band acceptance outcome.

    ``candidate_param`` is a synthetic carrier label (``"authorization_bearer"``
    when the JWT rides the ``Authorization`` header, ``"jwt_cookie:<name>"`` when
    it rides a cookie) rather than a request parameter — JWT is endpoint-scoped,
    the *token itself* on an authenticated request is the injection point (there
    is no injectable named parameter, unlike the SQLi/NoSQL/SSTI parameter loop).

    ``*_token_summary`` fields are **redacted** (decoded header + claim *names*
    only, signature elided) so a long token carrying sensitive claims is never
    persisted verbatim.

    N/A by construction on a non-JWT stack (DVWA's PHP session cookies): no JWT is
    captured for the engagement and none appears on the endpoint, so phase 1 finds
    no candidate token and nothing is emitted.
    """

    phases_completed: int = 0
    fingerprint: JWTFingerprint = Field(default_factory=JWTFingerprint)
    attack_type: JWTAttackType | None = None
    original_token_summary: str | None = None
    synthesized_token_summary: str | None = None
    expected_indicator: str | None = None
    indicator_type: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` means the methodology emitted a finding.
    # ``verification_strength`` qualifies it: ``"verified"`` = the forged/tampered
    # token was accepted on a JWT-gated endpoint (the in-band proof — a non-401/403
    # response matching the valid-token baseline and diverging from the
    # broken-signature reject); ``"likely"`` = a weak secret cracked locally but
    # server acceptance could not be cleanly confirmed.
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


# ---------------------------------------------------------------------------
# File-upload methodology types
# ---------------------------------------------------------------------------


class FileUploadExecutionType(StrEnum):
    """How an uploaded file is reachable for execution / abuse.

    Selected by the LLM checkpoint at phase 3 given the restriction-
    fingerprint outcome. Each value implies a different verification rule:

    - ``DIRECT_EXECUTION``: the uploaded file is reachable at a predictable
      URL and the server interprets it (PHP info dump, command output,
      raw script echo).
    - ``INCLUSION_CHAIN``: the upload itself is harmless but is consumed by
      a known LFI primitive elsewhere in the app — the finding documents
      the upload-shaped half of the chain.
    - ``INTERPRETER_MISCONFIG``: an unusual extension (``.phtml``,
      ``.php.jpg``, ``.svg`` with JS) is mapped to the script handler;
      the upload itself proves the misconfiguration.
    - ``CLIENT_SIDE_ONLY``: only client-side JavaScript validates extension
      / MIME / size — server accepts everything. Finding is medium-low,
      not critical, because reachable-execution depends on path knowledge.
    """

    DIRECT_EXECUTION = "direct_execution"
    INCLUSION_CHAIN = "inclusion_chain"
    INTERPRETER_MISCONFIG = "interpreter_misconfig"
    CLIENT_SIDE_ONLY = "client_side_only"


class FileUploadRestrictions(BaseModel):
    """Restrictions the upload endpoint enforces, as observed by phase-2 probes.

    Each list / flag is the outcome of one fingerprinting probe. ``True`` /
    populated list means a validation gap that synthesis can exploit;
    ``False`` / empty means the server enforces that check.

    Attributes:
        working_extensions: Script-handler extensions whose upload was
            accepted (``.php``, ``.phtml``, etc.). Empty when every
            tried extension was rejected.
        content_type_check: ``True`` when the server rejects on
            ``Content-Type`` alone — a payload with the wrong MIME and
            a script body comes back rejected. ``False`` when the server
            ignores the MIME header.
        magic_byte_check: ``True`` when the server appears to enforce a
            magic-byte / image-header check — prepending ``GIF89a`` to a
            script body either flips an accepted body to accepted or a
            rejected one to accepted (depending on the order probed).
        filename_injection_works: ``True`` when ``../`` / null-byte /
            path components in the filename produced a divergent response
            suggesting partial filename-injection survival.
        size_limit_observed: Free-text description of any size limit
            evidence (``"rejects 0 bytes"``, ``"rejects >5MB"``, ``""``).
    """

    working_extensions: list[str] = Field(default_factory=list)
    content_type_check: bool = False
    magic_byte_check: bool = False
    filename_injection_works: bool = False
    size_limit_observed: str = ""


class FileUploadMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one file-upload ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` but with file-upload-specific
    fields. Stored on the resulting Finding's evidence so the report has a
    complete audit trail of restriction fingerprinting, the LLM-picked
    execution type, the synthesized payload spec, and the verification
    outcome.
    """

    phases_completed: int = 0
    restrictions: FileUploadRestrictions = Field(default_factory=FileUploadRestrictions)
    execution_type: FileUploadExecutionType | None = None
    synthesized_filename: str | None = None
    synthesized_content_type: str | None = None
    synthesized_payload_summary: str | None = None
    uploaded_url: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` = upload accepted AND the uploaded payload was retrieved
    # and observed acting (executing, or being served as-is for inclusion).
    # ``"likely"`` = upload accepted but the resulting file location could
    # not be located / fetched / observed executing.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# XSS stored methodology types
# ---------------------------------------------------------------------------


class XSSStoredMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one stored-XSS ``_test_*`` invocation.

    Mirrors :class:`MethodologyResult` but every probe is a submit-then-fetch
    round trip and the verification phase observes the payload landing on
    a *different* URL than the one it was submitted to. ``read_back_url``
    is the URL the payload was observed on (or the URL we attempted to read
    back from when ``verified`` is False / strength is ``"unverified"``).
    """

    phases_completed: int = 0
    character_map: CharacterMap = Field(default_factory=CharacterMap)
    reflections: list[ReflectionPoint] = Field(default_factory=list)
    synthesized_payload: SynthesizedPayload | None = None
    bypass_attempts: list[str] = Field(default_factory=list)
    read_back_url: str | None = None
    verified: bool = False
    # ``verified`` = the payload was observed in the read-back URL's body
    # unescaped. ``"likely"`` = phase-3 synthesis produced a payload but the
    # read-back URL could not be confirmed (no obvious render endpoint).
    # ``"unverified"`` = the methodology emits a finding with strength=likely
    # based purely on phase-3 + submit-success evidence.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# DOM-XSS methodology types
# ---------------------------------------------------------------------------


class DOMXSSDetectionPath(StrEnum):
    """Which of the two DOM-XSS detection paths produced the finding.

    DOM-XSS cannot be verified without a real JS interpreter. The skill
    confirms exploitability through two complementary static paths:

    - ``CANARY_SCRIPT_CONTEXT``: a server-reflected canary lands inside a
      ``<script>`` block, meaning attacker input is concatenated into JS
      source — the same vector class as a JS-string-context reflected XSS,
      but driven through a client-side sink.
    - ``SOURCE_TO_SINK``: a static-analysis scan of inline ``<script>``
      blocks shows an attacker-controlled DOM source (``location.hash``,
      ``document.URL``, etc.) feeding a dangerous sink (``innerHTML``,
      ``document.write``, ``eval``) in the same block.
    - ``NONE``: neither path produced a hit. Methodology terminates with
      ``verified=False``.
    """

    CANARY_SCRIPT_CONTEXT = "canary_script_context"
    SOURCE_TO_SINK = "source_to_sink"
    NONE = "none"


class DOMSourceSinkPair(BaseModel):
    """One source/sink co-occurrence inside a single ``<script>`` block.

    Attributes:
        source: The DOM source pattern that matched (e.g.
            ``"location.hash"``, ``"document.URL"``).
        sink: The dangerous sink pattern that matched (e.g.
            ``"innerHTML"``, ``"document.write"``).
        script_excerpt: Truncated text of the script block — kept for
            evidence so a reviewer can audit the inference.
    """

    source: str
    sink: str
    script_excerpt: str


class DOMXSSMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one DOM-XSS ``_test_*`` invocation.

    Mirrors :class:`MethodologyResult` but distinguishes the two DOM-XSS
    detection paths and persists their structured evidence. ``reflections``
    classifies each canary occurrence by JS context (``js_dom``,
    ``js_inline``); ``source_sink_pairs`` carries the static-analysis hits
    when the SOURCE_TO_SINK path fires.

    Verification strength is always ``"likely"`` for DOM-XSS findings —
    confirming execution requires a headless browser, which the skill
    deliberately does not require. The methodology produces strong static
    evidence (canary in script context OR source→sink in the same block)
    that justifies emitting the finding.
    """

    phases_completed: int = 0
    detection_path: DOMXSSDetectionPath = DOMXSSDetectionPath.NONE
    character_map: CharacterMap = Field(default_factory=CharacterMap)
    reflections: list[ReflectionPoint] = Field(default_factory=list)
    source_sink_pairs: list[DOMSourceSinkPair] = Field(default_factory=list)
    synthesized_payload: SynthesizedPayload | None = None
    bypass_attempts: list[str] = Field(default_factory=list)
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` = the methodology emitted a finding. Strength is always
    # ``"likely"`` for DOM-XSS because static analysis cannot run the JS to
    # observe execution.
    verification_strength: str = "likely"


# ---------------------------------------------------------------------------
# JS-attacks methodology types
# ---------------------------------------------------------------------------


class JSAttackPatternType(StrEnum):
    """Which client-side security pattern the methodology classified.

    Selected by the phase-3 LLM checkpoint given the collected JS pattern
    set. Each value implies a different finding shape:

    - ``HIDDEN_FIELD_WRITE``: a hidden form field is populated by client-
      side JS — the DVWA "javascript" challenge pattern. Bypassable when
      the JS write is a string literal and we can POST the form directly.
    - ``CLIENT_VALIDATION``: equality / regex / ``checkValidity`` /
      ``preventDefault`` gates on a form input. Weaker static signal — we
      cannot prove the absence of server-side validation.
    - ``TOKEN_COMPUTATION``: JS computes a token-shaped value at submit
      time (concat / hash / encode). Subset of HIDDEN_FIELD_WRITE when the
      destination is a token-named hidden input.
    - ``NONE``: nothing exploitable observed.
    """

    HIDDEN_FIELD_WRITE = "hidden_field_write"
    CLIENT_VALIDATION = "client_validation"
    TOKEN_COMPUTATION = "token_computation"
    NONE = "none"


class JSAttacksMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one JS-attacks ``_test_*`` invocation.

    Stored on the resulting Finding's evidence so the report has a
    complete audit trail of form discovery, JS pattern collection, the
    LLM-picked classification, and any attempted bypass.

    Severity is ``medium`` by default (static detection) and upgrades to
    ``high`` when ``bypass_succeeded`` is True — proven by replaying the
    form submission with the JS-bypassed values and observing a success
    marker in the response.
    """

    phases_completed: int = 0
    forms_analyzed: int = 0
    hidden_fields_set_by_js: list[str] = Field(default_factory=list)
    validation_patterns: list[str] = Field(default_factory=list)
    pattern_type: JSAttackPatternType = JSAttackPatternType.NONE
    bypass_attempted: bool = False
    bypass_succeeded: bool = False
    bypass_payload: dict[str, str] = Field(default_factory=dict)
    bypass_marker: str = ""
    form_action: str = ""
    form_method: str = "GET"
    severity_inferred: str = "medium"
    rationale: str = ""


# ---------------------------------------------------------------------------
# Open-redirect methodology types
# ---------------------------------------------------------------------------


class RedirectBypassType(StrEnum):
    """The bypass shape that the synthesis phase will target.

    Selected by the LLM checkpoint at phase 3 given the redirect-handling
    fingerprint. Each value implies a different verification rule:

    - ``DIRECT_REDIRECT``: no validator at all — any URL is accepted and
      reflected in the ``Location`` header.
    - ``APPENDED_URL``: validator does a prefix / contains check on the
      expected host and missed an appended ``https://evil.example``.
    - ``AT_SYNTAX``: validator uses URL parsing that places the userinfo
      portion against the allowlisted host (``https://target.com@evil.example``).
    - ``PROTOCOL_RELATIVE``: validator accepts ``//evil.example`` because it
      lacks an explicit scheme check.
    - ``UNICODE_LOOKALIKE``: validator uses string compare that doesn't
      normalise homoglyphs — ``ⅽvil.example`` (or similar) bypasses the
      allowlist.
    - ``JS_PROTOCOL``: validator allows the ``javascript:`` scheme — a
      body-level ``window.location`` write or meta-refresh dispatches it.
    - ``DATA_PROTOCOL``: validator allows ``data:text/html`` — body-level
      redirect renders attacker-controlled content.
    - ``ALLOWLIST_BYPASS``: a substring/contains allowlist accepts any target
      that merely *contains* an allowlisted token, so an attacker URL carrying
      that token as a query/path/fragment/userinfo component is accepted while
      the browser still navigates to the attacker host (Juice Shop's outdated
      allowlist class).
    """

    DIRECT_REDIRECT = "direct_redirect"
    APPENDED_URL = "appended_url"
    AT_SYNTAX = "at_syntax"
    PROTOCOL_RELATIVE = "protocol_relative"
    UNICODE_LOOKALIKE = "unicode_lookalike"
    JS_PROTOCOL = "js_protocol"
    DATA_PROTOCOL = "data_protocol"
    ALLOWLIST_BYPASS = "allowlist_bypass"


class RedirectPrimitives(BaseModel):
    """Validator characteristics confirmed during phase-2 fingerprinting.

    Phase-4 payload synthesis constrains itself to these primitives — there
    is no point synthesizing an at-syntax payload when phase-2 proved the
    server rejects user-info-bearing URLs outright.

    Attributes:
        validator_type: Short label describing the validator shape
            (``"none"``, ``"prefix"``, ``"exact"``, ``"regex_allowlist"``,
            ``"unknown"``). Inferred from the per-probe response divergence
            and any redirect-target leakage.
        redirect_status_form: ``"3xx_location"`` when divergent responses
            return a ``3xx`` with ``Location`` set; ``"body_meta_refresh"``
            when the body carries ``<meta http-equiv="refresh">``;
            ``"body_js"`` when ``window.location`` is the dispatch path;
            ``"unknown"`` otherwise.
        working_bypass_primitives: Bypass shapes whose phase-2 probe
            produced a redirect target that left the original host — i.e.
            the validator accepted them. Drives phase-3 ranking.
    """

    validator_type: str = "unknown"
    redirect_status_form: str = "unknown"
    working_bypass_primitives: list[str] = Field(default_factory=list)


class OpenRedirectMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one open-redirect ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` but with open-redirect-specific
    fields. Stored on the resulting Finding's evidence so the report has a
    complete audit trail of validator fingerprinting, the LLM-picked
    bypass type, the synthesized payload, and the verification outcome.
    """

    phases_completed: int = 0
    primitives: RedirectPrimitives = Field(default_factory=RedirectPrimitives)
    bypass_type: RedirectBypassType | None = None
    synthesized_payload: str | None = None
    expected_indicator: str | None = None
    redirect_target_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` = the ``Location`` header (or body-level redirect) was
    # observed pointing to the attacker-controlled host. ``"likely"`` =
    # validator divergence was clearly observed but no attacker-host target
    # surfaced — bypass is plausible but unconfirmed.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# IDOR methodology types
# ---------------------------------------------------------------------------


class IDORExploitationType(StrEnum):
    """The shape of IDOR exploitation that the synthesis phase will target.

    Selected by the LLM checkpoint at phase 3 given the authorization-model
    fingerprint. Each value implies a different verification rule:

    - ``HORIZONTAL``: peer-resource access — same-role user reads another
      user's data (``/account?id=other_user``).
    - ``VERTICAL``: privilege-escalation — non-admin user reaches an
      admin-scoped resource (``/admin?user=...``).
    - ``FUNCTION_LEVEL``: a sensitive action is gated on a parameter the
      attacker controls (``?action=delete&id=X``).
    - ``PARAMETER_POLLUTION``: the server picks the wrong value when the
      same parameter is sent multiple times (``?id=mine&id=other``).
    """

    HORIZONTAL = "horizontal"
    VERTICAL = "vertical"
    FUNCTION_LEVEL = "function_level"
    PARAMETER_POLLUTION = "parameter_pollution"


class IDORPrimitives(BaseModel):
    """Authorization-model characteristics confirmed during phase-2 fingerprinting.

    Attributes:
        id_format: Short label describing the reference shape (``"numeric"``,
            ``"uuid"``, ``"hashed"``, ``"opaque"``, ``"unknown"``).
        predictability: ``"sequential"`` (increment/decrement diverges
            response), ``"random_uuid"``, ``"predictable_hash"`` (short hex
            digest of an integer), ``"opaque"`` (nothing structured
            detected). Drives the choice of probe value in synthesis.
        authz_check_present: ``True`` when changing the reference value
            produced ``401``/``403``/redirect-to-login — i.e. the endpoint
            enforces *some* authz. Bypass is still possible (e.g. via
            parameter-pollution), so this doesn't kill candidacy but does
            shape phase-3 ranking.
        increment_diverged: ``True`` when ``original_id ± 1`` produced a
            response distinct from baseline with the same general shape —
            classic IDOR signature.
        unauth_status_observed: HTTP status code observed for the
            unauthorized-access probe in phase 2. Used by verification to
            decide whether a phase-5 ``200`` is meaningful.
    """

    id_format: str = "unknown"
    predictability: str = "opaque"
    authz_check_present: bool = False
    increment_diverged: bool = False
    unauth_status_observed: int = 0


class IDORMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one IDOR ``_test_*`` invocation.

    Mirrors :class:`SQLiMethodologyResult` but with IDOR-specific fields.
    Stored on the resulting Finding's evidence so the report has a complete
    audit trail of reference-shape classification, authz-model
    fingerprinting, the LLM-picked exploitation type, the synthesized
    reference value, and the verification outcome.
    """

    phases_completed: int = 0
    primitives: IDORPrimitives = Field(default_factory=IDORPrimitives)
    exploitation_type: IDORExploitationType | None = None
    synthesized_reference: str | None = None
    rationale: str | None = None
    indicator_observed: str | None = None
    candidate_param: str | None = None
    verified: bool = False
    # ``verified`` = the response under the synthesized reference contained
    # data plausibly belonging to a different resource (content fingerprint
    # divergence, different identifier echo, response-diff above threshold).
    # ``"likely"`` = response diverged but no clean different-resource
    # signature surfaced.
    verification_strength: str = "verified"


# ---------------------------------------------------------------------------
# CSRF methodology types
# ---------------------------------------------------------------------------


class CSRFWeaknessType(StrEnum):
    """How the CSRF protection on a state-changing endpoint fails.

    Selected by the phase-3 LLM checkpoint given the form set + collected
    token-value samples. Each value implies a different finding shape:

    - ``MISSING``: no token-shaped hidden input on the form.
    - ``PREDICTABLE``: token exists but value is constant across requests
      (no per-request randomness).
    - ``REUSED``: token rotates per request but the server accepts an old
      token replayed — proven by phase-2 replay probes when available.
    - ``COOKIE_ONLY``: the form relies on session cookies alone without a
      defence-in-depth token. Severity depends on whether SameSite /
      Origin / Referer mitigations are also missing.
    - ``SAMESITE_COMPENSATED``: cookie-only authentication, but the
      session cookie has a ``SameSite=Strict|Lax`` attribute, so a
      cross-site POST is structurally blocked. Treated as protected.
    """

    MISSING = "missing"
    PREDICTABLE = "predictable"
    REUSED = "reused"
    COOKIE_ONLY = "cookie_only"
    SAMESITE_COMPENSATED = "samesite_compensated"


class CSRFMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one CSRF ``_test_*`` invocation.

    Stored on the resulting Finding's evidence so the report has a complete
    audit trail of the form-class hypothesis, the collected token-value
    samples, the LLM-picked weakness type, and the verification outcome.
    """

    phases_completed: int = 0
    form_action: str = ""
    method: str = "POST"
    tokens_observed: dict[str, list[str]] = Field(default_factory=dict)
    weakness_type: CSRFWeaknessType | None = None
    protected: bool = False
    rationale: str = ""


# ---------------------------------------------------------------------------
# Brute-force methodology types
# ---------------------------------------------------------------------------


class BruteForceProtectionType(StrEnum):
    """The shape of brute-force protection a login endpoint enforces.

    Selected by the phase-3 LLM checkpoint given 8 failed-auth observations.

    - ``LOCKOUT``: response body / status shifts to a lockout page after
      a small number of attempts (template / length divergence).
    - ``DELAY``: response time grows monotonically with attempt count,
      crossing a divergence threshold the LLM judges as deliberate.
    - ``CAPTCHA``: response body changes to mention captcha / challenge
      keywords at some attempt N.
    - ``RATE_LIMIT``: explicit HTTP rate-limiting signal — ``429``,
      ``Retry-After``, ``X-RateLimit-*``.
    - ``NONE``: no observable protection — the absence is the finding.
    """

    LOCKOUT = "lockout"
    DELAY = "delay"
    CAPTCHA = "captcha"
    RATE_LIMIT = "rate_limit"
    NONE = "none"


class BruteForceObservation(BaseModel):
    """One row of the 8-attempt observation matrix.

    Each attempt records the response signature so phase-3 can decide
    whether the shape changed across attempts (lockout) or stayed
    constant (no protection).
    """

    attempt: int
    status: int
    length: int
    time_ms: float
    retry_after: str = ""
    rate_limit_headers: dict[str, str] = Field(default_factory=dict)
    body_marker: str = ""


class BruteForceMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one brute-force ``_test_*`` invocation.

    Stored on the resulting Finding's evidence so the report has a complete
    audit trail of the login-form hypothesis, the 8-attempt observation
    matrix, and the LLM-picked protection classification.
    """

    phases_completed: int = 0
    login_url: str = ""
    method: str = "POST"
    observations: list[BruteForceObservation] = Field(default_factory=list)
    protection_type: BruteForceProtectionType = BruteForceProtectionType.NONE
    protected: bool = False
    observed_at_attempt: int | None = None
    rationale: str = ""


# ---------------------------------------------------------------------------
# Weak-session methodology types
# ---------------------------------------------------------------------------


class SessionWeaknessType(StrEnum):
    """How a session-token generator fails entropy / safety expectations.

    Multiple values may apply to one engagement — phase 4 aggregates them
    into the rationale.

    - ``SEQUENTIAL``: tokens form an arithmetic progression (numeric or
      hex counter).
    - ``TIME_CORRELATED``: token values track wall-clock or
      monotonically-increasing timestamps.
    - ``LOW_ENTROPY``: short token length AND limited character set.
    - ``PREDICTABLE_FORMAT``: token is a hash (md5/sha1) of guessable
      input — username, timestamp, request id, etc.
    - ``MISSING_FLAGS``: cookie carrying the token lacks HttpOnly /
      Secure (on HTTPS) / SameSite.
    """

    SEQUENTIAL = "sequential"
    TIME_CORRELATED = "time_correlated"
    LOW_ENTROPY = "low_entropy"
    PREDICTABLE_FORMAT = "predictable_format"
    MISSING_FLAGS = "missing_flags"


class WeakSessionMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one weak-session ``_test_*`` invocation.

    Observed-token values are stored truncated (first 16 chars) in the
    finding evidence to avoid leaking long opaque tokens; the full list
    stays in the trace.
    """

    phases_completed: int = 0
    trigger_url: str = ""
    cookie_name: str = ""
    observations: list[str] = Field(default_factory=list)
    cookie_flags: dict[str, bool] = Field(default_factory=dict)
    weakness_types: list[SessionWeaknessType] = Field(default_factory=list)
    weak: bool = False
    rationale: str = ""


# ---------------------------------------------------------------------------
# Security-headers methodology types
# ---------------------------------------------------------------------------


class HeaderWeaknessSeverity(StrEnum):
    """Severity rollup for the missing-or-weak-headers methodology.

    The phase-3 LLM checkpoint chooses one value based on which headers
    are missing or weak:

    - ``LOW``: minor / deprecated headers missing (``X-XSS-Protection``,
      ``Permissions-Policy``, etc.).
    - ``MEDIUM``: ``Content-Security-Policy`` or
      ``Strict-Transport-Security`` (on HTTPS) is missing.
    - ``HIGH``: CSP exists but is permissive enough to be useless
      (``unsafe-inline`` + ``unsafe-eval`` + wildcard sources).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SecurityHeadersMethodologyResult(BaseModel):
    """Roll-up of every phase's output for one security-headers invocation.

    The methodology emits one Finding per (origin, missing-or-weak header).
    Multiple URLs on the same origin produce one Finding — caller-side
    dedup tracker shares state across pages on the same engagement.
    """

    phases_completed: int = 0
    origin: str = ""
    observed_url: str = ""
    headers_observed: dict[str, str] = Field(default_factory=dict)
    missing_headers: list[str] = Field(default_factory=list)
    weak_headers: list[tuple[str, str]] = Field(default_factory=list)
    severity_rollup: HeaderWeaknessSeverity = HeaderWeaknessSeverity.LOW
    rationale: str = ""


__all__ = [
    "BruteForceMethodologyResult",
    "BruteForceObservation",
    "BruteForceProtectionType",
    "CMDIExecutionType",
    "CMDIMethodologyResult",
    "CSRFMethodologyResult",
    "CSRFWeaknessType",
    "CharacterMap",
    "DOMSourceSinkPair",
    "DOMXSSDetectionPath",
    "DOMXSSMethodologyResult",
    "FileUploadExecutionType",
    "FileUploadMethodologyResult",
    "FileUploadRestrictions",
    "FilterBehavior",
    "HeaderWeaknessSeverity",
    "IDORExploitationType",
    "IDORMethodologyResult",
    "IDORPrimitives",
    "InjectionPrimitives",
    "InjectionType",
    "JSAttackPatternType",
    "JSAttacksMethodologyResult",
    "JWTAlgorithm",
    "JWTAttackType",
    "JWTFingerprint",
    "JWTMethodologyResult",
    "LFIMethodologyResult",
    "LFIRetrievalType",
    "LFITraversalPrimitives",
    "MethodologyResult",
    "NoSQLContext",
    "NoSQLInjectionType",
    "NoSQLMethodologyResult",
    "NoSQLPrimitives",
    "OpenRedirectMethodologyResult",
    "RedirectBypassType",
    "RedirectPrimitives",
    "ReflectionContext",
    "ReflectionPoint",
    "SQLDialect",
    "SQLiMethodologyResult",
    "SSTIExploitationType",
    "SSTIMethodologyResult",
    "SSTIPrimitives",
    "SSTITemplateEngine",
    "SecurityHeadersMethodologyResult",
    "SessionWeaknessType",
    "ShellPrimitives",
    "ShellType",
    "SynthesizedPayload",
    "WeakSessionMethodologyResult",
    "XSSStoredMethodologyResult",
]
