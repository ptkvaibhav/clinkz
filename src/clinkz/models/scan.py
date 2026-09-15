"""Scan-phase data models for the deterministic scan agent (v2).

These models represent structured output from service-specific scanning:
HTTP crawling/fuzzing, FTP enumeration, SSH analysis, SMB share listing,
database probing, and the final scan synthesis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# HTTP scanning models
# ---------------------------------------------------------------------------


class ParamLocation(StrEnum):
    """Where an endpoint parameter is injected in an HTTP request.

    The Exploit-side request builder uses this to decide *how* to carry a
    probe value: a query-string pair, a JSON request-body field, a
    form-urlencoded body field, a URL path-segment substitution, or a
    request ``Cookie`` header.

    ``QUERY`` is the default (and the only value DVWA-style query/form
    endpoints ever need): an :class:`Endpoint` with an empty
    ``param_locations`` map behaves exactly as before this enum existed, so
    the addition is fully backward-compatible.

    ``COOKIE`` marks a param carried in the request ``Cookie`` header — the
    injection point when the server reads a value from ``$_COOKIE`` /
    ``req.cookies`` (e.g. DVWA's blind-SQLi ``high`` level reads ``id`` from
    a cookie, not the query string). The request builder clones the ambient
    auth jar and overrides only that one cookie, leaving session/auth cookies
    intact.

    ``SESSION`` marks a **cross-request** injection point: the value is written
    to a server-side session slot (``$_SESSION[field]``) by one request (a
    *setter*), then read by a *trigger* page's query on a later request (e.g.
    DVWA's SQLi ``high`` level reads ``$_SESSION['id']`` — set by POSTing to
    ``session-input.php`` — inside ``/vulnerabilities/sqli/``'s query). The
    request builder POSTs the value to the setter, then observes the trigger;
    both ride the ambient session, so the injected value round-trips through the
    server's session state. See :class:`SessionVector`.
    """

    QUERY = "query"
    JSON_BODY = "json_body"
    FORM_BODY = "form_body"
    PATH = "path"
    COOKIE = "cookie"
    SESSION = "session"


class MethodEvidence(StrEnum):
    """How the engine knows an endpoint's HTTP method.

    **An absence spelled as a measurement is the failure this exists to
    prevent.** ``JSCallSiteDiscoverer`` reads a frontend's own ``fetch`` /
    ``axios`` call sites, and the miner's fallback was::

        if method is None:
            method = "GET"

    so a call site whose verb the miner could not read became a ``GET``
    endpoint, byte-identical to one it read AS ``GET``. That matters more here
    than almost anywhere else, because ``GET`` is precisely the value that
    removes an endpoint from the seven Tier-1 classes gated on
    ``has_form or method in (POST, PUT, PATCH)``. An unread verb was therefore
    not a degraded endpoint, it was a silently absent one.

    Measured on the live cal.com target: of 12 bundles read, the miner emitted
    **2** call sites (both reported ``GET``) while **7** call sites in the same
    bundles carried a config argument it cannot see into — an identifier or a
    top-level spread. Every one of those seven was a ``GET`` in the plan.

    Three values, because there are three facts:

    * :attr:`NAMED` — the source or the protocol said so. A ``.post(`` token, a
      literal ``{method: "PUT"}``, an ``XMLHttpRequest.open("POST", …)``, an
      ``Allow:`` header, an OpenAPI operation, an HTML ``<form method>``.
    * :attr:`PLATFORM_DEFAULT` — no verb was named and **none could have been**:
      a bare ``fetch(url)``, or one whose init object we read in full and which
      declares no ``method``. The idiom's own default applies, so this is a
      reading, not a guess.
    * :attr:`UNREAD` — a config argument exists whose contents we could not
      read, so the verb may be anything. ``GET`` is standing in for an absence.

    :attr:`UNREAD` never admits an endpoint to a write-family class: a terminal,
    mutating methodology dispatched against a route with no evidence it writes
    is invariant 88 plus a residual mutation in another principal's data. What
    it does instead is get the route ASKED — the ``OPTIONS`` sweep probes an
    unread route ahead of one whose verb is known — and get the gap DISCLOSED.
    """

    NAMED = "named"
    PLATFORM_DEFAULT = "platform_default"
    UNREAD = "unread"


class Endpoint(BaseModel):
    """A single HTTP endpoint discovered during scanning.

    ``params`` is the union of *all* parameter names on the endpoint
    (query + body + path), kept as a flat name list for backward
    compatibility with every consumer that counts/iterates parameter names.
    ``param_locations`` annotates *where* each named param lives; a name
    absent from the map defaults to :attr:`ParamLocation.QUERY` (or
    ``PATH`` when the URL carries a ``:name`` / ``{name}`` placeholder for
    it). ``content_type`` records the request content-type a body-bearing
    endpoint expects (e.g. ``application/json``) so the builder serializes
    the body correctly.

    ``session_setters`` annotates a **param-less trigger** page with the
    same-origin URL(s) of a session-value *setter* it references (DVWA's SQLi
    ``high`` page links ``session-input.php`` via ``onclick="popUp(...)"``).
    Its presence is the signal the Exploit planner uses to queue the injection
    family against an otherwise param-less page — without it the cross-request
    session-indirection injection point is never reached. Empty by default, so
    the field is fully backward-compatible. See :class:`SessionVector`.

    ``sets_cookies``, ``has_form`` and ``has_dom_source`` are **observed response
    features**: what the crawl actually saw when it fetched this URL, as opposed
    to what its path or parameters merely suggest. They exist so the Exploit
    planner can rank an endpoint by whether a vuln-class's *precondition* is
    present there — a session-token test can only measure a page that hands out
    a cookie, a CSRF test can only evaluate a page that renders a form, and a
    DOM-XSS test can only fire where the page's own JavaScript reads a DOM
    source. Ranking those classes on a path substring instead put
    ``/vulnerabilities/weak_id/`` (which sets ``dvwaSession`` on every visit) in
    the same tie bucket as ``/security.php`` (which sets nothing), and the tie
    was broken by crawl order. ``has_dom_source`` was added for the same reason
    after a live run in which DOM-XSS ranked a ``.js`` asset above the
    application's actual DOM-XSS route and never tested it. Only cookie *names*
    are recorded — never a value, which is authentication material.
    """

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int = 0
    content_type: str | None = None
    param_locations: dict[str, ParamLocation] = Field(default_factory=dict)
    session_setters: list[str] = Field(default_factory=list)
    sets_cookies: list[str] = Field(default_factory=list)
    has_form: bool = False
    has_dom_source: bool = False
    #: How this endpoint's :attr:`method` came to be known. See
    #: :class:`MethodEvidence`. The default is the PESSIMISTIC value, because a
    #: producer that has not declared is a producer nobody checked, and the two
    #: things ``UNREAD`` causes - an ``OPTIONS`` probe and a line in the coverage
    #: disclosure - are both safe to over-apply, while reading an unread verb as
    #: a measurement is not. Every construction site in ``src/`` declares it
    #: explicitly, asserted by
    #: ``tests/test_agents/test_method_evidence_is_declared.py``.
    method_evidence: MethodEvidence = MethodEvidence.UNREAD
    #: Whether this response served a Content-Security-Policy governing script.
    #: The same kind of observation as the three above, added for the same
    #: reason: "is this policy bypassable" is a question only about a response
    #: that HAS one, and a route whose path says ``csp`` while serving no policy
    #: is not that class's surface. Recorded as a boolean, never the policy text
    #: — the methodology re-reads the policy verbatim at probe time, so a stale
    #: copy cannot become the thing a finding is asserted against.
    serves_csp: bool = False


class SessionVector(BaseModel):
    """A cross-request session-write injection vector.

    The value POSTed to ``field`` on ``setter_url`` is stored server-side in a
    session slot (``$_SESSION[field]``) keyed by the ambient session cookie,
    then read by a *trigger* page's query on a subsequent request. This is the
    injection point for DVWA's SQLi ``high`` level: POSTing ``id`` to
    ``.../sqli/session-input.php`` sets ``$_SESSION['id']``, which
    ``/vulnerabilities/sqli/`` reads into its ``SELECT ... WHERE user_id =
    '$id'`` query. A vector is only recorded after a benign-marker link gate
    proves the write actually flows to the trigger (see the Exploit agent's
    ``_harvest_session_vectors``); the setter/trigger pairing is what makes the
    otherwise param-less trigger injectable.
    """

    setter_url: str
    field: str


class FormField(BaseModel):
    """A single field within a web form."""

    name: str
    type: str = "text"
    value: str | None = None


class WebForm(BaseModel):
    """A web form discovered during scanning."""

    action: str
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)
    has_csrf_token: bool = False


class HTTPScanResult(BaseModel):
    """Structured output from HTTP service scanning (crawl + fuzz)."""

    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[WebForm] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)
    technologies_detected: list[str] = Field(default_factory=list)
    interesting_responses: list[dict[str, Any]] = Field(default_factory=list)
    crawl_tool_used: str = ""
    fuzz_tool_used: str = ""


# ---------------------------------------------------------------------------
# Non-HTTP service scan models
# ---------------------------------------------------------------------------


class FTPScanResult(BaseModel):
    """Structured output from FTP service scanning."""

    anonymous_access: bool = False
    writable_dirs: list[str] = Field(default_factory=list)
    version_vulns: list[str] = Field(default_factory=list)


class SSHScanResult(BaseModel):
    """Structured output from SSH service scanning."""

    version: str = ""
    auth_methods: list[str] = Field(default_factory=list)
    weak_config: list[str] = Field(default_factory=list)


class SMBScanResult(BaseModel):
    """Structured output from SMB service scanning."""

    shares: list[dict[str, Any]] = Field(default_factory=list)
    null_session: bool = False
    signing_required: bool = True


class DBScanResult(BaseModel):
    """Structured output from database service scanning."""

    accessible: bool = False
    version: str | None = None
    default_creds: bool = False
    db_type: str = ""


# ---------------------------------------------------------------------------
# Composite models
# ---------------------------------------------------------------------------

ServiceResult = HTTPScanResult | FTPScanResult | SSHScanResult | SMBScanResult | DBScanResult


class ServiceScanResult(BaseModel):
    """Result for a single service scan dispatched by service type."""

    service_type: str
    port: int
    result: ServiceResult


class CoverageAssessment(BaseModel):
    """LLM assessment of scan coverage sufficiency."""

    sufficient: bool = True
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Final output of the deterministic scan agent.

    Consumed by the Orchestrator and downstream agents (Exploit, Critic).
    """

    target: str
    service_scans: list[ServiceScanResult] = Field(default_factory=list)
    total_endpoints: int = 0
    total_forms: int = 0
    total_params: int = 0
    coverage_assessment: CoverageAssessment = Field(default_factory=CoverageAssessment)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
