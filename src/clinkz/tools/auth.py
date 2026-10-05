"""WebAuthenticator — deterministic web login handler.

Handles the full CSRF-aware login flow as CODE, not LLM reasoning:
  1. GET the login page → extract hidden form fields + cookies
  2. Auto-detect username/password field names from the HTML
  3. POST with all hidden fields, credentials, and cookies from step 1
  4. Check success heuristics (redirect to non-login page, "logout" in body)
  5. Return AuthResult with session cookies for downstream agents

This eliminates the failure mode where the LLM forgets to chain cookies
between GET and POST or misses CSRF tokens.

In addition to the cookie/form flow above, ``authenticate()`` falls back to a
**JSON/API auth** path when the form flow fails: it POSTs the credentials as
JSON to common API login routes (``/rest/user/login``, ``/api/login``, ...)
and extracts a token from the JSON response. This handles SPA targets such as
OWASP Juice Shop, which has no HTML login form and authenticates via
``POST /rest/user/login`` returning ``{authentication: {token}}``, used on
later requests as ``Authorization: Bearer <token>``. The two paths are
additive — the cookie/form flow is tried first and DVWA's behaviour is
unchanged.

A login is called successful only on POSITIVE evidence — session material,
or a redirect that actually occurred. A 4xx is never success, and a final URL
that differs from the login URL is not a redirect: a form whose ``action``
points at another path produces exactly that with an empty redirect chain, and
reading it as "redirected away, therefore logged in" is how a **415** became a
proven session. See :meth:`WebAuthenticator._login_verdict`.

The 415 is not merely refused, it is USED. A server answering
``415 Unsupported Media Type`` has stated the encoding it wants, so the same
credentials are re-POSTed to the same action under the content type the
response itself names (:func:`_negotiated_content_type`). The field names come
from the form's own HTML and the encoding from the server's own answer; neither
is guessed.

**A credential POST never follows a redirect.** Both form paths dispatched with
``-L``/``allow_redirects=True`` and the JSON arm with ``follow_redirects=True``,
so a **307** — which preserves the method and the body — re-sent the engagement's
plaintext credentials to a destination no scope check had ever seen.
``_resolve_post_url`` scope-checks where the credentials go FIRST, because the
target's form ``action`` chose it; the redirect is a second choice, made by
anything that can shape one response, which is a strictly weaker position than
controlling the form's HTML. So the 3xx is OBSERVED: its ``Location`` is
resolved, scope-checked, and only then dispatched to as a new request. A
destination outside scope ABORTS the attempt and says so —
``AuthResult.scope_refusal`` — rather than being dropped, because a credential
POST that vanished into a redirect and one the application rejected read
identically to everything downstream.

**Every exchange here walks hops through the one primitive**
(:mod:`clinkz.tools.redirect_walk`), and that includes the ones carrying no
credential body: the login-page GET that starts each form arm. It runs before
any credential exists, so nothing of ours can leak from it — but its response is
the form we read the field names and the ``action`` out of, and a request to a
host nothing authorised is outside scope whether or not it carries anything. It
also removed a mode divergence: aiohttp followed that GET and curl did not, so a
login page behind a redirect authenticated on the host and failed in the
container.


When TOOL_EXEC_MODE=docker, requests to Docker-internal IPs are executed
via ``curl`` inside the container (same pattern as HTTPClientTool).
Otherwise uses aiohttp on the host.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from enum import StrEnum
from html.parser import HTMLParser
from typing import Any, NamedTuple
from urllib.parse import urlencode, urljoin, urlparse

from pydantic import BaseModel

from clinkz.safety.governor import (
    REFUSED_CREDENTIAL_BUDGET,
    REFUSED_CREDENTIAL_STOPPED,
)
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.redirect_walk import (
    HopResponse,
    RedirectHop,
    WalkOutcome,
    classify_redirect,
    walk_redirects,
)

logger = logging.getLogger(__name__)

# Common JSON/API login routes tried (in order) when the cookie/form flow
# fails. Derived against the target's own origin only — never cross-origin.
_API_LOGIN_ROUTES: tuple[str, ...] = (
    "/rest/user/login",  # OWASP Juice Shop
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/login",
    "/login",
)

#: Governor refusal categories that mean "stop offering this account a password",
#: as opposed to "this one request was refused". Imported by value rather than
#: re-spelled, so a category renamed in the governor breaks the build here.
_CREDENTIAL_REFUSAL_CATEGORIES: frozenset[str] = frozenset(
    {REFUSED_CREDENTIAL_BUDGET, REFUSED_CREDENTIAL_STOPPED}
)

#: Content types this authenticator can encode a credential body as. A 415
#: naming anything outside this set is reported rather than retried: the server
#: told us what it wanted and we cannot produce it, which is a different fact
#: from "the credentials were wrong" and must not be recorded as one.
ENCODABLE_CONTENT_TYPES: tuple[str, ...] = (
    "application/json",
    "application/x-www-form-urlencoded",
)

#: Where a 415 response states the media type it wanted. Header first — it is
#: the protocol's own channel — then the JSON body shapes an API uses to say the
#: same thing. Nothing here parses prose.
_CONTENT_TYPE_BODY_PATHS: tuple[tuple[str, ...], ...] = (
    ("expects", "content_type"),
    ("expects", "contentType"),
    ("expected", "content_type"),
    ("expected", "contentType"),
    ("accepts",),
    ("expects",),
)

# JSON paths searched (in order) for an auth token in an API login response.
# Each tuple is a nested-key path walked into the parsed JSON object.
_TOKEN_JSON_PATHS: tuple[tuple[str, ...], ...] = (
    ("authentication", "token"),  # Juice Shop
    ("data", "authentication", "token"),
    ("data", "token"),
    ("token",),
    ("access_token",),
    ("accessToken",),
    ("jwt",),
    ("id_token",),
    ("idToken",),
)

# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


#: Body phrases that read as "this application refused the credential".
#:
#: A module constant rather than a local list because a vocabulary that lives
#: inside the function using it is invisible to the guard that has to enumerate
#: every marker oracle in the engine — and this one was, until the domain that
#: found it was widened to notice local literal lists.
#:
#: Every one of these is control-discounted before it counts. The list is not
#: the control; the control is.
_LOGIN_FAILURE_MARKERS: tuple[str, ...] = (
    "invalid",
    "incorrect",
    "wrong password",
    "login failed",
    "authentication failed",
    "bad credentials",
    "access denied",
)


class LoginVerdict(StrEnum):
    """What the credential exchange PROVED, in three values rather than two.

    ``bool`` was the defect. "The POST set no cookie" has two causes and a
    boolean collapses them into the same answer:

    * the application refused the credential; or
    * the application **promoted the pre-login session in place** — the cookie
      it issued on the login GET is now an authenticated session, and a
      successful login therefore sets nothing at all.

    Django's ``cycle_key``, PHP's ``session_regenerate_id(false)`` and every
    framework that keeps the same session id across a login produce the second
    shape. Reading it as the first reports a working credential as a wrong one,
    aborts the engagement, and tells the operator their password is bad.

    So the exchange answers with what it observed and the VERDICT is left to the
    oracle that can actually settle it —
    :func:`~clinkz.engagement.auth_state.assert_authenticated`, which compares an
    authenticated request against an anonymous control and is already running on
    every declared credential.
    """

    #: Positive evidence the credential POST produced a session.
    PROVEN = "proven"
    #: Nothing refused it and nothing proved it, and the exchange is carrying
    #: session material from before the credentials were sent. Defer.
    INDETERMINATE = "indeterminate"
    #: The response refused the credential, or produced nothing that could be a
    #: session and nothing to defer with.
    REFUSED = "refused"


class LoginJudgement(NamedTuple):
    """One verdict and the observation that produced it.

    The evidence travels with the verdict because a refusal has to be able to
    say what was ABSENT. "The credentials were wrong" is a claim about the
    operator's input; "the credential POST returned 200, set no cookie, returned
    no token, was not redirected and the exchange held nothing from before" is a
    list of things we looked for and did not find. Only the second is something
    this code observed, and only the second leaves an operator able to tell a bad
    password from a login shape we cannot read.
    """

    verdict: LoginVerdict
    evidence: str


class AuthResult(BaseModel):
    """Result of a web authentication attempt.

    Two authentication shapes are represented:

    - **Cookie/form auth** (DVWA-style): success carries ``session_cookies``.
    - **JSON/API auth** (Juice Shop-style): success carries ``bearer_token``,
      a JWT/opaque token sent on subsequent requests as
      ``Authorization: Bearer <token>``. ``session_cookies`` may be empty.
    """

    success: bool = False
    session_cookies: dict[str, str] = {}
    bearer_token: str = ""
    redirect_url: str = ""
    login_url: str = ""
    username: str = ""
    status_code: int = 0
    error: str = ""
    # The request shape that actually worked. The authenticator discovers the
    # login route and its identifier/secret field names empirically — it tries
    # the candidate shapes and one of them returns a token — so on success it
    # holds an OBSERVED body schema for the single endpoint every credential
    # attack targets. Recording it costs nothing and is the only non-guessed
    # source for a JSON login body, which no representation and no frontend
    # destructuring reveals. Empty for a form login (whose fields are already
    # readable from the HTML) and on failure.
    auth_body_fields: list[str] = []
    auth_content_type: str = ""
    # The URL the credential POST actually went to. Distinct from ``login_url``,
    # which is where we were TOLD to log in: a form's ``action`` sends the POST
    # somewhere else entirely, and an operator reading "login failed at
    # /portal/gateway" cannot tell that nothing was ever offered to
    # /portal/gateway. Empty when no credential POST was dispatched at all.
    posted_to: str = ""
    # Which step ended the attempt, for the abort message. A failure that never
    # reached the credential POST and one that reached it and was refused are
    # different diagnoses, and the message may not assert the second when it
    # observed the first.
    failure_stage: str = ""
    # The content type a 415 named and we retried under. Recorded because the
    # negotiation is an OBSERVATION about the target worth carrying into the
    # report, not an internal retry detail.
    negotiated_content_type: str = ""
    # The out-of-scope destination a 3xx answer to the credential POST named,
    # and which this authenticator therefore did NOT dispatch to. Non-empty
    # makes the whole attempt TERMINAL: it is not "this arm did not work, try
    # the next one", it is the target asking us to hand the engagement's
    # plaintext credentials to a host the operator never authorised. Trying a
    # second arm afterwards would offer the same credentials to the same target
    # and bury the refusal under whatever the second arm reported.
    scope_refusal: str = ""
    # What the credential exchange PROVED, in three values. ``success`` is
    # "the exchange did not refuse" and is therefore true for both PROVEN and
    # INDETERMINATE; ``proven`` is the narrower question, and the two consumers
    # need different ones. The declared-credential path may proceed on
    # INDETERMINATE because ``assert_authenticated`` runs immediately after it
    # and settles the question; the default-credential SWEEP may not, because
    # marking a guessed password "valid" is a claim, and an indeterminate
    # exchange has not earned it.
    verdict: LoginVerdict = LoginVerdict.REFUSED
    # The observation behind ``verdict`` — what was seen, or what was looked for
    # and not found. Carried into the abort message so a failure names absent
    # evidence rather than asserting the credentials were wrong.
    verdict_evidence: str = ""
    # ---- What the deterministic pass over the login page already knew -------
    # Each of these was read, used internally, and discarded before anything an
    # operator sees. Each changes the diagnosis. Defaults are the "nothing
    # observed" values so a result built anywhere else means exactly what it
    # did before.
    #
    # Whether the login form declared a destination. False means the parser
    # defaulted the POST to the login URL — which is a DEFAULT, not a
    # declaration, and "no destination declared" is the finding.
    form_action_declared: bool = True
    # Whether the login page served a ``<form>`` at all. False and
    # ``form_action_declared`` False together are one fact, not two.
    page_declared_a_form: bool = True
    # CSRF-shaped hidden fields with no cookie of that shape in the jar.
    csrf_fields_without_cookie: list[str] = []
    # What the login page headers say the stack is. Deterministic, never a guess.
    framework_fingerprint: str = ""
    # The credential POST came back the same size as the login page GET.
    post_changed_nothing: bool = False
    # Every input NAME the login form declared — identity, secret, hidden and
    # submit. Names are schema the application chose, never data, which is why
    # they travel out of here and values do not. Read by the adaptive-auth
    # agent, which may reference a name and may never invent one.
    form_field_names: list[str] = []
    # Cookie NAMES the login-page GET issued. The same rule one layer along: a
    # cookie VALUE is a session and is redacted, a cookie NAME is schema. "The
    # page set no cookie at all" and "the page set one we do not recognise" are
    # different diagnoses and a bare count collapses them.
    login_page_cookie_names: list[str] = []
    # What the login page served ITSELF as. Distinct from the form's enctype:
    # an application whose login page is already JSON is not a page with a form
    # whose enctype we failed to read.
    login_page_content_type: str = ""
    # Same-origin script URLs the login page referenced. The inventory an agent
    # reasons over when the credential destination is composed at runtime from
    # parts no single served file carries.
    referenced_scripts: list[str] = []
    # Lockout/rate-limit/captcha phrases the LOGIN PAGE ships — i.e. phrases a
    # later response cannot be stopped on, because this target serves them
    # whatever it is sent. The PRODUCER declares them, and it declares the
    # phrases rather than the page: the control is used for exactly one
    # comparison, the page is 383 KB on the target that found this, and a field
    # that large on a model this engine serialises is a transcript nobody reads
    # and a redaction surface nobody needs.
    #
    # Consumed by the adaptive layer, which proposes destinations the engagement
    # has no un-credentialed baseline for and would otherwise be stopped by the
    # same string that stopped the deterministic arm.
    login_page_lockout_markers: list[str] = []

    def deterministic_observations(self) -> list[str]:
        """The facts the login page itself stated, as sentences.

        These are the replacement for a remedy list that guessed. On the run
        that produced this method the operator was offered two fixes — "the
        credentials are wrong, or the account is locked" and "the login URL is
        wrong" — and both were false, while three true statements about the
        page were sitting in local variables.

        Returns:
            Zero or more observations, each independently true and each read
            deterministically off the login-page GET or the credential POST.
        """
        facts: list[str] = []
        if not self.page_declared_a_form:
            facts.append(
                "the login page served no <form> element at all, so the field names and "
                "the destination were taken from loose inputs rather than from a form"
            )
        elif not self.form_action_declared:
            facts.append(
                f"the <form> declared no action, so the credential POST was defaulted to "
                f"{self.posted_to or self.login_url} rather than sent to a destination the "
                f"page named"
            )
        if self.post_changed_nothing:
            facts.append(
                f"the POST to {self.posted_to or self.login_url} returned a response the "
                f"same size as the login page served without credentials — it changed "
                f"nothing this response can show"
            )
        if self.csrf_fields_without_cookie:
            names = ", ".join(repr(f) for f in self.csrf_fields_without_cookie)
            facts.append(
                f"the page carried the CSRF-shaped field(s) {names} and issued no cookie of "
                f"that shape, so only half of a double-submit token was ever in hand"
            )
        if self.framework_fingerprint:
            facts.append(f"the login page headers identify the stack: {self.framework_fingerprint}")
        return facts

    @property
    def proven(self) -> bool:
        """Whether the exchange itself proved a session, rather than deferring."""
        return self.verdict is LoginVerdict.PROVEN

    @property
    def carries_session_material(self) -> bool:
        """Whether this result holds anything that could BE a session.

        A success that carries neither a cookie nor a token is a contradiction:
        the flow concluded a session exists and is holding nothing to prove it
        with. :meth:`WebAuthenticator.authenticate` refuses such a result rather
        than handing ``cookies={}`` to the assertion, which would then fail with
        "no session material was supplied" — an accurate message about the wrong
        component, three layers from the code that invented the success.
        """
        return bool(self.session_cookies or self.bearer_token)


class AuthOutput(ToolOutput):
    """Structured output from the WebAuthenticator."""

    auth_result: AuthResult = AuthResult()


class _EncodingOrder(NamedTuple):
    """Which credential-encoding arm runs first, and the observation that said so.

    The reason travels with the order because "we tried the form first" and "we
    tried the form first BECAUSE nothing about this target favoured JSON" are
    different statements, and only the second one is diagnosable.

    ``login_page`` rides along because this method is the one place in the JSON
    arm's path that fetches the login page WITHOUT a credential, which makes it
    the only free control the arm can have. Carrying it costs nothing — the
    fetch already happened — and not carrying it is what left the chokepoint's
    lockout classifier uncontrolled.

    Attributes:
        arms: Which arm runs first.
        reason: The observation that decided.
        login_page: The login page body this probe fetched, or ``""`` when the
            order was decided without fetching (an operator declaration) or the
            fetch failed. Empty means "no control", never "an empty control".
    """

    arms: tuple[str, ...]
    reason: str
    login_page: str = ""


class CredentialAttemptRefusedError(Exception):
    """The safety rails refused a credential-bearing request before it was sent.

    A dedicated type for the same reason
    :class:`CredentialRedirectRefusedError` is one: the JSON arm's per-route
    loop catches ``Exception`` and moves to the next candidate, and this refusal
    must never become that. When the per-account budget is spent or the target
    has shown us it stopped evaluating credentials, "try the next route" is the
    exact behaviour being refused.

    Attributes:
        category: The governor's refusal category, so the failure message can
            distinguish a spent budget from an observed lockout.
        account: The account no further credential will be offered for.
    """

    def __init__(self, reason: str, *, category: str, account: str, url: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category
        self.account = account
        self.url = url


class CredentialRedirectRefusedError(Exception):
    """A credential POST was redirected outside the engagement scope.

    Raised only by the JSON arm, whose per-route loop catches ``Exception`` and
    moves on to the next candidate — exactly the silent drop this refusal may
    never become. A dedicated type is what lets that loop distinguish "this
    route errored, try the next" from "the target tried to bounce the
    credentials off-scope, stop".
    """

    def __init__(self, posted_to: str, destination: str, status: int, reason: str) -> None:
        super().__init__(reason)
        self.posted_to = posted_to
        self.destination = destination
        self.status = status
        self.reason = reason


# ---------------------------------------------------------------------------
# HTML form parser — extracts hidden fields, username/password field names
# ---------------------------------------------------------------------------


class _FormFields:
    """The credential-carrying fields of ONE form.

    Attributes:
        hidden_fields: ``<input type="hidden">`` names and values (CSRF tokens).
        submit_fields: Named submit buttons, which some applications require.
        username_field: The identity input's name, by name shape.
        password_field: The ``type="password"`` input's name.
        form_action: The ``action`` attribute, exactly as served.
        form_enctype: The declared ``enctype``, lower-cased, parameters dropped.
        form_method: The declared ``method``, upper-cased.
        from_form: Whether these fields came from a real ``<form>`` element, or
            from inputs the page left outside one. The distinction is a
            different diagnosis and it was not recorded: "the form declares no
            destination" and "the page served no form at all" are two findings,
            and the flow reported neither.
    """

    def __init__(
        self, *, action: str = "", enctype: str = "", method: str = "", from_form: bool = False
    ) -> None:
        self.hidden_fields: dict[str, str] = {}
        self.submit_fields: dict[str, str] = {}
        self.username_field: str = ""
        self.password_field: str = ""
        self.form_action: str = action
        self.form_enctype: str = enctype
        self.form_method: str = method
        self.from_form: bool = from_form

    def read_input(self, attrs: dict[str, str]) -> None:
        """Absorb one ``<input>`` belonging to this form."""
        input_type = attrs.get("type", "text").lower()
        input_name = attrs.get("name", "")
        input_value = attrs.get("value", "")
        if not input_name:
            return

        if input_type == "hidden":
            self.hidden_fields[input_name] = input_value
        elif input_type == "submit":
            self.submit_fields[input_name] = input_value
        elif input_type == "password":
            self.password_field = input_name
        elif input_type in ("text", "email"):
            name_lower = input_name.lower()
            if any(hint in name_lower for hint in ("user", "login", "email", "name", "account")):
                self.username_field = input_name


class _FormFieldParser(HTMLParser):
    """Extract the LOGIN form's fields from an HTML login page.

    Finds, **per form**:
    - All ``<input type="hidden">`` fields (CSRF tokens, etc.)
    - The username field name (input with name containing user/login/email)
    - The password field name (input with type="password")
    - The form action URL
    - The form's declared ``enctype``

    ``enctype`` is captured because it is the page's own statement about how it
    expects the credential body encoded, and a statement the target made beats
    an order this module fixed in advance. It is evidence for
    :func:`_encoding_order`, not a instruction: a form that declares nothing
    (the overwhelming majority) leaves the order to be decided by the other
    observations.

    **Per form is the correction.** ``_in_form`` was set on ``<form>`` and
    cleared on ``</form>`` and then gated nothing: every ``<input>`` on the page
    landed in one flat bucket, so a search box's hidden token, a newsletter
    form's ``list_id`` and a locale picker's ``redirect_to`` were all sent to the
    login endpoint as part of the credential body — fields the login form never
    declared, on a request whose rejection we would have reported as "the
    credentials were wrong". A variable that reads as a guard and gates nothing
    is worse than no variable, because the next reader believes the guard is
    there.

    Which form is the login form is decided by SHAPE, in
    :attr:`login_form`: the one carrying a ``type="password"`` input, which is
    the same deterministic signal
    :attr:`~clinkz.engagement.auth_state.ProbeResponse.serves_login_form` uses
    to decide a page is a login surface at all. Not by ``action``'s spelling, not
    by an ``id``.
    """

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[_FormFields] = []
        #: Inputs outside any ``<form>``. Kept because a fragment carrying bare
        #: inputs is a real shape — a template excerpt, an SPA's server-rendered
        #: skeleton — and dropping them would make the parser answer "no fields"
        #: for a page that has them. Used only when the page declared no form at
        #: all, so it can never mix another form's fields into a login body.
        self._loose = _FormFields()
        self._current: _FormFields | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict: dict[str, str] = {k: (v or "") for k, v in attrs}

        if tag == "form":
            self._current = _FormFields(
                action=attr_dict.get("action", ""),
                enctype=attr_dict.get("enctype", "").split(";")[0].strip().lower(),
                method=attr_dict.get("method", "").upper(),
                from_form=True,
            )
            self.forms.append(self._current)
            return

        if tag != "input":
            return

        (self._current or self._loose).read_input(attr_dict)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None

    @property
    def login_form(self) -> _FormFields:
        """The form a credential belongs in, chosen by shape.

        In order:

        1. The first form carrying a ``type="password"`` input. That input IS
           the login surface's deterministic signal, so a page with five forms
           and one password field has exactly one candidate.
        2. The first form declaring ``method="POST"`` — a login is a POST, and a
           page whose password input is rendered by script has no other tell.
        3. The first form.
        4. The inputs outside any form, when the page declared none.
        """
        for form in self.forms:
            if form.password_field:
                return form
        for form in self.forms:
            if form.form_method == "POST":
                return form
        return self.forms[0] if self.forms else self._loose


def _parse_form_fields(html: str) -> _FormFields:
    """Parse HTML and return the LOGIN form's field data."""
    parser = _FormFieldParser()
    parser.feed(html)
    return parser.login_form


#: Hidden-field name shapes that declare a cross-site-request token.
#: Matched on the NAME, which is schema the application chose, never on a value.
_CSRF_FIELD_TOKENS: tuple[str, ...] = (
    "csrf",
    "xsrf",
    "authenticity_token",
    "user_token",
    "_token",
    "nonce",
    "requestverificationtoken",
)


def _csrf_fields_without_cookie(hidden_fields: dict[str, str], jar: dict[str, str]) -> list[str]:
    """CSRF-shaped hidden fields the jar carries no matching cookie for.

    A double-submit token is a PAIR: the field and the cookie are the two halves
    of one control, and a page that hands out one half is a page whose login we
    have not actually reached. The flow extracted the field, found no cookie,
    posted anyway, and reported the result as a credential failure — so the
    operator was told their password was wrong by a run that had already
    observed the login was not going to work.

    This does not decide anything. It NAMES an inconsistency, which is all a
    deterministic reading of one page can honestly do: a synchronizer token
    stored in the session needs no cookie of its own, so this is a fact to
    report beside the others, never a refusal on its own.

    Args:
        hidden_fields: The login form hidden inputs, name to value.
        jar: The cookies the login-page GET left us holding, name to value.

    Returns:
        The CSRF-shaped field names with no cookie of the same shape, sorted.
    """
    jar_shapes = {
        token
        for name in jar
        for token in _CSRF_FIELD_TOKENS
        if token in name.lower().replace("-", "_")
    }
    unmatched: list[str] = []
    for field in hidden_fields:
        normalised = field.lower().replace("-", "_")
        shapes = [token for token in _CSRF_FIELD_TOKENS if token in normalised]
        if shapes and not any(shape in jar_shapes for shape in shapes):
            unmatched.append(field)
    return sorted(unmatched)


def _framework_fingerprint(headers: dict[str, str] | None) -> str:
    """What the login page HEADERS say the application is built with.

    A deterministic protocol artifact (invariant 22): the server wrote these,
    they are not an LLM tech list and not a guess off a path. Read only from
    headers whose presence is itself the statement —

    * ``X-Powered-By`` has no client-side function at all; its only effect is
      to name the stack.
    * ``Vary`` naming ``RSC`` / ``Next-Router-State-Tree`` is a React Server
      Components negotiation, which no other stack performs.
    * an ``x-nextjs-*`` header is Next.js naming itself.

    Two of the three were on every response of the run that produced this
    function, and none of them reached the operator. "This is a Next.js
    application" is the sentence that makes an unreadable HTML login form make
    sense, and it costs one dict read.

    Args:
        headers: Response headers from the login-page GET.

    Returns:
        A short human-readable fingerprint, or ``""`` when nothing named a
        stack. Never a guess — an empty string is the honest answer.
    """
    lower = {k.lower(): (v or "").strip() for k, v in (headers or {}).items()}
    parts: list[str] = []

    powered = lower.get("x-powered-by", "")
    if powered:
        parts.append(f"X-Powered-By: {powered}")

    vary = lower.get("vary", "").lower()
    rsc_tokens = [t for t in ("rsc", "next-router-state-tree") if t in vary]
    if rsc_tokens:
        parts.append("Vary negotiates React Server Components (" + ", ".join(rsc_tokens) + ")")

    nextjs_headers = sorted(k for k in lower if k.startswith("x-nextjs-"))
    if nextjs_headers:
        parts.append("Next.js headers: " + ", ".join(nextjs_headers))

    server = lower.get("server", "")
    if server and not parts:
        parts.append(f"Server: {server}")

    return "; ".join(parts)


def _form_field_names(form: _FormFields) -> list[str]:
    """Every input NAME the login form declared, deduplicated and sorted.

    Names only. This list leaves the authenticator and reaches a prompt, and the
    rule that makes that safe is that a field NAME is schema the application
    published while a field VALUE may be a CSRF token, a session, or the
    credential itself. Sorted so two runs against one target produce the same
    briefing and a transcript diff means something.

    Args:
        form: The login form, as parsed.

    Returns:
        The names, sorted. Empty for a page that declared no inputs.
    """
    names = {
        *form.hidden_fields,
        *form.submit_fields,
        *([form.username_field] if form.username_field else []),
        *([form.password_field] if form.password_field else []),
    }
    return sorted(n for n in names if n)


class _ScriptSrcParser(HTMLParser):
    """Collect ``<script src>`` values from a page.

    Separate from :class:`_FormFieldParser` rather than folded into it: that one
    answers "which form does a credential belong in", this one answers "what
    else did this page load", and a parser that answers two questions is a
    parser whose second answer nobody checks.
    """

    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        for key, value in attrs:
            if key == "src" and value:
                self.srcs.append(value)


def _referenced_scripts(html: str, page_url: str, limit: int = 60) -> list[str]:
    """Same-origin script URLs the page referenced, resolved and deduplicated.

    Same-origin only, and that is a scope statement rather than a tidiness one:
    a third-party CDN bundle is not this application, an engine that listed one
    would be inviting a reader to reason about somebody else's code, and a URL
    a target names is a URL a target chose.

    Args:
        html: The login page body.
        page_url: What served it, for resolving a relative ``src``.
        limit: How many to keep. A code-split application references hundreds;
            the list is context for a proposal, not an inventory, and the
            producer that DOES measure the inventory declares its own coverage
            (:mod:`clinkz.agents._package_identity`).

    Returns:
        Absolute URLs, in page order, deduplicated, at most *limit*.
    """
    parser = _ScriptSrcParser()
    try:
        parser.feed(html or "")
    except Exception:  # noqa: BLE001 — a malformed page yields what parsed
        pass
    origin = _origin_of(page_url)
    seen: dict[str, None] = {}
    for src in parser.srcs:
        absolute = urljoin(page_url, src)
        if origin and _origin_of(absolute) != origin:
            continue
        seen.setdefault(absolute, None)
        if len(seen) >= limit:
            break
    return list(seen)


def _login_page_lockout_markers(html: str) -> list[str]:
    """Lockout-vocabulary phrases this login page ships unconditionally.

    Computed from :data:`~clinkz.safety.lockout.LOCKOUT_PHRASES` rather than
    from a list here, so the control's vocabulary and the classifier's are the
    same vocabulary by construction. A second copy would go stale on the side
    nobody is looking at, which is the defect
    :mod:`clinkz.safety.lockout` was written to close.

    Args:
        html: The login page as served WITHOUT a credential.

    Returns:
        The phrases present, sorted. Empty means the page ships none, which is
        the common case and is why this costs nothing to carry.
    """
    from clinkz.safety.lockout import LOCKOUT_PHRASES

    low = (html or "").lower()
    return sorted({phrase for phrase, _kind in LOCKOUT_PHRASES if phrase in low})


def _origin_of(url: str) -> str:
    """``scheme://host:port`` for *url*, or ``""``."""
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _served_content_type(headers: dict[str, str] | None) -> str:
    """The response's own content type, parameters dropped, lower-cased."""
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            return (value or "").split(";")[0].strip().lower()
    return ""


def _cookies_from_set_cookie(values: Iterable[str]) -> dict[str, str]:
    """``name -> value`` for a list of ``Set-Cookie`` header values.

    One entry per header, as the transport reported them — never a single string
    a consumer has to split. A cookie value may itself contain a comma and an
    attribute list certainly does, so splitting a joined header is a guess about
    a separator somebody else chose (invariant 82: a consumer never guesses a
    producer's field names, and a separator is a field name's twin).

    Attributes (``Path``, ``HttpOnly``, ``SameSite``) are dropped; only the
    leading ``name=value`` pair is a session.

    Args:
        values: ``Set-Cookie`` header values, verbatim, in order.

    Returns:
        The cookies those headers set. Later headers win, which is the order a
        browser applies them in.
    """
    cookies: dict[str, str] = {}
    for value in values:
        pair = (value or "").split(";", 1)[0].strip()
        name, sep, val = pair.partition("=")
        if sep and name.strip():
            cookies[name.strip()] = val.strip()
    return cookies


# ---------------------------------------------------------------------------
# WebAuthenticator tool
# ---------------------------------------------------------------------------


class WebAuthenticator(ToolBase):
    """Deterministic web authentication handler.

    Performs the full GET→extract→POST login flow as code, handling CSRF
    tokens and cookie chaining automatically.

    Args:
        scope: Engagement scope for target validation.
        timeout: HTTP timeout in seconds.
        engagement_id: If provided, stores cookies in a per-engagement jar.
    """

    capabilities = ["web_authentication", "login", "session_management"]
    category = "utility"

    def __init__(
        self,
        scope: Any = None,
        timeout: int = 30,
        engagement_id: str | None = None,
    ) -> None:
        if scope is None:
            from clinkz.models.scope import EngagementScope

            scope = EngagementScope(name="default", targets=[])
        super().__init__(scope=scope, timeout=timeout)
        self._engagement_id = engagement_id

    @property
    def name(self) -> str:
        return "web_authenticator"

    @property
    def description(self) -> str:
        return "Perform deterministic web login with CSRF token handling."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {
                        "type": "string",
                        "description": "URL of the login page.",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to authenticate with.",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password to authenticate with.",
                    },
                    "username_field": {
                        "type": "string",
                        "description": (
                            "Override for the username form field name. Auto-detected if omitted."
                        ),
                        "default": "",
                    },
                    "password_field": {
                        "type": "string",
                        "description": (
                            "Override for the password form field name. Auto-detected if omitted."
                        ),
                        "default": "",
                    },
                    "content_type": {
                        "type": "string",
                        "description": (
                            "Content type for the credential POST. Declared by the operator; "
                            "OVERRIDES both the form's enctype and any negotiation. Empty "
                            "means discover it."
                        ),
                        "default": "",
                    },
                },
                "required": ["login_url", "username", "password"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        login_url = args.get("login_url", "").strip()
        if not login_url:
            raise ValueError("'login_url' is required")

        parsed = urlparse(login_url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"Invalid login URL: {login_url}")

        self._check_scope(login_url)

        return {
            "login_url": login_url,
            "username": args.get("username", ""),
            "password": args.get("password", ""),
            "username_field": args.get("username_field", ""),
            "password_field": args.get("password_field", ""),
            "content_type": (args.get("content_type", "") or "").split(";")[0].strip().lower(),
        }

    async def execute(self, args: dict[str, Any]) -> str:
        """Execute the full login flow and return JSON result.

        **The governor slot is taken per REQUEST, not per call.** It used to
        wrap this whole method: the login-page GET, both attempts, the 415
        re-POST and every redirect hop inside them shared one authorization and
        produced one action-log entry. Measured against Meridian, one
        ``authenticate()`` for a credential that does not work dispatches
        **16 credential POSTs in docker mode and 18 on the host** — and the
        client-facing action log recorded *one*, saying "POST mutates target
        state". The one component that could have bounded a brute-force we did
        not intend to perform could not see it.

        The JSON arm made the same call differently: it rides
        :class:`~clinkz.tools.http_client.HTTPClientTool`, so its seven-to-
        twenty-four POSTs were authorized and logged individually. Two
        accounting regimes inside one call meant the log's meaning depended on
        which transport the run happened to take.

        So the slot moves to :meth:`_governed_request`, which every request this
        flow makes now passes through, and a credential-bearing one NAMES THE
        ACCOUNT — which is what gives
        :attr:`~clinkz.models.engagement.SafetyPolicy.max_credential_attempts_per_account`
        somewhere to live.
        """
        return await self._dispatch(args)

    @asynccontextmanager
    async def _governed_request(
        self, method: str, url: str, *, account: str = ""
    ) -> AsyncIterator[None]:
        """One request through the safety rails — paced, counted, logged.

        Absent by default, like every other rail: with no governor installed
        this is a no-op and a direct invocation behaves byte for byte as before.

        Args:
            method: HTTP method of the request about to be made.
            url: Its URL.
            account: Non-empty when the request carries a credential FOR that
                account. That is what makes it countable against the per-account
                budget and what names it in the action log.

        Raises:
            CredentialAttemptRefusedError: The rails refused a credential
                attempt. Raised rather than returned because the callers are
                redirect-walk dispatch closures with no channel for a refusal,
                and because the JSON arm's ``except Exception: continue`` is the
                exact behaviour being refused — a dedicated type is what lets it
                tell "this route errored" from "stop offering this password".
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is None:
            yield
            return
        decision = await governor.authorize(
            method,
            url,
            stage="auth",
            field_names=["username", "password"] if account else None,
            account=account,
        )
        if not decision.allowed:
            # Raised for a non-credential request too — the only way one is
            # refused here is a halted engagement or a destructive
            # classification, and both are "stop", not "try something else".
            raise CredentialAttemptRefusedError(
                decision.reason,
                category=decision.category,
                account=account,
                url=url,
            )
        try:
            yield
        finally:
            governor.release()

    def _observe_credential_response(
        self,
        url: str,
        account: str,
        status: int,
        headers: dict[str, str] | None,
        body: str,
        control_body: str = "",
    ) -> None:
        """Hand one login response to the rails for lockout classification.

        Recorded, never raised: the refusal happens on the NEXT
        :meth:`_governed_request`, which keeps every stop in the action log
        beside every other one and keeps this off the data path.

        ``control_body`` is the login page served WITHOUT credentials. It
        matters more here than at the login verdict: a lockout phrase found in
        page furniture does not merely misread one exchange, it halts the
        engagement and asserts to the operator that the client account is
        locked. A phrase the login page already carried is not evidence about
        an account.
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is None or not account:
            return
        governor.observe_credential_response(
            url=url,
            account=account,
            status=status,
            headers=headers,
            body=body,
            control_body=control_body,
        )

    def _attempt_refused_result(
        self,
        refused: CredentialAttemptRefusedError,
        *,
        login_url: str,
        username: str,
        session_cookies: dict[str, str] | None = None,
    ) -> str:
        """The JSON body for a login the safety rails stopped.

        Its ``failure_stage`` says the rails stopped us. It does NOT say the
        credentials were wrong — nothing evaluated them.
        """
        self._logger.error(
            "LOGIN REQUEST REFUSED [%s]%s at %s: %s",
            refused.category,
            f" for {refused.account!r}" if refused.account else "",
            refused.url,
            refused.reason,
        )
        return json.dumps(
            {
                "success": False,
                "verdict": LoginVerdict.REFUSED.value,
                "verdict_evidence": refused.reason,
                "session_cookies": session_cookies or {},
                "redirect_url": "",
                "login_url": login_url,
                "username": username,
                "status_code": 0,
                "posted_to": refused.url,
                "error": f"refused by safety policy [{refused.category}]: {refused.reason}",
                "failure_stage": (
                    (
                        f"the safety rails refused a further credential attempt for "
                        f"{refused.account!r} [{refused.category}]: {refused.reason}. "
                        f"Nothing evaluated these credentials, so this is not a "
                        f"statement about them"
                    )
                    if refused.account
                    else (
                        f"the safety rails refused a request the login flow needed to "
                        f"make to {refused.url} [{refused.category}]: {refused.reason}"
                    )
                ),
            }
        )

    async def _dispatch(self, args: dict[str, Any]) -> str:
        """Route the login flow to the curl (docker) or aiohttp (host) path.

        Mirror HTTPClientTool: in docker mode, every request runs via
        ``docker exec curl`` inside the tools container. The container is on the
        same network as sibling targets (``clinkz-dvwa``, etc.) AND can reach the
        public internet, so the previous hostname whitelist was both incomplete
        (missed container aliases) and unnecessary.
        """
        from clinkz.config import settings

        if settings.tool_exec_mode == "docker":
            return await self._execute_curl(args)
        return await self._execute_aiohttp(args)

    def parse_output(self, raw_output: str) -> AuthOutput:
        """Parse the JSON result into AuthOutput."""
        if not raw_output or not raw_output.strip():
            return AuthOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output or "",
                error="Empty response",
            )

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            return AuthOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"JSON parse error: {exc}",
            )

        auth = AuthResult(
            success=data.get("success", False),
            session_cookies=data.get("session_cookies", {}),
            bearer_token=data.get("bearer_token", ""),
            redirect_url=data.get("redirect_url", ""),
            login_url=data.get("login_url", ""),
            username=data.get("username", ""),
            status_code=data.get("status_code", 0),
            error=data.get("error", ""),
            posted_to=data.get("posted_to", ""),
            failure_stage=data.get("failure_stage", ""),
            negotiated_content_type=data.get("negotiated_content_type", ""),
            # Carried through, or the refusal the form arm wrote dies here and
            # ``authenticate()`` runs the next arm as if nothing happened.
            scope_refusal=data.get("scope_refusal", ""),
            # Same rule for the verdict: an arm that answered INDETERMINATE and
            # is parsed back as a bare ``success=True`` has had the one thing it
            # was careful about erased at the boundary.
            #
            # The default FOLLOWS ``success`` rather than being pinned to
            # REFUSED. An envelope with no ``verdict`` key comes from a producer
            # that had only two values, and its ``success: true`` was an
            # unqualified claim of proof; reading it as a refusal would
            # contradict the producer's own field. Only a producer that KNOWS
            # about the third value can express it.
            verdict=LoginVerdict(
                data.get("verdict")
                or (
                    LoginVerdict.PROVEN.value
                    if data.get("success", False)
                    else LoginVerdict.REFUSED.value
                )
            ),
            verdict_evidence=data.get("verdict_evidence", ""),
            # The deterministic readings of the login page. Carried across the
            # seam for the same reason the verdict is: a producer that observed
            # something and a parser that drops it are indistinguishable from a
            # producer that observed nothing.
            form_action_declared=data.get("form_action_declared", True),
            page_declared_a_form=data.get("page_declared_a_form", True),
            csrf_fields_without_cookie=data.get("csrf_fields_without_cookie", []),
            framework_fingerprint=data.get("framework_fingerprint", ""),
            post_changed_nothing=data.get("post_changed_nothing", False),
            form_field_names=data.get("form_field_names", []),
            login_page_cookie_names=data.get("login_page_cookie_names", []),
            login_page_content_type=data.get("login_page_content_type", ""),
            referenced_scripts=data.get("referenced_scripts", []),
            login_page_lockout_markers=data.get("login_page_lockout_markers", []),
        )
        return AuthOutput(
            tool_name=self.name,
            success=auth.success,
            raw_output=raw_output,
            error=auth.error,
            auth_result=auth,
        )

    # ------------------------------------------------------------------
    # Public high-level API (for direct use by orchestrator/agents)
    # ------------------------------------------------------------------

    async def authenticate(
        self,
        login_url: str,
        username: str,
        password: str,
        *,
        api_login_url: str = "",
        identity_field: str = "",
        content_type: str = "",
    ) -> AuthResult:
        """Perform a full login and return structured AuthResult.

        This is the primary API for other components. Two auth shapes are
        attempted, and **the order is decided by what was observed** rather than
        fixed in advance:

        1. **Cookie/form auth** (``execute()``) — the CSRF-aware GET→POST flow,
           now with a 415 retry under the media type the server names.
        2. **JSON/API auth** (``_try_api_login()``) — POST the credentials as
           JSON, to the operator's declared route first and the canned ones
           after.

        Running the form arm unconditionally was a small waste on a JSON API and
        a real problem on one that answers a form POST with something the form
        arm reads as progress. :func:`_encoding_order` decides from the login
        page's own content type and its form's ``enctype``; with nothing
        observed it returns form-first, which is what every existing target
        gets.

        **A success must carry session material.** The last thing this method
        does is check that, because a result claiming a session while holding
        nothing to prove it with would reach ``assert_authenticated`` as
        ``cookies={}`` and fail there — reporting an accurate message about the
        wrong component, three layers from the code that invented the success.

        **An arm may also answer "I cannot tell".** An application that promotes
        its pre-login session in place answers a GOOD credential with ``200``,
        no ``Set-Cookie`` and no token, which is byte-identical to how many
        applications answer a bad one. That arm returns
        :attr:`LoginVerdict.INDETERMINATE`, and it is HELD rather than returned:
        a later arm may prove a session outright, and a proof outranks a
        deferral. If none does, the held result is returned with
        ``success=True`` and ``proven=False`` — carrying the session material
        the exchange holds so that
        :func:`~clinkz.engagement.auth_state.assert_authenticated`, the stronger
        oracle and the one already running on the next line of
        ``_authenticate_role``, can settle it against an anonymous control.

        **A scope refusal is TERMINAL, not an arm that did not work.** An arm
        whose credential POST was redirected outside the engagement scope
        returns immediately, without running the other one. The alternative
        offers the same credentials to the same target a second time and then
        reports whatever the second arm found, which buries the one fact the
        operator has to see.

        Args:
            login_url: URL of the login page.
            username: Username (or email) credential.
            password: Password credential.
            api_login_url: Operator-declared JSON login route. Tried FIRST by
                the JSON arm, and it OVERRIDES discovery rather than seeding it.
            identity_field: Operator-declared name of the identity field. Same
                rule: tried first, overriding both auto-detection and the
                conventional ``email``/``username`` shapes.
            content_type: Operator-declared content type for the credential
                POST. Overrides the form's ``enctype`` and any negotiation.

        Returns:
            AuthResult — on success, carries ``session_cookies`` (cookie/form or
            JSON-with-a-cookie auth) or ``bearer_token`` (JSON-with-a-token).
        """
        order = await self._encoding_order(login_url, declared_content_type=content_type)
        self._logger.info("Login encoding order for %s: %s", login_url, " then ".join(order.arms))

        form_result: AuthResult | None = None
        api_result: AuthResult | None = None
        # An arm that could not tell a promoted session from a refusal is HELD,
        # not returned: a later arm may still PROVE one, and a proof outranks a
        # deferral. Only the first is kept — the second would be the same
        # ambiguity about the same target.
        deferred: AuthResult | None = None

        for arm in order.arms:
            if arm == "form":
                form_result = await self._run_form_arm(
                    login_url,
                    username,
                    password,
                    identity_field=identity_field,
                    content_type=content_type,
                )
                result = form_result
            else:
                api_result = await self._try_api_login(
                    login_url,
                    username,
                    password,
                    api_login_url=api_login_url,
                    identity_field=identity_field,
                    control_body=order.login_page,
                )
                result = api_result

            if result.proven:
                return self._require_session_material(result)
            if result.scope_refusal:
                return result
            if result.verdict is LoginVerdict.INDETERMINATE and deferred is None:
                deferred = result
            elif arm == "form":
                self._logger.info("Cookie/form auth did not establish a session for %s", login_url)

        if deferred is not None:
            # No arm proved a session and one could not rule out a promoted
            # one. Hand it forward carrying the session material it holds; the
            # assertion decides. This is the ONLY path by which a caller
            # receives a success it must not treat as proof, which is why
            # ``verdict`` travels with it and ``proven`` is False.
            self._logger.warning(
                "Login for %s at %s is INDETERMINATE — deferring the verdict to the "
                "authenticated-state assertion. %s",
                username,
                deferred.posted_to or login_url,
                deferred.verdict_evidence,
            )
            return self._require_session_material(deferred)

        # Both arms refused. Surface the form arm's failure when there is one —
        # it carries the richer context (which URL was POSTed to, what came
        # back) that the abort message needs to say what actually happened.
        failed = form_result or api_result
        if failed is None:  # pragma: no cover — order.arms is never empty
            failed = AuthResult(success=False, login_url=login_url, username=username)
        if api_result is not None and form_result is not None and not failed.failure_stage:
            failed.failure_stage = api_result.failure_stage
        return failed

    async def _run_form_arm(
        self,
        login_url: str,
        username: str,
        password: str,
        *,
        identity_field: str = "",
        content_type: str = "",
    ) -> AuthResult:
        """The cookie/form arm, validated and parsed, never raising."""
        try:
            validated = self.validate_input(
                {
                    "login_url": login_url,
                    "username": username,
                    "password": password,
                    "username_field": identity_field,
                    "content_type": content_type,
                }
            )
            raw = await self.execute(validated)
            return self.parse_output(raw).auth_result
        except Exception as exc:
            self._logger.error("authenticate() form flow failed: %s", exc, exc_info=True)
            return AuthResult(
                success=False,
                login_url=login_url,
                username=username,
                error=str(exc),
                failure_stage=f"the form login flow against {login_url} raised: {exc}",
            )

    def _require_session_material(self, result: AuthResult) -> AuthResult:
        """Refuse a success that holds no session.

        A login flow that concluded "authenticated" while carrying neither a
        cookie nor a token has contradicted itself, and the contradiction is
        caught HERE — at the seam where the claim is made — rather than at
        ``assert_authenticated``, which would report the true but useless "no
        session material was supplied".
        """
        if not result.success or result.carries_session_material:
            return result
        self._logger.error(
            "CONTRADICTION: the login flow reported success for %s (status %d) while "
            "holding neither a session cookie nor a token. Refusing it — a session "
            "nothing can prove is not a session.",
            result.posted_to or result.login_url,
            result.status_code,
        )
        return result.model_copy(
            update={
                "success": False,
                "verdict": LoginVerdict.REFUSED,
                "verdict_evidence": (
                    f"the flow reported a session and held neither a cookie nor a token "
                    f"(status {result.status_code} from "
                    f"{result.posted_to or result.login_url})"
                ),
                "error": (
                    "login reported success but produced no session material "
                    f"(status {result.status_code} from "
                    f"{result.posted_to or result.login_url})"
                ),
                "failure_stage": (
                    f"the credential POST to {result.posted_to or result.login_url} "
                    f"returned {result.status_code} and set no cookie and returned no "
                    "token — there is nothing to authenticate with"
                ),
            }
        )

    async def _encoding_order(
        self, login_url: str, *, declared_content_type: str = ""
    ) -> _EncodingOrder:
        """Which arm to run first, decided on evidence.

        Three observations, strongest first:

        1. The operator DECLARED a content type. Nothing observed outranks
           something stated.
        2. The login page answers ``application/json`` — it is an API, not a
           page, and there is no form to parse.
        3. The page's ``<form enctype>`` names a type.

        With none of them, the answer is form-first: unchanged behaviour for
        every target that worked before, and the arm that can read a form
        ``action`` — which is the only way a JSON login route at an unguessable
        path is ever discovered.
        """
        if declared_content_type == "application/json":
            return _EncodingOrder(("json", "form"), f"operator declared {declared_content_type}")
        if declared_content_type:
            return _EncodingOrder(("form", "json"), f"operator declared {declared_content_type}")

        try:
            from clinkz.tools.http_client import HTTPClientTool

            http = HTTPClientTool(scope=self.scope, engagement_id=self._engagement_id, timeout=10)
            args = http.validate_input({"method": "GET", "url": login_url})
            parsed = http.parse_output(await http.execute(args))
        except Exception as exc:
            self._logger.debug("Encoding-order probe of %s failed: %s", login_url, exc)
            return _EncodingOrder(("form", "json"), "the login page could not be read")

        served = ""
        for key, value in (parsed.response_headers or {}).items():
            if key.lower() == "content-type":
                served = (value or "").split(";")[0].strip().lower()
                break
        page = parsed.response_body or ""
        if served == "application/json":
            return _EncodingOrder(("json", "form"), f"the login URL serves {served}", page)

        enctype = _parse_form_fields(page).form_enctype
        if enctype == "application/json":
            return _EncodingOrder(("json", "form"), f'the form declares enctype="{enctype}"', page)

        return _EncodingOrder(("form", "json"), "no observation favours JSON first", page)

    async def _try_api_login(
        self,
        login_url: str,
        username: str,
        password: str,
        *,
        api_login_url: str = "",
        identity_field: str = "",
        control_body: str = "",
    ) -> AuthResult:
        """Attempt JSON/API authentication, declarations first.

        **The route the operator declared is tried before anything canned.**
        This arm used to take ``login_url``, keep only its origin, and iterate
        six routes it had chosen in advance — so an operator who had told us
        exactly where their login lives watched us POST at six places that were
        not it, and read "no API login route returned an auth token". A
        declaration that is discarded is worse than no declaration, because the
        operator believes the engine knows.

        Order:

        1. ``api_login_url`` — declared, absolute, tried alone first.
        2. ``login_url`` itself — discovered, and an observation about this
           target either way.
        3. :data:`_API_LOGIN_ROUTES` — conventions, tried last.

        **A session cookie is a session — unless the response is a denial.**
        Success used to require a token, so an API that answers a JSON login
        with ``Set-Cookie`` and no token in the body — a common shape, and the
        one a same-site SPA uses — authenticated successfully and was recorded
        as a failure. Accepting the cookie then over-corrected: this arm sends
        no jar, so a framework that starts a session for any cookieless caller
        sets one on every route it is offered, whatever the credential said. The
        cookie counts only on a response :meth:`_session_survived` does not
        recognise as a denial.

        Args:
            login_url: The login URL as known; tried directly, and its origin
                used to resolve the conventional routes.
            username: Username, email or account identifier.
            password: Password credential.
            api_login_url: Operator-declared JSON login route. Overrides
                discovery; tried first.
            identity_field: Operator-declared identity field name. Overrides the
                conventional shapes; tried first.
            control_body: The login page as served WITHOUT a credential, from
                the encoding-order probe that already fetched it. Handed to the
                lockout classifier so a phrase this target ships in every
                response cannot stop the run. It is a control for the ORIGIN
                rather than for each route — the login page is the only
                un-credentialed response this arm holds — which is sound for
                exactly the thing being discarded: a string the application
                ships unconditionally is its own vocabulary whichever route
                echoes it back.

        Returns:
            AuthResult carrying ``bearer_token`` or ``session_cookies`` on
            success, else a failure naming what was tried.
        """
        parsed = urlparse(login_url)
        if not parsed.scheme or not parsed.netloc:
            return AuthResult(
                success=False,
                login_url=login_url,
                username=username,
                error=f"Cannot derive origin from login URL: {login_url}",
                failure_stage=(
                    f"no credential POST was dispatched: {login_url!r} has no origin "
                    "to resolve a login route against"
                ),
            )
        base = f"{parsed.scheme}://{parsed.netloc}"

        routes: list[str] = []
        for candidate in (api_login_url, login_url, *(f"{base}{r}" for r in _API_LOGIN_ROUTES)):
            if candidate and candidate not in routes:
                routes.append(candidate)

        # Identity key: declared first, then email-keyed (most JSON APIs, incl.
        # Juice Shop), then username-keyed when the identifier is not an email.
        keys: list[str] = []
        for key in (identity_field, "email", "" if "@" in username else "username"):
            if key and key not in keys:
                keys.append(key)
        bodies = [{key: username, "password": password} for key in keys]

        last_status = 0
        attempted: list[str] = []
        # The first route that could not be told apart from a promoted session.
        # Held rather than returned, because a LATER route may still prove one
        # outright and a proof outranks a deferral.
        indeterminate: AuthResult | None = None
        for url in routes:
            for body in bodies:
                try:
                    status, resp_body, set_cookies = await self._api_post_json(
                        url, body, account=username, control_body=control_body
                    )
                except CredentialRedirectRefusedError as refused:
                    # NOT "this route errored, try the next". The target asked
                    # us to hand these credentials to a host outside scope, and
                    # continuing would offer the same credentials to the same
                    # target five more times and then report "no API login route
                    # returned an auth token" — a true sentence about the wrong
                    # thing.
                    self._logger.error(
                        "SCOPE REFUSAL: the JSON credential POST to %s was answered %d "
                        "redirecting to %s, outside the engagement scope. Not following it.",
                        refused.posted_to,
                        refused.status,
                        refused.destination,
                    )
                    return AuthResult(
                        success=False,
                        login_url=login_url,
                        username=username,
                        status_code=refused.status,
                        posted_to=refused.posted_to,
                        scope_refusal=refused.destination,
                        error=(
                            f"credential POST to {refused.posted_to} redirected to "
                            f"{refused.destination}, which is outside the engagement scope"
                        ),
                        failure_stage=(
                            f"the credential POST to {refused.posted_to} {refused.reason}"
                        ),
                    )
                except CredentialAttemptRefusedError as refused:
                    # NOT "this route errored, try the next". Trying the next
                    # route is precisely what the rails just refused.
                    self._logger.error(
                        "CREDENTIAL ATTEMPT REFUSED [%s] for %r at %s: %s",
                        refused.category,
                        refused.account,
                        refused.url,
                        refused.reason,
                    )
                    if indeterminate is not None:
                        return indeterminate
                    return AuthResult(
                        success=False,
                        verdict=LoginVerdict.REFUSED,
                        verdict_evidence=refused.reason,
                        login_url=login_url,
                        username=username,
                        status_code=last_status,
                        posted_to=refused.url,
                        error=(f"refused by safety policy [{refused.category}]: {refused.reason}"),
                        failure_stage=(
                            f"the safety rails refused a further credential attempt for "
                            f"{refused.account!r} [{refused.category}]: {refused.reason}. "
                            f"Nothing evaluated these credentials, so this is not a "
                            f"statement about them"
                        ),
                    )
                except Exception as exc:
                    self._logger.debug("API login POST %s failed: %s", url, exc)
                    continue
                last_status = status or last_status
                attempted.append(f"POST {url} {sorted(body)} -> {status or 'error'}")
                if status < 200 or status >= 300:
                    continue
                token = self._extract_token(resp_body)
                # Every cookie this arm can see on THIS response was set after
                # the credentials went out — the JSON arm has no login-page GET
                # of its own, so there is no pre-credential exchange of its own
                # for one to have come from. The delta rule the form arms apply
                # is satisfied here by construction.
                cookies = _cookies_from_set_cookie(set_cookies)
                if not token and not cookies:
                    # 2xx, no token, no Set-Cookie. Same two causes as on the
                    # form arms and the same fix: an application that promoted
                    # its session in place answers a GOOD credential exactly
                    # like this. The jar the ENGAGEMENT is carrying — which the
                    # form arm's login GET may well have filled — is what a
                    # promoted session would be carried by, and if there is one,
                    # this is a deferral rather than a failure.
                    if indeterminate is None:
                        carried = self._carried_session_cookies()
                        if carried and self._session_survived(status, resp_body):
                            evidence = (
                                f"POST {url} returned {status} with no token and no "
                                f"Set-Cookie, and the engagement is carrying "
                                f"{', '.join(sorted(carried))} from before it. On an "
                                f"application that promotes its pre-login session in "
                                f"place that is what a SUCCESSFUL login looks like, so "
                                f"the verdict is deferred to the authenticated-state "
                                f"assertion"
                            )
                            self._logger.warning(
                                "JSON/API login at %s is INDETERMINATE — %s", url, evidence
                            )
                            indeterminate = AuthResult(
                                success=True,
                                verdict=LoginVerdict.INDETERMINATE,
                                verdict_evidence=evidence,
                                session_cookies=carried,
                                redirect_url=url,
                                login_url=url,
                                posted_to=url,
                                username=username,
                                status_code=status,
                                auth_body_fields=list(body),
                                auth_content_type="application/json",
                            )
                    continue
                # A cookie is only evidence about the credential if the response
                # is not itself a denial. ``_session_survived`` is the same rule
                # both form arms and both verification arms already run, and it
                # is what this arm was missing.
                #
                # "Set after the credentials went out" is NOT the delta rule.
                # This arm carries no jar, so a framework that starts a session
                # for any cookieless caller answers EVERY route in the canned
                # list with a fresh session cookie — measured on DVWA, whose
                # ``/login.php`` answers a JSON POST ``200`` with two
                # ``Set-Cookie: PHPSESSID`` headers and its own login form in the
                # body. Under the old rule two wrong passwords for ``admin``
                # reached ``PROVEN``, and a PROVEN verdict is what the
                # default-credential sweep marks ``valid`` and reports without
                # putting it to any further oracle. The pre-credential cookie
                # merged into the treatment, one arm over.
                if not token and not self._session_survived(status, resp_body):
                    self._logger.warning(
                        "JSON/API login at %s answered %d and set %s, but the response "
                        "is itself a login surface — a cookie the server issues to any "
                        "caller is not evidence that a credential worked. Not a success.",
                        url,
                        status,
                        ", ".join(sorted(cookies)) or "no cookie",
                    )
                    continue
                self._logger.info(
                    "JSON/API auth succeeded via %s (%s)",
                    url,
                    "token" if token else "session cookie",
                )
                return AuthResult(
                    success=True,
                    verdict=LoginVerdict.PROVEN,
                    verdict_evidence=(
                        f"POST {url} returned {status} carrying "
                        + (
                            "an authentication token"
                            if token
                            else f"Set-Cookie: {', '.join(sorted(cookies))}"
                        )
                    ),
                    bearer_token=token,
                    session_cookies=cookies,
                    redirect_url=url,
                    login_url=url,
                    posted_to=url,
                    username=username,
                    status_code=status,
                    auth_body_fields=list(body),
                    auth_content_type="application/json",
                )

        if indeterminate is not None:
            return indeterminate

        return AuthResult(
            success=False,
            verdict=LoginVerdict.REFUSED,
            verdict_evidence=(
                "no route answered 2xx carrying an authentication token or a Set-Cookie, "
                "and none answered in a way that could have been a promoted session"
            ),
            login_url=login_url,
            username=username,
            status_code=last_status,
            posted_to=routes[0] if routes else "",
            error="No API login route returned an auth token or a session cookie",
            failure_stage=(
                "the JSON arm dispatched "
                + (
                    "; ".join(attempted[:6])
                    if attempted
                    else "nothing — every candidate route errored"
                )
            ),
        )

    async def _api_post_json(
        self, url: str, payload: dict[str, str], *, account: str = "", control_body: str = ""
    ) -> tuple[int, str, list[str]]:
        """POST ``payload`` as JSON to ``url``, returning ``(status, body, set_cookies)``.

        Reuses :class:`HTTPClientTool` so the request honours the same
        docker/host execution routing, per-engagement cookie jar, and scope
        enforcement as every other HTTP call in the engagement.

        The ``Set-Cookie`` headers come back as a LIST, across every hop, because
        a JSON login whose session is a cookie is invisible without them and a
        response that sets two cookies sends two headers of the same name. The
        header dict keeps one of the two and which one depends on the transport,
        so the producer declares the list
        (:attr:`~clinkz.tools.http_client.HTTPClientOutput.set_cookie`) and this
        arm never splits a joined string.

        **This is a credential POST too**, so it does not follow redirects
        either. ``HTTPClientTool`` scope-checks the URL it is handed and then
        hands ``-L``/``allow_redirects`` to the transport, which is the same
        hole the form arm had: the initial route is checked and the 307's
        destination is not. Each hop is dispatched as its own validated request
        instead, which is what puts it back inside the scope check.

        Args:
            url: The route to POST to.
            payload: The credential body.
            account: The account this credential is for. Handed to the HTTP
                chokepoint so the attempt is counted against the per-account
                budget and named in the action log.
            control_body: The login page served without a credential. Armed on
                the same instance as *account* and for the same reason — the
                chokepoint observes this response for lockout signals and only
                the caller holds something the credential did not produce.

        Raises:
            CredentialRedirectRefusedError: A hop's destination is outside scope.
                An exception rather than a return value because the caller's
                per-route loop catches ``Exception`` and moves on, and this must
                not be one of the things it moves on from.
            CredentialAttemptRefusedError: The rails refused the attempt. Same
                reason, and the same rule: "try the next route" is the behaviour
                being refused.
        """
        from clinkz.tools.http_client import HTTPClientTool

        http = HTTPClientTool(scope=self.scope, engagement_id=self._engagement_id)
        # The chokepoint takes the slot for this arm — wrapping it here as well
        # would nest two acquisitions of the same semaphore and double-count
        # every rate token. It authorizes, counts and logs the attempt instead,
        # which is what makes the two arms account for a credential POST the
        # same way.
        http.credential_account = account
        http.credential_control_body = control_body
        body = json.dumps(payload)
        dispatched_to = url
        # Every hop's Set-Cookie, in order. A login answered 302-with-the-session
        # then 200 sets the cookie on the hop that redirected, and reading only
        # the response that ANSWERED would miss it.
        set_cookies: list[str] = []

        async def _dispatch(hop_url: str, carries_credentials: bool) -> HopResponse:
            nonlocal dispatched_to
            dispatched_to = hop_url
            request: dict[str, Any] = {
                "method": "POST" if carries_credentials else "GET",
                "url": hop_url,
                "headers": {"Accept": "application/json"},
                "follow_redirects": False,
            }
            if carries_credentials:
                request["headers"]["Content-Type"] = "application/json"
                request["body"] = body
            parsed = http.parse_output(await http.execute(http.validate_input(request)))
            # The chokepoint returns a refusal as an error-shaped response
            # rather than raising, which is right for a methodology probe and
            # wrong here: the caller's next move on a soft failure is to offer
            # the same password to the next route, and that is the thing being
            # refused. Promote it.
            if carries_credentials and parsed.safety_refusal in _CREDENTIAL_REFUSAL_CATEGORIES:
                raise CredentialAttemptRefusedError(
                    parsed.error or parsed.safety_refusal,
                    category=parsed.safety_refusal,
                    account=account,
                    url=hop_url,
                )
            set_cookies.extend(parsed.set_cookie)
            return HopResponse(
                status=parsed.status_code,
                headers=parsed.response_headers or {},
                payload=parsed.response_body,
                set_cookies=tuple(parsed.set_cookie),
            )

        outcome = await walk_redirects(
            start_url=url,
            dispatch=_dispatch,
            in_scope=self._check_scope,
            carries_body=True,
            label=f"JSON credential exchange at {url}",
            log=self._logger,
        )
        if outcome.refusal is not None:
            raise CredentialRedirectRefusedError(
                dispatched_to,
                outcome.refusal.url,
                outcome.response.status,
                outcome.refusal.reason,
            )
        return outcome.response.status, outcome.response.payload or "", set_cookies

    @staticmethod
    def _extract_token(response_body: str) -> str:
        """Extract an auth token from a JSON login response body.

        Walks each path in ``_TOKEN_JSON_PATHS`` into the parsed JSON object
        and returns the first non-empty string value found.

        Args:
            response_body: Raw response body (expected to be JSON).

        Returns:
            The token string, or "" if none of the known shapes matched.
        """
        try:
            data = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            return ""
        if not isinstance(data, dict):
            return ""

        for path in _TOKEN_JSON_PATHS:
            cursor: Any = data
            for key in path:
                if isinstance(cursor, dict) and key in cursor:
                    cursor = cursor[key]
                else:
                    cursor = None
                    break
            if isinstance(cursor, str) and cursor.strip():
                return cursor.strip()
        return ""

    async def verify_session(
        self,
        url: str,
        cookies: dict[str, str],
    ) -> bool:
        """Verify that a session is still valid by GETting a protected page.

        **A session verdict may never rest on a destination's spelling.** Both
        arms used to decide this on three substrings — ``login``, ``signin``,
        ``auth`` — matched against the ``Location`` of a redirect. That is the
        oracle a target whose login page lives at ``/portal/gateway`` defeated in
        :mod:`clinkz.engagement.auth_state`, where it was replaced by the
        redirect itself plus an anonymous control; it survived here, on the arm
        the default execution mode uses and on the path the default-credential
        sweep runs through, so the same application reached opposite verdicts
        depending on what its login page was called.

        The rule is now the one this codebase already uses to decide a page is a
        login surface: the response is READ, and an ``<input type="password">``
        in it says the session is gone
        (:attr:`~clinkz.engagement.auth_state.ProbeResponse.serves_login_form`).
        The redirect is not sniffed — it is WALKED, one deliberate scope-checked
        hop at a time through the same primitive every other exchange here uses,
        so a 302 to ``/portal/gateway`` and a 302 to ``/login`` are settled by
        what the destination serves rather than by what it is called. Walking it
        also puts the session material back inside the scope gate, which reading
        ``%{redirect_url}`` never did.

        Args:
            url: URL of a protected page (e.g., the app's main page).
            cookies: Session cookies to test.

        Returns:
            True if the session is still valid. A refused (out-of-scope) hop, a
            transport failure and an unreadable response all return False: the
            session was not observed to survive, and re-authenticating costs one
            login while scanning on a dead session costs the engagement.
        """
        from clinkz.config import settings

        try:
            if settings.tool_exec_mode == "docker":
                outcome = await self._verify_session_curl(url, cookies)
            else:
                outcome = await self._verify_session_aiohttp(url, cookies)
        except Exception as exc:
            self._logger.warning("Session verification failed: %s", exc)
            return False

        if outcome.refusal is not None:
            self._logger.warning(
                "Session check for %s was redirected to %s, outside the engagement "
                "scope — not following it, and not claiming the session survived",
                url,
                outcome.refusal.url,
            )
            return False
        return self._session_survived(outcome.response.status, str(outcome.response.payload or ""))

    def _carried_session_cookies(self) -> dict[str, str]:
        """Cookies the ENGAGEMENT is already carrying, for the deferral test only.

        Never evidence that a credential worked — a cookie that exists whatever
        we send cannot distinguish a good password from a bad one. It is read for
        exactly one question: is there anything here that a promoted session
        COULD be, so that an ambiguous response is worth deferring on rather than
        calling a failure.
        """
        if not self._engagement_id:
            return {}
        from clinkz.tools.http_client import get_session_cookies

        try:
            return get_session_cookies(self._engagement_id)
        except Exception as exc:  # noqa: BLE001 — a missing jar is not a login failure
            self._logger.debug("Could not read the engagement cookie jar: %s", exc)
            return {}

    @staticmethod
    def _session_survived(status: int, body: str) -> bool:
        """Whether a response to a session-bearing request says the session lives.

        Both execution modes run this one function, on the response that
        ANSWERED after every redirect has been walked. Two observations, neither
        of them a name:

        1. **401 or 403** — the protocol's own way of saying this identity may
           not have it. 403 is included because this request is not an
           authorization probe: it is a plain GET of a page the session is
           supposed to be able to read.
        2. **The body is a login form** — an ``<input type="password">``, the
           same deterministic signal
           :func:`~clinkz.engagement.auth_state.detect_auth_mechanism` uses to
           decide a page is a login surface at all. Reusing that vocabulary is
           deliberate: a second copy of "what does a login page look like" is a
           second thing to keep in step.

        A status of 0 means nothing was observed, which is not the same fact as
        a healthy session and is not reported as one.

        Args:
            status: Status of the response that answered.
            body: Its body.

        Returns:
            True only when the response was observed and shows no denial.
        """
        from clinkz.engagement.auth_state import ProbeResponse

        if status <= 0:
            return False
        if status in (401, 403):
            return False
        return not ProbeResponse(status=status, body=body or "").serves_login_form

    # ------------------------------------------------------------------
    # aiohttp implementation (host mode)
    # ------------------------------------------------------------------

    def _record_inprocess_hop(
        self,
        *,
        method: str,
        url: str,
        response: HopResponse,
        duration_ms: float,
        body_sent: Any = None,
        account: str = "",
    ) -> None:
        """Record one in-process HTTP exchange of the login flow.

        Parity with the curl arm, hop for hop. That arm records three
        invocations per login attempt — the login-page GET, the credential POST
        and the session check — because each is a separate ``_run_subprocess``.
        The aiohttp arm made the same three requests and recorded none, so a
        ``TOOL_EXEC_MODE=local`` engagement's authentication claim rested on
        ``AuthResult`` alone, with nothing on disk showing what was sent or what
        came back.

        ``stdout`` is the hop's raw HTTP text — status line, headers, body — which
        is what the curl arm's stdout is, so a record from either transport reads
        and diffs the same way.

        ``body_sent`` is carried on the request side and goes through the same
        redaction chokepoint as the curl argv that carried it as ``--data``. It is
        the engagement's own credential, and that chokepoint is the only reason
        recording it is safe on either transport.
        """
        raw = f"HTTP/1.1 {response.status}\n"
        for key, value in (response.headers or {}).items():
            raw += f"{key}: {value}\n"
        for cookie in response.set_cookies or ():
            raw += f"Set-Cookie: {cookie}\n"
        raw += f"\n{response.payload or ''}"
        request: dict[str, Any] = {"method": method, "url": url}
        if body_sent is not None:
            request["body"] = body_sent
        if account:
            request["account"] = account
        self._emit_inprocess_invocation(
            request=request,
            descriptor=[method, url],
            output=raw,
            failed=response.status <= 0,
            duration_ms=duration_ms,
        )

    async def _execute_aiohttp(self, args: dict[str, Any]) -> str:
        """Full login flow via aiohttp with retry on failure."""
        import aiohttp

        login_url = args["login_url"]
        username = args["username"]
        password = args["password"]
        username_field_override = args.get("username_field", "")
        password_field_override = args.get("password_field", "")
        declared_content_type = args.get("content_type", "")

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        # Try up to 2 attempts — second attempt uses a fresh GET for new CSRF token
        max_attempts = 2
        last_result: str = ""

        for attempt in range(1, max_attempts + 1):
            self._logger.info(
                "Auth attempt %d/%d for %s (user=%s)",
                attempt,
                max_attempts,
                login_url,
                username,
            )

            try:
                async with aiohttp.ClientSession(
                    timeout=timeout,
                    cookie_jar=aiohttp.CookieJar(unsafe=True),
                ) as session:
                    # Step 1: GET the login page.
                    #
                    # Walked, not followed. It carries no credential, but it is
                    # a request whose destination the target picks, and the page
                    # it lands on is where the field names and the form
                    # ``action`` come from.
                    async def _get_login_page(hop_url: str, _carries: bool) -> HopResponse:
                        hop_started = time.monotonic()
                        async with (
                            self._governed_request("GET", hop_url),
                            session.get(hop_url, ssl=False, allow_redirects=False) as get_resp,
                        ):
                            hop = HopResponse(
                                status=get_resp.status,
                                headers=dict(get_resp.headers),
                                landed_url=str(get_resp.url),
                                payload=await get_resp.text(errors="replace"),
                            )
                        self._record_inprocess_hop(
                            method="GET",
                            url=hop_url,
                            response=hop,
                            duration_ms=(time.monotonic() - hop_started) * 1000,
                        )
                        return hop

                    get_walk = await walk_redirects(
                        start_url=login_url,
                        dispatch=_get_login_page,
                        in_scope=self._check_scope,
                        label=f"the login page GET at {login_url}",
                        log=self._logger,
                    )
                    if get_walk.refusal is not None:
                        return self._refused_redirect_result(
                            login_url=login_url,
                            username=username,
                            post_url="",
                            status=get_walk.response.status,
                            final_url=get_walk.response.landed_url or login_url,
                            refusal=get_walk.refusal,
                            session_cookies={c.key: c.value for c in session.cookie_jar},
                        )
                    login_html = get_walk.response.payload or ""
                    get_status = get_walk.response.status
                    # The URL that actually SERVED the form. A relative form
                    # ``action`` resolves against this and not against the URL we
                    # asked for: the two differ the moment the login page sits
                    # behind a redirect, and resolving against the wrong one
                    # POSTs the credentials at a path that does not exist.
                    form_base = get_walk.chain[-1] if get_walk.chain else login_url
                    get_cookies = {c.key: c.value for c in session.cookie_jar}

                    self._logger.info(
                        "GET %s → %d (%d bytes) served by %s, cookies received: %s",
                        login_url,
                        get_status,
                        len(login_html),
                        form_base,
                        list(get_cookies.keys()),
                    )

                    # Step 2: Parse form fields from HTML
                    form = _parse_form_fields(login_html)

                    # What the page STATED, read once and carried. Each of these
                    # was previously computed, used, and dropped before anything
                    # an operator sees. The last four exist for the adaptive-auth
                    # agent, which reasons over a login page it could not act on
                    # — and they are NAMES and URLs the page published, never
                    # values, because this set reaches a prompt.
                    page_facts = {
                        "form_action_declared": bool(form.form_action.strip()),
                        "page_declared_a_form": form.from_form,
                        "csrf_fields_without_cookie": _csrf_fields_without_cookie(
                            form.hidden_fields, get_cookies
                        ),
                        "framework_fingerprint": _framework_fingerprint(get_walk.response.headers),
                        "form_field_names": _form_field_names(form),
                        "login_page_cookie_names": sorted(get_cookies),
                        "login_page_content_type": _served_content_type(get_walk.response.headers),
                        "referenced_scripts": _referenced_scripts(login_html, form_base),
                        "login_page_lockout_markers": _login_page_lockout_markers(login_html),
                    }
                    if not page_facts["form_action_declared"]:
                        self._logger.warning(
                            "The login form at %s declares no action; the credential POST "
                            "will DEFAULT to the login URL rather than go somewhere the "
                            "page named",
                            form_base,
                        )
                    if page_facts["csrf_fields_without_cookie"]:
                        self._logger.warning(
                            "CSRF-shaped field(s) %s were extracted and the jar carries no "
                            "cookie of that shape (jar: %s) — half a double-submit token",
                            page_facts["csrf_fields_without_cookie"],
                            sorted(get_cookies),
                        )
                    if page_facts["framework_fingerprint"]:
                        self._logger.info(
                            "Login page stack (headers): %s", page_facts["framework_fingerprint"]
                        )

                    # Determine field names (override > auto-detect > fallback)
                    ufield = username_field_override or form.username_field or "username"
                    pfield = password_field_override or form.password_field or "password"

                    self._logger.info(
                        "Form extraction — username_field: %r, password_field: %r, "
                        "hidden_fields: %s, form_action: %r",
                        ufield,
                        pfield,
                        {
                            k: v[:20] + "..." if len(v) > 20 else v
                            for k, v in form.hidden_fields.items()
                        },
                        form.form_action or "(same URL)",
                    )

                    # Step 3: Build POST body with hidden fields + submit buttons + credentials
                    post_data: dict[str, str] = {}
                    post_data.update(form.hidden_fields)
                    post_data.update(form.submit_fields)
                    post_data[ufield] = username
                    post_data[pfield] = password

                    # Resolve the form action. The TARGET wrote this URL, so
                    # it is scope-checked before any credential reaches it.
                    post_url = self._resolve_post_url(form_base, form.form_action)

                    self._logger.info(
                        "POST %s with %d fields (hidden: %d, creds: 2)",
                        post_url,
                        len(post_data),
                        len(form.hidden_fields),
                    )

                    # Step 4: POST with cookies from step 1 (aiohttp session handles this)
                    #
                    # The encoding is decided by the page and then, if the
                    # server objects, by the server. ``declared_content_type``
                    # is the operator overriding both.
                    content_type = (
                        declared_content_type
                        or (
                            form.form_enctype
                            if form.form_enctype in ENCODABLE_CONTENT_TYPES
                            else ""
                        )
                        or "application/x-www-form-urlencoded"
                    )
                    negotiated = ""

                    # The credential POST does NOT follow redirects. Each 3xx is
                    # observed, its destination scope-checked, and the next hop
                    # dispatched deliberately — the shared walk, so this arm and
                    # the curl arm and the JSON arm cannot drift apart.
                    async def _post(
                        ctype: str,
                    ) -> tuple[
                        int, str, str, list[str], dict[str, str], list[str], RedirectHop | None
                    ]:
                        body, extra = self._encode_credential_body(post_data, ctype)
                        # Set-Cookie across EVERY hop of this walk, in order.
                        # These are the cookies that exist because a credential
                        # was sent, and they are the only cookies that are
                        # evidence about the credential — see
                        # ``_login_verdict`` rule 1. Read off the
                        # multidict rather than the header dict: a response
                        # setting two cookies sends two headers of one name and
                        # ``dict(resp.headers)`` keeps the last.
                        set_cookies: list[str] = []

                        async def _dispatch(hop_url: str, carries_credentials: bool) -> HopResponse:
                            hop_started = time.monotonic()
                            # The slot is per HOP, and a hop that carries the
                            # credential names the account. A 307 re-POSTs the
                            # password; it is another attempt and it counts as
                            # one.
                            #
                            # The request is BUILT inside the slot, not before
                            # it: ``session.post`` returns a context manager
                            # wrapping a coroutine, and a refusal that raises
                            # past one that was never entered leaves it
                            # un-awaited.
                            async with self._governed_request(
                                "POST" if carries_credentials else "GET",
                                hop_url,
                                account=username if carries_credentials else "",
                            ):
                                request = (
                                    session.post(
                                        hop_url,
                                        data=body,
                                        headers=extra,
                                        ssl=False,
                                        allow_redirects=False,
                                    )
                                    if carries_credentials
                                    else session.get(hop_url, ssl=False, allow_redirects=False)
                                )
                                async with request as resp:
                                    hop_cookies = tuple(resp.headers.getall("Set-Cookie", []))
                                    set_cookies.extend(hop_cookies)
                                    hop_body = await resp.text(errors="replace")
                                    hop_headers = dict(resp.headers)
                                if carries_credentials:
                                    self._observe_credential_response(
                                        hop_url,
                                        username,
                                        resp.status,
                                        hop_headers,
                                        hop_body,
                                        control_body=login_html,
                                    )
                                hop = HopResponse(
                                    status=resp.status,
                                    headers=hop_headers,
                                    landed_url=str(resp.url),
                                    payload=hop_body,
                                    set_cookies=hop_cookies,
                                )
                                self._record_inprocess_hop(
                                    method="POST" if carries_credentials else "GET",
                                    url=hop_url,
                                    response=hop,
                                    duration_ms=(time.monotonic() - hop_started) * 1000,
                                    body_sent=body if carries_credentials else None,
                                    account=username if carries_credentials else "",
                                )
                                return hop

                        walk = await walk_redirects(
                            start_url=post_url,
                            dispatch=_dispatch,
                            in_scope=self._check_scope,
                            carries_body=True,
                            label=f"the credential exchange at {post_url}",
                            log=self._logger,
                        )
                        return (
                            walk.response.status,
                            walk.response.payload or "",
                            # The URL that ANSWERED the final response — which is
                            # the last destination when hops were taken, and the
                            # URL the refusal came from when one was refused.
                            walk.response.landed_url or post_url,
                            walk.chain,
                            walk.response.headers,
                            set_cookies,
                            walk.refusal,
                        )

                    (
                        post_status,
                        post_body,
                        final_url,
                        redirect_chain,
                        post_headers,
                        post_set_cookies,
                        refusal,
                    ) = await _post(content_type)

                    if refusal is not None:
                        return self._refused_redirect_result(
                            login_url=login_url,
                            username=username,
                            post_url=post_url,
                            status=post_status,
                            final_url=final_url,
                            refusal=refusal,
                            session_cookies={c.key: c.value for c in session.cookie_jar},
                        )

                    # A 415 is the server naming the encoding it wanted. Retry
                    # the SAME credentials at the SAME action under that type —
                    # the one branch that turns "authentication failed" into an
                    # authenticated session for a JSON API behind an HTML form.
                    wanted = self._negotiated_content_type(post_status, post_headers, post_body)
                    if wanted and wanted != content_type:
                        self._logger.info(
                            "POST %s -> 415; the response names %s — retrying under it",
                            post_url,
                            wanted,
                        )
                        negotiated = wanted
                        (
                            post_status,
                            post_body,
                            final_url,
                            redirect_chain,
                            post_headers,
                            post_set_cookies,
                            refusal,
                        ) = await _post(wanted)
                        if refusal is not None:
                            return self._refused_redirect_result(
                                login_url=login_url,
                                username=username,
                                post_url=post_url,
                                status=post_status,
                                final_url=final_url,
                                refusal=refusal,
                                session_cookies={c.key: c.value for c in session.cookie_jar},
                            )
                    elif post_status == 415:
                        self._logger.warning(
                            "POST %s -> 415 and the response named no media type this "
                            "authenticator can encode — not retrying",
                            post_url,
                        )

                    # Step 5: Separate what the exchange CARRIES from what the
                    # credential POST PRODUCED. The jar is the carriage — the
                    # login GET's cookie is genuinely the session on a framework
                    # that promotes it in place. The delta is the evidence, and
                    # merging the two is what let a cookie issued before any
                    # credential existed score as proof the credential worked.
                    session_cookies: dict[str, str] = {}
                    for cookie in session.cookie_jar:
                        session_cookies[cookie.key] = cookie.value
                    session_evidence = _cookies_from_set_cookie(post_set_cookies)

                    self._logger.info(
                        "POST response — status: %d, final_url: %s, "
                        "redirect_chain: %s, session_cookies: %s, "
                        "set by the credential POST: %s, response_length: %d",
                        post_status,
                        final_url,
                        redirect_chain,
                        list(session_cookies.keys()),
                        list(session_evidence.keys()),
                        len(post_body),
                    )

                    # Step 6: what did the exchange PROVE — in three values.
                    # The login-page GET is the control: the same URL, the
                    # same jar, no credential. It was held and compared against
                    # nothing.
                    judgement = self._login_verdict(
                        post_body,
                        post_status,
                        final_url,
                        login_url,
                        redirect_chain,
                        session_evidence,
                        session_cookies,
                        control_body=login_html,
                    )
                    success = judgement.verdict is not LoginVerdict.REFUSED

                    self._logger.info(
                        "Auth attempt %d verdict: %s — %s",
                        attempt,
                        judgement.verdict.value,
                        judgement.evidence,
                    )

                    last_result = json.dumps(
                        {
                            "success": success,
                            "verdict": judgement.verdict.value,
                            "verdict_evidence": judgement.evidence,
                            "session_cookies": session_cookies,
                            "redirect_url": final_url,
                            "login_url": login_url,
                            "username": username,
                            "status_code": post_status,
                            "posted_to": post_url,
                            "negotiated_content_type": negotiated,
                            "failure_stage": ("" if success else judgement.evidence),
                            **page_facts,
                            "post_changed_nothing": len(post_body) == len(login_html),
                        }
                    )

                    if judgement.verdict is LoginVerdict.PROVEN:
                        return last_result
                    if judgement.verdict is LoginVerdict.INDETERMINATE:
                        # Retrying would offer the same password again for no
                        # new information: the response was not a refusal and
                        # the assertion, not another POST, is what settles it.
                        self._logger.warning(
                            "Login at %s is INDETERMINATE — %s", post_url, judgement.evidence
                        )
                        return last_result

                    # If first attempt failed, retry with fresh session/CSRF
                    if attempt < max_attempts:
                        self._logger.warning(
                            "Auth attempt %d failed — retrying with fresh GET for new CSRF token",
                            attempt,
                        )
                        continue

            except CredentialAttemptRefusedError as refused:
                # Terminal, and never retried: the rails refused this attempt,
                # and the second attempt is the thing being refused.
                return self._attempt_refused_result(refused, login_url=login_url, username=username)
            except Exception as exc:
                self._logger.error(
                    "aiohttp login flow failed (attempt %d): %s",
                    attempt,
                    exc,
                    exc_info=True,
                )
                last_result = json.dumps(
                    {
                        "success": False,
                        "session_cookies": {},
                        "redirect_url": "",
                        "login_url": login_url,
                        "username": username,
                        "status_code": 0,
                        "error": str(exc),
                        "failure_stage": f"the login exchange with {login_url} raised",
                    }
                )
                if attempt < max_attempts:
                    self._logger.warning(
                        "Retrying after exception (attempt %d/%d)",
                        attempt,
                        max_attempts,
                    )
                    continue

        return last_result

    async def _verify_session_aiohttp(self, url: str, cookies: dict[str, str]) -> WalkOutcome:
        """Fetch a protected page over aiohttp, walking any redirect.

        This arm FETCHES; :meth:`_session_survived` decides. The split is what
        keeps the two execution modes from drifting into two different rules,
        which is exactly what they had: this one read the body and the curl one
        threw it away with ``-o /dev/null``.
        """
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as session:

            async def _dispatch(hop_url: str, _carries: bool) -> HopResponse:
                hop_started = time.monotonic()
                async with session.get(
                    hop_url, ssl=False, allow_redirects=False, cookies=cookies
                ) as resp:
                    hop = HopResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        landed_url=str(resp.url),
                        payload=await resp.text(errors="replace"),
                        set_cookies=tuple(resp.headers.getall("Set-Cookie", [])),
                    )
                self._record_inprocess_hop(
                    method="GET",
                    url=hop_url,
                    response=hop,
                    duration_ms=(time.monotonic() - hop_started) * 1000,
                )
                return hop

            return await walk_redirects(
                start_url=url,
                dispatch=_dispatch,
                in_scope=self._check_scope,
                label=f"the session check at {url}",
                log=self._logger,
            )

    # ------------------------------------------------------------------
    # curl implementation (Docker mode for internal IPs)
    # ------------------------------------------------------------------

    async def _execute_curl(self, args: dict[str, Any]) -> str:
        """Full login flow via curl inside Docker container."""
        login_url = args["login_url"]
        username = args["username"]
        password = args["password"]
        username_field_override = args.get("username_field", "")
        password_field_override = args.get("password_field", "")
        declared_content_type = args.get("content_type", "")

        cookie_jar = self._cookie_jar_path()

        try:
            # Step 1: GET the login page, save cookies.
            #
            # No ``-L`` here either, and the hops are walked for the same reason
            # the credential POST's are: the destination is the target's choice
            # and the jar travels with it. This is also what makes the two
            # execution modes agree — aiohttp followed this GET by default and
            # curl did not, so a login page behind a redirect authenticated on
            # the host and failed in the container.
            get_dumps: list[str] = []
            # Set-Cookie from the login-page GET, per hop. These are the
            # PRE-CREDENTIAL cookies: they exist whatever we send next, so they
            # are carriage and never evidence about a credential.
            get_set_cookies: list[str] = []
            get_rc = 0
            get_stderr = ""

            async def _get_login_page(hop_url: str, _carries: bool) -> HopResponse:
                nonlocal get_rc, get_stderr
                # ``-c`` on every hop, ``-b`` only after the first. A login flow
                # starts from a clean jar — the first request must not offer a
                # session left over from an earlier attempt, which is why the
                # original single GET wrote the jar and never read it — but a
                # hop AFTER it has to carry what the login page just set, which
                # is what ``-L`` did and what aiohttp's per-attempt session does.
                cmd = ["curl", "-s", "-S", "-D", "-"]
                if get_dumps:
                    cmd += ["-b", cookie_jar]
                cmd += ["-c", cookie_jar, hop_url]
                async with self._governed_request("GET", hop_url):
                    stdout, stderr, rc = await self._run_subprocess(cmd)
                get_dumps.append(stdout)
                get_rc, get_stderr = rc, stderr
                status, body, headers, hop_cookies = self._parse_curl_exchange(stdout)
                get_set_cookies.extend(hop_cookies)
                return HopResponse(
                    status=status,
                    headers=headers,
                    landed_url=hop_url,
                    payload=body,
                    set_cookies=tuple(hop_cookies),
                )

            get_walk = await walk_redirects(
                start_url=login_url,
                dispatch=_get_login_page,
                in_scope=self._check_scope,
                label=f"the login page GET at {login_url}",
                log=self._logger,
            )
            get_stdout = "".join(get_dumps)
            if get_walk.refusal is not None:
                return self._refused_redirect_result(
                    login_url=login_url,
                    username=username,
                    post_url="",
                    status=get_walk.response.status,
                    final_url=get_walk.response.landed_url or login_url,
                    refusal=get_walk.refusal,
                    session_cookies=_cookies_from_set_cookie(get_set_cookies),
                )
            # The URL that actually SERVED the form; a relative ``action``
            # resolves against it, not against the URL we asked for.
            form_base = get_walk.chain[-1] if get_walk.chain else login_url

            if get_rc != 0 and not get_stdout.strip():
                return json.dumps(
                    {
                        "success": False,
                        "session_cookies": {},
                        "redirect_url": "",
                        "login_url": login_url,
                        "username": username,
                        "status_code": 0,
                        "error": f"GET failed: curl exit {get_rc}: {get_stderr.strip()}",
                        "failure_stage": (
                            f"GET {login_url} never returned — the login page was not "
                            "reached, so no credential was offered to the application"
                        ),
                    }
                )

            # The body of the block that ANSWERED. Splitting the whole dump on
            # the first blank line would take the 3xx's empty body whenever the
            # login page sat behind a redirect.
            login_html = get_walk.response.payload or ""

            # Step 2: Parse form fields
            form = _parse_form_fields(login_html)

            # The same readings the aiohttp arm makes, off the same page. Two
            # arms that disagree about what the login page said would be a
            # defect the execution mode hides, so this block and its sibling are
            # asserted key-for-key by
            # ``test_both_transports_read_the_same_login_page_facts``.
            get_cookies = _cookies_from_set_cookie(get_set_cookies)
            page_facts = {
                "form_action_declared": bool(form.form_action.strip()),
                "page_declared_a_form": form.from_form,
                "csrf_fields_without_cookie": _csrf_fields_without_cookie(
                    form.hidden_fields, get_cookies
                ),
                "framework_fingerprint": _framework_fingerprint(get_walk.response.headers),
                "form_field_names": _form_field_names(form),
                "login_page_cookie_names": sorted(get_cookies),
                "login_page_content_type": _served_content_type(get_walk.response.headers),
                "referenced_scripts": _referenced_scripts(login_html, form_base),
                "login_page_lockout_markers": _login_page_lockout_markers(login_html),
            }
            if not page_facts["form_action_declared"]:
                self._logger.warning(
                    "The login form at %s declares no action; the credential POST will "
                    "DEFAULT to the login URL rather than go somewhere the page named",
                    form_base,
                )
            if page_facts["csrf_fields_without_cookie"]:
                self._logger.warning(
                    "CSRF-shaped field(s) %s were extracted and the jar carries no cookie "
                    "of that shape (jar: %s) — half a double-submit token",
                    page_facts["csrf_fields_without_cookie"],
                    sorted(get_cookies),
                )
            if page_facts["framework_fingerprint"]:
                self._logger.info(
                    "Login page stack (headers): %s", page_facts["framework_fingerprint"]
                )

            ufield = username_field_override or form.username_field or "username"
            pfield = password_field_override or form.password_field or "password"

            # Step 3: Build the credential field set. Names from the page's own
            # HTML; encoding decided below.
            post_fields: dict[str, str] = {}
            post_fields.update(form.hidden_fields)
            post_fields.update(form.submit_fields)
            post_fields[ufield] = username
            post_fields[pfield] = password

            # Resolve the form action. The TARGET wrote this URL, so it is
            # scope-checked before any credential reaches it.
            post_url = self._resolve_post_url(form_base, form.form_action)

            # Step 4: POST with cookies from GET, under the encoding the page
            # declared (or the operator did), retrying under the one a 415
            # names. Same rule as the aiohttp path, and it must stay the same:
            # a target that authenticates in one execution mode and not the
            # other is a defect the mode hides rather than a property of the
            # target.
            content_type = (
                declared_content_type
                or (form.form_enctype if form.form_enctype in ENCODABLE_CONTENT_TYPES else "")
                or "application/x-www-form-urlencoded"
            )
            negotiated = ""

            # No ``-L``. Curl following the redirect itself is curl choosing
            # the destination of a request carrying plaintext credentials, and
            # a 307 makes that choice for it. Each hop is dispatched here
            # instead, through the shared walk, after its destination has been
            # scope-checked. Each hop's ``Set-Cookie`` is kept because a session
            # can land on any of them; the ANSWER is the last one.
            async def _post(ctype: str) -> tuple[list[str], WalkOutcome]:
                body, extra = self._encode_credential_body(post_fields, ctype)
                # Set-Cookie across every hop of THIS walk — the delta across
                # the credential boundary, and the only cookies that are
                # evidence about the credential.
                hop_set_cookies: list[str] = []

                async def _dispatch(hop_url: str, carries_credentials: bool) -> HopResponse:
                    cmd = ["curl", "-s", "-S", "-D", "-"]
                    if carries_credentials:
                        cmd += ["-X", "POST"]
                        for header, value in extra.items():
                            cmd += ["-H", f"{header}: {value}"]
                        cmd += ["-d", body]
                    cmd += ["-b", cookie_jar, "-c", cookie_jar, hop_url]
                    # Per HOP, and naming the account on the hops that carry the
                    # credential. ``_run_subprocess`` takes no slot of its own
                    # (it gets the halt check only), so this does not nest.
                    async with self._governed_request(
                        "POST" if carries_credentials else "GET",
                        hop_url,
                        account=username if carries_credentials else "",
                    ):
                        stdout, _stderr, _rc = await self._run_subprocess(cmd)
                    status, resp_body, headers, hop_cookies = self._parse_curl_exchange(stdout)
                    hop_set_cookies.extend(hop_cookies)
                    if carries_credentials:
                        self._observe_credential_response(
                            hop_url,
                            username,
                            status,
                            headers,
                            resp_body,
                            control_body=login_html,
                        )
                    return HopResponse(
                        status=status,
                        headers=headers,
                        landed_url=hop_url,
                        payload=resp_body,
                        set_cookies=tuple(hop_cookies),
                    )

                walk = await walk_redirects(
                    start_url=post_url,
                    dispatch=_dispatch,
                    in_scope=self._check_scope,
                    carries_body=True,
                    label=f"the credential exchange at {post_url}",
                    log=self._logger,
                )
                return hop_set_cookies, walk

            post_set_cookies, walk = await _post(content_type)
            post_status = walk.response.status
            post_response_body = walk.response.payload or ""
            post_headers = walk.response.headers
            redirect_chain = walk.chain

            if walk.refusal is not None:
                return self._refused_redirect_result(
                    login_url=login_url,
                    username=username,
                    post_url=post_url,
                    status=post_status,
                    final_url=walk.response.landed_url or post_url,
                    refusal=walk.refusal,
                    session_cookies=_cookies_from_set_cookie([*get_set_cookies, *post_set_cookies]),
                )

            wanted = self._negotiated_content_type(post_status, post_headers, post_response_body)
            if wanted and wanted != content_type:
                self._logger.info(
                    "POST %s -> 415; the response names %s — retrying under it",
                    post_url,
                    wanted,
                )
                negotiated = wanted
                post_set_cookies, walk = await _post(wanted)
                post_status = walk.response.status
                post_response_body = walk.response.payload or ""
                post_headers = walk.response.headers
                redirect_chain = walk.chain
                if walk.refusal is not None:
                    return self._refused_redirect_result(
                        login_url=login_url,
                        username=username,
                        post_url=post_url,
                        status=post_status,
                        final_url=walk.response.landed_url or post_url,
                        refusal=walk.refusal,
                        session_cookies=_cookies_from_set_cookie(
                            [*get_set_cookies, *post_set_cookies]
                        ),
                    )
            elif post_status == 415:
                self._logger.warning(
                    "POST %s -> 415 and the response named no media type this "
                    "authenticator can encode — not retrying",
                    post_url,
                )

            final_url = walk.response.landed_url or post_url

            # Collect session cookies from the Set-Cookie headers each hop
            # DECLARED — curl writes the jar inside the clinkz-tools container
            # in docker mode, so reading from a host path here returns nothing,
            # and the header path is the only one that works in both modes.
            #
            # Carriage and evidence are separated here exactly as they are on
            # the aiohttp arm. ``session_cookies`` is what later requests carry
            # and includes the login GET's cookie, because on a framework that
            # promotes a pre-login session in place that cookie IS the session.
            # ``session_evidence`` is the delta across the credential boundary,
            # and it is what the success oracle reads: a cookie issued before a
            # credential was sent cannot be proof the credential worked.
            session_cookies: dict[str, str] = _cookies_from_set_cookie(
                [*get_set_cookies, *post_set_cookies]
            )
            session_evidence = _cookies_from_set_cookie(post_set_cookies)
            if not session_cookies:
                from clinkz.tools.http_client import get_session_cookies

                eid = self._engagement_id or "auth"
                jar_cookies = get_session_cookies(eid) if self._engagement_id else {}
                if not jar_cookies:
                    jar_cookies = self._read_cookie_jar(cookie_jar)
                session_cookies = jar_cookies

            # Same control as the aiohttp arm, for the same reason: a target
            # that authenticates in one execution mode and not the other is a
            # defect the mode hides rather than a property of the target.
            judgement = self._login_verdict(
                post_response_body,
                post_status,
                final_url,
                login_url,
                redirect_chain,
                session_evidence,
                session_cookies,
                control_body=login_html,
            )
            success = judgement.verdict is not LoginVerdict.REFUSED
            self._logger.info("Auth verdict: %s — %s", judgement.verdict.value, judgement.evidence)

            return json.dumps(
                {
                    "success": success,
                    "verdict": judgement.verdict.value,
                    "verdict_evidence": judgement.evidence,
                    "session_cookies": session_cookies,
                    "redirect_url": final_url,
                    "login_url": login_url,
                    "username": username,
                    "status_code": post_status,
                    "posted_to": post_url,
                    "negotiated_content_type": negotiated,
                    "failure_stage": ("" if success else judgement.evidence),
                    **page_facts,
                    "post_changed_nothing": len(post_response_body) == len(login_html),
                }
            )

        except CredentialAttemptRefusedError as refused:
            return self._attempt_refused_result(refused, login_url=login_url, username=username)
        except Exception as exc:
            self._logger.error("curl login flow failed: %s", exc, exc_info=True)
            return json.dumps(
                {
                    "success": False,
                    "session_cookies": {},
                    "redirect_url": "",
                    "login_url": login_url,
                    "username": username,
                    "status_code": 0,
                    "error": str(exc),
                    "failure_stage": f"the login exchange with {login_url} raised",
                }
            )

    def _cookie_jar_path(self) -> str:
        """Where curl's cookie jar lives for this engagement.

        ``/tmp`` here is inside the clinkz-tools Docker container — predictable
        by design so subsequent curl calls find the same jar; the engagement id
        keeps engagements isolated, and the container is single-tenant. It is a
        method rather than an inline literal so the one thing that is genuinely
        container-specific about the curl arm can be pointed at a host directory
        when the arm is exercised on the host.
        """
        if self._engagement_id:
            return f"/tmp/clinkz_{self._engagement_id}_cookies.txt"  # nosec B108
        return "/tmp/clinkz_auth_cookies.txt"  # nosec B108

    async def _verify_session_curl(self, url: str, cookies: dict[str, str]) -> WalkOutcome:
        """Fetch a protected page over curl, walking any redirect.

        The body is KEPT. This arm used to discard it (``-o /dev/null``) and ask
        ``%{redirect_url}`` for a destination it then matched against three
        substrings — so on the default execution mode the only thing that could
        detect a lost session was what the login page happened to be called, and
        the redirect it read was never scope-checked. It fetches and hands the
        response to :meth:`_session_survived`, the same function the aiohttp arm
        hands its response to.
        """
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        async def _dispatch(hop_url: str, _carries: bool) -> HopResponse:
            cmd = ["curl", "-s", "-S", "-D", "-"]
            if cookie_str:
                cmd += ["-b", cookie_str]
            cmd.append(hop_url)
            stdout, _stderr, _rc = await self._run_subprocess(cmd)
            status, body, headers, hop_cookies = self._parse_curl_exchange(stdout)
            return HopResponse(
                status=status,
                headers=headers,
                landed_url=hop_url,
                payload=body,
                set_cookies=tuple(hop_cookies),
            )

        return await walk_redirects(
            start_url=url,
            dispatch=_dispatch,
            in_scope=self._check_scope,
            label=f"the session check at {url}",
            log=self._logger,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _login_verdict(
        response_body: str,
        status_code: int,
        final_url: str,
        login_url: str,
        redirect_chain: list[str],
        session_evidence: dict[str, str] | None = None,
        carried_session: dict[str, str] | None = None,
        control_body: str = "",
    ) -> LoginJudgement:
        """What the credential exchange proved — in three values, not two.

        Success requires POSITIVE evidence:

        1. **Session material the CREDENTIAL POST produced** — cookies set on
           the credential exchange, or a token in its body. This is the thing a
           session IS, and the qualifier is load-bearing.

           ``session_evidence`` is the DELTA across the POST boundary, not the
           cookies the exchange is holding. Both form arms used to hand this
           test the merged jar — the login-page GET's cookies unioned with the
           POST's — so an application that issues its session cookie on the
           login **GET** (PHP does, Django does, every framework that starts a
           session to hold a CSRF token does) satisfied rule 1 before a
           credential had been sent at all. A control arm merged into the
           treatment is not a control.
        2. **A redirect that actually occurred** — ``redirect_chain`` non-empty,
           landing somewhere other than the login page.

           ``redirect_chain`` means one thing: **the absolute destinations a
           redirect pointed to, in hop order**
           (:func:`~clinkz.tools.redirect_walk.walk_redirects`). It used to mean
           two, and this test is why that mattered. The aiohttp arm filled it
           with the URLs that ANSWERED, so a POST to a form ``action`` answered
           "302 back to /login?error=1" produced a chain holding the ACTION path
           — read here as "redirected away, therefore logged in". The curl arm
           filled it with raw ``Location`` values, unresolved, so
           ``urlparse("index.php").path`` was compared against ``/login.php``.
        **There used to be a third, and it is gone.** A 2xx whose body carried
        one of eight English words — ``logout``, ``dashboard``, ``welcome``,
        ``profile``, … — was ``PROVEN``. It is the only rule here that read page
        furniture rather than the session, and the corpus is unambiguous about
        what it bought. Replayed over all 762 recorded credential POSTs in
        ``outputs/``, it carried the verdict **four** times, all four in one
        engagement (``d67835f5``, target ``https://ptkvaibhav.vercel.app/``) — a
        portfolio site with no login of any kind, whose page contains the word
        ``profile``. Four default-credential guesses (``admin:admin``,
        ``root:root``, ``admin:password``, ``test:test``) were marked VALID
        against a site that never evaluated one of them, and the run went on to
        ``verify_session`` carrying the cookie that page hands every visitor.
        Zero correct firings and four wrong ones is not a rule with a weak
        positive control; it is a rule whose only live evidence is against it.

        Nothing is lost by removing it. The shape it was standing in for — a
        good credential answered ``200`` with no new cookie, because the
        framework promoted the pre-login session in place — is what rule 4 below
        now says, and says correctly: ``INDETERMINATE``, deferred to
        ``assert_authenticated``, which compares an authenticated request
        against an anonymous control instead of reading a noun out of the HTML.

        Two rules bound those, and both were written by a live failure. **A 4xx
        is never success** — the old rule reached "logged in" on a **415**, which
        is the server stating what it wanted. **A different final path is not a
        redirect** — a form whose ``action`` points elsewhere satisfies that with
        no redirect having happened, which is exactly the shape of a JSON login
        API behind an HTML form.

        **And then the third value, which is the whole point of this being an
        enum.** When none of the three fire, "the POST set no cookie" still has
        two causes:

        * the application refused the credential; or
        * the application **promoted the pre-login session in place**. Django's
          ``cycle_key``, PHP's ``session_regenerate_id(False)``, and every
          framework that keeps one session id across the login boundary answer a
          GOOD credential with ``200``, no ``Set-Cookie``, and a page. The cookie
          that IS the session was issued on the login GET, so the delta — the
          only honest evidence — is empty on success.

        The two are indistinguishable from this response, so this function stops
        distinguishing them. An empty delta with a **non-empty carried jar**, on
        a response that is not itself a denial, is :attr:`LoginVerdict.INDETERMINATE`
        and the verdict passes to
        :func:`~clinkz.engagement.auth_state.assert_authenticated` — which
        compares an authenticated request against an anonymous control, is the
        stronger oracle, and is already running on the very next line of
        ``_authenticate_role``.

        "Not itself a denial" is :meth:`_session_survived`, the same shared rule
        both verification arms use: not a 401/403, and not a body serving an
        ``<input type="password">``. That is what keeps this from swallowing
        every failed login — an application that answers a wrong password by
        re-serving its login form is REFUSED here, on an observation, without
        needing its refusal to contain one of seven English substrings.

        Args:
            response_body: HTML/JSON body of the final response.
            status_code: HTTP status code of the final response.
            final_url: URL after all redirects. Deliberately not consulted for
                the verdict; carried for the caller's record.
            login_url: Original login URL.
            redirect_chain: Absolute destinations a redirect actually pointed
                to, in hop order. Empty when nothing redirected.
            session_evidence: Cookies the CREDENTIAL POST set — the delta across
                the POST boundary, never the cookies the exchange was already
                holding when it dispatched.
            carried_session: The cookies the exchange HOLDS. Only ever read to
                decide INDETERMINATE: it is what a promoted session would be
                carried by, and it is never on its own evidence that a
                credential worked.

        Returns:
            A :class:`LoginJudgement` — the verdict, and the observation behind
            it, phrased so a refusal names what was absent rather than asserting
            anything about the operator's password.
        """
        # A 4xx or 5xx is the server refusing. Nothing after this point can make
        # it a success, so nothing after this point gets to run.
        if status_code >= 400:
            return LoginJudgement(
                LoginVerdict.REFUSED,
                f"the credential POST was answered {status_code}, which is the server "
                f"refusing the request rather than issuing a session",
            )

        body_lower = (response_body or "").lower()
        control_lower = (control_body or "").lower()

        # 1. Session material — a cookie the CREDENTIAL POST set, or a token in
        #    its body. Not a cookie the login-page GET set: that one exists
        #    whatever we send, so it cannot distinguish a good credential from a
        #    bad one.
        #
        #    THIS RUNS FIRST, and the order is half the fix. The failure-keyword
        #    rule used to precede it, so a POST that came back carrying a
        #    brand-new session cookie was reported REFUSED because the page it
        #    landed on contained the word "invalid". An application that renders
        #    a validation hint, a password-policy blurb, or a "report an invalid
        #    listing" link anywhere on its post-login page therefore refused
        #    every good credential we offered it. Positive evidence about the
        #    session outranks a word.
        if session_evidence:
            return LoginJudgement(
                LoginVerdict.PROVEN,
                f"the credential POST set {', '.join(sorted(session_evidence))}",
            )
        if WebAuthenticator._extract_token(response_body or ""):
            return LoginJudgement(
                LoginVerdict.PROVEN,
                "the credential response body carried an authentication token",
            )

        # 2. A refusal marker THE CONTROL DOES NOT CARRY.
        #
        #    The control is the login-page GET: the same URL, fetched without
        #    credentials, which this flow already holds and previously compared
        #    against nothing. A marker present in a response the credential
        #    never touched is not evidence about the credential — invariants 27
        #    and 30, enforced on every dispatched marker oracle in the exploit
        #    path and with no equivalent here. Discards are NAMED in the
        #    evidence rather than dropped: "we saw the word and threw it away"
        #    is the sentence that lets an operator audit this rule.
        matched = ""
        discarded: list[str] = []
        for keyword in _LOGIN_FAILURE_MARKERS:
            if keyword not in body_lower:
                continue
            if control_lower and keyword in control_lower:
                discarded.append(keyword)
                continue
            matched = keyword
            break
        if matched:
            return LoginJudgement(
                LoginVerdict.REFUSED,
                f"the response body carries the refusal marker {matched!r}, which the "
                f"login page served without credentials does not",
            )

        # 3. A redirect that ACTUALLY occurred, to somewhere other than login.
        if redirect_chain and login_url:
            login_path = urlparse(login_url).path.rstrip("/")
            away = [r for r in redirect_chain if urlparse(r).path.rstrip("/") != login_path]
            if away:
                return LoginJudgement(
                    LoginVerdict.PROVEN,
                    f"the credential POST was answered with a redirect to {away[0]}, "
                    f"which is not the login page",
                )

        # An "authenticated-page marker" rule is deliberately absent. One of eight
        #   English nouns in a 2xx body — used to return PROVEN here. It fired
        #   four times in the whole recorded corpus, all four on a site with no
        #   login, and the shape it was there for is rule 4's job. See the
        #   docstring; the deletion is the fix, not a tightened keyword list,
        #   because every keyword list has the same defect and a longer one only
        #   moves which page furniture triggers it.

        # 4. The response IS the control. The POST did nothing.
        #
        #    Cheap, deterministic, and available on the run that made this
        #    necessary: the engine held the GET and the POST of the same URL,
        #    identical byte length, and compared nothing. A credential POST
        #    whose answer is the page we were already served changed no state
        #    this response can show — so there is no session, and equally there
        #    is nothing to defer WITH, which is why this runs ahead of rule 5.
        #    A framework that promotes its pre-login session in place still
        #    renders a DIFFERENT page once that session is authenticated; a
        #    byte-identical one is the login page again.
        if control_body and len(response_body or "") == len(control_body):
            same_bytes = (response_body or "") == control_body
            how = (
                "byte-identical to the login page served without credentials"
                if same_bytes
                else "the same length as the login page served without credentials"
            )
            also = (
                f" (refusal markers present in BOTH and discarded: "
                f"{', '.join(repr(d) for d in discarded)})"
                if discarded
                else ""
            )
            return LoginJudgement(
                LoginVerdict.REFUSED,
                f"the credential POST to {final_url or login_url} returned {status_code} and a "
                f"body of exactly {len(control_body)} bytes, {how}, so the POST changed "
                f"nothing this response can show{also}",
            )

        # 5. Nothing proved it. Is there anything to defer WITH?
        #
        # Only when the exchange is carrying session material from before the
        # credentials went out, and only when this response is not itself a
        # denial. Both halves are load-bearing: without the first there is
        # nothing an assertion could carry, and without the second every
        # re-served login page would become a deferral.
        if carried_session and WebAuthenticator._session_survived(status_code, response_body or ""):
            return LoginJudgement(
                LoginVerdict.INDETERMINATE,
                f"the credential POST returned {status_code}, set no cookie and returned "
                f"no token, and the exchange is carrying "
                f"{', '.join(sorted(carried_session))} from before the credentials were "
                f"sent. On an application that promotes its pre-login session in place "
                f"that cookie IS the session and this is what a SUCCESSFUL login looks "
                f"like, so the verdict is deferred to the authenticated-state assertion",
            )

        # No session material, no redirect, no marker, nothing carried. Say what
        # was absent. ``final_url`` differing from ``login_url`` is deliberately
        # not consulted — see the docstring.
        also = (
            f" (refusal markers present in the control too, and discarded: "
            f"{', '.join(repr(d) for d in discarded)})"
            if discarded
            else ""
        )
        return LoginJudgement(
            LoginVerdict.REFUSED,
            f"the credential POST to {final_url or login_url} returned {status_code}, set "
            f"no cookie, returned no token, was not redirected away from the login page, "
            f"and the exchange held no session material from before it — there is nothing "
            f"here that could be a session{also}",
        )

    @staticmethod
    def _negotiated_content_type(
        status_code: int,
        response_headers: dict[str, str] | None,
        response_body: str,
    ) -> str:
        """The media type a **415** response says it wanted, or ``""``.

        A 415 is the one status that carries a machine-readable instruction: the
        server has read the request, understood it, and refused it *for a reason
        it named*. Acting on that is the difference between "authentication
        failed" and "we sent the wrong encoding" — two diagnoses the engine
        previously could not tell apart, because it never asked.

        Three channels, protocol first: an ``Accept-Post`` header (RFC 7231's
        own answer to this exact question), an ``Accept`` header, then the JSON
        shapes an API uses to say the same thing. Prose is never parsed — a
        target controls this body, and a guard that reads text the target writes
        is a suppression primitive handed to the target.

        Returns:
            A content type from :data:`ENCODABLE_CONTENT_TYPES`, or ``""`` when
            the response named none we can produce.
        """
        if status_code != 415:
            return ""

        candidates: list[str] = []
        for key, value in (response_headers or {}).items():
            if key.lower() in ("accept-post", "accept-patch", "accept"):
                candidates.extend(part.strip() for part in (value or "").split(","))

        try:
            data = json.loads(response_body or "")
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, dict):
            for path in _CONTENT_TYPE_BODY_PATHS:
                cursor: Any = data
                for key in path:
                    if isinstance(cursor, dict) and key in cursor:
                        cursor = cursor[key]
                    else:
                        cursor = None
                        break
                if isinstance(cursor, str) and cursor.strip():
                    candidates.append(cursor)

        for candidate in candidates:
            media_type = candidate.split(";")[0].strip().lower()
            if media_type in ENCODABLE_CONTENT_TYPES:
                return media_type
        return ""

    @staticmethod
    def _encode_credential_body(
        fields: dict[str, str], content_type: str
    ) -> tuple[str, dict[str, str]]:
        """Encode *fields* as *content_type*, returning ``(body, headers)``.

        The field NAMES come from the login page's own HTML and the encoding
        from the server's own 415. Neither half is a guess, which is the whole
        reason this retry is allowed to exist.
        """
        if content_type == "application/json":
            return json.dumps(fields), {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        return (
            urlencode(fields),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )

    def _resolve_post_url(self, login_url: str, form_action: str) -> str:
        """Where the credential POST goes — scope-checked, because the TARGET chose it.

        ``validate_input`` checks ``login_url``. It cannot check this one: the
        form's ``action`` is an attribute of a page the target served, read after
        that check, and the POST that follows carries the engagement's plaintext
        credentials over aiohttp/curl directly rather than through the
        scope-enforcing HTTP client.

        A page serving ``<form action="https://attacker.tld/collect">`` therefore
        used to receive them. Scope is the control that exists for exactly this
        — "every tool validates targets against scope before any network
        activity" — and this seam was outside it.

        Relative actions resolve against the login URL's own origin and are in
        scope by construction; only an absolute action can leave it, and that is
        the one this refuses.

        Args:
            login_url: The login page, already scope-checked.
            form_action: The ``action`` attribute, exactly as served.

        Returns:
            The absolute URL to POST to.

        Raises:
            ValueError: The action points outside the engagement scope.
        """
        if not form_action:
            return login_url
        if form_action.startswith("http"):
            post_url = form_action
            # The only branch that can leave the origin, so the only one that
            # can leave the scope.
            self._check_scope(post_url)
            return post_url
        parsed = urlparse(login_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if form_action.startswith("/"):
            return f"{base}{form_action}"
        path = parsed.path.rsplit("/", 1)[0]
        return f"{base}{path}/{form_action}"

    def _classify_credential_redirect(
        self,
        status: int,
        headers: dict[str, str] | None,
        current_url: str,
    ) -> RedirectHop:
        """Decide the next hop of a credential exchange — scope-checked, deliberately.

        ``_resolve_post_url`` scope-checks where the credentials are FIRST sent,
        because the target's form ``action`` chose it. It cannot check where they
        are sent SECOND: a **307** answer preserves the method and the body, so a
        target — or anything that can shape one response, which is a strictly
        weaker position than controlling the form's HTML — moves the plaintext
        credentials to a destination no scope check has ever seen. Both credential
        POSTs dispatched with redirect-following on, so the transport did that
        move itself, silently, before any of this code ran.

        The rule itself is :func:`~clinkz.tools.redirect_walk.classify_redirect`,
        shared with every other exchange that must not follow blindly. This
        method is the seam that binds it to THIS tool's scope gate, so a refusal
        reaches the run's scope-refusal record attributed to the authenticator.

        Args:
            status: The status of the response in hand.
            headers: Its headers, for ``Location``.
            current_url: The URL that produced this response — the base a
                relative ``Location`` resolves against.

        Returns:
            The hop to take. See :class:`~clinkz.tools.redirect_walk.RedirectHop`.
        """
        return classify_redirect(status, headers, current_url, in_scope=self._check_scope)

    def _refused_redirect_result(
        self,
        *,
        login_url: str,
        username: str,
        post_url: str,
        status: int,
        final_url: str,
        refusal: RedirectHop,
        session_cookies: dict[str, str],
    ) -> str:
        """The ``execute()`` envelope for a request redirected off-scope.

        It ABORTS the attempt and says so. The distinction the message has to
        keep is the one invariant 88 is about: when a credential POST was
        dispatched, it **was** dispatched — to ``post_url``, an in-scope URL the
        target's own form chose — and it is only the redirect that was refused.
        Saying "no credential was offered" would be false about the first request
        and saying "the login failed" would be false about the second, so it says
        exactly which request went where.

        ``post_url`` empty is the other case, and it is a different sentence: the
        refusal came from the login-page GET, before any credential body existed,
        so nothing of ours was offered to anything. Reporting that as a refused
        credential POST would assert a dispatch that never happened.

        ``scope_refusal`` makes it terminal upstream: ``authenticate()`` stops
        instead of running the next arm, which would offer the same credentials
        to the same target and report whatever that arm found instead.
        """
        requested = post_url or final_url or login_url
        what = f"the credential POST to {post_url}" if post_url else f"GET {requested}"
        self._logger.error(
            "SCOPE REFUSAL: %s was answered %d redirecting to %s, outside the "
            "engagement scope. Not following it.",
            what,
            status,
            refusal.url,
        )
        return json.dumps(
            {
                "success": False,
                "session_cookies": session_cookies,
                "redirect_url": final_url,
                "login_url": login_url,
                "username": username,
                "status_code": status,
                "posted_to": post_url,
                "scope_refusal": refusal.url,
                "error": (
                    f"{what} redirected to {refusal.url}, which is outside the engagement scope"
                ),
                "failure_stage": f"{what} {refusal.reason}",
            }
        )

    @staticmethod
    def _parse_curl_exchange(
        raw_response: str,
    ) -> tuple[int, str, dict[str, str], list[str]]:
        """Split one curl dump into the status, body, headers and cookies that ANSWERED.

        Curl with ``-D -`` writes every response's headers to stdout ahead of
        the body, so a dump can hold several ``HTTP/x.y NNN`` blocks
        concatenated — a fixture captured under ``-L``, or the per-hop dumps this
        authenticator joins. The LAST block is the response that actually
        answered.

        The headers matter as much as the status: a 415 states the media type it
        wanted in ``Accept-Post``, and reading it out of the right block is what
        makes :meth:`_negotiated_content_type` an observation rather than a
        guess.

        ``Set-Cookie`` comes back SEPARATELY, as a list. It is the one header a
        response routinely sends more than once, so the header dict cannot hold
        it — and scanning the raw dump for ``set-cookie:`` lines, which is what
        this authenticator used to do, reads the response BODY as well as its
        headers. A page that renders the text ``Set-Cookie: admin=1`` would then
        have set a cookie, which is a target writing into our session state.
        Only the header section of the block that answered is read here.

        This deliberately does NOT return a redirect chain. It used to hand back
        every ``Location`` header in the dump, raw and unresolved, and that list
        was the curl arm's ``redirect_chain`` — a second meaning for a field the
        aiohttp arm filled with the URLs that ANSWERED. The chain now comes from
        :func:`~clinkz.tools.redirect_walk.walk_redirects`, which is the only
        thing that knows where a hop was actually dispatched.

        Args:
            raw_response: Curl's stdout — headers and body, possibly several
                blocks.

        Returns:
            ``(status, body, headers, set_cookies)`` of the final block.
        """
        blocks = [
            b
            for b in re.split(r"(?=^HTTP/[\d.]+ \d+)", raw_response, flags=re.MULTILINE)
            if b.strip()
        ]
        if not blocks:
            return 0, "", {}, []

        last_block = blocks[-1]
        parts = re.split(r"\r?\n\r?\n", last_block, maxsplit=1)
        head = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        status = 0
        status_match = re.match(r"HTTP/[\d.]+ (\d+)", head)
        if status_match:
            status = int(status_match.group(1))

        headers: dict[str, str] = {}
        set_cookies: list[str] = []
        for line in head.splitlines()[1:]:
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            name, value = name.strip(), value.strip()
            if name.lower() == "set-cookie":
                set_cookies.append(value)
            headers[name] = value

        return status, body, headers, set_cookies

    @staticmethod
    def _read_cookie_jar(jar_path: str) -> dict[str, str]:
        """Read a Netscape-format cookie jar into a dict."""
        import os

        cookies: dict[str, str] = {}
        if not os.path.isfile(jar_path):
            return cookies
        try:
            with open(jar_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 7:
                        cookies[parts[5]] = parts[6]
        except OSError:
            pass
        return cookies
