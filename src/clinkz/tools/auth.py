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
proven session. See :meth:`WebAuthenticator._check_login_success`.

The 415 is not merely refused, it is USED. A server answering
``415 Unsupported Media Type`` has stated the encoding it wants, so the same
credentials are re-POSTed to the same action under the content type the
response itself names (:func:`_negotiated_content_type`). The field names come
from the form's own HTML and the encoding from the server's own answer; neither
is guessed.

When TOOL_EXEC_MODE=docker, requests to Docker-internal IPs are executed
via ``curl`` inside the container (same pattern as HTTPClientTool).
Otherwise uses aiohttp on the host.
"""

from __future__ import annotations

import json
import logging
import re
from html.parser import HTMLParser
from typing import Any, NamedTuple
from urllib.parse import urlencode, urlparse

from pydantic import BaseModel

from clinkz.tools.base import ToolBase, ToolOutput

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
    """

    arms: tuple[str, ...]
    reason: str


# ---------------------------------------------------------------------------
# HTML form parser — extracts hidden fields, username/password field names
# ---------------------------------------------------------------------------


class _FormFieldParser(HTMLParser):
    """Extract form fields from HTML login pages.

    Finds:
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
    """

    def __init__(self) -> None:
        super().__init__()
        self.hidden_fields: dict[str, str] = {}
        self.submit_fields: dict[str, str] = {}
        self.username_field: str = ""
        self.password_field: str = ""
        self.form_action: str = ""
        self.form_enctype: str = ""
        self._in_form: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict: dict[str, str] = {k: (v or "") for k, v in attrs}

        if tag == "form":
            self._in_form = True
            method = attr_dict.get("method", "").upper()
            if method == "POST" or not self.form_action:
                self.form_action = attr_dict.get("action", "")
                self.form_enctype = attr_dict.get("enctype", "").split(";")[0].strip().lower()

        if tag != "input":
            return

        input_type = attr_dict.get("type", "text").lower()
        input_name = attr_dict.get("name", "")
        input_value = attr_dict.get("value", "")

        if input_type == "hidden" and input_name:
            self.hidden_fields[input_name] = input_value

        elif input_type == "submit" and input_name:
            self.submit_fields[input_name] = input_value

        elif input_type == "password" and input_name:
            self.password_field = input_name

        elif input_type in ("text", "email") and input_name:
            name_lower = input_name.lower()
            if any(hint in name_lower for hint in ("user", "login", "email", "name", "account")):
                self.username_field = input_name

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False


def _parse_form_fields(html: str) -> _FormFieldParser:
    """Parse HTML and return extracted form field data."""
    parser = _FormFieldParser()
    parser.feed(html)
    return parser


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

        The login flow is its own HTTP path (curl/aiohttp directly, not via
        :class:`~clinkz.tools.http_client.HTTPClientTool`), so it takes its own
        governor slot. It never nests with the HTTP chokepoint: the JSON/API
        fallback runs *after* this method returns.

        A login is state-changing enough to belong in the action log — an
        operator asking "what did it do to my app?" should see every
        authentication attempt — and it must be paced like everything else, so
        repeated default-credential attempts cannot become an unintended
        brute-force burst against a production login.
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is not None:
            decision = await governor.authorize(
                "POST",
                args["login_url"],
                stage="auth",
                field_names=["username", "password"],
            )
            if not decision.allowed:
                return json.dumps(
                    {
                        "success": False,
                        "session_cookies": {},
                        "redirect_url": "",
                        "login_url": args["login_url"],
                        "username": args.get("username", ""),
                        "status_code": 0,
                        "error": (
                            f"refused by safety policy [{decision.category}]: {decision.reason}"
                        ),
                    }
                )
            try:
                return await self._dispatch(args)
            finally:
                governor.release()
        return await self._dispatch(args)

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

        for arm in order.arms:
            if arm == "form":
                form_result = await self._run_form_arm(
                    login_url,
                    username,
                    password,
                    identity_field=identity_field,
                    content_type=content_type,
                )
                if form_result.success:
                    return self._require_session_material(form_result)
                self._logger.info("Cookie/form auth did not establish a session for %s", login_url)
            else:
                api_result = await self._try_api_login(
                    login_url,
                    username,
                    password,
                    api_login_url=api_login_url,
                    identity_field=identity_field,
                )
                if api_result.success:
                    return self._require_session_material(api_result)

        # Both arms failed. Surface the form arm's failure when there is one —
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
        if served == "application/json":
            return _EncodingOrder(("json", "form"), f"the login URL serves {served}")

        enctype = _parse_form_fields(parsed.response_body or "").form_enctype
        if enctype == "application/json":
            return _EncodingOrder(("json", "form"), f'the form declares enctype="{enctype}"')

        return _EncodingOrder(("form", "json"), "no observation favours JSON first")

    async def _try_api_login(
        self,
        login_url: str,
        username: str,
        password: str,
        *,
        api_login_url: str = "",
        identity_field: str = "",
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

        **A session cookie is a session.** Success used to require a token, so
        an API that answers a JSON login with ``Set-Cookie`` and no token in the
        body — a common shape, and the one a same-site SPA uses — authenticated
        successfully and was recorded as a failure.

        Args:
            login_url: The login URL as known; tried directly, and its origin
                used to resolve the conventional routes.
            username: Username, email or account identifier.
            password: Password credential.
            api_login_url: Operator-declared JSON login route. Overrides
                discovery; tried first.
            identity_field: Operator-declared identity field name. Overrides the
                conventional shapes; tried first.

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
        for url in routes:
            for body in bodies:
                try:
                    status, resp_body, resp_headers = await self._api_post_json(url, body)
                except Exception as exc:
                    self._logger.debug("API login POST %s failed: %s", url, exc)
                    continue
                last_status = status or last_status
                attempted.append(f"POST {url} {sorted(body)} -> {status or 'error'}")
                if status < 200 or status >= 300:
                    continue
                token = self._extract_token(resp_body)
                cookies = self._parse_set_cookie_header(resp_headers)
                if not token and not cookies:
                    continue
                self._logger.info(
                    "JSON/API auth succeeded via %s (%s)",
                    url,
                    "token" if token else "session cookie",
                )
                return AuthResult(
                    success=True,
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

        return AuthResult(
            success=False,
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

    @staticmethod
    def _parse_set_cookie_header(headers: dict[str, str] | None) -> dict[str, str]:
        """Cookies named by ``Set-Cookie`` on a single response.

        A JSON login that answers with a cookie and no token is authenticating
        by cookie, and this is where that session is picked up. Attributes
        (``Path``, ``HttpOnly``, ``SameSite``) are dropped; only the leading
        ``name=value`` pair is a session.
        """
        cookies: dict[str, str] = {}
        for key, value in (headers or {}).items():
            if key.lower() != "set-cookie":
                continue
            for chunk in (value or "").split("\n"):
                pair = chunk.split(";", 1)[0].strip()
                name, sep, val = pair.partition("=")
                if sep and name.strip():
                    cookies[name.strip()] = val.strip()
        return cookies

    async def _api_post_json(
        self, url: str, payload: dict[str, str]
    ) -> tuple[int, str, dict[str, str]]:
        """POST ``payload`` as JSON to ``url``, returning ``(status, body, headers)``.

        Reuses :class:`HTTPClientTool` so the request honours the same
        docker/host execution routing, per-engagement cookie jar, and scope
        enforcement as every other HTTP call in the engagement.

        The headers come back because ``Set-Cookie`` is on them, and a JSON
        login whose session is a cookie is invisible without it.
        """
        from clinkz.tools.http_client import HTTPClientTool

        http = HTTPClientTool(scope=self.scope, engagement_id=self._engagement_id)
        args = http.validate_input(
            {
                "method": "POST",
                "url": url,
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                "body": json.dumps(payload),
                "follow_redirects": True,
            }
        )
        raw = await http.execute(args)
        parsed = http.parse_output(raw)
        return parsed.status_code, parsed.response_body, parsed.response_headers or {}

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

        Args:
            url: URL of a protected page (e.g., the app's main page).
            cookies: Session cookies to test.

        Returns:
            True if the session is still valid (no redirect to login).
        """
        from clinkz.config import settings

        try:
            if settings.tool_exec_mode == "docker":
                return await self._verify_session_curl(url, cookies)
            return await self._verify_session_aiohttp(url, cookies)
        except Exception as exc:
            self._logger.warning("Session verification failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # aiohttp implementation (host mode)
    # ------------------------------------------------------------------

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
                    # Step 1: GET the login page
                    async with session.get(login_url, ssl=False) as get_resp:
                        login_html = await get_resp.text(errors="replace")
                        get_status = get_resp.status
                        get_cookies = {c.key: c.value for c in session.cookie_jar}

                    self._logger.info(
                        "GET %s → %d (%d bytes), cookies received: %s",
                        login_url,
                        get_status,
                        len(login_html),
                        list(get_cookies.keys()),
                    )

                    # Step 2: Parse form fields from HTML
                    form = _parse_form_fields(login_html)

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
                    post_url = self._resolve_post_url(login_url, form.form_action)

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

                    async def _post(ctype: str) -> tuple[int, str, str, list[str], dict[str, str]]:
                        body, extra = self._encode_credential_body(post_data, ctype)
                        async with session.post(
                            post_url,
                            data=body,
                            headers=extra,
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            return (
                                resp.status,
                                await resp.text(errors="replace"),
                                str(resp.url),
                                [str(r.url) for r in resp.history] if resp.history else [],
                                dict(resp.headers),
                            )

                    (
                        post_status,
                        post_body,
                        final_url,
                        redirect_chain,
                        post_headers,
                    ) = await _post(content_type)

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
                        ) = await _post(wanted)
                    elif post_status == 415:
                        self._logger.warning(
                            "POST %s -> 415 and the response named no media type this "
                            "authenticator can encode — not retrying",
                            post_url,
                        )

                    # Step 5: Extract all session cookies
                    session_cookies: dict[str, str] = {}
                    for cookie in session.cookie_jar:
                        session_cookies[cookie.key] = cookie.value

                    self._logger.info(
                        "POST response — status: %d, final_url: %s, "
                        "redirect_chain: %s, session_cookies: %s, "
                        "response_length: %d",
                        post_status,
                        final_url,
                        redirect_chain,
                        list(session_cookies.keys()),
                        len(post_body),
                    )

                    # Step 6: Does POSITIVE evidence say a session exists?
                    success = self._check_login_success(
                        post_body,
                        post_status,
                        final_url,
                        login_url,
                        redirect_chain,
                        session_cookies,
                    )

                    self._logger.info(
                        "Auth attempt %d result: success=%s",
                        attempt,
                        success,
                    )

                    last_result = json.dumps(
                        {
                            "success": success,
                            "session_cookies": session_cookies,
                            "redirect_url": final_url,
                            "login_url": login_url,
                            "username": username,
                            "status_code": post_status,
                            "posted_to": post_url,
                            "negotiated_content_type": negotiated,
                            "failure_stage": (
                                ""
                                if success
                                else f"credential POST to {post_url} returned {post_status} "
                                "with no session material"
                            ),
                        }
                    )

                    if success:
                        return last_result

                    # If first attempt failed, retry with fresh session/CSRF
                    if attempt < max_attempts:
                        self._logger.warning(
                            "Auth attempt %d failed — retrying with fresh GET for new CSRF token",
                            attempt,
                        )
                        continue

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

    async def _verify_session_aiohttp(self, url: str, cookies: dict[str, str]) -> bool:
        """Check session validity via aiohttp GET."""
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as session:
            async with session.get(url, ssl=False, allow_redirects=False, cookies=cookies) as resp:
                # If we get redirected to login page, session is dead
                if resp.status in (301, 302, 303, 307):
                    location = resp.headers.get("Location", "").lower()
                    if any(hint in location for hint in ("login", "signin", "auth")):
                        return False
                # If we get 401/403, session is dead
                if resp.status in (401, 403):
                    return False
                # If we get 200 with the page content, session is alive
                body = await resp.text(errors="replace")
                body_lower = body.lower()
                if "login" in body_lower and "form" in body_lower and "password" in body_lower:
                    # Looks like we got served the login page
                    return False
                return True

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

        # /tmp here is inside the clinkz-tools Docker container — predictable
        # by design so subsequent curl calls find the same jar; UUID prefix
        # keeps engagements isolated, and the container is single-tenant.
        cookie_jar = (
            f"/tmp/clinkz_{self._engagement_id}_cookies.txt"  # nosec B108
            if self._engagement_id
            else "/tmp/clinkz_auth_cookies.txt"  # nosec B108
        )

        try:
            # Step 1: GET the login page, save cookies
            get_cmd = [
                "curl",
                "-s",
                "-S",
                "-D",
                "-",
                "-c",
                cookie_jar,
                login_url,
            ]
            get_stdout, get_stderr, get_rc = await self._run_subprocess(get_cmd)

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

            # Extract body from GET response (skip headers)
            header_body_split = re.split(r"\r?\n\r?\n", get_stdout, maxsplit=1)
            login_html = header_body_split[1] if len(header_body_split) > 1 else get_stdout

            # Step 2: Parse form fields
            form = _parse_form_fields(login_html)
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
            post_url = self._resolve_post_url(login_url, form.form_action)

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

            async def _post(ctype: str) -> str:
                body, extra = self._encode_credential_body(post_fields, ctype)
                cmd = ["curl", "-s", "-S", "-D", "-", "-X", "POST", "-L"]
                for header, value in extra.items():
                    cmd += ["-H", f"{header}: {value}"]
                cmd += ["-d", body, "-b", cookie_jar, "-c", cookie_jar, post_url]
                stdout, _stderr, _rc = await self._run_subprocess(cmd)
                return stdout

            post_stdout = await _post(content_type)
            (
                post_status,
                post_response_body,
                post_headers,
                location_matches,
            ) = self._parse_curl_exchange(post_stdout)

            wanted = self._negotiated_content_type(post_status, post_headers, post_response_body)
            if wanted and wanted != content_type:
                self._logger.info(
                    "POST %s -> 415; the response names %s — retrying under it",
                    post_url,
                    wanted,
                )
                negotiated = wanted
                retry_stdout = await _post(wanted)
                (
                    post_status,
                    post_response_body,
                    post_headers,
                    location_matches,
                ) = self._parse_curl_exchange(retry_stdout)
                post_stdout = post_stdout + retry_stdout
            elif post_status == 415:
                self._logger.warning(
                    "POST %s -> 415 and the response named no media type this "
                    "authenticator can encode — not retrying",
                    post_url,
                )

            final_url = location_matches[-1].strip() if location_matches else post_url

            # Collect session cookies. Prefer parsing Set-Cookie headers from
            # the GET+POST responses — curl writes the jar inside the
            # clinkz-tools container in docker mode, so reading from a host
            # path here returns nothing. The Set-Cookie path is the only one
            # that works in both docker and local modes.
            session_cookies: dict[str, str] = {}
            session_cookies.update(self._parse_set_cookies(get_stdout))
            session_cookies.update(self._parse_set_cookies(post_stdout))
            if not session_cookies:
                from clinkz.tools.http_client import get_session_cookies

                eid = self._engagement_id or "auth"
                jar_cookies = get_session_cookies(eid) if self._engagement_id else {}
                if not jar_cookies:
                    jar_cookies = self._read_cookie_jar(cookie_jar)
                session_cookies = jar_cookies

            redirect_chain = location_matches

            success = self._check_login_success(
                post_response_body,
                post_status,
                final_url,
                login_url,
                redirect_chain,
                session_cookies,
            )

            return json.dumps(
                {
                    "success": success,
                    "session_cookies": session_cookies,
                    "redirect_url": final_url,
                    "login_url": login_url,
                    "username": username,
                    "status_code": post_status,
                    "posted_to": post_url,
                    "negotiated_content_type": negotiated,
                    "failure_stage": (
                        ""
                        if success
                        else f"credential POST to {post_url} returned {post_status} "
                        "with no session material"
                    ),
                }
            )

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

    async def _verify_session_curl(self, url: str, cookies: dict[str, str]) -> bool:
        """Check session validity via curl GET (no follow redirects)."""
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        cmd = [
            "curl",
            "-s",
            "-S",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{redirect_url}",
            "-b",
            cookie_str,
            url,
        ]
        stdout, _, rc = await self._run_subprocess(cmd)
        parts = stdout.strip().split()
        if not parts:
            return False
        status = int(parts[0]) if parts[0].isdigit() else 0
        redirect = parts[1] if len(parts) > 1 else ""

        if status in (401, 403):
            return False
        if status in (301, 302, 303, 307):
            if any(hint in redirect.lower() for hint in ("login", "signin", "auth")):
                return False
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_login_success(
        response_body: str,
        status_code: int,
        final_url: str,
        login_url: str,
        redirect_chain: list[str],
        session_cookies: dict[str, str] | None = None,
    ) -> bool:
        """Whether POSITIVE evidence says a session was established.

        Success is not the absence of a failure keyword. It requires one of:

        1. **Session material** — cookies the exchange set, or a token in the
           body. This is the thing a session IS.
        2. **A redirect that actually occurred** — ``redirect_chain`` non-empty,
           landing somewhere other than the login page. An application that
           answers a good credential with "go to your dashboard" said so in a
           ``Location`` header, and the chain is where that is recorded.
        3. **An authenticated-page marker** in the body, on a 2xx.

        Two rules bound it, and both were written by a live failure:

        **A 4xx is never success.** The old rule reached "logged in" on a
        **415**, and 415 is the server stating what it wanted — the clearest
        possible answer that nothing was accepted. Anything at or above 400
        returns ``False`` before any other test runs.

        **A different final path is not a redirect.** The old rule compared
        ``final_url``'s path with ``login_url``'s and called a difference
        "redirected away → success". A form whose ``action`` points at another
        path satisfies that with no redirect having happened at all, which is
        exactly the shape of a JSON login API behind an HTML form. The redirect
        test now reads ``redirect_chain``, which is empty unless a redirect
        genuinely occurred.

        Args:
            response_body: HTML/JSON body of the final response.
            status_code: HTTP status code of the final response.
            final_url: URL after all redirects.
            login_url: Original login URL.
            redirect_chain: URLs a redirect actually travelled through.
            session_cookies: Cookies the exchange set, if any.

        Returns:
            ``True`` only on positive evidence of a session.
        """
        # A 4xx or 5xx is the server refusing. Nothing after this point can
        # make it a success, so nothing after this point gets to run.
        if status_code >= 400:
            return False

        body_lower = (response_body or "").lower()

        failure_keywords = [
            "invalid",
            "incorrect",
            "wrong password",
            "login failed",
            "authentication failed",
            "bad credentials",
            "access denied",
        ]
        if any(kw in body_lower for kw in failure_keywords):
            return False

        # 1. Session material — a cookie the exchange set, or a token in the body.
        if session_cookies:
            return True
        if WebAuthenticator._extract_token(response_body or ""):
            return True

        # 2. A redirect that ACTUALLY occurred, to somewhere other than login.
        if redirect_chain and login_url:
            login_path = urlparse(login_url).path.rstrip("/")
            if any(urlparse(r).path.rstrip("/") != login_path for r in redirect_chain):
                return True

        # 3. An authenticated-page marker on a 2xx. Last, not first: a login
        #    page carrying the word "profile" in its footer is a page anyone can
        #    read, and the two tests above are about the session itself.
        if 200 <= status_code < 300:
            success_keywords = [
                "logout",
                "sign out",
                "signout",
                "log out",
                "dashboard",
                "welcome",
                "my account",
                "profile",
            ]
            if any(kw in body_lower for kw in success_keywords):
                return True

        # No session material, no redirect, no marker. ``final_url`` differing
        # from ``login_url`` is deliberately not consulted — see the docstring.
        return False

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

    @staticmethod
    def _parse_curl_exchange(
        raw_response: str,
    ) -> tuple[int, str, dict[str, str], list[str]]:
        """Split one ``curl -D - -L`` dump into its final status, body, headers, chain.

        Curl with ``-D -`` writes every response's headers to stdout ahead of
        the body, so a followed redirect leaves several ``HTTP/x.y NNN`` blocks
        concatenated. The LAST block is the response that actually answered;
        the ``Location`` headers across all of them are the chain that got
        there.

        The headers matter as much as the status now: a 415 states the media
        type it wanted in ``Accept-Post``, and reading it out of the right
        block is what makes :meth:`_negotiated_content_type` an observation
        rather than a guess.

        Args:
            raw_response: Curl's stdout — headers and body, possibly several
                blocks.

        Returns:
            ``(status, body, headers_of_the_final_block, location_chain)``.
        """
        locations = [
            m.strip()
            for m in re.findall(r"^Location:\s*(.+)$", raw_response, re.IGNORECASE | re.MULTILINE)
        ]

        blocks = [
            b
            for b in re.split(r"(?=^HTTP/[\d.]+ \d+)", raw_response, flags=re.MULTILINE)
            if b.strip()
        ]
        if not blocks:
            return 0, "", {}, locations

        last_block = blocks[-1]
        parts = re.split(r"\r?\n\r?\n", last_block, maxsplit=1)
        head = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        status = 0
        status_match = re.match(r"HTTP/[\d.]+ (\d+)", head)
        if status_match:
            status = int(status_match.group(1))

        headers: dict[str, str] = {}
        for line in head.splitlines()[1:]:
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()

        return status, body, headers, locations

    @staticmethod
    def _parse_set_cookies(raw_response: str) -> dict[str, str]:
        """Extract cookies from ``Set-Cookie`` headers in a raw HTTP response dump.

        Curl's ``-D -`` flag dumps headers (including ``Set-Cookie``) to
        stdout alongside the body, separated by a blank line. We pull every
        ``Set-Cookie`` line and parse out the leading ``name=value`` pair,
        ignoring attributes (``Path``, ``HttpOnly``, ``Domain``, ...).

        Args:
            raw_response: The full curl stdout dump (headers + body, possibly
                across multiple HTTP blocks from redirect chains).

        Returns:
            Dict mapping cookie name → cookie value. Empty if none found.
        """
        cookies: dict[str, str] = {}
        for line in raw_response.splitlines():
            if not line.lower().startswith("set-cookie:"):
                continue
            value = line.split(":", 1)[1].strip()
            pair = value.split(";", 1)[0].strip()
            if "=" not in pair:
                continue
            name, _, val = pair.partition("=")
            name = name.strip()
            if name:
                cookies[name] = val.strip()
        return cookies

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
