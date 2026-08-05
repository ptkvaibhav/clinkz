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

When TOOL_EXEC_MODE=docker, requests to Docker-internal IPs are executed
via ``curl`` inside the container (same pattern as HTTPClientTool).
Otherwise uses aiohttp on the host.
"""

from __future__ import annotations

import json
import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

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


class AuthOutput(ToolOutput):
    """Structured output from the WebAuthenticator."""

    auth_result: AuthResult = AuthResult()


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
    """

    def __init__(self) -> None:
        super().__init__()
        self.hidden_fields: dict[str, str] = {}
        self.submit_fields: dict[str, str] = {}
        self.username_field: str = ""
        self.password_field: str = ""
        self.form_action: str = ""
        self._in_form: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict: dict[str, str] = {k: (v or "") for k, v in attrs}

        if tag == "form":
            self._in_form = True
            method = attr_dict.get("method", "").upper()
            if method == "POST" or not self.form_action:
                self.form_action = attr_dict.get("action", "")

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
    ) -> AuthResult:
        """Perform a full login and return structured AuthResult.

        This is the primary API for other components. Handles validation,
        execution, and parsing in one call. Two auth shapes are attempted:

        1. **Cookie/form auth** (``execute()``) — the CSRF-aware GET→POST flow.
           DVWA and other form-based apps succeed here; behaviour unchanged.
        2. **JSON/API auth** (``_try_api_login()``) — only when (1) fails: POST
           the credentials as JSON to common API login routes and read a token
           from the response (Juice Shop and other SPA/JSON APIs).

        Args:
            login_url: URL of the login page.
            username: Username (or email) credential.
            password: Password credential.

        Returns:
            AuthResult — on success, carries ``session_cookies`` (cookie/form
            auth) or ``bearer_token`` (JSON/API auth).
        """
        try:
            validated = self.validate_input(
                {
                    "login_url": login_url,
                    "username": username,
                    "password": password,
                }
            )
            raw = await self.execute(validated)
            form_result = self.parse_output(raw).auth_result
        except Exception as exc:
            self._logger.error("authenticate() form flow failed: %s", exc, exc_info=True)
            return AuthResult(
                success=False,
                login_url=login_url,
                username=username,
                error=str(exc),
            )

        if form_result.success:
            return form_result

        # Form/cookie auth produced no session — try JSON/API auth (SPA targets
        # like Juice Shop have no HTML form and return a token in a JSON body).
        self._logger.info(
            "Cookie/form auth did not establish a session for %s — trying JSON/API auth",
            login_url,
        )
        api_result = await self._try_api_login(login_url, username, password)
        if api_result.success:
            return api_result

        # Both paths failed — surface the original form-auth failure (richer
        # context: status, redirect, etc.).
        return form_result

    async def _try_api_login(
        self,
        login_url: str,
        username: str,
        password: str,
    ) -> AuthResult:
        """Attempt JSON/API authentication against the target's own origin.

        POSTs the credentials as JSON to each route in ``_API_LOGIN_ROUTES``
        (resolved against the origin of ``login_url``) and returns the first
        response that yields an auth token. Both ``{email, password}`` and
        ``{username, password}`` body shapes are tried per route, since APIs
        differ on the identifier key.

        Args:
            login_url: Any URL on the target — only its scheme/host/port is used.
            username: Username or email credential.
            password: Password credential.

        Returns:
            AuthResult with ``bearer_token`` set on success, else a failure.
        """
        parsed = urlparse(login_url)
        if not parsed.scheme or not parsed.netloc:
            return AuthResult(
                success=False,
                login_url=login_url,
                username=username,
                error=f"Cannot derive origin from login URL: {login_url}",
            )
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Body shapes: email-keyed first (most JSON APIs, incl. Juice Shop),
        # then username-keyed when the identifier is not already an email.
        bodies: list[dict[str, str]] = [{"email": username, "password": password}]
        if "@" not in username:
            bodies.append({"username": username, "password": password})

        last_status = 0
        for route in _API_LOGIN_ROUTES:
            url = f"{base}{route}"
            for body in bodies:
                try:
                    status, resp_body = await self._api_post_json(url, body)
                except Exception as exc:
                    self._logger.debug("API login POST %s failed: %s", url, exc)
                    continue
                last_status = status or last_status
                if status < 200 or status >= 300:
                    continue
                token = self._extract_token(resp_body)
                if token:
                    self._logger.info("JSON/API auth succeeded via %s", url)
                    return AuthResult(
                        success=True,
                        bearer_token=token,
                        redirect_url=url,
                        login_url=url,
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
            error="No API login route returned an auth token",
        )

    async def _api_post_json(self, url: str, payload: dict[str, str]) -> tuple[int, str]:
        """POST ``payload`` as JSON to ``url`` and return ``(status, body)``.

        Reuses :class:`HTTPClientTool` so the request honours the same
        docker/host execution routing, per-engagement cookie jar, and scope
        enforcement as every other HTTP call in the engagement.
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
        return parsed.status_code, parsed.response_body

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

                    # Resolve form action URL
                    post_url = login_url
                    if form.form_action:
                        if form.form_action.startswith("http"):
                            post_url = form.form_action
                        else:
                            parsed = urlparse(login_url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            if form.form_action.startswith("/"):
                                post_url = f"{base}{form.form_action}"
                            else:
                                path = parsed.path.rsplit("/", 1)[0]
                                post_url = f"{base}{path}/{form.form_action}"

                    self._logger.info(
                        "POST %s with %d fields (hidden: %d, creds: 2)",
                        post_url,
                        len(post_data),
                        len(form.hidden_fields),
                    )

                    # Step 4: POST with cookies from step 1 (aiohttp session handles this)
                    async with session.post(
                        post_url,
                        data=post_data,
                        ssl=False,
                        allow_redirects=True,
                    ) as post_resp:
                        post_body = await post_resp.text(errors="replace")
                        post_status = post_resp.status
                        final_url = str(post_resp.url)

                        # Collect redirect chain
                        redirect_chain = (
                            [str(r.url) for r in post_resp.history] if post_resp.history else []
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

                    # Step 6: Check success heuristics
                    success = self._check_login_success(
                        post_body, post_status, final_url, login_url, redirect_chain
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
                    }
                )

            # Extract body from GET response (skip headers)
            header_body_split = re.split(r"\r?\n\r?\n", get_stdout, maxsplit=1)
            login_html = header_body_split[1] if len(header_body_split) > 1 else get_stdout

            # Step 2: Parse form fields
            form = _parse_form_fields(login_html)
            ufield = username_field_override or form.username_field or "username"
            pfield = password_field_override or form.password_field or "password"

            # Step 3: Build POST data
            post_parts: list[str] = []
            for k, v in form.hidden_fields.items():
                post_parts.append(f"{k}={v}")
            for k, v in form.submit_fields.items():
                post_parts.append(f"{k}={v}")
            post_parts.append(f"{ufield}={username}")
            post_parts.append(f"{pfield}={password}")
            post_body = "&".join(post_parts)

            # Resolve form action
            post_url = login_url
            if form.form_action:
                if form.form_action.startswith("http"):
                    post_url = form.form_action
                else:
                    parsed = urlparse(login_url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    if form.form_action.startswith("/"):
                        post_url = f"{base}{form.form_action}"
                    else:
                        path = parsed.path.rsplit("/", 1)[0]
                        post_url = f"{base}{path}/{form.form_action}"

            # Step 4: POST with cookies from GET
            post_cmd = [
                "curl",
                "-s",
                "-S",
                "-D",
                "-",
                "-X",
                "POST",
                "-L",  # follow redirects
                "-H",
                "Content-Type: application/x-www-form-urlencoded",
                "-d",
                post_body,
                "-b",
                cookie_jar,
                "-c",
                cookie_jar,
                post_url,
            ]
            post_stdout, post_stderr, post_rc = await self._run_subprocess(post_cmd)

            # Parse status code from response
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", post_stdout)
            post_status = int(status_match.group(1)) if status_match else 0

            # Find the final URL from redirect chain (last Location header)
            final_url = post_url
            location_matches = re.findall(
                r"^Location:\s*(.+)$", post_stdout, re.IGNORECASE | re.MULTILINE
            )
            if location_matches:
                final_url = location_matches[-1].strip()

            # Extract body from the last HTTP block
            blocks = re.split(r"(?=^HTTP/[\d.]+ \d+)", post_stdout, flags=re.MULTILINE)
            blocks = [b for b in blocks if b.strip()]
            if blocks:
                last_block = blocks[-1]
                parts = re.split(r"\r?\n\r?\n", last_block, maxsplit=1)
                post_response_body = parts[1] if len(parts) > 1 else ""
                # Get final status from last block
                sm = re.match(r"HTTP/[\d.]+ (\d+)", last_block)
                if sm:
                    post_status = int(sm.group(1))
            else:
                post_response_body = ""

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
                post_response_body, post_status, final_url, login_url, redirect_chain
            )

            return json.dumps(
                {
                    "success": success,
                    "session_cookies": session_cookies,
                    "redirect_url": final_url,
                    "login_url": login_url,
                    "username": username,
                    "status_code": post_status,
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
    ) -> bool:
        """Determine if a login attempt succeeded.

        Heuristics:
        1. Response body contains "logout" / "sign out" / "dashboard" → success
        2. Final URL is different from login URL (redirected away) → success
        3. Response body contains "invalid" / "incorrect" / "failed" → failure
        4. Status 200 with none of the failure keywords → tentative success

        Args:
            response_body: HTML body of the final response.
            status_code: HTTP status code.
            final_url: URL after all redirects.
            login_url: Original login URL.
            redirect_chain: List of redirect URLs.

        Returns:
            True if login appears successful.
        """
        body_lower = response_body.lower()

        # Clear failure indicators
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

        # Clear success indicators
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

        # Redirected away from login page → likely success
        if final_url and login_url:
            login_path = urlparse(login_url).path.rstrip("/")
            final_path = urlparse(final_url).path.rstrip("/")
            if login_path and final_path and final_path != login_path:
                return True

        # 302/303 redirect happened away from login → likely success
        if redirect_chain and login_url:
            login_path = urlparse(login_url).path.rstrip("/")
            # Only count as success if at least one redirect goes somewhere other than login
            if any(urlparse(r).path.rstrip("/") != login_path for r in redirect_chain):
                return True

        # Status 200 without any positive or negative signals is ambiguous —
        # do NOT treat it as success (prevents false positives on root-URL
        # fallbacks where POSTing to a non-login page always returns 200).
        return False

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
