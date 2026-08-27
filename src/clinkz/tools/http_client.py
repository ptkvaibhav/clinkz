"""HTTP Client tool — lets agents send arbitrary HTTP requests.

Enables manual exploitation workflows: crafting POST requests with
credentials, injecting payloads into parameters, testing authentication, etc.

When TOOL_EXEC_MODE=docker, executes curl inside the Docker container so that
requests originate from the container network. Otherwise uses aiohttp on the host.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlparse

from clinkz.tools.base import ToolBase, ToolOutput

#: The shared engagement cookie jar is read and written. The default, and what
#: every ordinary methodology probe carries.
SESSION_AMBIENT = "ambient"

#: The jar is neither read nor written; the explicit ``cookies``/``headers`` on
#: this request are the only session material it carries.
#:
#: This is the mode a request AS A NAMED PRINCIPAL needs, and it did not exist
#: before the four-arm IDOR oracle. The two modes that did are both wrong for it:
#: ``ambient`` sends role B's cookies but still passes ``-c jar``, so B's
#: ``Set-Cookie`` overwrites the engagement's own session and every later probe
#: silently becomes B; ``none`` drops the explicit cookies too, so the request
#: carries no principal at all. An access-control oracle whose entire claim is
#: "principal A read principal B's object" cannot afford either.
SESSION_ISOLATED = "isolated"

#: No session material at all — the anonymous control. What ``no_session`` meant
#: and still means.
SESSION_NONE = "none"

#: Every mode, in the order they carry LESS of the engagement's session.
SESSION_MODES: tuple[str, ...] = (SESSION_AMBIENT, SESSION_ISOLATED, SESSION_NONE)


class HTTPClientOutput(ToolOutput):
    """Structured output from an HTTP request."""

    status_code: int = 0
    response_headers: dict[str, str] = {}
    response_body: str = ""
    redirect_chain: list[str] = []
    response_time_ms: float = 0.0


def _cookie_jar_path(engagement_id: str) -> str:
    """Return the shared cookie jar file path for an engagement.

    All curl calls within the same engagement share this file, so cookies
    obtained during authentication persist across agents and tool invocations.

    The path is rooted at /tmp because curl runs inside the dedicated
    clinkz-tools Docker container. Predictability is required (the next
    curl call must find the same jar) and the UUID prefix prevents
    cross-engagement collisions; the container is single-tenant.

    Args:
        engagement_id: UUID of the active engagement.

    Returns:
        Absolute path string (``/tmp/clinkz_{engagement_id}_cookies.txt``).
    """
    return f"/tmp/clinkz_{engagement_id}_cookies.txt"  # nosec B108


def get_session_cookies(engagement_id: str) -> dict[str, str]:
    """Read the Netscape-format cookie jar and return cookies as a dict.

    Args:
        engagement_id: UUID of the active engagement.

    Returns:
        Dict of cookie_name → cookie_value.  Empty dict if the jar
        does not exist or is empty.
    """
    import os

    jar_path = _cookie_jar_path(engagement_id)
    cookies: dict[str, str] = {}

    if not os.path.isfile(jar_path):
        return cookies

    try:
        with open(jar_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    # Netscape cookie format: domain, flag, path, secure, exp, name, value
                    cookies[parts[5]] = parts[6]
    except OSError:
        pass

    return cookies


class HTTPClientTool(ToolBase):
    """Send arbitrary HTTP requests for manual testing and exploitation.

    In Docker mode, uses curl via ``docker exec`` so requests come from the
    container network. In local mode, uses aiohttp on the host.

    Args:
        engagement_id: If provided, a per-engagement cookie jar is used so
            session cookies persist across all requests in the engagement.
    """

    capabilities = [
        "http_request",
        "request_crafting",
        "authentication_testing",
        "manual_exploitation",
    ]
    category = "utility"

    def __init__(
        self,
        scope: Any = None,
        timeout: int = 300,
        engagement_id: str | None = None,
        stage: str = "",
    ) -> None:
        if scope is None:
            from clinkz.models.scope import EngagementScope

            scope = EngagementScope(name="default", targets=[])
        super().__init__(scope=scope, timeout=timeout)
        self._engagement_id = engagement_id
        self._stage = stage

    @property
    def name(self) -> str:
        return "http_client"

    @property
    def description(self) -> str:
        return "Send an arbitrary HTTP request to a target URL."

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).",
                        "default": "GET",
                    },
                    "url": {
                        "type": "string",
                        "description": "Full URL to send the request to.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom HTTP headers as key-value pairs.",
                        "default": {},
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body (for POST/PUT/PATCH).",
                        "default": "",
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Cookies as key-value pairs.",
                        "default": {},
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Whether to follow HTTP redirects.",
                        "default": False,
                    },
                    "no_session": {
                        "type": "boolean",
                        "description": (
                            "Send with NO session material at all: the shared "
                            "engagement cookie jar is neither read nor written. "
                            "This is what makes an anonymous control genuinely "
                            "anonymous. Shorthand for session_mode='none'."
                        ),
                        "default": False,
                    },
                    "session_mode": {
                        "type": "string",
                        "enum": list(SESSION_MODES),
                        "description": (
                            "Which session material this request carries. "
                            "'ambient' (default): the shared engagement jar is "
                            "read and written. 'isolated': the jar is neither "
                            "read nor written and the explicit cookies/headers "
                            "given here are the only session material — how a "
                            "request is sent AS A NAMED PRINCIPAL without "
                            "poisoning the engagement's own session. 'none': no "
                            "session material at all."
                        ),
                        "default": SESSION_AMBIENT,
                    },
                },
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        url = args.get("url", "").strip()
        if not url:
            raise ValueError("'url' is required for http_client")

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"Invalid URL: {url}")

        self._check_scope(url)

        method = args.get("method", "GET").upper()
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {method}")

        session_mode = self._resolve_session_mode(args)

        return {
            "method": method,
            "url": url,
            "headers": args.get("headers") or {},
            "body": args.get("body", ""),
            "cookies": args.get("cookies") or {},
            "follow_redirects": bool(args.get("follow_redirects", False)),
            "session_mode": session_mode,
            # DERIVED, never independently supplied past this point. Two booleans
            # that must agree are how ``attribution.commit`` and
            # ``attribution.sessionUrl`` disagreed and leaked; ``session_mode`` is
            # the one field the backends branch on, and this is a view of it kept
            # so the callers and witnesses that already read ``no_session`` — the
            # auth-bypass carrier assertion among them — keep reading a true fact.
            "no_session": session_mode == SESSION_NONE,
        }

    @staticmethod
    def _resolve_session_mode(args: dict[str, Any]) -> str:
        """The single session mode this request runs under.

        ``no_session=True`` is shorthand for :data:`SESSION_NONE` and stays
        supported, because it is what every anonymous-control call site in the
        engine says today and because "carries nothing" is the property those
        call sites are asserting. An explicit ``session_mode`` wins over it, and
        the two disagreeing (``session_mode='ambient'`` beside
        ``no_session=True``) is a caller bug rather than a precedence question —
        so it raises rather than picking one.

        Raises:
            ValueError: On an unknown mode, or on a contradictory pair.
        """
        declared = args.get("session_mode")
        legacy = bool(args.get("no_session", False))
        if declared is None:
            return SESSION_NONE if legacy else SESSION_AMBIENT
        mode = str(declared).strip().lower()
        if mode not in SESSION_MODES:
            raise ValueError(
                f"Invalid session_mode: {declared!r} (expected one of {SESSION_MODES})"
            )
        if legacy and mode != SESSION_NONE:
            raise ValueError(
                f"contradictory session material: no_session=True with session_mode={mode!r}. "
                "no_session is shorthand for session_mode='none'; pass one or the other."
            )
        return mode

    async def execute(self, args: dict[str, Any]) -> str:
        """Execute the HTTP request and return raw response info.

        This is the engagement's single HTTP chokepoint: every methodology probe,
        every enrichment fetch, and the JSON/API auth path all funnel through
        here. So it is also where the production safety rails apply — the
        governor decides whether the request may be sent, paces it, records it if
        it mutates state, and watches the response for signs the target has
        started blocking us.

        When no governor is installed (:func:`~clinkz.safety.governor.get_active_governor`
        returns ``None``) this is byte-for-byte the previous behaviour. That is
        the point: the rails govern an *engagement*, and a direct methodology
        invocation — a smoke test, a replay, a driver script — is unaffected.

        A refusal is returned as an ordinary error-shaped response rather than
        raised, because every caller already handles ``status_code == 0`` with an
        ``error``, and an exception thrown through twenty layers of methodology
        code would be swallowed by one of their ``except`` blocks and turn
        "refused by policy" into "that probe failed".
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is None:
            return await self._dispatch(args)

        decision = await governor.authorize(
            args["method"],
            args["url"],
            body=args.get("body", "") or "",
            stage=self._stage or self.category,
        )
        if not decision.allowed:
            self._logger.warning(
                "SAFETY REFUSAL [%s] %s %s — %s",
                decision.category,
                args["method"],
                args["url"],
                decision.reason,
            )
            return json.dumps(
                {
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "redirect_chain": [],
                    "response_time_ms": 0.0,
                    "error": (
                        f"refused by safety policy [{decision.category}]: {decision.reason}"
                        + (f" (signal: {decision.signal})" if decision.signal else "")
                    ),
                    "safety_refusal": decision.category,
                }
            )

        try:
            raw = await self._dispatch(args)
        finally:
            governor.release()

        self._observe(
            governor,
            raw,
            session_bearing=args.get("session_mode", SESSION_AMBIENT) == SESSION_AMBIENT,
        )
        return raw

    async def _dispatch(self, args: dict[str, Any]) -> str:
        """Route to the curl (docker) or aiohttp (host) implementation."""
        from clinkz.config import settings

        if settings.tool_exec_mode == "docker":
            return await self._execute_curl(args)
        return await self._execute_aiohttp(args)

    @staticmethod
    def _observe(governor: Any, raw: str, *, session_bearing: bool = True) -> None:
        """Feed the response back to the governor for blocking + session watching.

        ``session_bearing`` is the whole point of doing this here rather than in
        an observer: this seam is the only code that knows whether the request
        carried the engagement's session. A ``no_session`` request is an
        anonymous control by construction — its 401 is the intended result — and
        an observer forced to infer that from the response alone will read the
        proof that authentication works as proof that it broke.

        An ``isolated`` request is the same case for the same reason: it carries
        SOME principal's session, but not the engagement's, so what the target
        says about it is not evidence about the session the sentinel guards. A
        role-B probe that gets a 401 because role B lacks the object is not our
        session expiring.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        governor.observe_response(
            status=int(data.get("status_code") or 0),
            headers=data.get("response_headers") or {},
            body=data.get("response_body") or "",
            session_bearing=session_bearing,
        )

    # ------------------------------------------------------------------
    # Docker mode: curl inside container
    # ------------------------------------------------------------------

    async def _execute_curl(self, args: dict[str, Any]) -> str:
        """Build and run a curl command inside the Docker container."""
        method = args["method"]
        url = args["url"]
        headers: dict[str, str] = args.get("headers") or {}
        body: str = args.get("body", "")
        cookies: dict[str, str] = args.get("cookies") or {}
        follow_redirects: bool = args.get("follow_redirects", False)

        # Per-engagement cookie jar so sessions persist across all requests.
        # /tmp here is inside the clinkz-tools Docker container; see
        # _cookie_jar_path() for the rationale.
        cookie_jar = (
            _cookie_jar_path(self._engagement_id)
            if self._engagement_id
            else "/tmp/clinkz_cookies.txt"  # nosec B108
        )

        # Build curl command
        cmd: list[str] = [
            "curl",
            "-s",  # silent (no progress bar)
            "-S",  # show errors
            "-D",
            "-",  # dump response headers to stdout
            "-X",
            method,
            "-w",
            "\n__CURL_TIMING__%{time_total}\n",  # timing info at end
        ]

        if follow_redirects:
            cmd.append("-L")

        # Headers
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Request body. Use --data-binary, not -d: curl's -d strips CR/LF from
        # the payload, which corrupts multipart/form-data boundary framing (the
        # body's \r\n separators) and silently breaks file uploads. --data-binary
        # sends the body byte-for-byte; for urlencoded/JSON bodies (no embedded
        # newlines) it is equivalent.
        if body:
            cmd.extend(["--data-binary", body])

        # Session material, decided by the ONE mode field.
        #
        # ``-c`` is what WRITES the shared jar and ``-b <jar>`` is what READS it,
        # and the two are separable — which is the whole reason ``isolated``
        # exists. ``ambient`` does both, so a target's ``Set-Cookie`` keeps the
        # engagement's session current. ``isolated`` does neither: the explicit
        # cookies go out on the wire and whatever comes back stays out of the
        # jar, so a probe sent as another principal cannot overwrite the session
        # every later request depends on. ``none`` sends nothing and stores
        # nothing, which is what makes an anonymous control genuinely anonymous.
        mode = args.get("session_mode", SESSION_AMBIENT)
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if mode == SESSION_AMBIENT:
            cmd.extend(["-c", cookie_jar])
            # Cookies — if dict provided, send as header; otherwise read from jar
            cmd.extend(["-b", cookie_str or cookie_jar])
        elif mode == SESSION_ISOLATED and cookie_str:
            cmd.extend(["-b", cookie_str])

        cmd.append(url)

        start = time.monotonic()
        try:
            stdout, stderr, returncode = await self._run_subprocess(cmd)
            elapsed_ms = (time.monotonic() - start) * 1000

            if returncode != 0 and not stdout.strip():
                return json.dumps(
                    {
                        "status_code": 0,
                        "response_headers": {},
                        "response_body": "",
                        "redirect_chain": [],
                        "response_time_ms": round(elapsed_ms, 2),
                        "error": f"curl exited with code {returncode}: {stderr.strip()}",
                    }
                )

            return self._parse_curl_output(stdout, elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return json.dumps(
                {
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "redirect_chain": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "error": str(exc),
                }
            )

    def _parse_curl_output(self, raw: str, elapsed_ms: float) -> str:
        """Parse curl ``-D -`` output into structured JSON.

        The output format from ``curl -D - -w '\\n__CURL_TIMING__%%{time_total}'``
        is:
            HTTP/1.1 200 OK\\r\\n
            Header: value\\r\\n
            ...\\r\\n
            \\r\\n
            <body>
            __CURL_TIMING__0.123
        """
        # Extract timing from the end
        timing_match = re.search(r"__CURL_TIMING__([\d.]+)\s*$", raw)
        if timing_match:
            curl_time_s = float(timing_match.group(1))
            elapsed_ms = curl_time_s * 1000
            raw = raw[: timing_match.start()]

        # With -L (follow redirects), there may be multiple HTTP response blocks.
        # Split on HTTP status lines to find intermediate redirects and final response.
        # Pattern: "HTTP/<version> <status>" at start of a line
        http_blocks = re.split(r"(?=^HTTP/[\d.]+ \d+)", raw, flags=re.MULTILINE)
        http_blocks = [b for b in http_blocks if b.strip()]

        redirect_chain: list[str] = []
        status_code = 0
        resp_headers: dict[str, str] = {}
        resp_body = ""

        for i, block in enumerate(http_blocks):
            # Parse status line
            status_match = re.match(r"HTTP/[\d.]+ (\d+)", block)
            if not status_match:
                # This block is just body continuation
                resp_body += block
                continue

            code = int(status_match.group(1))

            # Split headers from body at the blank line
            header_body_split = re.split(r"\r?\n\r?\n", block, maxsplit=1)
            header_section = header_body_split[0]
            body_section = header_body_split[1] if len(header_body_split) > 1 else ""

            if i < len(http_blocks) - 1:
                # Intermediate response (redirect)
                # Extract Location header for redirect chain
                loc_match = re.search(
                    r"^Location:\s*(.+)$", header_section, re.IGNORECASE | re.MULTILINE
                )
                if loc_match:
                    redirect_chain.append(loc_match.group(1).strip())
            else:
                # Final response
                status_code = code
                resp_body = body_section

                # Parse headers (append duplicates with `, `)
                for line in header_section.split("\n"):
                    line = line.strip().rstrip("\r")
                    if ":" in line and not line.startswith("HTTP/"):
                        key, _, value = line.partition(":")
                        k, v = key.strip(), value.strip()
                        if k in resp_headers:
                            resp_headers[k] += f", {v}"
                        else:
                            resp_headers[k] = v

        raw_display = f"HTTP {status_code}\n"
        for k, v in resp_headers.items():
            raw_display += f"{k}: {v}\n"
        raw_display += f"\n{resp_body}"

        return json.dumps(
            {
                "status_code": status_code,
                "response_headers": resp_headers,
                "response_body": resp_body,
                "redirect_chain": redirect_chain,
                "response_time_ms": round(elapsed_ms, 2),
                "raw": raw_display,
            }
        )

    # ------------------------------------------------------------------
    # Local mode: aiohttp on the host
    # ------------------------------------------------------------------

    async def _execute_aiohttp(self, args: dict[str, Any]) -> str:
        """Execute the HTTP request using aiohttp (host-based)."""
        import aiohttp

        method = args["method"]
        url = args["url"]
        headers = args.get("headers") or {}
        body = args.get("body", "")
        # aiohttp builds a fresh CookieJar per request below, so there is no
        # shared jar for ``isolated`` to protect here — it differs from
        # ``ambient`` only on the docker path. ``none`` still drops the cookies.
        cookies = (
            {}
            if args.get("session_mode", SESSION_AMBIENT) == SESSION_NONE
            else (args.get("cookies") or {})
        )
        follow_redirects = args.get("follow_redirects", False)

        redirect_chain: list[str] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        start = time.monotonic()
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ) as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    cookies=cookies if cookies else None,
                    allow_redirects=follow_redirects,
                    ssl=False,
                ) as resp:
                    elapsed_ms = (time.monotonic() - start) * 1000

                    # Collect redirect history
                    if resp.history:
                        redirect_chain = [str(r.url) for r in resp.history]

                    resp_headers = {k: v for k, v in resp.headers.items()}
                    resp_body = await resp.text(errors="replace")

                    raw = (
                        f"HTTP/{resp.version.major}.{resp.version.minor} "
                        f"{resp.status} {resp.reason}\n"
                    )
                    for k, v in resp_headers.items():
                        raw += f"{k}: {v}\n"
                    raw += f"\n{resp_body}"

                    return json.dumps(
                        {
                            "status_code": resp.status,
                            "response_headers": resp_headers,
                            "response_body": resp_body,
                            "redirect_chain": redirect_chain,
                            "response_time_ms": round(elapsed_ms, 2),
                            "raw": raw,
                        }
                    )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return json.dumps(
                {
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "redirect_chain": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "error": str(exc),
                }
            )

    def parse_output(self, raw_output: str) -> HTTPClientOutput:
        """Parse the JSON response from execute() into structured output."""
        if not raw_output or not raw_output.strip():
            return HTTPClientOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output or "",
                error="Empty response",
            )

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            return HTTPClientOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output,
                error=f"JSON parse error: {exc}",
            )

        error = data.get("error", "")
        return HTTPClientOutput(
            tool_name=self.name,
            success=not error,
            raw_output=data.get("raw", raw_output),
            error=error,
            status_code=data.get("status_code", 0),
            response_headers=data.get("response_headers", {}),
            response_body=data.get("response_body", ""),
            redirect_chain=data.get("redirect_chain", []),
            response_time_ms=data.get("response_time_ms", 0.0),
        )
