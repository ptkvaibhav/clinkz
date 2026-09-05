"""Meridian Portal — a THIRD authentication shape, for reproducing auth failures.

DVWA is form + cookie. Juice Shop is JSON + bearer token. Both the authenticator
(:mod:`clinkz.tools.auth`) and the authenticated-state assertion
(:mod:`clinkz.engagement.auth_state`) were built against exactly those two, so a
target that combines them differently is the only way to find out which parts of
those two modules encode a SHAPE and which encode a NAME.

Meridian is that third shape:

* **JSON login at a non-obvious path.** ``POST /portal/v3/session-open``, body
  ``{"account": ..., "password": ...}``. The identity field is called
  ``account`` — neither ``email`` nor ``username``.
* **A session COOKIE issued on a JSON response.** The combination neither
  existing target has: Juice Shop returns a bearer token in the body and DVWA
  issues its cookie from a form POST. Meridian's login response carries
  ``Set-Cookie: meridian_portal=…`` and **no token of any kind** in the body.
* **Protected routes answer anonymously with 302 to the login page**, not with
  401 or 403. This is the commonest shape in production web applications and
  the one an oracle that keys on ``401/403`` cannot see.
* **One protected route answers 200 with the login page instead** (``/settings``)
  — the same authorization boundary wearing a different disguise, which is what
  an SPA shell does for every route it does not recognise.
* **Two genuinely public routes** (``/`` and ``/pricing``) that are byte-identical
  authenticated and anonymous, so a discriminator that fires on everything is
  caught rather than mistaken for a working one.

The login page at ``/portal/gateway`` serves a real ``<form>`` with a real
``<input type="password">``, exactly as a progressively-enhanced React login page
does. That is deliberate: it means the HTML-form path is *reachable*, so a failure
there is a failure of the flow and not merely of discovery.

Vocabulary is controlled on purpose. No page outside the authenticated area
contains "welcome", "dashboard", "logout" or "sign out" — those are the literal
strings the authenticator's success heuristic and the assertion's session-marker
discriminator match on, and a target that hands them out for free would make
every result here ambiguous.

Nothing here is intentionally vulnerable. Meridian exists to exercise the
**authentication path**, not the exploit phase.

Configuration (all optional, all environment variables):

===========================  =======================================  ===========
Variable                     Meaning                                  Default
===========================  =======================================  ===========
``MERIDIAN_PORT``            TCP port to listen on                    ``8090``
``MERIDIAN_HOST``            Bind address                             ``0.0.0.0``
``MERIDIAN_LOGIN_PATH``      Path of the HTML login page              ``/portal/gateway``
``MERIDIAN_ACCESS_LOG``      Emit one JSON line per request           ``1``
===========================  =======================================  ===========

``MERIDIAN_LOGIN_PATH`` is a variable rather than a constant because one of the
questions this target answers is whether an oracle keys on the *shape* of a
redirect or on the *spelling* of its destination. Running the same application
once at ``/portal/gateway`` and once at ``/login`` answers that in one step, and
a constant could not.

Standard library only — no third-party imports — so the pytest fixture can run
this in a thread on any machine and the container image needs no wheel build.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, urlparse

#: Cookie the portal issues. Named for the product, as a real application's is —
#: not ``session`` or ``PHPSESSID``, so nothing can match it by convention.
SESSION_COOKIE = "meridian_portal"

#: The JSON login endpoint. Non-obvious on purpose: it is in none of the
#: candidate route lists the engine probes.
LOGIN_API_PATH = "/portal/v3/session-open"

#: Logout, same family.
LOGOUT_API_PATH = "/portal/v3/session-close"

#: The identity field. Neither ``email`` nor ``username``.
IDENTITY_FIELD = "account"

#: The secret field keeps the conventional name, so exactly one thing about the
#: login body is unconventional and a failure can be attributed to it.
SECRET_FIELD = "password"

#: Accounts. ``privilege`` mirrors the rank an operator would declare on the
#: role in the credential file; it is carried here so a multi-role engagement
#: against this target has two genuinely different principals.
ACCOUNTS: dict[str, dict[str, Any]] = {
    "acct-4417": {
        "password": "s3cure-passphrase",
        "display_name": "D. Whitfield",
        "tier": "operator",
        "privilege": 0,
    },
    "acct-9002": {
        "password": "winter-harbor-77",
        "display_name": "R. Okonjo",
        "tier": "administrator",
        "privilege": 10,
    },
}

#: Routes that require a session and answer anonymously with a 302 to the login
#: page. The API pair is listed first because it is what an oracle reaches
#: earliest, and because a JSON route carries none of the HTML vocabulary that
#: could rescue a body-marker check by accident.
REDIRECTING_PROTECTED_PATHS: tuple[str, ...] = (
    "/api/orders",
    "/api/profile",
    "/dashboard",
    "/account",
)

#: The same boundary, answered with 200 and the login page. An SPA shell.
DISGUISED_PROTECTED_PATHS: tuple[str, ...] = ("/settings",)

#: Byte-identical authenticated and anonymous. A discriminator that fires on one
#: of these is firing on page chrome, and this target exists to catch that.
PUBLIC_PATHS: tuple[str, ...] = ("/", "/pricing")


def _login_path() -> str:
    """The HTML login page path, from the environment."""
    raw = os.environ.get("MERIDIAN_LOGIN_PATH", "/portal/gateway").strip() or "/portal/gateway"
    return raw if raw.startswith("/") else f"/{raw}"


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------


class _SessionStore:
    """In-memory sessions, guarded by a lock because the server is threaded."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, str] = {}

    def open(self, account: str) -> str:
        token = secrets.token_hex(16)
        with self._lock:
            self._sessions[token] = account
        return token

    def account_for(self, token: str) -> str:
        with self._lock:
            return self._sessions.get(token, "")

    def close(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)


SESSIONS = _SessionStore()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

_STYLE = (
    "<style>body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:44rem;"
    "color:#1c2733}h1{font-size:1.35rem}a{color:#0b5c8a}</style>"
)


def _page(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>{title} · Meridian</title>{_STYLE}</head><body>{body}</body></html>"
    ).encode()


def login_page(next_path: str = "") -> bytes:
    """The login page.

    A real form with a real password input, whose ``action`` is the JSON API.
    That mismatch — an HTML form pointed at a JSON-only endpoint — is not a
    contrivance; it is what a single-page application looks like to anything
    that reads the HTML rather than running the JavaScript.
    """
    hint = f'<input type=hidden name=next value="{next_path}">' if next_path else ""
    return _page(
        "Sign in",
        "<h1>Meridian Portal</h1>"
        "<p>Sign in to reach your statements and order history.</p>"
        f'<form method=post action="{LOGIN_API_PATH}">{hint}'
        f'<p><label>Account number<br><input type=text name={IDENTITY_FIELD} '
        'autocomplete=username></label></p>'
        f'<p><label>Password<br><input type=password name={SECRET_FIELD} '
        'autocomplete=current-password></label></p>'
        "<p><input type=submit name=submit value='Sign in'></p></form>"
        "<p><a href=/pricing>Pricing</a> · <a href=/>Home</a></p>",
    )


def landing_page() -> bytes:
    return _page(
        "Meridian",
        "<h1>Meridian</h1><p>Settlement and statement services for regional "
        "brokers.</p><p><a href=/pricing>Pricing</a> · "
        f'<a href="{_login_path()}">Portal</a></p>',
    )


def pricing_page() -> bytes:
    return _page(
        "Pricing",
        "<h1>Pricing</h1><ul><li>Standard — 40 settlements / month</li>"
        "<li>Regional — 400 settlements / month</li>"
        "<li>Clearing — unmetered</li></ul><p><a href=/>Home</a></p>",
    )


def dashboard_page(account: str) -> bytes:
    who = ACCOUNTS[account]["display_name"]
    return _page(
        "Overview",
        f"<h1>Overview</h1><p>Signed in as {who} ({account}).</p>"
        "<ul><li><a href=/account>Account</a></li>"
        "<li><a href=/settings>Settings</a></li></ul>"
        f'<p><a href="{LOGOUT_API_PATH}">Sign out</a></p>',
    )


def account_page(account: str) -> bytes:
    record = ACCOUNTS[account]
    return _page(
        "Account",
        f"<h1>Account</h1><p>{record['display_name']}</p>"
        f"<p>Account number: {account}</p><p>Tier: {record['tier']}</p>"
        f'<p><a href="{LOGOUT_API_PATH}">Sign out</a></p>',
    )


def settings_page(account: str) -> bytes:
    return _page(
        "Settings",
        "<h1>Settings</h1><p>Statement delivery: monthly, PDF.</p>"
        f"<p>Notification address on file for {account}.</p>"
        f'<p><a href="{LOGOUT_API_PATH}">Sign out</a></p>',
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class MeridianHandler(BaseHTTPRequestHandler):
    """One request. Every branch below is a deliberate part of the shape."""

    server_version = "Meridian/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence the default access log; :meth:`_audit` replaces it."""

    def _audit(self, **fields: Any) -> None:
        """One JSON line per request, on stdout.

        The target's own witness to what arrived. Field NAMES are recorded and
        values never are — the same rule the engine's own redaction follows, and
        the reason this log can be pasted into a report verbatim.
        """
        if os.environ.get("MERIDIAN_ACCESS_LOG", "1") != "1":
            return
        record = {"method": self.command, "path": self.path, **fields}
        sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
        sys.stdout.flush()

    def _cookies(self) -> dict[str, str]:
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", "") or "")
        return {k: v.value for k, v in jar.items()}

    def _session_account(self) -> str:
        token = self._cookies().get(SESSION_COOKIE, "")
        return SESSIONS.account_for(token) if token else ""

    def _respond(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: tuple[tuple[str, str], ...] = (),
        head_only: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra_headers:
            self.send_header(key, value)
        self.end_headers()
        if not head_only and body:
            self.wfile.write(body)

    def _json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        extra_headers: tuple[tuple[str, str], ...] = (),
        head_only: bool = False,
    ) -> None:
        self._respond(
            status,
            json.dumps(payload).encode(),
            content_type="application/json",
            extra_headers=extra_headers,
            head_only=head_only,
        )

    def _redirect_to_login(self, want: str, *, head_only: bool = False) -> None:
        """The 302 that is the whole point of this target.

        A protected route answers an anonymous request by sending the caller to
        the login page. No 401, no 403, no ``WWW-Authenticate`` — nothing whose
        status *class* says "denied". The only signal is the redirect and where
        it points.
        """
        location = f"{_login_path()}?next={quote(want, safe='')}"
        self._respond(
            302,
            b"",
            extra_headers=(("Location", location),),
            head_only=head_only,
        )
        self._audit(status=302, location=location, authenticated=False)

    # -- verbs ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's contract
        self._handle_read(head_only=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_read(head_only=True)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._respond(
            204,
            b"",
            extra_headers=(("Allow", "GET, HEAD, POST, OPTIONS"),),
            head_only=True,
        )
        self._audit(status=204)

    def _handle_read(self, *, head_only: bool) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        account = self._session_account()

        if path in PUBLIC_PATHS:
            body = landing_page() if path == "/" else pricing_page()
            self._respond(200, body, head_only=head_only)
            self._audit(status=200, authenticated=bool(account), public=True)
            return

        if path == _login_path():
            self._respond(200, login_page(), head_only=head_only)
            self._audit(status=200, authenticated=bool(account), login_page=True)
            return

        if path == LOGOUT_API_PATH:
            token = self._cookies().get(SESSION_COOKIE, "")
            if token:
                SESSIONS.close(token)
            self._respond(
                302,
                b"",
                extra_headers=(
                    ("Location", "/"),
                    ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0"),
                ),
                head_only=head_only,
            )
            self._audit(status=302, logout=True)
            return

        if path in REDIRECTING_PROTECTED_PATHS:
            if not account:
                self._redirect_to_login(self.path, head_only=head_only)
                return
            self._protected_body(path, account, head_only=head_only)
            return

        if path in DISGUISED_PROTECTED_PATHS:
            if not account:
                # Same boundary, different disguise: 200, and the body is the
                # login page. Nothing in the status line says "denied".
                self._respond(200, login_page(next_path=path), head_only=head_only)
                self._audit(status=200, authenticated=False, disguised_boundary=True)
                return
            self._respond(200, settings_page(account), head_only=head_only)
            self._audit(status=200, authenticated=True)
            return

        self._respond(404, _page("Not found", "<h1>404</h1>"), head_only=head_only)
        self._audit(status=404, authenticated=bool(account))

    def _protected_body(self, path: str, account: str, *, head_only: bool) -> None:
        if path == "/api/orders":
            # Deliberately echoes NOTHING that identifies the caller: no account
            # number, no display name, no logout link. An orders list keyed by
            # the session has no reason to repeat who you are, and this is the
            # route where the 302 boundary is the ONLY difference between the
            # authenticated and anonymous answers. /api/profile below is its
            # opposite and echoes the identity, as a profile route must — so the
            # two together separate an oracle that reads the boundary from one
            # that reads the body and got lucky.
            self._json(
                200,
                {
                    "orders": [
                        {"id": "ORD-88213", "settled": True, "amount_cents": 419900},
                        {"id": "ORD-88240", "settled": False, "amount_cents": 12750},
                    ]
                },
                head_only=head_only,
            )
        elif path == "/api/profile":
            record = ACCOUNTS[account]
            self._json(
                200,
                {
                    "account": account,
                    "display_name": record["display_name"],
                    "tier": record["tier"],
                },
                head_only=head_only,
            )
        elif path == "/dashboard":
            self._respond(200, dashboard_page(account), head_only=head_only)
        else:  # /account
            self._respond(200, account_page(account), head_only=head_only)
        self._audit(status=200, authenticated=True)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()

        if path == LOGOUT_API_PATH:
            token = self._cookies().get(SESSION_COOKIE, "")
            if token:
                SESSIONS.close(token)
            self._respond(
                204,
                b"",
                extra_headers=(("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0"),),
            )
            self._audit(status=204, logout=True)
            return

        if path != LOGIN_API_PATH:
            self._respond(405, b"", extra_headers=(("Allow", "GET, HEAD, OPTIONS"),))
            self._audit(status=405, content_type=content_type)
            return

        # JSON only. A form-encoded body is refused with the status that says
        # exactly why — 415, naming the media type it wanted. An engine that
        # reads this as a successful login is reading the URL it landed on
        # rather than the answer it received.
        if content_type != "application/json":
            self._json(
                415,
                {
                    "status": "error",
                    "reason": f"expected application/json, received {content_type or 'nothing'}",
                    "expects": {"content_type": "application/json"},
                },
            )
            self._audit(status=415, content_type=content_type, fields=_field_names(raw, content_type))
            return

        try:
            payload = json.loads(raw.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"status": "error", "reason": "body is not valid JSON"})
            self._audit(status=400, content_type=content_type)
            return
        if not isinstance(payload, dict):
            self._json(400, {"status": "error", "reason": "body is not a JSON object"})
            self._audit(status=400, content_type=content_type)
            return

        supplied = sorted(payload)
        account = str(payload.get(IDENTITY_FIELD, "") or "")
        password = str(payload.get(SECRET_FIELD, "") or "")

        if not account or not password:
            self._json(
                400,
                {
                    "status": "error",
                    "reason": "missing credential fields",
                    "expects": {"fields": [IDENTITY_FIELD, SECRET_FIELD]},
                },
            )
            self._audit(status=400, content_type=content_type, fields=supplied)
            return

        record = ACCOUNTS.get(account)
        if record is None or not secrets.compare_digest(record["password"], password):
            self._json(401, {"status": "error", "reason": "authentication failed"})
            self._audit(status=401, content_type=content_type, fields=supplied)
            return

        token = SESSIONS.open(account)
        self._json(
            200,
            {
                "status": "ok",
                "account": account,
                "display_name": record["display_name"],
                "tier": record["tier"],
            },
            extra_headers=(
                ("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"),
            ),
        )
        # No token in the body, deliberately. The session lives entirely in the
        # cookie, on a JSON response — the combination neither existing target
        # produces, and the one an extractor that only knows tokens discards.
        self._audit(status=200, content_type=content_type, fields=supplied, set_cookie=True)


def _field_names(raw: bytes, content_type: str) -> list[str]:
    """Field NAMES in a request body, for the audit log. Never values."""
    text = raw.decode("utf-8", "replace")
    if content_type == "application/json":
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            return []
        return sorted(parsed) if isinstance(parsed, dict) else []
    if not text:
        return []
    return sorted({pair.split("=", 1)[0] for pair in text.split("&") if pair})


def build_server(port: int = 0, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    """Return a bound, unstarted server. ``port=0`` picks a free one.

    Split out from :func:`main` so the pytest fixture binds an ephemeral port
    and reads it back, rather than hard-coding one that may be in use.
    """
    server = ThreadingHTTPServer((host, port), MeridianHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    port = int(os.environ.get("MERIDIAN_PORT", "8090"))
    host = os.environ.get("MERIDIAN_HOST", "0.0.0.0")  # noqa: S104 — container target
    server = build_server(port, host)
    sys.stdout.write(
        json.dumps(
            {
                "event": "listening",
                "host": host,
                "port": server.server_address[1],
                "login_page": _login_path(),
                "login_api": LOGIN_API_PATH,
                "identity_field": IDENTITY_FIELD,
                "session_cookie": SESSION_COOKIE,
            }
        )
        + "\n"
    )
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
