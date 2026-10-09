"""Northwind Notes — a client-rendered SPA whose login is a SEPARATE-ORIGIN Keycloak.

The fourth authentication shape, and the first one the engine cannot reach by
reading the application's own pages:

* **Every non-API path is a catch-all ``200 index.html``.** ``/login``,
  ``/settings``, ``/admin``, a typo — all answer 200 with the same shell, which
  carries a ``<div id="root">`` and a script tag. There is no ``<form>`` and no
  ``<input type="password">`` anywhere in the HTML this origin serves.
* **The credential is never posted to this origin.** ``GET /api/auth/login``
  answers ``302`` to the Keycloak authorization endpoint on a different host
  and port (authorization code + PKCE, ``state`` bound to a cookie). The
  password form lives on the IdP, whose action URL carries a one-time
  ``session_code`` / ``execution`` / ``tab_id`` and needs the IdP's own
  ``AUTH_SESSION_ID`` cookie.
* **The session is a cookie this origin sets only on the code exchange.**
  ``GET /api/auth/callback`` swaps the code for tokens server-side (a
  confidential client — the browser never holds a token) and sets
  ``nw_session``. No token is ever in a response body.
* **The boundary.** ``GET /api/me`` and ``GET /api/notes`` answer ``401`` JSON
  anonymously and ``200`` JSON with a session. The client renders the rest.

Keycloak is configured the way an operator would leave it: the realm's direct
access grant (the password grant) is OFF for this client, so there is no
``POST /token`` shortcut that skips the browser flow.

Standard library only, like ``docker/meridian``.

Environment:

``NW_PORT``          TCP port to listen on                       ``8000``
``NW_PUBLIC_URL``    This origin, as a browser addresses it      ``http://spa-app:8000``
``NW_IDP_PUBLIC``    Keycloak, as a browser addresses it         ``http://keycloak-idp:8080``
``NW_IDP_INTERNAL``  Keycloak, as this server addresses it       ``NW_IDP_PUBLIC``
``NW_REALM``         Realm name                                  ``northwind``
``NW_CLIENT_ID``     OIDC client id                              ``northwind-notes``
``NW_CLIENT_SECRET`` OIDC client secret                          (required)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PUBLIC_URL = os.environ.get("NW_PUBLIC_URL", "http://spa-app:8000").rstrip("/")
IDP_PUBLIC = os.environ.get("NW_IDP_PUBLIC", "http://keycloak-idp:8080").rstrip("/")
IDP_INTERNAL = os.environ.get("NW_IDP_INTERNAL", IDP_PUBLIC).rstrip("/")
REALM = os.environ.get("NW_REALM", "northwind")
CLIENT_ID = os.environ.get("NW_CLIENT_ID", "northwind-notes")
CLIENT_SECRET = os.environ.get("NW_CLIENT_SECRET", "")
REDIRECT_URI = f"{PUBLIC_URL}/api/auth/callback"

_OIDC = f"/realms/{REALM}/protocol/openid-connect"

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northwind Notes</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<div id="root"></div>
<script src="/assets/app.js" defer></script>
</body>
</html>
"""

APP_JS = """(function () {
  "use strict";
  var root = document.getElementById("root");
  function h(tag, text) {
    var el = document.createElement(tag);
    if (text) el.textContent = text;
    return el;
  }
  function signIn() {
    window.location.assign("/api/auth/login?next=" + encodeURIComponent(location.pathname));
  }
  function render(me) {
    root.textContent = "";
    var nav = h("nav");
    nav.appendChild(h("strong", "Northwind Notes"));
    root.appendChild(nav);
    if (!me) {
      var b = h("button", "Sign in");
      b.addEventListener("click", signIn);
      root.appendChild(b);
      return;
    }
    root.appendChild(h("p", "Signed in as " + me.preferred_username));
    fetch("/api/notes", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (notes) {
        var ul = h("ul");
        notes.forEach(function (n) { ul.appendChild(h("li", n.title)); });
        root.appendChild(ul);
      });
    var out = h("button", "Sign out");
    out.addEventListener("click", function () {
      fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" })
        .then(function () { render(null); });
    });
    root.appendChild(out);
  }
  fetch("/api/me", { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(render)
    .catch(function () { render(null); });
})();
"""

APP_CSS = "body{font-family:system-ui,sans-serif;margin:2rem}nav{margin-bottom:1rem}\n"

# Server-side state. In-memory: a restart logs everyone out, which is the
# behaviour a fixture wants.
_LOCK = threading.Lock()
_PENDING: dict[str, dict[str, str]] = {}  # state -> {verifier, next}
_SESSIONS: dict[str, dict[str, Any]] = {}  # session id -> {access_token, sub, username}
_NOTES: dict[str, list[dict[str, str]]] = {}  # sub -> notes


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _idp_post(path: str, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        f"{IDP_INTERNAL}{path}",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — fixture
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _idp_userinfo(access_token: str) -> dict[str, Any] | None:
    req = urllib.request.Request(
        f"{IDP_INTERNAL}{_OIDC}/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — fixture
            return json.loads(resp.read())
    except (urllib.error.URLError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    """One request. Everything not under ``/api`` or ``/assets`` is the shell."""

    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        if os.environ.get("NW_ACCESS_LOG", "1") == "1":
            super().log_message(fmt, *args)

    # -- helpers -----------------------------------------------------------
    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(
        self, status: int, payload: Any, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json", headers)

    def _redirect(self, location: str, headers: list[tuple[str, str]] | None = None) -> None:
        self._send(302, b"", "text/plain", [("Location", location), *(headers or [])])

    def _cookie(self, name: str) -> str:
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get(name)
        return morsel.value if morsel else ""

    def _session(self) -> dict[str, Any] | None:
        sid = self._cookie("nw_session")
        with _LOCK:
            return _SESSIONS.get(sid) if sid else None

    # -- routes ------------------------------------------------------------
    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        query = urllib.parse.parse_qs(url.query)
        if path == "/assets/app.js":
            return self._send(200, APP_JS.encode(), "application/javascript")
        if path == "/assets/app.css":
            return self._send(200, APP_CSS.encode(), "text/css")
        if path == "/api/auth/login":
            return self._login_start(query.get("next", ["/"])[0])
        if path == "/api/auth/callback":
            return self._login_callback(query)
        if path == "/api/me":
            session = self._session()
            if session is None:
                return self._json(401, {"error": "unauthenticated"})
            info = _idp_userinfo(session["access_token"])
            if info is None:
                return self._json(401, {"error": "session expired"})
            return self._json(
                200,
                {k: info.get(k) for k in ("sub", "preferred_username", "email", "name")},
            )
        if path == "/api/notes":
            session = self._session()
            if session is None:
                return self._json(401, {"error": "unauthenticated"})
            with _LOCK:
                return self._json(200, _NOTES.get(session["sub"], []))
        if path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        # The catch-all: every other path is the SPA shell, 200.
        return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")

    def _method_not_allowed(self) -> None:
        # http.server answers an unimplemented verb with 501, which no nginx
        # front ever does; a model reasoned from that 501 on the first cold run.
        self._send(405, b"Method Not Allowed", "text/plain", [("Allow", "GET, HEAD, POST")])

    do_OPTIONS = _method_not_allowed  # noqa: N815
    do_PUT = _method_not_allowed  # noqa: N815
    do_PATCH = _method_not_allowed  # noqa: N815
    do_DELETE = _method_not_allowed  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/api/auth/logout":
            sid = self._cookie("nw_session")
            with _LOCK:
                _SESSIONS.pop(sid, None)
            return self._json(200, {"ok": True}, [("Set-Cookie", "nw_session=; Path=/; Max-Age=0")])
        if path == "/api/notes":
            session = self._session()
            if session is None:
                return self._json(401, {"error": "unauthenticated"})
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return self._json(400, {"error": "invalid json"})
            note = {"id": secrets.token_hex(4), "title": str(body.get("title", ""))[:200]}
            with _LOCK:
                _NOTES.setdefault(session["sub"], []).append(note)
            return self._json(201, note)
        if path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        # A POST to the shell is a 405 from a static host, exactly as nginx would.
        return self._send(405, b"Method Not Allowed", "text/plain")

    def _login_start(self, next_path: str) -> None:
        state = _b64url(secrets.token_bytes(16))
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        local = next_path.startswith("/") and not next_path.startswith("//")
        safe_next = next_path if local else "/"
        with _LOCK:
            _PENDING[state] = {"verifier": verifier, "next": safe_next}
        params = urllib.parse.urlencode(
            {
                "client_id": CLIENT_ID,
                "response_type": "code",
                "scope": "openid profile email",
                "redirect_uri": REDIRECT_URI,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        self._redirect(
            f"{IDP_PUBLIC}{_OIDC}/auth?{params}",
            [("Set-Cookie", f"nw_login_state={state}; Path=/api/auth; HttpOnly; SameSite=Lax")],
        )

    def _login_callback(self, query: dict[str, list[str]]) -> None:
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        if not state or state != self._cookie("nw_login_state"):
            return self._json(400, {"error": "state mismatch"})
        with _LOCK:
            pending = _PENDING.pop(state, None)
        if pending is None or not code:
            return self._json(400, {"error": "unknown login attempt"})
        status, tokens = _idp_post(
            f"{_OIDC}/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": pending["verifier"],
            },
        )
        access = tokens.get("access_token") if status == 200 else None
        info = _idp_userinfo(access) if access else None
        if not access or info is None:
            return self._json(401, {"error": "code exchange failed"})
        sid = _b64url(secrets.token_bytes(24))
        with _LOCK:
            _SESSIONS[sid] = {
                "access_token": access,
                "sub": info.get("sub", ""),
                "username": info.get("preferred_username", ""),
            }
        self._redirect(
            pending["next"],
            [
                ("Set-Cookie", f"nw_session={sid}; Path=/; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "nw_login_state=; Path=/api/auth; Max-Age=0"),
            ],
        )


def main() -> None:
    """Serve until killed."""
    if not CLIENT_SECRET:
        raise SystemExit("NW_CLIENT_SECRET is required")
    port = int(os.environ.get("NW_PORT", "8000"))
    host = os.environ.get("NW_HOST", "0.0.0.0")  # noqa: S104 — container target
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
