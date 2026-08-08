"""A local fixture site for P7, serving the landing contexts that decide a verdict.

Everything is served from 127.0.0.1 so the browser tests never touch a network
the suite does not own. Each route reflects the ``q`` parameter into a different
context, which is the only variable that should change the outcome.
"""

from __future__ import annotations

import html
import http.server
import socketserver
import threading
from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest

#: Reused on every response from the static-nonce route — the weakness under test.
STATIC_NONCE = "c3RhdGljLW5vbmNlLXZhbHVl"

_ROTATING = {"n": 0}


def _page(body: str) -> bytes:
    return f"<!doctype html><html><head><title>p7</title></head><body>{body}</body></html>".encode()


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Serves one landing context per path. No state, no side effects."""

    protocol_version = "HTTP/1.1"

    def _respond(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parts = urlsplit(self.path)
        params = parse_qs(parts.query, keep_blank_values=True)
        payload = (params.get("q") or [""])[0]
        route = parts.path

        if route == "/reflect":
            # Raw reflection into the HTML body: an executable landing.
            self._respond(_page(f"<div>{payload}</div>"))
        elif route == "/escaped":
            # The same bytes, HTML-escaped: present but inert. This is the
            # confounder every previous XSS "confirmation" could not exclude.
            self._respond(_page(f"<div>{html.escape(payload)}</div>"))
        elif route == "/textnode":
            # Present in the DOM as text, via a JS assignment that cannot execute it.
            self._respond(
                _page(
                    "<div id=t></div><script>document.getElementById('t')"
                    f".textContent = {payload!r};</script>"
                )
            )
        elif route == "/csp-none":
            self._respond(
                _page(f"<div>{payload}</div>"), {"Content-Security-Policy": "script-src 'none'"}
            )
        elif route == "/csp-static-nonce":
            self._respond(
                _page(f"<div>{payload}</div>"),
                {
                    "Content-Security-Policy": (
                        f"script-src 'self' 'unsafe-inline' 'nonce-{STATIC_NONCE}'"
                    )
                },
            )
        elif route == "/csp-rotating-nonce":
            _ROTATING["n"] += 1
            self._respond(
                _page(f"<div>{payload}</div>"),
                {"Content-Security-Policy": f"script-src 'self' 'nonce-rotating{_ROTATING['n']}'"},
            )
        elif route == "/csp-meta":
            self._respond(
                _page(
                    "<meta http-equiv='Content-Security-Policy' content=\"script-src 'none'\">"
                    f"<div>{payload}</div>"
                )
            )
        elif route == "/dom-fragment":
            # A DOM sink fed from the fragment, which never reaches the server.
            self._respond(
                _page(
                    "<div id=out></div><script>"
                    "document.write(decodeURIComponent(location.hash.substring(1)));"
                    "</script>"
                )
            )
        elif route == "/dom-fragment-decodeuri":
            # The SAME sink built on decodeURI, which does NOT decode the reserved
            # set (`; / ? : @ & = + $ , #`). A probe that percent-encodes its whole
            # payload arrives here with `%2F` still spelled `%2F`, so `</script>`
            # never reforms and the page looks invulnerable when it is not. This
            # route exists because the decodeURIComponent one above cannot catch
            # that — it decodes everything, and hid the bug on a live target.
            self._respond(
                _page(
                    "<div id=out></div><script>"
                    "document.write(decodeURI(location.hash.substring(1)));"
                    "</script>"
                )
            )
        elif route == "/dom-query-decodeuri":
            # The query-channel twin: the sink reads the whole href and decodeURIs
            # the part after the parameter name, exactly as a real one does.
            self._respond(
                _page(
                    "<div id=out></div><script>"
                    "var h = document.location.href;"
                    "if (h.indexOf('q=') >= 0) {"
                    "  document.write(decodeURI(h.substring(h.indexOf('q=') + 2)));"
                    "}"
                    "</script>"
                )
            )
        elif route == "/offsite-subresource":
            self._respond(
                _page(f"<img src='http://offsite.invalid/pixel.png'><div>{payload}</div>")
            )
        elif route == "/second-navigation":
            self._respond(
                _page(f"<div>{payload}</div><script>location.href='/reflect?q=moved';</script>")
            )
        elif route == "/logout":
            self._respond(_page("<div>logged out</div>"))
        else:
            self._respond(_page("<div>ok</div>"))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        payload = (parse_qs(raw, keep_blank_values=True).get("include") or [""])[0]
        self._respond(_page(f"<div>{payload}</div>"))

    def log_message(self, *args: object) -> None:  # pragma: no cover - noise
        return


@pytest.fixture(scope="session")
def fixture_site() -> Iterator[str]:
    """Run the fixture site on an ephemeral loopback port; yield its base URL."""
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FixtureHandler) as httpd:
        httpd.daemon_threads = True
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{httpd.server_address[1]}"
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
