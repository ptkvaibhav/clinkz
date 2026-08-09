"""P7's browser-driving half — the code that runs *where the browser is*.

## Why this is a separate module with no Clinkz imports

The oracle's observation has to be made from a machine that can reach the
target. In ``TOOL_EXEC_MODE=docker`` — the default, and the only mode in which
this engine has a port scanner — every tool runs inside ``clinkz-tools`` and
:func:`~clinkz.orchestrator.target_resolver.resolve_target_for_docker_mode`
rewrites ``http://localhost:8080`` to ``http://clinkz-dvwa:80``, an alias that
resolves only on the shared bridge network. A browser on the host can neither
resolve that name nor route to the bridge subnet, so a host-side oracle in a
real engagement does not produce a wrong verdict — it produces no verdict at
all, on every single navigation.

So the browser runs in the container, and this module is what gets sent there:
it is executed by the container's bare ``python3`` with its source on stdin and
its job as a base64 argument. That constrains it absolutely — **the tools image
has Playwright and the standard library and nothing of Clinkz** — which is why
there is not one ``clinkz.`` import below, and why the job and result are plain
dicts rather than the Pydantic models used everywhere else in this codebase.

The same functions are imported and called directly for the in-process runtime,
so there is exactly one implementation of the browser rails. A second copy that
drifted from this one would mean the rails a validation driver exercises are not
the rails a real engagement runs under, which is the failure mode this split
exists to prevent.

## What it does NOT do, structurally

Nothing here clicks, fills, presses, submits, or evaluates page-authored script.
The only page interaction is :meth:`Page.goto` and one read of the ``<meta>``
elements. A form on the rendered page is inert as far as this module is
concerned, and the guards below make that a property rather than an omission:

* **One navigation.** The first navigation is the one Clinkz authorized and
  logged. Every later one — a meta refresh, a ``location`` assignment, a
  JS-driven ``form.submit()``, a logout link — was decided by the page, and is
  aborted.
* **Only the authorized request may mutate.** Every *other* request the page
  makes is held to a safe method, so a page cannot use ``fetch('/user/delete',
  {method:'DELETE'})`` to do what a blocked navigation could not.
* **A safe method is not automatically safe.** ``<img src="/logout">`` is a GET
  that destroys the engagement's session. Subresource paths are matched against
  the destructive vocabulary shipped in the job — the same one
  :mod:`clinkz.safety.destructive` owns — and refused on a hit.
* **Scope.** A subresource that is neither same-origin nor on a host the
  engagement covers is aborted before it is sent.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any
from urllib.parse import urlsplit

#: Marks the result object on stdout. Chromium, the Playwright driver and any
#: apt-installed library are all free to write to this process's stdout, so the
#: result is delimited rather than assumed to be the only thing there.
RESULT_SENTINEL = "__CLINKZ_P7_RESULT__"

#: The methods a *page-initiated* request may use. The one authorized
#: navigation is exempt — it is the request Clinkz decided to send, classified
#: by the governor and written to the action log before the browser started.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_DEFAULT_NAV_TIMEOUT_MS = 20_000
_DEFAULT_SETTLE_MS = 900
_DEFAULT_MAX_CONSOLE_LINES = 25

#: Bounds on recorded refusals, so a page that requests a thousand blocked
#: subresources cannot inflate an artifact.
_MAX_BLOCKED_NAVIGATIONS = 10
_MAX_BLOCKED_SUBRESOURCES = 20
_MAX_BLOCKED_MUTATIONS = 20


def _port_of(parts: Any) -> int:
    """Return the effective port for a split URL, defaulting by scheme."""
    if parts.port:
        return int(parts.port)
    return 443 if (parts.scheme or "").lower() == "https" else 80


def same_origin(a: str, b: str) -> bool:
    """Whether two URLs share scheme, host and effective port."""
    pa, pb = urlsplit(a), urlsplit(b)
    return (
        (pa.scheme or "").lower() == (pb.scheme or "").lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and _port_of(pa) == _port_of(pb)
    )


def _path_tokens(url: str) -> set[str]:
    """Lower-cased alphanumeric tokens of a URL's path and query.

    Deliberately crude. This is a *guard*, and a guard that refuses a few extra
    image loads costs nothing, whereas one that misses ``/logout`` costs the
    engagement's session — and with it every authenticated observation that
    would have followed.
    """
    parts = urlsplit(url)
    raw = f"{parts.path} {parts.query}"
    token = ""
    tokens: set[str] = set()
    for char in raw:
        if char.isalnum():
            token += char.lower()
        else:
            if token:
                tokens.add(token)
            token = ""
    if token:
        tokens.add(token)
    return tokens


def request_refusal(url: str, method: str, target_url: str, guard: dict[str, Any]) -> str:
    """Why a page-initiated request must not be sent, or ``""`` to allow it.

    Args:
        url: The URL the page asked for.
        method: Its HTTP method.
        target_url: The URL the oracle was authorized to navigate to.
        guard: The serialized rails — ``allowed_hosts``, ``blocked_path_tokens``,
            ``blocked_query_keys`` — built host-side from the engagement scope
            and :mod:`clinkz.safety.destructive`.

    Returns:
        A one-phrase reason, or an empty string when the request may proceed.
    """
    verb = (method or "GET").upper()
    if verb not in SAFE_METHODS:
        return f"page-initiated {verb} would mutate target state"

    if not same_origin(url, target_url):
        host = (urlsplit(url).hostname or "").lower()
        if host not in {h.lower() for h in guard.get("allowed_hosts") or ()}:
            return "host is outside the engagement scope"

    tokens = _path_tokens(url)
    hits = tokens & {t.lower() for t in guard.get("blocked_path_tokens") or ()}
    if hits:
        return f"path carries the state-changing token {sorted(hits)[0]!r}"

    query_keys = {
        (pair.split("=", 1)[0] or "").lower()
        for pair in (urlsplit(url).query or "").split("&")
        if pair
    }
    key_hits = query_keys & {k.lower() for k in guard.get("blocked_query_keys") or ()}
    if key_hits:
        return f"query carries the state-changing key {sorted(key_hits)[0]!r}"

    return ""


def _blank_result() -> dict[str, Any]:
    """The result shape, with every field present so the caller never guesses."""
    return {
        "witnesses": [],
        "console": [],
        "blocked_navigations": [],
        "blocked_subresources": [],
        "blocked_mutations": [],
        "final_url": "",
        "response_headers": {},
        "meta_policies": [],
        "unavailable": False,
        "error": "",
    }


async def run_witness(job: dict[str, Any]) -> dict[str, Any]:
    """Render one URL and report what the browser did. Never raises.

    Every failure is reported as a field on the result rather than an exception,
    because the caller's job on a broken browser is to keep its unproven lead —
    not to handle an error thrown through twenty layers of methodology code. A
    browser that could not run is a coverage gap and must never read as evidence
    that the target is safe.

    Args:
        job: ``url``, ``method``, ``post_body``, ``cookies``, ``binding_name``,
            ``guard``, ``launch_args``, and the three timing bounds.

    Returns:
        The observation dict — witnesses, refusals, and the target-authored
        artefacts the caller records as evidence.
    """
    result = _blank_result()
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        result["unavailable"] = True
        result["error"] = f"Playwright is not importable here: {exc}"
        return result

    url: str = job["url"]
    method: str = (job.get("method") or "GET").upper()
    post_body: str = job.get("post_body") or ""
    guard: dict[str, Any] = job.get("guard") or {}
    binding_name: str = job["binding_name"]
    settle_ms = int(job.get("settle_ms") or _DEFAULT_SETTLE_MS)
    nav_timeout_ms = int(job.get("nav_timeout_ms") or _DEFAULT_NAV_TIMEOUT_MS)
    max_console = int(job.get("max_console_lines") or _DEFAULT_MAX_CONSOLE_LINES)
    navigated = {"count": 0}

    def _record_console(message: Any) -> None:
        """Keep CSP-related console lines as TARGET-AUTHORED evidence only."""
        if len(result["console"]) >= max_console:
            return
        try:
            text = message.text
        except Exception:  # noqa: BLE001 — evidence only; never fails a run
            return
        if "Content Security Policy" in text or "Refused to" in text:
            result["console"].append(text[:300])

    async def _handle_route(route: Any, request: Any) -> None:
        """The per-request rail: scope, one-navigation, and the POST rewrite."""
        try:
            request_url = request.url
            if request.is_navigation_request():
                navigated["count"] += 1
                if navigated["count"] > 1:
                    # Only the first navigation is ours; the page decided this one.
                    if len(result["blocked_navigations"]) < _MAX_BLOCKED_NAVIGATIONS:
                        result["blocked_navigations"].append(request_url)
                    await route.abort()
                    return
                if method == "POST" and request_url.split("#")[0] == url.split("#")[0]:
                    await route.continue_(
                        method="POST",
                        post_data=post_body,
                        headers={
                            **request.headers,
                            "content-type": "application/x-www-form-urlencoded",
                        },
                    )
                    return
                await route.continue_()
                return

            refusal = request_refusal(request_url, request.method, url, guard)
            if refusal:
                bucket = (
                    "blocked_mutations"
                    if (request.method or "GET").upper() not in SAFE_METHODS
                    else "blocked_subresources"
                )
                cap = (
                    _MAX_BLOCKED_MUTATIONS
                    if bucket == "blocked_mutations"
                    else _MAX_BLOCKED_SUBRESOURCES
                )
                if len(result[bucket]) < cap:
                    result[bucket].append(f"{request.method} {request_url} — {refusal}")
                await route.abort()
                return

            await route.continue_()
        except Exception:  # noqa: BLE001 — a routing error must not hang the page
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass

    def _on_binding(source: dict[str, Any], value: Any = "") -> None:
        """Record one inbound call on the Clinkz-owned witness function.

        Returns nothing the page can learn from — in particular it never echoes
        the nonce back, so the channel is one-way and a page cannot use it as an
        oracle of its own.
        """
        frame_url = ""
        try:
            frame = source.get("frame") if isinstance(source, dict) else None
            frame_url = getattr(frame, "url", "") or ""
        except Exception:  # noqa: BLE001 — evidence only; never fails a run
            frame_url = ""
        result["witnesses"].append(
            {"value": value if isinstance(value, str) else "", "frame_url": frame_url}
        )

    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(
                    headless=True, args=list(job.get("launch_args") or [])
                )
            except Exception as exc:  # noqa: BLE001 — environment-dependent
                result["unavailable"] = True
                result["error"] = f"Chromium failed to launch: {exc}"
                return result

            # bypass_csp=False is the whole point of the CSP class: whatever
            # runs, runs under the policy the target actually served.
            context = await browser.new_context(bypass_csp=False, accept_downloads=False)
            try:
                await context.expose_binding(binding_name, _on_binding)
                cookies = job.get("cookies") or {}
                if cookies:
                    host = urlsplit(url).hostname
                    await context.add_cookies(
                        [
                            {"name": k, "value": v, "domain": host, "path": "/"}
                            for k, v in cookies.items()
                        ]
                    )

                page = await context.new_page()
                page.on("console", _record_console)
                # A dialog blocks the page forever in headless mode, and clicking
                # "OK" is an interaction. Dismiss, never accept.
                page.on("dialog", lambda d: _fire_and_forget(d.dismiss()))
                await page.route("**/*", _handle_route)

                response = await page.goto(url, wait_until="load", timeout=nav_timeout_ms)
                await page.wait_for_timeout(settle_ms)

                result["final_url"] = page.url
                if response is not None:
                    try:
                        result["response_headers"] = dict(response.headers or {})
                    except Exception:  # noqa: BLE001 — evidence only
                        result["response_headers"] = {}
                result["meta_policies"] = await _read_meta_policies(page)
            finally:
                await context.close()
                await browser.close()
    except Exception as exc:  # noqa: BLE001 — a navigation failure is a refusal
        result["error"] = str(exc)

    return result


async def _read_meta_policies(page: Any) -> list[str]:
    """Return the ``content`` of every ``<meta http-equiv=content-security-policy>``.

    Returned raw for the caller to parse: the CSP vocabulary belongs to
    :mod:`clinkz.browser.csp_policy`, and shipping a second parser here is
    exactly the drift this module is arranged to avoid.
    """
    try:
        policies = await page.eval_on_selector_all(
            "meta[http-equiv]",
            "els => els.filter(e => (e.getAttribute('http-equiv')||'').toLowerCase() "
            "=== 'content-security-policy').map(e => e.getAttribute('content')||'')",
        )
    except Exception:  # noqa: BLE001 — evidence only; never fails a run
        return []
    return [str(p) for p in (policies or [])]


def _fire_and_forget(coro: Any) -> None:
    """Schedule a coroutine from a synchronous Playwright event handler."""
    try:
        asyncio.ensure_future(coro)
    except Exception:  # noqa: BLE001
        pass


def chromium_present() -> bool:
    """Whether a downloaded Chromium exists in Playwright's browser registry.

    Deliberately a filesystem check rather than a Playwright API call.
    ``sync_playwright()`` raises when constructed inside a running event loop,
    and ``ToolResolver.is_available`` is reachable from async code — so asking
    the library "is chromium there" would itself be the thing that reports it
    missing. Launching a browser to find out is worse: an availability probe
    must not cost a process spawn.

    Honours ``PLAYWRIGHT_BROWSERS_PATH`` and falls back to the per-platform
    default registry directory used by the tools image and by developer machines
    alike. Lives here, with the rest of the code that runs where the browser is,
    so the host and the container are answering the identical question.
    """
    import os
    from pathlib import Path

    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if override in ("0", "false"):
        # 0 means "next to the package" — resolve relative to playwright itself.
        try:
            import playwright

            roots = [Path(playwright.__file__).parent / "driver" / "package" / ".local-browsers"]
        except Exception:  # noqa: BLE001
            return False
    elif override:
        roots = [Path(override)]
    else:
        local = os.environ.get("LOCALAPPDATA", "")
        roots = [
            Path(local) / "ms-playwright" if local else Path("~/.cache/ms-playwright"),
            Path("~/.cache/ms-playwright").expanduser(),
            Path("~/Library/Caches/ms-playwright").expanduser(),
        ]

    for root in roots:
        try:
            root = root.expanduser()
            if not root.is_dir():
                continue
            for entry in root.iterdir():
                if entry.name.startswith("chromium") and any(entry.rglob("chrome*")):
                    return True
        except Exception:  # noqa: BLE001 — an unreadable registry is an absent one
            continue
    return False


def oracle_available() -> bool:
    """Whether this machine can actually run the oracle: package AND browser."""
    try:
        import playwright.async_api  # noqa: F401
    except Exception:  # noqa: BLE001 — any import failure means unusable
        return False
    return chromium_present()


def main(argv: list[str]) -> int:
    """Stdin-delivered entry point: ``python3 - <base64-json-job>|--probe``.

    The job rides in ``argv`` rather than on stdin because stdin is already
    carrying this module's own source — that is how the code reaches a container
    which has Playwright but nothing of Clinkz installed.
    """
    if len(argv) < 2:
        sys.stderr.write("usage: python3 - <base64-json-job>|--probe\n")
        return 2
    if argv[1] == "--probe":
        sys.stdout.write(f"\n{RESULT_SENTINEL}{json.dumps({'available': oracle_available()})}\n")
        return 0
    try:
        job = json.loads(base64.b64decode(argv[1]).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"could not decode P7 job: {exc}\n")
        return 2
    result = asyncio.run(run_witness(job))
    sys.stdout.write(f"\n{RESULT_SENTINEL}{json.dumps(result)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
