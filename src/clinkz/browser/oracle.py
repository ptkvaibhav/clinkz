"""The P7 client-side execution oracle — a headless browser that witnesses.

## Why a browser at all

Three classes were unconfirmable by construction. DOM-based XSS has no server
response to inspect: the sink runs in the client, so the engine could prove a
controllable source reaches a dangerous sink and never that anything executed.
A reflected or stored payload landing in a client-rendered context has the same
gap. And a Content-Security-Policy is a statement about what a *browser* will
do, so "is this policy bypassable" is not a question an HTTP client can answer
at all. Each of those recorded an honest lead. This module is the missing
observation, and it changes nothing else about those classes.

## Why Playwright

The stack is Python + Docker and the observation needed is "did script run",
which requires driving a real engine, not parsing HTML. Playwright is the fit:
it ships a first-class async Python API (the codebase is asyncio throughout),
`playwright install --with-deps chromium` provisions a browser that actually
launches inside the existing Kali tools image, and — decisively — it exposes
:meth:`BrowserContext.expose_binding`, which installs a Python-backed function
in the page's main world *before any page script runs*. That binding is the
witness channel, and no other driver offers it as cleanly. Selenium would need a
separate grid and gives no equivalent in-page callback; a raw CDP client would
mean hand-rolling the same thing. The tool is nonetheless resolved through
:class:`~clinkz.tools.resolver.ToolResolver` by capability with a declared
fallback chain, so nothing in the engine names Playwright.

## Why the channel is a binding and not a network callback

P6 confirms out-of-band because a blind server-side capability has no in-band
channel. Reusing that here — have the payload `fetch()` a collaborator — would
be a mistake, because a CSP can forbid `connect-src` and `img-src`
independently of `script-src`. Under such a policy a script that genuinely
executed would produce no callback, and the oracle would report "did not
execute" about a page that did. For the CSP class that is precisely the wrong
answer, so the channel must not be a network operation.

A function call is not governed by any CSP directive. What it still requires is
JavaScript actually running — which is the entire question — so the channel
measures execution and nothing else. The spike that motivated this design
recorded, against a page serving `script-src 'none'`, a silent channel and a
console violation; against a policy carrying both `'unsafe-inline'` and a nonce,
the bare inline script was refused and only the nonced one called back.

## Unforgeability, stated exactly

A confirmation requires a Clinkz-minted single-use nonce to arrive as the
argument of a call to a Clinkz-minted, per-load-random function name, while a
second nonce minted in the same call and injected nowhere stays silent. Inert
reflected bytes cannot call a function; neither can escaped text, a text node,
or a payload sitting in an attribute the parser never executes. That is the
confounder this primitive structurally excludes, and it is the one that made
every previous DOM-XSS "confirmation" a phantom.

The residual, stated rather than glossed: a page whose own trusted script chose
to enumerate `window`, find the randomised binding, read the nonce back out of
its own DOM and call it, could manufacture a signal. That requires the target to
run code written against this oracle. P6 has no comparable residual, because
nothing on the target ever sees the collaborator's nonce channel; this is the
price of an in-browser channel and the reason the binding name is random per
load rather than fixed.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

from clinkz.browser.csp_policy import parse_csp, same_origin
from clinkz.browser.templates import (
    ClientWitnessTemplateId,
    build_witness_payload,
    mint_binding_name,
)
from clinkz.browser.witness import ExecutionWitness, WitnessRefusal, WitnessVerdict
from clinkz.oob.templates import mint_nonce
from clinkz.tools.base import ToolBase, ToolOutput

#: How long to let a page settle after load before giving up on a callback. A
#: witness that needs longer than this is one an operator would not see either.
_SETTLE_MS = 900

#: Hard ceiling on a single navigation.
_NAV_TIMEOUT_MS = 20_000

#: Bound on recorded console lines, so a chatty page cannot bloat an artifact.
_MAX_CONSOLE_LINES = 25


class ClientExecutionOutput(ToolOutput):
    """Structured result of one P7 run."""

    verdict: WitnessVerdict = WitnessVerdict()


class PlaywrightExecutionOracle(ToolBase):
    """Load a URL in a real browser and witness whether injected script executes.

    Every P1 production rail applies, and the browser is treated as the new and
    genuinely more dangerous surface it is — a thing that fetches subresources,
    follows redirects, and runs code the target wrote:

    * **Scope before navigation.** :meth:`validate_input` calls
      :meth:`ToolBase._check_scope` before the browser is even launched, and
      every subresource the page requests is checked again at the interception
      seam. A page cannot steer this browser at a host the engagement does not
      cover.
    * **The governor decides.** The navigation goes through
      :meth:`~clinkz.safety.governor.EngagementGovernor.authorize` exactly like
      an HTTP probe: rate limit, concurrency slot, kill switch, window, and the
      destructive classifier. A POST navigation is recorded in the action log,
      so "what did it do to my app" still answers correctly.
    * **Nothing is clicked and nothing is submitted.** This oracle never calls
      ``click``, ``fill``, ``press`` or ``submit``. A form on the rendered page
      is inert as far as it is concerned, which is what keeps a browser from
      becoming a state-changing surface the destructive vocabulary never sees.
    * **One navigation.** Any attempt to navigate away after the first — a
      meta-refresh, a script-driven `location` assignment, a logout link — is
      aborted at the interception seam.
    * **CSP is never bypassed.** The context is built with ``bypass_csp=False``
      and the verdict records that it was, because an oracle that disabled CSP
      would confirm every policy ever written.
    """

    capabilities = [
        "client_side_execution",
        "javascript_execution_witness",
        "headless_browser",
        "dom_rendering",
    ]
    category = "exploit"

    def __init__(
        self,
        scope: Any = None,
        timeout: int = 60,
        engagement_id: str | None = None,
        stage: str = "exploit",
    ) -> None:
        if scope is None:
            from clinkz.models.scope import EngagementScope

            scope = EngagementScope(name="default", targets=[])
        super().__init__(scope=scope, timeout=timeout)
        self._engagement_id = engagement_id
        self._stage = stage

    @classmethod
    def native_availability(cls) -> bool | None:
        """Whether the Python package AND a launchable browser are both present.

        Answered honestly rather than optimistically, because the caller uses it
        to decide whether a class *can* be confirmed at all. Claiming the oracle
        exists and then failing at navigation would turn a coverage gap into a
        run-time error in the middle of a methodology; claiming it never exists
        would silently disable P7 wherever it is genuinely installed.
        """
        try:
            import playwright.async_api  # noqa: F401
        except Exception:  # noqa: BLE001 — any import failure means unusable
            return False
        return _chromium_binary_present()

    @property
    def name(self) -> str:
        return "playwright_chromium"

    @property
    def description(self) -> str:
        return (
            "Render a URL in a real headless browser and witness whether an "
            "injected payload EXECUTES, via a single-use nonce returned through "
            "a Clinkz-owned in-page channel."
        )

    def get_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Absolute URL to render. Scope-checked before navigation.",
                    },
                    "template_id": {
                        "type": "string",
                        "description": (
                            "Which CLINKZ-OWNED witness template to build. The "
                            "payload string itself is never accepted from a caller."
                        ),
                        "default": ClientWitnessTemplateId.INLINE_SCRIPT.value,
                    },
                    "breakout": {
                        "type": "string",
                        "description": "Enclosing element to close first (closed vocabulary).",
                        "default": "none",
                    },
                    "injection": {
                        "type": "string",
                        "description": (
                            "Where the payload rides: 'query' (a URL parameter), "
                            "'fragment' (after '#', never sent to the server), "
                            "'body' (a form-encoded POST navigation), or 'stored' "
                            "(the payload is ALREADY on the target — the oracle "
                            "only navigates and observes)."
                        ),
                        "default": "query",
                    },
                    "nonce": {
                        "type": "string",
                        "description": (
                            "Pre-minted witness nonce, required by 'stored': the "
                            "caller had to build and store the payload before this "
                            "call, so it owns the nonce. Shape-validated here."
                        ),
                        "default": "",
                    },
                    "binding": {
                        "type": "string",
                        "description": "Pre-minted binding name that goes with 'nonce'.",
                        "default": "",
                    },
                    "param": {
                        "type": "string",
                        "description": "Parameter name carrying the payload.",
                        "default": "",
                    },
                    "csp_nonce": {
                        "type": "string",
                        "description": "Nonce to reuse.",
                        "default": "",
                    },
                    "gadget_path": {"type": "string", "description": "Same-origin gadget path."},
                    "gadget_param": {"type": "string", "description": "Gadget callback param."},
                    "cookies": {
                        "type": "object",
                        "description": "Session cookies to install before navigating.",
                        "default": {},
                    },
                },
                "required": ["url"],
            },
        }

    def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
        """Validate and scope-check BEFORE any browser is launched."""
        url = (args.get("url") or "").strip()
        if not url:
            raise ValueError("'url' is required for the client-side execution oracle")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"Invalid URL for browser navigation: {url}")

        # Scope enforcement before any network activity, per the tool contract.
        self._check_scope(url)

        injection = (args.get("injection") or "query").lower()
        if injection not in ("query", "fragment", "body", "stored"):
            raise ValueError(f"unknown injection channel: {injection!r}")

        # 'stored' means the payload already reached the target by some other
        # carrier, so the nonce was necessarily minted before this call. Both
        # halves are required together: a nonce without its binding names a
        # function the stored payload never calls.
        nonce = (args.get("nonce") or "").strip()
        binding = (args.get("binding") or "").strip()
        if injection == "stored":
            from clinkz.browser.templates import is_valid_binding
            from clinkz.oob.templates import is_valid_nonce

            if not is_valid_nonce(nonce) or not is_valid_binding(binding):
                raise ValueError(
                    "the 'stored' channel requires the pre-minted 'nonce' and "
                    "'binding' that were built into the stored payload"
                )
        elif nonce or binding:
            raise ValueError(
                "'nonce'/'binding' may only be supplied for the 'stored' channel; "
                "every other channel mints its own so the value cannot predate the probe"
            )

        try:
            template_id = ClientWitnessTemplateId(
                args.get("template_id") or ClientWitnessTemplateId.INLINE_SCRIPT.value
            )
        except ValueError as exc:
            raise ValueError(f"unknown witness template: {args.get('template_id')!r}") from exc

        return {
            "url": url,
            "template_id": template_id,
            "breakout": args.get("breakout") or "none",
            "injection": injection,
            "param": args.get("param") or "",
            "csp_nonce": args.get("csp_nonce") or "",
            "gadget_path": args.get("gadget_path") or "",
            "gadget_param": args.get("gadget_param") or "",
            "cookies": args.get("cookies") or {},
            "nonce": nonce,
            "binding": binding,
        }

    async def execute(self, args: dict[str, Any]) -> str:
        """Run one witness attempt and return the verdict as JSON."""
        from clinkz.browser.templates import MarkupBreakout

        verdict = WitnessVerdict(navigated_url=args["url"])
        started = time.monotonic()

        # The navigation channel decides the method: only a body injection needs
        # a POST, and a POST is what the governor classifies and logs.
        method = "POST" if args["injection"] == "body" else "GET"
        # A 'stored' run is a plain read of the read-back page: the write already
        # happened, through the carrier that was authorized to make it.

        # Rail: never navigate somewhere that mutates state.
        from clinkz.agents._url_safety import is_state_changing_url

        if is_state_changing_url(args["url"]):
            return self._refuse(
                verdict,
                WitnessRefusal.STATE_CHANGING_URL,
                "Navigating this URL would mutate target state; a browser that "
                "renders it also runs its scripts, so it is refused outright.",
                started,
            )

        if args["injection"] == "stored":
            # The payload is already on the target; this run only navigates and
            # watches. The nonce came from whoever stored it, and the control
            # below is still minted HERE — so the admissibility argument is
            # unchanged: a second nonce that no carrier ever touched must be
            # silent for the first one to count.
            binding, nonce = args["binding"], args["nonce"]
            payload = "(stored on the target by a prior submission)"
        else:
            try:
                binding = mint_binding_name()
                payload = build_witness_payload(
                    args["template_id"],
                    nonce := mint_nonce(),
                    binding,
                    breakout=MarkupBreakout(args["breakout"]),
                    csp_nonce=args["csp_nonce"] or None,
                    gadget_path=args["gadget_path"] or None,
                    gadget_param=args["gadget_param"] or None,
                )
            except ValueError as exc:
                return self._refuse(verdict, WitnessRefusal.SAFETY_REFUSED, str(exc), started)

        verdict.nonce = nonce
        # The control: minted here, carried by nothing, injected nowhere. Its
        # silence is what makes a positive admissible.
        verdict.control_nonce = mint_nonce()
        verdict.binding_name = binding
        verdict.injected_payload = payload
        verdict.template_id = args["template_id"].value

        target_url, post_body = self._build_request(args, payload)
        verdict.navigated_url = target_url

        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is not None:
            decision = await governor.authorize(
                method,
                target_url,
                body=post_body or "",
                stage=self._stage or self.category,
                field_names=[args["param"]] if args["param"] and method == "POST" else None,
            )
            if not decision.allowed:
                return self._refuse(
                    verdict,
                    WitnessRefusal.SAFETY_REFUSED,
                    f"[{decision.category}] {decision.reason}",
                    started,
                )

        try:
            await self._render(verdict, target_url, method, post_body, args["cookies"])
        except _OracleUnavailableError as exc:
            return self._refuse(verdict, WitnessRefusal.ORACLE_UNAVAILABLE, str(exc), started)
        except Exception as exc:  # noqa: BLE001 — a browser failure is a refusal, not a verdict
            return self._refuse(verdict, WitnessRefusal.NAVIGATION_FAILED, str(exc), started)
        finally:
            if governor is not None:
                governor.release()

        verdict.decide()
        verdict.duration_ms = round((time.monotonic() - started) * 1000, 1)

        if governor is not None and verdict.final_url:
            governor.observe_response(
                status=200,
                headers={"content-security-policy": verdict.policy_in_force}
                if verdict.policy_in_force
                else {},
                body="",
                session_bearing=bool(args["cookies"]),
            )

        return json.dumps({"verdict": verdict.model_dump(mode="json")}, default=str)

    @staticmethod
    def _url_place(payload: str, *, in_query: bool) -> str:
        """Encode a payload for a URL as LITTLE as correctness allows.

        This is a correctness requirement of DOM sinks, not a style choice. The
        common sink reads ``location.href`` and passes it through ``decodeURI``,
        which by definition does NOT decode the reserved set
        (``; / ? : @ & = + $ , #``). So a fully percent-encoded payload arrives at
        such a sink with ``%2F`` still spelled ``%2F``, and ``</script>`` never
        reforms — the probe is inert for a reason that has nothing to do with the
        target's defences, and the class reports "not exploitable" about a page
        that is.

        Encoding only what would otherwise break the URL leaves the browser to
        normalise the rest (it percent-encodes ``<``, ``>`` and ``"`` on its own),
        and ``decodeURI`` reverses exactly that set. Measured against a live
        ``decodeURI`` sink: over-encoded payloads executed at no security level,
        minimally-encoded ones executed at every level the sink was reachable.

        Args:
            payload: The witness payload.
            in_query: Whether it rides in the query string, where ``&`` would
                otherwise start a new parameter.
        """
        from urllib.parse import quote

        # `#` would terminate the component; `%` would corrupt an existing escape;
        # whitespace is not legal in a URL. `&` additionally splits a query.
        unsafe = "#%& " if in_query else "#% "
        safe = "".join(chr(c) for c in range(33, 127) if chr(c) not in unsafe)
        return quote(payload, safe=safe)

    def _build_request(self, args: dict[str, Any], payload: str) -> tuple[str, str]:
        """Place the payload in its channel; return ``(url, post_body)``."""
        from urllib.parse import parse_qsl, urlencode, urlunsplit

        parts = urlsplit(args["url"])
        param = args["param"]

        if args["injection"] == "body":
            body = urlencode({param: payload}) if param else ""
            return args["url"], body

        if args["injection"] == "stored":
            # Nothing to place — navigate to the read-back page as it stands.
            return args["url"], ""

        if args["injection"] == "fragment":
            # A fragment is never transmitted to the server — which is exactly why
            # it reaches a client-side sink that a server-side filter cannot see.
            return (
                urlunsplit(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        parts.query,
                        self._url_place(payload, in_query=False),
                    )
                ),
                "",
            )

        # The other parameters are re-encoded normally; only the one carrying the
        # payload is placed minimally, and it is appended last so its encoding
        # survives instead of being normalised away by ``urlencode``.
        others = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
        query = urlencode(others)
        if param:
            placed = f"{param}={self._url_place(payload, in_query=True)}"
            query = f"{query}&{placed}" if query else placed
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), ""

    async def _render(
        self,
        verdict: WitnessVerdict,
        url: str,
        method: str,
        post_body: str,
        cookies: dict[str, str],
    ) -> None:
        """Drive the browser. The only place Playwright is imported."""
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise _OracleUnavailableError(
                "Playwright is not installed. Install the optional oracle with "
                "`pip install -e '.[browser]' && playwright install chromium`."
            ) from exc

        witnesses: list[ExecutionWitness] = []
        console: list[str] = []
        navigated = {"count": 0}
        blocked_navs: list[str] = []
        blocked_subs: list[str] = []

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True)
            except Exception as exc:  # pragma: no cover - environment-dependent
                raise _OracleUnavailableError(
                    f"Chromium failed to launch ({exc}). Run `playwright install chromium`."
                ) from exc

            # bypass_csp=False is the whole point of the CSP class: whatever runs,
            # runs under the policy the target actually served.
            context = await browser.new_context(bypass_csp=False, accept_downloads=False)
            verdict.bypass_csp_disabled = True
            try:
                await self._install_channel(context, verdict, witnesses)
                if cookies:
                    await context.add_cookies(
                        [
                            {"name": k, "value": v, "domain": urlsplit(url).hostname, "path": "/"}
                            for k, v in cookies.items()
                        ]
                    )

                page = await context.new_page()
                page.on("console", lambda m: self._record_console(console, m))
                # A dialog blocks the page forever in headless mode, and clicking
                # "OK" is an interaction. Dismiss, never accept.
                page.on("dialog", lambda d: _fire_and_forget(d.dismiss()))

                await page.route(
                    "**/*",
                    lambda route, request: _fire_and_forget(
                        self._intercept(
                            route,
                            request,
                            url,
                            method,
                            post_body,
                            navigated,
                            blocked_navs,
                            blocked_subs,
                        )
                    ),
                )

                response = await page.goto(url, wait_until="load", timeout=_NAV_TIMEOUT_MS)
                await page.wait_for_timeout(_SETTLE_MS)

                verdict.final_url = page.url
                if response is not None:
                    policy = parse_csp(dict(response.headers or {}))
                    verdict.policy_in_force = policy.raw
                    verdict.policy_source = policy.source
                if not verdict.policy_in_force:
                    await self._read_meta_policy(page, verdict)
            finally:
                await context.close()
                await browser.close()

        verdict.witnesses = witnesses
        verdict.console_violations = console
        verdict.blocked_navigations = blocked_navs
        verdict.blocked_subresources = blocked_subs

        # A refused navigation leaves Chromium on an internal error page, so the
        # recorded landing URL would otherwise read as a failed load rather than
        # as the rail working. Say which it was.
        if blocked_navs and verdict.final_url.startswith("chrome-error:"):
            verdict.final_url = (
                f"{url} (page attempted to navigate away; refused — browser left on an error page)"
            )

    async def _install_channel(
        self,
        context: Any,
        verdict: WitnessVerdict,
        witnesses: list[ExecutionWitness],
    ) -> None:
        """Install the Clinkz-owned witness function into every frame's main world.

        The handler is Python. It records the call and returns nothing the page
        can learn from — in particular it never echoes the nonce back, so the
        channel is one-way and a page cannot use it as an oracle of its own.
        """

        def _on_call(source: dict[str, Any], value: Any = "") -> None:
            frame_url = ""
            try:
                frame = source.get("frame") if isinstance(source, dict) else None
                frame_url = getattr(frame, "url", "") or ""
            except Exception:  # noqa: BLE001 — evidence only; never fails a run
                frame_url = ""
            witnesses.append(
                ExecutionWitness(value=value if isinstance(value, str) else "", frame_url=frame_url)
            )

        await context.expose_binding(verdict.binding_name, _on_call)

    async def _intercept(
        self,
        route: Any,
        request: Any,
        target_url: str,
        method: str,
        post_body: str,
        navigated: dict[str, int],
        blocked_navs: list[str],
        blocked_subs: list[str],
    ) -> None:
        """The per-request rail: scope, one-navigation, and the POST rewrite.

        A rendered page is hostile input, and the most dangerous thing it can do
        to a browser under our control is send it somewhere. So every request is
        checked here, not only the one we asked for.
        """
        try:
            url = request.url
            is_nav = request.is_navigation_request()

            if is_nav:
                navigated["count"] += 1
                # Only the first navigation is ours. Anything after it was
                # decided by the page.
                if navigated["count"] > 1:
                    if len(blocked_navs) < 10:
                        blocked_navs.append(url)
                    self._logger.info("P7: refusing page-initiated navigation to %s", url)
                    await route.abort()
                    return
                if method == "POST" and url.split("#")[0] == target_url.split("#")[0]:
                    await route.continue_(
                        method="POST",
                        post_data=post_body,
                        headers={
                            **request.headers,
                            "content-type": "application/x-www-form-urlencoded",
                        },
                    )
                    return

            # Subresources: same-origin always, anything else must be in scope.
            if not same_origin(url, target_url) and not self.scope.contains(url):
                if len(blocked_subs) < 20:
                    blocked_subs.append(url)
                self._logger.debug("P7: aborting out-of-scope subresource %s", url)
                await route.abort()
                return

            await route.continue_()
        except Exception:  # noqa: BLE001 — a routing error must not hang the page
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _record_console(console: list[str], message: Any) -> None:
        """Record CSP-related console lines as TARGET-AUTHORED evidence only."""
        if len(console) >= _MAX_CONSOLE_LINES:
            return
        try:
            text = message.text
        except Exception:  # noqa: BLE001
            return
        if "Content Security Policy" in text or "Refused to" in text:
            console.append(text[:300])

    @staticmethod
    async def _read_meta_policy(page: Any, verdict: WitnessVerdict) -> None:
        """Read a `<meta http-equiv>` CSP when no header carried one."""
        try:
            policies = await page.eval_on_selector_all(
                "meta[http-equiv]",
                "els => els.filter(e => (e.getAttribute('http-equiv')||'').toLowerCase() "
                "=== 'content-security-policy').map(e => e.getAttribute('content')||'')",
            )
        except Exception:  # noqa: BLE001
            return
        parsed = parse_csp(None, meta_policies=list(policies or []))
        if parsed.raw:
            verdict.policy_in_force = parsed.raw
            verdict.policy_source = "meta"

    def _refuse(
        self,
        verdict: WitnessVerdict,
        refusal: WitnessRefusal,
        detail: str,
        started: float,
    ) -> str:
        """Return a refusal verdict — never a negative result about the target."""
        verdict.executed = False
        verdict.refusal = refusal
        verdict.refusal_detail = detail
        verdict.duration_ms = round((time.monotonic() - started) * 1000, 1)
        self._logger.info("P7 refusal [%s]: %s", refusal.value, detail)
        return json.dumps({"verdict": verdict.model_dump(mode="json")}, default=str)

    def parse_output(self, raw_output: str) -> ClientExecutionOutput:
        """Parse the JSON verdict into a structured tool output."""
        try:
            data = json.loads(raw_output)
            verdict = WitnessVerdict.model_validate(data.get("verdict") or {})
        except Exception as exc:  # noqa: BLE001
            return ClientExecutionOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output[:2000],
                error=f"could not parse P7 verdict: {exc}",
            )
        return ClientExecutionOutput(
            tool_name=self.name,
            success=verdict.refusal in (WitnessRefusal.NONE, WitnessRefusal.NOT_EXECUTED),
            raw_output=raw_output[:4000],
            error=verdict.refusal_detail if not verdict.is_target_statement else "",
            verdict=verdict,
        )


class _OracleUnavailableError(RuntimeError):
    """Playwright or its browser binary is missing. A coverage gap, not a verdict."""


def _chromium_binary_present() -> bool:
    """Whether a downloaded Chromium exists in Playwright's browser registry.

    Deliberately a filesystem check rather than a Playwright API call.
    ``sync_playwright()`` raises when constructed inside a running event loop,
    and :meth:`ToolResolver.is_available` is reachable from async code — so
    asking the library "is chromium there" would itself be the thing that
    reports it missing. Launching a browser to find out is worse: an
    availability probe must not cost a process spawn.

    Honours ``PLAYWRIGHT_BROWSERS_PATH`` and falls back to the per-platform
    default registry directory used by the tools image and by developer
    machines alike.
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


def _fire_and_forget(coro: Any) -> None:
    """Schedule a coroutine from a sync Playwright event handler."""
    import asyncio

    try:
        asyncio.ensure_future(coro)
    except Exception:  # noqa: BLE001
        pass


__all__ = ["ClientExecutionOutput", "PlaywrightExecutionOracle"]
