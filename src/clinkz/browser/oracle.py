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

## Where the browser runs, and why that is not a detail

An oracle has to observe from a machine that can reach the target, and in this
engine those are not the same machine. `TOOL_EXEC_MODE=docker` is the default —
and the only mode with a port scanner — so every tool runs inside
`clinkz-tools`, and `resolve_target_for_docker_mode` rewrites the operator's
`http://localhost:8080` into `http://clinkz-dvwa:80`: a network alias that
resolves on the shared bridge and nowhere else. A browser on the host cannot
resolve that name or route to the bridge subnet, so a host-side oracle in a real
engagement fails *every* navigation. Meanwhile local mode, where a host browser
would work, has no `nmap` or `ffuf` on a developer machine. Neither mode could
deliver P7, which is why it was reachable only from a driver that hand-built its
own conditions.

So the browser runs where the tools already run. The driving code lives in
:mod:`clinkz.browser._container_runner`, which imports nothing from Clinkz and
is delivered to the container's bare `python3` on stdin. Two runtimes call the
same functions — in-process for local mode, `docker exec` for docker mode — so
the rails a validation driver exercises are the rails a real engagement runs
under. The transport is chosen by `TOOL_EXEC_MODE`, which is also what decides
where `_run_subprocess_stdin` sends the command, so the two cannot disagree.
"""

from __future__ import annotations

import base64
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from clinkz.browser import _container_runner
from clinkz.browser._container_runner import RESULT_SENTINEL
from clinkz.browser.csp_policy import parse_csp
from clinkz.browser.templates import (
    ClientWitnessTemplateId,
    build_witness_payload,
    mint_binding_name,
)
from clinkz.browser.witness import ExecutionWitness, WitnessRefusal, WitnessVerdict
from clinkz.oob.templates import mint_nonce
from clinkz.safety.action_log import OUTCOME_REFUSED, OUTCOME_SENT
from clinkz.safety.destructive import subresource_guard_spec
from clinkz.tools.base import ToolBase, ToolOutput

#: How long to let a page settle after load before giving up on a callback. A
#: witness that needs longer than this is one an operator would not see either.
_SETTLE_MS = 900

#: Hard ceiling on a single navigation.
_NAV_TIMEOUT_MS = 20_000

#: Bound on recorded console lines, so a chatty page cannot bloat an artifact.
_MAX_CONSOLE_LINES = 25

#: Drive Playwright in this process. Correct when the target is reachable from
#: here — local exec mode, and the browser test suite's loopback fixture site.
RUNTIME_IN_PROCESS = "in_process"

#: Drive Playwright inside the tools container, which is where a docker-mode
#: engagement's rewritten target address is actually routable.
RUNTIME_CONTAINER = "container"

#: Launch flags the container runtime needs and the host runtime must not be
#: given gratuitously. Chromium's setuid sandbox cannot initialise as root
#: inside a container, and ``/dev/shm`` is 64 MB there by default — large pages
#: crash the renderer without this.
_CONTAINER_LAUNCH_ARGS = ("--no-sandbox", "--disable-dev-shm-usage")

#: Availability answers, keyed by the runtime they describe. The resolver asks
#: repeatedly while ranking a capability chain, and the container answer costs a
#: ``docker exec`` — an availability probe must not cost a process spawn per
#: call. Keyed rather than a single flag so a changed exec mode re-probes.
_AVAILABILITY_CACHE: dict[str, bool] = {}

#: Pulls the runner's delimited result out of a stream Chromium, the Playwright
#: driver and apt-installed libraries are all free to write to.
_RESULT_RE = re.compile(rf"{re.escape(RESULT_SENTINEL)}(.*)")


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
    * **Every navigation is in the action log.** Not only a mutating one: what
      is recorded is that a real engine was pointed at the target and ran its
      code, and "what did it do to my app" is answered wrongly by a log in which
      that does not appear.
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
        runtime: str | None = None,
    ) -> None:
        if scope is None:
            from clinkz.models.scope import EngagementScope

            scope = EngagementScope(name="default", targets=[])
        super().__init__(scope=scope, timeout=timeout)
        self._engagement_id = engagement_id
        self._stage = stage
        self._runtime = runtime or self.default_runtime()

    @staticmethod
    def default_runtime() -> str:
        """Where the browser should run, given how every other tool is executed.

        Tied to ``TOOL_EXEC_MODE`` rather than configured separately, because
        the target address an engagement holds is a consequence of that setting:
        in docker mode it is a container-network alias, and a browser outside
        that network cannot reach it. Letting the two be set independently would
        allow exactly one combination that silently fails every navigation.
        """
        from clinkz.config import settings

        return RUNTIME_CONTAINER if settings.tool_exec_mode == "docker" else RUNTIME_IN_PROCESS

    @classmethod
    def runtime_available(cls, runtime: str) -> bool:
        """Whether Playwright and a launchable Chromium exist for *runtime*.

        Answered about the machine the browser would actually run on. The
        previous check asked the host unconditionally, which is the wrong
        question in docker mode and answered it wrongly in both directions: it
        reported the oracle absent on a host without Playwright even though the
        tools image ships one, and would have reported it present on a
        developer host that cannot route to the target.

        Cached per runtime — see :data:`_AVAILABILITY_CACHE`.
        """
        cached = _AVAILABILITY_CACHE.get(runtime)
        if cached is not None:
            return cached
        available = (
            _container_oracle_available()
            if runtime == RUNTIME_CONTAINER
            else _container_runner.oracle_available()
        )
        _AVAILABILITY_CACHE[runtime] = available
        return available

    @classmethod
    def native_availability(cls) -> bool | None:
        """Whether the oracle is usable, for the runtime this run would use.

        Answered honestly rather than optimistically, because the caller uses it
        to decide whether a class *can* be confirmed at all. Claiming the oracle
        exists and then failing at navigation would turn a coverage gap into a
        run-time error in the middle of a methodology; claiming it never exists
        would silently disable P7 wherever it is genuinely installed.
        """
        return cls.runtime_available(cls.default_runtime())

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
            reason = (
                "Navigating this URL would mutate target state; a browser that "
                "renders it also runs its scripts, so it is refused outright."
            )
            self._log_navigation(
                outcome=OUTCOME_REFUSED,
                method=method,
                url=args["url"],
                category=WitnessRefusal.STATE_CHANGING_URL.value,
                reason=reason,
            )
            return self._refuse(verdict, WitnessRefusal.STATE_CHANGING_URL, reason, started)

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
                self._log_navigation(
                    outcome=OUTCOME_REFUSED,
                    method=method,
                    url=target_url,
                    category=decision.category,
                    reason=decision.reason,
                    signal=decision.signal,
                    body=post_body,
                )
                return self._refuse(
                    verdict,
                    WitnessRefusal.SAFETY_REFUSED,
                    f"[{decision.category}] {decision.reason}",
                    started,
                )

        def _record_attempt() -> None:
            """Record that this navigation actually went to the target.

            Placed on the outcome rather than before the call, because the two
            failure modes differ in what they did to the app.
            ORACLE_UNAVAILABLE means no browser ever launched and not one byte
            reached the target, so logging it would put an action in the log
            that never happened — and this log is the artifact an operator reads
            to answer "what did it do to my app". Every other outcome, including
            a renderer that crashed mid-load, DID hand the page to an engine
            that ran the target's code, and is recorded.
            """
            self._log_navigation(
                outcome=OUTCOME_SENT,
                method=method,
                url=target_url,
                reason=(
                    f"P7 client-side execution oracle rendered this URL in a real "
                    f"browser ({self._runtime} runtime)"
                ),
                body=post_body,
            )

        try:
            await self._render(verdict, target_url, method, post_body, args["cookies"])
        except _OracleUnavailableError as exc:
            return self._refuse(verdict, WitnessRefusal.ORACLE_UNAVAILABLE, str(exc), started)
        except Exception as exc:  # noqa: BLE001 — a browser failure is a refusal, not a verdict
            _record_attempt()
            return self._refuse(verdict, WitnessRefusal.NAVIGATION_FAILED, str(exc), started)
        else:
            _record_attempt()
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

    def _scope_hosts(self, target_url: str) -> list[str]:
        """Hostnames a subresource may be fetched from, beyond the page's origin.

        The in-browser scope rail cannot call :meth:`EngagementScope.contains`,
        because the decision has to be made synchronously inside a routing
        callback that may be running in a container with nothing of Clinkz
        importable. So the scope is projected to an explicit host list here.

        The projection is one-directional: every host it lists is in scope, and
        a host it omits is refused. Against a scope written as a CIDR or a
        wildcard that is *stricter* than ``contains`` — which is the correct
        direction for a guard whose failure mode is letting a hostile page steer
        our browser somewhere the engagement does not cover. The cost of an
        over-refusal is a subresource that does not load, recorded on the
        verdict; the cost of an under-refusal is a request to a third party.
        """
        hosts = {(urlsplit(target_url).hostname or "").lower()}
        for entry in getattr(self.scope, "targets", []) or []:
            value = getattr(entry, "value", "") or ""
            host = urlsplit(value).hostname if "://" in value else value.split(":", 1)[0]
            if host:
                hosts.add(host.lower())
        return sorted(h for h in hosts if h)

    def _build_job(
        self,
        verdict: WitnessVerdict,
        url: str,
        method: str,
        post_body: str,
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        """Assemble the JSON job the runner executes, rails included."""
        return {
            "url": url,
            "method": method,
            "post_body": post_body,
            "cookies": dict(cookies or {}),
            "binding_name": verdict.binding_name,
            "settle_ms": _SETTLE_MS,
            "nav_timeout_ms": _NAV_TIMEOUT_MS,
            "max_console_lines": _MAX_CONSOLE_LINES,
            "launch_args": (
                list(_CONTAINER_LAUNCH_ARGS) if self._runtime == RUNTIME_CONTAINER else []
            ),
            "guard": {
                "allowed_hosts": self._scope_hosts(url),
                **subresource_guard_spec(),
            },
        }

    async def _render(
        self,
        verdict: WitnessVerdict,
        url: str,
        method: str,
        post_body: str,
        cookies: dict[str, str],
    ) -> None:
        """Run one witness attempt on the selected runtime and record what it saw."""
        job = self._build_job(verdict, url, method, post_body, cookies)
        # bypass_csp=False is the whole point of the CSP class: whatever runs,
        # runs under the policy the target actually served. The runner builds
        # every context that way and has no parameter through which a caller
        # could ask otherwise.
        verdict.bypass_csp_disabled = True

        if self._runtime == RUNTIME_CONTAINER:
            observation = await self._run_in_container(job)
        else:
            observation = await _container_runner.run_witness(job)

        if observation.get("unavailable"):
            raise _OracleUnavailableError(
                observation.get("error")
                or "Playwright or its browser binary is missing where the oracle runs."
            )
        if observation.get("error"):
            raise RuntimeError(observation["error"])

        self._apply_observation(verdict, observation, url)

    async def _run_in_container(self, job: dict[str, Any]) -> dict[str, Any]:
        """Execute the runner inside the tools container and read its result back.

        The runner's own source is piped to a bare ``python3`` — the tools image
        has Playwright but no Clinkz install — and the job rides in ``argv``
        because stdin is already carrying the program. Going through
        :meth:`ToolBase._run_subprocess_stdin` is what puts the ``docker exec``
        prefix on the command, honours the kill switch, and records the whole
        invocation (source, job, stdout) in ``tool_invocations/`` like every
        other tool's.
        """
        job_arg = base64.b64encode(json.dumps(job).encode("utf-8")).decode("ascii")
        # What gets RECORDED is not what gets run. The job carries the
        # engagement's session cookies, and base64 hides them from the redaction
        # chokepoint completely: the redactor recognises credential material by
        # its shape, and an encoded blob presents no shape at all — it is one
        # opaque token rather than the `name=value` a cookie rule can match. So
        # the curl path's cookies are redacted in the trace and these would not
        # have been, landing a live PHPSESSID in a bundle whose disclosure gate
        # then truthfully reports zero credential shapes about the wrong
        # question. Cookie NAMES survive and VALUES do not, which is the rule
        # everywhere else in the engagement.
        traced_job = {**job, "cookies": {name: "[REDACTED]" for name in job.get("cookies") or {}}}
        traced_arg = base64.b64encode(json.dumps(traced_job).encode("utf-8")).decode("ascii")
        stdout, stderr, returncode = await self._run_subprocess_stdin(
            ["python3", "-", job_arg],
            _runner_source(),
            trace_cmd=["python3", "-", traced_arg],
        )
        match = _RESULT_RE.search(stdout or "")
        if match is None:
            detail = (stderr or stdout or "").strip()[:500] or f"exit code {returncode}"
            unavailable = "No module named" in detail or "ModuleNotFoundError" in detail
            return {
                **_container_runner._blank_result(),
                "unavailable": unavailable,
                "error": f"the container-side oracle returned no verdict: {detail}",
            }
        try:
            return dict(json.loads(match.group(1)))
        except json.JSONDecodeError as exc:
            return {
                **_container_runner._blank_result(),
                "error": f"could not parse the container-side oracle result: {exc}",
            }

    def _apply_observation(
        self, verdict: WitnessVerdict, observation: dict[str, Any], url: str
    ) -> None:
        """Map the runner's observation onto the verdict.

        Note what crosses this boundary and what does not. The runner reports
        *what happened* — calls received, requests refused, headers served. It
        never reports a verdict, and :meth:`WitnessVerdict.decide` is still the
        only thing that sets ``executed``, from the nonce equality checks it
        performs here. Parsing the policy is likewise done on this side, because
        the CSP vocabulary lives in :mod:`clinkz.browser.csp_policy` and a second
        parser shipped into the container would be free to drift from it.
        """
        verdict.witnesses = [
            ExecutionWitness(
                value=w.get("value") or "",
                frame_url=w.get("frame_url") or "",
            )
            for w in observation.get("witnesses") or []
        ]
        verdict.console_violations = list(observation.get("console") or [])
        verdict.blocked_navigations = list(observation.get("blocked_navigations") or [])
        verdict.blocked_subresources = list(observation.get("blocked_subresources") or [])
        verdict.blocked_mutations = list(observation.get("blocked_mutations") or [])
        verdict.final_url = observation.get("final_url") or ""

        policy = parse_csp(dict(observation.get("response_headers") or {}))
        verdict.policy_in_force = policy.raw
        verdict.policy_source = policy.source
        if not verdict.policy_in_force:
            meta = parse_csp(None, meta_policies=list(observation.get("meta_policies") or []))
            if meta.raw:
                verdict.policy_in_force = meta.raw
                verdict.policy_source = "meta"

        # A refused navigation leaves Chromium on an internal error page, so the
        # recorded landing URL would otherwise read as a failed load rather than
        # as the rail working. Say which it was.
        if verdict.blocked_navigations and verdict.final_url.startswith("chrome-error:"):
            verdict.final_url = (
                f"{url} (page attempted to navigate away; refused — browser left on an error page)"
            )

    def _log_navigation(
        self,
        *,
        outcome: str,
        method: str,
        url: str,
        category: str = "",
        reason: str = "",
        signal: str = "",
        body: str = "",
    ) -> None:
        """Write one navigation to the engagement's action log, if one is active.

        No-ops without a governor, which is the same rule every other rail
        follows: outside an engagement — a smoke test, a replay, a driver —
        there is no log to write to and the oracle behaves byte-identically.

        Never raises, for the same reason :meth:`ToolBase._emit_trace_records`
        does not: recording what happened must not be able to change what
        happens. A failure here would otherwise surface as a NAVIGATION_FAILED
        verdict — an oracle problem misreported as an observation about the
        target.
        """
        from clinkz.safety.governor import get_active_governor

        governor = get_active_governor()
        if governor is None:
            return
        try:
            governor.record_navigation(
                outcome=outcome,
                method=method,
                url=url,
                stage=self._stage or self.category,
                category=category,
                reason=reason,
                signal=signal,
                body=body,
            )
        except Exception as exc:  # noqa: BLE001 — logging must never fail a run
            self._logger.warning("Could not record P7 navigation in the action log: %s", exc)

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
        """Parse the JSON verdict into a structured tool output.

        **A reply with no verdict is the oracle not reporting, not the oracle
        reporting nothing.** ``model_validate(data.get("verdict") or {})``
        coalesced an absent key into a DEFAULT verdict — ``executed=False``,
        ``control_silent=True``, ``refusal=NONE`` — and the old success test
        (``refusal in (NONE, NOT_EXECUTED)``) then returned ``success=True``. A
        runner that produced nothing was indistinguishable from a browser that
        loaded the page and saw no script run.

        P7 only ever promotes, so nothing is manufactured into a finding by this.
        The cost lands one layer later, in the client deliverable: a run counted
        as an execution witness that never happened pushes the report's
        *What was NOT tested* section toward "the oracle ran and found nothing"
        when the honest answer is that this attempt never reported — the two
        categories this engine deliberately keeps apart.

        Both no-verdict shapes therefore refuse:
        :attr:`~clinkz.browser.witness.WitnessRefusal.NO_VERDICT_REPORTED`, which
        is an oracle failure and so is excluded from
        :attr:`~clinkz.browser.witness.WitnessVerdict.is_target_statement` like
        every other one.
        """
        try:
            data = json.loads(raw_output)
            if not isinstance(data, dict):
                raise TypeError(f"runner reply is {type(data).__name__}, not an object")
            reported = data.get("verdict")
            if not isinstance(reported, dict) or not reported:
                raise ValueError("runner reply carries no verdict")
            verdict = WitnessVerdict.model_validate(reported)
        except Exception as exc:  # noqa: BLE001
            # Bounded, because ``exc`` is not always engine-authored: a pydantic
            # ValidationError over the runner's verdict quotes the offending
            # ``input_value``, and two of that model's fields hold TARGET-authored
            # bytes (``policy_in_force``, ``console_violations``). Same reason
            # ``raw_output`` is sliced two lines down, and the same lesson as the
            # pypdf ``str(exc)`` that republished document bytes into a gate
            # report. ``refusal_detail`` reaches the trace and the lead, so an
            # unbounded target-influenced string must not ride it.
            detail = f"the P7 runner produced no usable verdict: {exc}"[:500]
            return ClientExecutionOutput(
                tool_name=self.name,
                success=False,
                raw_output=raw_output[:2000],
                error=detail,
                verdict=WitnessVerdict(
                    refusal=WitnessRefusal.NO_VERDICT_REPORTED, refusal_detail=detail
                ),
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


def _runner_source() -> str:
    """The runner module's source, as it will be piped into the container.

    Read from disk on each use rather than cached, so an edit to the runner
    takes effect without a restart — and, more importantly, so there is exactly
    one artifact: the file the in-process runtime imports is byte-for-byte the
    file the container executes.
    """
    return (Path(__file__).parent / "_container_runner.py").read_text(encoding="utf-8")


def _container_oracle_available() -> bool:
    """Whether the tools container has Playwright and a launchable Chromium.

    Asks the container the same question :func:`_container_runner.oracle_available`
    answers locally, by sending it that very function. Synchronous and short —
    the resolver calls availability from both sync and async contexts, so this
    must not need an event loop, and :data:`_AVAILABILITY_CACHE` keeps it to one
    ``docker exec`` per engagement.

    Any failure — no docker, container stopped, no Playwright inside — is
    ``False``: an oracle that cannot be reached is an absent one, and the
    affected classes keep their unproven leads.
    """
    import subprocess

    from clinkz.config import settings

    try:
        result = subprocess.run(
            ["docker", "exec", "-i", settings.docker_container, "python3", "-", "--probe"],
            input=_runner_source().encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
    except Exception:  # noqa: BLE001 — no docker, no container, no oracle
        return False
    match = _RESULT_RE.search(result.stdout.decode("utf-8", errors="replace"))
    if match is None:
        return False
    try:
        return bool(json.loads(match.group(1)).get("available"))
    except json.JSONDecodeError:
        return False


__all__ = ["ClientExecutionOutput", "PlaywrightExecutionOracle"]
