"""Live validation of P7 — the client-side execution oracle — against DVWA.

Isolates the ONE new variable (a witnessed client-side execution) across a
SECURITY-GRADED control, which is the whole point: a primitive that confirms
identically at every level of DVWA's ladder is matching the application's benign
response, not its vulnerability. This drives the REAL methodologies against the
REAL containers — no harness, no mocks — and prints raw evidence:

  A. ``xss_d`` (DOM XSS) at low / medium / high / impossible.
     Expect execution witnessed where the sink is genuinely reachable, and
     SILENCE at impossible. A confirm at impossible is a loophole in the oracle
     and is reported as the headline, not buried.
  B. ``csp`` (Content-Security-Policy bypass) at all four levels, with the policy
     in force at execution time recorded for each.
  C. For every confirm: the nonce OUT (in the injected payload) and BACK (through
     the in-page witness channel), plus the never-injected CONTROL nonce, which
     must be silent.
  D. Inert-reflection control: a payload that lands escaped must NOT confirm.

Pre-flight (STOP + report, never a substitute): DVWA reachable and logged in, and
the P7 oracle actually installed. If the oracle is missing this script says so and
exits non-zero — it never falls back to inference.

Usage::

    python scripts/live_p7_client_execution_validation.py [--base http://localhost:8080]
"""

from __future__ import annotations

import argparse
import asyncio
import http.cookiejar
import logging
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp (lesson #22).
os.environ.setdefault("TOOL_EXEC_MODE", "local")
# P7 is opt-in; this driver is one of the callers that opts in.
os.environ.setdefault("CLIENT_ORACLE_MODE", "playwright")

from _artifact_io import write_redacted_json  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-26s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
for _noisy in ("httpcore", "httpx", "aiohttp", "urllib3", "google", "anthropic", "openai"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("p7_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent
LEVELS = ("low", "medium", "high", "impossible")


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


class DVWA:
    """Minimal authenticated DVWA client — enough to set the security level."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _open(self, req: Any) -> tuple[int, str]:
        for attempt in range(3):
            try:
                resp = self.opener.open(req, timeout=20)
                return resp.status, resp.read().decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001 - driver-side retry
                if attempt == 2:
                    raise
                log.debug("retry after %s", exc)
        raise RuntimeError("unreachable")

    def get(self, path: str) -> tuple[int, str]:
        return self._open(urllib.request.Request(self.base + path))

    def post(self, path: str, data: dict[str, str]) -> tuple[int, str]:
        body = urllib.parse.urlencode(data).encode()
        return self._open(urllib.request.Request(self.base + path, body))

    @staticmethod
    def _token(body: str) -> str:
        match = re.search(r"user_token'\s*value='([^']+)'", body)
        return match.group(1) if match else ""

    def login(self) -> bool:
        _, body = self.get("/login.php")
        _, body = self.post(
            "/login.php",
            {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": self._token(body),
            },
        )
        return "logout" in body.lower()

    def set_level(self, level: str) -> None:
        _, body = self.get("/security.php")
        self.post(
            "/security.php",
            {"security": level, "seclev_submit": "Submit", "user_token": self._token(body)},
        )

    def cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.jar}


def _print_verdict(label: str, verdict: Any) -> None:
    """Render the raw P7 evidence: nonce out, nonce back, control, policy."""
    back = next((w.value for w in verdict.witnesses if w.value == verdict.nonce), None)
    print(f"    {label}")
    print(f"      executed          : {verdict.executed}")
    print(f"      refusal           : {verdict.refusal.value} {verdict.refusal_detail[:80]}")
    print(f"      nonce OUT         : {verdict.nonce}")
    print(f"        in payload      : {verdict.injected_payload[:110]}")
    print(f"      nonce BACK        : {back!r}")
    print(f"      CONTROL (never    : {verdict.control_nonce}")
    print(f"        injected) silent: {verdict.control_silent}")
    print(f"      bypass_csp_disabled: {verdict.bypass_csp_disabled}")
    print(f"      policy in force   : {verdict.policy_in_force or '(none served)'}")
    if verdict.console_violations:
        print(f"      target console    : {verdict.console_violations[0][:90]}")


async def _witness(oracle: Any, url: str, **kw: Any) -> Any:
    args = oracle.validate_input({"url": url, **kw})
    raw = await oracle.execute(args)
    return oracle.parse_output(raw).verdict


def _make_agent(scope: Any, oracle: Any) -> Any:
    """A real ExploitAgent, so the CSP section exercises shipped code.

    The P7 CSP path takes no LLM checkpoint — route selection, the two-fetch
    nonce observation and the gadget probe are all deterministic — so a silent
    client is correct here rather than a shortcut.
    """
    from unittest.mock import AsyncMock

    from clinkz.agents.exploit import ExploitAgent
    from clinkz.llm.base import LLMClient
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    class _Silent(LLMClient):
        async def reason(self, messages: Any, tools: Any = None) -> Any:
            raise NotImplementedError

        async def research(self, query: str) -> str:
            return ""

        async def generate_text(self, prompt: str) -> str:
            return ""

    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-1")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()

    agent = ExploitAgent(
        llm=_Silent(),
        tools=[],
        scope=scope,
        state=state,
        engagement_id="p7-live",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    agent._client_execution_oracle = oracle
    return agent


async def run(base: str) -> int:
    from clinkz.browser.oracle import PlaywrightExecutionOracle
    from clinkz.browser.templates import ClientWitnessTemplateId as T
    from clinkz.browser.templates import MarkupBreakout
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

    _rule("PRE-FLIGHT")
    if not PlaywrightExecutionOracle.native_availability():
        print("STOP: the P7 oracle is not installed.")
        print("  pip install -e '.[browser]' && playwright install chromium")
        print("  Refusing to substitute inference for a witnessed execution.")
        return 2
    print("P7 oracle          : available (playwright + chromium)")

    dvwa = DVWA(base)
    if not dvwa.login():
        print(f"STOP: could not log in to DVWA at {base}.")
        return 2
    print(f"DVWA               : logged in at {base}")

    host = urllib.parse.urlsplit(base).hostname or "localhost"
    scope = EngagementScope(
        name="p7-live",
        targets=[ScopeEntry(value=host, type=ScopeType.DOMAIN)],
    )
    oracle = PlaywrightExecutionOracle(scope=scope, engagement_id="p7-live")

    results: dict[str, dict[str, Any]] = {"xss_d": {}, "csp": {}, "controls": {}}

    # ------------------------------------------------------------------
    _rule("A. DOM XSS (xss_d) — execution witnessed, per security level")
    # The sink reads location.href after 'default='; both the QUERY and the
    # FRAGMENT reach it, and only the query is visible to the server-side
    # whitelist. Shapes are ranked; the first that executes wins.
    shapes = [
        ("fragment", T.INLINE_SCRIPT, MarkupBreakout.OPTION_SELECT),
        ("query", T.INLINE_SCRIPT, MarkupBreakout.OPTION_SELECT),
        ("fragment", T.IMG_ONERROR, MarkupBreakout.OPTION_SELECT),
        ("query", T.IMG_ONERROR, MarkupBreakout.OPTION_SELECT),
    ]
    for level in LEVELS:
        dvwa.set_level(level)
        cookies = dvwa.cookies()
        print(f"\n  --- security={level} ---")
        confirmed: Any = None
        attempts = []
        for injection, template, breakout in shapes:
            url = f"{base}/vulnerabilities/xss_d/?default=English"
            verdict = await _witness(
                oracle,
                url,
                param="default",
                injection=injection,
                template_id=template.value,
                breakout=breakout.value,
                cookies=cookies,
            )
            attempts.append(
                {
                    "channel": injection,
                    "template": template.value,
                    "executed": verdict.executed,
                    "refusal": verdict.refusal.value,
                }
            )
            if verdict.executed:
                confirmed = verdict
                _print_verdict(f"CONFIRMED via {injection}/{template.value}", verdict)
                break
        if confirmed is None:
            print(f"    NOT CONFIRMED — {len(attempts)} shapes tried, none executed")
            for a in attempts:
                print(f"      {a['channel']:9s} {a['template']:14s} executed={a['executed']}")
        results["xss_d"][level] = {
            "executed": confirmed is not None,
            "attempts": attempts,
            "evidence": confirmed.evidence_summary() if confirmed else "",
        }

    # ------------------------------------------------------------------
    _rule("B. CSP bypass (csp) — did script execute UNDER THE SERVED POLICY")
    # Driven through the REAL ExploitAgent helpers, not a copy of them: the route
    # choice, the two-fetch nonce observation and the same-origin gadget probe are
    # all shipped code, so what this section reports is what an engagement does.
    from clinkz.browser.csp_policy import nonce_is_static, parse_csp

    agent = _make_agent(scope, oracle)

    for level in LEVELS:
        dvwa.set_level(level)
        agent._session_cookies = dvwa.cookies()
        agent._csp_nonce_observations.clear()
        agent._p7_gadget_for_url.clear()
        url = f"{base}/vulnerabilities/csp/"

        route, headers = await agent._p7_csp_route(url)
        policy = parse_csp(headers)
        observed, _ = await agent._p7_observed_csp_nonces(url)
        gadget = agent._p7_gadget_for_origin(url)

        print(f"\n  --- security={level} ---")
        print(f"    served policy   : {policy.raw or '(none)'}")
        print(f"    allows_inline   : {policy.allows_inline}  allows_self: {policy.allows_self}")
        print(f"    nonce observed  : {observed} static={nonce_is_static(observed)}")
        if gadget is not None:
            print(f"    script gadget   : {gadget.path}?{gadget.param}=  ({gadget.content_type})")
            print(f"      probe         : {gadget.probe_url}")
            print(f"      response head : {gadget.evidence[:90]}")
        else:
            print("    script gadget   : none found on this origin's own scripts")
        print(f"    chosen route    : {route.template_id.value if route.template_id else 'NONE'}")
        print(f"      reason        : {route.reason[:170]}")
        if route.unreachable_note:
            print(f"      note          : {route.unreachable_note[:200]}")

        verdict = None
        if route.template_id is not None:
            # A gadget route is tried as a full <script src> tag AND as a bare
            # URL, because an app that asks for a script URL puts the value
            # straight into a `src` attribute where a nested tag cannot execute.
            attempts = [route.template_id]
            if route.template_id is T.SAME_ORIGIN_SCRIPT_GADGET:
                attempts.append(T.SAME_ORIGIN_SCRIPT_GADGET_URL)
            for template in attempts:
                verdict = await _witness(
                    oracle,
                    url,
                    param="include",
                    injection="body",
                    template_id=template.value,
                    breakout=MarkupBreakout.NONE.value,
                    csp_nonce=route.csp_nonce or "",
                    gadget_path=gadget.path if gadget else "",
                    gadget_param=gadget.param if gadget else "",
                    cookies=dvwa.cookies(),
                )
                if verdict.executed:
                    break
            _print_verdict(f"{'CONFIRMED' if verdict.executed else 'NOT CONFIRMED'}", verdict)

        results["csp"][level] = {
            "policy": policy.raw,
            "nonce_static": nonce_is_static(observed),
            "gadget": (f"{gadget.path}?{gadget.param}=" if gadget else None),
            "route": route.template_id.value if route.template_id else None,
            "unreachable_note": route.unreachable_note,
            "executed": bool(verdict and verdict.executed),
            "evidence": verdict.evidence_summary() if verdict else "",
        }

    # ------------------------------------------------------------------
    _rule("C. INERT-REFLECTION CONTROL — a payload present but not executed")
    dvwa.set_level("impossible")
    verdict = await _witness(
        oracle,
        f"{base}/vulnerabilities/xss_r/",
        param="name",
        injection="query",
        template_id=T.INLINE_SCRIPT.value,
        breakout=MarkupBreakout.NONE.value,
        cookies=dvwa.cookies(),
    )
    _print_verdict("xss_r at impossible (payload escaped on the way out)", verdict)
    results["controls"]["escaped_reflection_impossible"] = {
        "executed": verdict.executed,
        "refusal": verdict.refusal.value,
    }

    # ------------------------------------------------------------------
    _rule("SUMMARY")
    print("  xss_d (DOM XSS):")
    for level in LEVELS:
        row = results["xss_d"][level]
        print(f"    {level:11s} executed={row['executed']}")
    print("  csp (policy bypass):")
    for level in LEVELS:
        row = results["csp"][level]
        print(f"    {level:11s} executed={row['executed']:<6} route={row['route']}")

    impossible_confirms = [
        name
        for name, section in (("xss_d", results["xss_d"]), ("csp", results["csp"]))
        if section["impossible"]["executed"]
    ]
    print()
    if impossible_confirms:
        print("  !! CONFIRMED AT 'impossible' IN: " + ", ".join(impossible_confirms))
        print("     Per the honesty control this is either a genuine property of the")
        print("     target at that level or a loophole in the oracle — read the raw")
        print("     evidence above and decide before trusting the label.")
    else:
        print("  No confirmation at 'impossible' in either module.")

    # Through the engine's redaction chokepoint, like every writer inside it.
    out = write_redacted_json(REPO_ROOT / "outputs" / "p7_live_validation.json", results)
    print(f"\n  raw results: {out}")

    engagement = await _emit_engagement(base, dvwa, scope, oracle, results)
    if engagement:
        print(f"  engagement  : {engagement}")
        print(f"  report      : outputs/{engagement}/report_{engagement}.json")
    return 0


async def _emit_engagement(base: str, dvwa: DVWA, scope: Any, oracle: Any, results: dict) -> str:
    """Run the REAL emission path end to end and produce a report artifact.

    Everything here is shipped code: the six-phase DOM-XSS methodology (LLM
    synthesis checkpoint included), the P7 promotion, the ``_persist_finding``
    chokepoint, and the Report Agent. The point of the artifact is that a
    reviewer can read the finding's own evidence — nonce out, nonce back,
    never-injected control, policy in force — rather than trusting this script's
    summary.

    Two security levels are exercised in ONE engagement: ``low``, where the sink
    is genuinely reachable, and ``impossible``, where it is not. A report that
    contains a finding for the first and an unproven lead for the second is the
    graded control rendered in the deliverable itself.
    """
    _rule("D. REAL ENGAGEMENT — the shipped emission path, end to end")
    try:
        from clinkz.agents.exploit import ExploitAgent, PageAnalysis
        from clinkz.agents.report import ReportAgent
        from clinkz.llm.factory import get_llm_client
        from clinkz.observability.trace import TraceWriter, set_active_trace_writer
        from clinkz.state import StateStore
        from clinkz.tools.resolver import ToolResolver
    except Exception as exc:  # noqa: BLE001
        print(f"  SKIPPED — could not import the engagement path: {exc}")
        return ""

    try:
        llm = get_llm_client("anthropic")
    except Exception as exc:  # noqa: BLE001
        print(f"  STOP — no usable Anthropic client ({exc}); refusing a keyless stand-in.")
        return ""

    db_path = REPO_ROOT / "clinkz.db"
    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "P7 client-side execution oracle — DVWA xss_d", scope.model_dump(mode="json")
        )
        # Constructed AND registered, in that order, like every other driver
        # here. Building a writer alone still creates ``outputs/<id>/`` and an
        # empty ``trace.jsonl``, so the previous bare ``TraceWriter(...)`` left a
        # bundle that looked traced and recorded nothing: engagements 18cc9af6
        # and 908b7130 each shipped a report beside a zero-byte trace.
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        agent = ExploitAgent(
            llm=llm,
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            resolver=ToolResolver(),
            persistent_kb=None,
        )
        agent._client_execution_oracle = oracle

        for level in ("low", "impossible"):
            dvwa.set_level(level)
            agent._session_cookies = dvwa.cookies()
            url = f"{base}/vulnerabilities/xss_d/?default=English"
            status, body = dvwa.get("/vulnerabilities/xss_d/?default=English")
            page = PageAnalysis(url=url, body=body, status=status, input_params=["default"])
            findings = await agent._test_xss_dom(page)
            for finding in findings:
                await agent._persist_finding(finding)
            print(
                f"  security={level:11s} findings={len(findings)} "
                f"leads={len(agent._unproven_exploit_leads)}"
            )
            for finding in findings:
                print(f"    + {finding.title}")

        # Leads are persisted by the same chokepoint the Orchestrator uses, so the
        # report renders BOTH halves of the graded control: a finding at the level
        # the sink is reachable, and an unproven lead at the level it is not.
        await agent._persist_research_leads()

        report_agent = ReportAgent(
            llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
        )
        rep = await report_agent.run(
            {
                "engagement_id": engagement_id,
                "engagement_name": "P7 client-side execution oracle — DVWA xss_d",
            }
        )
        print(f"  report json : {rep.get('json_path')}")
        print(f"  trace       : {trace.path} ({trace.events_written} events)")
        results["engagement_id"] = engagement_id
        trace.close()
        set_active_trace_writer(None)
        return engagement_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://localhost:8080")
    args = parser.parse_args()
    return asyncio.run(run(args.base))


if __name__ == "__main__":
    raise SystemExit(main())
