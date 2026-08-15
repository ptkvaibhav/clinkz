"""Live validation of the D8 auth-bypass fixes (A + B) against OWASP Juice Shop.

Drives the REAL carrier and the REAL oracle — no mocked HTTP, no mocked verdict.
The only test double is a passive TEE around ``HTTPClientTool.execute`` that
records each dispatched request and delegates to the genuine implementation, so
the evidence below quotes what actually went on the wire.

What is being validated
-----------------------
**FIX A** — ``AUTH_BYPASS`` never reaches the phase-4 LLM checkpoint. Asserted on
the CALL, not the result: the LLM is replaced with a spy that raises, so a
version that consults a model and discards its answer fails here.

**FIX B** — the identity suppression is keyed on credential POSSESSION rather
than on identity coincidence. Juice Shop is the exact adversarial case: the
tautology returns a token for ``admin@juice-sh.op``, which is also the account
this engagement authenticates as. Keyed on coincidence, the real bypass is
suppressed. Keyed on possession, it confirms — and a request that really does
hand over that account's password is still suppressed.

The five controls, all required
-------------------------------
1. inverted tautology ``OR '1'='2'``        → refuse   (payload)
2. benign credential arm                    → refuse   (oracle)
3. B-CONTROL: sessionless arm submitting a VALID credential through the
   identical arm structure → refuse, ``principal_is_an_identity_we_supplied``
   (suppression). If this arm confirms, FIX B is wrong and the run is void.
4. a never-injected nonce                   → absent from every evidence field
5. a non-login endpoint, same payload       → silent

Usage::

    python scripts/live_d8_auth_bypass_validation.py [--base http://localhost:3000]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp and the
# target is not rewritten to a docker-network alias this process cannot reach.
os.environ.setdefault("TOOL_EXEC_MODE", "local")

from _artifact_io import (  # noqa: E402 — after TOOL_EXEC_MODE, which it imports clinkz behind
    redacted,
    register_lab_credential,
    write_redacted_json,
)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-30s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
for _noisy in ("httpcore", "httpx", "aiohttp", "urllib3", "google", "anthropic", "openai"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("d8_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent

ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASSWORD = "admin123"
LOGIN_PATH = "/rest/user/login"
SEARCH_PATH = "/rest/products/search"

# A driver that hardcodes a password is a third intake route, so it registers on
# the way in like the other two. Shape redaction is always on and would remove
# the session token regardless; a plaintext password has no shape and is removed
# only because it is registered here.
register_lab_credential(ADMIN_PASSWORD)


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _post_json(url: str, body: dict[str, Any]) -> tuple[int, str]:
    req = urllib.request.Request(  # noqa: S310 — fixed http scheme, local lab
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except OSError as exc:
        return 0, str(exc)


class RequestTee:
    """Records every request dispatched through the HTTP chokepoint.

    A tee, not a substitute: the real ``execute`` still runs and the real
    response comes back. It exists so the evidence can quote the request body
    verbatim — including the password each arm submitted — rather than
    describing it.
    """

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self._original: Any = None

    def install(self) -> None:
        from clinkz.tools.http_client import HTTPClientTool

        self._original = HTTPClientTool.execute
        original = self._original
        sent = self.sent

        async def _teed(inner_self: Any, args: dict[str, Any]) -> str:
            raw = await original(inner_self, args)
            sent.append({"request": dict(args), "raw_response": raw})
            return raw

        HTTPClientTool.execute = _teed  # type: ignore[method-assign]

    def remove(self) -> None:
        from clinkz.tools.http_client import HTTPClientTool

        if self._original is not None:
            HTTPClientTool.execute = self._original  # type: ignore[method-assign]

    def since(self, mark: int) -> list[dict[str, Any]]:
        return self.sent[mark:]

    def mark(self) -> int:
        return len(self.sent)


def _render_exchange(entry: dict[str, Any], *, body_limit: int = 700) -> str:
    """One exchange, verbatim except for credential material.

    Redacted like the file this driver writes: a run piped through ``tee``
    produces a durable artifact too, and ``outputs/`` already holds three such
    logs. What the arms are asserting survives it — a fingerprint still shows
    that THIS token came back where THAT one did not, and ``[REDACTED]`` in a
    body still shows the field was populated.
    """
    req = redacted(entry["request"])
    try:
        parsed = redacted(json.loads(entry["raw_response"]))
    except (ValueError, TypeError):
        parsed = {}
    lines = [
        f"    > {req.get('method')} {req.get('url')}",
        f"    > headers        : {req.get('headers') or {}}",
        f"    > cookies        : {req.get('cookies') or {}}",
        f"    > no_session     : {req.get('no_session')}",
        f"    > body           : {req.get('body') or '(none)'}",
        f"    < status         : {parsed.get('status_code')}",
        f"    < set-cookie     : "
        f"{(parsed.get('response_headers') or {}).get('Set-Cookie', '(none)')}",
        f"    < body           : {str(parsed.get('response_body'))[:body_limit]}",
    ]
    return "\n".join(lines)


def _make_agent(scope: Any, engagement_id: str) -> Any:
    """A real ExploitAgent with a state double and an LLM that must never run."""
    from unittest.mock import AsyncMock

    from clinkz.agents.exploit import ExploitAgent
    from clinkz.llm.base import LLMClient
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    class _Forbidden(LLMClient):
        async def reason(self, messages: Any, tools: Any = None) -> Any:
            raise AssertionError("the LLM was called")

        async def research(self, query: str) -> str:
            raise AssertionError("the LLM was called")

        async def generate_text(self, prompt: str) -> str:
            raise AssertionError("the LLM was called")

    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="f-1")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()

    agent = ExploitAgent(
        llm=_Forbidden(),
        tools=[],
        scope=scope,
        state=state,
        engagement_id=engagement_id,
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    return agent


def _login_page(base: str, *, password_value: str | None = None) -> Any:
    """The login endpoint as the scan phase would hand it over.

    ``password_value`` is the ONE knob: when given, the page carries a form whose
    password field declares that value, and :meth:`_build_form_data` preserves a
    declared sibling value — which is how the B-control makes an arm submit a
    real credential without touching a line of the code under test. When absent
    the JSON-body shape is used, which is what a real engagement sends (benign
    filler in every sibling).
    """
    from clinkz.agents.exploit import PageAnalysis
    from clinkz.models.scan import ParamLocation

    if password_value is None:
        return PageAnalysis(
            url=f"{base}{LOGIN_PATH}",
            body="",
            status=200,
            input_params=["email", "password"],
            request_method="POST",
            content_type="application/json",
            param_locations={
                "email": ParamLocation.JSON_BODY,
                "password": ParamLocation.JSON_BODY,
            },
        )
    # No JSON_BODY location: the carrier dispatches on the param's location
    # FIRST, so an explicit json_body mapping would never reach the form branch.
    # A form with `encoding="json"` posts the same JSON body to the same URL.
    return PageAnalysis(
        url=f"{base}{LOGIN_PATH}",
        body="",
        status=200,
        input_params=["email", "password"],
        request_method="POST",
        content_type="application/json",
        forms=[
            {
                "action": LOGIN_PATH,
                "method": "POST",
                "encoding": "json",
                "fields": [
                    {"name": "email", "type": "email", "value": ""},
                    {"name": "password", "type": "password", "value": password_value},
                ],
            }
        ],
    )


async def run(base: str) -> int:  # noqa: PLR0915 — a control harness is a script
    from clinkz.models.methodology import InjectionPrimitives, InjectionType, SQLDialect
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

    results: dict[str, Any] = {"controls": {}}
    failures: list[str] = []

    # ------------------------------------------------------------------
    _rule("PRE-FLIGHT")
    status, body = _post_json(f"{base}{LOGIN_PATH}", {"email": "nobody@x", "password": "x"})
    if status == 0:
        print(f"STOP: Juice Shop unreachable at {base} ({body})")
        return 2
    print(f"Juice Shop            : reachable at {base} (login answers {status})")

    status, body = _post_json(
        f"{base}{LOGIN_PATH}", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    if status != 200 or "authentication" not in body:
        print(f"STOP: {ADMIN_EMAIL} / <password> is not a valid credential (status={status}).")
        print("  The B-control is a statement about a credential we HOLD and KNOW works.")
        return 2
    print(f"Credential            : {ADMIN_EMAIL} + <password> PROVED valid (status 200 + token)")

    host = urllib.parse.urlsplit(base).hostname or "localhost"
    scope = EngagementScope(name="d8-live", targets=[ScopeEntry(value=host, type=ScopeType.DOMAIN)])

    # The nonce for control 4: minted here, injected NOWHERE.
    never_injected_nonce = f"CLINKZNEVERINJECTED{secrets.token_hex(8).upper()}"
    print(f"Never-injected nonce  : {never_injected_nonce}")

    tee = RequestTee()
    tee.install()
    try:
        # --------------------------------------------------------------
        _rule("FIX A — the LLM synthesizer is not CALLED for AUTH_BYPASS")
        agent = _make_agent(scope, "d8-live-a")
        llm_calls: list[str] = []

        async def _spy(prompt: str, **kw: Any) -> str:
            llm_calls.append(prompt)
            raise AssertionError("the phase-4 LLM synthesizer was called for AUTH_BYPASS")

        agent._llm_analyze = _spy  # type: ignore[method-assign]

        # break_prefix=None is the state that used to fall through to the model.
        primitives = InjectionPrimitives(
            quote_chars=["'"], comment_syntax=["--"], break_prefix=None
        )
        synth = await agent._sqli_phase4_synthesize_payload(
            InjectionType.AUTH_BYPASS, SQLDialect.SQLITE, primitives, {"value": "clinkz"}
        )
        print("  break_prefix          : None  (the fall-through state)")
        print(f"  LLM calls             : {len(llm_calls)}")
        print(f"  payload               : {synth['payload']!r}")
        print(f"  control_payload       : {synth['control_payload']!r}")
        print(f"  indicator_type        : {synth['indicator_type']!r}")
        if llm_calls:
            failures.append("FIX A: the LLM synthesizer was called for AUTH_BYPASS")
        results["fix_a"] = {
            "llm_calls": len(llm_calls),
            "payload": synth["payload"],
            "control_payload": synth["control_payload"],
            "indicator_type": synth["indicator_type"],
        }

        # --------------------------------------------------------------
        # One deterministic pair, reused by the main run and by controls 1/2/5.
        benign_email = "clinkz-probe@example.com"
        baseline = {"value": benign_email}
        pair = agent._fallback_synthesis_sqli(
            InjectionType.AUTH_BYPASS,
            SQLDialect.SQLITE,
            InjectionPrimitives(quote_chars=["'"], comment_syntax=["--"], break_prefix="'"),
            baseline,
        )
        payload, control_payload = pair["payload"], pair["control_payload"]

        # --------------------------------------------------------------
        _rule("MAIN RUN — the tautology on /rest/user/login (controls 1 + 2 inline)")
        agent = _make_agent(scope, "d8-live-main")
        agent._authenticated_as = ADMIN_EMAIL
        agent._known_valid_credentials = agent._harvest_known_valid_credentials(
            [{"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD}]
        )
        traced: list[dict[str, Any]] = []
        real_trace = agent._trace_methodology_phase
        agent._trace_methodology_phase = lambda **kw: (  # type: ignore[method-assign]
            traced.append(kw),
            real_trace(**kw),
        )[0]
        print(f"  authenticated_as      : {agent._authenticated_as}")
        print(
            f"  known-valid creds     : {sorted(agent._known_valid_credentials)} "
            f"(fingerprints only)"
        )
        print(f"  probe   (tautology)   : {payload!r}")
        print(f"  control (contradiction): {control_payload!r}")
        print(f"  benign                : {benign_email!r}")

        mark = tee.mark()
        confirmed, observed = await agent._sqli_verify_auth_bypass(
            _login_page(base), "email", payload, control_payload, baseline
        )
        exchanges = tee.since(mark)

        print("\n  --- the three arms, verbatim (arm order: benign, control, probe) ---")
        for label, entry in zip(
            ("benign", "control(contradiction)", "probe(tautology)"), exchanges
        ):
            print(f"\n  [{label}]")
            print(_render_exchange(entry))

        extra = next(
            (t["extra"] for t in traced if t.get("phase_name") == "auth_bypass_differential"), {}
        )
        print("\n  --- verdict ---")
        print(f"  confirmed             : {confirmed}")
        print(f"  reason                : {extra.get('reason')}")
        print(f"  probe_authenticated   : {extra.get('probe_authenticated')}")
        print(f"  control_refused       : {extra.get('control_refused')}")
        print(f"  benign_refused        : {extra.get('benign_refused')}")
        print(f"  principal_is_foreign  : {extra.get('principal_is_foreign')}")
        print(f"  observed              : {extra.get('observed')}")
        print("\n  --- instrumentation (FIX B) ---")
        print(f"  carrier_session_free  : {extra.get('carrier_session_free')}")
        print(f"  carrier_note          : {extra.get('carrier_note')!r}")
        print(f"  supplied  PRE-drop    : {extra.get('supplied_identities_pre_drop')}")
        print(f"  supplied POST-drop    : {extra.get('supplied_identities_post_drop')}")
        print(f"  credential_backed     : {extra.get('credential_backed_identities')}")

        pre = extra.get("supplied_identities_pre_drop") or []
        b_exercised = ADMIN_EMAIL in pre
        print(
            f"  B exercised?          : {b_exercised} "
            f"({'admin was in the pre-drop set' if b_exercised else 'ADMIN ABSENT — B NOT TESTED'})"
        )
        if not confirmed:
            failures.append(f"MAIN: the bypass did not confirm ({extra.get('reason')})")
        results["main"] = {
            "confirmed": confirmed,
            "observation": observed,
            **{
                k: extra.get(k)
                for k in (
                    "reason",
                    "probe_authenticated",
                    "control_refused",
                    "benign_refused",
                    "principal_is_foreign",
                    "observed",
                    "carrier_session_free",
                    "carrier_note",
                    "supplied_identities_pre_drop",
                    "supplied_identities_post_drop",
                    "credential_backed_identities",
                )
            },
            "b_exercised": b_exercised,
            "exchanges": exchanges,
        }

        # --------------------------------------------------------------
        _rule("CONTROL 1 — the inverted tautology, sent alone (payload control)")
        c1 = [e for e in exchanges if control_payload in (e["request"].get("body") or "")]
        for entry in c1:
            print(_render_exchange(entry, body_limit=200))
        c1_refused = extra.get("control_refused") is True
        print(f"  control arm returned an auth artifact? {not c1_refused}")
        print(f"  RESULT: {'PASS — refused' if c1_refused else 'FAIL — it authenticated'}")
        if not c1_refused:
            failures.append("CONTROL 1: the inverted tautology authenticated")
        results["controls"]["1_inverted_tautology"] = {"refused": c1_refused}

        # --------------------------------------------------------------
        _rule("CONTROL 2 — the benign credential arm (oracle control)")
        c2_refused = extra.get("benign_refused") is True
        print(f"  benign arm returned an auth artifact? {not c2_refused}")
        print(f"  RESULT: {'PASS — refused' if c2_refused else 'FAIL — it authenticated'}")
        if not c2_refused:
            failures.append("CONTROL 2: the benign credential arm authenticated")
        results["controls"]["2_benign_credentials"] = {"refused": c2_refused}

        # --------------------------------------------------------------
        _rule("CONTROL 3 (B-CONTROL) — a sessionless arm submitting a VALID credential")
        print("  Identical arm structure. The probe value is the real identity and the")
        print("  password sibling carries the real password (declared on the form, which")
        print("  _build_form_data preserves — no production code is patched).")
        print("  MUST return not-confirmed / principal_is_an_identity_we_supplied.")
        agent_b = _make_agent(scope, "d8-live-bcontrol")
        agent_b._authenticated_as = ""  # isolate: possession alone must catch this
        agent_b._known_valid_credentials = agent_b._harvest_known_valid_credentials(
            [{"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD}]
        )
        traced_b: list[dict[str, Any]] = []
        real_trace_b = agent_b._trace_methodology_phase
        agent_b._trace_methodology_phase = lambda **kw: (  # type: ignore[method-assign]
            traced_b.append(kw),
            real_trace_b(**kw),
        )[0]
        mark = tee.mark()
        b_confirmed, b_observed = await agent_b._sqli_verify_auth_bypass(
            _login_page(base, password_value=ADMIN_PASSWORD),
            "email",
            ADMIN_EMAIL,
            f"{ADMIN_EMAIL}x",
            {"value": benign_email},
        )
        b_exchanges = tee.since(mark)
        for label, entry in zip(("benign", "control", "probe(valid credential)"), b_exchanges):
            print(f"\n  [{label}]")
            print(_render_exchange(entry, body_limit=260))
        extra_b = next(
            (t["extra"] for t in traced_b if t.get("phase_name") == "auth_bypass_differential"), {}
        )
        print("\n  --- verdict ---")
        print(f"  confirmed             : {b_confirmed}")
        print(f"  reason                : {extra_b.get('reason')}")
        print(f"  authenticated_as      : {agent_b._authenticated_as!r} (empty — not the key)")
        print(f"  supplied  PRE-drop    : {extra_b.get('supplied_identities_pre_drop')}")
        print(f"  supplied POST-drop    : {extra_b.get('supplied_identities_post_drop')}")
        print(f"  credential_backed     : {extra_b.get('credential_backed_identities')}")
        print(f"  carrier_session_free  : {extra_b.get('carrier_session_free')}")
        b_ok = (
            b_confirmed is False and extra_b.get("reason") == "principal_is_an_identity_we_supplied"
        )
        print(f"  RESULT: {'PASS' if b_ok else 'FAIL — FIX B IS WRONG AND THIS RUN IS VOID'}")
        if not b_ok:
            failures.append(
                "CONTROL 3 (B-CONTROL): a valid-credential arm was not suppressed — "
                f"confirmed={b_confirmed} reason={extra_b.get('reason')}"
            )
        results["controls"]["3_b_control_valid_credential"] = {
            "confirmed": b_confirmed,
            "reason": extra_b.get("reason"),
            "observation": b_observed,
            "credential_backed": extra_b.get("credential_backed_identities"),
            "exchanges": b_exchanges,
        }

        # --------------------------------------------------------------
        _rule("CONTROL 4 — a never-injected nonce is absent from every evidence field")
        haystack = json.dumps(results, default=str) + " ".join(
            json.dumps(e, default=str) for e in tee.sent
        )
        leaked = never_injected_nonce in haystack
        print(f"  nonce                 : {never_injected_nonce}")
        print("  injected into         : nothing (minted and held)")
        print(f"  present in evidence?  : {leaked}")
        verdict = (
            "FAIL — the engine reported something it never sent" if leaked else "PASS — absent"
        )
        print(f"  RESULT: {verdict}")
        if leaked:
            failures.append("CONTROL 4: a never-injected nonce appeared in the evidence")
        results["controls"]["4_never_injected_nonce"] = {
            "nonce": never_injected_nonce,
            "found_in_evidence": leaked,
        }

        # --------------------------------------------------------------
        _rule("CONTROL 5 — the same payload on a NON-login endpoint stays silent")
        from clinkz.agents.exploit import PageAnalysis
        from clinkz.models.scan import ParamLocation

        search_page = PageAnalysis(
            url=f"{base}{SEARCH_PATH}?q=apple",
            body="",
            status=200,
            input_params=["q"],
            param_locations={"q": ParamLocation.QUERY},
        )
        agent_c = _make_agent(scope, "d8-live-nonlogin")
        agent_c._authenticated_as = ADMIN_EMAIL
        applicable, why = agent_c._sqli_auth_bypass_applicable(search_page, "q")
        print(f"  applicability gate    : applicable={applicable} — {why}")
        mark = tee.mark()
        c5_confirmed, c5_observed = await agent_c._sqli_verify_auth_bypass(
            search_page, "q", payload, control_payload, {"value": "apple"}
        )
        c5_exchanges = tee.since(mark)
        print("\n  [probe on the search endpoint]")
        print(_render_exchange(c5_exchanges[-1], body_limit=220))
        print(f"\n  forced verdict        : confirmed={c5_confirmed}")
        print(f"  observation           : {c5_observed[:200]}")
        c5_ok = applicable is False and c5_confirmed is False
        print(f"  RESULT: {'PASS — gated out AND silent when forced' if c5_ok else 'FAIL'}")
        if not c5_ok:
            failures.append(
                f"CONTROL 5: non-login endpoint applicable={applicable} confirmed={c5_confirmed}"
            )
        results["controls"]["5_non_login_endpoint"] = {
            "applicable": applicable,
            "gate_reason": why,
            "confirmed": c5_confirmed,
            "observation": c5_observed,
        }
    finally:
        tee.remove()

    # ------------------------------------------------------------------
    _rule("SUMMARY")
    for name, block in results["controls"].items():
        print(
            f"  {name:34s} "
            f"{json.dumps(redacted({k: v for k, v in block.items() if k != 'exchanges'}))[:120]}"
        )
    print(f"\n  main run confirmed    : {results['main']['confirmed']}")
    print(f"  B actually exercised  : {results['main']['b_exercised']}")
    if failures:
        print("\n  FAILURES:")
        for line in failures:
            print(f"    - {line}")
    else:
        print("\n  ALL CONTROLS PASSED")

    # Through the engine's redaction chokepoint. `results` carries every teed
    # exchange, so a raw dump writes the target's session JWT and the lab
    # password to disk — which is exactly what the previous version of this
    # line did.
    out = write_redacted_json(
        REPO_ROOT / "outputs" / "d8_auth_bypass_live_validation.json", results
    )
    print(f"\n  written: {out}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://localhost:3000")
    args = parser.parse_args()
    return asyncio.run(run(args.base.rstrip("/")))


if __name__ == "__main__":
    raise SystemExit(main())
