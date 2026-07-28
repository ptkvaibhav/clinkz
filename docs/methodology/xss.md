# XSS — `_test_xss_reflected` / `_test_xss_stored` / `_test_xss_dom`

Part of the adaptive **payload-injection family** (six-phase reflection /
fingerprint / synthesize / verify / emit with LLM-driven payload synthesis; see
[README](README.md) for the shared pattern).

## Emission rule

- **Stored XSS** emits only when the phase-5 oracle AND the phase-6 confirmation
  gate both pass (see below); a synthesized-but-unverified payload emits nothing.
- **Reflected XSS** confirms on the reflected payload landing unescaped in an
  executable context, anchored on a benign baseline.
- **DOM XSS emits nothing today.** Its evidence is *reachability*, never
  execution — see below.

## Stored-XSS confirmation gate (gap G1, engagement `913fecee`)

At DVWA `impossible` the methodology emitted **"Stored XSS via `user_token` in
form"** — high severity, `status=confirmed`. The chain: the injection point was
the anti-CSRF token field; the synthesized payload was the bare alphanumeric
`alert1`; `read_back_url` was `None`; and the synthesis LLM's own verdict read
*"No JavaScript execution occurs … all characters needed to create a script
context are stripped."* Phase-5 returned `True` because `"alert1" in body`, and
emission took the **disjunction** of the substring hit and the LLM verdict.

Four independent conditions now have to hold, and each one alone kills that
finding. `_xss_stored_confirmation_gate` is the single AND:

1. **A genuine read-back.** `read_back_url` must be an endpoint phase 1 observed
   the canary rendered at. Phase 5 previously fell back to
   `read_back_url or page.url`, silently re-reading the page the payload was
   submitted to — so any substring already on that page confirmed. A confirm
   with `read_back_url=None` is now impossible by construction.
2. **Escaping-robust survival with functional capability.** The payload must
   appear literally (so an `htmlspecialchars` store cannot match) *and* carry
   XSS-functional characters for the context it landed in
   (`_xss_payload_has_functional_capability`): a markup landing needs `<`+`>` or
   a quote+`=`; a `script` landing needs a string/statement breakout. A payload
   with no functional character can never confirm.
3. **A genuine user-controlled injection point.**
   `_xss_stored_field_is_app_controlled` skips token-shaped fields (the
   anti-CSRF vocabulary) and hidden fields the form pre-populated — those are
   the app echoing its own state into its own form by design, not stored user
   content.
4. **The deterministic check GATES the LLM — never an OR.** The deterministic
   oracle decides; a synthesis whose own verdict states the payload cannot
   execute can only **veto** on top of it. Phase 6 raises rather than rendering a
   result that did not pass the gate, so there is no second path to emission.

## DOM XSS: reachability is not exploitation (gap G2, engagement `913fecee`)

DOM XSS confirmed **identically at all four DVWA levels**, because the inline
`document.write(location.href.substring(...))` script that the source→sink scan
matches is the same at every level — a textbook
[uniform-confirm-across-a-graded-control](dvwa-per-level-honesty.md) phantom. Two
defects:

- The evidence string hardcoded `"(payload executed by client-side JS)"` — an
  observation the methodology cannot make and never made. **Deleted.** Never
  write an observation into evidence that was not made.
- `verification_strength="likely"` mapped onto `status=confirmed severity=high`,
  while the skill's own docstring says the strength is `likely` *because*
  confirming execution needs a headless browser.

`_dom_xss_dispatch_result` now routes on strength: `"verified"` (execution
witnessed) emits a finding; `"likely"` records an
`UnprovenExploitLead` — a **different type** than `Finding`, with no path to
`_persist_finding`, rendered in the report's own "Unproven exploitation leads
(UNCONFIRMED)" section and never counted in coverage. Its
`why_unconfirmed` is `execution_not_witnessed_requires_client_side_oracle`.
Nothing sets `"verified"` today; phase 6 stays wired as the seam a client-side
execution oracle (P7) plugs into, and raises if reached without one.

## Reflected-XSS verifying-response capture (report-integrity BUG 1, DVWA f7a761a1)

`_run_xss_reflected_methodology` threads the phase-5 verifying response (anchored
on the reflected payload, `_xss_evidence_snippet`) onto
`MethodologyResult.verifying_response`, and `_xss_phase6_emit` renders THAT as the
Response evidence — never the old hardcoded `(response unavailable)` placeholder.

**Honesty guard**: `verified` but no captured response ⇒ emit returns `None`
(verification ran blind — never a silently-verified finding), the same "reject on
missing evidence, not on a label" discipline as CMDi/LFI phase-5; this stopped the
FP-suppression pass from flagging a genuine Low reflected XSS.
