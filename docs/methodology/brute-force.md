# Brute force — `_test_brute_force`

Part of the adaptive **behavioral family** (four-phase hypothesis / observe /
analyze / emit; see [README](README.md) for the shared pattern).

## Emission rule

A "no brute-force protection" finding is an argument from **absence**, which
makes it the most failure-prone shape in the suite: absence of a lockout marker
is only evidence when the request that lacked it *was actually authenticated*,
and only when nothing else about the response is itself a control.

Emission therefore requires **both**:

    result.auth_reached  AND  not result.protected

## G3-a: the positive control (engagement `291617a2`, DVWA `high`)

At `high`, eight attempts came back `[200, 302×7]` with `length=1`. DVWA `high`
gates the brute-force form on a rotating anti-CSRF token; the parsed token was
valid for the first submit only, and the remaining seven were redirected away
before the credential check ran. So "no lockout marker appeared" was **trivially
true of requests that never reached authentication** — and the module reported
the endpoint unprotected.

`_brute_force_attempt_reached_auth` scores every attempt. A known-bad-credential
submission counts as having reached authentication only when the response is an
authentication **outcome rendered in place** — any one of:

| signal | why it is an auth outcome |
|---|---|
| `401` / `403`, or a `WWW-Authenticate` header | status-level auth rejection; language-independent |
| `2xx` with a non-trivial body carrying an auth-failure marker **absent from the unauthenticated page baseline** | the handler rendered a rejection; the baseline delta is what attributes it |
| `2xx` with a non-trivial body differing from that baseline | the response is a function of the submitted credentials |
| `3xx` whose `Location` resolves back to the **same** auth endpoint | POST-redirect-GET login — the outcome renders on the redirect target |

A `3xx` that bounces elsewhere, a body under `_BRUTE_FORCE_MIN_AUTH_BODY` (32
bytes — DVWA `high` returned 1), and `status == 0` all mean the credentials were
never evaluated.

The series verdict is **all-or-nothing**: unless every attempt reached
authentication, the protection type is `INCONCLUSIVE` and `protected=True`, so no
finding can be emitted. Explicit protection signals (429 / `Retry-After` /
captcha / lockout marker) are evaluated *before* the control, because those hold
regardless of whether the attempts authenticated — and the observation loop
breaks early on them, so a real lockout is classified as protection, never as a
contaminated series.

## G3-b: a constant delay is still a protection (engagement `48e438e3`, DVWA `medium`)

At `medium`, all eight attempts took ~2250 ms against a ~200 ms page load — a
deliberate `sleep(2)` per failed login. The delay check only looked for
**monotonic growth**, so a flat penalty read as "times fluctuating narrowly
without a growth trend … no brute-force protection".

Wrong shape. A throttle is a throttle whether it ramps or not. Phase 2 now times
an unauthenticated GET of the login page as the "no penalty" reference, and the
classifier recognises two delay shapes:

- **Constant penalty** — *every* attempt costs at least
  `max(baseline × 3, baseline + 500 ms)`. → `DELAY`, protected.
- **Progressive** — the series grows past `max(150 ms, first × 3)`. → `DELAY`,
  protected.

The baseline is what makes this a *delta* rather than a magnitude threshold: 2250
ms means nothing on its own; 2250 ms against a 205 ms page load is a control.

## The deterministic verdict gates the LLM

`_fallback_brute_force_analysis` is no longer a fallback — it is the decision.
The phase-3 LLM checkpoint may only make the verdict **stricter**:

- deterministic says protected **or** inconclusive → that stands, whatever the
  LLM says. This is what stops an LLM reading eight bounced redirects, or eight
  identical `sleep(2)` responses, as "consistent, therefore unprotected" — which
  is exactly what its rationale said in both engagements.
- deterministic says unprotected → the LLM may still raise a protection it
  recognised, and that wins.

A finding exists only where both agree there is none.

## Evidence

The emitted finding carries the unauthenticated baseline time, the per-attempt
positive-control verdicts (`auth_reach=…`), and the statuses/times matrix — so a
reader can re-derive the conclusion instead of trusting the label.
