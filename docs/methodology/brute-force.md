# Brute force — `_test_brute_force`

Part of the adaptive **behavioral family** (four-phase hypothesis / observe /
analyze / emit; see [README](README.md) for the shared pattern).

**Phase 3 calls no LLM** (since 2026-08-19), and this one was not a determinism
nuance. The model ran alongside the classifier under a one-way rule — it could
ADD a protection the deterministic pass missed, never clear one it found — and
across **296 recorded calls it overrode 3 verdicts, every one of them by writing
an `observed_at_attempt` of its own (5, 4, 6) against 138 the engine derived
from a real observation**. That ordinal is carried on the result and into the
trace and is read as a measurement; nothing checked that the model's number
corresponded to anything. Three findings were suppressed on it. The residual —
a throttle outside the classifier's vocabulary is now reported `none` — is a
stated recall loss, pinned by a test so it stays a decision. See
[deterministic-verdict-classes.md](deterministic-verdict-classes.md).

## Emission rule

A "no brute-force protection" finding is an argument from **absence**, which
makes it the most failure-prone shape in the suite: absence of a lockout marker
is only evidence when the request that lacked it *was actually authenticated*,
and only when nothing else about the response is itself a control.

Emission therefore requires **both**:

    result.auth_reached  AND  not result.protected

## The absence is BOUNDED, and the bound is ours

Every other absence this engine reports is complete in the observation that
found it. A missing `X-Frame-Options` is missing in the one response that had to
carry it, and no further request can make it present — `_test_security_headers`
reads a response and the question is settled.

This one is not that shape. The finding asserts *nothing stopped us*, and that is
only ever true **up to the number of attempts we made**. Worse, the number is
always **ours**: the emission gate requires `not result.protected`, and
`protected` False means no attempt in the series was refused, which means the
series ended when `_BRUTE_FORCE_ATTEMPTS` ran out rather than when the target
answered. A login whose policy trips at nine is, from here, byte-identical to one
with no policy at all.

So the ceiling is carried on the result (`BruteForceMethodologyResult.attempt_ceiling`,
with `ceiling_is_our_budget` naming whose it is) and stated in all three
client-facing places:

| where | what it says |
|---|---|
| title | `No Brute-Force Protection Observed in 8 Attempts on <url>` |
| description | `BOUNDED OBSERVATION: … the series ended at this engine's own per-form ceiling of 8 attempts, not at a refusal the target made … a policy that trips at 9 would look identical here` |
| evidence | `bound=our budget: 8 of a 8-attempt ceiling this engine set … a control triggering at attempt 9 would not have been observed` |

`_BRUTE_FORCE_ATTEMPTS` is a named constant rather than a literal in the loop for
exactly this reason: the emitter has to state the bound to the client, and a
bound enforced in one place and quoted in another drifts.

## Has the instrument ever fired? — the corpus, swept

A bounded absence is worth nothing if the thing that would bound it can never be
observed, so the question is empirical: across every stored `trace.jsonl`, has a
refusal at attempt *k* ever been recorded?

Swept over **2,976 traces / 369 phase-3 verdicts in 153 engagements**:

| verdict | rows | what it was |
|---|---|---|
| `none` | 186 | the emitting case |
| `inconclusive` | 136 | the positive control refusing to conclude |
| `delay` | 35 | DVWA `medium`'s flat `sleep(2)` |
| `lockout` | **10** | DVWA `high`, marker `account has been locked` |
| `rate_limit` | 2 | Juice Shop `/rest/2fa/setup` — and see below |

**The instrument is not dead.** Ten series ended early on a refusal the target
made: `len(observations) == 1` on all ten, against 359 that ran the full eight.

**But every one of them was `attempt 0`** — the account was already locked when
the series began, from an earlier run. What has never been observed is a
*transition*: attempts 1…k−1 answered normally and attempt k refused. That is
the observation which would let this class report a *measured* ceiling instead of
an assumed one, and it remains unobserved. Stated rather than claimed.

**And the two `rate_limit` rows were phantoms.** Both came off
`X-RateLimit-Remaining: 99` — an endpoint advertising ninety-nine remaining
requests, graded PROTECTED. Phase 3 read `o.rate_limit_headers` raw (any
`X-RateLimit-*` header at all) while `classify_lockout`, the shared vocabulary
this class was migrated onto, requires the remaining count to have reached zero.
Two readings of one observation, and the looser one decided the verdict —
suppressing a finding on a signal that is not a refusal. Phase 3 now reads the
**declared** `lockout_kind` for all three kinds, which is invariant 82's rule
applied to the classifier's own vocabulary: the consumer never re-derives what
the producer already said. The same change stops a rate-limit phrase in a body
(`try again later`) being reported to the client as an account lockout, which is
what `if o.body_marker:` did.

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
