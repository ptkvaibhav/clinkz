# Authentication bypass (D8) — `InjectionType.AUTH_BYPASS`

Code: [`agents/_auth_bypass.py`](../../src/clinkz/agents/_auth_bypass.py) (the
decision, pure) + the carrier in `agents/exploit.py`
(`_sqli_verify_auth_bypass`, `_auth_bypass_send_probe`).
Driver: [`scripts/live_d8_auth_bypass_validation.py`](../../scripts/live_d8_auth_bypass_validation.py).

## The gap

Forty SQL-injection payloads landed in a login form's email field, the target
graded the challenge solved, and `_test_sqli` emitted **nothing** — correctly. A
DB error, a boolean row-set delta and a UNION row are the only effects its
oracle could see, and an authentication bypass produces none of them. It
produces `200` and a JWT. The methodology was not wrong; it had no indicator for
the effect that actually occurred.

## The defining effect

**Authenticated as a principal whose credential we never supplied.** Not "the
request succeeded", not "a cookie came back" — an application that issues an
anonymous session on every response would confirm on that forever, on every
endpoint. DVWA is exactly that application: it re-issues `PHPSESSID` on *every*
response including `login.php`, which is why the class refuses there and must.

Three arms, all sessionless, probe last:

| arm | value | required |
|---|---|---|
| benign | the original parameter value | must NOT authenticate |
| control | the contradiction `OR '1'='2'`, one character from the probe | must NOT authenticate |
| probe | the tautology `OR '1'='1'` | must authenticate |

Plus: where the artifact NAMES a principal, that principal must not be an
identity we supplied.

## Applicability is deterministic in both directions

`_sqli_auth_bypass_applicable` gates on a protocol artifact — a password-shaped
field with the param under test identity-shaped beside it — so the LLM can
neither invent the class on a search box nor omit it on a login.

## The two fixes that made it work on a live target

### FIX A — the LLM synthesizer is structurally unreachable for this type

`_sqli_phase4_synthesize_payload` used to prefer the deterministic build only
when phase 2 had confirmed a breakout; with `break_prefix is None` it fell
through to the LLM checkpoint. For `AUTH_BYPASS` there is **no state in which
that path helps**:

* the phase-4 prompt has no `auth_bypass` vocabulary and the `indicator_type`
  enum it asks for excludes the value, so every pair a model can return is
  either rejected at phase 5 as an unknown indicator or routed to a
  row-set/error/timing oracle **that cannot see this effect** — the wrong oracle,
  running against a live login handler;
* the control's whole job is to be the same shape one character apart, and a
  model that paraphrases either half destroys the differential.

So the type is excluded before anything else runs, and when the deterministic
table declines the class **abstains** with a recorded reason
(`_SQLI_AUTH_BYPASS_ABSTAIN_REASON`, traced as `auth_bypass_abstained`) rather
than continuing. An abstention that leaves no trace reads exactly like a class
that was never ranked.

The test asserts the **call does not happen**, not that the returned pair looks
right: a behavioural test passes just as happily against a version that consults
the model and discards its answer.

### FIX B — the suppression key is credential POSSESSION, not identity coincidence

What the identity suppression must catch is *"we authenticated legitimately and
the endpoint told us who we are"*. That has exactly two routes:

1. **the request rode a session** for that principal — killed by `07ec668`,
   which made all three arms sessionless;
2. **the request submitted a valid credential** for that principal.

`principal == self._authenticated_as` proxies both of those badly, and the
expensive direction is the strict one. Juice Shop is the proof: `' OR 1=1 --`
returns a token for `admin@juice-sh.op` because that is the first row in the
users table — and `admin@juice-sh.op` is also the account the engagement
authenticates as. Keyed on coincidence, a textbook bypass carrying **no password
at all** is suppressed as if we had logged in.

So:

* **the session route is closed verifiably, not assumed.**
  `_auth_bypass_send_probe` returns an `_AuthBypassCarrier` per arm, and
  `_auth_bypass_assert_session_free` reads the *validated arguments the HTTP
  chokepoint received* — `no_session` set, no explicit cookie dict, and no
  auth-carrying request header (`_AUTH_CARRYING_HEADERS` unioned with this
  engagement's own live session-header names). Only when **all three** arms pass
  is `self._authenticated_as` dropped from the supplied set. Any arm that cannot
  make the statement — including one that sent nothing because a destructive
  submission was refused — **keeps** it, which is the pre-fix stricter
  behaviour, and the verdict says why. Asserting from the branch that built the
  request is exactly the assumption this guard exists to stop making: it holds
  today because of `07ec668`, and it must keep holding after the next carrier
  refactor.
* **the credential route is closed by reading what the arms actually
  submitted.** `_identities_authenticated_by` requires **both halves in the same
  request** — the identity in some field and, in a password-shaped field, a
  value whose fingerprint matches the one held for that identity. The registry
  (`_known_valid_credentials`) is harvested from the orchestrator's existing
  validated-credential handoff and reduced to `identity → salted fingerprint` on
  the way in: the `CredentialSet` is structurally kept off this agent and this
  must not become the exception that puts it back.

The injected payload is deliberately **not** a supplied identity. An identity
quoted inside `admin@juice-sh.op'--` is the target's answer, not our claim, and
the substring rule in `_principal_matches_supplied` would otherwise suppress the
very finding the class exists for.

Both directions are recorded on every run — pre-drop set, post-drop set, carrier
verdict, credential-backed identities — in the run log and in the phase-5 trace
event, so "was the suppression even exercised?" is answerable from the artifact
rather than by re-deriving it.

## Live validation

`scripts/live_d8_auth_bypass_validation.py` drives the real carrier and the real
oracle against a live OWASP Juice Shop. Five controls, all required:

| # | control | tests | required |
|---|---|---|---|
| 1 | inverted tautology `OR '1'='2'` | the payload | refuse |
| 2 | benign credential arm | the oracle | refuse |
| 3 | **B-CONTROL** — a sessionless arm submitting a **valid** credential through the identical arm structure | the suppression | refuse, `principal_is_an_identity_we_supplied` |
| 4 | a never-injected nonce | evidence integrity | absent from every field |
| 5 | the same payload on a non-login endpoint | applicability | silent |

Control 3 is the one that grades FIX B: an inverted tautology tests the
*payload* and refuses for reasons unrelated to whether the supplied-identity set
is sound, so the suppression needs its own control. If that arm confirms, FIX B
is wrong and the run is void. It rides the real carrier — the page declares a
form whose password field carries the real password, and `_build_form_data`
preserves a declared sibling value, so nothing in the code under test is
patched.

**DVWA is the control group.** Its `PHPSESSID`-on-every-response behaviour means
the control arm authenticates too, the verdict short-circuits at
`shape_matched_control_also_authenticated`, and the identity suppression is
never reached. An auth-bypass confirm at any DVWA level would mean the
loosening went too far.

### Results — harness (Juice Shop 19.x, local)

| | outcome |
|---|---|
| FIX A | `break_prefix=None`, **0 LLM calls**, deterministic pair returned, `indicator_type=auth_bypass` |
| main run | **CONFIRMED** — probe 200 + JWT `principal=admin@juice-sh.op`; control 401; benign 401 |
| control 1 | 401, no artifact — refused |
| control 2 | 401, no artifact — refused |
| control 3 (B) | 200 + JWT, **not-confirmed / `principal_is_an_identity_we_supplied`**, `credential_backed=['admin@juice-sh.op']` with `_authenticated_as=""` |
| control 4 | never-injected nonce absent from every field |
| control 5 | gate `applicable=False` ("request declares no password-shaped field"); forced verdict `no_auth_artifact_returned` |

Instrumentation on the main run — `carrier_session_free=True`, pre-drop
`[…, admin@juice-sh.op]` → post-drop `[…]`, `credential_backed=[]`. The
suppression was therefore genuinely exercised: without FIX B this confirmation
would have been suppressed.

### Results — full engagement (`5b1a93e8`, benchmark profile ON)

`[critical] Authentication bypass via SQL injection in email` at
`/rest/user/login`, `status=confirmed`, `strength=verified`. The same phase-5
instrumentation appears in the trace, and the carrier statement is part of the
finding's own evidence, so a reader can re-derive the drop decision from the
deliverable.

The evidence names `AuthArtifact.principal`; the raw response's own
`"umail":"admin@juice-sh.op"` corroborates it independently of the JWT decode,
and the 717-character token value reaches no writer — the bundle contains no
JWT-shaped string at all.
