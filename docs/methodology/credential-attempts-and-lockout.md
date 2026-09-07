# Credential attempts — the deferral, the budget, and the stop the target declares

Three defects in one seam, and they are the same defect twice over: **a login
answer read as a statement about the password when it was not one.**

* **"The POST set no cookie" has two causes** and the code collapsed them into
  one, so an application that promotes its session in place had every successful
  login reported as a wrong password.
* **"The login refused" has two causes** and the code collapsed those too, so a
  lockout or a captcha was read as a wrong password and answered with fifteen
  more attempts.

The first costs the engagement. The second costs the client an account.

---

## Part 1 — the POST that sets nothing

### The shape

```
GET  /portal/gateway    -> 200, Set-Cookie: SESSIONID=abc, a login form
POST /session   (GOOD)  -> 200, NO Set-Cookie, an account page
POST /session   (BAD)   -> 200, NO Set-Cookie, the login form again
```

`session_regenerate_id(False)` in PHP. Django's `cycle_key` on a reused key.
Every framework that attaches an identity to the session id it has already
issued rather than minting a new one. On all of them a **successful** login
produces an empty `Set-Cookie` delta, and the delta is the only honest evidence a
credential POST can produce — a cookie the login GET set exists whatever we send,
which is [invariant 11's](../invariants.md) whole point and the reason the merged
jar was removed from the success test in the first place.

So the fix that made the evidence honest also made it empty on this shape.
`_check_login_success` returned `bool`; empty evidence and a refusal reached the
same `False`, the engagement aborted, and the operator was told their password
was wrong about a password that worked.

### The fix — a third value, and an oracle that can settle it

`WebAuthenticator._login_verdict` returns a `LoginJudgement`
(`LoginVerdict` + the observation behind it):

| verdict | when | what happens |
|---|---|---|
| `PROVEN` | the POST set a cookie, returned a token, redirected away, or the body carries an authenticated-page marker | `authenticate()` returns it |
| `INDETERMINATE` | none of those, **and** the exchange is carrying session material from before the credentials went out, **and** the response is not itself a denial | held, then handed forward with `success=True` and `proven=False` |
| `REFUSED` | anything else, including a 4xx and a body carrying a refusal marker | the arm failed |

**The verdict passes to `assert_authenticated`** — which compares an
authenticated request against an anonymous control, is the stronger oracle, and
was already running on the next line of `_authenticate_role`. Nothing new is
believed; a question the credential exchange cannot answer is asked of the
component that can.

**"Not itself a denial" is `_session_survived`**, the same shared rule both
verification arms use: not a 401/403, and not a body serving an
`<input type="password">`. That is what stops the deferral swallowing every
failed login — and it is strictly stronger than what it replaced, because an
application whose refusal reads "Those details do not match" contains none of the
seven failure keywords and is now REFUSED on the form it re-served rather than
on English it did not use.

**The JSON arm has the same hole and the same fix.** `2xx + (token or
Set-Cookie)` skipped to the next route on a promoted session; it now holds the
first indeterminate candidate, keeps looking (a proof outranks a deferral), and
returns the candidate only if nothing proved one.

### And the cookie half of that rule had a hole of its own

The arm's licence for reading a `Set-Cookie` as proof was written into the code:

> Every cookie this arm can see on THIS response was set after the credentials
> went out — the JSON arm has no login-page GET of its own, so there is no
> pre-credential exchange of its own for one to have come from. The delta rule
> the form arms apply is satisfied here by construction.

"After the credentials went out" is not the delta rule. The delta rule is about a
cookie the **credential** caused, and the reason the form arms compute a delta at
all is that a login-page GET issues one whatever you send. This arm carries no
jar, so every cookieless request it makes to a session-starting framework is
answered with a fresh session cookie — on all eight canned routes, for any
password, including a rejected one.

Measured against `clinkz-dvwa`, 2026-09-07:

```
POST /login.php  {"username": "admin", "password": "wrongpass-a"}
-> 200
   Set-Cookie: security=impossible
   Set-Cookie: PHPSESSID=766d4ae9…
   Set-Cookie: PHPSESSID=08787c34…
   <the login form>
```

Two wrong passwords for `admin` reached `LoginVerdict.PROVEN` on that shape,
with evidence reading *"POST http://…/login.php returned 200 carrying
Set-Cookie: PHPSESSID"*. And PROVEN is the verdict nothing re-checks:
`_attempt_login` re-proves only an INDETERMINATE guess, so the
default-credential sweep would have marked both **valid**, stored a session for
them and reported a default-credential finding built on a cookie the server
hands anyone. The pre-credential cookie merged into the treatment, one arm over.

The cookie branch is gated by `_session_survived` now — the same rule both form
arms and both verification arms already run, and the one this arm was missing.
Pinned in `tests/test_tools/test_json_arm_anonymous_cookie.py`, in both
directions: a session-starting origin that answers every route `200 + Set-Cookie
+ a login form` must not authenticate a wrong password, and a same-site JSON API
that answers with a session cookie and no token must still authenticate — a fix
that refuses the second has traded a false positive for a false negative on the
commoner shape.

### Where the deferral may NOT go

The **default-credential sweep** marks a guessed password `valid`, and that is a
claim that reaches the report. On a promote-in-place application every guess is
indeterminate — good or bad — so a sweep that treated the deferral as success
would mark all of them valid. `_attempt_login` puts an indeterminate guess to
`assert_authenticated` first (`_prove_swept_session`) and marks it invalid if the
oracle does not prove a session. Those are GETs, not credential POSTs, so the
extra work costs the account nothing.

### A guessed password is a client credential the moment it works

Found by the security review of this branch's own diff, rated **MEDIUM**, and it
belongs here rather than in a gates checklist: it is a defect of the sweep, on
the sweep's own path, and the reason it existed is a piece of reasoning about
credentials that reads as obviously true and is not.

`run()` registers the operator's secrets for redaction. The sweep's catalogue
passwords were not registered, because they are **public** — `admin` / `password`
is in this repository, in the OWASP lists, and in the target's own documentation.
Redacting a value everybody already has looks like theatre.

It is not. A default password is public **until it works**. The moment one
authenticates it stops being a catalogue entry and becomes a live credential for
the client's system — and by then it has already been written, verbatim, into
`actions.jsonl`'s body excerpt on the JSON arm, which is exactly the artifact the
disclosure gate exists to keep clean. The window is the whole sweep: we cannot
know which guess is the live one until after we have sent it.

So `register_secret(password)` runs **before** the attempt, not on success —
`orchestrator.py::_attempt_login`. Registering on the outcome would be the same
bug with a smaller window, because the write that leaks it happens during the
attempt.

The generalisation is the one the redactor's own domain law already carries: a
value's classification is not a property of where it came from, and "this is
public" is a claim about the past.

### The positive control

**No target this project owns has this shape.** DVWA sets a fresh `PHPSESSID` on
the credential POST, Juice Shop returns a JWT, Meridian sets `meridian_portal` —
all three give the exchange something the POST itself produced, so all three pass
whether the branch works or not. A branch nothing reaches is indistinguishable
from a branch that does not work, so the shape is built:

* `tests/test_tools/test_promoted_session_login.py` — a loopback origin that
  promotes in place, end to end: the good credential reaches `INDETERMINATE` and
  carries the promoted cookie, `assert_authenticated` then **PROVES** the
  session, and the bad credential on the same origin is still `REFUSED`.
* `test_auth_transport_equivalence.py::the_session_is_promoted_in_place_and_the_post_sets_nothing`
  — the same shape through both credential arms, asserting the same verdict, the
  same cookie and one attempt each.

The negative control is not optional. Without it the fix is "believe every
ambiguous login", which is the original defect with its sign flipped.

---

## Part 2 — what one account was offered, measured

Counted at the transport against the Meridian container, 2026-09-06, one
`authenticate()` call, one role, no operator declarations:

| | docker (curl) | local (aiohttp) |
|---|---|---|
| credential that WORKS | 2 | 2 |
| credential that does NOT | **16** | **18** |

Two, on a success, because Meridian answers the form-encoded POST `415` and the
same credentials are re-POSTed under the type it names. Sixteen and eighteen on a
failure because the form arm's attempts are followed by the JSON arm's
`routes × identity keys` sweep, every non-2xx of which `continue`s.

That call happens more than once — again from `_verify_and_refresh_session`
whenever the sentinel says the session is gone, and **once per default credential
pair** in the sweep. The catalogue holds four distinct passwords for `admin`, two
of them seeded for every technology recon identifies. **Worst realistic sum
against one account: 4 × 16 = 64 credential POSTs**, 72 on the host.

And the client-facing record of that, for a two-role Meridian engagement, was
**two `actions.jsonl` entries**, both reading `POST mutates target state`.

### Why the log said two

`execute()` took ONE governor authorization for the whole form arm — both
attempts, the 415 re-POST, every redirect hop — because that arm drives
aiohttp and curl directly. The JSON arm rides `HTTPClientTool`, the HTTP
chokepoint, so its 7–24 POSTs were authorized and logged individually. **Two
accounting regimes inside one call**: what the log meant depended on which
transport the run happened to take.

The governor owns the rate limit, the concurrency cap, the kill switch and that
log. It is the only component that could have bounded a brute-force we did not
intend to perform, and it could not see one.

---

## Part 3 — the slot moves to the POST

`WebAuthenticator._governed_request` is the one seam every request in the login
flow passes through, and a credential-bearing one **names the account**:

```python
async with self._governed_request("POST", hop_url, account=username):
    ...
```

Both form arms wrap their redirect-walk dispatch closures in it (per HOP — a 307
re-POSTs the password, and that is another attempt). The JSON arm cannot: it
rides the chokepoint, which takes the slot already, and a second acquisition of
the same semaphore would deadlock it and double-count every rate token
(invariant: `_run_subprocess` gets the halt check ONLY). So the chokepoint learns
the account instead — `HTTPClientTool.credential_account` — and both arms now
account for a credential POST the same way.

`account` non-empty is what makes a request countable. Empty — every other
request in the engagement — is byte-identical to before.

### A login is not a credential CHANGE

Naming the account also declares the request's SHAPE. Without that declaration
the destructive classifier reads the body's own field names, and `account` is a
mutation qualifier ("account settings") — so a JSON login whose identity field is
spelled `account`, which Meridian's is, classified as `credential_change` and was
**refused**, then reported as "no API login route returned a token". The form
arms have always declared `["username", "password"]` explicitly, which is what
hid it. Both arms declare it now.

### The budget

`SafetyPolicy.max_credential_attempts_per_account`, default **8**, keyed on
`(origin, account)`:

* **origin, not URL** — the JSON arm walks eight routes on one host offering the
  same password to each; a per-URL counter hands every route a fresh budget and
  bounds nothing.
* **account, not role** — the sweep tries four passwords for `admin` under four
  technology labels, and the account is what locks.

Eight is a decision, not a default nobody chose: every measured success costs 2,
so 8 leaves four times the headroom a working login needs and cuts the failing
case by half in docker mode and by more than half on the host. Declarable with
`--max-credential-attempts`; `0` removes the bound.

It does **not** promise no lockout — a policy that trips at three trips at three.
That is what part 4 is for.

### Measured after the fix, same driver, same target

| | docker | local |
|---|---|---|
| credential that WORKS | 2 POSTs, **2** action-log entries | 2 POSTs, 2 entries |
| credential that does NOT | **8** POSTs, 8 entries + 1 refusal | **8** POSTs, 8 entries + 1 refusal |

### And measured across a SWEEP, on a second target

Meridian's 64 was the projection `4 × 16`. Driven end to end against
`clinkz-dvwa` on 2026-09-07 — four distinct catalogue passwords for `admin` at
one origin, `TOOL_EXEC_MODE=local`, the governor's own counters and its
`actions.jsonl` read back afterwards:

| `--max-credential-attempts` | credential POSTs vs `admin` | action-log entries |
|---|---|---|
| `0` (the bound removed) | **64** | 64 sent, 0 refused |
| `8` (the default) | **8** | 8 sent + 7 refused = 15 |

64 is the projection, reproduced on a target that never informed it. And the
governor slot is now genuinely **per credential POST**: 64 POSTs produced 64
entries — one each, not one for the call — which is the accounting defect this
part exists to close, at the scale it actually occurs.

**The budget is keyed `(origin, account)` and the counter lives for the
engagement**, so the four sweep pairs share one budget of eight rather than
getting eight apiece. The first pair spends it; the remaining three are refused
with nothing dispatched. That is why the answer to "how many times did you offer
a password for this account" is **8** for a whole default run — the role login,
every session refresh and every sweep pair included — rather than 8 per
producer.

Each entry reads `credential attempt N of 8 for account 'acct-4417' at
http://…`, and carries the account in `signal`. The password does not reach the
log: the body excerpt goes through `redact`, and the field NAME survives because
it is schema, not data.

---

## Part 4 — the stop the target declares

`clinkz/safety/lockout.py` is the **one lockout vocabulary**, and it is shared
the way `safety/destructive.py` is shared. `_test_brute_force` owned a 26-phrase
tuple, a header read and a stop rule, because grading a login's brute-force
protection *is* reading those signals. The authenticator owned nothing.

Same observation, opposite purposes:

* the methodology reads it to decide whether the **target** is protected;
* the authenticator reads it to decide whether **we** must stop.

So the vocabulary is shared and the two verdicts are not. `classify_lockout`
reads **headers and status before body text** — a protocol artifact cannot be
page furniture and cannot be attacker-influenced content the way a body can —
and returns a `LockoutSignal` naming which of three kinds it saw:

| kind | examples |
|---|---|
| `LOCKOUT` | `account has been locked`, `too many failed`, `temporarily blocked` |
| `RATE_LIMIT` | `429`, `Retry-After`, `X-RateLimit-Remaining: 0`, `try again later` |
| `CAPTCHA` | `solve the captcha`, `verify you are human`, `invalid captcha` |

`X-RateLimit-Remaining: 7` is deliberately not a signal: a budget with room left
in it is not a refusal.

`_test_brute_force` now reads the shared classifier and stores the DECLARED kind
on each `BruteForceObservation` rather than leaving the grader to re-derive it
from a substring of the marker (`"captcha" in body_marker` was the consumer
guessing at a producer's vocabulary — invariant 82).

### Acting on it

`EngagementGovernor.observe_credential_response` classifies each login response
and records the FIRST signal per account. The refusal happens on the **next**
`authorize`, which keeps the governor's "never raises from the data path" rule
intact and puts the stop in the action log beside every other refusal. The stop
is checked **before** the budget, because it is an observation about the target
and the budget is only an assumption about it.

The refusal names what the target said and does not say the password was wrong:

> the login at `http://…` already answered with captcha (response body: `'solve
> the captcha'`) for account `'admin'`. That answer was not about the password,
> so offering another one tells us nothing and, on a lockout, extends it

### The sweep stops on the first evidence, for ANY account

`_try_default_credentials` asks `first_credential_stop()` before each pair, not
`credential_stop(url, account)`. A lockout, a rate limit or a captcha is usually a
statement about the SOURCE or the endpoint rather than about one identity, and an
engine that stops guessing `admin`'s password and carries straight on to `root`'s
has learned nothing from the evidence it just received. The log names how many
pairs were left untried.

### Captcha, specifically

A captcha-gated login was the documented case: the form arm POSTed the
credentials **into the gate**, the refusal matched none of the failure keywords,
no session material came back, and the result said "the credentials were wrong"
about a request the application never evaluated. The sweep then marked each pair
invalid on that evidence and moved on.

Two things changed. The gate's refusal is now a **stop**, so it costs one attempt
rather than N. And a login declared failed names the evidence that was
absent — `the credential POST returned 200, set no cookie, returned no token, was
not redirected away from the login page, and the exchange held no session
material from before it` — rather than asserting anything about the credential.

**Still not built:** detecting the captcha from the login page's own markup and
abstaining with nothing sent. It is one shape test on HTML the form parser
already walks, and it would take the cost from one attempt to zero. Logged here
rather than built.

---

## What this does not fix

* **A policy that trips at three.** The budget defaults to 8 and the stop is
  reactive by construction — it reads a response, so the attempt that produced it
  has already happened. An operator who knows their policy should set
  `--max-credential-attempts` below it, and the flag exists so that they can.
* **The JSON arm's route search.** Eight routes × three identity keys is what
  spends a budget on a target we have not been told about. The remedy is the
  operator's declarations (`login_api_url`, `login_field`,
  `login_content_type`), which reach the login in one attempt and which the
  budget refusal now names explicitly.
* **The body vocabulary is text the TARGET controls** (invariant 55). A target
  that answers every login with "too many attempts" stops our sweep after one
  guess — which is the SAFE direction for the authenticator, whose only power
  here is to stop sending — but it is a false negative for `_test_brute_force`,
  which would grade the login PROTECTED on a claim rather than a behaviour. That
  asymmetry is why the header and status checks run FIRST and why the phrases are
  multi-word; it is not why the phrases are safe. The methodology's own positive
  control (`auth_reached`) is the bound that remains, and closing the rest means
  corroborating a claimed lockout with a behaviour — a valid credential refused
  after the marker appears — which is a credential attempt this budget exists to
  refuse. Stated rather than closed.
* **A shared source address.** The stop is keyed per account. A rate limiter
  that answers about our IP is recorded against whichever account was in flight;
  the sweep's `first_credential_stop()` covers the common case, but a per-role
  login on a throttled source will each see it once.
