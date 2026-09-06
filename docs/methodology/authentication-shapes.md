# Authentication shapes — observing the login, never guessing its name

> Invariants 87–91 in [`CLAUDE.md`](../../CLAUDE.md). The rules are there; the
> incident is here.

## The target that found it

DVWA is form + cookie. Juice Shop is JSON + bearer. The authenticator
(`tools/auth.py`) and the authenticated-state assertion
(`engagement/auth_state.py`) were both built against exactly those two, so every
defect below was invisible: each one needed a target that combined the pieces
differently.

**Meridian Portal** (`docker/meridian/app.py`) is that third shape. It is not
intentionally vulnerable — it exercises the *authentication path*, nothing else:

| Property | Value | What it defeats |
|---|---|---|
| Login page | `/portal/gateway` | Every list of login path names |
| Login API | `POST /portal/v3/session-open`, reached only via the form's `action` | Six canned API routes |
| Identity field | `account` | `email` / `username` auto-detection |
| Session | `Set-Cookie` on a **JSON** response, no token anywhere | A token-only extractor |
| Anonymous denial | **302 to the login page**, not 401/403 | A status-class oracle |
| One protected route | `/settings` answers **200 with the login page** | An SPA shell in disguise |
| Two public routes | `/` and `/pricing`, byte-identical either way | A discriminator that fires on everything |

Its vocabulary is controlled on purpose: no page outside the authenticated area
contains "welcome", "dashboard", "logout" or "sign out", because those are the
literal strings the old success heuristic and the session-marker discriminator
match on, and a target that hands them out for free makes every result here
ambiguous.

`MERIDIAN_LOGIN_PATH` is an environment variable rather than a constant because
of one question: does an oracle read the **shape** of a redirect or the
**spelling** of its destination? Running the same application at
`/portal/gateway` and at `/login` answers it in one step, and a constant could
not.

## Defect 1 — a 415 was a proven session

`_check_login_success` returned `True` on **status 415**.

The path: Meridian's login page is a real HTML form whose `action` is a JSON-only
API. The form arm posted it form-encoded to `/portal/v3/session-open`, the server
answered `415 Unsupported Media Type`, and the heuristic reached

```python
if login_path and final_path and final_path != login_path:
    return True          # "redirected away from login → success"
```

`final_url` was the form's action and `login_url` was the login page. They differ.
**No redirect had occurred at all** — the redirect chain was empty — and the
server had just stated in the clearest terms available to it that it accepted
nothing.

Three things were wrong and each is fixed separately:

1. **A 4xx is never success.** `status_code >= 400` returns `False` before any
   other test runs.
2. **A different final path is not a redirect.** The redirect test now reads
   `redirect_chain`, which is empty unless a redirect genuinely happened.
3. **Success requires positive evidence** — session material (a cookie the
   exchange set, or a token in the body) or a real redirect away from the login
   page, or an authenticated-page marker on a 2xx. The absence of a failure
   keyword is not evidence of anything.

### The 415 is not merely refused — it is used

A 415 is the one status that carries a machine-readable instruction: the server
read the request, understood it, and refused it *for a reason it named*.
`_negotiated_content_type` reads that reason from three channels, protocol first
— `Accept-Post`, `Accept`, then the JSON shapes an API uses to say the same
thing (`{"expects": {"content_type": ...}}`) — and the credentials are re-POSTed
to the same action under that type.

**Prose is never parsed.** A body saying "please send application/json" states
nothing machine-readable, and a guard that reads text the target controls is a
suppression primitive handed to the target (invariant 55). A 415 naming a type
we cannot encode is reported, not guessed at.

The field names come from the form's own HTML and the encoding from the server's
own answer. Neither half of the successful request is a guess — which is the
only reason this retry is allowed to exist.

### A success that carries no session is a contradiction

The old code produced `success=True, session_cookies={}, bearer_token=""` and
handed it on. `assert_authenticated` then failed with *"no session material was
supplied"* — an accurate message about the wrong component, three layers from the
code that invented the success.

`_require_session_material` catches it at the seam where the claim is made.

## Defect 2 — the redirect discriminator read a name

```python
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "sso", "session/new")
if anon.redirects_to_login and not authed.redirects_to_login:
```

Seven substrings stood between the engine and **the commonest denial shape in
production web applications**. `/portal/gateway?next=%2Fapi%2Forders` contains
none of them.

The decisive test: rename the page to `/login`, change nothing else, and the
verdict flips. That is a name oracle, and invariant 64 already says the alias is
OBSERVED, never inferred.

**The gate is now the redirect.** An anonymous 3xx and an authenticated 2xx on
the same URL is the boundary — the two requests differ in exactly one thing, and
that thing is the session. Where the redirect points is corroboration, gathered
and reported but never required:

* the destination is spelled like a login surface (the old list, demoted);
* the destination **serves a password input** — one extra request, made once,
  after the boundary is already established;
* the `Location` carries a query parameter whose **value** names the path we
  requested. An application that says "go here, and afterwards come back to the
  thing you wanted" is describing a login redirect by construction. The
  parameter's own name is not consulted: `next`, `return_to`, `r` and `ReturnUrl`
  are the same idea, and matching on the value reads the application instead of
  a list we would have to maintain.

`follow_redirects=False` on both arms of the comparison is what makes any of this
observable, and it stays.

### `looks_unauthenticated` deliberately did NOT change

The mid-run session sentinel still keys on `redirects_to_login`. It is a
heuristic that raises a flag for an oracle to check — never a verdict — and
firing it on *any* 3xx would flood it with the ordinary redirects a scan walks
through all day. A permanent false alarm trains an operator to skim the section
where a real one will appear (invariant 77).

## Defect 3 — the same name filter, one layer up

`_find_login_url` collected URLs from a handful of sources and then discarded
every one that did not match six path names. So Meridian could link its login
page from its own landing page, hand it to this method — and still come back "no
login surface proven".

The strategies now **collect** candidates and a single shape test decides.
Login-shaped names are tried **first**, because each shape test costs a request;
being login-shaped is no longer what makes a candidate *eligible*, only what
makes it *early*. `LOGIN_SHAPE_PROBE_BUDGET` bounds the walk and announces itself
when it bites, because a bound that decides coverage is never silent
(invariant 14).

The sources it collected from were another matter — most of them had never
produced anything, `login_urls` included. See defect 9.

## Defect 4 — one message for three different failures

The abort message said, unconditionally:

```
  - the application has no URL that behaves differently when authenticated
    among the ones tried; supply a known authenticated-only URL
```

On the run that produced it, `attempted` was empty. **The assertion never ran**,
and the credentials had never been offered to the application at all. All three
of the message's remedies were wrong at once, and an operator acting on the third
would have gone looking for a protected URL to declare for a session that failed
three steps earlier.

**An error may not assert a negative about a comparison that was never made.**
The per-role line now reports which of three things happened:

| What happened | What the message says |
|---|---|
| Nothing was dispatched | No credential was ever offered; which step ended it; the URL we would have used |
| A credential POST was dispatched and refused | The URL it **actually went to** — not the login URL, whenever a form `action` pointed elsewhere — and why |
| The assertion ran and found nothing | That it ran, plus every URL compared with **both** status codes |

The remedies are filtered the same way. `assert_url` is only offered to a run
that reached the assertion; the three discovery declarations are only offered to
one that did not.

`AuthResult.posted_to` is what makes the middle row sayable: "login failed at
`/portal/gateway`" and "we POSTed to `/portal/v3/session-open` and it returned
401" are different facts, and an operator cannot tell them apart from the first.

## Defect 5 — declarability

`assert_url` exists, is documented and is gate-loaded. Three things were not
declarable at all, and the worst of them was already known to the operator:

`_try_api_login` took the declared `login_url`, kept only its **origin**, and
iterated six canned routes. The operator had told us where their login lives and
we ignored it. **A declaration that is discarded is worse than no declaration,
because the operator believes the engine knows.**

Three new fields on `RoleCredential`, all of which **OVERRIDE discovery rather
than seed it**:

| Field | For |
|---|---|
| `login_api_url` | The JSON login route, when it is not the login *page* |
| `login_field` | The identity field name, when it is neither `email` nor `username` |
| `login_content_type` | The credential POST's encoding, overriding both the form's `enctype` and any negotiation |

`login_content_type` is validated against `ENCODABLE_CONTENT_TYPES` at model
construction: declaring a type the authenticator cannot produce would be silently
ignored, which is the failure the field exists to end. `extra="forbid"` already
catches a misspelled key; this catches a misspelled value.

## Defect 6 — the arms ran in a fixed order

The form arm ran unconditionally and the JSON arm only saw what it left behind.
`_encoding_order` now decides from what was observed, strongest first:

1. the operator declared a content type;
2. the login URL serves `application/json` — it is an API, not a page;
3. the form declares an `enctype`.

With none of them the answer is **form-first**, which is unchanged behaviour for
every target that worked before — and it is the arm that can read a form
`action`, which is the only way a JSON login route at an unguessable path is ever
discovered. Meridian is found by the form arm and authenticated by the
negotiation, not by the ordering.

## Defect 7 — the credential POST followed a redirect nobody checked

Found while reviewing defects 1-6, and it is the one an attacker reaches most
easily.

`_resolve_post_url` scope-checks where the credentials go FIRST, because the
form's `action` is written by the target and read *after* `validate_input`
checked the login URL. It does not check where they go SECOND. Both form
credential POSTs were dispatched with `-L` / `allow_redirects=True`, and the
JSON arm with `follow_redirects=True`, so the transport chose the next
destination on its own.

**A 307 preserves the method and the body.** That is the whole defect:

```
POST /session         creds ──▶  target       "307, Location: https://attacker.tld/collect"
                                    │
              transport follows ────┘
POST /collect         creds ──▶  attacker     ← scope never saw this URL
```

Controlling the form's HTML is not required — shaping one response is enough,
which is a strictly weaker position and available to anything on the path. And
the 415 renegotiation would have earned a second copy of the credentials in
another encoding at the same destination.

The 3xx is now **observed**. The classifier reads the `Location`, resolves it
against the URL that answered, scope-checks the result, and returns the hop to
take:

| Status | Follow-up | Why it is still scope-checked |
|---|---|---|
| 307, 308 | re-POST, same body | carries the credentials verbatim |
| 301, 302, 303 | bodyless GET | carries the cookie jar |
| any 3xx with no `Location` | stop | reading it as a redirect would invent a chain |
| destination out of scope | **refuse** | nothing is dispatched to it |

Each in-scope hop is then dispatched as its own request, capped at five. What
the two execution modes *recorded* about that walk is defect 8.

**A refusal aborts, and it is terminal.** `AuthResult.scope_refusal` carries the
destination, and `authenticate()` returns on it rather than running the other
arm — which would offer the same credentials to the same target at six more
routes and then report "no API login route returned an auth token", a true
sentence about the wrong thing. The message keeps defect 4's distinction: the
credential POST **was** dispatched, to an in-scope URL the target's own form
chose, and only the redirect was refused.

The control is the seeded-leak shape, in
`tests/test_tools/test_credential_redirect_scope.py`. `127.0.0.2` is a real,
bindable, **reachable** host that a scope naming only `127.0.0.1` excludes, so
the collector standing there is one the credentials could actually arrive at —
a destination that merely fails to resolve would prove nothing, because nothing
can reach it either way. The file proves the collector works by handing it a
credential directly, then observes it receive nothing while the in-scope form
action still gets the POST. Run against the pre-fix code it records
`('POST', '/collect', 'account=…&password=…')`.

## Defect 8 — three classifiers, and the hops nobody counted

Defect 7's fix landed as three copies of one rule, one per transport: the
aiohttp form arm, the curl form arm, and the JSON arm over `HTTPClientTool`. The
third site was found while reviewing the first two, which is the wrong way to
find the third site. Three implementations that must agree is two chances to
drift, in the seam that decides where plaintext credentials go.

The rule now lives once, in `src/clinkz/tools/redirect_walk.py`. Writing it once
surfaced three things the copies had each got slightly wrong.

**The body decays one way.** Every arm recomputed the flag per hop:

```python
carries_credentials = hop.action == "resend"      # per hop, from scratch
```

So `POST → 302 → GET → 307` re-acquires the body. A third destination, named by
the second response, receives the credentials the first response had already
declined to carry. The walk's flag is monotonic — `carrying = carrying and
hop.action == RESEND` — so once a hop is a bodyless GET, every later hop is.

**The hops carrying no credential were never bound.** Three of them:

| Exchange | Followed redirects via | What it carries |
|---|---|---|
| the login-page GET (`_execute_aiohttp` step 1) | aiohttp's default | the cookie jar; the form it parses |
| `detect_auth_mechanism`'s candidate walk | `follow_redirects=True` → `-L` | nothing, and it is still a request |
| `_corroborate_destination` | `follow_redirects=True` → `-L` | nothing, and the URL comes from the target's own `Location` |

None of them carries a credential body, which is why they were missed. A request
to a host nothing authorised is outside scope whatever it carries, and a hop
that *did* carry the jar would be a session handed over. `_ToolHttpProbe` no
longer passes `follow_redirects` down to the transport at all: it walks the hops
itself and gates each destination through `validate_input`, the same scope check
every other request in the engagement passes — so a refusal lands in the run's
scope-refusal record with the usual attribution rather than in a second copy of
the containment test.

Fixing the login-page GET also removed a divergence that has nothing to do with
scope. aiohttp followed it and curl did not, so a login page behind a redirect
authenticated under `TOOL_EXEC_MODE=local` and failed under `docker`. And the
form's relative `action` was resolved against the URL we ASKED for rather than
the one that SERVED the form:

```
GET  /login          ──▶ 302, Location: /app/portal
GET  /app/portal     ──▶ 200, <form method=post action="session">
POST /session        ──▶ 404          ← resolved against /login
POST /app/session    ──▶ 200          ← resolved against what answered
```

**`redirect_chain` had two meanings, and the success oracle reads it.** aiohttp
filled it from `resp.history` — the URLs that *answered* with a redirect — and
curl from the raw `Location` header values, unresolved. `_check_login_success`
rule 2 asks whether a redirect landed somewhere other than the login page:

| Shape | aiohttp chain | verdict | curl chain | verdict |
|---|---|---|---|---|
| `POST /session` → `302 /portal/gateway?error=1`, no cookie | `[…/session]` | **success** | `[/portal/gateway?error=1]` | rejected |
| `POST /login.php` → `302 index.php`, cookie set | `[…/login.php]` | (cookie decides) | `[index.php]` | success |

Row one is a **rejected credential scoring as a session**, and it is reachable
on any application whose form `action` is not its login path — the same shape
defect 1 was about. Row two shows the curl side comparing
`urlparse("index.php").path` against `/login.php` and getting the right answer
for no reason.

The chain is now the **absolute destinations a redirect pointed to, in hop
order** — which is what the classifier already computed and then discarded. Both
transports produce the identical list for the identical target.
`_parse_curl_exchange` no longer returns a location list at all, so the second
meaning has nowhere to come back from.

The control is defect 7's, extended in the same file. The out-of-scope collector
now records the `Cookie` and `Authorization` headers it receives as well as the
body, and is proved live by handing it a session directly — the same
seeded-leak discipline applied to the other thing a followed redirect hands
over. `TestRedirectChainHasOneMeaning` drives one rejecting login through both
execution modes and asserts the success oracle is handed the same absolute chain
by each.

## Defect 9 — login discovery read four producers that had never produced

Defect 3 removed the name filter from `_find_login_url` and defect 3's follow-up
added the landing-page anchor reader, because the crawl does not exist yet at
authentication time. What neither did was remove the sources that had been
feeding the filter nothing:

| Source | Producer | Runs before auth? |
|---|---|---|
| `recon_result["login_urls"]` | none — nothing in the tree writes it | — |
| `hosts` / `results` / `endpoints` / `urls` keys | not on a v2 `ReconResult` at any nesting level | — |
| `scan_result` parameter | passed `None` at both call sites | no |
| `state.get_endpoints()` | `agents/scan.py`, the only `add_endpoint` caller | **no** |
| `recon_result["summary"]` | the recon synthesis LLM | yes |
| `_linked_urls(base)` | the landing page's own anchors | yes |

Only the last two had ever contributed a candidate. In most code that is
ordinary dead weight; here it is the method whose entire history is a name
oracle, so a dead branch is exactly where one is reintroduced with nothing to
catch it.

The tests made that worse rather than better. `TestLoginUrlIsRankedByShapeNotName`
pinned *names order the work, they do not gate it* — the right property — by
feeding a `scan_result`, so it asserted the property against a path production
cannot execute and counted as coverage of one it does. They now drive
`_linked_urls`.

The other option, moving authentication after the scan phase so the crawl
exists, is not a pricing question: the scan phase **consumes** the session
authentication establishes. Running it first scans an authenticated application
anonymously, which is the empty report that reads as a clean bill of health.

`technology` went with the `login_urls` branch — it was the only reader — and
with it the per-technology cache over a function that never varied by
technology.

The guard is computed, not declared
(`TestLoginDiscoveryReadsOnlyProducersThatHaveRun`): `run()`'s call sequence is
read by AST walk to confirm authentication still precedes the concurrent phase,
the endpoint table's writer set is computed from the tree, and only then is
`_find_login_url` asserted to take no `scan_result` and call no
`get_endpoints`. A second endpoint producer, or a reordered `run()`, fails the
guard rather than silently widening it.

## Defect 10 — the name oracle survived the fix, on the default transport

Defect 2 took the name gate out of `assert_authenticated`. It was still live one
module away, in the session check:

```python
# _verify_session_curl, and _verify_session_aiohttp said the same thing
if status in (301, 302, 303, 307):
    if any(hint in redirect.lower() for hint in ("login", "signin", "auth")):
        return False
```

Three substrings, matched against `%{redirect_url}` — on the arm
`TOOL_EXEC_MODE=docker` (the default) uses, and on the path the
default-credential sweep runs through when it re-verifies a session it
established. `/portal/gateway` fails it today: the session is dead, the app says
so with a 302, and `verify_session` returns True.

The curl arm was worse than a name gate. It ran with `-o /dev/null`, so the
response body — the one thing that could have said "this is the login page
again" — was discarded before anything could read it, and the redirect it did
read was never scope-checked.

**Both arms now FETCH and one function DECIDES.** `_session_survived` takes the
status and the body of the response that answered and applies two observations:
a 401 or 403, and an `<input type="password">` in the body — the same
deterministic signal `detect_auth_mechanism` uses to decide a page is a login
surface at all. The redirect is not sniffed, it is **walked**, through the same
`walk_redirects` primitive every other exchange here uses, so a 302 to
`/portal/gateway` and a 302 to `/login` are settled by what the destination
serves. Walking it also puts the session material back inside the scope gate.

### The domain, computed

Fixing one function is fixing one function. A grep for three substrings is the
same guess one layer up, so
`tests/test_tools/test_session_verdict_name_oracles.py` computes the set this
rule binds:

* **Sinks are declared** — ten seams where an authenticated / not-authenticated
  decision is taken, each with the decision it makes.
* **The domain is computed** — every function whose return reaches one of those
  sinks through a *verdict-carrying* edge: a call or property read whose value
  lands in a `return`, a branch test, a comparison, a boolean operator, an
  `assert`, or a local that later reaches one of those. A callee whose result is
  appended to an evidence list or passed on as an argument decides nothing and
  is not in it. **70 functions**, across `tools/`, `engagement/`, `agents/`,
  `orchestrator/`, `models/`.
* **The flag is computed** — 22 of the 70 compare a value against a string
  literal, resolved through module constants, local assignments, and the
  iterables of `for` loops and comprehensions. That last part is the guard's own
  near-miss: the first detector read only the `Compare` node, so
  `any(hint in location for hint in _LOGIN_HINTS)` was invisible to it and the
  very oracle the file is named after went unflagged.
* **The classification is declared** — what each of the 22 actually tests: a
  cookie name, a header name, a JSON key, a media type, URL grammar, a body
  marker, a token this engine itself wrote, or a **destination's spelling**.

Both directions are asserted, and the resolution is import-aware rather than by
simple name: resolving `self.x()` and `.get` by spelling alone put 180 functions
in the domain, most of them coincidences. A domain nobody can read is not a
domain anybody checks.

**One member is classified `destination_spelling`:**
`ProbeResponse.redirects_to_login`. It is kept, and it carries a licence naming
every consumer and the bound on each — `looks_unauthenticated` raises a
hypothesis an oracle answers (invariant 37); `detect_auth_mechanism` labels a
surface UNKNOWN, which is a statement about what could not be determined; and
`read_auth_artifact`'s fourth arm treats a *not*-login-spelled redirect as
authenticated state, where the differential bounds it — a login page this list
does not recognise makes the **control** arm authenticated too, and
`decide_auth_bypass` then refuses to confirm. An unrecognised spelling costs
coverage there, not honesty. The session assertion may never read it again, and
that is asserted as a call-graph fact rather than a grep.

## Defect 11 — the pre-credential cookie was the control arm, merged into the treatment

`_check_login_success` rule 1 accepted "session material" as proof a credential
worked. Both form arms handed it the merged jar: the login-page GET's cookies
unioned with the POST's.

A framework that starts a session on the login **GET** to hold a CSRF token —
PHP does, Django does, most of them do — therefore satisfied rule 1 *before a
credential had been sent*. A wrong password answered `200 <the login page
again>` scored as a proven session, and the only thing between that and the
report was the failure-keyword list: seven substrings, none of which appear in
"Those details do not match".

**Session evidence is the DELTA across the POST boundary.** Both arms now
collect `Set-Cookie` across every hop of the credential walk — and only that
walk — and hand *that* to rule 1. Evidence and carriage are separated, because
they are different questions: `AuthResult.session_cookies` still carries the
GET's cookie, since on a framework that promotes a pre-login session in place
that cookie IS the session and dropping it would break every later request.

The JSON arm needed no change and now says so: it has no login-page GET, so
every cookie it can see is post-credential by construction.

## Defect 12 — multi-cookie `Set-Cookie` was lossy on both transports

`sid` + `csrf` on one response loses one, and **the transport picks which**:

| producer | how it collapses | which cookie survives |
|---|---|---|
| `HTTPClientTool._parse_curl_output` | joins duplicate headers with `", "` | the first (a consumer splitting on a guessed separator keeps it) |
| `HTTPClientTool._execute_aiohttp` | a dict comprehension over a `CIMultiDict` | the last |

A `dict` cannot hold a header a response legitimately sends twice, and no
consumer can undo the join: a cookie value may itself contain a comma, so
splitting the joined string is a guess about a separator this code chose.

**The producer declares the list.** `HTTPClientOutput.set_cookie` and
`HopResponse.set_cookies` carry `Set-Cookie` verbatim, one entry per header, read
off the multidict and off the header block where the full list still exists;
`_cookies_from_set_cookie` is the one parser. `WebAuthenticator._parse_set_cookies`
- which scanned the raw curl dump line by line, **including response bodies**, so
a page rendering the text `Set-Cookie: admin=1` set a cookie — is gone.

## Defect 13 — a variable that reads as a guard and gates nothing

`_FormFieldParser._in_form` was set on `<form>` and cleared on `</form>` and then
gated no collection at all. Every `<input>` on the page went into one flat bucket.

On a page with a search box, a login form and a newsletter signup, the credential
POST carried the search form's hidden token, the newsletter's `list_id`, and —
because the newsletter's `email` input was the last identity-shaped field parsed —
put the username in **`email`** instead of `account`. A rejection caused by fields
the login form never declared would have been reported as "the credentials were
wrong".

Fields are now collected **per form**, and which form is the login form is decided
by shape: the one carrying a `type="password"` input, falling back to the first
`method="POST"` form, then the first form, then — only when the page declared no
form at all — the inputs outside one. That first rule is the same deterministic
signal `serves_login_form` uses. A variable that reads as a guard and gates
nothing is worse than no variable, because the next reader believes the guard is
there.

## What one role is offered — an accounting, not a fix

The authenticator has no concept of account lockout. `_test_brute_force` does: it
sends 8 attempts, watches for lockout / rate-limit / captcha markers, and **stops
early on a hard lockout**. None of that exists on the login path, and locking out
an account a client handed us is a harm we cause.

Per `authenticate()` call, one role, one login URL, no operator declarations:

| arm | credential POSTs | why |
|---|---|---|
| form, aiohttp (`local`) | 1-4 | `max_attempts = 2`, and each attempt may re-POST once under a 415-negotiated type |
| form, curl (`docker`, the default) | 1-2 | single shot, plus the same 415 re-POST |
| JSON (`_try_api_login`, runs whenever the form arm fails) | 7-24, typically 14 | `routes × bodies`: up to 8 routes (declared + `login_url` + 6 canned, deduped) × up to 3 identity keys (declared, `email`, `username`). Every non-2xx `continue`s, so the loop runs to completion |

**One `authenticate()` is therefore 16-18 credential POSTs against one account in
the ordinary failing case, and up to 28.**

That call happens more than once:

* once when the engagement authenticates;
* again from `_verify_and_refresh_session` whenever `verify_session` says the
  session is gone — and the `SessionSentinel` can trigger that more than once a
  run;
* once **per default credential pair** in the sweep, which runs only when the
  operator supplied none. The catalogue holds four distinct passwords for
  `admin` (`password`, `admin`, `tomcat`, `admin123`); two of them are `generic`
  and are seeded for *every* technology recon identifies, so `admin` sees at
  least two pairs and up to four.

**Worst realistic sum against `admin`, docker mode, sweep active: 4 pairs ×
16 = 64 credential POSTs to one account**, 72 in local mode — with no lockout
awareness anywhere and no counter shared between the three paths.

Two further facts an operator would want:

* The governor paces this (5 req/s, concurrency 4) but does not bound it. Its
  slot is taken per `authenticate()` call, not per credential POST.
* The **action log under-counts**. `execute()` takes ONE governor authorization
  for the whole form arm — both attempts, the 415 re-POST, every redirect hop —
  because that arm drives aiohttp and curl directly. The JSON arm rides
  `HTTPClientTool`, so its 7-24 POSTs are individually authorized and logged. Two
  accounting regimes inside one call.

No fix is made here. The numbers are the deliverable.

## Captcha-gated login does not abstain — logged, not built

A login behind a captcha is not detected. The form arm parses the page, POSTs the
credentials **into the gate**, and reads the refusal as bad credentials: the
`failure_keywords` list matches nothing, no session material comes back, and the
result says "the credentials were wrong" about a request the application never
evaluated. The default-credential sweep then marks each pair invalid on the same
evidence and moves on.

That is the three-wrong-bullets failure again — a wrong cause, reported
confidently. Detect-and-abstain is cheap: the login page already parses, and a
captcha declares itself in the markup a form-shaped detector can read the same
way it reads `type="password"`. Converting this from *silently wrong* to
*correctly refusing* costs one shape test and an `AuthResult.failure_stage` that
says the login is gated. Solving the captcha is out of scope and always will be.

Logged here rather than built: it is a real gap, it is not this branch's work,
and an operator reading a "the credentials were wrong" abort against a
captcha-gated login deserves to find this paragraph.

## The regression that is the test

`tests/test_engagement/test_meridian_auth.py` runs Meridian in a thread on an
ephemeral port (standard library only — no container, no network beyond
loopback) and asserts that **`/portal/gateway` and `/login` reach the same
verdict**.

The equality is on `(established, discriminator, authenticated_status,
anonymous_status)`, not on `established` alone. That matters, and the old code
proves why: under the name gate, `/portal/gateway` still reached
`established=True` — by `session_marker`, a body keyword — while `/login` proved
it by the actual boundary. An equality assertion on `established` would have
passed. A name oracle passes every test that only ever spells the login page the
way it expects.

Both execution modes are covered. `tests/test_tools/test_auth_curl_path.py`
parses fixtures captured from a real `curl -s -S -D — -X POST -L` against a
running Meridian — the bytes curl writes, not a plausible transcript of them
(invariant 83) — because an application that authenticates under
`TOOL_EXEC_MODE=local` and not under `docker` is a defect the mode hides rather
than a property of the application.

**And reading the two arms side by side is not enough.** Every divergence between
them was found that way, one at a time, after a live run had already gone wrong.
`tests/test_tools/test_auth_transport_equivalence.py` is the other half, and it
has the same shape as the `/portal/gateway` ↔ `/login` equality: **the equality
IS the test, and it has a domain where inspection does not.** Eight scenarios —
each one a shape the arms have actually diverged on — are served by one scripted
loopback origin, replayed once through `_execute_aiohttp` and once through
`_execute_curl` (a real `curl`, `TOOL_EXEC_MODE=local`), and three things are
compared: the verdict tuple, the exact surviving cookie set, and how many
credential-bearing POSTs the origin received.

The attempt count is **not** asserted equal, because it is not: the aiohttp arm
retries a failed login once and the curl arm does not. Each scenario declares a
number per transport, and where they differ it must say why — a divergence note
nobody can point at is how a real one gets absorbed. Where they agree, a reason
is refused.

## Running Meridian

```bash
docker compose -f docker/docker-compose.yml up -d meridian          # :8090
MERIDIAN_LOGIN_PATH=/login docker compose -f docker/docker-compose.yml \
    up -d --force-recreate meridian                                 # the other spelling
```

Accounts: `acct-4417` / `s3cure-passphrase` (privilege 0) and `acct-9002` /
`winter-harbor-77` (privilege 10) — two genuinely different principals, so a
multi-role engagement against it has an uphill crossing to declare.
