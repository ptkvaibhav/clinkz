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
parses fixtures captured from a real `curl -s -S -D - -X POST -L` against a
running Meridian — the bytes curl writes, not a plausible transcript of them
(invariant 83) — because an application that authenticates under
`TOOL_EXEC_MODE=local` and not under `docker` is a defect the mode hides rather
than a property of the application.

## Running Meridian

```bash
docker compose -f docker/docker-compose.yml up -d meridian          # :8090
MERIDIAN_LOGIN_PATH=/login docker compose -f docker/docker-compose.yml \
    up -d --force-recreate meridian                                 # the other spelling
```

Accounts: `acct-4417` / `s3cure-passphrase` (privilege 0) and `acct-9002` /
`winter-harbor-77` (privilege 10) — two genuinely different principals, so a
multi-role engagement against it has an uphill crossing to declare.
