# Adaptive authentication — the model proposes, the oracle decides

> Invariant 102 in [`CLAUDE.md`](../../CLAUDE.md). The rule is there; the target,
> the measurement and the shape of the thing are here.
> Predecessor: [`authentication-shapes.md`](authentication-shapes.md), which is
> the deterministic pass this layer runs *after*.

## The target that found it, and why reading harder does not fix it

Every previous defect in this engine's auth stack was a reading defect: a name
oracle where a shape oracle belonged, a boolean where three values belonged, a
control arm that was missing. Each one was fixed by reading the target more
carefully, and each fix made the deterministic path strictly stronger.

cal.diy is the first one that is not.

| What the deterministic pass reads | What it says |
|---|---|
| `<form noValidate data-testid="login-form">` | declares **no `action`** |
| the credential POST | **defaulted** to `/login`, because nothing named a destination |
| GET `/login` vs POST `/login` | **byte-identical**, ~383,5xx bytes, for any account |
| hidden fields | `csrfToken`, with **no cookie of that shape** in the jar |
| response headers | `X-Powered-By: Next.js`; `Vary: rsc, next-router-state-tree` |
| referenced bundles | **31 chunks, 1.66 MB** |

The destination this application actually authenticates on is composed at
runtime from a base in one chunk and a provider literal in another. **It is not
a literal anywhere** — not in the HTML, not in a header, not in any single file
the target serves. The route *is* recoverable from the full chunk set (engagement
`00ad137e` fetched 8 of 31 and missed it), and that is a real gap worth closing
in the ingestor — but closing it does not make this a reading problem in general.
The general problem is that a framework's route convention is a property of the
framework, and the deployment need not state it anywhere.

What produces the destination is *knowing the stack*. An application whose login
form posts nowhere, which ships a `csrfToken` field, and whose headers name a
particular framework is using an auth library whose routes are a property of the
library. That is knowledge a language model has and a parser does not, and it is
the first thing in this project a model can contribute that the deterministic
layer cannot compute.

So the agent's job is stated narrowly: **propose the destination from the
framework identity plus the deterministic facts already held.** Not find it, not
search for it, not crawl for it.

## Deterministic first, and it is a property of the call graph

The layer is reached from exactly two places, both inside
`OrchestratorAgent._authenticate_role`, each guarded by a test for the session
not being seated:

* the credential exchange failed (`not result.success`), or
* the exchange produced session material and `assert_authenticated` could not
  prove it (`not assertion.established`).

DVWA, Juice Shop and Meridian all seat and prove a session deterministically, so
on those three the layer is not merely unlikely to engage — it is unreachable.
Each of them carries a `NOT_ENGAGED` transcript with zero LLM turns and zero
requests, which is how the claim is *shown* rather than asserted.

`test_auth_agent_deterministic_first.py` holds three layers of that:

1. **The call graph** — `_adaptive_auth` has exactly two call sites and both are
   in `_authenticate_role`. A third, added anywhere, fails the test. "We only
   call it on failure" is a property of the graph, not of a comment.
2. **An LLM that raises on contact.** A fake that merely counted calls would let
   a zero pass for the wrong reason: a fake nobody wired up also records zero.
   The paired positive control drives the same harness with a *failing* login and
   asserts the model IS reached.
3. **The shapes themselves.** DVWA's and Meridian's forms declare an `action`, so
   the POST is addressed rather than defaulted; the contrast case — a form
   declaring nothing — is asserted beside them. Tying the negative to that
   property rather than to a target name is what keeps the test meaningful when a
   fifth target arrives.

## The three rules that make a model safe in the credential path

### 1. The model proposes; `assert_authenticated` decides

There is no field on any type in `engagement/auth_agent.py` that an LLM can set
to mean success. `AuthProposal` — the *only* thing parsed out of a model's answer
— has no `established`, no `outcome`, no verdict of any kind.
`AuthAgentOutcome.AUTHENTICATED` is written at one place, on the line after the
assertion returned `established=True`, and that assertion is the same
anonymous-control comparison that proves every other session in this engine.

The test that pins this is a pair: the same proposal, the same dispatch, the same
`200`-with-a-cookie, differing **only** in what the asserter says. One
authenticates and one abstains. If the loop could conclude anything from the
exchange itself the two would not differ, and the assertion would be decoration.

### 2. The model names FIELDS; the engine supplies every VALUE

A proposal carries field *names*, chosen from a set the engine observed: the
login page's own inputs, and the top-level keys of a JSON body a previous read
returned. Values are looked up from what the target served. The credential itself
is inserted by the loop — it is never quoted into a prompt and never echoed back
by the model.

There is no body field on `AuthProposal`, no header field, and no raw-request
field. A model answering `{"body": "user=admin&pass=hunter2"}` has nowhere for
that to land. So the worst a confused or compromised model can do is name the
wrong route or the wrong field; it cannot author the bytes of a request and it
cannot move a secret.

The one path by which a value from a *response* enters a credential body is a
read: its JSON keys become referenceable names, the loop stores the values, and
the model is shown the names only. That is what makes an application whose
credential exchange needs a fetched token reachable at all — without the model
ever authoring the token.

### 3. Every proposal passes a deterministic gate before anything is sent

`validate_proposal` is pure, reads no model output but the proposal it is
judging, and runs identically whichever provider produced it. Ten refusals, each
named, each with its own fix:

| Refusal | What it catches |
|---|---|
| `not_a_url` | a relative destination — resolving one here would make the gate choose the host |
| `out_of_scope` | the one place in this engine where a destination is named by neither the target nor the operator |
| `method_not_permitted` | a read using a writing method; a credential in a URL |
| `content_type_not_encodable` | a type the engine cannot encode — refused rather than downgraded, so the transcript never describes a request nobody made |
| `no_identity_field` | the engine will not choose the credential's field names itself |
| `unknown_carry_field` | a field name nothing observed supplies a value for |
| `destructive` | `safety/destructive.py`, unchanged — a login shape is not a licence to POST anywhere |
| `budget_spent` | the per-account credential budget |
| `read_ceiling` | reads cost no credential budget, which is exactly why they need a bound of their own |
| `repeat_of_refused` | a request this episode already settled — refused here, or dispatched and answered — carrying the same fields |

The corpus driver exercises all ten against URLs the corpus actually contains
(below). The first version of that driver reported `destructive` as *unfired*,
because its scope predicate was exact-URL and every destructive case names a path
under the target — so the out-of-scope rule shadowed it one line earlier. A gate
whose later rules are shadowed reports clean for the same reason a dead
instrument does.

## The budget is the binding constraint, and it cannot be spent past

The per-account budget (`SafetyPolicy.max_credential_attempts_per_account`,
default 8) is already partly spent by the deterministic attempt when this layer
starts, and the remaining balance is handed in. `EngagementGovernor
.credential_attempts_remaining` is the pre-flight, and it exists because a loop
that proposes an attempt it cannot afford spends a turn and learns nothing.

Two properties, both tested:

* **It never disagrees with the gate it is checking.** A pre-flight saying "one
  left" where `authorize` refuses would send a caller into a refusal it had just
  been told it could avoid.
* **A recorded stop returns zero ahead of the arithmetic** (invariant 92). The
  target telling us it has stopped evaluating credentials outranks a budget we
  assumed; "seven remaining" against a locked account is true and useless.

An unconfigured bound returns `None`, not `0` — `0` already means *unbounded* to
`_credential_decision`, so returning it here would make a caller read the
unbounded case as the spent case and refuse everything.

The dispatcher routes through `HTTPClientTool` with `credential_account` armed,
which is the **second** site in the engine to arm it. That count used to be a
test (`test_only_one_place_arms_the_chokepoints_counter`) and a count is the
wrong instrument for the property it was protecting: it refuses a *correct*
second arming exactly as loudly as an accidental one. It is now a declared table
— `DECLARED_ARMING_SITES` — so a new arming site fails the build until somebody
writes down what it sends and why the budget should see it.

## The episode carries its own cookie jar

`session_mode='isolated'`. The first turn is often a read whose only purpose is
to be issued a token the credential POST must present, so cookies plainly have to
persist *across* the episode; they must equally not leak *out* of it, because the
engagement's shared jar may already hold a session from a default-credential
sweep and a route that reflects whatever it is sent would then produce a
"session" the engagement handed itself. Isolated is exactly that pair: explicit
cookies go out, nothing that comes back enters the shared jar.

## An abstention is a result

`ABSTAINED` carries what it read, what it proposed, what came back and what it
concluded — and the reason names what was **absent**. It may never say the
credentials were wrong, for the same reason invariant 91 forbids it on the
deterministic path: nothing in this loop evaluates a credential, and a run whose
POSTs were answered by routes that never evaluated one has observed nothing about
it at all.

`NOT_ATTEMPTED` is kept separate from `ABSTAINED` because "we tried three
destinations and none worked" and "we never got to try one" are different
sentences with different fixes. The budget being spent before the layer starts is
the second, not the first.

## What the client sees

The Authentication section renders on **every** run, including the ones where the
layer never engaged. A section that appeared only when a model steered the login
would make its presence the signal, and a reader would have to know the section
exists to read its absence — the same rule the crawl-budget disclosure follows
(invariant 15).

Three facts, separated because they are separate in the engine:

* **which layer seated the session** (`seated_by`, deterministic or adaptive);
* **what the adaptive layer proposed**, with the model's own rationale verbatim;
* **what it concluded**, including when it concluded nothing.

A session the adaptive layer seated is still a session `assert_authenticated`
proved, and the proof rendered above it is identical either way. Separating them
is the point: the strength of the proof does not depend on which layer found the
destination, and a reader deciding how much to trust the authenticated coverage
is entitled to both facts rather than to the stronger one alone.

The transcript is redacted twice on the way to `outputs/`. The first control is
this module's own rule — cookie VALUES never enter a transcript, only names. The
second is `redact_structure`, and it is the one that catches a token the target
embedded in a body excerpt, which no rule here could have anticipated because the
target chose the bytes.

## The prompt does not name the answer

`src/clinkz/agents/prompts/auth_agent_system.md`. A prompt naming the library or
the route would be a benchmark-tuned list wearing a paragraph, and the capability
claim would be worthless — the model would be reading the answer back rather than
recognising the stack. `TestThePrompt.test_the_prompt_names_no_route_and_no_library`
asserts the absence of every spelling of the answer for the target this was built
against, and a second test asserts the prompt and the gate describe the same
system: a prompt promising more freedom than the gate allows spends every turn on
refusals, one promising less suppresses the proposals this layer exists for.

## The corpus replay

`scripts/auth_agent_corpus.py`, offline, over `outputs/`.

Two questions with different failure modes. **Is the briefing non-vacuous on real
data?** — the agent's claim is that the deterministic pass already knows enough
to recognise a stack from, and every recorded engagement that ran a login kept
the login page's own bytes. **Which gate rules are dead instruments?** —
invariant 94's shape, one component along.

The observation is rebuilt through the engine's own reading functions, imported
rather than copied, so a change to how the engine reads a login page changes what
the driver reports.

Measured over the full corpus, 2026-09-09:

```
Login exchanges replayed:            350   (192 bundles, 15 distinct login URLs)
Briefings carrying ≤2 facts:           0
Gate rules with no firing:             0   (all ten fire)
post_changed_nothing:                 21
form declared no action:             195
```

Briefing-fact distribution: `4×3, 6×168, 7×6, 8×22, 9×148, 11×3`. The three
11-fact briefings are the cal.diy exchanges — the richest input in the corpus is
the target the deterministic path could not read, which is the shape the
capability claim needs.

Frameworks named: `PHP/8.5.6` (267), nothing (46), `Apache/2.4.25` (29),
`Meridian/1.0` (4), Next.js + RSC (4).

A positive control runs before any corpus number is printed: a plainly
permissible proposal must pass and a plainly impermissible one must be refused.
A corpus of zeros proves nothing about a measurement that cannot measure.

## Carried, not built

Two decisions made elsewhere that this work made it necessary to write down.

**`_looks_blocked`'s lost case is now a declared boundary**
(`safety/governor.py::BLOCKING_BODY_ARM_BOUNDARY`). The body arm's control
discards a signature this target already served unblocked; that costs exactly one
case — a target that *genuinely* blocks with a phrase it also ships
unconditionally. The case is accepted rather than mitigated, and the asymmetry is
the argument: what the control prevents is a **false halt**, which generates
absences that read as a clean target; what it costs is a **late halt** on one
shape, because the status arm (429/503) and the header arm are untouched and
outrank every keyword. The boundary is in `stats()` beside
`benign_block_markers`, so the operator reading "we ruled out *access denied*"
finds the sentence saying what that rules out.

**The 8080→80 published-port crossing is now a named rule**
(`models/scope.py::PortGateRule`). It was an `if match is PUBLISHED_PORT: return
True` under a two-line comment, which is where a rule goes to be rediscovered.
The general form is worth stating because it is not about docker: **a port that
participated in establishing an identity cannot also be evidence against it.**
A loopback dispatch to `localhost:8080` matched `clinkz-dvwa:80` *because* 8080 is
the host port that container publishes, so comparing 8080 against 80 afterwards
compares two namespaces and refuses every docker-mode engagement. Docker
publishing is merely the only namespace crossing this engine resolves today. The
call site reads the rule rather than re-testing the enum, because a name nothing
calls is a comment with a type annotation.

## The live runs, and the four defects they found

Stage A was validated against four live targets. Three of them were meant to
prove the layer stays out of the way; one was meant to prove it does something.
All four found something.

### 1. cal.diy — the target this was built for

Cold, no `login_url` declared, `TOOL_EXEC_MODE=local` against
`http://127.0.0.1:3100`.

```
Turn 1  GET  /api/auth/csrf                  200 · JSON {csrfToken} · set next-auth.csrf-token, next-auth.callback-url
Turn 2  POST /api/auth/callback/credentials  302 → /api/auth/error?error=incorrect-email-password · set no cookie
Turn 3  GET  /api/auth/providers             200 · JSON {credentials, email}
```

The deterministic pass got a byte-identical 200 for any account. The adaptive
layer reached the destination composed at runtime from chunk 13 and chunk 28 —
**which appears in no list and in no prompt** — and got back the application's
own credential rejection. Turn 1 also produced the missing half of the
double-submit pair the deterministic pass had already observed and could do
nothing with.

The password was a placeholder (the real credential file is untracked). So the
outcome is `ABSTAINED`, and the reason is the point: the failure moved from *we
never found where to send it* to *the destination we found evaluated it and said
no*. That is an accurate reason, and an accurate reason is the pass condition.

### 2. DVWA, Juice Shop, Meridian — the layer stays out of the way

| Target | Result |
|---|---|
| DVWA (`localhost:8080`) | `established=True`, `seated_by=deterministic`, **not engaged** |
| Juice Shop (`localhost:3000`) | `established=True`, `seated_by=deterministic`, **not engaged** |
| Meridian (in-process) | `established=True`, `seated_by=deterministic`, **not engaged** |

Zero model calls, zero adaptive requests, `NOT_ENGAGED` transcripts.

Meridian needed its login URL supplied, because
`scripts/live_adaptive_auth_validation.py` skips recon and `/portal/gateway` is
in no canned list — which is Meridian's whole design. In a pipeline run the crawl
supplies it via `_find_login_url`. Run without it, the layer engaged, proposed
three safe reads, spent **zero** credential attempts and abstained: the correct
behaviour when the observations do not support a hypothesis.

### 3. Ghost — a target neither of us had configured

`ghost:5-alpine`, named before the run. Its admin panel is an Ember SPA serving
**no `<form>` at all**, and its credential endpoint is a product convention
(`POST /ghost/api/admin/session/`) in none of this engine's route lists.

```
Turn 1  GET     /ghost/api/admin/site/                            200 · JSON {site}
Turn 2  OPTIONS /ghost/api/admin/session/                         200
Turn 3  POST    /ghost/api/admin/session/  identification,password  401
Turn 4  GET     /ghost/api/admin/session/                         403 · JSON {errors}
Turn 5  POST    /ghost/api/admin/session/  username,password        500 · set ghost-admin-api-session
Turn 6  GET     /ghost/api/admin/users/me/                        403 · JSON {errors}
```

The route is correct. The field name is correct by turn 5 — the agent read the
401, changed the identity field, and Ghost issued its admin session cookie. The
500 is Ghost's **second factor**: `sendAuthCodeToUser` emails an auth code and
this container has no mail configured, which is a property of the target rather
than of the layer. A manual, correct, `Origin`-bearing curl gets the same 500.

The honest part is the ending. Ghost's pre-2FA cookie is session material and is
not a session; the loop did not claim one, `assert_authenticated` refused it, and
the transcript abstained. On a cold run — with only the public blog root and no
`/ghost/` — the agent identified the product from `/public/cards.min.js` and
`/public/member-attribution.min.js` and proposed Ghost's *Members* auth instead,
which is the auth surface actually visible from there.

### The security review's finding: the jar was not origin-keyed

`/security-review` on the branch found one issue, and it is the kind that only
appears once a component starts choosing its own destinations.

`HttpToolDispatcher` accumulated every `Set-Cookie` into ONE flat jar and
presented that jar on every subsequent request. `session_mode='isolated'` sends
what it is given and asks no questions — the curl backend emits explicit cookies
as a raw `-b "name=value"` header, the aiohttp backend hands them to
`session.request(cookies=...)`, and neither applies cookie-domain scoping (the
ambient `-c/-b` jar file DOES, which is why this had never bitten). An
`EngagementScope` routinely names more than one host, so a cookie host A issued
was sent to host B on the next turn.

The proposal gate checks where a request may **go**. That is the right check and
it is not a check on what it may **carry** — and the thing being carried here is
credential material crossing the boundary this engine draws everywhere else
(invariants 63–64).

The jar is keyed by origin now, and `jar` hands the assertion the credential
origin's cookies rather than the union: a union would give the
authenticated-state assertion material from an application the credential was
never offered to, and the assertion would then be comparing a session it cannot
attribute. The scheme is part of the key, so an https-issued cookie cannot be
replayed over cleartext to the same host.

It costs the capability nothing. The loop's one legitimate need — a token
fetched on turn 1, presented on turn 2's credential POST — is same-origin by
construction, and the regression test asserts both directions: the cross-origin
cookie is absent, and the same-origin one still rides.

### The four defects

**A third credential-observation site had no control** (`HTTPClientTool
._observe_credential`). Invariant 98 gave `_login_verdict` and `classify_lockout`
a control arm and reached the authenticator's two form arms; the JSON arm
observes through the chokepoint and was missed. cal.diy's login page ships the
strings `rate limit` and `try again later` in 383 KB of shell — the two form
attempts correctly DISCARDED them, this site classified the same bytes as a
rate-limit stop, and the run refused every later credential for the account. A
stop asserting the client's account is rate limited, produced by a page footer.
The control is now armed beside `credential_account`, by the same caller, and
`test_every_credential_arming_site_arms_the_control_too` computes the domain
rather than listing it.

**The deterministic pass spent the entire budget.** 8 of 8: two form attempts,
then the JSON arm walking its route list with two identity-key shapes each. Every
one was a correct thing to try, and between them they left the adaptive layer
zero — `NOT_ATTEMPTED`, on the one target it exists for. Invariant 88's shape:
being last is what starves a consumer, so it RESERVES.
`SafetyPolicy.adaptive_auth_credential_reserve` (default 3) is held back from the
deterministic pass, clamped to `budget - 1` so it cannot starve it in the other
direction, and `0` restores the previous behaviour exactly.

**Session evidence was read off the jar, not the delta.** Invariant 91's rule,
violated by this loop's first version. Turn 1's read was issued two CSRF cookies,
turn 2's credential POST set none, and the loop ran the assertion anyway —
against the CSRF cookies. The assertion correctly found nothing, and the
abstention then said "1 credential POST produced session material", which was a
statement about the jar wearing the credential's name. The jar is carriage; the
delta (`Set-Cookie` on *this* response, or a token in *this* body) is evidence.

**The signature could not tell a corrected retry from a repeat.** On Ghost the
loop re-POSTed to a URL it had already POSTed to. Whether that was a corrected
retry or a wasted attempt is the whole question, and a signature of `(kind,
method, url, content_type)` gives the same answer to both — so it could neither
refuse the waste nor permit the fix. The field names are in the signature now,
the repeat rule covers what was DISPATCHED rather than only what was refused, and
the transcript renders the field NAMES each POST carried so a reader can tell the
two apart. The turn ceiling moved from 3 to 6 for the same reason: at 3 it was
the operative bound rather than the backstop, and it stopped both cal.diy and
Ghost one move short of the read that would have settled the question.

The re-validation run after all of that showed the same defect one field along.
The reserve worked exactly as designed — the deterministic pass was refused at
5 with the refusal naming why its share was smaller than the policy, and the
adaptive layer got its 3 — and it spent all three on
`/api/auth/callback/credentials`, rendering three identical transcript lines.
They were three legitimately different attempts, differing in **content type**,
and the signature knew it while the render did not. Everything the signature
treats as making a request different is rendered now, or a reader still cannot
tell a corrected retry from a wasted one.
