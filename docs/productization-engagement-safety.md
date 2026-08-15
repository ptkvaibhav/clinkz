# Productization P1 — engagement setup, authenticated scanning, safety rails

The pass that made Clinkz runnable against an application that is **not** a
deliberately-vulnerable benchmark. Everything here is generic; no target-specific
logic exists anywhere in it.

Three things change when the target is real:

1. Somebody has to have **authorized** it, and the report has to say who.
2. The engine has to **see** the application — an anonymous scan of an
   authenticated app produces an empty report that reads like a clean result.
3. A probe must never **damage** the target. This tool once blanked DVWA's admin
   password and only a hash check caught it.

---

## A · Engagement setup

### The authorization record — required, not a flag with a default

`AuthorizationRecord` (`models/engagement.py`) carries the authorizing party's
name, role and contact, the authorization reference, the permitted-technique
list, and an emergency contact. **Every field is required** and blank values are
rejected at validation, so the model has no partially-populated shape: "we forgot
to capture the authorizing party" surfaces as a setup error rather than a blank
line in a client deliverable.

The refusal lives at `engagement/gate.py::open_engagement`, called as the **first
statement** of `OrchestratorAgent.run()` — before the docker pre-flight, before
the state store, before a single packet. There is no path to a tool call that
does not pass through it, and no flag that skips it.

```bash
clinkz scan --target app.example.com --scope scope.json --authorization auth.json
```

`auth.json`:

```json
{
  "authorizing_party": "Dana Okafor",
  "authorizing_role": "VP Engineering",
  "authorizing_contact": "dana@example.com",
  "authorization_reference": "SOW-2026-114",
  "permitted_techniques": ["sql_injection", "xss", "idor", "lfi"],
  "emergency_contact": "+1-555-0100 (24h ops bridge)",
  "notes": "No testing against the payments provider."
}
```

The record may also be embedded as an `"authorization"` object inside the scope
file. `--authorization` overrides it.

**The permitted-technique list is enforced, not just recorded.** It gates the
Exploit Agent's dispatch chokepoint (`_technique_permitted`), refused *before*
the page fetch so an unauthorized class costs the target no request, and each
withheld class appears in the report under *Techniques not authorized*.
`["*"]` authorizes everything — but it has to be written down; an empty list is
rejected rather than read as "no restriction".

### The engagement window

`EngagementWindow` sets a hard stop at each end. Checked at startup and then
**re-checked on every request** by the governor, so a run that overruns its
window stops mid-flight rather than at the next phase boundary. Naive datetimes
are read as UTC, deliberately: a hard stop must not depend on which machine the
engagement happens to run on.

### Credentials

`CredentialSet` holds one `RoleCredential` per role, with `SecretStr` passwords.
Loaded from an **untracked local file** (`--credentials`) or a secure prompt
(`--prompt-credentials admin,user`, read without echo).

Hygiene is structural first and defensive second:

* Passwords are `SecretStr`, so `model_dump()` yields a mask.
* The credential set is **never attached to `EngagementScope`**, which is
  `model_dump()`-ed into the state store at engagement creation. Anything
  reachable from the scope is persisted; the credential set deliberately is not.
* `load_credential_file` **refuses outright** if the file is tracked by git — a
  credential file under version control is a leaked credential file — and warns
  if it is inside the repo but merely un-ignored.
* Every loaded secret is registered with `engagement/secrets.py`, whose
  `redact()` / `redact_structure()` run at every artifact writer.

*Honest limitation*: value redaction is substring replacement, so a secret
shorter than four characters is accepted but **not** substring-redacted —
replacing a two-character value would corrupt every artifact it appears in.
`register_secret` returns `False` and the loader warns, so the gap is visible.

`tests/test_engagement/test_gate_and_secrets.py::test_the_supplied_password_appears_in_no_artifact`
takes a real password through the action log, the persisted scope, and the
credential model, and asserts the plaintext appears in none of them.

### What a report bundle may contain

Everything under `outputs/<engagement_id>/` is the deliverable — not just
`report_<id>.md`. The trace, the action log, the tool-invocation records and the
step inputs travel with it, and an operator who zips the directory has handed
over all of it. The contract is one sentence:

> **An artifact handed to a client must never carry a usable session token.**

Where a token's *presence* is the evidence, the artifact records a **fingerprint**
instead — a salted hash prefix plus the algorithm, the registered `iss`/`sub`
claims, and the NAMES of the remaining claims:

```
[REDACTED:JWT sha256=032980c2f6e5 alg=RS256 claims=[data{email,password,role,…},iat,status]]
```

That is enough to correlate (*this* token was accepted where *that* one was
rejected — same value, same fingerprint) and useless to replay. Naming the claims
is deliberate: it tells the reader the token's payload carried a password hash
without the artifact carrying one. The salt is per-process, so a short
low-entropy value cannot be recovered by hashing a dictionary.

**Two definitions of "secret", because one was not enough.** Redaction removes a
string for what it IS (a registered value) *and* for what it LOOKS LIKE
(`engagement/credential_shapes.py` — JWTs, `Authorization`/`Cookie`/`Set-Cookie`
values, vendor API keys, PEM private-key blocks). Value-only redaction is
structurally incapable of removing credential material the engagement
**captures** rather than one the operator **supplies**: a live authenticated run
wrote five session JWTs into `trace.jsonl`, one of whose payload carried the
account's password hash and TOTP secret, and every writer was redacting
correctly the whole time. Nothing was registered, so nothing was removed. Shape
redaction is always on, registry or not.

Cookie **names** survive and cookie **values** do not, because a name is evidence
(`Endpoint.sets_cookies` records names for exactly this reason) and a value is
the session.

*Cost, stated rather than hidden*: `clinkz tool-invoke <id> <seq> --replay` can no
longer replay an authenticated request verbatim — the credential in the recorded
argv is a fingerprint. Re-authenticate and replay against a fresh session. A
replayable token in a client deliverable is the defect, not a feature.

### The disclosure gate (`engagement/artifact_scan.py`)

The contract above is enforced by the writers and **checked independently** by a
gate that runs automatically at the end of every engagement, after every writer
has flushed. It reads the bundle back off disk and looks with its own eyes.

That independence is the point. The check in place when the JWTs leaked searched
for the credential values the operator had *configured*, and a token the target
issued is not one of those — so it reported zero leaks, truthfully, about the
wrong question. **A guarantee asserted by the same logic that produces it is not
checked at all.** The gate shares the shape *vocabulary* with the redactor (so the
two cannot drift) but re-reads the bytes rather than trusting the write path.

Two severities, and only one fails the gate:

| Severity | What it is | Effect |
|---|---|---|
| `credential` | a definite shape — JWT with a decoding header, `Authorization` value, cookie value, vendor key, PEM private key | **fails loudly**: ERROR log, `status: credential_material_found` in the run summary, `DO NOT SHARE` |
| `suspicious` | the entropy heuristic — long, high-entropy, mixed-charset, matching no shape | reported, never fatal |

The entropy rule lives only in the gate, never in the redactor. This tool's
evidence is *made of* alarming-looking strings — payloads, extracted hashes,
base64 from an XXE response — so an entropy rule on the write path would shred
findings, and one that failed the gate would cry wolf until it was ignored, which
is the same as not having a gate.

**The scan report never contains what it found**: a finding carries the kind, the
file, line and column, the length and a fingerprint, never the value, not even a
prefix. A leak report that reproduces the leak is a new artifact with the same
defect.

The verdict is written to `outputs/<id>/artifact_scan.json` — the last file
written, and excluded from its own scan so a re-run is idempotent. Re-run it by
hand over any bundle, including an older one, with:

```
python -m clinkz artifact-scan <engagement_id>
```

which exits non-zero when credential material is present, so it can be used as a
release check before anything is sent.

#### Two regions — a guard's root is part of its verdict

The gate once reported `ARTIFACT SCAN CLEAN — 3,123 files` while a complete RS256
session JWT sat one directory up, in
`outputs/d8_auth_bypass_live_validation.json`. Nothing about that verdict was
false. It answered a question about a region that had been chosen so as to
exclude where the leak landed — structurally the same defect as a leak guard that
inspects the git tree and therefore cannot see a pull request's own title and
body.

So the gate covers two regions and returns **one** verdict:

| Region | What it is |
|---|---|
| `REGION_BUNDLE` | `outputs/<id>/` — this engagement's deliverable |
| `REGION_COMPANION` | everything else under the outputs root that no engagement's gate covers: loose files a driver wrote, named result directories (`outputs/_juiceshop_benchmark/`, `outputs/cross-service-b1/`) |

One verdict, because the operator's question is *may I share what is in this
directory*. Two regions, because "the directory around your bundle is not
shareable" is a different instruction from "your bundle leaked" — so every
finding carries its region and the rendering keeps them apart.

A directory whose name is an engagement id is some **other** engagement's bundle,
covered by its own gate, and is never swept in: a run must not be made to answer
for a leak it did not write, and folding neighbours in would re-scan thousands of
files for a verdict that is not about this engagement.

Every `summary_line()` now names its coverage — `3,123 bundle file(s) + 346
companion file(s)` — clean or not. A CLEAN that does not say what it looked at is
precisely how this survived. `--bundle-only` asks the older, narrower question
when that is genuinely what you want.

#### Drivers write through the chokepoint too

The redaction guarantee holds where the *engine* writes. A validation driver in
`scripts/` is a hand-written harness that reaches around the writers — it tees
`HTTPClientTool.execute` to capture raw exchanges and serialises them itself — so
the guarantee never applied to it. That is what put the JWT above on disk,
together with the lab password in plaintext in three request bodies, while
`report.json` from the same run was clean and the auth-bypass oracle's own
`observed` field carried a fingerprint and claim names only.

Driver artifacts now go through `scripts/_artifact_io.py`, which is a **call
site** of `redact_structure` and not a second redactor. A driver that hardcodes
`ADMIN_PASSWORD = "admin123"` is a third intake route beside the credential file
and the interactive prompt, so it registers the value on the way in — shape
redaction cannot help there, because a plaintext password has no shape.

Redaction costs a driver nothing it needs: a control arm asserts *which* token
came back where another did not, and a fingerprint answers that and replays
nowhere; `[REDACTED]` in a request body still shows the field was populated.

`tests/test_engagement/test_driver_artifact_writes.py` enforces it structurally —
it parses every `scripts/*.py` and refuses a raw `write_text`/`write_bytes`
unless the file is allow-listed with a reason. The per-driver assertions protect
the drivers that exist; only the source-level one protects the driver somebody
writes next month, and a driver is exactly the kind of file a `src/`-and-`tests/`
grep misses.

### `--dry-run`

Enumerates what the engagement *would* do — scope in and out, roles, rails,
every class it would and would not attempt with the reason, and the destructive
categories that will be refused — and **sends nothing**. That constraint is what
makes it trustworthy: a dry run that quietly crawled the target to produce a
better list would be exactly what the operator asked it not to do.

The refusal list is *demonstrated*, not asserted: the real classifier is run over
synthetic sample actions and its actual verdicts are printed.

---

## B · Authenticated scanning

### Detect the mechanism, do not assume it

`engagement/auth_state.py::detect_auth_mechanism` probes for an HTML login form
(a `type="password"` input), then a JSON login route (a route that answers a
credential-shaped POST with 4xx rather than 404/405 exists and rejected us), then
a session cookie issued with no discoverable form. Read-only — no real
credentials are submitted during detection.

Detection only runs when there is something to authenticate *with*. With no
credentials and no session, the engagement proceeds anonymously and says so,
rather than spending a dozen requests looking for a login it cannot use.

### The assertion — proven, never assumed

This is the load-bearing piece. `assert_authenticated` fetches the same URL
**twice** — once with the session material and once deliberately without — and
accepts only a discriminator that an authorization boundary produces:

| Discriminator | What it observes |
|---|---|
| `login_redirect` | anonymous redirects to a login page, authenticated does not |
| `status_class` | anonymous 401/403, authenticated 2xx |
| `login_form` | anonymous is served a login form, authenticated is not |
| `session_marker` | a logout/account marker present **only** when authenticated |
| `identity_echo` | the authenticated username present only in the authed response |

**A body-length delta is explicitly not on that list.** It is a correlate — page
chrome, a CSRF token, a timestamp all move the length with no boundary present —
and this codebase does not confirm on correlates anywhere else either.

Making the control genuinely anonymous required `HTTPClientTool`'s `no_session`
flag. The shared engagement cookie jar was read *and* written by every curl, so
without it the "anonymous" leg would have carried our own session and the
comparison would have proven nothing while looking like it proved everything.

If no candidate discriminates, `established=False` and — **when credentials were
supplied** — the engagement aborts with the full comparison printed. "We could
not prove the session is authenticated" is an honest outcome; scanning anyway is
not.

### Session maintenance

`SessionSentinel` is registered as a governor **response observer**, so it sees
every response the engagement receives. That placement matters: the code that
lost the session is exactly the code that will not notice.

It keys on being sent back to the login surface (401, a login redirect, a body
that has become a login form). A bare 403 does **not** count — 403 is the correct
answer to an authorization probe, and the IDOR class produces them deliberately.

**Only a session-bearing response is evidence about the session.** A live run
reported `session_losses_detected=15` and `reauthentications=0`, and both numbers
were wrong in opposite directions. Every one of the fifteen came from a request
the engine had deliberately sent with *no session at all*:

* the auth-mechanism probe that POSTs empty credentials to a candidate login
  route, whose 401 is the **positive** signal that an API login endpoint exists;
* the anonymous control in `assert_authenticated`, whose 401 **is the proof** the
  session works.

The sentinel was counting the controls that prove authentication as evidence
authentication had been lost. `HTTPClientTool` is the only code that knows
whether a request carried the session, so it passes `session_bearing` through
`governor.observe_response` to the observers; a session-free response is now
ignored in **both** directions — it does not count as a loss and does not reset a
streak either, because it says nothing about the session in either direction.

The zero was structural as well. The flag needed *N consecutive* signals through
one sentinel fed by three concurrent phases, so any interleaved success reset it.
A second trigger — `escalation`, a total of scattered session-bearing losses —
means a genuinely dead session diluted by public-page 200s still earns one check
instead of being invisible forever.

**The flag is a hypothesis; the assertion is the oracle.** `reauth_needed` means
"verify the session", not "the session is dead". The Orchestrator re-runs
`assert_authenticated` against the URL the startup proof succeeded at, because a
run of 401s from an authorization boundary the scan legitimately walked into is
indistinguishable from a dead session at the response level. A session that
re-proves itself is recorded as a **false alarm** and costs two requests instead
of a needless re-login that rotates a working token mid-phase. Verification
failure is not proof of health: if the probe cannot be made, it falls through to
re-authentication.

`reauthentications` counts **successes only**. It used to be incremented on the
way *in*, before anything had been attempted, so a run with no credential to
re-authenticate with still reported having re-authenticated — in the report,
which is where an operator reads that number.

The whole verify-and-refresh sequence is serialised behind a lock: Scan, Research
and Exploit poll the same sentinel concurrently, and two simultaneous re-logins
would race to write `_role_sessions` and push the loser's token.

On a confirmed loss the Orchestrator re-authenticates and **pushes the fresh
session into the live agent instances** (`_push_session_to_agents`). An agent
reads its session once, at task start, so without that push the rest of the phase
would keep using the dead one.

The report renders all five counters and explains them, so
"15 losses / 0 re-authentications" can never again be printed without saying what
the fifteen were.

### Multi-role

Each supplied role gets its own authenticated session. Access-control classes
need two principals to compare; with one role (or none) the report says so under
*Limited by the sessions available* rather than reporting boundary crossings it
could not have observed.

---

## C · Production safety rails

### The destructive classifier (`safety/destructive.py`)

Default-deny, over **path, method, field names, and button/label text**. It
classifies a *request*, not a form, so it sits at the HTTP chokepoint and sees
traffic no form parser touched — a JSON API call, a REST verb, a synthesized
link.

Categories: `deletion`, `credential_change`, `identity_change`, `payment`,
`cancellation`, `key_revocation`, `bulk_messaging`, `data_reset`,
`session_destruction`, `security_control_toggle`, `unsafe_method`.

Rules that decide the hard cases:

* `DELETE` refuses unconditionally — the verb is the harm.
* `PUT`/`PATCH` against a sensitive resource refuses: a whole-resource replace is
  a destroy-and-recreate whatever the field names say.
* `POST` alone is **not** a refusal. POST is how an application says "submit this
  form"; refusing it wholesale would reduce the engine to a read-only crawler.
* The predecessor guard's rules are preserved **verbatim**
  (`_legacy_form_verdict`), so this module can only ever refuse *more*, never
  less.

**The load-bearing detail is `_PLAIN_VALUE`.** A parameter value is read for
semantics only when it looks like an identifier the *application* chose
(`?action=delete`), never like a payload *we* chose. Our probes carry the exact
vocabulary this module refuses on — `?id=1' OR 1=1; DROP TABLE--` contains
`drop`, a command-injection probe contains `rm`, an LFI probe contains `passwd`.
Without that discriminator the safety rail would refuse the engine's own payloads
and silently reduce an authorized engagement to a crawler while every phase still
reported success.

`is_state_changing_url` and `is_destructive_form_submission` now delegate here,
so the navigation guard and the submission guard share one vocabulary and cannot
drift apart.

### The governor (`safety/governor.py`)

One object between the engagement and the network. Every request asks
`authorize()` first and reports back through `observe_response()`.

| Rail | Behaviour |
|---|---|
| Rate limit | shared token bucket, default **5 req/s** |
| Concurrency | semaphore, default **4** in flight |
| Destructive refusal | the classifier, on every request |
| Kill switch | in-process `halt()` + `outputs/<id>/HALT` sentinel |
| Blocking detection | consecutive throttle/block responses trip a halt |
| Window | re-checked on every request |
| Action log | every state-changing request, sent or refused |

Two design decisions worth stating:

**The governor never raises from the data path.** It returns a
`RequestDecision`; a refusal becomes an error-shaped tool output every caller
already handles. Raising through twenty layers of methodology code — each with
its own `except Exception` — would make "halted" indistinguishable from "that
probe failed". Stopping the engagement is the Orchestrator's job: `_run_phase`
polls `governor.halted`, winds the phase down, and proceeds to the report.

**Absent by default.** `get_active_governor()` returns `None` unless an
engagement installed one, and every hook no-ops in that case. The rails govern an
*engagement*, not a process — so the DVWA and Juice Shop smoke suites, which
invoke methodologies directly, keep their existing behaviour byte for byte.

Blocking detection is deliberately conservative, because a false trip halts a
paid engagement: 429/503 always count; 401/403/406 count only alongside a WAF
signature; the body-signature list holds only phrases no ordinary page emits; and
any clean response resets the streak.

`ToolBase._run_subprocess` gets the **halt check only**. The docker path reaches
it from *inside* the HTTP chokepoint, so acquiring a second concurrency slot per
request would deadlock the semaphore and double-count every rate token. Tools
that generate their own traffic are paced by their own flags instead — `ffuf`'s
`-rate` and `-t` are driven from the policy.

### Kill switch

```bash
clinkz abort <engagement_id>
```

Writes the sentinel the running governor polls. Within one poll interval the
engagement stops sending requests, phases wind down, and **the report is still
produced** — a halt is a clean stop, and the operator who pulled the switch needs
the report more than one whose run completed, not less.

### Action log

```bash
clinkz actions <engagement_id>            # human table
clinkz actions <engagement_id> --raw      # JSONL
clinkz actions <engagement_id> --outcome refused
```

`outputs/<id>/actions.jsonl` holds every state-changing request as `sent` or
`refused`, with method, URL, a bounded redacted body excerpt, a digest of the
full body, and — for a refusal — the category and the exact deciding signal.

Read-only requests are deliberately absent: the trace already records those, and
burying twelve mutations in forty thousand GETs would defeat the purpose.
Recording refusals alongside sends is what makes the log *checkable* — "no
destructive request was sent" is provable by reading it, and a false refusal can
be argued with instead of silently costing coverage.

---

## D · The client-ready report

`outputs/<id>/report_<id>.md` and `.json`:

1. **Authorization** — the record verbatim.
2. **Engagement window** — authorized vs actually performed.
3. **Scope** — in scope, and out of scope *"never contacted"*.
4. **Authentication** — mechanism, roles, and the discriminator that proved the
   session (or a plain statement that no session was established).
5. **Testing conduct** — rate, state-changing requests sent, requests refused,
   any halt.
6. **Findings** — severity, CVSS, endpoint, raw PoC evidence, remediation.
7. **Unconfirmed leads** — separate types, separate sections, never counted.
8. **What was NOT tested.**

### Remediation

Findings never carried remediation before this pass. The methodologies emit
*proof*, not advice, so the advice lives once per class in
`models/vuln_classes.py` and is attached at render time by resolving the
finding's own title. A title that matches nothing gets no guidance — a missing
remediation is honest; a confidently wrong one is not.

### What was NOT tested

Generated from the class registry and the run's own action log, never
hand-written, so it cannot drift out of date:

* hosts the client excluded;
* techniques the client did not authorize;
* classes with **no client-side oracle** — DOM-XSS, and CSP *enforceability*
  (the header is assessed; whether a given policy is bypassable needs a browser);
* classes with **no methodology** — Insecure CAPTCHA, business logic, races;
* action categories the safety rails refused, with counts and an example;
* coverage cut short by a halt;
* surface unreachable without a session, or without a second role.

A client reading "no findings" is entitled to know whether that means "we looked
and it is sound" or "we could not look".

---

## Files

| Path | Role |
|---|---|
| `models/engagement.py` | `AuthorizationRecord`, `EngagementWindow`, `SafetyPolicy`, `RoleCredential`, `CredentialSet` |
| `models/vuln_classes.py` | class registry — label, capability, limitation, remediation |
| `models/report.py` | `NotTestedItem` / `NotTestedCategory` + the report header fields |
| `engagement/gate.py` | the refusals (dependency-free, so the governor can import it) |
| `engagement/secrets.py` | credential intake + the redaction chokepoint (values AND shapes) |
| `engagement/credential_shapes.py` | the one credential-shape vocabulary; redactor + gate share it |
| `engagement/artifact_scan.py` | the disclosure gate over `outputs/<id>/` **and the companion region beside it** |
| `scripts/_artifact_io.py` | validation drivers' write path — a call site of `redact_structure`, not a second redactor |
| `engagement/auth_state.py` | mechanism detection, the assertion, `SessionSentinel` |
| `engagement/dryrun.py` | `--dry-run` |
| `safety/destructive.py` | the default-deny classifier |
| `safety/governor.py` | rate, concurrency, kill switch, blocking, window |
| `safety/action_log.py` | `outputs/<id>/actions.jsonl` |
