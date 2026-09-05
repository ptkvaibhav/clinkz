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
Loaded from an **untracked local file** (`--creds`, alias `--credentials`) or a
secure prompt (`--creds-prompt admin,user`, alias `--prompt-credentials`, read
without echo).

Every field except `role` is optional, and **every one of them lives on the role
entry** — `login_url` and `assert_url` included:

```json
{
  "credentials": [
    {
      "role": "admin",
      "username": "admin@example.com",
      "password": "...",
      "login_url": "https://app.example.com/portal/gateway",
      "login_api_url": "https://app.example.com/portal/v3/session-open",
      "login_field": "account",
      "login_content_type": "application/json",
      "assert_url": "https://app.example.com/account",
      "privilege": 10
    },
    {"role": "customer", "username": "...", "password": "...", "privilege": 0},
    {"role": "anonymous"}
  ]
}
```

`login_url` is per role rather than per engagement because an application's
login can differ per principal, which a single engagement-wide value could not
express — so it is not on `EngagementScope` beside `EngagementWindow`, and it is
not an environment variable. `assert_url` names a URL known to behave
differently authenticated vs anonymous; the assertion tries it first, before its
conventional-path fallbacks.

**Every declaration OVERRIDES discovery rather than seeding it.** That is the
whole point of the four login fields, and it is a correction: `_try_api_login`
used to take the declared `login_url`, keep only its *origin*, and iterate six
canned routes — so the operator had told us where their login lives and we
POSTed at six places that were not it. A declaration that is discarded is worse
than no declaration, because the operator believes the engine knows.

| Field | Declares | Discovery it replaces |
|---|---|---|
| `login_url` | The login **page** | Shape-probing the crawl and the conventional paths |
| `login_api_url` | The JSON login **route**, when it is not the page | Six canned API routes |
| `login_field` | The identity field name | Reading it from the form, then `email`, then `username` |
| `login_content_type` | The credential POST's encoding | The form's `enctype`, then a 415 negotiation |

`login_content_type` is validated at model construction against the types the
authenticator can actually encode: declaring one it cannot produce would be
silently ignored, which is the failure the field exists to end. `extra="forbid"`
already catches a misspelled KEY; this catches a misspelled VALUE.

An operator who declares none of them loses nothing — the engine reads the form
its login page serves, follows the `action`, and renegotiates on a 415. **Detail
→** [`methodology/authentication-shapes.md`](methodology/authentication-shapes.md).

`privilege` ranks the role in the application's own hierarchy — lower is less
privileged, and only the relative order is read, so any integers work. The
access-control classes dispatch their crossing arm from the LEAST privileged
identity supplied, because an administrator being served a subordinate's record
is in most applications the feature rather than the flaw. Nothing infers this
from the role LABEL: a label is free text chosen for one application, and a
hierarchy guessed out of it would manufacture a false positive on the commonest
engagement there is — one supplied admin or service account. Undeclared is a
legitimate answer and costs a confirmation rather than producing a wrong one; the
crossing is still dispatched and recorded, and reported as a lead naming the
missing declaration. See
[`docs/methodology/idor.md`](methodology/idor.md#which-identity-the-crossing-runs-from).

Both existed and appeared in **no example, no `--help` text and no document** —
only in the model's own docstrings. A misplaced key used to validate cleanly and
do nothing (Pydantic ignores extras by default), so an operator working from
documentation could write correct-looking input three ways and get the same hard
abort on an unprovable session, with nothing connecting the two. `RoleCredential`
and `CredentialSet` now set `extra="forbid"`, and a per-role key written at the
top level is refused with the level it belongs at named.

**A rejected credential file must not quote itself.** Making those cases *raise*
exposed a leak the previous silence had hidden: Pydantic stringifies a
`ValidationError` with an `input_value=` echo of the data that failed, and
`cli.py` prints `CredentialFileError` verbatim to stderr — so a malformed
credential file put the plaintext password on the terminal. Neither existing
defence reaches it. `SecretStr` does not, because validation is what would have
produced a `SecretStr` and validation is what failed; `redact()` does not,
because `_register_all` runs only after a *successful* parse, so the chokepoint
has never seen that password. `describe_credential_validation_error` reads the
error's STRUCTURED entries and quotes only `loc`, `msg` and `type` — the input is
never touched, so no formatting choice downstream can put it back. The message
still names the offending key and where it sits; withholding the input must not
cost the operator the diagnosis.

`tests/test_docs/test_documented_configs_parse.py` loads every JSON example in
`README.md` and `docs/`, plus `.env.example`, through its real validator. It is
the same guarantee as `test_every_documented_flag_is_actually_accepted`, applied
to config files instead of flags.

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

#### Every file it does not read is named

A severity table says what the gate does with what it *found*. It said nothing
about what it never opened, and that is the half every guard here has been
caught by: the verdict is true about the bytes it read and gets read as a
statement about the directory.

So the skip list is inverted. `_SKIP_ALLOWED` is an allow-list keyed by suffix,
each entry carrying the reason that suffix is not read, and anything skipped
without an entry — an unreadable file, an unparseable or encrypted PDF, a file
over the size cap — is recorded as a `SkippedFile` with an empty reason and
makes the report **not clean**. The counts sit in `summary_line` next to the
scanned ones, because a coverage number that omits what it declined to open is
the same defect one level down.

The allow reasons are written as **disclosures, not absolutions**:

| Suffix | Reason |
|---|---|
| `.png` `.jpg` `.jpeg` `.gif` `.ico` | raster image; carries no extractable text |
| `.db` `.sqlite` | SQLite; no reader here, and its TEXT columns are NOT covered by this verdict |
| `.zip` `.gz` `.tar` | archive; members are NOT covered by this verdict |

The last two rows are real holes, stated rather than dismissed — a SQLite `TEXT`
column and an archive member are both plaintext on disk. Run over a real bundle,
the gate reports `20 skipped (allowed)` and names them: twenty state databases
that had been sitting inside a CLEAN verdict without being read.

#### A PDF is read through two channels

`.pdf` used to be in the skip list, so every PDF in a bundle was certified
without being opened. Removing it is not enough on its own, because a PDF holds
text in two places and **each is blind to what the other catches**:

* **page content streams** are Flate-compressed, so a byte scan of the file
  finds nothing however carefully the token is written;
* the **document information dictionary** (`/Info` — `/Title`, `/Author`,
  `/Subject`, and any custom key) never appears in page text.

Measured, not assumed: with a token planted in the page body it is absent from
the file's raw bytes, and with one planted in `/Title` it is absent from every
page's extracted text. Both channels are pulled through `pypdf` into a single
blob with `[metadata]` and `[page N]` markers, so a reported line number still
tells an operator which channel to look in. A PDF that cannot be parsed is an
unexplained skip, not a clean file.

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

---

## Operating rules relocated from CLAUDE.md (2026-09-02)

The summary bullets CLAUDE.md carried until the context-budget split. They
are the same subject as the rest of this file; kept verbatim so the wording
that survived review is the wording on record.

The layer that makes a run against a **non-benchmark** target possible. **Full
detail → `docs/productization-engagement-safety.md`.**

- **The gate** (`engagement/gate.py::open_engagement`) is the FIRST statement of
  `OrchestratorAgent.run()` — before docker, before state, before a packet. No
  `AuthorizationRecord` (authorizing party + role + contact, authorization
  reference, permitted techniques, emergency contact; every field required, no
  partially-populated shape) ⇒ refusal, with no flag to skip it. An
  `EngagementWindow` is a hard stop re-checked on every request.
- **Credentials are never on `EngagementScope`** — the scope is `model_dump()`-ed
  into the state store, so keeping the `CredentialSet` off it is structural, not
  disciplinary. `SecretStr` passwords; git-tracked credential files are refused
  outright; `engagement/secrets.py` is the redaction chokepoint every artifact
  writer runs through — **including the report**, which used to be the one
  writer that did not (short-secret limit stated, not hidden).
- **Redaction removes what a secret IS and what it LOOKS LIKE.** Value-only
  redaction cannot remove credential material the engagement *captures* rather
  than the operator *supplies* — a session token the target issued was never
  registered. `engagement/credential_shapes.py` is the **one shape vocabulary**
  (JWT gated on a decoding header, `Authorization`/`Cookie`/`Set-Cookie` values,
  vendor keys, PEM blocks), always on, registry or not. A token becomes a
  **fingerprint** — salted hash prefix + `alg`/`iss`/`sub` + claim NAMES — which
  correlates within a bundle and replays nowhere. Cookie NAMES survive, cookie
  VALUES do not. `redact_structure` is **key-aware**, because a `Set-Cookie`
  value has no intrinsic shape and only the key identifies it.
- **`engagement/artifact_scan.py` is the disclosure gate**, run automatically
  after every writer has flushed: it re-reads `outputs/<id>/` off disk and
  refuses to certify the bundle on the strength of the logic that wrote it. **A
  guarantee asserted by the same logic that produces it is not checked at all** —
  the previous check searched for *configured* secret values and truthfully
  reported zero leaks about the wrong question. Definite shapes FAIL the run
  loudly (`DO NOT SHARE`); the entropy heuristic is advisory-only and lives ONLY
  in the gate — an entropy rule on the write path would shred evidence made of
  alarming-looking strings, and a gate that cried wolf would be ignored. The scan
  report never reproduces what it found. `clinkz artifact-scan <id>` re-runs it
  over any bundle and exits non-zero.
- **A guard's ROOT is part of its verdict, so the gate covers two regions.** It
  reported CLEAN over 3,123 files while a live JWT sat one directory up, in
  `outputs/d8_auth_bypass_live_validation.json` — true, and about a region chosen
  so as to exclude where the leak landed (the same shape as a tree-scanning leak
  guard that cannot see a PR's own text). `REGION_BUNDLE` is `outputs/<id>/`;
  `REGION_COMPANION` is everything else under the outputs root that no
  engagement's gate covers — loose driver files, `outputs/_juiceshop_benchmark/`
  and friends. **One verdict, two regions**, because the operator's question is
  "may I share this directory"; findings carry their region and render apart,
  because "the directory around your bundle is not shareable" is a different
  instruction from "your bundle leaked". A directory named like an engagement id
  is somebody else's bundle and is never swept in. Every `summary_line` states
  its coverage — a CLEAN that does not say what it looked at is how this
  survived.
- **Every file the gate does not read is NAMED, and an unexplained one FAILS.**
  A silently skipped file is the mechanism behind every guard here that
  certified a region it never looked at. `_SKIP_ALLOWED` is an allow-list keyed
  by suffix, each entry carrying *the reason that suffix is not read*, and
  anything skipped without one — unreadable, unparseable, over the size cap — is
  a `SkippedFile` with an empty reason that makes `clean` False. Counts sit in
  `summary_line` beside the scanned ones. The reasons are **disclosures, not
  absolutions**: `.db` is skipped because there is no SQLite reader here, not
  because a SQLite file is safe — its TEXT columns are plaintext in page data,
  and the reason string says so. Over a real bundle this surfaced 20 state
  databases that had been inside a CLEAN verdict unread.
- **A PDF is read through TWO channels, because each is blind to the other.**
  Page text is in Flate-compressed content streams (a byte scan of the file
  finds nothing); document metadata is in a separate `/Info` dictionary that
  never appears in page text. Measured both ways, not assumed. Both are pulled
  via `pypdf` — the only dependency declared here that anything imports — into
  one blob with `[metadata]` / `[page N]` markers so a line number still names
  the channel. `.pdf` used to sit in the skip list, so every PDF was certified
  unopened; a PDF that cannot be parsed is now an unexplained skip, not a clean
  file.
- **The engine's redaction reaches only where the engine writes.** A `scripts/`
  driver tees the HTTP chokepoint and serialises the exchanges itself, so it
  wrote past every writer: a complete RS256 session JWT plus the lab password in
  plaintext, while `report.json` from the same run was clean. Driver artifacts go
  through `scripts/_artifact_io.py` — a CALL SITE of `redact_structure`, never a
  second redactor — and a hardcoded lab password is a **third intake route** that
  registers on the way in like the other two. Enforced structurally by
  `tests/test_engagement/test_driver_artifact_writes.py`, which reads every
  `scripts/*.py` and refuses a raw `write_text`/`write_bytes` unless allow-listed
  with a reason: drivers are exactly what a `src/`-and-`tests/` grep misses.
- **The credential the client gave us goes first.** The default-credential
  sweep ran unconditionally ahead of the supplied credential: 52 requests of
  `admin/admin`, `root/root`, `admin/password`, `test/test` across six routes,
  landing in the client's authentication logs as credential stuffing — from an
  authorized test, before that test did the thing it was authorized to do.
  Guessing is what you do when you have not been handed a key, so
  `_should_sweep_default_credentials()` is `not credentials.authenticating` and
  nothing else. There is deliberately no "…or the supplied credential failed"
  branch: that path ABORTS (below), so the sweep is not merely deferred past a
  failure but unreachable after one — falling back to guessing passwords the
  moment the client's own credential is rejected is the same log entry this
  removes.
- **A login URL is proven by response SHAPE, never by a status code.** A
  single-page application serves its shell for every path it does not recognise,
  so `/login.php` answers **200 with 9903 bytes of Angular** on a Node target
  that has never had a PHP file — and a `status < 400` HEAD probe accepted it,
  which is how six credential POSTs landed on `/login.php` at a Node app.
  `_serves_a_login_form` GETs the body (a HEAD cannot see this) and requires the
  marker no catch-all produces by accident: an `<input type="password">` beside
  an identity-shaped field. Nothing proven ⇒ **`None`**, not the root URL: the
  "fall back to the root as the login page" strategy is deleted, because a root
  URL is not a login page, it is where a credential POST goes when nobody proved
  anything. A JSON login API serves no form and is found by
  `detect_auth_mechanism`, which is the component that knows how to ask.
- **Authenticated state is PROVEN, not assumed** (`engagement/auth_state.py`).
  The same URL is fetched with the session and deliberately without it
  (`HTTPClientTool`'s `no_session` — the shared cookie jar would otherwise make
  the "anonymous" control carry our own session), and only a boundary
  discriminator is accepted: login redirect, status class, login form, session
  marker, identity echo. **A body-length delta is a correlate and is refused.**
  Credentials supplied + assertion failed ⇒ the engagement aborts loudly.
  `SessionSentinel` rides the governor's response observers, because the code
  that lost the session is the code that will not notice.
- **Only a session-bearing response is evidence about the session.** The HTTP
  chokepoint is the only code that knows whether a request carried the session,
  so it passes `session_bearing` through `observe_response`; a session-free
  response is ignored in BOTH directions (it neither counts as a loss nor resets
  a streak). Without it the sentinel reads the engine's own anonymous control —
  whose 401 *is the proof the session works* — as proof the session broke.
  **The raised flag is a hypothesis; `assert_authenticated` is the oracle**: the
  Orchestrator re-proves the session before re-authenticating, records a false
  alarm when it survives, and counts `reauthentications` on **success only** (it
  used to count the attempt, before anything was tried). Consecutive-counting
  alone cannot survive a concurrent phase — any interleaved 200 resets it — so a
  scattered-loss `escalation` ceiling also earns one check.
- **The rails are absent by default** — `get_active_governor()` is `None` unless
  an engagement installed one and every hook no-ops, so direct methodology
  invocation (smoke suites, replays, drivers) is byte-identical. The governor
  (`safety/governor.py`) owns rate (5 req/s), concurrency (4), the kill switch
  (`clinkz abort` → `outputs/<id>/HALT`), blocking detection, the window, and the
  action log. **It never raises from the data path** — it returns a refusal the
  callers already handle; `_run_phase` polls `halted` and winds down so the
  report is still produced.
- **`safety/destructive.py` is the one destructive vocabulary**, consulted by
  both `is_state_changing_url` (navigation) and `is_destructive_form_submission`
  (submission), over path + method + field names + label text. The predecessor's
  rules are preserved verbatim, so it can only refuse MORE. **A parameter VALUE
  is read for semantics only when it looks like an identifier the APP chose**
  (`_PLAIN_VALUE`) — our own payloads carry `drop`/`rm`/`passwd`, and reading
  them back as application semantics would refuse the engine's own probes and
  silently reduce an authorized engagement to a crawler.
- **`_run_subprocess` gets the halt check ONLY** — it is reached from inside the
  HTTP chokepoint, so a second slot per request would deadlock the semaphore and
  double-count every rate token. Self-flooding tools are paced by their own flags
  (`ffuf -rate`).
- **The permitted-technique list gates dispatch**, refused before the page fetch,
  and every withheld class is named in the report.
- **`models/vuln_classes.py` is the client-facing class registry** (label,
  capability, limitation, remediation), asserted in sync with the Exploit Agent's
  dispatch table: a class it dispatches but the registry has never heard of is
  BOTH invisible in the report and ungated by authorization. `DISCOVERY_CLASSES`
  and `COMPOSITION_CLASSES` (`attack_chain`) emit findings without a dispatch
  entry — they are never *planned against an endpoint* — so they are held apart
  from that sync assertion and gated by registry KEY instead. **That sync
  assertion's domain is `DISPATCHABLE_TEST_METHODS`**, the table the dispatcher
  itself reads; it used to be `_CLASS_PATH_TOKENS` — a *ranking signal* map
  holding 27 of the 30 — so the two classes with no registry entry at all were
  outside the check that exists to find them. **A dispatch-table entry that can
  never emit is a capability claim**, so `_test_tier2_technique` /
  `_test_tier3_technique` are registered `NOT_IMPLEMENTED`
  (`_apply_technique` has three exits, all `return []`: it sends no request and
  constructs no `Finding`), which is what puts them in *What was NOT tested* and
  makes every dispatched technique task a ledger row instead of silence.
