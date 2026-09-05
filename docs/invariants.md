# Key design decisions — the full record
> Relocated out of [`CLAUDE.md`](../CLAUDE.md) on 2026-09-02, verbatim.
> CLAUDE.md carries the RULE — one line, loaded every session; this file
> carries the incident that produced it. When the two disagree, CLAUDE.md
> is the operating instruction and this is the record of why.

The 85 invariants, in their original order, with the forensic detail that
CLAUDE.md's one-line form drops. Numbering is positional within this file and
is **not** a stable id — cite an invariant by its rule text, never by its
number, the same way `.claude/LESSONS.md` ids are historical-not-positional.

## Architecture, comms, and tool discovery

### 1. Deterministic steps + LLM checkpoints

**Deterministic steps + LLM checkpoints**; no free-form ReAct.

### 2. Orchestrator-mediated comms

**Orchestrator-mediated comms** — agents never talk directly; all messages
route through the Orchestrator. What routes them is the v2 deterministic phase
sequence, NOT an LLM router: `_handle_query`'s `RESPIN_*` branch has never
fired because no agent constructs a `QUERY`, and
`MAX_CROSS_PHASE_RESPINS` bounds a path nothing reaches.

### 3. Agents are spun up/down on demand

**Agents are spun up/down on demand**, in the order the phase shape declares.

### 4. Dynamic tool discovery

**Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a
tool name or direct import.

### 5. LLM-agnostic + per-agent providers

**LLM-agnostic + per-agent providers** — never import a provider SDK outside
`llm/`. **Anthropic is priority 1 for every call on every phase**; priority is
declared in `Settings.llm_provider_priority` (validated Anthropic-first) and a
discovered key confers *availability*, never a position. **Detail →
[`docs/provider-routing.md`](docs/provider-routing.md).**

## LLM routing, fallback, and degradation

### 6. A fallback is a disqualifying event, and on an emit or suppress path it is refused outright — in BOTH run modes

**A fallback is a disqualifying event, and on an emit or suppress path it is
refused outright — in BOTH run modes** (`llm/call_purpose.py`). `client` mode
degrades and stamps because a client engagement should not die over a bad
minute at a provider, and because reduced coverage is something a stamp can
honestly disclose. That reasoning stops at the two paths where it is false: a
finding a degraded cross-check DEMOTED is not in the report, so there is no row
to caveat and nothing separates "the engine did not find it" from "a cheaper
model decided it was not real". Six of the twelve recorded Gemini-served
exploit calls were false-positive cross-checks. Every agent call site declares
its purpose and an unclassified one is a red build, not a permissive default.

### 7. A run where NOTHING answered is not a clean run

**A run where NOTHING answered is not a clean run** (`llm/degradation.py`).
`degraded` was `bool(self._events)` and an event was written only on a
**substitution**; a chain that runs out substitutes nothing, so the worst
outcome wrote nothing and the eligibility flag computed from that list said
the run was fit to be a baseline. Engagement `2e21a200` failed recon, scan AND
exploit with `All providers exhausted`, produced zero findings, and reported
`provider_degraded: false, baseline_eligible: true`. Three kinds degrade a run
now — `SUBSTITUTION`, `TERMINAL_EXCLUSION` (a provider lost for the rest of
the run, so every later call ran a shorter chain and was silent about it) and
`CHAIN_EXHAUSTED` — the last two carried as **absences**, which have no served
model and so could not be expressed as a `ProviderFallback` at all.
`baseline_eligible` now FOLLOWS `degraded` rather than re-deriving it: two
expressions of one fact drift, and this pair did.
**Two witnesses, because neither covers both instances.** The register catches
a raise the trace attributes to the last provider that worked (run `9317e813`,
one methodology call, `stop_reason=refusal`); `model_stamp` catches the outage
in a STORED bundle, where the process that knew ended long ago.
`reconcile_with_model_stamp` refuses a clean claim the run's own stamp
contradicts, only ever tightening, at **both** the build seam (so `report.json`
carries it) and the render seam (so an older bundle re-renders honestly).

### 8. A report about a run that did not happen must say so

**A report about a run that did not happen must say so.** The same engagement
rendered "0 findings identified. Risk rating: Informational." — the strongest
claim a pentest report contains, made out of no evidence at all.
`ExecutiveSummary.run_completed` / `incomplete_reason` are computed by
`_run_completion` from the orchestrator's `phase_outcomes` AND the model
stamp's exhausted stages; incomplete + zero findings rates **`Not assessed`**,
because "Informational" is a verdict about the target. The banner renders
ahead of the counts in all three documents.

### 9. A capability lost to routing is STATED, never absorbed

**A capability lost to routing is STATED, never absorbed.** Research led with
Gemini for native Search Grounding and the Anthropic path has none, so a
research answer is bounded by a training cutoff with no signal in the text that
anything is missing. The producer declares (`LLMClient.RESEARCH_GROUNDING`),
the resilient client reports who ANSWERED, the phase reports the WEAKEST
grounding any of its calls ran under, every runbook entry carries it (the claim
persists to the KB, so the caveat must too), and the report renders it either
way. `undeclared` counts as ungrounded.

## What the deliverable may claim

### 10. A section that reads one field and contradicts the document's own contents is worse than a missing section

**A section that reads one field and contradicts the document's own contents is
worse than a missing section** (`agents/_report_integrity.py`, **detail →
[`docs/report-integrity.md`](docs/report-integrity.md)**). Three of them
shipped, all on the first page, all checkable by a client without tooling.
**The testing window** was `test_start`/`test_end` defaulting to
`datetime.now(UTC)` because nobody ever passed either, so a 4,597s run rendered
as zero directly beneath the authorized window — the one place the document
evidences that testing happened inside it. The producer is now the governor,
the only component every dispatched request passes through, and the rule is
*any request sent ⇒ `test_end > test_start`, or the render fails*. Its one
exception is a bundle carrying **no stamp at all**: the ABSENCE of the key is
what separates an old bundle from a new one that is lying, so an old bundle
renders an explicit "not recorded" and `clinkz report-pdf` recovers the
narrower window from the bundle's own `actions.jsonl`, provenance attached.
**The authentication state** was one boolean whose negative branch renders the
strongest sentence in the header — "Anything behind authentication was not
examined" — above 22 findings behind DVWA's login. Reconciled into four states
now (`PROVEN` / `DISPROVEN` / `INCONSISTENT` / `NOT_ATTEMPTED`): a negative
claim is only as good as the check that produced it, and in that run
`assertion` is `null`, so no check ran. **The cost** was `$0.00` beside "a
LOWER BOUND", which reads as a wrong number; an engagement whose models carry
no declared rate is `not priced`. Every reconciliation is pure, reads only
engine-declared fields, only ever TIGHTENS, and runs at BOTH seams — the build
seam so `report.json` carries it, the render seam so a stored bundle
re-renders honestly. Same shape, same reason, as `reconcile_with_model_stamp`.

### 11. A session the engine GUESSED is still a session, and the record has to say so

**A session the engine GUESSED is still a session, and the record has to say
so.** `_authentication_summary` reads `_role_sessions` and `_auth_assertion`,
and only the SUPPLIED-credential path writes them — the default-credential
sweep's `_attempt_login` wrote its cookies, jar path and bearer token to the
credential store, which is what every later phase reads. So a run logged in for
its whole duration reported that it had never logged in, on all four ladder
levels (`DEFAULT CRED VALID: admin:*** on .../login.php`).
`_register_swept_session` files it under `SWEPT_CREDENTIAL_ROLE`, deliberately
not a supplied role name, because "a credential the client handed us" and "one
this engine guessed" are different provenance. `established` stays False and
`_role_session_handoff` still skips it: holding session material and having
PROVEN a session are different facts, and *we posted a password and got a
cookie* is the assumed-not-proven claim refused everywhere else here.

### 12. A class the never-sent rule does not bind is not a class with no control — it is a class whose control is a DIFFERENT rule, and the row names it

**A class the never-sent rule does not bind is not a class with no control — it
is a class whose control is a DIFFERENT rule, and the row names it.** The
control-arm section header promises "the row says which rule applies instead"
and 19 of 29 rows said only which rule does NOT govern them. Nineteen verbatim
repetitions of an absence invite a client to read the strongest evidence in the
document — a browser-witnessed nonce, a rejected broken signature — as
unverified. The PRODUCER declares it (`VulnClass.control_arm.governing_rule`,
plus `evidence_key`, the field in the finding's OWN structured evidence
carrying the observation the rule turned on), required for every member of
`CONTROL_EXEMPT_CLASSES`, and `control_arm_row` raises on a row that names no
rule. The observation is read by `declared_observation`, which the host under
test cannot reach: the strict structured reader first, then an entry whose
FIRST token is `key=` — position 0 is never occupied by target bytes, because
every entry carrying them is written by the engine with its own `Request: ` /
`Response: ` prefix.

### 13. An IDOR finding proves attribution with NAMES and FINGERPRINTS, never values

**An IDOR finding proves attribution with NAMES and FINGERPRINTS, never
values.** `attributing_values` reproduced `field=value` pairs out of the OWNING
principal's record — the first target data this class has ever carried into a
deliverable — and an 80-character cap bounds volume, not sensitivity: on a
client engagement that value is a real customer's email or postal address, in a
document that gets emailed. `attributing_fields` renders
`field=<name> owner_fp=<hash> caller_fp=<hash|absent>`: the owning value the
crossing carried, against what the caller's own anchored record holds under
that field (or `absent`), which is the whole claim. The field NAME survives because it is schema, not data, and is
what a remediation has to name. Same trade as `AuthArtifact.principal` — the
claim survives, the value never lands.

### 14. A bound that decides coverage is reported in the DELIVERABLE, not just the log

**A bound that decides coverage is reported in the DELIVERABLE, not just the
log** (`observability/plan_alarms.py`). The plan cap ranks `(class, endpoint)`
pairs and drops the tail — four D1 runs each truncated ~1,500 candidates to 150
— and it was loud only in the run log and `trace.jsonl`, neither of which a
client reads. Truncation and **ranking inversions** stay separate numbers with
separate renderings because they have different fixes: a bigger cap covers a
truncated tail and does nothing for a task dropped from an endpoint carrying
its own class's observed surface. Rendered on a clean run too.
**And `kept` is a total, so it is not evidence about its parts**:
`kept_by_class` + `classes_with_candidates` separate "the cap took every
candidate this class had" (a bigger cap) from "tasks survived and the class
still never ran" — indistinguishable before, and the second is the ffuf
shape at class granularity. That second verdict is
`no_phase_event_tasks_survived_the_cap`, and it deliberately does **not** name
the dispatcher: it used to read "the plan reached it and the dispatcher did
not", which sent maintenance to the wrong file. A class that returns `[]` at
its own entry gate, before its first phase trace, produces a byte-identical
shape — and every observed instance was that (a form gate reading `page.forms`
on a framework target). The alarm names what was observed, and points at the
class's applicability gate first. The **class-coverage account**
(`scripts/d1_consistency_runner.py::class_coverage`) gives every dispatchable
class exactly one verdict on **how far its own pipeline got**, never on what
it says about itself; "the plan held nothing for it" is the fifth fact and is
NOT an alarm, an indeterminate answer IS one. Which skill names a class is
DECLARED by the producer (`_CLASS_TRACE_SKILL`), verified against the call
graph, because guessing `_test_x → "x"` is right 23 times and wrong for
`_test_javascript_attacks` — and a mis-guessed skill reports zero coverage,
which reads exactly like a class that never ran. **`kept_breakdown_present` is
consulted FIRST, ahead of every benign branch**: all three never-dispatched
verdicts are read off `kept_by_class`, so its absence decides them before any
of them is asked. It used to sit last, behind "the plan held no candidate" —
whose inputs are empty in exactly the same way an absent breakdown's are — so
a bundle with **no `trace.jsonl` at all** reported thirty correctly-empty
classes, `alarms: []` and `reached_an_endpoint: 0`: a clean coverage account
for the whole engine, out of a missing file.
**Detail → [`docs/observability.md`](docs/observability.md).**

### 15. The crawl's enrichment budget is that same bound, one layer earlier

**The crawl's enrichment budget is that same bound, one layer earlier**
(`CrawlBudgetTruncation`). It decides which discovered URLs ever BECOME
endpoints, so everything the plan cap can see has already passed through it —
and on the first non-benchmark run 3,070 crawled URLs became 212 candidates of
which the budget opened **80**, leaving 132 (62%) never enqueued at INFO in the
run log and nowhere in `report.json`. Rendered as a *Crawl coverage* section
on a clean run too, `opened_by_host` beside `dropped_by_host` because a total
cannot say whether an entire host went unlooked-at. It also **qualifies the
refusal tally**: refusals count requests that were REFUSED, and a candidate the
budget never opened never became a request, so a refusal count describes the
opened slice of the out-of-scope surface. **One href is one candidate** —
`crawl_dedup_key` strips a trailing `%5C`, the escape artifact left by reading
a URL out of a JSON-escaped payload, which arrived as three spellings and spent
three visits. It is a dedup KEY, not a rewrite: the smallest spelling in the
group is kept, which is the clean URL when it was discovered and the mangled
one unchanged when it was not.

## Probe safety and how a class reads the target

### 16. Crawl-safety / session hygiene

**Crawl-safety / session hygiene** — `is_state_changing_url` is the chokepoint
guarding every crawl visit, endpoint emission, and exploit-plan entry; its
submission counterpart `is_destructive_form_submission` guards every form
submit at `_submit_form_fields`. **A probe never destroys target state**: a
credential/account-mutating form is refused, not fuzzed, and a field the
methodology did not intend to set is omitted — never sent empty-but-present.

### 17. A new injection shape gets a DEDICATED carrier

**A new injection *shape* gets a DEDICATED carrier**; leave the shared
string-only `_send_probe` untouched.

### 18. How a class READS the target is not the class's business

**How a class READS the target is not the class's business** — there are two
accessors and a class uses them, never the raw layer beneath. `page.forms` is
`_http_get` + `_FormParser().feed(body)`, so it is `[]` on any
React/Angular/Vue target: the form exists, it is just rendered after the bytes
we parsed. `_http_get(page.url, {param: value})` puts the probe in the query
string whatever the parameter's declared location is. So a form-shaped class
reads **`_injectable_forms`** (HTML forms first and unchanged, plus the JSON
and multipart pseudo-forms this agent synthesizes for body-bearing API
endpoints) and a probing class carries through **`_send_probe`**. Eight of the
eleven classes read the raw layer and were therefore invisible on a framework
target while reporting nothing — which reads exactly like a clean result.
Enforced structurally: `tests/test_agents/test_tier1_migrations.py` AST-walks
the agent for `self._http_get(url, {k: v})` and fails on any site not
allow-listed with a reason (the domain is the source, per the guard-domain
law). **`_test_javascript_attacks` is the one that does NOT migrate** and says
why: its phase-1 hypothesis is a conjunction of a form AND an inline
`<script>` block, and its only confirming path needs a hidden field of that
form written by that script — a pseudo-form has no hidden field by
construction and a JSON response has no script. Reaching a framework's
client-side security logic means reading its bundle, which is a new oracle.

### 19. An upload point is declared by a protocol artifact, never by a URL that sounds like one

**An upload point is declared by a protocol artifact, never by a URL that
sounds like one.** The upload pseudo-form is synthesized only when the
endpoint's DECLARED request content type is `multipart/*` — read off the
frontend's own `new FormData()` builder by `_js_api_mining`, not guessed — AND
one of the field names that builder appended is upload-shaped. A multipart
endpoint with no file part gets no pseudo-form, because there is nothing for an
upload test to submit and a fabricated one would be a target detector.

### 20. A body field is a PATH, not a name

**A body field is a PATH, not a name** (`agents/_json_body.py`) —
`config.app.name`, `items[0].sku`. Written into place with `set_json_path`, so
the body that goes out has the shape the target declared; only **leaves** are
written (replacing a container destroys the object holding the field under
test) and **every sibling keeps a benign value** — an endpoint that validates
its input rejects a body whose unrelated fields were blanked or dropped, and a
rejected request never reaches the sink. The G8 form rule, generalized to
structure. On the response side the echo guard undoes **JSON** escaping too (a
JSON API re-encodes the payload on the way out, so `<` returns as `<` and
the guard cannot otherwise find the echo it exists to blank), and
`locate_in_body` reports *where* a marker landed — `data[0].comment` is a
stored record, `errors[0].msg` is the API quoting us back.

### 21. Surface mapping never writes to the target

**Surface mapping never writes to the target.** Every API schema learner takes
a probe restricted to `GET`/`HEAD`/`OPTIONS`, asserted at the seam. The
rejected alternative is instructive: a `{}`-POST read for its validation error
answered `201 Created` on two of six live endpoints and *created an account*
during discovery, for one field name.

### 22. Stack-conditioned branches

**Stack-conditioned branches** (`_is_php_stack`, engine fingerprints, dialect)
are backed by a deterministic protocol artifact (a `PHPSESSID` cookie, a `.php`
path, a header) — never the flaky LLM tech list alone (LESSONS #28).

## The client-side execution oracle (P7)

### 23. P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES

**P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES**
(`src/clinkz/browser/`, **detail →
[`docs/methodology/client-side-execution-p7.md`](docs/methodology/client-side-execution-p7.md)**).
A Clinkz-minted single-use nonce returns **by a call from inside the page's JS
context** to a Clinkz-owned in-page binding, while a second nonce minted
alongside and **injected nowhere** stays silent — inert reflected bytes cannot
call a function, which is the confounder that made every prior DOM-XSS
"confirmation" a phantom. The channel is a function call, **not** a network
callback, because `connect-src` is governed independently of `script-src` and a
beacon would report "did not execute" about a page that did. `bypass_csp` is
asserted OFF and recorded, so a CSP finding answers *did script execute under
the served policy*. **Everything the page authors is evidence, never a verdict
input** — `WitnessVerdict.decide()` reads three engine-owned booleans, so a
console line saying "Refused to execute" cannot suppress a witnessed execution.
Resolved by **capability**; absent, broken or out-of-budget ⇒ the
`UnprovenExploitLead` stands unchanged. **A missing browser costs coverage,
never honesty**, and there is no path from a P7 verdict to demoting or
suppressing anything.

### 24. An oracle must observe from a machine that can REACH the target

**An oracle must observe from a machine that can REACH the target.** The
browser runs where the tools run (docker mode ⇒ inside `clinkz-tools`), because
the engagement's address is itself a consequence of `TOOL_EXEC_MODE`: docker
mode rewrites `localhost:8080` to a bridge alias no host browser can resolve,
and local mode — where a host browser would work — has no port scanner. The
runtime is therefore **tied to `TOOL_EXEC_MODE`, never configured separately**,
so the one combination that silently fails every navigation cannot be selected.
`browser/_container_runner.py` carries the browser-driving half with **zero
clinkz imports** and both runtimes call it, so a driver and a real engagement
run the same rails.

### 25. A browser is a new destructive surface, and its rails are structural

**A browser is a new destructive surface, and its rails are structural.** Scope
is checked before launch; the governor authorizes the navigation exactly like
an HTTP probe; **every navigation is written to the action log** (a GET too —
what is recorded is that a real engine ran the target's code — tallied apart
from `state_changing_sent` so neither number needs qualifying). Inside the
page: only the FIRST navigation is ours and every later one is aborted; only
that authorized request may use a mutating method, so a page cannot
`fetch('/x',{method:'DELETE'})` what a blocked navigation could not; and a
**safe method is not automatically safe** — `<img src="/logout">` is a GET that
destroys the session, so subresource paths are matched against
`safety/destructive.py::subresource_guard_spec()`, the one vocabulary, shipped
into the browser as data. Nothing is ever clicked, filled, or submitted. Every
refusal is recorded on the verdict, never silent.

## Oracles, control arms, and the defining effect

### 26. Deterministic skills as contracts

**Deterministic skills as contracts** — if the vuln is present, the `_test_*`
method MUST find it. Verification-honest emission: emit only when the evidence
proves the DEFINING security effect. **Never write an observation into evidence
that was not made**; an effect that was not witnessed is an
`UnprovenExploitLead` (a distinct type with no path to `_persist_finding`),
never a finding. **A finding that confirms identically across every level of a
security-graded control is a phantom by construction** — see
`docs/methodology/dvwa-per-level-honesty.md`.

### 27. No marker oracle confirms without a dispatched control arm that REFUSED

**No marker oracle confirms without a dispatched control arm that REFUSED**
(`agents/_control_arm.py`, **detail →
[`docs/methodology/never-sent-control.md`](docs/methodology/never-sent-control.md)**).
Ten classes confirm by finding a string in a body, which is proof only while
the string has one route in; the first non-benchmark run shipped 14 phantoms
from two second routes (a Next.js RSC payload echoing the query string
percent-encoded, and `<span>Linux</span>` matching the bare-word `uname`
regex). The control is the confirming request with the exploitation primitive
removed and the marker re-minted, graded by the SAME phase-5 oracle — and it
must **round-trip like the payload**, because a bare decoy is
encoding-invariant, refuses everywhere, and would have passed that run
cleanly. `MARKER_ORACLE_CLASSES` / `DIFFERENTIAL_CONTROL_CLASSES` /
`CONTROL_EXEMPT_CLASSES` partition every dispatchable class with a stated
reason; an unclassified one is a red build. The middle table exists because
**what the decoy must BE differs by oracle kind**: a marker oracle's control
carries a minted token, because what it must not do is appear in a body; a
DIFFERENTIAL oracle's control carries a value of the class's own SHAPE, because
what it must do is round-trip through the same handler and differ only in the
primitive. Handing `_test_idor` a `clinkzdecoyidor48211` where the endpoint
expects an integer produces a control that takes the parse-error path, differs
from everything, and passes on a vulnerable target and a phantom alike.
`control_required()` is the union, so the RULE stays one rule.
Enforced at `_persist_finding`, read only from fully-structured evidence so a
page echoing `never_sent_control=refused` cannot license itself.

### 28. Every kill discloses, wherever it happens

**Every kill discloses, wherever it happens.** The rule had two enforcement
sites and one disclosure between them: ground 8 at `_persist_finding` wrote an
`UnprovenExploitLead`, a phase-5 kill returned `continue` and wrote nothing —
so the 2026-08-20 ladder fired ten arms, recorded **zero** disclosure records,
and three DVWA levels carrying genuine command injection reported silence that
reads exactly like a clean target. The lead is now written inside
`_run_control_arm`, the one seam every arm passes, so a class cannot forget
because a class does not do it; `_control_arm_kills` /
`_control_arm_kill_disclosures` make it a count rather than a convention. The
lead says the class **could not PROVE** the vulnerability — never that the
endpoint is clean, which the tests refuse in so many words: an oracle whose
control also confirmed produced no evidence in either direction.

### 29. The arm's lookup key is DECLARED by the emitting site, never re-derived

**The arm's lookup key is DECLARED by the emitting site, never re-derived.**
`_run_control_arm` files a verdict under the parameter it DISPATCHED against,
so a class that renames its vector for the report misses its own arm and is
then refused for not having one. `_test_sqli` at DVWA `high` dispatches
`\x00session:id` and emits `id (session)`: both arms refused correctly and both
findings were suppressed as un-armed — low and medium survived only because
their parameter has one name. `_test_file_upload` had the same shape
(`uploaded` vs `file`). `_make_finding` takes `control_arm_parameter` from the
site that did the renaming; a miss while a sibling arm exists on the same
`(test_method, endpoint)` is a traced `control_arm_key_mismatch` that still
refuses — an arm dispatched against a different parameter is evidence about
that parameter.

### 30. An oracle confirms on its class's DEFINING effect, and the arm is what proves it does

**An oracle confirms on its class's DEFINING effect, and the arm is what
proves it does** (**detail →
[`docs/methodology/defining-effect-oracles.md`](docs/methodology/defining-effect-oracles.md)**).
Two oracles were measuring something the endpoint does regardless of the
payload, and their own control arms said so on targets that really are
vulnerable. `_test_cmdi`'s `time_delta` compared one reading to an **absolute**
4.0s constant and never read the baseline it was handed — DVWA's `ping -c 4`
baseline is 4.04s, so it confirmed on an untouched request; it is now an
interleaved, repeated differential against that endpoint's own baseline, and
phase 4 prefers the marker channel phase 1 already PROVED (recorded as
`ShellPrimitives.marker_separator`) over whatever the model ranks first.
`_test_file_upload` confirmed on "a nonce we wrote came back", which a PHP
interpreter reproduces for any `.php` file of bare text — the indicator is now
a value the interpreter must COMPUTE (`'clinkz'.'exec'.(A*B)`) and that appears
nowhere in the uploaded bytes. Neither is reachable by weakening the control:
a decoy that does not round-trip refuses everywhere and proves nothing.

## Access control — principals, sessions, IDOR

### 31. Whose object is this? is a relation, not a property of a response — so the access-control oracle needs a SECOND identity, and it now has one

**Whose object is this? is a relation, not a property of a response — so the
access-control oracle needs a SECOND identity, and it now has one**
(`agents/_idor_oracle.py`, `agents/_principal.py`, **detail →
[`docs/methodology/idor.md`](docs/methodology/idor.md)**). Two defects, one
class. The **plumbing stopped one layer short**: the Orchestrator logged in
every supplied role, asserted each session, kept all of them and logged that
the access-control classes could compare principals — while handing Exploit
the primary role's cookies and nothing else. And the ORACLE had its control
inverted: phase 5 opened by requiring the target to have REFUSED an
out-of-allotment reference, which consumed **616 of 668 phase-5 refusals**
across 2,955 recorded engagements, because an application that 404s an id
nobody owns and 200s a neighbour's record discriminates perfectly and that
gate read the shape as "no boundary exists". `ref(∅)` is now the CONTROL, in
four dispatched arms — `self` (A, ref(A)), `crossing` (A, ref(B)),
`nonexistent` (A, ref(∅), must differ materially), `anonymous` (no session,
ref(B), must NOT return it) — plus B's own authorized read, which is what makes
ref(B) *attributable* and is the arm one principal cannot dispatch. The control
round-trips like the payload (numeric far outside the OBSERVED issued range, a
fresh v4, or the same length and character classes) because a minted marker is
encoding-invariant and would pass on a vulnerable target and a phantom alike.
**Reflection is deliberately NOT covered by it**: a sink echoes the control
too, so the control refuses correctly and the owner's read echoes the same
string back — three arms agreeing on one substitution — and it keeps its own
guard.

### 32. A class that needs two identities declares it in the registry, and the code READS the declaration

**A class that needs two identities declares it in the registry, and the code
READS the declaration.** `models/vuln_classes.py` has said "requires at least
two authenticated roles" since it was written, the report rendered that
verbatim, and the oracle emitted `high`/CONFIRMED on a single role 49 times. A
limitation only the report knows about is a disclaimer.
`MultiPrincipalRequirement` makes it a number the emission chokepoint compares
against the run's own principal list, with the lead reason declared beside it
(`single_role_cannot_attribute`, registered in `UNPROVEN_WHY_UNCONFIRMED`).
**Tier 1 multi-role MAY CONFIRM; Tier 2 single-role MAY ONLY LEAD** — "not A's"
is satisfied identically by a public catalogue record, so three negatives are
not a positive. Enforced at the methodology AND at `_persist_finding`
(deterministic ground 9), because a rule a class has to remember is a rule that
holds until the twenty-fifth class is written. A direct invocation holds no
principals and is in the single-role tier: that is the honest answer, not an
exemption.

### 33. `ref(A)` is a reference the CALLER owns, or the class abstains — and attribution comes off the OBJECT, never off a comparison

**`ref(A)` is a reference the CALLER owns, or the class abstains — and
attribution comes off the OBJECT, never off a comparison**
(`agents/_idor_oracle.py`, **detail →
[`docs/methodology/idor.md`](docs/methodology/idor.md)**). Two more defects in
one class, both of which a target-confirmed scoreboard solve certified as
working. The **self arm carried the CRAWL's value**, which is a fact about
whichever session was crawling: the crawl saw `id=1`, A was `jim` — user
**2** — phase 3 incremented to `2`, so `self` read admin's basket and
`crossing` read A's own. Every downstream arm cleared, because every one of
them is a comparison and *a comparison does not know which side it is standing
on*. `ref(A)` is now DISCOVERED first (`anchor_self_reference` +
`_idor_anchor`): candidates are probed **as A** and the anchor is the first
record naming A as its owner, where A's identity comes from
`Principal.identity_tokens()` — the supplied username and the identity claims
of the bearer token the target issued US, never a response. Unanchorable ⇒
ABSTAIN (`self_reference_not_anchored_to_the_caller`), and
`ref(self) != ref(crossing)` is asserted both before dispatch and on what was
actually sent, a mismatch being a LOUD refusal rather than a quiet abstain.
And the attribution route `identical_rendering` was **vacuous by construction
under this class's own direction rule**: A is the least-privileged identity so
B outranks it, and an outranking B reading A's record returns A's record —
"identical to B's read" then proves *B can also read this*, which is the
feature. Direction needs A least-privileged and attribution-by-`owner_read`
needs B not to outrank A; both cannot hold. The claim now rests on an OWNING
FIELD (`owner_claim`) — a field the application itself uses to name a record's
owner (`UserId`, `email`, `author`) carrying a value that is not the
caller's, or ANY field whose value is an identity we hold. `owner_read` is
still dispatched and is reported as `corroboration`. No owning field ⇒
ABSTAIN (`crossing_response_names_no_owning_principal`), which retires the
public-catalogue shape without a decoration-tolerant differ — **and costs
recall on an endpoint whose per-user records name no owner**, pinned as a
test named after the loss rather than left to surface as a silent gap.
Two consequences of `idor_normalise_body`'s digit folding fall out and are
fixed with it: *is this A's own object?* asks `names_the_caller` before the
fingerprint (two baskets differing only in `UserId` normalise equal), and
`reflection_explains` abstains below a four-character reference and is not
asked at all of a body carrying an owning field — substitution is global, so
rewriting `1` into `2` turns the owner's record into the caller's and reads
as a perfect echo.

### 34. An anonymous 200 on `ref(B)` is DISQUALIFYING, full stop

**An anonymous 200 on `ref(B)` is DISQUALIFYING, full stop.** It was one input
to `materially_differs`, so `/rest/products/:id/reviews` — served 200
anonymously — confirmed on a per-caller `"liked":true` decoration of the SAME
review, same `_id`, 13 bytes. If an anonymous caller is served the resource
there is no boundary to cross, whatever else the bytes do. An anonymous arm
that was never DISPATCHED refused nothing and abstains
(`anonymous_control_arm_not_dispatched`), the rule `ControlVerdict` applies to
every other arm.

### 35. An acceptance test that reads only an external grader cannot detect an oracle that reached the right verdict by the wrong arm

**An acceptance test that reads only an external grader cannot detect an
oracle that reached the right verdict by the wrong arm** (**detail →
[`.claude/skills/clinkz-dev/SKILL.md`](.claude/skills/clinkz-dev/SKILL.md)**,
beside the guard-domain and guard-pattern laws). IDOR's criterion was "a
target-confirmed scoreboard solve plus an emitted finding of the matching
class", and it passed three identical runs over the inverted arms above,
because **the scoreboard grades the OUTCOME and the oracle grades the
REASONING, and nothing compared them**. The criterion must assert the ARMS —
which request went out, as whom, carrying what, and what each is required to
show — all of them engine facts in the run's own trace. Pinned as
`IDOR_ACCEPTANCE_CLAIMS` /`idor_acceptance_failures` in
`tests/test_agents/test_idor_four_arm_oracle.py`, with the negative control
that matters: a verdict carrying every outcome signal there is and no anchored
arms behind it fails every claim.

### 36. A crossing arm is evidence only when it runs UPHILL, and which way is up is the operator's to declare

**A crossing arm is evidence only when it runs UPHILL, and which way is up is
the operator's to declare.** Two principals make the arm dispatchable; they do
not make it meaningful. Every one of the four arms is satisfied by an
administrator being served a customer's record — which in most applications is
the feature — and the commonest client engagement supplies exactly one admin or
service account, so A being the PRIMARY role pointed the oracle at a false
positive on the shape it will meet most often. A is now the LEAST privileged
identity the engagement holds (`_principal.privilege_order`), and the candidate
owners are everyone A does not outrank — equal rank included, since two
customers are peers and no role either holds authorizes reading the other's
record. The rank is DECLARED (`privilege` on the role credential, lower is
less privileged) and never inferred from a role LABEL: a label is free text an
operator picked for their own application, and reading a hierarchy out of it is
the consumer-guesses-the-producer pattern that has already cost a component's
field names, a tool's output model and a version's provenance. An undeclared
rank does not stop the arms — the crossing dispatches and is recorded — it
bounds the VERDICT to a lead
(`privilege_order_undeclared_crossing_may_be_authorized`), which an operator
clears in one line of their credential file. Enforced at the methodology AND at
`_persist_finding` (deterministic ground 10), the same pair as the tier rule,
and the two grounds are mutually exclusive so a lead names the observation that
was actually missing.

### 37. A request carries the ENGAGEMENT's session, a NAMED principal's, or none — one field, three values

**A request carries the ENGAGEMENT's session, a NAMED principal's, or none —
one field, three values** (`tools/http_client.py::session_mode`). `isolated`
did not exist and both alternatives are wrong for a cross-principal arm: under
`ambient` curl still passes `-c <jar>`, so role B's `Set-Cookie` overwrites the
engagement's own session and every later probe silently becomes B; under `none`
the explicit cookies are dropped and the request carries no principal at all.
`no_session` stays as shorthand for `none` and is now DERIVED from the mode
rather than supplied beside it — two booleans that must agree is how the
session-link leak happened. Only an `ambient` response is `session_bearing`, so
a role-B 401 is never read as our own session expiring. The agent-side carrier
(`_as_principal`) swaps the ambient material for the duration of one arm and is
**not re-entrant**: nesting raises, because concurrent use would send one
principal's session under another's label.

### 38. A control arm's outcome is the PROOF, so a consumer must know WHICH arm it read

**A control arm's outcome is the PROOF, so a consumer must know WHICH arm it
read.** "Marker-bound" is declared per class, and `_test_sqli` confirms on five
channels: four are marker matches and `auth_bypass` is a three-arm differential
whose contradiction and benign arms are DISPATCHED and must refuse. Neither
string carries that fact — `_test_nosqli` has an `auth_bypass` channel with no
shape-matched contradiction at all — so the PRODUCER declares it
(`VulnClass.control_arm`, an unreasoned exemption refused at construction) and
every consumer reads the declaration. Two read it wrong on the same finding,
the juice-shop authentication bypass: the offline re-grade filed a CRITICAL as
`NO_ARM`, and `_fp_ground_error_page` would have demoted it for the two
`status=401`s that ARE its control refusing — spared only because `re.search`
stopped at the tautology's `200` first, which is an ordering, not a rule.
Attributing each status to an arm fixed those two shapes and was the wrong
depth: the ground was reading the `Response:` entry, which is where the **host
under test's** bytes land, so a target serving `status=500`, `stack trace` or
`verified=False` suppressed the finding proving its own vulnerability — and
the arm-aware reader made that easier, scanning every match per entry where
`re.search` stopped at the first. **A guard reads only what the engine
declared** (`response_status`, `reflection_in_error_block`, `verified`),
through the fully-structured reader a response body cannot satisfy. Same rule,
same reason, as `_evidence_strength`. No producer declares those two fields
yet, so that ground fires on nothing today — measured as costing nothing: it
fired 0/90 on stored bundles and the 14 portfolio phantoms die on the control
arm and attribution instead. The **live gate does not relax**: the engine can
dispatch a never-sent arm for the `auth_bypass` channel and does, so
`_persist_finding` still demands one; a stored bundle can dispatch nothing,
which is the whole asymmetry.

## Emission and suppression

### 39. An observation must be attributable to the payload that produced it

**An observation must be attributable to the payload that produced it.** A
confirmation citing a command-output channel the payload never invoked
(`;echo <canary>` does not print `uname` output), or minting a marker and then
citing something else, refutes itself in its own evidence — which shipped
verbatim seven times.

### 40. A deterministic guard whose value is that it needs no model is never gated by one

**A deterministic guard whose value is that it needs no model is never gated by
one.** All **ten** grounds run unconditionally at `_persist_finding` over
every finding, from one declaration (`_deterministic_grounds` — probe plus the
lead reason it produces, read by the emission gate and the FP cross-check
alike). Grounds 9 and 10 are the two that read no evidence at all: they
compare a registry DECLARATION against the run's own principal list — how
MANY principals it holds, and whether it can say which of them outranks the
other — both engine facts, so nothing the target sends reaches them in either
direction. Four of them used to be reachable only *through* the cross-check, i.e.
only once a model had nominated the finding; on the portfolio run that check
returned **no opinion at all** and every ground behind it went unconsulted.
Two consequences are structural, not incidental: an LLM can no longer suppress
anything the code did not already suppress (a finding reaching the cross-check
carries no contradiction by construction, and one that does is logged as a
**bypassed gate**), and every ground's `why_unconfirmed` must be in
`UNPROVEN_WHY_UNCONFIRMED` — an unregistered reason is normalised to
`not_instrumentable` ("we lack the access"), which is not what happened and is
the only part of a lead an operator can act on.

### 41. Silence from a detection path is not evidence of cleanliness

**Silence from a detection path is not evidence of cleanliness.** The
cross-check and the emission gate are ledger components. A review that ANSWERED
and named nothing is `correctly_empty` — the fifth fact, not an alarm; a review
that never ran is `ok=False` ⇒ `ALL_FAILED`, and `ExploitAnalysis.cross_check_ran`
(default `False`) carries the distinction to every consumer. What hid it was an
asymmetry between two siblings: `ProviderPolicyError` was hardened against the
broad-`except` pattern and `DecisionPathFallbackError` was not, so the refusal
on the SUPPRESS path became an empty suspect list — the exact shape of a clean
review. **Both are now `BaseException`**; they differ in *who* catches them, not
in whether anyone can. The second is caught **explicitly, by name**, at the two
sites where degrading is correct — an explicit handler is somewhere to log,
record and disclose the loss; a broad one reaches none of those, and a new
EMIT/SUPPRESS call site that forgets one now fails loudly.

### 42. Suppress, never annotate

**Suppress, never annotate** — a finding the engagement itself believes is a
false positive is **demoted** (removed from `findings`, deleted from the store,
re-recorded as an `UnprovenExploitLead` with `why_unconfirmed`), never emitted
as `confirmed` carrying a caveat. A caveat inside a confirmed finding is still
a confirmed finding. Four shapes can never confirm, in any methodology: a
**conditional execution claim** (speculation about an unobserved downstream
transform), a **reflection inside a framework error page** (reachability, not
an executable context), a **check that determines it is not applicable**
(which returns no finding, never one whose title says "not applicable"), and a
**description of a client-side control** — that the page computes a token in
JS is reachability; the effect is the server ACCEPTING a value we rebuilt from
the page's own chain while rejecting an equal-shaped control. **Whether the
confirming attempt runs is never the LLM's call** — gate it on a deterministic
signal, or the class's only reachable outcome is the description
([client-side-logic](docs/methodology/client-side-logic.md)).

### 43. One engagement is one target state, so a confirmation SUPERSEDES its lead

**One engagement is one target state, so a confirmation SUPERSEDES its lead.**
A lead saying "execution was not witnessed" and a confirmed finding saying it
was cannot both be true of the same `(endpoint, parameter, technique)` — a
deliverable carrying both reads as the report contradicting itself (engagement
`908b7130` shipped exactly that pair, from a driver that switched DVWA's level
underneath one engagement id). The confirmation wins and the lead is dropped
**before** it reaches the store, since the Report agent renders from the table.
Directional, like every other rule here: a witnessed effect outranks the
absence of one, and there is no path by which a lead suppresses a finding.
Matched narrowly — a different parameter, endpoint or technique survives — and
read from the FINAL finding list, so a demoted finding supersedes nothing.

### 44. The suppression runs the same direction as emission: an LLM never overrules a deterministic oracle

**The suppression runs the same direction as emission: an LLM never overrules a
deterministic oracle.** The FP cross-check may demote ONLY by naming a
deterministic **contradiction in the evidence** that the code itself verified
(`_fp_deterministic_contradiction` — an encoded character the payload needed,
malformed/self-inconsistent evidence, a speculative execution claim, an
error-page reflection, or an observation that merely restates the rationale). "The
differential is small" and "this looks like a false positive" name no
contradiction and demote nothing. Emission-side and suppression-side are the same
rule: **a deterministic signal decides, in both directions.** The mechanism ground
is additionally applied at the emission chokepoint (`_persist_finding`), so a
candidate whose observation merely restates its own rationale is a lead whether or
not a reviewer noticed it.

### 45. A veto that reads the model's PROSE applies only to an effect nobody witnessed

**A veto that reads the model's PROSE applies only to an effect nobody
witnessed.** A speculative-execution claim ("if a later layer decodes this, it
executes") contradicts nothing once the deterministic side has seen the payload
land byte-for-byte in an executable position — and prose varies run to run
while a measurement does not, so such a veto over a measurement is a coin flip
that drops live vulnerabilities. Phase 5 records the witness
(`literal_landing_witnessed`); the gate and the FP cross-check both read it,
and a skipped veto is logged and traced (`prose_veto_overruled_by_witness`) —
the suppression that did not happen is as auditable as one that did.

### 46. An execution-type branch is a CLAIM, and it confirms only on the observation that proves ITS effect

**An execution-type branch is a CLAIM, and it confirms only on the observation
that proves ITS effect** — a family whose branches share one verifier drifts
into confirming the weakest of them. Each upload branch declares
(effect, proving observation) in `_FILE_UPLOAD_BRANCH_EFFECT`; only branches
this engine can actually observe may confirm (`_FILE_UPLOAD_CONFIRMABLE_TYPES`),
the rest emit leads naming both halves. And a branch that cannot prove its
effect must never **pre-empt** one that can: the LLM ranks within each half,
the confirmable half runs first, so which branch is tried is the model's call
and whether the class may confirm is not.

### 47. A thin-but-real measurement carries its own control

**A thin-but-real measurement carries its own control** — a differential is
proof when it is *reproducible*, not when it is large. The boolean-blind oracle
sends baseline/true/false as one interleaved triple, repeats it, requires the
signed delta identical in every repeat, and renders all of it into the evidence.
Strengthen the proof rather than loosen the gate.

### 48. Attack the handler, not the listing

**Attack the handler, not the listing** — an endpoint whose response is its own
script source is refused as an exploitation target at the dispatch chokepoint
(`_serves_own_source` in `_execute_task`). Decided on **what came back**, never
on the path: a path fragment is not evidence about a route, and grading a bare
`/source/` segment as noise once cost a real finding.

### 49. A deterministic observation gates the LLM's list, not just its verdict

**A deterministic observation gates the LLM's list, not just its verdict** — a
posture/analysis entry contradicted by what we actually observed (a header
reported missing that is present) is dropped, and severity is recomputed from
the surviving set.

## Determinism, ranking, and coverage truncation

### 50. A class whose input is fully observed asks no model, and a baseline carries the model that produced it

**A class whose input is fully observed asks no model, and a baseline carries
the model that produced it.** The header set is captured in phase 2 and every
WSTG-CONF-07 rule is a pure function of it, so `security_headers` phase 3 is
deterministic end to end (`_deterministic_security_headers_analysis`, formerly
the *fallback*) and the LLM is unreachable — asserted on the CALL, since a test
that only compares verdicts passes against a version that consults the model
and discards the answer. The evidence: over 1,033 recorded phase-3 calls across
126 engagements, the same prompt on a byte-identical observation produced the
version-disclosure entries 27% of the time under `claude-sonnet-5` and 80%
under `claude-sonnet-4-6`, so **a model bump silently re-baselined the DVWA
ladder** and read as a posture regression. `Server`/`X-Powered-By` were
reachable ONLY through that path and are 78% of every weak-header mention ever
produced; they are now deterministic rules. The residual is stated, not
absorbed: **129 mentions across 9 header names** the evaluator has no rule for
(`x-xss-protection` 44, `access-control-allow-origin` 26, `feature-policy` 23,
`cache-control` 17, `x-frame-options` 8, `location` 4, `x-content-type-options`
3, `permissions-policy` 3, `x-recruiting` 1 — the last two of those being the
model naming headers off a page rather than evaluating the set). Ladder
invariance is pinned as a test on fixed observations: byte-identical headers
⇒ byte-identical `(missing, weak, severity)` at all four levels, **and** the
shared verdict is pinned, because four identical wrongs satisfy the first
assertion alone.

### 51. Coverage truncation is never silent

**Coverage truncation is never silent** — the plan cap is loud (per class:
how many candidates were dropped and the first omitted endpoint), each class's
bucket is ordered by relevance to *that* class, and every applicable class is
guaranteed one task before the cap applies. A drop on an endpoint carrying the
class's **own** surface, while lower-relevance tasks survive, is logged
separately as a **RANKING FAILURE**: an ordering defect reads nothing like
tail truncation and must not hide inside it.

### 52. A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound on it is the fingerprint too

**A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound
on it is the fingerprint too** (`agents/_plan_ranking.py`, **detail →
[`docs/methodology/plan-ranking.md`](docs/methodology/plan-ranking.md)**). Two
defects, one shape. The ORDER was a model's answer, so the same fingerprint
ranked 210 times produced 16 different orders and 48 of the 64 fingerprints
ranked more than once produced at least two — an engagement whose plan is drawn
from a distribution cannot be re-run or compared against its own baseline, so
this is a measurement defect before it is a coverage one. And the FINGERPRINT
WAS NOT READ: phase 2 counts the UNION columns and proves the breakout context
and the ranking discarded both, while `predictability == "opaque"` — *you
cannot guess the next identifier* — was read as *there is no horizontal
access*. Replayed over the recorded corpus the old fallback rankings keep
**770 of 833 confirmations** a current vocabulary can express, and 41 of the 63
they miss are IDOR `horizontal` from that one condition.
A ranking now returns the order AND `supported`, the subset some phase-2 probe
empirically backed; `attempt_window` never truncates a supported type and
applies the cap to the unsupported tail, which is hypothesis rather than
evidence. The tail is never empty, because "the fingerprint did not back it" is
not "the fingerprint refuted it" — three recorded `appended_url` confirmations
sit on parameters whose fingerprint said that primitive does not work, and a
ranking built only out of confirmed primitives could not probe them at all. `sqli` and `cmdi` make no
phase-3 LLM call; elsewhere the model orders the SUPPORTED block only — on the
tail it ranks hypotheses against no observation, and it ranked LFI
`error_based_path` ahead of the `wrapper_extraction` that confirmed. Held by a
reachability guard whose domain is COMPUTED from each enum, with both
directions asserted and every exemption reasoned.

### 53. The plan order is a function of the endpoint SET, never of the crawl's order

**The plan order is a function of the endpoint SET, never of the crawl's
order** — a concurrent crawler emits a different sequence each run, so any tie
broken by traversal order makes the engagement non-reproducible. Ranking scores
a **(class, endpoint) PAIR** on three class-specific signals — a parameter of
the shape the class attacks, an **observed** precondition it needs
(`Endpoint.sets_cookies` / `has_form` / `session_setters`), and a path naming
its surface — then breaks ties on how many matched, then on generic surface
value, then on the endpoint's structural identity. Every Tier-1 class carries
signals (`_CLASS_PATH_TOKENS` / `_CLASS_PARAM_NAMES` / `_CLASS_PRECONDITIONS`);
a class with no entry ranks on nothing and its answer hides in a tie bucket.
Same rule for the crawl's enrichment budget (`crawl_visit_priority`) and for
which duplicate represents a collapsed route. **A class with a task is not a
class that can fire** — the floor reserves its best endpoint even when the LLM
named that class somewhere worse.

### 54. `verification_strength` decides emission, and it is a closed vocabulary

**`verification_strength` decides emission, and it is a closed vocabulary** — a
methodology's own `"likely"` means the defining effect was NOT witnessed, while
`_make_finding` stamps `CONFIRMED` unconditionally, so a `likely` result
reaching an emit is a finding that contradicts itself in its own evidence.
Classified explicitly in both directions
(`_CONFIRMING_VERIFICATION_STRENGTHS` / `_NON_CONFIRMING_…`; a test fails on any
unclassified literal), enforced per class AND at `_persist_finding`.

### 55. A guard never parses text the target controls

**A guard never parses text the target controls** — evidence entries hold raw
response bytes, and a value read out of them is a value the *host under test*
can choose. `_evidence_strength` reads only fully-structured `key=value`
entries, so a page echoing `strength=likely` cannot suppress a genuine finding.
A suppression primitive handed to the target is worse than the phantom the
guard prevents.

### 56. Persistent KB feedback loop (Layer-2)

**Persistent KB feedback loop (Layer-2)** — a confirmed discovery finding writes
a per-technology capability fact; confidence is a decayed corroboration PRIOR
from confirming observations only and never gates emission. The older
technique-success loop is retired (read-only for the report's history).

## Components, versions, and provenance

### 57. A CVE match on a version string is a LEAD, never a finding

**A CVE match on a version string is a LEAD, never a finding**
(`knowledge/component_cves.py`). **Affected ranges are half-open**
(`discovery/versions.py`): `[introduced, fixed)` is the primitive, because it
is derivable from the one number an advisory states, while a closed bound
obliges the author to name the last release before the fix — and a guess that
is low by one produces a MISSED finding, which is silence, which is what a
correct run against a patched target also looks like. No control arm here can
see that; every other error this engine makes announces itself. The artifact
was already in the catalogue: jQuery CVE-2020-11022 (advisory `< 3.5.0`) was
carried as `[1.2.0,3.4.9]`, silently excluding `3.4.95`. Prerelease
precedence is SemVer §11 and build metadata is excluded per §10 — stated,
not tolerated by accident — and three boundary decisions are recorded at the
site, each resolving toward the VISIBLE error: an inclusive lower bound
admits every prerelease and distro repackaging of its core (`2.4.49-1ubuntu3.2`
is inside `[2.4.49,2.4.50)`; the open `(X,Y)` is the escape hatch, so the
widening is in the grammar rather than in a convention an author must
remember), a prerelease of the FIXED version is still in range, and the
resulting overlap of adjacent ranges on their shared boundary's prereleases is
pinned rather than hidden. Pinned as PROPERTIES over a generated universe —
total order, boundary side, `[a,c) == [a,b) ⊎ [b,c)` — never a table of cases,
which only asserts the inputs its author thought of.
**Back-ports: provenance gates the CLAIM, never the TEST**
(`ComponentCVEMatch.disposition`). Dispatching only on lockfile-grade
provenance was considered and refused: a dispatch is a hypothesis handed to
our own oracle, so a back-ported host in range is tested, observed to do
nothing, and stays a lead — while refusing it would delete the only
published-CVE coverage of the components most often observed by banner and
buy no honesty `_persist_finding` does not already enforce. An unconfirmable
match has no oracle behind it, so THAT is where provenance speaks: the lead
carries `BACKPORT_CAVEAT` verbatim, and provenance still orders the scarce
reserved slots. The dependency→CVE path runs
fingerprint → component+version inventory (`ReconResult.components`) → known
CVE → **our own oracle on the live target**. It reached the reader only after
the Exploit handoff was unwrapped: the orchestrator passed the recon phase
ENVELOPE (`{"result": …}`) where Scan and Research are both handed their inner
result, so every top-level lookup Exploit makes against recon —
`components`, `tech_stack`, `web_info` — resolved against three envelope keys
and returned nothing on every engagement ever run. Fixed at the handoff, not
in the reader: a reader that tolerates both shapes cannot tell you the next
producer changed. A match either becomes an
`ExploitTask` for the class whose oracle can witness that CVE's effect — and
the CVE is then CONTEXT on a normally-proven finding — or an
`UnprovenExploitLead` saying we have no oracle. A third outcome does not
exist. Same rule that demoted the sqlmap-only SQLi: somebody else's conclusion
is not an observation we made. An **unversioned** component matches nothing
version-bounded (a deliberate recall loss), and an entry that would match
unconditionally — an unbounded `*` over an alternation of generic servers — is
refused by a gate, because a lead equally true of every host says nothing
about this one.

### 58. The fourth plan source RESERVES its slots, and spends them by version provenance

**The fourth plan source RESERVES its slots, and spends them by version
provenance.** Being a plan source it could never win a slot in is the same as
not being one: the Tier-1 interleave fills the plan to
`exploit_max_plan_tasks`, so by the time the CVE union ran `len(merged) >= cap`
was already true and every confirmable match took a "the plan cap was reached"
branch — on every engagement ever run. `_resolve_component_cve_reservation`
now runs BEFORE planning, sizes the reservation at
`min(_MAX_COMPONENT_CVE_MATCHES, dispatchable)` — the 16 is a ceiling, never
the size — and the Tier-1 passes spend `cap - reserved`. Unused reservation
returns to the Tier-1 fill, so a match deduped away against another source's
task costs coverage nothing; **a run that matched no CVE reserves zero and
plans byte-identically**, which is pinned as a test because that is nearly
every engagement. The reservation is a bound that decides coverage, so it is
in `report.json` (`plan_coverage.passes[].reserved` / `configured_cap`), not
only the log.
**Which matches get the reserved slots is decided by how the VERSION was
observed** (`models/recon.py::VersionProvenance`, declared by the PRODUCER —
a consumer parsing `nmap:service` back out to guess the evidence kind is the
`getattr`-with-a-default pattern again). A `Server:` banner is a string the
target chose and a back-ported fix defeats it; a lockfile entry or an artifact
hash is one it cannot easily lie about. `ARTIFACT_STRING` — the version baked
into a bundle the target served — is its own rank between `MANIFEST` and
`BANNER` and not a second spelling of the latter: both die to a back-port, but
a `Server:` header is composed per request and one `ServerTokens` line from
saying nothing, while a `/*! jQuery v3.4.1 */` comment is in the shipped bytes
and names the package's own release. `match_components` orders confirmable
first, then by provenance, THEN by published severity — ahead of severity
deliberately, because the ordering decides what is TESTED and ranking a
banner-backed CRITICAL over a lockfile-backed MEDIUM spends the scarce slots
on the weakest evidence in the system and calls it prioritisation.
`undeclared` ranks last, like `undeclared` research grounding. Every
fingerprinting TOOL declares `BANNER` and says why in its own docstring;
`agents/_package_identity.py` is the producer that declares the three stronger
values, which is what made `dedupe_components`' provenance tie-break stop
being a no-op. An AST guard
(`tests/test_tools/test_component_provenance_declared.py`) fails a
construction site that declares nothing, so a new reader cannot be silently
demoted to the weakest rank.
**The inventory itself is now in the deliverable**
(`report.component_inventory`, rendered as *Component inventory* in the
Markdown and the PDF): provenance decides which match is TESTED, so it is a
bound that decides coverage and belongs beside `plan_coverage` and
`crawl_coverage`. It also lifts a replay ceiling — `hosts[].services` is empty
on all 70 stored bundles carrying `plan_coverage`, so no stored report has
ever carried an inventory and every offline replay had to reconstruct one from
recorded tool stdout.
**The provenance rides the task into the finding** (`ComponentCVEContext` on
`ExploitTask`, stamped onto findings at the `_execute_task` seam). The CVE is
still context and nothing here can create, promote or rescue a finding — but
the deliverable now says *which* observation the oracle was pointed at and how
strong it was, which is the difference between this and a template scanner.
The evidence line is prose by construction so the structured-evidence readers
(`_evidence_strength`, the deterministic grounds) cannot mistake a
target-chosen product name for an engine verdict.

### 59. A plan source that gets no slots must still say so

**A plan source that gets no slots must still say so.** The tier-2/3 research
source sat behind `if len(tasks) < cap`, which the interleave makes false on
any saturating target — so `_build_tier23_tasks` was never even CALLED and a
starved research source looked identical to a research phase that produced no
techniques. It is now always computed and its candidates join the truncation
buckets, so the cap refusing them shows up in the report's per-class dropped
counts. It is deliberately given no reservation of its own: both names it
produces are registered `NOT_IMPLEMENTED` and construct no `Finding`, while
the dispatcher fetches the endpoint before calling them — so a reserved slot
would cost the client's target a real request and a confirming class a real
task. The fill itself is unchanged.

### 60. The PRODUCER declares what it fingerprinted, too

**The PRODUCER declares what it fingerprinted, too.** `detected_components()` /
`declares_components()` is the discovery contract's twin, for the seam that
used to read `hasattr(r, "technologies")` then `hasattr(r, "tech")` — two
spellings because two wrappers differ, and a third would have contributed
nothing silently. A non-declaring wrapper is a loud `DEAD_SEAM`, never an
empty list.

### 61. A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the resolver reads the declared ORDER

**A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the
resolver reads the declared ORDER.** `find_tool` resolves through the
capability map, so a chain entry the wrapper does not declare is a fallback
that cannot fire (httpx, nikto — and `subdomain_discovery`, which resolved to
`None` on every call ever made). The map is built in module-import order, which
was invisible while every chained capability had one implementer and became a
silent preference inversion the moment a fallback became real.

### 62. Resolving is not the same as being used, and an unused capability states its reason

**Resolving is not the same as being used, and an unused capability states its
reason.** `tests/test_tools/test_tool_wiring_decisions.py` accounts for every
chained capability as either wired (with its caller) or deliberately unwired
(with a substantive reason, verified against the source so it cannot become
documentation of a wish). `vulnerability_scanning` (nuclei/nikto) stays unwired
because its output is verdicts we would have to confirm ourselves — and the
confirmable subset, version matching, is what `component_cves.py` already does
with an explicit affected-range predicate. `subdomain_discovery` (subfinder)
stays unwired because it expands the TARGET SET, and the target set is the
authorization boundary: acting on a discovered subdomain would test a host the
client never authorised.

## Fences, seams, and guard domains

### 63. One origin fence

**One origin fence** (`agents/_origin.py`). The scheme dimension was missed
twice in one week by two code paths — that is a missing abstraction, not two
mistakes, because the host comparison is the obvious half and each new call
site re-derives only the obvious half.

### 64. "Is this the same string" is the right question for a FENCE and the wrong one for a finding's IDENTITY

**"Is this the same string" is the right question for a FENCE and the wrong
one for a finding's IDENTITY** (`agents/_origin.py::OriginIdentity`). One
Juice Shop container answered as `http://clinkz-juiceshop:3000` and as
`http://172.20.0.2:3000` — the crawler resolves the host itself and reports
the address it connected to, so a hostname goes into the plan and an address
comes out of the very next component — and the header class emitted a missing
CSP and a missing Referrer-Policy against each: **four findings for two issues
on one service**. The alias is OBSERVED, never inferred: curl's
`%{remote_ip}` at the HTTP chokepoint is the only code that knows what address
it reached, so the producer declares (`HTTPClientOutput.resolved_address`) and
the consumer reads — and `exploit._observed` is the ONE seam every response
returns through, because eight call sites built a byte-identical response
block and a ninth would have been the one that did not observe. **Name-based
virtual hosting fails SAFE**: an address seen under more than one NAME is
ambiguous and every origin on it keys on itself, because over-merging HIDES a
finding and emitting one twice does not. **Unobserved ⇒ an origin is its own
identity**, so a run that resolves nothing behaves exactly as before. The same
defect one layer down gave `/rest/basket/:id` and `/rest/basket/:p3` from one
crossing: the parameter name is whichever discoverer found the route, so the
IDOR key is the **dispatched request** (`(service, crossing path)`), not the
name.

### 65. A phase stopped at its own wall clock is not a run that did not happen

**A phase stopped at its own wall clock is not a run that did not happen**
(`agents/report.py::_run_completion`). `"timeout"` sat in the same set as
`"error"`, so three identical envelope runs disagreed on the honesty banner:
the research phase overran the orchestrator's grace window once and that
report rendered "THIS RUN DID NOT COMPLETE" over the same findings the other
two rendered clean. **A banner that fires on a third of good runs is one a
reader learns to skip.** The split is on an engine fact, not on a list of
which phases may time out — `_phase_stop_result` carries the agent's delivered
result through a stop, so a timeout WITH a result is a phase that did its work
and ran out of clock, while a timeout with NOTHING is indistinguishable from a
phase that never ran and still trips the banner. Behind it, the research
budget is now a real deadline rather than a checkpoint gate
(`research._within_budget`): it used to bound only where a new STEP began, so
one slow in-flight call carried the phase into the force-kill that DISCARDS
its return value — the trap already documented for Scan, reached by another
route.

### 66. A mock at a tool or parser seam returns the REAL output model

**A mock at a tool or parser seam returns the REAL output model.** Gated by
`tests/test_tools/test_mock_shape_audit.py`: a test-local `ToolOutput`
subclass is refused unless allow-listed *with a reason*, and the only entries
are the deliberately-broken producers that ARE the dead-seam alarm's negative
control. A test that can only pass against a fiction is worse than no test,
because it is counted as coverage.

### 67. A guard's DOMAIN is computed from the same source of truth as the thing it guards; only the CLASSIFICATION is hand-maintained

**A guard's DOMAIN is computed from the same source of truth as the thing it
guards; only the CLASSIFICATION is hand-maintained** (**detail →
[`.claude/skills/clinkz-dev/SKILL.md`](.claude/skills/clinkz-dev/SKILL.md),
"The guard-domain law"**). A partition asserted over a domain that excludes
the unclassified members is a partition of whatever is left — and the members
a hand-maintained domain forgets are exactly the ones that most need the
guard, because one omission produced both. `test_control_arm_registry`'s
`_dispatchable()` was `_CLASS_TRACE_SKILL | _BUSINESS_LOGIC_CLASSES`, 27 of
the dispatch table's 30, so `_test_log4shell` — the engine's one CVE oracle —
EXITED the never-sent-control completeness check rather than failing it, and
the guard was green throughout. Both directions are asserted (`computed -
declared` catches the new member; `declared - computed` catches the entry that
outlived what it described), and an exemption is an allow-list entry with a
substantive reason, never a silent skip. The pattern to copy is
`test_tool_wiring_decisions.py` (domain = `TOOL_CHAINS`) and
`test_parser_input_assumptions.py` (domain = an AST walk over the real
modules).

## Chaining, business logic, and the benchmark profile

### 68. Two confirmed findings do not imply the chain between them, and neither does a successful second request

**Two confirmed findings do not imply the chain between them, and neither does
a successful second request.** A carriage is proven against a control: the real
artifact ACCEPTED and an **equivalently-shaped decoy the target never issued**
REFUSED (`chaining/composition.py`). An accept-everything endpoint cannot
produce that observation, and a guess cannot either. Decoy accepted too ⇒ the
endpoint accepts the SHAPE not the VALUE, and the honest outcome is a
`ChainResearchLead` naming the link — never a finding with a caveat. The
carriage's primitive is **P4**, so chaining introduces no new confirmation
primitive and inherits the zero-FP boundary rather than widening it.

### 69. A yield is what a class's confirmation PROVES, never what the class is named after

**A yield is what a class's confirmation PROVES, never what the class is named
after.** Reflected XSS is *about* stealing a session and this engine has never
demonstrated exfiltrating one, so it declares no yield and says why
(`chaining/vocabulary.py::NO_YIELD_REASON`) — declaring the aspiration would
head a chain whose next link could not be carried, and a chain that cannot be
carried cannot be falsified. Every dispatchable class is in one table or the
other. Artifacts are harvested at ONE seam (`_persist_finding`, driven by the
DECLARED yield), and the carried VALUE is excluded from serialisation — a chain
carries exactly the material a report must not reproduce, so the evidence
quotes a shape and a salted fingerprint. Escalation is a function of the
DEMONSTRATION: only a confirmed composition escalates, and a chain never LOWERS
what a single link already earned.

### 70. Business-logic intent must be EVIDENCED from the application's own surface

**Business-logic intent must be EVIDENCED from the application's own surface**
(`agents/_business_logic.py`) — a field in the server's own representation, the
value range that representation shows, or the app's own words when it refuses.
Unevidenced ⇒ a lead: unusual-but-intended looks exactly like a flaw from
outside (a negative balance may be a credit note), and what an application
*should* do is an opinion. Every finding states intent + evidence + the
observation exceeding it, built at ONE seam. **The status code is never the
effect** — the read-back is, because an API that accepts `quantity=-1` and
stores `1` enforced the constraint, and an idempotent handler answers 200 to a
replay.

### 71. The destructive refusal is the contract, and the benchmark profile does not loosen it

**The destructive refusal is the contract, and the benchmark profile does not
loosen it** (`models/engagement.py::BenchmarkProfile`, `safety/benchmark.py`).
No flag and no partial shape: a verbatim attestation, an explicit per-category
list (no wildcard), a declaring party and a reference, or the model refuses to
construct. **Session destruction and security-posture toggles are never
permittable on any target** — they damage the ENGAGEMENT, not the target.
Permission is by the category that DECIDED the refusal, never an alias. Absent
by default like the governor; every permitted request is logged
`benchmark_permitted:<category>` and the profile is in the report header.

## The contribution ledger and reachability

### 72. A total is not evidence about its parts

**A total is not evidence about its parts** (`observability/ledger.py`, **detail
→ [`docs/lessons/silent-degradation-and-the-dead-seam.md`](docs/lessons/silent-degradation-and-the-dead-seam.md)**).
Three defects shipped with one shape — an empty LLM planner absorbed by the
class floor, a timeout absorbed by provider fallback, 100% of ffuf's output
discarded by a duck-typed seam and absorbed by the crawler. Each time a
component produced NOTHING, a fallback covered, findings still appeared, and
no gate fired. The ledger records per component invocations, successes and
**items contributed**, and reports at WARNING (run log + `report.json` +
the report's *Component contribution* section) every component invoked that
contributed zero. Four alarm classes stay apart because they have different
fixes — `DEAD_SEAM` (the consumer cannot read this producer), `SILENT`
(succeeded, contributed nothing), `ALL_FAILED`, `FALLBACK_ACTIVATED` — and
*declared but never invoked* is tracked separately, since a capability the run
never reached for did not degrade. **Absent by default** like the governor,
and it never raises from the data path.

### 73. A benchmark number a client sees must be what TESTING earned

**A benchmark number a client sees must be what TESTING earned.** Runs 2 and 3
of the Juice Shop variance envelope dispatched **zero** methodology tasks and
still had four challenges marked solved by the target — `errorHandling`,
`loginAdmin`, `securityPolicy`, `weakPassword` — from authenticating and
crawling alone. Those are in `solved_total` for every run including the ones
that tested, so run 1's "7 of 49" is roughly twice what exploitation achieved;
the honest figure is 3. `reconciliation.json` now carries `solved_by_testing`
BESIDE `solved_total` (both are true, only one is a claim about this engine),
plus `methodology_dispatches` and the floor's provenance. The floor is
**measured, never declared**: written by a run whose ledger shows
`methodology:*` contributing zero dispatches, carrying the engagement id that
produced it, and `record_floor` REFUSES any other kind of run — a floor taken
from a run that tested is this engine subtracting its own results from itself.
A union across zero-dispatch runs, one-way. **No floor measured ⇒
`solved_by_testing: null`**, not zero: defaulting to "subtract nothing"
silently restores the inflated number. `--record-floor` derives one offline
from a stored bundle and sends nothing.
**And a solve we cannot point at a finding for is not something we can tell a
client we did.** `solved_by_testing` is what our traffic tripped; a solve is
the TARGET's verdict and a finding is ours, and the two are not the same
claim. All three envelope runs earned three solves and emitted a finding for
two — `basketAccess` and `redirect`; `forgedFeedback` is a **write** crossing
carrying another user's `UserId` in a POST body, which no dispatched class
claims. `attribute_solves` splits them into `solved_attributable` and
`solved_target_confirmed_only`, **naming** the unattributed keys and why.
**The binding is to a FINDING, not to a class.** A category-level link is
satisfied by any sibling of the class: run 3 emitted `_test_idor` findings at
`/rest/basket/:id` AND at `/api/Users/:p3`, so `basketAccess` read as
attributable from either — and the corrected anchored oracle, which refutes
the first and keeps the second, left the positive reading standing on
evidence that had been removed. A positive reading that outlives its own
evidence is a phantom wearing a category label, and it is the same failure as
grading an oracle by an external scoreboard. So a solve is attributable when
a specific surviving confirmed finding clears BOTH halves: its class could
claim the challenge's own category (`CATEGORY_CLASSES`, held to the
guard-domain law against `CATEGORY_ADDRESSABLE` and against
`DISPATCHABLE_TEST_METHODS`), and it was DISPATCHED against the surface the
challenge NAMES (`CHALLENGE_SURFACES`, compared as a path shape that
normalises away the origin, the query string and an identifier segment —
`:id` / `:p3` / `2` are three spellings of one route). The finding is named
beside the solve, so removing it removes the claim. Juice Shop's records carry
a category and a sentence and never a route, so the route is declared with the
sentence that sources it verbatim; a **stale** entry naming a challenge the
target does not ship is a loud failure, while an **undeclared** challenge is
unattributable by construction — the safe direction, because a missing entry
costs a number and a category-level match costs the number's meaning. It is
still NOT a claim that a particular finding solved a particular challenge: the
scoreboard does not record the request that tripped it, and inventing that is
the consumer-guesses-the-producer move this codebase keeps paying for.
Collection-vs-item is the finest distinction the records support — a finding's
target carries no method — and it is load-bearing: `forgedFeedback` is a WRITE
on `/api/Feedbacks` and run 3's read crossing at `/api/Feedbacks/2` does not
reach it. The negative is the half that matters: a solve no surviving finding
can be bound to is one we cannot show our work for.
**"Any other kind of run" is four kinds, and three of them were found in the
bundle the stored floor was taken from.** A floor is what authenticating and
crawling trip **as those principals**, so it is KEYED by the credential set
(`credential_set_key`, read from the run's own `authentication.roles`) and a
floor measured under different principals is refused rather than applied:
adding `jim` beside `admin` adds whatever `jim`'s login trips, and subtracting
the admin-only floor credits that to testing — the inflation re-entering by
the door nobody was watching. One record per credential set, unioned only
within one. A run whose **`model_stamp` names an unserved stage** is refused:
it dispatched zero because nothing served it, which from the harness's
position is indistinguishable from a floor observation, and its truncated
crawl UNDER-measures the floor, which inflates `solved_by_testing`. And a
ledger carrying **no `methodology:*` row at all** is unmeasurable, not zero —
those components are declared at engagement start, so their absence means the
bundle predates that registration (four stored Juice Shop bundles, 6–11
findings each, would each have qualified as a floor). The stamp is the witness
because the register is not: `2e21a200` reports `provider_degraded: false,
baseline_eligible: true` beside a stamp saying nothing served recon, scan or
exploit. **No stored bundle satisfies all four guards**, so the floor on disk
is a legacy unkeyed record that applies to nothing and the re-measure is a
prerequisite, not a nicety.

### 74. A batch is unattended, so a credit lapse must stop it rather than fill it

**A batch is unattended, so a credit lapse must stop it rather than fill it**
(`scripts/three_run_envelope.py`). The 2026-08-25 envelope produced three
bundles and one measurement: runs 2 and 3 died to a depleted Anthropic
balance. Two guards, both reusing vocabulary that already exists. **Before the
batch**, `preflight_providers()` — already run at every engagement start —
classifies a depleted balance or revoked key as `KeyStatus.INVALID`, which is
what `primary_usable` is False on; the Orchestrator logs it and continues,
correct for one engagement an operator is watching and wrong for a batch, so
the batch refuses to start (exit 3, nothing sent). A busy provider
(`UNREACHABLE`) does NOT refuse — the chain retries, and a three-hour batch
should not die of a 429 at t=0. **After each run**, a bundle whose
`model_stamp` names an unserved stage is excluded from the envelope entirely
and the batch aborts (exit 4): an average over one real run and two dead ones
is a wrong number, not a wider envelope, and an account condition does not
clear between runs. **And a metric no run REPORTED is `null`, not zero** — the
rule `variance` documents and three of its four metrics kept by doing nothing,
since `recorded.get(key)` is already `None` on a missing key. `findings_emitted`
is a list and `len(... or [])` broke it in the one place it took an expression
to keep: an omitted key became `0`, which passes the `is not None` filter and
widens the envelope downward as a real observation of a run that found nothing.
`envelope_metrics()` is the one reader, and `isinstance(v, list)` is what
separates a recorded empty list (a measurement of zero) from an absent key.

### 75. A recon component that RAISED must not look like a target with nothing to find

**A recon component that RAISED must not look like a target with nothing to
find.** Recon is where the component inventory comes from, and an empty
inventory has two causes indistinguishable from every downstream position: a
target with no versioned component, or a parser that raised on the tool's real
bytes (`whatweb` discarded a complete Apache/PHP fingerprint on every run for
years, silently). The fingerprinter's handler was fixed alone; its two
siblings in the same file had the identical shape — including
`_step_service_scan`, the RICHER source, since `nmap -sV` resolves a banner to
a product AND a version through nmap's own signature database, which is why
its provenance outranks a `Server:` header. All three record now, and the
domain is COMPUTED (guard-domain law): every `except` inside a
component-bearing method must reach the ledger or carry an allow-list entry
with its reason (`tests/test_agents/test_recon_failures_reach_the_ledger.py`).

### 76. A ledger VIEW is not a second population

**A ledger VIEW is not a second population.** `exploit.component_cve_match`
appearing twice in `component_ledger` is `components` (the population) plus a
by-name reference from `correctly_empty` — one registration, `invocations: 1`.
Containment, not double registration and not a serialization bug. It was
pinned for `alarms` alone while three sibling views went unchecked, so the
domain is now every list key `to_dict()` emits, each classified as a VIEW (and
its containment asserted) or its own population (with the reason `fallbacks`
is one). The distinction decides whether a consumer may SUM, and a union would
stay invisible until a component alarms while carrying real items.

### 77. "Correctly found nothing" is a fifth fact, and it is NOT an alarm

**"Correctly found nothing" is a fifth fact, and it is NOT an alarm.** A
GraphQL discoverer on an app with no GraphQL contributes zero forever and is
working perfectly; reported as a defect it becomes a permanent false alarm,
and a permanent false alarm trains an operator to skim the section where a
real one will appear. So a component may declare its **precondition absent**
and the zero is recorded NOT APPLICABLE with the reason, held apart from the
alarm list like *never invoked*. The claim must be **falsifiable, never a
self-assessment** — "there was nothing to find" is what a broken reader says
too — so the discriminator is how far the component's own pipeline got
(`_route_discovery.DiscoveryReport`): no input of its kind, or input read
containing nothing of its shape, is correct; **candidates found and none
emitted is the ffuf shape and stays SILENT**, and no reason string may talk
it away. A discoverer that does not declare `contribution_report()` is a
loud `DEAD_SEAM`, never an assumed zero.

### 78. A component the ledger never hears from is not measurable, so every component is DECLARED at engagement start

**A component the ledger never hears from is not measurable, so every
component is DECLARED at engagement start**
(`observability/component_registry.py`). The ledger can only measure what
registers, and exactly one call site in the engine declared anything (LLM
providers) — so a vuln class that never dispatched, a discoverer that never
ran and a tool the resolver never found all produced the same artifact:
nothing at all, indistinguishable from never having been built. `declare_all()`
runs immediately after `set_active_ledger` and declares every member of three
**computed** domains — `DISPATCHABLE_TEST_METHODS`, `default_discoverers()`,
`TOOL_CHAINS` — plus `STATIC_EXPLOIT_COMPONENTS`, the declared half, held to a
**bidirectional AST assertion** over every string-literal `record_contribution`
name in `src/` (guard-domain law: `computed − declared` catches a new call
site, `declared − computed` catches an entry that outlived one). Per-class
methodology components register at the ONE dispatch seam, keyed on the
`_test_*` name VERBATIM — never a derived skill, because `_test_x → "x"` is
right 23 times and wrong once — and their `items` counts DISPATCHES, not
findings: counting findings would trip SILENT for every clean class on every
clean run, which is the permanent false alarm this whole section exists to
prevent.

### 79. "Declared and never invoked" has two opposite readings, so reachability is a COMPUTED PREDICATE and its TIMING is split from the declaration's

**"Declared and never invoked" has two opposite readings, so reachability is a
COMPUTED PREDICATE and its TIMING is split from the declaration's.** A
free-text `reachable_because` is a hand-maintained excuse list and would drift
the way every hand-maintained guard domain here has; a sentence attached to a
*predicate function* cannot, because there is one per predicate rather than
one per entry. Existence is knowable at engagement start; reachability is not
— whether the target has a SQL surface is something only Scan can answer, and
the plan does not exist yet. So `ContributionLedger.resolve_reachability` runs
at REPORT time against an `EngagementReachability` the orchestrator assembles
from completed phase state. Three states fall out mechanically: predicate true
+ not invoked ⇒ **`BUILT_BUT_NOT_RUN`**, a new alarm class (built, reachable,
did not run); predicate false + not invoked ⇒ NOT APPLICABLE with the
predicate's own sentence as the reason (`component_ledger.unreachable`,
enumerated in `report.json` and summarised as a count in the Markdown so
thirty per-class lines cannot bury the alarm table); no predicate declarable ⇒
a build failure, not a runtime branch. `reachable is None` — never evaluated,
a direct invocation or a run that stopped early — is not `False` and never
alarms. The tool predicate has three distinct "no" answers because they have
three different fixes: nobody asked for the capability (nuclei, subfinder —
both deliberately unwired), the tool is a declared fallback and the preferred
one answered, or it is not available in this execution mode. That first answer
needs `ToolResolver.requested_capabilities`, and the chain map the predicate
reads is built through `available_chain()`, which does NOT record — a question
asked *about* a run must never become part of what the run did.

### 80. A predicate may only be evaluated against a producer that SPOKE, so there is a FOURTH state: NOT DETERMINED

**A predicate may only be evaluated against a producer that SPOKE, so there is
a FOURTH state: NOT DETERMINED.** Every predicate compares a counter against
zero and then writes a sentence about the CLIENT'S APPLICATION — *no endpoint
the scan discovered carried this class's surface* — and a counter left at its
default is byte-identical to one a producer set to zero. An exploit phase that
errored yields all-zero state, `resolve_reachability` ran on it
unconditionally, and every methodology class was filed NOT APPLICABLE carrying
that sentence, in the client PDF under *Built, but not reachable on this
target*. Not a wrong number: a wrong sentence about a client's application,
generated from a phase that never ran. **Suppressing a wall of alarms and
substituting a target claim are different acts**, and the defensive-defaults
docstring bought the first with the second. Each predicate now declares its
`ReachabilitySource` (`EXPLOIT_PHASE` / `EXPLOIT_PLAN` / `SCAN_PHASE` /
`ENGINE`), `EngagementReachability.reported_sources` declares which producers
delivered — defaulting to NONE, so an unpopulated state answers nothing — and
a predicate reading a silent producer gets
`set_reachability_undetermined`: `reachable` stays `None` (no alarm), the
record leaves `unreachable` (no claim) and lands in
`component_ledger.reachability_undetermined`, which both documents render as
*reachability not determined* naming the silent PRODUCER and never a
per-class sentence. **Both doors are closed**, because gating on the exploit
result alone leaves the second open: `plan_alarm_summary()` returns the same
empty `classes_with_candidates` when no register is installed, and a register
that recorded no pass has said nothing about a plan the planner writes on
every pass, truncated or not. The gate is per-PREDICATE, not per-run — a dead
exploit phase must not cost the answers a live scan supports. And it is
reconciled against the run-completion banner
(`_report_integrity.reconcile_reachability_claims`, pure, only ever
tightening, at BOTH seams): a phase can deliver a result whose reasoning step
nothing served, which the source gate cannot see, and a document whose own
summary says the run did not complete must not carry target claims derived
from the phase that did not.

### 81. The prompt cache is a ledger component like any other, because it degraded exactly like one

**The prompt cache is a ledger component like any other, because it degraded
exactly like one.** It was invoked every run, succeeded every time, and
contributed **zero**: the breakpoint sat after the engagement-scoped span —
~12,500 tokens of observed inventory presented ONCE per run — so 154 recorded
engagements paid 96,759 cache-WRITE tokens and read back 0. Caching pays from
the second presentation (`1.25 + 0.10(N-1) < N` ⟺ `N > 1.28`); the deployment
had `N = 1`, making it ~25% *more* expensive than no caching on that span.
`PromptSegments` now splits by **how often bytes repeat** — `invariant`
(engine: role, catalogue, preconditions, worked examples) / `stable`
(this engagement's observations) / `volatile` (the ask) — and the breakpoint
goes after `invariant` only. The item the cache contributes is
`cache_read_input_tokens`, so a write nobody reads trips SILENT in the run
log and `report.json`. **And it kept tripping, so the cache is now OFF by
default** (`llm_prompt_cache_enabled`): the smaller span was the right span
and `N` was still 1. Every trace on disk — 13 breakpoint calls across 13
engagements, **zero** ever making a second one, 104,589 write tokens against
0 reads, and no two breakpoint calls closer than 1,692s against a 300s TTL —
says the second presentation does not exist by either route, in-run or
cross-run. A permanent SILENT alarm is worse than the cost it names: **a
ledger where an alarm always fires teaches the operator to stop reading it.**
The flag and the split stay, because the machinery is correct and only the
arithmetic failed; a deployment that really re-presents a prefix inside the
TTL turns it on and re-derives its own hit rate from its own traces.

## Producers, parsers, and traces

### 82. A consumer never guesses a producer's field names

**A consumer never guesses a producer's field names.** The PRODUCER declares
what it contributes (`ToolOutput.discovered_urls` / `declares_discovery`); a
wrapper that declares nothing is a loud dead seam, not an empty list. Never
`getattr(parsed, "field", default)` over a model — the default is what turns a
typo into a permanently dead capability (`sqlmap`'s `injectable` vs
`vulnerable` returned False on every run for years). **A mock mirrors the real
model's contract**, never the consumer's assumption about it: `_MockFuzzOutput`
declared `paths`/`directories`, names no real tool has ever carried, so the
suite asserted a contract only the mock honoured.

### 83. A parser never assumes it owns the process's stdout, and the fixture must be the bytes the tool WRITES

**A parser never assumes it owns the process's stdout, and the fixture must be
the bytes the tool WRITES.** `whatweb --log-json=-` keeps writing its brief
human-readable log to the same stream, so the JSON array and plain-text lines
interleave, `json.loads` on the blob raised, and 100% of a successful
fingerprint — Apache 2.4.67, PHP 8.5.6 — was discarded on **every run**,
starving the whole published-CVE path. The committed fixture was a
hand-authored clean array, so the unit suite passed throughout, and the
corpus baseline faithfully locked in `success: false` for 114 of 115 recorded
invocations. Whole-blob `json.loads` is correct ONLY for JSON the wrapper
itself serialised; every parser now declares which case it is
(`tests/test_tools/test_parser_input_assumptions.py`, verified against the
source so a `self_produced` claim cannot be a wish).

### 84. An auth bypass is a defining effect no injection oracle can see, so it gets its own indicator

**An auth bypass is a defining effect no injection oracle can see, so it gets
its own indicator** (`agents/_auth_bypass.py`, `InjectionType.AUTH_BYPASS`).
A DB error, a boolean row-set delta and a UNION row are the SQLi oracles; a
bypass returns 200 and a JWT, so 40 payloads reached a login field, the target
graded it solved, and the class correctly emitted nothing. The effect is
**authenticated as a principal whose credential we never supplied**, proven on
three arms: the tautology returns an auth artifact, the *shape-matched
contradiction* (one character apart) does NOT, and an ordinary credential
attempt does not either. **Never 200-plus-a-cookie.**
Applicability is a deterministic protocol signal (an identity field beside a
password-shaped one), gated in BOTH directions so the LLM can neither invent
the class on a search box nor omit it on a login. **The LLM synthesizer is
structurally unreachable for this type** — its prompt has no `auth_bypass`
vocabulary, so an LLM-built pair either fails phase 5 as an unknown indicator
or runs a row-set oracle against a login handler; the deterministic table
declining ⇒ the class ABSTAINS, recorded. **The identity suppression keys on
credential POSSESSION, not identity coincidence**: "we logged in legitimately
and it told us who we are" has two routes — a session for the principal, or a
valid credential for it — and equality with `_authenticated_as` proxies both
badly. It suppresses `admin@juice-sh.op'--`, a bypass carrying no password, on
every app whose first row is the admin. So the session route is closed by a
**runtime carrier assertion** (all three arms' dispatched args carried no
cookie jar, cookie dict or auth header — else the identity is KEPT, failing
safe, with the reason on the verdict) and the credential route by requiring
BOTH halves in the same request (identity + a password-shaped field whose
fingerprint matches one we hold). The payload is never a supplied identity.
**Detail →
[`docs/methodology/auth-bypass.md`](docs/methodology/auth-bypass.md).**

### 85. Execution traces

**Execution traces** — each engagement writes `outputs/<id>/trace.jsonl` (tool
calls, LLM calls, agent steps, handoffs, methodology-phase events). `outputs/`
is local-only by policy — never committed.

## Terminal classes: when the test changes the target

### 87. When the payload's effect outlives the request, the CONTROL runs first

Every control arm in this engine runs *after* the confirming one. The class
observes its effect, dispatches a probe with the exploitation mechanism removed,
requires the same oracle to refuse, and emits. That order is not a convention —
it is the only order that made sense, because every payload the engine had sent
until now leaves the target's *behaviour* exactly as it found it.

Prototype pollution does not. The payload writes a key onto the target process's
`Object.prototype`, and from that moment every object the process creates
inherits it. A control arm dispatched afterwards is therefore observed *through a
prototype the payload has already written to*: it exhibits the effect too, the
arm records `confirmed_on_control`, and the finding dies. Not a false positive —
a **false negative manufactured by the proof itself**, on the one class where the
proof is the strongest evidence available.

This was not discovered in production; it was reasoned out before the class was
written, and then measured. `test_prototype_pollution_oracle.py::TestTheArmsMustRunInThisOrder`
grades the real recorded pollutable case with the two observations swapped, and
both gadgets flip from confirmed to refused.
`test_prototype_pollution_live.py::test_the_control_would_have_confirmed_had_it_run_second`
dispatches a control *after* the payload against the live Node target and asserts
it does show the effect — so if the fixture ever stopped exhibiting the
constraint, the test depending on it fails rather than passing vacuously.

The remedy is a seam, not a rule the class remembers. `_run_control_arm_first`
dispatches the control, runs the class's confirming arm, and records both through
the same `_finalise_control_arm` every ordinary arm uses — so the ledger row, the
trace entry and the disclosure-on-kill hold identically for both orders. The
class hands its half back as a `ConfirmingArm` rather than calling the recorder
itself, because a class that can forget to record is a class that will.

**Write crossings will hit this next.** A crossing arm that modifies the other
principal's object leaves that object modified, so its control has the same
problem. The class docstring says so, and the seam is already there.

### 88. A class whose effect outlives the RUN is terminal, and a transient task after one stops the run

The ordering rule above is about two arms of one class. This is about the other
twenty-nine.

A prototype write changes how the application answers requests *the class never
made*. Every observation after it — every probe, and specifically every other
class's control arm — is a measurement of a target this run has already altered.
So the class is dispatched last, after every other class has finished, and the
rotation in `_step_execute_exploits` only reaches it once no transient task is
left.

The predicate is narrower than "writes to the target", and drawing it carelessly
would have caught half the engine. Stored XSS stores a payload; mass assignment
creates objects; the business-logic classes advance records. Those are ordinary
application records, deleted the way a client deletes any record, and none of
them changes the behaviour of an unrelated request. What makes a class terminal
is that its write is **process-global and irreversible through the application**.

`TERMINAL_DISPATCH_CLASSES` / `TRANSIENT_DISPATCH_CLASSES` partition
`DISPATCHABLE_TEST_METHODS` — the domain computed from the table the dispatcher
itself reads, both directions asserted, a substantive reason per entry, exactly
as `CONTROL_EXEMPT_CLASSES` does. A class in neither is a red build: "nobody
classified it" and "it leaves nothing behind" are different facts and only one of
them is safe to dispatch early.

And the ordering is asserted **at dispatch, on every dispatch**
(`assert_terminal_dispatch_order`), where it raises `TerminalDispatchOrderError`
and stops the run rather than warning. It holds by construction today, which is
the reason for the check and not an argument against it: a scheduler change that
interleaved differently would break the property silently, and the corrupted
results would be indistinguishable from sound ones in every artifact the run
produces. A warning in a log nobody reads is not a guard against a failure whose
whole character is that it looks fine.

Two consequences worth stating rather than discovering:

* **A terminal class is the first thing an early deadline costs.** It is last in
  the rotation, so a cooperative-deadline stop drops it before anything else.
  That is the correct trade — dispatching it early to preserve breadth would
  corrupt every observation after it — and
  `test_breadth_survives_dispatch_deadline` now asserts the exclusion rather than
  tolerating it, so the loss is visible in the test that owns breadth.
* **A wildcard authorization does not cover a terminal class.** `permits_all` is
  how a client says "test everything"; it is not how they say "leave my process
  altered until I restart it". Every other class either observes or writes a
  record the application can delete, so a blanket yes carries no obligation a
  client would have wanted to be asked about separately. This one does, so it
  needs its key named, and the report's *What was NOT tested* section says which
  key and why.

### 89. A change TESTING made that the target cannot undo goes in the client-facing document

Every honest-limits section in a Clinkz report is about what the engine could not
prove. `ResidualMutation` is the first one that is about what it **did**.

A confirmed prototype pollution leaves a key on a running process. No request
removes it, no administrative action removes it, no cache clear removes it — the
process holds it in memory and has to be restarted, every worker if the service
runs more than one. That is the first finding in this engine's history whose
remediation is something the operator must do to their own infrastructure
*because we ran the test*, and reporting it only in `trace.jsonl` would hand them
an unlabelled change to their own systems whose first symptom is something
downstream behaving oddly.

So it renders as **Changes this test left on your systems**, ahead of the
findings, in the Markdown and the PDF — naming the key, stating it is still
present, and giving the restart as an instruction rather than a recommendation.

Two details carry the honesty:

* **Recorded on the witnessed effect, not on emission.** If the control arm then
  refuses the finding, the operator's process is altered just the same. A
  disclosure that fires only when we also got a finding out of it is a disclosure
  that serves us.
* **Rendered only when populated.** A section reporting "nothing was left behind"
  on every clean run is one an operator learns to skip — which is exactly the
  state they must not be in on the run where it is populated. Same reasoning as
  the ledger's permanent-benign-alarm rule (invariant 77).
