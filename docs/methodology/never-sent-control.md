# The never-sent control arm

> **The rule.** No marker-oracle class emits `confirmed` without a **dispatched
> control arm that refused**. Implemented in
> `src/clinkz/agents/_control_arm.py`, enforced at `_persist_finding`.

## Why the rule exists

Ten of the twenty-four dispatchable classes confirm by finding a string in a
response body. That reads as proof only while the string can get there by exactly
one route — the vulnerability. Every phantom this engine has shipped was a second
route the oracle could not see.

Engagement `d67835f5` (2026-08-19, the first run against a real non-benchmark
target) produced **14 phantoms out of 17 findings** from two such routes:

* **SQLi UNION, 7 phantom HIGHs.** Next.js App Router echoes the request's own
  query string into the RSC flight payload
  (`self.__next_f.push([1,"0:{…\"c\":[\"\",\"?name=<value>\"]…"])`), so *any*
  query value comes back and `marker in body` is satisfied by reflection alone.
  The oracle's echo guard (`_marker_only_in_payload_echo`) blanks a **verbatim**
  copy of the payload; the RSC copy is percent-encoded, so the guard misses it.
* **Command injection, 7 phantom HIGHs.** `_UNAME_OUTPUT_RE` is the bare word
  `Linux`, and the target's homepage carries `<span>Linux</span>` as a skill
  badge — present on the clean baseline before anything was injected.

Neither is reachable by making the oracle cleverer: the confounder is a property
of the *target*, not of the payload. The next framework echoes in a different
encoding and the next page contains a different word.

**The three classes that were honest that day were exactly the three that already
run a control arm** — P7 (a nonce minted alongside and injected nowhere, 40 runs,
every one `executed=False` with `control_silent=True`), D8 auth bypass (a
shape-matched contradiction one character apart), and JWT (a broken-signature
token the server must reject). The rule generalises what they do.

## What the control is

**The confirming request with the exploitation primitive removed and the marker
re-minted.** Everything else is identical, and it is graded by the **same** phase-5
oracle — a control judged by a second, more careful comparison proves nothing
about the one that emitted.

Confirmation now requires all three:

1. the confirming arm's oracle says yes;
2. a control arm was **dispatched**;
3. the same oracle **refused** on it.

A control that was not sent is `not_dispatched`, which is not the same as one that
refused. A class that recorded no arm at all gets `never_sent_control=absent`,
which the emission gate refuses — so forgetting costs the finding, which is the
safe direction.

## The control must reflect the way the payload did

The first cut of the arm minted a bare alphanumeric decoy. It is inert, and it
would have passed the portfolio run cleanly.

A bare decoy is **encoding-invariant**: it round-trips byte-identical, so the echo
guard blanks it and the oracle refuses — on the phantom target as readily as on
the real one. A control that round-trips differently from the confirming payload
is graded by a different guard, and then it is not a control over the oracle that
emitted.

So the neutralisation preserves transport shape:

| Class | Primitive removed | What survives |
|---|---|---|
| `_test_sqli` (union) | keywords mangled to same-length non-keywords (`UNION` → `UNIQN`) | every space, quote, comment marker — so the percent-encoding is byte-for-byte the confirming shape |
| `_test_sqli` (error / timing) | keywords **and** break-out punctuation (`'`, `)`, `--`) | an ordinary value that cannot escape its literal |
| `_test_sqli` (boolean / auth) | both arms carry the SAME value | a surviving difference is noise, not a predicate |
| `_test_cmdi` | the separator (`value;echo X` → `valueecho X`); `${IFS}` → a space so the `echo` scaffold survives | the scaffold the reflection guard keys on |
| `_test_ssti` | template delimiters (`#{gadget}` → `#gadget`) | the gadget text, so it reflects identically |
| `_test_lfi` | the traversal — a benign non-traversal filename | the existing evidence control, now **gating** rather than decorating |
| `_test_xxe` | the external-entity declaration | well-formed XML the parser accepts |
| `_test_nosqli` | the operator object → a plain string | the same request shape and code path |
| `_test_xss_*` | XSS-functional characters | an alphanumeric decoy in the same landing position |
| `_test_file_upload` | the `<?php … ?>` tag; same extension | a file the store accepts identically |
| `_test_ssrf` | a non-resolving control host | the cloud-metadata branch now **gates** on it too |

Measured on both real target shapes:

| | confirming arm | control arm | outcome |
|---|---|---|---|
| Next.js RSC | oracle confirms (guard missed the encoded echo) | oracle **also confirms** | arm fails → 7 findings die |
| DVWA verbatim echo | oracle confirms (marker in a data cell) | oracle **refuses** (marker only inside its own echo) | arm satisfied → genuine finding stands |

## Attribution: the second rule in the same module

A confirmation names what it saw. Two ways that name refutes itself, both read
from `key=value` evidence the engine wrote:

* it cites a **command-output channel the payload never invoked** —
  `;echo <canary>` runs `echo`, not `uname`; or
* the methodology **minted a marker for this attempt and the observation does not
  cite it**.

The portfolio run shipped both halves in one evidence list, seven times:
`expected_indicator=clinkzcmdi51696` beside
`indicator_observed=matched uname output: Linux`.

The `id` / `uname` / `ver` branches now require the payload to have invoked that
command. Tightening the regex would only move the next collision: **a channel we
did not ask for is not a channel we can read.**

Descriptive indicators (`"response time >= 5s"`, `"true ≈ baseline AND false ≠
baseline"`) are not minted markers and are out of this rule's scope — there is
nothing to have seen, and those channels carry their own thresholds.

## Why the gate is at `_persist_finding` and not only in the FP cross-check

`_fp_deterministic_contradiction` exists for exactly this, and on the portfolio
run it **never returned an opinion at all**. The reason is worth stating in full,
because it is a third instance of the silent-degradation shape:

1. `_llm_analyze_results` is declared `LLMCallPurpose.SUPPRESS`.
2. Its Anthropic call failed.
3. The Gemini fallback was **correctly refused** — `DecisionPathFallbackError`,
   exactly as `llm/call_purpose.py` requires on a suppress path.
4. The broad `except Exception` around the parse caught the refusal and returned
   `ExploitAnalysis(coverage_summary="Analysis unavailable…")` with an **empty**
   `false_positive_suspects` list.
5. `_mark_false_positive_suspects` saw no suspects, logged
   `"Step 3b: no false-positive suspects to demote"` at INFO, and returned.

So every deterministic ground behind that check went unconsulted, and nothing in
`report.json` says the false-positive pass did not run. The guard was neither dead
nor comparing the wrong fields — **it was not reached**, because it sits
downstream of an LLM naming the finding first. A guard reachable only when a
provider happens to be up is not a guard.

Both new grounds (attribution, control arm) are therefore applied at the emission
chokepoint as well as in the cross-check's list.

## Registry completeness

`MARKER_ORACLE_CLASSES` and `CONTROL_EXEMPT_CLASSES` partition every dispatchable
class. A class in neither is a red build
(`tests/test_agents/test_control_arm_registry.py`), because "nobody classified it"
and "it needs no control" are different facts and only one of them is safe. Every
exemption states its reason.

Exempt classes fall in three groups: those that already run a gating control (P7
classes, JWT, JS attacks, crypto, secrets exposure, input validation, mass
assignment, business logic), those whose oracle is a protocol observation rather
than text (open redirect's 3xx `Location` host resolution, IDOR's boundary
precondition), and those that inject no marker at all (security headers, brute
force, CSRF, weak session).

### An exemption is not an absence, and the row says which rule governs

Being exempt from *this* rule does not mean a class has no control — it means its
control is a **different rule**, and the deliverable has to name that one. The
control-arm section header promises "the row says which rule applies instead" and
19 of 29 rows across the two generated PDFs said only which rule does **not**
govern them. Nineteen verbatim repetitions of an absence invite a client to read
the strongest evidence in the document as unverified.

So every member of `CONTROL_EXEMPT_CLASSES` declares
`VulnClass.control_arm.governing_rule` — what its oracle DOES require before it
may confirm — plus an optional `evidence_key` naming the field in the finding's
own structured evidence that carries the observation the rule turned on.
`control_arm_row` reads the declaration and raises `ControlArmRuleMissingError`
on a row that names none, so the render fails rather than shipping the twentieth
repetition. The domain is COMPUTED from `CONTROL_EXEMPT_CLASSES` and asserted in
both directions (`tests/test_agents/test_report_integrity.py`). Detail →
[`../report-integrity.md`](../report-integrity.md).

## The target cannot write the verdict

The control entry is read only out of **fully-structured** evidence entries —
every whitespace-separated token must be `key=value`. `_make_finding` puts the
target's raw response bytes at index 1, ahead of every verdict the engine appends,
so a page echoing `never_sent_control=refused` in its own body would otherwise
license its own phantom. Same rule, and the same reason, as the `strength=` reader.

## Which arm produced that observation

The rule above is declared per **class**, because "this oracle matches a string
in a body" is a property of a class. One class breaks that: `_test_sqli` confirms
on five channels, and `auth_bypass` is not a marker oracle at all — it is a
three-arm differential in which the tautology must return an auth artifact, a
*shape-matched contradiction one character apart* must NOT, and an ordinary
credential attempt must not either. Both refusing arms are **dispatched**, so the
property this whole rule exists to establish is established by the oracle itself.

The indicator *name* does not carry the fact either. `_test_nosqli` has an
`auth_bypass` channel that compares a probe against a benign baseline with no
shape-matched contradiction at all. Key on the class and you get the SQLi one
wrong; key on the indicator and you get the NoSQL one wrong. So the **producer
declares** it — `VulnClass.control_arm.self_controlled_indicators`, with a reason
the model refuses to construct without — and consumers read the declaration.

Two consumers had it wrong, and both landed on the same finding: the juice-shop
authentication bypass, a CRITICAL whose stored evidence reads

```
probe(tautology): status=200 body_token ... principal=admin@juice-sh.op
  | control(contradiction): status=401 no auth artifact
  | benign: status=401 no auth artifact
```

1. **The re-grade** filed it `NO_ARM` — "the question was never asked" — about a
   finding carrying two dispatched refusals.
2. **`_fp_ground_error_page`** reads evidence for `status=4xx` to catch the
   reflection-in-an-error-page phantom. Those two `401`s are the proof, not the
   phantom. It survived only because `re.search` stopped at the tautology's
   `200` before reaching either one — an ordering, not a rule, and one
   loop-widening from suppressing the class.

The second diagnosis was right and **shallow**. Attributing each status to an arm
fixed the two shapes that provoked it — this bypass, and a confirmed chain's
`decoy_status=403` — and left the real defect standing: the ground was reading
the `Response:` evidence entry, which is where the **host under test's** own
bytes land (the SSRF signature match, the raw-auditable confirming excerpts, JWT
claim names, an open-redirect `Location`). A target serving `status=500`, any of
`_ERROR_BLOCK_MARKERS` (`warning:` and `stack trace` among them), or
`verified=False` suppressed the finding proving its own vulnerability. Moving
every ground to the emission chokepoint made that run on every candidate with no
model in the loop, and the arm-aware reader made it *easier*: it scans every
match per entry where `re.search` stopped at the first.

So the fix went a level down. These grounds read only fields the **engine
declared** — `response_status`, `reflection_in_error_block`, `verified` —
through the fully-structured reader a response body can never satisfy. Same
rule, and the same reason, as `_evidence_strength`: **a suppression primitive
handed to the target is worse than the phantom the guard prevents.**

No producer declares the first two yet, so that ground fires on nothing today.
Measured rather than assumed: it fired **0 times across all 90 stored confirmed
findings**, and the fourteen portfolio phantoms it was written for die on the
never-sent control and the attribution ground instead. Absence of evidence never
grounds a demotion — the rule the character map already follows — so a candidate
whose emitter recorded no status is unknown, not failed. Restoring the coverage
means a producer declaring the field; it does not mean handing the primitive
back.

**The live gate does not relax.** The engine *can* dispatch a never-sent arm for
`auth_bypass` and does (`_sqli_control_confirms` sends the same value down both
arms, so any surviving difference is noise), so `_persist_finding` still demands
one. A stored bundle can dispatch nothing. That asymmetry is the point: demanding
more prospectively is free, and demanding it retrospectively is impossible.

## Re-grading stored bundles

`scripts/regrade_stored_bundles.py` runs both checks over every stored
`report_<id>.json` offline and sends nothing. Three verdicts:

* `SURVIVES` — attributable, and either the class is not marker-bound, the
  channel it confirmed on is declared self-controlled, or a refusing arm is
  recorded.
* `NO_ARM` — marker-bound, and **no control of any kind** was run. **The honest
  terminal verdict for a stored bundle**: the arm needs a request that was never
  sent, and no amount of re-reading the artifact can send it. Held apart from
  both answers, because "we did not ask" is not a result in either direction.
* `REFUSED` — self-refuting evidence; it would be rejected at emission today.

The distinction it exists to draw: a finding that was correct **because the target
was genuinely vulnerable**, but which would fail its own control, is a phantom
that landed on a real bug — and by the report alone the two are indistinguishable.


## Every kill discloses, and the arm's key is declared

Two changes the 2026-08-20 ladder forced, both about what happens AFTER an arm
fires.

**1. A phase-5 kill writes the same lead a `_persist_finding` kill writes.**
The rule had two enforcement sites and one disclosure between them: ground 8 at
the emission chokepoint recorded an `UnprovenExploitLead`, while a phase-5 kill
returned `continue` and wrote nothing at all. Ten arms fired on that ladder and
produced **zero** records — so three DVWA levels carrying genuine command
injection reported silence, which in a pentest report reads as a clean result.

The disclosure now happens inside `_run_control_arm`, at the one seam every arm
passes through, so a class cannot forget it because a class does not do it.
`_control_arm_kills` and `_control_arm_kill_disclosures` make the invariant a
count rather than a convention, and
`tests/test_agents/test_control_arm_kill_discloses.py` asserts they stay equal.

The lead says the class **could not prove** the vulnerability. It does not say
the endpoint is clean, and the tests refuse that wording: an oracle whose control
also confirmed produced no evidence in either direction, and a lead implying
otherwise would be a worse artifact than the silence it replaces.

**2. The arm's lookup key is declared by the emitting site, not re-derived.**
`_run_control_arm` files the verdict under the parameter it DISPATCHED against.
A class that renames its vector for the report then misses its own arm:

* `_test_sqli` at DVWA `high` dispatches against ` session:id` and emits
  `id (session)`. Both arms refused correctly, and both findings were suppressed
  by ground 8 for carrying no arm.
* `_test_file_upload` dispatches against the form's file-field name (`uploaded`)
  and emitted `file`. Found by the mismatch detector below on its first live run.

`_make_finding` takes `control_arm_parameter` so the site that did the renaming —
the only code that knows both halves — declares it. Stripping a `(session)`
suffix here would be the same guess written one layer lower.

A lookup that misses while an arm exists for the same `(test_method, endpoint)`
under a different parameter is logged and traced as `control_arm_key_mismatch`
and still refuses the finding. It never silently promotes the sibling: an arm
dispatched against a different parameter is evidence about that parameter.
