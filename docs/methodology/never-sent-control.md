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

## The target cannot write the verdict

The control entry is read only out of **fully-structured** evidence entries —
every whitespace-separated token must be `key=value`. `_make_finding` puts the
target's raw response bytes at index 1, ahead of every verdict the engine appends,
so a page echoing `never_sent_control=refused` in its own body would otherwise
license its own phantom. Same rule, and the same reason, as the `strength=` reader.

## Re-grading stored bundles

`scripts/regrade_stored_bundles.py` runs both checks over every stored
`report_<id>.json` offline and sends nothing. Three verdicts:

* `SURVIVES` — attributable, and either the class is not marker-bound or a
  refusing arm is recorded.
* `NO_ARM` — marker-bound, no control was ever run. **The honest terminal verdict
  for a stored bundle**: the arm needs a request that was never sent, and no
  amount of re-reading the artifact can send it. Held apart from both answers,
  because "we did not ask" is not a result in either direction.
* `REFUSED` — self-refuting evidence; it would be rejected at emission today.

The distinction it exists to draw: a finding that was correct **because the target
was genuinely vulnerable**, but which would fail its own control, is a phantom
that landed on a real bug — and by the report alone the two are indistinguishable.
