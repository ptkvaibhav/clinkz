# D1 Phase 3 — consistency, and the honest per-level baseline

Run with `scripts/d1_consistency_runner.py`. Each run recreates the DVWA
container at the target level (the level is a *container* property — DVWA seeds a
session's `security` cookie from `DEFAULT_SECURITY_LEVEL`, and the engagement
authenticates in its own session, so setting the cookie from a harness would grade
the wrong level silently), resets the data rows via `setup.php`, records `admin`'s
password hash, runs the real end-to-end pipeline, and re-reads the hash.

## The result

| run | engagement | findings | headers | other | leads | admin hash | violations |
|---|---|---|---|---|---|---|---|
| LOW 1 | `f1bb93bc` | 17 | 5 | 12 | 1 | unchanged | 0 |
| LOW 2 | `079c1420` | 18 | 5 | 13 | 1 | unchanged | 0 |
| LOW 3 | `f3109168` | 18 | 5 | 13 | 1 | unchanged | 0 |
| HIGH | `b17ba8cd` | 10 | 5 | 5 | 1 | unchanged | 0 |

**LOW is NOT stable across 3 runs**, so per the batch-4 brief the ladder was
**not** extended to MEDIUM and HIGH — the cause is root-caused below instead.

Every VALIDATION assertion held on every run, asserted from the raw report: no
emitted finding carries a false-positive annotation, no emitted finding's
`Response:` line merely restates its own `rationale=`, every demotion states a
missing observation, and `admin`'s hash is byte-identical before and after.

## Flakiness: 4 entries, of which 2 are real

Keyed on `title @ target`, four entries varied. Two are an artifact of the key:

    Open Redirect … source/low.php?redirect=info.php?id=1   -> runs [3]
    Open Redirect … source/low.php?redirect=info.php?id=2   -> runs [1, 2]

Same handler, same bypass type; the crawl surfaced a different `info.php?id=N`
link. The module fired in **all three** runs. Re-keyed on module + path, the
stable set is 17 and the genuine flakiness is two modules:

| module | endpoint | present in |
|---|---|---|
| `_test_weak_session` | `/vulnerabilities/weak_id/` | run 2 only |
| `_test_sqli` | `/vulnerabilities/brute/` (username) | run 3 only |

## Root cause — one cause, and it is the plan cap

Both come from the same place, and the HIGH run's missing SQLi is the third
instance of it.

The cap fires hard on DVWA at every level: `kept=150`, `dropped=469…498`. Which
150 survive is decided by `_endpoint_class_relevance`, and its **grade 2
("shape-compatible but unremarkable") is a very large tie bucket whose order is
the crawl's own** — and the crawl order varies run to run. Measured:

| class | endpoint | grade |
|---|---|---|
| `_test_weak_session` | `/vulnerabilities/weak_id/` | **2** |
| `_test_weak_session` | `/security.php` (sets no session cookie) | **2** |
| `_test_sqli` | `/vulnerabilities/sqli/` **with** an `id` query param | 0 |
| `_test_sqli` | `/vulnerabilities/sqli/` **without** one | **2** |
| `_test_sqli` | `/vulnerabilities/brute/` (`username`, `password`) | **2** |

So:

- **`weak_id` ties with `security.php`.** `_CLASS_PATH_TOKENS["_test_weak_session"]`
  is `("session", "token", "login", "auth", "cookie", "sid")` and the path
  `/vulnerabilities/weak_id/` matches none of them. The trace shows the
  consequence directly — in runs 1 and 3 the class dispatched only against
  `security.php#`, `setup.php#`, `captcha/#`, each reporting `cookies=[]
  sample_counts=[]`; in run 2 it reached `weak_id` and immediately confirmed
  (`cookies=['dvwaSession'] sample_counts=[8]` → `weak=True` →
  `types=['low_entropy','sequential']`). The oracle is fine. It was never pointed
  at the endpoint.
- **`_test_sqli` has no `_CLASS_PATH_TOKENS` entry at all**, so it grades on the
  parameter predicate alone. At HIGH, DVWA's SQLi page takes its `id` through
  session indirection rather than a query parameter, so the crawl records no
  param, the endpoint grades 2, and `http://…/vulnerabilities/sqli/` appears
  verbatim in that run's `_test_sqli` dropped list. Same story for `brute/`,
  whose `username` is not id-shaped.

### Did the G4 class floor mitigate G7?

**Partially — it fixed the symptom it was built for and left the one that costs
findings.** G7's original shape was a class getting *no* tasks (27 at LOW vs 1 at
MEDIUM/HIGH); no class is starved now. But the floor guarantees a class **a**
task, not a task **on an endpoint where that class can fire**. With ~480 tasks
dropped per run and a grade-2 tie broken by crawl order, whether the one endpoint
that can confirm survives is close to a coin flip:

- `weak_id` reached `_test_weak_session` in **1 of 3** LOW runs,
- `brute/` reached `_test_sqli` in **1 of 3** LOW runs,
- `sqli/` reached `_test_sqli` in **0 of 1** HIGH runs.

The fix is not a bigger cap — it is that grade 2 must stop being where the
answer hides. Concretely: give `_test_weak_session` a signal it can actually rank
on (an endpoint *observed to set a cookie*, which the scan already knows, rather
than a path substring), give `_test_sqli` a path-token entry, and break grade-2
ties on something stable rather than crawl order so a re-run cannot reorder them.
Deliberately **not** done in batch 4: the ranking decides which 150 tasks survive
for *every* class at every level, so it needs its own re-run of the whole ladder
to validate, and shipping it un-revalidated is how a coverage fix becomes a
coverage regression.

## The per-level baseline, honestly

**LOW — 18 findings (best of the three runs), 5 of them posture headers.**
The 13 exploitation findings: SQLi (`sqli/`), SQLi (`sqli_blind/`), Command
Injection, LFI, Reflected XSS, Stored XSS, Unrestricted File Upload (critical),
CSRF ×2, No Brute-Force Protection, Open Redirect, **Client-side security control
bypassed (the G16 forge-and-accept)**, and — in one run each — Weak Session ID and
SQLi on `brute/`.

**HIGH — 10 findings, 5 posture headers, 5 exploitation-shaped, of which 4 are
genuine:** LFI, Reflected XSS, Stored XSS, and Open Redirect (`allowlist_bypass`,
a real 3xx `Location` to `https://evil.example/`). SQLi is absent for the
truncation reason above, not because an oracle failed — G14's evidence is visibly
working in the raw, e.g. `boolean_blind verified=False
cause=response_invariant_to_payload baseline=[5239,5239,5239]B true=[23,23,23]B
false=[23,23,23]B over 3 controlled repeats`.

### The fifth HIGH finding is a phantom (open — G17)

`File Upload Validation Gap (client_side_only)`, medium/confirmed. Its entire
observation is `upload accepted; payload retrievable at …/profile_pic.jpg`, with
`working_extensions: []` — nothing executed. `_file_upload_phase5_verify` returns
`verified=True` on `fetch_resp.status == 200` alone for this branch, commented as
"documentation-grade". That is the upload row's forbidden oracle verbatim — the
honesty table confirms upload on *the stored artifact executing*, **never** on
"merely retrievable" — and the finding's `rationale=` is a conditional execution
claim ("the goal is a stored/reflected XSS via a file that the app treats as an
image"), a shape that can never confirm.

Note the payload was not even the deterministic `clinkz_clientside.html` the
synthesis intends: phase-4 substituted a `.jpg`, so at HIGH this records DVWA's
upload feature *working as designed* as a finding. Left open deliberately —
it is a shared upload-methodology change and the contract requires re-running the
whole upload family across all four levels to validate it.

---

# Batch 5 — the ranking fix, measured

Two LOW ladders were run (N=3 each): one on the first cut of the fix, one after
the four defects that ladder exposed were repaired.

## Ladder A — the first cut

| run | engagement | confirmed | violations |
|---|---|---|---|
| 1 | `890424e8` | 21 | 0 |
| 2 | `255b74aa` | 18 | 1 |
| 3 | `fe1c0b1b` | 19 | 0 |

15 stable, 9 flaky. It exposed four defects **in the fix itself**, all found by
replaying the ranking over the endpoint sets those runs actually produced:

1. **The precondition chosen for the session class is not observable.** Verified
   against the running container: a GET to `/vulnerabilities/weak_id/` returns no
   `Set-Cookie` — DVWA issues `dvwaSession` inside `if REQUEST_METHOD == "POST"`.
   A read-only crawl cannot see a POST-gated issuer, and mapping an application
   must not submit forms to find out.
2. **The parameter vocabulary was never consulted.** `_param_name_tokens` was
   written and not wired in, and the caller lowercased names before tokenising,
   erasing the camelCase boundary (`txtName` → one word `txtname`). The guestbook
   form sorted LAST of its class's ten candidates — a regression against batch 4.
3. **The class floor got stricter, not looser.** Reserving only when the
   deterministic head outranked the LLM's pick meant any grade-0 LLM pick
   satisfied the floor.
4. **A stage that truncated nothing wrote no trace event**, so the harness could
   not tell it from a stage that never ran and fell back to the deterministic
   stage — which drops ~500 candidates by design — reporting one class's ordinary
   tail as a coverage failure. (The single "violation" above is that artifact.)

## Ladder B — after the repairs

| run | engagement | confirmed | admin hash | violations |
|---|---|---|---|---|
| 1 | `01b8e683` | 21 | unchanged | 0 |
| 2 | `43c813ba` | 21 | unchanged | 0 |
| 3 | `f8d9a7bc` | 21 | unchanged | 0 |

**Every exploitation module is now stable across all three runs** — including all
three that batch 4 measured as flaky:

| module | endpoint | batch 4 | ladder B |
|---|---|---|---|
| `_test_weak_session` | `/vulnerabilities/weak_id/` | 1 of 3 | **3 of 3** |
| `_test_sqli` | `/vulnerabilities/brute/` | 1 of 3 | **3 of 3** |
| `_test_xss_stored` | `/vulnerabilities/xss_s/` | 3 of 3 | **3 of 3** |

The 13 stable modules: SQLi (`sqli/`), SQLi (`sqli_blind/`), SQLi (`brute/`),
Command Injection, LFI, Stored XSS, Unrestricted File Upload, CSRF x2,
No Brute-Force Protection, Open Redirect, the G16 forge-and-accept, and Weak
Session ID.

**Zero VALIDATION violations on every run**: no FP-annotated finding, no evidence
restating its own rationale, no `likely` under a confirmed status anywhere, every
demotion naming a deterministic contradiction, `admin`'s hash byte-identical, and
no plan task dropped on a class's own primary target for a class that then
emitted nothing.

Offline replay over all three runs' real endpoint sets: eleven watched classes
rank their own target inside the floor, **identically in every run**.

## Residual flake — LOW is NOT yet stable

Three causes remain, so per the brief the ladder was **not** extended to MEDIUM
and HIGH.

1. **Security-header target (12 of 16 flaky entries; FIXED, not yet re-measured).**
   `_test_security_headers` emits one finding per `(origin, header)` and the first
   URL to reach it wins the dedup — but the finding recorded *that URL* as its
   target. Runs 1 and 3 reached `/` first, run 2 reached `/hackable/uploads/`, so
   the same seven origin-level findings changed address. The target is now the
   origin (the measured page stays in the evidence as provenance). This needs a
   third ladder to confirm.
2. **`Reflected XSS in name parameter` absent in run 2** (present 1 and 3). Not a
   ranking miss — the class was planned and dispatched. Cause not yet isolated;
   it is the next thing to diagnose.
3. **`File Upload Validation Gap (inclusion_chain)` present only in run 2**, on
   the same endpoint whose `Unrestricted File Upload` finding is stable in all
   three. A second upload finding appearing in one run of three; the
   `verified-stored` branch introduced in this batch is the place to look.

---

# Batch 6 — the three residual flakes, and the two the ladder then found

## G20 · the header finding's ADDRESS (closed, then re-opened one level down)

The target is the origin now (`scheme://netloc`, no path/slash/query/fragment,
extracted as `_security_headers_origin` so its determinism is asserted rather
than inferred). The measured page stays in the evidence as `observed_url=`.

Re-measured over three LOW runs: **all seven header findings carry an identical
`(title, target)` in every run.** The 12-of-16 flake is gone.

What the re-measurement then exposed is the same defect one level down: the
address was origin-scoped, the **verdict** was not. DVWA serves a
`Content-Security-Policy` on `/vulnerabilities/csp/` and nowhere else, and
`(origin, header)` dedups on the first page to reach it — so:

| run | first page measured | CSP verdict | rollup |
|---|---|---|---|
| 1 | `/` (`has_csp=False`) | **Missing** | medium |
| 2 | `/vulnerabilities/csp/` (`has_csp=True`) | **Weak** | low |
| 3 | `/` (`has_csp=False`) | **Missing** | medium |

Same origin, same posture, different finding — and a different severity. Rule 4
of the applicability gate now settles it deterministically: a header present on
*this* page but absent from the **origin root** is reported missing for the
origin. That is the mirror of the merge phase 2 already does in the other
direction (a header the root sets covers a deep page), and it is skipped when the
root could not be fetched, because absence of evidence never vetoes.

## G21 · reflected XSS absent in B2 — isolated

Not a ranking miss and not a dispatch miss. All three runs reached phase 5 on the
same parameter with the same measurement (`verified=True strength=verified
context=html_body`, `probed=25 survived=25`); run 2 suppressed **both** of its
tasks at phase 6 on `execution claim is conditional on an unobserved transform
('when' + 'unescape')`. The model wrote a different sentence.

Full write-up → [xss.md](xss.md#a-prose-veto-may-not-overrule-a-measurement-g21-batch-6).

## G22 · the upload family — one rule, not a third patch

Each branch declares its defining effect and the one deterministic observation
that proves it; only branches whose observation this engine can make may confirm.
`inclusion_chain` verified on a bare `status == 200` from a **direct** GET while
claiming a consumer sink composes with the upload — so it emits a lead, as
`client_side_only` already did. And because retrievability is trivially true
whenever real execution would also have worked, the ranking alone decided
CRITICAL-vs-HIGH on one endpoint; the confirmable half now runs first, and a
confirmable branch the model omits is added from the fingerprint.

Full write-up → [file-upload.md](file-upload.md#the-familys-confirmation-model-g22-batch-6).

## G23 · the ladder found one more, same shape as G21

The first LOW ladder on the batch-6 code lost `SQL Injection in username` on
`/vulnerabilities/brute/` in one run of three. Identical phase 1/2/3
(`dialect=mysql`, `ranked=['error_based', …]`); phase-4 synthesis then wrote

    run 1  expected_indicator="XPATH syntax error: '~"      -> verified
    run 2  expected_indicator="XPATH syntax error: '~5.7"   -> no error substring

— a **guessed server version**, against a MariaDB target. The recorded response
(`tool_invocations/00402_http_client.json`) reads `XPATH syntax error:
'~10.11.18-MariaDB-ubu2204'`: the error fired, and only the model's guess made it
invisible.

`_sqli_has_db_error` should have confirmed regardless and could not —
`_DIALECT_ERROR_PATTERNS` had no pattern for the error-FUNCTION channel, which is
how error-based injection actually exfiltrates (`extractvalue()`/`updatexml()`
report inside an XPath complaint; the `floor(rand()*2)` group-by trick inside a
duplicate-key one). The class's own primary channel had no deterministic
signature, so an LLM string was the only oracle. Both are in the table now, with
the two sibling engines' equivalents (Postgres cast-to-int, SQL Server implicit
convert) because the gap was structural rather than MySQL's.

## Phase 3 — the full ladder

Three levels, N=3 each, all nine runs on the same frozen commit. Every number
below is re-derived from the reports themselves, not read off the runner's
summary.

| level | run | engagement | confirmed | leads | admin hash | violations |
|---|---|---|---|---|---|---|
| LOW | 1 | `608de145` | 21 | 0 | unchanged | 0 |
| LOW | 2 | `36aa5d2a` | 21 | 0 | unchanged | 0 |
| LOW | 3 | `5d5727f9` | 21 | 1 | unchanged | 0 |
| MEDIUM | 1 | `e3a7b1bf` | 18 | 1 | unchanged | 0 |
| MEDIUM | 2 | `ac159526` | 18 | 1 | unchanged | 0 |
| MEDIUM | 3 | `8d3c4e31` | 18 | 1 | unchanged | 0 |
| HIGH | 1 | `6a64f2d3` | 14 | 2 | unchanged | 0 |
| HIGH | 2 | `e819a1e4` | 14 | 3 | unchanged | 0 |
| HIGH | 3 | `925007e6` | 14 | 2 | unchanged | 0 |

**STABLE 21 / 18 / 14. FLAKY 0 at every level. VALIDATION violations 0 across
all nine runs.**

### The per-level set, and why it shrinks

| module | LOW | MEDIUM | HIGH |
|---|---|---|---|
| SQLi `sqli/` | yes | yes | yes (session-indirection carrier) |
| SQLi `sqli_blind/` | yes | yes | — |
| SQLi `brute/` | yes | — | — |
| Command Injection | yes | yes | yes |
| LFI | yes | yes | yes |
| Reflected XSS | yes | yes | yes |
| Stored XSS | yes | yes | yes |
| Unrestricted File Upload | yes (critical) | yes (critical) | — (lead) |
| CSRF ×2 | yes | yes | — |
| No Brute-Force Protection | yes | — | — |
| Open Redirect | `direct_redirect` | `protocol_relative` | `allowlist_bypass` |
| Client-side control bypassed | yes | — | — |
| Weak Session ID | yes | yes | yes |
| posture headers | 7 | 7 | 7 |
| **exploitation total** | **14** | **11** | **7** |

The shrink is the honesty control. Each drop matches a control DVWA actually
adds at that level — the brute-force lockout, the CSRF token+referer check, the
hardened JS token, the upload's real-extension and image-dimension validation —
and the open-redirect bypass type changes with the level's filter rather than
staying constant. A set that confirmed identically at every level of a graded
control would be the phantom signature.

**The two batch-4/5 defects are visibly closed at the level that exposed them.**
At HIGH the upload class emits **no finding** and records
`upload_accepted_but_no_restriction_bypass_observed` instead (batch 4 emitted
that same upload point as a confirmed/medium `File Upload Validation Gap
(client_side_only)`), and `SQL Injection in id session value` is present in all
three runs (batch 4's HIGH run had it absent, the G18 ranking miss).

### The RANKING assertion was over-broad (harness, not engine)

HIGH run 2 initially reported three violations:

    RANKING: _test_brute_force        primary target dropped (/vulnerabilities/upload/#)
    RANKING: _test_javascript_attacks primary target dropped (/vulnerabilities/xss_r/#)
    RANKING: _test_csrf               primary target dropped (/vulnerabilities/exec/#)

None of those is that class's target, and the trace shows all three classes were
dispatched to their real ones in the same run (`brute/` with
`login_form_shape: True, path_match: True`; `csrf/#` `state_changing=True`;
`javascript/` `candidate=True`). They emitted nothing because HIGH defends all
three, which is the correct per-level result.

The cause is in `_endpoint_class_relevance`: it returns **grade 0** on
`param_match OR precondition_match`, and `_CLASS_PRECONDITIONS` gives the form
classes the bare precondition `("form",)`. On an application where nearly every
page posts something, grade 0 for those classes means "has a form", not "this
class's surface" — so every form-bearing page in the truncated tail looked like a
dropped primary target. Reporting ordinary tail truncation as an ordering defect
is the same confusion the RANKING check exists to prevent, pointed the other way.

The **harness** is narrowed: for a class whose preconditions include the generic
`form`, a grade-0 drop must also be named by that class's own vocabulary (a path
token or a parameter of its shape, evaluated with the engine's own tables and
predicates). Classes with a specific precondition (`site_root`,
`session_setter`, `file_server_path`, `xml_body`) keep the original stricter
reading. Excused drops are still returned and printed, so nothing is hidden.

**Open — not fixed here.** The underlying imprecision is in the engine: grade 0
should mean the class's own surface, and for the five form classes it does not.
Fixing it changes which 150 of ~620 tasks survive for **every** class at **every**
level, so it invalidates this ladder and needs its own three-level re-run — the
same reason batch 4 deferred the ranking fix and batch 5 had to run three ladders
to land it. It cost no coverage across these nine runs: every affected class
reached its genuine target in every run.
