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
