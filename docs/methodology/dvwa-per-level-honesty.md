# DVWA per-level honesty (the honesty control)

**A finding that confirms *identically at every security level* — including the
hardened/impossible one — is the signature that the methodology's success-oracle
is matching the app's own benign response, not real exploitation** (LESSONS #27).
Treat **uniform-confirm-across-a-graded-control as a prime phantom signal.** Any
finding at DVWA `impossible` (or any hardened control) is a loophole in the
oracle, not a catch.

Each methodology's emission must be deterministic ground-truth, not LLM prose —
re-validated by re-running the affected methodologies at all four DVWA security
levels.

## The Bucket-A matrix (low/medium/high/impossible)

| level | expected |
|---|---|
| low | genuine finding confirms |
| medium | genuine finding confirms |
| high | confirms only the genuinely-present vector (phantoms stay non-findings) |
| impossible | emits none (N/A by construction) |

The four fixes and their per-class detail:

- **SQLi** — escaping-robust marker-echo guard + `-- -` breakout terminator +
  inline-DB-error union guard. See [sqli](sqli.md).
- **Weak session** — deterministic predictability gate. See
  [weak-session](weak-session.md).
- **CSRF** — rotating-session-bound-token deterministic override + security-
  sensitivity gate. See [csrf](csrf.md).
- **File upload** — acceptance + ground-truth execution + multipart transport fix.
  See [file-upload](file-upload.md).

## Bucket-B DVWA `high` vectors

The `high`-level SQLi and LFI sinks a query-only enumeration missed, unlocked by
two contained methodology fixes (live-validated across all four levels):

- **Cookie injection** (`$_COOKIE['id']`) + **session-indirection**
  (`$_SESSION['id']`) SQLi vectors. See [sqli](sqli.md).
- **LFI `file://` bypass-adaptive** (fi/high's relative-traversal filter). See
  [lfi](lfi.md).

Re-validated on the **real pipeline** (LESSONS #18 — real pipeline, not a
harness), not the keyless harness which pins a silent LLM and only exercises the
deterministic fallback.

## The graded-control-invariance rule (generalised)

**A finding that confirms identically across every level of a security-graded
control is suspect BY CONSTRUCTION, because the control is designed to vary.**
Where a graded control is present, uniform confirmation should suppress + flag
rather than emit.

This generalises the DVWA-specific statement at the top of this file to any app
that exposes a graded control — a difficulty selector, a "strict mode" toggle, a
policy tier. The reasoning is structural, not DVWA-specific: if the app changes
its defence between levels and the oracle's verdict does not change with it, the
oracle is keying on something the defence does not touch — i.e. on the app's own
benign response.

The D1 baseline is the canonical instance. `DOM-based XSS via URL fragment /
location source` confirmed at **low, medium, high, AND impossible** (engagements
`e183af87`, `48e438e3`, `291617a2`, `913fecee`). It had to: the signal was a
static scan of an inline `<script>` block that DVWA ships unchanged at every
level. Uniform confirmation was the diagnosis, arrived at before anyone read the
code.

### The rule inverts for a class whose INPUT the control does not vary

Uniform confirmation is a phantom signal because the control is *designed to
vary* — and it varies the **module code** the exploitation classes attack. It
does not vary Apache's or PHP's response headers. DVWA serves the same `Server`,
the same `X-Powered-By` and the same header names at every level, and
WSTG-CONF-07 is a pure function of that observed set: since the determinism pass,
`_deterministic_security_headers_analysis` is the whole of phase 3 and no LLM is
reachable from it.

So for the header class the same reasoning runs the other way. **Identical input,
deterministic evaluator ⇒ identical output is the requirement, and a divergence
is the defect.** Applying the phantom rule here would be a category error: it
would read the one class that *cannot* honestly vary as the one most in need of
suspicion.

That makes header invariance a **stronger ladder gate than exploitation-set
counts**, and `scripts/dvwa_ladder_run.py` asserts it as the primary one. Counts
move for honest reasons — the crawl surfaces a different endpoint, a level really
does patch a module — so a gate built on them cannot discriminate a regression
from a legitimate difference. A byte-comparison over an input already proven
identical can, which is why the driver reads the observed header set back out of
each run's own trace instead of assuming the premise it rests on.

The two rules divide cleanly, and the dividing line is the class's input:

| class family | does the control vary its input? | uniform across levels means |
|---|---|---|
| exploitation (`_test_sqli`, `_test_lfi`, …) | yes — the module code | **phantom**, until proven otherwise |
| posture (`_test_security_headers`) | no — same server headers | **correct**; divergence is the defect |

### The measured result (2026-08-17, post-determinism)

One batched pass, benchmark profile active, `rc=0` and `admin`'s hash unchanged
at every level.

| level | engagement | runtime | findings | header | exploitation |
|---|---|---|---|---|---|
| low | `cebc9928` | 32.8 min | 22 | 7 | 15 |
| medium | `677cfb44` | 37.2 min | 19 | 7 | 12 |
| high | `3cf06e02` | 31.8 min | 16 | 7 | 9 |
| impossible | `58ca24a3` | 34.1 min | 7 | 7 | **0** |

**Premise, read back from each run's own trace:** the origin root
(`http://172.20.0.3`) served the same 9 headers at all four levels —
`cache-control, content-length, content-type, date, expires, pragma, server,
vary, x-powered-by` — with `Server: Apache/2.4.67 (Debian)` and `X-Powered-By:
PHP/8.5.6`.

**Verdict: IDENTICAL.** The same seven findings at every level, same names, same
missing/weak split, same severity, same count:

```
missing Content-Security-Policy [medium]   missing X-Frame-Options       [medium]
missing Permissions-Policy      [medium]   weak    Server                [medium]
missing Referrer-Policy         [medium]   weak    X-Powered-By          [medium]
missing X-Content-Type-Options  [medium]
```

Two traps this gate walked into, both worth keeping written down because both
produced a *confident wrong number* rather than an error:

1. **A rendered finding carries no `technique`.** The emitter stamps
   `WSTG-CONF-07` internally and `report_<id>.json` does not carry the field, so
   filtering header findings on it scored every level at zero while seven sat in
   the report — and zero-equals-zero satisfies an equality gate perfectly. Key on
   the emitter's own title shape, and make an unrecognised shape loud.
2. **"The observed headers" is not one observation.** Phase 2 runs per page (1–24
   times per run here), so taking the last one makes the premise a function of
   crawl order: low ended on `/setup.php` (9 headers) and high on `/phpinfo.php`
   (10 — phpinfo is chunked, so Apache adds `Transfer-Encoding`). That read as a
   broken premise against a completely consistent target. A header finding is
   addressed to the ORIGIN, so the origin ROOT is the observation it is a
   function of; the per-page sets genuinely do vary (`x-xss-protection` on
   `xss_r`, `content-security-policy` on `csp/`, CORS headers on `api/v1/user/`)
   and rule 4 of the gate is what turns that into an origin-level verdict.

### Why the *suppression* half is documented rather than implemented

Not implemented in `src/` in batch 1. Two structural blockers, both worth stating
plainly rather than papering over with a partial mechanism:

1. **An engagement sees exactly one level.** The graded control is set outside
   the run (for DVWA, a container env var seeding the session's `security`
   cookie), and crawl-safety deliberately refuses to touch it —
   `is_state_changing_url` exists precisely to stop the engine flipping a
   security toggle mid-run. So "confirms identically across every level" is a
   **cross-engagement** predicate; no single run can evaluate it. Making it
   in-engagement would mean re-confirming under a hardened control on a scratch
   session, which is a design pass of its own.
2. **There is no replayable oracle at the emission chokepoint.** `_persist_finding`
   receives a `Finding` — a rendered artifact, not a re-runnable confirmation.
   Suppressing on invariance requires re-running *the methodology's own oracle*
   under the varied control, which needs a per-methodology confirmation-replay
   protocol that does not exist yet. Approximating it by re-matching evidence
   strings would be a new phantom, in the direction that costs genuine findings.

The honest status: **it stays a documented rule and a diagnostic procedure the
operator runs across levels** (compare `outputs/<id>/report_<id>.json` per level;
any exploitation finding present at the hardened level, or present unchanged at
all levels, is a phantom until proven otherwise). A confirmation-replay protocol
is the prerequisite for automating it, and belongs with P7 rather than bolted on.

Worth noting for scope: both instances the rule would have caught in D1 are
killed directly by the batch-1 oracle fixes — the stored-XSS gate ([xss](xss.md)
G1) and the DOM-XSS lead reclassification ([xss](xss.md) G2). The rule earns its
keep as the *detector* that finds the next one, not as a substitute for fixing
the oracle.
