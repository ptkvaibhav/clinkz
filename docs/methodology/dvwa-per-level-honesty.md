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
