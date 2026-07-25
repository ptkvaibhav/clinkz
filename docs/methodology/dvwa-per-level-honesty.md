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
