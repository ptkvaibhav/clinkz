# The SQLi context-adaptation ladder — measured, and the decision (gap G5)

The ladder was built in batch 2 on a stated premise. Batch 3 measured it against
the six D1 runs that had been recorded since, and the premise did not hold. This
file is the record, kept because "a ladder that never confirms is worse than no
ladder" is only actionable if the *why* is written down: it burns budget and it
creates the illusion of coverage.

## What was claimed

> Phase-4 synthesis defaults to the quoted string-literal break (`1' AND '1'='1`).
> On a target that escapes quotes, every ranked type sends a variant of the same
> inert shape, so the bare-numeric context is never tried. `_sqli_adapt_context`
> asks that other question.

## What the runs show

Every `context_adaptation` event in the six batch-2 engagement traces, classified
by comparing each rung's own reported true/false/baseline byte counts:

| Run | Level | Rungs fired | Confirmed | Parameters the ladder ran on |
|---|---|---|---|---|
| `783fb78b` | low | 25 | 0 | `page`, `name`, `include`, `txtName`, `mtxMessage` |
| `441c5728` | low | 15 | 0 | `page`, `name`, `include` |
| `df7ce6ee` | low | 10 | 0 | `page`, `name` |
| `fe234e99` | medium | 15 | 0 | `page`, `name`, `username` |
| `8dc7edfe` | high | 20 | 0 | `page`, `name`, `txtName`, `mtxMessage` |
| `82d6052a` | impossible | 25 | 0 | `id` ×2, `token`, `page`, `user_token` |
| **total** | | **110** | **0** | |

**106 of the 110 rungs reported the true-shape and false-shape response bodies
BYTE-IDENTICAL** (`no boolean diff: true=4758 (delta=487) false=4758 (delta=487)`).
The remaining 4 (all at `impossible`) split between a diverged true shape and a
false shape no more divergent than the true one.

That is not "the filter was not defeated". Identical bodies for
`{v} AND 1=1` and `{v} AND 1=2` mean the **truth value of the injected predicate
did not affect the response at all** — the parameter reaches no query. The
parameters confirm it: `page` is DVWA's file-include path, `name` / `txtName` /
`mtxMessage` are reflected text fields, `token` / `user_token` are CSRF tokens.

## Why they got there

Phase-1 candidacy is deliberately loose — *any* status, length, or fingerprint
change from an appended quote. Two shapes slip through and neither is a query:

- **Echo.** `name`: `4767 → 4768 → 4768` bytes across original / single-quote /
  double-quote. The response grew by exactly the one character we added: the field
  reflected our quote.
- **A different sink failing.** `page`: `5236 → 4735 → 4745`. The quote broke the
  *include*, not a query, and DVWA rendered its PHP warning instead of the file.

## Where the SQL confirmations actually came from

Every SQLi finding in every one of the six runs came from phase-4 synthesis or the
session-indirection carrier — never from the ladder:

- **low** — `sqli/` error-based (`1'`), `sqli_blind/` time-blind
  (`1' AND SLEEP(5)-- -`), `brute` `username` error-based (`extractvalue`).
- **medium** — `sqli/` error-based, and `sqli_blind/` **boolean-blind with the
  bare-numeric shape `1 AND 1=1-- -`, synthesised by phase 4 itself.** This is the
  falsification: synthesis reads the primitives (`break_prefix=''`) and picks the
  numeric context without help, so the ladder's numeric rungs are redundant with
  what already ran and failed for other reasons.
- **high** — `SQL Injection in id session value`, via the session-indirection
  carrier.
- **impossible** — none, correctly (PDO parameterised).

## The decision

**The ladder is not the answer to level-specific filters.** Those are answered by
phase-4 synthesis (numeric context at `medium`) and the session-indirection carrier
(`high`), both of which do confirm. The defect the ladder's zero-confirmation record
actually exposes is that its **firing condition was a statement about our payloads**
("every ranked type failed") rather than about the target.

It is kept, not deleted, because "drop the quote" remains a real generic capability
for a target whose synthesis genuinely does default to quotes — but it is now gated,
bounded and instrumented:

1. **Precondition — a demonstrated query context** (`_sqli_ladder_precondition`).
   It fires only when one of three signals is already in hand, so it costs no extra
   request to decide: a **DB error signature** in any phase-1 probe body, a **known
   dialect**, or a **discovered break prefix** (which is itself a boolean
   differential — `_sqli_discover_break_prefix` requires the TRUE and FALSE forms to
   both parse *and* differ). Applied to the runs above, this alone removes the
   `page`, `name`, `include`, `txtName`, `mtxMessage` and `impossible`-`id` rungs —
   85 of the 110 — and keeps the ones on parameters with genuine SQL evidence
   (`brute`'s `username`, and the two token params whose break-prefix probe did
   produce a differential).
2. **Invariance abort.** `_SQLI_LADDER_MAX_INVARIANT_RUNGS = 2`: once two
   consecutive rungs report `response_invariant_to_payload`, the rest cannot
   produce a differential. The live runs re-learned that fact five times per
   parameter.
3. **A deterministic cause per rung.** Each rung traces its payload, its control
   payload, what came back, and a `cause` from the closed
   `_SQLI_BOOLEAN_*` vocabulary the oracle uses — plus a per-parameter
   `context_adaptation_summary` naming the precondition that let it fire, every
   rung's cause, and the abort reason. G5 asked for exactly this: what was
   attempted, what came back, and why it failed.

**The standing commitment.** With the precondition in place, if a later run still
shows the ladder at 0 confirmations, delete it. The instrumentation above is what
makes that judgement possible from a trace instead of from a re-derivation, and the
`context_adaptation_summary` event is where to look.
