# Classes whose verdict asks no model

Four methodologies now decide phase 3 with **no LLM call on the verdict path**:
`security_headers`, `csrf`, `weak_session`, `brute_force`. This file records what
each one measured before the call was removed, because the measurements are the
argument — and one of them is a defect, not a tuning nuance.

The rule they all satisfy: **a class whose input is fully observed asks no
model.** If every rule is a pure function of an observation the engine already
made, the model is answering a question the code can answer, and it is a live
surface on which a model change re-baselines the class silently.

Each has a test asserting the model is **not called**, not merely that the
verdict matches. A behavioural test passes just as happily against a version that
consults the model and discards the reply, which is a different property.

```python
assert llm.prompts == []
assert llm.answers, "the scripted answer must still be unconsumed"
```

---

## `security_headers` — the one that proved the class exists

Measured over **1,033 recorded phase-3 calls across 126 engagements**. On a
byte-identical DVWA observation (`server='Apache/2.4.67 (Debian)'`,
`x-powered-by='PHP/8.5.6'`) the same prompt produced the version-disclosure
entries **27%** of the time under `claude-sonnet-5` and **80%** under
`claude-sonnet-4-6`.

Neither number is a security property of the target. A run-to-run coin flip is
bad; a coin flip whose bias moves with a model upgrade **silently re-baselined
the DVWA ladder** and read as a posture regression. `Server` / `X-Powered-By`
were reachable only through that path and account for 78% of every weak-header
mention ever produced; they are deterministic rules now.

The residual is stated rather than absorbed: **129 mentions across 9 header
names** the evaluator has no rule for (`x-xss-protection` 44,
`access-control-allow-origin` 26, `feature-policy` 23, `cache-control` 17,
`x-frame-options` 8, `location` 4, `x-content-type-options` 3,
`permissions-policy` 3, `x-recruiting` 1 — the last two being the model naming
headers off a page rather than evaluating the set).

Full treatment, including why the ladder gate **inverts** for this class →
[`dvwa-per-level-honesty.md`](dvwa-per-level-honesty.md).

## `csrf` — 0 of 227

Everything the verdict needs is observed in phase 2: the token-shaped fields,
their values across three fetches, the `SameSite` directive, and whether a token
survives a cookie-stripped fetch. Every rule is a pure function of those.

The model was asked anyway, with the deterministic classifier kept as a fallback.
Across **227 recorded phase-3 CSRF calls it changed the verdict zero times.**

Free to remove, and not free to keep. The rotating session-bound protection
override still runs first and still short-circuits to `protected` (the DVWA-high
phantom), so genuine protection can never be downgraded into a "missing"
finding — that guarantee predates this change and is unaffected by it.

`_fallback_csrf_analysis` → `_deterministic_csrf_analysis`. The `form` argument
went with the LLM prompt that was the only thing reading it.

## `weak_session` — 0, and the model's prose was in the evidence

The emission decision was **already** deterministic: only a ground-truth signal
from `_deterministic_session_weaknesses` — an integer sequence, a timestamp
correlation, a cracked md5/sha1/sha256 preimage, or measured low entropy — could
mark a session weak. That is what stops LLM prose labelling a high-entropy
`bin2hex(random_bytes(20))` token predictable, and what keeps a missing
`SameSite` from driving a HIGH "weak session ID".

What the model still did was write an *advisory rationale*, appended to
`result.rationale` — and `_weak_session_phase4_emit` copies that string verbatim
into the finding's `evidence` list.

**Model prose sitting in an evidence field, beside measurements, is a claim
nobody made.** It changed the verdict zero times, so the call bought nothing and
carried a fabrication surface into the deliverable. Removed rather than filtered:
an advisory that may not be quoted has no consumer.

The cookie name and flags were prompt inputs only. They are still recorded on the
result and in the trace by the caller.

## `brute_force` — 3 of 296, and all three were fabricated ordinals

This one is not a determinism nuance.

The model ran alongside the classifier under a one-way rule — it could **add** a
protection the deterministic pass missed, never clear one it found. That reads as
conservative. What it actually bought, per the recorded traces: **3 overrides in
296 calls**, and every one of the three was the model writing an
`observed_at_attempt` of its own — **5, 4 and 6** — against **138** values the
engine derived from a real observation.

`observed_at_attempt` is the ordinal of the request where a control appeared. It
is carried on the result, written into the phase-3 trace, and read by an operator
as a measurement. Every deterministic branch takes it from `o.attempt` of an
observation the engine actually made:

```python
return (BruteForceProtectionType.RATE_LIMIT, True, o.attempt, ...)
```

The model had no such constraint. It was handed eight observation dicts and asked
to name a number, and **nothing downstream checked that the number corresponded
to anything.** That is a fabrication surface in evidence. Three findings were
suppressed on it.

The review allowed either remedy — derive the field from observed responses, or
remove it from evidence entirely. Removing the call satisfies the first: the only
writer left is the deterministic classifier, and it can only quote an attempt
that happened. `test_every_reported_ordinal_is_an_observed_attempt` pins it
across the rate-limit, captcha, lockout and inconclusive branches.

### The residual, stated

The classifier's vocabulary is now the whole vocabulary: rate-limit signals (429
/ `Retry-After` / `X-RateLimit-*`), captcha and lockout body markers, the
positive control, a constant per-attempt penalty and a progressive one.

A brute-force control outside that set is a **recall loss** — this class will
report `none` where a human would recognise a throttle we have no rule for. The
fix is a new rule, tested, not a model improvising one and suppressing a finding
on an ordinal it authored. `test_model_can_no_longer_add_a_protection_it_alone_saw`
pins the trade so it stays a decision rather than an accident.

## `js_attacks` — 5 of 57, and why that number is not the reason

The model flipped the classification on **5 of 57** recorded calls. None of those
five could reach a finding, and the reason is worth recording so nobody re-reads
the number as consequential:

* **`severity` is discarded on the only path that emits.** A finding exists
  solely when `forge_confirmed` is true, and the caller overwrites the severity
  with `high` at that moment. The model's `low`/`medium`/`high` never reaches a
  deliverable.
* **`should_attempt_bypass` gates nothing.** The confirmation attempt is driven
  deterministically (a JS-controlled hidden field on a POST form). The model's
  opinion is recorded in the trace and read by no branch — that was already
  deliberate, after engagement `1f9a0932` emitted a mechanism description having
  never submitted anything.
* **`rationale` is preserved as a *prediction*** and reconciled against what the
  confirmation then did (`_js_attacks_reconciled_rationale`).

What was live: the model could return `none`, and the caller **skips a form whose
pattern is `NONE`**. That is a suppression path decided by a checkpoint whose
other three outputs are inert, and it is the reason this class inverts rather
than being left alone. The deterministic classifier cannot return `NONE` at that
point — the caller has already returned early unless there is a controlled field
or a validation hit.

The docstring on `_js_attacks_phase3_analyze` carries this, so the 5/57 is not
re-litigated.

## What this does NOT change

The other twenty methodology checkpoints still consult a model, through
`_llm_analyze`, and should: payload synthesis, encoding/bypass selection and
character probing are not pure functions of an observation. That funnel is pinned
to Anthropic with **no fallback tail** (`_build_methodology_llm` uses
`override_chain=["anthropic"]`) and declared `EMIT` in
`llm/call_purpose.py`, so a provider the engagement did not choose can never
serve one. See [`../provider-routing.md`](../provider-routing.md) §4.

The emission rule is unchanged in every class: **the deterministic check gates
the LLM**, and no LLM verdict emits on its own.
