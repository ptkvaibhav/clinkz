# Client-side security logic (WSTG-CLNT-11) — `_test_javascript_attacks`

## The defining effect

A page that computes a security token in JavaScript is telling us its check runs
where the attacker lives. That statement is **reachability**. The *effect* is:

> the server **ACCEPTS** a value we rebuilt by replaying the page's own
> client-side algorithm, while **REJECTING** an equal-shaped value that algorithm
> never produces.

Describing the mechanism confirms nothing. Until the forgery is submitted and
accepted, the observation is an `UnprovenExploitLead`
(`why_unconfirmed="client_side_control_described_server_acceptance_not_witnessed"`),
never a finding.

## The phantom this replaced (G16)

Engagement `1f9a0932` (DVWA low) emitted **`JavaScript-controlled hidden field(s)
token`**, medium/confirmed, `phases_completed=4`, whose entire evidence was:

```
Request:  POST form at …/vulnerabilities/javascript/ contains hidden field(s)
          populated by client-side JavaScript
Response: Form fields: ['token', 'phrase', 'send']. Rationale: The hidden field
          'token' is populated by client-side JS using md5(rot13(phrase)), …
rationale=The hidden field 'token' is populated by client-side JS using
          md5(rot13(phrase)), …
```

Nothing was ever submitted. `bypass_attempted` is absent from that evidence
because the attempt was gated on the LLM's `should_attempt_bypass`, and the model
said no — the old `_attempt_js_bypass` only fired for a **string-literal** write,
and `md5(rot13(phrase))` is a function call. So the methodology's only reachable
outcome on a real computed token was a mechanism description.

Two things were wrong and both are fixed:

1. **The attempt was the LLM's call.** It is now driven **deterministically** —
   the confirmation runs whenever the chain is replayable over a POST form.
   `should_attempt_bypass` is recorded in the trace as advisory and gates nothing.
2. **The mechanism description could emit.** Phase 4 now raises unless
   `forge_confirmed`; the caller records a lead instead.

`1f9a0932` **predates** the emission-chokepoint ground (`c2f64ac`, 64 minutes
later), and replaying that finding's exact evidence through today's
`_fp_ground_observation_is_rationale` returns the mechanism string — so the
chokepoint already demoted this shape. The chokepoint is a *net*, though: it
catches the candidate by the shape of its prose. This class now fails to produce
the candidate at all, which is the fix at the level the defect lives.

## The oracle: a four-arm interleaved differential

    control(nonce₁) → forged → control(nonce₂) → forged

Confirmation requires **all three**:

| requirement | what it rules out |
|---|---|
| `control_stable` — the two controls returned the same page | per-request chrome (a rotating CSRF token, a timestamp) masquerading as a differential |
| `forged_stable` — the two forged arms returned the same page | a one-off difference that does not reproduce |
| forged ≠ control | the server ignoring the field entirely |

Every value **we** submitted is blanked out of each body before comparing, so an
app that merely echoes the token back cannot manufacture a difference.

`_js_control_value` draws the control at the **same length and character class**
as the forged value (`_js_control_alphabet` keeps hex case, because an
uppercase-hex digest and a lowercase-hex digest are different *shapes*). That is
what licenses the attribution: the arms differ in exactly one respect — whether
the value is the one the page's algorithm computes — so a divergence is the
server acting on a value it validated.

**Nothing keys on a success vocabulary.** "Well done" is pleasant to find in the
excerpt and proves nothing: a phrase the app also emits on its benign path would
confirm every time. The old `_attempt_js_bypass` matched against a fixed marker
list with **no control arm at all**; it is deleted, not kept alongside.

## Replaying the chain: a bounded grammar, not an interpreter

`_JSValueParser` accepts only: string literals, form-field reads
(`document.getElementById('x').value`, `x.value`), `+` concatenation,
single-argument calls to the **standard** transforms in `_JS_TRANSFORMS` (md5,
sha1, sha256, sha512, rot13, btoa, atob, encodeURIComponent, encodeURI, escape),
and zero-argument string methods (toUpperCase, toLowerCase, trim).
`_js_resolve_names` walks a local variable back to the field it reads, bounded by
`_JS_MAX_VAR_HOPS`.

Everything else — `Date.now()`, `Math.random()`, arithmetic, a page-defined
helper whose body we never saw — is a **parse failure**, which means no forgery,
which means a lead. That is the N/A-by-construction boundary, and it is where the
class stops rather than where it guesses.

Naming md5/rot13/btoa is not a hardcoded target value. The *composition*, the
*field it reads*, and the *input values* are all read off the live page.

A target-authored literal can also be undecodable (`"\xZZ"` is a truncated escape
a browser tolerates and `unicode_escape` rejects). `_js_decode_string_literal`
converts that to `_JSParseError` — a page we cannot decode is an expression we
cannot replay, not an exception the methodology dies on.

## Finding the isolating input

An app may gate on the **input** before it ever looks at the token. DVWA's
javascript module checks the phrase first, so with the form's own default
(`ChangeMe`) both arms return *"You got the phrase wrong."* and the token check
is invisible. The isolating input has to be searched for, and its candidates
discovered from the app itself:

1. the field's own declared default,
2. literals the page's client-side JS compares a `.value` against — exactly the
   values the app considers valid,
3. quoted words in the page's **visible** text (an app expecting a specific word
   tends to name it in the instructions).

Bounded by `_JS_MAX_ISOLATING_CANDIDATES` (6) and `_JS_MAX_FORGE_FIELDS` (3).
A wrong candidate simply produces no differential, and **each candidate is tested
against its own control**, so the search cannot manufacture a confirmation — it
can only reveal one that was already there.

On DVWA low the candidates come out as `['ChangeMe', 'success']`; `ChangeMe`
yields no differential and `success` yields one. No DVWA string is in the code.

## Live validation

`scripts/live_js_forge_confirmation_validation.py` drives the real methodology
against the running DVWA at every level.

| level | outcome | why |
|---|---|---|
| low | **1 confirmed finding**, high | inline `generate_token()`; chain `md5(rot13(<field:phrase>))` replayed, isolating input `success` discovered, control → *"Invalid token."*, forged → *"Well done!"*, both arms stable |
| medium | 0 findings, 0 leads | the token JS is an **external** file, so phase 2 collects no inline JS write — N/A by construction |
| high | 0 findings, 0 leads | same |

The confirmed finding's `Response:` line carries measurements
(`control_stable`/`forged_stable` plus the divergence excerpt), so
`_fp_ground_observation_is_rationale` does **not** fire on it — held by a
regression test, since that is precisely the ground the old shape tripped.

## The rationale must reflect the outcome reached (G19, batch 5)

The emitted forged-token finding carried
`rationale="Hidden field(s) ['token'] populated by client-side JS. Bypass not
feasible — non-literal write."` while its own evidence read
`forge_confirmed=True`.

Both statements were produced honestly, in this order: phase 3's classifier
*predicts* feasibility from the shape of the JS write, and the deterministic
confirmation then runs **without consulting that prediction** (that independence
is the G16/#39 fix — whether the confirming attempt runs is never the LLM's
call). So a prediction the attempt falsified was left standing as the finding's
stated reasoning, which is the self-inconsistent-evidence shape the FP detector
hunts for.

`_js_attacks_reconciled_rationale` now composes both halves explicitly —
`Classifier prediction: … Outcome: …` — with the last word belonging to the
deterministic arm, in all three outcomes (accepted / attempted-and-rejected /
not attempted). The prediction is preserved rather than overwritten: it is part
of the audit trail, it just no longer reads as the conclusion.
