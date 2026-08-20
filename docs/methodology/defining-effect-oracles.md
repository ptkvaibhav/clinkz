# Three oracles rebuilt on their defining effects

The 2026-08-20 ladder run dispatched 31 never-sent control arms and **10 of them
confirmed** — the same oracle answered yes to a probe with the exploitation
mechanism removed, so `_persist_finding` refused the finding. Six were
`_test_cmdi` (low, medium, high × 2 attempts each) and four were
`_test_file_upload` (low, medium × 2). Every one of those pages *is* vulnerable.

The control was right in all ten. This document is the specification the three
rebuilt oracles were written against, and every number in it is a measurement
taken from the live containers before a line of the fix existed.

The measurement scripts are `.tmpwork/probe_cmdi.py`, `.tmpwork/probe_levels.py`
and `.tmpwork/probe_upload.py` — throwaway drivers, not committed. What they
produced is reproduced below in full, because a specification that cites numbers
nobody can re-derive is the thing this codebase keeps refusing to ship.

---

## 1. `_test_cmdi` — the defining effect is a nonce that only `echo` can place

### What was wrong

The confirming payload on all six killed arms was `test;sleep 5`, confirmed on
`indicator_type=time_delta`. That branch of `_cmdi_phase5_verify` read:

```python
t0 = time.monotonic()
await self._send_probe(page, param, payload)
elapsed = time.monotonic() - t0
if elapsed >= _CMDI_VERIFY_THRESHOLD:      # 4.0, absolute
    return True, ...
```

An **absolute** wall-clock threshold. `original_baseline` is a parameter of the
method and is never read. DVWA's exec page runs `ping -c 4 <ip>`, and `ping -c 4`
takes about four seconds by construction:

```
BASELINE original  (ip=test)          elapsed=  4.04s   len=4632
PAYLOAD  test;sleep 5                 elapsed=  8.99s   len=4632
CONTROL  testsleep 5                  elapsed=  8.00s   len=4632
```

The baseline alone clears the threshold. The oracle would have confirmed command
injection on an untouched request. The control arm — the payload with the
separator removed, so no second command can run — measured 8.00s and confirmed
too, which is precisely the observation the arm exists to make.

**This is not a phantom finding on a clean target. It is a real vulnerability
confirmed by an oracle that was not measuring it.** Both statements have to be
said, because only the first is usually said.

### The defining effect

A value this engine minted appears in the response **in command-output
position**, and can have got there only by the shell running our `echo`.

### The oracle

* Phase 4 synthesises `<original><sep>echo <marker>` where `<marker>` is
  `clinkzcmdi<nonce>`, minted per attempt.
* Phase 5 confirms on `marker in body`, with the existing echo-scaffold guard:
  if the marker is also inside the payload AND the body still shows `echo
  <marker>` (percent- or entity-decoded), the parameter is reflecting, not
  executing, and the answer is no.
* Error responses (5xx, or a recognised shell/stack error body) are rejected
  before any match, unchanged.

### The control

`strip_shell_separators(payload)` — `127.0.0.1;echo clinkzX` becomes
`127.0.0.1echo clinkzX`. Same bytes, same channel, same length class, no second
command. Graded by the same phase-5 call.

### Measured, per level, per separator

Marker present in the response body; CONTROL is the same probe with separators
removed. `clinkzMK991` throughout.

| separator | low | medium | high | impossible |
|---|---|---|---|---|
| `;`      | **yes** | no  | no  | no |
| `&&`     | **yes** | no  | no  | no |
| `\|` (no space) | **yes** | **yes** | **yes** | no |
| `\| ` (space)   | **yes** | **yes** | no  | no |
| newline  | **yes** | **yes** | **yes** | no |
| `&`      | **yes** | **yes** | no  | no |
| **control, every separator, every level** | refused | refused | refused | refused |

Six channels open at low, four at medium, two at high, none at impossible — and
the control refuses on all 24 cells. That is a graded control behaving like a
graded control, which is the inverse of the phantom rule in
[`dvwa-per-level-honesty.md`](dvwa-per-level-honesty.md): a finding that
confirms *identically* at every level is a phantom, and one whose channel count
falls monotonically as the control tightens is a measurement.

The time channel produces the opposite table — 4.0s+ at every level including
`impossible`'s 0.05s only because `impossible` short-circuits — and cannot
discriminate anywhere.

### Consequences for the code

1. `time_delta` may no longer confirm on an absolute threshold. It becomes a
   **paired differential**: baseline and payload interleaved, repeated, and the
   payload must exceed the *baseline* by the injected sleep with the sign
   identical in every repeat. This is the rule
   [`_test_sqli`'s boolean-blind oracle already follows](sqli.md); it is being
   reused, not invented.
2. Phase 3 must **rank the marker channel first when phase 1 has already carried
   a canary through**. Phase 1 on the killed low run recorded
   `('original', 200, 4633)` beside `('canary_semicolon', 200, 4648)` — a 15-byte
   delta that *is* the marker landing in the output. The primitive was
   empirically confirmed in phase 1 and the LLM then ranked `blind_time` first
   and phase 4 built a sleep. CLAUDE.md already states the rule this violates:
   *"the deterministic check GATES the LLM … when phase-2 has empirically
   confirmed the primitive, phase-4 prefers the deterministic build."*

---

## 2. `_test_file_upload` — the defining effect is a value the interpreter COMPUTED

### What was wrong

Phase 5 appends `<?php echo '<canary>'; ?>` to the uploaded content, fetches the
artifact back, and confirms on:

```python
executed = (fetch_resp.status == 200
            and canary in fetched_body
            and "<?php" not in fetched_body
            and "<?=" not in fetched_body)
```

The control uploads the same filename shape with the decoy **as plain text
instead of inside a PHP tag**. That control is not inert: a `.php` file
containing bare text is emitted verbatim by the PHP interpreter. So the decoy
comes back, `<?php` is absent because the control never had a tag, and
`executed` is `True`.

Measured:

```
CONTROL  clinkz_c.php  content='clinkz exec 554*242'
         fetched status=200  body='clinkz exec 554*242'
```

The nonce is in the body. Under the old oracle that is a confirmation. **"The
nonce came back" cannot distinguish an interpreter running our code from a web
server handing back our file**, and the never-sent control is what made that
visible.

### The defining effect

The retrieved artifact contains a value **that does not appear anywhere in the
bytes we uploaded** and that only an interpreter evaluating our code could
produce.

### The oracle

Mint two random 3-digit factors `A`, `B`. Append:

```php
<?php echo 'clinkz'.'exec'.(A*B); ?>
```

Expected indicator: `clinkzexec<A*B>`.

The uploaded bytes contain `clinkz`, `exec`, `A` and `B` as separate tokens and
never the assembled string. Confirmation requires the interpreter to have done
both the multiplication and the concatenation. The parentheses are load-bearing:
`'exec'.554*242` makes PHP read `.554` as a float literal and raises a parse
error — measured, first attempt.

The indicator still matches `is_minted_marker` (`^[A-Za-z0-9_-]*clinkz[A-Za-z0-9_-]*$`),
so the attribution ground in `_control_arm.py` keeps working on it unchanged.

Confirmation is on **retrieval**, never on upload acceptance — that part of the
existing phase 5 was already right and stays.

### The control

The same upload with the same tokens carried as inert text: `clinkz exec A*B`.
Same extension, same store, same fetch-back. The interpreter has nothing to
evaluate, so the literal comes back and the assembled indicator does not.

### Measured, per level

| level | payload | control | verdict |
|---|---|---|---|
| low        | `clinkzexec134068` in body, no source served | body is `clinkz exec 554*242`, indicator **absent** | confirm |
| medium     | `clinkzexec134068` in body, no source served | body is `clinkz exec 554*242`, indicator **absent** | confirm |
| high       | upload rejected | upload rejected | no finding |
| impossible | upload rejected | upload rejected | no finding |

The class is expected to emit at low and medium and to emit nothing at high and
impossible, where DVWA validates the real extension and re-encodes the image.
That is the ladder behaving correctly, not a coverage loss.

---

## 3. `_test_sqli` at high — the oracle is identical and the finding died anyway

The brief asked: *if the high oracle differs, say how; if the same oracle
behaves differently, that is the finding.*

**Neither. The oracle is byte-identical and it worked. The finding was killed by
a dictionary key.**

From the `dvwa/high` trace, both SQLi control arms were dispatched and **refused**:

```
ok  sqli  param='\x00session:id'  disp=True refused=True  satisfied=True
ok  sqli  param='\x00cookie:id'   disp=True refused=True  satisfied=True
```

and then, in the same run:

```
emission_suppressed_deterministic_contradiction:
  SQL Injection in id session value @ .../vulnerabilities/sqli/
  why=never_sent_control_did_not_refuse
  mech=_test_sqli confirms on a marker match and NO never-sent control arm was recorded
```

`_run_control_arm` files the verdict under

```python
self._control_arms[(test_method, endpoint, parameter)] = verdict
```

with `parameter` the **raw injection vector** — `"\x00session:id"`. At high,
DVWA moves the injection behind a session write, so `_sqli_phase6_emit` renames
the vector for the report:

```python
title     = f"SQL Injection in {display_param} session value"
parameter = f"{display_param} (session)"          # "id (session)"
```

and `_make_finding` then looks the arm up under `("_test_sqli", endpoint,
"id (session)")`. Miss. The evidence gets `never_sent_control=absent`, and
ground 8 refuses a finding whose control arm had already refused.

At low and medium the injection is an ordinary query parameter, so the emit name
and the arm name are the same string and the lookup happens to hit. **Low and
medium survive because their parameter has one name; high dies because its
parameter has two.**

This is the codebase's own recurring defect — *a consumer never guesses a
producer's key* — appearing inside the control-arm machinery itself, and it is
strictly worse than a lost finding: `control_required("")` is `False`, so any
emit whose title or parameter drifts from what the arm was filed under **exits
the never-sent-control gate entirely** rather than failing it.

### The fix

Not a normalisation table mapping `"id (session)"` back to `"\x00session:id"` —
that is the same guess written down. The arm is **carried on the candidate**:
`_run_control_arm` returns the verdict, the methodology stores it on the result
model it already threads through phase 6, and `_make_finding` takes it as an
explicit argument. A class that dispatches an arm and forgets to pass it loses
the finding, which is the safe direction and is already the documented
behaviour. The tuple lookup stays as a fallback for the classes not yet
converted, and a lookup that MISSES while an arm exists for the same
`(test_method, endpoint)` under a different parameter is logged and traced as a
mismatch instead of silently reading `absent`.

---

## What this changes about reporting

All three findings above were invisible in the deliverable. The ladder reports
for low, medium and high contain no command-injection finding, no
command-injection lead, and no *"What was NOT tested"* entry for it — because a
phase-5 control kill returns `continue` and writes nothing. Part 1 of this change
makes that impossible: every kill discloses, wherever it happens, and the lead
says the class could not **prove** the vulnerability rather than that the target
is clean.

Those are different claims and only one of them is true.
