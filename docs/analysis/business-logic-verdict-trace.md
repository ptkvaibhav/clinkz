# The three business-logic classes, traced to where they stop

**Measurement only, 2026-09-12, tree at `037c59b`.** Answers R9's open question:
*85 dispatches, 0 findings, 0 leads — report where one of them stopped, traced
end to end.*

**Answer: R9's premise is wrong in two places, and the corrected picture is a
narrower and sharper defect.**

1. One of the three classes — `_test_constraint_violation` — **does** reach a
   verdict, 18 times, and **does** emit leads. R9 said none of them had ever
   reached a verdict of any kind; that is false for this class and the leads are
   in the stored bundles.
2. The other two abstain at phase 1 on **every** dispatch, and the cause is not
   the `("form",)` precondition R9 guessed at. It is that the endpoints they are
   correctly dispatched against **have no collection representation to read**,
   and phase 1 has no second evidence source available to it at that point.

---

## 1 · The measurement, from `trace.jsonl` across every stored bundle

`_business_logic_intent` writes a phase-1 event on every dispatch and
`_emit_business_logic` writes a phase-5 event on every verdict, so the ratio
between them is the abstention rate, directly, without inference.

| skill | phase-1 events | phase-5 verdicts | reaches a verdict |
|---|---|---|---|
| `business_logic_single_use_action` | 102 | **0** | never |
| `business_logic_ordering_constraint` | 62 | **0** | never |
| `business_logic_quantity_bound` | 50 | **18** | 36% of dispatches |

(214 phase-1 events, against R9's 85 — R9 counted the 35 bundles carrying a
methodology ledger; every bundle with a trace carries these events.)

`quantity_bound` is not a dead instrument. Its 18 verdicts are all
`confirmed=False, why_unconfirmed="violating_value_refused"` on Juice Shop —
**the target enforced the bound its own records implied**, which is the correct
negative and the strongest thing a black-box oracle can say short of a finding.
Each one produced an `unproven_leads` entry; R9 reported zero because it matched
the class's registry `title_tokens` against a field that does not carry them.

Verbatim, from `20fad9dc`:

```json
{"claim": "Candidate Business logic — numeric constraint violation: quantity persists 0",
 "why_unconfirmed": "not_instrumentable", "technique": "WSTG-BUSL-03",
 "endpoint": "http://clinkz-juiceshop:3000/api/BasketItems", "parameter": "quantity",
 "missing_observation": "the application refused 'quantity'='0', so it enforces the bound its own records imply"}
```

---

## 2 · One dispatch of `_test_repeatability`, traced end to end

Engagement `47c9bd5c`, Juice Shop, `POST /rest/basket/:p3/checkout` — one of 41
single-use dispatches that read zero records.

| step | code | what happened |
|---|---|---|
| 1 | `exploit.py:33572` | `_business_logic_intent(page, SINGLE_USE_ACTION)` |
| 2 | `exploit.py:33372` | `_collection_url(page.url)` → the collection for `/rest/basket/:p3/checkout` |
| 3 | `exploit.py:33373` | `_observed_records(collection)` → **`[]` — 0 records** |
| 4 | `_business_logic.py:211` | `infer_intent(entity="checkout", representation=[], routes=[...], rejections=[])` → **0 assertions** |
| 5 | `exploit.py:33382` | phase-1 trace event written: `records=0 evidenced_single_use_action=0` |
| 6 | `exploit.py:33396` | `matching` empty → returns `(None, [])` |
| 7 | **`exploit.py:33573-33574`** | **`if intent is None: return []`** |

**It stopped at step 7.** No probe was sent, no control arm was dispatched, no
phase-5 verdict was written, and `_emit_business_logic` — the only code that
records a lead for these classes — was never reached. That is why 0 leads, and
why the lead path is not at fault: the class abstains *upstream* of it.

The same seven steps, same result, on all 41. `records_observed` is **0 on every
single one**:

| skill (Juice Shop only) | `records=0` | `records>0` |
|---|---|---|
| `single_use_action` | 41 | 1 |
| `ordering_constraint` | 23 | 0 |
| `quantity_bound` | 2 | 38 |

The one dispatch that DID read a record is its own small confirmation of the
mechanism: `/rest/image-captcha/:id` returned `records=1` and still produced
`evidenced_single_use_action=0`, because one record carrying no consumption-marker
field name evidences nothing. The gate is the evidence, not the fetch.

---

## 3 · Why the records are empty, and why it is not the endpoint allocation

The obvious hypothesis is that these two classes are dispatched against the wrong
endpoints. **They are not.** The allocation is good:

```
single_use_action     /rest/basket/:p3/checkout, /rest/user/erasure-request,
                      /rest/user/data-export, /rest/repeat-notification,
                      /rest/continue-code/apply/:id, /rest/user/reset-password
ordering_constraint   /rest/basket/:p3/checkout, /rest/order-history/:p3/delivery-status,
                      /rest/user/erasure-request, /rest/continue-code/apply/:p4
quantity_bound        /api/BasketItems, /api/Products/:p3, /api/Cards,
                      /api/Feedbacks, /rest/wallet/balance, /api/Quantitys/:p3
```

Those are exactly the right targets for each facet. A checkout *is* single-use; a
delivery status *is* ordering-constrained.

The difference is what those endpoints **are**. `quantity_bound`'s are REST
**collections** — `GET /api/BasketItems` returns records, so
`_observed_records` gets 5 and `infer_intent` can read a numeric range out of
them. The other two classes' are RPC-style **action** endpoints. There is no
collection behind `/rest/basket/:id/checkout`; a GET of it returns no records,
and no amount of correct dispatch changes that.

### The circularity

`infer_intent` evidences these two facets from either of two sources:

* a **representation** — a state field carrying both an initial and a terminal
  value (ordering), or a consumption-marker field name (single-use);
* a **rejection** — the application's own refusal wording, from
  `self._business_logic_rejections`.

On an action endpoint the first is structurally unavailable. And the second is
filled by `_remember_rejection`, which these three classes call **at phase 3**,
after the malformed control goes out — *downstream of the phase-1 gate they never
pass*. So on an action endpoint both sources are empty by construction, and the
abstention is unconditional rather than target-dependent. The evidence the class
needs is a by-product of probes the class never gets to send.

That is a real design gap and it is **not** the write-surface blocker: these
classes were dispatched against write endpoints, repeatedly, on a target that
has them.

---

## 4 · What this decides for the disclosure

Both `_test_repeatability` and `_test_state_sequence` declare
`capability=SERVER_SIDE`, whose contract is *"the defining effect is observable in
a server response, so a finding here is confirmable in-band."* Across 164
dispatches neither has reached a verdict of any kind, so that claim has never
been exercised. It is not false — the oracle is written and would confirm — but
the report renders `capability` as a statement about what the engine **can
prove**, and an unexercised oracle is not a demonstrated one.

`_test_constraint_violation` keeps `SERVER_SIDE` on the evidence: 18 verdicts,
leads emitted, the read-back oracle doing exactly what its `limitation` says.

The registered fix is therefore per-class and not per-family, which R9 could not
have known. It is R11, and its cause is R13.

**Landed in this round:** the abstention itself is now declared. All three classes
call `_record_intent_abstention` at the phase-1 gate, writing an
`InconclusiveMeasurement` that the report renders under
`MEASUREMENT_INCONCLUSIVE` — so a run in which these classes could not begin no
longer produces the artifact that silence produces. The `capability` declaration
stays as it is until the cause (R13) is fixed; a downgrade shipped first would be
reverted by the round that fixes it, and the disclosure is the half a client
reads.

## 5 · A second finding, worth its own entry

Every business-logic non-confirmation is filed under
`why_unconfirmed="not_instrumentable"`, and the 18 `quantity_bound` verdicts show
why that is wrong. `violating_value_refused` means **the application enforced its
own constraint** — the engine measured a control working. Filing that as a
"Candidate Business logic — numeric constraint violation" lead under
"not instrumentable" reports a correct negative as an unresolved suspicion, on
every well-built endpoint the class ever meets. That is the permanent-false-alarm
shape invariant 77 exists for, at the lead layer rather than the alarm layer.
Registered as R12.
