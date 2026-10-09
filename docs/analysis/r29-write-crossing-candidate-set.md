# R29 — why `/api/Complaints` left the write-crossing plan, and the set check

**State: CLOSED by this change.** Register entry R29 (opened 2026-10-09 by the
docs truth pass, PR #148) recorded that the engine's only confirmed
cross-principal write, `/api/Complaints` on `f6ff1381`, was not dispatched on the
#145 ride-along `d29c80ee`, and left the cause undetermined between (a) the verb
was not read and (b) discovery never produced the write. **Neither.** Traced
producer by producer from the two stored bundles; no live run.

## 1. Producer by producer

| stage | `f6ff1381` (baseline, 2026-09-21) | `d29c80ee` (#145 ride-along, 2026-10-05) |
|---|---|---|
| discovered (`endpoints` table) | `POST /api/Complaints`, params `UserId, message, file`, all `json_body` | identical |
| verb read (`method_evidence`) | `unread` | **`named`**, better than the baseline |
| routed to `_test_write_crossing` | yes (pre-#145 routing did not consult the evidence) | yes (`_is_observed_write_surface`: NAMED + POST) |
| deterministic pass (cap 8 per class) | **dropped**, one of 20 | **dropped**, the same 20 |
| union pass, from the LLM planner | **added** (with `/api/Feedbacks`) | not added |
| dispatched / confirmed | yes / **confirmed** via `UserId` | no |

Union arithmetic, from the trace's `plan_coverage` records: in both runs the
deterministic pass kept 8 write-crossing tasks. The union then dropped 4 of
those 8 on the baseline while keeping 6, so **2 came from the LLM plan**. On the
ride-along it dropped 3 and kept 5, so **none came from the LLM plan**. The
dispatched hypotheses confirm it: the baseline's extra two are Complaints and
Feedbacks.

## 2. The stage and the commit

**The stage is the deterministic ranking.** The commit that exposed it is
`b9a853f` (PR #145, merge `d6c5c85`). That change resolves effort per call purpose,
so the planner went from `effort: high` (20,245 output tokens, 155 s) to
`effort: low` (7,113 tokens, 43 s). The R29 table's "effort `low`" describes the
ride-along only: every call in the baseline ran at `high`. The high-effort planner
named Complaints and the low-effort planner did not.

So #145 caused the loss, but the baseline's confirmation already rested on LLM
recall. Invariant 49 says a deterministic observation gates the LLM's list, and
here the deterministic pass had dropped the endpoint in **both** runs:

```
0 (0,-3) POST /api/Users          param=T  (username, email)
1 (0,-3) POST /rest/user/login    param=T  (email)
2 (0,-2) POST /api/Addresss       param=F  ← carries UserId
3 (0,-2) POST /api/BasketItems    param=F
4 (0,-2) POST /api/Cards          param=F  ← carries UserId
5 (0,-2) POST /rest/2fa/setup     param=T  (setupToken)
6 (0,-2) POST /rest/2fa/verify    param=T  (tmpToken)
7 (0,-2) POST /rest/user/data-export
-- cap 8 --
17 (0,-1) POST /api/Complaints    param=F  ← carries UserId
18 (0,-1) POST /api/Feedbacks     param=F  ← carries UserId
```

The class's parameter signal was `_STATE_CHANGE_PARAM_NAMES`, borrowed from
mass assignment. That is a CSRF vocabulary (`token`, `password_new`, `email`),
and no owned object carries those fields. It rewarded the 2FA endpoints. The
four endpoints whose body names an owner (`UserId`, the field the methodology
anchors and attributes through) scored nothing.

**Was this a capability regression? Yes.** A confirmation the engine had made
could no longer be reached under the profile #145 made the default. It is fixed
here, before anything else.

## 3. The fix

`_test_write_crossing`'s parameter signal is now the methodology's own
owning-field vocabulary. `_idor_oracle.field_names_owner` is the public face of
the predicate `owning_fields` selects with, registered in
`_CLASS_PARAM_PREDICATE_NAMES`. There is one vocabulary for one question. Replayed
over the ride-along's stored endpoints, Complaints moves from 18th to **6th** of 36,
and all four `UserId` writes are inside the cap. Pinned by
`tests/test_agents/test_write_crossing_ranking.py` over the recorded 36-row
slice. With the old vocabulary restored, three of its four tests fail.

**Residual, named:** Complaints and Feedbacks tie at evidence 2 with nine
endpoints that score only on the path signal (`BasketItems`, `user/data-export`,
…). They lead those nine because `api/` sorts before `rest/`. The order is
deterministic (invariant 53), but the tiebreak is spelling (invariant 106). The
global fix would rank observed signals (param, precondition) ahead of the path
signal, which is how the grade already defines them. It changes every class's
order, so it is a separate, measured change.

## 4. The guard: compare SETS, not counts

`kept_by_class` 6 → 5 passed review because it is a count. The new check is over
members:

* **Producer.** `ExploitAgent._trace_plan_sets` records the final dispatched
  plan, after every merge, and every `(class, endpoint)` the deterministic pass
  bucketed before any cap (`plan_coverage` / `plan_sets`).
  `_trace_confirmed_finding` attributes each persisted confirmed finding to its
  task (`plan_coverage` / `confirmed_finding`). Existing consumers filter on
  `phase_name == "truncation"`, so they never see these records.
* **Consumer.** `observability/candidate_regression.py`: for every pair the
  baseline confirmed, the later run must have **planned** it. A lost pair is
  named as `truncated` (it was a candidate and a cap removed it, as here) or
  `absent` (it was never a candidate). Those have different fixes.
* **Driver.** `scripts/candidate_set_regression.py <baseline> <later>` exits 0
  on a pass, 1 on a REGRESSION and 2 when NOT DETERMINED.

The two R29 bundles predate the records and return **NOT DETERMINED** (exit 2),
not a pass: a trace that carries only counts cannot answer a set question.
Planned-but-not-confirmed passes, because the check covers whether the engine
reached the pair. Whether the oracle fires again is the oracle's business.
