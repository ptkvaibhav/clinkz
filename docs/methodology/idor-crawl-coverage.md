# The IDOR crawl gap — diagnosis only

**Status: diagnosed, not fixed.** The four-arm oracle
([idor.md](idor.md)) is necessary and not sufficient: an oracle that cannot be
wrong is worth nothing on an endpoint the plan never held a task for. This file
records what the corpus actually says, so the fix is aimed at the right layer.

Everything here is offline, from `outputs/*/trace.jsonl` and
`outputs/*/tool_invocations/`. Nothing was sent.

## The finding

Across the whole four-level DVWA ladder — engagements `3c47a0de` (low),
`3e73b1fc` (medium), `b25bb25e` (high), `26906e01` (impossible) — the IDOR
bucket of the exploit plan held tasks for **exactly two endpoints, at every
level**:

```
/vulnerabilities/view_source.php
/vulnerabilities/view_source_all.php
```

Both are source viewers. Neither is a record handler. Read together with the
"attack the handler, not the listing" rule, the class was pointed at the one
kind of endpoint it is least able to say anything about.

Per level, from each run's own `plan_coverage` truncation record:

| level | IDOR tasks kept | IDOR candidates dropped by the cap | `authbypass` | `bac` | `api` |
|---|---|---|---|---|---|
| low | 2 | 18 | absent | absent | absent |
| medium | 2 | 19 | absent | absent | **dropped** |
| high | 1 | 18 | absent | absent | absent |
| impossible | 2 | 16 | absent | absent | absent |

"Absent" means absent from the bucket entirely — neither kept nor dropped. The
cap did not truncate them; they were never candidates.

## Which layer lost them

Not the crawl, and this corrects the working hypothesis. The URLs WERE fetched,
dozens of times per level:

| level | requests to those paths | stage |
|---|---|---|
| low | 44 | `utility` only |
| medium | 191 | `utility` only |
| high | 58 | `utility` only |
| impossible | 43 | `utility` only |

Every one at stage `utility` — route discovery and API-schema probing — and
**none at stage `scan`** (the crawl that produces `Endpoint`s) or stage
`exploit` (methodology dispatch). The frontend's own call sites were mined
successfully: `/vulnerabilities/authbypass/authbypass.js`,
`/vulnerabilities/authbypass/get_user_data.php`, `/vulnerabilities/api/v1/user/`,
`/vulnerabilities/api/v2/user/`, `/vulnerabilities/bac/log_viewer.php` and
`/vulnerabilities/api/openapi.yml` all appear. `get_user_data.php` and
`/api/v*/user/` are precisely the record handlers this class exists for.

So the loss is between **discovery and the endpoint set the planner ranks over**,
not at the crawler's frontier. The three candidate seams, in the order worth
checking:

1. `_route_discovery` unions four discoverers into `HTTPScanResult.endpoints`;
   whether a JS-mined call site with no observed parameters survives that union
   is the first question.
2. `crawl_visit_priority` decides which discovered URLs are ENRICHED into
   endpoints within the enrichment budget. A record handler reached only from
   the authenticated index sorts against application pages that were reached
   directly.
3. `_CLASS_PARAM_NAMES` / `_CLASS_PATH_TOKENS` for `_test_idor` decide the
   bucket's ranking once an endpoint exists.

## Why this reads as a clean class today

`class_coverage` gives every dispatchable class one verdict on how far its own
pipeline got. `_test_idor` dispatched, ran phases, and emitted nothing — which
is `correctly_empty`'s shape, and is indistinguishable from "the class ran
against the endpoints that mattered and the target was clean". It is the **ffuf
shape at endpoint granularity**: the component succeeded, a fallback covered,
findings still appeared elsewhere, and no gate fired.

The existing alarm vocabulary does not have a word for it. `kept_by_class`
separates "the cap took every candidate this class had" from "tasks survived and
the class still never ran"; neither says "tasks survived, the class ran, and
every endpoint it ran against was structurally incapable of showing its effect".

## The corpus consequence

271,169 recorded HTTP invocations contain exactly **one** clean per-principal
record read (`/vulnerabilities/sqli/?id=1`, fetched by `_test_sqli`, not by
`_test_idor`). There is no recorded `id=2` peer read anywhere in the corpus.
That is why `tests/fixtures/idor_recorded_records.json` carries one real
rendering and varies its record fields for the peer and owner arms — the bytes
of chrome, token and whitespace are what the target sent, and the corpus simply
does not contain the second read.

## Regression target

Engagement `9317e813` solved `basketAccess` and `forgedFeedback` while emitting
zero IDOR findings **and zero IDOR leads** — the engine read another user's
basket and said nothing in either direction. Its 51 phase-5 verifications all
died on the authz precondition, which the four-arm oracle removes. Those two
challenges are the acceptance test for the oracle half; this file is the other
half, and it is not yet done.
