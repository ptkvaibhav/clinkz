# The OPTIONS probe budget selected by spelling — measured, fixed, and what R1 turned out not to be

**Measured 2026-09-12, tree at `037c59b`, over the 44 real routes of engagement
`e4814440` read back from `clinkz.db`.** Follows
[`options-sweep-measurement.md`](options-sweep-measurement.md) §5, which named the
bound and left the fix open.

**Result: the ordering fix is sufficient and R1 is not load-bearing here. The
`.css` chunks prove it.**

---

## 1 · What the bound did

`learn_allowed_methods` selected `sorted(by_route)[:MAX_OPTIONS_PROBES]` —
lexicographic over the full URL — against 44 routes with a budget of 40.

```
  0  http://127.0.0.1:3100/
  1  …/_next/static/chunks/0.8m7s4-_2v_b.js
 …   (30 more .js and 2 .css chunks)
 32  …/_next/static/chunks/turbopack-06_9ml8svt5e_.js
 33  http://127.0.0.1:3100/api/book/event     ← the booking entry point
 34  http://127.0.0.1:3100/api/logo
 35  http://127.0.0.1:3100/api/trpc           ← the tRPC entry point
 36  …/email-clients/gmail.svg
 …
 43  http://127.0.0.1:3100/site.webmanifest
```

`_` (0x5F) sorts before `a` (0x61), so **32 of the 40 probes (80%) went to
chunks** and the three application routes survived at indices 33–35 — inside the
budget by six slots. cal.com's login page alone references 31 chunks, so a crawl
that had found 41 rather than 32 would have spent the entire budget on bundles
and probed **no application route at all**, and the sweep would have returned the
same clean "this target declares no write verb" it returned here, having asked
nothing that could have said otherwise.

## 2 · The fix: select by relevance, on the vocabulary that already exists

`_select_routes` grades each route with
`_url_shape.crawl_visit_priority` — the same function the crawl enrichment budget
has used since the D1 ordering fix — and ties break on the route string, so the
selected set is a function of the route SET and never of the crawl's emission
order (invariant 53).

Re-run over the same 44 routes:

| | old (lexical) | new (relevance) |
|---|---|---|
| probes spent on chunks | 32 | 30 |
| `/api/*` routes probed | 3, at indices 33–35 | **3, at indices 0–2** |
| routes dropped | `favicon.ico`, `ring.mp3`, `safari-pinned-tab.svg`, `site.webmanifest` | `proton.svg`, `yahoo.svg`, `favicon.ico`, `safari-pinned-tab.svg` |
| would 41 chunks starve the API routes? | **yes, silently** | no |

`crawl_visit_priority` grades the 44 routes `{1: 3, 2: 33, 5: 8}` — the three
`/api/` routes at grade 1 (`is_api_path`), the chunks and root at 2, the CSS/SVG/ICO
at 5. Grade 1 sorts first unconditionally, so **no bundle set of any size can
displace an application route**. That is the property the old bound lacked.

The same treatment went to `learn_body_schema_from_representation`, whose
candidate set is much smaller but whose bound had the identical shape.

## 3 · The bound still bites, and that is now benign

44 routes, 40 probes: 4 are still dropped. They are grade-5 static assets in both
orderings. The budget is unchanged — only the order is — and what changed is
*which* four, from a mix that happened to be harmless to a set that is harmless
**by construction**.

That distinction is why the truncation is now disclosed rather than logged:
`ProbeBudgetTruncation` carries the drop broken down by relevance grade and
separates two facts with different fixes —

* **truncated** — the tail was dropped; a larger budget would probe it;
* **ordering_failure** — a route at a grade the sweep exists to reach was dropped
  while a static asset was probed. A larger budget does not fix that.

Rendered on a clean run too, in Markdown and in the PDF, for the reason every
other bound in `plan_alarms.py` is: a sweep that probed only bundles returns
exactly what a sweep that found no write verb returns.

## 4 · R1 is not what made the chunks candidates

`options-sweep-measurement.md` §2 asked for R1 (`js` absent from
`STATIC_ASSET_EXTENSIONS`) to be fixed first, on the reading that it is "why
chunks are candidates at all". **Measured: it is not, and the control is in the
data.**

Two of the 32 chunk routes are `.css`:

```
…/_next/static/chunks/06mptb6daw5yk.css
…/_next/static/chunks/0m0556th5o~91.css
```

`css` **is** in `STATIC_ASSET_EXTENSIONS` and has been throughout. It reached the
endpoint set anyway and consumed a probe slot anyway, so whatever emitted these
endpoints does not consult that set — and adding `js` to it would not have stopped
the `.js` chunks either. The set's two readers are both in `agents/exploit.py`
(`_applicable_methods_for_endpoint`, `_endpoint_generic_rank`) plus the crawl's
own page filter; none of them is upstream of endpoint candidacy for the sweep.

R1 remains open and remains real — it governs how a `.js` endpoint is *planned*,
which is where its reported 72-task consequence lives — but it is not a
prerequisite for this fix, and taking it blind would have carried the
discovery-starvation risk the register entry flags for no gain here.

## 5 · The guard

`tests/test_agents/test_probe_bounds_select_by_relevance.py`. The domain is
**computed**: every bounded slice in `src/clinkz` whose operand is a `sorted(...)`
call or a local assigned from one — nine sites, read from the AST, because the
bound that matters is the one where *the sort order decides which members
survive*. A grep for `MAX_` finds 79 bounded slices and almost all are byte or
character truncations of an evidence string.

The classification is hand-maintained, one entry per site with a reason, asserted
in both directions. It found one further instance immediately:
`discovery/js_source_ingest.py::_read_files` caps a gray-box source ingest at
2,000 files chosen by filesystem path spelling. Registered as **R10** rather than
fixed here — source-path relevance is a grading function that does not exist yet,
and inventing one would starve the discoverer the write-surface work is currently
blocked on.
