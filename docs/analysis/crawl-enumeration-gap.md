# The crawl enumeration gap — diagnosis only

> Not fixed. This file records what was measured and where the mechanism is, so
> the fix is designed against numbers rather than against an impression.

## The claim, and what it turned out to be

The observation that started this: engagement `d67835f5` reported *"Scope control
held: 75 refusals / 18 distinct URLs across nextjs.org, www.w3.org, github.com;
nothing sent"* — while `https://www.linkedin.com/in/ptkvaibhav/` is a real
`<a href>` on the page and appears **nowhere** in the refusal log, and 14 of 15
distinct github.com hrefs likewise.

The refusal log is **what was reached for, not a census**. That is now measured.

## Reproduced offline from the stored bundle

`outputs/d67835f5-…/tool_invocations/00039_katana.json` holds katana's real
stdout. Replaying the scan agent's own filters over it:

| stage | count |
|---|---|
| URLs katana emitted | **3,070** |
| after dedup + `is_state_changing_url` | **212** candidates |
| opened by endpoint enrichment (`max_visits = 80`) | **80** |
| never enqueued | **132 (62%)** |

Host distribution of the 80 opened — `ptkvaibhav.vercel.app` 63, `nextjs.org` 9,
`www.w3.org` 5, `github.com` 3 — reproduces the refusal log's distinct-URL
distribution exactly.

`https://github.com/ptkvaibhav` ranks **19** and is opened.
`https://www.linkedin.com/in/ptkvaibhav/` ranks **99** and is not. Both are real
links on the same page. The difference is the 80-visit budget, not the extractor.

## Four findings

### 1. The bound that decides coverage is logged at INFO and reaches no deliverable

`agents/scan.py::_enrich_endpoints` caps enrichment at `max_visits = 80`,
prioritised by `crawl_visit_priority`, and logs the drop:

```
Endpoint enrichment: 132 of 212 candidate URL(s) exceed the 80-visit budget and
were not opened (lowest-priority dropped first) — first omitted: …
```

That is exactly the shape `observability/plan_alarms.py` was built for one layer
up — *"a bound that decides coverage is reported in the DELIVERABLE, not just the
log"* — and this bound has no equivalent. `plan_coverage` in `report.json` reports
the exploit plan cap and says nothing about the crawl budget, so a reader has no
way to know that 62% of the discovered surface was never opened.

The refusal log inherits the same blind spot: it records requests that were
**refused**, and the enrichment budget decides which candidates ever become
requests. Nothing anywhere records the discovered-but-never-enqueued set, so
"75 refusals across 3 hosts" reads as the out-of-scope surface when it is the
top-80 slice of it.

### 2. Escaped-payload artifacts inflate the candidate set

14 of the 212 candidates (6.6%) are mangled:

```
https://github.com/ptkvaibhav%5C
https://github.com/ptkvaibhav%5C%5C%5C
https://www.linkedin.com/in/ptkvaibhav/%5C
https://www.linkedin.com/in/ptkvaibhav/%5C%5C%5C
http://www.w3.org/2000/svg%5C
https://ptkvaibhav.vercel.app/_next/y3s%5C
https://ptkvaibhav.vercel.app/_next/{4,9,q,g,iV}
```

`%5C` is a URL-encoded backslash: these come from reading URLs out of the escaped
RSC flight payload and minified JS **without unescaping**, so `…/ptkvaibhav\` and
`…/ptkvaibhav\\\` are harvested as distinct URLs. The dedup key
(`url.split("#")[0].rstrip("/")`) treats them as different candidates, so **one
href consumed three of the eighty slots** — and did so for github, linkedin, x.com
and w3.org alike. `_url_shape` has no rule for a trailing `%5C`.

### 3. Path-doubling inflation

```
/static/chunks/app/static/chunks/app/static/chunks/125-….js
```

katana resolves relative chunk paths against a chunk URL, producing arbitrarily
deep repeats. `crawl_visit_priority` already deprioritises doubled-path artifacts,
so these sank correctly — but they still occupy candidate slots and account for
most of the 132 dropped.

### 4. Internal coverage on THIS target was fine; the in-house fallback would not have been

Of 189 same-host candidates, 48 are non-asset application URLs and **44 were
opened**. The ranking did its job: application pages before assets.

So the internal under-crawling worry is **not** demonstrated on this run — but
that is because katana resolved. `agents/scan.py::_extract_links`, the in-house
HTTP crawl fallback that runs when it does not, is materially narrower:

* `if absolute.startswith(base_origin)` — **same-origin only**, so it builds no
  outbound-link census at all (correct for a crawler, and the reason no census
  exists);
* `(?:href|src|action)\s*=\s*["\']([^"\']+)["\']` — requires quoted attributes;
* it reads **HTML only**. A Next.js App Router route that exists only in the RSC
  flight payload appears as `"href":"/x"` inside a `<script>`, JSON-escaped, which
  that regex cannot match — so a client-routed page reachable by no server-rendered
  anchor is invisible to it.

Since most client applications are React/Next/Vue, the fallback path is the one
carrying the real risk, and it is untested against a flight payload.

## What a fix would have to do

Recorded, not implemented:

1. render the crawl budget's drop in `report.json` the way the plan cap is —
   candidates, opened, dropped, first omitted, per host;
2. unescape before harvesting, and normalise a trailing `%5C` in `_url_shape`, so
   one link is one candidate;
3. give `_extract_links` an RSC/JSON-string source alongside the attribute regex,
   and test it against a real flight payload rather than hand-written HTML.
