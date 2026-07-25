# Open redirect — `_test_open_redirect`

Confirm on a **server-side 3xx whose `Location` header resolves to the attacker
host** (browser-resolved) — never on an attacker string reflected in body / JS /
a same-host path. Severity **medium** (server 3xx) / **low** (DOM/client-side).

## Dispatch fix — the emission blocker (LESSONS #29)

The real endpoint reaches `_test_open_redirect` only if it carries the `redirect`
param, and it wasn't: a URL-only crawler (katana) emits
`.../open_redirect/source/<level>.php?redirect=info.php` as a **bare**
`Endpoint(params=[])`; enrichment then finds the *same* URL as a `?redirect=`
link, but the scan crawl-merge kept the first-seen (bare) endpoint and **dropped**
the enriched param version — so the endpoint reached Exploit param-less and the
param-gated methodology never ran (this, not the confirm logic, is why the module
confirmed NOTHING at every level in the pr76 real run — the earlier
"live-validated L/M/H" claim was false). `ScanAgent._merge_crawl_endpoints_
preferring_params` now **upgrades** the bare endpoint in place with the enriched
params (general fix — any query/redirect link a URL-only crawler emits raw now
keeps its params).

## Confirm-honesty — phantom guard

The ONLY primary confirmation is a **server-side 3xx** whose `Location` header
resolves (`urljoin`, `_redirect_target_is_attacker`) to the attacker host —
`_open_redirect_phase5_verify` requires `status in {301,302,303,307,308}` + a
`Location`, so a status-200 body that merely *contains* or reflects an
attacker-looking string never confirms, and a same-host path containing
`evil.example` (DVWA Low `info.phphttps://evil.example`, `/go?u=…`) is a justified
non-finding.

- **`javascript:`/`data:` are removed** from the bypass-probe set, ranking,
  synthesis, the `RedirectBypassType` enum, and severity — a `javascript:`/`data:`
  sink is XSS / content injection, not host-navigation open redirect.
- **Body-level (meta-refresh / JS `location`) redirects are demoted** to a
  separate, lower-severity **DOM-redirect signal** (`_open_redirect_dom_signal`,
  `OpenRedirectMethodologyResult.dom_redirect`), gated on the same host-resolution
  and NEVER on the 3xx confirm path — a LOW-severity finding tagged
  `(DOM/client-side)`.

## Prefer-deterministic at BOTH ranking and synthesis (LESSONS #18/#28/#30)

The phase-2 empirical working-set beats the LLM twice:

- **Phase 3** stable-partitions the ranked bypass types so every phase-2-confirmed
  primitive precedes every unconfirmed one and re-adds any the LLM dropped
  (`_prioritize_confirmed_bypass_types`) — otherwise a live LLM ranks a NON-working
  type first and phase 4/5 confirm a genuine redirect under that wrong label (the
  `e72ed60a` full-pipeline `appended_url` **mislabel**: a real off-site 302 through
  the crawled `source/low.php?redirect=` endpoint, attributed to a type phase 2
  disproved — NOT a phantom; `_build_request_url` REPLACES the same-named param, so
  the actual request is a clean `?redirect=//evil.example`, and the earlier
  "doubled-param same-site 302 FALSE POSITIVE" reading was a mis-reconstructed curl
  of a URL the pipeline never sends — LESSONS #30).
- **Phase 4** then uses the empirically-grounded deterministic build for a bypass
  type whose primitive phase 2 confirmed (`_redirect_primitive_confirmed` over
  `working_bypass_primitives`) and skips the LLM; the LLM stays advisory for
  unconfirmed primitives (ranking tie-break + non-canonical shapes). Phase 5 is
  confirm-honest regardless — it `urljoin`-resolves the `Location` host, uniform
  across every bypass type; there is no payload-substring path.

## Allowlist bypass

A redirect-shaped param (`to`/`redirect`/`url`/`next`/…) not confirmed by generic
probes harvests an allowlisted token — highest-signal the param's **own**
`?redirect=info.php` value, else `_harvest_allowlist_tokens` from the
page-under-test / origin root / same-origin bundles (absolute outbound-allowlist
URLs for Juice Shop's `/redirect?to=`, relative path/file tokens for DVWA High) —
and embeds it in an attacker URL (`https://evil.example/?x=<token>`, path,
fragment, `@`-userinfo), confirmed by host-resolution despite the substring
allowlist (`RedirectBypassType.ALLOWLIST_BYPASS`).

## Live-validated end-to-end (LESSONS #25/#29/#30)

Through the scan-merge → planner-dispatch → methodology chain with a LIVE
Anthropic exploit LLM (`ghcr.io/digininja/dvwa`, handler
`open_redirect/source/<level>.php` — level in the *path*, not the cookie):
**Low** (direct off-site 302 → `https://evil.example/`), **Medium**
(protocol-relative `//evil.example`; absolute `http(s)://` blocked → 500),
**High** (substring-allowlist bypass, `info.php` token) each confirm; **Impossible**
(numeric-ID) and `view_source.php` emit nothing. Full-pipeline re-validated
(engagement `75ea835f`, DVWA low): the crawl-discovered
`source/low.php?redirect=info.php?id=2` endpoint confirms a genuine `at_syntax`
off-site 302 (`https://target.com@evil.example/`, curl-cross-checked), phase 3
`ranked=[at_syntax, protocol_relative, direct_redirect, appended_url, …]`,
correctly labeled, one emission, no regression. The isolated `_test_open_redirect`
smoke test could not catch the dispatch gap (it hands the param in directly), so
`test_open_redirect_through_scan_merge_and_dispatch_against_dvwa` now gates the
full chain.
