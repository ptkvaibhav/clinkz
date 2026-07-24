# XXE — `_test_xxe`

Third new Tier-1 primitive. Mirrors the SQLi/NoSQL/SSTI six-phase
injection-family shape, with two deliberate structural differences. Models in
`models/methodology.py` (`XXEExploitationType`, `XXEParserCapability`,
`XXEMethodologyResult`).

## Structural differences

1. **Endpoint-scoped, not parameter-scoped**: XXE has no injectable named param —
   the whole XML *document* is the payload — so `_test_xxe` runs the methodology
   once per page (like `_test_file_upload`), not in a `for param` loop;
   `candidate_param` is a synthetic carrier label (`file` / `xml_body`).
2. **New carrier**: a raw XML body is the one shape `_send_probe`/`_http_post_json`
   cannot express, so `_http_post_xml` (raw `application/xml`) + an
   `_xxe_send_probe` dispatcher carry it — multipart **file upload** (reusing
   `_http_post_multipart`, field `file`, filename `*.xml` — Juice Shop's
   `POST /file-upload`) for upload-shaped endpoints, raw body otherwise;
   `_send_probe` is left untouched (the NoSQL discipline).

## Phases

- **Phase 1** sends a **benign internal-entity probe** (`<!ENTITY t "MARKER">…&t;`)
  and is a candidate only if the endpoint *parses XML* (the marker expands, an XML
  parse-error surfaces, or a malformed/well-formed divergence) — so a non-XML
  stack (DVWA) is N/A.
- **Phase 2** fingerprints the **parser-capability vector** (`XXEParserCapability`:
  entity-resolution / external-entity / parameter-entity / in-band-reflection) —
  the SQL-dialect / SSTI-engine analogue; no `entity_resolution` ⇒ phase 3 returns
  nothing.
- **Phase 3** ranks `file_disclosure` / `ssrf` / `dos`; `oob_exfil` is **pruned**
  (no OAST collaborator wired, the same limitation as CMDi `BLIND_OOB`).
- **Phase 4** prefers the deterministic capability-grounded build and
  **scope-validates** every external-entity / SSRF target (`self.scope.contains`
  — no exfil to arbitrary hosts; `file://` reads are the target's own filesystem).
- **Phase 5 is the key deviation from the prior trio: the legitimate XXE
  disclosure channel is a 4xx body** — Juice Shop returns the expanded entity in
  an **HTTP 410** (`…deprecated for security reasons: <…>root:x:0:0:…`), so unlike
  CMDi/SSTI a 4xx/5xx status is **NOT** a reject signal. Honesty comes from
  confirming on actual **file content** (`_XXE_FILE_CONTENT_SIGNATURES` —
  embedded, *not* line-anchored like `_LFI_FILE_SIGNATURES`, since the disclosure
  arrives wrapped — LESSONS #26) that we never sent. DoS confirms on a **bounded**
  nested-entity parse-time delta / 503 timeout, **never a real billion-laughs**
  (which segfaults the Juice Shop libxml); expansion capped tiny (`8**4` ≈ 100 KB).
  Severity **high** (file disclosure / SSRF) / **medium** (DoS).

## Juice Shop reachability nuance

The XML parse + entity-expansion path is gated only by
`deprecatedInterfaceChallenge` (no `disabledEnv` → runs in Docker); the two XXE
*challenges* (`xxeFileDisclosure`/`xxeDos`) are `disabledEnv:[Docker,Heroku,
Gitpod]`, which suppresses only the **scoreboard banner**, not the vulnerable
code. So XXE file disclosure may be a **real in-band finding even on
default-Docker** *if* the container's libxml resolves the external file entity
(documented-unreliable — the reason the challenges are Docker-disabled); when it
doesn't, the methodology emits nothing — verification-honest either way (the
`juiceshop_smoke` gate is skip-tolerant like SSTI's). N/A by construction on DVWA
(no XML parser).
