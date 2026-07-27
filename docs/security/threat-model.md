# Clinkz — Threat-model brief for the security scan

Paste this into the scan's **Threat-model** phase. Clinkz is an autonomous
pentest system: it *sends* attacks at a target it has been authorised to test.
That inverts two things a generic scan assumes — see §7 before filing anything.

Every claim below was verified against `main` (`1bb92fd`) at the cited
`file:line`. Where a pre-scan check already found a candidate gap it is marked
**[GAP — confirm or refute independently]**; do not inherit the conclusion.

---

## 1 · Scope enforcement — the #1 control

Scope is a **legal/ethical** boundary, not a technical nicety. Touching a host
outside `EngagementScope` is the worst outcome in this system, ahead of any
memory-safety or crash bug.

**The control.** `EngagementScope.contains` — `src/clinkz/models/scope.py:114`.
Exclusions are checked first and take precedence (`scope.py:137-139`).
Two enforcement routes:

- **Tool wrappers** → `ToolBase._check_scope` (`tools/base.py:175`, calls
  `scope.contains` at `base.py:184`). 12 call sites: `ffuf.py:111`,
  `http_client.py:176`, `katana.py:83`, `nikto.py:80`, `httpx_tool.py:106`,
  `nmap.py:74`, `nuclei.py:85`, `sqlmap.py:103`, `subfinder.py:61`,
  `whatweb.py:78`, `wafw00f.py:75`, `auth.py:255`.
- **Direct** `scope.contains` in agents: `exploit.py:3890, 3921, 3987, 4037,
  7920, 7983, 8881, 10252`; `scan.py:612`.

**Ordering is sound where the check exists.** Every `_check_scope` lives in
`validate_input`, and the canonical dispatch is `agents/base.py:856-857`
(`validate_input` then `execute`). The fail-open-looking default at
`http_client.py:111-114` is never taken, and would fail *closed* anyway — an
empty-target scope makes `contains` return `False` for everything.

### The question for the scan

The invariant is not "is there a check" but: **is the value that was validated
the same value that is later sent?** Clinkz validates the destination the
*caller* supplied and never re-validates a destination the *target* supplied.
Enumerate every path ending in network egress and state which check covers it.

**[GAP — confirm or refute independently] Target-controlled credential POST.**
`tools/auth.py` parses `<form action=...>` out of the target's login-page HTML
(`auth.py:131-132`), then takes it verbatim if absolute:
`if form.form_action.startswith("http"): post_url = form.form_action`
(`auth.py:818-820` docker / `auth.py:611-613` local). The POST body built at
`auth.py:807-814` carries the engagement's real username and password. No
`_check_scope` runs between that assignment and the send (`auth.py:850` curl
`-d` + `-L`; `auth.py:631` aiohttp `allow_redirects=True`). `validate_input`
checked only `login_url` (`auth.py:255`). Credentials come from
`credentials/store.py` and are real engagement secrets. This is simultaneously
a scope breach and a credential disclosure — treat as the highest-value target
of this scan.

**[GAP] Argument injection into nmap's argv.** `nmap.py:125`
`cmd.extend(args["flags"].split())` splices LLM-supplied tokens in before the
scope-checked target at `nmap.py:126`. The guard (`nmap.py:85-106`) rejects
only a fixed *flag-name* blocklist, so a bare operand (`10.0.0.0/8`) passes and
nmap treats it as an additional scan target that `contains` never saw.

**[GAP] Subdomain fuzzing bypasses exclusions.** `ffuf.py:111` validates
`urlparse(url).netloc`, which may still hold the literal `FUZZ` placeholder
(`ffuf.py:105-106`). `FUZZ.example.com` satisfies the suffix rule at
`scope.py:251` under a `example.com` entry, and the exclusion pass at
`scope.py:137` also fails to match — so an explicitly *excluded* sibling host is
requested once the wordlist yields that label.

**[GAP] Unscoped fetch + `chmod +x`.** `tools/installer.py` has no scope check
anywhere. `validate_input` (`installer.py:91-109`) checks only the method
allowlist and shell metacharacters — `/` and `:` are not blocked, so a URL
passes. `install_method="download"` runs `wget -O /usr/local/bin/<base> <url>`
then `chmod +x` (`installer.py:32-35`), landing an attacker-fetched executable
on `PATH` inside the tools container. Reachable as an ordinary LLM tool call
(`agents/base.py:519, 534-535`). Contained only by the docker-mode refusal at
`installer.py:115-119`.

**Redirect following** (`http_client.py:236` curl `-L`, `:409`
`allow_redirects`; `httpx_tool.py:124`, default **True**): only hop 1 is
validated; hops 2..n are attacker-chosen, and the engagement cookie jar rides
along (`http_client.py:258`).

**Latent, not live:** the whole MCP branch (`mcp_client.py:176, 218, 226`) has
no scope object — `MCPClient` is not a `ToolBase`. It is unreachable today
because `ToolResolver.initialize()` is never awaited in `src/` (it appears only
in docstrings at `resolver.py:12, 166`), so `_mcp_tools_cache` stays empty and
`find_tool` never returns an MCP match. Flag it as a gap that opens the moment
anyone wires it.

**Not gaps, stated so you skip them:** `sqlmap.py:103` validates `netloc` rather
than the URL, but every divergence I could construct fails *closed*
(`_HOSTNAME_SAFE` at `scope.py:30` rejects `@`, so userinfo tricks resolve
empty). `subfinder.py:61` authorises the query subject, not the third-party
OSINT hosts it contacts — inherent to passive enumeration. DNS resolution
inside `contains` itself (`scope.py:357, 383`) cannot be scope-validated: it is
what produces the data the decision is made on.

## 2 · Exfil guardrail — assert it still holds

`oob/templates.py::build_oob_payload` (`templates.py:121-127`) is the single
carrier. It is structurally incapable of exfiltration:

- **No parameter accepts target data** — only `(template_id, nonce, zone, shape)`.
- Nonce validated `^[a-z0-9]{16,64}$` (`templates.py:35`, enforced `:154`);
  zone validated as a bare host authority (`templates.py:42`, enforced `:159`).
  Both raise `ValueError` on mismatch.
- Templates are Clinkz-owned enum constants (`OOBTemplateId`, `templates.py:49-74`).

**What would break it:** (a) adding any parameter that reaches the f-strings at
`templates.py:165-189`; (b) loosening `_NONCE_RE`/`_ZONE_RE` to admit `.`, `/`,
or `$`; (c) sourcing `zone` from observed content instead of collaborator
minting; (d) **any payload built outside this chokepoint** — check for
`jndi:`/callback-URL string construction elsewhere. (a) and (d) are the ones a
diff could introduce quietly.

## 3 · Credential hygiene

API keys must never reach logs, reports, traces, capability facts, or payloads.

**Structural (impossible by construction):**
- Capability KB schema has **no target-identity column**
  (`knowledge/persistent_kb.py:89-123`). `technology_key` is commented
  *"never a host"*; `observed_technology` is *"a tech, not a host"*;
  `evidence_ref` is *"a LINK … never bytes"*. `engagement_id` is a local
  correlation id, not target data. Confirmed as stated.
- `trace.py::llm_call` (`trace.py:371-394`) has **no headers/raw-request
  parameter** — it records provider, model, `_summarise`d prompt/response,
  tokens, duration.

**Convention only (nothing structural stops it):**
- `trace.py:381` `extra: dict[str, Any]` is an open escape hatch on every trace
  record. A caller passing request headers would serialize an `Authorization` /
  `x-api-key` value straight into `outputs/<id>/trace.jsonl`. **Ask the scan to
  check every `extra=` call site.**
- No logger currently interpolates a key *value*; the only key-adjacent
  f-string is `llm/fallback.py:437`, which names the env vars without reading
  them. That is current style, not an enforced invariant — a
  `logger.debug(f"{settings}")` would leak.

## 4 · Untrusted-input parsing

Untrusted = ingested target source (hostile if the tree is) **and** all tool
output / HTTP response bodies (always hostile).

**Correction to the premise:** `discovery/` is the *bounded* surface —
`_MAX_FILES = 2000`, `_MAX_FILE_BYTES = 512KB`
(`discovery/source_ingest.py:100-101`, mirrored `js_source_ingest.py:92-93`
plus `_MAX_HANDLER_SCAN`, `_MAX_MANIFEST_BYTES`). 34 of 53 `re.compile` sites
there carry a quantifier, but the input is capped.

**The unbounded reads are elsewhere, and they are the real risk:**
- `tools/http_client.py:419` — `await resp.text(errors="replace")`, **no size cap**.
- `tools/base.py:220` and `:272` — `proc.communicate()`, timeout-bounded but
  **no output size cap**.

Those two feed the large regex battery in `agents/exploit.py` (≈150 patterns,
many lazy `.*?` under `IGNORECASE`, e.g. `exploit.py:161-175`). Ask the scan to
assess the **compound**: polynomial-backtracking regexes over an *unbounded*
attacker-controlled body. Report catastrophic backtracking only with a real
mechanism (nested/adjacent quantifiers over overlapping classes); a lone `\w+`
or `[^"]*` is linear — do not inflate it.

## 5 · Subprocess

**Correction to the stated invariant:** there are **11** subprocess call sites,
not 7. Seven async — `cli.py:263`, `orchestrator/target_resolver.py:334`,
`tools/base.py:215`, `base.py:266`, `binary_identity.py:53`,
`docker_preflight.py:56`, `katana.py:141` — **plus four synchronous
`subprocess.run`**: `models/scope.py:383, 419, 440` and `tools/resolver.py:391`.

All 11 are list-form. `create_subprocess_shell`: **0**. `shell=True`: **0** (the
3 grep hits are a comment and a `noqa` rationale). No `os.system`/`os.popen` in
Clinkz's own execution.

**Preserve this as an invariant.** Ask the scan to verify no shell path exists
*or can be reached* — and note that argument injection into a list-form call is
already live at `nmap.py:125` (§1). It cannot spawn a shell, but it can change
what the command *does*. `resolver.py:391` interpolates `tool_name` into
`docker exec … which <tool_name>` with no metacharacter guard (list-form, so
low risk — but confirm `tool_name` provenance).

## 6 · Guard integrity — known weakness, in scope

**Confirmed.** `.github/workflows/ci.yml:20-31` — the `leak-guard` job runs
`python3 .claude/hooks/outputs_guard.py --tree HEAD` and the secret guard, both
from the **PR's own checkout**. `actions/checkout@v4` with no `ref:` pin, no
fetch of `main`, no checksum anywhere in `.github/workflows/`. So a diff that
neuters `.claude/hooks/` passes its own inspection.

The local layer is weaker still: `.githooks/pre-commit:19-21` invokes the same
three guards, and `core.hooksPath` is per-clone config that only
`scripts/bootstrap.py` sets — a fresh clone is unprotected, and `--no-verify`
skips it. CI is the only fail-closed layer, and it is self-referential.

Ask for a concrete fix that does not depend on the PR's own copy.

## 7 · What is NOT a vulnerability — read before filing

Clinkz's source contains **attack payloads as data** and **detection patterns as
data**. Both look alarming to a grep and neither is a defect.

1. **Payload constants.** `agents/exploit.py:375` holds a Jinja2 SSTI payload
   containing `os.popen('__CMD__')`. There are JNDI (`oob/templates.py:173,
   179`), LFI, SQLi, XSS and command-injection payload constants throughout
   `agents/exploit.py`, `knowledge/`, and `oob/`. These are strings Clinkz
   **sends to a target** over HTTP. They never reach a Clinkz subprocess argv,
   and every wrapper builds list-form argv with no shell (§5).

2. **Detection regexes.** `agents/exploit.py:905` and `:1052` are
   `re.compile(r"\beval\s*\(")` — Clinkz looking for `eval(` in the *target's*
   JavaScript. A grep for `eval(`/`exec(`/`popen` across `src/` returns **only**
   these two classes; it returns **zero** real dangerous sinks.

A finding that flags a payload constant or a detection pattern as command
injection / RCE / SSTI **in Clinkz** is a false positive and will be rejected.
Report a mechanism only where **attacker-controlled input reaches a dangerous
operation in Clinkz's own execution**.

---

## Triage standard applied to your output

Same discipline Clinkz holds itself to — **suppress a true positive before
emitting a false one.**

- **CONFIRMED** needs a mechanism-level argument *and* a concrete path from
  attacker-controlled input to impact, in Clinkz's actual code, cited `file:line`.
- **REJECTED** needs the reason — payload-as-data, unreachable, structurally
  prevented, or misread. Never rejection by assertion.
- Severity only with evidence. No CVSS theatre.
