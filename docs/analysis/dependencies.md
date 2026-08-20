# Clinkz — Dependencies + Code Quality

Original audit: 2026-05-06 (pip-audit, radon, importlib.metadata; developer
working environment, `feat/v2-architecture`).
**Corrected: 2026-08-20.** Sections 0–3 are re-derived against
`requirements-ci.lock` — the set CI actually installs. Sections 4–6 are the
original snapshot and say so where they have not been re-derived.

---

## 0. Correction to the 2026-05-06 audit

The original audit was wrong in four ways, three of which follow from one
methodology error. They are stated here rather than quietly fixed because the
wrong version of this file has been readable for three months, and a client
security team reads this file.

**It scanned a working virtualenv, not the declared dependency set.**
`pip-audit` was run against whatever happened to be installed on one machine.
That environment still contained the `langchain` / `langsmith` / `langgraph`
family — orphans of a dependency that had already been removed from
`pyproject.toml` six weeks earlier, in `3949f50` (2026-03-23), and never
uninstalled from the venv. Everything below follows from that.

### 0.1 The langchain chain was ours, not MCP's

The audit said the chain arrived "transitive via mcp" and closed with:

> The langchain/langsmith/langgraph chain pulls in dozens of packages we don't
> use. Worth investigating whether `mcp[cli]` actually needs them or whether
> it's an over-installed extra.

`mcp[cli]` has never required any of them. Its complete first-order requirement
set, read from the installed distribution's own metadata:

```
$ python -c "import importlib.metadata as md; [print(r) for r in md.distribution('mcp').requires]"
anyio>=4.5                       pyjwt[crypto]>=2.10.1
httpx-sse>=0.4                   python-multipart>=0.0.9
httpx>=0.27.1                    pywin32>=310; sys_platform == 'win32'
jsonschema>=4.20.0               sse-starlette>=1.6.1
pydantic-settings>=2.5.2         starlette>=0.27
pydantic<3.0.0,>=2.11.0          typing-extensions>=4.9.0
typing-inspection>=0.4.1         uvicorn>=0.31.1; sys_platform != 'emscripten'
python-dotenv>=1.0.0; extra == 'cli'      typer>=0.16.0; extra == 'cli'
rich>=13.9.4; extra == 'rich'             websockets>=15.0.1; extra == 'ws'
```

No langchain, no langsmith, no langgraph. The chain entered through **clinkz's
own** `langgraph>=0.1.0`, a direct dependency added in the initial scaffold
(`05e063f`, 2026-03-03) and removed in `3949f50` (2026-03-23):

```
$ git log --oneline -S"langgraph" -- pyproject.toml
3949f50 chore: comprehensive security audit and code cleanup
05e063f feat: initial clinkz project scaffold with LLM abstraction layer
```

Two further attributions in the §2 table were wrong for the same reason:

* **`pyjwt`** — recorded as "Indirect (langgraph deps)". It is a *first-order*
  `mcp` requirement (`pyjwt[crypto]>=2.10.1`), and is today a direct clinkz
  dependency (`PyJWT>=2.13.0`).
* **`requests`** — recorded as "Indirect (langchain ecosystem)". It arrives via
  `google-genai`, a direct clinkz dependency.

### 0.2 The vulnerability count was inflated by roughly a third

The audit reported **25 vulnerabilities across 12 packages**. Nine of those —
`langchain-core` (1), `langsmith` (1), `pypdf` (7) — were in packages from the
orphaned chain. That is **36% of the reported total**, attributed to a
dependency the project had already dropped. The audit's own top-priority item
said as much without noticing it:

> It pulls 12+ packages with 9 of the 25 reported vulns.

Nine of twenty-five, in packages that were not going to be installed by anyone
who created a fresh environment from `pyproject.toml`.

### 0.3 The recommended remediation was a no-op

> If `mcp[cli]` only needs them for an unused feature, drop the extra or pin
> minimal deps.

The `[cli]` extra resolves to exactly two packages: `python-dotenv>=1.0.0` and
`typer>=0.16.0`. Clinkz declares **both** as direct dependencies. Dropping the
extra would have removed nothing from the tree and changed no CVE count, while
appearing in a report as a completed remediation.

### 0.4 The licence conclusion rested on a grep that could not have found anything

Separately from the venv error: §3 declared "zero copyleft licenses in the
entire installed environment" on the strength of a `grep` over a CSV that
carried no licence classifiers. Two copyleft-family packages are in the lock
today — `certifi` (MPL-2.0) and `pyphen` (GPL-2.0+/LGPL-2.1+/MPL-1.1). The
audit's conclusion happens to survive; the sentence supporting it was false when
written. Full detail, and the zero-cost way to remove the GPL-family package
entirely, in §3.

### 0.5 What actually fixed the rest

Not the recommendation. The lockfile: CI installs
`pip install -c requirements-ci.lock -e ".[dev]"` and then asserts the result
with `python scripts/lockfile.py --check`, so the audited set and the installed
set are the same object. A stale venv can no longer be mistaken for the
dependency graph, which is the only reason this class of error was possible.

---

## 1. Dependency tree — current

**Direct dependencies (`pyproject.toml`):** 17.
**Resolved dependency set CI installs (`requirements-ci.lock`):** 84 packages,
every one pinned exactly, generated by `scripts/lockfile.py --generate` for the
linux/cp312 target and enforced as a pip `-c` constraint.

The original audit's "165 transitive dependencies" was a count of one
developer's virtualenv. It is not the number CI installs and never was.

Three direct deps are pinned exactly rather than floored — `typer==0.27.1`,
`click==8.4.2`, `rich==15.0.0` — because the CLI's exit-code contract and its
documented flag list are asserted against what those three *render*. `mcp[cli]`
carries an upper bound (`>=1.0.0,<2`) because mcp 2.0.0 moved server-side
FastMCP out of the package.

**Zero langchain-ecosystem packages appear in the lock:**

```
$ grep -icE "langchain|langsmith|langgraph" requirements-ci.lock
0
```

## 2. Vulnerabilities — every finding from the original audit, re-checked

Each row is the original audit's finding against what `requirements-ci.lock`
pins today.

| Package | Audit saw | Audit's fix version | Lock pins | Status |
|---|---|---|---|---|
| `cryptography` | 46.0.5 | 46.0.6 / 46.0.7 | **50.0.0** | Fixed |
| `pillow` | 12.1.1 | 12.2.0 | **12.2.0** | Fixed |
| `pyjwt` | 2.11.0 | 2.12.0 | **2.13.0** | Fixed — and a *direct* dep, not a langgraph one |
| `requests` | 2.32.5 | 2.33.0 | **2.34.2** | Fixed — arrives via `google-genai`, not langchain |
| `pygments` | 2.19.2 | 2.20.0 | **2.21.0** | Fixed |
| `pyasn1` | 0.6.2 | 0.6.3 | **0.6.4** | Fixed |
| `python-multipart` | 0.0.22 | 0.0.26 | **0.0.32** | Fixed |
| `pypdf` | 6.8.0 | 6.9.1+ | **6.16.1** | Fixed — now a *direct* dep, floored at 6.9.1 |
| `pytest` | 9.0.2 | 9.0.3 | **9.1.1** | Fixed (test-only) |
| `langchain-core` | 1.2.17 | 1.2.28 | — | **Absent from the lock** |
| `langsmith` | 0.7.11 | 0.7.31 | — | **Absent from the lock** |
| `pip` | 25.3 | 26.0+ | not pinned | Install-time tooling, outside the lock |

**Every one of the 25 reported vulnerabilities is either fixed at the pinned
version or absent from the dependency set entirely.**

`pypdf` deserves a note because its status inverted. The audit filed it as
"Indirect. Not used directly by Clinkz" with 7 CVEs. It is now a **direct**
dependency with a named consumer: `engagement/artifact_scan.py`, the disclosure
gate. A PDF's page text lives in Flate-compressed content streams and its
metadata in a separate `/Info` dictionary, so a byte scan of the file sees
neither — without a real extractor, letting `.pdf` into the scanned set would
have created a region the gate reports CLEAN over by construction. It is floored
at `>=6.9.1`, above all 7 advisories, rather than at the 5.x that would satisfy
the import.

## 3. License compatibility — the original §3 was also wrong

The original audit concluded:

> Searched 189 distributions for GPL/AGPL/LGPL/copyleft markers:
> `$ grep -iE "GPL|AGPL|copyleft|LGPL" licenses.csv` → (no output)
> **Result: zero copyleft licenses in the entire installed environment.**

That grep found nothing because the CSV it read carried no classifier data, not
because there was nothing to find. Re-run against all **84** packages in
`requirements-ci.lock`, reading each distribution's own metadata and classifiers,
**two copyleft-family packages are present today**:

| Package | Version | Licence | Route in |
|---|---|---|---|
| `certifi` | 2026.2.25 | **MPL-2.0** | `requests` / `httpx` — the CA bundle behind every HTTPS call |
| `pyphen` | 0.17.2 | **GPL-2.0+ / LGPL-2.1+ / MPL-1.1** (tri-licensed) | `weasyprint`, and nothing else |

### What that does and does not mean

**The conclusion survives — but by election, not by absence, and that
distinction is the whole point of writing it down.**

* `certifi` is MPL-2.0, a *file-level* weak copyleft. Using it unmodified as a
  dependency imposes no obligation on a larger work. Nothing to do.
* `pyphen` is offered under **three** licences and a downstream elects one.
  Electing LGPL-2.1+ or MPL-1.1 permits commercial distribution of a larger
  work; electing GPL-2.0+ would not. Nobody has elected anything, because the
  audit reported the package as not being there.

So "enterprise extensions can be commercial without forced open-sourcing" is
still true. It was true by luck rather than by verification, and it rested on a
sentence — "zero copyleft licenses in the entire installed environment" — that a
client security team could reasonably have relied on and that was false when
written.

### And the GPL-family package is removable at zero cost

`pyphen` enters through exactly one route, `weasyprint`, which is used for
hyphenation in PDF rendering. `weasyprint` is imported **nowhere**:

```
$ grep -rn "weasyprint" src/ scripts/ tests/ --include=*.py
(no output)
```

`pyproject.toml` says as much in its own comment — `weasyprint` and `jinja2` are
"declared for a report renderer that does not exist", left in place deliberately
because removing a dependency is a separate decision from noticing it is unused.
That decision now has a second reason attached: dropping `weasyprint` removes
the only GPL-family package in the dependency graph, along with `pyphen`,
`pydyf`, `tinyhtml5`, `tinycss2`, `cssselect2`, `fonttools`, `Pillow`, `Brotli`
and `zopfli` — and `Pillow` is one of the two packages the original audit
correctly flagged as runtime-reachable with five CVEs.

The PDF path that *does* exist reads with `pypdf` (§2) and writes nothing.

## 4. Unmaintained / abandoned packages

From the original snapshot, still accurate for the direct set: every direct
dependency is actively released except `defusedxml` 0.7.1 (~2021), which is
stale but stable — a small, security-focused library that receives occasional
patches. No abandonware.

## 5. Code quality — **2026-05-06 snapshot, not re-derived**

⚠️ **These metrics are three months stale and should not be quoted.** The single
cheapest check shows how far:

| File | Audit (2026-05-06) | Today |
|---|---:|---:|
| `agents/exploit.py` | 4,880 LOC | **30,186 LOC** |
| `orchestrator/orchestrator.py` | 1,443 LOC | 3,148 LOC |
| `agents/scan.py` | 1,171 LOC | 2,053 LOC |

Every line number, complexity rank and maintainability index in the original
§5/§6 refers to a tree that no longer exists. The *shape* of the finding stands
— `agents/exploit.py` is by a wide margin the largest module and mixes plan
generation, per-class `_test_*` methodologies, and KB recording — and it has
grown 6.2×, so it stands more strongly than when it was written.

The original per-function table is retained below for provenance only.

<details>
<summary>Original 2026-05-06 complexity table (stale line numbers)</summary>

| Rank | Score | Location |
|---|---|---|
| F | 45 | `OrchestratorAgent._extract_technologies` (`orchestrator.py:876`) |
| F | 43 | `OrchestratorAgent._find_login_url` (`orchestrator.py:1052`) |
| E | 32 | `ExploitAgent._test_brute_force` (`exploit.py:3688`) |
| E | 31 | `ExploitAgent._fallback_synthesized_payload` (`exploit.py:2876`) |
| D | 30 | `ExploitAgent._test_javascript_attacks` (`exploit.py:4052`) |
| D | 28 | `ReconAgent._step_web_recon` (`recon.py:449`) |
| D | 27 | `NmapTool.parse_output` (`nmap.py:130`) |
| D | 24 | `ScanAgent._enrich_endpoints_with_params` (`scan.py:498`) |
| D | 23 | `OrchestratorAgent._run_phase` (`orchestrator.py:542`) |

Maintainability Index: all modules A or B except `agents/exploit.py` at C.

</details>

## 6. Actionable findings — status

| # | Original recommendation | Status |
|---|---|---|
| 1 | Bump `cryptography` ≥46.0.7 and `pillow` ≥12.2.0 | **Done** — lock pins 50.0.0 / 12.2.0 |
| 2 | Pin upper bounds or commit a lock | **Done** — `requirements-ci.lock`, enforced as a pip constraint *and* asserted by `scripts/lockfile.py --check` |
| 3 | Decide whether the langchain chain is needed | **Void** — see §0. It was never MCP's, it was already removed, and the proposed remediation was a no-op |
| 4 | Refactor `agents/exploit.py` into a sub-package | **Open**, and larger than when written: 4,880 → 30,186 LOC |
| 5 | Extract `_extract_technologies` / `_find_login_url` | **Open** (line numbers stale) |
| 6 | CI step running `pip-audit`, failing on a direct-dep vuln | **Open.** The lockfile closed the reproducibility half of this; auditing the locked set on every PR is the half still missing, and it is what would have caught §0 automatically |
| 7 | Document dev tooling deps separately | **Open** |
| 8 | `NmapTool.parse_output` → XML + `defusedxml` | **Open** |
| 9 | Split `WebAuthenticator._execute_curl` | **Open** |
| 10 | *(new)* Drop the unused `weasyprint` / `jinja2` declarations | **Open** — removes the only GPL-family package in the graph (`pyphen`), plus `Pillow` and eight other transitives, and nothing imports either one |
| 11 | *(new)* Elect a licence for `pyphen` if `weasyprint` is kept | **Open** — LGPL-2.1+ or MPL-1.1; see §3 |

## 7. How to reproduce this correction

```bash
# The chain was ours, and it was already gone.
git log --oneline -S"langgraph" -- pyproject.toml

# mcp[cli] requires none of it.
python -c "import importlib.metadata as md; print(md.distribution('mcp').requires)"

# Nor does the set CI installs.
grep -icE "langchain|langsmith|langgraph" requirements-ci.lock   # -> 0

# And the audited set is the installed set.
pip install -c requirements-ci.lock -e ".[dev]" && python scripts/lockfile.py --check

# The licence scan the original §3 believed it had run: read each locked
# distribution's OWN metadata and classifiers rather than a CSV that carried
# neither. Reports certifi (MPL-2.0) and pyphen (GPL-2.0+/LGPL-2.1+/MPL-1.1).
python - <<'EOF'
import importlib.metadata as md, re, pathlib
lock = [l.split("==")[0].strip().lower().replace("_", "-")
        for l in pathlib.Path("requirements-ci.lock").read_text().splitlines()
        if re.match(r"^[A-Za-z0-9_.-]+==", l)]
for d in md.distributions():
    name = (d.metadata["Name"] or "").lower().replace("_", "-")
    if name not in lock:
        continue
    blob = " ".join(filter(None, [d.metadata.get("License"),
                                  d.metadata.get("License-Expression"),
                                  *(d.metadata.get_all("Classifier") or [])]))
    if re.search(r"\b(GPL|AGPL|LGPL|MPL|EUPL|CDDL)\b", blob, re.I):
        print(name, d.version, "->", blob[:90])
EOF

# The only GPL-family package arrives through a dependency nothing imports.
grep -rn "weasyprint" src/ scripts/ tests/ --include=*.py   # -> (no output)
```
