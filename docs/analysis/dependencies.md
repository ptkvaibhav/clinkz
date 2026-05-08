# Clinkz v2 — Dependencies + Code Quality

Date: 2026-05-06
Tooling: pip-audit, radon, importlib.metadata.
Snapshot of the working environment (Python 3.12+, src tree on
`feat/v2-architecture`).

## 1. Dependency tree summary

- **Direct dependencies (per `pyproject.toml`):** 12
- **Total transitive dependencies installed:** 165
- **All direct deps pin a lower bound but no upper bound** (`>=`).
  This is operator-friendly but means a breaking minor release in
  any direct dep can land in CI overnight. Recommend pinning upper
  bounds in a `requirements-lock.txt` for reproducibility.

### Direct deps + status

| Package | Pinned | Installed | Vulns | License |
|---|---|---|---|---|
| `openai` | `>=1.30.0` | 2.24.0 | 0 | Apache-2.0 |
| `anthropic` | `>=0.34.0` | 0.84.0 | 0 | MIT |
| `google-genai` | `>=0.5.0` | 1.66.0 | 0 | Apache-2.0 |
| `pydantic` | `>=2.7.0` | 2.12.5 | 0 | MIT |
| `typer` | `>=0.12.0` | 0.24.1 | 0 | MIT |
| `aiohttp` | `>=3.13.4` | 3.13.5 | 0 | Apache-2.0 + MIT |
| `aiosqlite` | `>=0.20.0` | 0.22.1 | 0 | MIT |
| `weasyprint` | `>=62.0` | 68.1 | 0 | BSD-3-Clause |
| `jinja2` | `>=3.1.0` | 3.1.6 | 0 | BSD-3-Clause |
| `python-dotenv` | `>=1.0.0` | 1.2.2 | 0 | BSD-3-Clause |
| `mcp[cli]` | `>=1.0.0` | 1.26.0 | 0 | MIT |
| `defusedxml` | `>=0.7.1` | 0.7.1 | 0 | PSFL |

✅ **Zero direct-dep vulnerabilities.** All known CVEs in the
environment come from transitive packages.

## 2. pip-audit — vulnerable transitive deps

`python -m pip_audit` reports **25 known vulnerabilities across 12
packages**. None are direct deps; all surface through transitive
imports of MCP, weasyprint, langchain (pulled via mcp), or developer
tooling (pip, pytest).

| Package | Installed | Fix versions | CVEs | Reachability |
|---|---|---|---|---|
| `cryptography` | 46.0.5 | 46.0.6, 46.0.7 | CVE-2026-34073, CVE-2026-39892 | TLS — used by every HTTPS call. **Bump.** |
| `pillow` | 12.1.1 | 12.2.0 | 5 CVEs | Pulled by weasyprint for image rendering in reports. **Bump.** |
| `pyjwt` | 2.11.0 | 2.12.0 | CVE-2026-32597 | Indirect (langgraph deps). Low risk for our usage. |
| `requests` | 2.32.5 | 2.33.0 | CVE-2026-25645 | Indirect (langchain ecosystem). Low risk. |
| `pygments` | 2.19.2 | 2.20.0 | CVE-2026-4539 | Renders syntax highlighting in reports — bump. |
| `pyasn1` | 0.6.2 | 0.6.3 | CVE-2026-30922 | Indirect via cryptography. Low risk. |
| `langchain-core` | 1.2.17 | 1.2.28 | CVE-2026-40087 | Pulled by langgraph (transitive via mcp). Not used directly by Clinkz. |
| `langsmith` | 0.7.11 | 0.7.31 | CVE-2026-41182 | Same. Not used directly. |
| `pypdf` | 6.8.0 | 6.9.1+ | 7 CVEs | Indirect. Not used directly by Clinkz. |
| `python-multipart` | 0.0.22 | 0.0.26 | CVE-2026-40347 | Indirect via mcp HTTP transport. |
| `pip` | 25.3 | 26.0+ | 3 CVEs | Tooling — only matters during install. |
| `pytest` | 9.0.2 | 9.0.3 | CVE-2025-71176 | Test-only. |

**Triage priority:**
- 🔴 **High:** `cryptography`, `pillow` — runtime-reachable.
- 🟡 **Medium:** `pygments` — only reachable in report rendering.
- 🟢 **Low:** `pyjwt`, `requests`, `pyasn1`, `pypdf`, `python-multipart`,
  `pip`, `pytest`, langchain ecosystem — not directly imported by
  Clinkz code.

The langchain/langsmith/langgraph chain pulls in dozens of packages we
don't use. Worth investigating whether `mcp[cli]` actually needs them
or whether it's an over-installed extra.

## 3. License compatibility

Per `pyproject.toml`: `license = {text = "MIT"}`.

Plan from architecture: open-source core, paid enterprise — **must
avoid GPL/AGPL/LGPL deps that would require open-sourcing
enterprise extensions.**

### Direct deps

All direct deps are MIT / Apache-2.0 / BSD / PSFL — **all
permissive**. No GPL/AGPL anywhere in direct dependency list.

### Transitive deps (full installed environment)

Searched 189 distributions for GPL/AGPL/LGPL/copyleft markers:

```
$ grep -iE "GPL|AGPL|copyleft|LGPL" licenses.csv
(no output)
```

**Result: zero copyleft licenses in the entire installed environment.**

Distributions with no License field but with classifier-stated MIT/BSD:

- `aiosqlite` — classifier-stated MIT
- `weasyprint` — classifier-stated BSD
- `jinja2` — classifier-stated BSD-3-Clause

Distributions reporting `PSFL` (Python Software Foundation License):

- `defusedxml` 0.7.1
- `aiohappyeyeballs` 2.6.1

PSFL is permissive and compatible with MIT.

✅ **Enterprise extensions can be commercial without forced open-sourcing.**

## 4. Unmaintained / abandoned packages

Looking for packages whose latest release is > 2 years old, or whose
download counts are suspiciously low. Spot-checked the direct-dep set:

| Package | Latest release | Status |
|---|---|---|
| `openai` | 2.24.0 (2026) | Active |
| `anthropic` | 0.84.0 (2026) | Active |
| `google-genai` | 1.66.0 (2026) | Active |
| `pydantic` | 2.12.5 (2026) | Active |
| `typer` | 0.24.1 (2026) | Active |
| `aiohttp` | 3.13.5 (2026) | Active |
| `aiosqlite` | 0.22.1 (~2025) | Active |
| `weasyprint` | 68.1 (2026) | Active |
| `jinja2` | 3.1.6 (~2025) | Active |
| `python-dotenv` | 1.2.2 (~2025) | Active |
| `mcp` | 1.26.0 (2026) | Active |
| `defusedxml` | 0.7.1 (~2021) | **Stale but stable** — minor lib, security-focused, gets occasional patches |

✅ No abandonware in the direct deps.

## 5. Code quality — per-module metrics

### Cyclomatic complexity (radon cc)

- **Total blocks analysed:** 715 (classes, functions, methods)
- **Average complexity:** A (4.36) — well within healthy range
- **Highest-complexity functions (rank D and worse):**

| Rank | Score | Location |
|---|---|---|
| **F** | **45** | `OrchestratorAgent._extract_technologies` (`orchestrator.py:876`) |
| **F** | **43** | `OrchestratorAgent._find_login_url` (`orchestrator.py:1052`) |
| **E** | 32 | `ExploitAgent._test_brute_force` (`exploit.py:3688`) |
| **E** | 31 | `ExploitAgent._fallback_synthesized_payload` (`exploit.py:2876`) |
| **D** | 30 | `ExploitAgent._test_javascript_attacks` (`exploit.py:4052`) |
| **D** | 28 | `ReconAgent._step_web_recon` (`recon.py:449`) |
| **D** | 27 | `NmapTool.parse_output` (`nmap.py:130`) |
| **D** | 25 | `ReconAgent.run` (`recon.py:102`) |
| **D** | 25 | `WebAuthenticator._execute_curl` (`auth.py:554`) |
| **D** | 24 | `ExploitAgent._sqli_phase5_verify` (`exploit.py:2191`) |
| **D** | 24 | `ScanAgent._enrich_endpoints_with_params` (`scan.py:498`) |
| **D** | 23 | `OrchestratorAgent._run_phase` (`orchestrator.py:542`) |
| **D** | 22 | `ExploitAgent._sqli_probe_primitives` (`exploit.py:1753`) |
| **D** | 21 | `ExploitAgent._check_predictable_session_cookies` (`exploit.py:3980`) |
| **D** | 21 | `ScanAgent._scan_http_service` (`scan.py:326`) |
| **D** | 21 | `ScanAgent._http_crawl_fallback` (`scan.py:590`) |

The two **F-rank** functions are both in the orchestrator and both do
the same kind of work: try-many-strategies-and-pick-one. They're prime
candidates for table-driven extraction (each "strategy" becomes its own
function, picked by a strategy list).

### Maintainability Index (radon mi)

- **All modules rank A or B except `agents/exploit.py` which is C (0.00).**

| Module | MI | Rank | Notes |
|---|---|---|---|
| `agents/exploit.py` | 0.00 | **C** | Lowest in the codebase. 4880 LOC, 12 D/E/F-rank methods. |
| `agents/scan.py` | 13.63 | B | 1171 LOC, 3 D-rank methods. |
| `orchestrator/orchestrator.py` | 10.96 | B | 1443 LOC, 2 F-rank + 1 D-rank. |
| `tools/auth.py` | 27.45 | A | Borderline — large file, one D-rank method. |
| `agents/recon.py` | 35.58 | A | 716 LOC, 2 D-rank methods. |
| Everything else | 40+ | A | |

### File-size outliers

| File | LOC |
|---|---|
| `agents/exploit.py` | 4880 |
| `orchestrator/orchestrator.py` | 1443 |
| `agents/scan.py` | 1171 |
| `agents/recon.py` | 716 |

**`agents/exploit.py` is the elephant.** 4880 lines, 12 D/E/F-rank
methods, MI rank C. It mixes:

- Plan generation (LLM-driven)
- Per-vuln `_test_*` methods (deterministic) — there are 30+ of these
- Adaptive XSS/SQLi methodology helpers (multi-phase)
- KB recording

Splitting into `exploit/{plan.py,sqli.py,xss.py,brute_force.py,...}` is
the obvious refactor. The current single-file approach makes the file
hard to review and impossible to subclass.

### Test coverage

- **Test files:** 63
- **Test LOC:** 16799
- **Source LOC:** 22470
- **Test-to-source ratio:** 0.75

A real coverage run would require a coverage-instrumented test
execution. Several tests are gated on DVWA / network access / API keys
(`tests/test_skills_dvwa/`, `tests/test_integration/`), so a quick
`pytest --cov` undercount is expected. Recommend a CI job that runs
the integration suites against a docker-compose-managed DVWA.

## 6. Code quality — patterns worth fixing

(Cross-references to threat model and semantic review are noted.)

1. **`OrchestratorAgent._extract_technologies` (F-45)** is a manual
   parse-multiple-formats loop. Could be a `dispatch` table keyed by
   format detection. Closely coupled to the `summary` / `tech_stack` /
   `services` ambiguity called out in §2 of `semantic_review.md`.
2. **`OrchestratorAgent._find_login_url` (F-43)** is a 6-strategy
   fallback chain. Each strategy is a self-contained closure today;
   extract them, run them in a generator, return the first hit. ~20%
   line reduction and the function becomes testable.
3. **`agents/exploit.py` 4880 LOC** — split into a sub-package.
4. **`NmapTool.parse_output` D-27** — the nmap text format is annoying
   but the function is parsing it manually. Use `python-nmap` (already
   parses) or `defusedxml` against `nmap -oX -` output.

## Actionable Findings

### Top priority

1. **Bump `cryptography` to ≥46.0.7 and `pillow` to ≥12.2.0.** Both are
   runtime-reachable and have multiple CVEs. Add upper-bound pins after
   the bump.
2. **Pin upper bounds in `pyproject.toml`** OR commit a
   `requirements-lock.txt` for reproducibility. Today every install
   gets the latest compatible version, which is fine until it isn't.
3. **Decide whether the langchain/langsmith/langgraph transitive chain
   is needed.** It pulls 12+ packages with 9 of the 25 reported vulns.
   If `mcp[cli]` only needs them for an unused feature, drop the extra
   or pin minimal deps.

### Medium priority

4. **Refactor `agents/exploit.py` into a sub-package.** Group `_test_*`
   methods by vuln class. Move `_fallback_synthesized_payload` and
   methodology helpers into `exploit/methodology.py`. Goal: every
   resulting file < 800 LOC and MI rank A.
5. **Extract `_extract_technologies` and `_find_login_url`** from the
   orchestrator into table-driven strategy picker modules.
6. **Add a CI step that runs `pip-audit` on every PR** and fails when
   a *direct* dep has a known vuln.
7. **Document the dev tooling deps separately.** Today only `ruff` /
   `pytest` / `pytest-asyncio` are listed under `[project.optional-dependencies.dev]`.
   Add `pip-audit`, `radon`, `bandit` so contributors can reproduce
   the scans without guessing.

### Lower priority

8. **`NmapTool.parse_output`** — switch to XML output and `defusedxml`,
   delete the manual text parser.
9. **`WebAuthenticator._execute_curl` D-25** — split the curl-mode and
   aiohttp-mode flows so each is its own < 100-line method.
