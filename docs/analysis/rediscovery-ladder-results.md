# Rediscovery ladder — results

Outcomes for the pre-registered ladder in
[`rediscovery-ladder.md`](rediscovery-ladder.md), graded under its "Scoring
rules". Predictions are copied from that file, not restated. A prediction is
never edited after a run: a disagreement is recorded here and explained.

**Status: NO RUNS YET.**

| Rung | Target | Prediction | Outcome | Where it stopped (from the trace) | Engagement id | Cost |
|---|---|---|---|---|---|---|
| 1 | `django/CVE-2021-35042` | HIT | NOT RUN | — | — | — |
| 2a | `weblogic/ssrf`, OOB disabled | MISS | NOT RUN | — | — | — |
| 2b | `weblogic/ssrf`, P6 wired | HIT | NOT RUN | — | — | — |
| 3 | `spring/CVE-2022-22963` | MISS (header carrier) | NOT RUN | — | — | — |
| 4 | `php/php_xxe` (lab, class check) | HIT | NOT RUN | — | — | — |
| 5 | `shiro/CVE-2016-4437` | MISS (no class) | NOT RUN | — | — | — |
| 6 | `nacos/CVE-2021-29441` | MISS (header carrier) | NOT RUN | — | — | — |

**Tally** (two columns, never summed): rediscovered CVEs — / 5 · class checks — / 1.
