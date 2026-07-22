# solr_log4shell_partial — deliberately PARTIAL source (design §6.2)

A copy of `solr_log4shell/` with the **log-sink source file
(`CoreAdminOperation.java`) withheld**, keeping the manifest (`pom.xml`) and the
request-param entrypoint (`CoreAdminHandler.java` reads `action`/`core`/`name`).

This reproduces the §6.2 "gets smarter" cold-control / warm-B condition:

- The recognizer finds **no** `log().info(…)` LOG_INTERPOLATION call site → the
  manifest is not even scanned → **no** `LOG4J_VULNERABLE_TOKEN` → the
  LOG_INTERPOLATION primitive is not active → **zero cold-derived hypotheses**.
- Entrypoints survive (`action`/`core`/`name`), so a Layer-2 **capability recall**
  (the `log4j-core <2.15` fact reached via the `bundles` edge) can SEED a
  hypothesis on those channels at HYPOTHESIZED reachability — the thing a cold
  start cannot do.

Hypothesis-present (warm) vs hypothesis-absent (cold-control) under this identical
partial source is the unambiguous "recall substituted for derivation" signal.
