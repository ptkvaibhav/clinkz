# NoSQL injection — `_test_nosqli`

First new Tier-1 primitive. Mirrors the SQLi six-phase injection-family shape;
only the operators/carriers differ (MongoDB `$ne`/`$gt`/`$regex`/`$where` vs SQL
clauses). Models in `models/methodology.py` (`NoSQLContext`,
`NoSQLInjectionType`, `NoSQLPrimitives`, `NoSQLMethodologyResult`).

## Dedicated probe carrier

`_nosql_send_probe` / `_build_nosql_json_body` (the shared string-only
`_send_probe` is left untouched). NoSQL operator injection needs a **nested
operator object** (`{"$ne": null}`) as a JSON-body field *value* (not a
stringified literal) — `_http_post_json` serialises `dict[str, Any]` and carries
cookies + JWT.

## Carriers

- **(A) JSON-body operator object** — `PATCH /rest/products/reviews
  {"id":{"$ne":-1}}` (Juice Shop "NoSQL Manipulation", confirmed by a
  `modified`-count widening over the benign baseline).
- **(B) string `$where`** in a path/query segment — track-order / `sleep(N)`
  ("NoSQL DoS", confirmed by a time delta).

## Honesty

- **Phase 2** classifies the carrier from **NoSQL-only signals**: operator
  confirmation requires a NoSQL error signature OR a count-based match-set
  widening (a bare body diff is rejected so a DVWA `id[$ne]=` PHP "Array to
  string" warning is not mistaken for NoSQL), and `$where` needs a NoSQL error or
  a non-SQL 5xx.
- **Phase 3** returns **no candidate type** when no NoSQL signal exists, so NoSQL
  is N/A by construction on a SQL/PHP stack (DVWA — no false emission).
- **Phase 5** is verification-honest like SQLi/CMDi: a marker/operator echoed in a
  4xx/5xx body, or a SQL error, never confirms.

**Juice Shop's login is SQL injection, not NoSQL**, so the canonical NoSQL gate
is the reviews-manipulation surface — not a login `{"$ne":null}` bypass (that
auth-bypass type is implemented but correctly does not fire there).
