"""Live OWASP Juice Shop skill smoke tests.

One test per validated Juice Shop skill mapping. Each directly invokes a
single ``_test_*`` method on ``ExploitAgent`` against a known-vulnerable
Juice Shop endpoint with an authenticated session — no orchestrator, no
plan, no LLM reasoning beyond what the skill itself does.

Validates that the deterministic skill methodologies handle Juice Shop's
SPA-style param consumption (DOM-context reflection driven by
``window.location.hash``), not just PHP-style server reflection.

Run with::

    pytest tests/test_skills_juiceshop/ -v -m juiceshop_smoke --tb=short
"""
