"""Live DVWA skill smoke tests.

One test per Tier-1 vulnerability category. Each directly invokes a single
``_test_*`` method on ``ExploitAgent`` against a known-vulnerable DVWA
endpoint with an authenticated session — no orchestrator, no plan, no LLM
reasoning beyond what the skill itself does.

If any of these tests fail, the corresponding skill is broken. Run with::

    pytest tests/test_skills_dvwa/ -v -m dvwa_smoke --tb=short
"""
