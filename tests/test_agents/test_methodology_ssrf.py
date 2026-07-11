"""Unit tests for the adaptive SSRF (server-side request forgery) methodology.

SSRF is the second **Tier-2** primitive. It is parameter-scoped (like SSTI) and
reuses the shared string-only ``_send_probe`` — the internal URL is just a string
param *value*. Confirmation is **in-band only** this build: the in-scope server's
response must reflect internal content it should not have (a cloud-metadata / IAM
signature, or its own loopback content). A ``file://`` local-file read is **not**
SSRF — that is local file inclusion / disclosure (``_test_lfi``) — so a param that
only reads ``file:///etc/passwd`` yields zero SSRF findings. A confirmed fetch with
no reflected content is **blind SSRF**, which is *deferred* (no out-of-band
collaborator) — it emits NOTHING and notes the limitation.

Each phase is exercised against a simulated server-side fetcher (a monkeypatched
``_http_get``) and a silent LLM (so the deterministic fallbacks drive). The
real-target Juice Shop SSRF is blind by design, so these in-band tests are the
authoritative confirmation of the in-band path.

The scope-interaction tests are the **safety proof**: an in-scope request whose
parameter *value* is an internal address is ALLOWED, while a direct connection to
an internal address is BLOCKED — using the real ``EngagementScope`` /
``HTTPClientTool.validate_input`` (no mocks).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlparse

import pytest

from clinkz.agents.exploit import (
    _SSRF_UNFETCHABLE_HOST,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.discovery.constants import CARRIER_ALIGN_HOST
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import SSRFCapability, SSRFExploitationType
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.http_client import HTTPClientTool
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-ssrf-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)
PAGE = PageAnalysis(url="http://example.com/fetch", body="", status=200, input_params=["url"])
MARKER = "ClinkzReflectedAppTitle"


# ---------------------------------------------------------------------------
# Mocks / fixtures
# ---------------------------------------------------------------------------


class _SilentLLM(LLMClient):
    """LLM whose ``generate_text`` returns "" so deterministic fallbacks drive."""

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


FetchGet = Callable[[str, dict[str, str]], Any]


def _make_agent(http_get: FetchGet | None = None) -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="methodology-ssrf-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    if http_get is not None:
        agent._http_get = http_get  # type: ignore[method-assign]
    return agent


def _resp(status: int, body: str = "", headers: dict[str, str] | None = None) -> _HTTPResponse:
    return _HTTPResponse(status=status, body=body, headers=headers or {})


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fake server-side fetchers. Each models ``_http_get(url, params)``:
#   * no params  -> a direct fetch of the origin root (the marker source).
#   * params     -> the SSRF probe; branch on the injected URL value.
# ---------------------------------------------------------------------------


def _reflecting_fetcher() -> FetchGet:
    """A fully-vulnerable fetcher that reflects the fetched body in-band."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<html><head><title>{MARKER}</title></head><body>home</body></html>")
        value = next(iter(params.values()))
        low = value.lower()
        if "169.254.169.254/latest/meta-data/iam" in low:
            return _resp(200, '{"r":{"AccessKeyId":"AKIAFAKE12345","SecretAccessKey":"sk-fake"}}')
        if "169.254.169.254/latest/meta-data" in low or "100.100.100.100" in low:
            return _resp(200, "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\npublic-keys/\n")
        if low.startswith("file://"):
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/sbin:/x\n")
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: getaddrinfo ENOTFOUND")
        if "127.0.0.1" in low or "localhost" in low or "[::1]" in low:
            return _resp(200, f"<html><title>{MARKER}</title>loopback</html>")
        return _resp(200, f"<html><title>{MARKER}</title>fetched {value}</html>")

    return http_get


def _file_only_fetcher() -> FetchGet:
    """Reflects only ``file://`` reads; metadata + loopback are unreachable."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        low = next(iter(params.values())).lower()
        if low.startswith("file://"):
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\n")
        if "169.254" in low or "100.100.100.100" in low or "metadata.google" in low:
            return _resp(502, "Error: ETIMEDOUT")
        if "127.0.0.1" in low or "localhost" in low or "[::1]" in low:
            return _resp(502, "Error: ECONNREFUSED 127.0.0.1")
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: ENOTFOUND")
        return _resp(200, f"<title>{MARKER}</title>fetched")

    return http_get


def _internal_only_fetcher() -> FetchGet:
    """Reflects http(s) fetches (incl. loopback) but no file:// and no metadata."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        low = next(iter(params.values())).lower()
        if low.startswith("file://"):
            return _resp(502, "Error: unsupported scheme")
        if "169.254" in low or "100.100.100.100" in low or "metadata.google" in low:
            return _resp(502, "Error: ETIMEDOUT")
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: ENOTFOUND")
        return _resp(200, f"<title>{MARKER}</title>internal-or-origin")

    return http_get


def _iam_only_fetcher() -> FetchGet:
    """The plain metadata listing carries no signature token; only IAM creds do."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        low = next(iter(params.values())).lower()
        if "iam/security-credentials" in low:
            return _resp(200, '{"role":{"AccessKeyId":"AKIAFAKESECRET99","SecretAccessKey":"x"}}')
        if "169.254.169.254/latest/meta-data" in low:
            return _resp(200, "no-useful-tokens-on-this-line\n")
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: ENOTFOUND")
        return _resp(200, f"<title>{MARKER}</title>")

    return http_get


def _blind_fetcher() -> FetchGet:
    """Fetches (status diverges from a non-resolving host) but never reflects."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        low = next(iter(params.values())).lower()
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: ENOTFOUND")
        # Fetched then piped to a file (Juice Shop model): 302, empty body.
        return _resp(302, "", {"Location": "/profile"})

    return http_get


def _echo_fetcher() -> FetchGet:
    """Not a fetcher at all: it merely echoes the submitted value (no fetch)."""

    async def http_get(url: str, params: dict[str, str]) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        return _resp(200, f"<html>Hello {next(iter(params.values()))}, welcome</html>")

    return http_get


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_looks_like_url():
    assert ExploitAgent._looks_like_url("http://x/") is True
    assert ExploitAgent._looks_like_url("https://x/a") is True
    assert ExploitAgent._looks_like_url("//evil") is True
    assert ExploitAgent._looks_like_url("file:///etc/passwd") is True
    assert ExploitAgent._looks_like_url("just-text") is False
    assert ExploitAgent._looks_like_url("") is False


def test_fetch_signal_strips_echoed_value():
    """A reflecting field (different value lengths) is NOT a fetch signal."""
    a = _resp(200, "Hello http://example.com/, welcome")
    junk = f"http://{_SSRF_UNFETCHABLE_HOST}/"
    b = _resp(200, f"Hello {junk}, welcome")
    assert ExploitAgent._ssrf_fetch_signal(a, "http://example.com/", b, junk) is False
    # A status flip the echo cannot explain IS a signal.
    assert ExploitAgent._ssrf_fetch_signal(_resp(302, ""), "x", _resp(502, "err"), "y") is True


def test_signature_match_rejects_payload_echo():
    """A token echoed from the URL we sent is NOT metadata (reflection guard)."""
    # 'ami-id' present, but it is part of the URL we sent -> not confirmed.
    assert (
        ExploitAgent._ssrf_signature_match(
            SSRFExploitationType.CLOUD_METADATA, "aws", "ami-id", "http://x/ami-id"
        )
        == ""
    )
    # 'ami-id' present as genuine response content (not in the sent URL) -> match.
    label = ExploitAgent._ssrf_signature_match(
        SSRFExploitationType.CLOUD_METADATA,
        "aws",
        "ami-id\ninstance-id\n",
        "http://169.254.169.254/latest/meta-data/",
    )
    assert "ami-id" in label
    # IAM creds: only the field NAME is reported, never the secret value.
    iam = ExploitAgent._ssrf_signature_match(
        SSRFExploitationType.CLOUD_METADATA,
        "aws_iam",
        '{"AccessKeyId":"AKIAFAKE"}',
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    )
    assert "AccessKeyId field present" in iam
    assert "AKIAFAKE" not in iam


# ---------------------------------------------------------------------------
# Phase 1 — injection-point mapping
# ---------------------------------------------------------------------------


def test_phase1_detects_url_fetch_param():
    agent = _make_agent(_reflecting_fetcher())
    is_candidate, cap, _ = _run(agent._ssrf_phase1_injection_point(PAGE, "url"))
    assert is_candidate is True
    assert cap.fetch_confirmed is True
    assert cap.content_reflected is True


def test_phase1_na_on_non_url_echo_param():
    """A non-URL param on a pure-echo app is not a candidate (no fetch signal)."""
    agent = _make_agent(_echo_fetcher())
    page = PageAnalysis(url="http://example.com/page", body="", status=200, input_params=["name"])
    is_candidate, cap, _ = _run(agent._ssrf_phase1_injection_point(page, "name"))
    assert is_candidate is False
    assert cap.fetch_confirmed is False
    assert cap.content_reflected is False


def test_phase1_blind_fetch_confirmed_no_reflection():
    agent = _make_agent(_blind_fetcher())
    is_candidate, cap, _ = _run(agent._ssrf_phase1_injection_point(PAGE, "url"))
    assert is_candidate is True
    assert cap.fetch_confirmed is True
    assert cap.content_reflected is False


# ---------------------------------------------------------------------------
# Phase 2 — capability fingerprinting
# ---------------------------------------------------------------------------


def test_phase2_never_probes_file_scheme():
    """file:// is LFI, not SSRF — phase 2 must not add a file scheme nor flip reflection.

    Even against a fetcher that *would* reflect a ``file://`` read, phase 2
    leaves the capability untouched: a local-file read is reported by
    ``_test_lfi``, never reclassified as SSRF (the ``/fi/?page=file://`` mislabel).
    """
    agent = _make_agent(_file_only_fetcher())
    cap = SSRFCapability(fetch_confirmed=False, content_reflected=False, schemes_allowed=["http"])
    cap = _run(agent._ssrf_phase2_fingerprint(PAGE, "url", cap))
    assert "file" not in cap.schemes_allowed
    assert cap.content_reflected is False


# ---------------------------------------------------------------------------
# Phase 3 — exploitation-type ranking
# ---------------------------------------------------------------------------


def test_phase3_blind_when_no_reflection():
    agent = _make_agent()
    cap = SSRFCapability(fetch_confirmed=True, content_reflected=False)
    ranked = _run(agent._ssrf_phase3_rank(cap))
    assert ranked == [SSRFExploitationType.BLIND_DEFERRED]


def test_phase3_ranks_inband_with_reflection():
    agent = _make_agent()
    cap = SSRFCapability(fetch_confirmed=True, content_reflected=True, schemes_allowed=["http"])
    ranked = _run(agent._ssrf_phase3_rank(cap))
    assert SSRFExploitationType.CLOUD_METADATA in ranked
    assert SSRFExploitationType.INTERNAL_SERVICE in ranked


# ---------------------------------------------------------------------------
# Phase 4 — payload synthesis (deterministic, bounded to fixed internal targets)
# ---------------------------------------------------------------------------


def test_phase4_metadata_targets():
    agent = _make_agent()
    cap = SSRFCapability(content_reflected=True, schemes_allowed=["http"])
    synth = agent._ssrf_phase4_synthesize(SSRFExploitationType.CLOUD_METADATA, cap, PAGE)
    assert synth is not None
    assert "169.254.169.254" in synth["payload"]
    assert any(t[2] == "aws_iam" for t in synth["targets"])


def test_phase4_internal_uses_page_port():
    agent = _make_agent()
    cap = SSRFCapability(content_reflected=True, schemes_allowed=["http"])
    page = PageAnalysis(
        url="http://example.com:8080/fetch", body="", status=200, input_params=["url"]
    )
    synth = agent._ssrf_phase4_synthesize(SSRFExploitationType.INTERNAL_SERVICE, cap, page)
    assert synth is not None
    assert "127.0.0.1:8080" in synth["payload"]


# ---------------------------------------------------------------------------
# Phase 5 + end-to-end — in-band verification
# ---------------------------------------------------------------------------


def test_end_to_end_cloud_metadata():
    agent = _make_agent(_reflecting_fetcher())
    findings = _run(agent._test_ssrf(PAGE))
    assert len(findings) == 1
    f = findings[0]
    assert "ssrf" in f.title.lower()
    assert f.severity.value == "critical"
    joined = " ".join(f.evidence)
    assert "exploitation_type=cloud_metadata" in joined
    assert "phases_completed=" in joined


def test_end_to_end_file_scheme_is_not_ssrf():
    """A param that only discloses a ``file://`` read is LFI — zero SSRF findings.

    The fetcher honours ``file:///etc/passwd`` but reaches no internal network
    target (metadata + loopback both fail), so there is no in-band SSRF
    confirmation. Local file disclosure here is ``_test_lfi``'s job; SSRF must
    emit nothing (the ``/fi/?page=file://`` mislabel is gone).
    """
    agent = _make_agent(_file_only_fetcher())
    findings = _run(agent._test_ssrf(PAGE))
    assert findings == []


def test_end_to_end_internal_service():
    agent = _make_agent(_internal_only_fetcher())
    findings = _run(agent._test_ssrf(PAGE))
    assert len(findings) == 1
    f = findings[0]
    assert "ssrf" in f.title.lower()
    assert f.severity.value == "high"
    assert any("exploitation_type=internal_service" in ev for ev in f.evidence)


def test_iam_credentials_redacted_in_finding():
    agent = _make_agent(_iam_only_fetcher())
    findings = _run(agent._test_ssrf(PAGE))
    assert len(findings) == 1
    blob = " ".join(findings[0].evidence)
    assert "AccessKeyId field present" in blob
    # The secret value is never persisted in the finding.
    assert "AKIAFAKESECRET99" not in blob


# ---------------------------------------------------------------------------
# Confirmation evidence — raw, bounded, independently auditable proof.
#
# The slice-1 gap: the trace preserved the confirmation CONCLUSION
# (``content_reflected=True``) but not the EVIDENCE, so genuine-vs-chrome could
# not be independently checked. A confirmation must now record the RAW reflected
# excerpt (the bytes that satisfied P3 — content we never sent) AND the control
# it was distinguished against (the without-carrier / non-resolving probe that
# did NOT reflect it). These are the unit gate for that preservation.
# ---------------------------------------------------------------------------


def _carrier_gated_fetcher() -> Callable[..., Any]:
    """Reflects loopback content ONLY when the Host carrier aligns (GeoServer model).

    Models CVE-2021-40822: the servlet's host-check guard passes only when the
    request ``Host`` header (carried as ``host_override``) equals the injected
    url's host. WITHOUT the carrier the fetch is rejected (``IllegalStateException``
    — TestWfsPost's own error chrome, no marker); WITH it, the loopback content is
    proxied back and the marker reflects in-band. Accepts ``**_`` so it tolerates
    the ``host_override`` kwarg the real ``_http_get`` consumes.
    """

    async def http_get(
        url: str, params: dict[str, str], host_override: str | None = None, **_: Any
    ) -> _HTTPResponse:
        if not params:
            return _resp(200, f"<title>{MARKER}</title>")
        value = next(iter(params.values()))
        low = value.lower()
        if _SSRF_UNFETCHABLE_HOST in low:
            return _resp(502, "Error: ENOTFOUND")
        host = urlparse(value).netloc
        if host_override != host:
            return _resp(500, "java.lang.IllegalStateException: Invalid url requested")
        return _resp(200, f"<title>{MARKER}</title>loopback-proxied")

    return http_get


def test_internal_confirmation_records_excerpt_and_differential_control():
    """A no-carrier internal-service confirm records the reflected excerpt + control."""
    agent = _make_agent(_internal_only_fetcher())
    result = _run(agent._run_ssrf_methodology(PAGE, "url"))
    assert result.verified is True
    ev = result.confirmation_evidence
    assert ev is not None
    assert ev.primitive == "P3"
    assert MARKER in ev.confirming_marker  # the internal content we never sent
    assert MARKER in ev.confirming_excerpt  # the raw reflected bytes, in context
    assert ev.control_confirms is False  # the control did NOT reflect the marker
    assert _SSRF_UNFETCHABLE_HOST in ev.control_label
    assert "ENOTFOUND" in ev.control_excerpt  # the differential control's own output
    # ...and the pair reaches the finding evidence, not only the result object.
    findings = _run(agent._test_ssrf(PAGE))
    blob = "\n".join(findings[0].evidence)
    assert "confirming_excerpt:" in blob
    assert "control_excerpt:" in blob
    assert MARKER in blob


def test_carrier_confirmation_records_without_carrier_control():
    """A carrier-bearing confirm records the WITHOUT-carrier control (IllegalStateException).

    The load-bearing proof the slice-1 trace omitted: WITH the Host-alignment
    carrier the marker reflects; the SAME probe WITHOUT it is rejected and does
    NOT reflect — so a reviewer sees the marker is fetched content, not the
    servlet's own chrome. The confirming target is the non-self-aligned loopback
    (127.0.0.1), so the carrier is genuinely load-bearing (§4.2 masking avoided).
    """
    page = PageAnalysis(
        url="http://example.com/fetch",
        body="",
        status=200,
        input_params=["url"],
        carrier_constraints=[CARRIER_ALIGN_HOST],
    )
    agent = _make_agent(_carrier_gated_fetcher())
    result = _run(agent._run_ssrf_methodology(page, "url"))
    assert result.verified is True
    assert result.exploitation_type == SSRFExploitationType.INTERNAL_SERVICE
    ev = result.confirmation_evidence
    assert ev is not None
    assert MARKER in ev.confirming_excerpt  # reflected WITH the carrier
    assert "127.0.0.1" in ev.confirming_target  # non-self-aligned target
    assert "WITHOUT the Host-alignment carrier" in ev.control_label
    assert "IllegalStateException" in ev.control_excerpt  # rejected WITHOUT the carrier
    assert ev.control_status == 500
    assert ev.control_confirms is False


def test_metadata_confirmation_excerpt_redacts_secret_value():
    """A cloud-metadata confirm records a redacted excerpt — field names, never secrets."""
    agent = _make_agent(_iam_only_fetcher())
    result = _run(agent._run_ssrf_methodology(PAGE, "url"))
    assert result.verified is True
    ev = result.confirmation_evidence
    assert ev is not None
    assert "AccessKeyId" in ev.confirming_marker  # proves access by field NAME
    assert ev.confirming_excerpt  # an excerpt was captured
    assert "<redacted>" in ev.confirming_excerpt  # the secret VALUE is masked
    # The secret value never appears in ANY stored form of the evidence.
    assert "AKIAFAKESECRET99" not in ev.model_dump_json()
    findings = _run(agent._test_ssrf(PAGE))
    assert "AKIAFAKESECRET99" not in "\n".join(findings[0].evidence)


def test_blind_deferred_emits_nothing():
    agent = _make_agent(_blind_fetcher())
    findings = _run(agent._test_ssrf(PAGE))
    assert findings == []
    result = _run(agent._run_ssrf_methodology(PAGE, "url"))
    assert result.verified is False
    assert result.blind_suspected is True
    assert result.exploitation_type is None


def test_na_no_url_param_emits_nothing():
    agent = _make_agent(_echo_fetcher())
    page = PageAnalysis(url="http://example.com/page", body="", status=200, input_params=["name"])
    findings = _run(agent._test_ssrf(page))
    assert findings == []


# ---------------------------------------------------------------------------
# Scope-interaction safety proof — the whole SSRF safety model
# ---------------------------------------------------------------------------


def test_scope_allows_inscope_request_with_internal_query_payload():
    """An in-scope request whose query VALUE is an internal address is ALLOWED.

    Clinkz connects to the in-scope target; the internal address rides as a
    parameter value. ``scope.contains`` extracts the host via urlparse, so the
    embedded internal address is never the netloc.
    """
    url = "http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
    assert SCOPE.contains(url) is True
    tool = HTTPClientTool(scope=SCOPE, engagement_id="scope-test")
    validated = tool.validate_input({"method": "GET", "url": url})
    assert validated["url"] == url  # no raise


def test_scope_allows_inscope_post_with_internal_body_payload():
    """A clean in-scope POST URL is allowed; the internal address lives in the body."""
    url = "http://example.com/profile/image/url"
    tool = HTTPClientTool(scope=SCOPE, engagement_id="scope-test")
    validated = tool.validate_input(
        {"method": "POST", "url": url, "body": "imageUrl=http://169.254.169.254/latest/meta-data/"}
    )
    assert validated["url"] == url  # body is never scope-checked


def test_scope_blocks_direct_internal_connection():
    """A DIRECT connection to an internal address is BLOCKED — the safety boundary."""
    assert SCOPE.contains("http://169.254.169.254/") is False
    assert SCOPE.contains("http://127.0.0.1:8080/") is False
    tool = HTTPClientTool(scope=SCOPE, engagement_id="scope-test")
    with pytest.raises(ValueError, match="outside the engagement scope"):
        tool.validate_input({"method": "GET", "url": "http://169.254.169.254/latest/meta-data/"})
