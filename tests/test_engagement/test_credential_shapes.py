"""Redaction by SHAPE, and the disclosure gate that checks it independently.

The defect these cover, stated once: redaction knew only what a secret IS — the
value the operator supplied and we registered. It had no notion of a token whose
payload CONTAINS secrets. A live engagement against a JWT-issuing target wrote
five session tokens into ``trace.jsonl``; one decoded to a payload carrying the
account's password hash and TOTP secret. Every writer was redacting correctly.
Nothing was registered, so nothing was removed.

Two things are asserted here and they are deliberately independent:

  * the write path removes credential SHAPES, registry or no registry;
  * the audit path re-reads the bytes and would have caught it — including on a
    deliberately planted token, because a gate that has never been seen to fire
    is not known to work.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from clinkz.engagement.artifact_scan import (
    SCAN_REPORT_FILENAME,
    SEVERITY_CREDENTIAL,
    run_disclosure_gate,
    scan_artifact_tree,
    scan_text,
)
from clinkz.engagement.credential_shapes import (
    find_shapes,
    fingerprint_jwt,
    jwt_payload_claim_names,
    redact_shapes,
    reset_fingerprint_salt,
)
from clinkz.engagement.secrets import clear_secrets, redact, redact_structure, register_secret


@pytest.fixture(autouse=True)
def _clean_registry_and_salt():
    """Both are module-level; a leak between tests is a real bug."""
    clear_secrets()
    reset_fingerprint_salt()
    yield
    clear_secrets()


# ---------------------------------------------------------------------------
# Helpers — a JWT shaped like the one the live run leaked
# ---------------------------------------------------------------------------


def _b64(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(
    *,
    alg: str = "RS256",
    claims: dict[str, object] | None = None,
    signature: str = "c2lnbmF0dXJlLWJ5dGVz",
) -> str:
    """Build an unsigned-but-well-formed JWT. Signature validity is irrelevant.

    The default claim set mirrors the shape that actually leaked: an application
    that embeds the user record — including the password hash — in the token
    body. No target name or literal appears; only the shape is reproduced.
    """
    body = (
        claims
        if claims is not None
        else {
            "status": "success",
            "data": {
                "id": 1,
                "username": "",
                "email": "operator@engagement.test",
                "password": "fa66987dc09a0b83f083cdb3b07bf7eb",
                "role": "customer",
                "totpSecret": "",
                "isActive": True,
            },
            "iat": 1754331416,
        }
    )
    return f"{_b64({'typ': 'JWT', 'alg': alg})}.{_b64(body)}.{signature}"


#: A payload claim whose presence in an artifact is the failure condition.
_CREDENTIAL_CLAIMS = ("password", "totpSecret", "secret", "passwd")


def _carries_decodable_credential_token(text: str) -> list[str]:
    """Every decodable JWT in *text* whose payload names a credential claim.

    This is the regression assertion in function form: not "no JWT-looking
    string" but "nothing that decodes to a payload with credential fields in
    it", which is the property that actually matters to a client.
    """
    offenders: list[str] = []
    for hit in find_shapes(text):
        if hit.kind != "jwt":
            continue
        token = text[hit.start : hit.start + hit.length]
        names = jwt_payload_claim_names(token)
        if any(claim in name for name in names for claim in _CREDENTIAL_CLAIMS):
            offenders.append(hit.fingerprint)
    return offenders


# ---------------------------------------------------------------------------
# The write path
# ---------------------------------------------------------------------------


def test_a_captured_session_token_is_redacted_without_being_registered() -> None:
    """The whole defect in one assertion.

    Nothing is registered — there is nothing to register, because the target
    issued this token, not the operator. Value-based redaction is structurally
    incapable of removing it.
    """
    token = _jwt()
    line = f'{{"authentication":{{"token":"{token}"}}}}'

    out = redact(line)

    assert token not in out
    assert "fa66987dc09a0b83f083cdb3b07bf7eb" not in out
    assert not _carries_decodable_credential_token(out)
    assert "[REDACTED:JWT" in out


def test_the_fingerprint_names_the_claims_without_carrying_them() -> None:
    """Enough to correlate, useless to replay — and legible about the risk.

    Naming ``password`` as a claim the token carried is what tells a reader the
    token was credential material, without the artifact being credential
    material.
    """
    token = _jwt()
    rendered = fingerprint_jwt(token)

    assert "alg=RS256" in rendered
    assert "password" in rendered, "a reader cannot see what the token carried"
    assert "fa66987dc09a0b83f083cdb3b07bf7eb" not in rendered
    assert "operator@engagement.test" not in rendered
    assert token.split(".")[1] not in rendered


def test_fingerprints_correlate_within_a_bundle() -> None:
    """Same token, same fingerprint; different token, different fingerprint.

    This is the property JWT evidence depends on: an artifact must still be able
    to say *this* token was accepted where *that* one was rejected.
    """
    a, b = _jwt(), _jwt(claims={"sub": "other", "iat": 1})

    first = redact_shapes(f"token={a}")
    again = redact_shapes(f"header={a}")
    other = redact_shapes(f"token={b}")

    assert first.split("sha256=")[1] == again.split("sha256=")[1]
    assert first.split("sha256=")[1] != other.split("sha256=")[1]


def test_a_truncated_token_is_still_a_leaked_token() -> None:
    """Trace summaries cut mid-token; the header survives, so the rule must too."""
    token = _jwt()
    truncated = token[:87]

    out = redact_shapes(f"cmd: curl -H 'Authorization: Bearer {truncated}...[truncated]'")

    assert truncated not in out
    assert "[REDACTED:JWT" in out


def test_an_authorization_header_value_goes_whether_or_not_it_is_a_jwt() -> None:
    opaque = "Bearer 8f14e45fceea167a5a36dedd4bea2543aa1b2c3d"
    inline = redact_shapes(f"curl -H 'Authorization: {opaque}' http://app.test/")
    as_value = redact_structure({"headers": {"Authorization": opaque}})
    basic = redact_shapes("Authorization: Basic YWRtaW46aHVudGVyMg==")

    assert "8f14e45fceea167a5a36dedd4bea2543aa1b2c3d" not in inline
    assert "8f14e45fceea167a5a36dedd4bea2543aa1b2c3d" not in json.dumps(as_value)
    assert "YWRtaW46aHVudGVyMg==" not in basic
    assert "Basic" in basic, "the scheme is not the secret and stays for the reader"


def test_a_cookie_keeps_its_name_and_loses_its_value() -> None:
    """A cookie NAME is evidence; a cookie VALUE is the session.

    ``Endpoint.sets_cookies`` records names precisely because a value is
    authentication material, so redaction must draw the line in the same place.
    """
    structured = redact_structure(
        {"response_headers": {"Set-Cookie": "PHPSESSID=8a1f9c2d4e6b; Path=/; HttpOnly"}}
    )
    rendered = json.dumps(structured)

    assert "PHPSESSID" in rendered, "the cookie name is evidence and must survive"
    assert "8a1f9c2d4e6b" not in rendered
    assert "HttpOnly" in rendered, "attributes are not secret"


def test_a_bare_scheme_value_with_no_header_around_it_is_covered() -> None:
    """What a header dict yields once the walker has split key from value.

    Anchored: prose that merely mentions a bearer token must survive intact, or
    every LLM prompt summary in the trace becomes unreadable.
    """
    opaque = "8f14e45fceea167a5a36dedd4bea2543"
    assert opaque not in redact_shapes(f"Bearer {opaque}")
    assert find_shapes(f"Bearer {opaque}")

    prose = "the endpoint needs a Bearer token before it will answer"
    assert redact_shapes(prose) == prose
    assert find_shapes(prose) == []


def test_a_cookie_header_in_a_joined_argv_is_covered() -> None:
    out = redact_shapes("docker exec tools curl -b token=abc123def456; -H 'Cookie: sid=deadbeef'")
    assert "abc123def456" not in out
    assert "deadbeef" not in out
    assert "sid" in out


#: Assembled at runtime, never written as a literal. The commit guard
#: (``.claude/hooks/secret_guard.py``) refuses a PEM banner in any tracked file
#: and cannot tell a fixture from a real key — correctly, so the fixture is the
#: thing that has to bend. The guard's own source dodges its own patterns the
#: same way.
_PEM_BANNER = "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5
_PEM_END = "-" * 5 + "END RSA PRIVATE KEY" + "-" * 5


def test_vendor_keys_and_private_key_blocks_are_removed() -> None:
    key_block = f"{_PEM_BANNER}\nMIIEow...\n{_PEM_END}"
    out = redact_shapes(f"config: sk-ant-{'a' * 40} and\n{key_block}")

    assert "sk-ant-" not in out
    assert "MIIEow" not in out
    assert "[REDACTED:PRIVATE_KEY]" in out


def test_redaction_is_idempotent() -> None:
    """Invocation records are re-written after parsing; a second pass must no-op."""
    once = redact_shapes(f"Authorization: Bearer {_jwt()}")
    twice = redact_shapes(once)
    assert once == twice


def test_shape_redaction_does_not_shred_the_evidence_it_travels_with() -> None:
    """The reason the write path has no entropy rule.

    This tool's evidence is made of alarming-looking strings. Redaction is
    structural and conservative on purpose; breadth lives in the scanner, where
    a false positive costs a human ten seconds instead of a finding.
    """
    evidence = (
        "payload: ' UNION SELECT username,password FROM users-- "
        "response: 5f4dcc3b5aa765d61d8327deb882cf99 "
        "note: the endpoint requires a bearer token to reach "
        "b64: aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBzZWNyZXQ="
    )
    assert redact_shapes(evidence) == evidence


def test_registered_values_are_still_redacted_alongside_shapes() -> None:
    register_secret("Rk7-Feldspar-Cinder-52")
    out = redact(f"login password=Rk7-Feldspar-Cinder-52 then token={_jwt()}")

    assert "Rk7-Feldspar-Cinder-52" not in out
    assert "[REDACTED]" in out
    assert "[REDACTED:JWT" in out


# ---------------------------------------------------------------------------
# The audit path
# ---------------------------------------------------------------------------


def test_the_scanner_fires_on_a_planted_token(tmp_path: Path) -> None:
    """A gate that has never been seen to fire is not known to work."""
    token = _jwt()
    (tmp_path / "trace.jsonl").write_text(
        json.dumps({"payload": {"cmd": f"curl -H 'Authorization: Bearer {token}'"}}),
        encoding="utf-8",
    )

    report = scan_artifact_tree(tmp_path, engagement_id="planted")

    assert not report.clean
    kinds = {finding.kind for finding in report.findings}
    assert "jwt" in kinds
    assert all(finding.severity == SEVERITY_CREDENTIAL for finding in report.findings)


def test_the_scan_report_never_reproduces_what_it_found(tmp_path: Path) -> None:
    """A leak report that contains the leak is a new artifact with the defect."""
    token = _jwt()
    (tmp_path / "trace.jsonl").write_text(f"token={token}\n", encoding="utf-8")

    report = scan_artifact_tree(tmp_path, engagement_id="planted")
    serialised = report.model_dump_json() + report.render()

    assert token not in serialised
    assert token.split(".")[1] not in serialised
    assert "fa66987dc09a0b83f083cdb3b07bf7eb" not in serialised
    assert report.findings[0].line == 1


def test_a_redacted_bundle_passes_the_gate(tmp_path: Path) -> None:
    """The write path and the audit path agree on a bundle that went through both."""
    token = _jwt()
    line = {"payload": {"cmd": f"curl -H 'Authorization: Bearer {token}'"}}
    (tmp_path / "trace.jsonl").write_text(
        json.dumps(redact_structure(line)),
        encoding="utf-8",
    )

    report = scan_artifact_tree(tmp_path, engagement_id="redacted")

    assert report.clean, report.render()


def test_the_gate_writes_its_verdict_beside_the_artifacts(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_text('{"findings": []}', encoding="utf-8")

    report = run_disclosure_gate(tmp_path, engagement_id="eng-1")

    written = tmp_path / SCAN_REPORT_FILENAME
    assert written.is_file()
    assert report.clean
    assert "CLEAN" in report.summary_line()

    # Idempotent: the gate does not scan its own output and find itself.
    again = run_disclosure_gate(tmp_path, engagement_id="eng-1")
    assert again.clean
    assert again.files_scanned == report.files_scanned


def test_the_entropy_heuristic_is_advisory_and_never_fails_the_gate(tmp_path: Path) -> None:
    """Reported so a human can look, not so a machine can block.

    A gate that cried wolf on this tool's own evidence would be silenced within
    a week, which is the same as not having one.
    """
    findings, suspicions = scan_text("blob=Xk92mQvT4bRp7Ls0YwZa3NcE8UdHjF6i")

    assert findings == []
    assert suspicions and suspicions[0].kind == "entropy"

    (tmp_path / "trace.jsonl").write_text("blob=Xk92mQvT4bRp7Ls0YwZa3NcE8UdHjF6i", encoding="utf-8")
    report = scan_artifact_tree(tmp_path)
    assert report.clean
    assert report.suspicions


def test_uuids_and_digests_are_not_reported_as_suspicious() -> None:
    """This system generates both by the thousand; reporting them buries the signal."""
    _, suspicions = scan_text(
        "engagement=8bc05d0e-4c6d-4f4e-b344-820634e31908 "
        "digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )
    assert suspicions == []


# ---------------------------------------------------------------------------
# End to end through the real writers
# ---------------------------------------------------------------------------


def test_no_writer_puts_a_decodable_credential_token_on_disk(tmp_path: Path) -> None:
    """The regression, end to end, through the writers that actually leaked.

    Drives the trace writer, the invocation recorder and the step-input
    recorder with a live-shaped session token — as the auth path and every
    subsequent probe do — then asserts against the bytes on disk that nothing
    decodes to a payload with credential fields in it.
    """
    from clinkz.observability.trace import TraceWriter

    token = _jwt()
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        writer = TraceWriter(engagement_id="eng-shape")
        try:
            seq, _ = writer.record_tool_invocation(
                tool_name="http_client",
                exec_mode="docker",
                cwd=str(tmp_path),
                command=["curl", "-H", f"Authorization: Bearer {token}", "http://app.test/api"],
                stdout=json.dumps({"authentication": {"token": token}}),
            )
            writer.tool_call(
                stage="exploit",
                cmd=["curl", "-H", f"Authorization: Bearer {token}"],
                stdout_summary=json.dumps({"token": token}),
                exit_code=0,
            )
            writer.attach_parsed_output(
                seq=seq,
                parsed_output_type="HTTPResponse",
                parsed_output={"response_headers": {"Set-Cookie": f"token={token}; Path=/"}},
                parse_succeeded=True,
            )
            with writer.step(agent="exploit", step_name="probe", inputs={"session": token}):
                pass
        finally:
            writer.close()

        root = Path("outputs") / "eng-shape"
        combined = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in root.rglob("*")
            if path.is_file()
        )
        report = scan_artifact_tree(root, engagement_id="eng-shape")
    finally:
        os.chdir(cwd)

    assert token not in combined, "a live session token reached an artifact"
    assert not _carries_decodable_credential_token(combined), (
        "an artifact carries a JWT that decodes to a payload with credential fields"
    )
    assert report.clean, report.render()
