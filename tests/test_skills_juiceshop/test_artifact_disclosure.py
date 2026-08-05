"""No artifact may carry a usable session token — proven against a live issuer.

The unit coverage in ``tests/test_engagement/test_credential_shapes.py`` builds
a JWT by hand. That is enough to test the rules and not enough to test the
claim, because the defect was never in the rules: it was that redaction had no
notion of a token the ENGAGEMENT captures rather than the operator supplies, and
a hand-built token is still one the test author supplied.

So this suite authenticates against a real JWT-issuing target, captures the real
token the way every methodology does, drives it through the real artifact
writers, and then asserts against the bytes on disk that nothing decodes to a
payload with credential fields in it. Juice Shop is the witness here, not the
subject: it embeds the account's password hash in the token body, which is
exactly the shape that made a value-based redactor insufficient.

Marked ``juiceshop_smoke`` — part of the container gate, skipped when the target
is not running.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clinkz.engagement.artifact_scan import scan_artifact_tree
from clinkz.engagement.credential_shapes import find_shapes, jwt_payload_claim_names
from clinkz.engagement.secrets import clear_secrets
from clinkz.observability.trace import TraceWriter

pytestmark = pytest.mark.juiceshop_smoke

#: Claim names whose presence in a decodable payload makes a token credential
#: material rather than an opaque identifier.
_CREDENTIAL_CLAIMS = ("password", "totpsecret", "secret", "passwd", "token")


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_secrets()
    yield
    clear_secrets()


def _bearer(auth_headers: dict[str, str]) -> str:
    token = auth_headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        pytest.skip("no bearer token was issued")
    return token


def _decodable_credential_tokens(text: str) -> list[str]:
    """Fingerprints of every decodable JWT whose payload names a credential claim."""
    offenders: list[str] = []
    for hit in find_shapes(text):
        if hit.kind != "jwt":
            continue
        token = text[hit.start : hit.start + hit.length]
        names = [name.lower() for name in jwt_payload_claim_names(token)]
        if any(claim in name for name in names for claim in _CREDENTIAL_CLAIMS):
            offenders.append(hit.fingerprint)
    return offenders


def test_the_live_token_is_the_shape_this_guards_against(juiceshop_auth: dict[str, str]) -> None:
    """Premise check: the target really does embed credential material in its token.

    If this ever stops holding, the test below still passes but proves nothing —
    so the premise is asserted rather than assumed. A frozen vulnerable-app image
    is often years behind the cheat sheet.
    """
    token = _bearer(juiceshop_auth)
    names = [name.lower() for name in jwt_payload_claim_names(token)]

    assert names, "the live token did not decode to a claim set"
    assert any(claim in name for name in names for claim in _CREDENTIAL_CLAIMS), (
        "the live target no longer embeds credential material in its JWT; this "
        "suite is no longer exercising the shape it was written for"
    )


def test_no_artifact_carries_a_decodable_credential_token(
    juiceshop_auth: dict[str, str],
    juiceshop_url: str,
    tmp_path: Path,
) -> None:
    """The regression, against a live issuer, through the real writers.

    Drives a captured session token through every path that leaked it: the trace
    line, the full-fidelity invocation record (argv + stdout), the parsed-output
    re-write, and the step-input file.
    """
    token = _bearer(juiceshop_auth)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        writer = TraceWriter(engagement_id="js-disclosure")
        try:
            seq, _ = writer.record_tool_invocation(
                tool_name="http_client",
                exec_mode="docker",
                cwd=str(tmp_path),
                command=[
                    "curl",
                    "-s",
                    "-H",
                    f"Authorization: Bearer {token}",
                    f"{juiceshop_url}/rest/basket/1",
                ],
                stdout=json.dumps({"authentication": {"token": token, "bid": 1}}),
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
            with writer.step(agent="exploit", step_name="jwt", inputs={"bearer": token}):
                pass
        finally:
            writer.close()

        root = Path("outputs") / "js-disclosure"
        blobs = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in sorted(root.rglob("*"))
            if path.is_file()
        )
        report = scan_artifact_tree(root, engagement_id="js-disclosure")
    finally:
        os.chdir(cwd)

    assert token not in blobs, "the live session token reached an artifact verbatim"
    assert not _decodable_credential_tokens(blobs), (
        "an artifact carries a JWT that decodes to a payload with credential fields"
    )
    assert report.clean, report.render()
    assert "[REDACTED:JWT" in blobs, (
        "nothing was redacted — the token never reached the writers, so this run "
        "proves the writers are clean by accident rather than by redaction"
    )


def test_the_gate_fires_on_a_planted_live_token(
    juiceshop_auth: dict[str, str], tmp_path: Path
) -> None:
    """A gate that has never been seen to fire is not known to work."""
    token = _bearer(juiceshop_auth)
    (tmp_path / "trace.jsonl").write_text(
        json.dumps({"payload": {"cmd": f"curl -H 'Authorization: Bearer {token}'"}}) + "\n",
        encoding="utf-8",
    )

    report = scan_artifact_tree(tmp_path, engagement_id="planted")

    assert not report.clean, "the gate passed a bundle containing a live session token"
    assert "jwt" in {finding.kind for finding in report.findings}

    rendered = report.render() + report.model_dump_json()
    assert token not in rendered, "the leak report reproduced the leak"
