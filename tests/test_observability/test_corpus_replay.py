"""Standing offline regression gate over the recorded tool-invocation corpus.

Two layers, because the corpus and the baseline have different lifetimes:

* The **baseline** (``tests/fixtures/corpus_replay_baseline.json``) is committed
  and small, so the parser-behaviour assertions run everywhere, always.
* The **corpus** (``outputs/``) is local-only by policy and never committed, so
  the full sweep skips with a stated reason when it is absent rather than
  passing vacuously.

What a green run here does NOT mean is documented on
``clinkz.observability.corpus_replay`` and repeated in
``test_the_gate_states_its_own_limits`` so it cannot quietly drift out of the
module docstring.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.observability.corpus_replay import (
    DEFAULT_BASELINE,
    PARSERS,
    InvocationRecord,
    ReplayReport,
    _canonical,
    load_baseline,
    load_corpus,
    parse_record,
    replay_corpus,
)

CORPUS_ROOT = Path("outputs")

#: The four P7 DVWA engagements the baseline was derived from.
P7_ENGAGEMENTS = [
    "35511096-d613-45df-9b24-529e7e24acdd",
    "1b23a1ef-1573-491b-84a5-e033293f74c4",
    "946e7036-6ce0-47ea-95a2-bfd0b6b81046",
    "f4b0c5c8-f3cd-4025-80b7-a6f888ec4ffa",
]


def _corpus_present() -> bool:
    return any((CORPUS_ROOT / e / "tool_invocations").is_dir() for e in P7_ENGAGEMENTS)


requires_corpus = pytest.mark.skipif(
    not _corpus_present(),
    reason=(
        "recorded corpus absent — outputs/ is local-only by policy and is not "
        "committed; run an engagement to populate it"
    ),
)


# ---------------------------------------------------------------------------
# The committed baseline — runs everywhere
# ---------------------------------------------------------------------------


class TestCommittedBaseline:
    def test_the_baseline_exists_and_is_loadable(self) -> None:
        baseline = load_baseline(DEFAULT_BASELINE)
        assert baseline is not None, f"missing baseline at {DEFAULT_BASELINE}"
        assert baseline["version"] == 1
        assert baseline["entries"]

    def test_every_baseline_key_names_a_tool_we_can_still_parse(self) -> None:
        """A baseline entry for a tool with no parser can never be checked."""
        baseline = load_baseline(DEFAULT_BASELINE)
        assert baseline is not None
        for key in baseline["entries"]:
            tool = key.split(":", 1)[0]
            assert tool in PARSERS, f"baseline has {tool} but no parser is registered"

    def test_the_baseline_carries_no_credential_material(self) -> None:
        """It is derived from real engagement traffic and it is committed.

        Cookie NAMES are expected to survive — ``Set-Cookie`` appears as a
        header name and nmap reports ``PHPSESSID`` with its flags. A cookie
        VALUE must not.
        """
        from clinkz.engagement.credential_shapes import redact_shapes

        raw = DEFAULT_BASELINE.read_text(encoding="utf-8")
        assert redact_shapes(raw) == raw, (
            "the committed baseline contains a credential-shaped value; "
            "regenerate it through build_baseline (which redacts) and re-inspect"
        )

    def test_baseline_holds_only_summaries_not_response_bodies(self) -> None:
        """A body digest, never the body — the baseline is not a corpus copy."""
        baseline = load_baseline(DEFAULT_BASELINE)
        assert baseline is not None
        for key, entry in baseline["entries"].items():
            if key.startswith("http_client:"):
                assert "response_body" not in entry
                assert "raw_output" not in entry
                assert len(entry["body_sha"]) == 16


# ---------------------------------------------------------------------------
# Determinism — the property the whole gate rests on
# ---------------------------------------------------------------------------


class TestCanonicalisation:
    def test_minted_identity_is_stripped(self) -> None:
        """Parsers mint a fresh uuid per host; two parses of one input differ."""
        a = {"id": "uuid-a", "ip": "10.0.0.1", "ports": [80]}
        b = {"id": "uuid-b", "ip": "10.0.0.1", "ports": [80]}
        assert _canonical(a) == _canonical(b)

    def test_stripping_is_recursive(self) -> None:
        a = {"hosts": [{"id": "x", "ip": "10.0.0.1"}]}
        b = {"hosts": [{"id": "y", "ip": "10.0.0.1"}]}
        assert _canonical(a) == _canonical(b)

    def test_real_differences_still_differ(self) -> None:
        """Control — canonicalisation must not flatten everything."""
        a = {"id": "x", "ip": "10.0.0.1"}
        b = {"id": "x", "ip": "10.0.0.2"}
        assert _canonical(a) != _canonical(b)


# ---------------------------------------------------------------------------
# The full sweep — local only
# ---------------------------------------------------------------------------


@requires_corpus
class TestCorpusSweep:
    def test_replay_matches_the_committed_baseline(self) -> None:
        baseline = load_baseline(DEFAULT_BASELINE)
        assert baseline is not None
        report = replay_corpus(baseline, CORPUS_ROOT, engagements=P7_ENGAGEMENTS)

        # Coverage is asserted separately from correctness: a run that checked
        # nothing has no mismatches either, and must not read as a pass.
        assert report.checked > 0, "gate checked nothing — that is not a pass"
        assert report.ok, f"parser regression: {report.summary()}\n" + "\n".join(
            f"  {m['key']} {m['path']}" for m in report.mismatched[:5]
        )

    def test_parsing_the_corpus_twice_gives_the_same_answer(self) -> None:
        """Determinism, measured rather than assumed."""
        records = [
            r
            for r in load_corpus(CORPUS_ROOT, engagements=P7_ENGAGEMENTS[:1])
            if r.tool_name in PARSERS
        ][:200]
        assert records, "no replayable records found"
        for record in records:
            assert parse_record(record) == parse_record(record)

    def test_no_parser_raises_on_any_recorded_output(self) -> None:
        """6,582 real HTTP responses, including 404s and error pages."""
        failures: list[str] = []
        for record in load_corpus(CORPUS_ROOT, engagements=P7_ENGAGEMENTS):
            if record.tool_name not in PARSERS:
                continue
            try:
                parse_record(record)
            except Exception as exc:  # noqa: BLE001 — that is the finding
                failures.append(f"{record.path}: {type(exc).__name__}: {exc}")
        assert not failures, "parsers raised on recorded output:\n" + "\n".join(failures[:10])

    def test_tools_without_a_parser_are_reported_not_silently_passed(self) -> None:
        """Missing coverage is missing coverage, not a green tick."""
        baseline = load_baseline(DEFAULT_BASELINE)
        assert baseline is not None
        report = replay_corpus(baseline, CORPUS_ROOT, engagements=P7_ENGAGEMENTS)
        # web_authenticator and playwright_chromium have no parse_output seam.
        assert report.unreplayable
        assert "no-parser=" in report.summary()


# ---------------------------------------------------------------------------
# The gate must be able to fail
# ---------------------------------------------------------------------------


class TestTheGateDetectsRegressions:
    """A gate that cannot fail is decoration. These inject the failure."""

    def _record(self, stdout: str, tool: str = "http_client") -> InvocationRecord:
        return InvocationRecord(
            path=Path("synthetic"),
            engagement="synthetic",
            seq=1,
            tool_name=tool,
            stdout=stdout,
            exit_code=0,
            duration_ms=1.0,
        )

    RESPONSE = (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.67 (Debian)\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html>hello</html>\n"
        "__CURL_TIMING__0.004\n"
    )

    def test_a_changed_parse_result_is_reported_as_a_mismatch(self) -> None:
        record = self._record(self.RESPONSE)
        truth = parse_record(record)
        assert truth is not None and truth["status_code"] == 200

        # A baseline that recorded a different status: exactly the shape of a
        # parser that started mis-reading the status line.
        poisoned = {**truth, "status_code": 500}
        baseline = {"version": 1, "entries": {record.key: poisoned}}

        report = ReplayReport()
        actual = parse_record(record)
        if actual != baseline["entries"][record.key]:
            report.mismatched.append({"key": record.key, "path": "synthetic"})
        report.checked += 1

        assert not report.ok
        assert len(report.mismatched) == 1

    def test_a_status_line_regression_is_visible_in_the_parse(self) -> None:
        """The property the gate keys on: a parse defect changes the summary."""
        good = parse_record(self._record(self.RESPONSE))
        bad = parse_record(
            self._record(self.RESPONSE.replace("HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found"))
        )
        assert good is not None and bad is not None
        assert good["status_code"] != bad["status_code"]

    def test_a_dropped_header_changes_the_summary(self) -> None:
        good = parse_record(self._record(self.RESPONSE))
        bad = parse_record(
            self._record(self.RESPONSE.replace("Server: Apache/2.4.67 (Debian)\r\n", ""))
        )
        assert good is not None and bad is not None
        assert good["header_names"] != bad["header_names"]

    def test_a_body_change_changes_the_digest(self) -> None:
        good = parse_record(self._record(self.RESPONSE))
        bad = parse_record(
            self._record(self.RESPONSE.replace("<html>hello</html>", "<html>goodbye</html>"))
        )
        assert good is not None and bad is not None
        assert good["body_sha"] != bad["body_sha"]

    def test_a_throwing_parser_is_recorded_as_errored_not_matched(self, tmp_path: Path) -> None:
        """Driven through the real replay_corpus over a synthetic corpus.

        A parser that starts raising is the loudest kind of regression and must
        not be mistaken for a crash of the gate itself.
        """
        import json as _json

        import clinkz.observability.corpus_replay as mod

        def _explode(_record: InvocationRecord) -> dict[str, object]:
            raise ValueError("parser blew up")

        stdout = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody\n"
        invocations = tmp_path / "synthetic-engagement" / "tool_invocations"
        invocations.mkdir(parents=True)
        (invocations / "00001_http_client.json").write_text(
            _json.dumps({"seq": 1, "tool_name": "http_client", "stdout": stdout, "exit_code": 0}),
            encoding="utf-8",
        )

        record = self._record(stdout)
        baseline = {"version": 1, "entries": {record.key: parse_record(record)}}

        # Sanity: the gate is green before the break.
        assert replay_corpus(baseline, tmp_path).ok

        original = mod.PARSERS["http_client"]
        mod.PARSERS["http_client"] = _explode
        try:
            report = replay_corpus(baseline, tmp_path)
        finally:
            mod.PARSERS["http_client"] = original

        assert not report.ok
        assert report.errored


class TestTheGateStatesItsOwnLimits:
    def test_module_documents_what_replay_cannot_cover(self) -> None:
        """The honesty requirement, pinned so it survives an edit."""
        import clinkz.observability.corpus_replay as mod

        doc = mod.__doc__ or ""
        assert "new probe shape is not in the corpus" in doc
        assert "never a substitute for a live proof" in doc

    def test_tool_invoke_replay_is_explicitly_ruled_out_as_a_gate(self) -> None:
        """It re-executes against the live target and always exits 0."""
        import clinkz.observability.corpus_replay as mod

        doc = mod.__doc__ or ""
        assert "tool-invoke --replay" in doc
        assert "re-executes" in doc

    def test_a_truncated_record_reports_no_exit_code_rather_than_success(
        self, tmp_path: Path
    ) -> None:
        """``int(data.get("exit_code") or 0)`` said the tool succeeded.

        Zero is the strongest reading available - *the tool exited cleanly* -
        and a half-written file from an interrupted run never made that claim.
        Nothing reads the field today, which is the reason to fix it in the type
        rather than at a consumer: the first consumer to read it would inherit
        the wrong answer with nothing to notice.
        """
        import json

        invocations = tmp_path / "eng" / "tool_invocations"
        invocations.mkdir(parents=True)
        stdout = "HTTP/1.1 200 OK\r\n\r\nbody"
        (invocations / "1.json").write_text(
            json.dumps({"seq": 1, "tool_name": "http_client", "stdout": stdout}),
            encoding="utf-8",
        )
        (invocations / "2.json").write_text(
            json.dumps(
                {
                    "seq": 2,
                    "tool_name": "http_client",
                    "stdout": stdout,
                    "exit_code": 0,
                }
            ),
            encoding="utf-8",
        )
        records = {r.seq: r for r in load_corpus(tmp_path)}
        assert records[1].exit_code is None, "an absent exit code is not a zero"
        assert records[2].exit_code == 0, "a recorded zero IS a measurement"

    def test_replay_never_opens_a_socket(self) -> None:
        """Structural: the gate must be offline, not merely usually offline."""
        import socket

        record = InvocationRecord(
            path=Path("synthetic"),
            engagement="synthetic",
            seq=1,
            tool_name="http_client",
            stdout="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody\n",
            exit_code=0,
            duration_ms=1.0,
        )

        original = socket.socket

        def _forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("corpus replay attempted a network connection")

        socket.socket = _forbidden  # type: ignore[assignment]
        try:
            assert parse_record(record) is not None
        finally:
            socket.socket = original  # type: ignore[assignment]
