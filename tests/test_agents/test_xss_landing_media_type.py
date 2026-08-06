"""A payload stored in a JSON response is stored, not executable.

The first live run in which the engine could inject into JSON request bodies
emitted three "confirmed" HIGH stored-XSS findings whose read-back was an
``application/json`` document — ``POST /api/Addresss`` with
``fullName=<img src=x onerror=…>``, read back at ``GET /api/Addresss``, labelled
``landing_context=html_body``. The target's own scoreboard marked no XSS
challenge solved, and it was right: a browser handed
``{"fullName":"<img onerror=…>"}`` under ``application/json`` (with
``X-Content-Type-Options: nosniff``, as that target sends) parses JSON and
executes nothing.

The cause was that ``_classify_landing_context`` ends in ``return "html_body"``
— the answer for "no HTML structure surrounds this" — and on a JSON response
that means "not HTML at all", not "plain HTML body". Before body injection
reached JSON APIs the case could not arise.
"""

from __future__ import annotations

from clinkz.agents.exploit import _response_is_non_executable


class TestNonExecutableMediaTypes:
    def test_data_formats_cannot_execute_markup(self) -> None:
        for media in (
            "application/json",
            "application/json; charset=utf-8",
            "text/json",
            "application/vnd.api+json",  # vendor suffix, not enumerated
            "application/xml",
            "text/xml",
            "text/csv",
            "text/plain",
            "application/octet-stream",
            "image/png",
            "application/pdf",
        ):
            assert _response_is_non_executable(media), media

    def test_markup_types_remain_executable(self) -> None:
        """The rule must never suppress a context that really does execute.

        XHTML is HTML, and an SVG navigated to directly runs its own
        ``<script>`` — both match a structured-suffix rule that would otherwise
        classify them as inert, so both are checked first.
        """
        for media in (
            "text/html",
            "text/html; charset=utf-8",
            "application/xhtml+xml",
            "image/svg+xml",
        ):
            assert not _response_is_non_executable(media), media

    def test_an_undeclared_content_type_never_vetoes(self) -> None:
        """Absence of evidence must not suppress a finding — the same guardrail
        the origin-header rule uses when the root could not be fetched."""
        assert not _response_is_non_executable(None)
        assert not _response_is_non_executable("")
        assert not _response_is_non_executable("   ")

    def test_an_unknown_media_type_is_treated_as_executable(self) -> None:
        """An allow-list of 'this is not HTML', never a deny-list of 'this is'."""
        assert not _response_is_non_executable("application/x-made-up")


class TestLandingClassification:
    def _classify(self, body: str, payload: str, content_type: str | None) -> str:
        from clinkz.agents.exploit import ExploitAgent

        agent = ExploitAgent.__new__(ExploitAgent)
        return ExploitAgent._classify_landing_context(
            agent, body, body.find(payload), payload, content_type
        )

    def test_the_live_case_is_classified_non_executable(self) -> None:
        payload = "<img src=x onerror=alert(document.domain)>"
        body = '{"status":"success","data":[{"id":1,"fullName":"' + payload + '"}]}'
        assert self._classify(body, payload, "application/json; charset=utf-8") == (
            "non_html_response"
        )

    def test_the_same_bytes_in_an_html_response_still_confirm(self) -> None:
        """The control: only the media type changed, and the verdict flips.

        This is what keeps the fix from being a blanket suppression — a genuine
        markup landing is unaffected, which is why the server-rendered baseline
        does not move.
        """
        payload = "<img src=x onerror=alert(document.domain)>"
        body = f"<html><body><p>Name: {payload}</p></body></html>"
        assert self._classify(body, payload, "text/html; charset=utf-8") == "html_body"
        assert self._classify(body, payload, None) == "html_body"
