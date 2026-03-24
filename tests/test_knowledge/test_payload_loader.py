"""Tests for PayloadLoader — structured payload database for vulnerability testing."""

from __future__ import annotations

import pytest

from clinkz.knowledge.payload_loader import PayloadLoader


@pytest.fixture(scope="module")
def loader() -> PayloadLoader:
    """Load the PayloadLoader once for all tests in this module."""
    return PayloadLoader()


# ------------------------------------------------------------------
# Data loading
# ------------------------------------------------------------------


class TestDataLoading:
    """Verify payloads.json loads correctly."""

    def test_loader_loads_without_error(self, loader: PayloadLoader) -> None:
        """PayloadLoader should load without errors."""
        assert loader is not None
        assert len(loader.vulnerability_classes) > 0

    def test_all_expected_classes_present(self, loader: PayloadLoader) -> None:
        """All documented vulnerability classes should be present."""
        expected = {
            "sqli", "xss", "command_injection", "lfi", "file_upload",
            "csrf", "brute_force", "idor", "ssrf", "session", "xxe",
        }
        actual = set(loader.vulnerability_classes)
        assert expected <= actual, f"Missing classes: {expected - actual}"


# ------------------------------------------------------------------
# get_payloads
# ------------------------------------------------------------------


class TestGetPayloads:
    """Tests for get_payloads()."""

    def test_sqli_returns_categories(self, loader: PayloadLoader) -> None:
        """SQLi payloads should have detection, extraction, blind categories."""
        payloads = loader.get_payloads("sqli")
        assert "detection" in payloads
        assert "extraction" in payloads
        assert "blind_boolean" in payloads
        assert "blind_time" in payloads

    def test_xss_returns_categories(self, loader: PayloadLoader) -> None:
        """XSS payloads should have reflected, stored, dom, filter_bypass."""
        payloads = loader.get_payloads("xss")
        assert "reflected" in payloads
        assert "stored" in payloads
        assert "dom" in payloads
        assert "filter_bypass" in payloads

    def test_unknown_class_returns_empty(self, loader: PayloadLoader) -> None:
        """Unknown vulnerability class should return empty dict."""
        assert loader.get_payloads("nonexistent") == {}

    def test_command_injection_has_detection(self, loader: PayloadLoader) -> None:
        """Command injection should have detection payloads."""
        payloads = loader.get_payloads("command_injection")
        assert "detection" in payloads
        assert len(payloads["detection"]) > 0

    def test_lfi_has_php_wrappers(self, loader: PayloadLoader) -> None:
        """LFI should have PHP wrapper payloads."""
        payloads = loader.get_payloads("lfi")
        assert "php_wrappers" in payloads

    def test_file_upload_has_extensions(self, loader: PayloadLoader) -> None:
        """File upload should have extensions and webshells."""
        payloads = loader.get_payloads("file_upload")
        assert "extensions" in payloads
        assert "webshells" in payloads

    def test_ssrf_has_cloud_metadata(self, loader: PayloadLoader) -> None:
        """SSRF should have cloud metadata payloads."""
        payloads = loader.get_payloads("ssrf")
        assert "cloud_metadata" in payloads


# ------------------------------------------------------------------
# get_detection_payloads
# ------------------------------------------------------------------


class TestGetDetectionPayloads:
    """Tests for get_detection_payloads()."""

    def test_sqli_detection(self, loader: PayloadLoader) -> None:
        """SQLi detection payloads should include classic probes."""
        detection = loader.get_detection_payloads("sqli")
        assert len(detection) > 0
        assert "'" in detection

    def test_xss_detection(self, loader: PayloadLoader) -> None:
        """XSS detection payloads should include script tags."""
        detection = loader.get_detection_payloads("xss")
        assert len(detection) > 0
        assert any("script" in p.lower() for p in detection)

    def test_command_injection_detection(self, loader: PayloadLoader) -> None:
        """Command injection detection should include ; id."""
        detection = loader.get_detection_payloads("command_injection")
        assert "; id" in detection

    def test_lfi_detection(self, loader: PayloadLoader) -> None:
        """LFI detection should include etc/passwd traversal."""
        detection = loader.get_detection_payloads("lfi")
        assert any("etc/passwd" in p for p in detection)

    def test_ssrf_detection(self, loader: PayloadLoader) -> None:
        """SSRF detection should include localhost variants."""
        detection = loader.get_detection_payloads("ssrf")
        assert any("127.0.0.1" in p for p in detection)

    def test_unknown_class_returns_empty(self, loader: PayloadLoader) -> None:
        """Unknown class should return empty list."""
        assert loader.get_detection_payloads("nonexistent") == []


# ------------------------------------------------------------------
# get_bypass_payloads
# ------------------------------------------------------------------


class TestGetBypassPayloads:
    """Tests for get_bypass_payloads()."""

    def test_xss_bypass(self, loader: PayloadLoader) -> None:
        """XSS should have filter bypass payloads."""
        bypasses = loader.get_bypass_payloads("xss")
        assert len(bypasses) > 0

    def test_command_injection_bypass(self, loader: PayloadLoader) -> None:
        """Command injection should have filter bypass payloads."""
        bypasses = loader.get_bypass_payloads("command_injection")
        assert len(bypasses) > 0

    def test_lfi_bypass_includes_wrappers_and_windows(self, loader: PayloadLoader) -> None:
        """LFI bypass payloads should include PHP wrappers and Windows paths."""
        bypasses = loader.get_bypass_payloads("lfi")
        assert len(bypasses) > 0
        combined = " ".join(bypasses)
        assert "php://" in combined or "windows" in combined.lower()

    def test_sqli_no_bypass_category(self, loader: PayloadLoader) -> None:
        """SQLi has no explicit 'bypass' category, should return empty."""
        bypasses = loader.get_bypass_payloads("sqli")
        assert bypasses == []


# ------------------------------------------------------------------
# get_extraction_payloads
# ------------------------------------------------------------------


class TestGetExtractionPayloads:
    """Tests for get_extraction_payloads()."""

    def test_sqli_extraction(self, loader: PayloadLoader) -> None:
        """SQLi should have extraction and blind payloads."""
        extraction = loader.get_extraction_payloads("sqli")
        assert len(extraction) > 0
        combined = " ".join(extraction)
        assert "UNION" in combined or "SLEEP" in combined or "blind" in combined.lower()

    def test_xss_stored(self, loader: PayloadLoader) -> None:
        """XSS should include stored payloads in extraction."""
        extraction = loader.get_extraction_payloads("xss")
        assert len(extraction) > 0

    def test_ssrf_extraction(self, loader: PayloadLoader) -> None:
        """SSRF should include cloud metadata and protocol payloads."""
        extraction = loader.get_extraction_payloads("ssrf")
        assert len(extraction) > 0

    def test_file_upload_extraction(self, loader: PayloadLoader) -> None:
        """File upload should include webshell payloads."""
        extraction = loader.get_extraction_payloads("file_upload")
        assert len(extraction) > 0


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests."""

    def test_multiple_instantiation(self) -> None:
        """Creating multiple PayloadLoader instances should work."""
        l1 = PayloadLoader()
        l2 = PayloadLoader()
        assert l1.vulnerability_classes == l2.vulnerability_classes

    def test_get_payloads_returns_copy(self, loader: PayloadLoader) -> None:
        """get_payloads should return a copy, not the internal dict."""
        p1 = loader.get_payloads("sqli")
        p2 = loader.get_payloads("sqli")
        assert p1 == p2
        p1["new_key"] = "test"
        p3 = loader.get_payloads("sqli")
        assert "new_key" not in p3
