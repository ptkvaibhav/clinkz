"""PayloadLoader — loads and queries the structured payload database.

Provides categorized test payloads for each vulnerability class so that
agents can systematically test endpoints without relying on the LLM to
generate payloads from memory.

Usage::

    loader = PayloadLoader()
    xss_payloads = loader.get_payloads("xss")
    detection = loader.get_detection_payloads("sqli")
    bypasses = loader.get_bypass_payloads("command_injection")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PAYLOADS_PATH = Path(__file__).parent / "payloads.json"


class PayloadLoader:
    """Structured payload database for vulnerability testing.

    Loads ``payloads.json`` from the knowledge directory and provides
    typed accessors for each vulnerability class and payload category.

    Thread-safe for read-only access (no mutation after ``load()``).
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        """Load payloads.json from disk.

        Called automatically on construction. Can be called again to
        reload after the file changes.
        """
        try:
            self._data = json.loads(_PAYLOADS_PATH.read_text(encoding="utf-8"))
            logger.info(
                "PayloadLoader loaded %d vulnerability classes",
                len(self._data),
            )
        except FileNotFoundError:
            logger.warning("Payload file not found: %s", _PAYLOADS_PATH)
            self._data = {}
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in %s: %s", _PAYLOADS_PATH, exc)
            self._data = {}

    @property
    def vulnerability_classes(self) -> list[str]:
        """Return all available vulnerability class names."""
        return list(self._data.keys())

    def get_payloads(self, vuln_class: str) -> dict[str, Any]:
        """Return all payload categories for a vulnerability class.

        Args:
            vuln_class: Vulnerability class key (e.g., "sqli", "xss",
                "command_injection", "lfi", "file_upload").

        Returns:
            Dict mapping category names to payload lists/values.
            Empty dict if the class is not found.
        """
        return dict(self._data.get(vuln_class, {}))

    def get_detection_payloads(self, vuln_class: str) -> list[str]:
        """Return initial detection/probe payloads for a vulnerability class.

        Looks for keys named ``detection``, ``reflected``, ``detection_checks``,
        ``internal``, or ``numeric_tests`` — whichever is the primary probe
        category for the given class.

        Args:
            vuln_class: Vulnerability class key.

        Returns:
            List of detection payload strings. Empty list if not found.
        """
        data = self._data.get(vuln_class, {})
        # Try common detection key names in priority order
        for key in ("detection", "reflected", "detection_checks", "internal", "numeric_tests"):
            if key in data:
                val = data[key]
                return list(val) if isinstance(val, list) else [str(val)]
        # Fallback: return the first list-valued category
        for val in data.values():
            if isinstance(val, list):
                return list(val)
        return []

    def get_bypass_payloads(self, vuln_class: str) -> list[str]:
        """Return filter bypass payloads for a vulnerability class.

        Looks for keys containing ``bypass``, ``wrapper``, or ``windows``.

        Args:
            vuln_class: Vulnerability class key.

        Returns:
            List of bypass payload strings. Empty list if not found.
        """
        data = self._data.get(vuln_class, {})
        result: list[str] = []
        for key, val in data.items():
            if any(term in key.lower() for term in ("bypass", "wrapper", "windows")):
                if isinstance(val, list):
                    result.extend(val)
                else:
                    result.append(str(val))
        return result

    def get_extraction_payloads(self, vuln_class: str) -> list[str]:
        """Return data extraction payloads for a vulnerability class.

        Looks for keys containing ``extraction``, ``blind``, ``stored``,
        ``webshell``, ``cloud``, or ``protocol``.

        Args:
            vuln_class: Vulnerability class key.

        Returns:
            List of extraction payload strings. Empty list if not found.
        """
        data = self._data.get(vuln_class, {})
        result: list[str] = []
        for key, val in data.items():
            if any(
                term in key.lower()
                for term in ("extraction", "blind", "stored", "webshell", "cloud", "protocol")
            ):
                if isinstance(val, list):
                    result.extend(val)
                else:
                    result.append(str(val))
        return result
