"""Runtime security research — live CVE and exploit lookup.

The Exploit Agent calls this module when it identifies a technology
stack to fetch current CVEs, PoC exploits, and bug bounty writeups.

This is intentionally decoupled from the LLM client so it can be swapped
out for different data sources (NVD API, Shodan, etc.) independently.
"""

from __future__ import annotations

import logging

import aiohttp

from clinkz.llm.base import LLMClient

logger = logging.getLogger(__name__)

# Public APIs used for CVE lookups (no auth required)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/search"


class RuntimeResearcher:
    """Performs live security research during a pentest engagement.

    Combines:
    1. NVD API — structured CVE data (CVSS scores, affected versions)
    2. LLM knowledge — exploit techniques, PoC patterns, mitigations

    Args:
        llm: LLM client for generating research summaries.
    """

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    async def research_technology(self, technology: str, version: str = "") -> str:
        """Research known vulnerabilities for a technology.

        Called by the Exploit Agent when a new service or product is identified.

        Args:
            technology: Technology name (e.g., "Apache httpd", "WordPress", "OpenSSL").
            version: Version string (e.g., "2.4.51", "5.8.1").

        Returns:
            Research summary including CVEs, exploit techniques, and mitigations.
        """
        query = f"Known vulnerabilities and exploit techniques for {technology}"
        if version:
            query += f" version {version}"
        query += (
            ". Include CVE IDs, CVSS scores, exploit techniques, PoC availability, and mitigations."
        )

        logger.info("Researching: %s %s", technology, version)

        # First, try to get structured CVE data from NVD
        cve_data = await self._fetch_nvd_cves(technology, version)

        # Then use LLM to synthesise a research summary
        prompt = f"{query}\n\nKnown CVE data from NVD:\n{cve_data}"
        summary = await self.llm.research(prompt)
        return summary

    async def research_cve(self, cve_id: str) -> str:
        """Fetch details for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345").

        Returns:
            CVE details including description, CVSS score, and exploit info.
        """
        logger.info("Looking up CVE: %s", cve_id)
        cve_data = await self._fetch_nvd_cve_by_id(cve_id)
        return await self.llm.research(
            f"Provide a detailed exploit guide for {cve_id}.\n\nCVE data: {cve_data}"
        )

    # ------------------------------------------------------------------
    # NVD API helpers
    # ------------------------------------------------------------------

    async def _fetch_nvd_cves(self, keyword: str, version: str = "") -> str:
        """Query NVD for CVEs matching a keyword.

        Args:
            keyword: Search keyword (technology name).
            version: Optional version to narrow results.

        Returns:
            JSON string of NVD results, or empty string on error.
        """
        params: dict[str, str] = {"keywordSearch": keyword, "resultsPerPage": "10"}
        if version:
            params["keywordSearch"] = f"{keyword} {version}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API_URL, params=params, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return str(data.get("vulnerabilities", [])[:5])  # top 5
                    logger.warning("NVD API returned %d", resp.status)
        except Exception as exc:
            logger.warning("NVD API request failed: %s", exc)
        return ""

    async def _fetch_nvd_cve_by_id(self, cve_id: str) -> str:
        """Fetch a single CVE by ID from NVD.

        Args:
            cve_id: Full CVE identifier.

        Returns:
            CVE JSON string, or empty string on error.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API_URL,
                    params={"cveId": cve_id},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        return str(vulns[0]) if vulns else ""
        except Exception as exc:
            logger.warning("NVD CVE lookup failed for %s: %s", cve_id, exc)
        return ""
