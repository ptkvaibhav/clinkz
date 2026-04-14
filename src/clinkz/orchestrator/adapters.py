"""Temporary adapters: v2 ScanResult/ResearchResult → v1 Exploit Agent format.

These adapters bridge the gap between the new deterministic agents (which produce
typed Pydantic models) and the existing Exploit Agent (which reads plain dicts
from ``input_data``).  They will be removed when the Exploit Agent is rewritten
in Phase 3.
"""

from __future__ import annotations

from typing import Any

from clinkz.models.research import AdaptedTechnique, ResearchResult, Technique
from clinkz.models.scan import (
    HTTPScanResult,
    ScanResult,
)


def adapt_scan_result_for_exploit(scan_result: ScanResult | dict[str, Any]) -> dict[str, Any]:
    """Convert v2 ScanResult to the format the v1 Exploit Agent expects.

    The Exploit Agent reads from ``input_data`` the following keys:
      - ``endpoints``: list of endpoint dicts (url, method, params…)
      - ``hosts``: list of host/service dicts
      - ``technologies``: list of technology strings

    Args:
        scan_result: A v2 ScanResult object or its serialised dict.

    Returns:
        Dict with ``endpoints``, ``hosts``, ``technologies`` keys.
    """
    if isinstance(scan_result, dict):
        scan_result = ScanResult.model_validate(scan_result)

    endpoints: list[dict[str, Any]] = []
    technologies: list[str] = []

    for svc_scan in scan_result.service_scans:
        result = svc_scan.result
        if isinstance(result, HTTPScanResult):
            for ep in result.endpoints:
                endpoints.append(
                    {
                        "url": ep.url,
                        "method": ep.method,
                        "params": ep.params,
                        "status_code": ep.status_code,
                    }
                )
            for form in result.forms:
                endpoints.append(
                    {
                        "url": form.action,
                        "method": form.method,
                        "params": [f.name for f in form.fields],
                        "has_csrf_token": form.has_csrf_token,
                    }
                )
            technologies.extend(result.technologies_detected)

    return {
        "endpoints": endpoints,
        "hosts": [
            {
                "ip": scan_result.target,
                "services": [
                    {
                        "port": svc.port,
                        "service_type": svc.service_type,
                    }
                    for svc in scan_result.service_scans
                ],
            }
        ],
        "technologies": sorted(set(technologies)),
    }


def adapt_research_result_for_exploit(
    research_result: ResearchResult | dict[str, Any],
) -> dict[str, Any]:
    """Convert v2 ResearchResult to runbook format the v1 Exploit Agent can use.

    The Exploit Agent reads ``recon_findings`` and optionally ``technologies``
    from its ``input_data``.  It also reads the per-engagement runbook from
    the shared state store (populated by the Research Agent directly).

    This adapter provides an in-memory summary that supplements the DB-persisted
    runbook, so the Exploit Agent has immediate access to research insights
    without needing a DB round-trip.

    Args:
        research_result: A v2 ResearchResult object or its serialised dict.

    Returns:
        Dict with ``technologies``, ``techniques`` (list of technique dicts).
    """
    if isinstance(research_result, dict):
        research_result = ResearchResult.model_validate(research_result)

    def _technique_to_dict(t: Technique | AdaptedTechnique) -> dict[str, Any]:
        if isinstance(t, AdaptedTechnique):
            return {
                "name": t.original.name,
                "description": t.original.description,
                "steps": t.original.steps,
                "vuln_class": t.original.vuln_class,
                "severity": t.original.severity,
                "source": t.original.source,
                "adapted_for": t.target_technology,
                "adaptations": t.adaptations,
                "confidence": t.confidence,
            }
        return {
            "name": t.name,
            "description": t.description,
            "steps": t.steps,
            "vuln_class": t.vuln_class,
            "severity": t.severity,
            "source": t.source,
        }

    techniques = [_technique_to_dict(t) for t in research_result.runbook]

    return {
        "technologies": research_result.technologies,
        "techniques": techniques,
    }
