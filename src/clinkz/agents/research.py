"""Deterministic Research Agent (v2) — persistent brain with cross-engagement learning.

Unlike the v1 ResearchAgent (which ran a free-form ReAct loop), this agent
follows a fixed sequence of steps with LLM reasoning at key checkpoints:

    1. Query persistent KB for existing knowledge   (DETERMINISTIC)
    2. Research NEW vulns via web search             (TOOL + LLM)
    3. LLM synthesizes into actionable techniques    (REASONING)
    4. Query related technologies from persistent KB (DETERMINISTIC)
    5. LLM adapts past techniques for current target (REASONING)
    6. Persist results to engagement + persistent KB (DETERMINISTIC)
    7. Build structured result                       (CODE)

The Research Agent runs CONCURRENTLY with Scan and Exploit phases.
It also exposes ``research_additional()`` for mid-engagement tech discovery.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents.base import BaseAgent
from clinkz.llm.base import LLMClient
from clinkz.models.research import (
    AdaptedTechnique,
    ExistingKnowledge,
    NewResearch,
    ResearchResult,
    Technique,
    WebSearchResult,
)
from clinkz.models.scope import EngagementScope
from clinkz.state import StateStore
from clinkz.tools.base import ToolBase

if TYPE_CHECKING:
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.knowledge.query import KnowledgeBase
    from clinkz.research.runtime_research import RuntimeResearcher

logger = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "research_system.md"
_SYSTEM_PROMPT: str = _PROMPT_PATH.read_text(encoding="utf-8")

# Threshold: if KB has this many playbook entries with success_rate > 0.5,
# skip web research for that technology.
_COMPREHENSIVE_ENTRY_COUNT = 5
_COMPREHENSIVE_SUCCESS_RATE = 0.5


class ResearchAgent(BaseAgent):
    """Persistent brain — cross-engagement knowledge that grows over time.

    Follows the v2 deterministic-steps-with-LLM-checkpoints pattern.
    Every tool call goes through RuntimeResearcher (web search).
    Every LLM call goes through self.llm (from BaseAgent).

    Args:
        llm: LLM client for reasoning checkpoints.
        tools: Passed to BaseAgent (not used directly).
        scope: Engagement scope for target validation.
        state: SQLite state store.
        engagement_id: UUID of the active engagement.
        persistent_kb: Cross-engagement knowledge base (required for v2).
        runtime_researcher: Web search client (auto-created if not provided).
        knowledge_base: Optional knowledge base for security testing reference.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: list[ToolBase],
        scope: EngagementScope,
        state: StateStore,
        engagement_id: str,
        persistent_kb: PersistentKnowledgeBase | None = None,
        runtime_researcher: RuntimeResearcher | None = None,
        knowledge_base: KnowledgeBase | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            llm=llm,
            tools=tools,
            scope=scope,
            state=state,
            engagement_id=engagement_id,
            knowledge_base=knowledge_base,
            persistent_kb=persistent_kb,
            **kwargs,
        )
        self._runtime_researcher = runtime_researcher
        # Accumulated runbook for the engagement (grows with research_additional)
        self._runbook: list[Technique | AdaptedTechnique] = []
        self._new_kb_entries_added: int = 0

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "research"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    @property
    def max_iterations(self) -> int:
        return 10

    # ------------------------------------------------------------------
    # Lazy RuntimeResearcher creation
    # ------------------------------------------------------------------

    def _get_researcher(self) -> RuntimeResearcher:
        """Return the RuntimeResearcher, creating it lazily if needed."""
        if self._runtime_researcher is None:
            from clinkz.research.runtime_research import RuntimeResearcher

            self._runtime_researcher = RuntimeResearcher(llm=self.llm)
        return self._runtime_researcher

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Execute the 7-step deterministic research pipeline.

        Args:
            input_data: Must contain ``technologies`` (list[str]).

        Returns:
            Dict with ``result`` (ResearchResult dict), ``summary``, and ``status``.
        """
        technologies: list[str] = [str(t) for t in (input_data.get("technologies") or [])]

        if not technologies:
            self._logger.warning("ResearchAgent called with no technologies — returning early.")
            empty = ResearchResult()
            return {
                "result": empty.model_dump(mode="json"),
                "summary": "No technologies provided for research.",
                "status": "complete",
            }

        self._logger.info(
            "ResearchAgent v2 starting — %d technologies: %s",
            len(technologies),
            technologies,
        )

        # Step 1: Query persistent KB for existing knowledge (DETERMINISTIC)
        self._logger.info("Step 1: Query existing knowledge")
        existing = await self._step_query_existing_knowledge(technologies)
        self._logger.info(
            "Step 1 complete: %d playbook entries, %d past results",
            len(existing.playbook_entries),
            len(existing.past_results),
        )

        # Step 2: Research NEW vulns via web search (TOOL + LLM)
        self._logger.info("Step 2: Web research for new vulnerabilities")
        new_research = await self._step_research_new_vulns(technologies, existing)
        self._logger.info(
            "Step 2 complete: %d findings, %d CVEs",
            len(new_research.findings),
            len(new_research.cves_found),
        )

        # Step 3: LLM synthesizes into actionable techniques (REASONING)
        self._logger.info("Step 3: LLM synthesize techniques")
        techniques = await self._llm_synthesize_techniques(technologies, existing, new_research)
        self._logger.info("Step 3 complete: %d techniques synthesized", len(techniques))

        # Step 4: Query related technologies from persistent KB (DETERMINISTIC)
        self._logger.info("Step 4: Query related technologies")
        related = await self._step_query_related_technologies(technologies)
        self._logger.info(
            "Step 4 complete: %d related technique sets",
            len(related),
        )

        # Step 5: LLM adapts past techniques for current target (REASONING)
        self._logger.info("Step 5: LLM adapt related techniques")
        adapted = await self._llm_adapt_techniques(technologies, related, techniques)
        self._logger.info("Step 5 complete: %d adapted techniques", len(adapted))

        # Step 6: Persist results (DETERMINISTIC)
        self._logger.info("Step 6: Persist results to KB")
        await self._step_persist_results(self.engagement_id, technologies, techniques, adapted)
        self._logger.info(
            "Step 6 complete: %d new KB entries added",
            self._new_kb_entries_added,
        )

        # Step 7: Build structured result (CODE)
        self._logger.info("Step 7: Building result")
        result = self._build_result(technologies, existing, techniques, adapted)
        self._logger.info("ResearchAgent v2 complete for %s", technologies)

        summary = (
            f"Research complete for {len(technologies)} technologies. "
            f"Found {len(techniques)} new techniques, "
            f"adapted {len(adapted)} from related technologies. "
            f"Total runbook entries: {len(result.runbook)}."
        )

        return {
            "result": result.model_dump(mode="json"),
            "summary": summary,
            "status": "complete",
        }

    # ------------------------------------------------------------------
    # Incremental research (called mid-engagement by Orchestrator)
    # ------------------------------------------------------------------

    async def research_additional(self, new_technologies: list[str]) -> list[Technique]:
        """Research additional technologies discovered mid-engagement.

        Runs steps 1-5 for the new technologies and appends to the runbook.
        Called when Scan discovers new services/tech.

        Args:
            new_technologies: Newly discovered technology strings.

        Returns:
            List of new techniques added to the runbook.
        """
        if not new_technologies:
            return []

        self._logger.info(
            "research_additional: %d new technologies: %s",
            len(new_technologies),
            new_technologies,
        )

        existing = await self._step_query_existing_knowledge(new_technologies)
        new_research = await self._step_research_new_vulns(new_technologies, existing)
        techniques = await self._llm_synthesize_techniques(new_technologies, existing, new_research)
        related = await self._step_query_related_technologies(new_technologies)
        adapted = await self._llm_adapt_techniques(new_technologies, related, techniques)

        await self._step_persist_results(self.engagement_id, new_technologies, techniques, adapted)

        # Append to the running runbook
        all_new: list[Technique] = list(techniques)
        for a in adapted:
            # Create a merged technique from the adaptation
            merged = Technique(
                name=f"{a.original.name} (adapted for {a.target_technology})",
                description=f"{a.original.description}\n\nAdaptation: {a.adaptations}",
                steps=a.original.steps,
                vuln_class=a.original.vuln_class,
                severity=a.original.severity,
                source=a.original.source,
                source_url=a.original.source_url,
            )
            all_new.append(merged)

        self._runbook.extend(all_new)
        self._logger.info("research_additional complete: %d new techniques", len(all_new))
        return all_new

    # ------------------------------------------------------------------
    # Step 1: Query existing knowledge
    # ------------------------------------------------------------------

    async def _step_query_existing_knowledge(self, technologies: list[str]) -> ExistingKnowledge:
        """Query persistent KB for existing playbook entries and past results.

        Args:
            technologies: List of technology strings to query.

        Returns:
            ExistingKnowledge with all matching entries.
        """
        all_entries: list[dict[str, Any]] = []
        all_results: list[dict[str, Any]] = []
        covered: list[str] = []

        if self.persistent_kb is None:
            self._logger.warning("No persistent KB available — step 1 returning empty")
            return ExistingKnowledge()

        for tech in technologies:
            entries = await self.persistent_kb.get_playbook_for_technology(tech)
            results = await self.persistent_kb.get_past_results_for_technology(tech)
            if entries or results:
                covered.append(tech)
            all_entries.extend(entries)
            all_results.extend(results)

        return ExistingKnowledge(
            playbook_entries=all_entries,
            past_results=all_results,
            technologies_covered=covered,
        )

    # ------------------------------------------------------------------
    # Step 2: Research new vulns via web search
    # ------------------------------------------------------------------

    async def _step_research_new_vulns(
        self,
        technologies: list[str],
        existing: ExistingKnowledge,
    ) -> NewResearch:
        """Research new vulnerabilities for technologies not fully covered in KB.

        Skips technologies that already have comprehensive coverage
        (many entries with high success rates).

        Args:
            technologies: Technologies to research.
            existing: Existing knowledge from step 1.

        Returns:
            NewResearch with web search findings.
        """
        findings: list[WebSearchResult] = []
        cves_found: list[str] = []
        researched: list[str] = []
        researcher = self._get_researcher()

        for tech in technologies:
            # Check if KB already has comprehensive coverage
            if self._has_comprehensive_coverage(tech, existing):
                self._logger.info(
                    "Skipping web research for '%s' — comprehensive KB coverage", tech
                )
                continue

            researched.append(tech)

            # Use LLM to generate search queries
            queries = await self._llm_generate_search_queries(tech)

            for query in queries:
                self._logger.info("Web research query: %s", query)
                try:
                    result_text = await researcher.research_technology(tech)
                    # Parse CVE IDs from the result
                    import re

                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", result_text)
                    cves_found.extend(cve_matches)

                    findings.append(
                        WebSearchResult(
                            query=query,
                            results=[{"text": result_text}],
                            source_urls=[],
                        )
                    )
                except Exception as exc:
                    self._logger.warning("Web research failed for '%s': %s", query, exc)

        # Deduplicate CVEs
        cves_found = sorted(set(cves_found))

        return NewResearch(
            findings=findings,
            cves_found=cves_found,
            technologies_researched=researched,
        )

    def _has_comprehensive_coverage(self, tech: str, existing: ExistingKnowledge) -> bool:
        """Check if a technology already has comprehensive KB coverage.

        A technology is considered comprehensively covered if there are
        at least _COMPREHENSIVE_ENTRY_COUNT playbook entries with
        success_rate above _COMPREHENSIVE_SUCCESS_RATE.

        Args:
            tech: Technology string.
            existing: Existing knowledge from KB.

        Returns:
            True if coverage is comprehensive.
        """
        tech_lower = tech.lower()
        matching = [
            e
            for e in existing.playbook_entries
            if tech_lower in str(e.get("technology_pattern", "")).lower()
            or str(e.get("technology_pattern", "")).lower() in tech_lower
            or tech_lower in str(e.get("technique_name", "")).lower()
        ]
        high_success = [
            e for e in matching if (e.get("success_rate") or 0) > _COMPREHENSIVE_SUCCESS_RATE
        ]
        return len(high_success) >= _COMPREHENSIVE_ENTRY_COUNT

    async def _llm_generate_search_queries(self, technology: str) -> list[str]:
        """Use LLM to generate targeted search queries for a technology.

        Args:
            technology: Technology string (e.g., "Apache 2.4.25").

        Returns:
            List of search query strings.
        """
        prompt = (
            f"Generate 3 search queries to find recent CVEs, exploits, and "
            f"bug bounty writeups for: {technology}\n\n"
            f"Return ONLY a JSON array of query strings, nothing else.\n"
            f'Example: ["CVE {technology} exploit PoC", '
            f'"{technology} HackerOne writeup", '
            f'"{technology} penetration testing technique"]'
        )
        try:
            response = await self.llm.generate_text(prompt)
            json_start = response.find("[")
            json_end = response.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                queries = json.loads(response[json_start:json_end])
                if isinstance(queries, list):
                    return [str(q) for q in queries[:3]]
        except (json.JSONDecodeError, Exception) as exc:
            self._logger.warning("Failed to parse search queries: %s", exc)

        # Fallback: generate deterministic queries
        return [
            f"CVE {technology} exploit proof of concept",
            f"{technology} HackerOne bug bounty writeup",
            f"{technology} penetration testing techniques",
        ]

    # ------------------------------------------------------------------
    # Step 3: LLM synthesize techniques
    # ------------------------------------------------------------------

    async def _llm_synthesize_techniques(
        self,
        technologies: list[str],
        existing: ExistingKnowledge,
        new_research: NewResearch,
    ) -> list[Technique]:
        """LLM synthesizes existing knowledge + new research into techniques.

        Args:
            technologies: Target technologies.
            existing: Existing KB knowledge.
            new_research: New web research findings.

        Returns:
            List of Technique models.
        """
        # Build context for the LLM
        existing_summary = ""
        if existing.playbook_entries:
            entries_desc = []
            for e in existing.playbook_entries[:10]:
                entries_desc.append(
                    f"- {e.get('technique_name', 'unknown')}: "
                    f"{e.get('technique_description', 'N/A')[:200]}"
                )
            existing_summary = "Existing playbook entries:\n" + "\n".join(entries_desc)

        research_summary = ""
        if new_research.findings:
            research_parts = []
            for f in new_research.findings[:10]:
                text = ""
                if f.results:
                    text = str(f.results[0].get("text", ""))[:500]
                research_parts.append(f"Query: {f.query}\nFindings: {text}")
            research_summary = "New research findings:\n" + "\n\n".join(research_parts)

        cve_list = ""
        if new_research.cves_found:
            cve_list = f"CVEs found: {', '.join(new_research.cves_found)}"

        prompt = (
            "You are synthesizing security research into actionable exploitation "
            "techniques.\n\n"
            f"Technologies: {', '.join(technologies)}\n\n"
            f"{existing_summary}\n\n"
            f"{research_summary}\n\n"
            f"{cve_list}\n\n"
            "For each technique, provide a JSON array of objects with:\n"
            '- "name": short descriptive name\n'
            '- "description": detailed description with context\n'
            '- "steps": ordered list of exploitation steps\n'
            '- "vuln_class": vulnerability class (e.g., "sqli", "xss", "rce")\n'
            '- "severity": "critical", "high", "medium", "low", or "info"\n'
            '- "source": where you found this (e.g., "NVD", "HackerOne")\n'
            '- "source_url": URL if available, null otherwise\n\n'
            "Return ONLY a JSON array. Include at least one technique per "
            "technology if research found anything relevant."
        )

        try:
            response = await self.llm.generate_text(prompt)
            json_start = response.find("[")
            json_end = response.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                raw_techniques = json.loads(response[json_start:json_end])
                techniques = []
                for item in raw_techniques:
                    if isinstance(item, dict):
                        techniques.append(
                            Technique(
                                name=item.get("name", "unknown"),
                                description=item.get("description", ""),
                                steps=item.get("steps", []),
                                vuln_class=item.get("vuln_class", ""),
                                severity=item.get("severity", "info"),
                                source=item.get("source", ""),
                                source_url=item.get("source_url"),
                            )
                        )
                return techniques
        except (json.JSONDecodeError, Exception) as exc:
            self._logger.warning("Failed to parse synthesized techniques: %s", exc)

        return []

    # ------------------------------------------------------------------
    # Step 4: Query related technologies
    # ------------------------------------------------------------------

    async def _step_query_related_technologies(
        self, technologies: list[str]
    ) -> list[dict[str, Any]]:
        """Query KB for related technologies and their playbook entries.

        Args:
            technologies: Target technologies.

        Returns:
            List of dicts with related tech info and their playbook entries.
        """
        related_data: list[dict[str, Any]] = []

        if self.persistent_kb is None:
            return related_data

        for tech in technologies:
            relations = await self.persistent_kb.get_related_technologies(tech)
            for rel in relations:
                # Get the related tech name (the other side of the relation)
                related_tech = (
                    rel["tech_b"] if rel["tech_a"].lower() == tech.lower() else rel["tech_a"]
                )
                entries = await self.persistent_kb.get_playbook_for_technology(related_tech)
                if entries:
                    related_data.append(
                        {
                            "source_technology": tech,
                            "related_technology": related_tech,
                            "relation_type": rel.get("relation_type", "similar"),
                            "similarity_score": rel.get("similarity_score", 0.5),
                            "playbook_entries": entries,
                        }
                    )

        return related_data

    # ------------------------------------------------------------------
    # Step 5: LLM adapt techniques from related technologies
    # ------------------------------------------------------------------

    async def _llm_adapt_techniques(
        self,
        technologies: list[str],
        related: list[dict[str, Any]],
        current_techniques: list[Technique],
    ) -> list[AdaptedTechnique]:
        """LLM adapts techniques from related technologies for the current target.

        Args:
            technologies: Current target technologies.
            related: Related technology data from step 4.
            current_techniques: Techniques already synthesized in step 3.

        Returns:
            List of AdaptedTechnique models.
        """
        if not related:
            return []

        # Build context about related techniques
        related_summary = []
        for r in related[:5]:
            entries_desc = []
            for e in r["playbook_entries"][:3]:
                entries_desc.append(
                    f"  - {e.get('technique_name', '?')}: "
                    f"{e.get('technique_description', 'N/A')[:200]}"
                )
            related_summary.append(
                f"Related tech: {r['related_technology']} "
                f"(similarity: {r.get('similarity_score', 0.5):.1f})\n"
                f"Techniques:\n" + "\n".join(entries_desc)
            )

        # Names of techniques already synthesized (avoid duplicates)
        existing_names = {t.name for t in current_techniques}

        prompt = (
            "These techniques worked on related technologies. Adapt them "
            f"for the current target's stack: {', '.join(technologies)}.\n\n"
            "Adjust payloads, endpoints, and detection methods as needed.\n\n"
            "Related technology techniques:\n" + "\n\n".join(related_summary) + "\n\n"
            f"Already synthesized (do NOT duplicate): {', '.join(existing_names)}\n\n"
            "For each adapted technique, provide a JSON array of objects with:\n"
            '- "original_name": name of the technique being adapted\n'
            '- "original_description": brief description of the original\n'
            '- "original_steps": original steps\n'
            '- "original_vuln_class": vulnerability class\n'
            '- "original_severity": severity\n'
            '- "original_source": source\n'
            '- "adaptations": what changed for the current target\n'
            '- "target_technology": which current technology this targets\n'
            '- "confidence": 0.0-1.0 confidence this will work\n\n'
            "Return ONLY a JSON array. Skip if no meaningful adaptation is possible."
        )

        try:
            response = await self.llm.generate_text(prompt)
            json_start = response.find("[")
            json_end = response.rfind("]") + 1
            if json_start >= 0 and json_end > json_start:
                raw_adapted = json.loads(response[json_start:json_end])
                adapted = []
                for item in raw_adapted:
                    if isinstance(item, dict):
                        original = Technique(
                            name=item.get("original_name", "unknown"),
                            description=item.get("original_description", ""),
                            steps=item.get("original_steps", []),
                            vuln_class=item.get("original_vuln_class", ""),
                            severity=item.get("original_severity", "info"),
                            source=item.get("original_source", ""),
                        )
                        adapted.append(
                            AdaptedTechnique(
                                original=original,
                                adaptations=item.get("adaptations", ""),
                                target_technology=item.get("target_technology", ""),
                                confidence=min(1.0, max(0.0, float(item.get("confidence", 0.5)))),
                            )
                        )
                return adapted
        except (json.JSONDecodeError, Exception) as exc:
            self._logger.warning("Failed to parse adapted techniques: %s", exc)

        return []

    # ------------------------------------------------------------------
    # Step 6: Persist results
    # ------------------------------------------------------------------

    async def _step_persist_results(
        self,
        engagement_id: str,
        technologies: list[str],
        techniques: list[Technique],
        adapted: list[AdaptedTechnique],
    ) -> None:
        """Write new techniques to the persistent KB and engagement runbook.

        New techniques (not already in KB) are added as Tier 3 (experimental).
        Adapted techniques are NOT duplicated — they go only into the engagement
        runbook.

        Args:
            engagement_id: Current engagement ID.
            technologies: Technologies researched.
            techniques: New techniques from step 3.
            adapted: Adapted techniques from step 5.
        """
        if self.persistent_kb is None:
            self._logger.warning("No persistent KB — skipping persist step")
            return

        for tech in techniques:
            # Determine which technology pattern to use
            tech_pattern = None
            for t in technologies:
                if t.lower() in tech.name.lower() or t.lower() in tech.description.lower():
                    tech_pattern = t
                    break
            if tech_pattern is None and technologies:
                tech_pattern = technologies[0]

            # Check if this technique already exists
            existing = await self.persistent_kb.get_playbook_for_technology(tech_pattern or "")
            already_exists = any(
                e.get("technique_name", "").lower() == tech.name.lower() for e in existing
            )

            if not already_exists:
                try:
                    await self.persistent_kb.add_playbook_entry(
                        tier=3,
                        technique_name=tech.name,
                        technology_pattern=tech_pattern,
                        technique_description=tech.description,
                        steps=tech.steps,
                        source_url=tech.source_url,
                        source_type="research_agent",
                        cve_id=self._extract_cve_id(tech.name),
                        severity=tech.severity,
                        applicable_vuln_classes=[tech.vuln_class] if tech.vuln_class else None,
                        created_from_engagement=engagement_id,
                    )
                    self._new_kb_entries_added += 1
                except Exception as exc:
                    self._logger.warning("Failed to persist technique '%s': %s", tech.name, exc)

    @staticmethod
    def _extract_cve_id(text: str) -> str | None:
        """Extract a CVE ID from text if present."""
        import re

        match = re.search(r"CVE-\d{4}-\d{4,}", text)
        return match.group(0) if match else None

    # ------------------------------------------------------------------
    # Step 7: Build result
    # ------------------------------------------------------------------

    def _build_result(
        self,
        technologies: list[str],
        existing: ExistingKnowledge,
        techniques: list[Technique],
        adapted: list[AdaptedTechnique],
    ) -> ResearchResult:
        """Assemble all data into the final ResearchResult.

        Pure code — no LLM or tool calls.

        Args:
            technologies: Researched technologies.
            existing: Existing KB knowledge.
            techniques: Synthesized techniques.
            adapted: Adapted techniques.

        Returns:
            ResearchResult for the Orchestrator/Exploit Agent.
        """
        # Build combined runbook ordered by priority:
        # 1. High/critical severity first
        # 2. New techniques before adapted ones
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        runbook: list[Technique | AdaptedTechnique] = []
        runbook.extend(sorted(techniques, key=lambda t: severity_order.get(t.severity, 4)))
        runbook.extend(sorted(adapted, key=lambda a: severity_order.get(a.original.severity, 4)))

        # Also include existing KB techniques in the runbook
        for entry in existing.playbook_entries:
            vuln_classes = entry.get("applicable_vuln_classes")
            vuln_class = ""
            if isinstance(vuln_classes, list) and vuln_classes:
                vuln_class = vuln_classes[0]

            existing_tech = Technique(
                name=entry.get("technique_name", "unknown"),
                description=entry.get("technique_description", ""),
                steps=entry.get("steps", []) if isinstance(entry.get("steps"), list) else [],
                vuln_class=vuln_class,
                severity=entry.get("severity", "info"),
                source=entry.get("source_type", "persistent_kb"),
                source_url=entry.get("source_url"),
            )
            runbook.append(existing_tech)

        # Update internal runbook
        self._runbook = runbook

        return ResearchResult(
            technologies=technologies,
            existing_knowledge=existing,
            new_techniques=techniques,
            adapted_techniques=adapted,
            runbook=runbook,
            new_kb_entries_added=self._new_kb_entries_added,
        )
