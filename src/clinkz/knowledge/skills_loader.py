"""Skills loader — provides agents with documented procedures for specific tasks.

Skills are markdown files in knowledge/skills/ that describe step-by-step
procedures for common pentesting tasks (e.g., CSRF token extraction, SQLi
column count determination, XSS context analysis).  Agents request skills
at runtime via the ``get_skill_reference`` meta-tool so the LLM reads the
relevant procedure before acting.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory containing skill markdown files.
_SKILLS_DIR = Path(__file__).parent / "skills"

# Keyword → skill name mapping for basic relevance matching.
_SKILL_KEYWORDS: dict[str, list[str]] = {
    "csrf_token_extraction": [
        "csrf", "login", "authenticate", "token", "session", "cookie",
    ],
    "sqli_column_count": [
        "sqli", "sql injection", "union", "column", "order by", "select",
    ],
    "session_management": [
        "session", "cookie", "authenticated", "login", "expire", "re-auth",
    ],
    "response_analysis": [
        "response", "analyze", "size", "error", "reflection", "timing",
        "status code", "baseline",
    ],
    "behavior_observation": [
        "observe", "behavior", "baseline", "classify", "hypothesis",
        "probe", "understand",
    ],
    "xss_context_analysis": [
        "xss", "cross-site scripting", "reflected", "stored", "dom",
        "canary", "context", "script", "attribute",
    ],
    "lfi_exploitation": [
        "lfi", "local file inclusion", "file inclusion", "path traversal",
        "directory traversal", "php://filter", "etc/passwd",
    ],
    "file_upload_bypass": [
        "upload", "file upload", "webshell", "php upload", "extension",
        "content-type", "magic bytes",
    ],
    "command_injection": [
        "command injection", "os command", "rce", "remote code execution",
        "exec", "system", "shell", "ping", "semicolon",
    ],
    "idor_testing": [
        "idor", "insecure direct object", "object reference", "authorization",
        "access control", "horizontal", "vertical", "privilege escalation",
    ],
    "ssrf_testing": [
        "ssrf", "server-side request forgery", "url fetch", "metadata",
        "internal", "localhost", "cloud", "webhook",
    ],
}


class SkillsLoader:
    """Loads and queries agent skills from markdown files.

    Skills are documented procedures that agents reference at runtime to
    perform specific tasks correctly.  The LLM reads the skill content
    before acting, ensuring it follows the correct procedure.

    Args:
        skills_dir: Path to the skills directory.  Defaults to the built-in
            ``knowledge/skills/`` directory.
    """

    def __init__(self, skills_dir: Path | None = None) -> None:
        self._skills_dir = skills_dir or _SKILLS_DIR

    def load_skill(self, skill_name: str) -> str:
        """Load a skill's markdown content by name.

        Args:
            skill_name: Skill identifier (filename without .md extension).

        Returns:
            The full markdown content of the skill.

        Raises:
            FileNotFoundError: If the skill file does not exist.
        """
        skill_path = self._skills_dir / f"{skill_name}.md"
        if not skill_path.exists():
            available = self.list_skills()
            raise FileNotFoundError(
                f"Skill '{skill_name}' not found. Available skills: {available}"
            )
        content = skill_path.read_text(encoding="utf-8")
        logger.debug("Loaded skill '%s' (%d chars)", skill_name, len(content))
        return content

    def list_skills(self) -> list[str]:
        """List all available skill names.

        Returns:
            Sorted list of skill identifiers (filenames without .md).
        """
        if not self._skills_dir.exists():
            return []
        return sorted(p.stem for p in self._skills_dir.glob("*.md"))

    def get_skills_for_task(self, task: str) -> list[str]:
        """Suggest relevant skills based on keyword matching.

        Performs case-insensitive keyword matching against the task
        description to find skills that are likely relevant.

        Args:
            task: Free-text task description or context string.

        Returns:
            List of skill names ranked by keyword match count (best first).
        """
        task_lower = task.lower()
        scored: list[tuple[str, int]] = []

        for skill_name, keywords in _SKILL_KEYWORDS.items():
            # Only suggest skills that actually exist on disk.
            skill_path = self._skills_dir / f"{skill_name}.md"
            if not skill_path.exists():
                continue

            score = sum(1 for kw in keywords if kw in task_lower)
            if score > 0:
                scored.append((skill_name, score))

        # Sort by score descending, then alphabetically for stability.
        scored.sort(key=lambda x: (-x[1], x[0]))
        return [name for name, _score in scored]

    def get_skill_names_summary(self) -> str:
        """Return a formatted summary of available skills for injection into prompts.

        Returns:
            Markdown-formatted list of skill names with brief descriptions.
        """
        skills = self.list_skills()
        if not skills:
            return "No skills available."

        lines = ["Available skills (use `get_skill_reference` to read any skill):"]
        for skill_name in skills:
            # Convert skill_name to human-readable label.
            label = skill_name.replace("_", " ").title()
            lines.append(f"- `{skill_name}` — {label}")
        return "\n".join(lines)
