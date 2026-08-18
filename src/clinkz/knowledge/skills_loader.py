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
