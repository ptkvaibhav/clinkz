"""Every config example in the docs is loaded through its REAL validator.

The CLI is in good shape because ``test_every_documented_flag_is_actually_accepted``
reads ``--help`` and asserts each documented flag is accepted. Config files had
no equivalent, and config files are where a first-time user actually starts.

The instance that prompted this was ``login_url``. It exists — on
:class:`~clinkz.models.engagement.RoleCredential`, per role — and it appeared in
no example, no ``--help`` text and no document, only in the model's docstring.
An operator who needed it guessed, and until ``extra="forbid"`` every guess
*parsed cleanly and did nothing*: Pydantic ignores unknown keys by default, so a
top-level ``login_url`` in the credential file validated, changed no behaviour,
and the engagement then hard-aborted on an unprovable session with nothing
connecting the two. Three correct-looking attempts, three silent no-ops, one
hard block, no diagnostic. That is what a client trial hits on day one.

So this test is about the CLASS, not the instance:

* Every ``json`` fenced block in ``README.md`` and ``docs/`` that is recognisably
  one of our config documents is validated by the model that actually loads it.
  A documented example that the loader would reject is a red build.
* ``.env.example`` is loaded through ``Settings.from_env`` — the same function a
  run calls — so a variable documented with an invalid value fails here rather
  than at engagement start.
* The recogniser itself is asserted, because a matcher that silently matches
  nothing turns this whole file green and vacuous.
"""

from __future__ import annotations

import json
import os
import pathlib
import re

import pytest

from clinkz.config import Settings
from clinkz.models.engagement import (
    AuthorizationRecord,
    BenchmarkProfile,
    CredentialSet,
    EngagementWindow,
)
from clinkz.models.scope import EngagementScope

_ROOT = pathlib.Path(__file__).resolve().parents[2]

_JSON_FENCE = re.compile(r"```json\s*\n(.*?)```", re.DOTALL)

#: A documented example is matched to its loader by a key only that document
#: has. Keyed on a REQUIRED field, so a partial example cannot be matched to the
#: wrong model — and the first matching entry wins, so order is significant.
_RECOGNISERS: tuple[tuple[str, type], ...] = (
    ("authorizing_party", AuthorizationRecord),
    ("credentials", CredentialSet),
    ("acknowledgement", BenchmarkProfile),
    ("targets", EngagementScope),
    ("starts_at", EngagementWindow),
)


def _documentation_files() -> list[pathlib.Path]:
    files = [_ROOT / "README.md", _ROOT / "CLAUDE.md", _ROOT / "CONTRIBUTING.md"]
    files.extend(sorted((_ROOT / "docs").rglob("*.md")))
    return [f for f in files if f.is_file()]


def _config_examples() -> list[tuple[pathlib.Path, int, type, dict]]:
    """``(path, line, model, payload)`` for every recognisable config example."""
    found: list[tuple[pathlib.Path, int, type, dict]] = []
    for path in _documentation_files():
        text = path.read_text(encoding="utf-8")
        for match in _JSON_FENCE.finditer(text):
            line = text[: match.start()].count("\n") + 1
            try:
                payload = json.loads(match.group(1))
            except json.JSONDecodeError:
                # Not every ```json block is a config document — several are
                # illustrative record shapes with elisions. Malformed JSON is
                # caught by its own test below so it cannot hide here.
                continue
            if not isinstance(payload, dict):
                continue
            for key, model in _RECOGNISERS:
                if key in payload:
                    found.append((path, line, model, payload))
                    break
    return found


def _env_example_pairs() -> dict[str, str]:
    pairs: dict[str, str] = {}
    for raw in (_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        pairs[key.strip()] = value.strip()
    return pairs


class TestTheScannerWorks:
    """A matcher that matches nothing makes every test below vacuous."""

    def test_documentation_files_are_found(self) -> None:
        assert len(_documentation_files()) >= 5

    def test_the_known_examples_are_recognised(self) -> None:
        examples = _config_examples()
        models = {model for _p, _l, model, _d in examples}
        assert AuthorizationRecord in models, "the auth.json example is not being found"
        assert CredentialSet in models, "the credential-file example is not being found"

    def test_env_example_is_read(self) -> None:
        pairs = _env_example_pairs()
        assert "ANTHROPIC_API_KEY" in pairs
        assert len(pairs) >= 10


class TestEveryDocumentedExampleLoads:
    def test_every_config_example_passes_its_real_validator(self) -> None:
        failures: list[str] = []
        for path, line, model, payload in _config_examples():
            try:
                model.model_validate(payload)
            except Exception as exc:  # noqa: BLE001 — the whole point is to report it
                failures.append(
                    f"{path.relative_to(_ROOT)}:{line} -> {model.__name__}: "
                    f"{str(exc).splitlines()[0]}"
                )
        assert not failures, (
            "These documented examples do not load. A user working from "
            "documentation alone hits exactly this, and a config file has no "
            "--help to check it against:\n  " + "\n  ".join(failures)
        )

    def test_every_json_fence_in_a_config_document_is_valid_json(self) -> None:
        """A malformed example is a hard block before any validator sees it."""
        config_docs = {
            _ROOT / "README.md",
            _ROOT / "docs" / "productization-engagement-safety.md",
        }
        broken: list[str] = []
        for path in config_docs:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for match in _JSON_FENCE.finditer(text):
                line = text[: match.start()].count("\n") + 1
                try:
                    json.loads(match.group(1))
                except json.JSONDecodeError as exc:
                    broken.append(f"{path.relative_to(_ROOT)}:{line} -> {exc}")
        assert not broken, "\n  " + "\n  ".join(broken)

    def test_env_example_loads_through_the_real_settings_loader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``Settings.from_env`` is what a run calls, so it is what this calls.

        Validating the values by hand would test a second implementation of the
        loader and pass while the real one refused — the ``gemini_thinking_level``
        validator, for instance, rejects a value the SDK's own enum offers.
        """
        for key, value in _env_example_pairs().items():
            monkeypatch.setenv(key, value)
        settings = Settings.from_env()
        assert settings.llm_provider_priority[0] == "anthropic"

    def test_every_env_example_variable_is_one_the_loader_reads(self) -> None:
        """A documented variable nothing reads is a silent no-op, the same class.

        Asserted against the loader's source rather than a hand-kept list, so a
        variable that stops being read fails here instead of quietly doing
        nothing in every deployment that set it.
        """
        source = (_ROOT / "src" / "clinkz" / "config.py").read_text(encoding="utf-8")
        unread = sorted(key for key in _env_example_pairs() if f'"{key}"' not in source)
        assert not unread, (
            "These variables are documented in .env.example and read by nothing "
            f"in config.py — setting them does nothing at all: {unread}"
        )


class TestTheLoginUrlInstance:
    """The specific defect, kept as a regression alongside the class fix."""

    def test_login_url_on_a_role_is_accepted(self) -> None:
        creds = CredentialSet.model_validate(
            {
                "credentials": [
                    {
                        "role": "admin",
                        "username": "a@example.com",
                        "password": "pw",
                        "login_url": "https://app.example.com/rest/user/login",
                    }
                ]
            }
        )
        assert creds.credentials[0].login_url == "https://app.example.com/rest/user/login"

    def test_login_url_at_the_top_level_is_refused_by_name(self) -> None:
        """It used to validate and do nothing. Now it says where the key goes."""
        with pytest.raises(Exception) as excinfo:
            CredentialSet.model_validate(
                {
                    "login_url": "https://app.example.com/login",
                    "credentials": [{"role": "admin", "username": "a", "password": "b"}],
                }
            )
        message = str(excinfo.value)
        assert "login_url" in message
        assert "inside 'credentials'" in message

    def test_a_typo_on_a_role_is_refused_rather_than_dropped(self) -> None:
        with pytest.raises(Exception) as excinfo:
            CredentialSet.model_validate(
                {"credentials": [{"role": "admin", "loginUrl": "https://app/login"}]}
            )
        assert "loginUrl" in str(excinfo.value)

    def test_login_url_is_documented_somewhere_a_user_will_read(self) -> None:
        """The field existed and worked. Nothing said it existed.

        A model docstring is not documentation for an operator writing a JSON
        file, and this is the whole reason the block happened.
        """
        documented_in = [
            path.name
            for path in _documentation_files()
            if "login_url" in path.read_text(encoding="utf-8")
        ]
        assert documented_in, (
            "login_url appears in no README or docs/ file. It is the field that "
            "makes an undiscoverable login survivable, and an operator who "
            "cannot find it gets a hard abort instead."
        )

    def test_assert_url_is_documented_too(self) -> None:
        documented_in = [
            path.name
            for path in _documentation_files()
            if "assert_url" in path.read_text(encoding="utf-8")
        ]
        assert documented_in, "assert_url is undocumented — the same defect, one field over"


class TestTheEnvironmentIsNotMutated:
    """This file sets environment variables; nothing may leak out of it."""

    def test_settings_load_did_not_leave_variables_behind(self) -> None:
        assert os.environ.get("CLINKZ_RUN_MODE") in (None, "client", "baseline")
