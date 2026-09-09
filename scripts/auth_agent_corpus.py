#!/usr/bin/env python3
"""Replay the adaptive-auth observer and gate over stored login exchanges. Offline.

Two questions, and they fail for different reasons.

**Is the briefing non-vacuous on real data?** The agent's whole claim is that the
deterministic pass already knows enough for a model to recognise a stack from —
and that claim is checkable without a network, because every recorded engagement
that ran a login kept the login page's own bytes. This driver rebuilds the
:class:`~clinkz.engagement.auth_agent.AuthObservation` from those bytes **using
the engine's own reading functions**, not a copy of them, and counts the facts
each one carries. A briefing that reduces to "we fetched a page" on every stored
target is an agent that could never have worked, and that is discoverable here
rather than against a live application.

**Which gate rules are dead instruments?** Invariant 94's shape, one component
along: a refusal rule with no firing over the corpus is a rule nobody has tested
against real data, and it is named rather than assumed sound. The proposals are
synthesised from URLs the corpus actually contains — the login URLs, the script
URLs those pages referenced, and the hosts other bundles were pointed at — so
"out of scope" is exercised against a host this engine really was aimed at once,
not against ``http://evil.example``.

**The instrument must be able to register a hit.** A corpus of zeros proves
nothing about a measurement that cannot measure, so a positive control runs
first: a plainly-permissible proposal must pass the gate, and a plainly
impermissible one must be refused. Either failing exits non-zero before any
corpus number is printed, because a number from a dead instrument is worse than
no number.

Usage::

    python scripts/auth_agent_corpus.py [--outputs-root outputs] [--json] [--limit N]

Exits non-zero when the positive control fails, or when the observer produced a
vacuous briefing for every login exchange in the corpus.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from clinkz.engagement.auth_agent import (  # noqa: E402
    AuthObservation,
    AuthProposal,
    ProposalKind,
    ProposalRefusal,
    validate_proposal,
)
from clinkz.tools.auth import (  # noqa: E402
    _csrf_fields_without_cookie,
    _form_field_names,
    _framework_fingerprint,
    _parse_form_fields,
    _referenced_scripts,
    _served_content_type,
)

#: Header/body separator in a curl ``-D -`` dump. CRLF is what the protocol
#: writes and what the recorded bytes carry; the LF form is accepted because a
#: recording that passed through a text-mode write on Windows has lost the CRs,
#: and refusing those would silently shrink the corpus rather than read it.
_SEPARATORS = ("\r\n\r\n", "\n\n")


@dataclass
class Exchange:
    """One recorded login-page GET, and the credential POST that followed it."""

    bundle: str
    url: str
    get_status: int = 0
    get_headers: dict[str, str] = field(default_factory=dict)
    get_body: str = ""
    get_cookies: dict[str, str] = field(default_factory=dict)
    post_status: int = 0
    post_body: str = ""
    had_post: bool = False


def _split_dump(stdout: str) -> tuple[int, dict[str, str], str]:
    """``(status, headers, body)`` for a curl ``-D -`` dump.

    Takes the LAST header block, which is the response that ANSWERED: a login
    page behind a redirect writes one block per hop, and reading the first one
    takes the 3xx's empty body. That is the same correction
    ``_parse_curl_exchange`` carries, restated here because this driver reads
    raw recordings rather than the tool's parsed output — the fixture is the
    bytes the tool WROTE (invariant 83), and a replay that read a parsed
    envelope would be replaying the parser rather than the decision.
    """
    text = stdout or ""
    blocks: list[str] = []
    rest = text
    while rest.startswith("HTTP/"):
        cut = (
            min((rest.find(sep), sep) for sep in _SEPARATORS if rest.find(sep) != -1)
            if any(sep in rest for sep in _SEPARATORS)
            else None
        )
        if cut is None:
            blocks.append(rest)
            rest = ""
            break
        index, sep = cut
        blocks.append(rest[:index])
        rest = rest[index + len(sep) :]
    if not blocks:
        return 0, {}, text

    head = blocks[-1]
    lines = head.splitlines()
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip()
        if key.lower() == "set-cookie":
            set_cookies.append(value.strip())
        headers[key] = value.strip()
    if set_cookies:
        headers["Set-Cookie"] = set_cookies[-1]
    headers["__set_cookies__"] = "\n".join(set_cookies)
    return status, headers, rest


def _cookie_names(headers: dict[str, str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for raw in (headers.get("__set_cookies__") or "").splitlines():
        pair = raw.split(";", 1)[0].strip()
        name, sep, value = pair.partition("=")
        if sep and name.strip():
            cookies[name.strip()] = value.strip()
    return cookies


def _origin(url: str) -> str:
    """``scheme://host:port`` for *url*. Scope is a property of a host."""
    parsed = urlparse(url or "")
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""


def _url_of(command: list[Any]) -> str:
    for item in reversed([str(c) for c in command]):
        if item.startswith("http://") or item.startswith("https://"):
            return item
    return ""


def _is_post(command: list[Any]) -> bool:
    joined = " ".join(str(c) for c in command)
    return "-X POST" in joined or "--data" in joined or "-d " in joined


def read_exchanges(outputs_root: pathlib.Path, limit: int | None = None) -> list[Exchange]:
    """Every recorded login exchange in the corpus, newest bundles first."""
    bundles = [d for d in outputs_root.iterdir() if (d / "tool_invocations").is_dir()]
    bundles.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    exchanges: list[Exchange] = []
    for bundle in bundles:
        records = sorted((bundle / "tool_invocations").glob("*_web_authenticator.json"))
        if not records:
            continue
        pending: dict[str, Exchange] = {}
        for path in records:
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            command = data.get("command") or []
            url = _url_of(command)
            if not url:
                continue
            status, headers, body = _split_dump(data.get("stdout") or "")
            if _is_post(command):
                exchange = pending.get(url)
                if exchange is None:
                    continue
                exchange.had_post = True
                exchange.post_status = status
                exchange.post_body = body
                continue
            pending[url] = Exchange(
                bundle=bundle.name,
                url=url,
                get_status=status,
                get_headers=headers,
                get_body=body,
                get_cookies=_cookie_names(headers),
            )
        exchanges.extend(pending.values())
        if limit is not None and len(exchanges) >= limit:
            break
    return exchanges[:limit] if limit is not None else exchanges


def observe(exchange: Exchange) -> AuthObservation:
    """Rebuild the briefing from stored bytes, through the engine's own readers.

    Every reading below is imported from :mod:`clinkz.tools.auth` rather than
    reimplemented. That is the property that makes this a replay: a change to
    how the engine reads a login page changes what this driver reports, and a
    driver carrying its own copy would keep reporting the old answer.
    """
    form = _parse_form_fields(exchange.get_body)
    return AuthObservation(
        base_url=exchange.url.rsplit("/", 1)[0],
        login_url=exchange.url,
        posted_to=exchange.url if exchange.had_post else "",
        post_status=exchange.post_status,
        page_declared_a_form=form.from_form,
        form_action_declared=bool(form.form_action.strip()),
        form_field_names=_form_field_names(form),
        csrf_fields_without_cookie=_csrf_fields_without_cookie(
            form.hidden_fields, exchange.get_cookies
        ),
        login_page_cookie_names=sorted(exchange.get_cookies),
        framework_fingerprint=_framework_fingerprint(exchange.get_headers),
        login_page_content_type=_served_content_type(exchange.get_headers),
        post_changed_nothing=(
            exchange.had_post and len(exchange.post_body) == len(exchange.get_body)
        ),
        referenced_scripts=_referenced_scripts(exchange.get_body, exchange.url),
    )


def briefing_facts(observation: AuthObservation) -> int:
    """How many lines the briefing carries. The vacuity measure."""
    return len(observation.as_briefing().splitlines())


def positive_control() -> tuple[bool, list[str]]:
    """The instrument must register a hit in both directions.

    A gate that permitted everything and a gate that refused everything would
    both produce a clean-looking corpus tally, and they are the two failure modes
    a tally cannot distinguish. So one plainly-permissible proposal must pass and
    one plainly-impermissible one must be refused, before any corpus number is
    printed.
    """
    problems: list[str] = []
    permitted = validate_proposal(
        AuthProposal(
            url="http://target.test/session",
            identity_field="email",
            secret_field="password",
            carry_fields=["token"],
        ),
        in_scope=lambda _u: True,
        known_field_names=frozenset({"token"}),
        credential_budget_remaining=4,
        reads_remaining=4,
        already_refused=frozenset(),
    )
    if not permitted.allowed:
        problems.append(f"the gate refused a plainly-permissible proposal: {permitted.reason}")

    refused = validate_proposal(
        AuthProposal(url="http://elsewhere.test/session", identity_field="email"),
        in_scope=lambda _u: False,
        known_field_names=frozenset(),
        credential_budget_remaining=4,
        reads_remaining=4,
        already_refused=frozenset(),
    )
    if refused.allowed or refused.refusal is not ProposalRefusal.OUT_OF_SCOPE:
        problems.append("the gate permitted an out-of-scope proposal")
    return not problems, problems


def exercise_gate(exchanges: list[Exchange]) -> Counter[str]:
    """Fire every refusal rule against proposals built from corpus URLs.

    The URLs are real: the login URLs the corpus recorded, and paths under the
    same origin. An out-of-scope case uses a login URL from a DIFFERENT bundle,
    which is a host this engine really was pointed at once — so the refusal is
    exercised against something an operator could plausibly have in a scope
    file, rather than against a placeholder.

    **The scope predicate is per-ORIGIN, not per-URL.** An exact-URL predicate
    was the first version and it made the destructive rule unfireable: every
    destructive case names a path under the target, so an equality check refused
    it as out-of-scope one rule earlier and the tally reported ``destructive``
    as untested. A gate whose later rules are shadowed by a stricter earlier one
    reports clean for the same reason a dead instrument does.
    """
    tally: Counter[str] = Counter()
    if not exchanges:
        return tally

    origins = sorted({e.url for e in exchanges})
    for index, exchange in enumerate(exchanges):
        observation = observe(exchange)
        known = observation.carryable_field_names()
        in_scope_url = exchange.url
        foreign = next(
            (u for u in origins if _origin(u) != _origin(exchange.url)),
            origins[(index + 1) % len(origins)],
        )
        cases: list[tuple[AuthProposal, dict[str, Any]]] = [
            # Permitted, in scope, affordable.
            (
                AuthProposal(url=in_scope_url, identity_field="email", secret_field="password"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            # A read.
            (
                AuthProposal(kind=ProposalKind.READ, url=in_scope_url, method="GET"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            # Every refusal, one case each.
            (
                AuthProposal(url="/relative/only", identity_field="email"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(url=foreign, identity_field="email"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(url=in_scope_url, method="PUT", identity_field="email"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(url=in_scope_url, content_type="text/xml", identity_field="email"),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(url=in_scope_url, identity_field=""),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(
                    url=in_scope_url,
                    identity_field="email",
                    carry_fields=["a_field_no_page_served"],
                ),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
            (
                AuthProposal(url=in_scope_url, identity_field="email"),
                {"credential_budget_remaining": 0, "reads_remaining": 4},
            ),
            (
                AuthProposal(kind=ProposalKind.READ, url=in_scope_url, method="GET"),
                {"credential_budget_remaining": 4, "reads_remaining": 0},
            ),
            (
                AuthProposal(
                    url=f"{in_scope_url.rstrip('/')}/account/delete",
                    identity_field="email",
                ),
                {"credential_budget_remaining": 4, "reads_remaining": 4},
            ),
        ]
        origin = _origin(in_scope_url)
        for proposal, budgets in cases:
            verdict = validate_proposal(
                proposal,
                in_scope=lambda url, this=origin: _origin(url) == this,
                known_field_names=known,
                already_refused=frozenset(),
                **budgets,
            )
            tally[verdict.refusal.value if verdict.refusal else "ALLOWED"] += 1

        # The repeat rule needs a prior refusal to exist, so it is fired on its own.
        repeated = AuthProposal(url=foreign, identity_field="email")
        repeat_verdict = validate_proposal(
            repeated,
            in_scope=lambda url, this=origin: _origin(url) == this,
            known_field_names=known,
            credential_budget_remaining=4,
            reads_remaining=4,
            already_refused=frozenset({repeated.signature()}),
        )
        tally[repeat_verdict.refusal.value if repeat_verdict.refusal else "ALLOWED"] += 1
    return tally


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputs-root", default="outputs", type=pathlib.Path)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    ok, problems = positive_control()
    if not ok:
        print("POSITIVE CONTROL FAILED — this instrument cannot measure:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    if not args.outputs_root.is_dir():
        print(f"no corpus at {args.outputs_root}")
        return 2

    exchanges = read_exchanges(args.outputs_root, args.limit)
    rows = []
    for exchange in exchanges:
        observation = observe(exchange)
        rows.append(
            {
                "bundle": exchange.bundle,
                "url": exchange.url,
                "get_status": exchange.get_status,
                "had_post": exchange.had_post,
                "post_changed_nothing": observation.post_changed_nothing,
                "form_declared": observation.page_declared_a_form,
                "action_declared": observation.form_action_declared,
                "fields": observation.form_field_names,
                "csrf_without_cookie": observation.csrf_fields_without_cookie,
                "framework": observation.framework_fingerprint,
                "scripts": len(observation.referenced_scripts),
                "briefing_facts": briefing_facts(observation),
            }
        )

    tally = exercise_gate(exchanges)
    unfired = sorted(r.value for r in ProposalRefusal if not tally.get(r.value))
    vacuous = [r for r in rows if r["briefing_facts"] <= 2]

    if args.as_json:
        print(
            json.dumps(
                {
                    "exchanges": rows,
                    "gate_firings": dict(sorted(tally.items())),
                    "unfired_rules": unfired,
                    "vacuous_briefings": len(vacuous),
                },
                indent=2,
            )
        )
    else:
        print(f"Login exchanges replayed: {len(rows)}")
        for row in rows[:25]:
            print(
                f"  {row['bundle'][:8]} {row['url']}\n"
                f"      GET {row['get_status']}  post={row['had_post']}  "
                f"post_changed_nothing={row['post_changed_nothing']}  "
                f"form={row['form_declared']} action={row['action_declared']}\n"
                f"      fields={row['fields']}  csrf_without_cookie="
                f"{row['csrf_without_cookie']}\n"
                f"      framework={row['framework'] or '(none named)'}  "
                f"scripts={row['scripts']}  briefing_facts={row['briefing_facts']}"
            )
        if len(rows) > 25:
            print(f"  ... and {len(rows) - 25} more")
        print("\nGate firings over the corpus:")
        for name, count in sorted(tally.items()):
            print(f"  {count:6d}  {name}")
        if unfired:
            print(
                "\nRULES WITH NO FIRING — untested against real data, named rather "
                "than assumed sound:"
            )
            for name in unfired:
                print(f"  - {name}")
        print(
            f"\nBriefings carrying two facts or fewer: {len(vacuous)} of {len(rows)}. "
            "A briefing that reduces to 'we fetched a page' is an agent that could "
            "not have worked."
        )

    if rows and len(vacuous) == len(rows):
        print("\nFAIL: every briefing in the corpus is vacuous.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
