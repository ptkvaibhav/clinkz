"""No session verdict rests on a destination's spelling — over a COMPUTED domain.

``assert_authenticated`` stopped deciding ``login_redirect`` on seven substrings
when a target whose login page lives at ``/portal/gateway`` proved what that
costs. The same oracle survived one module away, in
``WebAuthenticator._verify_session_curl``: ``login`` / ``signin`` / ``auth``,
matched against ``%{redirect_url}``, on the arm the DEFAULT execution mode uses
and on the path the default-credential sweep runs through. Renaming a login page
still flipped a session verdict; it just took a different route to get there.

The fix for that one function is a fix for one function. **The domain is the
deliverable.** A grep for three substrings is the same guess one layer up: it
finds the spellings its author thought of, in the files its author thought of,
and reports clean on everything else — the guard-pattern law in
``.claude/skills/clinkz-dev/SKILL.md`` §4. So the set of functions this rule
binds is COMPUTED from the call graph:

* **Sinks** are declared: the seams where an authenticated / not-authenticated
  decision is actually taken, each with the decision it makes. This is the
  classification half, and a human owns it.
* **The domain** is every function whose return value feeds one of those sinks,
  transitively, through **verdict-carrying** edges — a call or property read
  whose value reaches a ``return``, a branch test, a comparison, a boolean
  operator, an ``assert``, or a local that later reaches one of those. A callee
  whose result is discarded, appended to an evidence list, or passed on as an
  argument is not deciding anything and is not in the domain.
* **The flag** is computed too: a member that compares a value against a string
  literal, resolved through module constants, local assignments and the
  iterables of ``for`` loops and comprehensions. That last part matters — the
  first version of this detector read only the ``Compare`` node, so
  ``any(hint in location for hint in _LOGIN_HINTS)`` was invisible to it and the
  very oracle this file exists to pin was not flagged.
* **The classification** says what each flagged member tests. Only
  ``destination_spelling`` is dangerous, and every entry carrying it needs a
  licence naming its consumer and the bound that keeps it from being a verdict.

Assert both directions: an unclassified flagged member fails, and an entry that
outlived the code it described fails.

No network, no container: everything here is read out of the source.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
PKG = SRC / "clinkz"

# ---------------------------------------------------------------------------
# Declared: the seams where a session verdict is taken
# ---------------------------------------------------------------------------

#: Simple function name -> the authenticated / not-authenticated decision it
#: makes. Every function reachable from one of these through a verdict-carrying
#: edge is in the domain this file guards.
SESSION_VERDICT_SINKS: dict[str, str] = {
    "_check_login_success": (
        "decides whether a credential exchange established a session; its return "
        "IS AuthResult.success"
    ),
    "_require_session_material": (
        "decides whether a success that carries no session material may stand"
    ),
    "verify_session": (
        "decides whether a stored session is still live, which decides whether the "
        "engagement re-authenticates or keeps scanning with it"
    ),
    "_session_survived": (
        "the shared rule both execution modes hand their session-check response to"
    ),
    "assert_authenticated": (
        "the oracle: proves authenticated state against an anonymous control, and "
        "a False here aborts the engagement"
    ),
    "_discriminate": "picks the boundary discriminator that proves the session",
    "looks_unauthenticated": ("decides whether a mid-run response says the session has been lost"),
    "read_auth_artifact": (
        "decides whether a response carries authenticated state — the probe arm of "
        "the auth-bypass differential"
    ),
    "_attempt_login": ("decides whether a swept credential is valid and its session stored"),
    "_verify_and_refresh_session": (
        "decides whether the session handed to Scan and Exploit is the stored one, "
        "a re-authenticated one, or none"
    ),
}

# ---------------------------------------------------------------------------
# Declared: what each flagged member's string literals actually test
# ---------------------------------------------------------------------------

#: The only kind that can put a session verdict at the mercy of a name.
DESTINATION_SPELLING = "destination_spelling"

#: Every kind a flagged member may be classified as.
LITERAL_KINDS: frozenset[str] = frozenset(
    {
        DESTINATION_SPELLING,
        "body_marker",  # a token in the response BODY
        "cookie_name",  # the NAME of a cookie
        "header_name",  # the NAME of an HTTP header
        "response_key_name",  # a key in a JSON body
        "media_type",  # a content type
        "url_syntax",  # ":", "://", "@" — grammar, not naming
        "engine_token",  # a value this engine itself writes and reads back
    }
)

#: qualname -> (kind, why that is what the literals test).
#:
#: A member appears here when the detector below finds it comparing a value
#: against a string literal. The detector computes the domain and the flag; this
#: table is the only hand-maintained half.
LITERAL_TESTS: dict[str, tuple[str, str]] = {
    "clinkz.agents._auth_bypass:_looks_like_session_cookie": (
        "cookie_name",
        "Tests the NAME of a cookie the response set against session-cookie "
        "tokens. A name is all a cookie has — there is no shape to read — and it "
        "gates whether an artifact is recorded, never where a redirect points.",
    ),
    "clinkz.agents._auth_bypass:read_auth_artifact": (
        "response_key_name",
        "Tests JSON body keys and header names against token-carrying key names. "
        "The destination test in its fourth arm is the redirects_to_login "
        "property, classified separately, and its licence is recorded below.",
    ),
    "clinkz.engagement.auth_state:ProbeResponse.location": (
        "header_name",
        "Matches the header NAME 'location' case-insensitively. That is the "
        "protocol's own spelling of the field, not the application's spelling of "
        "a page.",
    ),
    "clinkz.engagement.auth_state:ProbeResponse.redirects_to_login": (
        DESTINATION_SPELLING,
        "This IS the destination-spelling test — _LOGIN_HINTS against the "
        "Location header. It is deliberately kept and deliberately not a "
        "verdict; see the licence table for each consumer and the bound that "
        "holds it there.",
    ),
    "clinkz.engagement.auth_state:_discriminate": (
        "body_marker",
        "Tests _SESSION_MARKERS against the response BODY, and only accepts a "
        "marker present in the authenticated response and ABSENT from the "
        "anonymous control. The control is what makes it evidence; a marker in "
        "both proves nothing and is skipped.",
    ),
    "clinkz.engagement.auth_state:assert_authenticated": (
        "engine_token",
        "Compares the discriminator name this module itself wrote "
        "('login_redirect') to decide whether to gather corroboration. The string "
        "is the engine's own vocabulary, produced ten lines earlier by "
        "_discriminate; no target can influence it.",
    ),
    "clinkz.models.scope:EngagementScope._extract_host_port": (
        "url_syntax",
        "Splits a URL on '://' and ':' and recognises the http/https schemes. URL "
        "grammar, applied before any scope decision — it names no page and reads "
        "no application.",
    ),
    "clinkz.models.scope:EngagementScope._resolved_addresses": (
        "engine_token",
        "Compares the configured tool execution mode against 'docker'. That value "
        "is this engine's own setting, not anything a target says.",
    ),
    "clinkz.tools.auth:WebAuthenticator._check_login_success": (
        "body_marker",
        "Tests failure and success keywords against the response BODY, and the "
        "success markers run LAST — after session material and after a redirect "
        "that actually occurred — precisely because a body marker is the weakest "
        "of the three. Nothing here reads where a redirect points.",
    ),
    "clinkz.tools.auth:WebAuthenticator._dispatch": (
        "engine_token",
        "Routes to the curl or aiohttp arm on the configured execution mode "
        "('docker'). The engine's own setting; no response is read.",
    ),
    "clinkz.tools.auth:WebAuthenticator.verify_session": (
        "engine_token",
        "Same execution-mode routing as _dispatch. The verdict itself is "
        "_session_survived's, which tests no string at all.",
    ),
    "clinkz.tools.auth:WebAuthenticator._encode_credential_body": (
        "media_type",
        "Encodes the credential body as JSON or form data depending on the "
        "content type. A media type is a protocol register, and this one was "
        "either declared by the operator, declared by the form, or named by the "
        "server's own 415.",
    ),
    "clinkz.tools.auth:WebAuthenticator._execute_aiohttp": (
        "media_type",
        "Checks the form's declared enctype against ENCODABLE_CONTENT_TYPES "
        "before using it, so an enctype this authenticator cannot produce falls "
        "back rather than being sent as a guess.",
    ),
    "clinkz.tools.auth:WebAuthenticator._execute_curl": (
        "media_type",
        "The same enctype check as the aiohttp arm, kept identical on purpose: a "
        "target that authenticates in one execution mode and not the other is a "
        "defect the mode hides.",
    ),
    "clinkz.tools.auth:WebAuthenticator._extract_token": (
        "response_key_name",
        "Walks _TOKEN_JSON_PATHS into the parsed JSON body — key names in a "
        "document, not a URL. A missing key ends that path and nothing else.",
    ),
    "clinkz.tools.auth:WebAuthenticator._negotiated_content_type": (
        "media_type",
        "Reads Accept-Post / Accept header names and the media types they name, "
        "and the JSON keys an API states the same thing under. Prose is never "
        "parsed and the result is bounded to types this module can encode.",
    ),
    "clinkz.tools.auth:WebAuthenticator._parse_curl_exchange": (
        "header_name",
        "Splits header lines on ':' and recognises the header NAME 'set-cookie' "
        "so multi-cookie responses come back as a list. HTTP grammar, not naming.",
    ),
    "clinkz.tools.auth:WebAuthenticator._try_api_login": (
        "url_syntax",
        "Tests the supplied identifier for '@' to decide whether to also try a "
        "username-keyed body. It shapes which candidate bodies are sent; the "
        "verdict is the response.",
    ),
    "clinkz.tools.auth:WebAuthenticator.authenticate": (
        "engine_token",
        "Compares the arm name ('form') that _encoding_order returned. The engine "
        "wrote that string one call earlier.",
    ),
    "clinkz.tools.auth:_FormFieldParser.login_form": (
        "engine_token",
        "Falls back to the first form declaring method POST when no form carries "
        "a password input. HTML's own method register, and the primary rule above "
        "it is the password input — a shape, not a name.",
    ),
    "clinkz.tools.redirect_walk:classify_redirect": (
        "header_name",
        "Finds the header NAME 'location' case-insensitively before resolving and "
        "scope-checking the destination. It never reads what the destination is "
        "called.",
    ),
    "clinkz.tools.redirect_walk:walk_redirects": (
        "engine_token",
        "Compares the hop action this module's own classify_redirect returned "
        "('stop' / 'resend' / 'refuse'). Engine vocabulary end to end.",
    ),
}

#: qualname of a ``destination_spelling`` member -> every consumer that reads it,
#: and the bound that keeps it from being the verdict there.
#:
#: An exemption is an allow-list entry with a substantive reason, never a silent
#: skip. A member that appears here and NOT in the code any more fails, and a
#: ``destination_spelling`` member with no entry here fails.
DESTINATION_SPELLING_LICENCE: dict[str, str] = {
    "clinkz.engagement.auth_state:ProbeResponse.redirects_to_login": (
        "Three consumers, and none of them may be the verdict. (1) "
        "looks_unauthenticated raises a HYPOTHESIS for SessionSentinel, which "
        "answers it by re-running assert_authenticated — the oracle — so a "
        "missed spelling costs a re-verification and never a wrong claim "
        "(invariant 37). (2) detect_auth_mechanism uses it to label a surface "
        "UNKNOWN when nothing else was found, which is a statement about what we "
        "could not determine. (3) read_auth_artifact's fourth arm treats a "
        "redirect that is NOT login-spelled as authenticated state; the "
        "differential bounds it, because a login page this list does not "
        "recognise makes the control arm authenticated too and "
        "decide_auth_bypass then refuses to confirm — so an unrecognised "
        "spelling costs COVERAGE there, not a false finding. The session "
        "assertion itself stopped reading this property when /portal/gateway "
        "proved the cost, and it must never read it again."
    ),
}

#: Members the fix put on the observed rule. They are asserted to be in the
#: domain and to test NO string literal at all, so re-introducing a name gate in
#: any of them fails this file rather than passing quietly.
NO_LITERAL_TEST_AT_ALL: tuple[str, ...] = (
    "clinkz.tools.auth:WebAuthenticator._session_survived",
    "clinkz.tools.auth:WebAuthenticator._verify_session_curl",
    "clinkz.tools.auth:WebAuthenticator._verify_session_aiohttp",
)


# ---------------------------------------------------------------------------
# Computed: the call graph, the domain, the flag
# ---------------------------------------------------------------------------

#: Ancestor node types that mean "this value is being used to decide something".
_VERDICT_ANCESTORS = (ast.Return, ast.Assert, ast.Compare, ast.BoolOp)


class _Fn:
    """One function or property, with the module and class that own it."""

    __slots__ = ("qual", "node", "module", "cls", "is_property")

    def __init__(
        self, qual: str, node: ast.AST, module: str, cls: str | None, is_property: bool
    ) -> None:
        self.qual = qual
        self.node = node
        self.module = module
        self.cls = cls
        self.is_property = is_property


class _Module:
    """One parsed module: its functions, its classes, and what it imports."""

    __slots__ = ("name", "tree", "functions", "class_bases", "imports", "constants")

    def __init__(self, name: str, tree: ast.Module) -> None:
        self.name = name
        self.tree = tree
        self.functions: list[_Fn] = []
        self.class_bases: dict[str, list[str]] = {}
        self.imports: dict[str, str] = {}
        self.constants: dict[str, ast.expr] = {}


def _module_name(path: Path) -> str:
    return str(path.relative_to(SRC)).replace("\\", "/")[: -len(".py")].replace("/", ".")


def _parse_module(path: Path) -> _Module:
    module = _Module(_module_name(path), ast.parse(path.read_text(encoding="utf-8")))

    def walk(node: ast.AST, cls: str | None, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                if cls is None:
                    module.class_bases[child.name] = [
                        base.id for base in child.bases if isinstance(base, ast.Name)
                    ] + [base.attr for base in child.bases if isinstance(base, ast.Attribute)]
                walk(child, child.name, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_property = any(
                    isinstance(d, ast.Name) and d.id == "property" for d in child.decorator_list
                )
                module.functions.append(
                    _Fn(f"{module.name}:{prefix}{child.name}", child, module.name, cls, is_property)
                )
                walk(child, cls, f"{prefix}{child.name}.")

    walk(module.tree, None, "")

    for node in ast.walk(module.tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                module.imports[alias.asname or alias.name] = node.module
    for node in module.tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                module.constants[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            module.constants[node.target.id] = node.value
    return module


def _parents(fn: _Fn) -> dict[int, ast.AST]:
    table: dict[int, ast.AST] = {}
    for node in ast.walk(fn.node):
        for child in ast.iter_child_nodes(node):
            table[id(child)] = node
    return table


def _verdict_carrying_nodes(fn: _Fn) -> set[int]:
    """ids of Call/Attribute nodes inside *fn* whose value decides something.

    Two passes. The first is syntactic: the node sits, somewhere up its ancestor
    chain, inside a return, a branch test, a comparison, a boolean operator, a
    ``not``, an assert, or a comprehension's filter. The second follows one
    assignment hop: a call whose result is bound to a local that the first pass
    marked is carrying the same value into the same decision.

    One hop is the deliberate limit. Longer chains exist, and the effect of
    stopping here is a SMALLER domain — which is the direction that can hide a
    member, so it is stated rather than assumed: a producer three assignments
    from a branch is not caught. Every function this rule is actually about
    reaches its decision inside one.
    """
    parents = _parents(fn)

    def decides(node: ast.AST) -> bool:
        previous: ast.AST = node
        current: ast.AST = node
        while id(current) in parents:
            current = parents[id(current)]
            if isinstance(current, _VERDICT_ANCESTORS):
                return True
            if isinstance(current, ast.UnaryOp) and isinstance(current.op, ast.Not):
                return True
            if isinstance(current, (ast.If, ast.While, ast.IfExp)) and current.test is previous:
                return True
            if isinstance(current, ast.comprehension) and previous in current.ifs:
                return True
            if current is fn.node:
                return False
            previous = current
        return False

    deciding_names: set[str] = set()
    for node in ast.walk(fn.node):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and decides(node):
            deciding_names.add(node.id)
        elif isinstance(node, ast.Attribute) and decides(node):
            base: ast.expr = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                deciding_names.add(base.id)

    marked: set[int] = set()
    for node in ast.walk(fn.node):
        if not isinstance(node, (ast.Call, ast.Attribute)):
            continue
        if decides(node):
            marked.add(id(node))
            continue
        parent = parents.get(id(node))
        if isinstance(parent, ast.Await):
            parent = parents.get(id(parent))
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            bound = {sub.id for t in targets for sub in ast.walk(t) if isinstance(sub, ast.Name)}
            if bound & deciding_names:
                marked.add(id(node))
    return marked


class _CallGraph:
    """Verdict-carrying edges over every module under ``src/clinkz``."""

    def __init__(self) -> None:
        self.modules: dict[str, _Module] = {}
        for path in sorted(PKG.rglob("*.py")):
            module = _parse_module(path)
            self.modules[module.name] = module

        self.by_qual: dict[str, _Fn] = {}
        self.module_functions: dict[str, dict[str, str]] = {}
        self.class_methods: dict[str, dict[str, dict[str, str]]] = {}
        for module in self.modules.values():
            self.module_functions[module.name] = {}
            self.class_methods[module.name] = {}
            for fn in module.functions:
                self.by_qual[fn.qual] = fn
                local = fn.qual.split(":", 1)[1]
                if "." not in local:
                    self.module_functions[module.name][local] = fn.qual
                elif fn.cls and local.count(".") == 1:
                    self.class_methods[module.name].setdefault(fn.cls, {})[local.split(".")[1]] = (
                        fn.qual
                    )

        self.edges: dict[str, set[str]] = {
            qual: self._callees(fn) for qual, fn in self.by_qual.items()
        }

    def _visible_classes(self, module_name: str) -> dict[str, tuple[str, str]]:
        module = self.modules[module_name]
        visible = {name: (module_name, name) for name in module.class_bases}
        for alias, source in module.imports.items():
            if source in self.modules and alias in self.modules[source].class_bases:
                visible[alias] = (source, alias)
        return visible

    def _method(
        self, module_name: str, cls: str, attr: str, seen: tuple[tuple[str, str], ...] = ()
    ) -> str | None:
        if (module_name, cls) in seen:
            return None
        found = self.class_methods.get(module_name, {}).get(cls, {}).get(attr)
        if found:
            return found
        visible = self._visible_classes(module_name)
        for base in self.modules[module_name].class_bases.get(cls, []):
            if base in visible:
                base_module, base_cls = visible[base]
                found = self._method(base_module, base_cls, attr, (*seen, (module_name, cls)))
                if found:
                    return found
        return None

    def _callees(self, fn: _Fn) -> set[str]:
        """Qualnames whose RETURN feeds a decision inside *fn*.

        Resolution is import-aware rather than by bare name: ``self.x()`` against
        the owning class and its bases, a plain call against this module's own
        functions and the names it imported, an attribute against the classes
        visible in this module. Resolving by simple name alone put 180 functions
        in the domain, most of them a ``.name`` or a ``.get`` that happened to
        share a spelling — a domain nobody can read is not a domain anybody
        checks.
        """
        marked = _verdict_carrying_nodes(fn)
        module = self.modules[fn.module]
        visible = self._visible_classes(fn.module)
        callees: set[str] = set()
        for node in ast.walk(fn.node):
            if id(node) not in marked:
                continue
            attribute_only = isinstance(node, ast.Attribute)
            target = node.func if isinstance(node, ast.Call) else node
            if isinstance(target, ast.Name):
                found = self.module_functions.get(fn.module, {}).get(target.id)
                if not found and target.id in module.imports:
                    found = self.module_functions.get(module.imports[target.id], {}).get(target.id)
                if found:
                    callees.add(found)
            elif isinstance(target, ast.Attribute):
                base = target.value
                if isinstance(base, ast.Name) and base.id == "self" and fn.cls:
                    found = self._method(fn.module, fn.cls, target.attr)
                    if found:
                        callees.add(found)
                    continue
                for class_module, class_name in visible.values():
                    found = self._method(class_module, class_name, target.attr)
                    if not found:
                        continue
                    if attribute_only and not self.by_qual[found].is_property:
                        continue
                    callees.add(found)
        return callees

    def domain(self, sinks: dict[str, str]) -> set[str]:
        seeds = {qual for qual in self.by_qual if qual.split(":", 1)[1].rsplit(".", 1)[-1] in sinks}
        reached = set(seeds)
        frontier = list(seeds)
        while frontier:
            for callee in self.edges.get(frontier.pop(), ()):
                if callee not in reached:
                    reached.add(callee)
                    frontier.append(callee)
        return reached


def _string_constants(node: ast.AST, env: dict[str, ast.expr], depth: int = 0) -> list[str]:
    """Every string literal *node* can be resolved to, through *env*."""
    if depth > 6:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [s for element in node.elts for s in _string_constants(element, env, depth + 1)]
    if isinstance(node, ast.Name) and node.id in env:
        return _string_constants(env[node.id], env, depth + 1)
    return []


def _literal_tests(fn: _Fn, module: _Module) -> list[str]:
    """String literals *fn* compares a value against, in source order.

    The environment is built from the module's own constants, the function's
    local assignments, and — the part a ``Compare``-only reader misses — the
    iterables of ``for`` loops and comprehensions, so
    ``any(hint in location for hint in _LOGIN_HINTS)`` resolves ``hint`` to the
    hints rather than to nothing.
    """
    parents = _parents(fn)
    env: dict[str, ast.expr] = dict(module.constants)
    for node in ast.walk(fn.node):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                env[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            env[node.target.id] = node.value
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            env[node.target.id] = node.iter

    found: list[str] = []
    for node in ast.walk(fn.node):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], (ast.In, ast.NotIn, ast.Eq, ast.NotEq)):
            continue
        # Comprehension targets bind only inside their own comprehension, so
        # they are resolved by walking up from this Compare rather than from a
        # module-wide pass that the last comprehension would win.
        scoped = dict(env)
        current: ast.AST = node
        while id(current) in parents:
            current = parents[id(current)]
            if isinstance(current, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
                for generator in current.generators:
                    if isinstance(generator.target, ast.Name):
                        scoped[generator.target.id] = generator.iter
            if current is fn.node:
                break
        literals = _string_constants(node.left, scoped) + _string_constants(
            node.comparators[0], scoped
        )
        found.extend(literals)
    return found


@pytest.fixture(scope="module")
def graph() -> _CallGraph:
    return _CallGraph()


@pytest.fixture(scope="module")
def flagged(graph: _CallGraph) -> dict[str, list[str]]:
    """Domain members that compare a value against a string literal."""
    found: dict[str, list[str]] = {}
    for qual in graph.domain(SESSION_VERDICT_SINKS):
        fn = graph.by_qual[qual]
        literals = _literal_tests(fn, graph.modules[fn.module])
        if literals:
            found[qual] = literals
    return found


def test_every_declared_sink_still_exists(graph: _CallGraph) -> None:
    """A renamed sink must fail loudly, not shrink the domain in silence."""
    defined = {qual.split(":", 1)[1].rsplit(".", 1)[-1] for qual in graph.by_qual}
    missing = set(SESSION_VERDICT_SINKS) - defined
    assert not missing, (
        f"declared session-verdict sinks that no longer exist: {sorted(missing)}. "
        f"A sink that vanished takes its whole subtree out of the domain with it."
    )


def test_the_domain_is_not_trivially_small(graph: _CallGraph) -> None:
    """A domain that collapsed is a guard that stopped guarding.

    The floor is deliberately far below the real size (70 at the time of
    writing): it catches a resolution change that silently empties the closure,
    not a refactor that moves a few functions around.
    """
    domain = graph.domain(SESSION_VERDICT_SINKS)
    assert len(domain) >= 30, (
        f"the session-verdict domain computed to {len(domain)} members, which "
        f"means the call-graph walk stopped resolving: {sorted(domain)}"
    )


def test_every_flagged_member_declares_what_its_literals_test(
    flagged: dict[str, list[str]],
) -> None:
    """The domain is computed; the classification is declared. Both directions."""
    undeclared = set(flagged) - set(LITERAL_TESTS)
    assert not undeclared, (
        "these functions decide a session verdict and compare a value against a "
        "string literal, with no entry saying what the literal tests:\n"
        + "\n".join(f"  {q}: {sorted(set(flagged[q]))[:8]}" for q in sorted(undeclared))
        + "\nDeclare each one. If it tests where a redirect POINTS, it is a "
        "destination_spelling entry and it needs a licence."
    )
    stale = set(LITERAL_TESTS) - set(flagged)
    assert not stale, (
        f"entries for functions that are no longer in the session-verdict domain, "
        f"or no longer test a string literal: {sorted(stale)}"
    )


def test_every_classification_is_substantive() -> None:
    """A one-word reason is a box tick, not a decision."""
    for qual, (kind, reason) in LITERAL_TESTS.items():
        assert kind in LITERAL_KINDS, f"{qual}: unknown kind {kind!r}"
        assert len(reason.split()) >= 12, f"{qual}: reason is too thin to be a decision"


def test_every_destination_spelling_test_is_licensed() -> None:
    """A name test that reaches a verdict is the defect; one that cannot is a note."""
    spelling = {q for q, (kind, _) in LITERAL_TESTS.items() if kind == DESTINATION_SPELLING}
    unlicensed = spelling - set(DESTINATION_SPELLING_LICENCE)
    assert not unlicensed, (
        f"these read a destination's spelling with no licence naming their "
        f"consumers and the bound that stops it being the verdict: {sorted(unlicensed)}"
    )
    stale = set(DESTINATION_SPELLING_LICENCE) - spelling
    assert not stale, f"licences for tests that no longer exist: {sorted(stale)}"
    for qual, licence in DESTINATION_SPELLING_LICENCE.items():
        assert len(licence.split()) >= 30, (
            f"{qual}: a licence names every consumer and the bound on each — "
            f"this one is too short to have done that"
        )


@pytest.mark.parametrize("qual", NO_LITERAL_TEST_AT_ALL)
def test_the_session_check_tests_no_string_at_all(
    graph: _CallGraph, flagged: dict[str, list[str]], qual: str
) -> None:
    """The regression pin for the oracle this file is named after.

    ``_verify_session_curl`` matched ``login`` / ``signin`` / ``auth`` against
    ``%{redirect_url}``; ``_verify_session_aiohttp`` matched the same three
    against ``Location``. Both now fetch and hand the response to
    ``_session_survived``, which decides on a status class and an
    ``<input type="password">``. None of the three may compare a string again.
    """
    assert qual in graph.domain(SESSION_VERDICT_SINKS), (
        f"{qual} is no longer reachable from a session-verdict sink — either it "
        f"was renamed or the walk stopped resolving it"
    )
    assert qual not in flagged, (
        f"{qual} compares a value against a string literal again: "
        f"{sorted(set(flagged.get(qual, [])))}. A session verdict may not rest on "
        f"a destination's spelling."
    )


def test_the_assertion_oracle_never_reads_the_destination_property(graph: _CallGraph) -> None:
    """``_discriminate`` is where the /portal/gateway defect lived. It stays clean.

    Stated as a call-graph fact rather than a grep: the property must not be
    reachable from ``_discriminate`` through a verdict-carrying edge at all.
    """
    reached: set[str] = set()
    frontier = ["clinkz.engagement.auth_state:_discriminate"]
    while frontier:
        for callee in graph.edges.get(frontier.pop(), ()):
            if callee not in reached:
                reached.add(callee)
                frontier.append(callee)
    assert "clinkz.engagement.auth_state:ProbeResponse.redirects_to_login" not in reached, (
        "the session assertion reads the destination-spelling property again — "
        "that is the defect a login page at /portal/gateway proved, restored"
    )
