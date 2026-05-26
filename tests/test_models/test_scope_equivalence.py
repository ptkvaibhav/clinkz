"""Scope-equivalence tests — same target reached via different names.

Engagements habitually see the same address described two ways: katana
rewrites ``clinkz-dvwa`` to ``172.20.0.3`` for its single-label crawler,
target_resolver rewrites ``localhost:8080`` to ``clinkz-dvwa:80``, and so
on. The scope check must recognise that those URLs identify the same
target — otherwise every Exploit-Agent HTTP request gets rejected and
the engagement produces zero findings even though the pipeline ran end
to end.

These tests pin the equivalence contract: same address ⇒ in scope; truly
unrelated addresses ⇒ rejected, even when they happen to share a docker
network. The DNS resolver is stubbed out so unit tests do not depend on
a live container stack.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.models import scope as scope_module
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType


def _scope(
    targets: list[tuple[str, ScopeType]],
    excluded: list[tuple[str, ScopeType]] | None = None,
) -> EngagementScope:
    return EngagementScope(
        name="equiv",
        targets=[ScopeEntry(value=v, type=t) for v, t in targets],
        excluded=[ScopeEntry(value=v, type=t) for v, t in (excluded or [])],
    )


@pytest.fixture
def stub_resolver(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace the module-level DNS helpers with controllable stubs.

    Tests update ``dns`` to declare which hostnames resolve to which IPs
    and ``ports`` to declare which container publishes which host port.
    Every call into the resolver is counted so cache-hit tests can assert
    on call count.
    """
    state: dict[str, Any] = {
        "dns": {},  # host -> frozenset[str]
        "ports": {},  # host_port -> container_name | None
        "dns_calls": 0,
        "port_calls": 0,
    }

    def fake_resolve(host: str) -> frozenset[str]:
        state["dns_calls"] += 1
        return state["dns"].get(host, frozenset())

    def fake_port(port: int) -> str | None:
        state["port_calls"] += 1
        return state["ports"].get(port)

    monkeypatch.setattr(scope_module, "_resolve_host_addresses", fake_resolve)
    monkeypatch.setattr(scope_module, "_resolve_docker_port_container", fake_port)
    return state


class TestContainerAliasVsIP:
    """clinkz-dvwa:80 ↔ 172.20.0.3:80 — the actual reported bug."""

    def test_ip_form_matches_container_alias_scope_entry(
        self, stub_resolver: dict[str, Any]
    ) -> None:
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "172.20.0.3": frozenset({"172.20.0.3"}),
        }
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        assert scope.contains("http://172.20.0.3:80/vulnerabilities/sqli/") is True

    def test_container_alias_matches_ip_scope_entry(self, stub_resolver: dict[str, Any]) -> None:
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "172.20.0.3": frozenset({"172.20.0.3"}),
        }
        scope = _scope([("172.20.0.3", ScopeType.IP)])
        assert scope.contains("http://clinkz-dvwa:80/") is True


class TestPortOptional:
    """clinkz-dvwa ↔ clinkz-dvwa:80 — port irrelevant for hostname scopes."""

    def test_bare_alias_matches_with_port(self, stub_resolver: dict[str, Any]) -> None:
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        # Direct hostname match — no resolver call needed.
        assert scope.contains("http://clinkz-dvwa:80/") is True
        assert stub_resolver["dns_calls"] == 0


class TestLocalhostPortMapping:
    """localhost:8080 ↔ clinkz-dvwa:80 — only in docker mode."""

    def test_localhost_with_port_matches_via_docker_port_map(
        self, stub_resolver: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "localhost": frozenset({"127.0.0.1"}),
        }
        stub_resolver["ports"] = {8080: "clinkz-dvwa"}
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        assert scope.contains("http://localhost:8080/") is True

    def test_localhost_without_docker_mode_does_not_consult_port_map(
        self, stub_resolver: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "local")
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "localhost": frozenset({"127.0.0.1"}),
        }
        stub_resolver["ports"] = {8080: "clinkz-dvwa"}
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        assert scope.contains("http://localhost:8080/") is False
        assert stub_resolver["port_calls"] == 0, (
            "Port map must not be consulted outside docker mode — would leak host topology"
        )


class TestRejectionCases:
    """Equivalence must not become a scope bypass."""

    def test_unrelated_public_domain_vs_internal_ip(self, stub_resolver: dict[str, Any]) -> None:
        stub_resolver["dns"] = {
            "example.com": frozenset({"93.184.216.34"}),
            "172.20.0.3": frozenset({"172.20.0.3"}),
        }
        scope = _scope([("example.com", ScopeType.DOMAIN)])
        assert scope.contains("http://172.20.0.3/") is False

    def test_unrelated_ip_same_docker_network_does_not_match_alias(
        self, stub_resolver: dict[str, Any]
    ) -> None:
        """An IP we never resolved to belongs to the scope alias is not in scope.

        The attacker's case: an exploit payload smuggles in a different
        sibling container's IP (``172.20.0.99``). The scope only names
        ``clinkz-dvwa`` (which resolves to ``172.20.0.3``). The two IPs
        share a /24 but are different addresses — must be rejected.
        """
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "172.20.0.99": frozenset({"172.20.0.99"}),
        }
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        assert scope.contains("http://172.20.0.99/admin") is False

    def test_unresolvable_target_is_out_of_scope(self, stub_resolver: dict[str, Any]) -> None:
        """Resolution failure must keep the address out of scope, not bypass it."""
        stub_resolver["dns"] = {"clinkz-dvwa": frozenset({"172.20.0.3"})}
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        # phantom-host.invalid does not appear in the stub → resolves to empty set
        assert scope.contains("http://phantom-host.invalid/") is False


class TestExclusionsTakePrecedence:
    """Equivalence-matched exclusions must still win over equivalence-matched targets."""

    def test_excluded_alias_blocks_ip_form(self, stub_resolver: dict[str, Any]) -> None:
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "172.20.0.3": frozenset({"172.20.0.3"}),
        }
        scope = _scope(
            targets=[("172.20.0.0/24", ScopeType.CIDR)],
            excluded=[("clinkz-dvwa", ScopeType.DOMAIN)],
        )
        # In-CIDR address is normally in scope...
        assert scope.contains("http://172.20.0.4/") is True
        # ...but the alias exclusion must block any IP equivalent to it.
        assert scope.contains("http://172.20.0.3/") is False


class TestCaching:
    """Resolution happens once per hostname per engagement."""

    def test_repeated_contains_does_not_re_resolve(self, stub_resolver: dict[str, Any]) -> None:
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "172.20.0.3": frozenset({"172.20.0.3"}),
        }
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        for _ in range(10):
            assert scope.contains("http://172.20.0.3/") is True
        # 2 calls total: one for the target host, one for the entry host —
        # then every subsequent contains() is served from cache.
        assert stub_resolver["dns_calls"] == 2

    def test_port_lookup_cached_too(
        self, stub_resolver: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from clinkz.config import settings

        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        stub_resolver["dns"] = {
            "clinkz-dvwa": frozenset({"172.20.0.3"}),
            "localhost": frozenset({"127.0.0.1"}),
        }
        stub_resolver["ports"] = {8080: "clinkz-dvwa"}
        scope = _scope([("clinkz-dvwa", ScopeType.DOMAIN)])
        for _ in range(5):
            assert scope.contains("http://localhost:8080/") is True
        assert stub_resolver["port_calls"] == 1


class TestBackwardsCompatibility:
    """Existing IP / CIDR / domain semantics must keep working untouched."""

    def test_direct_ip_match_no_resolver_needed(self, stub_resolver: dict[str, Any]) -> None:
        scope = _scope([("10.10.10.1", ScopeType.IP)])
        assert scope.contains("10.10.10.1") is True
        assert stub_resolver["dns_calls"] == 0

    def test_cidr_membership_unchanged(self, stub_resolver: dict[str, Any]) -> None:
        scope = _scope([("10.10.10.0/24", ScopeType.CIDR)])
        assert scope.contains("10.10.10.50") is True
        assert scope.contains("10.10.11.1") is False

    def test_subdomain_suffix_match_unchanged(self, stub_resolver: dict[str, Any]) -> None:
        scope = _scope([("example.com", ScopeType.DOMAIN)])
        assert scope.contains("api.example.com") is True
        assert scope.contains("attacker.com") is False
