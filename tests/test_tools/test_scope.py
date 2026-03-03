"""Tests for EngagementScope.contains() — scope enforcement logic."""

from __future__ import annotations

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType


def make_scope(
    targets: list[tuple[str, ScopeType]],
    excluded: list[tuple[str, ScopeType]] | None = None,
) -> EngagementScope:
    return EngagementScope(
        name="test",
        targets=[ScopeEntry(value=v, type=t) for v, t in targets],
        excluded=[ScopeEntry(value=v, type=t) for v, t in (excluded or [])],
    )


class TestIpScope:
    def test_exact_ip_in_scope(self) -> None:
        scope = make_scope([("10.10.10.1", ScopeType.IP)])
        assert scope.contains("10.10.10.1") is True

    def test_different_ip_out_of_scope(self) -> None:
        scope = make_scope([("10.10.10.1", ScopeType.IP)])
        assert scope.contains("10.10.10.2") is False


class TestCidrScope:
    def test_ip_inside_cidr(self) -> None:
        scope = make_scope([("10.10.10.0/24", ScopeType.CIDR)])
        assert scope.contains("10.10.10.100") is True

    def test_ip_outside_cidr(self) -> None:
        scope = make_scope([("10.10.10.0/24", ScopeType.CIDR)])
        assert scope.contains("10.10.11.1") is False


class TestDomainScope:
    def test_exact_domain_match(self) -> None:
        scope = make_scope([("example.com", ScopeType.DOMAIN)])
        assert scope.contains("example.com") is True

    def test_subdomain_match(self) -> None:
        scope = make_scope([("example.com", ScopeType.DOMAIN)])
        assert scope.contains("sub.example.com") is True

    def test_different_domain_out_of_scope(self) -> None:
        scope = make_scope([("example.com", ScopeType.DOMAIN)])
        assert scope.contains("attacker.com") is False


class TestExclusions:
    def test_excluded_ip_not_in_scope(self) -> None:
        scope = make_scope(
            targets=[("10.10.10.0/24", ScopeType.CIDR)],
            excluded=[("10.10.10.1", ScopeType.IP)],
        )
        assert scope.contains("10.10.10.1") is False
        assert scope.contains("10.10.10.2") is True
