"""One server reachable by two names is one finding per issue.

Run 2 of the Juice Shop variance envelope emitted four security-header findings
for two issues: a missing ``Content-Security-Policy`` and a missing
``Referrer-Policy``, each once against ``http://clinkz-juiceshop:3000`` and once
against ``http://172.20.0.2:3000``. Run 1 saw only the address. One container,
two spellings, and neither the class nor the operator chose them — the crawler
resolves the host itself and reports the address it connected to, so a hostname
goes into the plan and an address comes back out of the very next component.

The same defect at a different granularity produced ``/rest/basket/:id`` and
``/rest/basket/:p3``: two discoverers named one path segment differently, both
lowered to the same dispatched request ``GET /rest/basket/2``, and the class
emitted a finding for each. The parameter name is the discoverer's; the request
is the observation.
"""

from __future__ import annotations

from clinkz.agents._origin import OriginIdentity


class TestOriginIdentity:
    def test_unobserved_origins_key_on_themselves(self) -> None:
        """The whole thing is additive: with nothing resolved, nothing merges.

        Over-merging two genuinely different servers HIDES a finding, which is a
        worse failure than emitting one twice — so an origin with no observed
        address is its own identity and the behaviour is what it always was.
        """
        identity = OriginIdentity()
        assert identity.identity("http://a:3000") == "http://a:3000"
        assert identity.identity("http://b:3000") == "http://b:3000"
        assert identity.identity("http://a:3000") != identity.identity("http://b:3000")

    def test_hostname_and_address_collapse_when_both_were_resolved(self) -> None:
        identity = OriginIdentity()
        identity.observe("http://clinkz-juiceshop:3000/rest/products", "172.20.0.2")
        identity.observe("http://172.20.0.2:3000/rest/products", "172.20.0.2")
        assert identity.identity("http://clinkz-juiceshop:3000") == identity.identity(
            "http://172.20.0.2:3000"
        )

    def test_resolving_the_name_alone_is_enough(self) -> None:
        """This is the shape the live defect actually had.

        The scope named the hostname and the crawler emitted the address, so
        only the hostname ever needed resolving — an address origin is already
        its own resolution. One observation collapses them.
        """
        identity = OriginIdentity()
        identity.observe("http://clinkz-juiceshop:3000/x", "172.20.0.2")
        assert identity.identity("http://clinkz-juiceshop:3000") == identity.identity(
            "http://172.20.0.2:3000"
        )

    def test_two_names_on_one_address_never_merge(self) -> None:
        """Name-based virtual hosting is the confound, and it fails SAFE.

        Two hostnames on one address are routinely two applications with
        different header posture. Merging them would HIDE a finding, which is
        worse than emitting one twice, so an address seen under more than one
        name is ambiguous and every origin on it keys on itself.
        """
        identity = OriginIdentity()
        identity.observe("http://shop.example.com/x", "203.0.113.7")
        identity.observe("http://blog.example.com/x", "203.0.113.7")
        assert identity.identity("http://shop.example.com") != identity.identity(
            "http://blog.example.com"
        )
        # And neither is silently rewritten to the shared address.
        assert identity.identity("http://shop.example.com") == "http://shop.example.com"

    def test_a_second_name_retracts_an_earlier_merge(self) -> None:
        """The ambiguity is a property of the address, not of when it was seen."""
        identity = OriginIdentity()
        identity.observe("http://shop.example.com/x", "203.0.113.7")
        assert identity.identity("http://shop.example.com") == "http://203.0.113.7"
        identity.observe("http://blog.example.com/x", "203.0.113.7")
        assert identity.identity("http://shop.example.com") == "http://shop.example.com"

    def test_port_is_part_of_the_identity(self) -> None:
        """Two services on one machine are two services."""
        identity = OriginIdentity()
        identity.observe("http://host:3000/x", "10.0.0.5")
        identity.observe("http://host:4000/x", "10.0.0.5")
        assert identity.identity("http://host:3000") != identity.identity("http://host:4000")

    def test_scheme_is_part_of_the_identity(self) -> None:
        """Header posture is a property of the service, not of the machine."""
        identity = OriginIdentity()
        identity.observe("http://host:8443/x", "10.0.0.5")
        identity.observe("https://host:8443/x", "10.0.0.5")
        assert identity.identity("http://host:8443") != identity.identity("https://host:8443")

    def test_empty_address_is_ignored(self) -> None:
        """The aiohttp path and every pre-marker recording report nothing."""
        identity = OriginIdentity()
        identity.observe("http://host:3000/x", "")
        identity.observe("http://10.0.0.5:3000/x", "")
        assert identity.identity("http://host:3000") == "http://host:3000"

    def test_a_value_naming_no_origin_never_collides(self) -> None:
        identity = OriginIdentity()
        assert identity.identity("/relative/path") == "/relative/path"
        assert identity.identity("") == ""

    def test_default_port_spellings_are_one_origin(self) -> None:
        """``canonical_origin`` already drops it; the identity inherits that."""
        identity = OriginIdentity()
        identity.observe("http://host:80/x", "10.0.0.5")
        assert identity.identity("http://host") == identity.identity("http://host:80")
