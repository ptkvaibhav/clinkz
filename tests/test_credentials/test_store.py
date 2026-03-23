"""Unit tests for the credential store."""

from __future__ import annotations

import pytest
import pytest_asyncio

from clinkz.credentials.store import CredentialStore, _DEFAULT_CREDENTIALS
from clinkz.state import StateStore


@pytest_asyncio.fixture
async def store(tmp_path):
    """Create an in-memory state store with credential table."""
    db_path = tmp_path / "test.db"
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("test", {"name": "test", "targets": []})
    cred_store = CredentialStore(state)
    await cred_store.initialize()
    yield cred_store, eid, state
    await state.close()


# ---------------------------------------------------------------------------
# Default credentials
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_dvwa_defaults(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("dvwa")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("admin", "password") in pairs

    def test_tomcat_defaults(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("tomcat")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("tomcat", "tomcat") in pairs

    def test_wordpress_defaults(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("wordpress")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("admin", "admin") in pairs

    def test_phpmyadmin_defaults(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("phpmyadmin")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("root", "") in pairs

    def test_juice_shop_defaults(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("juice_shop")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("admin", "admin123") in pairs

    def test_generic_defaults_included(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("dvwa")
        pairs = [(d["username"], d["password"]) for d in defaults]
        # Generic defaults should also be included
        assert ("admin", "admin") in pairs
        assert ("root", "root") in pairs
        assert ("test", "test") in pairs

    def test_unknown_tech_returns_generic_only(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("unknown_app")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("admin", "admin") in pairs
        assert ("root", "root") in pairs

    def test_case_insensitive_lookup(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("DVWA")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert ("admin", "password") in pairs

    def test_no_duplicates(self) -> None:
        cs = CredentialStore.__new__(CredentialStore)
        defaults = cs.get_defaults_for_technology("generic")
        pairs = [(d["username"], d["password"]) for d in defaults]
        assert len(pairs) == len(set(pairs))


# ---------------------------------------------------------------------------
# Database CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_and_get(store) -> None:
    cred_store, eid, _ = store
    cred_id = await cred_store.add(eid, "admin", "secret", technology="dvwa")
    assert cred_id

    creds = await cred_store.get(eid)
    assert len(creds) == 1
    assert creds[0].username == "admin"
    assert creds[0].password == "secret"
    assert creds[0].technology == "dvwa"
    assert creds[0].valid is None  # untested


@pytest.mark.asyncio
async def test_get_by_technology(store) -> None:
    cred_store, eid, _ = store
    await cred_store.add(eid, "admin", "pass1", technology="dvwa")
    await cred_store.add(eid, "root", "pass2", technology="mysql")

    dvwa_creds = await cred_store.get(eid, technology="dvwa")
    assert len(dvwa_creds) == 1
    assert dvwa_creds[0].username == "admin"


@pytest.mark.asyncio
async def test_mark_valid(store) -> None:
    cred_store, eid, _ = store
    cred_id = await cred_store.add(eid, "admin", "password")

    await cred_store.mark_valid(cred_id)

    creds = await cred_store.get(eid)
    assert creds[0].valid is True


@pytest.mark.asyncio
async def test_mark_invalid(store) -> None:
    cred_store, eid, _ = store
    cred_id = await cred_store.add(eid, "admin", "wrong")

    await cred_store.mark_invalid(cred_id)

    creds = await cred_store.get(eid)
    assert creds[0].valid is False


@pytest.mark.asyncio
async def test_get_all_valid(store) -> None:
    cred_store, eid, _ = store
    id1 = await cred_store.add(eid, "admin", "good")
    id2 = await cred_store.add(eid, "admin", "bad")
    id3 = await cred_store.add(eid, "root", "also_good")

    await cred_store.mark_valid(id1)
    await cred_store.mark_invalid(id2)
    await cred_store.mark_valid(id3)

    valid = await cred_store.get_all_valid(eid)
    assert len(valid) == 2
    usernames = {c.username for c in valid}
    assert usernames == {"admin", "root"}


@pytest.mark.asyncio
async def test_seed_defaults(store) -> None:
    cred_store, eid, _ = store
    ids = await cred_store.seed_defaults(eid, "dvwa")
    assert len(ids) > 0

    creds = await cred_store.get(eid)
    pairs = [(c.username, c.password) for c in creds]
    assert ("admin", "password") in pairs
    assert all(c.source == "default" for c in creds)


@pytest.mark.asyncio
async def test_add_with_url(store) -> None:
    cred_store, eid, _ = store
    await cred_store.add(eid, "admin", "pass", url="http://target.com/login", source="discovered")

    creds = await cred_store.get(eid)
    assert creds[0].url == "http://target.com/login"
    assert creds[0].source == "discovered"
