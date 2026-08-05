"""Unit tests for structured-body addressing (keyless — pure functions)."""

from __future__ import annotations

from clinkz.agents._json_body import (
    get_json_path,
    is_nested,
    json_unescape,
    leaf_name,
    leaf_paths,
    locate_in_body,
    locate_value,
    parse_path,
    set_json_path,
)


def test_path_grammar() -> None:
    assert parse_path("a.b[2].c") == ["a", "b", 2, "c"]
    assert parse_path("field") == ["field"]
    assert parse_path("") == []
    assert parse_path("bad[") == []
    assert leaf_name("user.email") == "email"
    assert leaf_name("items[0]") == "items"
    assert is_nested("a.b") and not is_nested("a")


def test_set_json_path_builds_the_shape_the_target_declared() -> None:
    body: dict = {}
    assert set_json_path(body, "config.application.name", "X")
    assert set_json_path(body, "config.server.port", 8080)
    assert set_json_path(body, "items[1].sku", "S")
    assert body == {
        "config": {"application": {"name": "X"}, "server": {"port": 8080}},
        "items": [{}, {"sku": "S"}],
    }
    assert get_json_path(body, "items[1].sku") == "S"
    assert get_json_path(body, "nope.x") is None


def test_setting_one_field_leaves_its_siblings_intact() -> None:
    """The G8 rule generalised: an endpoint that validates its input rejects a
    body whose unrelated fields were dropped, and a rejected request never
    reaches the sink."""
    body = {"email": "a@b.c", "profile": {"name": "n", "bio": "b"}, "tags": ["x"]}
    assert set_json_path(body, "profile.bio", "PAYLOAD")
    assert body == {"email": "a@b.c", "profile": {"name": "n", "bio": "PAYLOAD"}, "tags": ["x"]}


def test_leaf_paths_drops_containers_of_other_paths() -> None:
    """Writing to ``config`` would destroy the object holding the field under test."""
    assert leaf_paths(["config", "config.app", "config.app.name", "comment"]) == [
        "config.app.name",
        "comment",
    ]


def test_set_json_path_refuses_rather_than_destroys() -> None:
    body = {"a": "already a string"}
    # ``a`` is replaced by a container only because the path demands one; a
    # write into a list where a dict is required is refused instead.
    assert set_json_path(body, "a.b", 1)
    assert body == {"a": {"b": 1}}
    assert not set_json_path({}, "", 1)


def test_locate_value_says_where_a_marker_came_back() -> None:
    """A path distinguishes an API quoting our input back from a stored record."""
    body = '{"data":[{"comment":"hi CLZ1 there"}],"errors":[{"msg":"bad input CLZ1"}]}'
    assert locate_in_body(body, "CLZ1") == ["data[0].comment", "errors[0].msg"]
    assert locate_in_body("not json", "CLZ1") == []
    assert locate_value({"a": "x"}, "") == []


def test_json_escaped_reflection_is_still_found() -> None:
    """A JSON API re-encodes the payload on the way out."""
    assert json_unescape(r"a<b\/c") == "a<b/c"
    assert locate_in_body(r'{"data":[{"c":"x<script>"}]}', "<script>") == ["data[0].c"]


def test_hostile_structures_are_bounded() -> None:
    deep = "[" * 200 + "1" + "]" * 200
    assert locate_in_body(deep, "1") == []  # too deep to reach, and it returns
    wide = '{"data":[' + ",".join('{"f":"m"}' for _ in range(500)) + "]}"
    assert len(locate_in_body(wide, "m")) <= 8
