"""A credential key protects its value through a CONTAINER, not only bare.

``redact_structure`` is key-aware because a ``Set-Cookie`` value has no
intrinsic shape: the target chose it, and the only thing identifying it as the
session is the key it arrived under. The rule was written as::

    if isinstance(key, str) and isinstance(value, str):
        if key.strip().lower() in CREDENTIAL_HEADER_KEYS:

— and that second `isinstance` silently narrowed it to bare strings. Any
credential key whose value is a **list** stepped past the key rule into the
generic walk, where each element meets only the SHAPE rules, and a session
cookie the target named matches none of them.

That is not hypothetical. ``Set-Cookie`` is the one header a response
legitimately sends more than once, so the producers that keep all of them keep
them as a list (``HTTPClientOutput.set_cookie``, ``HopResponse.set_cookies``),
and ``model_dump()`` writes that list into the trace's ``parsed_output`` — which
``redact_structure`` is the last thing to touch before it lands in
``outputs/<id>/invocations/``. The header DICT beside it was redacted correctly
the whole time, which is what made the gap easy to miss.

Two failures, one defect, and the tests below pin both halves:

1. the key vocabulary knew ``set-cookie`` and not the ``set_cookie`` /
   ``set_cookies`` spelling a model field turns into after ``model_dump()``;
2. the walker's key rule did not survive a container.

The domain is computed: every credential key in the vocabulary is exercised
through every container the walker claims to handle, so a key added later is
covered without anybody remembering to extend a list here.
"""

from __future__ import annotations

import pytest

from clinkz.engagement.credential_shapes import CREDENTIAL_HEADER_KEYS
from clinkz.engagement.secrets import redact_structure

#: A value with no credential SHAPE at all. Nothing about it is recognisable —
#: it is protected by its key or it is not protected. A shaped value (a JWT, an
#: `sk-` token) would be caught by the string rules and prove nothing about the
#: key rule.
_SHAPELESS_SECRET = "qX7pLm2vRt9wZa4b"


@pytest.mark.parametrize("key", sorted(CREDENTIAL_HEADER_KEYS))
def test_a_credential_key_protects_a_bare_string(key: str) -> None:
    out = redact_structure({key: _SHAPELESS_SECRET})
    assert _SHAPELESS_SECRET not in repr(out), (
        f"a shapeless secret survived redaction under the credential key {key!r}"
    )


@pytest.mark.parametrize("key", sorted(CREDENTIAL_HEADER_KEYS))
@pytest.mark.parametrize("container", ["list", "tuple"])
def test_a_credential_key_protects_a_container_of_strings(key: str, container: str) -> None:
    """The half that was missing. A list under the key is still the key's value."""
    values = [f"first={_SHAPELESS_SECRET}", f"second={_SHAPELESS_SECRET}"]
    payload = {key: values if container == "list" else tuple(values)}
    out = redact_structure(payload)
    assert _SHAPELESS_SECRET not in repr(out), (
        f"a shapeless secret survived redaction inside a {container} under the "
        f"credential key {key!r} — the key rule did not reach through the container"
    )


def test_a_cookie_list_keeps_its_names_and_loses_its_values() -> None:
    """A name is evidence; a value is the session. Both halves, on the list form.

    Routing the model-field spelling to the generic header branch would have
    replaced each header whole and taken the cookie NAME with it, which is a
    different defect in the opposite direction: the report can no longer say
    which cookie the application set.
    """
    out = redact_structure(
        {
            "set_cookie": [
                "sid=qX7pLm2vRt9wZa4b; Path=/; HttpOnly",
                "csrf=Tm5xYw8dHs1nQe6u; Path=/",
            ]
        }
    )
    rendered = repr(out)
    assert "qX7pLm2vRt9wZa4b" not in rendered
    assert "Tm5xYw8dHs1nQe6u" not in rendered
    assert "sid=" in out["set_cookie"][0]
    assert "csrf=" in out["set_cookie"][1]


def test_the_producer_field_names_are_in_the_vocabulary() -> None:
    """The keys the models actually emit, named rather than assumed.

    ``model_dump()`` turns a field name into a dict key, so the vocabulary has
    to hold the field's spelling — the hyphenated header name never matches one.
    """
    from clinkz.tools.http_client import HTTPClientOutput
    from clinkz.tools.redirect_walk import HopResponse

    assert "set_cookie" in HTTPClientOutput.model_fields
    assert "set_cookie" in CREDENTIAL_HEADER_KEYS
    assert "set_cookies" in HopResponse._fields
    assert "set_cookies" in CREDENTIAL_HEADER_KEYS


def test_the_http_client_output_never_carries_a_cookie_value_into_a_trace() -> None:
    """End to end over the real model, on the path the trace writer takes.

    ``TraceWriter.attach_parsed_output`` calls ``redact_structure`` on the
    parsed model's ``model_dump()`` and writes the result to
    ``outputs/<id>/invocations/``. This is that call, with the model a real HTTP
    probe produces against a target that sets two cookies.
    """
    from clinkz.tools.http_client import HTTPClientOutput

    parsed = HTTPClientOutput(
        tool_name="http_client",
        success=True,
        status_code=200,
        response_headers={"Set-Cookie": "session=qX7pLm2vRt9wZa4b; Path=/; HttpOnly"},
        set_cookie=[
            "session=qX7pLm2vRt9wZa4b; Path=/; HttpOnly",
            "remember=Tm5xYw8dHs1nQe6u; Path=/",
        ],
        response_body="{}",
    )
    redacted = redact_structure(parsed.model_dump(mode="json"))
    rendered = repr(redacted)
    assert "qX7pLm2vRt9wZa4b" not in rendered, "the session cookie reached the trace"
    assert "Tm5xYw8dHs1nQe6u" not in rendered, "the second cookie reached the trace"
