#!/usr/bin/env python3
"""Suite offline de wudder (sin endpoint GraphQL).

La suite de integración (tests/test.py, con run-tests.sh) requiere credenciales
y endpoint; esta suite cubre la lógica interna sin infraestructura:
constantes graphn, hashing (sha3_512, ordered_stringify, cthash), Fragment y
Event completos.
"""
import hashlib
import json

import pytest

from wudder import __version__, graphn, utils
from wudder.event import Event, EventTypes, Fragment


def test_version():
    assert __version__ == "4.2610.0"


# ------------------------------------------------------------------ graphn
def test_graphn_constants():
    assert graphn.PROTOCOL_VERSION == 3
    assert graphn.HASH_LENGTH == 128
    assert graphn.ZEROS_HASH == "0" * 128
    assert graphn.MAX_TX_SIGNATURE_LENGTH == 256


def test_graphn_nodecodes():
    assert graphn.Nodecodes.CREATE_GRAPH == 1
    assert graphn.Nodecodes.EXTEND_GRAPH == 2
    assert graphn.Nodecodes.VALIDATE_NODE == 3


# ------------------------------------------------------------------- utils
def test_sha3_512_matches_reference():
    for text in ("", "abc", "wudder event content"):
        expected = hashlib.sha3_512(text.encode("utf-8")).hexdigest()
        assert utils.sha3_512(text) == expected


def test_ordered_stringify_sorts_keys():
    result = utils.ordered_stringify({"b": 2, "a": 1, "c": [3]})
    parsed_pairs = json.loads(result, object_pairs_hook=lambda pairs: pairs)
    assert [key for key, _ in parsed_pairs] == ["a", "b", "c"]
    assert dict(parsed_pairs) == {"a": 1, "b": 2, "c": [3]}


def test_cthash_is_deterministic_regardless_of_key_order():
    content_a = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [
            {"field": "k1", "value": "v1"},
            {"field": "k2", "value": "v2", "salt": "s2"},
        ],
    }
    content_b = {
        "trace": graphn.ZEROS_HASH,
        "type": "TRACE",
        "fragments": [
            {"value": "v1", "field": "k1"},
            {"salt": "s2", "value": "v2", "field": "k2"},
        ],
    }
    assert utils.cthash(content_a) == utils.cthash(content_b)


def test_cthash_depends_on_fragments_and_trace():
    base = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [{"field": "k", "value": "v"}],
    }
    different_value = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [{"field": "k", "value": "otra"}],
    }
    different_trace = dict(base, trace="f" * 128)
    assert utils.cthash(base) != utils.cthash(different_value)
    assert utils.cthash(base) != utils.cthash(different_trace)


def test_cthash_ignores_visibility_but_not_salt():
    without_salt = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [{"field": "k", "value": "v", "visibility": "private"}],
    }
    other_visibility = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [{"field": "k", "value": "v", "visibility": "public"}],
    }
    with_salt = {
        "type": "TRACE",
        "trace": graphn.ZEROS_HASH,
        "fragments": [
            {"field": "k", "value": "v", "visibility": "private", "salt": "s"},
        ],
    }
    # visibility no entra en el hash del fragmento
    assert utils.cthash(without_salt) == utils.cthash(other_visibility)
    # el salt sí cambia el hash
    assert utils.cthash(without_salt) != utils.cthash(with_salt)


# ------------------------------------------------------------------ eventos
def test_event_types():
    assert EventTypes.TRACE == "TRACE"
    assert EventTypes.ADD_EVENT == "ADD_EVENT"
    assert EventTypes.VALIDATE == "VALIDATE"
    assert EventTypes.FILE == "FILE"


def test_fragment_defaults():
    fragment = Fragment(field="k", value="v")
    assert fragment.visibility == Fragment.VISIBILITY_PUBLIC
    assert fragment.salt is None
    assert fragment.dict == {"field": "k", "value": "v", "visibility": "public"}


def test_fragment_with_salt_roundtrip():
    fragment = Fragment(
        field="k", value="v", visibility=Fragment.VISIBILITY_PRIVATE, salt="s"
    )
    exported = fragment.dict
    assert exported == {
        "field": "k",
        "value": "v",
        "visibility": "private",
        "salt": "s",
    }
    reloaded = Fragment(fragment_dict=exported)
    assert reloaded.field == fragment.field
    assert reloaded.value == fragment.value
    assert reloaded.visibility == fragment.visibility
    assert reloaded.salt == fragment.salt


def test_fragment_dict_defaults_when_loading():
    reloaded = Fragment(fragment_dict={"field": "k", "value": "v"})
    assert reloaded.visibility == Fragment.VISIBILITY_PUBLIC
    assert reloaded.salt is None


def test_fragment_match():
    a = Fragment(field="k", value="v")
    b = Fragment(field="k", value="v", visibility="private", salt="s")
    assert a.match(b)
    assert not a.match(Fragment(field="k", value="otro"))
    assert not a.match(Fragment(field="otra", value="v"))


# -------------------------------------------------------------------- Event
def _fragments():
    return [Fragment(field="k", value="v"), Fragment(field="k2", value="v2")]


def test_event_new_without_trace_uses_zero_trace():
    event = Event(fragments=_fragments())
    assert event.type == EventTypes.TRACE
    assert event.trace == graphn.ZEROS_HASH
    assert isinstance(event.timestamp, int)
    assert event.salt is None
    assert event.proof is None


def test_event_with_trace_is_add_event_type():
    event = Event(fragments=_fragments(), trace="a" * 128)
    assert event.type == EventTypes.ADD_EVENT
    assert event.trace == "a" * 128


def test_event_requires_list_of_fragments():
    with pytest.raises(TypeError):
        Event(fragments="no es lista")
    with pytest.raises(TypeError):
        Event(fragments=[{"field": "k", "value": "v"}])


def test_event_dict_roundtrip():
    event = Event(
        fragments=_fragments(),
        trace="b" * 128,
        event_type=EventTypes.ADD_EVENT,
        salt="sal",
    )
    exported = event.dict
    assert exported["trace"] == "b" * 128
    assert exported["type"] == EventTypes.ADD_EVENT
    assert exported["salt"] == "sal"
    assert exported["fragments"] == [f.dict for f in _fragments()]

    # la carga desde dict sí preserva un timestamp explícito
    exported["timestamp"] = 1234567890
    reloaded = Event(event_dict=exported)
    assert reloaded.timestamp == 1234567890
    assert reloaded.salt == "sal"
    assert [f.dict for f in reloaded.fragments] == exported["fragments"]


def test_event_dict_without_salt_omits_key():
    event = Event(fragments=_fragments())
    assert "salt" not in event.dict


def test_event_dict_load_defaults():
    reloaded = Event(event_dict={
        "fragments": [{"field": "k", "value": "v"}],
        "trace": graphn.ZEROS_HASH,
        "type": EventTypes.TRACE,
    })
    assert reloaded.salt is None
    assert reloaded.proof is None
    assert isinstance(reloaded.timestamp, int)


def test_event_match_detects_differences():
    base = {
        "fragments": [f.dict for f in _fragments()],
        "trace": graphn.ZEROS_HASH,
        "type": EventTypes.TRACE,
        "timestamp": 1,
    }
    a = Event(event_dict=base)
    equal = Event(event_dict=dict(base))
    assert a.match(equal)

    different_value = Event(event_dict=dict(base, fragments=[
        {"field": "k", "value": "otra"},
        {"field": "k2", "value": "v2"},
    ]))
    assert not a.match(different_value)

    different_timestamp = Event(event_dict=dict(base, timestamp=2))
    assert not a.match(different_timestamp)

    different_trace = Event(event_dict=dict(base, trace="c" * 128))
    assert not a.match(different_trace)


def test_event_fragments_property_returns_copies():
    event = Event(fragments=_fragments())
    copies = event.fragments
    assert copies is not event._fragments
    assert [f.dict for f in copies] == [f.dict for f in event._fragments]
