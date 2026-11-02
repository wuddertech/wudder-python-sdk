"""SDK trace retrieval and the protocol-3 corroboration contract, offline."""
import json
from unittest.mock import Mock, patch

import pytest
from wudder import Wudder, Event, EventTypes, Fragment, graphn, utils, exceptions
from wudder.client import WudderClient


def test_trace_retrieves_all_children_and_keeps_masked_content_without_proof():
    client = object.__new__(WudderClient)
    masked = {'type': 'TRACE', 'fragments': ['f' * 128]}
    root = {'evhash': 'a' * 128, 'type': 'TRACE', 'displayName': 'Root',
            'originalContent': json.dumps({'content': masked}), 'graphnData': None}
    child = {**root, 'evhash': 'b' * 128, 'type': 'VALIDATE',
             'graphnData': json.dumps({'tx': {'nodecode': 3}})}
    client.graphql = Mock()
    client.graphql.execute.return_value = ({'trace': {
        'creationEvidence': root, 'childs': [child]}}, None)
    result = client.get_trace('a' * 128)
    assert result['creationEvidence']['event'] == masked
    assert result['childs'][0]['evhash'] == 'b' * 128
    assert result['childs'][0]['tx'] == {'nodecode': 3}
    assert client.graphql.execute.call_args.args[1] == {'evhash': 'a' * 128}
    client._get_trace_call = Mock(side_effect=exceptions.NotFoundError())
    assert client.get_trace('c' * 128) is None


def test_corroboration_uses_validate_node_without_content_hash_in_both_modes():
    owner = object.__new__(Wudder)
    owner._wudder_client = Mock()
    owner._send_event = Mock(return_value='signed')
    owner._wudder_client.send_event_directly.return_value = 'direct'
    for direct in (False, True):
        assert owner.corroborate('A' * 128, direct=direct) == ('direct' if direct else 'signed')
        call = owner._wudder_client.send_event_directly if direct else owner._send_event
        event = call.call_args.args[1]
        assert event.type == EventTypes.VALIDATE and event.trace == 'a' * 128
        assert event.fragments == []
        tx = utils.get_event_tx(event)
        assert tx['version'] == 3 and tx['nodecode'] == 3
        assert tx['from'] == ['a' * 128] and 'cthash' not in tx
    for value in (None, '', 'a', 'x' * 128, graphn.ZEROS_HASH):
        with pytest.raises(ValueError):
            owner.corroborate(value)


def test_explicit_timestamp_fragment_count_and_batch_type_are_preserved():
    event = Event(fragments=[], timestamp=1700000000000)
    assert event.timestamp == 1700000000000 and event.type == EventTypes.TRACE
    assert not event.match(Event(fragments=[Fragment(field='extra', value='v')], timestamp=event.timestamp))
    bundle = {'title': 'Approval', 'type': EventTypes.VALIDATE, 'trace': 'a' * 128, 'fragments': []}
    owner = object.__new__(Wudder)
    owner._send_many_events = Mock()
    owner.send_many([bundle])
    assert owner._send_many_events.call_args.args[0][0]['event'].type == EventTypes.VALIDATE
    assert set(bundle) == {'title', 'type', 'trace', 'fragments'}


def test_new_account_key_is_loaded_before_first_signature():
    owner = object.__new__(Wudder)
    owner._private_key = None
    owner._wudder_client = Mock()
    owner._wudder_client.login.return_value = None
    key = {'crypto': 'synthetic'}
    with patch('wudder.wudder.utils.generate_private_key', return_value=key), \
            patch('wudder.wudder.EcdsaPrivateKey') as constructor:
        owner._login('test@example.invalid', 'password', 'key-password')
    assert owner.private_key is constructor.return_value
    owner._wudder_client.update_private_key.assert_called_once_with(key)
