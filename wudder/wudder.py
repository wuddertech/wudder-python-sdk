#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils
from .utils import retry
from . import graphn
from .event import Event, Fragment, EventTypes
from .client import WudderClient
from . import exceptions
from easyweb3 import EasyWeb3


class Wudder:
    DEFAULT_ETHEREUM_ENDPOINT = 'https://cloudflare-eth.com/'

    @staticmethod
    @retry
    def signup(email: str, password: str, private_key_password: str, graphql_endpoint: str = None):
        private_key = utils.generate_private_key(private_key_password)
        EasyWeb3(private_key, private_key_password)
        WudderClient.create_user(email, password, private_key, graphql_endpoint)

    def __init__(self,
                 email: str,
                 password: str,
                 private_key_password: str,
                 graphql_endpoint: str = None,
                 ethereum_endpoint: str = None):
        self._wudder_client = WudderClient(email, password, private_key_password, graphql_endpoint)
        self._login(email, password, private_key_password)
        if ethereum_endpoint is None:
            self._ethereum_endpoint = self.DEFAULT_ETHEREUM_ENDPOINT

    @property
    def private_key(self) -> dict:
        return self._private_key

    def _login(self, email: str, password: str, private_key_password: str):
        self._private_key = self._wudder_client.login(email, password, private_key_password)

        # Create private_key if missing
        if not self._private_key:
            self._private_key = utils.generate_private_key(private_key_password)
            self._wudder_client.update_private_key(self._private_key)

        try:
            self._web3 = EasyWeb3(self._private_key, private_key_password)
        except ValueError:
            raise exceptions.AuthError('private key cannot be decrypted')

    def send(self,
             title: str,
             fragments: list,
             trace: str = None,
             event_type: str = None,
             direct=False) -> str:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        if direct:
            return self._wudder_client.send_event_directly(title, event)
        return self._send_event(title, event)

    def corroborate(self, trace: str, direct=False):
        raise NotImplementedError

    def get_event(self, evhash: str) -> Event:
        return self._wudder_client.get_event(evhash)

    def get_trace(self, evhash: str) -> dict:
        return self._wudder_client.get_trace(evhash)

    def get_proof(self, evhash: str) -> dict:
        return self._wudder_client.get_proof(evhash)

    def prepare(self, title: str, fragments: list, trace: str = None) -> dict:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        return self._wudder_client.prepare(title, event)

    def get_prepared(self, tmp_hash: str) -> dict:
        return self._wudder_client.get_prepared(tmp_hash)

    def send_prepared(self, tx: dict) -> str:
        signature = None
        if self._web3 is not None:
            signature = self._get_signature(tx)
        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash

    def get_event_tx(self, event: Event) -> dict:
        cthash = utils.cthash(event.dict)
        tx = {'cthash': cthash, 'version': graphn.PROTOCOL_VERSION}

        tx['from'] = [event.trace]

        if event.type == EventTypes.TRACE:
            tx['nodecode'] = graphn.Nodecodes.CREATE_GRAPH
        elif event.type == EventTypes.ADD_EVENT:
            tx['nodecode'] = graphn.Nodecodes.EXTEND_GRAPH
        elif event.type == EventTypes.VALIDATE:
            tx['nodecode'] = graphn.Nodecodes.VALIDATE_NODE
        elif event.type == EventTypes.FILE:
            tx['nodecode'] = graphn.Nodecodes.CREATE_GRAPH

        return tx

    def check_sighash(self, sighash: str, event: Event) -> bool:
        tx = self.get_event_tx(event)
        obtained_sighash = self._get_sighash(tx)
        if obtained_sighash == sighash:
            return True
        return False

    def check_signature(self, signature: str, event: Event) -> bool:
        tx = self.get_event_tx(event)
        obtained_signature = self._get_signature(tx)
        if obtained_signature == signature:
            return True
        return False

    def check_ethereum_proof(self, graphn_proof: str, anchor_tx: str) -> bool:
        root_hash = utils.check_compound_proof(graphn_proof)['root_hash']
        engraved_root_hash = utils.get_ethereum_tx_input(anchor_tx,
                                                         self._ethereum_endpoint)[2:]  # remove 0x
        if root_hash == engraved_root_hash:
            return True
        return False

    def check_graphn_proof(self, graphn_proof: str, evhash: str) -> bool:
        result = utils.check_compound_proof(graphn_proof)
        return evhash == result['verified_hash']

    def _get_signature(self, tx: dict) -> str:
        tx_str = utils.ordered_stringify(tx)
        signature = self._web3.sign(tx_str)
        return signature

    def _get_sighash(self, tx: dict) -> str:
        signature = self._get_signature(tx)
        sighash = utils.sha3_512(signature)
        return sighash

    def _send_event(self, title: str, event: Event) -> str:
        result = self._wudder_client.prepare(title, event)

        # Do not trust the server
        if not event.match(result['event']):
            raise ValueError(f"event mismatch\n{event.dict}\nvs.\n{result['event'].dict}")

        tx = self.get_event_tx(result['event'])
        if utils.ordered_stringify(result['tx']) != utils.ordered_stringify(tx):
            raise ValueError(
                f"tx mismatch\n{utils.ordered_stringify(result['tx'])}\nvs.\n{utils.ordered_stringify(tx)}"
            )

        signature = None
        if self._web3 is not None:
            signature = self._get_signature(tx)

        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash