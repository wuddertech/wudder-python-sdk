#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils
from . import graphn
from .event import Event, Fragment, EventTypes
from .client import WudderClient
from . import exceptions
from easyweb3 import EasyWeb3
from digsig import PrivateKey, PrivateKeyExtensions
import json


class Wudder:
    DEFAULT_ETHEREUM_ENDPOINT = 'https://cloudflare-eth.com/'

    @staticmethod
    def signup(email: str, password: str, private_key_password: str, endpoint: str = None):
        private_key = utils.generate_private_key(private_key_password)
        private_key = PrivateKey(
            content=json.dumps(private_key),
            extension=PrivateKeyExtensions.JSON,
            password=private_key_password,
        )
        WudderClient.create_user(email, password, private_key, endpoint)

    def __init__(self,
                 email: str,
                 password: str,
                 private_key_path: str = None,
                 private_key_password: str = None,
                 endpoint: str = None,
                 ethereum_endpoint: str = None):
        self._private_key = None
        if private_key_path is not None:
            self._private_key = PrivateKey(private_key_path, private_key_password)
        self._wudder_client = WudderClient(email, password, endpoint)
        self._login(email, password, private_key_password)
        if ethereum_endpoint is None:
            self._ethereum_endpoint = self.DEFAULT_ETHEREUM_ENDPOINT

    @property
    def private_key(self) -> dict:
        return self._private_key

    def send(self,
             title: str,
             fragments: dict,
             trace: str = None,
             event_type: str = None,
             direct=False,
             full_signature=True,
             sighash_signature=False) -> str:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        fragments = [Fragment(**fragment) for fragment in fragments]
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        if direct:
            return self._wudder_client.send_event_directly(title, event)
        return self._send_event(title, event, full_signature, sighash_signature)

    def corroborate(self, trace: str, direct=False):
        raise NotImplementedError

    def get_event(self, evhash: str) -> Event:
        return self._wudder_client.get_event(evhash)

    def get_trace(self, evhash: str) -> dict:
        return self._wudder_client.get_trace(evhash)

    def get_proof(self, evhash: str) -> dict:
        return self._wudder_client.get_proof(evhash)

    def prepare(self, title: str, fragments: dict, trace: str = None) -> dict:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        fragments = [Fragment(**fragment) for fragment in fragments]
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        return self._wudder_client.prepare(title, event)

    def get_prepared(self, tmp_hash: str) -> dict:
        return self._wudder_client.get_prepared(tmp_hash)

    def send_prepared(self, tx: dict, full_signature=True, sighash_signature=False) -> str:
        signature = None
        if full_signature:
            signature = self._get_signature(tx)
        if sighash_signature:
            signature = self._get_sighash(tx)
        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash

    def check_sighash(self, sighash: str, event: Event) -> bool:
        tx = utils.get_event_tx(event)
        obtained_sighash = self._get_sighash(tx)
        if obtained_sighash == sighash:
            return True
        return False

    def check_signature(self, signature: str, event: Event) -> bool:
        tx = utils.get_event_tx(event)
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

    def update_private_key(self, private_key: dict, private_key_password: str):
        self._private_key = PrivateKey(
            content=json.dumps(private_key),
            extension=PrivateKeyExtensions.JSON,
            password=private_key_password,
        )
        self._wudder_client.update_private_key(private_key)

    def _login(self, email: str, password: str, private_key_password: str):
        stored_private_key = self._wudder_client.login(email, password)
        if self.private_key is None:
            if stored_private_key is None:
                new_private_key = utils.generate_private_key(private_key_password)
                self._wudder_client.update_private_key(new_private_key)
                return

            self._private_key = PrivateKey(
                content=json.dumps(stored_private_key),
                extension=PrivateKeyExtensions.JSON,
                password=private_key_password,
            )

    def _get_signature(self, tx: dict) -> str:
        tx_str = utils.ordered_stringify(tx)
        signature = self._private_key.sign(tx_str)
        return signature

    def _get_sighash(self, tx: dict) -> str:
        signature = self._get_signature(tx)
        sighash = utils.sha3_512(signature)
        return sighash

    def _send_event(self, title: str, event: Event, full_signature: bool,
                    sighash_signature: bool) -> str:
        result = self._wudder_client.prepare(title, event)

        # Do not trust the server
        if not event.match(result['event']):
            raise ValueError(f"event mismatch\n{event.dict}\nvs.\n{result['event'].dict}")

        tx = utils.get_event_tx(result['event'])
        if utils.ordered_stringify(result['tx']) != utils.ordered_stringify(tx):
            raise ValueError(
                f"tx mismatch\n{utils.ordered_stringify(result['tx'])}\nvs.\n{utils.ordered_stringify(tx)}"
            )

        signature = None
        if full_signature:
            signature = self._get_signature(tx)
        if sighash_signature:
            signature = self._get_sighash(tx)

        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash
