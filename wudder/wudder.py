#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils
from . import graphn
from .event import Event, Fragment, EventTypes
from .client import WudderClient
from digsig import PrivateKey, EcdsaPrivateKey, EcdsaFormats, EcdsaModes
import json
from typing import Dict, List
from os import environ as env


class Wudder:
    utils = utils

    @staticmethod
    def signup(
        email: str,
        password: str,
        private_key_password: str,
        endpoint: str = None,
    ):
        private_key = utils.generate_private_key(private_key_password)
        WudderClient.create_user(email, password, private_key, endpoint)

    def __init__(
        self,
        email: str,
        password: str,
        private_key=None,
        private_key_mode: str = None,
        private_key_format: str = None,
        private_key_password: str = None,
        private_key_path: str = None,
        endpoint: str = None,
        ethereum_endpoint: str = None,
    ):
        self._private_key = None
        if private_key is not None:
            self._private_key = PrivateKey.get_instance(
                key=private_key,
                mode=private_key_mode,
                key_format=private_key_format,
            )
        elif private_key_path is not None:
            self._private_key = PrivateKey.get_instance(
                filepath=private_key_path,
                password=private_key_password,
                mode=private_key_mode,
                key_format=private_key_format,
            )
        self._wudder_client = WudderClient(email, password, endpoint)
        self._login(email, password, private_key_password)

        if ethereum_endpoint is not None:
            self._ethereum_endpoint = ethereum_endpoint
        else:
            self._ethereum_endpoint = env['ETHEREUM_ENDPOINT'] \
                if 'ETHEREUM_ENDPOINT' in env \
                else 'https://cloudflare-eth.com/'

    @property
    def private_key(self) -> Dict:
        return self._private_key

    def send(
        self,
        title: str,
        fragments: Dict,
        trace: str = None,
        event_type: str = None,
        direct=False,
        full_signature=True,
        sighash_signature=False,
    ) -> str:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        fragments = [Fragment(**fragment) for fragment in fragments]
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        if direct:
            return self._wudder_client.send_event_directly(title, event)
        return self._send_event(title, event, full_signature,
                                sighash_signature)

    def send_many(
        self,
        event_bundles: List[Dict],
        full_signature=True,
        sighash_signature=False,
    ) -> str:
        processed_events = []
        for event_bundle in event_bundles:
            event_bundle['trace'] = event_bundle['trace'] if 'trace' in event_bundle else None
            event_bundle['type'] = EventTypes.TRACE if event_bundle['trace']  is None else EventTypes.ADD_EVENT
            event = Event(event_dict=event_bundle)
            processed_events.append({
                'event': event,
                'title': event_bundle['title']
            })
        return self._send_many_events(processed_events, full_signature,
                                      sighash_signature)

    def corroborate(self, trace: str, direct=False):
        raise NotImplementedError

    def get_event(self, evhash: str) -> Dict:
        return self._wudder_client.get_event(evhash)

    def get_trace(self, evhash: str) -> Dict:
        return self._wudder_client.get_trace(evhash)

    def prepare(self, title: str, fragments: Dict, trace: str = None) -> Dict:
        event_type = EventTypes.TRACE if trace is None \
            else EventTypes.ADD_EVENT
        fragments = [Fragment(**fragment) for fragment in fragments]
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        return self._wudder_client.prepare(title, event)

    def get_prepared(self, tmp_hash: str) -> Dict:
        return self._wudder_client.get_prepared(tmp_hash)

    def send_prepared(
        self,
        tx: Dict,
        full_signature=True,
        sighash_signature=False,
    ) -> str:
        signature = None
        if full_signature:
            signature = self._get_signature(tx)
        if sighash_signature:
            signature = self._get_sighash(tx)
        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash

    def check_ethereum_proof(self, graphn_proof: str, anchor_tx: str) -> bool:
        root_hash = utils.check_proof(graphn_proof)['root_hash']
        engraved_root_hash = utils.get_ethereum_tx_input(
            anchor_tx, self._ethereum_endpoint)[2:]  # remove 0x
        if root_hash == engraved_root_hash:
            return True
        return False

    def check_graphn_proof(self, graphn_proof: str, evhash: str) -> bool:
        result = utils.check_proof(graphn_proof)
        return evhash == result['verified_hash']

    def update_private_key(self, private_key: Dict, private_key_password: str):
        self._private_key = EcdsaPrivateKey(
            key=json.dumps(private_key),
            password=private_key_password,
            mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
            key_format=EcdsaFormats.ETHEREUM_JSON,
        )
        self._wudder_client.update_private_key(private_key)

    def _login(self, email: str, password: str, private_key_password: str):
        stored_private_key = self._wudder_client.login(email, password)

        if self.private_key:
            return

        if stored_private_key is not None:
            self._private_key = EcdsaPrivateKey(
                key=json.dumps(stored_private_key),
                password=private_key_password,
                mode=EcdsaModes.SECP256K1_KECCAK_256_ETHEREUM,
                key_format=EcdsaFormats.ETHEREUM_JSON,
            )
            return

        stored_private_key = utils.generate_private_key(private_key_password)
        self._wudder_client.update_private_key(stored_private_key)

    def _get_signature(self, tx: Dict) -> str:
        tx_str = utils.ordered_stringify(tx)
        signature = self._private_key.sign(tx_str).hex()
        return signature

    def _get_sighash(self, tx: Dict) -> str:
        signature = self._get_signature(tx)
        sighash = utils.sha3_512(signature)
        return sighash

    def _send_event(
        self,
        title: str,
        event: Event,
        full_signature: bool,
        sighash_signature: bool,
    ) -> str:
        result = self._wudder_client.prepare(title, event)

        # Do not trust the server
        if not event.match(result['event']):
            raise ValueError(
                f"event mismatch\n{event.dict}\nvs.\n{result['event'].dict}")

        tx = utils.get_event_tx(result['event'])
        if utils.ordered_stringify(
                result['tx']) != utils.ordered_stringify(tx):
            raise ValueError(
                f"tx mismatch\n{utils.ordered_stringify(result['tx'])}"
                f"\nvs.\n{utils.ordered_stringify(tx)}")

        signature = None
        if full_signature:
            signature = self._get_signature(tx)
        if sighash_signature:
            signature = self._get_sighash(tx)

        evhash = self._wudder_client.send_prepared(tx, signature)
        return evhash

    def _send_many_events(
        self,
        processed_events: List[Event],
        full_signature: bool,
        sighash_signature: bool,
    ) -> List[str]:
        event_bundles = []
        for processed_event in processed_events:
            tx = utils.get_event_tx(processed_event['event'])
            signature = None
            if full_signature:
                signature = self._get_signature(tx)
            if sighash_signature:
                signature = self._get_sighash(tx)
            event_bundle = processed_event
            event_bundle['signature'] = signature
            event_bundles.append(event_bundle)

        return self._wudder_client.send_events_directly(event_bundles)
