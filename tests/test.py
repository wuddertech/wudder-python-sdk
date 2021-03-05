#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from wudder import Wudder, Event, graphn, utils, exceptions
from os import environ
from tests import env
from easyweb3 import EasyWeb3
import time


class TestWudder(unittest.TestCase):
    wudder = Wudder(environ['WUDDER_EMAIL'],
                    environ['WUDDER_PASSWORD'],
                    private_key_password=environ['WUDDER_PRIVATE_KEY_PASSWORD'],
                    endpoint=environ['GRAPHQL_ENDPOINT'])

    evhash = env.evhash
    event_dict = env.event_dict
    new_evhash = None

    def test_create_trace_unsigned(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  full_signature=False)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_create_trace_signature(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  full_signature=True)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_create_trace_sighash(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  sighash_signature=True)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_create_trace_directly(self):
        evhash = self.wudder.send('Title', [{'field': 'key', 'value': 'value'}], direct=True)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_extend_trace(self):
        evhash = self.wudder.send('Title', [{'field': 'key', 'value': 'value'}], trace=self.evhash)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_extend_trace_directly(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  trace=self.evhash,
                                  direct=True)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_extend_trace_two_steps(self):
        prepared_hash = self.wudder.prepare('Title', [{'field': 'key', 'value': 'value'}])['hash']
        prepared_tx = self.wudder.get_prepared(prepared_hash)['tx']
        evhash = self.wudder.send_prepared(prepared_tx)
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_get_event(self):
        event = self.wudder.get_event(self.evhash)
        self.assertTrue(event.match(Event(event_dict=self.event_dict)))

    def test_get_proof(self):
        proof_data = self.wudder.get_proof(self.evhash)
        result = utils.check_compound_proof(proof_data['proof'])
        self.assertEqual(self.evhash, result['verified_hash'])

    def test_check_ethereum_proof(self):
        proof_data = self.wudder.get_proof(self.evhash)
        self.assertTrue(
            self.wudder.check_ethereum_proof(
                proof_data['proof'],
                proof_data['l1_suffixes']['ethereum']['tx_hash'],
            ))

    def test_check_graphn_proof(self):
        proof_data = self.wudder.get_proof(self.evhash)
        self.assertTrue(self.wudder.check_graphn_proof(proof_data['proof'], self.evhash))

    def test_signature(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  full_signature=True)
        event = self.wudder.get_event(evhash)
        attempts = 10
        while attempts > 0:
            attempts -= 1
            try:
                signature = self.wudder.get_proof(evhash)['signature']
                self.assertTrue(self.wudder.check_signature(signature, event))
                return
            except exceptions.NotFoundError:
                time.sleep(1)
        self.assertTrue(False)

    def test_sighash(self):
        evhash = self.wudder.send('Title', [{
            'field': 'key',
            'value': 'value'
        }],
                                  sighash_signature=True)
        event = self.wudder.get_event(evhash)
        attempts = 10
        while attempts > 0:
            attempts -= 1
            try:
                sighash = self.wudder.get_proof(evhash)['signature']
                self.assertTrue(self.wudder.check_sighash(sighash, event))
                return
            except exceptions.NotFoundError:
                time.sleep(1)
        self.assertTrue(False)

    def test_update_private_key(self):
        new_private_key = utils.generate_private_key(environ['WUDDER_PRIVATE_KEY_PASSWORD'])
        new_address = new_private_key['address']
        self.wudder.update_private_key(new_private_key, environ['WUDDER_PRIVATE_KEY_PASSWORD'])
        self.assertEqual(new_address, self.wudder.private_key._private_key.address[2:].lower())

    def test_get_non_existing_event(self):
        try:
            self.wudder.get_event(graphn.ZEROS_HASH)
            self.assertTrue(False)
        except exceptions.NotFoundError:
            self.assertTrue(True)

    def test_get_non_existing_trace(self):
        try:
            self.wudder.get_trace(graphn.ZEROS_HASH)
            self.assertTrue(False)
        except exceptions.NotFoundError:
            self.assertTrue(True)

    def test_get_non_existing_proof(self):
        try:
            self.wudder.get_proof(graphn.ZEROS_HASH)
            self.assertTrue(False)
        except exceptions.NotFoundError:
            self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()