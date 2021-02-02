#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from wudder import Wudder, Event, Fragment, graphn, utils
from os import environ
from tests import env


class TestWudder(unittest.TestCase):
    wudder = Wudder(environ['WUDDER_EMAIL'],
                    environ['WUDDER_PASSWORD'],
                    environ['WUDDER_PRIVATE_KEY_PASSWORD'],
                    graphql_endpoint=environ['GRAPHQL_ENDPOINT'])

    evhash = env.evhash
    event_dict = env.event_dict

    evhash2 = env.evhash2
    signature = env.signature

    def test_create_proof(self):
        evhash = self.wudder.create_proof('Title', [Fragment('clave', 'valor')])
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_create_simple_proof(self):
        evhash = self.wudder.create_simple_proof('Title', [Fragment('clave', 'valor')])
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_create_trace(self):
        evhash = self.wudder.create_trace('Title', [Fragment('clave', 'valor')])
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_add_event(self):
        evhash = self.wudder.add_event(self.evhash2, 'Title', [Fragment('clave', 'valor')])
        self.assertEqual(len(evhash), graphn.HASH_LENGTH)

    def test_get_event(self):
        event = self.wudder.get_event(self.evhash)
        self.assertTrue(event.match(Event(event_dict=self.event_dict)))

    def test_get_proof(self):
        graphn_proof = self.wudder.get_proof(self.evhash)['proof']
        result = utils.check_compound_proof(graphn_proof)
        self.assertEqual(self.evhash, result['verified_hash'])

    def test_check_ethereum_proof(self):
        proof = self.wudder.get_proof(self.evhash)
        self.assertTrue(
            self.wudder.check_ethereum_proof(
                proof['proof'],
                proof['prefixes']['ethereum']['tx_hash'],
            ))

    def test_check_graphn_proof(self):
        graphn_proof = self.wudder.get_proof(self.evhash)['proof']
        self.assertTrue(self.wudder.check_graphn_proof(graphn_proof, self.evhash))

    def test_signature(self):
        event = self.wudder.get_event(self.evhash2)
        self.assertTrue(self.wudder.check_signature(self.signature, event))


if __name__ == '__main__':
    unittest.main()