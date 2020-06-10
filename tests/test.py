#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from wudder import Wudder, Fragment
from os import environ
from tests import env


class TestWudder(unittest.TestCase):
    wudder = Wudder(environ['WUDDER_EMAIL'],
                    environ['WUDDER_PASSWORD'],
                    environ['WUDDER_PRIVATE_KEY_PASSWORD'],
                    graphql_endpoint=environ['GRAPHQL_ENDPOINT'])

    evhash = env.evhash
    proof = env.proof
    event_dict = env.event_dict
    trace = env.trace
    evhash2 = env.evhash2
    sighash = env.sighash

    def test_create_proof(self):
        evhash = self.wudder.create_proof('Title', Fragment('clave', 'valor'))
        self.assertEqual(len(evhash), 64)

    def test_create_trace(self):
        evhash = self.wudder.create_trace('Title', Fragment('clave', 'valor'))
        self.assertEqual(len(evhash), 64)

    def test_add_event(self):
        evhash = self.wudder.add_event(self.evhash2, 'Title', Fragment('clave', 'valor'))
        self.assertEqual(len(evhash), 64)

    def test_get_event(self):
        event = self.wudder.get_event(self.evhash)
        self.assertDictEqual(event.dict, self.event_dict)

    # def test_get_trace(self):
    #     trace = self.wudder.get_trace(self.evhash)
    #     self.assertDictEqual(trace, self.trace)

    def test_get_proof(self):
        proof = self.wudder.get_proof(self.evhash)
        self.assertDictEqual(proof, self.proof)

    def test_check_ethereum_proof(self):
        self.assertTrue(
            self.wudder.check_ethereum_proof(self.proof['graphn_proof'], self.proof['anchor_txs']['ethereum']))

    def test_check_graphn_proof(self):
        self.assertTrue(self.wudder.check_graphn_proof(self.proof['graphn_proof']))

    def test_sighash(self):
        event = self.wudder.get_event(self.evhash2)
        self.assertTrue(self.wudder.check_sighash(self.sighash, event))


if __name__ == '__main__':
    unittest.main()