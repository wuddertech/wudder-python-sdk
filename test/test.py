#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from wudder import Wudder, Fragment
from os import environ
from test import env


class TestWudder(unittest.TestCase):

    user = environ['WUDDER_USER']
    password = environ['WUDDER_PASSWORD']
    graphql_endpoint = environ['GRAPHQL_ENDPOINT']

    wudder = Wudder(graphql_endpoint, user, password)

    evhash = env.evhash
    proof = env.proof
    event_dict = env.event_dict
    trace = env.trace

    def test_login(self):
        self.wudder.login(self.user, self.password)

    def test_create_event(self):
        evhash = self.wudder.create_event('Title', Fragment('clave', 'valor'))
        self.assertEqual(len(evhash), 64)

    def test_get_event(self):
        event = self.wudder.get_event(self.evhash)
        self.assertDictEqual(event.dict, self.event_dict)

    def test_get_trace(self):
        trace = self.wudder.get_trace(self.evhash)
        self.assertDictEqual(trace, self.trace)

    def test_get_proof(self):
        proof = self.wudder.get_proof(self.evhash)
        self.assertDictEqual(proof, self.proof)

    def test_check_ethereum_proof(self):
        self.assertTrue(
            self.wudder.check_ethereum_proof(self.proof['graphn_proof'], self.proof['anchor_txs']['ethereum']))

    def test_check_graphn_proof(self):
        self.assertTrue(self.wudder.check_graphn_proof(self.proof['graphn_proof']))


if __name__ == '__main__':
    unittest.main()