#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils
from .errors import *
from easygraphql import GraphQL
import json
from threading import Thread
import time
import requests
from os import environ
from easyweb3 import EasyWeb3


class Fragment:

    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_PRIVATE = 'private'

    def __init__(self, field=None, value=None, visibility=VISIBILITY_PUBLIC, fragment_dict: dict = None):
        if fragment_dict is not None:
            self._load_fragment_dict(fragment_dict)
            return

        self.field = field
        self.value = value
        self.visibility = visibility

    def _load_fragment_dict(self, fragment_dict):
        self.field = fragment_dict['field']
        self.value = fragment_dict['value']
        if 'visibility' in fragment_dict:
            self.visibility = fragment_dict['visibility']

    @property
    def dict(self):
        return {'field': self.field, 'value': self.value, 'visibility': self.visibility}


class Event:

    TYPE_NEW_TRACE = 'NEW_TRACE'
    TYPE_NEW_EVENT = 'ADD_EVENT'

    def __init__(self,
                 fragments=None,
                 trace: str = None,
                 operation_type: str = None,
                 salt: str = None,
                 event_dict: dict = None):
        if event_dict is not None:
            self._load_event_dict(event_dict)
            return

        if isinstance(fragments, Fragment):
            fragments = [fragments]
        self.fragments = fragments

        self.trace = trace

        if operation_type is None:
            operation_type = Event.TYPE_NEW_TRACE
        self.type = operation_type

        self.salt = salt

        self.proof = None

    def _load_event_dict(self, event_dict):
        self.fragments = event_dict['fragments']
        self.trace = event_dict['trace']
        self.type = event_dict['type']
        self.salt = event_dict['salt']
        if 'proof' in event_dict:
            self.proof = event_dict['proof']

    @property
    def dict(self):
        fragments = []
        for fragment in self.fragments:
            if isinstance(fragment, Fragment):
                fragment = fragment.dict
            fragments.append(fragment)
        event_dict = {'fragments': fragments, 'trace': self.trace, 'type': self.type}
        if self.salt is not None:
            event_dict['salt'] = self.salt
        return event_dict


class Wudder:

    DEFAULT_GRAPHQL_ENDPOINT = 'https://api.testnet.wudder.tech/graphql/'
    DEFAULT_ETHEREUM_ENDPOINT = 'https://cloudflare-eth.com/'

    @staticmethod
    def signup(email, password, private_key_password, graphql_endpoint=DEFAULT_GRAPHQL_ENDPOINT):
        private_key = utils.generate_private_key(private_key_password)
        EasyWeb3(private_key, private_key_password)
        Wudder._create_user(email, password, private_key, graphql_endpoint)

        remaining_attempts = 5
        done = False
        while not done:
            try:
                Wudder(email, password, private_key_password)
                done = True
            except NotFoundError:
                print('User creation failed, retrying...')
                if remaining_attempts > 0:
                    Wudder._create_user(email, password, private_key, graphql_endpoint)
                    remaining_attempts -= 1
                    time.sleep(5)

    def _create_user(email, password, private_key, graphql_endpoint):
        mutation = '''
            mutation CreateUser($user: UserInput!, $password: String!){
                createUser(user: $user, password: $password) {
                    id
                }
            }
        '''
        variables = {'user': {'email': email, 'ethAccount': utils.ordered_stringify(private_key)}, 'password': password}
        _, errors = GraphQL(graphql_endpoint).execute(mutation, variables)

        if errors:
            raise SignupError

    def __init__(self,
                 email,
                 password,
                 private_key_password,
                 graphql_endpoint=DEFAULT_GRAPHQL_ENDPOINT,
                 ethereum_endpoint=DEFAULT_ETHEREUM_ENDPOINT):
        self.graphql = GraphQL(graphql_endpoint)

        self._private_key_password = private_key_password
        self.web3 = None

        self._login(email, password, private_key_password)
        self.ethereum_endpoint = ethereum_endpoint
        Thread(target=self._loop_refresh, daemon=True).start()

    @property
    def private_key(self):
        return self._private_key

    def update_private_key(self, private_key):
        mutation = '''
            mutation UpdateUser($user: UserInput!){
                updateUser(user: $user) {
                    id
                }
            }
        '''
        if isinstance(private_key, dict):
            private_key = utils.ordered_stringify(private_key)
        variables = {'user': {'ethAccount': private_key}}
        self.graphql.execute(mutation, variables)

    def _login(self, email, password, private_key_password):
        mutation = '''
            mutation Login($email: String!, $password: String!) {
                login(email: $email, password: $password){
                    token
                    refreshToken
                    ethAccount
                }
            }
        '''
        variables = {'email': email, 'password': password}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_common_errors(errors)

        self.token = data['login']['token']
        self.refresh_token = data['login']['refreshToken']
        self._update_headers()

        # Create private_key if missing
        if not data['login']['ethAccount']:
            self._private_key = utils.generate_private_key(private_key_password)
            self.update_private_key(self._private_key)
        else:
            self._private_key = json.loads(data['login']['ethAccount'])

        try:
            self.web3 = EasyWeb3(self._private_key, private_key_password)
        except ValueError:
            raise AuthError

    def create_event(self, title, fragments, trace=None, operation=None):
        tx_dict, _ = self._format_event(title, fragments, trace, operation)
        signature = ''
        if self.web3 is not None:
            signature, tx_str = self._get_signature(tx_dict)
        evhash = self._send_event(tx_str, signature)
        return evhash

    def check_sighash(self, sighash, event, version=1, nodecode=1):
        cthash = utils.cthash(event.dict)
        tx_dict = {'cthash': cthash, 'nodecode': nodecode, 'version': version}

        if event.trace:
            if not isinstance(event.trace, list):
                event.trace = [event.trace]
            tx_dict['from'] = event.trace

        obtained_sighash = self._get_sighash(tx_dict)

        if obtained_sighash == sighash:
            return True
        return False

    def get_event(self, evhash):
        query = '''
            query GetEvidence($evhash: String!){
                evidence(evhash: $evhash){
                    graphnData
                    type
                    displayName
                    originalContent
                }
            }
        '''
        variables = {'evhash': evhash}
        data, errors = self.graphql.execute(query, variables)
        self._manage_common_errors(errors)

        if data['evidence'] is None:
            raise NotFoundError

        original_content = json.loads(data['evidence']['originalContent'])['content']

        event_dict = {
            'type': original_content['type'],
            'trace': original_content['trace'],
            'fragments': original_content['fragments'],
            'salt': original_content['salt']
        }
        event = Event(event_dict=event_dict)
        return event

    def get_trace(self, evhash):
        query = '''
            query GetTrace($evhash: String!){
                trace(evhash: $evhash){
                    creationEvidence {
                        evhash
                        type
                        graphnData
                        displayName
                        originalContent
                    }
                    childs {
                        evhash
                        type
                        graphnData
                        displayName
                        originalContent
                    }
                }
            }
        '''
        variables = {'evhash': evhash}
        data, errors = self.graphql.execute(query, variables)
        self._manage_common_errors(errors)

        if data['trace'] is None:
            raise NotFoundError

        return data['trace']

    def get_proof(self, evhash, force_tmp_l2_proof=False):
        query = '''
            query GetEvidence($evhash: String!){
                evidence(evhash: $evhash){
                    graphnData
                }
            }
        '''
        variables = {'evhash': evhash}
        data, errors = self.graphql.execute(query, variables)
        self._manage_common_errors(errors)

        if data['evidence'] is None or data['evidence']['graphnData'] is None:
            raise NotFoundError

        if 'graphnData' in data['evidence']:
            proof_dict = self._extract_proof_from_graphn_data(data['evidence']['graphnData'])
            if force_tmp_l2_proof or 'anchor_txs' in proof_dict:
                return proof_dict

    def check_ethereum_proof(self, graphn_proof, anchor_tx):
        root_hash = utils.get_root_hash(graphn_proof)
        return self._check_ethereum_root_hash(anchor_tx, root_hash)

    def check_graphn_proof(self, graphn_proof):
        if utils.get_root_hash(graphn_proof) is not None:
            return True
        return False

    def _extract_proof_from_graphn_data(self, graphn_data_str):
        graphn_data = json.loads(graphn_data_str)
        proof_dict = {'graphn_proof': graphn_data['proof']}
        if 'prefixes' in graphn_data and 'ethereum' in graphn_data['prefixes']:
            anchor_txs = {private_key: value['tx_hash'] for private_key, value in graphn_data['prefixes'].items()}
            proof_dict['anchor_txs'] = anchor_txs
        return proof_dict

    def _check_ethereum_root_hash(self, anchor_tx, root_hash):
        eth_root_hash = self._get_ethereum_tx_input(anchor_tx, self.ethereum_endpoint)[2:]  # remove 0x
        if eth_root_hash == root_hash:
            return True
        return False

    def _get_ethereum_tx_input(self, tx_hash, endpoint):
        payload = {"jsonrpc": "2.0", "method": "eth_getTransactionByHash", "params": [tx_hash], "id": 1}
        headers = {'Content-Type': 'application/json'}
        return requests.post(endpoint, json=payload, headers=headers).json()['result']['input']

    def _loop_refresh(self):
        while True:
            time.sleep(3600)
            self._refresh()

    def _update_headers(self):
        self.graphql.set_headers({'x-jwt-token': self.token})

    def _refresh(self):
        mutation = '''
            mutation RefreshToken($refreshToken: String!) {
                refreshToken(token: $refreshToken){
                    token
                    refreshToken
                }
            }
        '''
        variables = {'refreshToken': self.refresh_token}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_common_errors(errors)

        self.token = data['refreshToken']['token']
        self.refresh_token = data['refreshToken']['refreshToken']
        self._update_headers()

    def _format_event(self, title, fragments, trace, operation):
        event = Event(fragments, trace, operation)
        mutation = '''
            mutation FormatTransaction($content: ContentInput!, $displayName: String!){
                formatTransaction(content: $content, displayName: $displayName){
                    formattedTransaction
                    preparedContent
                }
            }
        '''
        variables = {'displayName': title, 'content': event.dict}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_common_errors(errors)

        formatted_transaction = json.loads(data['formatTransaction']['formattedTransaction'])
        prepared_content = json.loads(data['formatTransaction']['preparedContent'])
        return formatted_transaction, prepared_content

    def _send_event(self, tx_str, signature=''):
        mutation = '''
            mutation CreateEvidence($evidence: EvidenceInput!){
                createEvidence(evidence: $evidence){
                    evhash
                }
            }
        '''
        variables = {'evidence': {'event_tx': tx_str, 'signature': signature}}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_common_errors(errors)
        return data['createEvidence']['evhash']

    def _manage_common_errors(self, errors):
        if not errors:
            return

        if errors[0]['code'] == 429:
            raise RateLimitExceededError

        if errors[0]['code'] == 404:
            raise NotFoundError

        elif errors[0]['code'] == 401:
            raise AuthError

        raise UnexpectedError(errors[0]['message'])

    def _get_sighash(self, tx_dict):
        signature, _ = self._get_signature(tx_dict)
        sighash = utils.mtk_512(signature)
        return sighash

    def _get_signature(self, tx_dict):
        if isinstance(tx_dict, str):
            tx_dict = json.loads(tx_dict)
        tx_str = utils.ordered_stringify(tx_dict)
        signature = self.web3.sign(tx_str)
        return signature, tx_str