#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils, errors
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

    def __init__(self, fragments=None, trace: str = None, operation_type=None, event_dict: dict = None):
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

        self.proof = None

    def _load_event_dict(self, event_dict):
        self.fragments = event_dict['fragments']
        self.trace = event_dict['trace']
        self.type = event_dict['type']
        if 'proof' in event_dict:
            self.proof = event_dict['proof']

    @property
    def dict(self):
        fragments = []
        for fragment in self.fragments:
            if isinstance(fragment, Fragment):
                fragment = fragment.dict
            fragments.append(fragment)
        return {'fragments': fragments, 'trace': self.trace, 'type': self.type}


class Wudder:
    def __init__(self,
                 graphql_endpoint,
                 email=None,
                 password=None,
                 key_path=None,
                 key_password=None,
                 ethereum_endpoint='https://cloudflare-eth.com/',
                 token=None,
                 refresh_token=None):
        self.graphql = GraphQL(graphql_endpoint)
        self.logged = False

        if key_password:
            if key_path is None:
                key_path = f'./{email}.json'
            self.web3 = EasyWeb3(key_path, key_password)
        self.web3 = None

        if token:
            self.token = token
        else:
            self.token = None

        if refresh_token:
            self.refresh_token = refresh_token
        else:
            self.refresh_token = None

        if self.token and self.refresh_token:
            self.logged = True
        else:
            self.logged = False

        self.ethereum_endpoint = ethereum_endpoint

        if email and password:
            self.login(email, password)

        Thread(target=self._loop_refresh, daemon=True).start()

    def signup(self, email, password='', key_path=None, key_password=None):
        if key_password is None:
            encrypted_key = None
        else:
            if key_path is None:
                key_path = f'./{email}.json'
            encrypted_key = utils.gen_key(key_path, key_password)
            self.web3 = EasyWeb3(key_path, key_password)
        self._create_user(email, password, encrypted_key)
        self.login(email, password)

    def update_key(self, encrypted_key):
        raise NotImplementedError
        # mutation = '''
        #     mutation UpdateUser($user: UserInput!){
        #         updateUser(user: $user) {
        #             id
        #         }
        #     }
        # '''
        # variables = {'user': {'ethAccount': encrypted_key}}
        # self.graphql.execute(mutation, variables)

    def login(self, email, password):
        mutation = '''
            mutation {
                login(email: "''' + email + '''", password: "''' + password + '''"){
                    token
                    refreshToken
                }
            }
        '''
        response = self.graphql.execute(mutation)

        if response['login'] is None:
            raise errors.AuthError

        self.token = response['login']['token']
        self.refresh_token = response['login']['refreshToken']
        self._update_headers()
        self.logged = True

    def create_event(self, title, fragments, trace=None, operation=None):
        transaction, _ = self._format_event(title, fragments, trace, operation)
        signature_hash = ''
        if self.web3 is not None:
            signature = self.web3.sign(transaction)
            signature_hash = utils.mtk_512(signature)
        evhash = self._send_event(transaction, signature_hash)
        return evhash

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
        response = self.graphql.execute(query, variables)

        if response['evidence'] is None:
            raise errors.UnknownEvent

        if 'graphnData' in response['evidence']:
            proof = self._extract_proof_from_graphn_data(response['evidence']['graphnData'])

        original_content = json.loads(response['evidence']['originalContent'])['content']

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
        response = self.graphql.execute(query, variables)

        if response['trace'] is None:
            raise errors.UnknownEvent

        return response['trace']

    def get_proof(self, evhash):
        query = '''
            query GetEvidence($evhash: String!){
                evidence(evhash: $evhash){
                    graphnData
                }
            }
        '''
        variables = {'evhash': evhash}
        response = self.graphql.execute(query, variables)

        if response['evidence'] is None:
            raise errors.UnknownEvent

        if 'graphnData' in response['evidence']:
            return self._extract_proof_from_graphn_data(response['evidence']['graphnData'])

    def check_ethereum_proof(self, graphn_proof, anchor_tx):
        root_hash = utils.get_root_hash(graphn_proof)
        return self._check_ethereum_root_hash(anchor_tx, root_hash)

    def check_graphn_proof(self, graphn_proof):
        if utils.get_root_hash(graphn_proof) is not None:
            return True
        return False

    def _extract_proof_from_graphn_data(self, graphn_data_str):
        graphn_data = json.loads(graphn_data_str)
        if 'prefixes' in graphn_data and 'telsius' in graphn_data['prefixes']:
            anchor_txs = {key: value['tx_hash'] for key, value in graphn_data['prefixes'].items()}
            return {'graphn_proof': graphn_data['proof'], 'anchor_txs': anchor_txs}

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
            if self.logged:
                time.sleep(3600)
                self._refresh()
            else:
                time.sleep(60)

    def _update_headers(self):
        self.graphql.set_headers({'x-jwt-token': self.token})

    def _create_user(self, email, password, key=None):
        mutation = '''
            mutation CreateUser($user: UserInput!, $password: String!){
                createUser(user: $user, password: $password) {
                    id
                }
            }
        '''
        variables = {'user': {'email': email}, 'password': password}
        if key is not None:
            variables['ethAccount'] = key
        self.graphql.execute(mutation, variables)

    def _refresh(self):
        mutation = '''
            mutation {
                refreshToken(token: "''' + self.refresh_token + '''"){
                    token
                    refreshToken
                }
            }
        '''
        response = self.graphql.execute(mutation)
        self.token = response['refreshToken']['token']
        self.refresh_token = response['refreshToken']['refreshToken']
        self._update_headers()

    def _format_event(self, title, fragments, trace=None, operation=None):
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
        response = self.graphql.execute(mutation, variables)
        formatted_transaction = response['formatTransaction']['formattedTransaction']
        prepared_content = json.loads(response['formatTransaction']['preparedContent'])
        return formatted_transaction, prepared_content

    def _send_event(self, transaction, signature_hash=''):
        mutation = '''
            mutation CreateEvidence($evidence: EvidenceInput!){
                createEvidence(evidence: $evidence){
                    evhash
                }
            }
        '''
        variables = {'evidence': {'event_tx': transaction, 'signature': signature_hash}}
        response = self.graphql.execute(mutation, variables)
        return response['createEvidence']['evhash']