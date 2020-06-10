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

RETRY_ATTEMPTS = 3
RETRY_INTERVAL = 1


def retry(method):
    def _try_except(self, *args, **kwargs):
        remaining_attempts = RETRY_ATTEMPTS
        while remaining_attempts > 0:
            try:
                return method(self, *args, **kwargs)
                remaining_attempts = 0
            except Exception as e:
                remaining_attempts -= 1
                print(e)
                time.sleep(RETRY_INTERVAL)

    return _try_except


class Fragment:

    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_PRIVATE = 'private'

    def __init__(self,
                 field=None,
                 value=None,
                 visibility=VISIBILITY_PUBLIC,
                 salt: str = None,
                 fragment_dict: dict = None):
        if fragment_dict is not None:
            self._load_fragment_dict(fragment_dict)
            return

        self.field = field
        self.value = value
        self.visibility = visibility
        self.salt = salt

    def match(self, fragment):
        if isinstance(fragment, dict):
            fragment = Fragment(fragment_dict=fragment)

        if self.field != fragment.field:
            return False
        if self.value != fragment.value:
            return False
        return True

    def _load_fragment_dict(self, fragment_dict):
        self.field = fragment_dict['field']
        self.value = fragment_dict['value']
        if 'visibility' in fragment_dict:
            self.visibility = fragment_dict['visibility']
        else:
            self.visibility = Fragment.VISIBILITY_PUBLIC
        if 'salt' in fragment_dict:
            self.salt = fragment_dict['salt']
        else:
            self.salt = None

    @property
    def dict(self):
        fragment_dict = {'field': self.field, 'value': self.value, 'visibility': self.visibility}
        if self.salt is not None:
            fragment_dict['salt'] = self.salt
        return fragment_dict


class Event:

    TYPE_NEW_TRACE = 'NEW_TRACE'
    TYPE_NEW_EVENT = 'ADD_EVENT'

    def __init__(self, fragments=None, trace: str = None, salt: str = None, type_: str = None, event_dict: dict = None):
        if event_dict is not None:
            self._load_event_dict(event_dict)
            return

        if isinstance(fragments, Fragment):
            fragments = [fragments]
        self.fragments = fragments

        self.trace = trace

        if not type_:
            if self.trace is None:
                self.type = Event.TYPE_NEW_TRACE
            else:
                self.type = Event.TYPE_NEW_EVENT
        else:
            self.type = type_

        self.salt = salt
        self.proof = None

    def match(self, event):
        if isinstance(event, dict):
            event = Event(event_dict=event)

        if self.trace != event.trace:
            return False
        if self.type != event.type:
            return False
        for self_fragment, event_fragment in zip(self.fragments, event.fragments):
            if not self_fragment.match(event_fragment):
                return False
        return True

    def _load_event_dict(self, event_dict):
        self.fragments = event_dict['fragments']
        self.trace = event_dict['trace']
        self.type = event_dict['type']
        self.salt = event_dict['salt']
        if 'proof' in event_dict:
            self.proof = event_dict['proof']
        else:
            self.proof = None

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

    GRAPHN_PROTOCOL_VERSION = 1
    GRAPHN_NODECODE_CREATE_GRAPH = 1
    GRAPHN_NODECODE_EXTEND_GRAPH = 2

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

    @retry
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

    @retry
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

    @retry
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

    def create_proof(self, title, fragments):
        return self.create_trace(title, fragments)

    def create_trace(self, title, fragments):
        type_ = Event.TYPE_NEW_TRACE
        return self._add_event(title, fragments, type_)

    def add_event(self, trace, title, fragments):
        type_ = Event.TYPE_NEW_EVENT
        return self._add_event(title, fragments, type_, trace)

    def get_tx(self, event, version=GRAPHN_PROTOCOL_VERSION):
        cthash = utils.cthash(event.dict)
        tx = {'cthash': cthash, 'version': version}

        nodecode = Wudder.GRAPHN_NODECODE_CREATE_GRAPH
        if event.trace:
            if not isinstance(event.trace, list):
                event.trace = [event.trace]
            tx['from'] = event.trace
            nodecode = Wudder.GRAPHN_NODECODE_EXTEND_GRAPH

        tx['nodecode'] = nodecode
        return tx

    def check_sighash(self, sighash, event):
        tx = self.get_tx(event)
        obtained_sighash = self._get_sighash(tx)
        if obtained_sighash == sighash:
            return True
        return False

    @retry
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

    @retry
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

    @retry
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

    def _add_event(self, title, fragments, type_=None, trace=None):
        event = Event(fragments=fragments, trace=trace, type_=type_)
        server_tx, server_event = self._format_event(title, event)

        # Do not trust the server
        if not event.match(server_event):
            raise ValueError('event mismatch')

        tx = self.get_tx(server_event)
        if utils.ordered_stringify(server_tx) != utils.ordered_stringify(tx):
            raise ValueError('tx mismatch')

        signature = ''
        if self.web3 is not None:
            signature, tx_str = self._get_signature(tx)
        evhash = self._send_event(tx_str, signature)
        return evhash

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

    @retry
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

    @retry
    def _format_event(self, title, event):
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

        tx = json.loads(data['formatTransaction']['formattedTransaction'])
        event = Event(event_dict=json.loads(data['formatTransaction']['preparedContent']))
        return tx, event

    @retry
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

        try:
            if errors[0]['code'] == 429:
                raise RateLimitExceededError

            if errors[0]['code'] == 404:
                raise NotFoundError

            elif errors[0]['code'] == 401:
                raise AuthError

            raise UnexpectedError(errors[0]['message'])

        except KeyError:
            print(errors[0])

    def _get_sighash(self, tx):
        signature, _ = self._get_signature(tx)
        sighash = utils.mtk_512(signature)
        return sighash

    def _get_signature(self, tx):
        if isinstance(tx, str):
            tx = json.loads(tx)
        tx_str = utils.ordered_stringify(tx)
        signature = self.web3.sign(tx_str)
        return signature, tx_str