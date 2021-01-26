#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import utils
from . import exceptions
from . import graphn
from easygraphql import GraphQL
import json
from threading import Thread
import time
import requests
from os import environ
from easyweb3 import EasyWeb3
import traceback

RETRY_ATTEMPTS = 3
RETRY_INTERVAL = 1

# TODO
# - get_tx
# - timestamp evento
# - evento simple
# - preparar tx -> url, etc
# - crear sin comprobar


def retry(method):
    def _try_except(self, *args, **kwargs):
        remaining_attempts = RETRY_ATTEMPTS
        while remaining_attempts > 1:
            try:
                return method(self, *args, **kwargs)
            except Exception:
                remaining_attempts -= 1
                time.sleep(RETRY_INTERVAL)
        return method(self, *args, **kwargs)

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
    def __init__(self,
                 fragments=None,
                 trace: str = None,
                 event_type: str = None,
                 timestamp: int = None,
                 salt: str = None,
                 event_dict: dict = None):
        if event_dict is not None:
            self._load_event_dict(event_dict)
            return

        if isinstance(fragments, Fragment):
            fragments = [fragments]
        self.fragments = fragments

        self._set_trace(trace)
        self.salt = salt

        self.type = event_type
        if self.type is None:
            if self.trace is None:
                self.type = EventTypes.TRACE
            else:
                self.type = EventTypes.ADD_EVENT

        if timestamp is None:
            self.timestamp = utils.get_timestamp_ms()

        self.proof = None

    def match(self, event):
        if isinstance(event, dict):
            event = Event(event_dict=event)

        for self_fragment, event_fragment in zip(self.fragments, event.fragments):
            if not self_fragment.match(event_fragment):
                return False

        if self.trace != event.trace:
            return False

        if self.type != event.type:
            return False

        if self.timestamp != event.timestamp:
            return False

        # Salt is added by the server

        return True

    def _set_trace(self, trace):
        if trace is None:
            trace = graphn.ZEROS_HASH
        self.trace = trace

    def _load_event_dict(self, event_dict):
        self.fragments = event_dict['fragments']
        self._set_trace(event_dict['trace'])
        self.type = event_dict['type']
        self.salt = event_dict['salt']
        self.timestamp = event_dict['timestamp']

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
        event_dict = {
            'fragments': fragments,
            'trace': self.trace,
            'type': self.type,
            'timestamp': self.timestamp
        }
        if self.salt is not None:
            event_dict['salt'] = self.salt
        return event_dict


class EventTypes:
    TRACE = 'TRACE'
    ADD_EVENT = 'ADD_EVENT'
    VALIDATE = 'VALIDATE'
    FILE = 'FILE'


class Wudder:
    DEFAULT_GRAPHQL_ENDPOINT = 'https://api.phoenix.wudder.tech/graphql/'
    DEFAULT_ETHEREUM_ENDPOINT = 'https://cloudflare-eth.com/'

    @staticmethod
    @retry
    def signup(email, password, private_key_password, graphql_endpoint=DEFAULT_GRAPHQL_ENDPOINT):
        private_key = utils.generate_private_key(private_key_password)
        EasyWeb3(private_key, private_key_password)
        Wudder._create_user(email, password, private_key, graphql_endpoint)

    @staticmethod
    @retry
    def _create_user(email, password, private_key, graphql_endpoint):
        mutation = '''
            mutation CreateUser($user: UserInput!, $password: String!){
                createUser(user: $user, password: $password) {
                    id
                }
            }
        '''
        variables = {
            'user': {
                'email': email,
                'ethAccount': utils.ordered_stringify(private_key)
            },
            'password': password
        }
        _, errors = GraphQL(graphql_endpoint).execute(mutation, variables)

        if errors:
            raise exceptions.SignupError

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
        self._manage_errors(errors)

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
            raise exceptions.AuthError

    def create_proof(self, title, fragments):
        return self.create_trace(title, fragments)

    def create_trace(self, title, fragments):
        return self._add_event(title, fragments, EventTypes.TRACE)

    def add_event(self, trace, title, fragments):
        return self._add_event(title, fragments, EventTypes.ADD_EVENT, trace)

    def get_tx(self, event: Event) -> dict:
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

    def check_sighash(self, sighash, event):
        tx = self.get_tx(event)
        obtained_sighash = self._get_sighash(tx)
        if obtained_sighash == sighash:
            return True
        return False

    def check_signature(self, signature, event):
        tx = self.get_tx(event)
        obtained_signature = self._get_signature(tx)
        if obtained_signature == signature:
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
        self._manage_errors(errors)

        if data['evidence'] is None:
            raise exceptions.NotFoundError

        original_content = json.loads(data['evidence']['originalContent'])['content']
        event_dict = {
            'type': original_content['type'],
            'trace': original_content['trace'],
            'fragments': original_content['fragments'],
            'timestamp': original_content['timestamp'],
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
        self._manage_errors(errors)

        if data['trace'] is None:
            raise exceptions.NotFoundError

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
        self._manage_errors(errors)

        if data['evidence'] is None or data['evidence']['graphnData'] is None:
            raise exceptions.NotFoundError

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

    def _add_event(self, title, fragments, event_type=None, trace=None):
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        server_tx, server_event = self._format_event(title, event)

        # Do not trust the server
        if not event.match(server_event):
            raise ValueError(f'event mismatch\n{event.dict}\nvs.\n{server_event.dict}')

        tx = self.get_tx(server_event)
        if utils.ordered_stringify(server_tx) != utils.ordered_stringify(tx):
            raise ValueError(
                f'tx mismatch\n{utils.ordered_stringify(server_tx)}\nvs.\n{utils.ordered_stringify(tx)}'
            )

        signature = ''
        if self.web3 is not None:
            signature = self._get_signature(tx)
        tx_str = utils.ordered_stringify(tx)
        evhash = self._send_event(tx_str, signature)
        return evhash

    def _extract_proof_from_graphn_data(self, graphn_data_str):
        graphn_data = json.loads(graphn_data_str)
        proof_dict = {'graphn_proof': graphn_data['proof']}
        if 'prefixes' in graphn_data and 'ethereum' in graphn_data['prefixes']:
            anchor_txs = {
                private_key: value['tx_hash']
                for private_key, value in graphn_data['prefixes'].items()
            }
            proof_dict['anchor_txs'] = anchor_txs
        return proof_dict

    def _check_ethereum_root_hash(self, anchor_tx, root_hash):
        eth_root_hash = self._get_ethereum_tx_input(anchor_tx,
                                                    self.ethereum_endpoint)[2:]  # remove 0x
        if eth_root_hash == root_hash:
            return True
        return False

    def _get_ethereum_tx_input(self, tx_hash, endpoint):
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": [tx_hash],
            "id": 1
        }
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
        self._manage_errors(errors)

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
        self._manage_errors(errors)

        tx = json.loads(data['formatTransaction']['formattedTransaction'])
        event = Event(event_dict=json.loads(data['formatTransaction']['preparedContent']))
        return tx, event

    @retry
    def _send_event(self, tx_str: str, signature=''):
        mutation = '''
            mutation ConfirmPreparedEvidence($evidence: PreparedEvidenceInput!){
                confirmPreparedEvidence(evidence: $evidence){
                    evhash
                }
            }
        '''
        variables = {'evidence': {'preparedEvidence': tx_str, 'signature': signature}}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_errors(errors)
        return data['confirmPreparedEvidence']['evhash']

    def _manage_errors(self, errors):
        if not errors:
            return

        try:
            if errors[0]['code'] == 429:
                raise exceptions.RateLimitExceededError(errors[0])

            if errors[0]['code'] == 404:
                raise exceptions.NotFoundError(errors[0])

            if errors[0]['code'] == 401:
                raise exceptions.AuthError(errors[0])

            if errors[0]['code'] == 400:
                raise exceptions.BadRequestError(errors[0])

        except KeyError:
            raise exceptions.UnexpectedError(errors[0])

    def _get_signature(self, tx):
        if isinstance(tx, str):
            tx = json.loads(tx)
        tx_str = utils.ordered_stringify(tx)
        signature = self.web3.sign(tx_str)
        return signature

    def _get_sighash(self, tx):
        signature = self._get_signature(tx)
        sighash = utils.sha3_512(signature)
        return sighash
