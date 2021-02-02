#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations
from . import utils
from . import exceptions
from . import graphn
from easygraphql import GraphQL
import json
from threading import Thread
import time
from os import environ
from easyweb3 import EasyWeb3
import traceback

RETRY_ATTEMPTS = 2
RETRY_INTERVAL = 1


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
                 field: str = None,
                 value: str = None,
                 visibility: str = VISIBILITY_PUBLIC,
                 salt: str = None,
                 fragment_dict: dict = None):

        if fragment_dict is not None:
            self._load_fragment_dict(fragment_dict)
            return

        self.field = field
        self.value = value
        self.visibility = visibility
        self.salt = salt

    def match(self, fragment: Fragment) -> bool:
        if self.field != fragment.field:
            return False

        if self.value != fragment.value:
            return False

        return True

    def _load_fragment_dict(self, fragment: dict):
        self.field = fragment['field']
        self.value = fragment['value']

        if 'visibility' in fragment:
            self.visibility = fragment['visibility']
        else:
            self.visibility = Fragment.VISIBILITY_PUBLIC

        if 'salt' in fragment:
            self.salt = fragment['salt']
        else:
            self.salt = None

    @property
    def dict(self) -> dict:
        fragment_dict = {'field': self.field, 'value': self.value, 'visibility': self.visibility}
        if self.salt is not None:
            fragment_dict['salt'] = self.salt
        return fragment_dict


class Event:
    def __init__(self,
                 fragments: list = None,
                 trace: str = None,
                 event_type: str = None,
                 timestamp: int = None,
                 salt: str = None,
                 event_dict: dict = None):
        if event_dict is not None:
            self._load_event_dict(event_dict)
            return

        self._set_fragments(fragments)
        self._set_trace(trace)

        self.type = event_type
        if self.type is None:
            if self.trace is None:
                self.type = EventTypes.TRACE
            else:
                self.type = EventTypes.ADD_EVENT

        if timestamp is None:
            self.timestamp = utils.get_timestamp_ms()

        self.salt = salt
        self.proof = None

    @property
    def fragments(self) -> list:
        fragments = []
        for fragment in self._fragments:
            fragments.append(Fragment(fragment_dict=fragment.dict))
        return fragments

    def match(self, event: Event) -> bool:
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

    def _set_fragments(self, fragments: list):
        if not isinstance(fragments, list):
            raise TypeError

        for fragment in fragments:
            if not isinstance(fragment, Fragment):
                raise TypeError
        self._fragments = fragments

    def _set_trace(self, trace: str):
        if trace is None:
            trace = graphn.ZEROS_HASH
        self.trace = trace

    def _load_event_dict(self, event: dict):
        self._set_fragments([Fragment(fragment_dict=fragment) for fragment in event['fragments']])
        self._set_trace(event['trace'])
        self.type = event['type']
        self.salt = event['salt']
        self.timestamp = event['timestamp']

        if 'proof' in event:
            self.proof = event['proof']
        else:
            self.proof = None

    @property
    def dict(self) -> dict:
        fragments = []
        for fragment in self.fragments:
            fragments.append(fragment.dict)

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
    def signup(email: str,
               password: str,
               private_key_password: str,
               graphql_endpoint: str = DEFAULT_GRAPHQL_ENDPOINT):
        private_key = utils.generate_private_key(private_key_password)
        EasyWeb3(private_key, private_key_password)
        Wudder._create_user(email, password, private_key, graphql_endpoint)

    @staticmethod
    @retry
    def _create_user(email: str, password: str, private_key: str, graphql_endpoint: str):
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
                 email: str,
                 password: str,
                 private_key_password: str,
                 graphql_endpoint: str = DEFAULT_GRAPHQL_ENDPOINT,
                 ethereum_endpoint: str = DEFAULT_ETHEREUM_ENDPOINT):
        self.graphql = GraphQL(graphql_endpoint)

        self._private_key_password = private_key_password
        self.web3 = None

        self._login(email, password, private_key_password)
        self.ethereum_endpoint = ethereum_endpoint
        Thread(target=self._loop_refresh, daemon=True).start()

    @property
    def private_key(self) -> dict:
        return self._private_key

    @retry
    def update_private_key(self, private_key: str):
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



    def send(self,
             title: str,
             fragments: list,
             trace: str = None,
             event_type: str = None,
             direct=False) -> str:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        if direct:
            return self._send_event_directly(title, event)
        return self._send_event(title, event)

    def corroborate(self, trace: str, direct=False):
        raise NotImplementedError

    def prepare(self, title: str, fragments: list, trace: str = None) -> dict:
        event_type = EventTypes.TRACE if trace is None else EventTypes.ADD_EVENT
        event = Event(fragments=fragments, trace=trace, event_type=event_type)
        return self._prepare(title, event)

    def get_prepared(self, tmp_hash: str) -> dict:
        return self._get_prepared(tmp_hash)

    def send_prepared(self, tx: dict) -> str:
        signature = None
        if self.web3 is not None:
            signature = self._get_signature(tx)
        evhash = self._send_prepared(tx, signature)
        return evhash

    def get_event_tx(self, event: Event) -> dict:
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

    def check_sighash(self, sighash: str, event: Event) -> bool:
        tx = self.get_event_tx(event)
        obtained_sighash = self._get_sighash(tx)
        if obtained_sighash == sighash:
            return True
        return False

    def check_signature(self, signature: str, event: Event) -> bool:
        tx = self.get_event_tx(event)
        obtained_signature = self._get_signature(tx)
        if obtained_signature == signature:
            return True
        return False

    @retry
    def get_event(self, evhash: str) -> Event:
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

        return Event(event_dict=event_dict)

    @retry
    def get_trace(self, evhash: str) -> dict:
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


    def check_ethereum_proof(self, graphn_proof: str, anchor_tx: str) -> bool:
        root_hash = utils.check_compound_proof(graphn_proof)['root_hash']
        engraved_root_hash = utils.get_ethereum_tx_input(anchor_tx,
                                                         self.ethereum_endpoint)[2:]  # remove 0x
        if root_hash == engraved_root_hash:
            return True
        return False

    def check_graphn_proof(self, graphn_proof: str, evhash: str) -> bool:
        result = utils.check_compound_proof(graphn_proof)
        return evhash == result['verified_hash']

    @retry
    def _login(self, email: str, password: str, private_key_password: str):
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
        
    def _send_event(self, title: str, event: Event) -> str:
        result = self._prepare(title, event)

        # Do not trust the server
        if not event.match(result['event']):
            raise ValueError(f"event mismatch\n{event.dict}\nvs.\n{result['event'].dict}")

        tx = self.get_event_tx(result['event'])
        if utils.ordered_stringify(result['tx']) != utils.ordered_stringify(tx):
            raise ValueError(
                f"tx mismatch\n{utils.ordered_stringify(result['tx'])}\nvs.\n{utils.ordered_stringify(tx)}"
            )

        signature = None
        if self.web3 is not None:
            signature = self._get_signature(tx)
        evhash = self._send_prepared(tx, signature)
        return evhash

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
    def _send_event_directly(self, title: str, event: Event) -> str:
        mutation = '''
            mutation CreateEvidence($evidence: EvidenceInput!, $displayName: String!){
                createEvidence(evidence: $evidence, displayName: $displayName){
                    evhash
                }
            }
        '''
        variables = {'displayName': title, 'evidence': {'content': event.dict}}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_errors(errors)
        return data['createEvidence']['evhash']

    @retry
    def _prepare(self, title: str, event: Event) -> dict:
        mutation = '''
            mutation PrepareEvidence($content: ContentInput!, $displayName: String!){
                prepareEvidence(content: $content, displayName: $displayName){
                    formattedTransaction
                    preparedContent
                    hash
                    url
                }
            }
        '''
        variables = {'displayName': title, 'content': event.dict}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_errors(errors)

        output_data = {
            'tx': json.loads(data['prepareEvidence']['formattedTransaction']),
            'event': Event(event_dict=json.loads(data['prepareEvidence']['preparedContent'])),
            'hash': data['prepareEvidence']['hash'],
            'url': data['prepareEvidence']['url'],
        }
        return output_data

    @retry
    def _get_prepared(self, tmp_hash: str) -> dict:
        query = '''
            query PreparedEvidence($hash: String!){
                preparedEvidence(hash: $hash){
                    formattedTransaction
                    preparedContent
                    url
                }
            }
        '''
        variables = {'hash': tmp_hash}
        data, errors = self.graphql.execute(query, variables)
        self._manage_errors(errors)

        output_data = {
            'tx': json.loads(data['preparedEvidence']['formattedTransaction']),
            'event': Event(event_dict=json.loads(data['preparedEvidence']['preparedContent'])),
            'hash': tmp_hash,
            'url': data['preparedEvidence']['url'],
        }
        return output_data

    @retry
    def _send_prepared(self, tx: dict, signature: str = None) -> str:
        mutation = '''
            mutation ConfirmPreparedEvidence($evidence: PreparedEvidenceInput!){
                confirmPreparedEvidence(evidence: $evidence){
                    evhash
                }
            }
        '''
        tx_str = utils.ordered_stringify(tx)
        if signature is None:
            signature = ''
        variables = {'evidence': {'preparedEvidence': tx_str, 'signature': signature}}
        data, errors = self.graphql.execute(mutation, variables)
        self._manage_errors(errors)
        return data['confirmPreparedEvidence']['evhash']


    @retry
    def get_proof(self, evhash: str) -> dict:
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

        graphn_data = json.loads(data['evidence']['graphnData'])

        proof_data = {
            'block_proof': graphn_data['block_proof'],
        }
        if 'proof' in graphn_data:
            proof_data['proof'] = graphn_data['proof']
            proof_data['prefixes'] = graphn_data['prefixes']

        return proof_data

    def _manage_errors(self, errors: list):
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

    def _get_signature(self, tx: dict) -> str:
        tx_str = utils.ordered_stringify(tx)
        signature = self.web3.sign(tx_str)
        return signature

    def _get_sighash(self, tx: dict) -> str:
        signature = self._get_signature(tx)
        sighash = utils.sha3_512(signature)
        return sighash
