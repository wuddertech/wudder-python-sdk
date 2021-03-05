#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .utils import retry
from . import exceptions
from . import utils
from .event import Event, Fragment
from easygraphql import GraphQL
from threading import Thread
import time
import json


class WudderClient:
    DEFAULT_GRAPHQL_ENDPOINT = 'https://api.pre.wudder.tech/graphql/'

    def __init__(self, email: str, password: str, endpoint: str = None):
        if endpoint is None:
            endpoint = self.DEFAULT_GRAPHQL_ENDPOINT

        self.graphql = GraphQL(endpoint)
        self.refresh_token = None
        Thread(target=self._loop_refresh, daemon=True).start()

    @staticmethod
    def create_user(email: str, password: str, private_key: str, endpoint: str = None):
        if endpoint is None:
            endpoint = WudderClient.DEFAULT_GRAPHQL_ENDPOINT
        WudderClient._create_user_call(email, password, private_key, endpoint)

    @retry
    def login(self, email: str, password: str) -> dict:
        try:
            response = self._login_call(email, password)
        except TypeError:
            raise exceptions.LoginError

        self._update_tokens(response['token'], response['refreshToken'])
        private_key = response['ethAccount']
        if private_key:
            return json.loads(private_key)

    def update_private_key(self, private_key: dict) -> dict:
        private_key_str = utils.ordered_stringify(private_key)
        response = self._update_private_key_call(private_key_str)
        return response['ethAccount']

    def send_event_directly(self, title: str, event: Event) -> str:
        response = self._send_event_directly_call(title, event.dict)
        return response['evhash']

    def prepare(self, title: str, event: Event) -> dict:
        response = self._prepare_call(title, event.dict)
        output_data = {
            'tx': json.loads(response['formattedTransaction']),
            'event': Event(event_dict=json.loads(response['preparedContent'])),
            'hash': response['hash'],
            'url': response['url'],
        }
        return output_data

    def get_prepared(self, tmp_hash: str) -> dict:
        response = self._get_prepared_call(tmp_hash)
        output_data = {
            'tx': json.loads(response['formattedTransaction']),
            'event': Event(event_dict=json.loads(response['preparedContent'])),
            'hash': tmp_hash,
            'url': response['url'],
        }
        return output_data

    def send_prepared(self, tx: dict, signature: str = None) -> str:
        tx_str = utils.ordered_stringify(tx)
        response = self._send_prepared_call(tx_str, signature)
        return response['evhash']

    def get_event(self, evhash: str) -> Event:
        response = self._get_event_call(evhash)
        original_content = json.loads(response['originalContent'])['content']
        event_dict = {
            'type': original_content['type'],
            'trace': original_content['trace'],
            'fragments': original_content['fragments'],
            'timestamp': original_content['timestamp'],
            'salt': original_content['salt']
        }
        return Event(event_dict=event_dict)

    def get_trace(self, evhash: str) -> dict:
        return self._get_trace_call(evhash)

    def get_proof(self, evhash: str) -> dict:
        response = self._get_proof_call(evhash)
        if response['graphnData'] is None:
            raise exceptions.NotFoundError('transaction not found')
        graphn_data = json.loads(response['graphnData'])
        return graphn_data

    def _loop_refresh(self):
        while True:
            time.sleep(900)
            response = self._refresh_call()
            self._update_tokens(response['token'], response['refreshToken'])

    def _update_tokens(self, token: str, refresh_token: str):
        self.refresh_token = refresh_token
        self.graphql.set_headers({'x-jwt-token': token})

    @staticmethod
    def _manage_errors(errors: list):
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

            if errors[0]['code'] == 440:
                raise exceptions.AuthError(errors[0])

        except KeyError:
            pass

        raise exceptions.UnexpectedError(errors[0])

    @staticmethod
    @retry
    def _create_user_call(email: str, password: str, private_key: str, endpoint: str) -> dict:
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
        data, errors = GraphQL(endpoint).execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['createUser']

    @retry
    def _login_call(self, email: str, password: str) -> dict:
        mutation = '''
            mutation Login($email: String!, $password: String!) {
                login(email: $email, password: $password){
                    token
                    refreshToken
                    ethAccount
                }
            }
        '''
        variables = {
            'email': email,
            'password': password,
        }
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['login']

    @retry
    def _refresh_call(self) -> dict:
        mutation = '''
            mutation RefreshToken($refreshToken: String!) {
                refreshToken(token: $refreshToken){
                    token
                    refreshToken
                }
            }
        '''
        variables = {
            'refreshToken': self.refresh_token,
        }
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['refreshToken']

    @retry
    def _update_private_key_call(self, private_key: str) -> dict:
        mutation = '''
            mutation UpdateUser($user: UserInput!){
                updateUser(user: $user) {
                    ethAccount
                }
            }
        '''
        variables = {
            'user': {
                'ethAccount': private_key
            },
        }
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['updateUser']

    @retry
    def _send_event_directly_call(self, title: str, event: dict) -> dict:
        mutation = '''
            mutation CreateEvidence($evidence: EvidenceInput!, $displayName: String!){
                createEvidence(evidence: $evidence, displayName: $displayName){
                    evhash
                }
            }
        '''
        variables = {
            'displayName': title,
            'evidence': {
                'content': event
            },
        }
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['createEvidence']

    @retry
    def _prepare_call(self, title: str, event: dict) -> dict:
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
        variables = {'displayName': title, 'content': event}
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['prepareEvidence']

    @retry
    def _send_prepared_call(self, tx: str, signature: str) -> str:
        mutation = '''
            mutation ConfirmPreparedEvidence($evidence: PreparedEvidenceInput!){
                confirmPreparedEvidence(evidence: $evidence){
                    evhash
                }
            }
        '''
        variables = {
            'evidence': {
                'preparedEvidence': tx,
                'signature': signature
            },
        }
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['confirmPreparedEvidence']

    @retry
    def _get_prepared_call(self, tmp_hash: str) -> dict:
        query = '''
            query PreparedEvidence($hash: String!){
                preparedEvidence(hash: $hash){
                    formattedTransaction
                    preparedContent
                    url
                }
            }
        '''
        variables = {
            'hash': tmp_hash,
        }
        data, errors = self.graphql.execute(query, variables)
        WudderClient._manage_errors(errors)
        return data['preparedEvidence']

    @retry
    def _get_event_call(self, evhash: str) -> Event:
        query = '''
            query Evidence($evhash: String!){
                evidence(evhash: $evhash){
                    graphnData
                    type
                    displayName
                    originalContent
                }
            }
        '''
        variables = {
            'evhash': evhash,
        }
        data, errors = self.graphql.execute(query, variables)
        WudderClient._manage_errors(errors)
        return data['evidence']

    @retry
    def _get_trace_call(self, evhash: str) -> dict:
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
        variables = {
            'evhash': evhash,
        }
        data, errors = self.graphql.execute(query, variables)
        WudderClient._manage_errors(errors)
        return data['getTrace']

    @retry
    def _get_proof_call(self, evhash: str) -> dict:
        query = '''
            query Evidence($evhash: String!){
                evidence(evhash: $evhash){
                    graphnData
                }
            }
        '''
        variables = {
            'evhash': evhash,
        }
        data, errors = self.graphql.execute(query, variables)
        WudderClient._manage_errors(errors)
        return data['evidence']
