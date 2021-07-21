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
from typing import Dict, List


class WudderClient:
    DEFAULT_GRAPHQL_ENDPOINT = 'https://api.pre.wudder.tech/graphql/'

    def __init__(self, email: str, password: str, endpoint: str = None):
        if endpoint is None:
            endpoint = self.DEFAULT_GRAPHQL_ENDPOINT

        self.graphql = GraphQL(endpoint)
        self.refresh_token = None
        Thread(target=self._loop_refresh, daemon=True).start()

    @staticmethod
    def create_user(email: str,
                    password: str,
                    private_key: str,
                    endpoint: str = None):
        if endpoint is None:
            endpoint = WudderClient.DEFAULT_GRAPHQL_ENDPOINT
        WudderClient._create_user_call(email, password, private_key, endpoint)

    @retry
    def login(self, email: str, password: str) -> Dict:
        try:
            response = self._login_call(email, password)
        except TypeError:
            raise exceptions.LoginError

        self._update_tokens(response['token'], response['refreshToken'])
        private_key = response['ethAccount']
        if private_key:
            return json.loads(private_key)

    def update_private_key(self, private_key: Dict) -> Dict:
        private_key_str = utils.ordered_stringify(private_key)
        response = self._update_private_key_call(private_key_str)
        return response['ethAccount']

    def send_event_directly(self, title: str, event: Event) -> str:
        response = self._send_event_directly_call(title, event.dict)
        return response['evhash']

    def send_events_directly(self, event_bundles: List[Dict]) -> List[str]:
        event_bundles = [{
            'title': event_bundle['title'],
            'event': event_bundle['event'].dict,
            'signature': event_bundle['signature']
        } for event_bundle in event_bundles]
        response = self._send_events_directly_call(event_bundles)
        return [item['evhash'] for item in response]

    def prepare(self, title: str, event: Event) -> Dict:
        response = self._prepare_call(title, event.dict)
        output_data = {
            'tx': json.loads(response['formattedTransaction']),
            'event': Event(event_dict=json.loads(response['preparedContent'])),
            'hash': response['hash'],
            'url': response['url'],
        }
        return output_data

    def get_prepared(self, tmp_hash: str) -> Dict:
        try:
            response = self._get_prepared_call(tmp_hash)
        except exceptions.NotFoundError:
            return None
        output_data = {
            'tx': json.loads(response['formattedTransaction']),
            'event': Event(event_dict=json.loads(response['preparedContent'])),
            'hash': tmp_hash,
            'url': response['url'],
        }
        return output_data

    def send_prepared(self, tx: Dict, signature: str = None) -> str:
        tx_str = utils.ordered_stringify(tx)
        response = self._send_prepared_call(tx_str, signature)
        return response['evhash']

    def get_event(self, evhash: str) -> Dict:
        try:
            response = self._get_event_call(evhash)
        except exceptions.NotFoundError:
            return None
        event_dict = {
            'event': json.loads(response['originalContent'])['content']
        }
        if 'graphnData' in response:
            event_dict.update(json.loads(response['graphnData']))
        return event_dict

    def get_trace(self, evhash: str) -> Dict:
        # TODO transform response as in get_event
        raise NotImplementedError
        # try:
        #     response = self._get_trace_call(evhash)
        # except exceptions.NotFoundError:
        #     return None

    def _loop_refresh(self):
        while True:
            time.sleep(900)
            response = self._refresh_call()
            self._update_tokens(response['token'], response['refreshToken'])

    def _update_tokens(self, token: str, refresh_token: str):
        self.refresh_token = refresh_token
        self.graphql.set_headers({'x-jwt-token': token})

    @staticmethod
    def _manage_errors(errors: List):
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
    def _create_user_call(email: str, password: str, private_key: str,
                          endpoint: str) -> Dict:
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
    def _login_call(self, email: str, password: str) -> Dict:
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
    def _refresh_call(self) -> Dict:
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
    def _update_private_key_call(self, private_key: str) -> Dict:
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
    def _send_event_directly_call(self, title: str, event: Dict) -> Dict:
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
    def _send_events_directly_call(self, event_bundles: List[Dict]) -> Dict:
        mutation = '''
            mutation CreateEvidences($evidences: [EvidenceInput]!, ){
                createEvidences(evidences: $evidences){
                    evhash
                }
            }
        '''
        evidences = []
        for event_bundle in event_bundles:
            evidence = {
                'displayName': event_bundle['title'],
                'content': event_bundle['event']
            }
            if 'signature' in event_bundle and event_bundle['signature']:
                evidence['signature'] = event_bundle['signature']
            evidences.append(evidence)
        variables = {'evidences': evidences}
        data, errors = self.graphql.execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['createEvidences']

    @retry
    def _prepare_call(self, title: str, event: Dict) -> Dict:
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
    def _get_prepared_call(self, tmp_hash: str) -> Dict:
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
    def _get_trace_call(self, evhash: str) -> Dict:
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
