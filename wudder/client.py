#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .utils import retry
from . import exceptions
from . import utils
from .event import Event
from easygraphql import GraphQL
from threading import Event as StopEvent, RLock, Thread, current_thread
import logging
import json
from typing import Dict, List


class WudderClient:
    DEFAULT_GRAPHQL_ENDPOINT = 'https://api.dev.wudder.tech/graphql/'

    def __init__(self, email: str, password: str, endpoint: str = None):
        if endpoint is None:
            endpoint = self.DEFAULT_GRAPHQL_ENDPOINT

        self.graphql = GraphQL(endpoint)
        self.refresh_token = None
        self._credentials = None
        self._session_lock = RLock()
        self._closed = StopEvent()
        self._refresh_thread = Thread(target=self._loop_refresh, daemon=True)
        self._refresh_thread.start()

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
        with self._session_lock:
            response = self._login_call(email, password)
            if not response:
                raise exceptions.LoginError
            self._update_tokens(response['token'], response['refreshToken'])
            self._credentials = (email, password)
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
        return self._event_data(response)

    def get_trace(self, evhash: str) -> Dict:
        try:
            response = self._get_trace_call(evhash)
        except exceptions.NotFoundError:
            return None

        def adapt(evidence):
            return {
                'evhash': evidence['evhash'],
                'type': evidence['type'],
                'displayName': evidence.get('displayName'),
                **self._event_data(evidence),
            }

        return {
            'creationEvidence': adapt(response['creationEvidence']),
            'childs': [adapt(item) for item in response.get('childs') or []],
        }

    @staticmethod
    def _event_data(response):
        proof = json.loads(response['graphnData']) if response.get('graphnData') else {}
        if not isinstance(proof, dict):
            raise ValueError('Invalid Graphn evidence response')
        return {**proof, 'event': json.loads(response['originalContent'])['content']}

    def _loop_refresh(self):
        delay = 900
        while not self._closed.wait(delay):
            if self.refresh_token is None:
                continue
            try:
                self._renew_session(self.graphql.headers.get('x-jwt-token'))
                delay = 900
            except Exception as error:
                logging.getLogger(__name__).warning('Session renewal failed (%s)', type(error).__name__)
                delay = 30

    def close(self):
        self._closed.set()
        if current_thread() is not self._refresh_thread:
            self._refresh_thread.join(timeout=1)
        with self._session_lock:
            self._credentials = None
            self.refresh_token = None
            self.graphql.unset_headers()

    def _renew_session(self, rejected_token):
        with self._session_lock:
            if self._closed.is_set():
                raise exceptions.AuthError('Client is closed')
            if self.graphql.headers.get('x-jwt-token') != rejected_token:
                return  # Another request already renewed this session.
            try:
                response = self._refresh_call()
            except exceptions.AuthError:
                response = None
            if not response:
                if self._credentials is None:
                    raise exceptions.AuthError('Login is required')
                response = self._login_call(*self._credentials)
            if not response:
                raise exceptions.AuthError('Login was rejected')
            self._update_tokens(response['token'], response['refreshToken'])

    def _execute(self, operation, variables):
        headers = self.graphql.headers
        data, errors = self.graphql.execute(operation, variables, headers=headers)
        try:
            self._manage_errors(errors)
        except exceptions.AuthError:
            # Never replay partial GraphQL mutations: an effect may exist.
            if data and any(value is not None for value in data.values()):
                raise
            self._renew_session(headers.get('x-jwt-token'))
            data, errors = self.graphql.execute(operation, variables)
            self._manage_errors(errors)
        return data, errors

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

            if errors[0]['code'] in [401, 403]:
                raise exceptions.AuthError(errors[0])

            if errors[0]['code'] == 400:
                raise exceptions.BadRequestError(errors[0])

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
        data, errors = self._execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['updateUser']

    @retry
    def _send_event_directly_call(self, title: str, event: Dict) -> Dict:
        mutation = '''
            mutation CreateEvidence(
                $evidence: EvidenceInput!, $displayName: String!
            ){
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
        data, errors = self._execute(mutation, variables)
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
        data, errors = self._execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['createEvidences']

    @retry
    def _prepare_call(self, title: str, event: Dict) -> Dict:
        mutation = '''
            mutation PrepareEvidence(
                $content: ContentInput!, $displayName: String!
            ){
                prepareEvidence(content: $content, displayName: $displayName){
                    formattedTransaction
                    preparedContent
                    hash
                    url
                }
            }
        '''
        variables = {'displayName': title, 'content': event}
        data, errors = self._execute(mutation, variables)
        WudderClient._manage_errors(errors)
        return data['prepareEvidence']

    @retry
    def _send_prepared_call(self, tx: str, signature: str) -> str:
        mutation = '''
            mutation ConfirmPreparedEvidence(
                $evidence: PreparedEvidenceInput!
            ){
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
        data, errors = self._execute(mutation, variables)
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
        data, errors = self._execute(query, variables)
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
        data, errors = self._execute(query, variables)
        WudderClient._manage_errors(errors)
        return data['evidence']

    @retry
    def _get_trace_call(self, evhash: str) -> Dict:
        query = '''
            query Trace($evhash: String!) {
                trace(evhash: $evhash) {
                    creationEvidence {
                        evhash type displayName originalContent graphnData
                    }
                    childs {
                        evhash type displayName originalContent graphnData
                    }
                }
            }
        '''
        data, errors = self._execute(query, {'evhash': evhash})
        self._manage_errors(errors)
        return data['trace']
