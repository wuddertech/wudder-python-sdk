#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations
from . import utils
from . import graphn
from typing import Dict, List


class EventTypes:
    TRACE = 'TRACE'
    ADD_EVENT = 'ADD_EVENT'
    VALIDATE = 'VALIDATE'
    FILE = 'FILE'


class Fragment:
    VISIBILITY_PUBLIC = 'public'
    VISIBILITY_PRIVATE = 'private'

    def __init__(self,
                 field: str = None,
                 value: str = None,
                 visibility: str = VISIBILITY_PUBLIC,
                 salt: str = None,
                 fragment_dict: Dict = None):

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

    def _load_fragment_dict(self, fragment: Dict):
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
    def dict(self) -> Dict:
        fragment_dict = {
            'field': self.field,
            'value': self.value,
            'visibility': self.visibility
        }
        if self.salt is not None:
            fragment_dict['salt'] = self.salt
        return fragment_dict


class Event:
    def __init__(self,
                 fragments: List = None,
                 trace: str = None,
                 event_type: str = None,
                 timestamp: int = None,
                 salt: str = None,
                 event_dict: Dict = None):
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
    def fragments(self) -> List:
        fragments = []
        for fragment in self._fragments:
            fragments.append(Fragment(fragment_dict=fragment.dict))
        return fragments

    def match(self, event: Event) -> bool:
        for self_fragment, event_fragment in zip(self.fragments,
                                                 event.fragments):
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

    def _set_fragments(self, fragments: List):
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

    def _load_event_dict(self, event: Dict):
        self._set_fragments([
            Fragment(fragment_dict=fragment) for fragment in event['fragments']
        ])
        self._set_trace(event['trace'])
        self.type = event['type']

        if 'salt' in event:
            self.salt = event['salt']
        else:
            self.salt = None

        if 'timestamp' in event:
            self.timestamp = event['timestamp']
        else:
            self.timestamp = utils.get_timestamp_ms()

        if 'proof' in event:
            self.proof = event['proof']
        else:
            self.proof = None

    @property
    def dict(self) -> Dict:
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
