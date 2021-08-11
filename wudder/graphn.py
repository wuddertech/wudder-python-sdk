#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GRAPHN
PROTOCOL_VERSION = 3
HASH_LENGTH = 128
ZEROS_HASH = HASH_LENGTH * '0'
MAX_TX_SIGNATURE_LENGTH = 256


class Nodecodes:
    CREATE_GRAPH = 1
    EXTEND_GRAPH = 2
    VALIDATE_NODE = 3
