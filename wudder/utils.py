#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import json
from eth_account import Account as EthereumAccount
from os import makedirs
import time
import requests
from typing import Dict
from . import graphn
from .event import Event, EventTypes

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


def sha3_512(text: str) -> str:
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()


def ordered_stringify(unordered_dict: Dict) -> str:
    keys = sorted(list(unordered_dict.keys()))
    new_dict = dict()
    for key in keys:
        new_dict[key] = unordered_dict[key]
    return json.dumps(new_dict, separators=(',', ':'), ensure_ascii=False)


def cthash(content: Dict) -> str:
    fragment_hashes = []
    for fragment in content['fragments']:
        pure_fragment = {
            'field': fragment['field'],
            'value': fragment['value']
        }
        if 'salt' in fragment:
            pure_fragment['salt'] = fragment['salt']
        fragment = pure_fragment

        if isinstance(fragment, str) and len(fragment) == graphn.HASH_LENGTH:
            fragment_hashes.append(fragment)
        else:
            fragment_hashes.append(sha3_512(ordered_stringify(fragment)))
    original_content = {
        'type': content['type'],
        'trace': content['trace'],
        'fragment_hashes': sorted(fragment_hashes),
    }
    if 'salt' in content:
        original_content['salt'] = content['salt']
    original_content = ordered_stringify(original_content)
    cthash = sha3_512(original_content)
    return cthash


def generate_private_key(password: str) -> dict:
    private_key = EthereumAccount().create()
    private_key_dict = private_key.encrypt(password)
    try:
        makedirs('./private-keys')
    except FileExistsError:
        pass
    with open(f'./private-keys/{private_key.address}.json',
              'w') as output_file:
        json.dump(private_key_dict, output_file)
    return private_key_dict


def get_timestamp_ms() -> int:
    return int(round(time.time() * 1000))


def dbmt_hash(value: str, level: int = None) -> str:
    return sha3_512(f'{level}{value}')


def check_proof(compound_proof: str = None,
                tree_proof: str = None,
                block_proof: str = None,
                blocktree_proof: str = None) -> dict:
    if compound_proof is not None:
        return check_proof(None, *compound_proof.split(':'))

    # Check tree proof
    tree_proof_result = check_tree_proof(tree_proof)
    if not tree_proof_result['valid']:
        return {'valid': False}

    # Are proofs linked? (1/2)
    proofs_linked = tree_proof_result['root_hash'] \
        == block_proof[1:graphn.HASH_LENGTH + 1]
    if not proofs_linked:
        return {'valid': False}

    block_proof_result = check_block_proof(block_proof)
    if not block_proof_result['valid']:
        return {'valid': False}

    if blocktree_proof is None:
        block_proof_result['verified_hash'] = \
            tree_proof[1:graphn.HASH_LENGTH +  1]
        return block_proof_result

    # Are proofs linked? (2/2)
    proofs_linked = block_proof_result['root_hash'] == blocktree_proof[
        1:graphn.HASH_LENGTH + 1]
    if not proofs_linked:
        return {'valid': False}

    # Check blocktree proof
    blocktree_proof_result = check_tree_proof(blocktree_proof)
    blocktree_proof_result['verified_hash'] = \
        tree_proof[1:graphn.HASH_LENGTH + 1]
    return blocktree_proof_result


def check_block_proof(proof: str) -> dict:
    block_proof = proof[:-2 * graphn.HASH_LENGTH]
    block_proof_result = check_tree_proof(block_proof)
    if not block_proof_result['valid']:
        return {'valid': False}

    proof_extension = proof[-2 * graphn.HASH_LENGTH:]
    meta_hash = proof_extension[:graphn.HASH_LENGTH]
    block_hash = proof_extension[graphn.HASH_LENGTH:]
    current_hash = dbmt_hash(meta_hash + block_proof_result['root_hash'])
    if current_hash == block_hash:
        return {
            'verified_hash': block_proof_result['verified_hash'],
            'root_hash': block_hash,
            'valid': True
        }
    return {'valid': False}


def check_tree_proof(proof: str) -> dict:
    if len(proof) < graphn.HASH_LENGTH + 1:
        return {'valid': False}

    actual_proof = proof[:-graphn.HASH_LENGTH]
    root_hash = proof[-graphn.HASH_LENGTH:]

    # Position + 512 bits (129 chars)
    items = [
        actual_proof[i:i + graphn.HASH_LENGTH + 1]
        for i in range(0, len(actual_proof), graphn.HASH_LENGTH + 1)
    ]

    start_index = 0
    current_hash = items[0][1:]
    if items[0][0] != 'o':
        start_index = 1

    for i in range(start_index, len(items)):
        level = i - start_index

        if items[i][0] == 'l':
            current_hash = dbmt_hash(items[i][1:] + current_hash, level=level)
        elif items[i][0] == 'r':
            current_hash = dbmt_hash(current_hash + items[i][1:], level=level)
        elif items[i][0] == 'o':
            current_hash = dbmt_hash(current_hash, level=level)
        else:
            return {'valid': False}

    # root_hash == tree hash, not merkle_root_hash
    if current_hash == root_hash:
        return {
            'verified_hash': items[0][1:],
            'root_hash': root_hash,
            'valid': True
        }

    return {'valid': False}


def get_ethereum_tx_input(tx_hash: str, endpoint: str) -> str:
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    }
    headers = {'Content-Type': 'application/json'}
    response_dict = requests.post(endpoint, json=payload,
                                  headers=headers).json()
    return response_dict['result']['input']


def get_event_tx(event: Event) -> dict:
    tx = {
        'cthash': cthash(event.dict),
        'version': graphn.PROTOCOL_VERSION,
        'from': [event.trace]
    }

    if event.type == EventTypes.TRACE:
        tx['nodecode'] = graphn.Nodecodes.CREATE_GRAPH
    elif event.type == EventTypes.ADD_EVENT:
        tx['nodecode'] = graphn.Nodecodes.EXTEND_GRAPH
    elif event.type == EventTypes.VALIDATE:
        tx['nodecode'] = graphn.Nodecodes.VALIDATE_NODE
    elif event.type == EventTypes.FILE:
        tx['nodecode'] = graphn.Nodecodes.CREATE_GRAPH

    return tx
