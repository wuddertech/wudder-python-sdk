#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import json
from easyweb3 import EasyWeb3
from os import makedirs


def sha3_512(text: str) -> str:
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()


def ordered_stringify(unordered_dict: dict):
    private_keys = sorted(list(unordered_dict.keys()))
    new_dict = dict()
    for private_key in private_keys:
        new_dict[private_key] = unordered_dict[private_key]
    return json.dumps(new_dict, separators=(',', ':'), ensure_ascii=False)


def cthash(content: dict):
    fragment_hashes = []
    for fragment in content['fragments']:
        if isinstance(fragment, str) and len(fragment) == 128:
            fragment_hashes.append(fragment)
        else:
            fragment_hashes.append(sha3_512(ordered_stringify(fragment)))

    original_content = ordered_stringify({
        'type': content['type'],
        'trace': content['trace'],
        'fragment_hashes': sorted(fragment_hashes),
        'salt': content['salt']
    })

    return sha3_512(original_content)


def get_root_hash(proof: str) -> str:
    def dbmt_hash(value: str, level: int = None) -> str:
        return sha3_512(f'{level}{value}')

    if len(proof) < 128 + 1:
        return

    root_hash = proof[-128:]
    actual_proof = proof[:-128]

    items = [actual_proof[i:i + 128 + 1] for i in range(0, len(actual_proof), 128 + 1)]

    start_index = 0
    current_hash = items[0][1:]
    if items[0][0] != 'o':
        start_index = 1

    for i in range(start_index, len(items)):
        is_last_item = i == len(items) - 1
        level = i - start_index if not is_last_item else None

        if items[i][0] == 'l':
            current_hash = dbmt_hash(items[i][1:] + current_hash, level=level)
        elif items[i][0] == 'r':
            current_hash = dbmt_hash(current_hash + items[i][1:], level=level)
        elif items[i][0] == 'o':
            current_hash = dbmt_hash(current_hash, level=level)
        else:
            return

    if current_hash == root_hash:
        return root_hash


def generate_private_key(password):
    private_key = EasyWeb3().web3.eth.account.create()
    private_key_dict = private_key.encrypt(password)
    try:
        makedirs('./private-keys')
    except FileExistsError:
        pass
    with open(f'./private-keys/{private_key.address}.json', 'w') as output_file:
        json.dump(private_key_dict, output_file)
    return private_key_dict