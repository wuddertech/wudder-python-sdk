#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import json
from easyweb3 import EasyWeb3


def _blake2b_256(text: str):
    return hashlib.blake2b(text.encode('utf-8'), digest_size=32).hexdigest()


def _blake2b_512(text: str):
    return hashlib.blake2b(text.encode('utf-8'), digest_size=64).hexdigest()


def _sha3_512(text: str):
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()


def mtk_512(text: str):
    return _blake2b_512(_sha3_512(text) + text)


def mtk_256(text: str):
    return _blake2b_256(_sha3_512(text) + text)


def ordered_stringify(unordered_dict: dict):
    private_keys = sorted(list(unordered_dict.keys()))
    new_dict = dict()
    for private_key in private_keys:
        new_dict[private_key] = unordered_dict[private_key]
    return json.dumps(new_dict, separators=(',', ':'))


def cthash(content: dict):
    fragment_hashes = []
    for fragment in content['fragments']:
        if isinstance(fragment, str) and len(fragment) == 128:
            fragment_hashes.append(fragment)
        else:
            fragment_hashes.append(mtk_512(ordered_stringify(fragment)))

    original_content = ordered_stringify({
        'type': content['type'],
        'trace': content['trace'],
        'fragment_hashes': sorted(fragment_hashes),
        'salt': content['salt']
    })

    return mtk_512(original_content)


def get_root_hash(proof: str):
    if len(proof) < 65:
        return {'valid': False}

    root_hash = proof[-64:]
    proof = proof[:-64]

    # Position + 256 bits (65 chars)
    items = [proof[i:i + 65] for i in range(0, len(proof), 65)]

    start_index = 2
    if items[0][0] == 'l':
        current_hash = mtk_256(items[0][1:] + items[1][1:])
    elif items[0][0] == 'r':
        current_hash = mtk_256(items[1][1:] + items[0][1:])
    elif items[0][0] == 'o':
        current_hash = mtk_256(items[0][1:])
        start_index = 1
    else:
        return {'valid': False}

    for i in range(start_index, len(items)):
        if items[i][0] == 'l':
            current_hash = mtk_256(items[i][1:] + current_hash)
        elif items[i][0] == 'r':
            current_hash = mtk_256(current_hash + items[i][1:])
        elif items[i][0] == 'o':
            current_hash = mtk_256(current_hash)
        else:
            return {'valid': False}

    if current_hash == root_hash:
        return root_hash


def generate_private_key(password):
    private_key = EasyWeb3().web3.eth.account.create()
    private_key_dict = private_key.encrypt(password)
    with open(f'{private_key.address}.json', 'w') as output_file:
        json.dump(private_key_dict, output_file)
    return private_key_dict