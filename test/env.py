#!/usr/bin/env python
# -*- coding: utf-8 -*-

evhash = '2ed31a9977c3612b9331a8f94bffbc90d30f0ebf6ae67dae0ea7d61b93166637'

proof = {
    'graphn_proof':
    'o2ed31a9977c3612b9331a8f94bffbc90d30f0ebf6ae67dae0ea7d61b93166637lb09c1433bd15a1a928dfea83e6b27009948230179240ece5e4ecb19010dde578r4c628b011cec3a21c7b6d0406ef9997e01709c1c5d11cfbb93efedee8220d4bal44efc6e29d10ecef92874ff7a087040095decfee54c33cc2214a0bcd534dd212r29e6b0da01a74da31ad53ec8510211ab813e3b397ad2bac0ef821ec89ab32685r0c2227c21d681a7650dff22a71ed6351a52b388f5f4d534209c5677ac85c0f37l9c1b738a1fe46e72ba5b1f24d7bbbfd017816e504814d3b111f4735612659f5cle7bd11b1b481f1d8cb31d7c3ea7571a0eb23d26d633c8f4579daf9be3e89897br72feaeacc38b8dd89cb3b0eb3209e35c7283c6bf701c9380d162ef18f20d2bafr8dbedbeef72138eceaff49dfa2d58a951c516ee24301e6dfc535457537aef570rb041a4f8287f0a8e77fe89837d887a4e9ead8be33116b5df3a8aa72fd0fb6234l20a556be4b70793b657c4c350ee7e54d95b4b10b962e3be08cb6552778b7faca3f7df17a1c7659aaa9959888b884738d4ccbe7dea1a37419feb571a931a7a5c2',
    'anchor_txs': {
        'telsius': '0x4bc0869565db23bcfe7a80d04af3bbfbf60ccd56b242de379b71fa9b99e07bcb',
        'ethereum': '0x1ff2f2fe9017a0eb435365cd750d40848b0ca7acd7941e63b1fa266ef3fd196a'
    }
}

event_dict = {
    'fragments': [{
        'field': 'fragmento1',
        'salt': '9yi7x1ok4',
        'value': 'contenido del fragmento1'
    }, {
        'field': 'fragmento2',
        'salt': 'p8glvr0x3t',
        'value': 'contenido del fragmento1'
    }],
    'trace':
    'c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04',
    'type':
    'NEW_TRACE'
}

trace = {
    'creationEvidence': {
        'evhash':
        '2ed31a9977c3612b9331a8f94bffbc90d30f0ebf6ae67dae0ea7d61b93166637',
        'type':
        'TRACE',
        'graphnData':
        '{"hash":"2ed31a9977c3612b9331a8f94bffbc90d30f0ebf6ae67dae0ea7d61b93166637","cthash":"0531710d445f895a3820255ebe0eb2afd20230c2cd115b594cbd0f11448d859a6dfe1c50b948c79a834f10a2f8ee1638f44736e32795c495f1746ebafb80670c","from":["c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04"],"nodecode":1,"sighash":"f2505882f4d5456b97ac3e751e4ae587ade77bad8b405af04dc5ab2264a75952067483889b4da528466a2236fe0446449a9fc330f0d725e7de0d591570819d40","version":1,"block":"eb59b0a88d7c82c505a93425486ab84f9bf66b080003ecbc5f7bf801f0eb19a8","block_proof":"leb59b0a88d7c82c505a93425486ab84f9bf66b080003ecbc5f7bf801f0eb19a8r4c628b011cec3a21c7b6d0406ef9997e01709c1c5d11cfbb93efedee8220d4bal44efc6e29d10ecef92874ff7a087040095decfee54c33cc2214a0bcd534dd212r29e6b0da01a74da31ad53ec8510211ab813e3b397ad2bac0ef821ec89ab32685r0c2227c21d681a7650dff22a71ed6351a52b388f5f4d534209c5677ac85c0f37l9c1b738a1fe46e72ba5b1f24d7bbbfd017816e504814d3b111f4735612659f5cle7bd11b1b481f1d8cb31d7c3ea7571a0eb23d26d633c8f4579daf9be3e89897br72feaeacc38b8dd89cb3b0eb3209e35c7283c6bf701c9380d162ef18f20d2bafr8dbedbeef72138eceaff49dfa2d58a951c516ee24301e6dfc535457537aef570rb041a4f8287f0a8e77fe89837d887a4e9ead8be33116b5df3a8aa72fd0fb6234l20a556be4b70793b657c4c350ee7e54d95b4b10b962e3be08cb6552778b7faca3f7df17a1c7659aaa9959888b884738d4ccbe7dea1a37419feb571a931a7a5c2","hyperblock":"3f7df17a1c7659aaa9959888b884738d4ccbe7dea1a37419feb571a931a7a5c2","proof":"o2ed31a9977c3612b9331a8f94bffbc90d30f0ebf6ae67dae0ea7d61b93166637lb09c1433bd15a1a928dfea83e6b27009948230179240ece5e4ecb19010dde578r4c628b011cec3a21c7b6d0406ef9997e01709c1c5d11cfbb93efedee8220d4bal44efc6e29d10ecef92874ff7a087040095decfee54c33cc2214a0bcd534dd212r29e6b0da01a74da31ad53ec8510211ab813e3b397ad2bac0ef821ec89ab32685r0c2227c21d681a7650dff22a71ed6351a52b388f5f4d534209c5677ac85c0f37l9c1b738a1fe46e72ba5b1f24d7bbbfd017816e504814d3b111f4735612659f5cle7bd11b1b481f1d8cb31d7c3ea7571a0eb23d26d633c8f4579daf9be3e89897br72feaeacc38b8dd89cb3b0eb3209e35c7283c6bf701c9380d162ef18f20d2bafr8dbedbeef72138eceaff49dfa2d58a951c516ee24301e6dfc535457537aef570rb041a4f8287f0a8e77fe89837d887a4e9ead8be33116b5df3a8aa72fd0fb6234l20a556be4b70793b657c4c350ee7e54d95b4b10b962e3be08cb6552778b7faca3f7df17a1c7659aaa9959888b884738d4ccbe7dea1a37419feb571a931a7a5c2","hyperblock_index":50,"prefixes":{"telsius":{"tx_hash":"0x4bc0869565db23bcfe7a80d04af3bbfbf60ccd56b242de379b71fa9b99e07bcb"},"ethereum":{"tx_hash":"0x1ff2f2fe9017a0eb435365cd750d40848b0ca7acd7941e63b1fa266ef3fd196a"}}}',
        'displayName':
        'Nombre del evento inicial',
        'originalContent':
        '{"content":{"fragments":[{"field":"fragmento1","salt":"9yi7x1ok4","value":"contenido del fragmento1"},{"field":"fragmento2","salt":"p8glvr0x3t","value":"contenido del fragmento1"}],"salt":"dtdzxyi38p","trace":"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04","type":"NEW_TRACE"},"event_tx":"{\\"cthash\\":\\"0531710d445f895a3820255ebe0eb2afd20230c2cd115b594cbd0f11448d859a6dfe1c50b948c79a834f10a2f8ee1638f44736e32795c495f1746ebafb80670c\\",\\"from\\":[\\"c106851cc1ce91b68254c1e82b2b5e2dbd97471ec7d7ffb6f55aeadba7683a04\\"],\\"nodecode\\":1,\\"version\\":1}","signature":""}'
    },
    'childs': []
}