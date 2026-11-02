"""Use loopback HTTP only, including redirects and a stalled provider."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Thread

import pytest
import requests
from wudder.utils import get_ethereum_tx_input


@contextmanager
def provider(mode):
    release = Event()
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            if mode == 'stall':
                release.wait(2)
                return
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'input': '0x1234'}}).encode()
            self.send_response(302 if mode == 'redirect' else 200)
            if mode == 'redirect':
                self.send_header('Location', '/elsewhere')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', calls
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_rpc_reads_the_transaction_without_following_redirects():
    with provider('ok') as (url, calls):
        assert get_ethereum_tx_input('0xfixture', url) == '0x1234'
        assert calls == [{'jsonrpc': '2.0', 'method': 'eth_getTransactionByHash', 'params': ['0xfixture'], 'id': 1}]
    with provider('redirect') as (url, calls):
        with pytest.raises(requests.HTTPError, match='redirected'):
            get_ethereum_tx_input('0xfixture', url)
        assert len(calls) == 1


def test_stalled_rpc_has_a_bounded_read():
    with provider('stall') as (url, _):
        with pytest.raises(requests.Timeout):
            get_ethereum_tx_input('0xfixture', url, timeout=(.1, .1))
