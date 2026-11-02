from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock, Thread
from unittest.mock import Mock, patch
import pytest
from wudder.client import WudderClient
from wudder import exceptions


def test_revoked_session_recovers_once_for_concurrent_requests():
    state = {'token': 'token1', 'logins': 0, 'refreshes': 0}
    lock = Lock()
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            with lock:
                if 'mutation Login(' in body['query']:
                    assert body['variables'] == {'email': 'fixture', 'password': 'password'}
                    state['logins'] += 1
                    result = {'data': {'login': {'token': state['token'], 'refreshToken': state['token'], 'ethAccount': None}}}
                elif 'mutation RefreshToken(' in body['query']:
                    state['refreshes'] += 1
                    result = {'errors': [{'code': 403}]}
                elif self.headers.get('x-jwt-token') != state['token']:
                    result = {'errors': [{'code': 403}]}
                else:
                    result = {'data': {'value': 'ok'}}
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = WudderClient('fixture', 'password', f'http://127.0.0.1:{server.server_port}')
    try:
        client.login('fixture', 'password')
        state['token'] = 'token2'
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: client._execute('query { value }', {}), range(16)))
        assert all(data == {'value': 'ok'} and not errors for data, errors in results)
        assert state['logins'] == 2 and state['refreshes'] == 1
        assert client._refresh_thread.is_alive()
        with patch.object(client.graphql, 'execute', return_value=({'saved': {'id': 1}}, [{'code': 403}])) as execute:
            with pytest.raises(exceptions.AuthError):
                client._execute('mutation { saved }', {})
            assert execute.call_count == 1
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert not client._refresh_thread.is_alive() and client._credentials is None


def test_refresh_loop_survives_transient_errors_and_backs_off():
    client = object.__new__(WudderClient)
    client.refresh_token = 'fixture'
    client.graphql = Mock(headers={'x-jwt-token': 'fixture'})
    client._closed = Mock()
    client._closed.wait.side_effect = [False, False, True]
    client._renew_session = Mock(side_effect=[OSError('transient'), None])
    client._loop_refresh()
    assert client._renew_session.call_count == 2
    assert [call.args[0] for call in client._closed.wait.call_args_list] == [900, 30, 900]
