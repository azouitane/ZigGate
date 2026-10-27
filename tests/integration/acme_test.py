#!/usr/bin/env python3
"""Offline RFC 8555 test CA: trusted HTTPS, ES256 JWS verification and real CSR signing.
No public CA, DNS service, container, Pebble download or third-party Python package.
"""
import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tls_test as tls

BINARY = sys.argv[1]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode(text):
    assert isinstance(text, str) and '=' not in text
    return base64.urlsafe_b64decode(text + '=' * ((-len(text)) % 4))


def der_integer(data):
    data = data.lstrip(b'\0') or b'\0'
    if data[0] & 128:
        data = b'\0' + data
    return b'\x02' + bytes([len(data)]) + data


class CA:
    def __init__(self, directory):
        self.directory = directory
        self.root, self.root_key = directory / 'ca.pem', directory / 'ca.key'
        tls.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=Offline ACME Root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', self.root, '-keyout', self.root_key)
        endpoint_key, endpoint_csr, endpoint_cert = [directory / name for name in ('endpoint.key', 'endpoint.csr', 'endpoint.crt')]
        tls.openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', endpoint_key, '-out', endpoint_csr)
        ext = directory / 'endpoint.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        tls.openssl('x509', '-req', '-in', endpoint_csr, '-CA', self.root, '-CAkey', self.root_key, '-CAcreateserial', '-days', '2', '-extfile', ext, '-out', endpoint_cert)
        self.lock = threading.RLock()
        self.nonces = set()
        self.jwk = None
        self.orders = {}
        self.auths = {}
        self.serial = 0x87654320
        self.ari_ids = set()
        ski = subprocess.run(['openssl', 'x509', '-in', str(self.root), '-noout', '-ext', 'subjectKeyIdentifier'], capture_output=True, check=True).stdout.decode().splitlines()[-1].strip()
        self.aki = b64(bytes.fromhex(ski.replace(':', '')))
        self.accounts = 0
        self.bad_nonces = 0
        self.challenge_bodies = []
        self.urls = []
        self.errors = []
        self.mode = 'normal'
        self.ari = False
        self.ari_reads = 0
        self.replacements = 0
        self.bad_nonce_once = True
        self.gateway_port = None
        self.stalled = threading.Event()
        self.release = threading.Event()
        self.gate_orders = False
        self.order_started = threading.Event()
        self.order_release = threading.Event()
        ca = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def handle(self):
                try:
                    super().handle()
                except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
                    pass
            def log_message(self, *args):
                pass
            def reply(self, status, body=b'', location=None, retry=None):
                self.send_response(status)
                nonce = secrets.token_urlsafe(24)
                with ca.lock:
                    ca.nonces.add(nonce)
                self.send_header('Replay-Nonce', nonce)
                self.send_header('Content-Type', 'application/json' if not body.startswith(b'-----') else 'application/pem-certificate-chain')
                self.send_header('Content-Length', str(len(body)))
                if location:
                    self.send_header('Location', location)
                if retry is not None:
                    self.send_header('Retry-After', str(retry))
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(body)
            def problem(self, name, status=400, retry=None):
                self.reply(status, json.dumps({'type': 'urn:ietf:params:acme:error:' + name}).encode(), retry=retry)
            def do_HEAD(self):
                self.reply(204)
            def do_GET(self):
                try:
                    ca.urls.append(self.path)
                    if self.path.startswith('/renewal/'):
                        ca.ari_reads += 1
                        assert self.path.rsplit('/', 1)[1] in ca.ari_ids
                        now = int(time.time())
                        start = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 3600))
                        end = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 7200))
                        return self.reply(200, json.dumps({'suggestedWindow': {'start': start, 'end': end}}).encode(), retry=21600)
                    if self.path != '/directory':
                        return self.reply(404)
                    if ca.mode == 'timeout':
                        ca.stalled.set()
                        ca.release.wait(20)
                    if ca.mode == 'malformed':
                        return self.reply(200, b'{malformed')
                    if ca.mode == 'oversize':
                        return self.reply(200, b' ' * (1048576 + 1))
                    if ca.mode == 'redirect':
                        return self.reply(302, location=ca.origin + '/never-follow')
                    document = dict(newNonce=ca.origin + '/nonce', newAccount=ca.origin + '/account', newOrder=ca.origin + '/orders')
                    if ca.ari:
                        document['renewalInfo'] = ca.origin + '/renewal'
                    if ca.mode == 'cross-origin':
                        document['newNonce'] = 'https://127.0.0.1:1/nonce'
                    self.reply(200, json.dumps(document).encode())
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                except Exception as exc:
                    ca.errors.append(repr(exc))
            def jws(self):
                assert self.headers.get('Content-Type') == 'application/jose+json'
                length = int(self.headers['Content-Length'])
                assert 0 < length < 65536
                envelope = json.loads(self.rfile.read(length))
                protected = json.loads(decode(envelope['protected']))
                assert protected['alg'] == 'ES256'
                assert protected['url'] == ca.origin + self.path
                nonce = protected['nonce']
                with ca.lock:
                    assert nonce in ca.nonces, 'nonce reused or unknown'
                    ca.nonces.remove(nonce)
                if self.path == '/account':
                    assert 'jwk' in protected and 'kid' not in protected
                    jwk = protected['jwk']
                    assert jwk['kty'] == 'EC' and jwk['crv'] == 'P-256'
                    if ca.jwk:
                        assert jwk == ca.jwk
                else:
                    assert protected['kid'] == ca.origin + '/account/1' and 'jwk' not in protected
                    jwk = ca.jwk
                # Verify real ES256 output with OpenSSL, independently of the client.
                x, y = decode(jwk['x']), decode(jwk['y'])
                assert len(x) == len(y) == 32
                spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004') + x + y
                signature = decode(envelope['signature'])
                assert len(signature) == 64
                integers = der_integer(signature[:32]) + der_integer(signature[32:])
                with tempfile.TemporaryDirectory(dir=ca.directory) as temporary:
                    path = Path(temporary)
                    (path / 'pub.der').write_bytes(spki)
                    tls.openssl('pkey', '-pubin', '-inform', 'DER', '-in', path / 'pub.der', '-out', path / 'pub.pem')
                    (path / 'signature.der').write_bytes(b'\x30' + bytes([len(integers)]) + integers)
                    (path / 'input').write_text(envelope['protected'] + '.' + envelope['payload'])
                    tls.openssl('dgst', '-sha256', '-verify', path / 'pub.pem', '-signature', path / 'signature.der', path / 'input')
                raw = decode(envelope['payload'])
                return jwk, json.loads(raw) if raw else None
            def do_POST(self):
                try:
                    ca.urls.append(self.path)
                    jwk, payload = self.jws()
                    if ca.mode == 'bad-nonce' or (ca.bad_nonce_once and ca.bad_nonces == 0):
                        ca.bad_nonces += 1
                        return self.problem('badNonce')
                    if self.path == '/account':
                        assert payload['termsOfServiceAgreed'] is True
                        existing = ca.jwk is not None
                        if not existing:
                            ca.accounts += 1
                        ca.jwk = jwk
                        return self.reply(200 if existing else 201, b'{"status":"valid"}', ca.origin + '/account/1')
                    if self.path == '/account/1':
                        assert payload is None, 'account lookup must be POST-as-GET'
                        return self.reply(200, b'{"status":"valid"}')
                    if self.path == '/orders':
                        if ca.gate_orders:
                            ca.order_started.set()
                            assert ca.order_release.wait(10)
                            ca.gate_orders = False
                        if ca.mode == 'rate-limit':
                            return self.problem('rateLimited', 429, 120)
                        if ca.mode == 'failure':
                            return self.problem('serverInternal', 503, 1)
                        if 'replaces' in payload:
                            assert payload['replaces'] in ca.ari_ids
                            ca.replacements += 1
                        names = [identifier['value'] for identifier in payload['identifiers']]
                        assert all(identifier['type'] == 'dns' for identifier in payload['identifiers'])
                        order_id = len(ca.orders) + 1
                        auth_urls = []
                        for name in names:
                            auth_id = len(ca.auths) + 1
                            token = secrets.token_urlsafe(24)
                            ca.auths[auth_id] = dict(name=name, token=token, valid=False)
                            auth_urls.append(ca.origin + f'/auth/{auth_id}')
                        ca.orders[order_id] = dict(status='pending', identifiers=payload['identifiers'], authorizations=auth_urls, finalize=ca.origin + f'/finalize/{order_id}')
                        return self.reply(201, json.dumps(ca.orders[order_id]).encode(), ca.origin + f'/order/{order_id}')
                    if self.path.startswith('/auth/'):
                        assert payload is None
                        auth_id = int(self.path.split('/')[-1])
                        auth = ca.auths[auth_id]
                        if ca.mode == 'stall':
                            ca.stalled.set()
                            ca.release.wait(20)
                        return self.reply(200, json.dumps(dict(status='valid' if auth['valid'] else 'pending', identifier=dict(type='dns', value=auth['name']), challenges=[dict(type='http-01', token=auth['token'], url=ca.origin + f'/challenge/{auth_id}')])).encode())
                    if self.path.startswith('/challenge/'):
                        assert payload == {}
                        auth_id = int(self.path.split('/')[-1])
                        auth = ca.auths[auth_id]
                        connection = http.client.HTTPConnection('127.0.0.1', ca.gateway_port, timeout=5)
                        try:
                            connection.request('GET', '/.well-known/acme-challenge/' + auth['token'], headers={'Host': auth['name']})
                            response = connection.getresponse()
                            body = response.read()
                            thumb = b64(hashlib.sha256(json.dumps(ca.jwk, separators=(',', ':'), sort_keys=True).encode()).digest())
                            assert response.status == 200 and body == (auth['token'] + '.' + thumb).encode(), (response.status, body)
                            ca.challenge_bodies.append(body)
                        finally:
                            connection.close()
                        auth['valid'] = True
                        return self.reply(200, b'{"status":"processing"}', retry=1)
                    if self.path.startswith('/order/'):
                        assert payload is None
                        order_id = int(self.path.split('/')[-1])
                        order = ca.orders[order_id]
                        if order['status'] == 'pending' and all(ca.auths[int(url.split('/')[-1])]['valid'] for url in order['authorizations']):
                            order['status'] = 'ready'
                        return self.reply(200, json.dumps({key: value for key, value in order.items() if key != 'chain'}).encode())
                    if self.path.startswith('/finalize/'):
                        order_id = int(self.path.split('/')[-1])
                        order = ca.orders[order_id]
                        assert order['status'] == 'ready'
                        csr = decode(payload['csr'])
                        with tempfile.TemporaryDirectory(dir=ca.directory) as temporary:
                            path = Path(temporary)
                            (path / 'request.der').write_bytes(csr)
                            tls.openssl('req', '-inform', 'DER', '-in', path / 'request.der', '-verify', '-noout')
                            ca.serial += 1
                            tls.openssl('x509', '-req', '-inform', 'DER', '-in', path / 'request.der', '-CA', ca.root, '-CAkey', ca.root_key, '-set_serial', str(ca.serial), '-days', '90', '-copy_extensions', 'copy', '-out', path / 'leaf.pem')
                            certificate = (path / 'leaf.pem').read_bytes()
                            serial = ca.serial.to_bytes((ca.serial.bit_length() + 7) // 8, 'big')
                            if serial[0] & 128:
                                serial = b'\0' + serial
                            ca.ari_ids.add(ca.aki + '.' + b64(serial))
                            if ca.mode == 'wrong-certificate':
                                certificate = (ca.directory / 'endpoint.crt').read_bytes()
                            order['chain'] = certificate + ca.root.read_bytes()
                        order['status'] = 'valid'
                        order['certificate'] = ca.origin + f'/cert/{order_id}'
                        return self.reply(200, b'{"status":"processing"}')
                    if self.path.startswith('/cert/'):
                        assert payload is None
                        return self.reply(200, ca.orders[int(self.path.split('/')[-1])]['chain'])
                    self.reply(404)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                except Exception as exc:
                    ca.errors.append(repr(exc))
                    self.problem('serverInternal', 500)
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.http.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(endpoint_cert, endpoint_key)
        self.http.socket = context.wrap_socket(self.http.socket, server_side=True)
        self.origin = f'https://127.0.0.1:{self.http.server_address[1]}'
        self.thread = threading.Thread(target=self.http.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
    def close(self):
        self.release.set()
        self.order_release.set()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=3)
        assert not self.errors, self.errors


class Gateway:
    def __init__(self, ca, storage, *extra):
        self.port, self.tls_port = tls.port(), tls.port()
        ca.gateway_port = self.port
        self.storage = storage
        self.records, self.errors = [], []
        self.condition = threading.Condition()
        self.command = [BINARY, '--port', str(self.port), '--tls-listen', f'127.0.0.1:{self.tls_port}', '--acme-enabled', '--acme-accept-terms', '--acme-domain', 'example.test', '--acme-domain', 'second.test', '--acme-email', 'operator@example.test', '--acme-storage', str(storage), '--acme-directory', ca.origin + '/directory', '--acme-ca-file', str(ca.root), '--acme-issuer-ca-file', str(ca.root), *extra]
        self.proc = subprocess.Popen(self.command, stderr=subprocess.PIPE)
        def collect():
            for line in self.proc.stderr:
                with self.condition:
                    try:
                        self.records.append(json.loads(line))
                    except Exception:
                        self.errors.append(line)
                    self.condition.notify_all()
        self.reader = threading.Thread(target=collect, daemon=True)
        self.reader.start()
        self.wait('server_start')
    def wait(self, event, count=1, timeout=15):
        with self.condition:
            assert self.condition.wait_for(lambda: sum(r['event'] == event for r in self.records) >= count or self.errors, timeout=timeout), (event, self.records[-4:])
            assert not self.errors, self.errors
            return next(r for r in reversed(self.records) if r['event'] == event)
    def https(self, ca, name='example.test'):
        context = ssl.create_default_context(cafile=str(ca.root))
        return context.wrap_socket(socket.create_connection(('127.0.0.1', self.tls_port), timeout=5), server_hostname=name)
    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        assert self.proc.wait(timeout=6) == 0, self.records
        self.reader.join(timeout=3)
        assert not self.errors, self.errors
        self.proc.stderr.close()
    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.reader.join(timeout=3)
        self.proc.stderr.close()


@contextlib.contextmanager
def gateway(ca, storage, *extra):
    instance = Gateway(ca, storage, *extra)
    try:
        yield instance
    finally:
        instance.close()


def get_http(instance, path, status):
    connection = http.client.HTTPConnection('127.0.0.1', instance.port, timeout=3)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        body = response.read()
        assert response.status == status, (path, response.status, body)
        return body
    finally:
        connection.close()


def exchange(client):
    client.sendall(b'GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n')
    assert tls.Wire(client).response()[1] == b'ok\n'


def due(storage):
    path = storage / 'state.json'
    state = json.loads(path.read_text())
    state.update(renew_at=int(time.time()), next_attempt=0, failures=0)
    path.write_text(json.dumps(state))


@contextlib.contextmanager
def http_backend():
    observed = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def do_GET(self):
            observed['scheme'] = self.headers.get('X-Forwarded-Proto')
            body = b'backend-over-plaintext-http\n'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=backend.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    thread.start()
    try:
        yield backend.server_address[1], observed
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=3)


def issuance_and_renewal(ca, storage):
    ca.ari = True
    with http_backend() as (backend_port, observed), gateway(ca, storage, '--proxy', '/.well-known/=127.0.0.1:1', '--proxy', f'/probe=127.0.0.1:{backend_port}') as instance:
        instance.wait('acme_certificate_activated')
        assert ca.accounts == 1 and ca.bad_nonces == 1
        assert len(ca.challenge_bodies) == 2 and ca.ari_reads == 1
        for auth in ca.auths.values():
            get_http(instance, '/.well-known/acme-challenge/' + auth['token'], 404)
        get_http(instance, '/.well-known/acme-challenge/../../account.key', 400)
        get_http(instance, '/.well-known/acme-challenge/not-a-valid-token', 404)
        first_cert = None
        for hostname in ('example.test', 'second.test'):
            with instance.https(ca, hostname) as client:
                exchange(client)
                first_cert = client.getpeercert(binary_form=True)
                if hostname == 'example.test':
                    client.sendall(b'GET /probe HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-Proto: attacker\r\n\r\n')
                    assert tls.Wire(client).response()[1] == b'backend-over-plaintext-http\n'
                    assert observed['scheme'] == 'https'
                    tls.eof(client)
        for path in storage.rglob('*'):
            if path.is_file():
                assert path.stat().st_mode & 0o077 == 0, path
        assert storage.stat().st_mode & 0o077 == 0
        instance.stop()
    # Simulate an interrupted inactive-bundle/state write before restart. The
    # committed selector must continue to load the complete previous generation.
    (storage / '.temporary').write_text('interrupted state update')
    os.chmod(storage / '.temporary', 0o600)
    inactive = storage / 'bundle1'
    inactive.mkdir(mode=0o700, exist_ok=True)
    (inactive / 'key.pem').write_text('partial uncommitted key')
    os.chmod(inactive / 'key.pem', 0o600)
    account_key = (storage / 'account.key').read_bytes()
    old_state = json.loads((storage / 'state.json').read_text())
    (storage / 'account.json').unlink()  # recover Location with the same JWK after a crash
    due(storage)  # deterministic simulated eligibility, not a test-only server bypass
    ca.gate_orders = True
    ca.order_started.clear()
    ca.order_release.clear()
    with gateway(ca, storage, '--idle-timeout-ms', '60000') as instance:
        assert ca.order_started.wait(8)
        active = instance.https(ca)
        try:
            exchange(active)
            assert active.getpeercert(binary_form=True) == first_cert
            instance.proc.send_signal(signal.SIGHUP)
            instance.wait('tls_reload_success')
            with instance.https(ca) as second:
                exchange(second)
                ca.order_release.set()
                failed = instance.wait('acme_activation_failed')
                assert failed['data']['reason'] == 'TlsReloadBusy', failed
                exchange(active)
                exchange(second)
                active.close()
                instance.wait('acme_certificate_activated')
                exchange(second)
                assert second.getpeercert(binary_form=True) == first_cert
                with instance.https(ca) as rotated:
                    exchange(rotated)
                    assert rotated.getpeercert(binary_form=True) != first_cert
        finally:
            active.close()
            ca.order_release.set()
        instance.stop()
        metrics = [r['data'] for r in instance.records if r['event'] == 'metrics'][-1]
        assert metrics['acme_renewal_successes'] == 1
    assert ca.accounts == 1 and (storage / 'account.key').read_bytes() == account_key
    state = json.loads((storage / 'state.json').read_text())
    assert state['slot'] != old_state['slot']
    assert (storage / f'bundle{state["slot"]}' / 'key.pem').read_bytes() != (storage / f'bundle{old_state["slot"]}' / 'key.pem').read_bytes()
    # Both current and prior complete generations survive rotation.
    assert (storage / f'bundle{old_state["slot"]}' / 'chain.pem').exists()
    ca.mode = 'failure'
    due(storage)
    with gateway(ca, storage) as instance:
        instance.wait('acme_failure')
        with instance.https(ca) as client:
            exchange(client)
        instance.stop()
        metrics = [r['data'] for r in instance.records if r['event'] == 'metrics'][-1]
        assert metrics['acme_renewal_failures'] == 1
    failed = json.loads((storage / 'state.json').read_text())
    assert failed['next_attempt'] > time.time() and failed['failures'] == 1
    ca.mode = 'normal'
    due(storage)
    with gateway(ca, storage) as instance:
        instance.wait('acme_certificate_activated')
        instance.stop()
    assert ca.accounts == 1 and ca.replacements >= 2


def failures(ca, directory):
    ca.bad_nonce_once = False
    ca.jwk = None
    wrong_root = directory / 'unrelated.pem'
    wrong_key = directory / 'unrelated.key'
    tls.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=Unrelated CA', '-out', wrong_root, '-keyout', wrong_key)
    before = len(ca.orders)
    with gateway(ca, directory / 'untrusted-transport', '--acme-ca-file', str(wrong_root)) as instance:
        result = instance.wait('acme_failure')
        assert result['data']['reason'] == 'AcmeTransportFailed'
        instance.stop()
    assert len(ca.orders) == before
    for mode in ('bad-nonce', 'cross-origin', 'malformed', 'oversize', 'redirect', 'wrong-certificate', 'rate-limit', 'timeout'):
        ca.mode = mode
        # Independent accounts use independent persistent storage; reset fixture JWK.
        ca.jwk = None
        before = len(ca.orders)
        with gateway(ca, directory / ('failure-' + mode)) as instance:
            result = instance.wait('acme_failure', timeout=25)
            assert not any(r['event'] == 'acme_certificate_activated' for r in instance.records), result
            get_http(instance, '/health', 200)
            instance.stop()
            state = json.loads((instance.storage / 'state.json').read_text())
            assert not state['has_certificate'] and state['next_attempt'] > time.time()
            if mode == 'rate-limit':
                assert state['next_attempt'] >= time.time() + 118
                metrics = [r['data'] for r in instance.records if r['event'] == 'metrics'][-1]
                assert metrics['acme_rate_limits'] == 1
            assert 'PRIVATE KEY' not in str(instance.records)
        if mode in ('cross-origin', 'malformed', 'oversize', 'redirect'):
            assert len(ca.orders) == before
    assert '/never-follow' not in ca.urls
    ca.release.set()
    ca.stalled.clear()
    ca.release.clear()
    ca.mode = 'stall'
    ca.jwk = None
    with gateway(ca, directory / 'cancel') as instance:
        assert ca.stalled.wait(8)
        get_http(instance, '/health', 200)
        start = time.monotonic()
        instance.stop()
        assert time.monotonic() - start < 5
    requests_before_restart = len(ca.urls)
    with gateway(ca, directory / 'cancel') as instance:
        get_http(instance, '/health', 200)
        instance.wait('metrics')
        assert len(ca.urls) == requests_before_restart, 'cancelled/in-flight orders need a persisted restart guard'
        instance.stop()
    ca.release.set()


def storage_security(ca, directory):
    unsafe = directory / 'unsafe'
    unsafe.mkdir(mode=0o755)
    command = [BINARY, '--check-config', '--acme-enabled', '--acme-accept-terms', '--acme-domain', 'example.test', '--acme-email', 'ops@example.test', '--acme-directory', ca.origin + '/directory', '--acme-ca-file', str(ca.root), '--acme-issuer-ca-file', str(ca.root), '--tls-listen', '127.0.0.1:9443', '--acme-storage']
    assert subprocess.run([*command, str(unsafe)], capture_output=True).returncode == 2
    safe = directory / 'safe'
    safe.mkdir(mode=0o700)
    link = directory / 'link'
    link.symlink_to(safe, target_is_directory=True)
    assert subprocess.run([*command, str(link)], capture_output=True).returncode == 2
    (safe / 'account.key').symlink_to(ca.root_key)
    assert subprocess.run([*command, str(safe)], capture_output=True).returncode == 2
    (safe / 'account.key').unlink()
    os.link(ca.root_key, safe / 'account.key')
    assert subprocess.run([*command, str(safe)], capture_output=True).returncode == 2
    (safe / 'account.key').unlink()
    # An interrupted atomic write cannot become an account or current certificate.
    (safe / '.temporary').write_text('interrupted')
    os.chmod(safe / '.temporary', 0o600)
    assert subprocess.run([*command, str(safe)], capture_output=True).returncode == 0
    assert not (safe / 'account.key').exists(), '--check-config must not generate keys or use network'
    assert ca.accounts > 0


def main():
    with tempfile.TemporaryDirectory(prefix='ziggate-acme-') as temporary:
        directory = Path(temporary)
        ca = CA(directory)
        try:
            issuance_and_renewal(ca, directory / 'persistent')
            failures(ca, directory)
            storage_security(ca, directory)
        finally:
            ca.close()
    print('PASS: offline trusted-HTTPS ACME, ES256/JWK/nonce validation, badNonce retries, account recovery, HTTP-01 precedence/expiry, CSR/SAN/chain validation, issuance/renewal/recovery, TLS activation and active sessions, secure storage, protocol failures, rate limits, cancellation')


if __name__ == '__main__':
    main()
