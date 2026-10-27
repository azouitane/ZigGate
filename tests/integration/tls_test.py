#!/usr/bin/env python3
"""OpenSSL HTTPS integration, generated development certificates, event-gated lifecycle."""
import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import warnings

BINARY = sys.argv[1]
REQUEST = b'GET /health HTTP/1.1\r\nHost: default.test\r\n\r\n'
CLOSE = REQUEST[:-2] + b'Connection: close\r\n\r\n'


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def certificates(directory):
    paths = {}
    for hostname in ('default.test', 'alternate.test'):
        cert, key = directory / (hostname + '.crt'), directory / (hostname + '.key')
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=' + hostname, '-addext', 'subjectAltName=DNS:' + hostname, '-keyout', key, '-out', cert)
        paths[hostname] = (cert, key)
    # Real leaf/intermediate/root chain: the client trusts only the root.
    root_cert, root_key = directory / 'root.crt', directory / 'root.key'
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=Test Root', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', root_key, '-out', root_cert)
    intermediate_key, intermediate_csr, intermediate_cert = [directory / name for name in ('intermediate.key', 'intermediate.csr', 'intermediate.crt')]
    openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=Test Intermediate', '-keyout', intermediate_key, '-out', intermediate_csr)
    ext = directory / 'ca.ext'
    ext.write_text('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
    openssl('x509', '-req', '-in', intermediate_csr, '-CA', root_cert, '-CAkey', root_key, '-CAcreateserial', '-days', '2', '-extfile', ext, '-out', intermediate_cert)
    chain_key, chain_csr, chain_leaf = [directory / name for name in ('chain.key', 'chain.csr', 'chain.crt')]
    openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=default.test', '-keyout', chain_key, '-out', chain_csr)
    ext = directory / 'leaf.ext'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:default.test\n')
    openssl('x509', '-req', '-in', chain_csr, '-CA', intermediate_cert, '-CAkey', intermediate_key, '-CAcreateserial', '-days', '2', '-extfile', ext, '-out', chain_leaf)
    fullchain = directory / 'fullchain.pem'
    fullchain.write_bytes(chain_leaf.read_bytes() + intermediate_cert.read_bytes())
    paths['chain'] = (fullchain, chain_key)
    paths['root'] = root_cert
    return paths


class Server:
    def __init__(self, paths, *args, chain=False):
        self.port, self.tls_port = port(), port()
        self.chain = chain
        cert, key = paths['chain' if chain else 'default.test']
        self.command = [BINARY, '--port', str(self.port), '--tls-listen', f'127.0.0.1:{self.tls_port}', '--tls-cert', str(cert), '--tls-key', str(key), '--log-level', 'debug', *args]
        self.records = []
        self.condition = threading.Condition()
        self.errors = []
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

    def wait(self, event, count=1):
        with self.condition:
            assert self.condition.wait_for(lambda: sum(r['event'] == event for r in self.records) >= count or self.errors, timeout=8), (event, self.records)
            assert not self.errors, self.errors
            return next(r for r in reversed(self.records) if r['event'] == event)

    def client(self, paths, version=None, hostname='default.test', verify=True):
        ctx = ssl.create_default_context(cafile=str(paths['root'] if self.chain else paths['default.test'][0]))
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if hostname is None:
            ctx.check_hostname = False
        if version:
            ctx.minimum_version = ctx.maximum_version = version
        ctx.set_alpn_protocols(['http/1.1'])
        raw = socket.create_connection(('127.0.0.1', self.tls_port), timeout=5)
        try:
            return ctx.wrap_socket(raw, server_hostname=hostname, suppress_ragged_eofs=False)
        except Exception:
            raw.close()
            raise

    def stop(self, sig=signal.SIGTERM):
        if self.proc.poll() is None and not any(r["event"] == "shutdown_begin" for r in self.records):
            self.proc.send_signal(sig)
        returncode = self.proc.wait(timeout=6)
        assert returncode == 0, (returncode, self.records)
        self.reader.join(timeout=3)
        assert not self.errors, self.errors
        self.proc.stderr.close()

    def cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.reader.join(timeout=3)
        self.proc.stderr.close()


@contextlib.contextmanager
def server(paths, *args, **kwargs):
    instance = Server(paths, *args, **kwargs)
    try:
        yield instance
    finally:
        instance.cleanup()


class Wire:
    def __init__(self, sock):
        self.sock, self.buffer = sock, b''

    def response(self, status=200):
        while b'\r\n\r\n' not in self.buffer:
            chunk = self.sock.recv(65536)
            assert chunk, self.buffer
            self.buffer += chunk
        header, self.buffer = self.buffer.split(b'\r\n\r\n', 1)
        assert header.startswith(f'HTTP/1.1 {status} '.encode()), header
        fields = dict(line.lower().split(b': ', 1) for line in header.split(b'\r\n')[1:])
        length = int(fields[b'content-length'])
        while len(self.buffer) < length:
            chunk = self.sock.recv(65536)
            assert chunk
            self.buffer += chunk
        body, self.buffer = self.buffer[:length], self.buffer[length:]
        return fields, body


def eof(sock):
    try:
        assert sock.recv(1024) == b''
    except ConnectionResetError:
        pass


def basic(paths):
    alt_cert, alt_key = paths['alternate.test']
    with server(paths, '--tls-sni', f'alternate.test={alt_cert},{alt_key}') as gateway:
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with gateway.client(paths, version) as client:
                assert client.selected_alpn_protocol() == 'http/1.1'
                wire = Wire(client)
                for _ in range(3):
                    client.sendall(REQUEST)
                    fields, body = wire.response()
                    assert body == b'ok\n' and fields[b'connection'] == b'keep-alive'
                client.sendall(CLOSE)
                assert wire.response()[1] == b'ok\n'
                eof(client)  # strict ragged-EOF detection verifies server close_notify
        # Default, unknown and absent SNI; alternate selects a different leaf.
        for hostname in (None, 'unknown.test', 'alternate.test', 'ALTERNATE.TEST'):
            with gateway.client(paths, hostname=hostname, verify=False) as client:
                selected = 'alternate.test' if hostname and hostname.lower() == 'alternate.test' else 'default.test'
                assert client.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(paths[selected][0].read_text())
                client.sendall(CLOSE)
                assert Wire(client).response()[1] == b'ok\n'
                eof(client)
        # Plain HTTP remains available on the original listener.
        with socket.create_connection(('127.0.0.1', gateway.port), timeout=3) as plain:
            plain.sendall(CLOSE)
            assert Wire(plain).response()[1] == b'ok\n'
        # Concurrent clients, including keep-alive on every connection.
        barrier = threading.Barrier(32)
        def exchange(_):
            barrier.wait(timeout=8)
            with gateway.client(paths) as client:
                client.sendall(REQUEST)
                assert Wire(client).response()[1] == b'ok\n'
                client.sendall(CLOSE)
                assert Wire(client).response()[1] == b'ok\n'
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            list(pool.map(exchange, range(32)))
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = version
            ctx.set_ciphers('ALL:@SECLEVEL=0')
            with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
                try:
                    ctx.wrap_socket(raw, server_hostname='default.test')
                except ssl.SSLError:
                    pass
                else:
                    raise AssertionError('obsolete protocol accepted')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
            try:
                ctx.wrap_socket(raw, server_hostname='default.test')
            except ssl.SSLError:
                pass
            else:
                raise AssertionError('unsupported ALPN accepted')
        gateway.stop()
        metrics = [r['data'] for r in gateway.records if r['event'] == 'metrics'][-1]
        assert metrics['tls_1_2'] >= 1 and metrics['tls_1_3'] >= 1
        assert metrics['tls_handshake_failures'] >= 3
        assert metrics['active_tls'] == metrics['active_clients'] == 0
        assert 'PRIVATE KEY' not in json.dumps(gateway.records)
    with server(paths, chain=True) as gateway:
        # Trust only the root, requiring delivery of the intermediate.
        ctx = ssl.create_default_context(cafile=str(paths['root']))
        with ctx.wrap_socket(socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3), server_hostname='default.test') as client:
            client.sendall(CLOSE)
            assert Wire(client).response()[1] == b'ok\n'
        gateway.stop()


def framing(paths):
    with server(paths, '--header-bytes', '512') as gateway:
        for header, status in ((b'Content-Length: 0\r\nContent-Length: 0\r\n', 400), (b'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n', 400), (b' Folded: bad\r\n', 400), (b'X: ' + b'a' * 600 + b'\r\n', 431)):
            with gateway.client(paths) as client:
                client.sendall(b'GET /health HTTP/1.1\r\nHost: x\r\n' + header + b'\r\n')
                Wire(client).response(status)
                eof(client)
        # Feed a TLS record one wire byte at a time through MemoryBIO, then split
        # request headers into separate encrypted application records.
        ctx = ssl.create_default_context(cafile=str(paths['default.test'][0]))
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname='default.test')
        with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
            for _ in range(100):
                done = False
                try:
                    tls.do_handshake()
                    done = True
                except ssl.SSLWantReadError:
                    pass
                data = outgoing.read()
                if data:
                    for byte in data:
                        raw.sendall(bytes([byte]))
                if done:
                    break
                incoming.write(raw.recv(65536))
            else:
                raise AssertionError('fragmented handshake failed')
            for chunk in (b'GET /health HTTP/1.1\r\n', b'Host: x\r\nConnection: close\r\n\r\n'):
                tls.write(chunk)
                raw.sendall(outgoing.read())
            result = b''
            for _ in range(100):
                try:
                    result += tls.read(4096)
                    if result.endswith(b'ok\n'):
                        break
                except ssl.SSLWantReadError:
                    incoming.write(raw.recv(65536))
            assert result.endswith(b'ok\n'), result
        gateway.stop()


def decrypted_deadlines_and_truncation(paths):
    with server(paths, '--timeout-ms', '200', '--idle-timeout-ms', '200') as gateway:
        with gateway.client(paths) as client:
            client.sendall(b'GET /health HTTP/1.1\r\n')
            gateway.wait('request_started')
            Wire(client).response(408)
            eof(client)
        with gateway.client(paths) as client:
            client.sendall(REQUEST)
            assert Wire(client).response()[1] == b'ok\n'
            eof(client)  # idle keep-alive expiry emits close_notify without an HTTP response
        ctx = ssl.create_default_context(cafile=str(paths['default.test'][0]))
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname='default.test')
        with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
            for _ in range(100):
                ready = False
                try:
                    tls.do_handshake()
                    ready = True
                except ssl.SSLWantReadError:
                    pass
                data = outgoing.read()
                if data:
                    raw.sendall(data)
                if ready:
                    break
                incoming.write(raw.recv(65536))
            else:
                raise AssertionError('BIO handshake failed')
            tls.write(CLOSE)
            ciphertext = outgoing.read()
            assert len(ciphertext) > 8
            raw.sendall(ciphertext[:-8])  # incomplete encrypted application record
            raw.shutdown(socket.SHUT_WR)
            result = b''
            while True:
                try:
                    data = raw.recv(4096)
                except ConnectionResetError:
                    break
                if not data:
                    break
                result += data
            assert b'HTTP/1.1' not in result
        with gateway.client(paths) as client:
            client.sendall(CLOSE)
            assert Wire(client).response()[1] == b'ok\n'
        gateway.stop()


def handshakes(paths):
    with server(paths, '--tls-handshake-ms', '200', '--max-connections', '4') as gateway:
        held = [socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) for _ in range(4)]
        try:
            gateway.wait('tls_accepted', 4)
            with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as extra:
                eof(extra)
            # Incomplete TLS header cannot extend the absolute handshake deadline.
            for client in held:
                client.sendall(b'\x16\x03\x03\x40\x00')
            for client in held:
                eof(client)
            gateway.wait('tls_handshake_failed', 4)
        finally:
            for client in held:
                client.close()
        with gateway.client(paths) as client:
            client.sendall(CLOSE)
            assert Wire(client).response()[1] == b'ok\n'
        # Plaintext and malformed/oversized records never fall back to HTTP.
        for payload in (CLOSE, b'\x16\x03\x03\xff\xff' + b'x' * 32):
            with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
                raw.sendall(payload)
                try:
                    data = raw.recv(4096)
                    assert b'HTTP/1.1' not in data
                except ConnectionResetError:
                    pass
        gateway.stop()
        metrics = [r['data'] for r in gateway.records if r['event'] == 'metrics'][-1]
        assert metrics['tls_handshake_timeouts'] >= 4
        assert metrics['connection_rejections'] >= 1


class Backend:
    def __init__(self, size):
        self.payload = b'z' * size
        self.ready, self.release = threading.Event(), threading.Event()
        self.request = b''
        self.errors = []
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        def serve():
            try:
                conn, _ = self.socket.accept()
                with conn:
                    conn.settimeout(8)
                    while b'\r\n\r\n' not in self.request:
                        self.request += conn.recv(8192)
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n'.encode() + self.payload[:3])
                    self.ready.set()
                    assert self.release.wait(8)
                    conn.sendall(self.payload[3:])
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                self.errors.append(exc)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.thread.join(timeout=9)
        self.socket.close()
        assert not self.thread.is_alive() and not self.errors, self.errors


def proxy_shutdown(paths, mode):
    backend = Backend(3 * 1024 * 1024 if mode == 'drain' else 6)
    try:
        with server(paths, '--proxy', f'/api=127.0.0.1:{backend.port}', '--shutdown-ms', '200' if mode == 'deadline' else '3000') as gateway:
            with gateway.client(paths) as client:
                client.sendall(b'GET /api/stream HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: attacker\r\nForwarded: secret\r\n\r\n')
                assert backend.ready.wait(5)
                wire = Wire(client)
                while not wire.buffer.endswith(b'zzz'):
                    wire.buffer += client.recv(65536)
                assert b'X-Forwarded-Proto: https\r\n' in backend.request
                assert b'attacker' not in backend.request and b'Forwarded: secret' not in backend.request
                gateway.proc.terminate()
                gateway.wait('shutdown_begin')
                # Listener is closed as soon as the drain begins.
                try:
                    socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=1).close()
                except OSError:
                    pass
                else:
                    raise AssertionError('TLS listener still open')
                if mode == 'drain':
                    backend.release.set()
                    assert wire.response()[1] == backend.payload
                    eof(client)
                elif mode == 'second':
                    gateway.proc.send_signal(signal.SIGINT)
                gateway.stop()
                complete = next(r for r in gateway.records if r['event'] == 'shutdown_complete')
                assert complete['data']['forced'] == (mode != 'drain')
    finally:
        backend.close()


def proxy_disconnect(paths):
    backend = Backend(4 * 1024 * 1024)
    try:
        with server(paths, '--proxy', f'/api=127.0.0.1:{backend.port}', '--max-upstreams', '1') as gateway:
            baseline = len(list(Path(f'/proc/{gateway.proc.pid}/fd').iterdir()))
            client = gateway.client(paths)
            try:
                client.sendall(b'GET /api/stream HTTP/1.1\r\nHost: x\r\n\r\n')
                assert backend.ready.wait(5)
                first = b''
                while not first.endswith(b'zzz'):
                    first += client.recv(65536)
                os.close(client.detach())
            finally:
                client.close()
            backend.release.set()
            gateway.wait('http_request')  # stream retired after the client disappears
            with gateway.client(paths) as healthy:
                healthy.sendall(CLOSE)
                assert Wire(healthy).response()[1] == b'ok\n'
                eof(healthy)
            assert len(list(Path(f'/proc/{gateway.proc.pid}/fd').iterdir())) <= baseline + 1
            gateway.stop()
            metrics = [r['data'] for r in gateway.records if r['event'] == 'metrics'][-1]
            assert metrics['active_upstreams'] == metrics['active_clients'] == metrics['active_tls'] == 0
    finally:
        backend.close()


def disconnects(paths):
    with server(paths, '--tls-handshake-ms', '200') as gateway:
        fd_path = Path(f'/proc/{gateway.proc.pid}/fd')
        baseline = len(list(fd_path.iterdir()))
        for _ in range(30):
            with gateway.client(paths) as client:
                client.sendall(REQUEST)
                assert Wire(client).response()[1] == b'ok\n'
                os.close(client.detach())  # TCP EOF without TLS close_notify
        for _ in range(20):
            with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as raw:
                raw.sendall(b'\x16\x03\x03\x00\x40\x01')  # truncated handshake record
        gateway.wait('tls_handshake_failed', 20)
        # The next successful response demonstrates progress after the failure wave.
        with gateway.client(paths) as client:
            client.sendall(CLOSE)
            assert Wire(client).response()[1] == b'ok\n'
        assert len(list(fd_path.iterdir())) <= baseline + 2
        gateway.stop(signal.SIGINT)
    # Idle HTTPS keep-alive gets orderly close_notify during graceful shutdown.
    with server(paths) as gateway:
        with gateway.client(paths) as client:
            client.sendall(REQUEST)
            assert Wire(client).response()[1] == b'ok\n'
            gateway.proc.terminate()
            gateway.wait('shutdown_begin')
            eof(client)
            gateway.stop()


def invalid(paths, directory):
    cert, key = paths['default.test']
    invalid_cert = directory / 'invalid.pem'
    invalid_cert.write_text('not a certificate\n')
    encrypted = directory / 'encrypted.key'
    openssl('pkey', '-in', key, '-aes-256-cbc', '-passout', 'pass:test-only-password', '-out', encrypted)
    common = ['--tls-listen', '127.0.0.1:8443']
    configurations = [common, common + ['--tls-cert', str(cert)], common + ['--tls-key', str(key)], ['--tls-cert', str(cert), '--tls-key', str(key)], common + ['--tls-cert', str(cert), '--tls-key', str(paths['alternate.test'][1])], common + ['--tls-cert', str(invalid_cert), '--tls-key', str(key)], common + ['--tls-cert', str(cert), '--tls-key', str(directory / 'missing')], common + ['--tls-cert', str(cert), '--tls-key', str(encrypted)], ['--tls-listen', 'localhost:8443', '--tls-cert', str(cert), '--tls-key', str(key)], common + ['--tls-cert', str(cert), '--tls-key', str(key), '--tls-sni', '*.test=c,k']]
    for args in configurations:
        for check in ([], ['--check-config']):
            result = subprocess.run([BINARY, *args, *check], capture_output=True, timeout=5)
            assert result.returncode == 2, (args, result.stderr)
            assert b'PRIVATE KEY' not in result.stderr and b'test-only-password' not in result.stderr
    result = subprocess.run([BINARY, *common, '--tls-cert', str(cert), '--tls-key', str(key), '--check-config'], capture_output=True, timeout=5)
    assert result.returncode == 0


def main():
    with tempfile.TemporaryDirectory(prefix='ziggate-tls-') as temporary:
        directory = Path(temporary)
        paths = certificates(directory)
        invalid(paths, directory)
        basic(paths)
        framing(paths)
        decrypted_deadlines_and_truncation(paths)
        handshakes(paths)
        proxy_disconnect(paths)
        disconnects(paths)
        for mode in ('drain', 'deadline', 'second'):
            proxy_shutdown(paths, mode)
    print('PASS: TLS 1.2/1.3, HTTPS keep-alive, SNI, chain validation, old TLS/ALPN rejection, framing, fragmented records, handshake limits, cleanup, proxy HTTPS metadata, streaming and shutdown')


if __name__ == '__main__':
    main()
