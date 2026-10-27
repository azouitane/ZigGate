#!/usr/bin/env python3
"""Raw local mock backends exercise framing, streaming and failure cleanup."""
import concurrent.futures
import contextlib
import errno
import json
import select
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading
import time

BINARY = sys.argv[1] if len(sys.argv) > 1 else './zig-out/bin/ziggate'
MAX_CONCURRENT_CLIENTS = 100
BACKEND_BACKLOG = 256
PAYLOAD = b'ziggate-stream-0123456789\n' * 174763  # About 4 MiB; much larger than proxy buffers.


class Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # Python <=3.14 defaults to 5. Handler threads do not enlarge the accept queue.
    # Provision for the whole burst; keep gateway deadlines unchanged at 500 ms.
    request_queue_size = BACKEND_BACKLOG

    def __init__(self, label):
        super().__init__(('127.0.0.1', 0), Handler)
        self.label = label
        self.hold_started = threading.Event()
        self.hold_release = threading.Event()
        self.slow_started = threading.Event()
        self.slow_release = threading.Event()
        self.records = []
        self.lock = threading.Lock()

    @property
    def port(self):
        return self.server_address[1]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            raw = b''
            while b'\r\n\r\n' not in raw:
                chunk = self.request.recv(97)  # Backend deliberately consumes request fragments.
                if not chunk:
                    return
                raw += chunk
                assert len(raw) <= 16384
            lines = raw.split(b'\r\n')
            method, target, version = lines[0].decode().split(' ')
            assert version == 'HTTP/1.1'
            fields = {}
            for line in lines[1:]:
                if not line:
                    break
                name, value = line.split(b':', 1)
                fields[name.lower().decode()] = value.strip().decode()
            record = dict(method=method, target=target, headers=fields, backend=self.server.label)
            with self.server.lock:
                self.server.records.append(record)
            action = target.split('?', 1)[0].rsplit('/', 1)[-1]
            if action == 'gated-slow':
                self.server.slow_started.set()
                self.server.slow_release.wait(3)
            if action == 'hold':
                self.server.hold_started.set()
                self.server.hold_release.wait(4)
            if action in ('timeout', 'late-timeout'):
                if action == 'late-timeout':
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc')
                time.sleep(1.5)
                return
            if action == 'disconnect':
                return
            if action == 'bad-status':
                self.request.sendall(b'HTTP/1.1 20X OK\r\nContent-Length: 0\r\n\r\n')
                return
            if action == 'bad-length':
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx')
                return
            if action == 'folded':
                self.request.sendall(b'HTTP/1.1 200 OK\r\n folded: bad\r\n\r\n')
                return
            if action == 'huge-header':
                self.request.sendall(b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 8192 + b'\r\n\r\n')
                return
            if action == 'chunked':
                self.request.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n')
                return
            if action == 'short':
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc')
                return
            if action == 'close':
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-body')
                return
            if action == 'no-content':
                self.request.sendall(b'HTTP/1.1 204 No Content\r\n\r\n')
                return
            body = PAYLOAD if action == 'stream' else json.dumps(record, sort_keys=True).encode()
            header = (b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                      + f'Content-Length: {len(body)}\r\n'.encode()
                      + b'X-Remove: hidden\r\nConnection: X-Remove, close\r\nKeep-Alive: timeout=5\r\nX-End-To-End: yes\r\n\r\n')
            if action == 'fragmented':
                for offset in range(0, len(header), 7):
                    self.request.sendall(header[offset:offset + 7])
                    time.sleep(.001)
            else:
                self.request.sendall(header)
            if method == 'HEAD':
                return
            for offset in range(0, len(body), 1371):
                self.request.sendall(body[offset:offset + 1371])
        except (OSError, AssertionError):
            # Disconnects and cancellation are intentional scenarios.
            return


@contextlib.contextmanager
def backend(label):
    server = Backend(label)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.hold_release.set()
        server.slow_release.set()
        server.shutdown()
        server.server_close()
        thread.join(3)


def raw_request(path, extra=b'', method=b'GET'):
    return method + b' ' + path.encode() + b' HTTP/1.1\r\nHost: client.example\r\n' + extra + b'\r\n'


def read_all(sock, slow=False):
    data = bytearray()
    while True:
        try:
            part = sock.recv(32768)
        except ConnectionResetError:
            break
        if not part:
            return bytes(data)
        data.extend(part)
        if slow:
            time.sleep(.001)
    return bytes(data)


def exchange(port, path, status=200, extra=b'', method=b'GET', slow=False, half_close=False, start=None):
    with socket.create_connection(('127.0.0.1', port), timeout=8) as sock:
        if start is not None:
            start.wait(timeout=8)  # All frontend sockets exist before the upstream burst.
        sock.sendall(raw_request(path, extra, method))
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        if slow:
            time.sleep(.15)
        raw = read_all(sock, slow)
    header, body = raw.split(b'\r\n\r\n', 1)
    lines = header.split(b'\r\n')
    assert lines[0].startswith(f'HTTP/1.1 {status} '.encode()), raw[:512]
    fields = dict(line.lower().split(b': ', 1) for line in lines[1:])
    assert fields[b'connection'] == b'close'
    if method == b'HEAD':
        assert not body
    elif b'content-length' in fields and path.rsplit('/', 1)[-1] not in ('short', 'late-timeout'):
        assert len(body) == int(fields[b'content-length']), (len(body), fields)
    return fields, body, raw


@contextlib.contextmanager
def gateway(a, b, refused_port, *options):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    args = [BINARY, '--port', str(port), '--upstream-connect-ms', '500',
            '--upstream-read-ms', '500', '--upstream-write-ms', '500',
            '--proxy-total-ms', '5000', '--proxy', f'/=127.0.0.1:{b.port}',
            '--proxy', f'/api/=127.0.0.1:{a.port}',
            '--proxy', f'/api/deep/=127.0.0.1:{b.port}',
            '--proxy', f'/refused/=127.0.0.1:{refused_port}', *options]
    proc = subprocess.Popen(args, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            assert proc.poll() is None, 'gateway exited'
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError('gateway startup timeout')
        yield port, proc
        assert proc.poll() is None, 'gateway died'
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def concurrent_wave(port, count):
    start = threading.Barrier(count)

    def worker(index):
        path = f'/api/echo?wave={count}&id={index}'
        record = json.loads(exchange(port, path, start=start)[1])
        assert record['backend'] == 'a' and record['target'] == path, record
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        list(pool.map(worker, range(count)))


def backend_preflight(server):
    """Test the backend directly with the same IO budget before blaming the gateway."""
    start = threading.Barrier(MAX_CONCURRENT_CLIENTS)

    def worker(index):
        start.wait(timeout=8)
        path = f'/api/echo?direct={index}'
        with socket.create_connection(('127.0.0.1', server.port), timeout=.5) as sock:
            sock.sendall(raw_request(path))
            raw = read_all(sock)
        header, body = raw.split(b'\r\n\r\n', 1)
        assert header.startswith(b'HTTP/1.1 200 OK\r\n'), header
        assert json.loads(body)['target'] == path
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CLIENTS) as pool:
            list(pool.map(worker, range(MAX_CONCURRENT_CLIENTS)))
    except Exception as exc:
        raise AssertionError('mock backend failed a direct 100-client burst (500 ms IO budget)') from exc


@contextlib.contextmanager
def saturated_listener():
    """Linux-only: a full accept queue, with no acceptor, makes connect stay pending."""
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(0)  # Linux admits one completed connection at backlog zero.
        address = listener.getsockname()
        with socket.create_connection(address, timeout=1) as filler, socket.socket() as probe:
            probe.setblocking(False)
            result = probe.connect_ex(address)
            assert result in (errno.EINPROGRESS, errno.EWOULDBLOCK), result
            _, writable, failed = select.select([], [probe], [probe], .05)
            assert not writable and not failed, 'could not establish a pending-connect fixture'
            yield address[1]


def slow_upstream_fairness(port, server):
    server.slow_started.clear()
    server.slow_release.clear()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            slow = pool.submit(exchange, port, '/api/gated-slow', 504)
            assert server.slow_started.wait(2), 'slow backend never received the request'
            assert not slow.done(), 'read timeout fired before fairness checks could start'
            # The backend has the full request, proving this is a read timeout, not connect.
            for _ in range(10):
                assert exchange(port, '/health', extra=b'Connection: close\r\n')[1] == b'ok\n'
                exchange(port, '/api/echo')
            slow.result(timeout=3)
    finally:
        server.slow_release.set()


def main():
    checks = 0
    with backend('a') as a, backend('b') as b, socket.socket() as refused:
        # Bound but not listening: reserves the refused destination without port races.
        refused.bind(('127.0.0.1', 0))
        refused_port = refused.getsockname()[1]
        backend_preflight(a)
        checks += MAX_CONCURRENT_CLIENTS
        with gateway(a, b, refused_port) as (port, proc):
            extra = (b'X-Forwarded-For: attacker\r\nX-Forwarded-Proto: https\r\n'
                     b'Forwarded: attacker\r\nX-Real-IP: attacker\r\n'
                     b'X-Secret: hidden\r\nConnection: X-Secret, keep-alive\r\n'
                     b'Proxy-Connection: keep-alive\r\nTE: trailers\r\nAccept: text/plain\r\n')
            fields, body, _ = exchange(port, '/api/echo?original=1', extra=extra)
            record = json.loads(body)
            assert record['target'] == '/api/echo?original=1'
            assert record['method'] == 'GET' and record['backend'] == 'a'
            forwarded = record['headers']
            assert forwarded['host'] == f'127.0.0.1:{a.port}'
            assert forwarded['x-forwarded-for'] == '127.0.0.1'
            assert forwarded['x-forwarded-proto'] == 'http'
            assert forwarded['content-length'] == '0' and forwarded['connection'] == 'close'
            for removed in ('x-secret', 'forwarded', 'x-real-ip', 'proxy-connection', 'te'):
                assert removed not in forwarded, forwarded
            assert forwarded['accept'] == 'text/plain'
            assert b'x-remove' not in fields and b'keep-alive' not in fields
            assert fields[b'x-end-to-end'] == b'yes'
            checks += 1
            _, body, _ = exchange(port, '/api/deep/echo')
            assert json.loads(body)['backend'] == 'b'
            checks += 1
            for path, body in [('/', b'Welcome to ZigGate!\n'), ('/health', b'ok\n'), ('/ready', b'ready\n')]:
                assert exchange(port, path, extra=b'Connection: close\r\n')[1] == body
                checks += 1
            for action, status in [('echo', 200), ('fragmented', 200), ('close', 200),
                                   ('no-content', 204), ('bad-status', 502), ('bad-length', 502),
                                   ('folded', 502), ('huge-header', 502), ('chunked', 502),
                                   ('disconnect', 502), ('timeout', 504)]:
                fields, body, _ = exchange(port, '/api/' + action, status)
                if action == 'close':
                    assert b'content-length' not in fields and body == b'close-body'
                checks += 1
            exchange(port, '/refused/fail', 502)
            exchange(port, '/api/echo', method=b'HEAD')
            exchange(port, '/api/echo', method=b'OPTIONS')
            exchange(port, '/api/echo', half_close=True)
            checks += 4
            for action in ('short', 'late-timeout'):
                fields, body, raw = exchange(port, '/api/' + action)
                assert body == b'abc' and int(fields[b'content-length']) == 20
                assert raw.count(b'HTTP/1.1 ') == 1  # No second error status after commitment.
                checks += 1
            assert exchange(port, '/api/stream', slow=True)[1] == PAYLOAD
            checks += 1
            for count in (64, 100):
                concurrent_wave(port, count)
                checks += count
            slow_upstream_fairness(port, a)
            checks += 21
            # Abandon large responses, then ensure unrelated clients still work.
            for _ in range(12):
                with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                    sock.sendall(raw_request('/api/stream'))
                    assert sock.recv(1) == b'H'  # Disconnect after upstream forwarding has begun.
            exchange(port, '/api/echo')
            # Strict client framing errors must be rejected before opening upstream sockets.
            for extra, status in [(b'Content-Length: 1\r\n', 501),
                                  (b'Transfer-Encoding: chunked\r\n', 400),
                                  (b'Content-Length: 0\r\nContent-Length: 0\r\n', 400),
                                  (b'Connection: Content-Length\r\n', 400),
                                  (b'Upgrade: websocket\r\n', 501)]:
                exchange(port, '/api/echo', status, extra=extra)
                checks += 1
            time.sleep(.6)
            fd_path = Path(f'/proc/{proc.pid}/fd')
            before = len(list(fd_path.iterdir()))
            for _ in range(30):
                exchange(port, '/refused/fail', 502)
                exchange(port, '/api/bad-length', 502)
                exchange(port, '/api/echo')
            time.sleep(.1)
            assert len(list(fd_path.iterdir())) <= before + 2, 'descriptor leak after failures'
            exchange(port, '/api/echo')
            checks += 91
        with gateway(a, b, refused_port, '--max-upstreams', '1') as (port, _):
            a.hold_started.clear()
            a.hold_release.clear()
            with socket.create_connection(('127.0.0.1', port), timeout=3) as held:
                held.sendall(raw_request('/api/hold'))
                assert a.hold_started.wait(2)
                exchange(port, '/api/echo', 503)
                exchange(port, '/health', extra=b'Connection: close\r\n')
                a.hold_release.set()
                assert b'HTTP/1.1 200 OK\r\n' in read_all(held)
            exchange(port, '/api/echo')
            checks += 4
        # Full accept queue isolates connect timeout from response/header read timeout.
        with saturated_listener() as stalled_port:
            with gateway(a, b, refused_port, '--proxy', f'/connect-timeout/=127.0.0.1:{stalled_port}',
                         '--upstream-connect-ms', '100', '--upstream-read-ms', '3000') as (port, proc):
                fd_path = Path(f'/proc/{proc.pid}/fd')
                exchange(port, '/api/echo')
                time.sleep(.05)
                before = len(list(fd_path.iterdir()))
                for _ in range(10):
                    started = time.monotonic()
                    exchange(port, '/connect-timeout/echo', 504)
                    assert time.monotonic() - started < 2, '504 did not occur before the 3-second read deadline'
                    exchange(port, '/health', extra=b'Connection: close\r\n')
                exchange(port, '/api/echo')
                time.sleep(.05)
                assert len(list(fd_path.iterdir())) <= before + 2, 'descriptor leak after connect timeouts'
                checks += 22
        # The configured response-header ceiling is independent of the client header limit.
        with gateway(a, b, refused_port, '--upstream-header-bytes', '32') as (port, _):
            exchange(port, '/api/echo', 502)
            checks += 1
    print(f'PASS: {checks} proxy checks including streaming, backpressure, failures, concurrency and limits')


if __name__ == '__main__':
    main()
