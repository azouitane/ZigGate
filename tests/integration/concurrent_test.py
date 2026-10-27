#!/usr/bin/env python3
"""Phase 2 real TCP checks. Requires Linux /proc for descriptor accounting."""
import concurrent.futures
import contextlib
import socket
import subprocess
import sys
import time
from pathlib import Path

BINARY = sys.argv[1] if len(sys.argv) > 1 else './zig-out/bin/ziggate'
REQUEST = b'GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n'
CLOSE = b'GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'


class Client:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=3)
        self.buffer = b''

    def close(self):
        self.sock.close()

    def response(self, status=200, connection=b'keep-alive'):
        while b'\r\n\r\n' not in self.buffer:
            part = self.sock.recv(4096)
            assert part, self.buffer
            self.buffer += part
        header, self.buffer = self.buffer.split(b'\r\n\r\n', 1)
        lines = header.split(b'\r\n')
        assert lines[0].startswith(f'HTTP/1.1 {status} '.encode()), header
        fields = dict(line.split(b': ', 1) for line in lines[1:])
        assert fields[b'Connection'] == connection, header
        length = int(fields[b'Content-Length'])
        while len(self.buffer) < length:
            part = self.sock.recv(4096)
            assert part
            self.buffer += part
        body, self.buffer = self.buffer[:length], self.buffer[length:]
        if status == 200:
            assert body == b'ok\n', body
        return body

    def eof(self):
        try:
            assert self.sock.recv(1) == b''
        except ConnectionResetError:
            pass


@contextlib.contextmanager
def server(*args):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    proc = subprocess.Popen([BINARY, '--port', str(port), '--timeout-ms', '500',
                             '--idle-timeout-ms', '400', *args], stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            assert proc.poll() is None, 'server exited'
            try:
                client = Client(port)
                client.close()
                break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError('startup timeout')
        yield port, proc
        assert proc.poll() is None, 'server died'
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def check(port):
    client = Client(port)
    try:
        client.sock.sendall(CLOSE)
        client.response(connection=b'close')
        client.eof()
    finally:
        client.close()


def main():
    with server() as (port, proc):
        # All 100 sockets remain live together before any response is requested.
        clients = [Client(port) for _ in range(100)]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                def exchange(c):
                    c.sock.sendall(CLOSE)
                    c.response(connection=b'close')
                    c.eof()
                list(pool.map(exchange, clients))
        finally:
            for c in clients:
                c.close()
        c = Client(port)
        try:
            for _ in range(10):
                c.sock.sendall(REQUEST)
                c.response()
            c.sock.sendall(CLOSE)
            c.response(connection=b'close')
            c.eof()
        finally:
            c.close()
        c = Client(port)
        try:
            c.sock.sendall(REQUEST)
            c.response()
            c.eof()  # idle timeout closes without an unsolicited HTTP response
        finally:
            c.close()
        slow = Client(port)
        try:
            slow.sock.sendall(b'GET /health HTTP/1.1\r\n')
            check(port)  # a partial request must not block other clients
            time.sleep(.2)
            slow.sock.sendall(b'Host: x\r\n')
            slow.response(408, b'close')
            slow.eof()
        finally:
            slow.close()
        c = Client(port)
        try:
            for fragment in [b'GET /hea', b'lth HTTP/1.1\r', b'\nHost: x\r\n', b'\r\n']:
                c.sock.sendall(fragment)
                time.sleep(.01)
            c.response()
            c.sock.sendall(CLOSE)
            c.response(connection=b'close')
        finally:
            c.close()
        # Complete half-close still receives its response; incomplete half-close is discarded.
        for raw, complete in [(CLOSE, True), (b'GET /', False)]:
            c = Client(port)
            try:
                c.sock.sendall(raw)
                c.sock.shutdown(socket.SHUT_WR)
                if complete:
                    c.response(connection=b'close')
                c.eof()
            finally:
                c.close()
        # A malformed second request must close, never reinterpret framing as a third.
        for bad, status in [
            (b'Content-Length: 0\r\nContent-Length: 0\r\n', 400),
            (b'Transfer-Encoding: chunked\r\n', 400),
            (b'Content-Length: 1\r\n', 501),
        ]:
            c = Client(port)
            try:
                c.sock.sendall(REQUEST)
                c.response()
                c.sock.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n' + bad + b'\r\n')
                c.response(status, b'close')
                c.eof()
            finally:
                c.close()
        # Slow readers and abrupt resets must not affect other clients.
        held = [Client(port) for _ in range(20)]
        try:
            for c in held:
                c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256)
                c.sock.sendall(REQUEST)
            check(port)
            for c in held:
                c.response()
        finally:
            for c in held:
                c.close()
        time.sleep(.1)
        fd_path = Path(f'/proc/{proc.pid}/fd')
        before = len(list(fd_path.iterdir()))
        for _ in range(150):
            check(port)
        time.sleep(.1)
        assert len(list(fd_path.iterdir())) <= before + 2, 'descriptor leak'
        check(port)
    with server('--max-requests', '3') as (port, _):
        c = Client(port)
        try:
            for index in range(3):
                c.sock.sendall(REQUEST)
                c.response(connection=b'close' if index == 2 else b'keep-alive')
            c.eof()
        finally:
            c.close()
    with server('--max-connections', '2') as (port, _):
        # Synchronize acceptance with responses rather than relying on connect/backlog timing.
        time.sleep(.05)
        held = [Client(port) for _ in range(2)]
        try:
            for c in held:
                c.sock.sendall(REQUEST)
                c.response()
            extra = Client(port)
            try:
                extra.eof()
            finally:
                extra.close()
        finally:
            for c in held:
                c.close()
        time.sleep(.05)
        check(port)
    print('PASS: 100 concurrent clients, keep-alive, deadlines, limits, half-close, framing, slow readers, descriptor cleanup')


if __name__ == '__main__':
    main()
