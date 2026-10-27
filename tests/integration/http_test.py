#!/usr/bin/env python3
"""Real TCP tests; no third-party dependencies. Accepts a server binary path."""
import socket
import subprocess
import sys
import time


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else './zig-out/bin/ziggate'
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([binary, '--port', str(port), '--timeout-ms', '200'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    count = 0

    def connect():
        return socket.create_connection(('127.0.0.1', port), timeout=3)

    def receive(sock, status, body=None, head=False):
        nonlocal count
        data = bytearray()
        while True:
            try:
                part = sock.recv(4096)
            except ConnectionResetError:
                # Linux can reset on close if rejected input remains unread.
                break
            if not part:
                break
            data.extend(part)
        headers, payload = bytes(data).split(b'\r\n\r\n', 1)
        lines = headers.split(b'\r\n')
        assert lines[0].startswith(f'HTTP/1.1 {status} '.encode()), data
        fields = dict(line.split(b': ', 1) for line in lines[1:])
        assert fields[b'Connection'] == b'close', data
        assert len(payload) == (0 if head else int(fields[b'Content-Length'])), data
        if body is not None:
            assert payload == body, data
        count += 1

    def request(raw, status, body=None, head=False, *, add_close=True):
        with connect() as sock:
            # Preserve Phase 1 close-on-response checks explicitly.
            if add_close:
                raw = raw.replace(b'\r\n', b'\r\nConnection: close\r\n', 1)
            sock.sendall(raw)
            receive(sock, status, body, head)

    try:
        for _ in range(100):
            if server.poll() is not None:
                raise AssertionError('server exited during startup')
            try:
                with connect():
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise AssertionError('server did not start')
        for path, body in [('/', b'Welcome to ZigGate!\n'), ('/health', b'ok\n'),
                           ('/ready', b'ready\n'), ('/health?check=1', b'ok\n')]:
            request(f'GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode(), 200, body)
        cases = [
            (b'GET /missing HTTP/1.1\r\nHost: x\r\n\r\n', 404),
            (b'POST / HTTP/1.1\r\nHost: x\r\n\r\n', 405),
            (b'G@T / HTTP/1.1\r\nHost: x\r\n\r\n', 400),
            (b'BREW / HTTP/1.1\r\nHost: x\r\n\r\n', 501),
            (b'GET  / HTTP/1.1\r\nHost: x\r\n\r\n', 400),
            (b'GET / HTTP/1.0\r\nHost: x\r\n\r\n', 505),
            (b'GET / HTTP/2.0\r\nHost: x\r\n\r\n', 505),
            (b'GET / HTTP/1.1\r\n\r\n', 400),
            (b'GET / HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n', 400),
            (b'GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n', 400),
            (b'GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n', 400),
            (b'GET / HTTP/1.1\r\nHost: x\r\n folded: x\r\n\r\n', 400),
            (b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1048577\r\n\r\n', 413),
            (b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n', 501),
            (b'POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n', 417),
            (b'GET / HTTP/1.1\r\nHost: x\r\nX: ' + b'a' * 8200 + b'\r\n\r\n', 431),
        ]
        for raw, status in cases:
            request(raw, status)
        request(b'HEAD / HTTP/1.1\r\nHost: x\r\n\r\n', 405, head=True)
        # Count every byte on the wire, including Connection: close and CRLFCRLF.
        prefix = b'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX: '
        for size, status in [(8191, 200), (8192, 200), (8193, 431)]:
            raw = prefix + b'a' * (size - len(prefix) - 4) + b'\r\n\r\n'
            assert len(raw) == size
            request(raw, status, add_close=False)
            # Split inside the terminator. At 8192, the final byte fills the buffer.
            split = min(size - 1, 8191)
            with connect() as sock:
                sock.sendall(raw[:split])
                time.sleep(.01)
                sock.sendall(raw[split:])
                receive(sock, status)
        with connect() as sock:
            sock.sendall(b'GET / HTTP/1.1\r\n')
            receive(sock, 408)
        with connect() as sock:
            # Progress must not reset the absolute read deadline.
            start = time.monotonic()
            sock.sendall(b'GET / HTTP/1.1\r\n')
            time.sleep(.12)
            sock.sendall(b'Host: x\r\n')
            receive(sock, 408)
            assert time.monotonic() - start < .31
        with connect() as sock:
            sock.sendall(b'GET / HTTP/1.1\r\n')
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(1) == b''
        # Two requests produce only one response, with Connection: close.
        raw = b'GET /health HTTP/1.1\r\nHost: x\r\n\r\n'
        request(raw + raw, 200, b'ok\n')
        with connect() as sock:
            for fragment in [b'GET /health HTTP/1.1\r', b'\nHost: x\r\nConnection: close\r\n', b'\r\n']:
                sock.sendall(fragment)
                time.sleep(.01)
            receive(sock, 200, b'ok\n')
        request(raw, 200, b'ok\n')
        print(f'PASS: {count} HTTP response checks, early disconnect, and server survival')
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == '__main__':
    main()
