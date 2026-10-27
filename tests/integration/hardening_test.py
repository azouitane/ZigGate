#!/usr/bin/env python3
"""Event-gated shutdown and bounded logging checks, Linux/Python stdlib only."""
import json
import http.client
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time

BINARY = sys.argv[1]


def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, *args):
        self.port = unused_port()
        self.records = []
        self.events = queue.Queue()
        self.proc = subprocess.Popen([BINARY, '--port', str(self.port), *args], stderr=subprocess.PIPE)
        def collect():
            for line in self.proc.stderr:
                record = json.loads(line)
                self.records.append(record)
                self.events.put(record)
        self.reader = threading.Thread(target=collect, daemon=True)
        self.reader.start()
        self.wait('server_start')
        # Startup record precedes epoll registration; connect backlog synchronizes readiness.
        self.client = socket.create_connection(('127.0.0.1', self.port), timeout=3)

    def wait(self, event):
        deadline = time.monotonic() + 5
        while True:
            record = self.events.get(timeout=max(.001, deadline - time.monotonic()))
            if record['event'] == event:
                return record

    def finish(self):
        assert self.proc.wait(timeout=5) == 0
        self.reader.join(timeout=3)
        self.client.close()

    def cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.client.close()
        self.proc.stderr.close()


def eof(sock):
    try:
        assert sock.recv(4096) == b''
    except ConnectionResetError:
        pass


def local(sig):
    server = Server()
    try:
        server.client.sendall(b'GET /health?secret=hidden HTTP/1.1\r\nHost: x\r\nAuthorization: secret-token\r\nCookie: secret-cookie\r\n\r\n')
        server.wait('http_request')
        server.client.recv(4096)
        server.proc.send_signal(sig)
        server.wait('shutdown_begin')
        eof(server.client)
        server.finish()
        serialized = json.dumps(server.records)
        for secret in ('hidden', 'secret-token', 'secret-cookie'):
            assert secret not in serialized
        assert any(r['event'] == 'metrics' and r['data']['responses_2xx'] == 1 for r in server.records)
    finally:
        server.cleanup()


def streaming(mode):
    with socket.socket() as backend:
        backend.bind(('127.0.0.1', 0))
        backend.listen()
        ready = threading.Event()
        release = threading.Event()
        errors = []
        def serve():
            try:
                conn, _ = backend.accept()
                with conn:
                    conn.settimeout(5)
                    raw = b''
                    while b'\r\n\r\n' not in raw:
                        raw += conn.recv(4096)
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc')
                    ready.set()
                    assert release.wait(5)
                    conn.sendall(b'def')
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        server = Server('--proxy', f'/api=127.0.0.1:{backend.getsockname()[1]}', '--shutdown-ms', '300' if mode == 'deadline' else '3000')
        try:
            server.client.sendall(b'GET /api HTTP/1.1\r\nHost: x\r\n\r\n')
            assert ready.wait(5)
            response = b''
            while not response.endswith(b'abc'):
                response += server.client.recv(4096)
            server.proc.send_signal(signal.SIGTERM)
            server.wait('shutdown_begin')
            if mode == 'finish':
                release.set()
                while True:
                    chunk = server.client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert response.endswith(b'abcdef')
            elif mode == 'second':
                server.proc.send_signal(signal.SIGINT)
            server.finish()
            complete = next(r for r in server.records if r['event'] == 'shutdown_complete')
            assert complete['data']['forced'] == (mode != 'finish')
        finally:
            release.set()
            server.cleanup()
            worker.join(timeout=5)
        assert not errors, errors


def partial():
    server = Server('--log-level', 'debug')
    try:
        server.client.sendall(b'GET /health HTTP/1.1\r\n')
        server.wait('request_started')
        server.proc.send_signal(signal.SIGINT)
        server.wait('shutdown_begin')
        server.client.sendall(b'Host: x\r\n\r\n')
        response = b''
        while True:
            chunk = server.client.recv(4096)
            if not chunk:
                break
            response += chunk
        assert b'200 OK' in response and response.endswith(b'ok\n')
        assert b'Connection: close' in response
        server.finish()
    finally:
        server.cleanup()


def concurrent_shutdown():
    server = Server('--max-connections', '128')
    clients = [server.client]
    try:
        clients += [socket.create_connection(('127.0.0.1', server.port), timeout=3) for _ in range(99)]
        for client in clients:
            client.sendall(b'GET /health HTTP/1.1\r\nHost: x\r\n\r\n')
        for client in clients:
            response = b''
            while not response.endswith(b'ok\n'):
                response += client.recv(4096)
        server.proc.terminate()
        server.wait('shutdown_begin')
        for client in clients:
            eof(client)
        server.finish()
    finally:
        for client in clients:
            client.close()
        server.cleanup()


def slow_logs():
    # Intentionally never drain stderr until exit: the kernel pipe must fill.
    port = unused_port()
    proc = subprocess.Popen([BINARY, '--port', str(port)], stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            for _ in range(1000):
                conn.request('GET', '/health')
                response = conn.getresponse()
                assert response.status == 200 and response.read() == b'ok\n'
        finally:
            conn.close()
        proc.terminate()
        assert proc.wait(timeout=5) == 0
        for line in proc.stderr:
            json.loads(line)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stderr.close()


def main():
    server = Server('--request-ms', '100', '--timeout-ms', '3000', '--log-level', 'debug')
    try:
        server.client.sendall(b'GET /health HTTP/1.1\r\n')
        server.wait('request_started')
        eof(server.client)
        server.proc.terminate()
        server.finish()
    finally:
        server.cleanup()
    concurrent_shutdown()
    partial()
    slow_logs()
    for sig in (signal.SIGINT, signal.SIGTERM):
        local(sig)
    for mode in ('finish', 'deadline', 'second'):
        streaming(mode)
    for args in (['--header-bytes', '0'], ['--shutdown-ms', '0'], ['--request-ms', '0'], ['--pending-output-bytes', '999'], ['--log-level', 'bad'], ['--proxy', '/a/../b=127.0.0.1:80'], ['--bind', 'bad']):
        assert subprocess.run([BINARY, '--check-config', *args], capture_output=True).returncode == 2
    assert subprocess.run([BINARY, '--check-config', '--proxy', '/home=127.0.0.1:3000'], capture_output=True).returncode == 0
    print('PASS: signals, idle shutdown, streaming drain, deadline, second signal, JSONL redaction, metrics, configuration')


if __name__ == '__main__':
    main()
