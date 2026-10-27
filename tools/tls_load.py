#!/usr/bin/env python3
"""Bounded local TLS load/soak driver; shared-host observations, not capacity claims."""
import argparse
import collections
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import platform
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/integration'))
import tls_test as fixture


def resource(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    rss = next(int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith('VmRSS:'))
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return dict(rss_bytes=rss, fds=len(list(Path(f'/proc/{pid}/fd').iterdir())), cpu_seconds=(int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'))


class Gateway:
    def __init__(self, binary, paths, concurrency, backend=None, extra=(), samples=None):
        self.port, self.tls_port = fixture.port(), fixture.port()
        self.records = collections.deque(maxlen=128)
        self.counts = collections.Counter()
        self.condition = threading.Condition()
        self.metrics = {}
        self.metrics_sequence = 0
        self.samples = collections.deque(maxlen=10000)
        self.peaks = dict(rss_bytes=0, fds=0, cpu_percent_one_core=0)
        self.errors = []
        self.done = threading.Event()
        self.started = time.monotonic()
        cert, key = paths['default.test']
        command = [binary, '--port', str(self.port), '--tls-listen', f'127.0.0.1:{self.tls_port}', '--tls-cert', str(cert), '--tls-key', str(key), '--max-connections', '1024', '--max-tls-handshakes', str(max(128, concurrency)), '--tls-handshake-ms', '5000', '--idle-timeout-ms', '60000', '--log-level', 'info']
        if backend:
            command += ['--proxy', f'/bench=127.0.0.1:{backend}', '--max-upstreams', str(max(128, concurrency))]
        command += list(extra)
        self.proc = subprocess.Popen(command, stderr=subprocess.PIPE)
        def collect():
            for line in self.proc.stderr:
                with self.condition:
                    try:
                        record = json.loads(line)
                        self.records.append(record)
                        self.counts[record['event']] += 1
                        if record['event'] == 'metrics':
                            self.metrics = record['data']
                            self.metrics_sequence += 1
                    except Exception:
                        self.errors.append('non-JSON server diagnostic')
                    self.condition.notify_all()
        self.reader = threading.Thread(target=collect, daemon=True)
        self.reader.start()
        self.wait('server_start')
        self.initial = resource(self.proc.pid)
        def sample():
            previous, previous_time = self.initial, self.started
            while not self.done.is_set():
                try:
                    point = resource(self.proc.pid)
                    now = time.monotonic()
                    point['elapsed_s'] = round(now - self.started, 3)
                    point['cpu_percent_one_core'] = round(100 * (point['cpu_seconds'] - previous['cpu_seconds']) / max(.001, now - previous_time), 2)
                    for field in self.peaks:
                        self.peaks[field] = max(self.peaks[field], point[field])
                    self.samples.append(point)
                    if samples:
                        samples.write(json.dumps(dict(pid=self.proc.pid, **point)) + '\n')
                        samples.flush()
                    previous, previous_time = point, now
                except (OSError, StopIteration, ValueError):
                    pass
                self.done.wait(.1)
        self.sampler = threading.Thread(target=sample, daemon=True)
        self.sampler.start()

    def wait(self, event, count=1):
        with self.condition:
            assert self.condition.wait_for(lambda: self.counts[event] >= count or self.errors, timeout=12), (event, dict(self.counts))
            assert not self.errors, self.errors

    def reload(self):
        before = self.counts['tls_reload_success']
        self.proc.send_signal(signal.SIGHUP)
        self.wait('tls_reload_success', before + 1)

    def drain(self):
        with self.condition:
            sequence = self.metrics_sequence
            assert self.condition.wait_for(lambda: self.metrics_sequence > sequence and self.metrics.get('active_clients') == 0 and self.metrics.get('active_tls_handshakes') == 0, timeout=12), self.metrics
        return resource(self.proc.pid)

    def stop(self, already_draining=False):
        if self.proc.poll() is None and not already_draining:
            self.proc.terminate()
        assert self.proc.wait(timeout=8) == 0
        self.reader.join(timeout=3)
        self.done.set()
        self.sampler.join(timeout=3)
        self.proc.stderr.close()
        assert not self.errors, self.errors
        elapsed = time.monotonic() - self.started
        cpu_seconds = self.samples[-1]['cpu_seconds'] - self.initial['cpu_seconds'] if self.samples else 0
        return dict(metrics=self.metrics, sampled_peaks=self.peaks, server_cpu_seconds=round(cpu_seconds, 3), average_cpu_percent_one_core=round(100 * cpu_seconds / elapsed, 2), sample_window_elapsed_s=round(elapsed, 3), sample_count=len(self.samples))

    def cleanup(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.done.set()
        self.reader.join(timeout=3)
        self.sampler.join(timeout=3)
        self.proc.stderr.close()


class Backend(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        data = b''
        while b'\r\n\r\n' not in data:
            part = self.request.recv(8192)
            if not part or len(data) > 8192:
                return
            data += part
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n' + b'z' * 65536)


@contextlib.contextmanager
def backend():
    instance = Backend(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=instance.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
    thread.start()
    try:
        yield instance.server_address[1]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=3)


class LocalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        self.sock = self._context.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=self.timeout), server_hostname='default.test')


def client_context(paths, version):
    context = ssl.create_default_context(cafile=str(paths['default.test'][0]))
    context.minimum_version = context.maximum_version = getattr(ssl.TLSVersion, 'TLSv1_' + version[-1])
    context.set_alpn_protocols(['http/1.1'])
    return context


def wave(gateway, context, concurrency, per_client, mode, reload_active=False):
    barrier = threading.Barrier(concurrency)
    condition = threading.Condition()
    ready = 0
    resume = threading.Event()
    def client(_):
        nonlocal ready
        connection = LocalHTTPS('default.test', gateway.tls_port, context=context, timeout=10)
        latencies, failures = [], []
        transferred = 0
        try:
            barrier.wait(timeout=15)
            for index in range(per_client):
                start = time.perf_counter()
                connection.request('GET', '/bench' if mode == 'proxy' else '/health')
                response = connection.getresponse()
                body = response.read()
                assert response.status == 200 and len(body) == (65536 if mode == 'proxy' else 3)
                latencies.append((time.perf_counter() - start) * 1000)
                transferred += len(body)
                if index == 0 and reload_active:
                    with condition:
                        ready += 1
                        condition.notify_all()
                    assert resume.wait(15)
        except Exception as exc:
            failures.append(type(exc).__name__)
            with condition:
                condition.notify_all()
        finally:
            if mode == 'local' and connection.sock is not None:
                try:
                    connection.sock.unwrap().close()
                    connection.sock = None
                except (OSError, ssl.SSLError) as exc:
                    failures.append(type(exc).__name__ + 'DuringClose')
            connection.close()
        return latencies, transferred, failures
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(client, index) for index in range(concurrency)]
        if reload_active:
            try:
                with condition:
                    assert condition.wait_for(lambda: ready == concurrency or any(f.done() for f in futures), timeout=15), 'clients did not reach reload gate'
                    assert ready == concurrency
                gateway.reload()
            finally:
                resume.set()
        results = [future.result(timeout=30) for future in futures]
    elapsed = time.perf_counter() - started
    values = sorted(value for latencies, _, _ in results for value in latencies)
    failures = [failure for _, _, group in results for failure in group]
    def percentile(q):
        return round(values[int((len(values) - 1) * q)], 3) if values else None
    return dict(successful_requests=len(values), failed_clients=len(failures), failure_types=dict(collections.Counter(failures)), elapsed_s=round(elapsed, 4), requests_per_second=round(len(values) / elapsed, 1), latency_ms=dict(p50=percentile(.5), p95=percentile(.95), p99=percentile(.99)), payload_mib_per_second=round(sum(size for _, size, _ in results) / elapsed / 1048576, 2))


def measure(args, paths, concurrency, version, mode, backend_port, samples):
    gateway = Gateway(args.binary, paths, concurrency, backend_port if mode == 'proxy' else None, samples=samples)
    try:
        result = wave(gateway, client_context(paths, version), concurrency, args.per_client, mode, args.reload_active and mode == 'local')
        drained = gateway.drain()
        operational = gateway.stop()
        assert result['failed_clients'] == 0, result
        assert operational['metrics']['responses_2xx'] == operational['metrics']['requests'] == result['successful_requests'], operational
        return dict(version=version, mode=mode, concurrency=concurrency, per_client=args.per_client, reload_active=args.reload_active and mode == 'local', drained_resources=drained, **result, **operational)
    finally:
        gateway.cleanup()


def resilience(args, paths, samples):
    gateway = Gateway(args.binary, paths, 64, extra=('--max-tls-handshakes', '8', '--tls-handshake-ms', '500', '--log-level', 'debug'), samples=samples)
    clients = []
    raw = []
    try:
        context = client_context(paths, '1.3')
        # Established clients do not consume handshake permits.
        for _ in range(64):
            connection = LocalHTTPS('default.test', gateway.tls_port, context=context, timeout=5)
            connection.request('GET', '/health')
            assert connection.getresponse().read() == b'ok\n'
            clients.append(connection)
        for _ in range(8):
            held = socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=5)
            held.sendall(b'\x16\x03\x03\x40\x00\x01')
            raw.append(held)
        gateway.wait('tls_accepted', 72)
        rejected = 0
        for _ in range(16):
            with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=5) as excess:
                fixture.eof(excess)
                rejected += 1
        for held in raw:
            fixture.eof(held)
        gateway.wait('tls_handshake_failed', 8)
        for connection in clients[:32]:
            os.close(connection.sock.detach())
            connection.sock = None
        gateway.reload()
        for connection in clients[32:]:
            connection.request('GET', '/health')
            assert connection.getresponse().read() == b'ok\n'
        gateway.proc.terminate()
        gateway.wait('shutdown_begin')
        for connection in clients[32:]:
            fixture.eof(connection.sock)
        result = gateway.stop(already_draining=True)
        assert result['metrics']['active_tls_handshakes'] == result['metrics']['active_clients'] == 0
        assert result['metrics']['tls_handshake_rejections'] >= rejected
        return dict(profile='slow/incomplete handshakes, saturation, 32 abrupt disconnects, reload with 32 live sessions, graceful shutdown of established TLS clients', **result)
    finally:
        for connection in clients:
            connection.close()
        for held in raw:
            held.close()
        gateway.cleanup()


def growth(points):
    stable = list(points)[3:]  # exclude initial cache/provider warmup
    result = {'post_warmup_points': len(stable), 'fd_growth_suspicious': False, 'rss_growth_suspicious': False, 'interpretation': 'RSS can retain allocator/provider caches; trends require investigation, not a leak verdict'}
    if len(stable) >= 8:
        for field, threshold, key in (('fds', 2, 'fd_growth_suspicious'), ('rss_bytes', 8 * 1048576, 'rss_growth_suspicious')):
            values = [point[field] for point in stable]
            result[key] = all(b >= a for a, b in zip(values, values[1:])) and values[-1] - values[0] > threshold
            result[field + '_first_last'] = [values[0], values[-1]]
    return result


def soak(args, paths, backend_port, samples):
    concurrency = args.concurrency[0]
    gateway = Gateway(args.binary, paths, concurrency, backend_port if args.soak_mode == 'proxy' else None, samples=samples)
    points = collections.deque(maxlen=1024)
    started = time.monotonic()
    requests = 0
    rounds = 0
    try:
        context = client_context(paths, args.versions[0])
        while time.monotonic() - started < args.soak_seconds:
            result = wave(gateway, context, concurrency, args.per_client, args.soak_mode)
            assert result['failed_clients'] == 0, result
            requests += result['successful_requests']
            point = gateway.drain()
            point['elapsed_s'] = round(time.monotonic() - started, 3)
            points.append(point)
            rounds += 1
            if rounds % 5 == 0:
                gateway.reload()
        operational = gateway.stop()
        assert operational['metrics']['responses_2xx'] == operational['metrics']['requests'] == requests, operational
        return dict(mode=args.soak_mode, version=args.versions[0], requested_duration_s=args.soak_seconds, actual_duration_s=round(time.monotonic() - started, 3), concurrency=concurrency, rounds=rounds, successful_requests=requests, drained_points=list(points), growth=growth(points), **operational)
    finally:
        gateway.cleanup()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('--build-mode', default='unspecified')
    parser.add_argument('--concurrency', type=int, nargs='+', default=[16, 64, 128, 256])
    parser.add_argument('--versions', nargs='+', choices=['1.2', '1.3'], default=['1.2', '1.3'])
    parser.add_argument('--per-client', type=int, default=4)
    parser.add_argument('--reload-active', action='store_true')
    parser.add_argument('--resilience', action='store_true')
    parser.add_argument('--soak-seconds', type=int, default=0)
    parser.add_argument('--soak-mode', choices=['local', 'proxy'], default='local')
    parser.add_argument('--samples', help='Optional JSONL resource sample file (100 ms interval)')
    args = parser.parse_args()
    if not all(1 <= value <= 512 for value in args.concurrency) or not 1 <= args.per_client <= 1000 or not 0 <= args.soak_seconds <= 86400:
        parser.error('concurrency 1..512, per-client 1..1000, soak-seconds 0..86400')
    cpu = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), platform.machine())
    with tempfile.TemporaryDirectory(prefix='ziggate-tls-load-') as temporary, contextlib.ExitStack() as stack:
        paths = fixture.certificates(Path(temporary))
        samples = stack.enter_context(open(args.samples, 'w')) if args.samples else None
        backend_port = stack.enter_context(backend())
        output = dict(environment=dict(cpu=cpu, logical_cpus=os.cpu_count(), platform=platform.platform(), python=platform.python_version(), openssl=ssl.OPENSSL_VERSION, build_mode=args.build_mode), workload='loopback; 3-byte local keep-alive or 64KiB proxied responses closing each time; Python threads and threaded HTTP backend share host; default info logging; 100ms /proc sampling; no CPU pinning', measurements=[])
        if args.soak_seconds:
            output['soak'] = soak(args, paths, backend_port, samples)
        else:
            for version in args.versions:
                for concurrency in args.concurrency:
                    for mode in ('local', 'proxy'):
                        output['measurements'].append(measure(args, paths, concurrency, version, mode, backend_port, samples))
            if args.resilience:
                output['resilience'] = resilience(args, paths, samples)
        print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
