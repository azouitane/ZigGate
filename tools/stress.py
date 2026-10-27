#!/usr/bin/env python3
"""Bounded loopback workload. Results include client/backend overhead; not a load-generator ceiling test."""
import argparse
import concurrent.futures
import http.client
import json
import os
import platform
import socket
import subprocess
import threading
import time
from pathlib import Path


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def measure(binary, count, concurrency, mode):
    backend = None
    worker = None
    backend_port = port()
    stop = threading.Event()
    if mode == 'proxy':
        backend = socket.socket()
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        backend.bind(('127.0.0.1', backend_port))
        backend.listen(256)
        backend.settimeout(.1)
        payload = b'x' * 65536
        def serve():
            while not stop.is_set():
                try:
                    conn, _ = backend.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(3)
                    request = b''
                    while b'\r\n\r\n' not in request:
                        data = conn.recv(8192)
                        if not data:
                            break
                        request += data
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n' + payload)
        worker = threading.Thread(target=serve)
        worker.start()
    server_port = port()
    command = [binary, '--port', str(server_port), '--log-level', 'error']
    if backend:
        command += ['--proxy', f'/bench=127.0.0.1:{backend_port}']
    proc = subprocess.Popen(command, stderr=subprocess.DEVNULL)
    done = threading.Event()
    peaks = {'rss_bytes': 0, 'fd_count': 0}
    def sample():
        while not done.is_set():
            try:
                status = Path(f'/proc/{proc.pid}/status').read_text()
                rss = next(int(line.split()[1]) * 1024 for line in status.splitlines() if line.startswith('VmRSS:'))
                peaks['rss_bytes'] = max(peaks['rss_bytes'], rss)
                peaks['fd_count'] = max(peaks['fd_count'], len(list(Path(f'/proc/{proc.pid}/fd').iterdir())))
            except (OSError, StopIteration):
                pass
            done.wait(.01)
    sampler = threading.Thread(target=sample)
    sampler.start()
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', server_port), timeout=1):
                    break
            except OSError:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('server startup failed')
                time.sleep(.01)
        barrier = threading.Barrier(concurrency)
        def client(index):
            latencies = []
            transferred = 0
            connection = http.client.HTTPConnection('127.0.0.1', server_port, timeout=5)
            barrier.wait(timeout=10)
            try:
                for _ in range(index, count, concurrency):
                    started = time.perf_counter()
                    connection.request('GET', '/bench' if backend else '/health')
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == 200
                    assert len(body) == (65536 if backend else 3)
                    transferred += len(body)
                    latencies.append((time.perf_counter() - started) * 1000)
            finally:
                connection.close()
            return latencies, transferred
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(client, range(concurrency)))
        elapsed = time.perf_counter() - started
        values = sorted(v for latencies, _ in results for v in latencies)
        def percentile(q):
            return round(values[min(len(values)-1, int((len(values)-1)*q))], 3)
        return dict(mode=mode, requests=count, concurrency=concurrency, elapsed_s=round(elapsed, 3), requests_per_second=round(count/elapsed, 1), latency_ms=dict(p50=percentile(.5), p95=percentile(.95), p99=percentile(.99)), body_mib_per_second=round(sum(size for _, size in results)/elapsed/1048576, 2), sampled_peaks=peaks)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        done.set()
        sampler.join()
        stop.set()
        if worker:
            worker.join(timeout=5)
            backend.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('--requests', type=int, default=2000)
    parser.add_argument('--concurrency', type=int, default=16)
    parser.add_argument('--build-mode', default='unspecified')
    args = parser.parse_args()
    if not 1 <= args.concurrency <= min(args.requests, 256) or not 1 <= args.requests <= 1000000:
        parser.error('requests must be 1..1000000; concurrency 1..min(requests,256)')
    cpu = next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), platform.machine())
    print(json.dumps(dict(hardware=dict(cpu=cpu, logical_cpus=os.cpu_count(), platform=platform.platform()), build_mode=args.build_mode, workload='loopback HTTP/1.1; local keep-alive; proxy closes; one sequential Python backend; logging error level; sampled /proc every 10ms', results=[measure(args.binary, args.requests, args.concurrency, mode) for mode in ('local', 'proxy')]), indent=2))


if __name__ == '__main__':
    main()
