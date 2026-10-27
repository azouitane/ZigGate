#!/usr/bin/env python3
"""Phase 5A admission/reload regressions. No long-running soak in integration."""
import os
from pathlib import Path
import signal
import socket
import ssl
import sys
import tempfile
import threading
import tls_test as f
import concurrent_test as http_fixture


def replace(path, data):
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_bytes(data)
    os.replace(temporary, path)


def rotate(paths, name, directory):
    cert, key = directory / (name + '.rotated.crt'), directory / (name + '.rotated.key')
    f.openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=' + name, '-addext', 'subjectAltName=DNS:' + name, '-keyout', key, '-out', cert)
    replace(paths[name][0], cert.read_bytes())
    replace(paths[name][1], key.read_bytes())
    return ssl.PEM_cert_to_DER_cert(cert.read_text())


def reload(gateway, retry_rate_limit=True):
    for _ in range(4):
        count = sum(r['event'] in ('tls_reload_success', 'tls_reload_failed') for r in gateway.records)
        gateway.proc.send_signal(signal.SIGHUP)
        with gateway.condition:
            assert gateway.condition.wait_for(lambda: sum(r['event'] in ('tls_reload_success', 'tls_reload_failed') for r in gateway.records) > count or gateway.errors, timeout=5)
            assert not gateway.errors, gateway.errors
            result = next(r for r in reversed(gateway.records) if r['event'] in ('tls_reload_success', 'tls_reload_failed'))
        if result['data'].get('reason') != 'rate_limited' or not retry_rate_limit:
            return result
        # Wait exactly the server-advertised cooldown, not an assumed startup/IO delay.
        threading.Event().wait((result['data']['retry_after_ms'] + 2) / 1000)
    raise AssertionError('reload never left rate limit')


def selected_client(gateway, hostname='default.test'):
    # Invalid on-disk files must not be loaded into the test client's trust store.
    # Call sites compare the peer DER against the exact expected certificate.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=5), server_hostname=hostname)


def exchange(client, close=False):
    client.sendall(f.CLOSE if close else f.REQUEST)
    assert f.Wire(client).response()[1] == b'ok\n'
    if close:
        f.eof(client)


def admission(paths):
    with f.server(paths, '--max-tls-handshakes', '2', '--max-connections', '16', '--tls-handshake-timeout-ms', '300') as gateway:
        for wave in range(3):
            held = [socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) for _ in range(2)]
            try:
                gateway.wait('tls_accepted', 2 * (wave + 1) + wave)
                # Shared global capacity is still available: only TLS handshakes reject.
                with socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3) as excess:
                    f.eof(excess)
                gateway.wait('tls_handshake_rejected', wave + 1)
                with socket.create_connection(('127.0.0.1', gateway.port), timeout=3) as plain:
                    plain.sendall(f.CLOSE)
                    assert f.Wire(plain).response()[1] == b'ok\n'
                for client in held:
                    client.sendall(b'\x16\x03\x03\x40\x00\x01')
                for client in held:
                    f.eof(client)
                gateway.wait('tls_handshake_failed', (wave + 1) * 2)
            finally:
                for client in held:
                    client.close()
            with gateway.client(paths) as client:
                exchange(client, True)
        gateway.stop()
        metrics = [r['data'] for r in gateway.records if r['event'] == 'metrics'][-1]
        assert metrics['active_tls_handshakes'] == 0
        assert metrics['tls_handshake_rejections'] >= 3 and metrics['tls_handshake_timeouts'] >= 6
    # Permits are released on success even though established connections stay live.
    with f.server(paths, '--max-tls-handshakes', '1') as gateway:
        clients = []
        try:
            for _ in range(12):
                client = gateway.client(paths)
                clients.append(client)
                exchange(client)
            assert len(clients) == 12
        finally:
            for client in clients:
                client.close()
        gateway.stop()


def rotation(paths, directory):
    originals = {name: (paths[name][0].read_bytes(), paths[name][1].read_bytes()) for name in ('default.test', 'alternate.test')}
    alternate_cert, alternate_key = paths['alternate.test']
    try:
        with f.server(paths, '--tls-sni', f'alternate.test={alternate_cert},{alternate_key}', '--idle-timeout-ms', '60000') as gateway:
            # An unfinished handshake must retain the old SNI callback registry too.
            pending = socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=5)
            gateway.wait('tls_accepted')
            active = gateway.client(paths)
            exchange(active)
            old_der = active.getpeercert(binary_form=True)
            new_default = rotate(paths, 'default.test', directory)
            new_alternate = rotate(paths, 'alternate.test', directory)
            assert reload(gateway)['event'] == 'tls_reload_success'
            exchange(active)
            assert active.getpeercert(binary_form=True) == old_der
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(pending, server_hostname='alternate.test') as old_sni:
                assert old_sni.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(originals['alternate.test'][0].decode())
                exchange(old_sni, True)
            # A second rotation is bounded while the first retired generation is retained.
            outcome = reload(gateway)
            assert outcome['event'] == 'tls_reload_failed' and outcome['data']['reason'] == 'TlsReloadBusy', outcome
            for hostname, expected in (('default.test', new_default), ('alternate.test', new_alternate)):
                with selected_client(gateway, hostname) as new:
                    assert new.getpeercert(binary_form=True) == expected
                    exchange(new, True)
            exchange(active, True)
            active.close()
            assert reload(gateway)['event'] == 'tls_reload_success'
            # Failed candidates never replace either active default or SNI certificates.
            cert, key = paths['default.test']
            good_cert, good_key = cert.read_bytes(), key.read_bytes()
            failures = [lambda: replace(cert, b'invalid certificate\n'), lambda: replace(cert, good_cert + alternate_cert.read_bytes()), lambda: replace(key, alternate_key.read_bytes()), lambda: key.unlink(), lambda: replace(alternate_cert, b'invalid SNI certificate\n')]
            for mutate in failures:
                mutate()
                assert reload(gateway)['event'] == 'tls_reload_failed'
                with selected_client(gateway) as client:
                    assert client.getpeercert(binary_form=True) == new_default
                    exchange(client, True)
                replace(cert, good_cert)
                replace(key, good_key)
                # Restore SNI too after the final failure.
                if not alternate_cert.read_bytes().startswith(b'-----BEGIN'):
                    replace(alternate_cert, (directory / 'alternate.test.rotated.crt').read_bytes())
            # FIFO and oversize inputs are rejected without blocking the event loop.
            key.unlink()
            os.mkfifo(key)
            assert reload(gateway)['event'] == 'tls_reload_failed'
            key.unlink()
            replace(key, good_key)
            replace(cert, b'x' * (1024 * 1024 + 1))
            assert reload(gateway)['event'] == 'tls_reload_failed'
            replace(cert, good_cert)
            for _ in range(3):
                assert reload(gateway)['event'] == 'tls_reload_success'
            gateway.stop()
            metrics = [r['data'] for r in gateway.records if r['event'] == 'metrics'][-1]
            assert metrics['tls_reload_successes'] >= 5 and metrics['tls_reload_failures'] >= 7
            assert metrics['active_tls_handshakes'] == metrics['active_tls'] == 0
            assert 'PRIVATE KEY' not in str(gateway.records)
    finally:
        for name, (cert, key) in originals.items():
            for path, data in zip(paths[name], (cert, key)):
                if path.exists() and not path.is_file():
                    path.unlink()
                replace(path, data)


def streaming_reload(paths):
    backend = f.Backend(1024 * 1024)
    try:
        with f.server(paths, '--proxy', f'/api=127.0.0.1:{backend.port}') as gateway:
            with gateway.client(paths) as client:
                client.sendall(b'GET /api/stream HTTP/1.1\r\nHost: x\r\n\r\n')
                assert backend.ready.wait(5)
                wire = f.Wire(client)
                while not wire.buffer.endswith(b'zzz'):
                    wire.buffer += client.recv(65536)
                assert reload(gateway)['event'] == 'tls_reload_success'
                backend.release.set()
                assert wire.response()[1] == backend.payload
                f.eof(client)
            gateway.stop()
    finally:
        backend.close()
    # HUP during drain is ignored.
    with f.server(paths, '--max-tls-handshakes', '1') as gateway:
        raw = socket.create_connection(('127.0.0.1', gateway.tls_port), timeout=3)
        try:
            gateway.wait('tls_accepted')
            gateway.proc.send_signal(signal.SIGTERM)
            gateway.wait('shutdown_begin')
            gateway.proc.send_signal(signal.SIGHUP)
            f.eof(raw)
            gateway.stop()
        finally:
            raw.close()


def main():
    with http_fixture.server() as (port, proc):
        proc.send_signal(signal.SIGHUP)
        http_fixture.check(port)
    with tempfile.TemporaryDirectory(prefix='ziggate-reliability-') as temporary:
        directory = Path(temporary)
        paths = f.certificates(directory)
        admission(paths)
        rotation(paths, directory)
        streaming_reload(paths)
    print('PASS: handshake admission/reuse, timeout alias, old sessions and pending SNI across reload, bounded generations, invalid/mismatched/missing/SNI/FIFO/oversize reload recovery, streaming reload, shutdown accounting')


if __name__ == '__main__':
    main()
