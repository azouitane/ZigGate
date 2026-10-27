# TLS reliability, admission and certificate reload

ZigGate terminates inbound HTTPS with OpenSSL **3.x**, then uses the same strict HTTP/1.1 parser, router, limits and plaintext HTTP upstream transport as the HTTP listener. HTTPS is opt-in. The executable links OpenSSL and libc even in HTTP-only deployments. No TLS or cryptography is implemented by ZigGate itself.

## Dependencies and build

On Fedora:

```sh
sudo dnf install openssl openssl-devel pkgconf-pkg-config python3
zig version  # must be 0.15.2
zig build
zig build test
zig build integration
zig build -Doptimize=ReleaseSafe
```

`build.zig` links libc, libssl and libcrypto, compiles the small `src/tls/openssl_shim.c` wrapper, and imports its declarations through Zig's C interoperability. The wrapper centralizes policy and OpenSSL macros; deprecated OpenSSL APIs are hidden with `OPENSSL_API_COMPAT=30000` and `OPENSSL_NO_DEPRECATED`. C code builds with Wall/Wextra/Werror. `src/http` remains independent of OpenSSL. Fedora Linux 44 with OpenSSL 3.5.9 was used for native validation.

For a nonstandard Fedora-style development prefix containing `include/openssl` and `lib64/libssl.so` / `lib64/libcrypto.so`:

```sh
zig build -Dopenssl-prefix=/path/to/openssl-prefix
zig build integration -Dopenssl-prefix=/path/to/openssl-prefix
```

This option supplies compile/link search paths, not a runtime rpath or a bundled TLS distribution. Ensure compatible runtime libraries and their dependencies are installed on the deployment host. Development headers and linker files are required; runtime-only `libssl.so.3` files are insufficient for a normal build. Other Linux distributions can use standard system development packages without the prefix option.

Cross-compilation requires headers, configuration files, libraries and transitive dependencies **for the target architecture and ABI**, with a compatible libc/sysroot/toolchain. The Fedora 44 packages used here require glibc 2.38 or later; the plain `aarch64-linux-gnu` baseline fails on their versioned symbols. Native x86_64 OpenSSL headers/libraries cannot be reused for aarch64. For example, with a complete target prefix:

```sh
zig build -Dtarget=aarch64-linux-gnu.2.38 -Doptimize=ReleaseSafe \
  -Dopenssl-prefix=/path/to/aarch64/usr
```

A build is successful only when the complete TLS-enabled executable links. This does not prove runtime compatibility, provider availability or certificate validation on the target. See [validation](phase4b-validation.md) for this environment's actual outcome. Cross-build installation replaces `zig-out/bin/ziggate`; rebuild natively before running it on x86_64.

## Development certificates

Use this only for local testing; deploy certificates issued for your real names in production. Do not commit private keys.

```sh
mkdir -p certs
chmod 700 certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -days 2 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout certs/server.key -out certs/server.crt
chmod 600 certs/server.key
```

`-nodes` creates an unencrypted PEM key, allowing unattended startup. Protect it with filesystem permissions and deployment controls. ZigGate disables password prompting and rejects encrypted keys; it has no passphrase CLI, environment variable or secret logging facility.

## Listeners and validation

HTTP retains `--bind` / `--port` and is always enabled. HTTPS adds an independent numeric IPv4 bind address and shares the global client capacity with HTTP:

```sh
./zig-out/bin/ziggate --bind 127.0.0.1 --port 8080 \
  --tls-listen 127.0.0.1:8443 \
  --tls-cert ./certs/server.crt --tls-key ./certs/server.key \
  --proxy /home=127.0.0.1:3000

curl --cacert ./certs/server.crt https://localhost:8443/health
curl http://127.0.0.1:8080/health
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `--tls-listen IPv4:port` | absent | Opt-in HTTPS listener, explicit numeric IPv4 and port 1–65535 |
| `--tls-cert PEM` | absent | Default leaf certificate followed by intermediate certificates |
| `--tls-key PEM` | absent | Matching unencrypted private key |
| `--tls-handshake-ms N` | 5000 | Absolute handshake deadline, 1–60000 ms; `--tls-handshake-timeout-ms` is an alias |
| `--max-tls-handshakes N` | 128 | Maximum simultaneous unfinished handshakes, 1–32768; also bounded by global client capacity |
| `--tls-sni hostname=cert,key` | absent | Repeat for at most eight additional exact DNS names |

Listener, certificate and key must be supplied together. Incomplete configurations, zero/invalid ports, overlapping HTTP/HTTPS bind endpoints, invalid PEM, missing/unreadable files, key mismatches and invalid SNI maps fail startup. All contexts load before either listener is opened. No TLS failure activates plaintext on the HTTPS port. Port 8443 avoids privileged bind requirements.

`--check-config` loads and validates every configured chain/key, including SNI entries, without opening listeners:

```sh
./zig-out/bin/ziggate --check-config \
  --tls-listen 127.0.0.1:8443 \
  --tls-cert ./certs/server.crt --tls-key ./certs/server.key
```

Errors identify certificate loading, key loading/matching, policy or configuration failure without dumping OpenSSL's raw error queue or key contents. This validation checks bounded PEM loading, adjacent issuer/signature consistency in supplied chains and key correspondence, not CA trust, hostname coverage, expiration, revocation, coordinated file rotation or future port availability. Only regular files are accepted: certificate chains are at most 1 MiB and 16 certificates, and keys at most 64 KiB. Extra non-PEM chain data and multiple key blocks are rejected. Clients remain responsible for normal certificate verification. Order a chain leaf first, then its intermediates; normally omit the root.

## SNI and protocol policy

```sh
./zig-out/bin/ziggate --tls-listen 127.0.0.1:8443 \
  --tls-cert certs/default-chain.pem --tls-key certs/default.key \
  --tls-sni example.test=certs/example-chain.pem,certs/example.key \
  --tls-sni api.example.test=certs/api-chain.pem,certs/api.key
```

The default certificate serves clients without SNI and unknown valid names. Additional names use case-insensitive exact matching. Names are ASCII DNS labels, maximum 253 bytes total and 63 per label, with alphanumeric/hyphen characters; leading/trailing hyphens, empty labels, trailing dots, wildcard syntax and Unicode are rejected. Use explicit ASCII A-labels for internationalized domains. Duplicate names differing only in case are rejected. Commas delimit file paths in `--tls-sni` and cannot appear inside those paths. Malformed client SNI aborts the handshake. SNI selects certificates only: it does not select routes or authorize an HTTP Host header.

The supported protocol range is TLS 1.2–1.3. Earlier versions are disabled by the minimum version. OpenSSL's cipher/provider/security defaults remain in effect; no insecure ciphers are enabled. TLS compression and renegotiation are disabled. Only HTTP/1.1 is negotiated through ALPN; an ALPN offer containing no supported protocol fails, while clients omitting ALPN may use HTTP/1.1. No HTTP/2 is advertised or served.

Early data is disabled. Session tickets and session caching are also disabled in this phase, simplifying SNI policy and lifecycle; every new connection performs a full handshake. There is no client-certificate authentication. The executable does not enable unexpected-EOF tolerance: truncated TLS input is a protocol failure.

## Nonblocking transport and resource ownership

Accepted HTTPS sockets are NONBLOCK/CLOEXEC and occupy ordinary client slots immediately. They enter `tls_handshake`, then `reading` only after successful SSL_accept. SSL_read_ex and SSL_write_ex feed the existing HTTP logic. The transport tracks WANT_READ/WANT_WRITE independently of HTTP state, so reads may wait for OUT and writes for IN. Failed writes retain the same buffer address, contents and length until retry succeeds. Successful partial writes advance existing offsets. Proxy output remains bounded and upstream reads pause while output is pending.

OpenSSL-buffered plaintext is dispatched with a bounded synthetic-readiness budget; epoll is still polled for other connections, signals and listeners. This prevents complete buffered TLS records from waiting for another kernel readiness event. The loop has no blocking TLS network or DNS calls. SIGHUP reload performs synchronous bounded regular-file reads and OpenSSL parsing/verification on the loop, which can delay unrelated sockets and signal processing. OpenSSL handshake cryptography runs synchronously on the event-loop thread, so CPU cost can affect fairness under load; the shared client cap, handshake cap and timeout are not a per-second or per-source handshake rate limiter.

The handshake deadline begins at accept and cannot be extended by fragments. After success, the normal absolute HTTP header, request, write, idle and proxy deadlines apply. Request duration starts at handshake completion for the first HTTPS request. HTTP buffer limits count decrypted HTTP bytes, not TLS framing. OpenSSL has additional per-session buffers/allocations beyond ZigGate's fixed HTTP pools; capacity planning must include them and kernel buffers.

Contexts are initialized at stable addresses, callback arguments live through the event loop, and SSL objects retain their context references. Each client owns one SSL object, freed before its descriptor is closed. Socket BIOs created by SSL_set_fd do not take responsibility for closing the socket. The listener/epoll/client/upstream ownership rules remain centralized in the loop; contexts free after all client SSL objects. OpenSSL's per-thread error queue is cleared immediately before each TLS operation and after failures, and is inspected before another OpenSSL operation can alter it.

## Proxy boundary

The backend transport remains **plaintext HTTP**. Incoming Forwarded and X-Forwarded-* metadata is stripped and rebuilt; HTTPS clients produce `X-Forwarded-Proto: https`, while HTTP clients produce `http`. This describes the client-to-ZigGate connection, not encryption to the backend. Host is still rewritten to the configured numeric authority, and X-Forwarded-For comes from the actual socket peer. Client-selected schemes, hosts or SNI cannot choose arbitrary upstreams. Strict framing, route precedence, upstream capacity, timeout errors and post-commit truncation policies remain shared.

TLS read/write failures close the client and release any linked upstream. If a failed upstream transaction has a pending TLS write retry, the connection closes rather than replacing its write buffer with an error page. No response is processed before handshake success. HTTP remains available unless network deployment controls restrict its listener; HTTPS does not automatically redirect HTTP, add HSTS or force authentication.

## Shutdown and certificates

SIGINT/SIGTERM still flow through signalfd. The first signal closes both listeners, cancels unfinished handshakes, closes idle HTTPS keep-alive clients, and drains active requests/proxy responses under the existing grace deadline. Normal closure attempts SSL_shutdown to send close_notify. WANT_READ/WANT_WRITE is retried with a maximum one-second close budget, also bounded by the global drain deadline. Once our close_notify is sent, the server does not wait for the peer's reply.

TLS protocol errors, unfinished write/read operations that cannot safely be abandoned, grace expiry and a second delivered termination signal can force abrupt closure. SSL_shutdown is skipped after fatal TLS errors. Forced cleanup always frees remaining SSL objects and sockets; it never leaves a queued TLS-close state behind freed pool memory. Orderly close is best effort and not a delivery guarantee.

## Certificate hot reload with SIGHUP

```sh
./zig-out/bin/ziggate --tls-listen 127.0.0.1:9443 \
  --tls-cert certs/server.crt --tls-key certs/server.key \
  --max-tls-handshakes 128 --tls-handshake-timeout-ms 5000
# Replace the configured default and SNI PEM files under deployment control, then:
kill -HUP <pid>
```

SIGHUP is blocked and consumed through signalfd, outside any asynchronous signal handler. It rereads the **existing CLI certificate/key paths and all configured SNI paths**; it does not change listener addresses, route configuration, hostname maps, limits or path strings. Atomic file replacement or symlink retargeting is supported. Coordinate certificate/key deployment before signalling. If a pair is observed midway through replacement, mismatched or missing files cause failure and the last valid generation stays active. Restore all files and signal again to recover.

Two fixed context generations bound reload history and callback lifetimes. A candidate independently loads every configured default/SNI chain and key, validates parsing, chain adjacency/signatures and key correspondence, and prepares policy/callbacks. Only after all entries succeed does one event-loop index switch activate it for new accepts. No active SSL_CTX is mutated. Existing SSL objects, including unfinished handshakes that have not selected SNI yet, retain their original generation. The retired generation frees after its last SSL object is released. Callback arguments remain at stable addresses until then.

If the inactive slot still has live old-generation sessions, reload fails with `TlsReloadBusy`; it does not evict sessions, grow a history list, queue work or replace the active generation. Retry after old clients drain. Long-lived keep-alive sessions can therefore defer another rotation. There are at most two generations of up to nine contexts (default plus eight SNI entries), including candidates. Once old references reach zero, their contexts free promptly.

Reload is synchronous and has no background worker. Each file is opened NONBLOCK/CLOEXEC, checked with fstat for regular-file type, and read into size-bounded memory before OpenSSL sees it. FIFOs/devices and oversize data fail without a blocking pipe/device read. Each attempt considers at most nine certificate/key pairs, with the limits above. Regular filesystem access, allocation and OpenSSL parsing/signature checks can still stall the event loop; byte bounds are not latency guarantees. Deploy from local, trusted, responsive storage. Deadlines are checked against refreshed monotonic time before dispatch after reload, but the loop cannot service them during a filesystem stall.

Signals within one batch coalesce into one attempt. Attempts, including failures, are separated by at least one second after completion. Further requests within cooldown log `rate_limited` and are dropped, not queued. Logs include `retry_after_ms`; a later explicit SIGHUP is required. Linux standard signals themselves can coalesce, so signal counts are not attempt counts. Signal draining is bounded per epoll batch to avoid unlimited work under a signal flood.

SIGINT/SIGTERM take priority over reload observed in the same batch. HUP during draining is ignored; HUP in HTTP-only mode is a logged `TlsNotEnabled` failure and does not terminate service. On orderly termination the executable retains the blocked HUP/INT/TERM mask through final cleanup and exit, preventing pending signals from changing an orderly exit into default-signal termination. Error unwinding without a requested shutdown restores the previous mask. No reload or logging occurs inside an asynchronous signal handler.

## Handshake admission

The default is 128 simultaneous unfinished handshakes. It shares the global `--max-connections` ceiling: the effective bound cannot exceed available client slots. Excess HTTPS accepts close before SSL allocation, without an HTTP response. HTTP remains serviceable when TLS-only admission is full and global client slots remain available.

Each admitted Session owns one permit. Successful SSL_accept releases it immediately, even while the established connection stays alive. Failed initialization, protocol failure, timeout, disconnect, drain cancellation and forced cleanup release through the same idempotent ownership path. Permits do not transfer between reused slots and never remain held by established sessions. OpenSSL per-session allocations are still additional to fixed HTTP buffers; this cap bounds their number, not every allocator byte. There is no source-IP fairness or cryptographic CPU isolation.

## Logs and metrics

Phase 4A's pipe-only, bounded, lossy JSONL sink is unchanged. TLS logs include debug `tls_accepted`, info `tls_handshake` (numeric wire protocol version 771/772 and duration), and warn `tls_handshake_failed` with a timeout boolean. Admission rejection and reload success/failure events add bounded numeric fields and error categories. Payloads, keys, raw OpenSSL errors, SNI/HTTP names, paths and credentials are not logged.

Periodic and final metrics add:

| Field | Meaning |
| --- | --- |
| `active_tls_handshakes` | Current admitted unfinished TLS handshakes |
| `tls_handshake_rejections` | HTTPS accepts rejected by handshake admission or global client capacity |
| `tls_reload_successes`, `tls_reload_failures` | Activated generations and failed/rate-limited attempts; drain-ignored HUP is excluded |
| `tls_connection_closure_errors` | TLS objects released after protocol/transport failure or failed/timed-out close_notify; intentional cancellation without a TLS error is excluded |
| `active_tls` | Current HTTPS sockets, including handshaking/closing clients |
| `tls_handshake_successes` | Completed server handshakes |
| `tls_handshake_failures` | Failed/cancelled handshakes retired by the loop, including timeouts |
| `tls_handshake_timeouts` | Failures at or after their absolute handshake deadline; subset of failures |
| `tls_1_2`, `tls_1_3` | Cumulative successful handshakes by version, not active counts |
| `tls_shutdown_failures` | Fatal close_notify attempts or expiration of a queued TLS-close deadline |

Handshakes cancelled during forced cleanup count as failures; timeouts are the subset retired at their deadline. Skipped close attempts are not shutdown failures. A client TCP close without close_notify can legitimately increment closure errors; this is not necessarily a server defect. All counters are fixed-size and saturating. Metrics share log threshold/backpressure loss and expose no HTTP endpoint. They are operational observations, not exact accounting or guaranteed response-delivery confirmation.

## Tests and remaining work

```sh
zig fmt --check .
zig build
zig build test --summary all
zig build tls-integration
zig build integration
zig build -Doptimize=ReleaseSafe
```

Tests generate development keys/certificates in temporary directories, including a real root/intermediate/leaf chain. Python SSL clients verify trusted certificates; alternate/unknown SNI certificate selection is separately checked by DER comparison. A real OpenSSL memory-BIO unit test forces partial writes, WANT retries and close_notify backpressure without TCP timing assumptions. Integration synchronization uses readiness/log events, received bytes and backend gates. See [validation record](phase4b-validation.md) for exact executed commands and results.

No ACME, HTTP/2/3, QUIC, upstream TLS, OCSP stapling, mTLS, resumption, per-source/per-second handshake rate limiter or multiworker crypto isolation is included. SNI does not enforce HTTP Host consistency. Phase 5A adds measured shared-host load/soak tooling and emulated aarch64 validation; neither establishes production capacity or native aarch64 hardware coverage. See [Phase 5A results](phase5a-validation.md). Deployment requires security review beyond this test suite.

OpenSSL API references: [nonblocking I/O and error classification](https://docs.openssl.org/3.5/man3/SSL_get_error/), [write retry requirements](https://docs.openssl.org/3.3/man3/SSL_write/), [SNI callback ownership/selection](https://docs.openssl.org/3.0/man3/SSL_CTX_set_tlsext_servername_callback/), and [shutdown behavior](https://docs.openssl.org/3.5/man3/SSL_shutdown/).

## Optional load and soak commands

Default integration includes the bounded admission/reload suite; load and soak runs are separate.

```sh
zig build tls-reliability
zig build tls-reliability -Doptimize=ReleaseSafe
zig build tls-load -Doptimize=ReleaseSafe
# After installing a native ReleaseSafe binary:
python3 tools/tls_load.py ./zig-out/bin/ziggate --build-mode ReleaseSafe \
  --concurrency 16 64 128 256 --versions 1.2 1.3 --reload-active --resilience
python3 tools/tls_load.py ./zig-out/bin/ziggate --build-mode ReleaseSafe \
  --concurrency 16 --versions 1.3 --soak-seconds 300 --samples /tmp/ziggate-soak.jsonl
# Extended/manual runs: --soak-seconds 1800 or 7200
# Proxied soak: add --soak-mode proxy
```

The matrix uses four requests per client by default. Local mode keeps one TLS connection per client; proxy mode reconnects per response, forwarding 64 KiB bodies from a threaded Python HTTP backend. It uses 1024 global slots and raises handshake/upstream caps to at least the selected concurrency, so 256-client tests are not measurements of the default 128 cap. Clients verify the generated certificate and negotiate the requested TLS version. Normal local clients exchange close_notify; the resilience profile explicitly exercises abrupt closure. With `--reload-active`, local clients pause at a gate after the first response while a reload activates, then continue on their existing sessions. Request-rate timing includes thread setup, handshake and that gate; individual request latency includes handshake on a fresh connection.

The resilience profile covers 64 established sessions, eight incomplete handshakes, 16 excess rejections, 32 abrupt disconnects, reload while sessions remain alive and graceful termination. Integration separately tests rotation during gated active proxy streaming, invalid/mismatched files, old SNI handshakes and forced shutdown.

RSS/fds/CPU are sampled from the gateway's /proc entries every 100 ms; brief peaks can be missed. CPU percentages use 100% for one fully utilized core, are subject to tick quantization, and average CPU includes startup and the drain sampling window. Optional JSONL sampling writes from the test process, not the server. Client/backend threads and host activity affect all results.

Soak repeats waves, waits for a fresh zero-active-client/zero-handshake metrics snapshot after every wave, and reloads every fifth round. After three warmup points, at least eight drained points and a monotonic increase greater than two fds or 8 MiB RSS trigger a suspicious-growth flag. RSS alone never establishes a leak; allocator/provider caches can retain memory. Samples use a 10000-point rolling buffer and drained histories a 1024-point rolling buffer; JSONL can retain the full trace. Output contains RPS, latency percentiles, payload throughput, handshake/reload metrics, CPU and resources. Soak pacing intentionally includes drain sampling and is not a throughput benchmark. Flags are diagnostic rather than a formal leak proof.
