# ZigGate

ZigGate is an Apache-2.0 HTTP/1.1 server and reverse proxy written in **Zig 0.15.2**, targeting Linux x86_64 and aarch64. Phase 5A adds bounded TLS handshake admission, safe SIGHUP certificate rotation, reliability/load/soak tests and emulated aarch64 runtime validation to the OpenSSL 3.x HTTPS transport. This remains an incremental implementation, without production security certification. See [TLS setup](docs/tls.md), [Phase 5A validation](docs/phase5a-validation.md), and [operational notes](docs/production-hardening.md).

## Build and run

Install Zig **0.15.2 exactly**. OpenSSL 3.x development headers/libraries and libc are required (`sudo dnf install openssl-devel openssl pkgconf-pkg-config` on Fedora). Integration tests use Python 3 and Linux loopback networking.

```sh
zig build
zig build run
# With two configured proxy destinations:
./zig-out/bin/ziggate --bind 127.0.0.1 --port 8080 \
  --proxy /api/=127.0.0.1:8081 \
  --proxy /users/=127.0.0.1:8082
./zig-out/bin/ziggate --help
# Opt-in HTTPS alongside HTTP (certificate instructions: docs/tls.md):
./zig-out/bin/ziggate --tls-listen 127.0.0.1:8443 \
  --tls-cert ./certs/server.crt --tls-key ./certs/server.key \
  --proxy /home=127.0.0.1:3000
```

The backends must serve HTTP/1.1 with Content-Length or connection-close framing. For a complete local test with mock backends, run `zig build integration` or the dedicated proxy test below.

```sh
curl --http1.1 -i http://127.0.0.1:8080/
curl --http1.1 -i http://127.0.0.1:8080/health
curl --http1.1 -i http://127.0.0.1:8080/ready
curl --http1.1 -i 'http://127.0.0.1:8080/api/items?q=1'
curl --http1.1 -i http://127.0.0.1:8080/users/42
```

GET `/` returns `Welcome to ZigGate!`, `/health` returns `ok`, and `/ready` returns `ready`, each with a final newline. Readiness means the listener is serving requests; it does not check upstream health. These exact paths remain internal even when a proxy prefix `/` is configured. Query strings do not affect route selection. Unmatched requests retain the original router behavior: unknown GET paths receive 404, known methods other than GET receive 405 with `Allow: GET`, and unknown method tokens receive 501. HEAD responses omit payloads, including errors.

## Proxy configuration and precedence

Repeat `--proxy /prefix/=IPv4:port` for up to 16 routes. Configuration is validated at startup; duplicate prefixes, hostnames, URL schemes, invalid numeric IPv4 addresses, and invalid/zero ports are rejected. Prefixes must start with `/` and cannot contain whitespace, non-ASCII bytes, `?`, or `#`. There is no runtime DNS lookup and no destination chosen from client headers or request targets. Invalid CLI arguments exit with status 2; startup failures propagate as errors.

Selection order is: exact internal path first, then the longest matching configured prefix, then the original local router. Prefix matching uses the raw path before `?`, without decoding, normalization, or case folding. Prefixes match segment boundaries: `/api` matches `/api` and `/api/x`, but not `/apix`. `/api/` retains a required trailing slash. Ambiguous prefixes and traversal-style request paths are rejected; see the operational notes. The original method and full target, including query string, are forwarded unchanged. No prefix stripping, redirects, or arbitrary target proxying are performed.

On configured proxy paths, the existing parser accepts known HTTP methods with no body; CONNECT and explicit Upgrade requests receive 501. On local paths, existing method restrictions remain. Both the backend connection and the client connection close after a proxied response. Sequential keep-alive remains available for local requests; a local persistent connection may subsequently send one proxied request, which closes after its response. There is no upstream pooling or retry.

The backend Host is always the configured numeric `IPv4:port` authority. Incoming Host is validated and replaced. Client `Forwarded`, `X-Real-IP`, and all `X-Forwarded-*` headers are removed. ZigGate sets `X-Forwarded-For` to the actual socket peer's IPv4 address and `X-Forwarded-Proto` to `http` or `https` from the inbound transport. Backends remain plaintext HTTP. There is no trusted-forwarder override in this phase.

Fixed hop-by-hop headers and all headers nominated by any Connection token list are removed in both directions. Connection lists are validated case-insensitively across repeated fields; attempts to nominate Host, Content-Length, or Transfer-Encoding are rejected rather than concealing framing. Other end-to-end fields, including repeated Set-Cookie fields and Content-Encoding, are preserved. Upstream requests explicitly carry `Content-Length: 0` and `Connection: close`.

## Limits and deadlines

Configuration uses CLI arguments; there is no JSON configuration. SIGHUP reloads certificate/key contents at configured paths; listener and route configuration remain fixed.

| Option | Default | Accepted range / meaning |
| --- | --- | --- |
| `--tls-listen` | absent | Explicit HTTPS IPv4:port; requires certificate and key |
| `--tls-cert`, `--tls-key` | absent | PEM chain and matching unencrypted key |
| `--tls-sni` | absent | Up to 8 exact additional hostname=cert,key entries |
| `--tls-handshake-ms` | `5000` | 1–60000; absolute handshake deadline; alias `--tls-handshake-timeout-ms` |
| `--max-tls-handshakes` | `128` | 1–32768 unfinished handshakes; also subject to global client capacity |
| `--shutdown-ms` | `10000` | 1–60000; absolute graceful shutdown deadline |
| `--request-ms` | `60000` | 1–60000; total active request duration |
| `--header-bytes` | `8192` | 1–8192; inclusive request-header cap |
| `--pending-output-bytes` | `16384` | 1024–16384; proxy pending output cap (local cap: 1024) |
| `--log-level` | `info` | debug, info, warn, error; JSONL to nonblocking stderr pipes |
| `--check-config` | off | Validate arguments and exit without serving |
| `--bind` | `127.0.0.1` | IPv4 listener address |
| `--port` | `8080` | 1–65535 |
| `--timeout-ms` | `2000` | 1–60000; client header deadline and separate local-response/proxy-chunk write deadline |
| `--idle-timeout-ms` | `5000` | 1–60000; idle time between local persistent requests |
| `--max-connections` | `1024` | 1–32768 active accepted clients |
| `--max-requests` | `100` | 1–65535 requests per client; final local response closes |
| `--proxy` | none | Repeat `/prefix/=IPv4:port`, at most 16 distinct prefixes |
| `--max-upstreams` | `128` | 1–32768 active proxy transactions |
| `--upstream-connect-ms` | `2000` | 1–60000; absolute connect deadline |
| `--upstream-write-ms` | `2000` | 1–60000; absolute deadline to send the full upstream request |
| `--upstream-read-ms` | `5000` | 1–60000; absolute response-header deadline, then timeout waiting for the next body chunk |
| `--proxy-total-ms` | `30000` | 1–60000; absolute lifetime of the entire proxy transaction, including backpressure |
| `--upstream-header-bytes` | `8192` | 1–8192; inclusive upstream status line + headers + final CRLFCRLF |

All deadlines are monotonic. Initial client headers start at accept; subsequent headers start at the first read after idle. Trickle input never extends a header deadline. Empty initial clients receive 408 on expiry; idle reused clients close silently. Partial writes do not extend their write deadline. Body-read waiting resumes after the pending client output drains. The total proxy deadline bounds even an upstream that continuously trickles body bytes.

Client slots preallocate 8192 input bytes, 1024 local output bytes, and small state fields (roughly 9 MiB at the default client limit). When proxy routes exist, a separate pool preallocates 16 KiB request, 8 KiB response-header, and 16 KiB output storage per upstream slot (roughly 5 MiB at the default upstream limit). Normal streaming reads at most 8 KiB per chunk. Slot capacity bounds application memory independently of response body size; no response body is accumulated. Kernel socket buffers are additional and governed by Linux. A transaction retains its upstream slot until its output drains, even if the upstream descriptor has already closed.

While client output is pending, upstream readiness is unregistered; draining output re-registers reads. This provides backpressure without accumulating body chunks or spinning on an upstream EOF. Excess accepted clients are closed immediately without an HTTP response. Proxy capacity exhaustion returns 503. Accept resource exhaustion temporarily disables the listener and retries after approximately 100 ms while existing connections continue to receive service. The kernel backlog is 128 and accept work is limited to 64 calls per event.

## HTTP framing and errors

- The client header limit is **8192 inclusive wire bytes**, from the first request-line byte through the final byte of CRLFCRLF. All names, values, whitespace, and line endings count. Valid 8191- and 8192-byte requests are accepted; 8193 bytes receives 431, independent of fragmentation. Bodies/subsequent requests are outside this count. Boundary fixtures include `Connection: close` before sizing; inserting it afterward adds 19 bytes.
- Client requests must be HTTP/1.1 origin-form with one nonempty Host. HTTP/1.0 and HTTP/2.0 request lines receive 505. Invalid syntax, controls, folding, duplicate Content-Length, invalid Connection lists, and every Transfer-Encoding are rejected. There is no separate per-field size limit within the aggregate header cap.
- Request bodies remain unsupported and are never silently discarded. Declared lengths over 1 MiB receive 413; any other nonzero length receives 501; Expect receives 417. Parser/framing errors close the connection before any upstream request is sent.
- Upstream responses must have a valid HTTP/1.1 final status line (200–599), printable ASCII reason phrase, valid field syntax, and unambiguous framing. Duplicate, comma-list, signed, or overflowing Content-Length is rejected. Informational responses, protocol upgrades, and every Transfer-Encoding, including chunked, are unsupported and receive 502 **before any upstream headers are sent to the client**.
- Fixed Content-Length bodies stream exactly the declared bytes. Absent Content-Length, ordinary final responses stream until upstream EOF and use `Connection: close` downstream. HEAD, 204, 205, and 304 have no forwarded body; 204 with Content-Length and 205 with a nonzero length are rejected. HEAD/304 representation Content-Length metadata is preserved.
- Connection refusal, malformed/truncated upstream headers, and unsupported upstream framing produce 502. Upstream deadline expiry produces 504. Upstream resource exhaustion produces controlled rejection, normally 503. If response forwarding has already begun, failures close the client; **no second HTTP status is sent**. Early body EOF closes a partially forwarded response, exposing truncation through Content-Length. Extra bytes beyond a completed fixed-length body are never forwarded or reused.
- Only one request/response is active per client. Local pipelining is unsupported: buffered surplus forces close without dispatching another request, although later kernel-buffered bytes may be read sequentially after a local response. Proxied responses always close, so surplus bytes are never dispatched there.
- Partial reads/writes and EAGAIN retain offsets. Socket operations are nonblocking; sends use MSG_NOSIGNAL. Complete half-closed requests may still receive responses. Incomplete request EOF, socket errors, deadlines, and completion policies release descriptors. Linux may reset connections with rejected unread input; error delivery is best effort.

## Verification

```sh
zig fmt --check .
zig build
zig build test --summary all
zig build integration
zig build -Doptimize=ReleaseSafe
# Cross-linking TLS also requires a complete target OpenSSL prefix/sysroot:
zig build -Dtarget=aarch64-linux-gnu.2.38 -Doptimize=ReleaseSafe \
  -Dopenssl-prefix=/path/to/aarch64/usr
```

Existing Phase 1/2 tests are preserved. Proxy unit tests cover route validation/precedence, internal routing, metadata sanitization, Connection nominations, malicious upstream syntax/framing, inclusive upstream header boundaries, short writes, fragmented reads, EAGAIN, failed connect completion, staged/total deadlines, and a 1 MiB body processed through fixed chunks.

The dedicated raw mock-backend suite covers successful GETs, longest prefixes, internal routes, Host/metadata/hop-header policies, refusal, read timeout, malformed headers, Content-Length and close-delimited streaming, fragmented backend writes, slow readers, client/upstream disconnects, truncated/timed-out bodies without a second status, concurrent requests, capacity limits, repeated-failure descriptor accounting through `/proc`, unsupported chunked responses, and continued service. Actual partial-write behavior is tested deterministically in the same upstream driver; TCP packet boundaries alone cannot reliably force a short send.

The proxy fixture explicitly uses a 256-connection listen backlog. Inspection of Python 3.14 confirmed that the previous threaded backend inherited `TCPServer.request_queue_size = 5`: handler threads start only after acceptance and do not enlarge this queue. A burst could therefore overflow the backend queue and trigger genuine proxy timeouts even with fast handlers. The previous 64-request workload also used only 32 workers. The regressions now use synchronized waves of 64 and 100 workers, plus a direct 100-client backend preflight with a 500 ms IO budget. The ordinary gateway connect/read/write deadlines remain 500 ms; they were not increased to fix the load test. Socket-free fixture tests check the real server activation path's listen argument and threaded dispatch policy before the proxy integration suite starts.

Separate slow/late upstream cases remain. An event-gated slow request proves the backend has received the request before testing read timeout and progress by local/fast proxy clients. A Linux backlog-zero listener with a filled accept queue and a verified pending probe isolates connect timeout: it uses a 100 ms connect deadline and a distinct 3-second read deadline, then repeats timeouts while checking descriptors. This fixture fails explicitly if the kernel does not provide the required pending-connect condition. Client disconnects now happen after forwarding starts; descriptor accounting includes repeated successful requests as well as malformed/refused requests. These live checks were executed with the loopback permissions required by this environment.

Phase 4B verification adds TLS version/SNI/chain, encrypted framing, partial-write and TLS shutdown tests to the existing suites. See the [TLS validation record](docs/phase4b-validation.md). Phase 4A verification includes all existing suites and new signal, streaming drain, deadline, high concurrency shutdown, slow logging, redaction and configuration checks. See the [validation record](docs/phase4a-validation.md) for actual commands and results.

Individual scripts accept a binary path:

```sh
python3 tests/integration/http_test.py ./zig-out/bin/ziggate
python3 tests/integration/concurrent_test.py ./zig-out/bin/ziggate
python3 tests/integration/proxy_test.py ./zig-out/bin/ziggate
# Socket-free fixture regression checks alone:
python3 tests/unit/proxy_fixture_test.py
```

If the global Zig cache is restricted, prefix commands with `ZIG_GLOBAL_CACHE_DIR=/tmp/ziggate-cache`. Cross-compilation installs an aarch64 binary into the same output path; run native `zig build` again before executing on x86_64.

## Limitations and next steps

No ACME, upstream TLS, HTTP/2, HTTP/3, WebSocket tunneling, chunked response decoding, request bodies, DNS resolution, upstream pooling, retries, load balancing, active health checks, static files, virtual hosts, or JSON configuration are implemented. The single event-loop thread scans bounded slot arrays. Host validation on incoming requests remains lexical rather than complete authority validation. Upstream destinations are administrator-controlled and should be trusted to receive forwarded end-to-end request fields; client forwarding metadata is always discarded. There is no application rate limiter, security audit, or production capacity claim.

Next: broaden load/security testing and resource-exhaustion experiments. Next steps include native aarch64 hardware tests, longer isolated soak/load runs, per-source admission policy and a worker-based reload/crypto design if latency guarantees require it. See [architecture](docs/architecture.md) for ownership and state transitions.

## TLS admission and certificate rotation

```sh
./zig-out/bin/ziggate --tls-listen 127.0.0.1:9443 \
  --tls-cert certs/server.crt --tls-key certs/server.key \
  --max-tls-handshakes 128 --tls-handshake-timeout-ms 5000
# After coordinated, atomic replacement of the configured default/SNI files:
kill -HUP <pid>
zig build tls-reliability
zig build tls-load -Doptimize=ReleaseSafe
python3 tools/tls_load.py ./zig-out/bin/ziggate --build-mode ReleaseSafe \
  --concurrency 16 --versions 1.3 --soak-seconds 300
```

Reload validates a separate generation before activation. Active sessions retain their original certificates and SNI contexts; failure preserves the last valid generation. Two generations bound history, so another rotation can return `TlsReloadBusy` until old sessions drain. Attempts are limited to one per second, with no queued retries. Regular-file sizes and chain length are bounded; synchronous filesystem/OpenSSL work can briefly stall the loop. See [TLS semantics](docs/tls.md) and [measured Phase 5A results](docs/phase5a-validation.md), including the distinction between QEMU runtime coverage and real aarch64 hardware.
