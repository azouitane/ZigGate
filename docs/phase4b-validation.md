# Phase 4B validation record

Validated on 2026-10-27 using Zig **0.15.2**, Fedora Linux **44**, x86_64, and OpenSSL **3.5.9**. No Git commit or push was created. No TLS features or previous tests were removed to pass a build.

## Dependency setup in this environment

The host initially had OpenSSL runtime libraries but no development headers, pkg-config metadata or linker symlinks. `sudo dnf install openssl-devel` could not proceed because sudo required an interactive password. Fedora's matching `openssl-devel-3.5.9-1.fc44.x86_64.rpm` was downloaded and extracted under `/tmp/ziggate-openssl-dev/usr`; its local linker symlinks were completed with links to the installed matching runtime libraries. Commands below therefore use `-Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr`. On a Fedora host with `openssl-devel` installed, omit that option. Native compiler/cache and loopback tests required sandbox escalation.

The initial restricted-cache build failed on compiler/cache access and was rerun with permission. Development packages and cross-target files were kept outside the repository; no private keys or certificates were committed. Test certificates/keys are generated in temporary directories.

## Native checks

| Check | Result |
| --- | --- |
| `zig fmt --check .` | Passed |
| `git diff --check` | Passed |
| `python3 -m py_compile tests/integration/tls_test.py` | Passed |
| `zig build -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, native Debug |
| `zig build test -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr --summary all` | Passed, **42/42** Zig unit tests |
| `zig build tls-integration -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed |
| `zig build integration -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, all five integration suites plus two Python fixture tests |
| `zig build -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, native TLS-enabled ReleaseSafe |
| `zig build integration -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, all five suites plus Python fixtures |

Existing output reports **32 HTTP response checks**, **100 concurrent clients** with keep-alive/deadline/descriptor checks, **431 proxy checks**, and the Phase 4A signal/logging/configuration suite. The new HTTPS suite adds:

- Verified TLS 1.2 and TLS 1.3 handshakes; HTTPS GET and sequential keep-alive; HTTP and HTTPS listener coexistence.
- Default, absent, unknown and alternate SNI; case-insensitive exact selection checked against certificate DER; a real root/intermediate/leaf chain verified by a client trusting only the root.
- Missing/incomplete settings, malformed files, missing keys, mismatched keys, encrypted-key rejection without prompting, unsupported hostname configuration and validation-only mode.
- TLS 1.0/1.1 and unsupported ALPN rejection; plaintext input never receives a plaintext HTTP response on the TLS listener.
- Thirty-two concurrent TLS clients, a shared four-client capacity test with incomplete handshakes, handshake expiry, malformed/oversized records and fragmented handshake records sent one wire byte at a time.
- Duplicate Content-Length, CL+TE ambiguity, folded headers and a configured decrypted-header ceiling; decrypted header timeout and idle timeout; truncated encrypted application and handshake records.
- Abrupt TLS disconnects with /proc descriptor recovery, including a streaming reverse-proxy client disappearing while a linked HTTP upstream is active; continued HTTPS service afterward.
- HTTPS proxy streaming with sanitized `X-Forwarded-Proto: https`, a 3 MiB response, listener closure during drain, orderly idle closure, full streaming completion, grace expiry and distinct second-signal forced shutdown.
- JSONL parsing, TLS version/failure/timeout metrics and checks that credential/key markers do not appear in logs.

The real OpenSSL memory-BIO unit test generates an ephemeral certificate/key with OpenSSL APIs, negotiates TLS, transfers 32 KiB through bounded BIOs, forces successful partial writes and WANT retries, and checks every byte. It also fills the output BIO to force SSL_shutdown WANT_WRITE, drains the peer BIO, retries, and verifies the peer receives close_notify. This is deterministic backpressure coverage independent of TCP packet boundaries. A separate readiness unit test verifies opposite-direction interests override HTTP state.

The first BIO workload used a buffer so small that every application write retried and OpenSSL completed the entire original buffer on success; it did not force a successful short write. The corrected workload permits one record then fills before reading, proving both cases. The initial generated root CA lacked a key-usage extension required by Python's strict verification; the fixture was corrected without relaxing verification. A shutdown test helper also sent an unintended additional termination signal after draining had begun; it now leaves first-signal drain, deadline expiry and second-signal forcing distinct. The expanded suite passes with these fixes.

Synchronization uses backend gates, structured-log events, actual received bytes and bounded waits. Deadline tests necessarily wait for configured deadlines. Startup is not synchronized with arbitrary fixed sleeps. These tests do not provide allocator-fault injection, exhaustive provider/FIPS testing, a TLS security audit or production capacity proof.

## Complete aarch64 TLS cross-link

**Passed** with target OpenSSL libraries and an explicit compatible glibc version:

```sh
zig build -Dtarget=aarch64-linux-gnu.2.38 -Doptimize=ReleaseSafe \
  -Dopenssl-prefix=/tmp/ziggate-openssl-aarch64-dev/usr
```

Target packages downloaded from Fedora repositories and extracted into the target prefix:

- `openssl-devel-3.5.9-1.fc44.aarch64.rpm`
- `openssl-libs-3.5.9-1.fc44.aarch64.rpm`
- `zlib-ng-compat-2.3.3-3.fc44.aarch64.rpm`

Completed RPM payload digests were checked before using target runtime libraries. Repository/mirror timeouts required retries. No x86_64 OpenSSL binaries were substituted for target libraries.

The initial build with native OpenSSL headers failed on their architecture guard. With correct aarch64 libraries, the default GNU libc baseline failed on versioned symbols such as `__isoc23_strtol@GLIBC_2.38`, `pthread_create@GLIBC_2.34` and `stat@GLIBC_2.33`. Selecting `aarch64-linux-gnu.2.38` resolved the ABI requirement without suppressing undefined-symbol checks or disabling TLS.

`file` and `readelf` confirmed the linked executable:

```text
ELF64, Machine: AArch64
interpreter: /lib/ld-linux-aarch64.so.1
NEEDED: libssl.so.3
NEEDED: libcrypto.so.3
NEEDED: libc.so.6
```

This is a complete executable link, not just Zig object compilation. It was **not executed on aarch64**. Deployment still needs compatible target runtime libraries, their dependencies, OpenSSL providers/configuration and runtime testing. The native ReleaseSafe executable was rebuilt after cross-compilation.

## File inventory

Added:

- `src/tls/config.zig`: listener/SNI configuration and bounds.
- `src/tls/context.zig`: PEM chain/key loading, context ownership and SNI callback.
- `src/tls/session.zig`: nonblocking TLS operations, readiness state and real BIO tests.
- `src/tls/openssl_shim.h`, `src/tls/openssl_shim.c`: stable OpenSSL C interop, policy, ALPN and noninteractive password handling.
- `tests/integration/tls_test.py`: generated-certificate HTTPS regression suite.
- `docs/tls.md`: dependencies, certificates, CLI, lifecycle and security boundaries.
- `docs/phase4b-validation.md`: this record.

Modified:

- `.gitignore`: excludes the documented local `certs/` directory.
- `README.md`: TLS usage, dependencies and updated scope.
- `build.zig`: OpenSSL/libc linkage, development-prefix option and TLS integration step.
- `build.zig.zon`: includes existing stress tooling in packaged sources.
- `docs/architecture.md`, `docs/production-hardening.md`: TLS ownership and baseline documentation links.
- `src/main.zig`: context loading before serving or configuration validation.
- `src/cli/commands.zig`: HTTPS/SNI options, handshake bounds and listener conflict validation.
- `src/core/server.zig`: dual-listener creation and ownership transfer.
- `src/core/connection.zig`: per-client TLS ownership and handshake/shutdown states.
- `src/core/event_loop.zig`: dual listeners, TLS-aware client IO/interests, buffered plaintext scheduling, timeouts, metrics and drain lifecycle.
- `src/observability/metrics.zig`: bounded TLS operational counters.
- `src/proxy/reverse_proxy.zig`: inbound transport-derived forwarding scheme with existing API compatibility.
- `src/proxy/upstream_connection.zig`: shared TLS-capable client flush interface and scheme-aware request construction.

## Limitations and Phase 5

Certificate reload is restart-only; no SIGHUP reload behavior is added. Session resumption, early data, mTLS, OCSP, ACME, HTTP/2/3, QUIC and upstream TLS are absent. HTTP remains enabled alongside HTTPS; there is no automatic redirect or HSTS policy. The backend connection is plaintext. Certificate loading checks syntax/key correspondence, not expiry/trust/name coverage/revocation. SNI is certificate selection, not authorization.

OpenSSL allocations and synchronous handshake CPU add resource costs beyond the fixed HTTP pools. There is no handshake rate limiter or crypto worker pool. close_notify is best effort, bounded to one second and the global grace deadline; fatal errors and force-close can be abrupt. Metrics share the bounded/lossy pipe logging sink; forced cleanup may bypass handshake-failure accounting. No TLS performance numbers or production-readiness claim is made.

Phase 5 should prioritize aarch64 runtime validation, longer TLS soak/load tests with CPU/RSS/fd measurements, handshake admission controls, and failure injection. Live certificate reload needs a separate prepare/activate/retain lifecycle review. Further protocol/proxy expansion should remain explicitly scoped after these reliability checks.

## Final ReleaseSafe integration status

Passed: all five integration suites and the two socket-free Python fixture tests completed against the native ReleaseSafe TLS-enabled executable.
