# Phase 5A validation: TLS reliability and hot reload

Validated on 2026-10-27 with Zig **0.15.2**, Fedora Linux **44**, OpenSSL **3.5.9**, Python **3.14.8**, and a native x86_64 AMD Ryzen 5 PRO 4650U host (12 logical CPUs). Passing tests and shared-host measurements do not establish production readiness. No commit or push was created.

## Implementation and operations

`--max-tls-handshakes` defaults to **128**, accepts 1–32768, and remains subject to global client capacity. A Session acquires before SSL allocation and owns its permit until successful handshake or cleanup. Initialization failure, protocol error, timeout, disconnect and shutdown cannot double-release it. `--tls-handshake-timeout-ms` aliases the existing `--tls-handshake-ms` (default 5000, range 1–60000).

SIGHUP is consumed through signalfd. Preparation loads every default/SNI certificate/key into an inactive generation and validates bounded PEM syntax, adjacent issuer/signature consistency and key matching. Activation switches one event-loop index. Established SSL objects and unfinished SNI handshakes retain their original generation/callback registry. At most two generations exist; a still-referenced retired slot returns `TlsReloadBusy`. Failed candidates leave active contexts unchanged. Paths/maps/listeners stay as configured in CLI; file contents and symlink targets may be replaced under deployment control.

Attempts are separated by one second after completion, coalesced per readiness batch, and never queued. Failure/rate-limit logs include a retry interval. HUP during drain is ignored; termination takes priority over a reload observed in the same batch. HUP without TLS logs failure and preserves HTTP service. The signal mask remains blocked through final termination cleanup, preventing late pending signals from interrupting an orderly exit.

Only regular files are read, using the opened fd rather than reopening a pathname after stat. Limits: 1 MiB/16 certificates per chain, 64 KiB per key, at most nine pairs per generation. Synchronous regular filesystem access and OpenSSL parsing/signature checks can delay the event loop; these work/byte bounds are **not** wall-clock latency guarantees. No asynchronous signal handler performs application work. Reload does not validate public trust, hostname coverage, certificate expiry or revocation.

Metrics add active handshakes, admission rejections, reload outcomes and TLS connection closure errors. Existing handshake failures/timeouts now include forced-cleanup cancellations consistently. The pipe logger remains bounded and lossy. See [TLS operations](tls.md) for precise counters, generation limits and recovery instructions.

## Build and tests

The host still lacks system `openssl-devel`. Bare `zig build` was tried and failed because the linker could not find development `libssl.so` / `libcrypto.so` names. The root cause is the same dependency limitation documented in Phase 4B, not a source or TLS-disable workaround. Matching Fedora development headers/linker files under `/tmp/ziggate-openssl-dev/usr` resolved it through the supported prefix option. Install `openssl-devel` on a normal Fedora development host, or supply that option. Native compiler/cache and loopback commands required sandbox permission.

| Command | Result |
| --- | --- |
| `zig fmt --check .` | Passed |
| `git diff --check` | Passed |
| `python3 -m py_compile tools/tls_load.py tests/integration/tls_reliability_test.py` | Passed |
| `zig build -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, native Debug |
| `zig build test --summary all -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | **48/48 passed**, Debug |
| `zig build test -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr --summary all` | **48/48 passed**, ReleaseSafe |
| `zig build integration -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | All **six suites** and two Python fixture tests passed |
| `zig build -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed; native ReleaseSafe restored after cross-build |
| `zig build integration -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | All six suites and Python fixture tests passed |
| `zig build tls-reliability -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed independently |

The integration build includes both TLS-specific suites in Debug and ReleaseSafe. Existing output retains 32 HTTP response checks, 100-client concurrency, 431 proxy checks, Phase 4A hardening, and Phase 4B TLS coverage. No old tests were removed or relaxed.

New tests cover admission saturation/reuse, successful sessions no longer holding permits, timeout alias/bounds, old sessions and pending SNI handshakes across rotation, new default/SNI selection, a bounded busy generation, malformed/mismatched/missing/incorrect-chain/SNI/FIFO/oversize files, repeated valid/failed reloads, streaming reload, HTTP-only HUP and shutdown accounting. Tests synchronize on server logs, actual received bytes, backend gates and server-advertised reload cooldown; cooldown waits are intentional policy waits rather than assumed IO timing. Previous forced TLS shutdown, truncation, obsolete version rejection, secret omission and descriptor recovery tests remain.

The first new fixture attempted to unpack the root certificate path as a pair; it was corrected. Another selection check loaded the deliberately invalid on-disk certificate into its own trust store before connecting. It now uses a separate client and compares exact expected DER, while existing TLS verification tests remain strict. These were fixture failures, not weakened server checks.

## Measurements and reproducibility

```sh
zig build -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr
python3 tools/tls_load.py ./zig-out/bin/ziggate --build-mode ReleaseSafe \
  --reload-active --resilience --samples /tmp/ziggate-load.jsonl
python3 tools/tls_load.py ./zig-out/bin/ziggate --build-mode ReleaseSafe \
  --concurrency 16 --versions 1.3 --soak-seconds 300 \
  --samples /tmp/ziggate-soak.jsonl
# Optional longer/manual runs: --soak-seconds 1800 or 7200
# Optional proxied soak: --soak-mode proxy
```

`zig build tls-load -Doptimize=ReleaseSafe` provides the default matrix/resilience step and is separate from integration. The saved native ReleaseSafe binary was used for the soak while other validation ran. The matrix ran with loopback client/backend threads on the same shared host, no pinning, default info JSONL logging, 1024 global connections and handshake/upstream caps raised to at least the selected concurrency. Thus the 256-client cases do not measure the default 128-handshake cap. OpenSSL resumption is disabled. Each client makes four requests: local 3-byte responses use keep-alive, proxy 64 KiB responses close and reconnect each time. Local reload gates keep sessions alive across activation. RPS includes handshake/thread/gate overhead; fresh-connection request latency includes its handshake.

Full machine-readable results, metrics, CPU and resource observations: [load JSON](benchmarks/phase5a-load.json), [soak JSON](benchmarks/phase5a-soak.json). These contain no private keys or application credentials. Resource samples are 100 ms snapshots; short-lived peaks can be missed, including waves reporting eight sampled fds despite more concurrent live sockets between samples. CPU is percentage of one core, with tick quantization; average CPU includes startup/drain sampling time. Python/OpenSSL/backend scheduling dominates some cases. No performance improvement or production-capacity claim follows.

| TLS | Workload | Clients | Requests/s | p50 ms | p95 ms | p99 ms | Payload MiB/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.2 | local | 16 | 2573.9 | 1.723 | 10.336 | 10.647 | 0.01 |
| 1.2 | proxy | 16 | 935.3 | 13.889 | 23.44 | 25.15 | 58.46 |
| 1.2 | local | 64 | 3082.4 | 7.965 | 27.214 | 30.348 | 0.01 |
| 1.2 | proxy | 64 | 1030.9 | 54.243 | 78.526 | 84.636 | 64.43 |
| 1.2 | local | 128 | 3177.9 | 15.252 | 54.2 | 59.934 | 0.01 |
| 1.2 | proxy | 128 | 1045.8 | 107.417 | 148.076 | 156.548 | 65.36 |
| 1.2 | local | 256 | 2815.5 | 30.535 | 118.801 | 128.078 | 0.01 |
| 1.2 | proxy | 256 | 1033.7 | 224.405 | 295.548 | 329.789 | 64.61 |
| 1.3 | local | 16 | 836.5 | 5.094 | 49.37 | 49.618 | 0.0 |
| 1.3 | proxy | 16 | 298.7 | 47.507 | 60.963 | 61.578 | 18.67 |
| 1.3 | local | 64 | 1921.4 | 10.723 | 67.645 | 72.391 | 0.01 |
| 1.3 | proxy | 64 | 853.8 | 60.535 | 91.34 | 95.751 | 53.36 |
| 1.3 | local | 128 | 2434.3 | 14.737 | 96.306 | 107.293 | 0.01 |
| 1.3 | proxy | 128 | 968.6 | 116.7 | 169.812 | 192.946 | 60.54 |
| 1.3 | local | 256 | 2842.4 | 30.47 | 147.252 | 157.499 | 0.01 |
| 1.3 | proxy | 256 | 1006.8 | 223.119 | 322.347 | 380.471 | 62.92 |

All 7424 matrix requests succeeded, with exactly matching server request and 2xx counts. There were 4640 successful handshakes, zero failed handshakes, zero admission rejections and zero unexpected TLS closure errors in normal matrix cases. Every process returned to eight drained fds. Largest sampled matrix RSS was 43,499,520 bytes and fd count 513; these are sampled per-process observations, not promised bounds. Raw JSON records average/peak sampled CPU and handshake counts for every case.

The separate resilience profile kept 64 established clients, saturated eight handshake slots with incomplete records, observed **16 rejections and eight timeouts**, deliberately closed 32 clients abruptly, reloaded with live sessions and gracefully closed the remainder. Final counters showed 32 expected TLS closure errors, one reload success, and zero active clients/upstreams/handshakes. A TLS error counter can reflect client truncation rather than a server defect.

### Soak results and the bug it found

The initial 300-second soak completed but exposed an existing keep-alive observation gap: a request starting and finishing in the same dispatch could leave the state `idle` before and after, so the response was not counted. Completion now also checks the request counter, with a deterministic two-request driver regression. The first driver also closed each ordinary local TLS socket without close_notify, generating expected client truncation errors. Normal load/soak clients now unwrap TLS orderly; intentional abrupt closures remain in the resilience profile. The complete matrix and five-minute soak were rerun, with exact request/status-count assertions. Initial figures are not mixed into final results.

Final soak: **300.29 seconds**, TLS 1.3, 16 clients, 293 drained rounds, **18752 successful requests**, **4688 successful handshakes**, and **58 reloads**. Request and 2xx totals match exactly. Handshake failures, timeouts, TLS closure errors, shutdown failures and reload failures were all zero.

After three warmup rounds, drained fds remained **8 → 8** across 290 observations. Drained RSS moved **19,091,456 → 19,316,736 bytes** (+225,280 bytes, 220 KiB). Sampled peak RSS was 19,357,696 bytes; sampled peak fds 24. Sampled CPU time was 5.34 seconds, average 1.78% of one core over the full paced window. Neither suspicious-growth flag triggered. This small RSS change is consistent with caching/retention and does not demonstrate either a leak or absence of leaks.

The heuristic excludes three warmup points, requires at least eight subsequent drained points, and flags a nondecreasing increase greater than two fds or 8 MiB RSS. It can miss non-monotonic growth and is not heap profiling. A round waits for a fresh zero-active metrics snapshot, so soak request rate is deliberately paced and should not be read as throughput capacity. Native builds and QEMU tests ran on the shared host during part of the soak. Extended 30-minute/two-hour runs were **not executed**; commands are documented and separate from default integration. Sample/history buffers have fixed rolling capacities; optional JSONL retains full resource traces outside the repository.

## aarch64 link and emulated runtime

Complete TLS-enabled cross-link passed:

```sh
zig build -Dtarget=aarch64-linux-gnu.2.38 -Doptimize=ReleaseSafe \
  -Dopenssl-prefix=/tmp/ziggate-openssl-aarch64-dev/usr
```

`file` / `readelf` confirmed AArch64 ELF64, interpreter `/lib/ld-linux-aarch64.so.1`, and dependencies on libssl.so.3, libcrypto.so.3 and libc.so.6. TLS was not disabled and native libraries were not substituted for target libraries.

A **pre-existing QEMU aarch64 10.2.2 static emulator** was found. No emulator software was installed. Matching Fedora target glibc `2.43-9.fc44.aarch64` was downloaded with explicit permission, its RPM digest checked, and extracted into the existing temporary target runtime prefix alongside OpenSSL 3.5.9 and zlib-ng-compat. This allowed actual execution, not just linking:

```sh
qemu-aarch64-static -L /tmp/ziggate-openssl-aarch64-dev \
  -E LD_LIBRARY_PATH=/tmp/ziggate-openssl-aarch64-dev/usr/lib64 \
  /tmp/ziggate-phase5a-aarch64 --help
```

A temporary executable wrapper uses that exact invocation followed by `"$@"`. Runtime tests executed through it:

- `python3 tests/integration/http_test.py /tmp/ziggate-phase5a-aarch64-run`: passed all 32 HTTP checks.
- `python3 tests/integration/tls_test.py /tmp/ziggate-phase5a-aarch64-run`: passed TLS 1.2/1.3, chain/SNI, concurrent HTTPS, decrypted framing, HTTPS reverse proxy, streaming, cleanup and graceful/forced shutdown.
- `python3 tests/integration/tls_reliability_test.py /tmp/ziggate-phase5a-aarch64-run`: passed admission and reload lifecycle checks, including old pending SNI callbacks.

The final metrics fix was cross-linked again and TLS runtime tests rerun. This verifies emulated aarch64 execution and target OpenSSL/shared-library compatibility. **Native aarch64 hardware was unavailable**, so hardware-specific performance, provider behavior and long-duration reliability remain unvalidated. No aarch64 load/soak capacity claim is made. The native ReleaseSafe binary was restored in zig-out afterward.

## Complete repository inventory

Added:

- `src/tls/admission.zig`: bounded event-loop handshake permits and tests.
- `tests/integration/tls_reliability_test.py`: deterministic admission/reload/failure regressions.
- `tools/tls_load.py`: optional TLS matrix, resilience and drained-resource soak driver.
- `docs/phase5a-validation.md`: this record.
- `docs/benchmarks/phase5a-load.json`, `docs/benchmarks/phase5a-soak.json`: final machine-readable measurements.

Modified:

- `README.md`: admission/reload usage and validation links.
- `build.zig`: reliability integration and separate optional load step.
- `docs/architecture.md`: generation/permit ownership and signal flow.
- `docs/production-hardening.md`: operational changes, metrics and soak guidance.
- `docs/tls.md`: limits, reload lifecycle/recovery, synchronous-work caveat, metrics and load/soak commands.
- `src/cli/commands.zig`: admission cap, timeout alias and bound/compatibility tests.
- `src/core/event_loop.zig`: SIGHUP dispatch, cooldown/coalescing, admission integration, refreshed deadlines, closure accounting and fast keep-alive response observation regression.
- `src/core/shutdown.zig`: HUP mask and safe termination teardown.
- `src/observability/metrics.zig`: active handshakes, rejections, reload outcomes and closure errors.
- `src/tls/config.zig`: default handshake cap.
- `src/tls/context.zig`: two stable generations, Session references and bounded regular-file snapshots.
- `src/tls/openssl_shim.c`, `src/tls/openssl_shim.h`: bounded memory-PEM decoding and OpenSSL chain consistency checks.
- `src/tls/session.zig`: permit/generation ownership, idempotent cleanup and tests.

## Remaining security and reliability limits

Reload can stall on regular storage/crypto work and has no background worker or hard latency guarantee. Two generations can defer another rotation until old clients close. Certificate trust/expiry/revocation/name coverage remain deployment/client responsibilities; SNI is not authorization. Handshake admission is not per-IP/per-second fairness or CPU isolation. OpenSSL allocator/provider/kernel resource costs exceed fixed HTTP buffers. TLS close_notify remains best effort under errors/deadlines/force-close. Logs/metrics are bounded and lossy, not exact delivery accounting. There is no ACME, new HTTP protocol, WebSocket, upstream HTTPS, mTLS, OCSP, resumption or early data.

The 5-minute soak and QEMU coverage do not replace native hardware validation, allocator-failure injection, isolated load tests, long-duration memory profiling or an independent security review. Next work should prioritize those checks, longer 30-minute/two-hour soaks, source-aware handshake admission and any explicitly scoped asynchronous certificate preparation design.
