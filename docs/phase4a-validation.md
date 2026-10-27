# Phase 4A validation record

Validated on 2026-10-27 with Zig 0.15.2, Linux x86_64. Compiler/cache and socket operations required sandbox escalation; failed restricted-cache attempts were rerun with permission. No tests were removed, and no commit or push was made.

## Checks

| Command | Result |
| --- | --- |
| `zig fmt --check .` | Passed |
| `git diff --check` | Passed |
| `zig build` | Passed, native Debug |
| `zig build test --summary all` | Passed, 38/38 Zig tests |
| `zig build integration` | Passed, all four integration suites and two Python fixture tests |
| `zig build -Doptimize=ReleaseSafe` | Passed |
| `zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe` | Passed; compile-only, not executed on aarch64 |
| `zig build stress -Doptimize=ReleaseSafe` | Passed; results below |

Existing integration output reports 32 HTTP response checks, 100-client concurrency coverage and 431 proxy checks. Existing resource/timeout tests cover upstream capacity, client capacity, slow clients/upstreams, framing attacks, header filtering and descriptor recovery. New integration coverage includes SIGINT/SIGTERM, 100 simultaneous clients during shutdown, idle keep-alive closure, completing partial requests while draining, event-gated streaming completion, grace expiry, second termination signal, total request deadline, a deliberately undrained logging pipe, JSONL parsing, credential/query omission, metrics and invalid configuration.

New unit coverage includes shutdown transitions, numeric option bounds, segment-safe route matching, ambiguous route/path rejection, configurable request headers and pending upstream output, JSON escaping, and a full nonblocking log pipe. Streaming tests synchronize on backend events and received bytes; shutdown tests synchronize on structured events. Readiness retries use bounded polling. Actual timeout tests necessarily wait for configured deadlines.

## Measured workload

Command: `zig build stress -Doptimize=ReleaseSafe`.

Hardware: AMD Ryzen 5 PRO 4650U with Radeon Graphics, 12 logical CPUs. OS: Linux 7.2.11-200.fc44 x86_64, glibc 2.43. Build: Zig 0.15.2 ReleaseSafe. Each workload sends 2000 successful requests from 16 Python threads over loopback. Local mode uses keep-alive with 3-byte responses. Proxy mode uses 64 KiB bodies from one sequential Python backend, closing each proxied client connection. Logging threshold is error. RSS/fd counts are sampled every 10 ms from the gateway's /proc entries. The host is shared; CPU pinning and host isolation were not applied.

Final repeat:

| Workload | Requests/s | p50 ms | p95 ms | p99 ms | Payload MiB/s | Sampled peak RSS bytes | Peak fds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Local | 2664.7 | 3.664 | 15.768 | 26.739 | 0.01 | 9940992 | 22 |
| Reverse proxy | 1857.2 | 8.223 | 11.208 | 13.104 | 116.08 | 15204352 | 38 |

An earlier run on the completed implementation recorded 2865.9 local requests/s and 3076.3 proxy requests/s (192.27 MiB/s). A preliminary implementation run recorded 8741.5 local requests/s and 3053.3 proxy requests/s. This substantial variation prevents an isolated performance conclusion. Results include load-generator, Python/backend and shared-host effects; they are not production capacity numbers, a comparison against a baseline, or evidence of a performance improvement. Run longer repeated trials on an isolated target host, including default-info logging and multiple concurrency levels. Peak sampling can miss brief resource spikes. These checks do not replace allocator-fault injection, kernel fd-exhaustion experiments, a security audit or long-duration soak tests.

## Changed file inventory

Modified:

- `README.md`: updated phase status, CLI limits and operational links.
- `build.zig`: adds hardening integration and stress steps.
- `docs/architecture.md`: ownership, signal states and observability architecture.
- `src/main.zig`: validation-only command handling.
- `src/cli/commands.zig`: bounded numeric parsing, new flags and tests.
- `src/core/server.zig`: transfers listener ownership to the loop.
- `src/core/event_loop.zig`: signal integration, draining, deadlines, observations and cleanup.
- `src/core/connection.zig`: request limits, drain policy and observation state.
- `src/http/parser.zig`: ambiguous path and framing-nomination rejection.
- `src/proxy/proxy_config.zig`: prefix validation, segment matching and output limits.
- `src/proxy/upstream_connection.zig`: pending-output ceilings and response observations.

Added:

- `src/core/shutdown.zig`: signalfd ownership and shutdown state machine.
- `src/observability/logger.zig`: bounded, nonblocking pipe JSONL output.
- `src/observability/metrics.zig`: bounded operational counters.
- `tests/integration/hardening_test.py`: signal/drain/logging/configuration regression suite.
- `tools/stress.py`: reproducible local/proxy measurements and /proc sampling.
- `docs/production-hardening.md`: usage, defaults, security boundaries and limitations.
- `docs/phase4a-validation.md`: this validation record.

## Remaining boundaries and Phase 4B

Structured logs require a pipe collector and can be dropped; file/terminal sinks are intentionally unsupported. Request URLs and headers are omitted for privacy. Metrics share log delivery and filtering, have sum/max durations rather than histograms, and expose no HTTP endpoint. HTTP parsing stays intentionally limited: no request bodies, chunked responses, upgrade/tunnels or new protocols. Host validation remains lexical. Maximum configured pools can reserve large amounts of memory. Cross-compiled aarch64 behavior still needs runtime testing. There is no production-readiness claim.

Phase 4B should add a maintained TLS implementation with explicit nonblocking handshake/IO states, handshake resource/deadline limits, secure certificate loading/reload, TLS-aware graceful close and HTTPS forwarding metadata. Certificate/private-key handling and failure paths need dedicated tests and review; ACME and additional HTTP protocols should remain separate scopes.
