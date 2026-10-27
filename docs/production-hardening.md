# Phase 4A operational notes

These notes describe the Phase 4A baseline. See [TLS/HTTPS](tls.md) for Phase 4B transport additions.

This phase adds operational safeguards; passing tests and a short loopback workload do not establish production readiness.

## Shutdown and ownership

SIGINT and SIGTERM are blocked and consumed through a nonblocking CLOEXEC Linux signalfd registered in epoll. There is no asynchronous signal handler. The loop processes signal readiness before listener readiness in each returned batch. Shutdown states are `running`, `draining`, and `forced`. The first signal closes the listener, disables accept retries, and starts a monotonic absolute grace deadline. Idle persistent sockets and accepted sockets with no consumed request bytes close promptly. Requests whose headers have begun, local writes, and proxy responses continue under their existing deadlines. New local responses advertise Connection: close. An already serialized response can still advertise keep-alive; its socket closes after that response. No further persistent request is dispatched while draining.

A second delivered termination signal forces closure, as does expiry of `--shutdown-ms`. Standard Linux signals can coalesce: two identical signals sent before either is consumed can appear as one. After observing `shutdown_begin`, another signal predictably forces shutdown. Scans and epoll waits bound scheduler granularity to about 50 ms, excluding OS scheduling delays. Grace is an upper bound, not an extension of existing request/upstream deadlines.

The event loop takes ownership of the listener even on initialization failure. Deferred cleanup releases linked upstreams before clients, frees both slot pools, closes epoll and signalfd, and restores the previous signal mask on error unwinding. Phase 5A retains blocked termination/reload signals during requested termination until process exit. Closing the listener during draining is tracked separately to prevent double close. Slot generation tokens reject stale epoll events.

## CLI additions

Existing commands continue to work, including `--proxy /home=127.0.0.1:3000`.

| Option | Default | Range and behavior |
| --- | --- | --- |
| `--shutdown-ms` | 10000 | 1–60000; absolute drain grace |
| `--request-ms` | 60000 | 1–60000; total active request lifetime, including headers, writes, proxying and backpressure |
| `--header-bytes` | 8192 | 1–8192 inclusive request header wire bytes |
| `--pending-output-bytes` | 16384 | 1024–16384; pending proxy output ceiling; local output remains bounded at 1024 |
| `--log-level` | info | debug, info, warn, error; minimum severity |
| `--check-config` | off | Parse/validate all arguments and exit without opening a listener |

All numeric arguments are unsigned decimal digits. Existing client/upstream counts, header and stage timeout defaults are listed in the README. Header/output limits constrain usable bytes, not preallocated capacity. Lowering pending output can reject reconstructed response headers plus initial body bytes with 502; select a cap large enough for the expected upstream headers. A total request deadline closes the socket without sending a replacement response; ordinary header and proxy stage deadlines retain 408/504 behavior. Total deadline checks occur at scheduler scans.

```sh
./zig-out/bin/ziggate --check-config --proxy /home=127.0.0.1:3000
./zig-out/bin/ziggate --shutdown-ms 15000 --request-ms 30000 \
  --header-bytes 4096 --pending-output-bytes 16384 \
  --max-connections 512 --max-upstreams 64 --log-level info \
  --proxy /home=127.0.0.1:3000
kill -TERM <pid>
```

## Logging and metrics

Use stderr connected to a pipe and a collector that drains it continuously:

```sh
./zig-out/bin/ziggate --log-level info 2>&1 | your-jsonl-collector
```

The logger reopens `/proc/self/fd/2` with O_NONBLOCK and CLOEXEC, preserving inherited stderr flags. Only FIFO/pipe sinks are supported. Regular files, terminals, inaccessible `/proc`, and other sink types disable structured output; use a pipe collector to write files or display logs. This deliberately avoids blocking storage/terminal writes on the event loop. CLI/startup errors retain ordinary stderr diagnostics.

Records use a numeric UTC Unix timestamp in milliseconds (`timestamp_unix_ms`), `level`, `event`, and a `data` object. Events cover startup, shutdown, request observations, proxy failures, capacity/accept failures, and metrics. `request_started` is debug-only. All variable fields use Zig's JSON serializer. Each record is at most 2048 bytes, below Linux PIPE_BUF; nonblocking pipe writes are atomic. A full/closed pipe, unavailable sink, or oversized record drops that record immediately, with a saturating dropped counter reported at shutdown if that record can be delivered. There is no log queue or per-request heap allocation. Zig's executable startup ignores SIGPIPE; socket sends additionally use MSG_NOSIGNAL.

Request observations include status, duration_ms, bytes_sent (wire bytes including headers), and configured upstream authority for proxy transactions. A status may be observed even if a later disconnect truncates the response; it does not certify full delivery. Durations run from accept for the first request, or first readiness/read for subsequent requests, through completion or closure. No methods, paths, query strings, headers, cookies, Authorization values, response bodies, or arbitrary error details are logged. This intentionally avoids secrets embedded in URLs as well as header credentials. Upstream authorities are validated numeric administrator configuration, never client-selected values.

Metrics are fixed-size, saturating, event-loop-owned counters emitted about once per second and after cleanup. They include active client and upstream sockets, parsed/dispatched requests (including parser error responses), observed 2xx/4xx/5xx statuses, proxy failures, capacity connection rejections, request duration sum/max, and monotonic uptime. Abandoned incomplete requests without a status do not contribute to request/response counts; timeout responses may contribute only to observed status counts. Active upstream socket count excludes completed upstreams whose output still occupies a slot. Metrics share logging's loss and level filtering policies; info filtering disables metrics output. No HTTP metrics endpoint is exposed. A collector can access internal numeric upstream addresses, so restrict access to its output. There are no route labels, histograms, persistence, or guaranteed delivery.

## Security boundaries

The parser continues to reject malformed headers, folding, duplicate Content-Length, every Transfer-Encoding, CL+TE ambiguity, controls, unsupported bodies and Expect. Connection nominations cannot hide Host or framing headers, including on internal routes. Upstream response validation and hop-by-hop filtering remain strict. Host is replaced by the configured authority and incoming forwarding metadata is replaced by socket peer information. No client can select an arbitrary upstream destination.

Routes match on segment boundaries: `/home` matches `/home` and `/home/x`, not `/homepage`; `/home/` retains its literal trailing-slash behavior. Longest nested prefixes are supported; exact duplicate prefixes are rejected. Configuration rejects repeated slashes, dot segments, percent escapes and backslashes in route prefixes. Request paths reject repeated slashes, dot segments, backslashes, malformed percent escapes, encoded separators/dots/percent/controls. Accepted targets are forwarded unchanged; queries do not participate in route selection. Routing is not an authorization mechanism, and backend interpretation of other accepted percent encodings remains the administrator's responsibility.

Memory is preallocated from bounded slot counts. Maximum settings can still reserve substantial memory (about 288 MiB clients plus 1.25 GiB upstream storage); validate capacity against deployment memory. Kernel socket buffers, fd quotas, process limits and allocator failure remain external constraints. A single event-loop thread scans bounded arrays; there is no rate limiter, multiworker isolation, TLS, or public-network security audit. `/health` and `/ready` remain unauthenticated on the bind address. Bind defaults to loopback.

## Verification and stress tooling

```sh
zig fmt --check .
zig build
zig build test --summary all
zig build integration
zig build -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
# Reinstall a native binary after cross-compiling:
zig build -Doptimize=ReleaseSafe
zig build stress -Doptimize=ReleaseSafe
# Override the bounded workload size when using an installed native binary:
python3 tools/stress.py ./zig-out/bin/ziggate --requests 10000 \
  --concurrency 64 --build-mode ReleaseSafe
```

The stress driver starts isolated gateway processes for local and proxy workloads. It reports hardware, build mode, request rate, p50/p95/p99 client-observed latency, payload throughput, and sampled Linux /proc RSS/fd peaks. Defaults are 2000 requests and 16 simultaneous clients. Local responses are 3 bytes and use keep-alive; proxy responses are 64 KiB and close each connection. A sequential Python backend and Python client threads share the host with the gateway. Sampling is every 10 ms and can miss short peaks. Errors fail the run; this is reproducible tooling, not a statistically rigorous benchmark or a standalone server capacity measurement. Logs are filtered to error in this workload; default-info logging cost requires separate measurement.

See [validation record](phase4a-validation.md) for measured results and the changed file inventory.

## Phase 4B

Design TLS transport ownership around the existing connection lifecycle; define nonblocking handshake/read/write states, handshake deadlines and memory limits. Choose a maintained TLS provider and certificate-loading/reload policy, test error paths and partial TLS IO, and extend graceful drain to TLS close notifications. Keep certificate secrets out of logs. HTTPS forwarding metadata must be derived from the actual transport. ACME, HTTP/2 and HTTP/3 need separate scoped designs and validation.

## Phase 5A TLS reliability additions

HTTPS now admits at most 128 unfinished handshakes by default (`--max-tls-handshakes`, range 1–32768), while preserving the global client limit. `--tls-handshake-timeout-ms` aliases the existing `--tls-handshake-ms`. A Session owns each permit until handshake success or cleanup; no counter decrement is tied solely to epoll readiness.

SIGHUP through signalfd reloads bounded regular-file certificate/key inputs into a separate generation. Successful validation switches new accepts atomically; active sessions keep the original default/SNI callback registry. At most two generations exist, and an occupied retired slot yields `TlsReloadBusy`. Missing/invalid/mismatched files preserve the current generation. Attempts are separated by one second and never queued; HUP is ignored while draining. File IO and OpenSSL validation are synchronous, so storage latency can delay the event loop. Termination retains the blocked signal mask until process exit to avoid late pending signals interrupting final cleanup.

Metrics add active handshakes, TLS admission rejections, reload outcomes and TLS closure errors. Fast sequential keep-alive requests completing in a single epoll dispatch now each record their response, correcting a counter gap found by the soak workload. Counters remain lossy operational observations through the pipe logger, not a billing/delivery guarantee.

Optional `zig build tls-load -Doptimize=ReleaseSafe` measures 16/64/128/256-client TLS 1.2/1.3 local/proxy workloads and resilience controls. `tools/tls_load.py --soak-seconds 300` (binary positional argument required) enables a separate five-minute soak; use 1800/7200 for longer runs. Drained RSS/fd trends are flagged for investigation, with cache warmup excluded. See [TLS operations](tls.md) and [validation, measurements and runtime status](phase5a-validation.md).
