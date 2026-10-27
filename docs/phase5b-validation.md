# Phase 5B validation: automatic HTTPS / ACME v2

Validated on 2026-10-27 with Zig **0.15.2**, Fedora Linux **44**, OpenSSL **3.5.9**, libcurl **8.18.0** (OpenSSL, asynchronous DNS, thread-safe initialization), Python **3.14.8**, Linux x86_64. No public CA account/order was created, and no Git commit or push was made.

## Implementation summary

ACME is explicit opt-in, with separate staging/production selection and terms agreement. A single worker performs directory/nonce/account/order/authorization/finalization/download operations using OpenSSL ES256 and verified libcurl HTTPS. Directory-returned URLs remain on the exact configured origin; redirects, environment proxies and netrc are disabled. Automatic mode manages one SAN certificate for at most eight lowercase DNS names and cannot be mixed with manual certificate/SNI inputs.

HTTP-01 uses an eight-entry in-memory token table before proxy routing, not filesystem serving. Challenges expire monotonically and clear after validation/failure/cancellation. HTTP remains available during initial issuance; HTTPS connections close until a valid context exists. Normal TLS/manual CLI behavior remains available.

Issued chains undergo strict trusted X.509 verification, server-auth purpose, authentication level 2, exact SAN/key matching and effective validity checks. Keys use OpenSSL P-256; every issuance gets a fresh certificate key, while the account key persists. Renewal uses validity/jitter, optional RFC 9773 ARI windows/replaces, durable success/failure cooldowns and a pre-network restart guard. The event loop activates stored certificates through the existing two-generation TLS rotation with bounded busy retries.

Private fd-relative storage has an advisory exclusive lock, 0700 directories, 0600 generated files, no-follow traversal, regular-file/same-owner/single-link checks and atomic fsynced selectors. Three disk bundles keep committed and currently served files immutable during preparation, including expired/unactivated-candidate recovery. Account/selector state survives restart; partial inactive data is ignored.

See [ACME architecture, CLI and security details](acme.md).

## Dependencies and exact commands

The host has OpenSSL/libcurl runtimes but not the system development packages. Matching Fedora `libcurl-devel-8.18.0-14.fc44.x86_64` headers were downloaded and extracted into the existing `/tmp/ziggate-openssl-dev/usr` development prefix. No system package was installed. Native commands therefore use the supported `-Dopenssl-prefix` option; a normal Fedora host should install `openssl-devel libcurl-devel` and omit it. Build dependencies were not weakened or stubbed.

| Command | Result |
| --- | --- |
| `zig fmt --check .` | Passed |
| `git diff --check` | Passed |
| `python3 -m py_compile tests/integration/acme_test.py` | Passed |
| `zig build -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed, native Debug |
| `zig build test --summary all -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | **57/57 passed**, Debug |
| `zig build test --summary all -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | **57/57 passed**, ReleaseSafe |
| `zig build integration -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | All **seven suites** plus two Python fixture tests passed |
| `zig build integration -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | All seven suites plus Python fixture tests passed |
| `zig build acme-integration -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed independently |
| `zig build acme-integration -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Passed independently |
| `zig build -Doptimize=ReleaseSafe -Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr` | Native ReleaseSafe validated; restored after cross-build |

Native compiler/cache access and loopback sockets required sandbox escalation. The standard command forms without a prefix require the documented development packages; the prefix supplies genuine headers/linker files and preserves all features. No previous tests were removed or relaxed.

The seven suites are the existing HTTP, concurrency, proxy, Phase 4A hardening, Phase 4B TLS, Phase 5A TLS reliability suites, plus offline ACME. Existing output retains 32 HTTP response checks, 100 concurrent clients and 431 proxy checks. Both TLS-specific regression suites run in each integration build mode.

## Offline CA coverage

The default suite uses `tests/integration/acme_test.py`, a local HTTPS ACME test CA using only Python's standard library and OpenSSL CLI. It does not depend on external DNS, Docker, a public ACME service, Pebble installation or a third-party Python package. The fixture verifies the actual ES256 JWS with OpenSSL, independently constructs the account public key from JWK coordinates, consumes nonces once and verifies CSR signatures before issuing certificates.

Covered operations and regressions:

- Required directory endpoints, malformed/oversized JSON, exact-origin checking, redirect rejection and an unrelated API CA root rejected by HTTPS verification.
- JWK versus kid protected headers, URL binding, raw ES256 signature encoding, canonical thumbprints, POST-as-GET and bounded badNonce retries.
- Initial account registration; recovery of a lost account Location with the same persisted JWK; unchanged account key across renewal.
- Two-domain orders and HTTP-01 CA fetches through the real HTTP listener, with exact key authorization, proxy namespace precedence, unknown/removed-token rejection and parser traversal rejection. Unit tests cover expiry and bounded lookup.
- Real P-256 CSR signing, critical SAN handling, trusted certificate/key/SAN validation, rejection of a wrong certificate, and new certificate private keys on renewal.
- ARI suggested windows and `replaces`; certificate IDs are independently checked, including a serial number requiring a leading DER zero byte. Unit tests validate RFC 3339 calendars/offsets and fallback/backoff calculations.
- Verified automatically issued HTTPS for both SAN names and HTTPS-to-plaintext-HTTP proxying with sanitized `X-Forwarded-Proto: https`.
- Restart-driven renewal eligibility, failed renewal preserving the valid certificate, durable rate-limit/backoff state and later recovery. The fixture changes private renewal metadata to simulate due time; no production clock/verification bypass is added.
- Active sessions surviving certificate replacement. A gated order plus manual context rotation forces `TlsReloadBusy`; activation fails safely, old sessions remain usable and retry succeeds after the retired generation drains.
- Unsafe directory modes, path symlinks, account-key symlinks/hardlinks, private file modes and check-config without key generation/network requests.
- Interrupted temporary metadata and partial inactive-bundle writes: restart continues loading the committed complete generation, then safely replaces inactive material.
- Rate limiting with Retry-After, a real 15-second request timeout and normal HTTP progress during stalled ACME activity.
- Graceful cancellation of a stalled operation in less than five seconds on the test host; an immediate restart honors the durable pre-network guard instead of contacting the CA again.
- Final ACME metrics and absence of private-key markers in structured logs.

Certificate validity, renewal scheduling and storage are tested functionally; no 90-day wall-clock wait, power-cut fault injection or public issuance is implied. The fake CA is deliberately small and independently verifies core RFC wire/crypto behavior, but is not a replacement for interoperability testing with a production CA implementation.

## Findings resolved during implementation

Early compile checks caught Zig declaration shadowing. The first storage fixture used an O_PATH directory handle for chmod; it now opens a normal directory fd and sets private test permissions, without relaxing storage checks. The local CA initially serialized internal certificate bytes into JSON; those bytes are now excluded from order documents.

A verified TLS client rejected the initial CSR-derived certificate because an empty subject requires a critical SAN. CSR generation was corrected and strict issued-chain verification enabled; client verification was not weakened. Later audit added parent-directory fsync before selector commits, a third disk slot to preserve both selected/live bundles, entropy-error rollback rather than server panic, explicit curl/backend probing, and durable pre-network spacing to avoid restart-order loops. The final suites passed after these changes.

## aarch64 cross-compilation

Complete TLS/ACME-enabled executable cross-link passed:

```sh
zig build -Dtarget=aarch64-linux-gnu.2.38 -Doptimize=ReleaseSafe \
  -Dopenssl-prefix=/tmp/ziggate-openssl-aarch64-dev/usr
```

The target prefix contains genuine Fedora aarch64 OpenSSL libraries/configuration and architecture-neutral official libcurl headers staged under `include/curl`. No native x86_64 libraries were used in the target link. libcurl itself is dynamically resolved at automatic-mode startup, so the complete binary links without a target libcurl development symlink; ACME runtime still requires a compatible target `libcurl.so.4` and its dependencies.

`file` / `readelf` confirmed AArch64 ELF64, interpreter `/lib/ld-linux-aarch64.so.1`, and dependencies on libssl.so.3, libcrypto.so.3 and libc.so.6. ACME was not compiled out. The native ReleaseSafe binary was restored after this check.

**Phase 5B ACME runtime on aarch64 was not tested.** Previous Phase 5A QEMU runtime evidence remains valid for that phase but is not presented as ACME runtime coverage. Target OpenSSL-linked execution and target libcurl/CA-store compatibility need a new runtime test. No native aarch64 hardware was available.

## Storage, renewal and reload behavior

All development secrets were generated in temporary directories outside the repository. Production examples use private `/var/lib/ziggate/...` storage. The account key/URL are independent from certificate generations. Both a complete new bundle and its parent directory are synced before atomic state selection; unselected partial files do not become active. At most three disk bundles and two in-memory TLS generations are retained.

Scheduling state binds to the CA directory and ordered SAN set. Validity-based renewal uses two-thirds lifetime minus jitter; advertised usable ARI can supply a window. Backoff starts at 60 seconds, doubles to a bounded interval, adds jitter and honors longer Retry-After. A durable 60-second guard precedes a transaction, and successful issuance has minimum spacing to prevent short-window loops. Failed renewal preserves valid TLS material. Expiration warnings and counters are bounded operational observations, not delivery guarantees.

Activation is separate from stored-order success. Busy old contexts defer it with finite exponential retry groups and later re-publication, while active TLS sessions retain their contexts. Restart can load a committed validated candidate. The worker is cancelled and joined before its shared storage/state is destroyed; libcurl global state is cleaned after worker completion, while the dynamically loaded library mapping remains process-lifetime to avoid unloading beneath resolver internals.

## Complete modified/new file inventory

Added:

- `src/acme/config.zig`: explicit modes, domain/path validation and endpoint-origin restrictions.
- `src/acme/challenge.zig`: bounded memory-only HTTP-01 publication/expiry.
- `src/acme/crypto.zig`: OpenSSL key/JWK/CSR/validation wrappers and bounded JSON helpers.
- `src/acme/shim.c`, `src/acme/shim.h`: modern OpenSSL primitives, verified bounded libcurl transport and ABI probing.
- `src/acme/client.zig`: directory, nonce, JWS, POST-as-GET and problem/status handling.
- `src/acme/order.zig`: authorization, readiness/finalize/poll and certificate download.
- `src/acme/renewal.zig`: persisted schedule, jitter/backoff and safe bundle selection.
- `src/acme/ari.zig`: RFC 9773 identifiers/windows/rechecks/replaces support.
- `src/acme/storage.zig`: private fd-relative storage, atomic writes, locking and bundles.
- `src/acme/manager.zig`: worker lifecycle, account recovery, renewal orchestration and TLS activation.
- `tests/integration/acme_test.py`: independent offline HTTPS CA and lifecycle/security regressions.
- `docs/acme.md`: deployment, protocol, storage, limits, renewal and recovery documentation.
- `docs/phase5b-validation.md`: this record.

Modified:

- `build.zig`: ACME C shim/includes and separate/default integration test wiring.
- `src/cli/commands.zig`: explicit ACME flags, compatibility checks and tests.
- `src/main.zig`: no-network state preparation and manual/automatic TLS bootstrap.
- `src/core/server.zig`: optional manager ownership plumbing.
- `src/core/event_loop.zig`: worker startup/cancellation, metrics, activation and safe pending-TLS accepts.
- `src/core/connection.zig`: strict HTTP-01 namespace precedence and unit test.
- `src/tls/context.zig`: rotation with a separately prepared automatic certificate configuration.
- `src/observability/metrics.zig`: bounded ACME counters and expiration observation.
- `README.md`, `docs/tls.md`, `docs/architecture.md`: dependency, automatic HTTPS and lifecycle updates.

## Limitations and Phase 6

Public Let's Encrypt staging/production and Pebble were **not** contacted or tested. No public issuance, capacity benchmark, long-duration renewal soak, filesystem power-cut test or independent security audit is claimed. The local CA suite is passing evidence for the implemented subset, not production-readiness proof.

The initial client manages one SAN certificate/CA environment, has same-origin-only endpoints and local-loopback-only custom directories, and does not support EAB, revocation, account-key rollover, wildcard/DNS-01/TLS-ALPN-01 or multiple automated certificates. There is no new application protocol or upstream HTTPS proxying. HTTP remains enabled and there is no automatic redirect/HSTS policy.

Network calls/polling are bounded and cancellable outside epoll. Local filesystem stalls can still delay worker join, and TLS activation retains Phase 5A's synchronous bounded file-read behavior. OpenSSL/libcurl caches and trusted CA-store costs add to application buffers. Same-UID/root access to private storage remains trusted. Issuer roots for staging/private CAs require authenticated provisioning; verification is never disabled. ARI timestamps outside the supported RFC 3339 calendar range or invalid guidance fall back to validity scheduling. In-flight orders/CSR keys are not resumed after crashes, but persisted spacing prevents tight retries.

Phase 6 should first run Pebble and explicitly authorized public staging against real DNS/port-80 reachability, then perform storage fault injection and longer renewal/activation/restart tests. Native/target aarch64 ACME runtime, account-key backup/rotation, revocation/EAB, and a reviewed multi-certificate state model are useful later scopes. Any broader protocol or proxy expansion should remain separate from certificate lifecycle hardening.
