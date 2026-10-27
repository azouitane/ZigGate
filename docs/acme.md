# Automatic HTTPS with ACME v2

Phase 5B adds explicit, opt-in ACME v2 account management, HTTP-01 validation, ECDSA P-256 certificate issuance and renewal. It uses OpenSSL for cryptography and an OpenSSL-backed libcurl for outbound HTTPS. The client runs in one cancellable worker; the epoll loop retains HTTP/TLS ownership and serves challenges from a bounded memory table.

This implementation has offline local-CA validation, not public Let's Encrypt operational validation or a production-readiness certification. See [executed checks](phase5b-validation.md).

## Dependencies

Zig **0.15.2**, OpenSSL **3.x**, and libcurl development headers are needed to build:

```sh
sudo dnf install openssl openssl-devel libcurl libcurl-devel python3
zig build
zig build test
zig build integration
zig build -Doptimize=ReleaseSafe
```

`libcurl.so.4` must be at least 7.85, use OpenSSL, and advertise asynchronous DNS and thread-safe global initialization. ACME startup/check-config probes those properties. HTTP-only and manual TLS operation do not load libcurl. The C shim uses official curl headers and dynamically loads its stable API; it does not invoke a curl/openssl executable at runtime. The test CA invokes OpenSSL CLI for independent verification and signing. Runtime network transfers always use HTTPS and HTTP/1.1.

This environment stages development files under `/tmp/ziggate-openssl-dev/usr`; builds use `-Dopenssl-prefix=/tmp/ziggate-openssl-dev/usr`. Such a prefix needs `include/openssl`, `include/curl` and OpenSSL linker files under `lib64`. This supplies build paths, not a runtime rpath. A normal Fedora installation can omit the option. See [validation](phase5b-validation.md) for the aarch64 target prefix and runtime limitations.

## Staging-first configuration

Automatic mode requires all of: explicit activation, domains, an email contact, a storage directory, a TLS listener, a selected environment and explicit acceptance of the CA's terms. Review the CA terms before supplying `--acme-accept-terms`; the program does not make that decision for the operator.

```sh
# Example service-user storage preparation; choose your actual user/group:
sudo install -d -m 700 -o ziggate -g ziggate /var/lib/ziggate/acme-staging

./zig-out/bin/ziggate --bind 0.0.0.0 --port 8080 \
  --tls-listen 0.0.0.0:8443 \
  --acme-enabled --acme-staging --acme-accept-terms \
  --acme-domain example.com --acme-domain www.example.com \
  --acme-email admin@example.com \
  --acme-storage /var/lib/ziggate/acme-staging \
  --acme-issuer-ca-file /etc/ziggate/letsencrypt-staging-roots.pem \
  --proxy /api=127.0.0.1:3000
```

Provision staging issuer roots through an authenticated, reviewed channel using [Let's Encrypt staging documentation](https://letsencrypt.org/docs/staging-environment/). They are intentionally absent from ordinary public trust stores. Keep this trust bundle dedicated to staging validation; do not add staging roots to ordinary browser/system trust. The staging **API connection** still verifies against the system HTTPS trust store; `--acme-issuer-ca-file` concerns the issued certificate chain, not the API connection. Staging certificates will normally be untrusted by browsers.

Production uses a separate explicit flag and separate storage/account:

```sh
./zig-out/bin/ziggate --bind 0.0.0.0 --port 8080 \
  --tls-listen 0.0.0.0:8443 \
  --acme-enabled --acme-production --acme-accept-terms \
  --acme-domain example.com --acme-email admin@example.com \
  --acme-storage /var/lib/ziggate/acme-production
```

No production issuance is selected by default. Neither example is run by tests or `--check-config`. Staging and production accounts are environment-scoped; storage metadata rejects directory/domain-set changes. Changing the configured SAN set/order currently requires separate storage and a new lifecycle, rather than silently reusing another certificate's state.

### Domain, networking and listener requirements

- Public HTTP-01 validation connects to **TCP port 80** at each domain's DNS address. A local listener on 8080 needs external port forwarding from 80, or run with a correctly provisioned port-80 capability. Merely configuring `--port 8080` does not change the CA's validation port. The program does not alter firewall, DNS or capabilities.
- Serve every configured domain through this instance's HTTP challenge route. IPv6 requires an external IPv6-capable front end forwarding to ZigGate's IPv4 listener; ZigGate itself remains IPv4-only. Incorrect AAAA records can break validation.
- The HTTPS listener is explicit; the example 8443 needs forwarding from 443 for conventional public HTTPS. There is no automatic redirect, HSTS insertion or privileged port binding.
- Before initial issuance, HTTP and normal proxy routes continue serving. HTTPS accepts close while no validated context exists; no bootstrap self-signed certificate or plaintext fallback is served.
- Health/readiness routes retain their existing unauthenticated exposure on the bind address. Readiness indicates listener service, not ACME completion. Inspect activation events/metrics and a verified TLS connection for certificate readiness.

| Option | Meaning |
| --- | --- |
| `--acme-enabled` | Explicit automatic-HTTPS activation |
| `--acme-domain DNS` | Repeat for 1–8 distinct lowercase ASCII DNS names; A-labels supported lexically; no wildcard/IP/single-label names |
| `--acme-email EMAIL` | Unquoted ASCII mail contact |
| `--acme-storage ABSOLUTE` | Private storage outside the source repository; no dot/empty path components |
| `--acme-accept-terms` | Operator's explicit CA terms agreement |
| `--acme-staging` | Let's Encrypt staging v2 directory |
| `--acme-production` | Let's Encrypt production v2 directory |
| `--acme-directory URL` | Custom test directory, restricted to HTTPS numeric 127.0.0.1 with an explicit port |
| `--acme-ca-file PEM` | Optional API HTTPS trust bundle; system trust by default |
| `--acme-issuer-ca-file PEM` | Additional trust for issued chains; system trust also loaded |

Local custom directories require both trust-file options. There is no HTTP-only/insecure test exception. Explicit trust files must be bounded regular PEM files; there is no skip-verification flag. Manual `--tls-cert`, `--tls-key` and `--tls-sni` entries are incompatible with automatic mode. One SAN certificate serves the automatic listener's default/SNI clients; it covers every configured domain. Normal manual TLS and HTTP-only commands are unchanged.

```sh
./zig-out/bin/ziggate --check-config \
  --tls-listen 127.0.0.1:9443 \
  --acme-enabled --acme-staging --acme-accept-terms \
  --acme-domain example.com --acme-email admin@example.com \
  --acme-storage /var/lib/ziggate/acme-staging \
  --acme-issuer-ca-file /etc/ziggate/letsencrypt-staging-roots.pem
```

Validation checks flags, secure storage/lock, available transport capabilities, explicit CA files and any existing account/certificate state. It may create the private directory and lock file. It performs no CA request, generates no account key and creates no order. Existing selected certificates are verified against persisted metadata; expired historical material can be inspected for recovery, but is not enabled as an initial HTTPS context.

## Architecture and bounded work

| Module | Responsibility |
| --- | --- |
| `config.zig` | Explicit modes, DNS names, URL origin restrictions |
| `client.zig` | Directory, nonce, ES256 JWS, POST-as-GET, bounded problem/status handling |
| `crypto.zig`, `shim.c/.h` | OpenSSL keys/JWK/thumbprint/CSR/chain verification and bounded libcurl transport |
| `order.zig` | Authorization, HTTP-01 acknowledgement, readiness/finalization/poll/download flow |
| `challenge.zig` | Eight in-memory token entries, short locked copies and monotonic expiry |
| `renewal.zig`, `ari.zig` | Validity/jitter/backoff and optional RFC 9773 guidance |
| `storage.zig` | fd-relative private files, locking, bundles and durable selector updates |
| `manager.zig` | Single worker, persisted scheduling, bounded publication and TLS activation retries |

Only one order/renewal is in progress for the certificate. The worker begins after signalfd signals are blocked and inherits that mask, including in resolver threads. Network calls, key generation, CSR work, certificate verification and storage writes occur in the worker. Shared state uses short mutex-protected copies and an atomic cancellation byte, with no logging or IO under those locks. Worker progress logs use a coalescing single-event slot; cumulative counters remain available.

Transfers enforce a 5-second connect timeout, 15-second total request timeout, 16 KiB aggregate response headers and 1 MiB body ceiling. JSON is limited to 64 KiB, nesting to 32, and duplicate fields are rejected. URLs are at most 2048 bytes. Each signed operation has at most three badNonce attempts including the first, consuming a nonce before sending. The transaction admits at most 256 HTTP calls and checks a ten-minute budget between operations; a last admitted transfer can take its bounded timeout. Authorization/order polling loops have separate finite iteration limits and respect Retry-After, including HTTP-date values. Long delays defer to the persisted scheduler rather than sleeping indefinitely inside an order.

libcurl uses verified HTTPS, hostname verification, HTTP/1.1, no redirects, no environment proxy, no netrc credentials and no verbose dumps. Paths are sent without dot-segment normalization so JWS URL and request target stay aligned. Every directory-returned endpoint, Location, account URL, challenge/finalize/order/certificate URL and ARI URL must have the **same exact HTTPS scheme/authority** as the configured directory. Cross-origin CAs, arbitrary remote custom directories and redirects are deliberately unsupported. No explanation/terms URL is fetched automatically. External-account-binding-required directories fail explicitly; EAB is not implemented.

The system API HTTPS trust and issued-chain trust are distinct. The latter uses OpenSSL's trust store, SSL-server purpose, strict X.509 checks, minimum authentication level 2, current validity, adjacent-chain consistency, private-key matching and **exact requested DNS SAN membership**, without CN/wildcard fallback. A new P-256 key is generated for every issuance; the account P-256 key remains stable. CSRs use a critical SAN with an empty subject. Chain length is at most 16, material at most 1 MiB, and the effective validity intersects supplied chain validity. New material must remain usable for more than 60 seconds; excessive leaf lifetimes over 398 days are rejected.

## HTTP-01

Automatic mode reserves exactly `/.well-known/acme-challenge/` and its token suffix before proxy selection. GET/HEAD return only the published key authorization, with normal strict HTTP framing and request/header limits. Unknown, malformed, extra-segment or query-bearing tokens return 404; ordinary parsing may reject traversal before dispatch. Other methods receive the existing method/error semantics. Paths outside this namespace retain normal routing. The shared HTTP engine also serves this public token route over HTTPS once available, but CA validation uses HTTP port 80.

Tokens are base64url characters only, 22–128 bytes. Key authorization is `token.account-key-thumbprint`, never a file path. Entries expire after at most ten monotonic minutes, are removed after validation, and are cleared on failure/cancellation. The table can hold eight entries; this initial order flow validates authorizations serially. There is no challenge directory, arbitrary file serving or account-key exposure.

## Storage and crash recovery

Use a dedicated directory outside the repository, owned by the service's effective UID with mode **0700**. Existing unsafe/unwritable modes fail rather than being silently changed. Path components are opened relative to owned fds with directory/no-follow semantics. Files must be regular, same-owner, single-link and inaccessible to group/others; generated files use **0600**. Symlink and hardlink account/state attacks fail. A nonblocking exclusive flock prevents cooperating processes from sharing the same lifecycle storage.

```text
/var/lib/ziggate/acme-staging/       0700
├── lock                           0600, process lock
├── account.key                    0600, persistent P-256 key
├── account.json                   0600, account URL + directory binding
├── state.json                     0600, bundle selector + validity/renewal/backoff
├── bundle0/                       0700
│   ├── key.pem                    0600
│   └── chain.pem                  0600
├── bundle1/                       0700
└── bundle2/                       0700
```

There are at most three certificate bundles. A new issuance never overwrites the selected committed bundle or the bundle currently served by TLS; a third slot handles delayed/expired candidates while an older valid context remains active. The previous complete material remains available until a later safe replacement. Old TLS sessions already own their OpenSSL objects and do not read key files again.

A new bundle is fully validated, written privately, and file/directory/parent-synced before `state.json` selects it. Metadata/account replacement uses an exclusive private `.temporary`, file fsync, rename and directory fsync. The selector is the commit boundary; partial inactive bundles and interrupted temporary files are ignored on restart. The next transaction safely rewrites an inactive slot. There is no unbounded archive of account or certificate keys.

These barriers rely on local filesystem fsync/rename/flock semantics. No power-cut or disk-fault testing has been performed. Same-UID/root processes can alter their own private storage and remain trusted; this is not isolation from a compromised service account. Do not remove lock/state files while running. Back up account keys securely. If account Location metadata is lost, registration with the same JWK recovers the existing account; missing account keys with existing account metadata fail safely and require restoration, not silent replacement.

## Renewal and activation

Without usable ARI, eligibility is around two-thirds of the effective certificate lifetime, with up to five percent of lifetime subtracted as OpenSSL-generated jitter. If the directory advertises `renewalInfo`, the client derives RFC 9773 certificate IDs (including DER serial padding), fetches a same-origin suggested window, selects a random instant within a valid window and sends `replaces` on renewal orders. Unsupported/malformed/out-of-validity windows fall back to the validity schedule. RFC 3339 UTC/numeric-offset timestamps and fractional seconds are supported within 1970–2100; unsupported leap seconds fall back safely.

ARI rechecks persist their deadline and honor Retry-After with a minimum one-hour interval; absent guidance defaults to daily checks. A new successful issuance imposes at least 60 seconds and at most one hour of minimum order spacing (one-tenth lifetime, capped), preventing repeated short-window renewal loops. This cooldown is persisted. Failed operations preserve the active certificate, increment a bounded failure count, and retry after exponential intervals starting at 60 seconds up to 61,440 seconds, plus 0–29 seconds of jitter, or a longer Retry-After. A 60-second restart guard is durably saved before each new network transaction, so a crash/cancellation mid-order does not cause immediate repeated orders on restart. In-flight orders/CSR keys are not resumed; a later bounded retry creates a new order. Backoff has a monotonic in-process lower bound as well as persisted wall-clock state. Wall time is used for certificate dates; clock correctness is a deployment requirement.

A newly stored certificate is published to the epoll loop for the existing two-generation TLS rotation. Active sessions retain old contexts. `TlsReloadBusy` and other activation failures use exponential retries capped at 60 seconds, at most eight attempts per roughly 30-minute publication cycle. No new issuance overlaps an unactivated valid candidate. The selected bundle is already durable; restarting can load it directly. Expired candidates are not activated. Three storage slots preserve both selected and currently served material if renewal must recover after candidate expiry.

Warnings repeat at most hourly when the active certificate has less than seven days remaining. Renewal failure never intentionally replaces a valid certificate with an invalid one. An expired certificate may still be the only historical material; startup keeps HTTPS unavailable until replacement, while HTTP remains available. A persistent storage/trust/account error requires operator repair; rate-limit/backoff state is not discarded by restarting.

SIGHUP retains its manual-TLS context reload meaning; it is not an ACME issuance/rate-limit bypass. Automatic activation occurs independently. An operator should restore prerequisites and allow scheduled retry, or restart to load an already committed valid candidate. Do not delete account/backoff state to evade CA rate limits.

## Shutdown and observability

First SIGINT/SIGTERM cancels ACME work immediately while existing HTTP/TLS drain semantics remain. libcurl progress checks and short worker waits observe cancellation. The worker is joined before manager/storage destruction, avoiding detached threads referencing freed state. Pending challenges are cleared. Tests verify ordinary stalled-network cancellation within five seconds. Unresponsive local storage can still delay filesystem work and worker join; no hard shutdown guarantee is claimed for filesystem stalls. TLS activation uses the existing synchronous bounded PEM reload, which also has the Phase 5A filesystem responsiveness limitation.

JSONL remains bounded, pipe-only and lossy. Events include `acme_failure`, `acme_certificate_stored`, `acme_certificate_activated`, `acme_activation_failed` and `acme_expiration_warning`. Reasons are fixed error categories, not raw CA problems, JWS payloads, account URLs, keys, contacts or certificate contents. Coalescing can omit intermediate worker events.

Metrics add account-registration attempts, stored order successes/failures, validated authorizations/failures, renewal successes/failures, rate-limit responses/problems, activation failures and whole days until active effective expiration (`-1` when unavailable). Order success means validated and stored, not proof of TLS activation. Renewal successes are a subset of order successes. Cancellation can contribute challenge-failure observations. Counters reset on restart and share logging's delivery limits; durable scheduling state is separate.

## Offline tests and limits

```sh
zig build acme-integration
zig build acme-integration -Doptimize=ReleaseSafe
zig build integration
```

The local test CA uses verified loopback HTTPS and OpenSSL CLI to independently verify ES256 JWS, construct public keys from JWKs, verify CSR signatures and issue SAN certificates. It exercises real HTTP-01 fetches, fresh/bad nonces, account recovery, ARI IDs including leading serial padding, issuance, restart-driven renewal eligibility, failed renewal recovery, active TLS sessions, busy generation activation, malformed/oversized/cross-origin/redirect/rate-limited responses, real network timeout, cancellation and storage attacks/interruption. No public CA, container, third-party Python module or external DNS is used. Renewal eligibility is simulated through private fixture metadata, not a production verification bypass. See the validation record for executed results.

Pebble and public staging have **not** been run. Next operational checks should use Pebble, then explicitly authorized Let's Encrypt staging with real DNS/port-80 reachability, followed by failure-injection and longer lifecycle testing. No DNS-01, TLS-ALPN-01, ACME revocation/key rollover/EAB, multi-certificate automation, wildcard names, HTTP/2/3, QUIC, WebSockets or upstream HTTPS proxying is implemented. Certificate/account state is bound to one configured SAN set and one CA environment. Same-origin-only endpoints deliberately exclude federated/cross-origin CAs. No production-capacity or production-readiness claim is made.

References: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555), [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html), [libcurl verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html), and [OpenSSL signing](https://docs.openssl.org/3.5/man3/EVP_DigestSignInit/).
