# Test Plan & Acceptance Matrix

**Design only.** These cases are to be implemented by the developer; no tests have been executed by this documentation commit.

## Test approach

- Unit tests for target parser, auth verifier, IP classification, header sanitization and configuration.
- Integration tests with Go httptest TLS servers, fake resolver / dialer and byte-by-byte capture. Avoid depending on live third-party APIs in CI.
- End-to-end smoke tests in a staging VPS with outbound private-network firewall restrictions.
- Fuzz target URL parser, hostname normalization and header edge cases.
- Record exact Go version, dependency versions, system/network configuration and test results.

## Contract tests

| ID | Input | Expected |
| --- | --- | --- |
| API-01 | New public hostname in X-Relay-Target | Routes without config change/restart |
| API-02 | GET with target path+query (including % escapes) | Correct upstream path and original valid query |
| API-03 | JSON POST with upstream Authorization | Body bytes preserved and Authorization reaches target |
| API-04 | Form-urlencoded and multipart | Fields, boundary and file bytes preserved |
| API-05 | Binary request + download (PDF/ZIP/image) | Checksum and Content-Disposition preserved |
| API-06 | HEAD | Status/headers, no response body |
| API-07 | Upstream 400/401/429/500 | Return **upstream** status/response, no relay-generated JSON wrapper |
| API-08 | Upstream 301/302/307/308 | Return 3xx+Location without server-side following |
| API-09 | Duplicate relay target headers | Reject ambiguity (400) |
| API-10 | Query attached to relay URL | Reject; target query belongs in X-Relay-Target |
| API-11 | CONNECT or TRACE | 405, no upstream connection |
| API-12 | Gzip/encoding, ETag, Range requests | Preserve correct HTTP semantics (no silent transform) |
| API-13 | URL with %2F, UTF-8, empty query | Canonicalization consistent; invalid escapes rejected |

## Authentication and SSRF tests

| ID | Attack / condition | Expected |
| --- | --- | --- |
| SEC-01 | Missing, invalid, expired, disabled relay key | Uniform 401; zero DNS and outbound connects |
| SEC-02 | Valid relay key + upstream Authorization | Relay key stripped; upstream auth preserved |
| SEC-03 | Public DNS target resolves to 127.0.0.1, 10.0.0.1, 192.168.0.1 or 169.254.169.254 | Denied, zero connection |
| SEC-04 | ::1, fc00::/7, fe80::/10, mapped private IPv4 | Denied |
| SEC-05 | IP literal or localhost; URL userinfo; alternate port; http:// | Denied |
| SEC-06 | Mixed DNS A/AAAA public and private | Fail closed |
| SEC-07 | DNS rebinding between validation and dial | Actual dial only to pinned validated public IP |
| SEC-08 | Public target issues Location to internal IP | Return redirect; no internal fetch |
| SEC-09 | Host/X-Forwarded-For/Forwarded spoofing | Override/sanitize, do not forward spoofable values |
| SEC-10 | HTTP_PROXY/HTTPS_PROXY set in process environment | Cannot bypass guarded transport |
| SEC-11 | Malformed URL, control chars, duplicate key/target headers, weird escapes | Reject before any dial |
| SEC-12 | Invalid upstream TLS certificate, hostname mismatch | Connection fails securely |
| SEC-13 | Missing/oversized request header, aggressive invalid-key guessing | Proper 4xx/429 and no uncontrolled work |
| SEC-14 | Public API requiring special signed request Host | Do not claim compatibility unless tested |

## Streaming, robustness and observability

| ID | Scenario | Expected |
| --- | --- | --- |
| STR-01 | SSE chunks emitted periodically | Chunks arrive promptly, no full buffering |
| STR-02 | SSE longer than ordinary request timeout | Stays alive under configured streaming policy |
| STR-03 | Client aborts mid-SSE or upload | Upstream context canceled; resources reclaimed |
| STR-04 | Large upload/download | Memory bounded, byte limits enforced |
| STR-05 | Too many in-flight requests | Deterministic 429/backpressure |
| STR-06 | Slow DNS/connect/TLS/response headers | Stage-specific timeouts and safe errors |
| STR-07 | Upstream error after streaming headers sent | Connection closes; no impossible JSON error after headers |
| STR-08 | Cancellation + concurrent load + -race | No data races, goroutine/FD leaks |
| OBS-01 | Inspect logs across success/failure | Request ID and sanitized host present; NO keys, auth headers, body, full target query |
| OBS-02 | Inspect error status distinction | Relay errors marked; upstream non-2xx not mislabeled |
| OPS-01 | Restart/rolling deployment | Graceful draining; no credential leak |
| OPS-02 | Public ingress/TLS + private app listener | TLS valid, internal listener not publicly exposed |
| OPS-03 | Verify outbound egress restriction from actual deployment | Metadata/private ranges blocked at network layer |

## Release gates

- **MVP P1**: all API-01..API-11 and SEC-01..SEC-12; extra parsing/security fuzz cases.
- **Production P2/P3**: all streaming, observability and operational cases, plus load/race testing.
- **P4 feature releases**: independent WebSocket / gRPC / redirect / multi-node matrices prior to claims of support.

Use dedicated controlled test domains and servers; never run SSRF probes against hosts you do not own. Record test evidence with CI links and commit SHAs.

Related: [API](API_SPEC.md), [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Implementation plan](IMPLEMENTATION_PLAN.md).
