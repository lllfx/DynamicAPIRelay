# Implementation Plan (Go + Gin)

**Ownership:** Developer implements code. This document is the frozen starting specification, not code.

## Proposed directory structure (not created yet)

~~~text
DynamicAPIRelay/
  README.md
  docs/
    ARCHITECTURE.md
    API_SPEC.md
    SECURITY.md
    IMPLEMENTATION_PLAN.md
    TEST_PLAN.md
  cmd/relay/main.go
  internal/
    config/config.go
    httpserver/router.go
    auth/auth.go
    target/validator.go
    transport/safe_dialer.go
    relay/proxy.go
    limits/limiter.go
    telemetry/logging.go
  tests/
    integration/
  deployments/
    Dockerfile
    compose.yaml
    Caddyfile
  .env.example
  .github/workflows/ci.yml
~~~

## Phase P0 — contracts & infrastructure

- Select an actively supported Go version and pin dependencies. Enable gofmt, go vet, lint, dependency scanning and CI.
- Define Config and startup validation: listener, key verifier, max header/body/response bytes, concurrency, timeouts, target rules.
- Implement GET /healthz (liveness) and GET /readyz (readiness). Neither should leak credentials or detailed internal state.
- Use Gin for routing/middleware; secure public TLS with Caddy/NGINX. Private Gin listener behind ingress.
- Tests: no usable key at startup, missing limits, malformed config; health endpoints.

**Exit:** deterministic startup and configuration behavior; no relay exposed yet.

## Phase P1 — safe synchronous MVP

- Implement POST/GET/HEAD/PUT/PATCH/DELETE /v1/relay; reject CONNECT/TRACE, extra path and relay URL query.
- Authenticate relay keys **before** target DNS resolution.
- Validate exact target URL under the security policy; forbid special hosts, non-HTTPS, IP literals and non-443 ports.
- Implement DNS+connection-time IP validation/pinning with TLS SNI/cert validation preserved. No ProxyFromEnvironment.
- Implement httputil.ReverseProxy.Rewrite to use the **full target path/query** without joining /v1/relay. Strip X-Relay-* controls, scrub spoofable forwarded headers; preserve upstream Authorization.
- Stream response status, legitimate end-to-end headers and response bytes. Distinguish relay errors via X-Relay-Error header; handle upstream status even when non-2xx.
- No automatic redirect following, application-level retries or payload transformations.
- Tests: auth, target parsing, safe dialer, GET/POST, non-2xx, JSON/XML/form/binary, exact query/escapes and 3xx.

**Exit:** calling a new permissible public HTTPS hostname works without changing any server configuration.

## Phase P2 — streaming & resource protections

- SSE: immediate flushing, disable ingress response buffering, cancellations, no short global response timeout.
- Multipart upload + streamed binary downloads: bounded memory growth, size quotas and clear failure behavior.
- Per-key token bucket, concurrent request limit, global connection ceilings; header/body/response limits.
- Sanitize structured logs; request ID, key ID, method, upstream hostname, status, bytes and elapsed time.
- Tests for long SSE, slow upstream, client cancellation, 100 MiB upload (configurable), oversized requests, gzip passthrough, slowloris and exhausted quotas.

**Exit:** no uncontrolled memory growth under large bodies, and aborted requests free resources.

## Phase P3 — secure deployment

- Multi-stage container, unprivileged user, non-root filesystem where possible, read-only config, health checks.
- Docker Compose with explicit TLS front proxy and controlled listener exposure.
- GitHub Actions CI: go test ./..., go test -race ./..., lint, build and container smoke test.
- Operational docs: rotation, metrics, alerts, backup of non-secret configuration; rollback plan.
- Validate policy by probing from the actual overseas deployment environment, with firewall egress blocked to metadata/private networks.

**Exit:** all release-blocking checks in TEST_PLAN pass; no secrets in Git.

## Phase P4 — optional features after v1

- Dedicated WebSocket contract (/v1/ws); wss path resolution, Upgrade, ping/pong, keepalive, non-browser client auth, browser one-time tokens.
- Per-client database-backed key management, key scopes, revocation UI and Redis distributed quotas.
- Safe server-side redirects (if genuinely needed), tested across origin and body replay scenarios.
- Multi-node deployment, telemetry dashboard and region-aware routing.
- Separate HTTP CONNECT/SOCKS product if callers need unchanged original URLs rather than a relay endpoint.

## Design choices to retain

| Item | v1 decision | Rationale |
| --- | --- | --- |
| Target routing | X-Relay-Target full URL | Add site without relay change |
| Relay auth | X-Relay-Key | Does not conflict with upstream Authorization |
| Supported targets | HTTPS DNS hostname :443, public IP only | Smaller SSRF surface |
| HTTP proxy implementation | Go ReverseProxy + guarded Transport | Preserve HTTP semantics, reuse connections |
| Request & response body | Streaming raw bytes | JSON/form/files/SSE without adapters |
| Redirects | Do not follow | No hidden destination change or secret leakage |
| WebSocket | Not part of v1 acceptance | Needs dedicated upgrade/auth tests |
| gRPC | Deferred | HTTP/2/trailers require separate compatibility design |
| Logs | Redacted, per-request IDs | Auditable without leaking credentials |

## Definition of done

- Unit + integration + deployment security tests pass, including SSRF cases.
- New public target works without changing the relay.
- Relay-only secrets never reach upstream; upstream auth reaches only selected origin.
- No full-body buffering for file and SSE workflows.
- All error cases and redirect behavior match API_SPEC.md.
- Repository README accurately marks implementation and test status (not claimed before verified).
