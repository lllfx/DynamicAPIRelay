# DynamicAPIRelay

> A **dynamic, authenticated HTTPS API relay** built with Go + Gin, with a SQLite-backed per-key usage dashboard. **Status: v1 implemented** (see [Running](#running)).

## Goal

A client inside China calls a single HTTPS relay endpoint hosted on an overseas server, supplies the **full target URL at request time**, and receives the upstream HTTP response. Adding a new public API **must not require** changing relay code, configuration, or restarting the relay.

```text
Domestic client -- HTTPS + relay key + target URL --> Overseas Gin relay
       ^                   authenticate, validate target, connect safely |
       |                                                              |
       +-------------- upstream status/headers/body <--- Public HTTPS API
```

## Proposed contract (v1)

```http
POST /v1/relay HTTP/1.1
Host: relay.example.com
X-Relay-Key: <relay-secret>
X-Relay-Target: https://api.example.com/v1/messages?mode=test
Authorization: Bearer <upstream-secret>
Content-Type: application/json

{"hello":"world"}
```

- **`X-Relay-Key`** authenticates the caller to the relay and **MUST NOT** reach the upstream.
- **`X-Relay-Target`** is the complete HTTPS destination, including path and query; it **MUST NOT** reach the upstream.
- `Authorization` and other upstream-specific credentials are forwarded only to the validated destination.
- Forward the original HTTP method, request body (without JSON parsing), relevant end-to-end headers, and the upstream status, headers and response body.
- Supported first: GET, HEAD, POST, PUT, PATCH, DELETE; JSON, form, multipart, binary, downloads and SSE. WebSocket is a separate milestone; gRPC and arbitrary HTTP CONNECT are out of v1 scope.
- Initial policy: HTTPS on port 443 only, DNS hostnames only (no IP literals), public Internet destination IPs only. Authentication **does not** override SSRF restrictions.
- v1 does **not** follow redirects automatically. A 3xx `Location` is returned as received; clients must avoid following it directly if they require every hop to use the relay.

## Running

Requires Go 1.24+.

```bash
go build -o relay ./cmd/relay
RELAY_KEYS="client1:$(openssl rand -hex 32)" ./relay
```

- Relay listens on `127.0.0.1:8080`; put Caddy/NGINX in front for public TLS (see [`deploy/Caddyfile.example`](deploy/Caddyfile.example)).
- All settings are environment variables; see [`deploy/relay.env.example`](deploy/relay.env.example).
- `GET /healthz` is an unauthenticated liveness check.
- Logs are JSON on stdout and never contain relay keys, upstream credentials, or target paths/queries.

### Usage dashboard

Per-key request counts, bytes, error rates (relay errors vs. upstream 4xx/5xx vs. aborted streams; client cancels shown separately) and recent failed requests with request IDs.

- Stored in SQLite at `RELAY_STATS_DB` (default `./data/relay-stats.db`), retained `RELAY_STATS_RETENTION_DAYS` (default 30).
- Served on `127.0.0.1:8081` by default; open it through an SSH tunnel: `ssh -L 8081:127.0.0.1:8081 <server>` then browse `http://127.0.0.1:8081/`.
- Binding to a non-loopback address requires `RELAY_DASHBOARD_PASSWORD` (HTTP Basic, user `admin`). Set `RELAY_DASHBOARD_ADDR=` (empty) to disable it.

## Design documents

1. [Architecture & component boundaries](docs/ARCHITECTURE.md)
2. [HTTP API contract & examples](docs/API_SPEC.md)
3. [Security & threat model](docs/SECURITY.md)
4. [Usage dashboard design](docs/superpowers/specs/2026-11-18-usage-dashboard-design.md)
5. [Implementation plan](docs/superpowers/plans/2026-11-18-dynamic-api-relay-v1.md)

## Suggested technology

- Go, Gin for route/middleware; Go `net/http` + `httputil.ReverseProxy` for HTTP forwarding.
- A guarded `http.Transport` with connection-time destination-IP enforcement, strict TLS hostname verification, proxy-env disabled, connection pooling and timeouts.
- Caddy or NGINX for public HTTPS termination; container deployment after acceptance tests.
- JSON structured logs without secrets, basic metrics, per-key rate limits and concurrency quotas.

## Out of scope and caveats

This is an **HTTP API relay**, not a transparent VPN/browser proxy. Cookie domains, HTML resources, CORS, browser redirects and certain signature schemes may require extra adaptation. It cannot guarantee reachability of an upstream or permission to use that upstream. Hosting and usage must comply with applicable laws and service terms.

No credentials, API keys, or live endpoint secrets should be committed. See [SECURITY](docs/SECURITY.md).

## References

- [Go ReverseProxy docs](https://pkg.go.dev/net/http/httputil#ReverseProxy)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
