# Architecture — DynamicAPIRelay

Status: **design proposal / not implemented**. Version: **v1**.

## 1. Goals

1. Overseas server exposes ONE stable HTTPS entrypoint. Domestic clients specify a new overseas API URL per request; no route registry, code change or restart.
2. Caller identity is verified with a relay-specific credential; upstream authentication remains separate.
3. Prefer HTTP semantic transparency: method, body bytes, content type, response status and body, headers needed by application; support large uploads/downloads and SSE without loading whole bodies in RAM.
4. Enforce SSRF safety and resource controls **even for authenticated clients**.
5. Keep request flow inspectable, testable and extensible in Go.

Non-goals for v1: browser/full website rewriting, arbitrary TCP or HTTP CONNECT tunneling, HTTP target origins, gRPC, transforming APIs into a unified AI protocol, bypassing upstream access policies.

## 2. Deployment

~~~text
App/CLI (domestic)
    -- TLS, X-Relay-Key, X-Relay-Target, original method/headers/body -->
Public HTTPS hostname / TLS reverse proxy (Caddy or NGINX)
    --> Gin server (private internal port)
         authentication, quotas, target policy, observability
         --> safeguarded Go http.Transport
              DNS resolve + per-connection public IP checks + TLS SNI verification
              --> arbitrary public HTTPS API on port 443
         <-- status + filtered end-to-end headers + raw response bytes
    <-- response
~~~

One overseas node is sufficient when domestic clients can connect to it. A domestic frontend is optional and **does not guarantee** cross-border reachability. Secure the internal Gin listener and prevent direct public access to management endpoints.

## 3. Components

| Component | Responsibility |
| --- | --- |
| ingress | TLS termination, request IDs, size/connection caps, trusted client IP policy |
| Gin router | Health endpoints and /v1/relay route; reject unsupported methods and ambiguous paths |
| auth | Validate X-Relay-Key using a constant-time mechanism; key ID for logging; rotation and revocation |
| policy | Parse exact target, canonicalize/check hostname and port, resolve A/AAAA, disallow unsafe destinations |
| limiter | Per-key rate, concurrency, request/response byte ceilings; backpressure and cancellation |
| relay | Use net/http/httputil.ReverseProxy with Rewrite and a shared configured Transport |
| transport | Disable ambient proxies; DNS/IP pinning at connection time, TLS hostname verification, timeouts, pooling |
| telemetry | Structured logs, counts, bytes, latency, target host only, failure category; never secrets |
| config | Env/YAML values for limits and security policy, not a mandatory list of destination sites |

Use shared/pooled http.Transport across requests; a small per-request ReverseProxy wrapper is acceptable. Do not allocate a new transport for each request.

## 4. Request lifecycle

1. Accept /v1/relay and validate method, path, headers, size limits.
2. Authenticate X-Relay-Key. Unauthenticated requests MUST terminate before DNS or network access.
3. Parse X-Relay-Target as an **absolute URL**; require https://, DNS hostname, port 443 or omitted port, no userinfo, fragment or ambiguous encoding. Request-target URL carries all upstream path/query bytes.
4. Apply domain policy and DNS checks, then safely dial **only** validated public IPs while preserving original hostname for Host/SNI/certificate verification.
5. Construct outbound request using original method and streaming body. Remove X-Relay-Key, X-Relay-Target, any relay control headers and spoofable forwarding headers; leave upstream Authorization intact.
6. Forward via guarded reverse proxy; do not append /v1/relay to the target path. Preserve RawPath/RawQuery when valid; avoid URL re-encoding that invalidates signatures.
7. Return upstream response status, valid end-to-end headers and bytes. No automatic redirect following in v1. Cancel upstream work if the client disconnects.
8. Log sanitized audit fields and release concurrency slots.

**Important Go detail:** ProxyRequest.SetURL joins target base path with inbound path; for a full per-request target use an explicit outbound URL replacement (on a request-owned URL), not accidental path joining. Prefer Rewrite instead of legacy Director. Explicitly set outbound Host to the destination host.

## 5. HTTP transport rules

- v1 methods: GET, HEAD, POST, PUT, PATCH, DELETE; disallow CONNECT and TRACE.
- Raw body streaming: no BindJSON/ShouldBind or io.ReadAll on untrusted request bodies; honor cancellation.
- JSON, XML, form, multipart, text and binary are content formats, not separate route handlers.
- Preserve end-to-end headers where safe; Go reverse proxy handles hop-by-hop headers and connection upgrades (upgrade itself not an accepted v1 feature).
- Do not inject Forwarded/X-Forwarded-* by default; do not pass inbound forwarding headers.
- Do not override Authorization intended for the upstream. Relay key NEVER reaches upstream.
- Avoid silent gzip decompression/recompression; negotiate/preserve Content-Encoding deliberately.
- For streaming responses, flush promptly and disable buffering at outer gateways.
- Explicitly define retry semantics: v1 has NO automatic application retry, particularly for non-idempotent POST.
- 3xx: return status and Location untouched; caller MUST NOT auto-follow directly if it wants the entire exchange relayed. Server-side safe redirect following is optional v2 (new destination validation per hop, max hops, credential stripping across origins, replay-safe bodies).
- Standard proxying is not equivalent to raw TCP transparency. Signed requests depending on literal Host or wire-level byte representation need separate compatibility tests.

## 6. Suggested initial operational values

These are *starting defaults*, not correctness guarantees:

| Control | Initial proposal |
| --- | --- |
| Listener | 127.0.0.1:8080 behind TLS proxy |
| Target | public DNS hostname, HTTPS, port 443 only |
| API key | >=32 bytes of random entropy, one key per client |
| Connect/TLS handshake timeout | 10s |
| Response header timeout | 60s (configurable per client/type) |
| Idle connection timeout | 90s |
| SSE | no short whole-response timeout; idle heartbeat policy; configurable max session |
| Request body | 100 MiB default, configurable by authenticated client |
| Response bytes | quota/cap with streaming enforcement; never buffer whole response |
| Per-key rate/concurrency | e.g. 30 req/s and 20 in-flight, configurable |

Streaming responses must not inherit a short global http.Client.Timeout. Set appropriate server header read limits and keep application body/stream duration policy separate.

## 7. Extension boundaries

- **Milestone 2**: per-client key management, usage stats, Redis-backed distributed quota, Prometheus.
- **Milestone 3**: WebSocket via a dedicated /v1/ws contract and HTTP Upgrade-aware tests (wss origin), client libraries and/or one-time auth for browsers.
- **Milestone 4**: multi-region relay nodes, routing preference and health probes; no changes to target-agnostic API contract.
- **Possible separate product**: a forward proxy with HTTP CONNECT/SOCKS (consider GOST); it is not the same as this HTTP relay.

## 8. Core references

- Go ReverseProxy: https://pkg.go.dev/net/http/httputil#ReverseProxy
- OWASP SSRF prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
