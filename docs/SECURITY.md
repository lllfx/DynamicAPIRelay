# Security Design & Threat Model

**Status: design-only.** Dynamic destination routing is powerful; it can become a costly open proxy or an SSRF pivot. Relay authentication is necessary but **not sufficient**.

## Trust boundaries

- **Caller → relay**: untrusted public HTTPS requests, even when a key is valid.
- **Relay → DNS**: untrusted DNS answers (including rebinding and mixed public/private A/AAAA records).
- **Relay → upstream**: externally controlled servers and HTTP responses.
- **Relay → log/metrics**: never allow secrets or sensitive payloads into diagnostics.

## Mandatory v1 controls (block launch until tested)

### 1. Credentials

- Use a different secret for relay auth (**X-Relay-Key**) and upstream auth (e.g., **Authorization** or **x-api-key**).
- Generate relay keys from a CSPRNG with at least 256 bits of entropy; do not hardcode or commit secrets. Use secrets/environment injection or a secret manager.
- One credential per client. Store only a key identifier and a suitable verifier (e.g., keyed digest); compare fixed-length digests in constant time. Support expiration, revocation and overlap during rotation.
- Strip X-Relay-Key, X-Relay-Target and any reserved X-Relay-* request headers before connecting upstream.
- Do not log key, upstream Authorization, Cookie, request body, response body or full query strings.
- For browser clients, do not embed long-lived server relay keys in public JavaScript.

### 2. Validate destination before DNS

- Require exactly one target control header and a well-formed absolute https:// URL.
- v1: allow DNS hostname only; **disallow literal IPv4/IPv6**, URL userinfo, fragments, non-443 port, empty hostname, CR/LF/control characters, malformed escaping and ambiguous URL forms.
- Canonicalize IDN/hostname only via well-understood libraries and reject invalid DNS names. Treat localhost and similar special hostnames as forbidden.
- Avoid string-prefix matching or "contains example.com" checks for domains. A configurable **denylist** or per-key **allowlist** may add restrictions, but there is no central requirement to register every new public API.
- Never use the caller's supplied Host header as the upstream Host independently of X-Relay-Target.

### 3. Resolve and pin actual destination IP

- DNS may return private/reserved IPs or change answers between validation and connection.
- Reject all unsafe resolutions; check **every** A and AAAA candidate and never let fallback silently connect to an unvalidated address. Prefer fail-closed if any record is unsafe.
- Dial the vetted IP directly while keeping the original DNS hostname for outbound Host, TLS SNI and **normal certificate chain/hostname verification**; DO NOT use InsecureSkipVerify.
- Enforcement must happen on **every new connection** (including retries and HTTP/2 connections), not only before calling the reverse proxy.
- Public-IP checking requires more than IsGlobalUnicast: explicitly deny loopback, RFC1918, link-local, IPv4-mapped IPv6, ULA, multicast, unspecified, shared CGNAT, documentation, benchmarking, cloud metadata and other special-use/locally routed networks. Use a reviewed maintained IP policy or conservative allow strategy.
- HTTP_PROXY/HTTPS_PROXY environment variables must **not** silently redirect egress around the guard. Configure transport Proxy=nil unless an explicitly verified trusted upstream proxy is integrated.
- Defense in depth: outbound host firewall/cloud security group should deny internal, metadata and RFC1918 destinations, including IPv6.

### 4. Redirects and credential isolation

- **v1 must not automatically follow redirects.** Forward the 3xx + Location to the client and document caller follow policy.
- If server-side redirect following is introduced later, revalidate every new URL and IP, cap hop count, prevent HTTPS downgrade, strip Authorization/Cookie for cross-origin redirects, and only replay bodies when safe.
- Even with v1 no-follow, upstream may return Location pointing overseas; clients must avoid automatically following it outside the relay.

### 5. Resource abuse

- Bound request header bytes, target URL length, body bytes, active requests per key, new connections, active streams, and outbound response bytes.
- Apply per-key token-bucket limits and a global ceiling. Limit per-key concurrency separately from requests/sec.
- Set dial, TLS handshake, response-header and idle timeouts. Use a separate streaming policy for SSE; no short global whole-response timeout.
- Propagate client cancellation; implement graceful shutdown. Rate limit failed auth attempts and do not issue unlimited DNS requests.
- Avoid retries for non-idempotent methods. Circuit breakers only after clear expected semantics.
- Log request ID, key ID (not key), target host (not full URL), method, status, byte counts, duration, error category, and destination policy decision.

### 6. HTTP smuggling & header hygiene

- Never forward proxy-only hop-by-hop headers or spoofed Forwarded/X-Forwarded-*.
- Normalize/reject conflicting Content-Length and Transfer-Encoding framing according to Go HTTP parser rules; do not override framework-level safe parsing.
- Avoid decompression/recompression changing Content-Encoding or signed payloads; test compressed passthrough deliberately.
- Suppress server internals in error bodies. Strip unsafe headers only by a specified policy, not by guessing header names.
- Keep TLS verification enabled both domestic→relay and relay→upstream.
- Restrict incoming CORS origins if browser access is ever added. CORS is not authentication.

## Abuse matrix

| Attack | Mitigation / expected test |
| --- | --- |
| No or guessed key | Uniform 401; no DNS or upstream connection |
| Target 127.0.0.1, 10.0.0.1, ::1, 169.254.169.254 | Reject before connection |
| DNS name resolves public then private | Pin validated IP on dial; fail closed |
| CNAME or mixed A/AAAA records expose private IP | Reject candidate set |
| Public origin redirects to internal | Return 3xx only (v1); never auto-follow |
| Client sends upstream Authorization | Forward to **validated** selected origin only; redact from logs |
| Host or X-Forwarded-* spoofing | Replace Host with destination host; scrub forwarding headers |
| Massive upload/download or never-ending SSE | Configurable byte and duration caps, quotas, cancel propagation |
| Credential accidentally forwarded | Mock upstream asserts no X-Relay-* data |
| Authenticated user abuses public targets | Per-key quotas, optional destination policies, egress controls, monitoring |

## Explicit limitations

The service cannot prevent an authorized user from choosing a malicious **public** endpoint and knowingly sending an upstream token there. Strong per-client scope restrictions are recommended for multi-tenant use. No proxy design by itself guarantees that access to a service is allowed by that service's terms or applicable law.

**Sources:** [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [Go net/http](https://pkg.go.dev/net/http), [Go ReverseProxy](https://pkg.go.dev/net/http/httputil#ReverseProxy).
