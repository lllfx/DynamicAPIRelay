# HTTP API Specification — v1

Status: **design; not an implemented endpoint**.

## 1. Request

~~~http
POST /v1/relay HTTP/1.1
Host: relay.example.com
X-Relay-Key: <RELAY_KEY>
X-Relay-Target: https://api.example.com/v1/messages?foo=bar
Authorization: Bearer <UPSTREAM_TOKEN>
Content-Type: application/json

{"message":"hello"}
~~~

| Field | Requirement |
| --- | --- |
| Relay URL | https://relay.example.com/v1/relay |
| HTTP method | Same as upstream method: GET, HEAD, POST, PUT, PATCH, DELETE |
| X-Relay-Key | Required; authenticates use of relay; confidential; stripped before upstream |
| X-Relay-Target | Required; absolute full upstream URL including path and query; stripped before upstream |
| Authorization, x-api-key, etc. | Optional upstream-only authentication; forwarded to validated target |
| Body | Zero or more raw bytes; streamed, not JSON-parsed or wrapped |
| Content-Type | Passed through as an end-to-end request header |
| Request path/query on /v1/relay | Exact path only; no extra query in v1 (all target query belongs inside X-Relay-Target) |

Mandatory target constraints in v1: HTTPS; DNS hostname (not IP literal); no username/password, fragment, control characters or invalid percent-encoding; port omitted or 443; destination must resolve and connect only to permitted public IP ranges. No target hostname registry is required to add a new public website.

For compatibility, reject duplicated or conflicting relay control headers, rather than choosing an arbitrary value. Establish an upper bound for target header length (e.g. 4 KiB). A request must not be allowed to override its upstream Host independent of X-Relay-Target.

## 2. Successful response

Return the **upstream HTTP status** (including normal 4xx/5xx from upstream), response body bytes and relevant response headers (Content-Type, Content-Encoding, Content-Disposition, ETag, etc.). Strip hop-by-hop and unsafe forwarding headers per HTTP semantics.

An upstream HTTP 401 is **not** a relay authentication failure. Distinguish relay-generated errors via the response header X-Relay-Error: true (or an equivalent unambiguous documented signal). The relay may include a generated X-Relay-Request-ID in both successful and failed responses.

Do not force every response into JSON; responses can be HTML, JSON, XML, text, image, PDF, ZIP, or streaming SSE. Respect HEAD responses without sending an entity body.

## 3. Relay-generated errors

Relay errors alone use JSON (illustrative):

~~~json
{
  "error": {
    "code": "TARGET_FORBIDDEN",
    "message": "Destination is not allowed",
    "request_id": "req_..."
  }
}
~~~

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | TARGET_INVALID / REQUEST_INVALID | Invalid or missing target, ambiguous path/header/query |
| 401 | AUTH_FAILED | Missing or invalid relay key; don't reveal which case |
| 403 | TARGET_FORBIDDEN | Disallowed scheme, host, port or destination IP |
| 405 | METHOD_NOT_ALLOWED | Unsupported method |
| 413 | REQUEST_TOO_LARGE | Size limit exceeded |
| 429 | RATE_LIMITED / CONCURRENCY_LIMITED | Per-key quota hit |
| 502 | UPSTREAM_CONNECT_FAILED / UPSTREAM_PROTOCOL_ERROR | Cannot safely reach upstream or invalid response |
| 504 | UPSTREAM_TIMEOUT | Connect or response-header timeout |

If status/headers have already been sent (e.g. mid-stream failure), a JSON error response is **not possible**; terminate the stream and log a sanitized failure.

## 4. Curl examples

**GET an arbitrary new domain without editing the relay:**

~~~bash
curl --fail-with-body 'https://relay.example.com/v1/relay' \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://api.github.com/users/octocat'
~~~

**JSON POST (upstream bearer token is distinct):**

~~~bash
curl 'https://relay.example.com/v1/relay' \
  -X POST \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://api.example.com/v1/chat' \
  -H 'Authorization: Bearer UPSTREAM_TOKEN' \
  -H 'Content-Type: application/json' \
  --data-binary '{"message":"hello"}'
~~~

**Multipart upload (do not handcraft Content-Type boundary):**

~~~bash
curl 'https://relay.example.com/v1/relay' \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://uploads.example.com/v1/files' \
  -F 'file=@./demo.pdf' -F 'purpose=review'
~~~

**SSE:**

~~~bash
curl -N 'https://relay.example.com/v1/relay' \
  -X POST \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://api.example.com/v1/stream' \
  -H 'Content-Type: application/json' \
  --data-binary '{"stream":true}'
~~~

**Binary download:**

~~~bash
curl 'https://relay.example.com/v1/relay' \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://files.example.com/releases/archive.zip' \
  -o archive.zip
~~~

Note: example.com hosts above are illustrative and do not promise a real API exists.

## 5. Redirects, cookies, browsers

- v1: do not follow upstream 301/302/303/307/308 internally. Return upstream response (including Location) to caller. Client must not blindly follow that Location directly if overseas URL is inaccessible; it can issue a **new** relay request to a validated target.
- A client-side HTTP library may auto-follow redirects: callers should disable auto-follow for v1.
- Raw Set-Cookie/Domain headers may not be usable in browser requests to relay.example.com; cookie rewriting is not in v1.
- Browser JavaScript may require an explicitly scoped CORS policy and cannot securely store a server-side relay key. Do not set Access-Control-Allow-Origin:* as a blanket fix.

## 6. Security invariants

- X-Relay-Key and all X-Relay-* control headers are never forwarded to an upstream.
- Authorization and other upstream credentials never appear in relay access logs.
- No request body parsing/transformation or HTML rewriting by default.
- No HTTP CONNECT or general-purpose TCP tunnel in v1.
- Destination checks happen at actual dial time, not just at URL parse time.
- A new permissible public HTTPS hostname can be used **without modifying server configuration**.

See [security](SECURITY.md) and [test plan](TEST_PLAN.md).
