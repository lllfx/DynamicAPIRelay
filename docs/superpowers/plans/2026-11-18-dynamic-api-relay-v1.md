# DynamicAPIRelay v1 实现方案

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 Go + Gin 实现 `POST|GET|… /v1/relay`：鉴权后按请求头 `X-Relay-Target` 把原始请求流式转发到任意公网 HTTPS API，并原样返回上游响应，同时在拨号时强制 SSRF 防护。

**Architecture:** Gin 只负责路由与中间件（请求 ID、访问日志、恢复、精确路径、鉴权、限流）；转发核心是一个共享的 `httputil.ReverseProxy`（`Rewrite` 模式）+ 一个共享的受保护 `http.Transport`。目标 URL 校验（解析期）与目标 IP 校验（拨号期，`DialContext` + `net.Dialer.Control` 双重检查）分属两个包。所有 relay 自身错误统一为 JSON + `X-Relay-Error: true`。

**Tech Stack:** Go 1.24（本机 go1.24.13），`github.com/gin-gonic/gin v1.10.1`，`golang.org/x/time v0.15.0`（`rate`），标准库 `net/http`、`net/http/httputil`、`net/netip`、`log/slog`、`crypto/subtle`。

**Spec:** `README.md`、`docs/ARCHITECTURE.md`、`docs/API_SPEC.md`。（README 引用的 `docs/SECURITY.md`、`docs/IMPLEMENTATION_PLAN.md`、`docs/TEST_PLAN.md` 仓库中不存在；本方案以前三份为准。）

## Global Constraints

- Module 路径：`github.com/lllfx/DynamicAPIRelay`（取自 git remote）。代码放 `internal/`，入口 `cmd/relay/`。
- 方法白名单：GET, HEAD, POST, PUT, PATCH, DELETE；CONNECT、TRACE 及其他方法 → 405 `METHOD_NOT_ALLOWED`。
- 目标约束：`https`；DNS 主机名（禁止 IP 字面量）；无 userinfo、fragment、控制字符、非法百分号编码；端口省略或 `443`；`X-Relay-Target` 长度上限 4096 字节；重复的 relay 控制头 → 400。
- 只能连接公网 IP；鉴权**不**豁免 SSRF 规则；未鉴权请求在任何 DNS/网络访问前终止。
- `X-Relay-Key`、`X-Relay-Target` 及所有 `X-Relay-*` 头永不发往上游；入站 `Forwarded`/`X-Forwarded-*`/`X-Real-IP`/`Via` 等转发头不透传、不注入。
- 上游 `Authorization`、`x-api-key` 等原样透传；它们与 relay key、目标 query 永不进日志。
- 请求体流式转发：禁止 `BindJSON`/`ShouldBind`/`io.ReadAll` 读取不可信请求体；不解压/不重压缩（`DisableCompression: true`）。
- 不自动跟随重定向；无自动重试；客户端断开即取消上游。
- Transport：`Proxy: nil`（禁用代理环境变量）、TLS 最低 1.2 且校验主机名、共享连接池；**不设** `http.Client.Timeout`。
- 默认值：监听 `127.0.0.1:8080`；拨号 10s；TLS 握手 10s；响应头 60s；空闲连接 90s；请求体 100 MiB（104857600）；每 key 30 req/s、20 并发；relay key ≥ 32 字节。
- 错误表（状态码/错误码）严格按 `API_SPEC.md §3`；唯一扩展：未知路径 → 404 `NOT_FOUND`，未预期 panic → 500 `INTERNAL_ERROR`。
- 每个响应（成功或失败）都带 relay 生成的 `X-Relay-Request-ID`（格式 `req_` + 32 位小写十六进制），不信任入站同名头。

## Review Focus

1. **DNS 返回公私混合地址**（如 A 记录同时含 `10.0.0.1` 与公网地址，或 DNS rebinding）——只拨号允许的地址；全部不允许时返回 403。→ Task 5 `TestAllowedAddrsFiltersMixed`、`TestDialRejectsPrivateResolution`。
2. **上游伪造 `X-Relay-Error` / `X-Relay-Request-ID` 响应头**——必须剥除，否则客户端会把上游响应误判为 relay 错误。→ Task 7 `TestUpstreamRelayHeadersStripped`。
3. **流式响应中途失败**（响应上限超出、上游断流）——Gin Recovery 不得写 500 或打栈，连接应被中止。→ Task 8 `TestMidStreamAbortNoStackTrace`。
4. **带签名的 URL 编码**（路径中的 `%2F`、query 中的 `+`/`%20`）——必须逐字节到达上游。→ Task 7 `TestRawPathAndQueryPreserved`。
5. **SSE 进行中客户端断开**——上游被取消且并发槽释放，否则一个 key 会被“泄漏”的连接锁死。→ Task 8 `TestClientDisconnectReleasesSlot`。

---

## 文件结构

```
go.mod / go.sum
cmd/relay/main.go                 进程入口、优雅关闭
internal/relayerr/relayerr.go     错误码、状态码映射、JSON 错误写出、请求 ID 生成
internal/reqctx/reqctx.go         请求级可变信息 *Info 的 context 存取
internal/config/config.go         从环境变量加载配置
internal/auth/keystore.go         常量时间 key 校验，返回 key ID
internal/policy/target.go         X-Relay-Target 解析与校验（解析期）
internal/netguard/netguard.go     公网 IP 判定
internal/transport/transport.go   受保护的 http.Transport（拨号期校验）
internal/limiter/limiter.go       每 key 速率 + 并发
internal/relay/handler.go         ReverseProxy 核心、头过滤、响应上限、错误分类
internal/relaytest/relaytest.go   测试辅助：TLS 上游 + 映射解析器
internal/server/router.go         Gin 路由与中间件
internal/server/logging.go        访问日志中间件
deploy/Caddyfile.example, deploy/relay.env.example
```

---

### Task 1: 工程脚手架 + relayerr + reqctx

**Files:**
- Create: `go.mod`, `internal/relayerr/relayerr.go`, `internal/reqctx/reqctx.go`
- Test: `internal/relayerr/relayerr_test.go`, `internal/reqctx/reqctx_test.go`

**Interfaces:**
- Produces:
  - `type relayerr.Code string`，常量：`TargetInvalid="TARGET_INVALID"`, `RequestInvalid="REQUEST_INVALID"`, `AuthFailed="AUTH_FAILED"`, `TargetForbidden="TARGET_FORBIDDEN"`, `MethodNotAllowed="METHOD_NOT_ALLOWED"`, `RequestTooLarge="REQUEST_TOO_LARGE"`, `RateLimited="RATE_LIMITED"`, `ConcurrencyLimited="CONCURRENCY_LIMITED"`, `UpstreamConnectFailed="UPSTREAM_CONNECT_FAILED"`, `UpstreamProtocolError="UPSTREAM_PROTOCOL_ERROR"`, `UpstreamTimeout="UPSTREAM_TIMEOUT"`, `NotFound="NOT_FOUND"`, `Internal="INTERNAL_ERROR"`
  - `func (c Code) Status() int`
  - `type Error struct{ Code Code; Message string }`，实现 `error`；`func New(c Code) *Error`（Message 取固定默认文案，不含任何请求细节）
  - `func Write(w http.ResponseWriter, requestID string, e *Error)`
  - `const HeaderError = "X-Relay-Error"`, `HeaderRequestID = "X-Relay-Request-ID"`
  - `func NewRequestID() string`
  - `type reqctx.Info struct{ RequestID, KeyID, TargetHost string; ErrorCode relayerr.Code }`；`func reqctx.With(ctx context.Context, info *Info) context.Context`；`func reqctx.From(ctx context.Context) *Info`（不存在时返回非 nil 的空 `*Info`，调用方无需判空）

- [ ] **Step 1: 初始化模块**

Run: `go mod init github.com/lllfx/DynamicAPIRelay && go get github.com/gin-gonic/gin@v1.10.1 golang.org/x/time@v0.15.0`

- [ ] **Step 2: 写失败测试**

```go
func TestCodeStatus(t *testing.T) {
	cases := map[relayerr.Code]int{
		relayerr.TargetInvalid: 400, relayerr.RequestInvalid: 400, relayerr.AuthFailed: 401,
		relayerr.TargetForbidden: 403, relayerr.NotFound: 404, relayerr.MethodNotAllowed: 405,
		relayerr.RequestTooLarge: 413, relayerr.RateLimited: 429, relayerr.ConcurrencyLimited: 429,
		relayerr.Internal: 500, relayerr.UpstreamConnectFailed: 502, relayerr.UpstreamProtocolError: 502,
		relayerr.UpstreamTimeout: 504,
	}
	for c, want := range cases { if got := c.Status(); got != want { t.Errorf("%s: %d != %d", c, got, want) } }
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	relayerr.Write(rec, "req_abc", relayerr.New(relayerr.TargetForbidden))
	// 断言：rec.Code==403；Header X-Relay-Error=="true"；X-Relay-Request-ID=="req_abc"；
	// Content-Type=="application/json; charset=utf-8"；Cache-Control=="no-store"；
	// body JSON 等于 {"error":{"code":"TARGET_FORBIDDEN","message":"Destination is not allowed","request_id":"req_abc"}}
}

func TestNewRequestID(t *testing.T) {
	a, b := relayerr.NewRequestID(), relayerr.NewRequestID()
	// 断言：两者都匹配 ^req_[0-9a-f]{32}$ 且 a != b
}

func TestReqctxFromMissingReturnsEmpty(t *testing.T) {
	info := reqctx.From(context.Background())
	// 断言 info != nil；并且 With 之后 From 返回同一指针
}
```

`TargetForbidden` 的默认文案固定为 `"Destination is not allowed"`；`AuthFailed` 为 `"Relay authentication failed"`（不区分缺失/错误）；其余码各取一句不含变量的英文短句。

- [ ] **Step 3: 运行确认失败** — `go test ./internal/...`，Expected: 编译失败（未定义）。
- [ ] **Step 4: 实现** `relayerr`（`NewRequestID` 用 `crypto/rand` 读 16 字节 + `hex`）与 `reqctx`（私有 key 类型）。
- [ ] **Step 5: 运行确认通过** — `go test ./internal/... -v`，Expected: PASS。
- [ ] **Step 6: Commit** — `git add go.mod go.sum internal && git commit -m "feat: add relay error codes and request context"`

---

### Task 2: config

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:
```go
type Config struct {
	ListenAddr            string            // RELAY_LISTEN_ADDR, 默认 "127.0.0.1:8080"
	Keys                  map[string]string // RELAY_KEYS, 必填, keyID -> secret
	MaxRequestBytes       int64             // RELAY_MAX_REQUEST_BYTES, 默认 104857600
	MaxResponseBytes      int64             // RELAY_MAX_RESPONSE_BYTES, 默认 0（不限制）
	RatePerSec            float64           // RELAY_RATE_PER_SEC, 默认 30
	RateBurst             int               // RELAY_RATE_BURST, 默认 30
	MaxConcurrent         int               // RELAY_MAX_CONCURRENT, 默认 20
	DialTimeout           time.Duration     // RELAY_DIAL_TIMEOUT, 默认 10s
	TLSHandshakeTimeout   time.Duration     // RELAY_TLS_HANDSHAKE_TIMEOUT, 默认 10s
	ResponseHeaderTimeout time.Duration     // RELAY_RESPONSE_HEADER_TIMEOUT, 默认 60s
	IdleConnTimeout       time.Duration     // RELAY_IDLE_CONN_TIMEOUT, 默认 90s
	MaxRequestDuration    time.Duration     // RELAY_MAX_REQUEST_DURATION, 默认 0（不限制；SSE 会话上限）
	ReadHeaderTimeout     time.Duration     // RELAY_READ_HEADER_TIMEOUT, 默认 10s
}
func Load(lookup func(string) (string, bool)) (Config, error) // main 中传 os.LookupEnv
```

`RELAY_KEYS` 格式：`id1:secret1,id2:secret2`，按第一个 `:` 切分；keyID 必须匹配 `^[A-Za-z0-9_-]{1,64}$`；secret ≥ 32 字节；keyID 或 secret 重复均报错。时长用 `time.ParseDuration`，数值必须 ≥ 0（`RatePerSec`、`RateBurst`、`MaxConcurrent`、`MaxRequestBytes` 必须 > 0）。错误信息不得包含 secret 内容。目标端口固定 443，**不**暴露为配置项。

- [ ] **Step 1: 写失败测试**

```go
func env(m map[string]string) func(string) (string, bool) { return func(k string) (string, bool) { v, ok := m[k]; return v, ok } }
const secret = "0123456789abcdef0123456789abcdef" // 32 字节

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"RELAY_KEYS": "alice:" + secret}))
	// 断言 err==nil；ListenAddr=="127.0.0.1:8080"；MaxRequestBytes==104857600；RatePerSec==30；
	// MaxConcurrent==20；DialTimeout==10s；ResponseHeaderTimeout==60s；IdleConnTimeout==90s；Keys["alice"]==secret
}

func TestLoadRejects(t *testing.T) {
	for name, keys := range map[string]string{
		"missing":   "",
		"short":     "alice:short",
		"badID":     "al ice:" + secret,
		"dupID":     "a:" + secret + ",a:" + secret + "x",
		"dupSecret": "a:" + secret + ",b:" + secret,
	} {
		_, err := config.Load(env(map[string]string{"RELAY_KEYS": keys}))
		// 断言 err != nil，且 err.Error() 不包含 secret
	}
	// 另：RELAY_MAX_CONCURRENT=0、RELAY_DIAL_TIMEOUT=abc 均报错
}
```

- [ ] **Step 2: 运行确认失败** — `go test ./internal/config/`
- [ ] **Step 3: 实现 `Load`**
- [ ] **Step 4: 运行确认通过** — `go test ./internal/config/ -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: load relay config from environment"`

---

### Task 3: auth KeyStore

**Files:**
- Create: `internal/auth/keystore.go`
- Test: `internal/auth/keystore_test.go`

**Interfaces:**
- Consumes: `config.Config.Keys`
- Produces: `func NewKeyStore(keys map[string]string) *KeyStore`；`func (s *KeyStore) Authenticate(presented string) (keyID string, ok bool)`

实现：构造时只保存每个 secret 的 SHA-256；校验时对 presented 做 SHA-256，用 `subtle.ConstantTimeCompare` 与**全部**存储哈希比较（不提前退出），命中时记录 keyID。

- [ ] **Step 1: 写失败测试**

```go
func TestAuthenticate(t *testing.T) {
	s := auth.NewKeyStore(map[string]string{"alice": strings.Repeat("a", 32), "bob": strings.Repeat("b", 32)})
	// Authenticate(strings.Repeat("b",32)) == ("bob", true)
	// Authenticate("") == ("", false)
	// Authenticate(strings.Repeat("a",31)) == ("", false)
	// Authenticate(strings.Repeat("a",32)+"x") == ("", false)
}
```

- [ ] **Step 2: 运行确认失败** — `go test ./internal/auth/`
- [ ] **Step 3: 实现**
- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: Commit** — `git commit -m "feat: add constant-time relay key store"`

---

### Task 4: policy 目标 URL 校验

**Files:**
- Create: `internal/policy/target.go`
- Test: `internal/policy/target_test.go`

**Interfaces:**
- Consumes: `relayerr.New`, `relayerr.TargetInvalid`, `relayerr.TargetForbidden`
- Produces:
```go
type TargetPolicy struct {
	AllowedPort string // 生产固定 "443"；仅测试注入其他端口
	MaxLength   int    // 4096
}
func Default() TargetPolicy
func (p TargetPolicy) Parse(raw string) (*url.URL, *relayerr.Error)
```

规则（按顺序检查；第一个命中即返回）：

| 输入 | 结果 |
| --- | --- |
| 空、长度 > MaxLength、含字节 `<0x20`/`0x7f`/空格、含 `#`、存在 `%` 后未跟两位十六进制、`url.Parse` 失败、非绝对 URL、`Opaque != ""`、`User != nil` | 400 `TARGET_INVALID` |
| scheme 不是 `https` | 403 `TARGET_FORBIDDEN` |
| 主机为 IP 字面量（`netip.ParseAddr(u.Hostname())` 成功或 Host 以 `[` 开头） | 403 |
| 主机名非 ASCII LDH（每段 1–63 字符、`[a-z0-9-]`、不以 `-` 开头结尾，总长 ≤ 253，大写先转小写）、以 `.` 结尾 | 400 |
| 只有一段（如 `localhost`）、以 `.localhost` 结尾、最后一段全数字或形如 `0x…` | 403 |
| 端口非空且 ≠ AllowedPort | 403 |

成功时返回的 URL：Host 小写化；`Path == ""` 时设为 `/`；**保留** `RawPath` 与 `RawQuery` 原样（不得重新编码）。

- [ ] **Step 1: 写失败测试**（表驱动，每行 `raw, wantCode`，`""` 表示通过）

```go
func TestParse(t *testing.T) {
	p := policy.Default()
	cases := []struct{ raw string; want relayerr.Code }{
		{"https://api.example.com/v1/messages?mode=test", ""},
		{"https://API.Example.com:443/x", ""},
		{"https://xn--fiqs8s.example/", ""},
		{"", relayerr.TargetInvalid},
		{"/relative", relayerr.TargetInvalid},
		{"https://u:p@api.example.com/", relayerr.TargetInvalid},
		{"https://api.example.com/#frag", relayerr.TargetInvalid},
		{"https://api.example.com/a%zz", relayerr.TargetInvalid},
		{"https://api.example.com/a b", relayerr.TargetInvalid},
		{"https://api.example.com/\x01", relayerr.TargetInvalid},
		{"https://api.example.com./", relayerr.TargetInvalid},
		{"https://bücher.example/", relayerr.TargetInvalid},
		{"https://example.com/" + strings.Repeat("a", 4100), relayerr.TargetInvalid},
		{"http://api.example.com/", relayerr.TargetForbidden},
		{"ftp://api.example.com/", relayerr.TargetForbidden},
		{"https://127.0.0.1/", relayerr.TargetForbidden},
		{"https://[::1]/", relayerr.TargetForbidden},
		{"https://localhost/", relayerr.TargetForbidden},
		{"https://foo.localhost/", relayerr.TargetForbidden},
		{"https://0x7f.0.0.1/", relayerr.TargetForbidden},
		{"https://2130706433/", relayerr.TargetForbidden},
		{"https://api.example.com:8443/", relayerr.TargetForbidden},
	}
	// 对每行断言返回错误码（或 nil）
}

func TestParsePreservesEncoding(t *testing.T) {
	u, err := policy.Default().Parse("https://api.example.com/a%2Fb/c?sig=a+b%20c&x=%3D")
	// 断言 err==nil；u.EscapedPath()=="/a%2Fb/c"；u.RawQuery=="sig=a+b%20c&x=%3D"
}
```

- [ ] **Step 2: 运行确认失败** — `go test ./internal/policy/`
- [ ] **Step 3: 实现 `Parse`**
- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: Commit** — `git commit -m "feat: validate relay target URLs"`

---

### Task 5: netguard + 受保护 Transport

**Files:**
- Create: `internal/netguard/netguard.go`, `internal/transport/transport.go`
- Test: `internal/netguard/netguard_test.go`, `internal/transport/transport_test.go`

**Interfaces:**
- Produces:
```go
// netguard
func IsPublic(a netip.Addr) bool

// transport
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) // *net.Resolver 满足
}
type Options struct {
	Resolver              Resolver               // nil → net.DefaultResolver
	AllowIP               func(netip.Addr) bool  // nil → netguard.IsPublic
	RootCAs               *x509.CertPool         // nil → 系统根证书；仅测试注入
	DialTimeout, TLSHandshakeTimeout, ResponseHeaderTimeout, IdleConnTimeout time.Duration
}
var ErrDestinationForbidden = errors.New("destination address not allowed")
func New(opts Options) *http.Transport
func allowedAddrs(addrs []netip.Addr, allow func(netip.Addr) bool) []netip.Addr // 包内，供测试
```

`IsPublic`：先 `Unmap()`；以下返回 false：`!IsValid`、`IsUnspecified`、`IsLoopback`、`IsPrivate`、`IsLinkLocalUnicast`、`IsLinkLocalMulticast`、`IsInterfaceLocalMulticast`、`IsMulticast`，以及前缀 `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`（含 `255.255.255.255`）, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `2002::/16`。

`New`：`Proxy: nil`；`DisableCompression: true`；`ForceAttemptHTTP2: true`；`TLSClientConfig{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs}`；`MaxIdleConnsPerHost: 16`；四个超时取自 Options。`DialContext(ctx, network, addr)`：拆 host/port → host 若为 IP 则直接用 → 否则 `Resolver.LookupNetIP(ctx, "ip", host)` → `allowedAddrs` 过滤 → 解析结果非空但过滤后为空时返回包装了 `ErrDestinationForbidden` 的错误 → 依次拨号允许的地址（首个成功即返回）。拨号用 `net.Dialer{Timeout: DialTimeout, Control: ...}`，`Control` 中对实际连接地址 `netip.ParseAddrPort(address)` 再次调用 `AllowIP`，不允许时返回 `ErrDestinationForbidden`（纵深防御）。

- [ ] **Step 1: 写失败测试**

```go
func TestIsPublic(t *testing.T) {
	pub := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	priv := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1",
		"::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::", "2001::1"}
	// 断言 pub 全 true，priv 全 false
}

func TestAllowedAddrsFiltersMixed(t *testing.T) {
	in := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::1")}
	// allowedAddrs(in, netguard.IsPublic) == []netip.Addr{8.8.8.8}
}

func TestDialRejectsPrivateResolution(t *testing.T) {
	tr := transport.New(transport.Options{Resolver: mapResolver{"evil.example": {"127.0.0.1"}}, DialTimeout: time.Second})
	_, err := tr.DialContext(context.Background(), "tcp", "evil.example:443")
	// 断言 errors.Is(err, transport.ErrDestinationForbidden)
}

func TestDialControlRejectsLiteralPrivate(t *testing.T) {
	tr := transport.New(transport.Options{DialTimeout: time.Second})
	_, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	// 断言 errors.Is(err, transport.ErrDestinationForbidden)
}

func TestTransportHardening(t *testing.T) {
	tr := transport.New(transport.Options{})
	// 断言 tr.Proxy == nil；tr.DisableCompression；tr.TLSClientConfig.MinVersion == tls.VersionTLS12
}
```

（`mapResolver` 为测试文件内的 `map[string][]string` 实现。）

- [ ] **Step 2: 运行确认失败** — `go test ./internal/netguard/ ./internal/transport/`
- [ ] **Step 3: 实现 `IsPublic` 与 `New`**
- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: Commit** — `git commit -m "feat: add dial-time SSRF guarded transport"`

---

### Task 6: limiter

**Files:**
- Create: `internal/limiter/limiter.go`
- Test: `internal/limiter/limiter_test.go`

**Interfaces:**
- Consumes: `relayerr`
- Produces: `func New(ratePerSec float64, burst, maxConcurrent int) *Limiter`；`func (l *Limiter) Acquire(keyID string) (release func(), err *relayerr.Error)`

每个 keyID 懒创建 `rate.Limiter` 与容量为 `maxConcurrent` 的 `chan struct{}` 信号量（`sync.Mutex` 保护的 map）。先 `Allow()`，失败 → `RateLimited`；再非阻塞获取信号量，失败 → `ConcurrencyLimited`。`release` 幂等（`sync.Once`）。

- [ ] **Step 1: 写失败测试**

```go
func TestConcurrencyLimit(t *testing.T) {
	l := limiter.New(1000, 1000, 2)
	r1, e1 := l.Acquire("a"); r2, e2 := l.Acquire("a")
	_, e3 := l.Acquire("a")       // 断言 e1,e2 nil；e3.Code == ConcurrencyLimited
	_, e4 := l.Acquire("b")       // 断言 e4 nil（key 互相隔离）
	r1(); r1()                    // 幂等
	_, e5 := l.Acquire("a")       // 断言 e5 nil
	_ = r2
}

func TestRateLimit(t *testing.T) {
	l := limiter.New(1, 2, 100)
	// 连续三次 Acquire("a")：前两次 nil，第三次 Code == RateLimited
}
```

- [ ] **Step 2–4:** 运行失败 → 实现 → `go test ./internal/limiter/ -race -v` 通过
- [ ] **Step 5: Commit** — `git commit -m "feat: add per-key rate and concurrency limiter"`

---

### Task 7: relay 转发核心

**Files:**
- Create: `internal/relay/handler.go`, `internal/relaytest/relaytest.go`
- Test: `internal/relay/handler_test.go`

**Interfaces:**
- Consumes: `policy.TargetPolicy.Parse`, `transport.New`, `transport.ErrDestinationForbidden`, `relayerr.*`, `reqctx.From`
- Produces:
```go
// relay
type Options struct {
	Transport          http.RoundTripper
	Policy             policy.TargetPolicy
	MaxRequestBytes    int64
	MaxResponseBytes   int64         // 0 = 不限
	MaxRequestDuration time.Duration // 0 = 不限
	Logger             *slog.Logger
}
func New(opts Options) http.Handler

// relaytest
type Upstream struct {
	BaseURL   string               // "https://example.com:<port>"
	Transport *http.Transport      // 解析 example.com→127.0.0.1、信任测试证书、允许环回
	Policy    policy.TargetPolicy  // AllowedPort = 测试端口
	Resolver  *MapResolver
}
type MapResolver struct{ Hosts map[string][]netip.Addr; Calls atomic.Int64 } // 实现 transport.Resolver
func NewUpstream(t *testing.T, h http.Handler) *Upstream // 基于 httptest.NewTLSServer（其证书含 SAN example.com），t.Cleanup 关闭
```

`ServeHTTP` 流程：
1. `info := reqctx.From(ctx)`；`w.Header().Set(HeaderRequestID, info.RequestID)`（用 Set，与 Task 8 中间件设置的同值不会重复）。`X-Relay-Target` 出现多次（`len(r.Header.Values(...)) != 1`）→ 400 `REQUEST_INVALID`（缺失 → 400 `TARGET_INVALID`）。
2. `Policy.Parse` → 失败写错误；成功后 `info.TargetHost = u.Hostname()`。
3. `r.ContentLength > MaxRequestBytes` → 413；否则 `r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)`。
4. `MaxRequestDuration > 0` 时 `context.WithTimeout`。
5. 把目标 URL 放进私有 context key，交给**构造时创建一次**的 `httputil.ReverseProxy`。

ReverseProxy 配置：
- `Rewrite`：`pr.Out.URL = 目标 URL 的拷贝`；`pr.Out.Host = target.Host`；删除所有以 `X-Relay-` 开头的头，以及 `X-Real-Ip`、`Via`、`True-Client-Ip`、`Cf-Connecting-Ip`（`Forwarded`/`X-Forwarded-*` 由 Rewrite 模式自动删除；**不**调用 `SetXForwarded`、**不**调用 `SetURL`）。
- `ModifyResponse`：删除上游响应中所有 `X-Relay-*` 头（**不要**在 resp 上再设置 `X-Relay-Request-ID`：ReverseProxy 用 `Add` 合并头，会产生重复值）；`MaxResponseBytes > 0` 时：`resp.ContentLength > MaxResponseBytes` → 返回 `relayerr.New(UpstreamProtocolError)`；否则把 `resp.Body` 包装为超过上限即返回错误的读取器。
- `ErrorHandler`：`info.ErrorCode` 记录分类结果；`classify` 返回 nil（客户端已断开）时不写响应，只打日志。
- `FlushInterval` 保持 0（ReverseProxy 对 `text/event-stream` 与无长度响应自动立即 flush）。
- `ErrorLog`：接到 `Logger` 的 `slog.NewLogLogger`。

`func classify(r *http.Request, err error) *relayerr.Error`（按顺序）：`*relayerr.Error` → 原样；`*http.MaxBytesError` → `RequestTooLarge`；`ErrDestinationForbidden` → `TargetForbidden`；`context.Canceled` 且 `r.Context().Err() != nil` → nil；`context.DeadlineExceeded` 或 `net.Error.Timeout()` → `UpstreamTimeout`；`*net.DNSError`、`*net.OpError`、`*tls.CertificateVerificationError`、`x509.HostnameError`、`x509.UnknownAuthorityError` → `UpstreamConnectFailed`；其他 → `UpstreamProtocolError`。

- [ ] **Step 1: 写 relaytest 辅助与失败测试**

测试用 `httptest.NewRecorder` 或 `httptest.NewServer(relay.New(...))` 发请求（每个请求先用 `reqctx.With` 注入 `&reqctx.Info{RequestID: "req_test"}`），上游由 `relaytest.NewUpstream` 提供。每个测试的断言：

| 测试名 | 场景 | 断言 |
| --- | --- | --- |
| `TestForwardsMethodBodyAndHeaders` | POST，body `{"hello":"world"}`，带 `Authorization: Bearer up`、`X-Relay-Key`、`X-Relay-Foo`、`X-Forwarded-For`、`X-Real-IP`，目标 `BaseURL+"/v1/messages?mode=test"` | 上游收到 method POST、路径 `/v1/messages`、query `mode=test`、body 相同、`Authorization` 保留、`Host == example.com:<port>`、任何 `X-Relay-*`/`X-Forwarded-For`/`X-Real-Ip` 均不存在 |
| `TestReturnsUpstreamStatusAndHeaders` | 上游回 401 + `Content-Type: text/plain` + `ETag` | 客户端 401，无 `X-Relay-Error`，`ETag` 透传，有 `X-Relay-Request-ID: req_test` |
| `TestUpstreamRelayHeadersStripped` | 上游回 `X-Relay-Error: true`、`X-Relay-Request-ID: forged` | 客户端无 `X-Relay-Error`，`X-Relay-Request-ID == "req_test"` |
| `TestRawPathAndQueryPreserved` | 目标 `BaseURL+"/a%2Fb/c?sig=a+b%20c&x=%3D"` | 上游 `r.URL.EscapedPath()=="/a%2Fb/c"` 且 `r.URL.RawQuery=="sig=a+b%20c&x=%3D"` |
| `TestNoRedirectFollow` | 上游回 302 `Location: https://other.example/` | 客户端（`CheckRedirect` 返回 `http.ErrUseLastResponse`）收到 302 与原 Location |
| `TestNoSilentDecompression` | 客户端带 `Accept-Encoding: gzip`，上游回 gzip 字节 + `Content-Encoding: gzip` | 客户端收到的原始字节与上游相同，`Content-Encoding: gzip` 保留；客户端不带 `Accept-Encoding` 时上游收到的请求也没有 `Accept-Encoding` |
| `TestHeadNoBody` | HEAD | 上游收到 HEAD，客户端 body 为空 |
| `TestSSEStreamsIncrementally` | 上游写 `data: 1\n\n`、Flush、阻塞直到测试读到第一条事件后再写 `data: 2\n\n` | 测试在上游写第二条前读到 `data: 1`（2s 超时内） |
| `TestDuplicateTargetHeader` | 两个 `X-Relay-Target` | 400 `REQUEST_INVALID`，`Resolver.Calls == 0` |
| `TestRequestTooLarge` | `MaxRequestBytes=10`，body 11 字节（有 Content-Length）；以及 chunked 11 字节 | 均为 413 `REQUEST_TOO_LARGE` |
| `TestResponseTooLargeByContentLength` | `MaxResponseBytes=10`，上游回 `Content-Length: 11` | 502 `UPSTREAM_PROTOCOL_ERROR` |
| `TestTLSHostnameMismatch` | 解析器把 `evil.test` 映射到 127.0.0.1，目标 `https://evil.test:<port>/` | 502 `UPSTREAM_CONNECT_FAILED` |
| `TestForbiddenResolution` | Transport 用默认 `AllowIP`（`IsPublic`），解析到 127.0.0.1 | 403 `TARGET_FORBIDDEN` |
| `TestResponseHeaderTimeout` | `ResponseHeaderTimeout=100ms`，上游 sleep 1s | 504 `UPSTREAM_TIMEOUT` |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/relay/`
- [ ] **Step 3: 实现 `relay.New`、`classify`、`relaytest.NewUpstream`**
- [ ] **Step 4: 运行确认通过** — `go test ./internal/relay/ -race -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: add streaming reverse proxy relay core"`

---

### Task 8: Gin 路由、中间件与访问日志

**Files:**
- Create: `internal/server/router.go`, `internal/server/logging.go`
- Test: `internal/server/router_test.go`

**Interfaces:**
- Consumes: `auth.KeyStore.Authenticate`, `limiter.Limiter.Acquire`, `relay.New`, `relayerr.*`, `reqctx.*`
- Produces:
```go
type Deps struct {
	Auth    *auth.KeyStore
	Limiter *limiter.Limiter
	Relay   http.Handler
	Logger  *slog.Logger
}
func NewRouter(d Deps) *gin.Engine
```

路由配置：`gin.SetMode(gin.ReleaseMode)`；`gin.New()`；`RedirectTrailingSlash=false`、`RedirectFixedPath=false`、`HandleMethodNotAllowed=true`；`NoMethod` → 405、`NoRoute` → 404 `NOT_FOUND`（均用 `relayerr.Write`）。`GET /healthz` → 200 `{"status":"ok"}`，无需鉴权。对 GET/HEAD/POST/PUT/PATCH/DELETE 逐个 `Handle("/v1/relay", …)`（不用 `Any`，避免注册 CONNECT/TRACE）。

全局中间件顺序：
1. `requestContext`：生成 `NewRequestID()`，`reqctx.With` 注入 `*Info`，设置响应头 `X-Relay-Request-ID`；`c.Next()` 后输出一条 JSON 访问日志：`request_id, key_id, method, target_host, status, bytes_out, duration_ms, error_code`。**不得**记录任何请求头、目标 path/query、body。
2. `recoverer`：recover 到 `http.ErrAbortHandler` 时**重新 panic**（交给 net/http 静默中止连接）；其他 panic 记录错误日志并在未写响应时返回 500 `INTERNAL_ERROR`。不使用 `gin.Recovery()`。

`/v1/relay` 路由内中间件顺序：
3. `exactPath`：`r.URL.EscapedPath() != "/v1/relay" || r.URL.RawQuery != "" || r.URL.ForceQuery` → 400 `REQUEST_INVALID`。
4. `authenticate`：`X-Relay-Key` 恰好一个值且 `Authenticate` 通过，否则 401 `AUTH_FAILED`；成功写 `info.KeyID`。
5. `limit`：`Acquire(keyID)`，失败写对应 429；成功后 `defer release()` 再 `c.Next()`（panic 时也必须释放）。
6. 末端：`gin.WrapH(d.Relay)`。

- [ ] **Step 1: 写失败测试**

测试搭建：`relaytest.NewUpstream` + `relay.New` + `NewRouter`，挂到 `httptest.NewServer`；日志写入 `bytes.Buffer`（`slog.NewJSONHandler`）。

| 测试名 | 场景 | 断言 |
| --- | --- | --- |
| `TestHealthz` | `GET /healthz` 无 key | 200 |
| `TestAuthFailsBeforeDNS` | 无 key / 错 key / 两个 `X-Relay-Key` | 均 401 `AUTH_FAILED`、`X-Relay-Error: true`、body 相同；`Resolver.Calls == 0` |
| `TestMethodNotAllowed` | 用 `TRACE`、`OPTIONS`、`PROPFIND` 调 `/v1/relay`（CONNECT 由同一 NoMethod 路径覆盖） | 405 `METHOD_NOT_ALLOWED` |
| `TestAmbiguousPaths` | `/v1/relay?x=1`、`/v1/relay?`、`/v1/%72elay` | 400 `REQUEST_INVALID`；`/v1/relay/`、`/v1//relay` → 404 `NOT_FOUND`；均无重定向 |
| `TestEndToEndSuccess` | 合法 key + 目标 | 上游状态与 body 透传；响应有 `X-Relay-Request-ID` |
| `TestRateLimited` | `limiter.New(1,1,10)`，连发两次 | 第二次 429 `RATE_LIMITED` |
| `TestClientDisconnectReleasesSlot` | `limiter.New(100,100,1)`；上游 SSE 写一条后阻塞直到 `r.Context().Done()`（并记录被取消）；客户端读到第一条后取消请求 | 上游 context 在 2s 内被取消；随后同一 key 的新请求不再返回 429（2s 内轮询） |
| `TestMidStreamAbortNoStackTrace` | `MaxResponseBytes=10`，上游无 Content-Length 流式写 100 字节 | 客户端读 body 返回错误或少于 100 字节；状态码为 200（已写出）；日志中不含 `"INTERNAL_ERROR"` 与 `goroutine` |
| `TestLogsContainNoSecrets` | key `S3CRET…`，`Authorization: Bearer UPTOKEN`，目标 query `token=QTOKEN` | 日志 buffer 不含 `S3CRET`、`UPTOKEN`、`QTOKEN`；含 `"key_id":"alice"` 与 `"target_host":"example.com"` |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/server/`
- [ ] **Step 3: 实现 `NewRouter` 与中间件**
- [ ] **Step 4: 运行确认通过** — `go test ./... -race -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: add gin router, auth, limits and access logs"`

---

### Task 9: 进程入口、部署样例与文档

**Files:**
- Create: `cmd/relay/main.go`, `deploy/Caddyfile.example`, `deploy/relay.env.example`
- Modify: `README.md`（状态行与“如何运行”小节）

**Interfaces:**
- Consumes: `config.Load(os.LookupEnv)`、`auth.NewKeyStore`、`limiter.New`、`transport.New`、`policy.Default`、`relay.New`、`server.NewRouter`

`main`：加载配置（失败打印错误并 `os.Exit(1)`）→ 组装依赖（`slog.NewJSONHandler(os.Stdout)`）→ `http.Server{Addr: ListenAddr, Handler: router, ReadHeaderTimeout: cfg.ReadHeaderTimeout, MaxHeaderBytes: 64 << 10, IdleTimeout: 120 * time.Second}`，**不设** `WriteTimeout`/`ReadTimeout`（会截断 SSE 和大文件）→ 收到 SIGINT/SIGTERM 时 `Shutdown`，宽限 30s。

`deploy/Caddyfile.example`：`relay.example.com { reverse_proxy 127.0.0.1:8080 { flush_interval -1 } }`，并注释说明需关闭缓冲以支持 SSE、`request_body` 上限应 ≥ `RELAY_MAX_REQUEST_BYTES`。
`deploy/relay.env.example`：列出 Task 2 的全部变量与默认值，`RELAY_KEYS=client1:<用 openssl rand -hex 32 生成>`，不含真实密钥。

- [ ] **Step 1: 实现 `main.go` 与部署样例**
- [ ] **Step 2: 构建与静态检查** — `go build ./... && go vet ./... && go test ./... -race`，Expected: 全部通过
- [ ] **Step 3: 冒烟测试**

```bash
RELAY_KEYS="dev:$(openssl rand -hex 32)" go run ./cmd/relay &   # 记下 key
curl -s localhost:8080/healthz                                   # {"status":"ok"}
curl -si localhost:8080/v1/relay -H 'X-Relay-Target: https://api.github.com/zen'          # 401 AUTH_FAILED
curl -si localhost:8080/v1/relay -H "X-Relay-Key: $KEY" -H 'X-Relay-Target: https://127.0.0.1/'  # 403 TARGET_FORBIDDEN
curl -si localhost:8080/v1/relay -H "X-Relay-Key: $KEY" -H 'X-Relay-Target: https://api.github.com/zen'  # 200（需服务器能出网）
```

- [ ] **Step 4: 更新 README** —— 状态改为“v1 已实现”，新增运行方式与环境变量表链接到 `deploy/relay.env.example`；删除“仅设计文档”的表述。
- [ ] **Step 5: Commit** — `git commit -m "feat: add relay entrypoint and deployment examples"`

---

## 不在本计划范围（对应 ARCHITECTURE §7）

按 key 单独配置限额、Redis 分布式配额、Prometheus（Milestone 2）；WebSocket `/v1/ws`（Milestone 3）；多区域节点（Milestone 4）；服务端安全跟随重定向（v2）；容器镜像（验收通过后再做）。
