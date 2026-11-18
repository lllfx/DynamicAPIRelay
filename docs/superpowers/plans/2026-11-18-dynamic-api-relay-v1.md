# DynamicAPIRelay v1 实现方案

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 Go + Gin 实现 `POST|GET|… /v1/relay`：鉴权后按请求头 `X-Relay-Target` 把原始请求流式转发到任意公网 HTTPS API，并原样返回上游响应，同时在拨号时强制 SSRF 防护；并提供按 key 统计用量与报错的 SQLite 看板。

**Architecture:** Gin 只负责路由与中间件（请求 ID、访问日志、恢复、精确路径、鉴权、限流）；转发核心是一个共享的 `httputil.ReverseProxy`（`Rewrite` 模式）+ 一个共享的受保护 `http.Transport`。目标 URL 校验（解析期）与目标 IP 校验（拨号期，`DialContext` + `net.Dialer.Control` 双重检查）分属两个包。所有 relay 自身错误统一为 JSON + `X-Relay-Error: true`。

**Tech Stack:** Go 1.24（本机 go1.24.13），`github.com/gin-gonic/gin v1.10.1`，`golang.org/x/time v0.14.0`（`rate`；v0.15 需 Go 1.25），`modernc.org/sqlite v1.40.1`，标准库 `net/http`、`net/http/httputil`、`net/netip`、`log/slog`、`crypto/subtle`。

**Spec:** `README.md`、`docs/ARCHITECTURE.md`、`docs/API_SPEC.md`、`docs/superpowers/specs/2026-11-18-usage-dashboard-design.md`（看板，Task 8–11）。（README 引用的 `docs/SECURITY.md`、`docs/IMPLEMENTATION_PLAN.md`、`docs/TEST_PLAN.md` 仓库中不存在；本方案以前三份为准。）

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

（v1 转发部分）

1. **DNS 返回公私混合地址**（如 A 记录同时含 `10.0.0.1` 与公网地址，或 DNS rebinding）——只拨号允许的地址；全部不允许时返回 403。→ Task 5 `TestAllowedAddrsFiltersMixed`、`TestDialRejectsPrivateResolution`。
2. **上游伪造 `X-Relay-Error` / `X-Relay-Request-ID` 响应头**——必须剥除，否则客户端会把上游响应误判为 relay 错误。→ Task 7 `TestUpstreamRelayHeadersStripped`。
3. **流式响应中途失败**（响应上限超出、上游断流）——Gin Recovery 不得写 500 或打栈，连接应被中止。→ Task 9 `TestMidStreamAbortNoStackTrace`。
4. **带签名的 URL 编码**（路径中的 `%2F`、query 中的 `+`/`%20`）——必须逐字节到达上游。→ Task 7 `TestRawPathAndQueryPreserved`。
5. **SSE 进行中客户端断开**——上游被取消且并发槽释放，否则一个 key 会被“泄漏”的连接锁死。→ Task 9 `TestClientDisconnectReleasesSlot`。

（看板部分）

6. **SQLite 写入慢/失败或队列满**——转发必须不受影响，只丢统计并计数。→ Task 8 `TestRecordNeverBlocks`、`TestInsertFailureKeepsRunning`。
7. **伪造 `X-Forwarded-For`**——只有来自可信代理的连接才采信，否则记录直连 IP。→ Task 9 `TestUntrustedForwardedForIgnored`。
8. **看板误暴露**——非环回监听且无密码时拒绝启动。→ Task 11 `TestLoadRejectsPublicDashboardWithoutPassword`。

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
internal/server/record.go         统计记录中间件（仅 /v1/relay）
internal/stats/store.go           SQLite 打开、schema、批量插入、清理
internal/stats/recorder.go        非阻塞队列 + 后台批量写
internal/stats/query.go           看板查询
internal/dashboard/dashboard.go   看板 HTTP handler（含 Basic 认证、安全头）
internal/dashboard/templates/*.html, internal/dashboard/svg.go
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
- Modify: `internal/reqctx/reqctx.go`（`Info` 增加 `ClientIP string`、`BytesIn int64`、`Aborted bool`、`ClientCanceled bool`）
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
3. `r.ContentLength > MaxRequestBytes` → 413；否则 `r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)`，外层再包一个计数读取器，把实际读取的字节累加到 `info.BytesIn`。
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
| `TestCountsBytesIn` | POST 1234 字节 body | 请求结束后 `info.BytesIn == 1234` |
| `TestResponseHeaderTimeout` | `ResponseHeaderTimeout=100ms`，上游 sleep 1s | 504 `UPSTREAM_TIMEOUT` |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/relay/`
- [ ] **Step 3: 实现 `relay.New`、`classify`、`relaytest.NewUpstream`**
- [ ] **Step 4: 运行确认通过** — `go test ./internal/relay/ -race -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: add streaming reverse proxy relay core"`

---

### Task 8: stats 存储、异步记录与查询

**Files:**
- Create: `internal/stats/store.go`, `internal/stats/recorder.go`, `internal/stats/query.go`
- Test: `internal/stats/store_test.go`, `internal/stats/recorder_test.go`, `internal/stats/query_test.go`

**Interfaces:**
- Produces:
```go
type Record struct {
	Time                                              time.Time // 请求开始
	RequestID, KeyID, ClientIP, Method, TargetHost    string
	Status                                            int
	ErrorCode                                         string
	Aborted, ClientCanceled                           bool
	BytesIn, BytesOut                                 int64
	Duration                                          time.Duration
}
func Open(path string) (*Store, error)        // 建目录(0700)；WAL、busy_timeout=5000、synchronous=NORMAL；写连接 MaxOpenConns=1，读连接池独立；建表，PRAGMA user_version=1
func (s *Store) Close() error
func (s *Store) Insert(ctx context.Context, recs []Record) error      // 单事务
func (s *Store) Purge(ctx context.Context, before time.Time) (int64, error) // 每批 5000 行直到删完
func RunRetention(ctx context.Context, s *Store, retention, every time.Duration, now func() time.Time, logger *slog.Logger) // 立即清理一次，之后每 every 一次，ctx 结束返回

type RecorderOptions struct{ QueueSize, BatchSize int; FlushInterval time.Duration } // 生产：10000, 200, 1s
type Sink interface{ Insert(ctx context.Context, recs []Record) error } // *Store 满足；测试可注入失败的 Sink
func NewRecorder(sink Sink, logger *slog.Logger, opts RecorderOptions) *Recorder // 启动后台 goroutine
func (r *Recorder) Record(rec Record)                    // 非阻塞；队列满则丢弃并 dropped++
func (r *Recorder) Dropped() int64
func (r *Recorder) Close(ctx context.Context) error       // 停止接收、刷完队列；ctx 超时返回 ctx.Err()

type Range struct{ From, To time.Time }  // [From, To)
type Counts struct{ Requests, Success, UpstreamErrors, Aborted, RelayErrors, ClientCanceled int64 }
func (c Counts) ErrorRate() (rate float64, ok bool) // (Relay+Aborted+Upstream)/(Requests-ClientCanceled)；分母 0 → ok=false
type Totals struct{ Counts; BytesIn, BytesOut int64; P95 time.Duration; LastSeen time.Time }
type KeySummary struct{ KeyID string; Totals }
type Bucket struct{ Start time.Time; Counts }
type HostStat struct{ Host string; Requests, Errors, BytesOut int64 }
type LabelCount struct{ Label string; Count int64 }
type Failure struct{ ID int64; Time time.Time; Method, TargetHost string; Status int; ErrorCode string; Aborted bool; Duration time.Duration; RequestID, ClientIP string }

func (s *Store) Summaries(ctx context.Context, r Range) ([]KeySummary, error)            // 有数据的全部 key，按 Requests 降序
func (s *Store) KeyTotals(ctx context.Context, keyID string, r Range) (Totals, error)
func (s *Store) Trend(ctx context.Context, keyID *string, r Range, step time.Duration, loc *time.Location) ([]Bucket, error) // keyID nil=全部；返回连续桶（空桶补 0）
func (s *Store) TopHosts(ctx context.Context, keyID string, r Range, limit int) ([]HostStat, error)
func (s *Store) ErrorBreakdown(ctx context.Context, keyID string, r Range) (codes, statuses []LabelCount, err error) // codes: relay error_code；statuses: 上游错误类的 status
func (s *Store) RecentFailures(ctx context.Context, keyID string, r Range, beforeID int64, limit int) ([]Failure, error) // beforeID<=0 不限；id 倒序；只含非成功、非客户端取消
```

表结构与索引严格按设计文档 §4.2（含 `client_canceled` 列）。分类 SQL 在 `query.go` 中定义为一个常量，所有查询共用（优先级：客户端取消 > relay 错误 > 流中断 > 上游错误 > 成功）：
```sql
CASE WHEN client_canceled=1 THEN 'canceled' WHEN error_code<>'' THEN 'relay'
     WHEN aborted=1 THEN 'aborted' WHEN status>=400 THEN 'upstream' ELSE 'success' END
```
`Trend` 分桶：桶起点按 `loc` 对齐（小时桶对齐整点，天桶对齐当地零点），用 `loc` 在 `r.From` 处的固定偏移在 SQL 中计算 `(ts + offset_ms) / step_ms`（`Asia/Shanghai` 无夏令时）。`P95`：先 count，再 `ORDER BY duration_ms LIMIT 1 OFFSET ceil(0.95*n)-1`。Recorder 写库失败只记一条 `slog` 错误日志（含条数，不含记录内容）并丢弃该批。

- [ ] **Step 1: 写失败测试**（均用 `t.TempDir()` 下的数据库文件）

| 测试名 | 断言 |
| --- | --- |
| `TestOpenCreatesSchema` | 路径含不存在的子目录也能打开；目录权限 0700；`PRAGMA journal_mode` 为 `wal`；`PRAGMA user_version` 为 1；重复 Open 同一文件不报错 |
| `TestInsertAndPurge` | 插入 3 条（时间分别为 now-40d、now-31d、now-1d），`Purge(now-30d)` 返回 2，剩 1 条 |
| `TestRecorderFlushesBatch` | `BatchSize=2, FlushInterval=1h`，Record 两条 → 2s 内 Sink 收到 1 批 2 条 |
| `TestRecorderFlushesOnInterval` | `BatchSize=100, FlushInterval=50ms`，Record 一条 → 2s 内落库 |
| `TestRecorderCloseFlushes` | Record 5 条后立即 `Close` → Sink 共收到 5 条 |
| `TestRecordNeverBlocks` | Sink 的 Insert 阻塞到测试结束；`QueueSize=2, BatchSize=1`；连续 Record 100 条在 100ms 内返回；`Dropped() > 0` |
| `TestInsertFailureKeepsRunning` | Sink 第一次返回错误、之后成功：第一批丢弃，后续记录仍落库 |
| `TestClassification` | 插入 5 条：canceled+relay 错误码（应算 canceled）、relay 错误码+status 429、aborted+200、status 401、status 302；`KeyTotals` 的 Counts 依次为 ClientCanceled=1, RelayErrors=1, Aborted=1, UpstreamErrors=1, Success=1；`ErrorRate()` == 3/4 |
| `TestErrorRateZeroDenominator` | 只有 1 条 canceled → `ok == false` |
| `TestSummariesAndHosts` | alice 3 条、bob 1 条、`""` 2 条；`Summaries` 顺序 alice, `""`, bob；`TopHosts("alice")` 按请求数降序且 Errors/BytesOut 正确；范围外记录不计入 |
| `TestTrendBuckets` | loc=Asia/Shanghai，24h 范围、1h 步长 → 24 个连续桶，桶起点为当地整点，记录落在正确桶；7d 范围、24h 步长 → 7 个桶，起点为当地零点 |
| `TestRecentFailuresPaging` | 60 条失败 + 10 条成功 + 5 条 canceled：limit 50 第一页 50 条 id 倒序；用最后一条 id 作 beforeID 第二页 10 条；均不含成功与 canceled |
| `TestP95` | 1..100ms 共 100 条 → P95 == 95ms |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/stats/`
- [ ] **Step 3: 实现 store / recorder / query**（`go get modernc.org/sqlite@v1.40.1`，驱动名 `sqlite`）
- [ ] **Step 4: 运行确认通过** — `go test ./internal/stats/ -race -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: add sqlite request stats store and async recorder"`

---

### Task 9: Gin 路由、中间件、访问日志与统计记录

**Files:**
- Create: `internal/server/router.go`, `internal/server/logging.go`, `internal/server/record.go`
- Test: `internal/server/router_test.go`, `internal/server/record_test.go`

**Interfaces:**
- Consumes: `auth.KeyStore.Authenticate`, `limiter.Limiter.Acquire`, `relay.New`, `relayerr.*`, `reqctx.*`（含 Task 7 新字段）, `stats.Record`
- Produces:
```go
type Recorder interface{ Record(stats.Record) } // *stats.Recorder 满足
type Deps struct {
	Auth           *auth.KeyStore
	Limiter        *limiter.Limiter
	Relay          http.Handler
	Logger         *slog.Logger
	Recorder       Recorder // nil = 不记录
	TrustedProxies []string // CIDR；空 = 不信任任何代理
}
func NewRouter(d Deps) (*gin.Engine, error) // SetTrustedProxies 失败时返回错误
```

路由配置：`gin.SetMode(gin.ReleaseMode)`；`gin.New()`；`RedirectTrailingSlash=false`、`RedirectFixedPath=false`、`HandleMethodNotAllowed=true`；`RemoteIPHeaders = []string{"X-Forwarded-For"}`；`SetTrustedProxies(d.TrustedProxies)`（空切片时传 `nil` 表示不信任）。`NoMethod` → 405、`NoRoute` → 404 `NOT_FOUND`（均用 `relayerr.Write`）。`GET /healthz` → 200 `{"status":"ok"}`，无需鉴权。对 GET/HEAD/POST/PUT/PATCH/DELETE 逐个 `Handle("/v1/relay", …)`（不用 `Any`）。

全局中间件顺序：
1. `requestContext`：生成 `NewRequestID()`；`info.ClientIP = c.ClientIP()`；`reqctx.With` 注入；设置响应头 `X-Relay-Request-ID`；**在 `defer` 中**输出一条 JSON 访问日志：`request_id, key_id, client_ip, method, target_host, status, bytes_out, duration_ms, error_code`。**不得**记录任何请求头、目标 path/query、body。
2. `recoverer`：recover 到 `http.ErrAbortHandler` 时**重新 panic**；其他 panic 记录错误日志并在未写响应时返回 500 `INTERNAL_ERROR`。不使用 `gin.Recovery()`。

`/v1/relay` 路由内中间件顺序：
3. `record`（仅当 `Recorder != nil`）：记下开始时间，`c.Next()`；**在 `defer` 中**：若 recover 到 `http.ErrAbortHandler` 则 `info.Aborted = true`；`info.ClientCanceled = c.Request.Context().Err() != nil`；组装 `stats.Record`（`Status = c.Writer.Status()`，`BytesOut = max(c.Writer.Size(), 0)`，`ErrorCode = string(info.ErrorCode)`）调用 `Recorder.Record`；若之前 recover 到了 panic 值则原样重新 panic。
4. `exactPath`：`r.URL.EscapedPath() != "/v1/relay" || r.URL.RawQuery != "" || r.URL.ForceQuery` → 400 `REQUEST_INVALID`。
5. `authenticate`：`X-Relay-Key` 恰好一个值且 `Authenticate` 通过，否则 401 `AUTH_FAILED`；成功写 `info.KeyID`。
6. `limit`：`Acquire(keyID)`，失败写对应 429；成功后 `defer release()` 再 `c.Next()`。
7. 末端：`gin.WrapH(d.Relay)`。

所有中间件写 relay 错误时同时设置 `info.ErrorCode`。

- [ ] **Step 1: 写失败测试**

测试搭建：`relaytest.NewUpstream` + `relay.New` + `NewRouter`，挂到 `httptest.NewServer`；日志写入 `bytes.Buffer`（`slog.NewJSONHandler`）；`fakeRecorder`（互斥锁保护的切片，提供 `wait(t, n)` 在 2s 内轮询到 n 条）。`TrustedProxies` 默认 `[]string{"127.0.0.1/32"}`。

| 测试名 | 场景 | 断言 |
| --- | --- | --- |
| `TestHealthz` | `GET /healthz` 无 key | 200 |
| `TestAuthFailsBeforeDNS` | 无 key / 错 key / 两个 `X-Relay-Key` | 均 401 `AUTH_FAILED`、`X-Relay-Error: true`、body 相同；`Resolver.Calls == 0` |
| `TestMethodNotAllowed` | `TRACE`、`OPTIONS`、`PROPFIND` 调 `/v1/relay` | 405 `METHOD_NOT_ALLOWED` |
| `TestAmbiguousPaths` | `/v1/relay?x=1`、`/v1/relay?`、`/v1/%72elay` | 400 `REQUEST_INVALID`；`/v1/relay/`、`/v1//relay` → 404 `NOT_FOUND`；均无重定向 |
| `TestEndToEndSuccess` | 合法 key + 目标 | 上游状态与 body 透传；有 `X-Relay-Request-ID` |
| `TestRateLimited` | `limiter.New(1,1,10)`，连发两次 | 第二次 429 `RATE_LIMITED` |
| `TestClientDisconnectReleasesSlot` | `limiter.New(100,100,1)`；上游 SSE 写一条后阻塞到 `r.Context().Done()`；客户端读到第一条后取消 | 上游 context 2s 内被取消；随后同 key 新请求 2s 内不再 429；对应 Record 的 `ClientCanceled == true` |
| `TestMidStreamAbortNoStackTrace` | `MaxResponseBytes=10`，上游无 Content-Length 流式写 100 字节 | 客户端读 body 出错或少于 100 字节；状态 200；日志不含 `INTERNAL_ERROR` 与 `goroutine`；Record 的 `Aborted == true` |
| `TestLogsContainNoSecrets` | key `S3CRET…`，`Authorization: Bearer UPTOKEN`，目标 query `token=QTOKEN` | 日志不含 `S3CRET`、`UPTOKEN`、`QTOKEN`；含 `"key_id":"alice"`、`"target_host":"example.com"` |
| `TestRecordsRelayRequest` | 合法 POST，body 1234 字节，`X-Forwarded-For: 203.0.113.9` | 恰 1 条 Record：KeyID alice、Method POST、TargetHost example.com、Status 200、BytesIn 1234、BytesOut == 上游 body 长度、ClientIP `203.0.113.9`、RequestID 与响应头一致、Duration > 0；Record 各字符串字段均不含 key/Authorization/query 值 |
| `TestRecordsAuthFailure` | 错 key | 1 条 Record：KeyID `""`、Status 401、ErrorCode `AUTH_FAILED` |
| `TestNotRecorded` | `/healthz`、`/nope`、`TRACE /v1/relay` | 200ms 后 Record 数为 0 |
| `TestUntrustedForwardedForIgnored` | `TrustedProxies` 为空，带 `X-Forwarded-For: 203.0.113.9` | Record 的 ClientIP == `127.0.0.1` |
| `TestNilRecorder` | `Recorder: nil` 下合法请求 | 200，无 panic |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/server/`
- [ ] **Step 3: 实现 `NewRouter` 与中间件**
- [ ] **Step 4: 运行确认通过** — `go test ./... -race`
- [ ] **Step 5: Commit** — `git commit -m "feat: add gin router, auth, limits, access logs and stats recording"`

---

### Task 10: 看板 HTTP handler

**Files:**
- Create: `internal/dashboard/dashboard.go`, `internal/dashboard/svg.go`, `internal/dashboard/templates/layout.html`, `internal/dashboard/templates/overview.html`, `internal/dashboard/templates/key.html`
- Test: `internal/dashboard/dashboard_test.go`

**Interfaces:**
- Consumes: `stats.Store` 的 `Summaries`、`KeyTotals`、`Trend`、`TopHosts`、`ErrorBreakdown`、`RecentFailures`；`stats.Counts.ErrorRate`
- Produces:
```go
type Options struct {
	Store         *stats.Store
	Dropped       func() int64     // nil → 显示 0
	KeyIDs        []string         // 当前配置中的 key ID（不含 secret）
	Location      *time.Location
	Password      string           // 非空启用 Basic 认证，用户名 admin
	RetentionDays int
	Now           func() time.Time // nil → time.Now
}
func New(opts Options) http.Handler
```

路由（`http.ServeMux`，Go 1.22 模式）：`GET /{$}` 总览；`GET /keys/{id}` key 详情；`GET /unauthenticated` 未鉴权详情（keyID `""`）；其他路径 404。非 GET/HEAD → 405。`range` 取 `24h`（默认，1h 桶）、`7d`、`30d`（1 天桶），非法值回退 24h；范围 `[now-range, now)`。`id` 不匹配 `^[A-Za-z0-9_-]{1,64}$` → 404；合法但无数据 → 全 0 页面。`before` 非正整数时忽略。

每个响应：`Cache-Control: no-store`、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'`。Basic 认证用 `subtle.ConstantTimeCompare`，失败 401 + `WWW-Authenticate: Basic realm="relay-dashboard"`。

页面内容按设计文档 §4.5：总览 = 4 张卡片（请求总数、错误率、下行流量、活跃客户端数）+ 堆叠趋势 SVG + 客户端表（列：客户端、请求、成功、上游错误、流中断、relay 错误、客户端取消、错误率、上行、下行、p95 耗时、最近请求；`Summaries` ∪ `KeyIDs` 补 0 行；`""` 显示为 `(未鉴权)` 并链接 `/unauthenticated`，其他链接 `/keys/{id}`）+ 页脚“统计丢弃 N 条 · 数据保留 N 天”。详情 = 卡片 + 趋势 + 目标主机前 20 + 错误分布 + 最近失败（每页 50，列：时间、方法、目标主机、状态码、错误码、流中断、耗时、请求 ID、客户端 IP；满 50 条时显示“更早 →”链接 `?range=..&before=<最后一条 id>`）。错误率 `ok=false` 显示 `—`。时间按 `Location` 格式化 `01-02 15:04:05`。模板用 `html/template` + `go:embed`。

`svg.go`：`func trendSVG(buckets []stats.Bucket) template.HTML` —— 按桶画堆叠柱（成功/上游错误/流中断/relay 错误，客户端取消不画），固定 viewBox，无外部资源，只输出数字与固定颜色（无用户数据），所以可安全转为 `template.HTML`。

- [ ] **Step 1: 写失败测试**（用 `stats.Open(t.TempDir()+"/s.db")` + `Insert` 造数据，固定 `Now`）

| 测试名 | 断言 |
| --- | --- |
| `TestOverviewListsKeys` | alice 有 3 条（1 条 relay 错误）、`""` 1 条、配置 KeyIDs 含 `carol`（无数据）：200，`text/html`；body 含 `alice`、`(未鉴权)`、`href="/unauthenticated`、`carol`、`<svg`；alice 行出现 `33.3%` |
| `TestRangeSelection` | 记录在 now-3d：`?range=24h` 不计入、`?range=7d` 计入；`?range=bogus` 等同 24h |
| `TestKeyDetailFailures` | alice 有一条失败（request_id `req_fail1`, host `api.example.com`, error_code `UPSTREAM_TIMEOUT`）：`/keys/alice` 含这三个字符串 |
| `TestKeyDetailPaging` | 60 条失败：第一页含“更早”链接且含 `before=`；跟随后第二页 10 行且不含“更早”链接 |
| `TestUnauthenticatedPage` | `/unauthenticated` 200 并列出 `""` 的失败 |
| `TestInvalidKeyID` | `/keys/a%20b`、`/keys/` + 65 个 `a` → 404；`/keys/zed`（无数据）→ 200 |
| `TestSecurityHeaders` | 任意页面带上述 4 个头；`POST /` → 405 |
| `TestBasicAuth` | `Password: "pw"`：无凭据 401 且有 `WWW-Authenticate`；`admin:wrong` 401；`admin:pw` 200；`Password: ""` 时无凭据 200 |
| `TestHTMLEscapes` | 插入 target_host 为 `<script>x</script>` 的失败记录（绕过校验直接入库）：详情页不含原样 `<script>x`，含 `&lt;script&gt;` |

- [ ] **Step 2: 运行确认失败** — `go test ./internal/dashboard/`
- [ ] **Step 3: 实现**
- [ ] **Step 4: 运行确认通过** — `go test ./internal/dashboard/ -race -v`
- [ ] **Step 5: Commit** — `git commit -m "feat: add usage dashboard pages"`

---

### Task 11: 配置扩展、进程入口、部署样例与文档

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `README.md`
- Create: `cmd/relay/main.go`, `deploy/Caddyfile.example`, `deploy/relay.env.example`

**Interfaces:**
- Consumes: 全部前序任务的构造函数
- Produces（`config.Config` 新增字段）:
```go
StatsDB            string         // RELAY_STATS_DB，默认 "./data/relay-stats.db"
StatsRetentionDays int            // RELAY_STATS_RETENTION_DAYS，默认 30，>=1
DashboardAddr      string         // RELAY_DASHBOARD_ADDR，未设置默认 "127.0.0.1:8081"；显式设为空 = 关闭看板
DashboardPassword  string         // RELAY_DASHBOARD_PASSWORD
DashboardLocation  *time.Location // RELAY_DASHBOARD_TZ，默认 "Asia/Shanghai"，time.LoadLocation 校验
TrustedProxies     []string       // RELAY_TRUSTED_PROXIES，默认 ["127.0.0.1/32","::1/128"]，每项 netip.ParsePrefix 校验
```
看板地址校验：`DashboardAddr != ""` 且 host 不是 `localhost` 也不是环回 IP（含 host 为空如 `:8081`）且 `DashboardPassword == ""` → `Load` 返回错误。

- [ ] **Step 1: 写失败测试**（追加到 `config_test.go`）

```go
func TestLoadDashboardDefaults(t *testing.T) // StatsDB=="./data/relay-stats.db"；StatsRetentionDays==30；DashboardAddr=="127.0.0.1:8081"；DashboardLocation.String()=="Asia/Shanghai"；TrustedProxies==["127.0.0.1/32","::1/128"]
func TestLoadDashboardDisabled(t *testing.T) // RELAY_DASHBOARD_ADDR="" → DashboardAddr==""，无错误
func TestLoadRejectsPublicDashboardWithoutPassword(t *testing.T) // "0.0.0.0:8081"、":8081"、"10.0.0.5:8081" 无密码均报错；"0.0.0.0:8081"+密码通过；"localhost:8081"、"[::1]:8081" 无密码通过
func TestLoadRejectsBadDashboardValues(t *testing.T) // RELAY_DASHBOARD_TZ="Mars/Base"、RELAY_TRUSTED_PROXIES="notacidr"、RELAY_STATS_RETENTION_DAYS="0" 均报错
```

- [ ] **Step 2: 运行确认失败** — `go test ./internal/config/`
- [ ] **Step 3: 实现配置扩展**；运行 `go test ./internal/config/ -v` 通过
- [ ] **Step 4: 实现 `main.go`**

组装：`config.Load(os.LookupEnv)`（失败打印并 `os.Exit(1)`）→ `stats.Open(cfg.StatsDB)` → `stats.NewRecorder(store, logger, {10000, 200, time.Second})` → `go stats.RunRetention(ctx, store, days*24h, 24h, time.Now, logger)` → relay、router（`TrustedProxies`、`Recorder`）→ relay `http.Server{Addr: ListenAddr, ReadHeaderTimeout, MaxHeaderBytes: 64 << 10, IdleTimeout: 120s}`（**不设** `WriteTimeout`/`ReadTimeout`）→ `DashboardAddr != ""` 时另起 dashboard `http.Server{ReadHeaderTimeout: 10s, WriteTimeout: 30s}`，`KeyIDs` 取 `cfg.Keys` 的键排序。收到 SIGINT/SIGTERM：relay server `Shutdown`(30s) → dashboard `Shutdown`(5s) → 取消清理 ctx → `Recorder.Close`(5s) → `store.Close()`。

`deploy/Caddyfile.example`：`relay.example.com { reverse_proxy 127.0.0.1:8080 { flush_interval -1 } }`，注释说明 SSE 需关闭缓冲、`request_body` 上限应 ≥ `RELAY_MAX_REQUEST_BYTES`、看板端口不要经 Caddy 暴露。`deploy/relay.env.example`：列出 Task 2 与本任务全部变量及默认值，`RELAY_KEYS=client1:<用 openssl rand -hex 32 生成>`，不含真实密钥。`.gitignore` 加 `data/`。

- [ ] **Step 5: 构建与静态检查** — `go mod tidy && go build ./... && go vet ./... && go test ./... -race`，Expected: 全部通过
- [ ] **Step 6: 冒烟测试**

```bash
KEY=$(openssl rand -hex 32); RELAY_KEYS="dev:$KEY" RELAY_STATS_DB=/tmp/dar-smoke.db go run ./cmd/relay &
curl -s localhost:8080/healthz                                                   # {"status":"ok"}
curl -si localhost:8080/v1/relay -H 'X-Relay-Target: https://api.github.com/zen'  # 401 AUTH_FAILED
curl -si localhost:8080/v1/relay -H "X-Relay-Key: $KEY" -H 'X-Relay-Target: https://127.0.0.1/'  # 403 TARGET_FORBIDDEN
sleep 2; curl -s localhost:8081/ | grep -c '(未鉴权)'                              # ≥1，dev 行出现 1 条 relay 错误
```

- [ ] **Step 7: 更新 README** —— 状态改为“v1 已实现”，新增运行方式、看板访问方式（`ssh -L 8081:127.0.0.1:8081`）、环境变量参见 `deploy/relay.env.example`。
- [ ] **Step 8: Commit** — `git commit -m "feat: add relay entrypoint, dashboard wiring and deployment examples"`

---

## 不在本计划范围（对应 ARCHITECTURE §7）

按 key 单独配置限额、Redis 分布式配额、Prometheus（Milestone 2）；WebSocket `/v1/ws`（Milestone 3）；多区域节点（Milestone 4）；服务端安全跟随重定向（v2）；容器镜像（验收通过后再做）；看板的 JSON 接口、告警、实时刷新、多节点汇总。
