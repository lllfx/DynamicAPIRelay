# DynamicAPIRelay 设计方案（中文版）

> 状态：**仅设计文档，尚未实现代码或执行测试**。建议第一版采用 Go + Gin + net/http/httputil.ReverseProxy。

## 1. 核心需求

国内客户端通过一个固定的中转域名请求海外 API，**每次请求动态指定真实目标 URL**。以后新增 GitHub、OpenAI 或其他任何符合安全策略的 HTTPS 站点，国内只换目标 URL，中转服务器**无需增加路由、无需修改配置、无需重启**。

- 中转服务使用自己的 **X-Relay-Key** 进行客户端鉴权。
- 上游接口自己的 **Authorization、x-api-key** 与中转鉴权隔离。
- 支持 GET / HEAD / POST / PUT / PATCH / DELETE。
- 原样转发 JSON、XML、表单、Multipart、文本与二进制，支持文件上传/下载。
- SSE 必须实时流式返回，不先读取整个响应。
- v1 暂不承诺 WebSocket、gRPC、CONNECT 和浏览器整站代理；后续独立迭代。

## 2. 推荐架构

~~~text
国内 Go/Python/Java/CLI
    |
    | HTTPS + X-Relay-Key + X-Relay-Target + 原始 HTTP 请求
    v
海外 Caddy/NGINX (证书、TLS、基础连接限制)
    |
    v
Go Gin（仅监听内网）
    |
    +-- 中转密钥鉴权
    +-- 每 Key 限流与并发保护
    +-- URL 校验 / SSRF 防护
    +-- httputil.ReverseProxy
    |      +-- 安全 DNS 解析、连接时锁定合法公网 IP
    |      +-- TLS 正常验证，上游 Host/SNI 保持目标域名
    |      +-- 连接池、超时、取消传播
    |
    v
任意符合策略的公网 HTTPS API:443
    |
    +---- 原响应状态码 / 合法响应头 / 响应体（流式）---> 国内客户端
~~~

## 3. v1 接口协议

中转接口固定为 **/v1/relay**，目标地址不通过中转路径拼接，而是单独写在请求头中。

~~~http
POST /v1/relay HTTP/1.1
Host: relay.example.com
X-Relay-Key: YOUR_RELAY_KEY
X-Relay-Target: https://api.example.com/v1/messages?model=demo
Authorization: Bearer UPSTREAM_TOKEN
Content-Type: application/json

{"message":"hello"}
~~~

关键处理规则：

1. **先鉴权再解析 DNS**：未通过中转鉴权不得访问外部。
2. X-Relay-Target 是包含路径、查询参数的完整绝对 URL。中转入口自身不再添加路径或查询参数。
3. X-Relay-Key、X-Relay-Target 以及其他中转控制请求头不得传给上游。
4. 上游使用的 Authorization、x-api-key 只转发给校验后的目标地址。
5. 不使用 Gin 的 BindJSON 解析业务请求，也不把响应封装成统一 JSON；保持输入/输出字节流。
6. 透传上游 HTTP 状态码；上游 401/429/500 与中转自身错误不同。中转产生的错误用 X-Relay-Error: true 标记，返回简洁 JSON。
7. v1 **不自动跟随 3xx 重定向**，原样返回 Location。调用端应关闭自动重定向，必要时重新发起携带新 X-Relay-Target 的中转请求。

测试调用：

~~~bash
curl 'https://relay.example.com/v1/relay' \
  -H 'X-Relay-Key: YOUR_RELAY_KEY' \
  -H 'X-Relay-Target: https://api.github.com/users/octocat'
~~~

SSE 客户端使用 curl -N，并关闭边缘网关的响应缓冲。文件上传用 multipart 原始流，文件下载原样复制至文件，不在服务器内存中完整缓存。

## 4. 必须实现的安全约束

**动态公网目标，不等于允许访问任意网络地址。** 自定义密钥不能替代 SSRF 防护。

- v1 只允许 **HTTPS、DNS 域名、443 端口**；禁止 IP 字面量、用户信息、URL fragment、控制字符、异常编码。
- DNS 解析后判断所有 A/AAAA 地址：拒绝 127.0.0.0/8、RFC1918、169.254.0.0/16、IPv6 ULA/link-local、云元数据和其他特殊保留地址。不能仅依赖 IsGlobalUnicast。
- 必须在**实际拨号**时连接已校验的公网 IP，防止 DNS 重绑定；TLS SNI、Host 和证书校验仍使用原始目标域名。
- 关闭环境变量自动 HTTP_PROXY/HTTPS_PROXY，避免绕开安全拨号器。服务器出口防火墙应再次禁止私网/元数据访问。
- 每个调用方独立中转 Key，支持撤销、轮换、限速、并发上限；建议 Key 使用至少 256 bit 随机值。
- 限制请求头、请求体大小、响应字节数、连接数和流式会话占用；客户端断开时应取消上游请求。
- 日志只记录 request_id、Key ID、目标域名、方法、状态码、耗时、流量与错误分类；**不记录密钥、Authorization、Cookie、请求体或完整 URL 查询参数**。
- 禁止未经测试的自动重试，尤其是 POST。不要关闭 TLS 证书校验。
- 浏览器直接使用场景需额外设计 CORS、密钥保管与 Cookie 域名；v1 主要面向服务端/CLI 客户端。

## 5. 代码模块建议（目录尚未创建）

| 模块 | 职责 |
| --- | --- |
| cmd/relay | 启动入口与配置加载 |
| internal/httpserver | Gin 路由、健康检查、错误协议 |
| internal/auth | 中转 Key 验证、撤销/轮换 |
| internal/target | 完整 URL 解析、策略和 DNS 校验 |
| internal/transport | 安全拨号、TLS、超时、连接池 |
| internal/relay | ReverseProxy.Rewrite、请求响应转发 |
| internal/limits | 每 Key 限流、并发和流量限制 |
| internal/telemetry | 脱敏日志与指标 |
| deployments | Dockerfile、Compose、Caddyfile |
| tests/integration | 虚拟上游与 SSRF/流式测试 |

注意：ReverseProxy 的 SetURL 会将目标基础路径与传入路径合并。本项目目标 URL 已含完整路径，开发时需将**完整目标 URL**赋给本次请求的出站 URL，不能意外追加 /v1/relay。

## 6. 开发阶段和验收

- **P0 基础框架**：配置校验、健康检查、基础 Gin 路由、CI。
- **P1 最小可用**：动态目标、独立鉴权、HTTP 透传、DNS/IP/TLS 校验、规范错误。
- **P2 完整 API 中转**：SSE、文件、内存/流量限制、限速/并发、取消传播、脱敏日志。
- **P3 生产部署**：Docker Compose、Caddy HTTPS、容器最小权限、安全出口规则、集成测试。
- **P4 可选**：WebSocket、Redis 分布式限流、Key 管理台、多地区节点、可选安全重定向。

上线验收必须证明：新公网 API 不用改海外配置；鉴权失败前不触发 DNS；中转 Key 不到达上游；上游鉴权照常生效；内网与云元数据不可达；文件校验和一致；SSE 不缓冲；请求取消后无连接泄漏；所有安全用例通过。

## 7. 详细文档

- [Architecture](ARCHITECTURE.md) — 架构与 HTTP 语义细节
- [API Specification](API_SPEC.md) — 详细接口契约、请求示例与状态码
- [Security](SECURITY.md) — SSRF、鉴权、攻击模型和防护
- [Implementation Plan](IMPLEMENTATION_PLAN.md) — 目录、阶段和完成定义
- [Test Plan](TEST_PLAN.md) — 单测、集成测试与上线门槛

技术依据：[Go ReverseProxy](https://pkg.go.dev/net/http/httputil#ReverseProxy)、[OWASP SSRF 防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)。

> 本方案是面向公网 HTTPS API 的 HTTP 中转，并非所有网站或所有协议的透明网络代理。使用前须遵守适用法律、目标服务条款及网络安全要求。
