# 用量与报错看板 — 设计

状态：设计已定（2026-11-18）。所属：DynamicAPIRelay v1 之上的增量功能。
相关：`docs/ARCHITECTURE.md`、`docs/API_SPEC.md`、实现计划 `docs/superpowers/plans/2026-11-18-dynamic-api-relay-v1.md`。

## 1. 目的

运维者需要**按 relay key（即按客户端）**查看：

- **用量**：一段时间内的请求数、上下行字节、访问了哪些目标主机。
- **报错**：错误数与错误率，并区分 **relay 自身错误**（有 `error_code`：鉴权失败、限流、目标禁止、上游超时等）、**上游错误**（上游返回 4xx/5xx，如上游 401）、**流中断**（响应头已发出后中途失败）。
- 发现某客户端报错多时，能**下钻到具体失败请求**（时间、目标主机、状态码、错误码、耗时、请求 ID），再用请求 ID 去 JSON 日志里查。

量级：每天几千到几万请求。

## 2. 目标 / 非目标 / 反目标

**目标**：按 key 统计用量与报错；失败明细下钻；24h / 7d / 30d 三档时间范围；数据存 SQLite；不拖慢转发。

**非目标**：计费级精确对账（重启时队列中未落盘的少量记录可丢）；JSON/API 接口；告警推送；多节点汇总；实时刷新（手动刷新页面即可）；Prometheus（Milestone 2）。

**反目标**（技术上能跑也算失败）：
- 看板或数据库中出现 relay key、`Authorization` 等任何请求头、目标 URL 的 path/query、请求/响应 body。
- 看板可从公网直接访问且无鉴权。
- 记录统计导致转发请求阻塞或明显变慢（写库失败或变慢时只能丢统计，不能影响转发）。

## 3. 选定方案与备选

| 方案 | 说明 | 取舍 | 结论 |
| --- | --- | --- | --- |
| **1. 进程内 + 独立内网端口** | relay 访问日志中间件把记录投入内存队列，后台批量写 SQLite；同进程另开 `127.0.0.1:8081` 提供服务端渲染看板 | 单二进制单文件，部署最简；看板查询与转发共享进程资源（此量级可忽略） | **选定** |
| 2. 独立 dashboard 程序 | relay 写库，另一个进程只读同一 SQLite（WAL） | 解耦但多一个进程要部署运维，此量级无必要 | 放弃 |
| 3. Grafana + SQLite 插件 | 不写 UI | 多一套组件，按 key 下钻失败明细体验差 | 放弃 |

## 4. 设计

### 4.1 数据采集

数据源是实现计划 Task 8 的访问日志中间件（`requestContext`），它已持有 `reqctx.Info`。在其基础上：

- `reqctx.Info` 增加字段：`ClientIP string`、`BytesIn int64`、`Aborted bool`、`ClientCanceled bool`。
- **访问日志与统计记录必须在 `defer` 中输出**，保证 handler panic（含 `http.ErrAbortHandler` 流中断）时也会记录。
- `recoverer` 在捕获 `http.ErrAbortHandler` 时先置 `info.Aborted = true` 再重新 panic。
- `BytesIn`：relay handler 把请求体包装成计数读取器（在 `MaxBytesReader` 外层），记录实际读取的字节。`BytesOut` 取 `gin.ResponseWriter.Size()`（<0 时记 0）。
- **ClientIP**：Gin 默认信任所有代理，必须显式配置：`engine.SetTrustedProxies(cfg.TrustedProxies)`，`RemoteIPHeaders = ["X-Forwarded-For"]`，取 `c.ClientIP()`。默认可信代理 `127.0.0.1/32, ::1/128`（Caddy 在本机）。这只是**读取**，仍不向上游转发任何转发头。
- 时间戳取**请求开始时间**。
- **只记录 `/v1/relay` 路由上的请求**（包括其上的 401/400/429 等 relay 错误）；`/healthz`、未知路径 404、`/v1/relay` 上的 405 不记录，避免健康检查和扫描器噪声污染统计。*（实现者的决定）*
- **客户端取消**：请求结束时若 `r.Context().Err() != nil`（客户端断开）且不是 `MaxRequestDuration` 超时导致，则置 `info.ClientCanceled = true`。它既可能发生在响应头发出前（此时不写响应），也可能发生在流传输中途（此时同时会触发 `ErrAbortHandler`）。客户端取消不是 relay 或上游的错，单独成类、**不计入错误率**。*（实现者的决定）*

### 4.2 数据模型（SQLite）

```sql
CREATE TABLE IF NOT EXISTS requests (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,  -- 请求开始，Unix 毫秒
  request_id  TEXT    NOT NULL,
  key_id      TEXT    NOT NULL,  -- 未鉴权为 ''
  client_ip   TEXT    NOT NULL,
  method      TEXT    NOT NULL,
  target_host TEXT    NOT NULL,  -- 未到达目标解析阶段为 ''
  status      INTEGER NOT NULL,  -- 实际写给客户端的状态码
  error_code  TEXT    NOT NULL,  -- relay 错误码，非 relay 错误为 ''
  aborted     INTEGER NOT NULL,  -- 1 = 响应头已发出后中断
  client_canceled INTEGER NOT NULL, -- 1 = 客户端主动断开
  bytes_in    INTEGER NOT NULL,
  bytes_out   INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_ts     ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_key_ts ON requests(key_id, ts);
```

用 `PRAGMA user_version` 做 schema 版本（当前 1），启动时建表/迁移。

**结果分类**（看板中所有统计都基于此，互斥，优先级从上到下）：

| 类别 | 条件 |
| --- | --- |
| 客户端取消 | `client_canceled = 1` |
| relay 错误 | `error_code != ''` |
| 流中断 | `aborted = 1` |
| 上游错误 | `status >= 400` |
| 成功 | 其余（含 1xx/2xx/3xx） |

错误率 = (relay 错误 + 流中断 + 上游错误) / (总数 − 客户端取消)；分母为 0 时显示“—”。看板表格增加“客户端取消”一列。

### 4.3 写入路径

- `stats.Recorder`：容量 10000 的带缓冲 channel；`Record(r)` **非阻塞**发送，满则丢弃并累加 `dropped` 原子计数（看板页脚显示自启动以来丢弃数）。
- 单个后台 goroutine 每 1 秒或攒满 200 条，在**一个事务**内批量插入。
- 写库出错：记一条错误日志（不含记录内容以外的敏感信息），丢弃该批，继续运行；**永不影响转发**。
- 关闭时：停止接收、刷完队列，最多等 5 秒。
- SQLite 设置：`journal_mode=WAL`、`busy_timeout=5000`、`synchronous=NORMAL`；写连接独立（`MaxOpenConns=1`），看板读用另一个连接池。
- 驱动：`modernc.org/sqlite v1.40.1`（纯 Go，无 cgo，兼容 Go 1.24，本机已缓存）。

### 4.4 保留与清理

- 默认保留 30 天。启动时清理一次，之后每 24 小时一次：按 `ts < now - retention` 分批删除（每批 5000 行，直到删完），避免长时间持锁。
- 不做 VACUUM（此量级空间可复用即可）。

### 4.5 看板

**监听与访问控制**
- 独立 `http.Server`，默认 `127.0.0.1:8081`；`RELAY_DASHBOARD_ADDR` 为空表示不启用看板（统计仍照常写库）。
- 可选 HTTP Basic 认证：设置 `RELAY_DASHBOARD_PASSWORD` 后启用，用户名固定 `admin`，常量时间比较。
- **启动校验**：监听地址不是环回地址且未设置密码 → 拒绝启动并报错。
- 推荐访问方式：`ssh -L 8081:127.0.0.1:8081 <服务器>`。
- 所有页面只读，仅支持 GET；响应带 `Cache-Control: no-store`、`X-Frame-Options: DENY`、`Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'`。

**渲染**：`html/template` 服务端渲染；图表为服务端生成的内联 SVG；模板与 CSS 通过 `go:embed` 打包；不依赖任何外部 CDN/JS。时间按 `RELAY_DASHBOARD_TZ`（默认 `Asia/Shanghai`）显示与分桶。

**页面 1：总览 `GET /?range=24h|7d|30d`**（默认 24h）

```
DynamicAPIRelay 用量看板            [24小时] [7天] [30天]
┌──────────┬──────────┬──────────┬──────────────┐
│ 请求总数  │ 错误率    │ 下行流量  │ 活跃客户端     │
│ 12,345   │ 3.2%     │ 1.8 GiB  │ 5            │
└──────────┴──────────┴──────────┴──────────────┘
趋势（24h 按小时，7d/30d 按天；堆叠：成功/上游错误/流中断/relay错误）
▁▂▃▅▇▆▅▃▂▁ ...
客户端                请求    成功   上游错误 流中断 relay错误 错误率 上行  下行   p95耗时 最近请求
alice                 8,000  7,900  60       2      38       1.3%  2MiB 1GiB  820ms  11-18 14:02
bob                   4,000  3,700  250      0      50       7.5%  ...
(未鉴权)               345    0      0        0      345      100%  ...
页脚：统计丢弃 0 条 · 数据保留 30 天
```
- 客户端表按请求数降序，key_id 链接到详情页。`key_id=''` 显示为“(未鉴权)”。
- 客户端列表 = 该时间段有数据的 key ∪ 当前配置中的全部 key ID（无流量的显示为 0 行，便于发现停用的客户端）。看板只接收 key ID 列表，不接触 secret。*（实现者的决定）*
- 已从配置中删除的 key 仍按历史数据显示。
- p95 耗时：在 Go 中对该 key 该时间段的 `duration_ms` 计算（此量级可直接查出排序）；流式请求耗时包含整个流时长，这是预期行为。

**页面 2：客户端详情 `GET /keys/{key_id}?range=...`**；未鉴权请求的详情页为 `GET /unauthenticated?range=...`（不占用任何合法 key ID）。*（实现者的决定）*

- 该 key 的汇总卡片 + 趋势图（同总览）。
- **目标主机分布**：前 20 个 host，每个的请求数 / 错误数 / 错误率 / 下行字节。
- **错误分布**：按 `error_code`（relay 错误）与按 `status`（上游错误）分别计数，加流中断计数。
- **最近失败请求**：只列非“成功”类，按时间倒序，每页 50 条，列：时间、方法、目标主机、状态码、错误码、流中断、耗时、请求 ID、客户端 IP。分页用 `?before=<id>`（基于 id 的游标）。

数据完全以数据库为准：只有 key_id 格式不符合 `^[A-Za-z0-9_-]{1,64}$` 才返回 404；格式合法但无数据的 key 显示全 0 的详情页。`range` 非法值回退到 24h。*（实现者的决定）*

### 4.6 新增配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `RELAY_STATS_DB` | `./data/relay-stats.db` | SQLite 文件路径；目录不存在时创建（0700） |
| `RELAY_STATS_RETENTION_DAYS` | `30` | ≥1 |
| `RELAY_DASHBOARD_ADDR` | `127.0.0.1:8081` | 空 = 不启用看板 |
| `RELAY_DASHBOARD_PASSWORD` | 空 | 非空启用 Basic 认证；非环回监听时必填 |
| `RELAY_DASHBOARD_TZ` | `Asia/Shanghai` | `time.LoadLocation` 可解析的名称 |
| `RELAY_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | 逗号分隔 CIDR；用于解析客户端 IP |

## 5. 对现有实现计划的影响

- **Task 2（config）**：已完成，需追加上表配置项（新任务中修改）。
- **Task 7（relay）**：请求体计数读取器写入 `info.BytesIn`。
- **Task 8（server）**：访问日志改为 `defer`；`recoverer` 置 `Aborted`；设置可信代理并写 `info.ClientIP`；中间件结束时调用 `Recorder.Record`。`server.Deps` 增加 `Recorder`（接口，可为 nil 表示不记录）。
- **Task 9（main）**：打开 SQLite、启动 Recorder 与清理任务、启动看板 server；优雅关闭顺序：relay server → dashboard server → Recorder 刷盘 → 关闭 DB。
- **落地方式**：Task 7–9 尚未实现，直接修订实现计划中这三个任务的内容（把上述改动和测试并入），并新增 stats 与 dashboard 两个任务，而不是 v1 完成后再回头改。*（实现者的决定）*
- 新增包：`internal/stats`（schema、Recorder、清理、查询）、`internal/dashboard`（HTTP handler、模板、SVG）。

## 6. 留给实现者决定

CSS 样式与配色；SVG 图表的具体画法（柱状/面积）；查询 SQL 的具体写法；数字与字节的格式化方式；模板文件拆分方式。
