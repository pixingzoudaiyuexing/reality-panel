# Changelog — relay-node

All notable changes to the **relay-node** binary are documented here. This
binary is released together with the Panel under one `vX.Y.Z` tag.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

---

## [1.1.24] - 2026-09-11

统一版本发布。本次 ACME DNS-01 timeout 修复仅位于 Panel；relay-node 无功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.23 relay-node 与 v1.1.24 Panel 功能兼容；v1.1.24 Node artifact 仅同步发布版本号。

## [1.1.23] - 2026-09-11

### 新增

- 新增 Lite 节点部署模式，使用 Nginx 静态 fallback，跳过 Docker 和 Xiaoya。
- Lite marker 在 relay-node 重启和升级时保持运行模式不变。

### 兼容性

- Standard 节点和 legacy 节点继续保持原有 Docker/Xiaoya 行为。
- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.22 relay-node 可直接升级到 v1.1.23。

## [1.1.22] - 2026-09-10

### 兼容性

- relay-node 无功能代码变化；本版本与 Panel 一起发布以保持统一版本号。
- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.21 relay-node 可直接升级到 v1.1.22。

## [1.1.21] - 2026-09-10

### 修复

- 长连接 Raw TCP、TLS、WebSocket 转发流量在连接存活期间实时累计；Linux splice 仅在目标 socket 成功接收后计数。
- UDP 新会话保持既有 selector 顺序，并在目标 connect 失败时继续尝试后续候选目标。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.20 relay-node 可直接升级到 v1.1.21。

## [1.1.20] - 2026-09-09

### 改进

- 新节点 bootstrap 改为 Xiaoya-first，仅在 Xiaoya `127.0.0.1:5245` 健康后启用本地 camouflage fallback。
- 新增 Node-local 原生 BBR + fq 准备，正常启动和新节点安装复用同一实现；不支持时非阻断。
- 既有节点升级继续恢复历史 LKG，并忽略历史 camouflage 软件资源。

### 兼容性

- 不安装第三方内核，不自动重启，不增加自动历史 backend fallback。
- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.19 relay-node 可直接升级到 v1.1.20。

## [1.1.19] - 2026-09-09

统一版本发布。本次仅修正 Panel 前端测试的异步等待；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.18 relay-node 与 v1.1.19 Panel 功能兼容；v1.1.19 Node artifact 仅同步发布版本号。

## [1.1.18] - 2026-09-09

### 新增

- 新增 Node-local Xiaoya BYOA 管理，在保留 Legacy OpenList `127.0.0.1:5244` 的同时提供独立的 `127.0.0.1:5245` camouflage backend。
- Xiaoya 经严格健康检查后，使用现有 Nginx apply 和 LKG 事务完成 backend 切换；未知容器或端口占用会安全拒绝。
- 节点诊断显示当前实际使用的 camouflage backend。

### 兼容性

- Legacy OpenList 安装、数据、更新和卸载行为不变；Xiaoya 故障不会自动回退到 OpenList。
- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.17 relay-node 可直接升级到 v1.1.18。

## [1.1.17] - 2026-09-09

统一版本发布。本次仅修正 Panel 前端线路提交结果提示；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.16 relay-node 与 v1.1.17 Panel 功能兼容；v1.1.17 Node artifact 仅同步发布版本号。

## [1.1.16] - 2026-09-09

统一版本发布。本次仅修正 Panel 前端测试；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.15 relay-node 与 v1.1.16 Panel 功能兼容；v1.1.16 Node artifact 仅同步发布版本号。

## [1.1.15] - 2026-09-09

统一版本发布。本次线路功能配置与启用 UX 改动均位于 Panel；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.14 relay-node 与 v1.1.15 Panel 功能兼容；v1.1.15 Node artifact 仅同步发布版本号。

## [1.1.14] - 2026-09-09

统一版本发布。本次线路模式、Carrier 全网默认及 NodeStatus UX 改动均位于 Panel；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.13 relay-node 与 v1.1.14 Panel 功能兼容；v1.1.14 Node artifact 仅同步发布版本号。

## [1.1.13] - 2026-09-08

统一版本发布。本次 Hotfix 仅修改 Panel backend/frontend；relay-node 没有功能代码变化。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.12 relay-node 与 v1.1.13 Panel 功能兼容；v1.1.13 Node artifact 仅同步发布版本号。

## [1.1.12] - 2026-09-08

统一版本发布。批量滚动升级 orchestration 位于 Panel，Relay Node 继续使用现有单节点 Upgrade protocol 和精确完成确认。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.11 relay-node 可直接升级到 v1.1.12。

## [1.1.11] - 2026-09-08

### 修复

- 公网 IP 探测失败后按 5、10、30、60 秒退避重试，持续失败以 60 秒为上限，成功后恢复 30 分钟刷新周期。
- 缺少安全公网 IP 时保持普通 forwarding config 可用，并沿用现有 camouflage dependency withholding/LKG 保护。
- HTTP 配置拉取瞬时失败时保留健康的 Panel-authoritative Converged 状态；真实 runtime drift 仍执行原有 LKG repair。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.10 relay-node 可直接升级到 v1.1.11。

## [1.1.10] - 2026-09-08

### 修复

- Nginx SNI plan 分别保留 configured target identity 与 resolved runtime target，避免 hostname 规则被诊断为映射不一致。
- Nginx render 和 DNS refresh 继续使用解析后的 runtime target。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.9 relay-node 可直接升级到 v1.1.10。

## [1.1.9] - 2026-09-08

### 修复

- 修复 Linux 构建中 Reality TCP telemetry reader 的函数生命周期编译错误。
- TCP/UDP telemetry 行为和协议保持不变。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.6 relay-node 可直接升级到 v1.1.9。

## [1.1.8] - 2026-09-08

### 新增

- Rule diagnostics 由实际承载规则的 Relay Node 完成 DNS 解析和目标连接测试。
- 支持完整卸载受管 Relay Node，并安全清理 systemd、配置、缓存和受管 Nginx 资源。

### 修复

- 强化卸载操作的所有权检查、幂等结果回调、重启恢复和最终状态收敛。
- 分别上报 TCP 活跃连接与 UDP 活跃会话，并统计 Reality managed Nginx SNI 入站连接。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.6 relay-node 可直接升级到 v1.1.8。

## [1.1.6] - 2026-09-07

统一版本发布。证书全局资源修复位于 Panel，Relay Node runtime 和协议不变。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.5 relay-node 可直接升级到 v1.1.6。

## [1.1.5] - 2026-09-06

relay-node 本地恢复与 Panel 权威配置重新收敛热修复。

### 修复

- 修复 Config Protocol v10 的 LKG 在依赖暂缓时“desired fingerprint 与 effective config 不同”被误判为缓存损坏的问题。
- 本地恢复现在保留 Panel desired fingerprint 与 revision，不再错误回退到更旧的空 listener backup。
- 同 revision 的 Panel 权威配置在本地恢复后可以重新收敛到当前 desired runtime。
- 包含 v1.1.4 的 Node ID 单一事实来源修复。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- 无数据库 migration。
- v1.1.3 / v1.1.4 relay-node 可直接升级到 v1.1.5。

## [1.1.4] - 2026-09-06

relay-node Node ID 单一事实来源热修复。

### 修复

- HTTP 配置拉取和 WebSocket `config_changed` 刷新不再运行期重读 Node ID 文件。
- 所有常驻控制通道统一使用进程启动时解析的 Node ID，避免配置请求 503、空 LKG 回退和监听撤销。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.3 relay-node 可直接升级到 v1.1.4。

## [1.1.3] - 2026-09-06

统一版本热修复。Relay Node 运行时逻辑与协议不变；版本随 Panel 统一提升至 `1.1.3`。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.2 relay-node 可直接升级到 v1.1.3。

## [1.1.2] - 2026-09-06

统一版本发布。Relay Node 无运行时或协议变化；Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。

### 兼容性

- v1.1.1 可直接升级到 v1.1.2。

## [1.1.1] - 2026-09-05

Unified v1.1.1 relay-node release. Config Protocol remains 10 and Lifecycle
Protocol remains 1.

### Fixed

- Stable v1.1.0+ Nodes advertise the Reality Nginx SNI reapply capability
  independently from the stricter rule-restart capability gate.

### Improved

- Nginx SNI hostname targets use the shared 30-second DNS cache and safely
  reload only after a resolved-address change. Resolver failures retain the
  last known good upstream; literal targets, load balancing, and Proxy Protocol
  behavior are unchanged.

## [1.1.0] - 2026-09-03

First stable 1.1 relay-node release. This promotes the accepted RC9
node line without additional runtime or wire-protocol changes.
Config Protocol remains 10 and Lifecycle Protocol remains 1.

## [1.1.0-rc.9] - 2026-09-01

Unified Reality Panel release alignment. Carrier Affinity is implemented by
the Panel and DNSMgr integration and does not change the relay-node runtime or
wire contract. Config Protocol remains 10 and Lifecycle Protocol remains 1.

## [1.1.0-rc.8] - 2026-08-31

Reality relay-node release candidate with Config Protocol 10 and Lifecycle
Protocol 1 compatibility.

### Added

- Automatic synchronization of Panel-centralized certificates through the
  authenticated certificate endpoint.
- Node-local source metadata that tracks the Panel generation and certificate
  fingerprint without changing the existing timestamp generation semantics.

### Fixed

- Stale desired completion remains pending for reconciliation instead of
  leaving the Node permanently `DEPENDENCY_WITHHELD`.
- Centralized certificate application, restart recovery, and Nginx/LKG failure
  paths preserve the previous valid certificate and runtime.

## [1.1.0-rc.7] - 2026-08-30

Reality relay-node release candidate with Config Protocol 10 and Lifecycle
Protocol 1 compatibility.

### Added

- Safer Reality dependency reconciliation with LKG preservation, including
  config revision, ordering, and stale-state protections.
- Persistent certificate retry backoff and certificate-domain lifecycle
  deduplication for shared wildcard coverage.

### Fixed

- Wildcard certificate diagnosis now reflects objective certificate
  usability, while runtime, camouflage, and listener failures preserve the
  last known good state.

## [1.0.1] - 2026-08-29

Unified hotfix release. The relay-node runtime behavior and config protocol 8
remain unchanged; the Node package version is aligned with the Panel release.

## [1.0.0] - 2026-08-29

First stable relay-node release. This promotes the accepted rc.6 code line
without changing Node runtime behavior or config protocol 8.

## [1.0.0-rc.6] - 2026-08-28

Adds the managed global HTTP-to-HTTPS redirect, safely disables only the
standard Debian default-site symlink, and preserves the redirect across
certificate lifecycle work. Reality SNI `:443`, camouflage `:8443`, Proxy
Protocol behavior, Reality `xver=0`, and config protocol 8 remain unchanged.

## [1.0.0-rc.5] - 2026-08-28

Release candidate update for the Panel-side relay-node artifact metadata
permission repair. The node binary and config protocol are unchanged.

## [1.0.0-rc.4] - 2026-08-28

First Reality Panel release candidate for the relay-node binary. Includes the
validated Reality SNI, Proxy Protocol, lifecycle, reconciliation, recovery,
diagnostics, and camouflage runtime.

## [1.2.2] - 2026-08-13

Node release for Reality SNI forwarding. Requires a panel that speaks config
protocol 5 for `nginx_sni` rules.

### Added

- **Nginx Stream SNI router.** `relay-node` can now manage an Nginx
  `ssl_preread` stream configuration and route multiple Reality SNI domains
  through one public `:443` listener.
- **Load strategies for SNI upstreams.** `first`, `round_robin`, and
  `failover` are rendered into the generated Nginx upstreams.
- **Per-rule traffic ingestion.** The node tails the Nginx SNI access log,
  maps entries back to rule ids, and reports upload/download bytes to the
  panel.

### Changed

- **Node installer supports SNI mode.** `scripts/relay-node-install.sh` now
  accepts `--nginx-sni`, OpenList fallback via `--openlist-port`, and custom
  fallback settings via `--fallback-*`.
- **Fallback no longer creates a fake default site.** If no fallback is
  configured, unmatched SNI traffic fails closed to `127.0.0.1:9`. Operators can
  attach their own OpenList or HTTPS site instead.
- **Release source switched to this fork.** The installer and self-updater now
  use `pixingzoudaiyuexing/relay-panel` releases.

---

## [1.2.1] - 2026-08-02

Node only. Nothing on the wire changed — the config protocol stays at version
4, so this node runs against any current panel, and upgrading is optional
unless the node sits somewhere `api.ipify.org` cannot be reached.

### Changed

- **Public-IP detection no longer uses ipify.** `api.ipify.org` is unreachable
  from mainland China, so on a node there the probe timed out every 30 minutes
  forever and the panel showed no address for it — and therefore no country
  flag and no region — while the node was otherwise perfectly online. The
  defaults are now `api-ipv4.ip.sb` / `api-ipv6.ip.sb`, which answer from both
  sides.

  Both defaults must stay **family-pinned**, and a test now enforces it. The two
  probes validate the address family and discard a mismatch, so a dual-stack
  endpoint — one that replies with whichever family the connection happened to
  use — makes the IPv4 probe intermittently throw its answer away. That failure
  appears only on dual-stack hosts and only sometimes, which is why it is worth
  a test rather than a comment.

  Existing nodes keep working unchanged and can be fixed without upgrading, by
  setting `PUBLIC_IPV4_CHECK_URL` in `/opt/relay-node/relay-node.env` and
  restarting. The installer now writes both variables as commented examples.

## [1.2.0] - 2026-07-21

### Added

- **`restart_rule` control message.** The panel can ask the node to drop one
  rule's connections and rebuild its listeners on each node of its inbound group. Owner-scoped (a user may restart only their own
  rules); batch restart is the frontend calling it per rule, matching batch
  pause/resume, so there is deliberately no bulk endpoint. The rule's `paused`
  flag is never read or written — a restart is not a state transition. A paused
  rule is rejected rather than reported as a hollow success: it has no listener
  to restart, and the user's actual intent there is "resume".

  This is deliberately NOT implemented as pause+resume. That pair leaves the
  rule PAUSED if the resume half fails (node offline, authorization revoked
  between the two calls, panel restarted mid-way) — an outage caused by the
  button whose whole job is to end one. It also frees the listen port for
  auto-assignment during the gap, and writing `paused` resets `auto_paused`
  (v1.0.8), corrupting the system-paused vs. human-paused distinction.

  The response's `restarted` field counts nodes ACTUALLY reached and can be 0
  on an otherwise successful request (every node too old or offline), so the UI
  keys its message off that rather than the envelope code — a restart that
  silently did nothing would otherwise be undetectable.

- **Scheduled rule restart.** A rule with `auto_restart_minutes > 0` has its
  connections dropped on that interval. The `max_connections` cap is the actual
  fix for connection accumulation; this is the valve for when you'd rather shed
  than refuse.

  The schedule lives in MEMORY, not the database. Persisting `last_restart_at`
  would mean every rule whose interval elapsed while the panel was down comes
  due at once on boot — a panel upgrade would begin by dropping every
  auto-restart rule's connections simultaneously. In-memory re-bases each timer
  to "now" on restart; the cost is at most one skipped cycle, which is invisible
  next to an unscheduled mass disconnect. A rule seen for the first time is
  baselined, never restarted on the spot.

- **Rule connection controls, storage + API** (no enforcement yet — the node
  half lands separately). Two new per-rule settings, both `0` = off/unlimited so
  an upgrade changes nothing until a rule is explicitly opted in:
  - `max_connections` — cap on concurrent TCP connections, scoped PER NODE.
    Nodes share no state and a group-wide total would need a central allocator
    on the forwarding hot path, so a rule served by 3 nodes admits up to 3x this
    number. The panel ships it to nodes in `ListenerConfig`; a node that doesn't
    understand it ignores it (`#[serde(default)]`).
  - `auto_restart_minutes` — interval for scheduled restarts. A non-zero value
    below `MIN_AUTO_RESTART_MINUTES` (5) is rejected: a shorter loop would drop
    connections faster than clients can reconnect, turning the safety valve into
    the outage.

  Both are edit-only. The atomic create path (`create_rule_with_guard`) doesn't
  carry them, so offering them at create would silently discard the value.
  `PUT /rules/{id}` defaults an omitted one to the rule's CURRENT value rather
  than to 0 — otherwise setting only `max_connections` would silently switch off
  that rule's scheduled restart.

### Compatibility

- Nodes below **1.2.0** silently ignore the unknown `restart_rule` message. The
  panel gates on `node_supports_restart_rule` and surfaces those nodes as
  "upgrade required" rather than counting them as restarted — a restart that
  quietly did nothing would be undetectable to the operator. Node Status already
  offers one-click upgrade.

### Schema

- SQLite Migration **38**, PG revision **21** (`PG_SCHEMA_VERSION` 20 → 21):
  `forward_rules.max_connections` and `forward_rules.auto_restart_minutes`, both
  `NOT NULL DEFAULT 0`. 0 = unlimited/off. A pre-v1.2 rule must come out
  UNCAPPED — if 0 reached a node as a real cap, upgrading would throttle every
  existing rule to zero connections; `max_connections_zero_means_unlimited_on_the_wire`
  pins that.

---

_The node has no code, forwarding, protocol, or dependency changes in this
round, so no newer `node-v*` version is cut. A node release is only tagged when
something node-side actually changed._
