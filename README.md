# Reality Panel

> 面向 Reality SNI 中转场景的自托管控制面板：集中管理 Relay 节点、SNI 转发、DNS、证书、伪装站与节点生命周期，同时尽量让数据面不依赖 Panel 持续在线。

**当前稳定版：`v1.1.1`** · **Config Protocol：`10`** · **生产部署：Debian 12 / amd64 / systemd** · **License：AGPL-3.0**

---

## 项目简介

Reality Panel 用来管理一组 Relay 节点，并把 Reality / SNI 四层转发、DNS 自动化、证书生命周期和节点运维统一到一个控制面中。

它不是 Reality/Xray 的认证面板，也不会在 Relay 上终止 Reality TLS。Reality 握手仍然端到端到达真实后端；Relay 负责基于 SNI 进行四层透明转发。

```text
客户端
  │
  │  TCP / TLS ClientHello
  ▼
Relay Node :443
  │
  ├─ SNI = hk.example.com ──> Reality / Xray Backend A
  ├─ SNI = jp.example.com ──> Reality / Xray Backend B
  ├─ SNI = us.example.com ──> Reality / Xray Backend C
  │
  └─ 未命中 Reality SNI ────> HTTPS 伪装站 / OpenList
```

同一个 Relay 可以在 **同一监听端口（例如 443）** 上承载多个不同 SNI；规则由 Nginx Stream `ssl_preread` 进行路由。

项目的核心设计目标是：

> **控制面负责管理和收敛，数据面尽可能保留最后一份可工作的运行状态。**

---

## 主要能力

### Reality SNI 四层转发

- 基于 Nginx Stream 的 SNI 路由
- Reality TLS 端到端透传，不在 Relay 解密
- 同一入口端口支持多个不同 SNI
- 支持 IPv4 / IPv6 后端
- 支持后端目标使用 IP 或 hostname
- 支持 Proxy Protocol v1
- Nginx 配置在应用前执行校验，失败时保留旧运行状态

### 后端 DDNS 自动跟随

Reality 规则的 **转发目标** 可以填写域名，例如：

```text
home.example.com:50036
```

当该域名由你自己的 DDNS 客户端更新公网 IP 后，Relay Node 会重新解析后端 hostname：

```text
home.example.com
1.1.1.1
    ↓ DDNS 更新
2.2.2.2
    ↓
Relay 自动检测变化
    ↓
nginx -t
    ↓
safe reload
```

行为原则：

- 解析结果变化：更新 upstream
- 解析结果未变化：no-op，不重复 reload
- DNS 临时失败且已有旧地址：继续保留 Last Known Good upstream
- 不会因为一次临时解析失败把 Nginx upstream 清空

这套 DDNS 逻辑只作用于 **后端转发地址**，与 Reality SNI 的 DNS 自动化是两套独立能力。

### Relay 节点管理

Panel 可以集中管理 Relay Node：

- SSH Bootstrap 部署
- Manual Bootstrap 恢复路径
- 在线 / 离线 / 就绪 / 异常状态
- 节点日志
- 规则诊断
- 配置重新收敛
- 节点重启
- 一键更新
- Panel / Node 版本兼容性检查
- 多 Relay 共同承载同一个入口 Group

Node 安装包与 Panel 使用同一 GitHub Release，部署时会校验版本、架构与 SHA-256。

### DNSMgr 自动化

Reality Panel 可以通过 DNSMgr 自动维护 Reality SNI 对应的 DNS 记录。

主要安全边界：

- 只修改 Panel 能证明归属自己的记录
- 不静默接管已有外部记录
- DNS 冲突时 fail closed
- Provider mutation 后进行 read-back 验证
- 删除前重新确认记录身份和值
- DNS 状态不明确时不提交新的拓扑切换
- Panel / DNSMgr 暂时不可用时，不主动破坏已经工作的 Relay 数据面

### Carrier Affinity / 运营商线路绑定

对于支持线路解析的 DNS Provider，可以为同一个入口 Group 配置不同线路对应的 Relay。

每条线路可以选择：

- **不单独配置**：交给 DNS Provider 自己决定继承 / 默认行为
- **跟随默认 Relay**：随着 Group 的首选 Relay 一起切换
- **指定 Relay**：固定到一个指定且已就绪的 Relay

同一 Reality Rule 可以同时维护默认记录和多个线路记录。

### Relay Preference

每个入口 Group 可以配置首选 Relay。

切换时 Panel 会先确认目标 Relay 的就绪状态，再进入 DNS / 拓扑变更流程。失败时不会直接覆盖旧的可用状态。

### 定时 Relay 切换

支持预先配置：

- 单次切换
- 每日切换
- 每周切换
- Panel 重启后恢复计划

定时任务复用现有 Relay Preference、安全 DNS 事务和回滚边界。

### 集中式 wildcard 证书

Panel 可以集中申请并管理 wildcard 证书，再把同一代证书分发给 Group 内需要它的 Relay。

新规则如果已经被现有可信 managed wildcard 覆盖，可以直接复用该证书，而不必重复申请。

证书链路遵循以下原则：

```text
DNS ownership
    ↓
ACME DNS-01
    ↓
TXT propagation gate
    ↓
Certificate
    ↓
Generation publish
    ↓
Relay certificate sync
    ↓
Nginx validation / reload
```

`v1.1.1` 对 ACME DNS-01 增加了 hard propagation gate：传播失败的 issuance 不允许继续发布 managed generation；后续独立 retry 可以重新进入完整授权流程。

公网业务 A 记录的传播观察与证书签发可以并行推进，不需要无意义地串行等待。

### HTTPS 伪装站

Reality Rule 可以同时配置 HTTPS fallback / camouflage：

- OpenList
- 自定义 HTTP 上游
- wildcard 证书
- HTTPS fallback
- HTTP → HTTPS 跳转

Reality SNI 命中时进入四层转发；普通 HTTPS 请求进入伪装站。

### Proxy Protocol v1

可以让 Relay 向 Reality/Xray 后端发送 HAProxy PROXY Protocol v1，以便后端获取真实客户端地址。

正确启用顺序：

```text
后端先启用 PROXY Protocol 接收
        ↓
确认后端 Reload 并已生效
        ↓
最后在 Relay 打开发送
```

关闭时反过来：先关闭 Relay 发送，再关闭后端接收。

Reality 的 `xver` 与 Relay → Backend 的 Proxy Protocol 是两套独立机制。

### Diagnosis / 修复操作

规则诊断会聚合现有运行证据，包括：

- Node 配置收敛
- Nginx runtime
- SNI mapping
- Backend reachability
- Certificate
- TLS handshake
- Camouflage / fallback

对于 Reality/nginx_sni 规则，监听状态以真实 Nginx runtime 为依据，而不是 generic listener。

高级修复操作提供 **重新加载 SNI 路由**：基于 Node 最后接受的配置重新生成共享 Nginx SNI plan，执行配置校验并安全 reload；它不会重新签发证书、修改 DNS 或重启 relay-node。

---

## LKG：数据面优先

Reality Panel 和 Relay Node 大量使用 **Last Known Good（最后已知可用状态）** 思路。

典型行为：

- Panel 宕机：已运行 Relay 继续工作
- 新配置失败：不覆盖旧的可用配置
- Nginx 校验失败：不 reload 错误配置
- 新证书失败：不替换当前有效证书
- 后端 hostname 临时解析失败：继续使用旧 upstream
- Relay 重启：优先恢复本地最后已知可用运行状态

因此 Panel 是控制面，而不是每个数据包都必须经过的转发路径。

---

## 适用场景

Reality Panel 更适合下面这类结构：

```text
                    ┌─ Relay HK ─┐
客户端 ── DNS/SNI ──┼─ Relay JP ─┼── Reality / Xray Backend
                    └─ Relay US ─┘
                           │
                      Reality Panel
                      控制 / DNS / 证书
```

例如：

- 多台中转机统一管理
- 一个 443 端口承载多个 SNI
- Relay 与真实 Reality 后端解耦
- 多 Relay 主备 / 线路选择
- 定时切换入口 Relay
- 后端公网 IP 经常变化，需要 DDNS
- 希望 Panel 故障时已有规则仍能继续运行

---

## 系统要求

当前正式生产路径：

| 项目 | 要求 |
| --- | --- |
| Panel OS | Debian 12 |
| Relay OS | Debian 12 |
| 架构 | amd64 / x86_64 |
| 服务管理 | systemd |
| 安装权限 | root |
| Panel 默认端口 | `18888` |
| 当前稳定版 | `v1.1.1` |
| Config Protocol | `10` |

Docker 文件仍可能保留在仓库中作为开发 / 兼容资产，但 **Docker 已不再属于正式自动发布流程**。生产安装以 GitHub Release 的 systemd 二进制资产为准。

---

## 快速安装

在全新的 Debian 12 amd64 服务器上使用 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh | bash
```

安装器会：

1. 解析最新稳定 GitHub Release
2. 下载 Panel / Node / Web / 部署脚本
3. 校验 `SHA256SUMS`
4. 安装 systemd 服务
5. 初始化配置和数据目录
6. 启动并检查 Panel

默认端口：

```text
18888
```

全新数据库首次安装成功后，终端会一次性显示初始管理员账号信息。登录后请立即修改密码。

### 指定版本

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- v1.1.1
```

### 指定 Panel 端口

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- --port 28888
```

### 指定公网 Panel URL

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- --public-panel-url https://panel.example.com
```

如果没有显式提供 `PUBLIC_PANEL_URL`，安装器会尝试获取服务器公网 IPv4，并生成：

```text
http://PUBLIC_IPV4:18888
```

公网或不可信网络部署，建议使用 HTTPS。

---

## 安装目录

默认 systemd 部署主要使用：

```text
/etc/relay-panel/relay-panel.env
/var/lib/relay-panel/
/opt/relay-panel/
/usr/local/sbin/reality-panel-update
```

默认 SQLite 数据：

```text
/var/lib/relay-panel/data.db
```

Panel service：

```text
relay-panel.service
```

查看状态：

```bash
systemctl status relay-panel --no-pager
```

查看日志：

```bash
journalctl -u relay-panel -f
```

---

## 部署 Relay Node

正常情况下不需要手工在 Relay 上拼安装命令。

推荐流程：

```text
Panel
→ 节点管理
→ Node Bootstrap
→ 填写 Relay SSH 信息
→ Panel 选择当前 Release 的 Node artifact
→ 校验版本 / 架构 / SHA-256
→ 安装 relay-node
→ 建立控制通道
```

Panel 无法主动 SSH 到 Relay 时，可以使用 Manual Bootstrap 作为高级恢复路径。

生产 Node 应使用与 Panel 对应的正式 GitHub Release 资产，不建议使用分支临时构建或 CI 临时 artifact。

---

## 升级

安装完成后系统会提供：

```bash
reality-panel-update
```

升级到最新稳定版：

```bash
reality-panel-update
```

升级到指定版本：

```bash
reality-panel-update v1.1.1
```

更新器会先验证完整 Release，再执行切换，并保留配置、数据库、证书和运行数据。

生产升级前仍建议备份：

```text
/etc/relay-panel/
/var/lib/relay-panel/
```

Relay Node 可以从 Panel 节点管理中逐台执行更新。

---

## 卸载

默认卸载会删除 Panel 服务和安装文件，但保留本地配置与数据：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- uninstall
```

彻底删除本地配置和数据属于破坏性操作，请先备份后再使用 `--purge`。

卸载 Panel **不会主动删除远端 Relay、DNS 记录或 Reality 后端配置**。

---

## 建议的生产部署顺序

第一次使用可以按下面的顺序：

```text
1. 安装 Panel
2. 设置 PUBLIC_PANEL_URL，公网环境优先 HTTPS
3. 在 Panel 创建入口 Group
4. 通过 Node Bootstrap 安装 Relay
5. 配置 DNSMgr（需要自动 DNS 时）
6. 创建 Reality SNI Rule
7. 等待 DNS / Certificate / Nginx 收敛
8. 在诊断页确认运行状态
9. 再接入真实客户端流量
```

如果启用 Proxy Protocol，务必先修改并验证后端，再打开 Relay 发送。

---

## 安全与运维说明

- Panel 控制面包含敏感配置，请不要直接暴露弱口令管理入口。
- 集中证书同步包含私钥材料；跨公网控制链路建议使用 HTTPS。
- 不要手工覆盖 Panel 托管的 Nginx 配置后再期待控制面保持一致。
- DNSMgr 只应该连接你信任的 DNS 管理实例。
- 在重大升级、数据库迁移或拓扑调整前备份 `/var/lib/relay-panel`。
- `v1.1.1` 不引入新的 DB schema / migration，Config Protocol 仍为 `10`。
- 正式 Release 的 Panel、Node、Frontend 和脚本来自同一个 tag，并使用 SHA-256 清单校验。

---

## Release 资产

每个正式 `vX.Y.Z` Release 的 systemd 发布流程会生成：

```text
reality-panel-linux-amd64
reality-node-linux-amd64
reality-panel-web.tar.gz
install.sh
update.sh
deploy.sh
relay-node-install.sh
SHA256SUMS
```

Panel 和 Node 使用同一个正式版本号。

---

## 项目文档

更详细的内容：

- [部署说明](docs/DEPLOYMENT.md)
- [Relay Node](docs/NODE.zh-CN.md)
- [反向代理](docs/REVERSE-PROXY.md)
- [TLS 简化部署](docs/TLS-SIMPLE.md)
- [版本与 Release Contract](docs/VERSIONS.md)
- [CHANGELOG](CHANGELOG.md)
- [Node CHANGELOG](CHANGELOG-NODE.md)
- [免责声明](docs/DISCLAIMER.md)

---

## 技术栈

```text
Panel / Node     Rust
Frontend         React / TypeScript
Relay routing    Nginx Stream / ssl_preread
Service          systemd
Database         SQLite（默认）/ PostgreSQL
DNS automation   DNSMgr
Certificate      ACME DNS-01 / Certbot
Control channel  HTTP(S) + WebSocket
```

---

## License

Reality Panel 使用 [GNU Affero General Public License v3.0](LICENSE) 发布。

使用、修改、部署本项目时，请同时遵守所在地法律法规以及相关网络、DNS、证书和云服务提供商的使用条款。
