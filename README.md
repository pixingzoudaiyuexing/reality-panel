<p align="center">
  <img src="frontend/public/favicon.svg" width="80" height="80" alt="RelayPanel Logo" />
</p>

<h1 align="center">RelayPanel Reality SNI Edition</h1>

<p align="center">
  单公网 IP + 统一 443 + 基于 TLS SNI 的 Reality L4 转发面板
</p>

<p align="center">
  <a href="README.en.md">English</a> | <strong>中文</strong>
</p>

<p align="center">
  <a href="https://github.com/pixingzoudaiyuexing/relay-panel/releases/latest"><img src="https://img.shields.io/github/v/release/pixingzoudaiyuexing/relay-panel?style=flat-square&label=Release&color=blue" alt="Release" /></a>
  <a href="https://github.com/pixingzoudaiyuexing/relay-panel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/pixingzoudaiyuexing/relay-panel/ci.yml?style=flat-square&label=CI" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/pixingzoudaiyuexing/relay-panel?style=flat-square&label=License&color=red" alt="License" /></a>
</p>

<p align="center">
  基于 <a href="https://github.com/MoeShinX/relay-panel">MoeShinX/relay-panel</a> 二开。<br/>
  保留原有 TCP/UDP 转发、节点管理、用户额度、流量统计能力，并新增 Reality SNI 转发链路。
</p>

---

## 适合什么场景

这版主要用于 Reality 节点入口中转：

- 多个 Reality 落地节点共用一个中转公网 IP。
- 客户端统一连接 `中转IP:443`。
- 面板按 TLS ClientHello 里的 SNI，把 `op1.example.com`、`op2.example.com`、`op3.example.com` 分发到不同落地节点。
- 未命中规则的连接进入 fallback，可以接 OpenList、普通 HTTPS 站点或直接丢弃。
- 面板继续统计每条规则的流量、额度和在线节点状态。

典型链路：

```text
客户端
  -> 中转节点 64.x.x.x:443
  -> Nginx Stream ssl_preread 读取 SNI
  -> op1.example.com => Reality 节点 A:55443
  -> op2.example.com => Reality 节点 B:55443
  -> op3.example.com => Reality 节点 C:55443
```

## 功能

- Reality SNI 转发：同一个监听端口可以按不同 SNI 分流。
- Nginx Stream L4 转发：中转节点不解密 Reality TLS，只读取 SNI。
- 负载策略：支持 `first`、`round_robin`、`failover`。
- 流量统计：从 Nginx Stream access log 采集每条规则的上下行。
- 导入导出：规则导入导出保留 Reality SNI、协议、转发类型和负载策略。
- 节点安装脚本：支持 `--nginx-sni`、OpenList fallback 和自定义 fallback。
- Docker 发布：Panel 和 Node 镜像发布到本 fork 的 GHCR Packages。

## 面板部署

### 一键脚本

Debian / Ubuntu 上用 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/main/install.sh | bash
```

脚本会把项目安装到 `/opt/relay-panel`，自动安装 Docker、生成密钥并启动面板。

默认访问地址：

```text
http://服务器IP:18888
```

默认账号：

```text
admin / admin123
```

首次登录会强制修改密码。

### 卸载本机 Panel

先导出需要保留的 Rules。以下命令只删除本机 `/opt/relay-panel` 的 Panel
Compose 资源、持久数据和本地配置；不会创建导出文件，也不会操作任何远程 Relay、DNS
或 Reality 后端。命令会要求输入 `DELETE` 确认：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/<release-ref>/install.sh | bash -s -- uninstall
```

非交互自动化必须显式附加 `--yes`。

### Docker Compose

也可以手动部署：

```bash
git clone https://github.com/pixingzoudaiyuexing/relay-panel.git
cd relay-panel

cat > .env <<EOF
JWT_SECRET=$(openssl rand -hex 32)
PANEL_KEY=$(openssl rand -hex 16)
DATABASE_URL=sqlite:/app/data/data.db?mode=rwc
PUBLIC_PANEL_URL=http://你的面板IP:18888
EOF

docker compose -f docker-compose.release.yaml up -d
```

正式部署必须显式钉住同一发布的 `RELAYPANEL_RELEASE_REF` 与
`RELAYPANEL_RELEASE_VERSION`；不要让 fresh install 跟随旧 `main`。Panel 镜像内置
同一 source ref 构建的 amd64/arm64 relay-node artifact。

镜像标签由最终 release-time version 提供：

```text
ghcr.io/pixingzoudaiyuexing/relay-panel-panel:<release-version>
ghcr.io/pixingzoudaiyuexing/relay-panel-node:<explicit-node-tag-if-profile-enabled>
```

完整部署细节见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

## 节点部署

当前支持两种 Relay 部署方式，二者最终都会进入同一套 Stage 3.4
provisioning 状态，并共用唯一的 `scripts/relay-node-bootstrap.sh` mutation
engine：

### SSH 一键部署（推荐）

当 Panel 可以 SSH 访问 Relay 时，在 Panel 的 **Node Bootstrap** 页面选择
SSH 一键部署，选择入口设备分组并完成 host-key 确认。Panel 会选择架构、校验
artifact、执行事务 provisioning，并等待 Node WS online 与五项能力确认：
`nginx_stream`、`openlist`、`http01`、`certificate_lifecycle`、
`reality_camouflage`。

### 手动 Bootstrap

适用于 Panel 无法 SSH 到 Relay、但 Relay 可以通过 HTTP(S)/WebSocket 主动访问
Panel 的场景：

1. Panel 创建短期 enrollment。
2. 管理员复制不含 secret 的 launcher command。
3. Relay 通过 `/dev/tty` 隐藏读取一次性 enrollment secret。
4. Relay claim enrollment，下载并校验签名/哈希绑定的 bundle。
5. wrapper 调用同一 `scripts/relay-node-bootstrap.sh`。
6. Node WS authenticated，五项能力确认。
7. 本地 provisioning commit，之后由 Panel 完成可重试的 finalization。

`PUBLIC_PANEL_URL` 支持 `http://IP:PORT` 和 `https://hostname`。HTTPS 可提供加密传输；enrollment secret 只显示一次，
不能粘贴进 launcher command，也不是永久 group token 或 SSH credential。
Bootstrap 本身不会申请真实 SNI 证书；Reality/camouflage 配置仍由 Panel 的
Rules desired state 驱动，证书生命周期在 Node reconcile 阶段处理。

### 兼容性说明

`scripts/relay-node-install.sh` 仍保留给旧节点升级/迁移使用，但已 deprecated，
不再由当前 UI 或推荐文档生成新命令。新部署请使用 Node Bootstrap。该旧脚本的
legacy token、Docker Nginx、OpenList port、fallback、certbot 和 GitHub version
选项不属于当前产品 bootstrap contract。

节点状态与故障排查见 [docs/NODE.zh-CN.md](docs/NODE.zh-CN.md)；Panel 反向代理
与 WebSocket 要求见 [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md)。

## 添加 Reality SNI 规则

在面板“转发规则”里添加规则：

```text
协议: TCP
公网转发类型: REALITY SNI 转发 / nginx_sni
节点转发类型: REALITY SNI 转发 / nginx_sni
监听端口: 443
SNI: op1.13886.xyz
目标地址: 216.195.201.113
目标端口: 55443
负载策略: first / round_robin / failover
```

客户端配置保持：

```text
连接地址: 中转服务器公网 IP
连接端口: 443
SNI / serverName: op1.13886.xyz
Reality 落地节点参数: 按真实节点配置填写
```

同一个中转节点可以继续添加：

```text
op2.13886.xyz -> 141.11.219.133:55443
op3.13886.xyz -> 107.175.140.11:55443
```

注意：SNI 必须和客户端实际发送的 `serverName` 一致。域名 DNS 可以解析到中转 IP，也可以由客户端显式连接中转 IP；Nginx 分流依据是 TLS 握手里的 SNI，不是普通 HTTP Host。

## 更新

面板：

```bash
cd /opt/relay-panel
git pull --ff-only
./deploy.sh
```

节点：

使用 Panel 的 **Node Bootstrap** 页面重新执行 SSH 一键部署，或在 Relay
无法被 Panel SSH 访问时使用手动 Bootstrap。两种方式都会复用同一个事务
provisioning engine，并保留 Node ID、LKG、证书和 OpenList 数据。旧的一行
installer 仅供兼容旧节点，不再作为新部署或更新的推荐路径。

## 开发

```bash
cargo build
cargo run -p relay-panel
cd frontend && npm install && npm run dev
```

Rust 后端使用 Axum / Tokio / sqlx，前端使用 React 19 / TypeScript / Ant Design。

## 许可证与声明

本项目遵循 [AGPL-3.0](LICENSE)。

请只在合法合规的网络环境中使用。你需要自行承担部署、转发、域名、证书和节点使用带来的责任。
