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

默认镜像：

```text
ghcr.io/pixingzoudaiyuexing/relay-panel-panel:1.2.7
ghcr.io/pixingzoudaiyuexing/relay-panel-node:1.2.2
```

完整部署细节见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

## 节点部署

先在面板里创建一个“入口/监听”设备分组，复制分组 token，然后在中转节点服务器执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/main/scripts/relay-node-install.sh) \
  -t <NODE_TOKEN> \
  -u http://<PANEL_IP>:18888 \
  --nginx-sni
```

安装完成后，节点会运行 systemd 服务：

```bash
systemctl status relay-node
journalctl -u relay-node -f
```

节点文档见 [docs/NODE.zh-CN.md](docs/NODE.zh-CN.md)。

## 使用 OpenList 做 fallback 站点

如果你希望未命中 SNI 规则时显示一个真实 HTTPS 站点，可以先在中转节点上用 Docker 启动 OpenList。
OpenList 官方 Docker 文档推荐使用轻量镜像 `openlistteam/openlist:latest-lite`，服务端口为 `5244`。

建议只监听本机，避免绕过 Nginx 直接暴露：

```bash
docker run -d \
  --name openlist \
  --restart unless-stopped \
  -p 127.0.0.1:5244:5244 \
  -v /etc/openlist:/opt/openlist/data \
  -e UMASK=022 \
  -e TZ=Asia/Shanghai \
  openlistteam/openlist:latest-lite
```

然后安装或重装 relay-node：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/main/scripts/relay-node-install.sh) \
  -t <NODE_TOKEN> \
  -u http://<PANEL_IP>:18888 \
  --nginx-sni \
  --openlist-port 5244 \
  --fallback-name op1.example.com
```

这个模式会在节点本机创建一个 HTTPS wrapper：

```text
127.0.0.1:8443 -> http://127.0.0.1:5244
```

然后把 Nginx SNI 默认后端设为 `127.0.0.1:8443`。

如果你已经有自己的 HTTPS fallback，可以直接指定：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/main/scripts/relay-node-install.sh) \
  -t <NODE_TOKEN> \
  -u http://<PANEL_IP>:18888 \
  --nginx-sni \
  --fallback-backend 127.0.0.1:8443
```

要让浏览器显示“安全”，fallback 站点需要有效证书。可以用真实域名申请证书后传入：

```bash
--fallback-cert /etc/letsencrypt/live/op1.example.com/fullchain.pem \
--fallback-key /etc/letsencrypt/live/op1.example.com/privkey.pem
```

不配置 fallback 时，节点默认 fail-closed 到 `127.0.0.1:9`。

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

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/relay-panel/main/scripts/relay-node-install.sh) \
  -t <NODE_TOKEN> \
  -u http://<PANEL_IP>:18888 \
  --nginx-sni
```

systemd 节点也可以在面板“节点状态”里一键升级。

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
