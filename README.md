# Reality Panel

Reality Panel 是一个面向 **Reality SNI 中转场景** 的自托管控制面板，用来集中管理 Relay 节点、Reality 转发规则、DNS、证书、伪装站以及节点生命周期。

它不接管后端 Reality/Xray 的认证逻辑，也不会在 Relay 上终止 Reality TLS。Relay 只负责四层透明转发，让客户端先连接中转节点，再由中转节点把 Reality 流量送往真实后端。

```text
客户端
  │
  ▼
Relay 节点
  │
  ├── Reality / SNI 四层透明转发 ──> Reality / Xray 后端
  │
  └── HTTPS 伪装流量 ─────────────> OpenList / 自定义伪装站
```

项目的核心目标是：**让中转规则可以集中管理，但已经运行的转发不依赖 Panel 持续在线。**

---

## 主要功能

### Relay 节点管理

- 通过 Panel 部署和管理 Relay 节点
- 查看节点在线、就绪、异常等状态
- 节点日志查看与诊断
- 节点重启、配置重载、一键更新
- Panel 与 Node 版本兼容性检查
- 多 Relay 节点共同承载同一个 Reality Group

### Reality SNI 四层转发

- 基于 Nginx Stream 的 SNI 路由
- Reality TLS 保持端到端透明
- Relay 不保存 Reality 私钥
- 支持多个 Reality Rule
- 支持独立监听端口、SNI 和上游 Reality/Xray 后端
- 配置失败时保留上一份可工作的运行状态

### Relay Preference

每个 Group 可以设置一个首选 Relay。

切换首选 Relay 时，Reality Panel 会先检查目标 Relay 是否已经就绪，再执行对应 DNS 变更。发生失败时不会直接覆盖旧的可用状态。

### 定时 Relay 切换

支持预先设置 Relay 切换计划：

- 单次执行
- 每日执行
- 每周执行
- Panel 重启后恢复计划
- 与现有 Relay Preference、DNS 事务和回滚机制共用同一条安全链路

### Carrier Affinity（运营商线路绑定）

Reality Panel 可以从 DNSMgr 动态读取 DNS 服务商提供的线路目录，为同一个 Group 配置不同线路对应的 Relay。

每条线路支持三种状态：

- **不单独配置**：Reality Panel 不为该线路创建独立记录，最终解析行为由 DNS 服务商决定
- **跟随默认 Relay**：为该线路维护独立记录，并跟随 Group 的首选 Relay 一起切换
- **指定 Relay**：该线路固定使用指定的已就绪 Relay，不受默认 Relay 切换影响

同一条 Reality Rule 可以同时维护默认记录和多个线路记录。

Carrier Affinity 使用 DNSMgr 返回的真实线路 ID，不依赖线路名称猜测运营商身份，也不会在 DNSMgr 无法确认线路目录时盲目修改现有策略。

> 当前已经完成真实华为云 DNSMgr 控制面的创建、修改、删除、父子线路、多线路、首选 Relay 切换和异常保护验证。运营商真实递归 DNS 网络下的线路优先级仍以 DNS 服务商实际行为为准。

### DNSMgr 自动化

Panel 可以通过 DNSMgr 自动维护 Reality Rule 授权的 A 记录。

主要安全原则：

- 只操作 Reality Panel 能证明属于自己的记录
- 不会静默接管已有外部 DNS 记录
- DNS 冲突时失败关闭，而不是强制覆盖
- 写入后进行服务商侧回读确认
- 删除前重新确认记录 ID、线路、域名、类型和值
- DNS 状态不明确时冻结新的拓扑切换
- Panel 或 DNSMgr 临时离线不会改变 Relay 已运行的转发状态

### 集中式证书管理

Reality Panel 可以在 Panel 端统一申请和维护 wildcard 证书，再将同一代证书自动分发到 Group 内的 Relay 节点。

这样新增 Relay 时不需要每台机器分别执行 ACME 申请，也可以提前让备用 Relay 达到就绪状态。

证书更新遵循安全切换：

1. Panel 获取新证书
2. Relay 校验证书、SAN、私钥和有效期
3. Nginx 配置测试
4. Reload 成功
5. 新证书才成为当前可用状态

任何一步失败，都继续保留旧的有效证书和运行配置。

> 如果 `PUBLIC_PANEL_URL` 使用 `http://`，集中证书下发中的私钥会经过当前 HTTP 控制通道传输。公网或不可信网络部署应使用 HTTPS。

### Proxy Protocol v1

Reality Panel 支持 Relay 向 Reality/Xray 后端发送 HAProxy PROXY Protocol v1，用于让后端获取真实客户端 IP。

正确启用顺序：

1. 先在远端 Reality/Xray 后端启用 PROXY Protocol 接收
2. 确认后端已经成功 Reload 并实际生效
3. 最后在 Relay 端启用 PROXY Protocol 发送

关闭时顺序相反：先停止 Relay 发送，再关闭后端接收。

Reality 的 `xver` 与这里的 Relay → 后端 PROXY Protocol 是两套独立机制。

### HTTPS 伪装与 OpenList

Reality Rule 可以同时配置 HTTPS 伪装站：

- OpenList
- 自定义 HTTP 上游
- wildcard 证书
- 全局 HTTP → HTTPS 跳转

Reality SNI 命中时继续透明转发到 Reality/Xray；普通 HTTPS 访问则进入伪装站。

### LKG 可靠性保护

Reality Panel / Relay Node 使用 **Last Known Good（最后已知可用配置）** 思路保护生产转发。

核心原则：

- Panel 宕机不影响已经部署并运行的 Relay 规则
- 新配置失败不能覆盖旧的可用配置
- 新证书失败不能替换旧的有效证书
- Nginx 测试或 Reload 失败时继续使用原运行状态
- DNS 操作失败时不把未完成状态提交为成功
- Relay 重启后优先恢复最后可用运行配置

控制面可以暂时不可用，但数据面应该尽可能继续工作。

---

## 支持环境

当前正式部署路径：

| 项目 | 要求 |
| --- | --- |
| Panel 系统 | Debian 12 |
| Relay 系统 | Debian 12 |
| systemd 架构 | amd64 / x86_64 |
| Docker 架构 | amd64 / arm64 |
| 服务管理 | systemd |
| 安装权限 | root |
| Panel 默认端口 | `18888` |

Docker / Docker Compose 现在也是正式生产部署方式；官方镜像由 `v*` Tag 从同一份源码构建并发布到 GitHub Container Registry，支持 `amd64` 与 `arm64`。

---

## 安装

### 安装最新稳定版

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh | bash
```

默认安装器只选择 GitHub 上最新的 **稳定 Release**，不会自动安装 prerelease / RC。

安装完成后会创建：

```text
relay-panel.service
/usr/local/sbin/reality-panel-update
/etc/relay-panel/relay-panel.env
/var/lib/relay-panel/
/opt/relay-panel/
```

全新安装成功后，终端会一次性显示初始管理员账号信息。请登录后立即修改密码。

### Docker / Docker Compose

正式版同时发布 `amd64` / `arm64` 多架构 GHCR 镜像：

```text
ghcr.io/pixingzoudaiyuexing/reality-panel-panel:v1.1.1
ghcr.io/pixingzoudaiyuexing/reality-panel-node:v1.1.1
```

需要 Docker Engine、Docker Compose Plugin 和 OpenSSL。生产部署使用仓库中的
`docker-compose.release.yaml`，它只拉取已发布镜像，不在服务器上编译源码。

#### Docker 安装 Panel

```bash
git clone https://github.com/pixingzoudaiyuexing/reality-panel.git
cd reality-panel

umask 077
cat > .env <<EOF
RELAYPANEL_RELEASE_VERSION=v1.1.1
JWT_SECRET=$(openssl rand -hex 32)
PANEL_KEY=$(openssl rand -hex 32)
EOF

docker compose -f docker-compose.release.yaml pull panel
docker compose -f docker-compose.release.yaml up -d panel
```

`.env` 包含长期使用的签名和加密密钥。请限制其权限、纳入备份，不要在重建或升级时重新生成。

确认容器和健康状态：

```bash
docker compose -f docker-compose.release.yaml ps
docker compose -f docker-compose.release.yaml logs --tail=100 panel
curl -fsS http://127.0.0.1:18888/api/v1/health
docker compose -f docker-compose.release.yaml exec panel ./relay-panel --version
```

默认只启动 Panel，并将 `18888` 发布到所有网络接口。需要交给本机反向代理时，在 `.env` 中增加：

```text
RELAYPANEL_PANEL_PORT_BINDING=127.0.0.1:18888
PUBLIC_PANEL_URL=https://panel.example.com
```

#### 可选：同机启动 Relay Node

通常应从 Panel 部署独立 Relay Node。确实需要在 Panel 主机同时运行 Node 时，先在 Panel
中取得真实的入口分组 Token，再写入 `.env`：

```bash
cat >> .env <<'EOF'
RELAYPANEL_NODE_TAG=v1.1.1
NODE_TOKEN=请替换为真实入口分组Token
EOF

docker compose -f docker-compose.release.yaml --profile node pull panel node
docker compose -f docker-compose.release.yaml --profile node up -d panel node
docker compose -f docker-compose.release.yaml --profile node exec node ./relay-node --version
```

不要使用示例文字或 Panel 管理密钥代替 `NODE_TOKEN`。

#### Docker 常用运维命令

```bash
# 查看状态
docker compose -f docker-compose.release.yaml ps

# 查看日志
docker compose -f docker-compose.release.yaml logs -f --tail=200 panel

# 重启 Panel
docker compose -f docker-compose.release.yaml restart panel

# 停止后再启动
docker compose -f docker-compose.release.yaml stop panel
docker compose -f docker-compose.release.yaml start panel
```

Compose 默认使用命名卷 `panel_data` 保存 SQLite 数据；重建容器不会删除该卷。

#### Docker 升级

升级前先备份 `.env` 和默认 SQLite 数据卷。下面的备份命令会短暂停止 Panel，避免复制过程中
数据库继续写入：

```bash
mkdir -p backups
cp -p .env "backups/env-$(date +%Y%m%d-%H%M%S)"

docker compose -f docker-compose.release.yaml stop panel
docker compose -f docker-compose.release.yaml run --rm --no-deps --entrypoint /bin/sh panel \
  -c 'tar -C /app/data -czf - .' \
  > "backups/panel-data-$(date +%Y%m%d-%H%M%S).tar.gz"
docker compose -f docker-compose.release.yaml start panel
```

以上数据卷备份适用于默认 SQLite 部署。使用 PostgreSQL 时，应另外执行 `pg_dump`，不要用文件复制
代替数据库备份。

然后执行 `git pull --ff-only`，并将 `.env` 中的 `RELAYPANEL_RELEASE_VERSION` 改成需要升级到的
稳定版本，再拉取和重建 Panel：

```bash
git pull --ff-only
docker compose -f docker-compose.release.yaml pull panel
docker compose -f docker-compose.release.yaml up -d --no-deps panel

docker compose -f docker-compose.release.yaml exec panel ./relay-panel --version
curl -fsS http://127.0.0.1:18888/api/v1/health
```

同机 Node 也需要升级时，同时更新 `.env` 中的 `RELAYPANEL_NODE_TAG`，再执行：

```bash
docker compose -f docker-compose.release.yaml --profile node pull panel node
docker compose -f docker-compose.release.yaml --profile node up -d panel node
```

远端 Relay Node 不会因为重建 Panel 容器而自动升级；请在 Panel 的节点管理中逐台执行更新。

回滚前先确认旧版本能够读取当前数据库格式。不能确认时，应停止容器并恢复升级前的数据卷备份，
不要只改镜像标签后直接启动旧版本。

#### Docker 卸载

只删除容器和网络、保留 `.env` 与命名卷中的数据：

```bash
docker compose -f docker-compose.release.yaml --profile node --profile caddy --profile postgres \
  down --remove-orphans
```

以后仍可在当前目录执行 `docker compose -f docker-compose.release.yaml up -d panel` 恢复服务。

确认不再需要任何本地数据后，才执行彻底删除。以下命令会永久删除 SQLite、PostgreSQL 和 Caddy
命名卷，无法撤销：

```bash
docker compose -f docker-compose.release.yaml --profile node --profile caddy --profile postgres \
  down --volumes --remove-orphans
```

容器和数据卷删除后，如需释放镜像空间，可再删除已拉取镜像：

```bash
docker image rm \
  ghcr.io/pixingzoudaiyuexing/reality-panel-panel:v1.1.1 \
  ghcr.io/pixingzoudaiyuexing/reality-panel-node:v1.1.1
```

### 安装 v1.1.1 正式版

当前 1.1 正式版本：

```text
v1.1.1
```

显式安装 v1.1.1：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- v1.1.1
```

自定义 Panel 端口：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- v1.1.1 --port 28888
```

指定公网访问地址：

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- v1.1.1 \
  --public-panel-url https://panel.example.com
```

`PUBLIC_PANEL_URL` 应为不包含账号密码、路径、查询参数和 Fragment 的纯 Origin，例如：

```text
http://1.2.3.4:18888
https://panel.example.com
```

---

## 第一次使用

推荐顺序：

1. 安装 Reality Panel
2. 登录后台并修改初始管理员密码
3. 在管理设置中配置 DNSMgr
4. 创建 Reality Group 和 Rule
5. 从 Panel 添加并部署 Relay 节点
6. 等待 Relay 和 Rule 达到就绪状态
7. 再配置首选 Relay、定时切换或 Carrier Affinity
8. 使用诊断功能确认 DNS、证书、SNI、后端和伪装站状态

正常情况下，不需要手工修改 Relay 上的 Nginx 配置。

---

## 更新

更新到最新稳定版：

```bash
reality-panel-update
```

更新到指定版本，包括 RC：

```bash
reality-panel-update v1.1.1
```

Panel 更新完成后，再通过 Panel 的节点管理功能逐台更新 Relay Node。

安装器和更新器会校验 Release 中的 `SHA256SUMS`，并保留数据库、配置、密钥、节点身份、LKG、证书、DNSMgr 设置、Rule 和 OpenList 数据。

---

## RC9 升级注意事项

从旧版本升级到 `v1.1.0` 前，**先备份 Panel 数据库**。

RC9 为 Carrier Affinity 将 DNS 同步记录身份从：

```text
rule_id
```

升级为：

```text
(rule_id, line_key)
```

对应：

- SQLite migration 50
- PostgreSQL migration 34

PostgreSQL 16 的 RC8 → RC9 升级路径已经实际验证。

一旦 RC9 数据库已经产生 Carrier 行，不应直接使用 RC8 二进制打开该数据库。需要降级时，应恢复升级 RC9 前创建的数据库备份。

---

## 数据与目录

默认关键路径：

```text
/etc/relay-panel/relay-panel.env       Panel 配置
/var/lib/relay-panel/data.db           默认 SQLite 数据库
/var/lib/relay-panel/certificates      Panel 集中证书数据
/opt/relay-panel/current               当前 Release 文件
/opt/relay-panel/node-assets           Relay Node 发布工件
```

Panel systemd 服务：

```bash
systemctl status relay-panel
```

---

## 卸载

使用当前 RC9 安装脚本：

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.1.1/install.sh \
  | bash -s -- uninstall
```

默认卸载：

- 删除本机 Panel 服务和程序文件
- 保留 `/etc/relay-panel`
- 保留 `/var/lib/relay-panel`
- 不连接远端 Relay
- 不删除 DNSMgr 中的记录
- 不修改 Reality/Xray 后端

完全删除本地配置与数据时才使用 `--purge`。

---

## 发布与版本

Panel 和 Relay Node 使用同一个 Reality Panel Release 版本发布。

当前 1.1 正式版本：

```text
v1.1.1
```

Config Protocol：

```text
10
```

正式发布产物由 GitHub Actions 从对应 Tag 的源码构建，并包含 Panel、Node、Web、安装脚本、校验文件和源码提交标识。

生产更新来源只使用 GitHub Release，不使用分支中的临时二进制或未验证的 Actions 工件。

---

## 文档

- [部署说明](docs/DEPLOYMENT.md)
- [版本与 Release 规则](docs/VERSIONS.md)
- [发布验收清单](docs/RELEASE_CHECKLIST.md)
- [Panel 更新记录](CHANGELOG.md)
- [Node 更新记录](CHANGELOG-NODE.md)

---

## 使用边界

Reality Panel 当前主要解决的是 **Reality 中转控制面、Relay 生命周期、DNS、证书和可靠切换**。

使用时请注意：

- Reality/Xray 后端本身仍由你独立维护
- DNS 最终解析行为以权威 DNS 服务商为准
- Carrier Affinity 不通过线路名称猜测服务商语义
- 使用集中证书下发时，公网环境建议使用 HTTPS Panel 地址
- 当前生产部署目标是 Debian 12 amd64
- RC 版本需要显式指定，不会被默认稳定版更新器自动选择

---

## License

Reality Panel 使用 [GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0）开源。
