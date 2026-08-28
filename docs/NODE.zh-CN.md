# Relay Node

## 正常部署

正常路径是通过 Panel 的 Node Bootstrap 页面部署和升级 Relay。Panel 从
自己的 `/opt/relay-panel/node-assets` 根目录选择 Node 二进制，并校验
Linux 架构、版本、文件大小、ELF machine 和 SHA-256，然后执行事务化
Bootstrap。SSH Bootstrap 与 Manual Bootstrap 使用同一套配置和回滚边界。

v1 正式 Node 资产是与 Panel 同一 GitHub Release 中的
`reality-node-linux-amd64`。生产环境不要使用分支构建、临时 CI artifact
或本地二进制。

## 手工恢复

Manual Bootstrap 是高级恢复路径，适用于 Panel 无法 SSH 到 Relay、但 Relay
可以主动连接控制面的情况。复制的 launcher 只包含 Panel URL 和非敏感
enrollment ID。一次性 secret 通过隐藏终端提示输入，不放入 argv、环境变量
或 URL。

Panel endpoint 同时支持 `http://IP:PORT` 和 `https://hostname`；可用时建议
使用 HTTPS。

## 运行时边界

Relay 是 L4 SNI/Reality 透传，不终止或改写 Reality 握手，也不从 Panel 接收
Reality 私钥。Nginx Stream 使用 `ssl_preread`；Reality 认证由后端控制。
OpenList/camouflage 是独立的 fallback 路径。

控制协议保持版本 8。Reality `xver=0` 与可选的 Relay 到后端 HAProxy
PROXY protocol 是两套机制。启用 PROXY 时，先在远端 Reality/Xray 后端启用
接收，等待后端/Xray reload 并验证运行态接收已生效，最后启用 Relay 发送；
关闭时顺序相反。

## 生命周期

Node 升级由 Panel 发起。Panel 通过认证 operation 下发，Node 从 Panel
operation endpoint 获取资产，校验版本和 SHA 后原子替换二进制。Node ID、
LKG、证书、OpenList 数据及托管运行态保持不变。
