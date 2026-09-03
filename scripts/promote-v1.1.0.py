#!/usr/bin/env python3
"""将已验收的 v1.1.0-rc.9 发布契约提升为 v1.1.0 正式版。"""

from pathlib import Path

BASE = "1.1.0-rc.9"
VERSION = "1.1.0"
RELEASE_DATE = "2026-09-03"


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, text: str) -> None:
    Path(path).write_text(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match for {old!r}, got {count}")
    write(path, text.replace(old, new, 1))


# Panel / Node 版本必须同步。
for manifest in ("crates/panel/Cargo.toml", "crates/node/Cargo.toml"):
    replace_once(manifest, f'version = "{BASE}"', f'version = "{VERSION}"')

# Cargo.lock 中只改 workspace 自身两个 package 的版本。
lock_path = "Cargo.lock"
lock = read(lock_path)
for package in ("relay-panel", "relay-node"):
    old = f'name = "{package}"\nversion = "{BASE}"'
    new = f'name = "{package}"\nversion = "{VERSION}"'
    if lock.count(old) != 1:
        raise SystemExit(f"{lock_path}: expected one {package} {BASE} entry")
    lock = lock.replace(old, new, 1)
write(lock_path, lock)

# 兼容安装脚本中的示例与 SCRIPT_VERSION 一并升级。
installer = "scripts/relay-node-install.sh"
installer_text = read(installer)
if f'SCRIPT_VERSION="{BASE}"' not in installer_text:
    raise SystemExit(f"{installer}: SCRIPT_VERSION is not {BASE}")
write(installer, installer_text.replace(BASE, VERSION))

# 正式版说明明确为 RC9 的稳定提升，不暗示额外运行时改动。
marker = "---\n\n"
panel_path = "CHANGELOG.md"
panel = read(panel_path)
if marker + f"## [{VERSION}] - {RELEASE_DATE}\n" in panel[:500]:
    raise SystemExit(f"{panel_path}: {VERSION} already exists")
panel_entry = f"""## [{VERSION}] - {RELEASE_DATE}

First stable 1.1 release. This promotes the accepted RC9 code line
without additional Panel runtime, schema, or wire-protocol changes.

### Highlights

- Carrier Affinity with DNSMgr line-aware Relay selection and safe DNS
  transactions.
- Scheduled Relay switching with restart recovery and LKG protection.
- Panel-centralized wildcard certificate lifecycle and distribution.
- Multi-Relay readiness, diagnostics, safer topology switching, and the
  RC9 DNS ownership/value-drift protections.

### Upgrade

- Back up the Panel database before upgrading.
- RC9 to 1.1.0 keeps Config Protocol 10 and the RC9 database schema.
- The standard systemd release and the official Docker images are built
  from the same `v1.1.0` tagged source.

"""
if marker not in panel:
    raise SystemExit(f"{panel_path}: changelog marker missing")
write(panel_path, panel.replace(marker, marker + panel_entry, 1))

node_path = "CHANGELOG-NODE.md"
node = read(node_path)
if marker + f"## [{VERSION}] - {RELEASE_DATE}\n" in node[:500]:
    raise SystemExit(f"{node_path}: {VERSION} already exists")
node_entry = f"""## [{VERSION}] - {RELEASE_DATE}

First stable 1.1 relay-node release. This promotes the accepted RC9
node line without additional runtime or wire-protocol changes.
Config Protocol remains 10 and Lifecycle Protocol remains 1.

"""
if marker not in node:
    raise SystemExit(f"{node_path}: changelog marker missing")
write(node_path, node.replace(marker, marker + node_entry, 1))

# 发布检查同时接受“当前稳定版”和“开发候选版”的文档声明。
release_check_path = "scripts/release-check.sh"
release_check = read(release_check_path)
old_doc_check = (
    'grep -Fq "candidate is \\`v$VERSION\\`" "$ROOT/docs/VERSIONS.md" || \\\n'
    '    fail "docs/VERSIONS.md does not declare v$VERSION as the development candidate"'
)
new_doc_check = (
    'if ! grep -Fq "stable release is \\`v$VERSION\\`" "$ROOT/docs/VERSIONS.md" && \\\n'
    '   ! grep -Fq "candidate is \\`v$VERSION\\`" "$ROOT/docs/VERSIONS.md"; then\n'
    '    fail "docs/VERSIONS.md does not declare v$VERSION as stable or candidate"\n'
    'fi'
)
if release_check.count(old_doc_check) != 1:
    raise SystemExit(f"{release_check_path}: version-doc contract block not found")
release_check = release_check.replace(old_doc_check, new_doc_check, 1)

docker_anchor = """grep -q 'container: rust:1.96-bookworm' "$ROOT/.github/workflows/binary-release.yml" || fail "release binaries are not built on Debian 12"
"""
docker_checks = """grep -q 'container: rust:1.96-bookworm' "$ROOT/.github/workflows/binary-release.yml" || fail "release binaries are not built on Debian 12"
[ -s "$ROOT/.github/workflows/docker-release.yml" ] || fail "Docker release workflow missing"
grep -q 'packages: write' "$ROOT/.github/workflows/docker-release.yml" || fail "Docker release workflow cannot publish GHCR packages"
grep -q 'relay-panel-panel' "$ROOT/.github/workflows/docker-release.yml" || fail "Panel GHCR image contract missing"
grep -q 'relay-panel-node' "$ROOT/.github/workflows/docker-release.yml" || fail "Node GHCR image contract missing"
"""
if release_check.count(docker_anchor) != 1:
    raise SystemExit(f"{release_check_path}: Docker check insertion anchor not found")
write(release_check_path, release_check.replace(docker_anchor, docker_checks, 1))

# 版本文档将 v1.1.0 设置为当前稳定版，并记录 Docker 的正式发布来源。
versions_path = "docs/VERSIONS.md"
docs = read(versions_path)
old_intro = f"""Reality Panel uses one release tag and one compatibility version for the Panel
and Node. The current stable release is `v1.0.1`; the current 1.1 development
candidate is `v{BASE}`. The wire protocol remains
`CONFIG_PROTOCOL_VERSION = 10`."""
new_intro = f"""Reality Panel uses one release tag and one compatibility version for the Panel
and Node. The current stable release is `v{VERSION}`. The wire protocol remains
`CONFIG_PROTOCOL_VERSION = 10`."""
if docs.count(old_intro) != 1:
    raise SystemExit(f"{versions_path}: intro contract not found")
docs = docs.replace(old_intro, new_intro, 1)

old_source = (
    "No branch, raw commit, Actions artifact, GHCR image, or local binary\n"
    "is a production update source."
)
new_source = (
    "The systemd updater only trusts GitHub Release assets. Official Docker\n"
    "deployments use GHCR images produced from the same tagged checkout by\n"
    "`.github/workflows/docker-release.yml`; branch/local images are not\n"
    "production update sources."
)
if docs.count(old_source) != 1:
    raise SystemExit(f"{versions_path}: production-source paragraph not found")
docs = docs.replace(old_source, new_source, 1)

old_workflow = "- `.github/workflows/binary-release.yml` is the only v1 release workflow."
new_workflow = (
    "- `.github/workflows/binary-release.yml` publishes systemd release assets.\n"
    "- `.github/workflows/docker-release.yml` publishes the official multi-arch GHCR images."
)
if docs.count(old_workflow) != 1:
    raise SystemExit(f"{versions_path}: workflow declaration not found")
docs = docs.replace(old_workflow, new_workflow, 1)

old_check_command = f"bash scripts/release-check.sh {BASE}"
if docs.count(old_check_command) != 1:
    raise SystemExit(f"{versions_path}: release-check command not found")
docs = docs.replace(old_check_command, f"bash scripts/release-check.sh {VERSION}", 1)
write(versions_path, docs)

# README 将 v1.1.0 和 Docker/Compose 明确为正式生产路径。
readme_path = "README.md"
readme = read(readme_path)
old_docker_note = (
    "仓库中可能存在 Docker 相关开发或兼容文件，但 "
    "**Docker 不是当前 v1 的正式生产部署方式**。"
)
new_docker_note = (
    "Docker / Docker Compose 现在也是正式生产部署方式；官方镜像由 `v*` Tag "
    "从同一份源码构建并发布到 GitHub Container Registry，支持 `amd64` 与 `arm64`。"
)
if readme.count(old_docker_note) != 1:
    raise SystemExit(f"{readme_path}: Docker support note not found")
readme = readme.replace(old_docker_note, new_docker_note, 1)

old_arch_row = "| 架构 | amd64 / x86_64 |"
new_arch_rows = "| systemd 架构 | amd64 / x86_64 |\n| Docker 架构 | amd64 / arm64 |"
if readme.count(old_arch_row) != 1:
    raise SystemExit(f"{readme_path}: architecture row not found")
readme = readme.replace(old_arch_row, new_arch_rows, 1)

if readme.count("### 安装当前 RC9") != 1:
    raise SystemExit(f"{readme_path}: RC9 install heading not found")
readme = readme.replace("### 安装当前 RC9", "### 安装 v1.1.0 正式版", 1)

if readme.count("当前 1.1 发布候选版本：") != 1:
    raise SystemExit(f"{readme_path}: RC version label not found")
readme = readme.replace("当前 1.1 发布候选版本：", "当前 1.1 正式版本：", 1)
readme = readme.replace(BASE, VERSION)

docker_section = f"""### Docker / Docker Compose

正式版同时发布多架构 GHCR 镜像：

```text
ghcr.io/pixingzoudaiyuexing/relay-panel-panel:v{VERSION}
ghcr.io/pixingzoudaiyuexing/relay-panel-node:v{VERSION}
```

使用仓库中的生产 Compose：

```bash
git clone https://github.com/pixingzoudaiyuexing/reality-panel.git
cd reality-panel

export RELAYPANEL_RELEASE_VERSION=v{VERSION}
export JWT_SECRET="$(openssl rand -hex 32)"
export PANEL_KEY="$(openssl rand -hex 32)"

docker compose -f docker-compose.release.yaml up -d
```

默认只启动 Panel；Relay Node 通常部署在独立服务器。需要同机 Node 时，
再启用 `node` profile 并设置真实 `NODE_TOKEN`。

"""
stable_anchor = "### 安装 v1.1.0 正式版\n"
if readme.count(stable_anchor) != 1:
    raise SystemExit(f"{readme_path}: stable install anchor missing")
write(readme_path, readme.replace(stable_anchor, docker_section + stable_anchor, 1))
