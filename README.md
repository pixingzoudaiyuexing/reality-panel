# Reality Panel

Reality Panel is a self-hosted control plane for Reality SNI relays. It
manages relay-node configuration, transparent Nginx Stream forwarding,
Proxy Protocol v1, DNSMgr A records, DNS-01 certificates, OpenList fallback,
last-known-good recovery, lifecycle operations, diagnostics, and reapply.

The data path is intentionally layered:

```text
Client -> Relay (L4 SNI/Reality passthrough) -> Reality/Xray backend
                                      \-> HTTPS camouflage fallback
```

The Relay does not terminate or rewrite the Reality TLS handshake and does not
store Reality private material. The control protocol is version 8.

## Install

Versioned GitHub Releases are the only supported production source. The
current release candidate is installed explicitly:

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.6/install.sh \
  | bash -s -- install --version v1.0.0-rc.6 --public-panel-url http://203.0.113.10:18888
```

The supported first-release host is Debian 12 amd64 with systemd. The
installer downloads the Panel binary, frontend, matching Node binary, and
`SHA256SUMS` from the same Release. It validates every download before an
atomic installation. `PUBLIC_PANEL_URL` accepts a credential-free
`http://IP:PORT` or `https://hostname` origin with no path, query, or fragment.
HTTP is supported intentionally; HTTPS is recommended where available.
After a genuinely fresh install, the success output shows the seeded admin
credentials once and requires changing the password on first login.

After login, configure DNSMgr in Admin settings and deploy Relay nodes from
the Panel. The Panel-managed path keeps Node artifacts and compatibility
checks in one release. Manual Bootstrap is an advanced recovery path.

## Update

The first Panel installation installs the updater at
`/usr/local/sbin/reality-panel-update`. It is available directly on the Panel
host and uses the latest stable Release by default:

```bash
reality-panel-update
```

To select a specific stable or prerelease tag:

```bash
reality-panel-update v1.0.0
```

The absolute command path may also be used.

Updates are Release-only, verify `SHA256SUMS`, preserve the database,
configuration, secrets, Node identity, LKG, certificates, DNSMgr settings,
Rules, and OpenList data, and restore the previous binary if the health check
fails. An RC can be upgraded in place to a later stable tag.

## Uninstall

Default uninstall removes the local Panel service, installed binaries,
frontend, and Node artifacts but retains local configuration and data:

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.6/install.sh \
  | bash -s -- uninstall
```

It requires typing `UNINSTALL`. Add `--yes` only for an intentional
non-interactive operation. Add `--purge` only when local database,
configuration, and secrets should also be deleted. Rule exports are not
created automatically. Uninstall never contacts Relay nodes, DNSMgr, or
Reality backends.

## Proxy Protocol

When using Proxy Protocol v1, enable the backend receive side first:

1. Enable HAProxy PROXY protocol receive on the remote Reality/Xray backend.
2. Wait for its reload and verify the running backend/Xray inbound accepts it.
3. Enable Relay upstream Proxy Protocol sending last.

Disable in the reverse order: stop Relay sending first, then disable backend
receiving. Reality `xver=0` is a separate mechanism and remains `0`; it is not
the Relay-to-backend HAProxy PROXY protocol setting.

## DNS and certificates

DNSMgr automation is Panel-only and manages rule-authorized A records. It
requires exact ownership binding, never silently claims an external record,
fails closed on conflicts, verifies writes, and does not automatically manage
AAAA records or delete DNS. Public authoritative DNS remains the authority for
certificate issuance and propagation. DNSMgr outage does not change Relay
runtime or LKG authority.

Certificate activation, camouflage, and Reality routes converge after the
desired Rule and public DNS are ready. DNS-dependent withholding is not a
failure of local Relay provisioning.

## Diagnostics

Diagnostics can inspect Nginx SNI routing, backend TCP reachability,
certificates, renewal, camouflage, and Proxy Protocol configuration. VLESS
client authentication still requires a real client connection; the Panel does
not claim a complete automated VLESS fallback test without one.

See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for the fresh VPS
release-candidate acceptance sequence.
