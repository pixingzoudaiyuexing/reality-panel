# Reality Panel

Reality Panel is the self-hosted control plane for transparent Reality SNI
relays. It provides Relay node management, Nginx Stream forwarding, Proxy
Protocol v1, DNSMgr A records, DNS-01 certificates, OpenList camouflage,
last-known-good recovery, lifecycle operations, diagnostics, and reapply.

The bootstrap entrypoint follows `main` and installs the latest stable GitHub
Release by default:

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh | bash
```

The installer targets Debian 12 amd64 with systemd, verifies every asset with
`SHA256SUMS`, and installs the Panel, frontend, and matching Node binary from
one versioned GitHub Release. The default local port is `18888`, and the public
IPv4 is obtained from `api.ipify.org`. To select an exact stable/prerelease
Release and override installation parameters:

```bash
curl -fsSL https://raw.githubusercontent.com/pixingzoudaiyuexing/reality-panel/main/install.sh \
  | bash -s -- v1.1.0-rc.1 --port 28888 --public-panel-url https://panel.example.com
```

`PUBLIC_PANEL_URL` accepts a credential-free `http://IP:PORT` or
`https://hostname` origin with no path, query, or fragment. HTTP is supported
intentionally.
After a genuinely fresh install, the success output shows the seeded admin
credentials once and requires changing the password on first login.

Panel-managed Node deployment is the normal path. Manual Bootstrap is an
advanced recovery path. The first installation installs
`/usr/local/sbin/reality-panel-update` on the Panel host. The updater selects
the latest stable Release or an explicit tag, verifies it, preserves all
application/runtime state, and rolls back a failed health check:

```bash
reality-panel-update
reality-panel-update v1.0.0
```

Default uninstall retains local data and requires typing `UNINSTALL`:

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0/install.sh \
  | bash -s -- uninstall
```

Use `--yes` only for deliberate automation and `--purge` only to delete local
database/configuration/secrets. Remote Relays, DNSMgr, and Reality backends
are never contacted.

For Proxy Protocol v1, enable receive on the remote Reality/Xray backend first,
wait for its reload and verify the runtime receive setting, then enable Relay
sending last. Disable in the reverse order. Reality `xver=0` remains `0` and is
separate from Relay-to-backend HAProxy PROXY protocol.

DNSMgr is Panel-only, ownership-aware, A-record-only automation. It fails
closed on external conflicts, verifies mutations, never automatically manages
AAAA or deletes DNS, and cannot change Relay runtime/LKG authority during an
upstream outage. Public DNS remains the certificate authority.

Diagnostics cover SNI, backend TCP, certificate, camouflage, and PROXY
configuration. VLESS client authentication and full fallback E2E still need a
real client connection.

See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for the release
acceptance sequence.
