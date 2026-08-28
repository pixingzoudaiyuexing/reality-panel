# Reality Panel

Reality Panel is the self-hosted control plane for transparent Reality SNI
relays. It provides Relay node management, Nginx Stream forwarding, Proxy
Protocol v1, DNSMgr A records, DNS-01 certificates, OpenList camouflage,
last-known-good recovery, lifecycle operations, diagnostics, and reapply.

Production installs use only versioned GitHub Release assets. The first RC can
be installed with:

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.1/install.sh \
  | bash -s -- install --version v1.0.0-rc.1 --public-panel-url http://203.0.113.10:18888
```

The installer targets Debian 12 amd64 with systemd, verifies every asset with
`SHA256SUMS`, and installs the Panel, frontend, and matching Node binary from
one Release. `PUBLIC_PANEL_URL` accepts a credential-free `http://IP:PORT` or
`https://hostname` origin with no path, query, or fragment. HTTP is supported
intentionally.

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
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.1/install.sh \
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

See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for the RC
acceptance sequence.
