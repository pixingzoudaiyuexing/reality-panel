# Deployment

Reality Panel v1 supports a bare-metal Linux Panel on Debian 12 amd64 with
systemd. Production artifacts are downloaded only from a versioned GitHub
Release. Docker files in this repository are development/compatibility assets,
not the v1 production deployment path.

## Install

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.3/install.sh \
  | bash -s -- install --version v1.0.0-rc.3 --public-panel-url http://203.0.113.10:18888
```

The installer checks Linux, amd64, Debian 12, root, and systemd; downloads
the Panel, Node, frontend, and scripts from the same Release; and verifies
each item against `SHA256SUMS`. It creates only the internal secrets required
by the application. It never generates or prints an admin password.

## Configuration

Configuration is stored in `/etc/relay-panel/relay-panel.env`; SQLite data is
stored in `/var/lib/relay-panel/data.db` by default. `PUBLIC_PANEL_URL` must be
a credential-free `http://IP:PORT` or `https://hostname` origin without path,
query, or fragment. HTTP remains supported for deployments that intentionally
use plaintext control transport.

The service is `relay-panel.service`. Installed release files and the canonical
Node artifact root are under `/opt/relay-panel/current`; the root is exposed to
the application as `/opt/relay-panel/node-assets`. Bootstrap and lifecycle
upgrade use this same root.

## Upgrade

```bash
reality-panel-update
reality-panel-update v1.0.0
```

The first installation writes this executable command to
`/usr/local/sbin/reality-panel-update`. The first form selects the latest stable
Release; the second selects an exact tag, including an RC. The updater verifies
the complete release before an atomic switch, preserves
data/configuration/secrets and runtime state, and restores the previous release
when the new health check fails.

## Uninstall

```bash
curl -fsSL https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.0.0-rc.3/install.sh \
  | bash -s -- uninstall
```

Default uninstall stops and removes only the local Panel service, installed
release files, frontend, and Node artifacts. It retains `/etc/relay-panel` and
`/var/lib/relay-panel`, and requires typing `UNINSTALL`. Add `--yes` only for
intentional automation. Add `--purge` only to remove those data/configuration
directories too. Remote Relay nodes, DNSMgr, DNS records, and Reality backends
are never contacted.

## Relay deployment

Use the Panel Node Bootstrap UI for normal Relay installation and upgrades.
The Panel selects the matching Release artifact from its local
`node-assets` root, validates architecture/version/SHA-256, and performs the
transactional SSH or Manual Bootstrap flow. Manual Bootstrap accepts both HTTP
and HTTPS Panel endpoints and is intended for advanced recovery.

Proxy Protocol v1 requires receive to be enabled on the remote Reality/Xray
backend first, followed by a completed backend/Xray reload and runtime check;
enable Relay sending last. Disable in the reverse order. Reality `xver=0` is
independent and remains `0`.
