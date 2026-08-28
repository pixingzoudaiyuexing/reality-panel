# Relay Node

## Normal deployment

Deploy and upgrade Relay nodes from the Panel Node Bootstrap UI. The Panel
selects the Node binary from its own `/opt/relay-panel/node-assets` root,
validates the Linux architecture, version metadata, file size, ELF machine,
and SHA-256, then performs the transactional bootstrap. SSH Bootstrap and
Manual Bootstrap use the same provisioning engine and keep the local commit /
rollback boundary intact.

The supported v1 release artifact is `reality-node-linux-amd64` from the same
GitHub Release as the Panel. Do not download a branch build, CI artifact, or
local binary for a production node.

## Manual recovery

Manual Bootstrap is an advanced recovery path for a Relay that cannot be
reached by Panel SSH but can make outbound control-plane connections. The
launcher contains only the Panel URL and non-secret enrollment ID. The
one-time enrollment secret is entered through the hidden terminal prompt and
is never placed in command-line arguments, environment variables, or URLs.

Both `http://IP:PORT` and `https://hostname` Panel endpoints are supported.
Use HTTPS when available for encrypted control transport.

## Runtime boundaries

The Relay is an L4 SNI/Reality passthrough. It does not terminate or rewrite
the Reality handshake and does not receive Reality private material from the
Panel. Nginx Stream uses `ssl_preread`; the backend controls Reality
authentication. OpenList/camouflage is a separate fallback path.

The control protocol remains version 8. Reality `xver=0` is independent of
the optional Relay-to-backend HAProxy PROXY protocol. When PROXY is enabled,
enable receive on the remote Reality/Xray backend first, wait for its reload
and verify runtime receive, then enable Relay send last. Disable in the reverse
order.

## Lifecycle

Node upgrades are initiated by the Panel. The Panel sends an authenticated
operation and the Node downloads the artifact through the Panel operation
endpoint, verifies its version/SHA, and atomically swaps the binary. Node ID,
LKG, certificates, OpenList data, and managed runtime state remain in place.
