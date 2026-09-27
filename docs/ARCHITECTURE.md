# Reality Panel — Current Architecture

This document describes the current source design, including the Node Reuse product completion integrated at `555558f17218540211c59b9c08bd767d68e294a9` after independent review and Primary acceptance. The feature has not been released or deployed.

## Control plane and data plane

Reality Panel is the control plane. Relay Nodes form the data plane.

The Panel distributes desired configuration and operational commands. Relay Nodes keep forwarding locally and are designed to preserve useful runtime state when control-plane delivery fails.

Reality/SNI traffic does not traverse the Panel. For Reality relay rules, Nginx Stream uses SNI inspection to route Layer-4 TCP traffic. The real Reality TLS handshake remains end-to-end with the backend.

## Panel / Node control channels

Relay Nodes use authenticated HTTP(S) and WebSocket control paths.

Configuration compatibility is guarded by `CONFIG_PROTOCOL_VERSION = 10`. A mismatched or missing version is rejected instead of sending incompatible config. HTTP config delivery and WebSocket paths share the same compatibility model.

Lifecycle operations use a separate long-lived control protocol, currently `LIFECYCLE_PROTOCOL_VERSION = 1`, so config protocol evolution does not remove the node's upgrade path.

## Node configuration and LKG

The Panel builds node configuration from an inbound group and its active rules. For an authenticated, verified concrete Node, Node Reuse merges Home Group rules with only that Node's explicit reuse Bindings. Legacy Group Token Nodes remain Home-only even when they report an `X-Node-ID` matching a concrete Node. Node-specific details such as camouflage public-IP resolution retain the Home Group identity namespace.

Config snapshots include a durable monotonic revision and semantic fingerprint. Revision state is keyed by group and, when a node ID is present, by concrete node. Legacy self-reported node IDs use a separate revision namespace and cannot modify verified concrete-node revision authority. Both namespaces are read when planning the next revision for that identity, so switching authentication modes cannot move the delivered revision backward. EffectiveConfig revisions also track source-group membership, so adding or removing a zero-rule Binding after delivery advances the revision. Nodes reject stale config delivery so transport arrival order cannot roll runtime/LKG state backward.

Node Reuse is enabled by default in the integrated source. `NODE_REUSE_RUNTIME_ENABLED=0` (or `false`) is an emergency opt-out, not a normal setup step or UI toggle. Prospective Preflight is read-only and uses the same source collector/conflict semantics as delivery; Binding creation independently repeats validation. A failed EffectiveConfig build returns unavailable for HTTP and skips unsafe WS snapshots rather than authorizing an empty config. Binding mutations rely on normal Node polling, not a global config broadcast.

The admin runtime-status projection read-only plans the exact intended delivery snapshot without committing revision, attribution, certificate migration or certificate backup repair. The actual HTTP/WS delivery path uses the same revision planner and then persists authority. Status requires that the planned revision has already been committed for the concrete Node before comparing its fingerprint and revision with a fresh, verified Node reconciliation report. A generic `CONVERGED` report, uncommitted prediction or stale revision alone cannot prove Node Reuse sync. Offline, conflict, apply failure, and local recovery remain separate states. The Node's guarded apply preserves working listeners and LKG when a new desired configuration fails.

The LKG boundary is intentional:
- missing or invalid auth does not become an authoritative empty config;
- transient Panel/database failure does not instruct a node to delete working listeners;
- Nginx config is validated before reload;
- backend hostname resolution can retain a previously working upstream;
- failed new certificates/config should not replace valid runtime state.

## Routing model

### Relay Preference

Groups can select an effective Relay node.

### Carrier Affinity

Carrier policy is group-level. Its persisted model contains:
- `default_node_id`
- a list of line bindings with `line_id`
- each binding can follow the default or name a concrete `node_id`

This is not per-rule Carrier routing.

### Scheduled switching

Schedule mode reuses the same Relay switching and safety boundaries rather than defining a separate data-plane model.

### Failover

Failover remains group-level and same-group. Cross-group failover is outside the current Node Reuse V1 scope.

## Rules and group ownership

Forward rules belong to an inbound device group through the existing group fields. Deleting a group is blocked while rules still reference it through `device_group_in`, `device_group_out`, or `fallback_group`.

Node tokens and lifecycle operations are group/node ownership concerns. Node Reuse V1 must not rewrite existing ForwardRule ownership to simulate reuse.

## DNS

DNSMgr automation is designed around explicit ownership and fail-closed mutation:
- Panel only changes records it can prove it owns;
- external records are not silently taken over;
- provider mutation is followed by read-back;
- uncertain DNS state blocks topology changes instead of blindly replacing known-good state.

## Certificates

Panel-managed certificate flow uses ACME DNS-01 and publishes managed certificate generations to Relay Nodes. Camouflage desired state references certificate policy, while certificate material is obtained through a separate authenticated endpoint.

Certificate failure must not casually replace an existing working certificate/runtime generation.

## Node lifecycle

Relay lifecycle commands run over the authenticated control channel. The implementation includes controlled restart/update/uninstall behavior and systemd-managed production assumptions.

A node's identity uses the existing persistent node ID mechanism. Node Reuse V1 does not introduce a new hardware/stable identity framework.

## Persistence

The Panel supports SQLite as the default deployment and PostgreSQL as an optional backend. Persistent state includes group/rule configuration, config-revision metadata, routing policy, operational state, and other control-plane records.

## Deployment and release

The formal production path is:
- Debian 12 / amd64
- systemd-managed Panel and Node binaries
- frontend release bundle
- installer/updater scripts
- GitHub Release assets with `SHA256SUMS`

The release workflow builds both binaries and frontend from the tagged checkout. Docker assets remain for development/compatibility use but are not the automatic formal release path.

## Historical boundary

`docs/ROADMAP-v0.4.md` is historical. It records earlier development-line decisions and must not be treated as the current roadmap. In particular, Business WSS and Node Edge Caddy automation are explicitly cancelled historical directions.
