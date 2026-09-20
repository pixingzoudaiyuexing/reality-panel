# Reality Panel — Project

## Product

Reality Panel is a self-hosted control plane for Reality SNI relay infrastructure.

It manages Relay Nodes, Reality/SNI forwarding configuration, DNS automation, certificates, relay selection, diagnostics, lifecycle operations, and related operational state while keeping forwarding traffic off the Panel data path.

## Core goals

- Operate Nginx Stream SNI-based Layer-4 forwarding.
- Preserve end-to-end Reality TLS passthrough; Relay does not terminate the real Reality TLS session.
- Centralize relay node, DNS, certificate, routing-preference, failover, diagnosis, and lifecycle control.
- Keep already-working Relay runtime available when the Panel, DNS, or a newly proposed config is temporarily unavailable.
- Support release-driven systemd deployment with verified GitHub Release assets.

## Current functional boundary

The repository currently contains support for:
- Relay Node management and authenticated control channels;
- Nginx Stream `ssl_preread` SNI forwarding;
- backend hostname/DDNS following;
- DNSMgr ownership, mutation, and read-back verification;
- Relay Preference;
- Carrier Affinity;
- scheduled Relay switching;
- group-level failover;
- Panel-managed wildcard certificate / ACME DNS-01 flows;
- camouflage/fallback;
- diagnosis and reconciliation;
- node lifecycle/update;
- Lite-node related behavior;
- GitHub Release based publishing.

## Non-goals / boundaries

- The Panel is not a packet forwarding hop.
- Relay does not terminate the real Reality TLS session.
- Carrier routing remains group-level. The current model is a default node plus `line_id -> node_id` overrides, not per-rule Carrier targets.
- Failover remains group-level / same-group.
- Cross-group failover is not part of Node Reuse V1.
- Docker is not the formal automatic production release path.
- Historical Business WSS and Node Edge Caddy automation must not be revived as current roadmap items.

## Important constraints

- Config Protocol is currently 10.
- Lifecycle Protocol is currently 1.
- Stable release at the adoption baseline is `v1.1.24`.
- Production release artifacts are built and published from the tagged checkout.
- Existing SQLite deployment remains supported; PostgreSQL support is also present.
- Project-level decisions proposed by Codex require Primary acceptance before becoming canonical project knowledge.
