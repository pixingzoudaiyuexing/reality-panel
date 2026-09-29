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
- GitHub Release based publishing;
- exact-concrete-node Node Reuse with admin Preflight and guarded runtime delivery (released in `v1.1.26`; Owner reports production deployment);
- Node Pool V1 and RT-001, independently reviewed and runtime-accepted, published in `v1.3.0`; production deployment was not verified in the V2 task.
- Node Management V2 is integrated on `main` at `e55560b2fa619024362df4efa29e83b4755930df` after Primary and independent Gemini review. The reviewed RC-140-001 release-preparation HEAD is `1ed93c1fc9db5232da3f39040c28cbee93f9cf99`; the `1.4.0` release source is finalized from it. New Nodes are Pool-native and receive exact Permanent Credentials; automatic migration is only for historical Legacy Nodes.

## Non-goals / boundaries

- The Panel is not a packet forwarding hop.
- Relay does not terminate the real Reality TLS session.
- Carrier routing remains group-level, not per-rule. One provider line may target multiple exact Nodes only when each A value has a distinct provider record ID; grouped multi-value records fail closed.
- Failover remains group-level / same-group.
- Cross-group failover is not part of Node Reuse V1.
- Docker is not the formal automatic production release path.
- Historical Business WSS and Node Edge Caddy automation must not be revived as current roadmap items.

## Important constraints

- Config Protocol is currently 10.
- Lifecycle Protocol is currently 1.
- At the 2026-09-29 pre-tag source freeze, the latest published stable release was `v1.3.0`; consult GitHub Releases for subsequent publication. The Owner previously reported `v1.1.26` production deployment; current production version was not inspected.
- Node Management V2 and RC-140-001 passed their required Primary and independent reviews. Formal release assets are built from the exact tagged checkout; no production deployment is asserted by this source freeze.
- Group Token is historical compatibility only and must not be the identity credential for newly provisioned Nodes.
- Production release artifacts are built and published from the tagged checkout.
- Existing SQLite deployment remains supported; PostgreSQL support is also present.
- Project-level decisions proposed by Codex require Primary acceptance before becoming canonical project knowledge.
