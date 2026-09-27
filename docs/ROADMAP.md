# Reality Panel — Roadmap

## Current stage: Node Pool V1 implementation pending independent review

Node Pool V1 projects existing Nodes and memberships without automatic runtime changes, adds Pool-managed names and Group-centric assignment, and provisions new Nodes under a hidden identity anchor. It is not merged, released, or deployed. The Owner reports that stable `v1.1.26` is already deployed; this task has not independently verified production. See [ADR 0002](adr/0002-node-pool-v1.md).

## Stable baseline: Node Reuse product completion

The implementation based on `v1.1.25` adds default availability, prospective Preflight, server-enforced safe creation, server-proven sync status, and Node-detail management UI. It is integrated on `main` at `555558f17218540211c59b9c08bd767d68e294a9`, passed independent Gemini review, was accepted by Primary, and shipped in `v1.1.26`.

The Owner reports a later production deployment of `v1.1.26`; this implementation task has not accessed production.

## Explicitly deferred / excluded from Node Reuse V1

- full Node ↔ Group many-to-many ownership;
- Rule ↔ Node assignment;
- per-rule Carrier target model;
- whole-group reuse;
- share/invite/reuse-token model;
- new Stable Node ID / hardware identity framework;
- cross-group Failover.

## Historical roadmap

`docs/ROADMAP-v0.4.md` is preserved as historical planning only. It is not the current project roadmap.
