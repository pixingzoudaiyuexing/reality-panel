# Reality Panel — Roadmap

## Current stage: Node Reuse V1 — phased implementation

Workflow Adoption is complete. The project is now implementing Node Reuse V1 in independently reviewable slices under the approved boundary in `docs/adr/0001-node-reuse-v1.md`.

Slice 1 is merged and remains intentionally inert:
- persist explicit `(reusing_group_id, home_group_id, node_id)` reuse bindings;
- provide dual-backend Repository queries and deterministic resolver helpers;
- do not connect those bindings to config generation, traffic, certificates, routing, lifecycle, public APIs, frontend, release, or production runtime.

S2-A1 is the next independently reviewed inert foundation:
- define the strict Node-Reuse-only id grammar `^[A-Za-z0-9_-]{1,128}$` without changing legacy Home-only node-id handling;
- persist algorithm-neutral concrete-node credential verifier records for future credential work;
- keep credential issuance, claim, verification, runtime authority, management APIs, and Reusing Group config delivery disabled.

Later Node Reuse activation slices remain not implemented until separately authorized and reviewed.

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
