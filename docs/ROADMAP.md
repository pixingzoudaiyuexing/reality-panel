# Reality Panel — Roadmap

## Current stage: Node Pool V1 v1.3.0 release candidate pending Primary review

Node Pool V1 projects existing Nodes and memberships without automatic runtime changes, adds Pool-managed names and Group-centric assignment, and provisions new Nodes under a hidden identity anchor. Implementation and RT-001 have passed independent review; isolated Debian 12 amd64 runtime acceptance also passed, including post-migration restart, invalid descriptor and Pool-native SSH Bootstrap flows. Candidate version is `v1.3.0`; it is not released or deployed. The Owner reports stable `v1.1.26` production deployment; that state has not been independently verified in this task. See [ADR 0002](adr/0002-node-pool-v1.md).

## Stable baseline: Node Reuse product completion

The implementation based on `v1.1.25` adds default availability, prospective Preflight, server-enforced safe creation, server-proven sync status, and Node-detail management UI. It is integrated on `main` at `555558f17218540211c59b9c08bd767d68e294a9`, passed independent Gemini review, was accepted by Primary, and shipped in `v1.1.26`.

The Owner reports a later production deployment of `v1.1.26`; no production access occurred during RC preparation.

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
