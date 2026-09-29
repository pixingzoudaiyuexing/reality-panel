# Reality Panel — Roadmap

## Current stage: Node Management V2 v1.4.0 release candidate preparation

Node Pool V1 projects existing Nodes and memberships without automatic runtime changes, adds Pool-managed names and Group-centric assignment, and provisions new Nodes under a hidden identity anchor. Implementation and RT-001 have passed independent review; isolated Debian 12 amd64 runtime acceptance also passed, including post-migration restart, invalid descriptor and Pool-native SSH Bootstrap flows. GitHub Release `v1.3.0` is published. The Owner previously reported `v1.1.26` production deployment; current production version was not inspected in this task. V2 is not released or deployed. See [ADR 0002](adr/0002-node-pool-v1.md).

Node Management V2 adds unified health, exact membership projection, guarded retirement with a persistent tombstone and explicit restore, and one-time historical Legacy identity convergence. New Nodes remain Permanent-Credential-only. The implementation is integrated on `main` at `e55560b2fa619024362df4efa29e83b4755930df`; Primary and independent Gemini reviews passed. Version `1.4.0` is not tagged, released or deployed.

Carrier can target multiple Nodes on one provider line when each A value has a distinct Panel-owned provider record ID. Providers grouping several A values under one record ID fail closed with `CARRIER_MULTI_A_PROVIDER_UNSUPPORTED`. The public `v1.3.0` Node upgrade path and fresh `1.4.0` SSH Bootstrap have isolated Linux runtime evidence; neither implies production deployment.

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
