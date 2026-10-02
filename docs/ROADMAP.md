# Reality Panel — Roadmap

## Current stage: v1.4.3 profile-preserving upgrade acceptance

Published v1.4.2 functionality has prior authorized TEST acceptance. The v1.4.3 profile fix has not completed runtime acceptance and now requires exact-source version contracts, optimized artifact build, final tests, Gemini main gate, independent review and public TEST smoke. Publication and Production deployment require separate Owner authorization. The one-time official-v1.3.0 migration stays narrowly scoped; no new architecture or features belong to finalization.

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
