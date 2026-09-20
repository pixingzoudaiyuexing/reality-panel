# Reality Panel — Roadmap

## Current stage: Workflow Adoption

Goal:
- adopt AI Development Workflow v1 at pinned revision `ac2cdce29c7593f0e0c193a042d9854aaeb79b7d`;
- establish minimal Tier 3 project documentation;
- record verified current architecture and safety boundaries;
- repair current-stable-version README drift;
- return evidence to the Primary for Adoption Acceptance.

This stage does not implement Node Reuse.

## Next target: Node Reuse V1

Status: approved architecture direction, not yet implemented.

The next implementation phase may begin only after the Primary completes Adoption Acceptance and explicitly declares the project ready.

See `docs/adr/0001-node-reuse-v1.md`.

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
