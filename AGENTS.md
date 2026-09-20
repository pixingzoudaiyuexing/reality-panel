# AGENTS.md

## Workflow anchor

- Workflow source: https://github.com/pixingzoudaiyuexing/ai-development-workflow
- Workflow version: `v1`
- Workflow revision: `ac2cdce29c7593f0e0c193a042d9854aaeb79b7d`
- Project tier: Tier 3
- Project: Reality Panel

Do not silently adopt later workflow changes. Start from the pinned revision above unless the Primary explicitly upgrades it.

## Required reads

Before substantial work, read `docs/PROJECT.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/STATUS.md`, and any relevant ADR under `docs/adr/`.

## Git safety

- Known state is more important than artificially clean state.
- Check branch, HEAD, worktree changes, and relevant remote state before non-trivial work.
- Do not reset, clean, discard, overwrite, or delete unknown user work.
- Do not work directly on `main`.
- Do not merge, create a Release, or deploy unless explicitly authorized.
- Historical `integration/node-reuse-v1` is not a valid Node Reuse implementation baseline and must not be used as a development base.

## Production safety

Reality Panel is a control plane for production relay infrastructure. Local development tasks must not mutate production by default.

Do not, unless a task explicitly authorizes it:
- access or modify production servers;
- change DNS records;
- request, delete, or rotate certificates;
- migrate production databases;
- reinstall, upgrade, restart, or uninstall production relay nodes;
- publish a GitHub Release.

Preserve the data-plane Last Known Good principle: panel, DNS, or new-config failures must not casually destroy already-working relay runtime state.

## Baseline verification

Use the smallest sufficient set for the task. Existing project checks include:
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `bash scripts/check-repo-test-parity.sh`
- frontend: `npm ci --no-audit --no-fund`, `npm run typecheck`, `npm run lint`, `npm run test`, `npm run build`
- `python3 tests/e2e_test.py`

For release/version-contract work also use:
- `bash scripts/release-version-contract.sh vX.Y.Z`
- `bash scripts/release-check.sh X.Y.Z`

Documentation-only work does not require full production-like CI when targeted static/version checks are sufficient.

## Release and CI contract

The formal release path is systemd binaries plus GitHub Release assets. Docker files remain development/compatibility material and are not the automatic production release path.

Panel and Node share one release version. Current protocol anchors are:
- Config Protocol: 10
- Lifecycle Protocol: 1

## High-risk modules

Treat changes to these areas as especially sensitive:
- node configuration generation and revision ordering;
- Nginx SNI runtime generation/reload;
- DNSMgr ownership/mutation/read-back;
- relay preference, carrier routing, scheduling, and failover;
- certificate issuance/distribution;
- node lifecycle/update/uninstall;
- authentication/authorization;
- schema/migrations and production persistence;
- release/update/install paths.

## Node Reuse boundary

Node Reuse V1 is approved in architecture direction but not implemented. See `docs/adr/0001-node-reuse-v1.md`.

Do not introduce per-rule Carrier routing, whole-group reuse, Node many-to-many ownership, Rule-to-Node assignment, new stable hardware identity, or cross-group failover as part of V1 without a new Primary decision.
