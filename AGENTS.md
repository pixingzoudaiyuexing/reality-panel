# AGENTS.md

## Workflow anchor

- Workflow source: https://github.com/pixingzoudaiyuexing/ai-development-workflow
- Workflow version: `v1`
- Workflow revision: `69a4def98c9bf473936cdebe325dd828704d97dc`
- Project tier: Tier 3
- Project: Reality Panel

Do not silently adopt later workflow changes. Start from the pinned revision above unless the Primary explicitly upgrades it.

## Required reads

Before substantial work, read `docs/PROJECT.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/STATUS.md`, and any relevant ADR under `docs/adr/`.

## Git workflow and safety

- Known state is more important than artificially clean state.
- Check branch, HEAD, worktree changes, and relevant remote state before non-trivial work.
- Do not reset, clean, discard, overwrite, or delete unknown user work.
- Reality Panel is a single-developer project. **Pull Requests are optional and are not the default development path.**
- For substantial work, prefer an isolated worktree / feature branch for implementation and verification so the primary `main` worktree stays stable. After acceptance, the verified commit(s) may be integrated directly into `main` without creating a PR.
- For High-Risk work, the exact implementation HEAD/tree and evidence must receive independent Gemini Code Review before integration into `main`. If review fixes change the code, re-review the new exact HEAD before integration.
- Use a PR only when the Owner explicitly asks for one, when collaborating with other contributors, or when a PR materially helps a specific task.
- This project-specific rule overrides any upstream workflow assumption that a PR is a mandatory review container; the remaining evidence, review, and production authorization gates still apply.
- Do not create a Release or deploy unless explicitly authorized.
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

Node Reuse V1 is implemented and merged. See `docs/adr/0001-node-reuse-v1.md`.

Preserve the accepted V1 boundaries: one Home Group per Node, explicit reuse of specific concrete Nodes, original Rule/Group ownership and billing attribution, and shared LKG/offline behavior for Home and reused rules.

Do not introduce per-rule Carrier routing, whole-group reuse, Node many-to-many ownership, Rule-to-Node assignment, new stable hardware identity, or cross-group failover as part of V1 without a new Primary decision.
