# Reality Panel — Status

Last verified in source: 2026-09-29

## Current phase

Node Management V2 implementation is active on isolated branch `codex/node-management-v2`; it is not independently reviewed, integrated, released, or deployed. Its unreleased source version is `1.4.0`, allowing released `v1.3.0` Nodes to install a newer automatic-migration-capable binary. Historical identity convergence uses a unique live Lifecycle connection and the existing Permanent Credential machinery. New Nodes receive Permanent Credentials directly. Carrier multi-node/multi-A routing is included in the V2 scope, with per-target DNS ownership and health-driven membership. Isolated Debian 12 amd64 acceptance passed with the `1.4.0` Linux binaries: fresh SSH provisioning on SQLite and PostgreSQL, Claim/prepare/activate failure with rollback and same-identity retry, trusted-proxy rejection, current-version migration with lost completion ACK, and a checksum-verified public `v1.3.0` Node upgrading to `1.4.0` before migration. The final commit/tree still requires independent review.

Node Reuse product completion shipped in `v1.1.26`. The Owner reports that version was deployed to production; this remains Owner-reported. Node Pool V1 and RT-001 passed independent review and isolated Debian 12 amd64 runtime acceptance. GitHub Release `v1.3.0` was published on 2026-09-28, verified read-only on 2026-09-29. Current production version was not inspected.

## Git baseline

- Repository: https://github.com/pixingzoudaiyuexing/reality-panel
- Baseline branch: `main`
- Accepted Node Pool / RT-001 source: `fe8068f55578b6cacb040d4ac72ceaaf271c8321`
- RC preparation base: `fe8068f55578b6cacb040d4ac72ceaaf271c8321`
- Historical source/release notes contain the `v1.2.x` version line; Node Pool V1 therefore shipped as `v1.3.0`.
- Earlier Node Reuse release base: `28a5ea505ee0e7bf6beb81b34afa6cccbc7dffb0`
- Integrated implementation branch: `codex/node-reuse-product-completion`
- Accepted implementation commit: `555558f17218540211c59b9c08bd767d68e294a9`
- Release source commit: `5e249ed5b665065d917ce3812075b293414b1ac9`
- Current published stable release: `v1.3.0`
- Node Management V2 base: `be0acfb380a79883b582ecd7bb2c46a18595d491`
- Config Protocol: `10`
- Lifecycle Protocol: `1`
- SQLite Migration: `59`
- PostgreSQL schema revision: `43`

The Node Pool implementation was integrated by fast-forward after independent review. RT-001 was separately integrated after re-review. The post-RT-001 runtime acceptance passed against the exact integrated HEAD.

## Production state

The `v1.3.0` GitHub Release is published. The Owner previously reported `v1.1.26` production deployment; current production version was not independently verified here. V2 implementation has made no production access, deployment, or production mutation.

## Current review gate

Node Reuse, Node Pool V1, and the RT-001 fix passed their independent review gates before `v1.3.0` publication. Node Management V2 requires a new independent review of its exact final implementation HEAD.

Primary finding P-001 separated ACTIVE credentials from durable legacy migration completion. The accepted implementation adds an authenticated idempotent completion handshake and server-enforced membership admission. RT-001 startup authority is fixed and its isolated runtime regression passed.

## Next stage

Next: freeze the exact V2 implementation HEAD and submit the review package for independent Gemini review. Integration and any future release/deployment remain separate authorized steps.
