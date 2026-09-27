# Reality Panel — Status

Last verified in source: 2026-09-27

## Current phase

Node Reuse product completion is integrated, accepted, and published in stable `v1.1.26`. The Owner reports it is deployed to production. Node Pool V1 was independently reviewed and integrated on `main` at `95f230bf73e730b92b9023f01e5fad1c2e7d9763`, but is not released or deployed. RT-001 is a separate fix requiring independent review before integration.

Isolated Debian runtime acceptance of integrated Node Pool source found RT-001: after migration, a Node restart could transiently replace combined A+B LKG with legacy A-only config. A separate RT-001 fix branch now prioritizes durable credential authentication before config transport startup and rejects exact-node legacy config delivery after recorded migration completion. The fix is not integrated, released, deployed, or independently reviewed yet.

## Git baseline

- Repository: https://github.com/pixingzoudaiyuexing/reality-panel
- Baseline branch: `main`
- RT-001 exact fix base: `95f230bf73e730b92b9023f01e5fad1c2e7d9763`
- Earlier Node Reuse release base: `28a5ea505ee0e7bf6beb81b34afa6cccbc7dffb0`
- Integrated implementation branch: `codex/node-reuse-product-completion`
- Accepted implementation commit: `555558f17218540211c59b9c08bd767d68e294a9`
- Release source commit: `5e249ed5b665065d917ce3812075b293414b1ac9`
- Current stable release: `v1.1.26`
- Config Protocol: `10`
- Lifecycle Protocol: `1`

The implementation was a fast-forward from the exact released `main` base above. The original-base-to-final-HEAD review passed before integration and release.

## Production state

The `v1.1.26` GitHub Release is published. The Owner reports production deployment; it was not independently verified here. This Node Pool task has made no production access, database migration, deployment or production mutation.

## Current review gate

The earlier Node Reuse release passed independent Gemini Code Review and Primary acceptance. The integrated Node Pool V1 HEAD also passed independent review; RT-001 changes after that HEAD require a new independent Gemini review.

Primary pre-review finding P-001 separates ACTIVE credentials from durable legacy migration completion. The integrated fix includes an authenticated, idempotent completion handshake and server-enforced membership admission. Isolated Debian runtime acceptance later found RT-001; its fix needs a new Review Pack and formal review.

## Next stage

Next: finish RT-001 validation and independent review. Main integration, release and deployment require separate authorization.
