# Reality Panel — Status

Last verified in source: 2026-10-01

## Current phase

Node Reuse product completion is integrated, accepted, and published in stable `v1.1.26`. The Owner reports that it is deployed to production; this remains Owner-reported and was not independently verified. Node Pool V1 and RT-001 are integrated on `main`, passed independent review, and passed isolated Debian 12 amd64 runtime acceptance. Candidate source version `v1.3.0` is prepared but is not released or deployed.

## Git baseline

- Repository: https://github.com/pixingzoudaiyuexing/reality-panel
- Baseline branch: `main`
- Accepted Node Pool / RT-001 source: `fe8068f55578b6cacb040d4ac72ceaaf271c8321`
- RC preparation base: `fe8068f55578b6cacb040d4ac72ceaaf271c8321`
- Historical source/release notes contain the `v1.2.x` version line; the next candidate uses `v1.3.0`.
- Earlier Node Reuse release base: `28a5ea505ee0e7bf6beb81b34afa6cccbc7dffb0`
- Integrated implementation branch: `codex/node-reuse-product-completion`
- Accepted implementation commit: `555558f17218540211c59b9c08bd767d68e294a9`
- Release source commit: `5e249ed5b665065d917ce3812075b293414b1ac9`
- Current stable release: `v1.1.26`
- Config Protocol: `10`
- Lifecycle Protocol: `1`

The Node Pool implementation was integrated by fast-forward after independent review. RT-001 was separately integrated after re-review. The post-RT-001 runtime acceptance passed against the exact integrated HEAD.

## Production state

The `v1.1.26` GitHub Release is published. The Owner reports production deployment; it was not independently verified here. RC preparation has made no production access, deployment, or production mutation.

## Current review gate

Node Reuse, Node Pool V1, and the RT-001 fix have passed their independent review gates. The exact integrated runtime source also passed isolated Debian 12 amd64 re-acceptance. Candidate versioning, documentation, changelog accuracy and release contract are pending Primary review.

Primary finding P-001 separated ACTIVE credentials from durable legacy migration completion. The accepted implementation adds an authenticated idempotent completion handshake and server-enforced membership admission. RT-001 startup authority is fixed and its isolated runtime regression passed.

## Next stage

Next: Primary review of the `v1.3.0` candidate source commit and RC review package. Tagging, GitHub Release publication, release assets, and deployment remain separate authorized steps.

## Authorized branch continuation (2026-10-01)

The current engineering task is on `codex/carrier-multinode-dns-multia`, based on
Node Lifecycle Completion `05e135094562d91e1920520a781207e47f7bfcfb`, which retains
Pool-native Multi-Group `3dc147edd108906767d0e5447e79cd31f899750b`.

Carrier lines now accept multiple distinct Group Member Nodes. Desired DNS is a
deduplicated IPv4 set, with individual-record and Huawei RRset adapter handling.
Default remains scalar; Carrier never filters EffectiveConfig Rules. Offline
preserves selections/last-known addresses; missing IP permits save and reports
incomplete. Unknown A/CNAME requires exact current/desired confirmation, while
provider read failure remains an error. Remove/Delete prunes selections and
schedules existing DNS reconciliation; external failure never undoes retirement.

No new migration, dependency, config protocol, identity or lifecycle framework
is introduced. No push, integration into `main`, release or Production deployment
is authorized for this task. Formal independent review applies to the exact
implementation HEAD before any later integration. Adapter/integration validation
uses an HTTP provider mock. No external DNS TEST credential/zone was supplied,
so live-provider Multi-A acceptance remains NOT VERIFIED.
