# Reality Panel — Status

Last source update: 2026-10-02

## Current candidate

Owner-selected candidate: `v1.4.2`, on `codex/release-v1.4.2-finalization`, based on accepted source `be205a0159aebb63a0d4310de5394be0cbacd0fb`. Official published legacy baseline: `v1.3.0`, source `be0acfb380a79883b582ecd7bb2c46a18595d491`.

Pool-native Multi-Group, lifecycle completion, Carrier Multi-Node/DNS Multi-A, Rule DNS preflight and single-node official-v1.3.0 migration have passed prior authorized TEST technical acceptance. Physical A/B migration, real forwarding, Huawei/DNSMgr read-back and controlled precommit rollback passed. Offline preserves Membership; Carrier does not filter Rules; legacy replacement restores current business references and retires the exact old identity.

Release finalization is in progress: final exact-source tests, optimized release artifacts, Gemini main gate, final independent review and public TEST release smoke remain required. No claim of final gate PASS is made here. No push, main integration, tag, GitHub Release or Production deployment is authorized.

## Compatibility

Config Protocol `10`; Lifecycle Protocol `1`. No new database schema migration in this candidate. Multi-A cannot be bare-downgraded into a binary unaware of the stored sets. Legacy upgrade is limited to official v1.3.0 amd64 Debian 12 Lite/systemd, one Node per explicit invocation. Debian 13/Ubuntu have capability/fixture evidence; complete physical acceptance is not claimed.

## Production

Production remains outside the task. Earlier Owner-reported deployments were not independently verified here. Public TEST evidence does not imply Production acceptance.
