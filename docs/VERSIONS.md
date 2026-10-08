# Version status

The stable release is `v1.4.9` (the exact published source is recorded in its SOURCE_COMMIT asset).
The accepted UI product RC is `065038a4fa7098b912cb3a4e33e742cd15542080`; the final release adds only version/publication metadata.
v1.4.9 unifies Node Management navigation and Group-scoped rule pagination/selection. Backend business behavior and Node runtime are unchanged from v1.4.8. Production upgrades remain an Owner decision.

Reality Panel uses one application release version for Panel and Node. Published assets and checksums remain immutable. Candidate TEST acceptance and official publication are separate. Config Protocol remains `10`, Lifecycle Protocol remains `1`.

## Release assets

The stable release publishes exactly these ten systemd assets via helper-only/direct upload:

```text
reality-panel-linux-amd64
reality-node-linux-amd64
reality-panel-web.tar.gz
install.sh
update.sh
deploy.sh
relay-node-install.sh
SOURCE_COMMIT
VERSION
SHA256SUMS
```

Panel embeds its Bootstrap, credential, lifecycle and one-time migration scripts from the same checkout; Node download metadata is served from the verified Panel-managed Node artifact. SOURCE_COMMIT names the exact source HEAD. VERSION contains the bare application version. SHA256SUMS covers every listed asset except itself. A local verified release-shaped archive for TEST is not a GitHub Release.

## Version sources

- `crates/panel/Cargo.toml`, `crates/node/Cargo.toml` and their Cargo.lock entries: `1.4.9`.
- Panel configuration and both `--version` commands derive from their package version.
- Legacy compatibility `scripts/relay-node-install.sh` SCRIPT_VERSION: `1.4.9`.
- Workspace has no application version. Shared crate `0.1.0` and private frontend package `0.0.0` are independently versioned and are not public release versions.
- GitHub release tag is validated against Panel/Node package versions. The release workflow generates VERSION, SOURCE_COMMIT and the release installer default tag.
- Installer and updater resolve an explicit tag or the latest published stable Release; there is no unpublished latest fallback.
- Official legacy detector remains `1.3.0`, exact amd64 SHA and official source. The existing one-time upgrader remains pinned to official `1.4.4`; v1.4.9 does not publish a historical upgrader asset. The historical binary-release workflow and its pinned checksum gate are unchanged; direct publication temporarily isolates only conflicting workflows and restores their prior active states.
- Docker files do not carry an application version; images remain compatibility material, not the automatic formal release path.

```bash
bash scripts/release-check.sh 1.4.9
bash scripts/release-version-contract.test.sh v1.4.9
cargo build --workspace --release --locked
```

The checked-in optimized release profile uses stripping, fat LTO and one codegen unit. Resource limits may serialize compilation without changing this profile. Multi-A state and pending DNS transactions prohibit a bare downgrade to an older binary that does not understand the state; no downgrade converter is provided.

## v1.4.8 Carrier compatibility

Carrier policy adds optional `default_node_ids` beside `default_node_id`. Missing/null new field reads the legacy single value; an explicit array (including empty) takes precedence. Node IDs are deduplicated and stably sorted; the old anchor stays selected or moves to the first survivor. Carrier DNS and Follow Default use every selected Node's distinct IPv4. A missing selected IPv4 keeps the desired selection and previous DNS and reports incomplete status; it never silently applies a subset. Offline Nodes with valid last-known IPv4 remain valid Carrier targets.

Other modes keep their single-default contracts and retain the saved Carrier set. No database migration is required. Once a multi-default policy has been written, do not directly downgrade to an older Panel binary: older code ignores the new set and could shrink default/Follow Default records. Never downgrade during a pending DNS transaction. Complete/resolve the transaction and explicitly reduce the policy to a compatible single default before any planned downgrade; no downgrade converter is provided.

DNS observations are scoped to one apply/preflight or worker batch. They never replace fresh post-mutation readback or unknown/external overwrite confirmation. The same RRset is serialized; independent RRsets run at most four at once. Full paginated zone reads pause this process's zone mutations to obtain a coherent inventory. Existing TLS, bounded read retries, unknown-write handling, ownership and rollback gates remain in force.
