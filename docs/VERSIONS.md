# Release Contract

Reality Panel uses one application release version for Panel and Node. The published baseline is `v1.3.0`; the current candidate is `v1.4.2`. Candidate TEST acceptance and official publication are separate. Production was not accessed or verified during this task. Config Protocol remains `10`, Lifecycle Protocol remains `1`.

## Release assets

The tagged source produces these systemd Release assets:

```text
reality-panel-linux-amd64
reality-node-linux-amd64
reality-panel-web.tar.gz
install.sh
update.sh
deploy.sh
relay-node-install.sh
reality-node-v1.3.0-to-v1.4.2.sh
SOURCE_COMMIT
VERSION
SHA256SUMS
```

Panel embeds its Bootstrap, credential, lifecycle and one-time migration scripts from the same checkout; Node download metadata is served from the verified Panel-managed Node artifact. SOURCE_COMMIT names the exact source HEAD. VERSION contains the bare application version. SHA256SUMS covers every listed asset except itself. A local verified release-shaped archive for TEST is not a GitHub Release.

## Version sources

- `crates/panel/Cargo.toml`, `crates/node/Cargo.toml` and their Cargo.lock entries: `1.4.2`.
- Panel configuration and both `--version` commands derive from their package version.
- Legacy compatibility `scripts/relay-node-install.sh` SCRIPT_VERSION: `1.4.2`.
- Workspace has no application version. Shared crate `0.1.0` and private frontend package `0.0.0` are independently versioned and are not public release versions.
- GitHub release tag is validated against Panel/Node package versions. The release workflow generates VERSION, SOURCE_COMMIT and the release installer default tag.
- Installer and updater resolve an explicit tag or the latest published stable Release; there is no unpublished latest fallback.
- Official legacy detector remains `1.3.0`, exact amd64 SHA and official source. The one-time upgrade target is current Panel version and current verified Node artifact, `1.4.2` for this candidate.
- Docker files do not carry an application version; images remain compatibility material, not the automatic formal release path.

```bash
bash scripts/release-check.sh 1.4.2
bash scripts/release-version-contract.test.sh v1.4.2
cargo build --workspace --release --locked
```

The checked-in optimized release profile uses stripping, fat LTO and one codegen unit. Resource limits may serialize compilation without changing this profile. Multi-A state and pending DNS transactions prohibit a bare downgrade to an older binary that does not understand the state; no downgrade converter is provided.
