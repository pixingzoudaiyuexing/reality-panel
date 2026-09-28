# Release Contract

Reality Panel uses one release tag and one compatibility version for the Panel
and Node. The latest verified GitHub Release is `v1.3.0`. Node Management V2
development candidate is `v1.4.0` so a released `v1.3.0` Node can install the
new automatic-migration-capable binary through the monotonic lifecycle updater.
This source is not release-ready, reviewed, released, or deployed. The Owner previously reported
`v1.1.26` production deployment; current production version was not inspected.
Config Protocol remains `10` and Lifecycle Protocol remains `1`.

## Release assets

Each `vX.Y.Z` GitHub Release is built from its tagged checkout and contains:

```text
reality-panel-linux-amd64
reality-node-linux-amd64
reality-panel-web.tar.gz
install.sh
update.sh
deploy.sh
relay-node-install.sh
SHA256SUMS
```

The release workflow checks that Cargo package versions equal the tag, builds
both binaries and the frontend from that checkout, and creates the checksum
manifest. The systemd updater only trusts GitHub Release assets. Existing Docker
images remain available for compatibility deployments, but Docker is no longer
part of the automatic release workflow.

## Version locations

- `crates/panel/Cargo.toml` and `crates/node/Cargo.toml` carry the matching
  unreleased application version `1.4.0`.
- `Cargo.lock` records both package versions.
- `crates/panel/src/config.rs` reads the Panel package version by default.
- `scripts/relay-node-install.sh` is a legacy compatibility script only.
- `.github/workflows/binary-release.yml` publishes systemd release assets.

Validate version alignment before a later, separately authorized release:

```bash
bash scripts/release-check.sh 1.4.0
```

The default updater resolves the latest non-prerelease `v*` Release. An
explicit version may select `v1.0.0-rc.6`, `v1.0.0`, or a later stable tag.
This permits an in-place RC-to-stable upgrade without changing database or
runtime paths.
