# Release Contract

Reality Panel uses one release tag and one compatibility version for the Panel
and Node. The current candidate is `v1.0.0-rc.3`; the wire protocol remains
`CONFIG_PROTOCOL_VERSION = 8`.

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
manifest. No branch, raw commit, Actions artifact, GHCR image, or local binary
is a production update source.

## Version locations

- `crates/panel/Cargo.toml` and `crates/node/Cargo.toml` carry the matching
  application version.
- `Cargo.lock` records both package versions.
- `crates/panel/src/config.rs` reads the Panel package version by default.
- `scripts/relay-node-install.sh` is a legacy compatibility script only.
- `.github/workflows/binary-release.yml` is the only v1 release workflow.

Run before tagging:

```bash
bash scripts/release-check.sh 1.0.0-rc.3
```

The default updater resolves the latest non-prerelease `v*` Release. An
explicit version may select `v1.0.0-rc.3` or a later stable tag. This permits
an in-place RC-to-stable upgrade without changing database or runtime paths.
