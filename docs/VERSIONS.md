# Release Contract

Reality Panel uses one release tag and one compatibility version for the Panel
and Node. The latest verified GitHub Release is `v1.3.0`. The integrated Node
Management V2 release candidate is `v1.4.0`, so a released `v1.3.0` Node can
install the newer automatic-migration-capable binary through the monotonic
lifecycle updater. The implementation HEAD `e55560b2fa619024362df4efa29e83b4755930df`
passed Primary and Formal Independent Gemini review; `v1.4.0` is not tagged,
released or deployed. The Owner previously reported `v1.1.26` production
deployment; current production version was not inspected.
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
SOURCE_COMMIT
SHA256SUMS
```

The release workflow checks that Cargo package versions equal the tag, builds
both binaries and the frontend from that checkout, and creates the checksum
manifest. The systemd updater only trusts GitHub Release assets. Existing Docker
images remain available for compatibility deployments, but Docker is no longer
part of the automatic release workflow.

The source/raw installer has an empty `DEFAULT_RELEASE_TAG` and defaults to
latest stable. Release assembly injects the exact tag only into the staged
installer and requires exactly one marker before and after injection. Bundled
fresh `install` defaults to that tag; `update` ignores it and keeps resolving
latest stable. Explicit CLI versions override `TARGET_VERSION`, which overrides
the bundled fresh-install default. The installed updater remains latest-stable
by default and accepts an explicit tag.

## Version locations

- `crates/panel/Cargo.toml` and `crates/node/Cargo.toml` carry the matching
  unreleased candidate version `1.4.0`.
- `Cargo.lock` records both package versions.
- `crates/panel/src/config.rs` reads the Panel package version by default.
- `scripts/relay-node-install.sh` is a legacy compatibility script only.
- `.github/workflows/binary-release.yml` publishes systemd release assets.

Validate version alignment before a later, separately authorized release:

```bash
bash scripts/release-version-contract.sh v1.4.0
bash scripts/release-check.sh 1.4.0
```

The `1.4.0` schema anchors are SQLite Migration 59 and PostgreSQL revision 43.
Config Protocol remains 10 and Lifecycle Protocol remains 1. Carrier routing
supports multiple A values on one line only when each value has a distinct
provider record ID; grouped values under one ID fail closed with
`CARRIER_MULTI_A_PROVIDER_UNSUPPORTED`.

The default updater resolves the latest non-prerelease `v*` Release. An
explicit version may select `v1.0.0-rc.6`, `v1.0.0`, or a later stable tag.
This permits an in-place RC-to-stable upgrade without changing database or
runtime paths.
