# Upgrading Reality Node v1.3.0 to v1.4.4

This is a one-time upgrade for the **official v1.3.0 amd64 Debian 12 managed Standard or Lite/systemd Node only**, using a fresh Pool-native identity. It is not a general updater or batch migration. Unknown binaries, custom drop-ins or unsupported hosts stop before the Node is stopped.

## Official operator entrypoint

Repository: `scripts/reality-node-v1.3.0-to-v1.4.4.sh`.
Release asset: `reality-node-v1.3.0-to-v1.4.4.sh`, covered by Release `SHA256SUMS`.
The script pins target version **1.4.4** and its exact Node SHA; it never resolves `latest`. Future Panel versions or a mismatched Node artifact are rejected before STOP. A Release build must match the script's pinned Node hash.

After Owner-authorized publication, download the script and checksum manifest from the **v1.4.4 Release** over HTTPS; do not execute downloaded content before verifying its checksum:

```bash
curl --proto '=https' --tlsv1.2 -fL -O https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.4.4/reality-node-v1.3.0-to-v1.4.4.sh
curl --proto '=https' --tlsv1.2 -fL -O https://github.com/pixingzoudaiyuexing/reality-panel/releases/download/v1.4.4/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
chmod +x reality-node-v1.3.0-to-v1.4.4.sh
sudo ./reality-node-v1.3.0-to-v1.4.4.sh --check
sudo ./reality-node-v1.3.0-to-v1.4.4.sh
```

The default Panel URL comes from the managed Node environment. If needed, append `--panel https://panel.example.com`. `--help` and `--version` need no mutation or credentials.

The script asks for a Panel administrator username and a **masked password**; neither password nor permanent Node credential appears in the command line or output. Authentication stays in process memory. The normal Panel start creates the existing short-lived Node-scoped migration authorization. The script reads this host's managed identity and determines its Home Group itself. No manual API calls or Membership/Carrier JSON are required.

For each actual Rule, the normal invocation asks for an HTTP path and a stable expected response marker. Use that Rule's real forwarding service and a marker expected after the identity replacement. This tool requires HTTP forwarding probes for every Rule; non-HTTP workloads need an operator-provided HTTP check through the same Rule before migration. It does not directly probe a loopback backend as proof of public forwarding.

`--check` verifies the official binary/host, HTTPS Panel capability, Config Protocol 10, exact v1.4.4 artifact metadata and absence of an active migration. It performs only reads after normal login: no operation creation, Node stop, Membership/Carrier/DNS mutation, configuration revision delivery or Pool metadata reconciliation. It outputs the verified provenance and installation profile independently, then `READY` only for a supported old Node with the matching v1.4.4 Panel/artifact. Missing or contradictory profile evidence fails before STOP. It does not infer profile from disk size or marker absence. A completed migration receipt outputs `ALREADY_MIGRATED`, never claims an old-host check succeeded.

## Recommended order

1. Upgrade Panel to v1.4.4 using the normal update path.
2. Confirm old Nodes still forward on LKG.
3. Log into **one** selected Node host and run `--check`.
4. Run the script normally, then check Online, Rules, Carrier, DNS and public forwarding.
5. After manual confirmation, log into another host and explicitly repeat.

**Never upgrade multiple Nodes at once.** There is no `--all`, `--batch` or implicit next Node.

## State and commit boundary

The existing KV store holds a CAS-protected singleton and separate per-operation history. Short request leases serialize snapshot/finalize against mutations. The durable operation blocks its Node and business Groups while other Groups remain usable. Related DNS reconciliation is paused for the operation; ordinary Remove/Re-add/Delete behavior is unchanged.

The snapshot contains display name, memberships (including the old business Home), effective listener expectations, current Carrier/normal references, public IPv4, probes, and local Carrier/normal references. Rules and historical metrics/traffic are not copied.

The script downloads and checks all bundle hashes and candidate executability before stopping the old service. It captures the managed runtime/configuration/credential/certificate and Nginx files with private permissions, installs a fresh Pool-native identity, restores memberships, and waits for an authenticated live config connection, the current effective config revision/fingerprint, observed active listeners and real public forwarding.

Carrier references remain on the old identity until this verification succeeds. One DB transaction replaces current Carrier/normal references, removes old live memberships/Pool/status/revision, cancels pending credentials, revokes active old credentials, and marks the old identity retired. History stays on the old ID. Authentication and metadata registration reject retired identities. Same IPv4 means the DNS desired address set remains unchanged. PRECHECK and finalization perform no live Provider I/O. DNS is handled by normal Carrier apply/sync; independent operator DNS verification remains separate from migration acceptance. The migration performs no DNS shrink/expand or ordinary Node deletion.

`COMMITTED` is the point of no return. Once committed, identity rollback is forbidden. Post-commit verification failures keep the new runtime and require attention; retrying finalize cannot restore the old identity. A lost callback response triggers a durable-status query. An unavailable status query never authorizes old-identity restoration.

## Failure and explicit recovery

Before commit, the runner restores the exact managed host snapshot and starts the old service. It requests a fresh recovery-report barrier, waits for an old-identity report after that barrier plus an actual online connection and public forwarding PASS, then cleans/revokes the staged identity. A stale pre-stop report cannot complete rollback. Old memberships and Carrier references were never removed. A failed host rollback keeps the operation active and retains a root-only recovery directory. Failure backups may contain old runtime credentials and must remain protected; successful completion removes the operation token, bundle/bootstrap private material and old backup.

After an interrupted invocation, explicitly run the same command with:

```bash
--recover-work /var/lib/relay-panel/legacy-v130-upgrade/FAILED-INVOCATION-DIRECTORY
```

Recovery first queries the persisted operation. COMMITTED/SUCCESS completes verification/cleanup without restoring the old identity. Confirmed precommit state restores the snapshot and cleans the staged identity. If Panel is unavailable, stop and retain the new runtime and recovery files until its durable state can be checked. A lost start response reattaches through `/admin/legacy-node-upgrade-v130/current`, verifies exact old identity/profile/capability and persists recovery metadata before bounded polling of the same operation. It never POSTs a second start.

After one SUCCESS, inspect that Node, its rules and DNS manually. Any second Node requires a new explicit invocation. Do not downgrade an upgraded Panel onto a DB containing Multi-A data or a pending routing/DNS transaction; this tool supplies no downgrade converter.

## Verification

Run `python3 scripts/test_legacy_node_upgrade.py`, migration repository tests on SQLite and a real `TEST_PG_URL`, workspace tests, fmt, clippy, repository parity and frontend gates. Formal Independent Review must pass the precise candidate HEAD before destructive TEST migration. v1.4.4 acceptance additionally needs fresh Standard/Lite TEST installs, ordinary v1.4.3 updates preserving both profiles and identity, and the specifically authorized real Standard legacy host. Each destructive legacy attempt requires formal PASS, TEST acceptance and read-only `--check` READY first. Both official Standard and Lite physical TEST migrations are required for v1.4.4 RC acceptance. Automated fault simulations are not physical runtime evidence.

### Operator identity / interrupted recovery

The operator resolves this host through the read-only authenticated `/legacy-node-upgrade-v130/identity` endpoint. Group listing DTOs contain no token; no Pool registration or config delivery is used for `--check`.

After STOP, recovery can read the Panel URL from the private snapshot even if Bootstrap has not recreated `/etc/relay-node/relay-node.env`. An explicit override is also supported:

```bash
sudo ./reality-node-v1.3.0-to-v1.4.4.sh --recover-work /var/lib/relay-panel/legacy-v130-upgrade/<attempt> --panel https://panel.example.com
```

The script queries durable operation state before restoring the host. Preserve the protected attempt directory until recovery completes.

## Profile and history compatibility

Standard and Lite are equally supported installation profiles. `OFFICIAL_V130_MANAGED` reports what binary/systemd/ownership evidence proves; it does not invent a fresh-versus-upgraded history. Both official source histories use the actual managed fallback to select profile.

The Panel persists `source_profile` in the existing operation JSON and supplies matching `PROFILE` and `LITE_MODE`. Older persisted operations lacking that field remain readable for recovery; they cannot receive a new bundle with an implicit Lite default. Complete/recover an active old operation with its matching old tool before changing versions.

Standard checks the private Xiaoya ownership marker, data path, live Docker labels/env/mount/restart/loopback binding and health. It reuses the container and live data in place. Snapshot includes the marker and container/config identity; rollback restores the marker and managed host files and verifies that container identity/config/mounts stayed unchanged. The runner never snapshots then overwrites a live SQLite fallback data directory or removes/restarts the working container. Lite checks its explicit marker, managed Nginx files, owned loopback listener and health. Profile remains unchanged through install, rollback and uninstall.

Normal Pool-native v1.4.3 → v1.4.4 updates use ordinary binary update with the same identity/credential; do not invoke this legacy replacement tool. Publication and Production Panel deployment require separate authority.
