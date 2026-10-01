# One-time official v1.3.0 single-node replacement

This tool replaces one official released v1.3.0 amd64 Lite/systemd Node on Debian 12 with the Panel's configured current candidate artifact. It is an explicit maintenance operation, not the ordinary updater and not a compatibility framework. Panel and Node version numbers are not changed by this feature.

## Preconditions

Upgrade Panel first. Keep the released old Nodes running and verify their public forwarding. Enable the existing `NODE_REUSE_RUNTIME_ENABLED` setting and configure the normal HTTPS public Panel URL and current amd64 Node assets. The administrator supplies one identity group ID and one Node ID, plus an HTTP forwarding probe for every effective Rule. Automatic routing must be disabled; current normal/Carrier policy must be idle. DNS records associated with the Node must be Panel-owned and readable. Unknown binary hashes, another active migration, conflicting lifecycle work, unsupported listener/probe types, and unresolved configuration conflicts stop before the old service is stopped.

The script checks the exact released binary SHA256, not only the version string:

`5c70aac9aab2e78b739d0468d6920b56fac427fb31f18790bc0809c616f965f9`

Other versions, unknown locally compiled v1.3.0 artifacts, customized systemd drop-ins and symlinked managed root paths require manual inspection. The small script intentionally supports only this known installation layout. Its preflight does not promise that a later network/package operation cannot fail; such failures enter rollback.

## Run one Node

Obtain `/api/v1/legacy-node-upgrade-v130/script.sh` over the Panel's normal HTTPS endpoint and inspect the downloaded script. Prepare a local JSON probe file, for example:

```json
[{"rule_id":1,"path":"/marker","expected_marker":"NODE-B-G1"}]
```

Include every effective Rule, including all reused Groups. Invoke on the chosen Node host:

```bash
bash legacy-node-upgrade-v130.sh \
  --panel-url https://YOUR-TEST-PANEL \
  --identity-group-id 1 --node-id ONE-NODE-ID \
  --probe-file /root/forwarding-probes.json
```

The script prompts for administrator credentials through the terminal. Automated authorized operation may provide an already authenticated admin token and probes through `--auth-fd`; tokens are never command-line arguments. It never SSHs to another Node or starts a next operation.

## State and commit boundary

The existing KV store holds a CAS-protected singleton and separate per-operation history. Short request leases serialize snapshot/finalize against mutations. The durable operation blocks its Node and business Groups while other Groups remain usable. Related DNS reconciliation is paused for the operation; ordinary Remove/Re-add/Delete behavior is unchanged.

The snapshot contains display name, memberships (including the old business Home), effective listener expectations, current Carrier/normal references, public IPv4, probes, and Provider values/record IDs. Rules and historical metrics/traffic are not copied.

The script downloads and checks all bundle hashes and candidate executability before stopping the old service. It captures the managed runtime/configuration/credential/certificate and Nginx files with private permissions, installs a fresh Pool-native identity, restores memberships, and waits for an authenticated live config connection, the current effective config revision/fingerprint, observed active listeners and real public forwarding.

Carrier references remain on the old identity until this verification succeeds. One DB transaction replaces current Carrier/normal references, removes old live memberships/Pool/status/revision, cancels pending credentials, revokes active old credentials, and marks the old identity retired. History stays on the old ID. Authentication and metadata registration reject retired identities. Same IPv4 means the DNS desired address set remains unchanged; final verification reads the Provider and requires the original values and record IDs. It performs no DNS shrink/expand or ordinary Node deletion.

`COMMITTED` is the point of no return. Once committed, identity rollback is forbidden. Provider read-back failure keeps the new runtime and requires attention; retrying finalize only performs verification. A lost callback response triggers a durable-status query. An unavailable status query never authorizes old-identity restoration.

## Failure and explicit recovery

Before commit, the runner restores the exact managed host snapshot and starts the old service. It requests a fresh recovery-report barrier, waits for an old-identity report after that barrier plus an actual online connection and public forwarding PASS, then cleans/revokes the staged identity. A stale pre-stop report cannot complete rollback. Old memberships and Carrier references were never removed. A failed host rollback keeps the operation active and retains a root-only recovery directory. Failure backups may contain old runtime credentials and must remain protected; successful completion removes the operation token, bundle/bootstrap private material and old backup.

After an interrupted invocation, explicitly run the same command with:

```bash
--recover-work /var/lib/relay-panel/legacy-v130-upgrade/FAILED-INVOCATION-DIRECTORY
```

Recovery first queries the persisted operation. COMMITTED/SUCCESS completes verification/cleanup without restoring the old identity. Confirmed precommit state restores the snapshot and cleans the staged identity. If Panel is unavailable, stop and retain the new runtime and recovery files until its durable state can be checked. A start-response loss can be recovered by an administrator through `/admin/legacy-node-upgrade-v130/current`; it does not start another migration.

After one SUCCESS, inspect that Node, its rules and DNS manually. Any second Node requires a new explicit invocation. Do not downgrade an upgraded Panel onto a DB containing Multi-A data or a pending routing/DNS transaction; this tool supplies no downgrade converter.

## Verification

Run `python3 scripts/test_legacy_node_upgrade.py`, migration repository tests on SQLite and a real `TEST_PG_URL`, workspace tests, fmt, clippy, repository parity and frontend gates. Formal Independent Review must pass the precise candidate HEAD before destructive TEST migration. Real acceptance additionally needs official released Panel+A+B, continuous independent public probes during Panel-only upgrade, B migration and canary checkpoint, then a separate A operation. Automated fault simulations are not physical runtime evidence.
