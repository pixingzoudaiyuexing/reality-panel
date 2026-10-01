# Full uninstall and fresh-install acceptance

## Ownership boundary

`install.sh uninstall --yes --purge` and the installed `deploy.sh uninstall`
share the existing local Panel uninstall behavior. Normal uninstall preserves
`/etc/relay-panel` and `/var/lib/relay-panel`; purge removes both, the complete
`/opt/relay-panel` tree (including staging/certificate/legacy files), installed
scripts, update helper and Panel service. Symlinked roots/ancestors are rejected.
Stop/reload/account cleanup failures return failure rather than a success banner.
The installer records the system account UID/GID it created. Legacy ownership
requires a matching system account home/shell and actual Panel service; the
uninstaller persists that evidence before removing the service so retries work.
Unproven accounts and groups used by other accounts are preserved.

Shared packages, OS journal/history, external HTTPS ingress and external TLS
configuration are not Panel-owned and are retained. Local Panel uninstall never
contacts Nodes or mutates DNS. Uninstall Nodes while the Panel is still online.

## Node lifecycle uninstall

The existing authenticated lifecycle operation and durable finalizer remain the
uninstall path. Cleanup stops the Node, removes marker-tagged Nginx files, repairs
an interrupted stream include removal, validates/reloads Nginx while certificates
are still available for rollback, and then removes runtime/LKG/config/certificate
state. Exact managed files and directories are checked for symlink traversal.
The persistent finalizer/receipt and authentication material remain available
until cleanup is confirmed and the Panel acknowledges identity retirement.
Partial cleanup remains retryable; failure is not converted to success. A failed
finalizer systemd reload retains its executable/receipt and restores retry units.
The first callback acknowledges runtime cleanup with `host_cleanup_pending` and keeps
the Panel operation VERIFYING and its credential valid. The finalizer caches callback
authentication in memory, removes local credentials/units/binary/receipt, then sends
the final callback; only this callback retires Panel identity and reports SUCCESS.
A lost final callback is retried in process; if the host is already completely clean
and the Panel remains unreachable, it stays VERIFYING and requires Owner inspection
plus local Panel deletion. It never reports successful full cleanup prematurely.
Legacy finalizers that omit the field retain their previous completion semantics.
After the first acknowledgment, the actual credential Claim directory and empty parents,
finalizer units/binary/receipt and persistent timer stamp are removed.

BBR startup captures the original congestion/qdisc before changing them, once.
Uninstall restores each known value only if the current value still equals our
setting, preserving later operator changes. Legacy installations without a
baseline do not receive guessed values. Only exact product BBR persistence is
removed. Kernel modules and generic Docker/Nginx packages remain shared OS state.

OpenList requires its existing creation ownership marker and live image/mount
verification; reused container/data are preserved. Absent owned containers are
verified through Docker listing before data cleanup. Docker read/remove failures
retain retry information. Xiaoya uses its existing durable marker plus managed
label/environment/mount identity; unowned resources are never accessed/deleted.
The public compatibility Node installer labels newly created Nginx containers;
lifecycle cleanup requires that label and the exact product config mount.
An older unlabelled Docker Nginx container is preserved with an explicit failure
requiring an ownership check. This is not automatic Legacy migration.

## Panel installer capability boundary

Supported install hosts: Debian 12/13 amd64 and Ubuntu 22.04/24.04 amd64,
Linux/root, a running systemd manager, apt-get and usable dependencies/port/disk.
Shell fixture acceptance of an OS is separate from actual VM/physical runtime
acceptance. Release downloads remain HTTPS/checksum verified. The downloaded
deployer is called normally so the installer EXIT trap removes download staging.

## Create Rule DNS preflight

Administrators can click **Check domain** next to Create Rule SNI. The endpoint
uses existing DNSMgr normalization/zone resolution/default-line discovery and
exact existing binding ownership checks. It reads Provider/DB only, never adopts
bindings, creates a confirmation, schedules reconciliation or mutates records.
It distinguishes absent, Panel-compatible A, external A, CNAME, unmanaged zone,
unconfigured automation and Provider read failure. Changing SNI clears the old
result. External A/CNAME warnings never disable Rule submission; actual later
writes still require the existing ownership/confirmation flow. A failure is not
reported as absence. The advisory check inspects the default line only.

## Terminology audit

No user-facing Realm artifact remains. Current translated Node/Group UI already
uses Node Pool and Group membership. Home/Reusing/Native/Reused remain internal
identity/protocol/schema/history terms where technically meaningful. Migration
copy remains applicable to actual legacy Nodes; removing it would hide a real
operational boundary. Historical ADRs are retained; this task changes no Group
Delete semantics, Node identity, bindings or membership schema.

## Authorized TEST acceptance sequence

Before destructive acceptance, the exact candidate source must pass tests and
Formal Independent Review. Preserve artifacts/evidence off TEST hosts. Then:

1. Install authentic official v1.3.0 using its published installer/release assets;
   collect version, checksum/source, schema, counts, Group/Rule IDs, settings hash
   and DB integrity without exporting secrets into evidence.
2. Use release-shaped candidate assets and the existing deploy/update logic;
   run actual startup/migrations, verify Users/Groups/Rules/settings/DNSMgr
   preservation, public HTTPS/login/pages, fresh Node bootstrap and forwarding.
3. Via the Panel Node Uninstall operation retire both test Nodes; verify SSH/OS
   absence of units/processes/listeners/auth/LKG/managed Nginx/BBR/finalizer state,
   plus foreign resource preservation and `nginx -t`/reload.
4. Clean only this task's DNS/certificate automation records. Purge Panel through
   the product uninstaller. Verify product state absence separately from retained
   external ingress/shared packages/journal. Remove known engineering TEST
   build/backup files after transferring needed evidence off host.
5. Fresh-install the candidate without restoring DB/auth/install state. Configure
   TEST DNS afresh, Bootstrap A and B with new identities and preserve final
   `z1-e2e` A+B, g1–g4, Carrier default A / Liantong A+B / Dianxin A for Owner.
6. Real read-only preflight cases: absent/A/CNAME; Provider records identical
   before/after. Read failure can be proved by mock without damaging credentials.

This document specifies behavior/acceptance; it does not claim those later
runtime phases have already passed. No push/merge/tag/Release/Production action
is authorized by technical acceptance.
