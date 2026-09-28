# ADR 0002 - Node Pool V1

Status: **NODE POOL V1 RELEASED IN v1.3.0 / V2 CONTINUATION IN PROGRESS / PRODUCTION NOT INSPECTED**

## Decision

Administrators manage concrete Nodes in a Node Pool and add one existing Node at a time to an inbound business Group. Deployment is a separate entry. The Pool stores a human-readable display name for the concrete identity; IP addresses remain live status fields. The Group list projects native membership and existing Node Reuse Bindings.

Node Pool V1 retains the reviewed Node Reuse runtime. A concrete identity is still `(identity_group_id, node_id)` and additional business memberships are still `node_reuse_bindings`. Effective configuration, prospective conflict checks, guarded creation, revision authority, traffic attribution, and LKG protection remain on the existing paths. Pool metadata grants no runtime authority.

## Compatibility

Existing Nodes retain their current identity Group and their existing Bindings. Schema installation and idempotent Pool backfill only add metadata: neither operation delivers config, advances a revision, rotates a credential, mutates a Binding, nor broadcasts `config_changed`. Group-only status rows without a valid concrete Node ID do not become exact Pool identities.

Future deployments receive an internal, hidden, inbound-compatible Pool identity Group. It carries no ForwardRules and is excluded from business Group lists, regular-user authorization, rule selection, normal Group mutations, plan assignments, and billing. New SSH and Manual Bootstrap Nodes obtain a permanent exact credential before successful deployment. Their bootstrap path persists the credential without invoking the legacy-migration completion endpoint. The temporary Pool Group Token used during bootstrap is removed from the final Node environment.

An existing legacy Group-Token Node is not exact-authorized merely because it reports a Node ID. Its first cross-group assignment requires a short-lived administrator-issued Claim bound to its persistent Node ID and current identity Group. The operator runs one migration command on that Node. The Claim protocol creates and activates the existing permanent credential format; the Node persists it before control-plane authentication changes. The business Binding cannot be created before active credential verification and the existing guarded Preflight/Create checks.

Node Pool migration Claims carry an internal purpose marker. An ACTIVE server Credential alone does not finish migration: after the Node durably writes its credential state and runtime auth descriptor, its script proves possession of that exact Credential to an idempotent completion endpoint. The Panel records the matching Claim and Credential ID as migration-complete metadata. Prospective Preflight and guarded Create both require this completion for a Node with a Pool migration Claim. An activation or local-write failure leaves the Binding unchanged; the administrator can retrieve the same Claim command in Add Node and retry with the existing local Credential material. An ACK lost after completion is safe to retry. Online verified status separately confirms runtime use; later offline status does not undo durable migration readiness.

Previously established concrete Credentials retain eligibility when persisted exact verified status or a valid concrete config revision proves the prior runtime relationship. Existing Bindings remain intact but are not proof for a newly activated Credential. A completed legacy Claim with no such proof, including one from an earlier unreleased Node Pool attempt, remains recoverable with its original local Credential material. Successfully provisioned system-Pool Nodes use their existing exact Credential and do not require a legacy migration-complete record. This compatibility rule adds no completion row during upgrade and does not mutate config authority.

Running `v1.1.26` Node binaries have no authentication reload entry point. They must first be upgraded to a version reporting the reload capability. After that upgrade, the migration command does not restart forwarding listeners or delete LKG. A failed credential verification retains the previous control authentication and forwarding state. Server-proven synchronization, not Binding persistence, determines whether the new business membership is applied.

RT-001 restart safety: isolated Linux acceptance found that a migrated Node could restore combined LKG, then briefly apply newer Home-only config from its legacy environment Token before the asynchronous auth watcher selected its durable Credential. Startup now resolves the durable runtime auth descriptor after LKG restoration but before any HTTP/WS config transport starts. A present but invalid descriptor blocks control-plane startup and retries while forwarding remains on LKG; it never authorizes fallback to Group Token while present. The Panel also retires legacy config delivery for the exact Node once migration completion is recorded, including HTTP, WS handshake, and shared WS snapshot construction. Other unmigrated Nodes using the same Group Token remain unaffected. A missing descriptor after completion is still protected by the Panel's exact-node guard when the Node reports its persistent ID; lost or forged IDs cannot grant exact-node authority.

## Operational Boundary

Upgrade from `v1.1.26` to published `v1.3.0` applies additive SQLite Migration 58 or PostgreSQL revision 42 and performs idempotent Node Pool metadata backfill. Existing concrete identities and Bindings remain in place; installing the Panel alone does not deliver config, advance Node revisions, or restart Nodes. An existing Group-Token Node remains Home-only until it is upgraded to a Node version with runtime auth reload support and completes the exact-node credential migration. New Nodes use the hidden Pool anchor and receive their Permanent Credential during SSH or Manual Bootstrap.

This ADR describes Node Pool V1 source integrated on `main` at `95f230bf73e730b92b9023f01e5fad1c2e7d9763`, RT-001 fix `fe8068f55578b6cacb040d4ac72ceaaf271c8321`, and the published `v1.3.0` release. The Owner previously reported `v1.1.26` production deployment; current production version was not inspected. V2 continuation is unreleased and undeployed; no production access occurred during its implementation.

## Node Management V2 continuation

Group Token is historical compatibility only. New provisioning must create an
exact Permanent Credential before success and must not create a new Legacy
identity. Historical migration uses an administrator-authorized TOFU bootstrap
bound to exactly one live Lifecycle connection for the exact concrete identity.
The random bootstrap material is sent only to that connection and is persisted
privately by the Node before acknowledgement. A duplicate or replaced
connection invalidates the attempt; the system never resends the secret to a
new connection. After the durable ACK, the existing Claim/Credential machinery
is authorized over the same channel. Lost authorization frames resume from
durable state without resending the secret.

For V2 Carrier routing, one provider line may target multiple concrete Nodes. New targets use a separately encoded exact-node DNS key and independently owned provider record ID; old single-node keys remain compatible. The default-line owner and rule attribution do not change. Unknown external records fail closed. DNS membership follows traffic-serving evidence with failure/recovery hysteresis, and control-channel loss alone does not remove an A record. This remains implementation work, not a released Node Pool V1 behavior.

This trust boundary proves continuity of the selected live control connection,
not the historical physical host. Once the exact Permanent Credential is
verified and migration completion is recorded, Legacy config/control authority
is permanently retired for that Node. Restarts and future upgrades never fall
back to Group Token; sibling historical Nodes sharing the token are unaffected.
