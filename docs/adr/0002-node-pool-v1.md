# ADR 0002 - Node Pool V1

Status: **IMPLEMENTATION IN REVIEW / NOT RELEASED / NOT DEPLOYED**

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

This ADR describes Node Pool V1 source integrated on `main` at `95f230bf73e730b92b9023f01e5fad1c2e7d9763` and a separate, unreviewed RT-001 fix. The Owner reports that stable `v1.1.26` is deployed to production; that deployment has not been independently verified in this task. Node Pool V1 and RT-001 have not been released, deployed, or exercised against production.
