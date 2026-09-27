# ADR 0002 - Node Pool V1

Status: **IMPLEMENTATION IN REVIEW / NOT RELEASED / NOT DEPLOYED**

## Decision

Administrators manage concrete Nodes in a Node Pool and add one existing Node at a time to an inbound business Group. Deployment is a separate entry. The Pool stores a human-readable display name for the concrete identity; IP addresses remain live status fields. The Group list projects native membership and existing Node Reuse Bindings.

Node Pool V1 retains the reviewed Node Reuse runtime. A concrete identity is still `(identity_group_id, node_id)` and additional business memberships are still `node_reuse_bindings`. Effective configuration, prospective conflict checks, guarded creation, revision authority, traffic attribution, and LKG protection remain on the existing paths. Pool metadata grants no runtime authority.

## Compatibility

Existing Nodes retain their current identity Group and their existing Bindings. Schema installation and idempotent Pool backfill only add metadata: neither operation delivers config, advances a revision, rotates a credential, mutates a Binding, nor broadcasts `config_changed`. Group-only status rows without a valid concrete Node ID do not become exact Pool identities.

Future deployments receive an internal, hidden, inbound-compatible Pool identity Group. It carries no ForwardRules and is excluded from business Group lists, regular-user authorization, rule selection, normal Group mutations, plan assignments, and billing. New SSH and Manual Bootstrap Nodes obtain a permanent exact credential before successful deployment. The temporary Pool Group Token used during bootstrap is removed from the final Node environment.

An existing legacy Group-Token Node is not exact-authorized merely because it reports a Node ID. Its first cross-group assignment requires a short-lived administrator-issued Claim bound to its persistent Node ID and current identity Group. The operator runs one migration command on that Node. The Claim protocol creates and activates the existing permanent credential format; the Node persists it before control-plane authentication changes. The business Binding cannot be created before active credential verification and the existing guarded Preflight/Create checks.

Running `v1.1.26` Node binaries have no authentication reload entry point. They must first be upgraded to a version reporting the reload capability. After that upgrade, the migration command does not restart forwarding listeners or delete LKG. A failed credential verification retains the previous control authentication and forwarding state. Server-proven synchronization, not Binding persistence, determines whether the new business membership is applied.

## Operational Boundary

This ADR describes unreleased source work. The Owner reports that stable `v1.1.26` is deployed to production; that deployment has not been independently verified in this implementation task. Node Pool V1 has not been merged, released, deployed, or exercised against production.
