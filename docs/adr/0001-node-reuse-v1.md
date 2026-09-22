# ADR 0001 — Node Reuse V1

Status: **APPROVED / PHASED IMPLEMENTATION**

## Context

Reality Panel currently treats a Relay Node as belonging to one inbound/Home Group for identity, authentication, lifecycle, status, and configuration ownership.

The approved Node Reuse V1 direction allows another Group to reuse one specific existing Node without changing that node's ownership.

## Decision

Each Node has exactly one **Home Group**.

Other Groups may reuse a **specific concrete Node**.

Example:

```text
Group 2
├── Node E
└── Node F

Group 1 reuses Node E.
```

Expected runtime intent:

```text
EffectiveConfig(Node E)
= active(Home Group 2)
+ active(reusing Group 1)
[+ active(other Groups that explicitly reuse Node E)]

EffectiveConfig(Node F)
= active(Home Group 2)
```

This is a **Runtime Effective Config Merge** for a concrete node.

It is not a change to ForwardRule ownership.

## Ownership

The Home Group continues to own:
- node lifecycle;
- token/authentication;
- persistent `node_id`;
- node status;
- WebSocket identity/control channel;
- uninstall ownership.

Reuse does not transfer or duplicate node ownership.

## Specific-node scope

Reuse must target one concrete node, not an entire group.

A Group reusing Node E does not implicitly reuse Node F simply because E and F share the same Home Group.

## Routing boundaries

Carrier remains group-level:
- `default_node_id`
- `line_id -> node_id` overrides

Node Reuse V1 must not introduce per-rule Carrier routing.

Failover remains group-level / same-group. Cross-group failover is not part of V1.

## Non-goals / rejected directions

Node Reuse V1 does not implement:
- full Node ↔ Group many-to-many ownership;
- Rule ↔ Node assignment;
- per-rule Carrier target model;
- whole-group reuse;
- share code / invite code / reuse token;
- a new Stable Node ID or hardware identity framework;
- cross-group Failover.

The existing relay-node persistent node ID remains the node identity mechanism.

## Technical consequences

- Effective configuration generation will eventually need to merge active rules from the Home Group and all Groups that explicitly reuse the concrete node.
- The merge must preserve the existing LKG and monotonic config-revision safety model.
- Node-specific behavior must remain keyed to the concrete node identity.
- Existing ForwardRule rows must not be copied merely to achieve reuse.
- Existing `ForwardRule.device_group_in` ownership must not be rewritten to simulate reuse.
- Lifecycle/auth/status/uninstall behavior must continue to resolve through the Home Group.
- Any implementation that requires changing these frozen product boundaries must stop and return to the Primary for a new decision.

## Implementation status

Slice 1 is merged as an inert foundation: explicit concrete-node reuse bindings, dual-backend Repository access, and pure resolver helpers. It does not activate runtime reuse.

S2-A1 adds another inert foundation: a strict Node-Reuse-only node-id type plus an algorithm-neutral concrete-node credential verifier registry. A credential row is not proof that a Node has been claimed, authenticated, or granted Reuse authority.

Credential issuance/claim/verification, management APIs, wire-protocol changes, EffectiveConfig merge, traffic/billing, certificate scope, routing, LKG/revocation behavior, and production activation remain deferred to separately authorized and reviewed tasks.
