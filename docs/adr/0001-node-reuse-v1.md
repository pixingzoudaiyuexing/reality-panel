# ADR 0001 — Node Reuse V1

Status: **APPROVED BOUNDARY / IMPLEMENTED / RELEASED IN v1.1.26 / OWNER-REPORTED DEPLOYED**

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

- Effective configuration generation merges active rules from the Home Group and only Groups that explicitly reuse the authenticated concrete node. Legacy Group Token Nodes remain Home-only.
- The merge must preserve the existing LKG and monotonic config-revision safety model.
- Node-specific behavior must remain keyed to the concrete node identity.
- Existing ForwardRule rows must not be copied merely to achieve reuse.
- Existing `ForwardRule.device_group_in` ownership must not be rewritten to simulate reuse.
- Lifecycle/auth/status/uninstall behavior must continue to resolve through the Home Group.
- Any implementation that requires changing these frozen product boundaries must stop and return to the Primary for a new decision.

## Implementation status

The `v1.1.25` base includes concrete-node credential verification, exact-node management APIs, guarded EffectiveConfig merge, and Node-side LKG/failure isolation. Product completion was integrated on `main` at `555558f17218540211c59b9c08bd767d68e294a9` after independent Gemini review passed and Primary accepted it, then published in `v1.1.26` from `5e249ed5b665065d917ce3812075b293414b1ac9`. Reuse is available by default for verified concrete Nodes, with read-only prospective Preflight, independently guarded Create, and conservative exact-snapshot synchronization status in Node detail. A Binding save is not proof of Node application; offline removal cannot immediately stop remote traffic. The Owner reports `v1.1.26` production deployment; this Node Pool implementation task has not independently verified it.
