from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


def insert_after(path: str, marker: str, block: str) -> None:
    p = Path(path)
    text = p.read_text()
    if block.splitlines()[0] in text:
        raise SystemExit(f"{path}: release entry already present")
    if marker not in text:
        raise SystemExit(f"{path}: insertion marker missing")
    p.write_text(text.replace(marker, marker + block, 1))


node_ops = "crates/panel/src/api/node_ops.rs"

# A correlated authenticated boot confirmation is emitted only by the restarted
# process from the persisted lifecycle marker. Do not require observing the old
# websocket disconnect as a second hard gate: connection replacement can make
# that ordering/observation racy even though the new process is already online.
replace_once(
    node_ops,
    '''                    if event.action == NodeLifecycleAction::Upgrade
                        && event.node_version.as_deref()
                            != entry.operation.target_version.as_deref()
                    {
                        if entry.saw_disconnect {
                            entry.operation.status = OperationStatus::Failed;
                            entry.operation.message = format!(
                                "relay-node restarted with version {}, expected {}",
                                event.node_version.as_deref().unwrap_or("unknown"),
                                entry
                                    .operation
                                    .target_version
                                    .as_deref()
                                    .unwrap_or("unknown")
                            );
                            entry.operation.updated_at = now();
                            return LifecycleEventOutcome {
                                operation: Some(entry.operation.clone()),
                                boot_ack: Some(lifecycle_ack(&event)),
                            };
                        }
                        return LifecycleEventOutcome::default();
                    }
''',
    '''                    if event.action == NodeLifecycleAction::Upgrade
                        && event.node_version.as_deref()
                            != entry.operation.target_version.as_deref()
                    {
                        entry.operation.status = OperationStatus::Failed;
                        entry.operation.message = format!(
                            "relay-node restarted with version {}, expected {}",
                            event.node_version.as_deref().unwrap_or("unknown"),
                            entry
                                .operation
                                .target_version
                                .as_deref()
                                .unwrap_or("unknown")
                        );
                        entry.operation.updated_at = now();
                        return LifecycleEventOutcome {
                            operation: Some(entry.operation.clone()),
                            boot_ack: Some(lifecycle_ack(&event)),
                        };
                    }
''',
)

replace_once(
    node_ops,
    '''fn complete_if_ready(entry: &mut RegistryEntry) -> bool {
    if !entry.saw_disconnect || entry.matching_boot_confirmation.is_none() {
        return false;
    }
''',
    '''fn complete_if_ready(entry: &mut RegistryEntry) -> bool {
    if entry.matching_boot_confirmation.is_none() {
        return false;
    }
''',
)

# Update the order-independence regression: confirmation-first is now decisive.
replace_once(
    node_ops,
    '''        assert_eq!(
            outcome.operation.unwrap().status,
            OperationStatus::Verifying,
            "confirmation alone must not complete an upgrade"
        );
        assert_eq!(
            confirmation_first.disconnected(1, "node-a")[0].status,
            OperationStatus::Success
        );
''',
    '''        assert_eq!(
            outcome.operation.unwrap().status,
            OperationStatus::Success,
            "exact authenticated confirmation is decisive even if disconnect was not observed"
        );
        assert!(confirmation_first.disconnected(1, "node-a").is_empty());
''',
)

# Wrong target version is now decisive failure even if the old disconnect was
# not observed. Remove the old expectation that it is ignored until disconnect.
replace_once(
    node_ops,
    '''        let mut wrong_version = matching_upgrade_boot(&operation);
        wrong_version.node_version = Some("9.9.9".into());
        let outcome = registry.event_from_authenticated_node(1, Some("node-a"), wrong_version);
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_none());

''',
    '',
)

# Matching confirmation now completes immediately; duplicates remain ACKed and
# cannot reopen/change the terminal result.
replace_once(
    node_ops,
    '''        let first = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        let duplicate = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(first.boot_ack.is_some());
        assert!(duplicate.boot_ack.is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Verifying
        );
        registry.disconnected(1, "node-a");
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );
''',
    '''        let first = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert_eq!(
            first.operation.as_ref().unwrap().status,
            OperationStatus::Success
        );
        assert!(first.boot_ack.is_some());
        let duplicate = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(duplicate.operation.is_none());
        assert!(duplicate.boot_ack.is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );
        assert!(registry.disconnected(1, "node-a").is_empty());
''',
)

insert_after(
    node_ops,
    '''    #[test]
    fn upgrade_reconnect_requires_exact_target_version() {
''',
    '''        // placeholder removed below
''',
)
# The helper above inserts after the function marker, which is not what we want
# for Rust syntax. Restore that location with a single exact replacement into a
# standalone test immediately before the existing test.
replace_once(
    node_ops,
    '''    #[test]
    fn upgrade_reconnect_requires_exact_target_version() {
        // placeholder removed below
''',
    '''    #[test]
    fn restart_exact_boot_confirmation_succeeds_without_observed_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Restart);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        let outcome = registry.event_from_authenticated_node(
            1,
            Some("a"),
            lifecycle_event(&operation, NodeLifecycleEventStatus::Completed),
        );
        assert_eq!(
            outcome.operation.unwrap().status,
            OperationStatus::Success
        );
        assert!(outcome.boot_ack.is_some());
        assert!(registry.disconnected(1, "a").is_empty());
    }

    #[test]
    fn upgrade_reconnect_requires_exact_target_version() {
''',
)

replace_once(
    node_ops,
    '''    #[test]
    fn early_upgrade_confirmation_rejects_wrong_correlation_and_is_idempotent() {
''',
    '''    #[test]
    fn upgrade_boot_confirmation_wrong_version_fails_without_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = upgrade_operation(&registry);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        let mut wrong_version = matching_upgrade_boot(&operation);
        wrong_version.node_version = Some("9.9.9".into());
        let outcome =
            registry.event_from_authenticated_node(1, Some("node-a"), wrong_version);
        assert_eq!(
            outcome.operation.unwrap().status,
            OperationStatus::Failed
        );
        assert!(outcome.boot_ack.is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Failed
        );
    }

    #[test]
    fn early_upgrade_confirmation_rejects_wrong_correlation_and_is_idempotent() {
''',
)

# Unified release version metadata.
replace_once("crates/panel/Cargo.toml", 'version = "1.1.2"', 'version = "1.1.3"')
replace_once("crates/node/Cargo.toml", 'version = "1.1.2"', 'version = "1.1.3"')
replace_once(
    "Cargo.lock",
    'name = "relay-node"\nversion = "1.1.2"',
    'name = "relay-node"\nversion = "1.1.3"',
)
replace_once(
    "Cargo.lock",
    'name = "relay-panel"\nversion = "1.1.2"',
    'name = "relay-panel"\nversion = "1.1.3"',
)
replace_once("scripts/relay-node-install.sh", 'SCRIPT_VERSION="1.1.2"', 'SCRIPT_VERSION="1.1.3"')
replace_once(
    "scripts/release-version-contract.test.sh",
    'TAG="${1:-v1.1.2}"',
    'TAG="${1:-v1.1.3}"',
)
replace_once(
    "docs/VERSIONS.md",
    "The current stable release is `v1.1.2`.",
    "The current stable release is `v1.1.3`.",
)
replace_once(
    "docs/VERSIONS.md",
    "bash scripts/release-check.sh 1.1.2",
    "bash scripts/release-check.sh 1.1.3",
)
replace_once(
    "README.md",
    "**当前稳定版：`v1.1.2`**",
    "**当前稳定版：`v1.1.3`**",
)

panel_entry = '''## [1.1.3] - 2026-09-06

生产热修复：修复 relay-node 已升级并重新认证上线后，Panel 仍可能因未观察到旧 WebSocket disconnect 而长期停留“等待上线”的生命周期竞态。

### 修复

- Restart / Upgrade 收到经过认证且 operation / group / node / action 精确关联的 boot confirmation 后，不再把旧连接 disconnect 作为成功硬门槛。
- Upgrade 仍严格要求 boot confirmation 的 node version 与 target version 完全一致；版本不匹配会立即失败并 ACK，不再等待 disconnect。
- 保留重复 confirmation 幂等 ACK、Timeout 不重开、普通 reconnect 不可单独完成操作等既有安全边界。

### 兼容性

- 无数据库 migration。
- Config Protocol 保持 `10`。
- Lifecycle Protocol 保持 `1`。
- v1.1.2 可直接升级到 v1.1.3。

'''
insert_after("CHANGELOG.md", "---\n\n", panel_entry)

node_entry = '''## [1.1.3] - 2026-09-06

统一版本热修复。Relay Node 运行时逻辑与协议不变；版本随 Panel 统一提升至 `1.1.3`。

### 兼容性

- Config Protocol 保持 `10`，Lifecycle Protocol 保持 `1`。
- v1.1.2 relay-node 可直接升级到 v1.1.3。

'''
insert_after("CHANGELOG-NODE.md", "---\n\n", node_entry)
