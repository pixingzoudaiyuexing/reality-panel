from pathlib import Path

path = Path("crates/panel/src/api/ws.rs")
text = path.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match, got {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    '''        for conns in map.values_mut() {
            conns.retain(|_, e| {
                // Upgrade-only nodes intentionally keep their LKG and must not
                // even be told that a newer config exists.
                !e.config_compatible || e.tx.send(msg.to_string()).is_ok()
            });
        }
''',
    '''        for conns in map.values_mut() {
            conns.retain(|_, e| {
                // Upgrade-only nodes intentionally keep their LKG and must not
                // even be told that a newer config exists. Dead upgrade-only
                // senders are still pruned so the registry cannot accumulate.
                if !e.config_compatible {
                    return !e.tx.is_closed();
                }
                e.tx.send(msg.to_string()).is_ok()
            });
        }
''',
)

replace_once(
    '''        let mut sent = 0usize;
        conns.retain(|_, e| {
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    /// v0.4.14: send a message ONLY''',
    '''        let mut sent = 0usize;
        conns.retain(|_, e| {
            // 即使未来重新启用 group-wide 控制，也绝不能绕过 upgrade-only
            // 隔离边界。协议不兼容节点只允许收到 Upgrade。
            if !e.config_compatible {
                return !e.tx.is_closed();
            }
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    /// v0.4.14: send a message ONLY''',
)

replace_once(
    '''/// WebSocket endpoint for node control channel.
/// Node authenticates via Authorization: Bearer <NODE_TOKEN>.
''',
    '''/// 判断认证后的 Node 是否允许进入 WS 控制面。
///
/// 配置协议匹配时正常进入；配置协议不匹配时，只要有稳定 node_id 且具备
/// lifecycle upgrade 能力，就必须允许进入 upgrade-only 模式。这个门禁是
/// “未来配置协议升级永远不能封死一键升级”的核心不变量。
fn ws_connection_allowed(
    config_compatible: bool,
    has_node_id: bool,
    lifecycle_capable: bool,
) -> bool {
    config_compatible || (has_node_id && lifecycle_capable)
}

/// WebSocket endpoint for node control channel.
/// Node authenticates via Authorization: Bearer <NODE_TOKEN>.
''',
)

replace_once(
    '''    if !config_compatible && (node_id.is_none() || !lifecycle_capable) {
''',
    '''    if !ws_connection_allowed(config_compatible, node_id.is_some(), lifecycle_capable) {
''',
)

replace_once(
    '''        assert_eq!(conns.send_node(1, "old-node", "diagnose").await, 0);
        assert!(
            old_rx.try_recv().is_err(),
            "ordinary control must be blocked"
        );

        assert_eq!(conns.send_upgrade_node(1, "old-node", "upgrade").await, 1);
''',
    '''        assert_eq!(conns.send_node(1, "old-node", "diagnose").await, 0);
        assert!(
            old_rx.try_recv().is_err(),
            "ordinary control must be blocked"
        );

        // 防御性覆盖废弃的 group-wide 通道：它也不能绕过 upgrade-only。
        assert_eq!(conns.send_group(1, "group-control").await, 1);
        assert!(old_rx.try_recv().is_err(), "group control must be blocked");
        assert_eq!(current_rx.recv().await.as_deref(), Some("group-control"));

        assert_eq!(conns.send_upgrade_node(1, "old-node", "upgrade").await, 1);
''',
)

replace_once(
    '''    /// online_node_ids returns the node_ids with a live connection; older nodes
''',
    '''    #[test]
    fn config_mismatch_still_allows_known_upgrade_capable_node() {
        assert!(ws_connection_allowed(true, false, false));

        let rc3_lifecycle = legacy_node_supports_lifecycle(Some("1.1.0-rc.3"));
        assert!(rc3_lifecycle, "rc.3 is a shipped lifecycle-capable Node");
        assert!(
            ws_connection_allowed(false, true, rc3_lifecycle),
            "config mismatch must degrade to upgrade-only instead of HTTP 426"
        );

        assert!(!ws_connection_allowed(false, false, true));
        assert!(!ws_connection_allowed(false, true, false));
    }

    /// online_node_ids returns the node_ids with a live connection; older nodes
''',
)

path.write_text(text)
