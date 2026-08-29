//! Node control/lifecycle protocol capabilities.
//!
//! 这个协议故意与 CONFIG_PROTOCOL_VERSION 分离：配置结构发生破坏性变化时，
//! 旧 Node 可以停止接收新配置，但“一键升级”控制通道必须继续工作。只要认证
//! 有效、节点具备 lifecycle v1，就允许进入 upgrade-only 控制通道。

/// 生命周期控制协议版本。不要因为 ListenerConfig / NodeConfigResponse 变化而递增。
/// 只有 NodeLifecycleCommand / NodeLifecycleEvent 本身出现不可向后兼容的变化时才考虑升级；
/// 优先保持 v1 向后兼容，以保证已托管节点永远能够被 Panel 升级。
pub const LIFECYCLE_PROTOCOL_VERSION: u32 = 1;

pub fn lifecycle_protocol_versions_compatible(panel: u32, node: u32) -> bool {
    panel == node
}

/// 兼容尚未发送 X-Lifecycle-Protocol-Version 的已发布 Node。
///
/// v1.1.0-rc.2/rc.3 已经实现完整 node_lifecycle 命令，但当时没有独立 capability
/// header；这是 rc.4 升级死锁的桥接路径。除此之外复用历史明确能力门槛，绝不把
/// 仅仅“版本号较新”的未知旧构建猜成可升级，避免向不理解命令的 Node 下发操作。
pub fn legacy_node_supports_lifecycle(version: Option<&str>) -> bool {
    let Some(raw) = version else {
        return false;
    };
    let version = raw.trim().trim_start_matches('v');
    if version.is_empty() {
        return false;
    }

    if let Some(rc) = version
        .strip_prefix("1.1.0-rc.")
        .and_then(|value| value.parse::<u64>().ok())
    {
        return rc >= 2;
    }

    crate::protocol::node_supports_lifecycle(Some(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_protocol_is_independent_and_exact() {
        assert!(lifecycle_protocol_versions_compatible(1, 1));
        assert!(!lifecycle_protocol_versions_compatible(1, 2));
    }

    #[test]
    fn legacy_bridge_recognizes_only_shipped_upgrade_capable_nodes() {
        assert!(legacy_node_supports_lifecycle(Some("1.1.0-rc.2")));
        assert!(legacy_node_supports_lifecycle(Some("v1.1.0-rc.3")));
        assert!(legacy_node_supports_lifecycle(Some("1.0.0-rc.5")));
        assert!(legacy_node_supports_lifecycle(Some("1.2.3")));
        assert!(!legacy_node_supports_lifecycle(Some("1.1.0-rc.1")));
        assert!(!legacy_node_supports_lifecycle(Some("1.0.0-rc.4")));
        assert!(!legacy_node_supports_lifecycle(Some("1.0.0")));
        assert!(!legacy_node_supports_lifecycle(Some("invalid")));
        assert!(!legacy_node_supports_lifecycle(None));
    }
}
