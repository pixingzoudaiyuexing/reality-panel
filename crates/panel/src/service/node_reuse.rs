//! Node Reuse V1 Slice 1 query helpers.
//!
//! This module is intentionally inert: it exposes deterministic repository-backed
//! resolution only and is not called by config, traffic, certificate, routing,
//! lifecycle, WebSocket, or management API paths in Slice 1.

use crate::db::error::DbError;
use crate::db::repo::{ConcreteNodeIdentity, Repository};
use crate::node_identity::{ReuseEligibleNodeId, ReuseEligibleNodeIdError};

#[allow(
    dead_code,
    reason = "Node Reuse V1 Slice 1 inert foundation; reserved for a later reviewed activation slice"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeReuseIdentityError {
    SelfReuse,
    InvalidNodeId(ReuseEligibleNodeIdError),
}

/// Pure validation suitable for a future management/API activation layer. Group
/// existence/type and concrete-node existence cannot be proven by this helper.
#[allow(
    dead_code,
    reason = "Node Reuse V1 Slice 1 inert foundation; reserved for a later reviewed activation slice"
)]
pub fn validate_binding_identity(
    reusing_group_id: i64,
    home_group_id: i64,
    node_id: &str,
) -> Result<(), NodeReuseIdentityError> {
    if reusing_group_id == home_group_id {
        return Err(NodeReuseIdentityError::SelfReuse);
    }
    ReuseEligibleNodeId::parse(node_id).map_err(NodeReuseIdentityError::InvalidNodeId)?;
    Ok(())
}

/// Home Group first, followed by explicit reusing/source Groups in stable
/// ascending order. Stored bindings are unique, but sorting/deduping here keeps
/// the resolver contract deterministic even if a future repository changes its
/// physical query plan.
#[allow(
    dead_code,
    reason = "Node Reuse V1 Slice 1 inert foundation; reserved for a later reviewed activation slice"
)]
pub async fn effective_source_groups(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<Vec<i64>, DbError> {
    let mut reusing = db
        .list_reusing_group_ids_for_node(home_group_id, node_id)
        .await?;
    reusing.retain(|group_id| *group_id != home_group_id);
    reusing.sort_unstable();
    reusing.dedup();

    let mut groups = Vec::with_capacity(reusing.len() + 1);
    groups.push(home_group_id);
    groups.extend(reusing);
    Ok(groups)
}

/// Stable reverse resolver for the concrete nodes explicitly authorized for one
/// reusing/source Group. Each item retains its Home Group namespace.
#[allow(
    dead_code,
    reason = "Node Reuse V1 Slice 1 inert foundation; reserved for a later reviewed activation slice"
)]
pub async fn reused_concrete_nodes_for_group(
    db: &dyn Repository,
    reusing_group_id: i64,
) -> Result<Vec<ConcreteNodeIdentity>, DbError> {
    let mut nodes = db
        .list_reused_concrete_nodes_for_group(reusing_group_id)
        .await?;
    nodes.sort();
    nodes.dedup();
    Ok(nodes)
}
