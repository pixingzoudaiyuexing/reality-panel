use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::{NodePoolRecord, Repository};
use crate::node_identity::ReuseEligibleNodeId;
use crate::service::{node_pool, relay_failover, relay_preference, relay_schedule};
use serde::Serialize;

pub static RETIREMENT_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn references_retired(
    db: &dyn Repository,
    references: Vec<(i64, String)>,
) -> Result<bool, DbError> {
    let retired: Vec<_> = db
        .list_node_pool_records()
        .await?
        .into_iter()
        .filter(|record| record.retirement_state != "ACTIVE")
        .collect();
    for (business_group, node_id) in references {
        let reused = db
            .list_reused_concrete_nodes_for_group(business_group)
            .await?;
        if retired.iter().any(|record| {
            record.node_id == node_id
                && (record.identity_group_id == business_group
                    || reused.iter().any(|identity| {
                        identity.home_group_id == record.identity_group_id
                            && identity.node_id == node_id
                    }))
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Serialize)]
pub struct RetirementPreview {
    pub identity_group_id: i64,
    pub node_id: String,
    pub display_name: String,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub last_seen: Option<String>,
    pub online: bool,
    pub control_connected: bool,
    pub credential_active: bool,
    pub memberships: Vec<node_pool::PoolMembership>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub retirement_version: i64,
}

fn invalid_state(error: impl std::fmt::Debug) -> DbError {
    DbError::Other(sqlx::Error::Protocol(format!("{error:?}")))
}

fn references_node(
    policy: &relay_preference::CarrierPolicy,
    identity_group_id: i64,
    node_id: &str,
    belongs_to_group: bool,
) -> bool {
    belongs_to_group && policy.default_node_id.as_deref() == Some(node_id)
        || policy.bindings.iter().any(|binding| {
            binding.node_id.as_deref() == Some(node_id)
                && binding
                    .identity_group_id
                    .map_or(belongs_to_group, |identity| identity == identity_group_id)
        })
}

pub async fn preview(
    state: &AppState,
    group_id: i64,
    node_id: &str,
) -> Result<Option<RetirementPreview>, DbError> {
    ReuseEligibleNodeId::parse(node_id).map_err(invalid_state)?;
    let nodes = node_pool::list_nodes(state.db.as_ref()).await?;
    let Some(node) = nodes
        .iter()
        .find(|node| node.identity_group_id == group_id && node.node_id == node_id)
    else {
        return Ok(None);
    };
    let record = state
        .db
        .find_node_pool_record(group_id, node_id)
        .await?
        .ok_or(DbError::NotFound)?;
    let control_connected = state
        .node_connections
        .online_node_ids(group_id)
        .await
        .contains(node_id);
    let mut blockers = Vec::new();
    let affected_groups: std::collections::HashSet<i64> = node
        .memberships
        .iter()
        .map(|member| member.group_id)
        .chain(std::iter::once(group_id))
        .collect();
    if crate::service::node_convergence::load(state.db.as_ref(), group_id, node_id)
        .await?
        .is_some_and(|operation| {
            !matches!(
                operation.phase,
                crate::service::node_convergence::Phase::Complete
                    | crate::service::node_convergence::Phase::Failed
            )
        })
    {
        blockers.push("IDENTITY_CONVERGENCE".into());
    }
    for membership in &node.memberships {
        let business_group = membership.group_id;
        if !membership.native {
            blockers.push(format!("REUSE_MEMBERSHIP:{business_group}"));
        }
    }
    for (key, raw) in state
        .db
        .scan_prefix(relay_preference::RELAY_PREFERENCE_KEY_PREFIX)
        .await?
    {
        let business_group = key
            .strip_prefix(relay_preference::RELAY_PREFERENCE_KEY_PREFIX)
            .and_then(|id| id.parse::<i64>().ok())
            .ok_or_else(|| invalid_state("invalid relay preference key"))?;
        let preference: relay_preference::RelayPreferenceState =
            serde_json::from_str(&raw).map_err(invalid_state)?;
        let belongs_to_group = affected_groups.contains(&business_group);
        if belongs_to_group
            && (preference.normal_default_node_id.as_deref() == Some(node_id)
                || preference.preferred_node_id.as_deref() == Some(node_id)
                || preference.pending_node_id.as_deref() == Some(node_id))
        {
            blockers.push(format!("ROUTING_REFERENCE:{business_group}"));
        }
        if references_node(
            &preference.carrier_policy,
            group_id,
            node_id,
            belongs_to_group,
        ) || preference
            .pending_carrier_policy
            .as_ref()
            .is_some_and(|policy| references_node(policy, group_id, node_id, belongs_to_group))
        {
            blockers.push(format!("CARRIER_REFERENCE:{business_group}"));
        }
        if belongs_to_group
            && matches!(
                preference.state,
                relay_preference::RelayPreferencePhase::Switching
                    | relay_preference::RelayPreferencePhase::RollingBack
            )
        {
            blockers.push(format!("ROUTING_TRANSACTION:{business_group}"));
        }
    }
    for (key, raw) in state
        .db
        .scan_prefix(relay_failover::RELAY_FAILOVER_KEY_PREFIX)
        .await?
    {
        let business_group = key
            .strip_prefix(relay_failover::RELAY_FAILOVER_KEY_PREFIX)
            .and_then(|id| id.parse::<i64>().ok())
            .ok_or_else(|| invalid_state("invalid failover key"))?;
        let failover: relay_failover::RelayFailoverPolicy =
            serde_json::from_str(&raw).map_err(invalid_state)?;
        if failover.enabled
            && node
                .memberships
                .iter()
                .any(|member| member.group_id == business_group)
        {
            blockers.push(format!("FAILOVER_POLICY:{business_group}"));
        }
        if affected_groups.contains(&business_group)
            && (failover.excluded_failed_node_ids.contains(node_id)
                || failover.last_from_node_id.as_deref() == Some(node_id)
                || failover.last_to_node_id.as_deref() == Some(node_id))
        {
            blockers.push(format!("FAILOVER_REFERENCE:{business_group}"));
        }
    }
    let schedules: Vec<relay_schedule::RelaySchedule> = state
        .db
        .get(relay_schedule::RELAY_SWITCH_SCHEDULES_KEY)
        .await?
        .map(|raw| serde_json::from_str(&raw).map_err(invalid_state))
        .transpose()?
        .unwrap_or_default();
    for schedule in schedules {
        if schedule.target_node_id == node_id
            && affected_groups.contains(&schedule.group_id)
            && (schedule.enabled || schedule.last_run_at.is_none())
        {
            blockers.push(format!("SCHEDULE_REFERENCE:{}", schedule.id));
        }
    }
    for (_, raw) in state.db.scan_prefix("node_batch_upgrade:").await? {
        let batch: crate::api::node_batch_upgrade::BatchUpgradeOperation =
            serde_json::from_str(&raw).map_err(invalid_state)?;
        if !batch.status.terminal()
            && batch
                .items
                .iter()
                .any(|item| item.group_id == group_id && item.node_id == node_id)
        {
            blockers.push(format!("BATCH_UPGRADE:{}", batch.id));
        }
    }
    let exact_id = ReuseEligibleNodeId::parse(node_id).map_err(invalid_state)?;
    for claim in state
        .db
        .list_node_credential_claims_for_identity(group_id, &exact_id)
        .await?
    {
        if !matches!(claim.state.as_str(), "COMPLETED" | "CANCELLED" | "EXPIRED") {
            blockers.push(format!("CREDENTIAL_CLAIM:{}", claim.claim_id));
        }
        if state
            .db
            .find_node_credential_delivery(&claim.claim_id)
            .await?
            .is_some_and(|delivery| delivery.state == "PREPARED")
        {
            blockers.push(format!("CREDENTIAL_DELIVERY:{}", claim.claim_id));
        }
    }
    if state.node_operations.has_active_for_node(group_id, node_id)
        || state
            .deployments
            .has_active_for_node(group_id, node_id)
            .await
        || crate::api::node_ops::has_active_durable_uninstall(state, group_id, node_id)
            .await
            .map_err(invalid_state)?
    {
        blockers.push("LIFECYCLE_OPERATION".into());
    }
    let mut warnings = Vec::new();
    if node.online || control_connected {
        warnings.push("NODE_CURRENTLY_ONLINE".into());
    }
    if !node.credential_active {
        warnings.push("LEGACY_TOKEN_CANNOT_REVOKE_PHYSICAL_NODE".into());
    }
    blockers.sort();
    blockers.dedup();
    Ok(Some(RetirementPreview {
        identity_group_id: group_id,
        node_id: node_id.into(),
        display_name: node.display_name.clone(),
        public_ipv4: node.public_ipv4.clone(),
        public_ipv6: node.public_ipv6.clone(),
        last_seen: node.last_seen.clone(),
        online: node.online,
        control_connected,
        credential_active: node.credential_active,
        memberships: node.memberships.clone(),
        blockers,
        warnings,
        retirement_version: record.retirement_version,
    }))
}

pub async fn retired(db: &dyn Repository) -> Result<Vec<NodePoolRecord>, DbError> {
    Ok(db
        .list_node_pool_records()
        .await?
        .into_iter()
        .filter(|record| record.retirement_state == "RETIRED")
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::service::relay_preference::{CarrierLineBinding, CarrierLineMode, CarrierPolicy};

    #[tokio::test]
    async fn retired_id_in_another_identity_group_does_not_block_unrelated_reference() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,username,password,admin) VALUES(2,'test-admin','hash',1);
            INSERT INTO device_groups(id,name,group_type,token,uid) VALUES(10,'a','in','a',2),(11,'b','in','b',2);
            INSERT INTO node_pool_nodes(identity_group_id,node_id,retirement_state) VALUES(10,'SAME','RETIRED'),(11,'SAME','ACTIVE');")
            .execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        assert!(references_retired(&db, vec![(10, "SAME".into())])
            .await
            .unwrap());
        assert!(!references_retired(&db, vec![(11, "SAME".into())])
            .await
            .unwrap());
        let exact = CarrierPolicy {
            default_node_id: None,
            bindings: vec![CarrierLineBinding {
                line_id: "Dianxin".into(),
                mode: CarrierLineMode::Node,
                identity_group_id: Some(11),
                node_id: Some("SAME".into()),
            }],
        };
        assert!(!references_node(&exact, 10, "SAME", true));
        assert!(references_node(&exact, 11, "SAME", false));
    }
}
