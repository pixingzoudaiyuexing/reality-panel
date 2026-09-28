use crate::api::stats::{status_last_seen, NODE_ONLINE_WINDOW_SECS};
use crate::api::ws::{ControlSnapshot, NodeConnections};
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope, RuleRepository};
use crate::service::{node_pool, relay_preference};
use chrono::{DateTime, Utc};
use relay_shared::protocol::{ListenerError, ReconciliationStatus, ReconciliationStatusState};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeHealthState {
    Healthy,
    Degraded,
    Offline,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct NodeTelemetry {
    pub last_seen: Option<String>,
    pub age_seconds: Option<i64>,
    pub fresh: bool,
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub uptime: Option<f64>,
    pub process_uptime: Option<f64>,
    pub disk_total: Option<f64>,
    pub disk_used: Option<f64>,
    pub disk_usage_percent: Option<f64>,
    pub disk_mount: Option<String>,
    pub upload_bps: Option<f64>,
    pub download_bps: Option<f64>,
    pub boot_upload_bytes: Option<f64>,
    pub boot_download_bytes: Option<f64>,
    pub network_interface: Option<String>,
    pub connections: Option<i64>,
    pub tcp_connections: Option<i64>,
    pub udp_sessions: Option<i64>,
    pub public_ip: Option<String>,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub ipv4_country_code: Option<String>,
    pub ipv4_country_name: Option<String>,
    pub ipv6_country_code: Option<String>,
    pub ipv6_country_name: Option<String>,
    pub node_version: Option<String>,
    pub architecture: Option<String>,
    pub install_method: Option<String>,
    pub config_protocol_version: Option<u32>,
    pub verified_concrete_node: Option<bool>,
    pub auth_reload_supported: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct NodeRuntimeHealth {
    pub reconciliation: Option<ReconciliationStatus>,
    pub active_listener_rule_ids: Option<Vec<i64>>,
    pub listener_errors: Option<Vec<ListenerError>>,
}

#[derive(Debug, Serialize)]
pub struct NodeControlHealth {
    pub connected: bool,
    pub lifecycle_connected: bool,
    pub last_connected_at: Option<String>,
    pub last_disconnected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupReadiness {
    pub group_id: i64,
    pub group_name: String,
    pub ready: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeHealthSnapshot {
    pub identity_group_id: i64,
    pub identity_group_name: String,
    pub node_id: String,
    pub legacy_status: bool,
    pub display_name: String,
    pub as_of: String,
    pub state: NodeHealthState,
    pub telemetry: NodeTelemetry,
    pub control_connected: bool,
    pub control: NodeControlHealth,
    pub runtime: NodeRuntimeHealth,
    pub group_readiness: Vec<GroupReadiness>,
}

fn string_field(status: &Value, name: &str) -> Option<String> {
    status.get(name).and_then(Value::as_str).map(str::to_string)
}

fn number_field(status: &Value, name: &str) -> Option<f64> {
    status.get(name).and_then(Value::as_f64)
}

fn integer_field(status: &Value, name: &str) -> Option<i64> {
    status.get(name).and_then(Value::as_i64)
}

fn classify(
    has_report: bool,
    age_seconds: Option<i64>,
    control_connected: bool,
    converged: bool,
) -> NodeHealthState {
    if !has_report || age_seconds.is_none() {
        return NodeHealthState::Unknown;
    }
    let fresh = age_seconds.is_some_and(|age| age <= NODE_ONLINE_WINDOW_SECS);
    if !fresh && !control_connected {
        NodeHealthState::Offline
    } else if fresh && control_connected && converged {
        NodeHealthState::Healthy
    } else {
        NodeHealthState::Degraded
    }
}

pub async fn snapshots(
    db: &dyn Repository,
    connections: &NodeConnections,
) -> Result<Vec<NodeHealthSnapshot>, DbError> {
    let as_of = Utc::now();
    let status_rows = db.scan_prefix("node_status:").await?;
    let mut pool_nodes = node_pool::list_nodes_from_status_rows(db, &status_rows, as_of).await?;
    let system_group = db.node_pool_system_group_id().await?;
    for (key, raw) in &status_rows {
        let Some((group_id, None)) = crate::api::stats::parse_status_key(key) else {
            continue;
        };
        if system_group == Some(group_id) {
            continue;
        }
        let Some(group) = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?
        else {
            continue;
        };
        let status = serde_json::from_str::<Value>(raw).ok();
        let display_name = status
            .as_ref()
            .and_then(|status| {
                status
                    .get("public_ipv4")
                    .or_else(|| status.get("public_ip"))
            })
            .and_then(Value::as_str)
            .unwrap_or(&group.name)
            .to_string();
        pool_nodes.push(node_pool::PoolNode {
            identity_group_id: group_id,
            node_id: String::new(),
            display_name,
            public_ipv4: None,
            public_ipv6: None,
            online: false,
            node_version: None,
            last_seen: None,
            credential_ready: false,
            credential_active: false,
            safe_to_add: false,
            migration_incomplete: false,
            recovery_available: false,
            runtime_verified: false,
            migration_required: false,
            migration_pending: false,
            migration_claim_id: None,
            auth_reload_supported: false,
            automatic_migration_supported: false,
            memberships: vec![node_pool::PoolMembership {
                group_id,
                group_name: group.name,
                native: true,
            }],
        });
    }
    let control = connections.capture().await;
    let mut group_rules = HashMap::new();
    for group_id in pool_nodes
        .iter()
        .flat_map(|node| {
            node.memberships
                .iter()
                .map(|membership| membership.group_id)
        })
        .collect::<HashSet<_>>()
    {
        group_rules.insert(
            group_id,
            RuleRepository::list_active_for_config(db, group_id).await?,
        );
    }
    let statuses = status_rows
        .into_iter()
        .filter_map(|(key, raw)| {
            let (identity_group_id, node_id) = crate::api::stats::parse_status_key(&key)?;
            Some((
                (identity_group_id, node_id.unwrap_or_default().to_string()),
                raw,
            ))
        })
        .collect();
    let mut result = snapshots_from_observation(pool_nodes, statuses, control, group_rules, as_of);
    for snapshot in &mut result {
        if let Some(ip) = snapshot.telemetry.public_ipv4.as_deref() {
            if let Some(entry) = crate::api::geoip::read_cache(db, ip).await {
                snapshot.telemetry.ipv4_country_code = entry.country_code;
                snapshot.telemetry.ipv4_country_name = entry.country_name;
            }
        }
        if let Some(ip) = snapshot.telemetry.public_ipv6.as_deref() {
            if let Some(entry) = crate::api::geoip::read_cache(db, ip).await {
                snapshot.telemetry.ipv6_country_code = entry.country_code;
                snapshot.telemetry.ipv6_country_name = entry.country_name;
            }
        }
    }
    Ok(result)
}

fn snapshots_from_observation(
    pool_nodes: Vec<node_pool::PoolNode>,
    statuses: HashMap<(i64, String), String>,
    control: ControlSnapshot,
    group_rules: HashMap<i64, Vec<relay_shared::models::ForwardRule>>,
    as_of: DateTime<Utc>,
) -> Vec<NodeHealthSnapshot> {
    let mut live_by_identity = HashMap::new();
    for node in &pool_nodes {
        live_by_identity
            .entry(node.identity_group_id)
            .or_insert_with(|| control.online_node_ids(node.identity_group_id));
    }
    let mut readiness = HashMap::new();
    let mut members_by_group: HashMap<i64, Vec<&node_pool::PoolNode>> = HashMap::new();
    for node in &pool_nodes {
        for membership in &node.memberships {
            members_by_group
                .entry(membership.group_id)
                .or_default()
                .push(node);
        }
    }
    for (group_id, members) in members_by_group {
        let Some(rules) = group_rules.get(&group_id) else {
            continue;
        };
        for node in members {
            if node.node_id.is_empty() {
                readiness.insert(
                    (group_id, node.identity_group_id, String::new()),
                    GroupReadiness {
                        group_id,
                        group_name: node
                            .memberships
                            .iter()
                            .find(|member| member.group_id == group_id)
                            .expect("member collected from group membership")
                            .group_name
                            .clone(),
                        ready: false,
                        reasons: vec!["EXACT_NODE_ID_UNAVAILABLE".into()],
                    },
                );
                continue;
            }
            let identity = (node.identity_group_id, node.node_id.clone());
            let evaluated = relay_preference::evaluate_observed_group_node(
                node.identity_group_id,
                &node.node_id,
                statuses.get(&identity).map(String::as_str),
                as_of,
                &live_by_identity[&node.identity_group_id],
                rules,
                &node.display_name,
            );
            let membership = node
                .memberships
                .iter()
                .find(|member| member.group_id == group_id)
                .expect("member collected from group membership");
            readiness.insert(
                (group_id, identity.0, identity.1),
                GroupReadiness {
                    group_id,
                    group_name: membership.group_name.clone(),
                    ready: evaluated.ready,
                    reasons: evaluated.ready_reasons,
                },
            );
        }
    }
    let mut result = Vec::with_capacity(pool_nodes.len());
    for node in pool_nodes {
        let identity = (node.identity_group_id, node.node_id.clone());
        let raw = statuses.get(&identity).map(String::as_str);
        let status = raw.and_then(|raw| serde_json::from_str::<Value>(raw).ok());
        let age_seconds = raw
            .and_then(status_last_seen)
            .map(|last_seen: DateTime<Utc>| (as_of - last_seen).num_seconds());
        let control_connected = control.connected.contains(&identity);
        let lifecycle_connected = control.lifecycle_connected.contains(&identity);
        let (last_connected_at, last_disconnected_at) = control
            .observations
            .get(&identity)
            .cloned()
            .unwrap_or_default();
        let reconciliation = status
            .as_ref()
            .and_then(|status| status.get("reconciliation"))
            .and_then(|value| serde_json::from_value::<ReconciliationStatus>(value.clone()).ok());
        let listener_errors: Option<Vec<ListenerError>> = status
            .as_ref()
            .and_then(|status| status.get("listener_errors"))
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        let converged = reconciliation
            .as_ref()
            .is_some_and(|status| status.state == ReconciliationStatusState::Converged)
            && listener_errors.as_ref().is_none_or(Vec::is_empty);
        let state = if node.node_id.is_empty() {
            NodeHealthState::Unknown
        } else {
            classify(status.is_some(), age_seconds, control_connected, converged)
        };
        let empty = Value::Null;
        let status = status.as_ref().unwrap_or(&empty);
        let group_readiness = node
            .memberships
            .iter()
            .map(|membership| {
                readiness
                    .get(&(membership.group_id, identity.0, identity.1.clone()))
                    .cloned()
                    .unwrap_or(GroupReadiness {
                        group_id: membership.group_id,
                        group_name: membership.group_name.clone(),
                        ready: false,
                        reasons: vec!["READINESS_UNAVAILABLE".into()],
                    })
            })
            .collect();
        let identity_group_name = node
            .memberships
            .iter()
            .find(|membership| membership.native)
            .map(|membership| membership.group_name.clone())
            .unwrap_or_else(|| "节点池".into());
        result.push(NodeHealthSnapshot {
            identity_group_id: node.identity_group_id,
            identity_group_name,
            legacy_status: node.node_id.is_empty(),
            node_id: node.node_id,
            display_name: node.display_name,
            as_of: as_of.to_rfc3339(),
            state,
            telemetry: NodeTelemetry {
                last_seen: string_field(status, "last_seen"),
                age_seconds,
                fresh: age_seconds.is_some_and(|age| age <= NODE_ONLINE_WINDOW_SECS),
                cpu: number_field(status, "cpu"),
                mem: number_field(status, "mem"),
                uptime: number_field(status, "uptime"),
                process_uptime: number_field(status, "process_uptime"),
                disk_total: number_field(status, "disk_total"),
                disk_used: number_field(status, "disk_used"),
                disk_usage_percent: number_field(status, "disk_usage_percent"),
                disk_mount: string_field(status, "disk_mount"),
                upload_bps: number_field(status, "upload_bps"),
                download_bps: number_field(status, "download_bps"),
                boot_upload_bytes: number_field(status, "boot_upload_bytes"),
                boot_download_bytes: number_field(status, "boot_download_bytes"),
                network_interface: string_field(status, "network_interface"),
                connections: integer_field(status, "connections"),
                tcp_connections: integer_field(status, "tcp_connections"),
                udp_sessions: integer_field(status, "udp_sessions"),
                public_ip: string_field(status, "public_ip"),
                public_ipv4: string_field(status, "public_ipv4")
                    .or_else(|| string_field(status, "public_ip")),
                public_ipv6: string_field(status, "public_ipv6"),
                ipv4_country_code: None,
                ipv4_country_name: None,
                ipv6_country_code: None,
                ipv6_country_name: None,
                node_version: string_field(status, "node_version"),
                architecture: string_field(status, "architecture"),
                install_method: string_field(status, "install_method"),
                config_protocol_version: status
                    .get("config_protocol_version")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                verified_concrete_node: status
                    .get("verified_concrete_node")
                    .and_then(Value::as_bool),
                auth_reload_supported: status.get("auth_reload_supported").and_then(Value::as_bool),
            },
            control_connected,
            control: NodeControlHealth {
                connected: control_connected,
                lifecycle_connected,
                last_connected_at,
                last_disconnected_at,
            },
            runtime: NodeRuntimeHealth {
                reconciliation,
                listener_errors,
                active_listener_rule_ids: status
                    .get("active_listener_rule_ids")
                    .and_then(|value| serde_json::from_value(value.clone()).ok()),
            },
            group_readiness,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{KvsRepository, NodePoolRepository};
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    #[test]
    fn health_distinguishes_transient_control_loss_from_offline() {
        assert_eq!(
            classify(true, Some(30), true, true),
            NodeHealthState::Healthy
        );
        assert_eq!(
            classify(true, Some(30), false, true),
            NodeHealthState::Degraded
        );
        assert_eq!(
            classify(true, Some(31), true, true),
            NodeHealthState::Degraded
        );
        assert_eq!(
            classify(true, Some(31), false, true),
            NodeHealthState::Offline
        );
        assert_eq!(
            classify(false, None, false, false),
            NodeHealthState::Unknown
        );
    }

    #[tokio::test]
    async fn snapshots_follow_telemetry_and_control_without_inventing_reconnect() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_groups (id,name,group_type,token,uid) VALUES (10,'home','in','token-10',1)")
            .execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        db.register_node_pool_identity(10, "Node_A").await.unwrap();
        db.rename_node_pool_node(10, "Node_A", "Tokyo relay")
            .await
            .unwrap();
        let report = |seconds_ago| {
            serde_json::json!({
                "last_seen": (Utc::now() - chrono::Duration::seconds(seconds_ago)).to_rfc3339(),
                "public_ipv4": "203.0.113.5", "config_protocol_version": 10,
                "active_listener_rule_ids": [],
                "reconciliation": {"state":"CONVERGED", "recovery_source":"NONE"}
            })
            .to_string()
        };
        db.set("node_status:10:Node_A", &report(0)).await.unwrap();
        let connections = NodeConnections::new();
        let (conn, _rx) = connections.register(10, Some("Node_A".into())).await;
        let healthy = snapshots(&db, &connections).await.unwrap();
        assert_eq!(healthy[0].state, NodeHealthState::Healthy);
        assert_eq!(healthy[0].display_name, "Tokyo relay");
        assert!(healthy[0].group_readiness[0].ready);
        db.register_node_pool_identity(10, "Node_B").await.unwrap();
        db.set("node_status:10:Node_B", &report(0)).await.unwrap();
        let (_second, _second_rx) = connections.register(10, Some("Node_B".into())).await;
        let captured_at = Utc::now();
        let status_rows = db.scan_prefix("node_status:").await.unwrap();
        let pool_nodes = node_pool::list_nodes_from_status_rows(&db, &status_rows, captured_at)
            .await
            .unwrap();
        let control = connections.capture().await;
        let rules = RuleRepository::list_active_for_config(&db, 10)
            .await
            .unwrap();
        let statuses = status_rows
            .into_iter()
            .filter_map(|(key, value)| {
                let (group_id, node_id) = crate::api::stats::parse_status_key(&key)?;
                Some(((group_id, node_id?.to_string()), value))
            })
            .collect();
        connections.unregister(10, conn).await;
        let frozen = snapshots_from_observation(
            pool_nodes,
            statuses,
            control,
            HashMap::from([(10, rules)]),
            captured_at,
        );
        assert_eq!(frozen.len(), 2);
        assert!(frozen
            .iter()
            .all(|node| node.as_of == captured_at.to_rfc3339()));
        let first = frozen.iter().find(|node| node.node_id == "Node_A").unwrap();
        assert!(first.control.connected);
        assert!(first.group_readiness[0].ready);
        let later = snapshots(&db, &connections).await.unwrap();
        let first_later = later.iter().find(|node| node.node_id == "Node_A").unwrap();
        assert!(!first_later.control.connected);
        assert!(!first_later.group_readiness[0].ready);
        let mut runtime_error: serde_json::Value = serde_json::from_str(&report(0)).unwrap();
        runtime_error["listener_errors"] =
            serde_json::json!([{"port":443,"protocol":"tcp","error":"bind failed"}]);
        db.set("node_status:10:Node_A", &runtime_error.to_string())
            .await
            .unwrap();
        assert_eq!(
            snapshots(&db, &connections).await.unwrap()[0].state,
            NodeHealthState::Degraded
        );
        db.set("node_status:10:Node_A", &report(0)).await.unwrap();
        let degraded = snapshots(&db, &connections).await.unwrap();
        assert_eq!(degraded[0].state, NodeHealthState::Degraded);
        assert!(!degraded[0].group_readiness[0].ready);
        assert!(degraded[0].control.last_disconnected_at.is_some());
        db.set("node_status:10:Node_A", &report(40)).await.unwrap();
        assert_eq!(
            snapshots(&db, &connections).await.unwrap()[0].state,
            NodeHealthState::Offline
        );
        db.set("node_status:10:Node_A", "broken-json")
            .await
            .unwrap();
        assert_eq!(
            snapshots(&db, &connections).await.unwrap()[0].state,
            NodeHealthState::Unknown
        );
    }

    #[tokio::test]
    async fn group_only_status_remains_visible_without_becoming_an_exact_node() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_groups (id,name,group_type,token,uid) VALUES (10,'legacy','in','token-10',1)")
            .execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        db.set(
            "node_status:10",
            &serde_json::json!({
                "node_id": "self-reported-not-authoritative",
                "last_seen": Utc::now().to_rfc3339(),
                "public_ipv4": "203.0.113.10",
                "cpu": 7.0
            })
            .to_string(),
        )
        .await
        .unwrap();
        let result = snapshots(&db, &NodeConnections::new()).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_id, "");
        assert!(result[0].legacy_status);
        assert_eq!(result[0].identity_group_name, "legacy");
        assert_eq!(result[0].telemetry.cpu, Some(7.0));
        assert_eq!(result[0].state, NodeHealthState::Unknown);
        assert!(!result[0].group_readiness[0].ready);
        assert_eq!(
            result[0].group_readiness[0].reasons,
            ["EXACT_NODE_ID_UNAVAILABLE"]
        );
        assert!(db.list_node_pool_records().await.unwrap().is_empty());
    }
}
