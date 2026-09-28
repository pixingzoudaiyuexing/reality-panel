use crate::api::stats::{status_last_seen, NODE_ONLINE_WINDOW_SECS};
use crate::api::ws::NodeConnections;
use crate::db::error::DbError;
use crate::db::repo::Repository;
use crate::service::{node_pool, relay_preference};
use chrono::{DateTime, Utc};
use relay_shared::protocol::{ListenerError, ReconciliationStatus, ReconciliationStatusState};
use serde::Serialize;
use serde_json::Value;

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
    pub disk_usage_percent: Option<f64>,
    pub upload_bps: Option<f64>,
    pub download_bps: Option<f64>,
    pub connections: Option<i64>,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub node_version: Option<String>,
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
    pub last_connected_at: Option<String>,
    pub last_disconnected_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GroupReadiness {
    pub group_id: i64,
    pub group_name: String,
    pub ready: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeHealthSnapshot {
    pub identity_group_id: i64,
    pub node_id: String,
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
    let pool_nodes = node_pool::list_nodes(db).await?;
    let mut result = Vec::with_capacity(pool_nodes.len());
    for node in pool_nodes {
        let raw = db
            .get(&format!(
                "node_status:{}:{}",
                node.identity_group_id, node.node_id
            ))
            .await;
        let status = raw
            .as_ref()
            .ok()
            .and_then(|raw| raw.as_deref())
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
        let age_seconds = raw
            .as_ref()
            .ok()
            .and_then(|raw| raw.as_deref())
            .and_then(status_last_seen)
            .map(|last_seen: DateTime<Utc>| (as_of - last_seen).num_seconds());
        let control_connected = connections
            .online_node_ids(node.identity_group_id)
            .await
            .contains(&node.node_id);
        let (last_connected_at, last_disconnected_at) = connections
            .observation(node.identity_group_id, &node.node_id)
            .await;
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
        let state = classify(status.is_some(), age_seconds, control_connected, converged);
        let empty = Value::Null;
        let status = status.as_ref().unwrap_or(&empty);
        let mut group_readiness = Vec::with_capacity(node.memberships.len());
        for membership in &node.memberships {
            let match_node =
                relay_preference::evaluate_group_ready_nodes(db, connections, membership.group_id)
                    .await;
            let (ready, reasons) = match match_node {
                Ok(nodes) => nodes
                    .into_iter()
                    .find(|candidate| {
                        candidate.node_id == node.node_id
                            && candidate.identity_group_id == node.identity_group_id
                    })
                    .map(|candidate| (candidate.ready, candidate.ready_reasons))
                    .unwrap_or((false, vec!["STATUS_MISSING".into()])),
                Err(_) => (false, vec!["READINESS_UNAVAILABLE".into()]),
            };
            group_readiness.push(GroupReadiness {
                group_id: membership.group_id,
                group_name: membership.group_name.clone(),
                ready,
                reasons,
            });
        }
        result.push(NodeHealthSnapshot {
            identity_group_id: node.identity_group_id,
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
                disk_usage_percent: number_field(status, "disk_usage_percent"),
                upload_bps: number_field(status, "upload_bps"),
                download_bps: number_field(status, "download_bps"),
                connections: status.get("connections").and_then(Value::as_i64),
                public_ipv4: string_field(status, "public_ipv4")
                    .or_else(|| string_field(status, "public_ip")),
                public_ipv6: string_field(status, "public_ipv6"),
                node_version: string_field(status, "node_version"),
            },
            control_connected,
            control: NodeControlHealth {
                connected: control_connected,
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
    Ok(result)
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
        connections.unregister(10, conn).await;
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
}
