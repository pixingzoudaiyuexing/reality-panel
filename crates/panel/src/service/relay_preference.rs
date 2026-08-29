//! Panel-side Relay preference and readiness for Reality inbound groups.
//!
//! This module deliberately does not select a replacement Relay and does not
//! touch DNS.  It only evaluates the status telemetry already stored by the
//! Panel and initializes a preference when a group has exactly one ready node.

use crate::api::stats::{parse_status_key, NODE_ONLINE_WINDOW_SECS};
use crate::api::ws::NodeConnections;
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use relay_shared::models::ForwardRule;
use relay_shared::protocol::{
    CamouflageSiteStatus, ListenerError, ReconciliationStatus, ReconciliationStatusState,
    CONFIG_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;

pub const RELAY_PREFERENCE_KEY_PREFIX: &str = "relay_preference:";

/// The Panel is a single process. Serializing only the short initialization
/// transaction prevents concurrent status reports from choosing different
/// first preferences without adding database or distributed lock machinery.
static INITIALIZATION_LOCK: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayPreferencePhase {
    Idle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPreferenceState {
    pub preferred_node_id: Option<String>,
    pub pending_node_id: Option<String>,
    pub state: RelayPreferencePhase,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
}

impl Default for RelayPreferenceState {
    fn default() -> Self {
        Self {
            preferred_node_id: None,
            pending_node_id: None,
            state: RelayPreferencePhase::Idle,
            started_at: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayReadyNode {
    pub node_id: String,
    pub public_ipv4: Option<String>,
    pub online: bool,
    pub ready: bool,
    pub ready_reasons: Vec<String>,
    pub preferred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayPreferenceView {
    pub group_id: i64,
    pub preferred_node_id: Option<String>,
    pub preferred_node_public_ipv4: Option<String>,
    pub pending_node_id: Option<String>,
    pub state: RelayPreferencePhase,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
    pub nodes: Vec<RelayReadyNode>,
}

#[derive(Debug, Deserialize)]
struct StoredNodeStatus {
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    public_ipv4: Option<String>,
    #[serde(default)]
    public_ip: Option<String>,
    #[serde(default)]
    config_protocol_version: Option<u32>,
    #[serde(default)]
    active_listener_rule_ids: Option<Vec<i64>>,
    #[serde(default)]
    listener_errors: Option<Vec<ListenerError>>,
    #[serde(default)]
    camouflage_sites: Option<Vec<CamouflageSiteStatus>>,
    #[serde(default)]
    reconciliation: Option<ReconciliationStatus>,
}

#[derive(Debug)]
struct EvaluatedNode {
    info: RelayReadyNode,
    public_ipv4: Option<String>,
}

#[derive(Debug)]
pub enum RelayPreferenceError {
    Database(DbError),
    InvalidPreference(serde_json::Error),
}

impl std::fmt::Display for RelayPreferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::InvalidPreference(error) => write!(f, "invalid relay preference: {error}"),
        }
    }
}

impl std::error::Error for RelayPreferenceError {}

impl From<DbError> for RelayPreferenceError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

/// Evaluate one stored node status without making network calls. The status
/// key supplies the authoritative group/node identity; public IP is telemetry,
/// never an identity key.
fn evaluate_node(
    node_id: String,
    raw_status: Option<&str>,
    now: DateTime<Utc>,
    live_node_ids: &HashSet<String>,
    rules: &[ForwardRule],
) -> EvaluatedNode {
    let mut reasons = Vec::new();
    let Some(raw_status) = raw_status else {
        return EvaluatedNode {
            info: RelayReadyNode {
                node_id,
                public_ipv4: None,
                online: false,
                ready: false,
                ready_reasons: vec!["STATUS_MISSING".into()],
                preferred: false,
            },
            public_ipv4: None,
        };
    };
    let status = match serde_json::from_str::<StoredNodeStatus>(raw_status) {
        Ok(status) => status,
        Err(_) => {
            return EvaluatedNode {
                info: RelayReadyNode {
                    node_id,
                    public_ipv4: None,
                    online: false,
                    ready: false,
                    ready_reasons: vec!["STATUS_INVALID".into()],
                    preferred: false,
                },
                public_ipv4: None,
            };
        }
    };

    let online = match status.last_seen.as_deref().and_then(parse_timestamp) {
        Some(last_seen) if (now - last_seen).num_seconds() <= NODE_ONLINE_WINDOW_SECS => true,
        Some(_) => {
            reasons.push("STALE_STATUS".into());
            false
        }
        None => {
            reasons.push("LAST_SEEN_MISSING".into());
            false
        }
    };
    if !live_node_ids.contains(&node_id) {
        reasons.push("CONTROL_CHANNEL_OFFLINE".into());
    }
    if status.config_protocol_version != Some(CONFIG_PROTOCOL_VERSION) {
        reasons.push("CONFIG_PROTOCOL_MISMATCH".into());
    }

    let public_ipv4 = status
        .public_ipv4
        .clone()
        .or_else(|| status.public_ip.clone());
    match public_ipv4
        .as_deref()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
    {
        Some(ip) if !ip.is_loopback() && !ip.is_unspecified() => {}
        Some(_) => reasons.push("PUBLIC_IPV4_INVALID".into()),
        None if public_ipv4.is_some() => reasons.push("PUBLIC_IPV4_INVALID".into()),
        None => reasons.push("PUBLIC_IPV4_MISSING".into()),
    }

    if status.reconciliation.as_ref().map(|r| r.state) != Some(ReconciliationStatusState::Converged)
    {
        reasons.push("RECONCILIATION_NOT_CONVERGED".into());
    }

    match status.active_listener_rule_ids.as_ref() {
        Some(active_ids) => {
            for rule in rules {
                if !active_ids.contains(&rule.id) {
                    reasons.push(format!("ACTIVE_RULE_MISSING:{0}", rule.id));
                }
            }
        }
        None => reasons.push("ACTIVE_RULES_MISSING".into()),
    }

    for rule in rules.iter().filter(|rule| rule.camouflage_enabled) {
        let matching_site = status.camouflage_sites.as_ref().and_then(|sites| {
            sites.iter().find(|site| {
                site.sni
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(rule.sni.as_deref().unwrap_or("").trim_end_matches('.'))
            })
        });
        if matching_site.map(|site| site.site_status.as_str()) != Some("active") {
            reasons.push(format!("CAMOUFLAGE_SITE_NOT_ACTIVE:{0}", rule.id));
        }
        if matching_site.map(|site| site.certificate_status.as_str()) != Some("active") {
            reasons.push(format!("CERTIFICATE_NOT_ACTIVE:{0}", rule.id));
        }
    }

    if let Some(errors) = status.listener_errors.as_ref() {
        if errors
            .iter()
            .any(|error| listener_error_affects_rules(error, rules))
        {
            reasons.push("LISTENER_ERROR".into());
        }
    }

    reasons.sort();
    reasons.dedup();
    EvaluatedNode {
        info: RelayReadyNode {
            node_id,
            public_ipv4: public_ipv4.clone(),
            online,
            ready: reasons.is_empty(),
            ready_reasons: reasons,
            preferred: false,
        },
        public_ipv4,
    }
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn listener_error_affects_rules(error: &ListenerError, rules: &[ForwardRule]) -> bool {
    rules.iter().any(|rule| {
        if rule.listen_port != i32::from(error.port) {
            return false;
        }
        match error.protocol.to_ascii_lowercase().as_str() {
            "udp" => matches!(rule.protocol.as_str(), "udp" | "tcp_udp"),
            _ => matches!(rule.protocol.as_str(), "tcp" | "tcp_udp"),
        }
    })
}

fn preference_key(group_id: i64) -> String {
    format!("{RELAY_PREFERENCE_KEY_PREFIX}{group_id}")
}

fn initialize_preference_if_unique_ready(
    preference: &mut RelayPreferenceState,
    ready_node_ids: &[String],
) -> bool {
    if preference.preferred_node_id.is_none() && ready_node_ids.len() == 1 {
        preference.preferred_node_id = ready_node_ids.first().cloned();
        true
    } else {
        false
    }
}

fn status_identity(key: &str) -> Option<(i64, String)> {
    let (group_id, node_id) = parse_status_key(key)?;
    Some((group_id, node_id.unwrap_or("__legacy__").to_string()))
}

async fn evaluate_group_nodes(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<Vec<EvaluatedNode>, RelayPreferenceError> {
    let rules = db.list_active_for_config(group_id).await?;
    let rows = db.scan_prefix("node_status:").await?;
    let live_node_ids = node_connections.online_node_ids(group_id).await;
    let now = Utc::now();
    let mut statuses = BTreeMap::new();

    for (key, raw_status) in rows {
        let Some((status_group_id, node_id)) = status_identity(&key) else {
            continue;
        };
        if status_group_id != group_id {
            continue;
        }
        statuses.insert(node_id, raw_status);
    }
    for node_id in &live_node_ids {
        statuses.entry(node_id.clone()).or_default();
    }
    Ok(statuses
        .into_iter()
        .map(|(node_id, raw_status)| {
            let raw_status = (!raw_status.is_empty()).then_some(raw_status.as_str());
            evaluate_node(node_id, raw_status, now, &live_node_ids, &rules)
        })
        .collect())
}

/// Ensure an inbound group's preference has its one-time initial value.
/// Existing preferences are returned unchanged; this function never performs
/// failover or replaces an operator-selected/current preferred node.
pub async fn ensure_preference_initialized(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<RelayPreferenceState, RelayPreferenceError> {
    let _guard = INITIALIZATION_LOCK.lock().await;
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    if group.as_ref().map(|group| group.group_type.as_str()) != Some("in") {
        return Ok(RelayPreferenceState::default());
    }
    let raw_preference = db.get(&preference_key(group_id)).await?;
    let mut preference = match raw_preference {
        Some(raw) => serde_json::from_str(&raw).map_err(RelayPreferenceError::InvalidPreference)?,
        None => RelayPreferenceState::default(),
    };
    if preference.preferred_node_id.is_some() {
        return Ok(preference);
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;

    let ready_node_ids: Vec<String> = evaluated
        .iter()
        .filter(|node| node.info.ready)
        .map(|node| node.info.node_id.clone())
        .collect();
    if initialize_preference_if_unique_ready(&mut preference, &ready_node_ids) {
        db.set(
            &preference_key(group_id),
            &serde_json::to_string(&preference).expect("relay preference is serializable"),
        )
        .await?;
    }

    Ok(preference)
}

pub async fn delete_relay_preference(db: &dyn Repository, group_id: i64) -> Result<(), DbError> {
    let _guard = INITIALIZATION_LOCK.lock().await;
    db.delete(&preference_key(group_id)).await?;
    Ok(())
}

pub async fn get_relay_preference(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<RelayPreferenceView, RelayPreferenceError> {
    let preference = ensure_preference_initialized(db, node_connections, group_id).await?;
    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;

    let preferred_node_id = preference.preferred_node_id.clone();
    let preferred_ip = evaluated
        .iter()
        .find(|node| Some(node.info.node_id.as_str()) == preferred_node_id.as_deref())
        .and_then(|node| node.public_ipv4.clone());
    let nodes = evaluated
        .into_iter()
        .map(|mut node| {
            node.info.preferred = Some(node.info.node_id.as_str()) == preferred_node_id.as_deref();
            node.info
        })
        .collect();

    Ok(RelayPreferenceView {
        group_id,
        preferred_node_id,
        preferred_node_public_ipv4: preferred_ip,
        pending_node_id: preference.pending_node_id,
        state: preference.state,
        started_at: preference.started_at,
        last_error: preference.last_error,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::models::ForwardRule;

    fn rule(id: i64, camouflage: bool) -> ForwardRule {
        ForwardRule {
            id,
            name: format!("rule-{id}"),
            uid: 1,
            paused: false,
            listen_port: 443,
            protocol: "tcp".into(),
            public_transport: "nginx_sni".into(),
            node_transport: "nginx_sni".into(),
            route_mode: "direct".into(),
            device_group_in: 7,
            device_group_out: None,
            forward_mode: "direct".into(),
            tunnel_profile_id: None,
            domain: None,
            ws_path: None,
            ws_host: None,
            sni: Some("op1.example.com".into()),
            camouflage_enabled: camouflage,
            send_proxy_protocol: false,
            target_addr: "198.51.100.2".into(),
            target_port: 55443,
            targets: Vec::new(),
            load_balance_strategy: "first".into(),
            upload_limit_mbps: 0,
            download_limit_mbps: 0,
            max_connections: 0,
            auto_restart_minutes: 0,
            config: "{}".into(),
            traffic_used: 0,
            status: "active".into(),
            created_at: String::new(),
        }
    }

    fn status(overrides: serde_json::Value) -> String {
        let mut value = serde_json::json!({
            "last_seen": Utc::now().to_rfc3339(),
            "public_ipv4": "203.0.113.5",
            "config_protocol_version": CONFIG_PROTOCOL_VERSION,
            "active_listener_rule_ids": [1],
            "camouflage_sites": [{
                "site_id": "site-1",
                "sni": "op1.example.com",
                "site_status": "active",
                "certificate_status": "active",
                "line_type": "default"
            }],
            "reconciliation": {
                "state": "CONVERGED",
                "recovery_source": "NONE"
            }
        });
        if let (Some(target), Some(source)) = (value.as_object_mut(), overrides.as_object()) {
            for (key, val) in source {
                target.insert(key.clone(), val.clone());
            }
        }
        value.to_string()
    }

    fn status_with_ip(ip: &str, age_secs: i64) -> String {
        serde_json::json!({
            "last_seen": (Utc::now() - chrono::Duration::seconds(age_secs)).to_rfc3339(),
            "public_ipv4": ip,
            "config_protocol_version": CONFIG_PROTOCOL_VERSION,
            "active_listener_rule_ids": [1],
            "reconciliation": {
                "state": "CONVERGED",
                "recovery_source": "NONE"
            }
        })
        .to_string()
    }

    fn evaluate(raw: &str, rules: &[ForwardRule], online: bool) -> RelayReadyNode {
        let ids = online
            .then(|| HashSet::from(["node-a".to_string()]))
            .unwrap_or_default();
        evaluate_node("node-a".into(), Some(raw), Utc::now(), &ids, rules).info
    }

    #[test]
    fn qualified_node_is_ready_and_ip_does_not_define_identity() {
        let node = evaluate(&status(serde_json::json!({})), &[rule(1, false)], true);
        assert!(node.ready);
        assert_eq!(node.node_id, "node-a");
        assert_eq!(node.public_ipv4.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn offline_ws_protocol_reconciliation_and_rule_failures_are_explicit() {
        let raw = status(serde_json::json!({
            "config_protocol_version": CONFIG_PROTOCOL_VERSION - 1,
            "reconciliation": {"state": "APPLY_FAILED", "recovery_source": "NONE"},
            "active_listener_rule_ids": [],
        }));
        let node = evaluate(&raw, &[rule(1, false)], false);
        assert!(!node.ready);
        assert!(node
            .ready_reasons
            .contains(&"CONTROL_CHANNEL_OFFLINE".into()));
        assert!(node
            .ready_reasons
            .contains(&"CONFIG_PROTOCOL_MISMATCH".into()));
        assert!(node
            .ready_reasons
            .contains(&"RECONCILIATION_NOT_CONVERGED".into()));
        assert!(node.ready_reasons.contains(&"ACTIVE_RULE_MISSING:1".into()));
    }

    #[test]
    fn camouflage_and_certificate_must_both_be_active() {
        let raw = status(serde_json::json!({
            "camouflage_sites": [{
                "site_id": "site-1",
                "sni": "op1.example.com",
                "site_status": "preparing",
                "certificate_status": "pending",
                "line_type": "default"
            }]
        }));
        let node = evaluate(&raw, &[rule(1, true)], true);
        assert!(!node.ready);
        assert!(node
            .ready_reasons
            .contains(&"CAMOUFLAGE_SITE_NOT_ACTIVE:1".into()));
        assert!(node
            .ready_reasons
            .contains(&"CERTIFICATE_NOT_ACTIVE:1".into()));
    }

    #[test]
    fn listener_error_only_blocks_affected_rule() {
        let raw = status(serde_json::json!({
            "listener_errors": [{"port": 443, "protocol": "tcp", "error": "bind"}]
        }));
        let node = evaluate(&raw, &[rule(1, false)], true);
        assert!(!node.ready);
        assert!(node.ready_reasons.contains(&"LISTENER_ERROR".into()));
    }

    #[test]
    fn malformed_status_fails_closed() {
        let node = evaluate("not-json", &[], true);
        assert!(!node.ready);
        assert_eq!(node.ready_reasons, vec!["STATUS_INVALID"]);
    }

    #[test]
    fn missing_status_fails_closed_even_with_live_ws() {
        let ids = HashSet::from(["node-a".to_string()]);
        let node = evaluate_node("node-a".into(), None, Utc::now(), &ids, &[]).info;
        assert!(!node.ready);
        assert_eq!(node.ready_reasons, vec!["STATUS_MISSING"]);
    }

    #[test]
    fn status_key_uses_group_and_node_not_public_ip() {
        assert_eq!(
            status_identity("node_status:7:node-a"),
            Some((7, "node-a".into()))
        );
        assert_eq!(
            status_identity("node_status:7"),
            Some((7, "__legacy__".into()))
        );
        assert_eq!(
            status_identity("node_status:8:node-a"),
            Some((8, "node-a".into()))
        );
    }

    #[test]
    fn initializes_only_an_unset_preference_with_one_ready_node() {
        let mut preference = RelayPreferenceState::default();
        assert!(initialize_preference_if_unique_ready(
            &mut preference,
            &["node-a".into()]
        ));
        assert_eq!(preference.preferred_node_id.as_deref(), Some("node-a"));

        let mut existing = RelayPreferenceState {
            preferred_node_id: Some("node-a".into()),
            ..RelayPreferenceState::default()
        };
        assert!(!initialize_preference_if_unique_ready(
            &mut existing,
            &["node-b".into()]
        ));
        assert_eq!(existing.preferred_node_id.as_deref(), Some("node-a"));
    }

    #[test]
    fn preference_state_never_serializes_an_ip_copy() {
        let encoded = serde_json::to_value(RelayPreferenceState::default()).unwrap();
        assert_eq!(encoded["state"], "idle");
        assert!(encoded.get("preferred_ipv4").is_none());
        assert!(encoded.get("preferred_node_public_ipv4").is_none());
    }

    #[tokio::test]
    async fn sqlite_initializes_once_and_keeps_preferred_node_when_it_goes_offline() {
        use crate::db::repo::KvsRepository;
        use crate::db::schema::SCHEMA_SQL;
        use crate::db::sqlite_repo::SqliteRepository;
        use sqlx::sqlite::SqlitePoolOptions;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin) VALUES (2, 'owner', 'hash', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (7, 'reality', 'in', 'group-token', 2, '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (1, 'rule', 2, 443, 7, '198.51.100.2', 55443)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let repo = SqliteRepository::new(pool);
        repo.set("node_status:7:node-a", &status_with_ip("203.0.113.5", 0))
            .await
            .unwrap();
        let connections = NodeConnections::new();
        let (a_connection, _a_rx) = connections.register(7, Some("node-a".into())).await;

        let first = get_relay_preference(&repo, &connections, 7).await.unwrap();
        assert_eq!(first.preferred_node_id.as_deref(), Some("node-a"));
        assert!(first.nodes[0].ready);
        let persisted = repo.get(&preference_key(7)).await.unwrap().unwrap();
        assert!(!persisted.contains("public_ipv4"));

        repo.set(
            "node_status:7:node-a",
            &status_with_ip("203.0.113.9", NODE_ONLINE_WINDOW_SECS + 1),
        )
        .await
        .unwrap();
        let (b_connection, _b_rx) = connections.register(7, Some("node-b".into())).await;
        repo.set("node_status:7:node-b", &status_with_ip("203.0.113.9", 0))
            .await
            .unwrap();
        connections.unregister(7, a_connection).await;

        let second = get_relay_preference(&repo, &connections, 7).await.unwrap();
        assert_eq!(second.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(
            second.preferred_node_public_ipv4.as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(second.nodes.len(), 2, "same public IP must not merge nodes");
        assert!(second
            .nodes
            .iter()
            .any(|node| node.node_id == "node-b" && node.ready && node.preferred == false));
        connections.unregister(7, b_connection).await;
    }
}
