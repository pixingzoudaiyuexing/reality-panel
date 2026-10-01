//! Narrow, one-time official v1.3.0 replacement. Ordinary deletion is unchanged.
use crate::api::AppState;
use crate::db::repo::{
    ConcreteNodeIdentity, LegacyUpgradeCommit, LegacyUpgradeReplacement, Repository, ResourceScope,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SINGLETON: &str = "legacy_v130_upgrade:singleton";
pub const OFFICIAL_AMD64_SHA256: &str =
    "5c70aac9aab2e78b739d0468d6920b56fac427fb31f18790bc0809c616f965f9";
pub(crate) static MUTATIONS: Lazy<tokio::sync::RwLock<()>> =
    Lazy::new(|| tokio::sync::RwLock::new(()));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub rule_id: i64,
    pub path: String,
    pub expected_marker: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSnapshot {
    pub rule_id: i64,
    pub line: String,
    pub value: String,
    pub record_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub state: String,
    pub old: ConcreteNodeIdentity,
    pub new: ConcreteNodeIdentity,
    pub public_ipv4: String,
    pub display_name: String,
    pub memberships: Vec<i64>,
    pub listeners: serde_json::Value,
    pub routing: Vec<(String, String)>,
    pub dns: Vec<DnsSnapshot>,
    pub probes: Vec<Probe>,
    pub token_hash: String,
    pub created_by: i64,
    pub created_at: String,
    pub last_error: Option<String>,
    #[serde(default)]
    pub rollback_after: Option<String>,
}
impl Operation {
    pub fn active(&self) -> bool {
        !matches!(
            self.state.as_str(),
            "SUCCESS" | "ROLLED_BACK" | "FAILED_PRECHECK"
        )
    }
    pub fn committed(&self) -> bool {
        matches!(self.state.as_str(), "COMMITTED" | "SUCCESS")
    }
    pub fn groups(&self) -> &[i64] {
        &self.memberships
    }
}

pub fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
pub fn token(state: &AppState, id: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(state.config.jwt_secret.as_bytes())
        .expect("HMAC accepts any key");
    mac.update(b"legacy-v130-single-node-upgrade/v1\0");
    mac.update(id.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub async fn load(db: &dyn Repository) -> Result<Option<(String, Operation)>, String> {
    db.get(SINGLETON)
        .await
        .map_err(|_| "DATABASE_ERROR")?
        .map(|raw| {
            serde_json::from_str(&raw)
                .map(|op| (raw, op))
                .map_err(|_| "INVALID_MIGRATION_STATE".into())
        })
        .transpose()
}
pub async fn group_held(
    db: &dyn Repository,
    group: i64,
) -> Result<bool, crate::db::error::DbError> {
    let raw = db.get(SINGLETON).await?;
    let op = raw
        .map(|r| {
            serde_json::from_str::<Operation>(&r).map_err(|_| {
                crate::db::error::DbError::Other(sqlx::Error::Protocol(
                    "invalid migration state".into(),
                ))
            })
        })
        .transpose()?;
    Ok(op.is_some_and(|o| o.active() && o.memberships.contains(&group)))
}
pub async fn retired(
    db: &dyn Repository,
    group: i64,
    node: &str,
) -> Result<bool, crate::db::error::DbError> {
    Ok(db
        .get(&format!("legacy_v130_upgrade:retired:{group}:{node}"))
        .await?
        .is_some())
}

async fn store(
    db: &dyn Repository,
    expected: Option<String>,
    op: &Operation,
) -> Result<(), String> {
    let operation = serde_json::to_string(op).map_err(|_| "INVALID_MIGRATION_STATE")?;
    if !db
        .commit_legacy_upgrade(&LegacyUpgradeCommit {
            expected_operation: expected,
            operation_id: op.id.clone(),
            operation,
            routing: vec![],
            replacement: None,
            rollback: None,
        })
        .await
        .map_err(|_| "DATABASE_ERROR")?
    {
        return Err("MIGRATION_STATE_CHANGED".into());
    }
    Ok(())
}
fn ip(raw: &serde_json::Value) -> Option<String> {
    raw.get("public_ipv4")
        .or_else(|| raw.get("public_ip"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| a.to_string())
}
async fn status(
    db: &dyn Repository,
    identity: &ConcreteNodeIdentity,
) -> Result<serde_json::Value, String> {
    let raw = db
        .get(&format!(
            "node_status:{}:{}",
            identity.home_group_id, identity.node_id
        ))
        .await
        .map_err(|_| "DATABASE_ERROR")?
        .ok_or("NODE_STATUS_MISSING")?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|_| "INVALID_NODE_STATUS")?;
    let seen = value
        .get("last_seen")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or("NODE_OFFLINE")?;
    if chrono::Utc::now().signed_duration_since(seen).num_seconds() > 60 {
        return Err("NODE_OFFLINE".into());
    }
    Ok(value)
}

pub fn listener_snapshot(
    listeners: &[super::node_reuse::EffectiveConfigPreviewListener],
) -> Result<serde_json::Value, String> {
    let mut values = serde_json::to_value(listeners)
        .map_err(|_| "SNAPSHOT_INVALID")?
        .as_array()
        .ok_or("SNAPSHOT_INVALID")?
        .clone();
    values.sort_by_key(|v| (v["source_group_id"].as_i64(), v["rule_id"].as_i64()));
    Ok(serde_json::Value::Array(values))
}

pub async fn start(
    state: &AppState,
    admin: i64,
    old: ConcreteNodeIdentity,
    probes: Vec<Probe>,
    official_hash: &str,
) -> Result<Operation, String> {
    if !state.config.node_reuse_runtime_enabled {
        return Err("POOL_NATIVE_RUNTIME_REQUIRED".into());
    }
    if official_hash != OFFICIAL_AMD64_SHA256 {
        return Err("OFFICIAL_V130_BINARY_REQUIRED".into());
    }
    crate::node_identity::ReuseEligibleNodeId::parse(&old.node_id)
        .map_err(|_| "INVALID_NODE_ID")?;
    let _gate = MUTATIONS.write().await;
    let _authority = crate::service::relay_failover::lock_automatic_policy().await;
    let _preference = crate::service::relay_preference::RELAY_PREFERENCE_MUTATION_LOCK
        .lock()
        .await;
    let previous = load(state.db.as_ref()).await?;
    if previous.as_ref().is_some_and(|(_, o)| o.active()) {
        return Err("MIGRATION_IN_PROGRESS".into());
    }
    if retired(state.db.as_ref(), old.home_group_id, &old.node_id)
        .await
        .map_err(|_| "DATABASE_ERROR")?
    {
        return Err("ALREADY_MIGRATED".into());
    }
    let observed = status(state.db.as_ref(), &old).await?;
    if observed["node_version"] != "1.3.0" || observed["architecture"] != "x86_64" {
        return Err("OFFICIAL_V130_AMD64_REQUIRED".into());
    }
    let address = ip(&observed).ok_or("PUBLIC_IPV4_REQUIRED")?;
    if state
        .node_operations
        .has_active_for_node(old.home_group_id, &old.node_id)
        || crate::api::node_ops::has_active_durable_uninstall(
            state,
            old.home_group_id,
            &old.node_id,
        )
        .await
        .map_err(|_| "DATABASE_ERROR")?
        || crate::api::node_batch_upgrade::active_batch(state)
            .await
            .map_err(|_| "DATABASE_ERROR")?
            .is_some()
        || state.deployments.has_active_for_host(&address).await
    {
        return Err("RELATED_LIFECYCLE_OPERATION_ACTIVE".into());
    }

    // Match the old runtime's authenticated delivery scope. A legacy Bearer
    // report receives Home-only config; inactive or unused reuse authority
    // must not turn its migration snapshot into new business memberships.
    let (source_group_ids, listeners, has_conflicts) =
        if observed["verified_concrete_node"].as_bool() == Some(true) {
            let preview = super::node_reuse::preview_effective_config_for_node(
                state.db.as_ref(),
                old.home_group_id,
                &old.node_id,
            )
            .await
            .map_err(|_| "EFFECTIVE_CONFIG_UNAVAILABLE")?;
            (
                preview.source_group_ids,
                preview.listeners,
                !preview.conflicts.is_empty(),
            )
        } else {
            let config = super::node_config::build_node_config_for_node(
                state.db.as_ref(),
                old.home_group_id,
                Some(&old.node_id),
            )
            .await
            .map_err(|_| "EFFECTIVE_CONFIG_UNAVAILABLE")?;
            let listeners = config
                .listeners
                .into_iter()
                .map(|l| super::node_reuse::EffectiveConfigPreviewListener {
                    source_group_id: old.home_group_id,
                    rule_id: l.rule_id,
                    port: l.port,
                    protocol: l.protocol,
                    node_transport: l.node_transport,
                    sni: l.sni,
                    camouflage_required: l.camouflage_required,
                    send_proxy_protocol: l.send_proxy_protocol,
                    target_count: l.targets.len(),
                })
                .collect::<Vec<_>>();
            (vec![old.home_group_id], listeners, false)
        };
    if listeners.iter().any(|l| {
        l.protocol != relay_shared::protocol::Protocol::Tcp
            || !matches!(
                l.node_transport,
                relay_shared::protocol::NodeTransport::Raw
                    | relay_shared::protocol::NodeTransport::NginxSni
            )
    }) {
        return Err("SUPPORTED_HTTP_PROBE_LISTENERS_REQUIRED".into());
    }
    if has_conflicts || listeners.is_empty() {
        return Err("EXPECTED_LISTENERS_REQUIRED".into());
    }
    let wanted: BTreeSet<i64> = listeners.iter().map(|l| l.rule_id).collect();
    let supplied: BTreeSet<i64> = probes.iter().map(|p| p.rule_id).collect();
    if wanted != supplied
        || probes.len() != supplied.len()
        || probes.iter().any(|p| {
            !p.path.starts_with('/')
                || p.path.len() > 256
                || p.expected_marker.is_empty()
                || p.expected_marker.len() > 256
        })
    {
        return Err("FORWARDING_PROBES_REQUIRED_FOR_EVERY_RULE".into());
    }
    let records = state
        .db
        .list_node_pool_records()
        .await
        .map_err(|_| "DATABASE_ERROR")?;
    let record = records
        .into_iter()
        .find(|r| r.identity_group_id == old.home_group_id && r.node_id == old.node_id)
        .ok_or("NODE_IDENTITY_MISSING")?;
    let anchor = state
        .db
        .ensure_node_pool_system_group(admin, &uuid::Uuid::new_v4().to_string())
        .await
        .map_err(|_| "DATABASE_ERROR")?;
    let memberships: Vec<i64> = source_group_ids
        .iter()
        .copied()
        .filter(|g| *g != anchor.id)
        .collect();
    let mut routing = vec![];
    for group in &memberships {
        // Enabled automatic policies must be stopped by the operator first.
        let mode = super::relay_preference::get_routing_mode(state.db.as_ref(), *group)
            .await
            .map_err(|_| "ROUTING_UNAVAILABLE")?;
        if !matches!(
            mode.active_mode,
            Some(
                super::relay_preference::RoutingMode::Carrier
                    | super::relay_preference::RoutingMode::Normal
            )
        ) {
            return Err("DISABLE_AUTOMATIC_ROUTING_BEFORE_MIGRATION".into());
        }
        if mode.transition_state != super::relay_preference::RelayPreferencePhase::Idle {
            return Err("ROUTING_TRANSACTION_ACTIVE".into());
        }
        let key = format!("relay_preference:{group}");
        if let Some(raw) = state.db.get(&key).await.map_err(|_| "DATABASE_ERROR")? {
            routing.push((key, raw));
        }
        let group_nodes =
            super::node_reuse::reused_concrete_nodes_for_group(state.db.as_ref(), *group)
                .await
                .map_err(|_| "DATABASE_ERROR")?;
        if group_nodes
            .iter()
            .any(|n| n.node_id == old.node_id && n.home_group_id != old.home_group_id)
        {
            return Err("AMBIGUOUS_NODE_ID".into());
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let mut op = Operation {
        id: id.clone(),
        state: "PRECHECK".into(),
        old,
        new: ConcreteNodeIdentity {
            home_group_id: anchor.id,
            node_id: uuid::Uuid::new_v4().to_string(),
        },
        public_ipv4: address,
        display_name: record.display_name,
        memberships,
        listeners: listener_snapshot(&listeners)?,
        routing,
        dns: vec![],
        probes,
        token_hash: hash(token(state, &id).as_bytes()),
        created_by: admin,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_error: None,
        rollback_after: None,
    };
    store(state.db.as_ref(), previous.map(|(raw, _)| raw), &op).await?;
    drop(_preference);
    drop(_authority);
    drop(_gate);
    let raw = serde_json::to_string(&op).map_err(|_| "SNAPSHOT_INVALID")?;
    match snapshot_dns(state.db.as_ref(), &op).await {
        Ok(dns) => {
            op.dns = dns;
            op.state = "PREPARED".into();
            store(state.db.as_ref(), Some(raw), &op).await?;
            Ok(op)
        }
        Err(error) => {
            op.state = "FAILED_PRECHECK".into();
            op.last_error = Some(error.clone());
            store(state.db.as_ref(), Some(raw), &op).await?;
            Err(error)
        }
    }
}

pub async fn snapshot_dns(db: &dyn Repository, op: &Operation) -> Result<Vec<DnsSnapshot>, String> {
    use super::dnsmgr::{self, LineRecordSnapshot};
    let ids: BTreeSet<i64> = op
        .listeners
        .as_array()
        .ok_or("SNAPSHOT_INVALID")?
        .iter()
        .filter_map(|l| l["rule_id"].as_i64())
        .collect();
    let eligible: Vec<_> = db
        .list_rules(&ResourceScope::All)
        .await
        .map_err(|_| "DATABASE_ERROR")?
        .into_iter()
        .filter(|r| ids.contains(&r.id) && dnsmgr::rule_is_dns_eligible(r))
        .collect();
    if eligible.is_empty() {
        return Ok(vec![]);
    }
    let client = dnsmgr::load_client(db)
        .await
        .map_err(|_| "PROVIDER_READ_FAILURE")?
        .ok_or("DNS_PROVIDER_REQUIRED")?;
    let mut snapshots = vec![];
    for rule in eligible {
        let mut lines = BTreeSet::from(["__default__".to_string()]);
        if let Some((_, raw)) = op
            .routing
            .iter()
            .find(|(k, _)| k == &format!("relay_preference:{}", rule.device_group_in))
        {
            let p: super::relay_preference::RelayPreferenceState =
                serde_json::from_str(raw).map_err(|_| "SNAPSHOT_INVALID")?;
            lines.extend(p.carrier_policy.bindings.iter().map(|b| b.line_id.clone()));
        }
        for line in lines {
            let observed = if line == "__default__" {
                dnsmgr::inspect_default_line_record_for_transaction(db, &client, rule.id).await
            } else {
                dnsmgr::inspect_line_record(db, &client, rule.id, &line).await
            }
            .map_err(|_| "PROVIDER_READ_FAILURE_OR_UNOWNED_RECORD")?;
            match observed {
                LineRecordSnapshot::PanelOwned { value, record_id } => {
                    snapshots.push(DnsSnapshot {
                        rule_id: rule.id,
                        line,
                        value,
                        record_id,
                    })
                }
                _ => return Err("PANEL_OWNED_DNS_REQUIRED".into()),
            }
        }
    }
    Ok(snapshots)
}

pub async fn restore(
    state: &AppState,
    raw: String,
    mut op: Operation,
) -> Result<Operation, String> {
    let _gate = MUTATIONS.write().await;
    if !matches!(op.state.as_str(), "PREPARED" | "RESTORED") {
        return Err("MIGRATION_ALREADY_TERMINAL".into());
    }
    if load(state.db.as_ref()).await?.map(|(current, _)| current) != Some(raw.clone()) {
        return Err("MIGRATION_STATE_CHANGED".into());
    }
    if op.committed() || op.state == "ROLLED_BACK" {
        return Err("MIGRATION_ALREADY_TERMINAL".into());
    }
    let observed = status(state.db.as_ref(), &op.new).await?;
    if observed["public_ipv4_reported"] != true {
        return Err("PUBLIC_IPV4_NOT_REPORTED".into());
    }
    if !state
        .node_connections
        .config_online_node_ids(op.new.home_group_id)
        .await
        .contains(&op.new.node_id)
    {
        return Err("NODE_OFFLINE".into());
    }
    if ip(&observed).as_deref() != Some(&op.public_ipv4) {
        return Err("PUBLIC_IP_MISMATCH".into());
    }
    if state
        .db
        .find_current_active_node_credential_for_identity(
            op.new.home_group_id,
            &crate::node_identity::ReuseEligibleNodeId::parse(&op.new.node_id)
                .map_err(|_| "INVALID_NODE_ID")?,
        )
        .await
        .map_err(|_| "DATABASE_ERROR")?
        .is_none()
    {
        return Err("NEW_CREDENTIAL_NOT_ACTIVE".into());
    }
    for group in &op.memberships {
        super::node_reuse::create_binding(
            state.db.as_ref(),
            *group,
            op.new.home_group_id,
            &op.new.node_id,
        )
        .await
        .map_err(|_| "MEMBERSHIP_RESTORE_FAILED")?;
    }
    state
        .db
        .rename_node_pool_node(op.new.home_group_id, &op.new.node_id, &op.display_name)
        .await
        .map_err(|_| "DATABASE_ERROR")?;
    state
        .node_connections
        .broadcast_all(r#"{"type":"config_changed"}"#)
        .await;
    op.state = "RESTORED".into();
    store(state.db.as_ref(), Some(raw), &op).await?;
    Ok(op)
}

pub async fn ready(state: &AppState, op: &Operation) -> Result<String, String> {
    if !state
        .node_connections
        .config_online_node_ids(op.new.home_group_id)
        .await
        .contains(&op.new.node_id)
    {
        return Err("NODE_OFFLINE".into());
    }
    let observed = status(state.db.as_ref(), &op.new).await?;
    if observed["public_ipv4_reported"] != true {
        return Err("PUBLIC_IPV4_NOT_REPORTED".into());
    }
    if ip(&observed).as_deref() != Some(&op.public_ipv4) {
        return Err("PUBLIC_IP_MISMATCH".into());
    }
    let credential = state
        .db
        .find_current_active_node_credential_for_identity(
            op.new.home_group_id,
            &crate::node_identity::ReuseEligibleNodeId::parse(&op.new.node_id)
                .map_err(|_| "INVALID_NODE_ID")?,
        )
        .await
        .map_err(|_| "DATABASE_ERROR")?
        .ok_or("NEW_CREDENTIAL_NOT_ACTIVE")?;
    let preview = super::node_reuse::preview_effective_config_for_node(
        state.db.as_ref(),
        op.new.home_group_id,
        &op.new.node_id,
    )
    .await
    .map_err(|_| "EFFECTIVE_CONFIG_UNAVAILABLE")?;
    if listener_snapshot(&preview.listeners)? != op.listeners || !preview.conflicts.is_empty() {
        return Err("EFFECTIVE_RULES_CHANGED".into());
    }
    let planned = super::node_config::plan_effective_config_snapshot_for_status(
        state.db.as_ref(),
        std::path::Path::new(&state.config.certificate_state_dir()),
        op.new.home_group_id,
        &op.new.node_id,
    )
    .await
    .map_err(|_| "EFFECTIVE_CONFIG_NOT_CONVERGED")?;
    let rec = &observed["reconciliation"];
    if !planned.authority_committed
        || rec["applied_config_revision"].as_u64() != Some(planned.snapshot.config_revision)
        || rec["applied_fingerprint"].as_str() != Some(planned.snapshot.config_fingerprint.as_str())
    {
        return Err("EFFECTIVE_CONFIG_NOT_CONVERGED".into());
    }
    if rec["state"] != "CONVERGED"
        || rec["desired_config_revision"] != rec["applied_config_revision"]
        || rec["desired_fingerprint"] != rec["applied_fingerprint"]
        || rec["applied_fingerprint"]
            .as_str()
            .is_none_or(|s| s.is_empty())
    {
        return Err("EFFECTIVE_CONFIG_NOT_CONVERGED".into());
    }
    let expected: BTreeSet<i64> = op
        .listeners
        .as_array()
        .ok_or("SNAPSHOT_INVALID")?
        .iter()
        .filter_map(|l| l["rule_id"].as_i64())
        .collect();
    let active: BTreeSet<i64> = observed["active_listener_rule_ids"]
        .as_array()
        .ok_or("LISTENERS_NOT_READY")?
        .iter()
        .filter_map(|l| l.as_i64())
        .collect();
    if active != expected
        || observed["listener_errors"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    {
        return Err("LISTENERS_NOT_READY".into());
    }
    Ok(credential.credential_id)
}

pub async fn probe(state: &AppState, op: &Operation) -> Result<(), String> {
    for spec in &op.probes {
        let l = op
            .listeners
            .as_array()
            .and_then(|ls| {
                ls.iter()
                    .find(|l| l["rule_id"].as_i64() == Some(spec.rule_id))
            })
            .ok_or("PROBE_RULE_MISSING")?;
        if l["protocol"].as_str() != Some("tcp") {
            return Err("HTTP_FORWARDING_PROBE_REQUIRES_TCP".into());
        }
        let port = l["port"].as_u64().ok_or("SNAPSHOT_INVALID")? as u16;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(4));
        let url = if l["node_transport"].as_str() == Some("nginx_sni") {
            let sni = l["sni"].as_str().ok_or("SNI_REQUIRED")?;
            builder = builder.resolve(
                sni,
                std::net::SocketAddr::new(
                    op.public_ipv4.parse().map_err(|_| "PUBLIC_IPV4_REQUIRED")?,
                    port,
                ),
            );
            format!("https://{sni}:{port}{}", spec.path)
        } else {
            format!("http://{}:{port}{}", op.public_ipv4, spec.path)
        };
        let response = builder
            .build()
            .map_err(|_| "FORWARDING_PROBE_FAILED")?
            .get(url)
            .send()
            .await
            .map_err(|_| "FORWARDING_PROBE_FAILED")?;
        if !response.status().is_success() {
            return Err("FORWARDING_PROBE_FAILED".into());
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| "FORWARDING_PROBE_FAILED")?;
        if body.len() > 65536
            || !body
                .windows(spec.expected_marker.len())
                .any(|w| w == spec.expected_marker.as_bytes())
        {
            return Err("FORWARDING_MARKER_MISMATCH".into());
        }
    }
    let _ = state;
    Ok(())
}

pub fn replace_carrier(raw: &str, old: &str, new: &str) -> Result<String, String> {
    let mut v: serde_json::Value = serde_json::from_str(raw).map_err(|_| "SNAPSHOT_INVALID")?;
    for field in ["preferred_node_id", "normal_default_node_id"] {
        if v[field].as_str() == Some(old) {
            v[field] = new.into();
        }
    }
    if v["carrier_policy"]["default_node_id"].as_str() == Some(old) {
        v["carrier_policy"]["default_node_id"] = new.into();
    }
    if let Some(bindings) = v["carrier_policy"]["bindings"].as_array_mut() {
        for b in bindings {
            if b["node_id"].as_str() == Some(old) {
                b["node_id"] = new.into();
            }
        }
    }
    serde_json::to_string(&v).map_err(|_| "SNAPSHOT_INVALID".into())
}

pub async fn finalize(
    state: &AppState,
    raw: String,
    mut op: Operation,
) -> Result<Operation, String> {
    if op.state == "SUCCESS" {
        return Ok(op);
    }
    if !op.committed() {
        if op.state != "RESTORED" {
            return Err("MEMBERSHIPS_NOT_RESTORED".into());
        }
        let credential = ready(state, &op).await?;
        probe(state, &op).await?;
        let _gate = MUTATIONS.write().await;
        let _authority = super::relay_failover::lock_automatic_policy().await;
        let _preference = super::relay_preference::RELAY_PREFERENCE_MUTATION_LOCK
            .lock()
            .await;
        let _schedule = super::relay_schedule::RELAY_SCHEDULE_MUTATION_LOCK
            .lock()
            .await;
        let _failover = super::relay_failover::FAILOVER_MUTATION_LOCK.lock().await;
        ready(state, &op).await?;
        let routing = op
            .routing
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    v.clone(),
                    replace_carrier(v, &op.old.node_id, &op.new.node_id)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        op.state = "COMMITTED".into();
        let change = LegacyUpgradeCommit {
            expected_operation: Some(raw),
            operation_id: op.id.clone(),
            operation: serde_json::to_string(&op).map_err(|_| "SNAPSHOT_INVALID")?,
            routing,
            replacement: Some(LegacyUpgradeReplacement {
                old: op.old.clone(),
                new: op.new.clone(),
                new_credential_id: credential,
                memberships: op.memberships.clone(),
            }),
            rollback: None,
        };
        if !state
            .db
            .commit_legacy_upgrade(&change)
            .await
            .map_err(|_| "FINALIZE_TRANSACTION_FAILED")?
        {
            return Err("MIGRATION_SNAPSHOT_CHANGED".into());
        }
        state
            .node_connections
            .close_node(op.old.home_group_id, &op.old.node_id)
            .await;
    }
    // Read-back only. No identity rollback is allowed beyond COMMITTED.
    let (raw, current) = load(state.db.as_ref())
        .await?
        .ok_or("MIGRATION_STATE_MISSING")?;
    if current.id != op.id {
        return Err("MIGRATION_STATE_CHANGED".into());
    }
    let after = snapshot_dns(state.db.as_ref(), &op).await?;
    if serde_json::to_value(after).map_err(|_| "SNAPSHOT_INVALID")?
        != serde_json::to_value(&op.dns).map_err(|_| "SNAPSHOT_INVALID")?
    {
        return Err("DNS_RECORDS_CHANGED_NEEDS_ATTENTION".into());
    }
    op.state = "SUCCESS".into();
    store(state.db.as_ref(), Some(raw), &op).await?;
    Ok(op)
}

pub async fn begin_rollback(
    state: &AppState,
    raw: String,
    mut op: Operation,
) -> Result<Operation, String> {
    let _gate = MUTATIONS.write().await;
    if op.committed() {
        return Err("POINT_OF_NO_RETURN".into());
    }
    if matches!(op.state.as_str(), "ROLLED_BACK" | "ROLLBACK_PENDING") {
        return Ok(op);
    }
    op.rollback_after = Some(chrono::Utc::now().to_rfc3339());
    op.state = "ROLLBACK_PENDING".into();
    store(state.db.as_ref(), Some(raw), &op).await?;
    Ok(op)
}

fn recovered_report(op: &Operation, observed: &serde_json::Value) -> Result<(), String> {
    let after = op
        .rollback_after
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or("ROLLBACK_NOT_REQUESTED")?;
    let seen = observed["last_seen"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or("OLD_RUNTIME_NOT_RECOVERED")?;
    if seen <= after {
        return Err("OLD_RUNTIME_NOT_RECOVERED".into());
    }
    Ok(())
}

pub async fn abort(state: &AppState, raw: String, mut op: Operation) -> Result<Operation, String> {
    let _gate = MUTATIONS.write().await;
    if op.committed() {
        return Err("POINT_OF_NO_RETURN".into());
    }
    if op.state == "ROLLED_BACK" {
        return Ok(op);
    }
    let observed = status(state.db.as_ref(), &op.old).await?;
    recovered_report(&op, &observed)?;
    if !state
        .node_connections
        .config_online_node_ids(op.old.home_group_id)
        .await
        .contains(&op.old.node_id)
    {
        return Err("OLD_RUNTIME_NOT_RECOVERED".into());
    }
    probe(state, &op).await?;
    if ip(&observed).as_deref() != Some(&op.public_ipv4) {
        return Err("OLD_RUNTIME_NOT_RECOVERED".into());
    }
    op.state = "ROLLED_BACK".into();
    let change = LegacyUpgradeCommit {
        expected_operation: Some(raw),
        operation_id: op.id.clone(),
        operation: serde_json::to_string(&op).map_err(|_| "SNAPSHOT_INVALID")?,
        routing: vec![],
        replacement: None,
        rollback: Some(op.new.clone()),
    };
    if !state
        .db
        .commit_legacy_upgrade(&change)
        .await
        .map_err(|_| "STAGED_IDENTITY_CLEANUP_FAILED")?
    {
        return Err("MIGRATION_STATE_CHANGED".into());
    }
    state
        .node_connections
        .close_node(op.new.home_group_id, &op.new.node_id)
        .await;
    Ok(op)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::repo::{KvsRepository, NodePoolRepository, NodeReuseRepository};
    pub(crate) async fn fixture() -> AppState {
        use std::sync::Arc;
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        for g in [10_i64, 20] {
            sqlx::query(
                "INSERT INTO device_groups(id,name,group_type,token,uid) VALUES (?,?,'in',?,1)",
            )
            .bind(g)
            .bind(format!("group-{g}"))
            .bind(format!("token-{g}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO node_credentials(credential_id,home_group_id,node_id,generation,verifier_format,verifier_version,verifier_data,activated_at) VALUES ('legacy-credential',10,'OLD_NODE',1,'rp-node-sha256',1,?,datetime('now'))").bind(vec![9_u8;32]).execute(&pool).await.unwrap();
        for (id, g, port) in [(100_i64, 10_i64, 45100_i64), (200, 20, 45200)] {
            sqlx::query("INSERT INTO forward_rules(id,name,uid,listen_port,device_group_in,target_addr,target_port) VALUES (?, ?, 1, ?, ?, '127.0.0.1', 8080)").bind(id).bind(format!("rule-{id}")).bind(port).bind(g).execute(&pool).await.unwrap();
        }
        let db = Arc::new(crate::db::sqlite_repo::SqliteRepository::new(pool));
        db.insert_node_reuse_binding(20, 10, "OLD_NODE")
            .await
            .unwrap();
        db.register_node_pool_identity(10, "OLD_NODE")
            .await
            .unwrap();
        db.set("node_status:10:OLD_NODE",&serde_json::json!({"last_seen":chrono::Utc::now().to_rfc3339(),"public_ipv4":"192.0.2.1","node_version":"1.3.0","architecture":"x86_64","verified_concrete_node":true}).to_string()).await.unwrap();
        AppState {
            db,
            config: crate::config::Config {
                database_path: "test".into(),
                listen: "127.0.0.1:0".into(),
                key: "test".into(),
                jwt_secret: "test-only".into(),
                public_dir: "public".into(),
                public_panel_url: "https://test.example.com".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604800,
                node_reuse_runtime_enabled: true,
            },
            release_cache: crate::api::system::ReleaseCache::new(),
            node_connections: crate::api::ws::NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }
    fn probes() -> Vec<Probe> {
        vec![100, 200]
            .into_iter()
            .map(|id| Probe {
                rule_id: id,
                path: "/marker".into(),
                expected_marker: format!("G{id}"),
            })
            .collect()
    }
    #[tokio::test]
    async fn legacy_bearer_snapshot_preserves_only_delivered_home_rules() {
        // Both no credential and an unused exact credential still deliver
        // Home-only config when the authenticated report is legacy Bearer.
        for revoke in [true, false] {
            let state = fixture().await;
            let old = ConcreteNodeIdentity {
                home_group_id: 10,
                node_id: "OLD_NODE".into(),
            };
            if revoke {
                state
                    .db
                    .revoke_node_credential(
                        "legacy-credential",
                        10,
                        &crate::node_identity::ReuseEligibleNodeId::parse("OLD_NODE").unwrap(),
                        1,
                    )
                    .await
                    .unwrap();
            }
            let raw = state
                .db
                .get("node_status:10:OLD_NODE")
                .await
                .unwrap()
                .unwrap();
            let mut report: serde_json::Value = serde_json::from_str(&raw).unwrap();
            report["verified_concrete_node"] = false.into();
            state
                .db
                .set("node_status:10:OLD_NODE", &report.to_string())
                .await
                .unwrap();
            let delivered = super::super::node_config::build_node_config_for_node(
                state.db.as_ref(),
                10,
                Some("OLD_NODE"),
            )
            .await
            .unwrap();
            assert_eq!(delivered.listeners.len(), 1);
            assert_eq!(delivered.listeners[0].rule_id, 100);
            assert_eq!(
                state
                    .db
                    .list_reusing_group_ids_for_node(10, "OLD_NODE")
                    .await
                    .unwrap(),
                vec![20]
            );
            let op = start(
                &state,
                1,
                old,
                vec![Probe {
                    rule_id: 100,
                    path: "/marker".into(),
                    expected_marker: "G100".into(),
                }],
                OFFICIAL_AMD64_SHA256,
            )
            .await
            .unwrap();
            assert_eq!(op.state, "PREPARED");
            assert_eq!(op.memberships, vec![10]);
            let listeners = op.listeners.as_array().unwrap();
            assert_eq!(listeners.len(), 1);
            assert_eq!(listeners[0]["rule_id"], 100);
            assert_eq!(listeners[0]["source_group_id"], 10);
            if revoke {
                assert!(matches!(super::super::node_reuse::preview_effective_config_for_node(
                    state.db.as_ref(), 10, "OLD_NODE").await,
                    Err(super::super::node_reuse::NodeReuseServiceError::AdmissionRejected(
                        crate::db::repo::NodeReuseBindingCreateRejection::ActiveCredentialMissing))));
            }
        }
    }

    #[tokio::test]
    async fn snapshot_multi_group_single_active_and_rollback() {
        let state = fixture().await;
        let op = start(
            &state,
            1,
            ConcreteNodeIdentity {
                home_group_id: 10,
                node_id: "OLD_NODE".into(),
            },
            probes(),
            OFFICIAL_AMD64_SHA256,
        )
        .await
        .unwrap();
        assert_eq!(op.state, "PREPARED");
        assert_eq!(op.memberships, vec![10, 20]);
        assert_eq!(op.listeners.as_array().unwrap().len(), 2);
        assert!(group_held(state.db.as_ref(), 10).await.unwrap());
        assert!(!group_held(state.db.as_ref(), 30).await.unwrap());
        assert_eq!(
            start(
                &state,
                1,
                ConcreteNodeIdentity {
                    home_group_id: 10,
                    node_id: "SECOND_NODE".into()
                },
                probes(),
                OFFICIAL_AMD64_SHA256
            )
            .await
            .unwrap_err(),
            "MIGRATION_IN_PROGRESS"
        );
        assert_eq!(ready(&state, &op).await.unwrap_err(), "NODE_OFFLINE");
        let (raw, op) = load(state.db.as_ref()).await.unwrap().unwrap();
        assert_eq!(
            abort(&state, raw.clone(), op.clone()).await.unwrap_err(),
            "ROLLBACK_NOT_REQUESTED"
        );
        let waiting = begin_rollback(&state, raw, op).await.unwrap();
        assert_eq!(waiting.state, "ROLLBACK_PENDING");
        let before = state
            .db
            .get("node_status:10:OLD_NODE")
            .await
            .unwrap()
            .unwrap();
        let observed = serde_json::from_str(&before).unwrap();
        assert_eq!(
            recovered_report(&waiting, &observed).unwrap_err(),
            "OLD_RUNTIME_NOT_RECOVERED"
        );
        assert!(
            group_held(state.db.as_ref(), 10).await.unwrap(),
            "keep singleton held until real old recovery"
        );
        assert_eq!(
            state
                .db
                .list_reusing_group_ids_for_node(10, "OLD_NODE")
                .await
                .unwrap(),
            vec![20]
        );
        let fresh = serde_json::json!({"last_seen":chrono::Utc::now().to_rfc3339()});
        assert!(recovered_report(&waiting, &fresh).is_ok());
    }
    #[tokio::test]
    async fn unknown_artifact_and_incomplete_forwarding_probes_do_not_start() {
        let state = fixture().await;
        let old = ConcreteNodeIdentity {
            home_group_id: 10,
            node_id: "OLD_NODE".into(),
        };
        assert_eq!(
            start(&state, 1, old.clone(), probes(), "unknown")
                .await
                .unwrap_err(),
            "OFFICIAL_V130_BINARY_REQUIRED"
        );
        assert_eq!(
            start(&state, 1, old, vec![], OFFICIAL_AMD64_SHA256)
                .await
                .unwrap_err(),
            "FORWARDING_PROBES_REQUIRED_FOR_EVERY_RULE"
        );
        assert!(load(state.db.as_ref()).await.unwrap().is_none());
    }
    #[test]
    fn carrier_replace_preserves_history_other_nodes_and_lines() {
        let before = serde_json::json!({"preferred_node_id":"OLD","normal_default_node_id":"OLD","last_from_node_id":"OLD","last_to_node_id":"OLD","carrier_policy":{"default_node_id":"OLD","bindings":[{"line_id":"Liantong","node_id":"OLD","mode":"node"},{"line_id":"Liantong","node_id":"OTHER","mode":"node"},{"line_id":"Dianxin","node_id":"OLD","mode":"node"}]}});
        let after: serde_json::Value =
            serde_json::from_str(&replace_carrier(&before.to_string(), "OLD", "NEW").unwrap())
                .unwrap();
        assert_eq!(after["carrier_policy"]["default_node_id"], "NEW");
        assert_eq!(after["carrier_policy"]["bindings"][0]["node_id"], "NEW");
        assert_eq!(after["carrier_policy"]["bindings"][1]["node_id"], "OTHER");
        assert_eq!(after["carrier_policy"]["bindings"][2]["node_id"], "NEW");
        assert_eq!(after["normal_default_node_id"], "NEW");
        assert_eq!(after["last_from_node_id"], "OLD");
        assert_eq!(after["last_to_node_id"], "OLD");
        assert_eq!(
            replace_carrier(&after.to_string(), "OLD", "NEW").unwrap(),
            after.to_string(),
            "replacement is idempotent"
        );
        let ips = |v: &serde_json::Value| {
            v["carrier_policy"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| {
                    if b["node_id"] == "OTHER" {
                        "192.0.2.2"
                    } else {
                        "192.0.2.1"
                    }
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            ips(&before),
            ips(&after),
            "same IP replacement leaves DNS desired set unchanged"
        );
    }
    #[test]
    fn listener_snapshot_canonicalizes_multi_group_order() {
        use super::super::node_reuse::EffectiveConfigPreviewListener as L;
        use relay_shared::protocol::{NodeTransport, Protocol};
        let l = |group, rule| L {
            source_group_id: group,
            rule_id: rule,
            port: 44000 + rule as u16,
            protocol: Protocol::Tcp,
            node_transport: NodeTransport::Raw,
            sni: None,
            camouflage_required: false,
            send_proxy_protocol: false,
            target_count: 1,
        };
        let one = vec![l(20, 2), l(10, 1)];
        let two = vec![l(10, 1), l(20, 2)];
        assert_eq!(
            listener_snapshot(&one).unwrap(),
            listener_snapshot(&two).unwrap()
        );
        assert_ne!(
            listener_snapshot(&one).unwrap(),
            listener_snapshot(&[l(10, 1)]).unwrap()
        );
    }
    #[test]
    fn public_ipv4_requires_exact_v4_and_normalizes() {
        assert_eq!(
            ip(&serde_json::json!({"public_ipv4":"192.0.2.1"})),
            Some("192.0.2.1".into())
        );
        assert_eq!(ip(&serde_json::json!({"public_ipv4":"::1"})), None);
        assert_eq!(ip(&serde_json::json!({"public_ipv4":"hostname"})), None);
    }
}
