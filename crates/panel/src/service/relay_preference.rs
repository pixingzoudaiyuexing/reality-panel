//! Panel-side Relay preference and readiness for Reality inbound groups.
//!
//! This module evaluates Relay readiness and owns the persisted preference
//! transaction. DNS mutation remains in the existing DNSMgr reconciliation
//! worker; this service only schedules and finalizes that persisted work.

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

/// The Panel is a single process. Serializing short preference mutations keeps
/// initialization, manual switching, DNS finalization, and deletion coherent
/// without adding database or distributed lock machinery.
static RELAY_PREFERENCE_MUTATION_LOCK: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayPreferencePhase {
    Idle,
    Switching,
    Failed,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDnsTarget {
    NotSet,
    Resolved(String),
    Frozen,
    Invalid(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRelaySwitchOutcome {
    Started {
        from_node_id: Option<String>,
        to_node_id: String,
    },
    AlreadyPreferred,
    AlreadySwitching,
}

#[derive(Debug)]
pub enum StartRelaySwitchError {
    Database(DbError),
    InvalidPreference(serde_json::Error),
    InboundGroupNotFound,
    NodeNotInGroup,
    TargetNotReady(Vec<String>),
    TargetPublicIpv4Invalid,
    DnsMgrUnavailable,
    NoEligibleDnsRules,
    SwitchInProgress { pending_node_id: Option<String> },
    DnsSchedulingFailed(DbError),
}

impl std::fmt::Display for StartRelaySwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::InvalidPreference(error) => write!(f, "invalid relay preference: {error}"),
            Self::InboundGroupNotFound => write!(f, "inbound group not found"),
            Self::NodeNotInGroup => write!(f, "target node does not belong to this group"),
            Self::TargetNotReady(reasons) => {
                write!(f, "target node is not ready: {}", reasons.join(","))
            }
            Self::TargetPublicIpv4Invalid => write!(f, "target node public IPv4 is invalid"),
            Self::DnsMgrUnavailable => write!(f, "DNSMgr is disabled or not configured"),
            Self::NoEligibleDnsRules => write!(f, "group has no eligible Reality DNS rules"),
            Self::SwitchInProgress { pending_node_id } => write!(
                f,
                "relay switch already in progress{}",
                pending_node_id
                    .as_deref()
                    .map(|node_id| format!(" to {node_id}"))
                    .unwrap_or_default()
            ),
            Self::DnsSchedulingFailed(error) => {
                write!(f, "failed to schedule group DNS reconciliation: {error}")
            }
        }
    }
}

impl std::error::Error for StartRelaySwitchError {}

impl From<DbError> for StartRelaySwitchError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
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

fn valid_public_ipv4(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    match value.parse::<Ipv4Addr>() {
        Ok(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip.to_string()),
        _ => None,
    }
}

async fn load_preference(
    db: &dyn Repository,
    group_id: i64,
) -> Result<RelayPreferenceState, RelayPreferenceError> {
    match db.get(&preference_key(group_id)).await? {
        Some(raw) => serde_json::from_str(&raw).map_err(RelayPreferenceError::InvalidPreference),
        None => Ok(RelayPreferenceState::default()),
    }
}

async fn store_preference(
    db: &dyn Repository,
    group_id: i64,
    preference: &RelayPreferenceState,
) -> Result<(), DbError> {
    db.set(
        &preference_key(group_id),
        &serde_json::to_string(preference).expect("relay preference is serializable"),
    )
    .await
}

async fn stored_node_public_ipv4(
    db: &dyn Repository,
    group_id: i64,
    node_id: &str,
) -> Result<RelayDnsTarget, DbError> {
    let Some(raw) = db.get(&format!("node_status:{group_id}:{node_id}")).await? else {
        return Ok(RelayDnsTarget::Invalid("RELAY_NODE_STATUS_MISSING"));
    };
    let Ok(status) = serde_json::from_str::<StoredNodeStatus>(&raw) else {
        return Ok(RelayDnsTarget::Invalid("RELAY_NODE_STATUS_INVALID"));
    };
    let public_ipv4 = status
        .public_ipv4
        .as_deref()
        .or(status.public_ip.as_deref());
    Ok(match valid_public_ipv4(public_ipv4) {
        Some(ip) => RelayDnsTarget::Resolved(ip),
        None => RelayDnsTarget::Invalid("INVALID_RELAY_IPV4"),
    })
}

/// Resolve the DNS target from the current persisted preference. IP addresses
/// are never copied into preference state; every call reads current telemetry.
pub async fn resolve_dns_target(
    db: &dyn Repository,
    group_id: i64,
) -> Result<RelayDnsTarget, DbError> {
    let Some(raw) = db.get(&preference_key(group_id)).await? else {
        return Ok(RelayDnsTarget::NotSet);
    };
    let preference = match serde_json::from_str::<RelayPreferenceState>(&raw) {
        Ok(preference) => preference,
        Err(_) => return Ok(RelayDnsTarget::Invalid("RELAY_PREFERENCE_INVALID")),
    };
    if preference.state == RelayPreferencePhase::Failed && preference.pending_node_id.is_some() {
        return Ok(RelayDnsTarget::Frozen);
    }
    let selected_node_id = if preference.state == RelayPreferencePhase::Switching {
        preference.pending_node_id.as_deref()
    } else {
        preference.preferred_node_id.as_deref()
    };
    match selected_node_id {
        Some(node_id) => stored_node_public_ipv4(db, group_id, node_id).await,
        None => Ok(RelayDnsTarget::NotSet),
    }
}

fn initialize_preference_if_unique_ready(
    preference: &mut RelayPreferenceState,
    ready_node_ids: &[String],
) -> bool {
    if preference.state == RelayPreferencePhase::Idle
        && preference.preferred_node_id.is_none()
        && preference.pending_node_id.is_none()
        && ready_node_ids.len() == 1
    {
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
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    if group.as_ref().map(|group| group.group_type.as_str()) != Some("in") {
        return Ok(RelayPreferenceState::default());
    }
    let mut preference = load_preference(db, group_id).await?;
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
        store_preference(db, group_id, &preference).await?;
    }

    Ok(preference)
}

pub async fn delete_relay_preference(db: &dyn Repository, group_id: i64) -> Result<(), DbError> {
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;
    db.delete(&preference_key(group_id)).await?;
    Ok(())
}

pub async fn start_relay_switch(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    target_node_id: &str,
) -> Result<StartRelaySwitchOutcome, StartRelaySwitchError> {
    let target_node_id = target_node_id.trim();
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;

    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    if group.as_ref().map(|group| group.group_type.as_str()) != Some("in") {
        return Err(StartRelaySwitchError::InboundGroupNotFound);
    }

    let mut preference = match load_preference(db, group_id).await {
        Ok(preference) => preference,
        Err(RelayPreferenceError::Database(error)) => {
            return Err(StartRelaySwitchError::Database(error))
        }
        Err(RelayPreferenceError::InvalidPreference(error)) => {
            return Err(StartRelaySwitchError::InvalidPreference(error))
        }
    };
    if preference.state == RelayPreferencePhase::Switching {
        if preference.pending_node_id.as_deref() == Some(target_node_id) {
            return Ok(StartRelaySwitchOutcome::AlreadySwitching);
        }
        return Err(StartRelaySwitchError::SwitchInProgress {
            pending_node_id: preference.pending_node_id,
        });
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id)
        .await
        .map_err(|error| match error {
            RelayPreferenceError::Database(error) => StartRelaySwitchError::Database(error),
            RelayPreferenceError::InvalidPreference(error) => {
                StartRelaySwitchError::InvalidPreference(error)
            }
        })?;
    let Some(target) = evaluated
        .iter()
        .find(|node| node.info.node_id == target_node_id)
    else {
        return Err(StartRelaySwitchError::NodeNotInGroup);
    };
    if valid_public_ipv4(target.public_ipv4.as_deref()).is_none() {
        return Err(StartRelaySwitchError::TargetPublicIpv4Invalid);
    }
    if !target.info.ready {
        return Err(StartRelaySwitchError::TargetNotReady(
            target.info.ready_reasons.clone(),
        ));
    }

    let settings = db
        .get(crate::service::dnsmgr::DNSMGR_CONFIG_KEY)
        .await?
        .map(|raw| crate::service::dnsmgr::DnsMgrSettings::from_json(Some(&raw)))
        .unwrap_or_default();
    if !settings.enabled || !settings.configured() {
        return Err(StartRelaySwitchError::DnsMgrUnavailable);
    }
    let eligible_rule_ids =
        crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id).await?;
    if eligible_rule_ids.is_empty() {
        return Err(StartRelaySwitchError::NoEligibleDnsRules);
    }

    if preference.state == RelayPreferencePhase::Idle
        && preference.preferred_node_id.as_deref() == Some(target_node_id)
    {
        return Ok(StartRelaySwitchOutcome::AlreadyPreferred);
    }

    let from_node_id = preference.preferred_node_id.clone();
    preference.pending_node_id = Some(target_node_id.to_string());
    preference.state = RelayPreferencePhase::Switching;
    preference.started_at = Some(Utc::now().to_rfc3339());
    preference.last_error = None;
    store_preference(db, group_id, &preference).await?;

    if let Err(error) =
        crate::service::dnsmgr::schedule_group_eligible(db, group_id, &eligible_rule_ids).await
    {
        preference.state = RelayPreferencePhase::Failed;
        preference.last_error = Some("DNS_SCHEDULING_FAILED".into());
        store_preference(db, group_id, &preference).await?;
        return Err(StartRelaySwitchError::DnsSchedulingFailed(error));
    }

    Ok(StartRelaySwitchOutcome::Started {
        from_node_id,
        to_node_id: target_node_id.to_string(),
    })
}

#[derive(Debug)]
enum FinalizeOutcome {
    Pending,
    Committed {
        from_node_id: Option<String>,
        to_node_id: String,
    },
    Failed {
        from_node_id: Option<String>,
        to_node_id: String,
        error: String,
    },
}

fn terminal_dns_error(sync: &crate::db::repo::DnsRecordSync) -> Option<String> {
    let terminal = match sync.state.as_str() {
        "CONFLICT" | "MUTATION_OUTCOME_UNKNOWN" | "DISABLED" | "NOT_ELIGIBLE" => true,
        "FAILED" => sync.next_attempt_at.is_none(),
        _ => false,
    };
    terminal.then(|| {
        sync.last_error_category
            .clone()
            .unwrap_or_else(|| format!("DNS_SYNC_{}", sync.state))
    })
}

async fn fail_switch(
    db: &dyn Repository,
    group_id: i64,
    mut preference: RelayPreferenceState,
    target_node_id: String,
    error: &str,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    preference.state = RelayPreferencePhase::Failed;
    preference.last_error = Some(error.to_string());
    store_preference(db, group_id, &preference).await?;
    Ok(FinalizeOutcome::Failed {
        from_node_id: preference.preferred_node_id,
        to_node_id: target_node_id,
        error: error.to_string(),
    })
}

async fn finalize_switching_group(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;
    let mut preference = load_preference(db, group_id).await?;
    if preference.state != RelayPreferencePhase::Switching {
        return Ok(FinalizeOutcome::Pending);
    }
    let Some(target_node_id) = preference.pending_node_id.clone() else {
        preference.state = RelayPreferencePhase::Failed;
        preference.last_error = Some("PENDING_NODE_MISSING".into());
        store_preference(db, group_id, &preference).await?;
        return Ok(FinalizeOutcome::Failed {
            from_node_id: preference.preferred_node_id,
            to_node_id: String::new(),
            error: "PENDING_NODE_MISSING".into(),
        });
    };
    let target_ipv4 = match stored_node_public_ipv4(db, group_id, &target_node_id).await? {
        RelayDnsTarget::Resolved(target_ipv4) => target_ipv4,
        RelayDnsTarget::Invalid("RELAY_NODE_STATUS_MISSING" | "RELAY_NODE_STATUS_INVALID") => {
            return fail_switch(
                db,
                group_id,
                preference,
                target_node_id,
                "TARGET_STATUS_UNAVAILABLE",
            )
            .await;
        }
        RelayDnsTarget::Invalid(_) | RelayDnsTarget::NotSet | RelayDnsTarget::Frozen => {
            return fail_switch(
                db,
                group_id,
                preference,
                target_node_id,
                "TARGET_PUBLIC_IPV4_UNAVAILABLE",
            )
            .await;
        }
    };

    let rule_ids = crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id).await?;
    if rule_ids.is_empty() {
        let error = "NO_ELIGIBLE_DNS_RULES".to_string();
        preference.state = RelayPreferencePhase::Failed;
        preference.last_error = Some(error.clone());
        store_preference(db, group_id, &preference).await?;
        return Ok(FinalizeOutcome::Failed {
            from_node_id: preference.preferred_node_id,
            to_node_id: target_node_id,
            error,
        });
    }

    for rule_id in rule_ids {
        let Some(sync) = db.find_dns_record_sync(rule_id).await? else {
            return Ok(FinalizeOutcome::Pending);
        };
        if sync.expected_value != target_ipv4 {
            return Ok(FinalizeOutcome::Pending);
        }
        if let Some(error) = terminal_dns_error(&sync) {
            preference.state = RelayPreferencePhase::Failed;
            preference.last_error = Some(error.clone());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::Failed {
                from_node_id: preference.preferred_node_id,
                to_node_id: target_node_id,
                error,
            });
        }
        if sync.state != "PROPAGATED" {
            return Ok(FinalizeOutcome::Pending);
        }
        if sync.last_error_category.as_deref() == Some("PUBLIC_DNS_MULTIPLE_ANSWERS") {
            let error = "PUBLIC_DNS_MULTIPLE_ANSWERS".to_string();
            preference.state = RelayPreferencePhase::Failed;
            preference.last_error = Some(error.clone());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::Failed {
                from_node_id: preference.preferred_node_id,
                to_node_id: target_node_id,
                error,
            });
        }
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;
    if !evaluated
        .iter()
        .any(|node| node.info.node_id == target_node_id && node.info.ready)
    {
        return fail_switch(
            db,
            group_id,
            preference,
            target_node_id,
            "TARGET_NOT_READY_AFTER_DNS",
        )
        .await;
    }

    let from_node_id = preference.preferred_node_id.clone();
    preference.preferred_node_id = Some(target_node_id.clone());
    preference.pending_node_id = None;
    preference.state = RelayPreferencePhase::Idle;
    preference.started_at = None;
    preference.last_error = None;
    store_preference(db, group_id, &preference).await?;
    Ok(FinalizeOutcome::Committed {
        from_node_id,
        to_node_id: target_node_id,
    })
}

/// Observe persisted DNS transactions after each DNS worker tick. This is also
/// restart recovery: switching preferences and sync rows are both durable.
pub async fn finalize_switching_preferences(state: &crate::api::AppState) {
    let rows = match state.db.scan_prefix(RELAY_PREFERENCE_KEY_PREFIX).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("relay preference finalizer scan failed: {}", error);
            return;
        }
    };
    for (key, raw) in rows {
        let Ok(preference) = serde_json::from_str::<RelayPreferenceState>(&raw) else {
            tracing::error!(
                "relay preference finalizer ignored invalid state at {}",
                key
            );
            continue;
        };
        if preference.state != RelayPreferencePhase::Switching {
            continue;
        }
        let Some(group_id) = key
            .strip_prefix(RELAY_PREFERENCE_KEY_PREFIX)
            .and_then(|value| value.parse::<i64>().ok())
        else {
            continue;
        };
        match finalize_switching_group(state.db.as_ref(), &state.node_connections, group_id).await {
            Ok(FinalizeOutcome::Committed {
                from_node_id,
                to_node_id,
            }) => {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_SWITCH_COMMITTED",
                    "device_group",
                    group_id,
                    &format!(
                        "group_id={} from_node_id={} to_node_id={}",
                        group_id,
                        from_node_id.as_deref().unwrap_or("none"),
                        to_node_id
                    ),
                )
                .await;
            }
            Ok(FinalizeOutcome::Failed {
                from_node_id,
                to_node_id,
                error,
            }) => {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_SWITCH_FAILED",
                    "device_group",
                    group_id,
                    &format!(
                        "group_id={} from_node_id={} to_node_id={} error={}",
                        group_id,
                        from_node_id.as_deref().unwrap_or("none"),
                        to_node_id,
                        error
                    ),
                )
                .await;
            }
            Ok(FinalizeOutcome::Pending) => {}
            Err(error) => tracing::error!(
                "relay preference finalizer failed for group {}: {}",
                group_id,
                error
            ),
        }
    }
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
    use crate::db::repo::{DnsRecordSyncRepository, KvsRepository};
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

    fn switch_status(ip: &str) -> String {
        status(serde_json::json!({
            "public_ipv4": ip,
            "active_listener_rule_ids": [1, 3],
            "camouflage_sites": [
                {
                    "site_id": "site-1",
                    "sni": "op1.example.com",
                    "site_status": "active",
                    "certificate_status": "active",
                    "line_type": "default"
                },
                {
                    "site_id": "site-3",
                    "sni": "op3.example.com",
                    "site_status": "active",
                    "certificate_status": "active",
                    "line_type": "default"
                }
            ]
        }))
    }

    fn evaluate(raw: &str, rules: &[ForwardRule], online: bool) -> RelayReadyNode {
        let ids = if online {
            HashSet::from(["node-a".to_string()])
        } else {
            HashSet::new()
        };
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

        let mut switching = RelayPreferenceState {
            pending_node_id: Some("node-b".into()),
            state: RelayPreferencePhase::Switching,
            ..RelayPreferenceState::default()
        };
        assert!(!initialize_preference_if_unique_ready(
            &mut switching,
            &["node-b".into()]
        ));
        assert_eq!(switching.preferred_node_id, None);
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
            .any(|node| node.node_id == "node-b" && node.ready && !node.preferred));
        connections.unregister(7, b_connection).await;
    }

    async fn switch_fixture() -> (
        crate::db::sqlite_repo::SqliteRepository,
        NodeConnections,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        use crate::db::schema::SCHEMA_SQL;
        use crate::db::sqlite_repo::SqliteRepository;
        use sqlx::sqlite::SqlitePoolOptions;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        for (id, name) in [(7_i64, "group-a"), (8_i64, "group-b")] {
            sqlx::query(
                "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
                 VALUES (?, ?, 'in', ?, 1, '')",
            )
            .bind(id)
            .bind(name)
            .bind(format!("token-{id}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        for (id, group_id, sni) in [
            (1_i64, 7_i64, "op1.example.com"),
            (2_i64, 8_i64, "op2.example.com"),
            (3_i64, 7_i64, "op3.example.com"),
        ] {
            sqlx::query(
                "INSERT INTO forward_rules \
                 (id, name, uid, listen_port, device_group_in, target_addr, target_port, \
                  public_transport, node_transport, protocol, sni, camouflage_enabled) \
                 VALUES (?, ?, 1, 443, ?, '198.51.100.2', 55443, \
                         'nginx_sni', 'nginx_sni', 'tcp', ?, 1)",
            )
            .bind(id)
            .bind(format!("rule-{id}"))
            .bind(group_id)
            .bind(sni)
            .execute(&pool)
            .await
            .unwrap();
        }

        let repo = SqliteRepository::new(pool);
        repo.set(
            crate::service::dnsmgr::DNSMGR_CONFIG_KEY,
            r#"{"enabled":true,"base_url":"http://127.0.0.1:9","uid":7,"api_key":"test-key"}"#,
        )
        .await
        .unwrap();
        repo.set("node_status:7:node-a", &switch_status("203.0.113.5"))
            .await
            .unwrap();
        for (node_id, ip) in [
            ("node-b", "203.0.113.6"),
            ("node-c", "203.0.113.7"),
            ("node-d", "203.0.113.8"),
        ] {
            repo.set(&format!("node_status:7:{node_id}"), &switch_status(ip))
                .await
                .unwrap();
        }
        repo.set(
            "node_status:8:other-node",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.9",
                "active_listener_rule_ids": [2],
                "camouflage_sites": [{
                    "site_id": "site-2",
                    "sni": "op2.example.com",
                    "site_status": "active",
                    "certificate_status": "active",
                    "line_type": "default"
                }]
            })),
        )
        .await
        .unwrap();
        store_preference(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();

        let connections = NodeConnections::new();
        let mut observed_rx = None;
        for node_id in ["node-a", "node-b", "node-c", "node-d"] {
            let (_, rx) = connections.register(7, Some(node_id.into())).await;
            if node_id == "node-a" {
                observed_rx = Some(rx);
            }
        }
        let (_, _rx) = connections.register(8, Some("other-node".into())).await;
        (repo, connections, observed_rx.unwrap())
    }

    async fn set_sync_state(
        db: &crate::db::sqlite_repo::SqliteRepository,
        rule_id: i64,
        state: &str,
        error: Option<&str>,
        next_attempt_at: Option<&str>,
    ) {
        let sync = db.find_dns_record_sync(rule_id).await.unwrap().unwrap();
        db.update_dns_record_sync_observation(
            &sync,
            &sync.state,
            state,
            &sync.ownership,
            sync.mutation_verified_at.as_deref(),
            sync.last_observed_at.as_deref(),
            (state == "PROPAGATED").then_some("2026-08-29T00:00:00Z"),
            error,
            sync.attempt_count,
            next_attempt_at,
            "2026-08-29T00:00:00Z",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn manual_switch_keeps_old_preferred_and_schedules_only_its_group() {
        let (repo, connections, mut observed_rx) = switch_fixture().await;
        let outcome = start_relay_switch(&repo, &connections, 7, "node-c")
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StartRelaySwitchOutcome::Started {
                from_node_id: Some("node-a".into()),
                to_node_id: "node-c".into(),
            }
        );
        let preference = load_preference(&repo, 7).await.unwrap();
        assert_eq!(preference.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(preference.pending_node_id.as_deref(), Some("node-c"));
        assert_eq!(preference.state, RelayPreferencePhase::Switching);
        let view = get_relay_preference(&repo, &connections, 7).await.unwrap();
        assert_eq!(view.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(view.pending_node_id.as_deref(), Some("node-c"));
        assert_eq!(view.state, RelayPreferencePhase::Switching);

        let sync = repo.find_dns_record_sync(1).await.unwrap().unwrap();
        assert_eq!(sync.expected_value, "203.0.113.7");
        assert_eq!(sync.state, "PENDING");
        assert_eq!(
            repo.find_dns_record_sync(3)
                .await
                .unwrap()
                .unwrap()
                .expected_value,
            "203.0.113.7"
        );
        assert!(repo.find_dns_record_sync(2).await.unwrap().is_none());
        assert!(matches!(
            observed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-d").await,
            Err(StartRelaySwitchError::SwitchInProgress { .. })
        ));
        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-c")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadySwitching
        );
    }

    #[tokio::test]
    async fn switch_preflight_failures_do_not_change_preference_or_dns() {
        let (repo, connections, _) = switch_fixture().await;
        repo.set(
            "node_status:7:node-b",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.6",
                "active_listener_rule_ids": [1, 3],
                "reconciliation": {
                "state": "APPLY_FAILED", "recovery_source": "NONE"
            }})),
        )
        .await
        .unwrap();
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-b").await,
            Err(StartRelaySwitchError::TargetNotReady(_))
        ));
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "other-node").await,
            Err(StartRelaySwitchError::NodeNotInGroup)
        ));
        let preference = load_preference(&repo, 7).await.unwrap();
        assert_eq!(preference.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(preference.pending_node_id, None);
        assert_eq!(preference.state, RelayPreferencePhase::Idle);
        assert!(repo.find_dns_record_sync(1).await.unwrap().is_none());

        repo.set("node_status:7:node-c", &switch_status("127.0.0.1"))
            .await
            .unwrap();
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::TargetPublicIpv4Invalid)
        ));
        repo.set("node_status:7:node-c", &switch_status("203.0.113.7"))
            .await
            .unwrap();

        repo.delete(crate::service::dnsmgr::DNSMGR_CONFIG_KEY)
            .await
            .unwrap();
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::DnsMgrUnavailable)
        ));
        assert!(repo.find_dns_record_sync(1).await.unwrap().is_none());

        repo.set(
            crate::service::dnsmgr::DNSMGR_CONFIG_KEY,
            r#"{"enabled":true,"base_url":"http://127.0.0.1:9","uid":7,"api_key":"test-key"}"#,
        )
        .await
        .unwrap();
        for rule_id in [1, 3] {
            crate::db::repo::RuleRepository::update_rule_fields(
                &repo,
                rule_id,
                &ResourceScope::All,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(false),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::NoEligibleDnsRules)
        ));
    }

    #[tokio::test]
    async fn strict_dns_finalizer_commits_only_exact_propagation_and_recovers_from_kvs() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Pending
        ));
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Pending
        ));
        set_sync_state(&repo, 3, "PROPAGATED", None, None).await;

        // This call models a restarted worker: it reconstructs everything from
        // persisted KVS/sync state plus the current WS/status telemetry.
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Committed { .. }
        ));
        let committed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(committed.preferred_node_id.as_deref(), Some("node-b"));
        assert_eq!(committed.pending_node_id, None);
        assert_eq!(committed.state, RelayPreferencePhase::Idle);
        assert_eq!(committed.started_at, None);
    }

    #[tokio::test]
    async fn multiple_answers_and_terminal_dns_failure_never_commit_pending_node() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        set_sync_state(
            &repo,
            1,
            "PROPAGATED",
            Some("PUBLIC_DNS_MULTIPLE_ANSWERS"),
            None,
        )
        .await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Failed { .. }
        ));
        let failed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(failed.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(failed.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(failed.state, RelayPreferencePhase::Failed);
        assert_eq!(
            failed.last_error.as_deref(),
            Some("PUBLIC_DNS_MULTIPLE_ANSWERS")
        );
        let frozen_multiple = repo.find_dns_record_sync(1).await.unwrap().unwrap();
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        assert_eq!(
            repo.find_dns_record_sync(1).await.unwrap().unwrap(),
            frozen_multiple
        );

        let retry = start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        assert!(matches!(retry, StartRelaySwitchOutcome::Started { .. }));
        set_sync_state(&repo, 1, "CONFLICT", Some("DNS_RECORD_CONFLICT"), None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Failed { .. }
        ));
        let terminal = load_preference(&repo, 7).await.unwrap();
        assert_eq!(terminal.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(terminal.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(terminal.last_error.as_deref(), Some("DNS_RECORD_CONFLICT"));
        let frozen_conflict = repo.find_dns_record_sync(1).await.unwrap().unwrap();
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        assert_eq!(
            repo.find_dns_record_sync(1).await.unwrap().unwrap(),
            frozen_conflict
        );

        let choose_c = start_relay_switch(&repo, &connections, 7, "node-c")
            .await
            .unwrap();
        assert!(matches!(choose_c, StartRelaySwitchOutcome::Started { .. }));
        let switching_c = load_preference(&repo, 7).await.unwrap();
        assert_eq!(switching_c.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(switching_c.pending_node_id.as_deref(), Some("node-c"));
        assert_eq!(switching_c.state, RelayPreferencePhase::Switching);
    }

    #[tokio::test]
    async fn failed_switch_requires_explicit_post_to_restore_the_old_preferred() {
        let (repo, connections, _) = switch_fixture().await;
        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-a")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadyPreferred
        );
        assert!(repo.find_dns_record_sync(1).await.unwrap().is_none());

        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        set_sync_state(&repo, 3, "PROPAGATED", None, None).await;
        repo.set(
            "node_status:7:node-b",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.6",
                "active_listener_rule_ids": [1, 3],
                "last_seen": (Utc::now()
                    - chrono::Duration::seconds(NODE_ONLINE_WINDOW_SECS + 1))
                    .to_rfc3339()
            })),
        )
        .await
        .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Failed { .. }
        ));
        let failed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(failed.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(failed.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(failed.state, RelayPreferencePhase::Failed);
        assert_eq!(
            failed.last_error.as_deref(),
            Some("TARGET_NOT_READY_AFTER_DNS")
        );
        let frozen_b = repo.find_dns_record_sync(1).await.unwrap().unwrap();
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        assert_eq!(
            repo.find_dns_record_sync(1).await.unwrap().unwrap(),
            frozen_b
        );

        let rollback = start_relay_switch(&repo, &connections, 7, "node-a")
            .await
            .unwrap();
        assert!(matches!(rollback, StartRelaySwitchOutcome::Started { .. }));
        let switching_a = load_preference(&repo, 7).await.unwrap();
        assert_eq!(switching_a.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(switching_a.pending_node_id.as_deref(), Some("node-a"));
        assert_eq!(switching_a.state, RelayPreferencePhase::Switching);
        assert_eq!(
            repo.find_dns_record_sync(1)
                .await
                .unwrap()
                .unwrap()
                .expected_value,
            "203.0.113.5"
        );
    }

    #[tokio::test]
    async fn missing_target_status_or_ip_fails_instead_of_staying_switching() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        repo.delete("node_status:7:node-b").await.unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Failed { .. }
        ));
        let missing_status = load_preference(&repo, 7).await.unwrap();
        assert_eq!(missing_status.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(missing_status.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(missing_status.state, RelayPreferencePhase::Failed);
        assert_eq!(
            missing_status.last_error.as_deref(),
            Some("TARGET_STATUS_UNAVAILABLE")
        );
        let frozen = repo.find_dns_record_sync(1).await.unwrap().unwrap();
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        assert_eq!(repo.find_dns_record_sync(1).await.unwrap().unwrap(), frozen);

        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        repo.set(
            "node_status:7:node-b",
            &status(serde_json::json!({
                "public_ipv4": null,
                "public_ip": null,
                "active_listener_rule_ids": [1, 3]
            })),
        )
        .await
        .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Failed { .. }
        ));
        let missing_ip = load_preference(&repo, 7).await.unwrap();
        assert_eq!(missing_ip.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(missing_ip.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(missing_ip.state, RelayPreferencePhase::Failed);
        assert_eq!(
            missing_ip.last_error.as_deref(),
            Some("TARGET_PUBLIC_IPV4_UNAVAILABLE")
        );
    }
}
