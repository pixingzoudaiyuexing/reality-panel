//! Panel-side Relay preference and readiness for Reality inbound groups.
//!
//! This module evaluates Relay readiness and owns the persisted preference
//! transaction. DNS mutation remains in the existing DNSMgr reconciliation
//! worker; this service only schedules and finalizes that persisted work.

use crate::api::stats::{parse_status_key, NODE_ONLINE_WINDOW_SECS};
use crate::api::ws::NodeConnections;
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope, RuleRepository};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use relay_shared::models::ForwardRule;
use relay_shared::protocol::{
    CamouflageSiteStatus, ListenerError, ReconciliationStatus, ReconciliationStatusState,
    CONFIG_PROTOCOL_VERSION,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
    RollingBack,
    Failed,
    FailedRolledBack,
    FailedManualIntervention,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CarrierLineMode {
    FollowDefault,
    Node,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierLineBinding {
    pub line_id: String,
    pub mode: CarrierLineMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierPolicy {
    #[serde(default)]
    pub bindings: Vec<CarrierLineBinding>,
}

#[allow(dead_code)] // RC9-S4 persisted model; consumed by the Carrier Policy API in S5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierPolicyValidationError {
    InvalidLineId,
    DuplicateLineId,
    UnexpectedNodeId,
    MissingNodeId,
}

impl CarrierPolicy {
    #[allow(dead_code)] // RC9-S4 persisted model; consumed by the Carrier Policy API in S5.
    pub fn normalize(mut self) -> Result<Self, CarrierPolicyValidationError> {
        let mut seen = BTreeSet::new();
        for binding in &mut self.bindings {
            if binding.line_id.is_empty()
                || binding.line_id != binding.line_id.trim()
                || binding.line_id.len() > 256
                || binding.line_id.chars().any(char::is_control)
            {
                return Err(CarrierPolicyValidationError::InvalidLineId);
            }
            if !seen.insert(binding.line_id.clone()) {
                return Err(CarrierPolicyValidationError::DuplicateLineId);
            }
            match binding.mode {
                CarrierLineMode::FollowDefault if binding.node_id.is_some() => {
                    return Err(CarrierPolicyValidationError::UnexpectedNodeId)
                }
                CarrierLineMode::FollowDefault => {}
                CarrierLineMode::Node => {
                    let Some(node_id) = binding.node_id.as_mut() else {
                        return Err(CarrierPolicyValidationError::MissingNodeId);
                    };
                    *node_id = node_id.trim().to_string();
                    if node_id.is_empty() {
                        return Err(CarrierPolicyValidationError::MissingNodeId);
                    }
                }
            }
        }
        self.bindings
            .sort_by(|left, right| left.line_id.cmp(&right.line_id));
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayTransactionKind {
    PreferredSwitch,
    CarrierPolicyApply,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RelayDnsAction {
    Upsert,
    Delete,
}

impl Default for RelayDnsAction {
    fn default() -> Self {
        Self::Upsert
    }
}

fn default_dns_line() -> String {
    crate::service::dnsmgr::DEFAULT_LINE_KEY.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayDnsTransactionRecord {
    pub rule_id: i64,
    pub fqdn: String,
    #[serde(default = "default_dns_line")]
    pub line_id: String,
    #[serde(default = "default_dns_line")]
    pub line_key: String,
    #[serde(default)]
    pub target_action: RelayDnsAction,
    #[serde(default)]
    pub target_value: Option<String>,
    #[serde(default)]
    pub rollback_action: RelayDnsAction,
    #[serde(default)]
    pub rollback_value: Option<String>,
    #[serde(default)]
    pub target_record_id: Option<String>,
    #[serde(default)]
    pub rollback_record_id: Option<String>,
    #[serde(default)]
    pub target_state: Option<String>,
    #[serde(default)]
    pub target_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelayPreferenceState {
    pub preferred_node_id: Option<String>,
    pub pending_node_id: Option<String>,
    pub state: RelayPreferencePhase,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub rollback_error: Option<String>,
    #[serde(default)]
    pub dns_records: Vec<RelayDnsTransactionRecord>,
    #[serde(default)]
    pub carrier_policy: CarrierPolicy,
    #[serde(default)]
    pub pending_carrier_policy: Option<CarrierPolicy>,
    #[serde(default)]
    pub transaction_kind: Option<RelayTransactionKind>,
}

#[derive(Deserialize)]
struct RelayPreferenceStateWire {
    preferred_node_id: Option<String>,
    pending_node_id: Option<String>,
    state: RelayPreferencePhase,
    started_at: Option<String>,
    last_error: Option<String>,
    #[serde(default)]
    rollback_error: Option<String>,
    #[serde(default)]
    dns_records: Vec<RelayDnsTransactionRecord>,
    #[serde(default)]
    carrier_policy: CarrierPolicy,
    #[serde(default)]
    pending_carrier_policy: Option<CarrierPolicy>,
    #[serde(default)]
    transaction_kind: Option<RelayTransactionKind>,
}

impl<'de> Deserialize<'de> for RelayPreferenceState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RelayPreferenceStateWire::deserialize(deserializer)?;
        let transaction_kind = wire.transaction_kind.or_else(|| {
            (wire.state != RelayPreferencePhase::Idle)
                .then_some(RelayTransactionKind::PreferredSwitch)
        });
        Ok(Self {
            preferred_node_id: wire.preferred_node_id,
            pending_node_id: wire.pending_node_id,
            state: wire.state,
            started_at: wire.started_at,
            last_error: wire.last_error,
            rollback_error: wire.rollback_error,
            dns_records: wire.dns_records,
            carrier_policy: wire.carrier_policy,
            pending_carrier_policy: wire.pending_carrier_policy,
            transaction_kind,
        })
    }
}

impl Default for RelayPreferenceState {
    fn default() -> Self {
        Self {
            preferred_node_id: None,
            pending_node_id: None,
            state: RelayPreferencePhase::Idle,
            started_at: None,
            last_error: None,
            rollback_error: None,
            dns_records: Vec::new(),
            carrier_policy: CarrierPolicy::default(),
            pending_carrier_policy: None,
            transaction_kind: None,
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
    pub rollback_error: Option<String>,
    pub dns_records: Vec<RelayDnsRecordView>,
    pub nodes: Vec<RelayReadyNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayDnsRecordPosition {
    Rollback,
    Target,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayDnsRecordView {
    pub rule_id: i64,
    pub fqdn: String,
    pub rollback_value: Option<String>,
    pub target_value: String,
    pub expected_value: Option<String>,
    pub sync_state: Option<String>,
    pub position: RelayDnsRecordPosition,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierAffinityTransactionView {
    pub kind: Option<RelayTransactionKind>,
    pub state: RelayPreferencePhase,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
    pub rollback_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierAffinityBindingView {
    pub line_id: String,
    pub mode: CarrierLineMode,
    pub node_id: Option<String>,
    pub effective_node_id: Option<String>,
    pub relay_health: Option<String>,
    pub catalog_available: bool,
    pub dns_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CarrierAffinityView {
    pub group_id: i64,
    pub default_node_id: Option<String>,
    pub active_policy: CarrierPolicy,
    pub pending_policy: Option<CarrierPolicy>,
    pub transaction: CarrierAffinityTransactionView,
    pub bindings: Vec<CarrierAffinityBindingView>,
    pub catalog_stale: bool,
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
    CarrierDnsPreflightFailed(String),
    NoEligibleDnsRules,
    SwitchInProgress { pending_node_id: Option<String> },
    DnsSchedulingFailed(DbError),
}

#[derive(Debug)]
pub enum CarrierPolicyApplyError {
    Database(DbError),
    InvalidPreference(serde_json::Error),
    InvalidPolicy(CarrierPolicyValidationError),
    InboundGroupNotFound,
    TransactionInProgress,
    CatalogUnavailable,
    CatalogStale,
    LineUnavailable(String),
    NodeNotInGroup(String),
    TargetNotReady {
        node_id: String,
        reasons: Vec<String>,
    },
    TargetPublicIpv4Invalid(String),
    DnsMgrUnavailable,
    ProviderPreflight(String),
    OwnershipUnverified {
        rule_id: i64,
        line_id: String,
    },
    DnsSchedulingFailed,
}

impl std::fmt::Display for CarrierPolicyApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::InvalidPreference(error) => write!(f, "invalid relay preference: {error}"),
            Self::InvalidPolicy(error) => write!(f, "invalid carrier policy: {error:?}"),
            Self::InboundGroupNotFound => write!(f, "inbound group not found"),
            Self::TransactionInProgress => write!(f, "topology transaction already in progress"),
            Self::CatalogUnavailable => write!(f, "carrier line catalog is unavailable"),
            Self::CatalogStale => write!(f, "carrier line catalog is stale"),
            Self::LineUnavailable(line_id) => write!(f, "carrier line is unavailable: {line_id}"),
            Self::NodeNotInGroup(node_id) => {
                write!(f, "target node does not belong to this group: {node_id}")
            }
            Self::TargetNotReady { node_id, reasons } => write!(
                f,
                "target node is not ready: {node_id}:{}",
                reasons.join(",")
            ),
            Self::TargetPublicIpv4Invalid(node_id) => {
                write!(f, "target node public IPv4 is invalid: {node_id}")
            }
            Self::DnsMgrUnavailable => write!(f, "DNSMgr is disabled or not configured"),
            Self::ProviderPreflight(error) => write!(f, "DNS provider preflight failed: {error}"),
            Self::OwnershipUnverified { rule_id, line_id } => write!(
                f,
                "DNS ownership could not be verified for rule {rule_id} line {line_id}"
            ),
            Self::DnsSchedulingFailed => write!(f, "failed to schedule carrier DNS transaction"),
        }
    }
}

impl std::error::Error for CarrierPolicyApplyError {}

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
            Self::CarrierDnsPreflightFailed(error) => {
                write!(f, "carrier DNS preflight failed: {error}")
            }
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

impl From<DbError> for CarrierPolicyApplyError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

impl From<RelayPreferenceError> for CarrierPolicyApplyError {
    fn from(error: RelayPreferenceError) -> Self {
        match error {
            RelayPreferenceError::Database(error) => Self::Database(error),
            RelayPreferenceError::InvalidPreference(error) => Self::InvalidPreference(error),
        }
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
        if !matching_site.is_some_and(|site| {
            matches!(
                site.certificate_status.as_str(),
                "active" | "renewal_warning"
            )
        }) {
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

pub(crate) async fn dns_transaction_authorizes(
    db: &dyn Repository,
    rule_id: i64,
    fqdn: &str,
    line_key: &str,
    action: &str,
    value: Option<&str>,
) -> Result<bool, DbError> {
    let Some(rule) = RuleRepository::find_rule_by_id(db, rule_id, &ResourceScope::All).await?
    else {
        return Ok(false);
    };
    let Some(raw) = db.get(&preference_key(rule.device_group_in)).await? else {
        return Ok(false);
    };
    let Ok(preference) = serde_json::from_str::<RelayPreferenceState>(&raw) else {
        return Ok(false);
    };
    if preference.transaction_kind.is_none()
        || !matches!(
            preference.state,
            RelayPreferencePhase::Switching | RelayPreferencePhase::RollingBack
        )
    {
        return Ok(false);
    }
    Ok(preference.dns_records.iter().any(|record| {
        if record.rule_id != rule_id || record.fqdn != fqdn || record.line_key != line_key {
            return false;
        }
        let (expected_action, expected_value) =
            if preference.state == RelayPreferencePhase::RollingBack {
                (record.rollback_action, record.rollback_value.as_deref())
            } else {
                (record.target_action, record.target_value.as_deref())
            };
        let expected_action = match expected_action {
            RelayDnsAction::Upsert => "UPSERT",
            RelayDnsAction::Delete => "DELETE",
        };
        expected_action == action && expected_value == value
    }))
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
    resolve_dns_target_for_rule(db, group_id, None).await
}

pub async fn resolve_dns_target_for_rule(
    db: &dyn Repository,
    group_id: i64,
    rule_id: Option<i64>,
) -> Result<RelayDnsTarget, DbError> {
    let Some(raw) = db.get(&preference_key(group_id)).await? else {
        return Ok(RelayDnsTarget::NotSet);
    };
    let preference = match serde_json::from_str::<RelayPreferenceState>(&raw) {
        Ok(preference) => preference,
        Err(_) => return Ok(RelayDnsTarget::Invalid("RELAY_PREFERENCE_INVALID")),
    };
    let selected_node_id = match preference.state {
        RelayPreferencePhase::Switching
            if preference.transaction_kind == Some(RelayTransactionKind::CarrierPolicyApply) =>
        {
            preference.preferred_node_id.as_deref()
        }
        RelayPreferencePhase::Switching => {
            if let Some(value) = rule_id
                .and_then(|rule_id| {
                    preference.dns_records.iter().find(|record| {
                        record.rule_id == rule_id
                            && record.line_key == crate::service::dnsmgr::DEFAULT_LINE_KEY
                            && record.target_action == RelayDnsAction::Upsert
                    })
                })
                .and_then(|record| record.target_value.as_deref())
            {
                return Ok(match valid_public_ipv4(Some(value)) {
                    Some(value) => RelayDnsTarget::Resolved(value),
                    None => RelayDnsTarget::Invalid("TARGET_VALUE_UNAVAILABLE"),
                });
            }
            preference.pending_node_id.as_deref()
        }
        RelayPreferencePhase::RollingBack
            if preference.transaction_kind == Some(RelayTransactionKind::CarrierPolicyApply) =>
        {
            preference.preferred_node_id.as_deref()
        }
        RelayPreferencePhase::RollingBack => {
            let rollback_value = rule_id
                .and_then(|rule_id| {
                    preference.dns_records.iter().find(|record| {
                        record.rule_id == rule_id
                            && record.line_key == crate::service::dnsmgr::DEFAULT_LINE_KEY
                            && record.rollback_action == RelayDnsAction::Upsert
                    })
                })
                .and_then(|record| record.rollback_value.as_deref());
            return Ok(match valid_public_ipv4(rollback_value) {
                Some(value) => RelayDnsTarget::Resolved(value),
                None => RelayDnsTarget::Invalid("ROLLBACK_VALUE_UNAVAILABLE"),
            });
        }
        RelayPreferencePhase::Failed
        | RelayPreferencePhase::FailedRolledBack
        | RelayPreferencePhase::FailedManualIntervention => return Ok(RelayDnsTarget::Frozen),
        RelayPreferencePhase::Idle => preference.preferred_node_id.as_deref(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CarrierPolicyChange {
    line_id: String,
    old: Option<CarrierLineBinding>,
    new: Option<CarrierLineBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierPolicyApplyOutcome {
    NoChange,
    Started,
    CommittedWithoutDns,
}

fn carrier_policy_diff(
    active: &CarrierPolicy,
    requested: &CarrierPolicy,
) -> Vec<CarrierPolicyChange> {
    let active = active
        .bindings
        .iter()
        .map(|binding| (binding.line_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let requested = requested
        .bindings
        .iter()
        .map(|binding| (binding.line_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    active
        .keys()
        .chain(requested.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|line_id| {
            let old = active.get(line_id).map(|binding| (*binding).clone());
            let new = requested.get(line_id).map(|binding| (*binding).clone());
            (old != new).then(|| CarrierPolicyChange {
                line_id: line_id.to_string(),
                old,
                new,
            })
        })
        .collect()
}

async fn default_relay_value(
    db: &dyn Repository,
    group_id: i64,
    connect_host: &str,
    preferred_node_id: Option<&str>,
) -> Result<String, CarrierPolicyApplyError> {
    if let Some(node_id) = preferred_node_id {
        return match stored_node_public_ipv4(db, group_id, node_id).await? {
            RelayDnsTarget::Resolved(value) => Ok(value),
            RelayDnsTarget::NotSet | RelayDnsTarget::Frozen | RelayDnsTarget::Invalid(_) => Err(
                CarrierPolicyApplyError::TargetPublicIpv4Invalid(node_id.into()),
            ),
        };
    }
    valid_public_ipv4(Some(connect_host))
        .ok_or_else(|| CarrierPolicyApplyError::TargetPublicIpv4Invalid("default".into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CarrierLineDesired {
    pub line_id: String,
    pub action: RelayDnsAction,
    pub value: Option<String>,
}

pub(crate) async fn carrier_line_desired_for_rule(
    db: &dyn Repository,
    rule_id: i64,
) -> Result<Vec<CarrierLineDesired>, DbError> {
    let Some(rule) = RuleRepository::find_rule_by_id(db, rule_id, &ResourceScope::All).await?
    else {
        return Ok(Vec::new());
    };
    if !crate::service::dnsmgr::rule_is_dns_eligible(&rule) {
        return Ok(Vec::new());
    }
    let Some(group) = GroupRepository::find_by_id(db, rule.device_group_in, &ResourceScope::All)
        .await?
        .filter(|group| group.group_type == "in")
    else {
        return Ok(Vec::new());
    };
    let preference = match db.get(&preference_key(rule.device_group_in)).await? {
        Some(raw) => match serde_json::from_str::<RelayPreferenceState>(&raw) {
            Ok(preference) => preference,
            Err(_) => return Ok(Vec::new()),
        },
        None => RelayPreferenceState::default(),
    };
    let default_value =
        match resolve_dns_target_for_rule(db, rule.device_group_in, Some(rule_id)).await? {
            RelayDnsTarget::Resolved(value) => valid_public_ipv4(Some(&value)),
            RelayDnsTarget::NotSet => valid_public_ipv4(Some(&group.connect_host)),
            RelayDnsTarget::Frozen | RelayDnsTarget::Invalid(_) => None,
        };

    let mut desired = BTreeMap::new();
    let mut configured_lines = HashSet::new();
    for binding in &preference.carrier_policy.bindings {
        configured_lines.insert(binding.line_id.clone());
        let value = match binding.mode {
            CarrierLineMode::FollowDefault => default_value.clone(),
            CarrierLineMode::Node => match binding.node_id.as_deref() {
                Some(node_id) => {
                    match stored_node_public_ipv4(db, rule.device_group_in, node_id).await? {
                        RelayDnsTarget::Resolved(value) => Some(value),
                        RelayDnsTarget::NotSet
                        | RelayDnsTarget::Frozen
                        | RelayDnsTarget::Invalid(_) => None,
                    }
                }
                None => None,
            },
        };
        if let Some(value) = value {
            desired.insert(
                binding.line_id.clone(),
                CarrierLineDesired {
                    line_id: binding.line_id.clone(),
                    action: RelayDnsAction::Upsert,
                    value: Some(value),
                },
            );
        }
    }

    if preference.transaction_kind.is_some()
        && matches!(
            preference.state,
            RelayPreferencePhase::Switching | RelayPreferencePhase::RollingBack
        )
    {
        for record in preference.dns_records.iter().filter(|record| {
            record.rule_id == rule_id && record.line_key != crate::service::dnsmgr::DEFAULT_LINE_KEY
        }) {
            configured_lines.insert(record.line_id.clone());
            let (action, value) = if preference.state == RelayPreferencePhase::RollingBack {
                (record.rollback_action, record.rollback_value.clone())
            } else {
                (record.target_action, record.target_value.clone())
            };
            desired.insert(
                record.line_id.clone(),
                CarrierLineDesired {
                    line_id: record.line_id.clone(),
                    action,
                    value,
                },
            );
        }
    }

    for sync in db.list_dns_record_syncs_for_rule(rule_id).await? {
        if sync.line_key == crate::service::dnsmgr::DEFAULT_LINE_KEY
            || configured_lines.contains(&sync.line)
        {
            continue;
        }
        desired.insert(
            sync.line.clone(),
            CarrierLineDesired {
                line_id: sync.line,
                action: RelayDnsAction::Delete,
                value: None,
            },
        );
    }
    Ok(desired.into_values().collect())
}

fn carrier_binding_target(
    binding: &CarrierLineBinding,
    default_value: Option<&str>,
    default_node_id: Option<&str>,
    evaluated: &[EvaluatedNode],
) -> Result<(Option<String>, String), CarrierPolicyApplyError> {
    match binding.mode {
        CarrierLineMode::FollowDefault => {
            let default_value = default_value.expect("FollowDefault preflight resolved default");
            if let Some(node_id) = default_node_id {
                let Some(node) = evaluated
                    .iter()
                    .find(|candidate| candidate.info.node_id == node_id)
                else {
                    return Err(CarrierPolicyApplyError::NodeNotInGroup(node_id.into()));
                };
                if !node.info.ready {
                    return Err(CarrierPolicyApplyError::TargetNotReady {
                        node_id: node_id.into(),
                        reasons: node.info.ready_reasons.clone(),
                    });
                }
            }
            Ok((
                default_node_id.map(str::to_string),
                default_value.to_string(),
            ))
        }
        CarrierLineMode::Node => {
            let node_id = binding
                .node_id
                .as_deref()
                .expect("normalized Node binding has node_id");
            let Some(node) = evaluated
                .iter()
                .find(|candidate| candidate.info.node_id == node_id)
            else {
                return Err(CarrierPolicyApplyError::NodeNotInGroup(node_id.into()));
            };
            let Some(value) = valid_public_ipv4(node.public_ipv4.as_deref()) else {
                return Err(CarrierPolicyApplyError::TargetPublicIpv4Invalid(
                    node_id.into(),
                ));
            };
            if !node.info.ready {
                return Err(CarrierPolicyApplyError::TargetNotReady {
                    node_id: node_id.into(),
                    reasons: node.info.ready_reasons.clone(),
                });
            }
            Ok((Some(node_id.into()), value))
        }
    }
}

fn map_snapshot_error(
    rule_id: i64,
    line_id: &str,
    error: crate::service::dnsmgr::LineRecordSnapshotError,
) -> CarrierPolicyApplyError {
    use crate::service::dnsmgr::LineRecordSnapshotError;
    match error {
        LineRecordSnapshotError::Database => {
            CarrierPolicyApplyError::ProviderPreflight("database read failed".into())
        }
        LineRecordSnapshotError::OwnershipUnverified => {
            CarrierPolicyApplyError::OwnershipUnverified {
                rule_id,
                line_id: line_id.into(),
            }
        }
        LineRecordSnapshotError::Provider(error) => {
            CarrierPolicyApplyError::ProviderPreflight(error.to_string())
        }
        LineRecordSnapshotError::InvalidRule
        | LineRecordSnapshotError::InvalidLine
        | LineRecordSnapshotError::NoMatchingZone => CarrierPolicyApplyError::ProviderPreflight(
            format!("rule {rule_id} line {line_id} is no longer resolvable"),
        ),
    }
}

pub async fn start_carrier_policy_apply(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    requested: CarrierPolicy,
) -> Result<CarrierPolicyApplyOutcome, CarrierPolicyApplyError> {
    let requested = requested
        .normalize()
        .map_err(CarrierPolicyApplyError::InvalidPolicy)?;
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    let Some(group) = group.filter(|group| group.group_type == "in") else {
        return Err(CarrierPolicyApplyError::InboundGroupNotFound);
    };
    let mut preference = load_preference(db, group_id)
        .await
        .map_err(|error| match error {
            RelayPreferenceError::Database(error) => CarrierPolicyApplyError::Database(error),
            RelayPreferenceError::InvalidPreference(error) => {
                CarrierPolicyApplyError::InvalidPreference(error)
            }
        })?;
    if matches!(
        preference.state,
        RelayPreferencePhase::Switching
            | RelayPreferencePhase::RollingBack
            | RelayPreferencePhase::FailedManualIntervention
    ) {
        return Err(CarrierPolicyApplyError::TransactionInProgress);
    }
    let changes = carrier_policy_diff(&preference.carrier_policy, &requested);
    if changes.is_empty() {
        return Ok(CarrierPolicyApplyOutcome::NoChange);
    }

    if changes.iter().any(|change| change.new.is_some()) {
        let catalog = crate::service::carrier_lines::group_catalog(db, group_id)
            .await
            .map_err(|_| CarrierPolicyApplyError::CatalogUnavailable)?;
        if catalog.stale {
            return Err(CarrierPolicyApplyError::CatalogStale);
        }
        let available = catalog
            .lines
            .into_iter()
            .map(|line| line.id)
            .collect::<HashSet<_>>();
        if let Some(change) = changes
            .iter()
            .find(|change| change.new.is_some() && !available.contains(&change.line_id))
        {
            return Err(CarrierPolicyApplyError::LineUnavailable(
                change.line_id.clone(),
            ));
        }
    }

    let eligible_rule_ids =
        crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id).await?;
    if eligible_rule_ids.is_empty() {
        preference.carrier_policy = requested;
        preference.pending_carrier_policy = None;
        preference.transaction_kind = None;
        preference.state = RelayPreferencePhase::Idle;
        preference.started_at = None;
        preference.last_error = None;
        preference.rollback_error = None;
        preference.dns_records.clear();
        store_preference(db, group_id, &preference).await?;
        return Ok(CarrierPolicyApplyOutcome::CommittedWithoutDns);
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id)
        .await
        .map_err(|error| match error {
            RelayPreferenceError::Database(error) => CarrierPolicyApplyError::Database(error),
            RelayPreferenceError::InvalidPreference(error) => {
                CarrierPolicyApplyError::InvalidPreference(error)
            }
        })?;
    let needs_default = changes.iter().any(|change| {
        change
            .new
            .as_ref()
            .is_some_and(|binding| binding.mode == CarrierLineMode::FollowDefault)
    });
    let default_value = if needs_default {
        Some(
            default_relay_value(
                db,
                group_id,
                &group.connect_host,
                preference.preferred_node_id.as_deref(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut targets = BTreeMap::new();
    for change in &changes {
        if let Some(binding) = change.new.as_ref() {
            let (_, value) = carrier_binding_target(
                binding,
                default_value.as_deref(),
                preference.preferred_node_id.as_deref(),
                &evaluated,
            )?;
            targets.insert(change.line_id.clone(), value);
        }
    }
    let client = crate::service::dnsmgr::load_client(db)
        .await
        .map_err(|error| CarrierPolicyApplyError::ProviderPreflight(error.to_string()))?
        .ok_or(CarrierPolicyApplyError::DnsMgrUnavailable)?;

    let mut records = Vec::with_capacity(changes.len() * eligible_rule_ids.len());
    for rule_id in &eligible_rule_ids {
        let rule = RuleRepository::find_rule_by_id(db, *rule_id, &ResourceScope::All)
            .await?
            .ok_or_else(|| {
                CarrierPolicyApplyError::ProviderPreflight(format!(
                    "eligible rule {rule_id} disappeared"
                ))
            })?;
        let fqdn = rule
            .sni
            .as_deref()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        for change in &changes {
            let snapshot =
                crate::service::dnsmgr::inspect_line_record(db, &client, *rule_id, &change.line_id)
                    .await
                    .map_err(|error| map_snapshot_error(*rule_id, &change.line_id, error))?;
            let (rollback_action, rollback_value, rollback_record_id) = match snapshot {
                crate::service::dnsmgr::LineRecordSnapshot::Absent => {
                    (RelayDnsAction::Delete, None, None)
                }
                crate::service::dnsmgr::LineRecordSnapshot::PanelOwned { value, record_id } => {
                    (RelayDnsAction::Upsert, Some(value), Some(record_id))
                }
            };
            let (target_action, target_value) = match change.new.as_ref() {
                Some(_) => (
                    RelayDnsAction::Upsert,
                    targets.get(&change.line_id).cloned(),
                ),
                None => (RelayDnsAction::Delete, None),
            };
            records.push(RelayDnsTransactionRecord {
                rule_id: *rule_id,
                fqdn: fqdn.clone(),
                line_id: change.line_id.clone(),
                line_key: format!("dnsmgr:{}", change.line_id),
                target_action,
                target_value,
                rollback_action,
                rollback_value,
                target_record_id: None,
                rollback_record_id,
                target_state: None,
                target_error: None,
            });
        }
    }

    preference.pending_node_id = None;
    preference.pending_carrier_policy = Some(requested);
    preference.transaction_kind = Some(RelayTransactionKind::CarrierPolicyApply);
    preference.state = RelayPreferencePhase::Switching;
    preference.started_at = Some(Utc::now().to_rfc3339());
    preference.last_error = None;
    preference.rollback_error = None;
    preference.dns_records = records;
    store_preference(db, group_id, &preference).await?;
    if schedule_transaction_records(db, &preference.dns_records, false)
        .await
        .is_err()
    {
        begin_carrier_rollback(db, group_id, preference, "DNS_SCHEDULING_FAILED").await?;
        return Err(CarrierPolicyApplyError::DnsSchedulingFailed);
    }
    Ok(CarrierPolicyApplyOutcome::Started)
}

async fn build_dns_transaction_records(
    db: &dyn Repository,
    group_id: i64,
    preference: &RelayPreferenceState,
    eligible_rule_ids: &[i64],
    target_value: &str,
) -> Result<Vec<RelayDnsTransactionRecord>, DbError> {
    let preferred_value = match preference.preferred_node_id.as_deref() {
        Some(node_id) => match stored_node_public_ipv4(db, group_id, node_id).await? {
            RelayDnsTarget::Resolved(value) => Some(value),
            _ => None,
        },
        None => None,
    };
    let mut records = Vec::with_capacity(eligible_rule_ids.len());
    for rule_id in eligible_rule_ids {
        let Some(rule) = RuleRepository::find_rule_by_id(db, *rule_id, &ResourceScope::All).await?
        else {
            continue;
        };
        let sync = db
            .find_dns_record_sync(*rule_id, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await?;
        let rollback_value = preferred_value.clone().or_else(|| {
            sync.as_ref()
                .filter(|sync| sync.state == "PROPAGATED")
                .and_then(|sync| valid_public_ipv4(sync.expected_value.as_deref()))
        });
        records.push(RelayDnsTransactionRecord {
            rule_id: *rule_id,
            fqdn: rule
                .sni
                .as_deref()
                .unwrap_or_default()
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            line_id: crate::service::dnsmgr::DEFAULT_LINE_KEY.into(),
            line_key: crate::service::dnsmgr::DEFAULT_LINE_KEY.into(),
            target_action: RelayDnsAction::Upsert,
            target_value: Some(target_value.to_string()),
            rollback_action: RelayDnsAction::Upsert,
            rollback_value,
            target_record_id: None,
            rollback_record_id: None,
            target_state: None,
            target_error: None,
        });
    }
    Ok(records)
}

async fn append_follow_default_transaction_records(
    db: &dyn Repository,
    client: &crate::integrations::dnsmgr::DnsMgrClient,
    carrier_policy: &CarrierPolicy,
    eligible_rule_ids: &[i64],
    target_value: &str,
    records: &mut Vec<RelayDnsTransactionRecord>,
) -> Result<(), StartRelaySwitchError> {
    let follow_lines = carrier_policy
        .bindings
        .iter()
        .filter(|binding| binding.mode == CarrierLineMode::FollowDefault)
        .map(|binding| binding.line_id.clone())
        .collect::<Vec<_>>();
    for rule_id in eligible_rule_ids {
        let Some(rule) = RuleRepository::find_rule_by_id(db, *rule_id, &ResourceScope::All).await?
        else {
            continue;
        };
        let fqdn = rule
            .sni
            .as_deref()
            .unwrap_or_default()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        for line_id in &follow_lines {
            let snapshot =
                crate::service::dnsmgr::inspect_line_record(db, client, *rule_id, line_id)
                    .await
                    .map_err(|error| {
                        StartRelaySwitchError::CarrierDnsPreflightFailed(format!(
                            "rule {rule_id} line {line_id}: {error:?}"
                        ))
                    })?;
            let (rollback_action, rollback_value, rollback_record_id) = match snapshot {
                crate::service::dnsmgr::LineRecordSnapshot::Absent => {
                    (RelayDnsAction::Delete, None, None)
                }
                crate::service::dnsmgr::LineRecordSnapshot::PanelOwned { value, record_id } => {
                    (RelayDnsAction::Upsert, Some(value), Some(record_id))
                }
            };
            records.push(RelayDnsTransactionRecord {
                rule_id: *rule_id,
                fqdn: fqdn.clone(),
                line_id: line_id.clone(),
                line_key: format!("dnsmgr:{line_id}"),
                target_action: RelayDnsAction::Upsert,
                target_value: Some(target_value.into()),
                rollback_action,
                rollback_value,
                target_record_id: None,
                rollback_record_id,
                target_state: None,
                target_error: None,
            });
        }
    }
    Ok(())
}

fn transition_to_rollback(preference: &mut RelayPreferenceState, error: &str) {
    preference.last_error = Some(error.to_string());
    if !preference.dns_records.is_empty()
        && preference
            .dns_records
            .iter()
            .all(|record| match record.rollback_action {
                RelayDnsAction::Upsert => record.rollback_value.is_some(),
                RelayDnsAction::Delete => record.rollback_value.is_none(),
            })
    {
        preference.state = RelayPreferencePhase::RollingBack;
        preference.rollback_error = None;
    } else {
        preference.state = RelayPreferencePhase::FailedManualIntervention;
        preference.rollback_error = Some("ROLLBACK_VALUE_UNAVAILABLE".into());
    }
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
    if matches!(
        preference.state,
        RelayPreferencePhase::Switching | RelayPreferencePhase::RollingBack
    ) {
        if preference.pending_node_id.as_deref() == Some(target_node_id) {
            return Ok(StartRelaySwitchOutcome::AlreadySwitching);
        }
        return Err(StartRelaySwitchError::SwitchInProgress {
            pending_node_id: preference.pending_node_id,
        });
    }
    if preference.state == RelayPreferencePhase::FailedManualIntervention {
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
    let Some(target_public_ipv4) = valid_public_ipv4(target.public_ipv4.as_deref()) else {
        return Err(StartRelaySwitchError::TargetPublicIpv4Invalid);
    };
    if !target.info.ready {
        return Err(StartRelaySwitchError::TargetNotReady(
            target.info.ready_reasons.clone(),
        ));
    }

    if preference.state == RelayPreferencePhase::Idle
        && preference.preferred_node_id.as_deref() == Some(target_node_id)
    {
        return Ok(StartRelaySwitchOutcome::AlreadyPreferred);
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

    let from_node_id = preference.preferred_node_id.clone();
    preference.dns_records = build_dns_transaction_records(
        db,
        group_id,
        &preference,
        &eligible_rule_ids,
        &target_public_ipv4,
    )
    .await?;
    if preference
        .carrier_policy
        .bindings
        .iter()
        .any(|binding| binding.mode == CarrierLineMode::FollowDefault)
    {
        let client = crate::service::dnsmgr::load_client(db)
            .await
            .map_err(|error| StartRelaySwitchError::CarrierDnsPreflightFailed(error.to_string()))?
            .ok_or(StartRelaySwitchError::DnsMgrUnavailable)?;
        append_follow_default_transaction_records(
            db,
            &client,
            &preference.carrier_policy,
            &eligible_rule_ids,
            &target_public_ipv4,
            &mut preference.dns_records,
        )
        .await?;
    }
    preference.pending_node_id = Some(target_node_id.to_string());
    preference.transaction_kind = Some(RelayTransactionKind::PreferredSwitch);
    preference.state = RelayPreferencePhase::Switching;
    preference.started_at = Some(Utc::now().to_rfc3339());
    preference.last_error = None;
    preference.rollback_error = None;
    store_preference(db, group_id, &preference).await?;

    if let Err(error) =
        crate::service::dnsmgr::schedule_group_eligible(db, group_id, &eligible_rule_ids).await
    {
        match begin_rollback(
            db,
            group_id,
            preference,
            target_node_id.to_string(),
            "DNS_SCHEDULING_FAILED",
        )
        .await
        {
            Ok(_) => {}
            Err(RelayPreferenceError::Database(rollback_error)) => {
                return Err(StartRelaySwitchError::Database(rollback_error))
            }
            Err(RelayPreferenceError::InvalidPreference(rollback_error)) => {
                return Err(StartRelaySwitchError::InvalidPreference(rollback_error))
            }
        }
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
    RollbackStarted {
        from_node_id: Option<String>,
        to_node_id: String,
        error: String,
    },
    Committed {
        from_node_id: Option<String>,
        to_node_id: String,
    },
    RolledBack {
        from_node_id: Option<String>,
        to_node_id: String,
        error: String,
    },
    ManualIntervention {
        from_node_id: Option<String>,
        to_node_id: String,
        error: String,
        rollback_error: String,
    },
}

fn terminal_dns_error(sync: &crate::db::repo::DnsRecordSync) -> Option<String> {
    let terminal = match sync.state.as_str() {
        "CONFLICT" | "MUTATION_OUTCOME_UNKNOWN" | "DISABLED" | "NOT_ELIGIBLE" => true,
        "FAILED" => sync.next_attempt_at.is_none(),
        _ => false,
    };
    terminal.then(|| match sync.last_error_category.as_deref() {
        Some("DNS_CONFLICT") => "DNS_RECORD_CONFLICT".into(),
        Some("MUTATION_UNKNOWN" | "POST_WRITE_NOT_VERIFIED") => "MUTATION_OUTCOME_UNKNOWN".into(),
        Some("DNSMGR_DISABLED") => "DISABLED".into(),
        Some(category) => category.to_string(),
        None => format!("DNS_SYNC_{}", sync.state),
    })
}

async fn capture_target_outcomes(
    db: &dyn Repository,
    preference: &mut RelayPreferenceState,
) -> Result<(), DbError> {
    for record in &mut preference.dns_records {
        if let Some(sync) = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?
        {
            record.target_state = Some(sync.state);
            record.target_error = sync.last_error_category;
            if record.target_action == RelayDnsAction::Upsert
                && record.target_state.as_deref() == Some("PROPAGATED")
            {
                record.target_record_id = db
                    .find_dns_record_binding_for_rule(
                        record.rule_id,
                        &record.fqdn,
                        "A",
                        &record.line_key,
                    )
                    .await?
                    .map(|binding| binding.record_id);
            }
        }
    }
    Ok(())
}

async fn schedule_transaction_records(
    db: &dyn Repository,
    records: &[RelayDnsTransactionRecord],
    rollback: bool,
) -> Result<(), ()> {
    for record in records {
        let (action, value) = if rollback {
            (record.rollback_action, record.rollback_value.as_deref())
        } else {
            (record.target_action, record.target_value.as_deref())
        };
        match action {
            RelayDnsAction::Upsert => {
                let Some(value) = value else {
                    return Err(());
                };
                crate::service::dnsmgr::schedule_transaction_line(
                    db,
                    record.rule_id,
                    &record.fqdn,
                    &record.line_id,
                    "UPSERT",
                    Some(value),
                )
                .await
                .map_err(|_| ())?;
            }
            RelayDnsAction::Delete => {
                if value.is_some() {
                    return Err(());
                }
                crate::service::dnsmgr::schedule_transaction_line(
                    db,
                    record.rule_id,
                    &record.fqdn,
                    &record.line_id,
                    "DELETE",
                    None,
                )
                .await
                .map_err(|_| ())?;
            }
        }
    }
    Ok(())
}

async fn begin_carrier_rollback(
    db: &dyn Repository,
    group_id: i64,
    mut preference: RelayPreferenceState,
    error: &str,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    capture_target_outcomes(db, &mut preference).await?;
    transition_to_rollback(&mut preference, error);
    if preference.state != RelayPreferencePhase::RollingBack {
        store_preference(db, group_id, &preference).await?;
        return Ok(FinalizeOutcome::ManualIntervention {
            from_node_id: preference.preferred_node_id.clone(),
            to_node_id: String::new(),
            error: error.into(),
            rollback_error: preference
                .rollback_error
                .clone()
                .unwrap_or_else(|| "ROLLBACK_PLAN_UNAVAILABLE".into()),
        });
    }
    store_preference(db, group_id, &preference).await?;
    if schedule_transaction_records(db, &preference.dns_records, true)
        .await
        .is_err()
    {
        preference.state = RelayPreferencePhase::FailedManualIntervention;
        preference.rollback_error = Some("ROLLBACK_SCHEDULING_FAILED".into());
        store_preference(db, group_id, &preference).await?;
        return Ok(FinalizeOutcome::ManualIntervention {
            from_node_id: preference.preferred_node_id,
            to_node_id: String::new(),
            error: error.into(),
            rollback_error: "ROLLBACK_SCHEDULING_FAILED".into(),
        });
    }
    Ok(FinalizeOutcome::RollbackStarted {
        from_node_id: preference.preferred_node_id,
        to_node_id: String::new(),
        error: error.into(),
    })
}

async fn begin_rollback(
    db: &dyn Repository,
    group_id: i64,
    mut preference: RelayPreferenceState,
    target_node_id: String,
    error: &str,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    capture_target_outcomes(db, &mut preference).await?;
    transition_to_rollback(&mut preference, error);
    let outcome = if preference.state == RelayPreferencePhase::RollingBack {
        FinalizeOutcome::RollbackStarted {
            from_node_id: preference.preferred_node_id.clone(),
            to_node_id: target_node_id,
            error: error.to_string(),
        }
    } else {
        FinalizeOutcome::ManualIntervention {
            from_node_id: preference.preferred_node_id.clone(),
            to_node_id: target_node_id,
            error: error.to_string(),
            rollback_error: preference
                .rollback_error
                .clone()
                .unwrap_or_else(|| "ROLLBACK_VALUE_UNAVAILABLE".into()),
        }
    };
    store_preference(db, group_id, &preference).await?;
    if preference.state == RelayPreferencePhase::RollingBack {
        let rule_ids = preference
            .dns_records
            .iter()
            .map(|record| record.rule_id)
            .collect::<Vec<_>>();
        if let Err(schedule_error) =
            crate::service::dnsmgr::schedule_group_eligible(db, group_id, &rule_ids).await
        {
            preference.state = RelayPreferencePhase::FailedManualIntervention;
            preference.rollback_error = Some("ROLLBACK_SCHEDULING_FAILED".into());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::ManualIntervention {
                from_node_id: preference.preferred_node_id,
                to_node_id: preference.pending_node_id.unwrap_or_default(),
                error: error.to_string(),
                rollback_error: format!("ROLLBACK_SCHEDULING_FAILED:{schedule_error}"),
            });
        }
    }
    Ok(outcome)
}

async fn finalize_rollback(
    db: &dyn Repository,
    group_id: i64,
    mut preference: RelayPreferenceState,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    let target_node_id = preference.pending_node_id.clone().unwrap_or_default();
    let eligible = crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id).await?;
    let mut all_propagated = !preference.dns_records.is_empty();

    for record in &preference.dns_records {
        if eligible.binary_search(&record.rule_id).is_err() {
            preference.state = RelayPreferencePhase::FailedManualIntervention;
            preference.rollback_error = Some("ROLLBACK_RULE_NOT_ELIGIBLE".into());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::ManualIntervention {
                from_node_id: preference.preferred_node_id,
                to_node_id: target_node_id,
                error: preference
                    .last_error
                    .unwrap_or_else(|| "RELAY_SWITCH_FAILED".into()),
                rollback_error: "ROLLBACK_RULE_NOT_ELIGIBLE".into(),
            });
        }
        let Some(sync) = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?
        else {
            all_propagated = false;
            continue;
        };
        if !sync_matches_action(
            &sync,
            record.rollback_action,
            record.rollback_value.as_deref(),
        ) {
            all_propagated = false;
            continue;
        }
        let rollback_failure = terminal_dns_error(&sync).or_else(|| {
            (sync.last_error_category.as_deref() == Some("PUBLIC_DNS_MULTIPLE_ANSWERS"))
                .then(|| "PUBLIC_DNS_MULTIPLE_ANSWERS".into())
        });
        if let Some(error) = rollback_failure {
            preference.state = RelayPreferencePhase::FailedManualIntervention;
            preference.rollback_error = Some(error.clone());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::ManualIntervention {
                from_node_id: preference.preferred_node_id,
                to_node_id: target_node_id,
                error: preference
                    .last_error
                    .unwrap_or_else(|| "RELAY_SWITCH_FAILED".into()),
                rollback_error: error,
            });
        }
        if sync.state != "PROPAGATED"
            || sync.last_error_category.as_deref() == Some("PUBLIC_DNS_MULTIPLE_ANSWERS")
        {
            all_propagated = false;
        }
    }

    if !all_propagated {
        return Ok(FinalizeOutcome::Pending);
    }
    preference.state = RelayPreferencePhase::FailedRolledBack;
    preference.rollback_error = None;
    let error = preference
        .last_error
        .clone()
        .unwrap_or_else(|| "RELAY_SWITCH_FAILED".into());
    store_preference(db, group_id, &preference).await?;
    Ok(FinalizeOutcome::RolledBack {
        from_node_id: preference.preferred_node_id,
        to_node_id: target_node_id,
        error,
    })
}

fn sync_matches_action(
    sync: &crate::db::repo::DnsRecordSync,
    action: RelayDnsAction,
    value: Option<&str>,
) -> bool {
    match action {
        RelayDnsAction::Upsert => {
            sync.desired_action == "UPSERT" && sync.expected_value.as_deref() == value
        }
        RelayDnsAction::Delete => sync.desired_action == "DELETE" && sync.expected_value.is_none(),
    }
}

async fn finalize_carrier_rollback(
    db: &dyn Repository,
    group_id: i64,
    mut preference: RelayPreferenceState,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    let mut all_propagated = !preference.dns_records.is_empty();
    for record in &preference.dns_records {
        let Some(sync) = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?
        else {
            all_propagated = false;
            continue;
        };
        if !sync_matches_action(
            &sync,
            record.rollback_action,
            record.rollback_value.as_deref(),
        ) {
            all_propagated = false;
            continue;
        }
        if let Some(error) = terminal_dns_error(&sync) {
            preference.state = RelayPreferencePhase::FailedManualIntervention;
            preference.rollback_error = Some(error.clone());
            store_preference(db, group_id, &preference).await?;
            return Ok(FinalizeOutcome::ManualIntervention {
                from_node_id: preference.preferred_node_id,
                to_node_id: String::new(),
                error: preference
                    .last_error
                    .unwrap_or_else(|| "CARRIER_POLICY_APPLY_FAILED".into()),
                rollback_error: error,
            });
        }
        if sync.state != "PROPAGATED" {
            all_propagated = false;
        }
    }
    if !all_propagated {
        return Ok(FinalizeOutcome::Pending);
    }
    preference.state = RelayPreferencePhase::FailedRolledBack;
    preference.rollback_error = None;
    let error = preference
        .last_error
        .clone()
        .unwrap_or_else(|| "CARRIER_POLICY_APPLY_FAILED".into());
    store_preference(db, group_id, &preference).await?;
    Ok(FinalizeOutcome::RolledBack {
        from_node_id: preference.preferred_node_id,
        to_node_id: String::new(),
        error,
    })
}

async fn finalize_carrier_policy_group(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    mut preference: RelayPreferenceState,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    if preference.state == RelayPreferencePhase::RollingBack {
        return finalize_carrier_rollback(db, group_id, preference).await;
    }
    if preference.state != RelayPreferencePhase::Switching {
        return Ok(FinalizeOutcome::Pending);
    }
    if preference.pending_carrier_policy.is_none() || preference.dns_records.is_empty() {
        return begin_carrier_rollback(db, group_id, preference, "CARRIER_TRANSACTION_INCOMPLETE")
            .await;
    }

    let mut all_propagated = true;
    let mut terminal_error = None;
    for record in &preference.dns_records {
        let Some(sync) = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?
        else {
            all_propagated = false;
            continue;
        };
        if !sync_matches_action(&sync, record.target_action, record.target_value.as_deref()) {
            all_propagated = false;
            continue;
        }
        if let Some(error) = terminal_dns_error(&sync) {
            terminal_error.get_or_insert(error);
            continue;
        }
        if sync.state != "PROPAGATED" {
            all_propagated = false;
        }
    }
    if let Some(error) = terminal_error {
        return begin_carrier_rollback(db, group_id, preference, &error).await;
    }
    if !all_propagated {
        return Ok(FinalizeOutcome::Pending);
    }

    let transaction_rule_ids = preference
        .dns_records
        .iter()
        .map(|record| record.rule_id)
        .collect::<BTreeSet<_>>();
    let current_rule_ids = crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if transaction_rule_ids != current_rule_ids {
        return begin_carrier_rollback(db, group_id, preference, "DNS_RULE_SET_CHANGED").await;
    }
    if let Err(error) =
        recheck_carrier_commit_targets(db, node_connections, group_id, &preference).await?
    {
        return begin_carrier_rollback(db, group_id, preference, error).await;
    }

    preference.carrier_policy = preference
        .pending_carrier_policy
        .take()
        .expect("carrier transaction checked pending policy");
    preference.transaction_kind = None;
    preference.state = RelayPreferencePhase::Idle;
    preference.started_at = None;
    preference.last_error = None;
    preference.rollback_error = None;
    preference.dns_records.clear();
    store_preference(db, group_id, &preference).await?;
    Ok(FinalizeOutcome::Committed {
        from_node_id: preference.preferred_node_id.clone(),
        to_node_id: String::new(),
    })
}

async fn recheck_carrier_commit_targets(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    preference: &RelayPreferenceState,
) -> Result<Result<(), &'static str>, RelayPreferenceError> {
    let Some(pending) = preference.pending_carrier_policy.as_ref() else {
        return Ok(Err("CARRIER_TRANSACTION_INCOMPLETE"));
    };
    let bindings = pending
        .bindings
        .iter()
        .map(|binding| (binding.line_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut changed_targets = BTreeMap::<&str, &str>::new();
    for record in preference
        .dns_records
        .iter()
        .filter(|record| record.target_action == RelayDnsAction::Upsert)
    {
        let Some(value) = record.target_value.as_deref() else {
            return Ok(Err("CARRIER_TARGET_VALUE_UNAVAILABLE"));
        };
        if changed_targets
            .insert(record.line_id.as_str(), value)
            .is_some_and(|existing| existing != value)
        {
            return Ok(Err("CARRIER_TARGET_VALUE_INCONSISTENT"));
        }
    }
    if changed_targets.is_empty() {
        return Ok(Ok(()));
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    let Some(group) = group.filter(|group| group.group_type == "in") else {
        return Ok(Err("CARRIER_GROUP_UNAVAILABLE_AFTER_DNS"));
    };
    for (line_id, expected_value) in changed_targets {
        let Some(binding) = bindings.get(line_id) else {
            return Ok(Err("CARRIER_TARGET_BINDING_MISSING"));
        };
        let node_id = match binding.mode {
            CarrierLineMode::Node => binding.node_id.as_deref(),
            CarrierLineMode::FollowDefault => preference.preferred_node_id.as_deref(),
        };
        let Some(node_id) = node_id else {
            let Some(current_value) = valid_public_ipv4(Some(&group.connect_host)) else {
                return Ok(Err("CARRIER_TARGET_PUBLIC_IPV4_UNAVAILABLE_AFTER_DNS"));
            };
            if current_value != expected_value {
                return Ok(Err("CARRIER_TARGET_PUBLIC_IPV4_CHANGED"));
            }
            continue;
        };
        let Some(node) = evaluated
            .iter()
            .find(|candidate| candidate.info.node_id == node_id)
        else {
            return Ok(Err("CARRIER_TARGET_NOT_READY_AFTER_DNS"));
        };
        let Some(current_value) = valid_public_ipv4(node.public_ipv4.as_deref()) else {
            return Ok(Err("CARRIER_TARGET_PUBLIC_IPV4_UNAVAILABLE_AFTER_DNS"));
        };
        if current_value != expected_value {
            return Ok(Err("CARRIER_TARGET_PUBLIC_IPV4_CHANGED"));
        }
        if !node.info.ready {
            return Ok(Err("CARRIER_TARGET_NOT_READY_AFTER_DNS"));
        }
    }
    Ok(Ok(()))
}

async fn finalize_switching_group(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<FinalizeOutcome, RelayPreferenceError> {
    let _guard = RELAY_PREFERENCE_MUTATION_LOCK.lock().await;
    let mut preference = load_preference(db, group_id).await?;
    if preference.transaction_kind == Some(RelayTransactionKind::CarrierPolicyApply) {
        return finalize_carrier_policy_group(db, node_connections, group_id, preference).await;
    }
    if preference.state == RelayPreferencePhase::RollingBack {
        return finalize_rollback(db, group_id, preference).await;
    }
    if preference.state != RelayPreferencePhase::Switching {
        return Ok(FinalizeOutcome::Pending);
    }
    let Some(target_node_id) = preference.pending_node_id.clone() else {
        return begin_rollback(
            db,
            group_id,
            preference,
            String::new(),
            "PENDING_NODE_MISSING",
        )
        .await;
    };
    let target_ipv4 = match stored_node_public_ipv4(db, group_id, &target_node_id).await? {
        RelayDnsTarget::Resolved(target_ipv4) => target_ipv4,
        RelayDnsTarget::Invalid("RELAY_NODE_STATUS_MISSING" | "RELAY_NODE_STATUS_INVALID") => {
            return begin_rollback(
                db,
                group_id,
                preference,
                target_node_id,
                "TARGET_STATUS_UNAVAILABLE",
            )
            .await;
        }
        RelayDnsTarget::Invalid(_) | RelayDnsTarget::NotSet | RelayDnsTarget::Frozen => {
            return begin_rollback(
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
        return begin_rollback(
            db,
            group_id,
            preference,
            target_node_id,
            "NO_ELIGIBLE_DNS_RULES",
        )
        .await;
    }

    if preference.dns_records.is_empty() {
        if preference
            .carrier_policy
            .bindings
            .iter()
            .any(|binding| binding.mode == CarrierLineMode::FollowDefault)
        {
            return begin_rollback(
                db,
                group_id,
                preference,
                target_node_id,
                "DNS_TRANSACTION_JOURNAL_MISSING",
            )
            .await;
        }
        preference.dns_records =
            build_dns_transaction_records(db, group_id, &preference, &rule_ids, &target_ipv4)
                .await?;
        store_preference(db, group_id, &preference).await?;
    }
    if preference.dns_records.iter().any(|record| {
        record.target_action != RelayDnsAction::Upsert
            || record.target_value.as_deref() != Some(target_ipv4.as_str())
    }) {
        return begin_rollback(
            db,
            group_id,
            preference,
            target_node_id,
            "TARGET_PUBLIC_IPV4_CHANGED",
        )
        .await;
    }

    let transaction_ids = preference
        .dns_records
        .iter()
        .map(|record| record.rule_id)
        .collect::<HashSet<_>>();
    if rule_ids
        .iter()
        .any(|rule_id| !transaction_ids.contains(rule_id))
        || preference
            .dns_records
            .iter()
            .any(|record| rule_ids.binary_search(&record.rule_id).is_err())
    {
        return begin_rollback(
            db,
            group_id,
            preference,
            target_node_id,
            "DNS_RULE_SET_CHANGED",
        )
        .await;
    }

    let mut all_propagated = true;
    let mut terminal_error = None;
    for record in &preference.dns_records {
        let Some(sync) = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?
        else {
            all_propagated = false;
            continue;
        };
        if !sync_matches_action(&sync, record.target_action, record.target_value.as_deref()) {
            all_propagated = false;
            continue;
        }
        if let Some(error) = terminal_dns_error(&sync) {
            terminal_error.get_or_insert(error);
            continue;
        }
        if sync.state == "PROPAGATED"
            && sync.last_error_category.as_deref() == Some("PUBLIC_DNS_MULTIPLE_ANSWERS")
        {
            terminal_error.get_or_insert_with(|| "PUBLIC_DNS_MULTIPLE_ANSWERS".into());
            continue;
        }
        if sync.state != "PROPAGATED" {
            all_propagated = false;
        }
    }
    if let Some(error) = terminal_error {
        return begin_rollback(db, group_id, preference, target_node_id, &error).await;
    }
    if !all_propagated {
        return Ok(FinalizeOutcome::Pending);
    }

    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;
    if !evaluated
        .iter()
        .any(|node| node.info.node_id == target_node_id && node.info.ready)
    {
        return begin_rollback(
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
    preference.rollback_error = None;
    preference.dns_records.clear();
    preference.transaction_kind = None;
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
        if !matches!(
            preference.state,
            RelayPreferencePhase::Switching | RelayPreferencePhase::RollingBack
        ) {
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
            Ok(FinalizeOutcome::RollbackStarted {
                from_node_id,
                to_node_id,
                error,
            }) => {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_SWITCH_ROLLBACK_STARTED",
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
            Ok(FinalizeOutcome::RolledBack {
                from_node_id,
                to_node_id,
                error,
            }) => {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_SWITCH_FAILED_ROLLED_BACK",
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
            Ok(FinalizeOutcome::ManualIntervention {
                from_node_id,
                to_node_id,
                error,
                rollback_error,
            }) => {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_SWITCH_FAILED_MANUAL_INTERVENTION",
                    "device_group",
                    group_id,
                    &format!(
                        "group_id={} from_node_id={} to_node_id={} error={} rollback_error={}",
                        group_id,
                        from_node_id.as_deref().unwrap_or("none"),
                        to_node_id,
                        error,
                        rollback_error
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
    let mut dns_records = Vec::with_capacity(preference.dns_records.len());
    for record in &preference.dns_records {
        let sync = db
            .find_dns_record_sync(record.rule_id, &record.line_key)
            .await?;
        let propagated_value = sync
            .as_ref()
            .filter(|sync| sync.state == "PROPAGATED" && sync.last_error_category.is_none())
            .and_then(|sync| sync.expected_value.as_deref());
        let position = if propagated_value == record.rollback_value.as_deref() {
            RelayDnsRecordPosition::Rollback
        } else if propagated_value == record.target_value.as_deref()
            || (matches!(
                preference.state,
                RelayPreferencePhase::RollingBack | RelayPreferencePhase::FailedManualIntervention
            ) && record.target_state.as_deref() == Some("PROPAGATED")
                && record.target_error.is_none())
        {
            RelayDnsRecordPosition::Target
        } else {
            RelayDnsRecordPosition::Unknown
        };
        dns_records.push(RelayDnsRecordView {
            rule_id: record.rule_id,
            fqdn: record.fqdn.clone(),
            rollback_value: record.rollback_value.clone(),
            target_value: record.target_value.clone().unwrap_or_default(),
            expected_value: sync.as_ref().and_then(|sync| sync.expected_value.clone()),
            sync_state: sync.as_ref().map(|sync| sync.state.clone()),
            position,
            last_error: sync
                .as_ref()
                .and_then(|sync| sync.last_error_category.clone())
                .or_else(|| record.target_error.clone()),
        });
    }

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
        rollback_error: preference.rollback_error,
        dns_records,
        nodes,
    })
}

fn relay_health_for_node(evaluated: &[EvaluatedNode], node_id: Option<&str>) -> Option<String> {
    let node_id = node_id?;
    let node = evaluated
        .iter()
        .find(|candidate| candidate.info.node_id == node_id)?;
    Some(
        if node.info.ready {
            "ready"
        } else if node.info.online {
            "abnormal"
        } else {
            "offline"
        }
        .into(),
    )
}

pub async fn get_carrier_affinity(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<CarrierAffinityView, RelayPreferenceError> {
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    if group.as_ref().map(|group| group.group_type.as_str()) != Some("in") {
        return Err(RelayPreferenceError::Database(DbError::NotFound));
    }
    let preference = load_preference(db, group_id).await?;
    let evaluated = evaluate_group_nodes(db, node_connections, group_id).await?;
    let (catalog_ids, catalog_stale) =
        match crate::service::carrier_lines::group_catalog(db, group_id).await {
            Ok(catalog) => (
                catalog
                    .lines
                    .into_iter()
                    .map(|line| line.id)
                    .collect::<HashSet<_>>(),
                catalog.stale,
            ),
            Err(_) => (HashSet::new(), true),
        };
    let displayed_policy = preference
        .pending_carrier_policy
        .as_ref()
        .filter(|_| preference.transaction_kind == Some(RelayTransactionKind::CarrierPolicyApply))
        .unwrap_or(&preference.carrier_policy);
    let eligible = crate::service::dnsmgr::eligible_rule_ids_for_group(db, group_id).await?;
    let mut bindings = Vec::with_capacity(displayed_policy.bindings.len());
    for binding in &displayed_policy.bindings {
        let effective_node_id = match binding.mode {
            CarrierLineMode::FollowDefault => preference.preferred_node_id.clone(),
            CarrierLineMode::Node => binding.node_id.clone(),
        };
        let line_key = format!("dnsmgr:{}", binding.line_id);
        let mut states = Vec::with_capacity(eligible.len());
        for rule_id in &eligible {
            states.push(
                db.find_dns_record_sync(*rule_id, &line_key)
                    .await?
                    .map(|sync| sync.state),
            );
        }
        let dns_state = if states.is_empty() {
            "pending"
        } else if states
            .iter()
            .all(|state| state.as_deref() == Some("PROPAGATED"))
        {
            "effective"
        } else if states.iter().any(|state| {
            matches!(
                state.as_deref(),
                Some("CONFLICT" | "MUTATION_OUTCOME_UNKNOWN" | "FAILED")
            )
        }) {
            "failed"
        } else {
            "applying"
        };
        bindings.push(CarrierAffinityBindingView {
            line_id: binding.line_id.clone(),
            mode: binding.mode,
            node_id: binding.node_id.clone(),
            effective_node_id: effective_node_id.clone(),
            relay_health: relay_health_for_node(&evaluated, effective_node_id.as_deref()),
            catalog_available: catalog_ids.contains(&binding.line_id),
            dns_state: dns_state.into(),
        });
    }
    Ok(CarrierAffinityView {
        group_id,
        default_node_id: preference.preferred_node_id.clone(),
        active_policy: preference.carrier_policy,
        pending_policy: preference.pending_carrier_policy,
        transaction: CarrierAffinityTransactionView {
            kind: preference.transaction_kind,
            state: preference.state,
            started_at: preference.started_at,
            last_error: preference.last_error,
            rollback_error: preference.rollback_error,
        },
        bindings,
        catalog_stale,
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
    fn rc8_relay_preference_json_remains_compatible() {
        let idle: RelayPreferenceState = serde_json::from_value(serde_json::json!({
            "preferred_node_id": "node-a",
            "pending_node_id": null,
            "state": "idle",
            "started_at": null,
            "last_error": null,
            "rollback_error": null,
            "dns_records": []
        }))
        .unwrap();
        assert_eq!(idle.carrier_policy, CarrierPolicy::default());
        assert_eq!(idle.pending_carrier_policy, None);
        assert_eq!(idle.transaction_kind, None);

        for phase in ["switching", "rolling_back"] {
            let legacy: RelayPreferenceState = serde_json::from_value(serde_json::json!({
                "preferred_node_id": "node-a",
                "pending_node_id": "node-b",
                "state": phase,
                "started_at": "2026-08-31T00:00:00Z",
                "last_error": null,
                "dns_records": [{
                    "rule_id": 7,
                    "fqdn": "op1.example.com",
                    "rollback_value": "192.0.2.10",
                    "target_value": "192.0.2.20"
                }]
            }))
            .unwrap();
            assert_eq!(
                legacy.transaction_kind,
                Some(RelayTransactionKind::PreferredSwitch)
            );
            assert_eq!(legacy.dns_records[0].line_id, "default");
            assert_eq!(legacy.dns_records[0].line_key, "default");
            assert_eq!(legacy.dns_records[0].target_action, RelayDnsAction::Upsert);
            assert_eq!(
                legacy.dns_records[0].rollback_action,
                RelayDnsAction::Upsert
            );
        }
    }

    #[test]
    fn carrier_policy_normalizes_and_roundtrips_without_display_data() {
        let policy = CarrierPolicy {
            bindings: vec![
                CarrierLineBinding {
                    line_id: "Dianxin_Shandong".into(),
                    mode: CarrierLineMode::FollowDefault,
                    node_id: None,
                },
                CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::Node,
                    node_id: Some(" node-b ".into()),
                },
            ],
        }
        .normalize()
        .unwrap();
        assert_eq!(policy.bindings[0].line_id, "Dianxin");
        assert_eq!(policy.bindings[0].node_id.as_deref(), Some("node-b"));
        assert_eq!(policy.bindings[1].line_id, "Dianxin_Shandong");
        assert_eq!(
            serde_json::from_str::<CarrierPolicy>(&serde_json::to_string(&policy).unwrap())
                .unwrap(),
            policy
        );

        let case_sensitive = CarrierPolicy {
            bindings: vec![
                CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::FollowDefault,
                    node_id: None,
                },
                CarrierLineBinding {
                    line_id: "dianxin".into(),
                    mode: CarrierLineMode::FollowDefault,
                    node_id: None,
                },
            ],
        };
        assert!(case_sensitive.normalize().is_ok());
    }

    #[test]
    fn carrier_policy_rejects_duplicate_and_invalid_mode_payloads() {
        let duplicate = CarrierPolicy {
            bindings: vec![
                CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::FollowDefault,
                    node_id: None,
                },
                CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::Node,
                    node_id: Some("node-a".into()),
                },
            ],
        };
        assert_eq!(
            duplicate.normalize(),
            Err(CarrierPolicyValidationError::DuplicateLineId)
        );
        assert_eq!(
            CarrierPolicy {
                bindings: vec![CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::FollowDefault,
                    node_id: Some("node-a".into()),
                }]
            }
            .normalize(),
            Err(CarrierPolicyValidationError::UnexpectedNodeId)
        );
        assert_eq!(
            CarrierPolicy {
                bindings: vec![CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::Node,
                    node_id: None,
                }]
            }
            .normalize(),
            Err(CarrierPolicyValidationError::MissingNodeId)
        );
    }

    #[test]
    fn dynamic_dns_journal_roundtrips_upsert_and_delete_rollback() {
        let state = RelayPreferenceState {
            transaction_kind: Some(RelayTransactionKind::CarrierPolicyApply),
            pending_carrier_policy: Some(CarrierPolicy {
                bindings: vec![CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: CarrierLineMode::Node,
                    node_id: Some("node-b".into()),
                }],
            }),
            dns_records: vec![
                RelayDnsTransactionRecord {
                    rule_id: 7,
                    fqdn: "op1.example.com".into(),
                    line_id: "Dianxin".into(),
                    line_key: "dnsmgr:Dianxin".into(),
                    target_action: RelayDnsAction::Upsert,
                    target_value: Some("192.0.2.20".into()),
                    rollback_action: RelayDnsAction::Delete,
                    rollback_value: None,
                    target_record_id: Some("record-new".into()),
                    rollback_record_id: None,
                    target_state: Some("PROPAGATED".into()),
                    target_error: None,
                },
                RelayDnsTransactionRecord {
                    rule_id: 8,
                    fqdn: "op2.example.com".into(),
                    line_id: "Liantong".into(),
                    line_key: "dnsmgr:Liantong".into(),
                    target_action: RelayDnsAction::Delete,
                    target_value: None,
                    rollback_action: RelayDnsAction::Upsert,
                    rollback_value: Some("192.0.2.30".into()),
                    target_record_id: None,
                    rollback_record_id: Some("record-old".into()),
                    target_state: None,
                    target_error: None,
                },
            ],
            ..RelayPreferenceState::default()
        };
        let decoded: RelayPreferenceState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(
            decoded.dns_records[0].rollback_action,
            RelayDnsAction::Delete
        );
        assert_eq!(decoded.dns_records[1].target_action, RelayDnsAction::Delete);
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
    fn renewal_warning_certificate_remains_ready() {
        let raw = status(serde_json::json!({
            "camouflage_sites": [{
                "site_id": "site-1",
                "sni": "op1.example.com",
                "site_status": "active",
                "certificate_status": "renewal_warning",
                "last_error": "renewal will retry"
            }]
        }));
        let node = evaluate(&raw, &[rule(1, true)], true);
        assert!(node.ready);
        assert!(!node
            .ready_reasons
            .contains(&"CERTIFICATE_NOT_ACTIVE:1".into()));
    }

    #[test]
    fn unknown_camouflage_status_values_fail_safe_as_not_ready() {
        let raw = status(serde_json::json!({
            "camouflage_sites": [{
                "site_id": "site-1",
                "sni": "op1.example.com",
                "site_status": "future_site_state",
                "certificate_status": "future_certificate_state"
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
        let sync = db
            .find_dns_record_sync(rule_id, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
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

    async fn set_line_sync_state(
        db: &crate::db::sqlite_repo::SqliteRepository,
        rule_id: i64,
        line_key: &str,
        state: &str,
        error: Option<&str>,
    ) {
        let sync = db
            .find_dns_record_sync(rule_id, line_key)
            .await
            .unwrap()
            .unwrap();
        db.update_dns_record_sync_observation(
            &sync,
            &sync.state,
            state,
            &sync.ownership,
            sync.mutation_verified_at.as_deref(),
            sync.last_observed_at.as_deref(),
            (state == "PROPAGATED").then_some("2026-08-31T00:00:00Z"),
            error,
            sync.attempt_count,
            None,
            "2026-08-31T00:00:00Z",
        )
        .await
        .unwrap();
    }

    async fn set_rule_paused(
        db: &crate::db::sqlite_repo::SqliteRepository,
        rule_id: i64,
        paused: bool,
    ) {
        RuleRepository::update_rule_fields(
            db,
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
            None,
            None,
            None,
            None,
            None,
            None,
            Some(paused),
        )
        .await
        .unwrap();
    }

    fn carrier_binding(
        line_id: &str,
        mode: CarrierLineMode,
        node_id: Option<&str>,
    ) -> CarrierLineBinding {
        CarrierLineBinding {
            line_id: line_id.into(),
            mode,
            node_id: node_id.map(str::to_string),
        }
    }

    fn carrier_record(
        rule_id: i64,
        line_id: &str,
        target_action: RelayDnsAction,
        target_value: Option<&str>,
        rollback_action: RelayDnsAction,
        rollback_value: Option<&str>,
    ) -> RelayDnsTransactionRecord {
        RelayDnsTransactionRecord {
            rule_id,
            fqdn: if rule_id == 1 {
                "op1.example.com".into()
            } else {
                "op3.example.com".into()
            },
            line_id: line_id.into(),
            line_key: format!("dnsmgr:{line_id}"),
            target_action,
            target_value: target_value.map(str::to_string),
            rollback_action,
            rollback_value: rollback_value.map(str::to_string),
            target_record_id: None,
            rollback_record_id: None,
            target_state: None,
            target_error: None,
        }
    }

    #[test]
    fn carrier_policy_diff_covers_upsert_delete_and_noop() {
        let active = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin_Shandong", CarrierLineMode::FollowDefault, None),
            ],
        };
        assert!(carrier_policy_diff(&active, &active).is_empty());
        let requested = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-c")),
                carrier_binding("Liantong", CarrierLineMode::FollowDefault, None),
            ],
        };
        let changes = carrier_policy_diff(&active, &requested);
        assert_eq!(
            changes
                .iter()
                .map(|change| (
                    change.line_id.as_str(),
                    change.old.is_some(),
                    change.new.is_some()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("Dianxin", true, true),
                ("Dianxin_Shandong", true, false),
                ("Liantong", false, true),
            ]
        );
    }

    #[test]
    fn changed_follow_default_requires_ready_preferred_but_unrelated_nodes_do_not_block() {
        let ready = EvaluatedNode {
            info: RelayReadyNode {
                node_id: "node-a".into(),
                public_ipv4: Some("203.0.113.5".into()),
                online: true,
                ready: true,
                ready_reasons: Vec::new(),
                preferred: true,
            },
            public_ipv4: Some("203.0.113.5".into()),
        };
        let unhealthy = EvaluatedNode {
            info: RelayReadyNode {
                node_id: "node-b".into(),
                public_ipv4: Some("203.0.113.6".into()),
                online: true,
                ready: false,
                ready_reasons: vec!["RECONCILIATION_NOT_CONVERGED".into()],
                preferred: false,
            },
            public_ipv4: Some("203.0.113.6".into()),
        };
        let binding = carrier_binding("Dianxin", CarrierLineMode::FollowDefault, None);
        assert_eq!(
            carrier_binding_target(
                &binding,
                Some("203.0.113.5"),
                Some("node-a"),
                &[ready, unhealthy]
            )
            .unwrap(),
            (Some("node-a".into()), "203.0.113.5".into())
        );
        assert!(matches!(
            carrier_binding_target(
                &binding,
                Some("203.0.113.6"),
                Some("node-b"),
                &[EvaluatedNode {
                    info: RelayReadyNode {
                        node_id: "node-b".into(),
                        public_ipv4: Some("203.0.113.6".into()),
                        online: true,
                        ready: false,
                        ready_reasons: vec!["RECONCILIATION_NOT_CONVERGED".into()],
                        preferred: true,
                    },
                    public_ipv4: Some("203.0.113.6".into()),
                }]
            ),
            Err(CarrierPolicyApplyError::TargetNotReady { .. })
        ));

        let explicit = carrier_binding("Liantong", CarrierLineMode::Node, Some("node-c"));
        assert_eq!(
            carrier_binding_target(
                &explicit,
                None,
                Some("node-b"),
                &[EvaluatedNode {
                    info: RelayReadyNode {
                        node_id: "node-c".into(),
                        public_ipv4: Some("203.0.113.7".into()),
                        online: true,
                        ready: true,
                        ready_reasons: Vec::new(),
                        preferred: false,
                    },
                    public_ipv4: Some("203.0.113.7".into()),
                }]
            )
            .unwrap(),
            (Some("node-c".into()), "203.0.113.7".into())
        );
    }

    #[tokio::test]
    async fn carrier_apply_commits_only_after_every_line_converges() {
        let (repo, connections, _) = switch_fixture().await;
        let requested = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Dianxin",
                CarrierLineMode::FollowDefault,
                None,
            )],
        };
        let records = vec![
            carrier_record(
                1,
                "Dianxin",
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
                RelayDnsAction::Delete,
                None,
            ),
            carrier_record(
                3,
                "Dianxin",
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
                RelayDnsAction::Delete,
                None,
            ),
        ];
        let preference = RelayPreferenceState {
            preferred_node_id: Some("node-a".into()),
            pending_carrier_policy: Some(requested.clone()),
            transaction_kind: Some(RelayTransactionKind::CarrierPolicyApply),
            state: RelayPreferencePhase::Switching,
            dns_records: records.clone(),
            ..RelayPreferenceState::default()
        };
        store_preference(&repo, 7, &preference).await.unwrap();
        schedule_transaction_records(&repo, &records, false)
            .await
            .unwrap();
        set_line_sync_state(&repo, 1, "dnsmgr:Dianxin", "PROPAGATED", None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Pending
        ));
        assert!(load_preference(&repo, 7)
            .await
            .unwrap()
            .carrier_policy
            .bindings
            .is_empty());

        set_line_sync_state(&repo, 3, "dnsmgr:Dianxin", "PROPAGATED", None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Committed { .. }
        ));
        let committed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(committed.carrier_policy, requested);
        assert_eq!(committed.pending_carrier_policy, None);
        assert_eq!(committed.transaction_kind, None);
        assert_eq!(committed.state, RelayPreferencePhase::Idle);
    }

    async fn store_propagated_carrier_apply(
        repo: &crate::db::sqlite_repo::SqliteRepository,
        requested: CarrierPolicy,
        records: Vec<RelayDnsTransactionRecord>,
        active: CarrierPolicy,
    ) {
        store_preference(
            repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                carrier_policy: active,
                pending_carrier_policy: Some(requested),
                transaction_kind: Some(RelayTransactionKind::CarrierPolicyApply),
                state: RelayPreferencePhase::Switching,
                dns_records: records.clone(),
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();
        schedule_transaction_records(repo, &records, false)
            .await
            .unwrap();
        for record in &records {
            set_line_sync_state(repo, record.rule_id, &record.line_key, "PROPAGATED", None).await;
        }
    }

    fn two_rule_carrier_records(
        line_id: &str,
        action: RelayDnsAction,
        value: Option<&str>,
        rollback_action: RelayDnsAction,
        rollback_value: Option<&str>,
    ) -> Vec<RelayDnsTransactionRecord> {
        [1, 3]
            .into_iter()
            .map(|rule_id| {
                carrier_record(
                    rule_id,
                    line_id,
                    action,
                    value,
                    rollback_action,
                    rollback_value,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn carrier_commit_rechecks_changed_explicit_target_ready_and_ip() {
        for changed_status in [
            status(serde_json::json!({
                "public_ipv4": "203.0.113.7",
                "active_listener_rule_ids": [1, 3],
                "reconciliation": {"state": "APPLY_FAILED", "recovery_source": "NONE"}
            })),
            switch_status("203.0.113.70"),
        ] {
            let (repo, connections, _) = switch_fixture().await;
            let requested = CarrierPolicy {
                bindings: vec![carrier_binding(
                    "Dianxin",
                    CarrierLineMode::Node,
                    Some("node-c"),
                )],
            };
            let records = two_rule_carrier_records(
                "Dianxin",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Delete,
                None,
            );
            store_propagated_carrier_apply(&repo, requested, records, CarrierPolicy::default())
                .await;
            repo.set("node_status:7:node-c", &changed_status)
                .await
                .unwrap();

            assert!(matches!(
                finalize_switching_group(&repo, &connections, 7)
                    .await
                    .unwrap(),
                FinalizeOutcome::RollbackStarted { .. }
            ));
            let state = load_preference(&repo, 7).await.unwrap();
            assert_eq!(state.state, RelayPreferencePhase::RollingBack);
            assert!(state.carrier_policy.bindings.is_empty());
        }
    }

    #[tokio::test]
    async fn carrier_commit_rechecks_follow_default_but_ignores_unchanged_unhealthy_explicit() {
        let (repo, connections, _) = switch_fixture().await;
        let active = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Liantong",
                CarrierLineMode::Node,
                Some("node-b"),
            )],
        };
        let requested = CarrierPolicy {
            bindings: vec![
                carrier_binding("Liantong", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin", CarrierLineMode::FollowDefault, None),
            ],
        };
        let records = two_rule_carrier_records(
            "Dianxin",
            RelayDnsAction::Upsert,
            Some("203.0.113.5"),
            RelayDnsAction::Delete,
            None,
        );
        store_propagated_carrier_apply(&repo, requested.clone(), records, active).await;
        repo.set(
            "node_status:7:node-b",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.6",
                "active_listener_rule_ids": [1, 3],
                "reconciliation": {"state": "APPLY_FAILED", "recovery_source": "NONE"}
            })),
        )
        .await
        .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Committed { .. }
        ));
        assert_eq!(
            load_preference(&repo, 7).await.unwrap().carrier_policy,
            requested
        );

        let (repo, connections, _) = switch_fixture().await;
        let requested = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Dianxin",
                CarrierLineMode::FollowDefault,
                None,
            )],
        };
        let records = two_rule_carrier_records(
            "Dianxin",
            RelayDnsAction::Upsert,
            Some("203.0.113.5"),
            RelayDnsAction::Delete,
            None,
        );
        store_propagated_carrier_apply(&repo, requested, records, CarrierPolicy::default()).await;
        repo.set(
            "node_status:7:node-a",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.5",
                "active_listener_rule_ids": [1, 3],
                "reconciliation": {"state": "APPLY_FAILED", "recovery_source": "NONE"}
            })),
        )
        .await
        .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
    }

    #[tokio::test]
    async fn carrier_commit_rolls_back_when_eligible_rule_snapshot_changes() {
        for remove_rule in [false, true] {
            let (repo, connections, _) = switch_fixture().await;
            let active = CarrierPolicy {
                bindings: vec![carrier_binding(
                    "Dianxin",
                    CarrierLineMode::Node,
                    Some("node-b"),
                )],
            };
            let records = two_rule_carrier_records(
                "Dianxin",
                RelayDnsAction::Delete,
                None,
                RelayDnsAction::Upsert,
                Some("203.0.113.6"),
            );
            store_propagated_carrier_apply(
                &repo,
                CarrierPolicy::default(),
                records,
                active.clone(),
            )
            .await;
            if remove_rule {
                set_rule_paused(&repo, 3, true).await;
                crate::service::dnsmgr::schedule_rule(&repo, 3)
                    .await
                    .unwrap();
            } else {
                let new_rule_id = RuleRepository::create_rule_full(
                    &repo,
                    "rule-5",
                    1,
                    445,
                    "tcp",
                    "nginx_sni",
                    "nginx_sni",
                    "direct",
                    "nginx_sni",
                    None,
                    Some("op5.example.com"),
                    true,
                    false,
                    7,
                    None,
                    "direct",
                    "198.51.100.2",
                    55443,
                    &[],
                    "first",
                    0,
                    0,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
                assert!(new_rule_id > 3);
            }

            assert!(matches!(
                finalize_switching_group(&repo, &connections, 7)
                    .await
                    .unwrap(),
                FinalizeOutcome::RollbackStarted { .. }
            ));
            let state = load_preference(&repo, 7).await.unwrap();
            assert_eq!(state.state, RelayPreferencePhase::RollingBack);
            assert_eq!(state.carrier_policy, active);
            if remove_rule {
                crate::service::dnsmgr::refresh_all_desired(&repo)
                    .await
                    .unwrap();
                let rollback = repo
                    .find_dns_record_sync(3, "dnsmgr:Dianxin")
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(rollback.desired_action, "UPSERT");
                assert_eq!(rollback.expected_value.as_deref(), Some("203.0.113.6"));
                assert_eq!(rollback.state, "PENDING");
            }
        }
    }

    #[tokio::test]
    async fn carrier_failure_rolls_back_old_and_created_records_after_restart() {
        let (repo, connections, _) = switch_fixture().await;
        let active = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Dianxin",
                CarrierLineMode::Node,
                Some("node-b"),
            )],
        };
        let records = vec![
            carrier_record(
                1,
                "Dianxin",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Upsert,
                Some("203.0.113.6"),
            ),
            carrier_record(
                3,
                "Liantong",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Delete,
                None,
            ),
        ];
        store_preference(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                carrier_policy: active.clone(),
                pending_carrier_policy: Some(CarrierPolicy {
                    bindings: vec![
                        carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-c")),
                        carrier_binding("Liantong", CarrierLineMode::Node, Some("node-c")),
                    ],
                }),
                transaction_kind: Some(RelayTransactionKind::CarrierPolicyApply),
                state: RelayPreferencePhase::Switching,
                dns_records: records.clone(),
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();
        schedule_transaction_records(&repo, &records, false)
            .await
            .unwrap();
        set_line_sync_state(&repo, 1, "dnsmgr:Dianxin", "FAILED", Some("DNS_CONFLICT")).await;
        set_line_sync_state(&repo, 3, "dnsmgr:Liantong", "PROPAGATED", None).await;

        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let rolling_back = load_preference(&repo, 7).await.unwrap();
        assert_eq!(rolling_back.state, RelayPreferencePhase::RollingBack);
        let restored = repo
            .find_dns_record_sync(1, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.desired_action, "UPSERT");
        assert_eq!(restored.expected_value.as_deref(), Some("203.0.113.6"));
        let removed = repo
            .find_dns_record_sync(3, "dnsmgr:Liantong")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removed.desired_action, "DELETE");
        assert_eq!(removed.expected_value, None);

        set_line_sync_state(&repo, 1, "dnsmgr:Dianxin", "PROPAGATED", None).await;
        set_line_sync_state(&repo, 3, "dnsmgr:Liantong", "PROPAGATED", None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RolledBack { .. }
        ));
        let rolled_back = load_preference(&repo, 7).await.unwrap();
        assert_eq!(rolled_back.state, RelayPreferencePhase::FailedRolledBack);
        assert_eq!(rolled_back.carrier_policy, active);
    }

    #[tokio::test]
    async fn rule_pause_resume_restores_active_carrier_policy_with_current_default() {
        let (repo, _, _) = switch_fixture().await;
        let active = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin_Shandong", CarrierLineMode::FollowDefault, None),
            ],
        };
        let mut preference = load_preference(&repo, 7).await.unwrap();
        preference.carrier_policy = active;
        store_preference(&repo, 7, &preference).await.unwrap();

        crate::service::dnsmgr::schedule_rule(&repo, 1)
            .await
            .unwrap();
        assert_eq!(
            repo.find_dns_record_sync(1, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap()
                .expected_value
                .as_deref(),
            Some("203.0.113.6")
        );
        assert_eq!(
            repo.find_dns_record_sync(1, "dnsmgr:Dianxin_Shandong")
                .await
                .unwrap()
                .unwrap()
                .expected_value
                .as_deref(),
            Some("203.0.113.5")
        );

        set_rule_paused(&repo, 1, true).await;
        crate::service::dnsmgr::schedule_rule(&repo, 1)
            .await
            .unwrap();
        assert!(repo
            .list_dns_record_syncs_for_rule(1)
            .await
            .unwrap()
            .iter()
            .all(|sync| sync.state == "NOT_ELIGIBLE"));
        preference.preferred_node_id = Some("node-c".into());
        store_preference(&repo, 7, &preference).await.unwrap();

        set_rule_paused(&repo, 1, false).await;
        crate::service::dnsmgr::schedule_rule(&repo, 1)
            .await
            .unwrap();
        let default = repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        let explicit = repo
            .find_dns_record_sync(1, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        let follow = repo
            .find_dns_record_sync(1, "dnsmgr:Dianxin_Shandong")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(default.expected_value.as_deref(), Some("203.0.113.7"));
        assert_eq!(explicit.expected_value.as_deref(), Some("203.0.113.6"));
        assert_eq!(follow.expected_value.as_deref(), Some("203.0.113.7"));
        assert_eq!(explicit.desired_action, "UPSERT");
        assert_eq!(follow.desired_action, "UPSERT");
    }

    #[tokio::test]
    async fn unavailable_active_explicit_target_preserves_existing_dns_desired() {
        let (repo, _, _) = switch_fixture().await;
        let mut preference = load_preference(&repo, 7).await.unwrap();
        preference.carrier_policy = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Dianxin",
                CarrierLineMode::Node,
                Some("node-b"),
            )],
        };
        store_preference(&repo, 7, &preference).await.unwrap();
        crate::service::dnsmgr::schedule_rule(&repo, 1)
            .await
            .unwrap();
        repo.delete("node_status:7:node-b").await.unwrap();
        crate::service::dnsmgr::schedule_rule(&repo, 1)
            .await
            .unwrap();
        let sync = repo
            .find_dns_record_sync(1, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sync.desired_action, "UPSERT");
        assert_eq!(sync.expected_value.as_deref(), Some("203.0.113.6"));
    }

    #[tokio::test]
    async fn preferred_switch_journal_moves_default_and_follow_default_only() {
        let (repo, connections, _) = switch_fixture().await;
        let policy = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin_Shandong", CarrierLineMode::FollowDefault, None),
                carrier_binding("Liantong", CarrierLineMode::FollowDefault, None),
            ],
        };
        let mut records = build_dns_transaction_records(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                ..RelayPreferenceState::default()
            },
            &[1, 3],
            "203.0.113.7",
        )
        .await
        .unwrap();
        for rule_id in [1, 3] {
            records.push(carrier_record(
                rule_id,
                "Dianxin_Shandong",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
            ));
            records.push(carrier_record(
                rule_id,
                "Liantong",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
            ));
        }
        store_preference(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                pending_node_id: Some("node-c".into()),
                carrier_policy: policy,
                transaction_kind: Some(RelayTransactionKind::PreferredSwitch),
                state: RelayPreferencePhase::Switching,
                dns_records: records,
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();
        crate::service::dnsmgr::schedule_group_eligible(&repo, 7, &[1, 3])
            .await
            .unwrap();
        for rule_id in [1, 3] {
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "default")
                    .await
                    .unwrap()
                    .unwrap()
                    .expected_value
                    .as_deref(),
                Some("203.0.113.7")
            );
            for line in ["Dianxin_Shandong", "Liantong"] {
                assert_eq!(
                    repo.find_dns_record_sync(rule_id, &format!("dnsmgr:{line}"))
                        .await
                        .unwrap()
                        .unwrap()
                        .expected_value
                        .as_deref(),
                    Some("203.0.113.7")
                );
            }
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "dnsmgr:Dianxin")
                    .await
                    .unwrap()
                    .unwrap()
                    .expected_value
                    .as_deref(),
                Some("203.0.113.6")
            );
        }

        for rule_id in [1, 3] {
            set_sync_state(&repo, rule_id, "PROPAGATED", None, None).await;
            set_line_sync_state(
                &repo,
                rule_id,
                "dnsmgr:Dianxin_Shandong",
                "PROPAGATED",
                None,
            )
            .await;
            set_line_sync_state(&repo, rule_id, "dnsmgr:Liantong", "PROPAGATED", None).await;
        }
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Committed { .. }
        ));
        assert_eq!(
            load_preference(&repo, 7)
                .await
                .unwrap()
                .preferred_node_id
                .as_deref(),
            Some("node-c")
        );
    }

    #[tokio::test]
    async fn preferred_switch_does_not_reschedule_unchanged_explicit_lines() {
        let (repo, _, _) = switch_fixture().await;
        let policy = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin_Shandong", CarrierLineMode::FollowDefault, None),
            ],
        };
        store_preference(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                carrier_policy: policy.clone(),
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();
        for rule_id in [1, 3] {
            crate::service::dnsmgr::schedule_rule(&repo, rule_id)
                .await
                .unwrap();
            let sync = repo
                .find_dns_record_sync(rule_id, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap();
            repo.update_dns_record_sync_observation(
                &sync,
                &sync.state,
                "FAILED",
                "UNKNOWN",
                None,
                None,
                None,
                Some("DNSMGR_TEMPORARY"),
                3,
                Some("2099-01-01 00:00:00"),
                "2026-08-31 12:00:00",
            )
            .await
            .unwrap();
        }
        let mut before = Vec::new();
        for rule_id in [1, 3] {
            before.push(
                repo.find_dns_record_sync(rule_id, "dnsmgr:Dianxin")
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }

        let mut records = build_dns_transaction_records(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                ..RelayPreferenceState::default()
            },
            &[1, 3],
            "203.0.113.7",
        )
        .await
        .unwrap();
        for rule_id in [1, 3] {
            records.push(carrier_record(
                rule_id,
                "Dianxin_Shandong",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
            ));
        }
        store_preference(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                pending_node_id: Some("node-c".into()),
                carrier_policy: policy,
                transaction_kind: Some(RelayTransactionKind::PreferredSwitch),
                state: RelayPreferencePhase::Switching,
                dns_records: records,
                ..RelayPreferenceState::default()
            },
        )
        .await
        .unwrap();
        crate::service::dnsmgr::schedule_group_eligible(&repo, 7, &[1, 3])
            .await
            .unwrap();
        for (index, rule_id) in [1, 3].into_iter().enumerate() {
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "dnsmgr:Dianxin")
                    .await
                    .unwrap()
                    .unwrap(),
                before[index]
            );
        }
    }

    #[tokio::test]
    async fn preferred_rollback_restores_default_and_follow_default_without_touching_explicit() {
        let (repo, connections, _) = switch_fixture().await;
        let mut records = build_dns_transaction_records(
            &repo,
            7,
            &RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                ..RelayPreferenceState::default()
            },
            &[1, 3],
            "203.0.113.7",
        )
        .await
        .unwrap();
        for rule_id in [1, 3] {
            records.push(carrier_record(
                rule_id,
                "Dianxin_Shandong",
                RelayDnsAction::Upsert,
                Some("203.0.113.7"),
                RelayDnsAction::Upsert,
                Some("203.0.113.5"),
            ));
        }
        let policy = CarrierPolicy {
            bindings: vec![
                carrier_binding("Dianxin", CarrierLineMode::Node, Some("node-b")),
                carrier_binding("Dianxin_Shandong", CarrierLineMode::FollowDefault, None),
            ],
        };
        let preference = RelayPreferenceState {
            preferred_node_id: Some("node-a".into()),
            pending_node_id: Some("node-c".into()),
            carrier_policy: policy,
            transaction_kind: Some(RelayTransactionKind::PreferredSwitch),
            state: RelayPreferencePhase::Switching,
            dns_records: records,
            ..RelayPreferenceState::default()
        };
        store_preference(&repo, 7, &preference).await.unwrap();
        crate::service::dnsmgr::schedule_group_eligible(&repo, 7, &[1, 3])
            .await
            .unwrap();
        set_sync_state(&repo, 1, "FAILED", Some("DNS_CONFLICT"), None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
        for rule_id in [1, 3] {
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "default")
                    .await
                    .unwrap()
                    .unwrap()
                    .expected_value
                    .as_deref(),
                Some("203.0.113.5")
            );
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "dnsmgr:Dianxin_Shandong")
                    .await
                    .unwrap()
                    .unwrap()
                    .expected_value
                    .as_deref(),
                Some("203.0.113.5")
            );
            assert_eq!(
                repo.find_dns_record_sync(rule_id, "dnsmgr:Dianxin")
                    .await
                    .unwrap()
                    .unwrap()
                    .expected_value
                    .as_deref(),
                Some("203.0.113.6")
            );
        }
    }

    #[tokio::test]
    async fn carrier_apply_is_busy_for_preferred_and_already_preferred_stays_noop() {
        let (repo, connections, _) = switch_fixture().await;
        let mut preference = load_preference(&repo, 7).await.unwrap();
        preference.carrier_policy = CarrierPolicy {
            bindings: vec![carrier_binding(
                "Dianxin",
                CarrierLineMode::FollowDefault,
                None,
            )],
        };
        store_preference(&repo, 7, &preference).await.unwrap();
        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-a")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadyPreferred
        );
        assert_eq!(
            load_preference(&repo, 7).await.unwrap().state,
            RelayPreferencePhase::Idle
        );

        preference.state = RelayPreferencePhase::Switching;
        preference.transaction_kind = Some(RelayTransactionKind::CarrierPolicyApply);
        preference.pending_carrier_policy = Some(preference.carrier_policy.clone());
        store_preference(&repo, 7, &preference).await.unwrap();
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::SwitchInProgress { .. })
        ));

        preference.state = RelayPreferencePhase::FailedManualIntervention;
        preference.pending_node_id = Some("node-c".into());
        preference.last_error = Some("DNS_RECORD_CONFLICT".into());
        preference.rollback_error = Some("DNS_OWNERSHIP_UNVERIFIED".into());
        store_preference(&repo, 7, &preference).await.unwrap();
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::SwitchInProgress { .. })
        ));
        assert_eq!(
            load_preference(&repo, 7).await.unwrap().state,
            RelayPreferencePhase::FailedManualIntervention
        );
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

        let sync = repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sync.expected_value.as_deref(), Some("203.0.113.7"));
        assert_eq!(sync.state, "PENDING");
        assert_eq!(
            repo.find_dns_record_sync(3, crate::service::dnsmgr::DEFAULT_LINE_KEY)
                .await
                .unwrap()
                .unwrap()
                .expected_value
                .as_deref(),
            Some("203.0.113.7")
        );
        assert!(repo
            .find_dns_record_sync(2, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());
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
        assert!(repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());

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
        assert!(repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());

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
    async fn already_preferred_bypasses_only_dns_prerequisites() {
        let (repo, connections, _) = switch_fixture().await;
        repo.delete(crate::service::dnsmgr::DNSMGR_CONFIG_KEY)
            .await
            .unwrap();

        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-a")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadyPreferred
        );
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::DnsMgrUnavailable)
        ));

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

        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-a")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadyPreferred
        );
        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-c").await,
            Err(StartRelaySwitchError::NoEligibleDnsRules)
        ));

        let preference = load_preference(&repo, 7).await.unwrap();
        assert_eq!(preference.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(preference.pending_node_id, None);
        assert_eq!(preference.state, RelayPreferencePhase::Idle);
        assert!(repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());
        assert!(repo
            .find_dns_record_sync(3, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn already_preferred_still_requires_a_ready_target() {
        let (repo, connections, _) = switch_fixture().await;
        repo.set(
            "node_status:7:node-a",
            &status(serde_json::json!({
                "public_ipv4": "203.0.113.5",
                "active_listener_rule_ids": [1, 3],
                "reconciliation": {
                    "state": "APPLY_FAILED", "recovery_source": "NONE"
                }
            })),
        )
        .await
        .unwrap();

        assert!(matches!(
            start_relay_switch(&repo, &connections, 7, "node-a").await,
            Err(StartRelaySwitchError::TargetNotReady(_))
        ));
        let preference = load_preference(&repo, 7).await.unwrap();
        assert_eq!(preference.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(preference.pending_node_id, None);
        assert_eq!(preference.state, RelayPreferencePhase::Idle);
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
    async fn restart_during_switch_and_rollback_resumes_from_persisted_journal() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Pending
        ));

        // 模拟 Panel 在 target 只传播一半时重启：finalizer 不持有进程内事务，
        // 必须从 KVS journal 与 durable sync rows 恢复同一 switching transaction。
        let recovered_switch = load_preference(&repo, 7).await.unwrap();
        assert_eq!(recovered_switch.state, RelayPreferencePhase::Switching);
        assert_eq!(recovered_switch.dns_records.len(), 2);
        set_sync_state(&repo, 3, "CONFLICT", Some("DNS_CONFLICT"), None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));

        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::Pending
        ));

        // 再次模拟重启发生在 rollback 传播一半时。旧 preferred 与 pending
        // target 必须保留，下一 tick 继续 rollback，不能永久 Pending 或假成功。
        let recovered_rollback = load_preference(&repo, 7).await.unwrap();
        assert_eq!(recovered_rollback.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            recovered_rollback.preferred_node_id.as_deref(),
            Some("node-a")
        );
        assert_eq!(
            recovered_rollback.pending_node_id.as_deref(),
            Some("node-b")
        );
        set_sync_state(&repo, 3, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RolledBack { .. }
        ));
        let terminal = load_preference(&repo, 7).await.unwrap();
        assert_eq!(terminal.state, RelayPreferencePhase::FailedRolledBack);
        assert_eq!(terminal.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(terminal.pending_node_id.as_deref(), Some("node-b"));
    }

    #[tokio::test]
    async fn partial_target_failure_rolls_back_every_record_before_terminal_failure() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        set_sync_state(&repo, 3, "CONFLICT", Some("DNS_CONFLICT"), None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let rolling_back = load_preference(&repo, 7).await.unwrap();
        assert_eq!(rolling_back.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(rolling_back.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(rolling_back.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            rolling_back.last_error.as_deref(),
            Some("DNS_RECORD_CONFLICT")
        );
        assert_eq!(rolling_back.dns_records.len(), 2);
        assert_eq!(
            rolling_back.dns_records[0].target_state.as_deref(),
            Some("PROPAGATED")
        );

        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        for rule_id in [1, 3] {
            let sync = repo
                .find_dns_record_sync(rule_id, crate::service::dnsmgr::DEFAULT_LINE_KEY)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sync.expected_value.as_deref(), Some("203.0.113.5"));
            assert_eq!(sync.state, "PENDING");
            set_sync_state(&repo, rule_id, "PROPAGATED", None, None).await;
        }
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RolledBack { .. }
        ));
        let terminal = load_preference(&repo, 7).await.unwrap();
        assert_eq!(terminal.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(terminal.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(terminal.state, RelayPreferencePhase::FailedRolledBack);
        assert_eq!(terminal.last_error.as_deref(), Some("DNS_RECORD_CONFLICT"));
        let view = get_relay_preference(&repo, &connections, 7).await.unwrap();
        assert!(view
            .dns_records
            .iter()
            .all(|record| record.position == RelayDnsRecordPosition::Rollback));

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
    async fn target_not_ready_after_dns_is_rolled_back_before_explicit_retry() {
        let (repo, connections, _) = switch_fixture().await;
        assert_eq!(
            start_relay_switch(&repo, &connections, 7, "node-a")
                .await
                .unwrap(),
            StartRelaySwitchOutcome::AlreadyPreferred
        );
        assert!(repo
            .find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());

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
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let rolling_back = load_preference(&repo, 7).await.unwrap();
        assert_eq!(rolling_back.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(rolling_back.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(rolling_back.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            rolling_back.last_error.as_deref(),
            Some("TARGET_NOT_READY_AFTER_DNS")
        );
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        for rule_id in [1, 3] {
            set_sync_state(&repo, rule_id, "PROPAGATED", None, None).await;
        }
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RolledBack { .. }
        ));

        let rollback = start_relay_switch(&repo, &connections, 7, "node-a")
            .await
            .unwrap();
        assert!(matches!(rollback, StartRelaySwitchOutcome::Started { .. }));
        let switching_a = load_preference(&repo, 7).await.unwrap();
        assert_eq!(switching_a.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(switching_a.pending_node_id.as_deref(), Some("node-a"));
        assert_eq!(switching_a.state, RelayPreferencePhase::Switching);
        assert_eq!(
            repo.find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
                .await
                .unwrap()
                .unwrap()
                .expected_value
                .as_deref(),
            Some("203.0.113.5")
        );
    }

    #[tokio::test]
    async fn missing_target_status_or_ip_starts_rollback_instead_of_staying_switching() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        repo.delete("node_status:7:node-b").await.unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let missing_status = load_preference(&repo, 7).await.unwrap();
        assert_eq!(missing_status.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(missing_status.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(missing_status.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            missing_status.last_error.as_deref(),
            Some("TARGET_STATUS_UNAVAILABLE")
        );
        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        assert_eq!(
            repo.find_dns_record_sync(1, crate::service::dnsmgr::DEFAULT_LINE_KEY)
                .await
                .unwrap()
                .unwrap()
                .expected_value
                .as_deref(),
            Some("203.0.113.5")
        );

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
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let missing_ip = load_preference(&repo, 7).await.unwrap();
        assert_eq!(missing_ip.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(missing_ip.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(missing_ip.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            missing_ip.last_error.as_deref(),
            Some("TARGET_PUBLIC_IPV4_UNAVAILABLE")
        );

        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        repo.set("node_status:7:node-b", &switch_status("203.0.113.66"))
            .await
            .unwrap();
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));
        let changed_ip = load_preference(&repo, 7).await.unwrap();
        assert_eq!(changed_ip.state, RelayPreferencePhase::RollingBack);
        assert_eq!(
            changed_ip.last_error.as_deref(),
            Some("TARGET_PUBLIC_IPV4_CHANGED")
        );
    }

    #[tokio::test]
    async fn rollback_failure_exposes_split_dns_and_requires_manual_intervention() {
        let (repo, connections, _) = switch_fixture().await;
        start_relay_switch(&repo, &connections, 7, "node-b")
            .await
            .unwrap();
        set_sync_state(&repo, 1, "PROPAGATED", None, None).await;
        set_sync_state(&repo, 3, "CONFLICT", Some("DNS_RECORD_CONFLICT"), None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::RollbackStarted { .. }
        ));

        crate::service::dnsmgr::refresh_all_desired(&repo)
            .await
            .unwrap();
        set_sync_state(
            &repo,
            1,
            "CONFLICT",
            Some("ROLLBACK_PROVIDER_CONFLICT"),
            None,
        )
        .await;
        set_sync_state(&repo, 3, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::ManualIntervention { .. }
        ));

        let failed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(failed.state, RelayPreferencePhase::FailedManualIntervention);
        assert_eq!(failed.preferred_node_id.as_deref(), Some("node-a"));
        assert_eq!(failed.pending_node_id.as_deref(), Some("node-b"));
        assert_eq!(
            failed.rollback_error.as_deref(),
            Some("ROLLBACK_PROVIDER_CONFLICT")
        );
        let view = get_relay_preference(&repo, &connections, 7).await.unwrap();
        let by_rule = view
            .dns_records
            .iter()
            .map(|record| (record.rule_id, record.position.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_rule[&1], RelayDnsRecordPosition::Target);
        assert_eq!(by_rule[&3], RelayDnsRecordPosition::Rollback);
    }

    #[tokio::test]
    async fn multiple_public_answers_trigger_rollback_and_are_terminal_during_rollback() {
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
            FinalizeOutcome::RollbackStarted { .. }
        ));

        set_sync_state(
            &repo,
            1,
            "PROPAGATED",
            Some("PUBLIC_DNS_MULTIPLE_ANSWERS"),
            None,
        )
        .await;
        set_sync_state(&repo, 3, "PROPAGATED", None, None).await;
        assert!(matches!(
            finalize_switching_group(&repo, &connections, 7)
                .await
                .unwrap(),
            FinalizeOutcome::ManualIntervention { .. }
        ));
        let failed = load_preference(&repo, 7).await.unwrap();
        assert_eq!(failed.state, RelayPreferencePhase::FailedManualIntervention);
        assert_eq!(
            failed.rollback_error.as_deref(),
            Some("PUBLIC_DNS_MULTIPLE_ANSWERS")
        );
        let view = get_relay_preference(&repo, &connections, 7).await.unwrap();
        assert_eq!(
            view.dns_records
                .iter()
                .find(|record| record.rule_id == 1)
                .map(|record| &record.position),
            Some(&RelayDnsRecordPosition::Unknown),
            "multiple public answers must never be presented as a confirmed target or rollback"
        );
    }
}
