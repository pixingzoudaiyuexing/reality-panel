//! Group-level automatic Relay failover.
//!
//! Stable policy and exclusion state live in KVS. Probe observations and the
//! continuous-failure timer are deliberately process-local so a Panel restart
//! always establishes a fresh health baseline before it can switch anything.

use crate::api::ws::NodeConnections;
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use crate::service::relay_preference::{
    RelayPreferencePhase, RelayPreferenceState, RelayReadyNode, StartRelaySwitchOutcome,
};
use futures_util::{stream, StreamExt};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

pub const RELAY_FAILOVER_KEY_PREFIX: &str = "relay_failover:";
const MODEL_VERSION: u32 = 1;
const DEFAULT_HEALTH_CHECK_PORT: u16 = 443;
const DEFAULT_FAILURE_AFTER_SECONDS: u64 = 5;
const MAX_FAILURE_AFTER_SECONDS: u64 = 86_400;
const WATCH_TICK: Duration = Duration::from_secs(1);
const BACKUP_PROBE_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);
const MAX_CONCURRENT_GROUPS: usize = 16;
const MAX_CONCURRENT_PROBES: usize = 32;
const RETRY_BACKOFF_SECONDS: [u64; 4] = [5, 10, 20, 30];

/// Serializes writes which enable one of the three mutually-exclusive Group
/// automation policies. The Panel has one process, matching the existing KVS
/// and Relay Preference locking model.
static AUTOMATIC_POLICY_MUTATION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static FAILOVER_MUTATION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static GROUP_RUNTIMES: Lazy<StdMutex<HashMap<i64, Arc<GroupRuntime>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));
static PROBE_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(MAX_CONCURRENT_PROBES));

pub(crate) async fn lock_automatic_policy() -> tokio::sync::MutexGuard<'static, ()> {
    AUTOMATIC_POLICY_MUTATION_LOCK.lock().await
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RelayFailoverPolicy {
    pub model_version: u32,
    pub enabled: bool,
    pub health_check_port: u16,
    pub failure_after_seconds: u64,
    pub excluded_failed_node_ids: BTreeSet<String>,
    pub last_switch_at: Option<String>,
    pub last_from_node_id: Option<String>,
    pub last_to_node_id: Option<String>,
    pub last_result: Option<String>,
    pub last_error: Option<String>,
}

impl Default for RelayFailoverPolicy {
    fn default() -> Self {
        Self {
            model_version: MODEL_VERSION,
            enabled: false,
            health_check_port: DEFAULT_HEALTH_CHECK_PORT,
            failure_after_seconds: DEFAULT_FAILURE_AFTER_SECONDS,
            excluded_failed_node_ids: BTreeSet::new(),
            last_switch_at: None,
            last_from_node_id: None,
            last_to_node_id: None,
            last_result: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayProbeStatus {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayFailoverNodeView {
    pub node_id: String,
    pub public_ipv4: Option<String>,
    pub ready: bool,
    pub ready_reasons: Vec<String>,
    pub current: bool,
    pub excluded: bool,
    pub probe_status: RelayProbeStatus,
    pub last_probed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayFailoverView {
    #[serde(flatten)]
    pub policy: RelayFailoverPolicy,
    pub group_id: i64,
    pub current_node_id: Option<String>,
    pub nodes: Vec<RelayFailoverNodeView>,
}

#[derive(Debug)]
pub enum RelayFailoverError {
    Database(DbError),
    InvalidStoredData(String),
    InvalidInput(String),
    InboundGroupNotFound,
    ScheduleEnabled,
    CarrierPolicyEnabled,
    NodeNotInGroup,
    NodeNotReady,
    NodeProbeAddressInvalid,
    NodeStillUnhealthy,
}

impl std::fmt::Display for RelayFailoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::InvalidStoredData(error) => write!(f, "stored failover data is invalid: {error}"),
            Self::InvalidInput(error) => f.write_str(error),
            Self::InboundGroupNotFound => f.write_str("inbound group not found"),
            Self::ScheduleEnabled => {
                f.write_str("该分组已启用定时切换，请先停用后再启用故障切换。")
            }
            Self::CarrierPolicyEnabled => {
                f.write_str("该分组已启用运营商策略，请先清空后再启用故障切换。")
            }
            Self::NodeNotInGroup => f.write_str("节点不属于当前分组。"),
            Self::NodeNotReady | Self::NodeProbeAddressInvalid | Self::NodeStillUnhealthy => {
                f.write_str("当前节点仍未通过健康检查，无法重新纳入备选。")
            }
        }
    }
}

impl std::error::Error for RelayFailoverError {}

impl From<DbError> for RelayFailoverError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

impl From<crate::service::relay_preference::RelayPreferenceError> for RelayFailoverError {
    fn from(error: crate::service::relay_preference::RelayPreferenceError) -> Self {
        match error {
            crate::service::relay_preference::RelayPreferenceError::Database(error) => {
                Self::Database(error)
            }
            crate::service::relay_preference::RelayPreferenceError::InvalidPreference(error) => {
                Self::InvalidStoredData(error.to_string())
            }
        }
    }
}

impl From<crate::service::relay_schedule::RelayScheduleError> for RelayFailoverError {
    fn from(error: crate::service::relay_schedule::RelayScheduleError) -> Self {
        match error {
            crate::service::relay_schedule::RelayScheduleError::Database(error) => {
                Self::Database(error)
            }
            other => Self::InvalidStoredData(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
struct ProbeObservation {
    healthy: bool,
    observed_at: String,
}

#[derive(Debug, Default)]
struct TransientState {
    current_node_id: Option<String>,
    failure_started_at: Option<Instant>,
    last_backup_probe_at: Option<Instant>,
    last_decision_at: Option<Instant>,
    retry_attempts: usize,
    retry_not_before: Option<Instant>,
    probes: HashMap<String, ProbeObservation>,
}

#[derive(Debug, Default)]
struct GroupRuntime {
    operation: Mutex<()>,
    transient: Mutex<TransientState>,
}

fn failover_key(group_id: i64) -> String {
    format!("{RELAY_FAILOVER_KEY_PREFIX}{group_id}")
}

fn runtime_for(group_id: i64) -> Arc<GroupRuntime> {
    let mut runtimes = GROUP_RUNTIMES
        .lock()
        .expect("failover runtime map poisoned");
    runtimes
        .entry(group_id)
        .or_insert_with(|| Arc::new(GroupRuntime::default()))
        .clone()
}

fn remove_runtime(group_id: i64) {
    GROUP_RUNTIMES
        .lock()
        .expect("failover runtime map poisoned")
        .remove(&group_id);
}

fn runtime_is_current(group_id: i64, runtime: &Arc<GroupRuntime>) -> bool {
    GROUP_RUNTIMES
        .lock()
        .expect("failover runtime map poisoned")
        .get(&group_id)
        .is_some_and(|current| Arc::ptr_eq(current, runtime))
}

fn prune_runtimes(enabled_group_ids: &HashSet<i64>) {
    GROUP_RUNTIMES
        .lock()
        .expect("failover runtime map poisoned")
        .retain(|group_id, _| enabled_group_ids.contains(group_id));
}

pub(crate) async fn load_policy(
    db: &dyn Repository,
    group_id: i64,
) -> Result<RelayFailoverPolicy, RelayFailoverError> {
    let Some(raw) = db.get(&failover_key(group_id)).await? else {
        return Ok(RelayFailoverPolicy::default());
    };
    let policy: RelayFailoverPolicy = serde_json::from_str(&raw)
        .map_err(|error| RelayFailoverError::InvalidStoredData(error.to_string()))?;
    validate_policy(&policy)?;
    Ok(policy)
}

async fn store_policy(
    db: &dyn Repository,
    group_id: i64,
    policy: &RelayFailoverPolicy,
) -> Result<(), RelayFailoverError> {
    db.set(
        &failover_key(group_id),
        &serde_json::to_string(policy)
            .map_err(|error| RelayFailoverError::InvalidStoredData(error.to_string()))?,
    )
    .await?;
    Ok(())
}

fn validate_policy(policy: &RelayFailoverPolicy) -> Result<(), RelayFailoverError> {
    if policy.model_version != MODEL_VERSION {
        return Err(RelayFailoverError::InvalidStoredData(format!(
            "unsupported model_version {}",
            policy.model_version
        )));
    }
    if policy.health_check_port == 0 {
        return Err(RelayFailoverError::InvalidInput(
            "health_check_port must be between 1 and 65535".into(),
        ));
    }
    if policy.failure_after_seconds == 0 || policy.failure_after_seconds > MAX_FAILURE_AFTER_SECONDS
    {
        return Err(RelayFailoverError::InvalidInput(format!(
            "failure_after_seconds must be between 1 and {MAX_FAILURE_AFTER_SECONDS}"
        )));
    }
    Ok(())
}

async fn ensure_inbound_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<(), RelayFailoverError> {
    match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(group) if group.group_type == "in" => Ok(()),
        _ => Err(RelayFailoverError::InboundGroupNotFound),
    }
}

pub(crate) async fn enabled_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<bool, RelayFailoverError> {
    Ok(load_policy(db, group_id).await?.enabled)
}

pub async fn update_policy(
    db: &dyn Repository,
    group_id: i64,
    enabled: bool,
    health_check_port: u16,
    failure_after_seconds: u64,
) -> Result<RelayFailoverPolicy, RelayFailoverError> {
    ensure_inbound_group(db, group_id).await?;
    let candidate = RelayFailoverPolicy {
        enabled,
        health_check_port,
        failure_after_seconds,
        ..RelayFailoverPolicy::default()
    };
    validate_policy(&candidate)?;

    let _policy_guard = lock_automatic_policy().await;
    if enabled {
        if crate::service::relay_schedule::has_enabled_schedule_for_group(db, group_id).await? {
            return Err(RelayFailoverError::ScheduleEnabled);
        }
        if crate::service::relay_preference::carrier_policy_is_configured(db, group_id).await? {
            return Err(RelayFailoverError::CarrierPolicyEnabled);
        }
    }

    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    let mut policy = load_policy(db, group_id).await?;
    let resume_exhausted = enabled && automatic_switch_suspended(&policy);
    let reset_runtime = policy.enabled != enabled
        || policy.health_check_port != health_check_port
        || policy.failure_after_seconds != failure_after_seconds
        || resume_exhausted;
    if enabled && (!policy.enabled || resume_exhausted) {
        policy.last_result = None;
        policy.last_error = None;
    }
    policy.enabled = enabled;
    policy.health_check_port = health_check_port;
    policy.failure_after_seconds = failure_after_seconds;
    store_policy(db, group_id, &policy).await?;
    if reset_runtime {
        remove_runtime(group_id);
    }
    Ok(policy)
}

pub async fn delete_failover(db: &dyn Repository, group_id: i64) -> Result<(), DbError> {
    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    db.delete(&failover_key(group_id)).await?;
    remove_runtime(group_id);
    Ok(())
}

pub async fn remove_excluded_node(
    db: &dyn Repository,
    group_id: i64,
    node_id: &str,
) -> Result<bool, RelayFailoverError> {
    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    let Some(raw) = db.get(&failover_key(group_id)).await? else {
        return Ok(false);
    };
    let mut policy: RelayFailoverPolicy = serde_json::from_str(&raw)
        .map_err(|error| RelayFailoverError::InvalidStoredData(error.to_string()))?;
    if !policy.excluded_failed_node_ids.remove(node_id) {
        return Ok(false);
    }
    store_policy(db, group_id, &policy).await?;
    let runtime = {
        GROUP_RUNTIMES
            .lock()
            .expect("failover runtime map poisoned")
            .get(&group_id)
            .cloned()
    };
    if let Some(runtime) = runtime {
        runtime.transient.lock().await.probes.remove(node_id);
    }
    Ok(true)
}

/// Private and other ordinary unicast ranges are accepted intentionally: a
/// future Panel may probe Relays over a VPC. Special/non-host ranges and
/// link-local metadata space are never valid probe destinations.
fn valid_probe_ipv4(value: Option<&str>) -> Option<Ipv4Addr> {
    let ip = value?.trim().parse::<Ipv4Addr>().ok()?;
    let octets = ip.octets();
    let protocol_assignment = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
    let benchmark = octets[0] == 198 && matches!(octets[1], 18 | 19);
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || octets[0] == 0
        || octets[0] >= 240
        || protocol_assignment
        || benchmark
    {
        None
    } else {
        Some(ip)
    }
}

async fn tcp_probe(ip: Ipv4Addr, port: u16) -> bool {
    let permit = match PROBE_SEMAPHORE.acquire().await {
        Ok(permit) => permit,
        Err(_) => return false,
    };
    let result = tokio::time::timeout(
        PROBE_TIMEOUT,
        TcpStream::connect(SocketAddrV4::new(ip, port)),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    drop(permit);
    result
}

fn candidate_nodes(
    nodes: &[RelayReadyNode],
    current_node_id: &str,
    excluded: &BTreeSet<String>,
) -> Vec<(String, Ipv4Addr)> {
    nodes
        .iter()
        .filter(|node| node.node_id != current_node_id)
        .filter(|node| node.ready)
        .filter(|node| !excluded.contains(&node.node_id))
        .filter_map(|node| {
            valid_probe_ipv4(node.public_ipv4.as_deref()).map(|ip| (node.node_id.clone(), ip))
        })
        .collect()
}

fn choose_candidate(candidates: &mut [String]) -> Option<&str> {
    candidates.sort_unstable();
    candidates.first().map(String::as_str)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayAttemptDisposition {
    None,
    Wait,
    Succeeded,
    RolledBack,
    ManualIntervention,
    Aborted,
}

fn relay_attempt_disposition(
    policy: &RelayFailoverPolicy,
    preference: &RelayPreferenceState,
) -> RelayAttemptDisposition {
    if policy.last_result.as_deref() != Some("started") {
        return match preference.state {
            RelayPreferencePhase::Switching
            | RelayPreferencePhase::RollingBack
            | RelayPreferencePhase::FailedManualIntervention => RelayAttemptDisposition::Wait,
            _ => RelayAttemptDisposition::None,
        };
    }
    let (Some(from_node_id), Some(to_node_id)) = (
        policy.last_from_node_id.as_deref(),
        policy.last_to_node_id.as_deref(),
    ) else {
        return RelayAttemptDisposition::Aborted;
    };
    match preference.state {
        RelayPreferencePhase::Switching | RelayPreferencePhase::RollingBack => {
            RelayAttemptDisposition::Wait
        }
        RelayPreferencePhase::Idle
            if preference.preferred_node_id.as_deref() == Some(to_node_id) =>
        {
            RelayAttemptDisposition::Succeeded
        }
        RelayPreferencePhase::Failed | RelayPreferencePhase::FailedRolledBack
            if preference.preferred_node_id.as_deref() == Some(from_node_id) =>
        {
            RelayAttemptDisposition::RolledBack
        }
        RelayPreferencePhase::FailedManualIntervention => {
            RelayAttemptDisposition::ManualIntervention
        }
        _ => RelayAttemptDisposition::Aborted,
    }
}

fn retry_delay(attempt: usize) -> Duration {
    let index = attempt.min(RETRY_BACKOFF_SECONDS.len() - 1);
    Duration::from_secs(RETRY_BACKOFF_SECONDS[index])
}

fn schedule_retry(transient: &mut TransientState, now: Instant) {
    transient.retry_not_before = Some(now + retry_delay(transient.retry_attempts));
    transient.retry_attempts = transient.retry_attempts.saturating_add(1);
}

fn retry_ready(transient: &TransientState, now: Instant) -> bool {
    transient
        .retry_not_before
        .is_none_or(|not_before| now >= not_before)
}

fn reset_retry(transient: &mut TransientState) {
    transient.retry_attempts = 0;
    transient.retry_not_before = None;
}

fn automatic_switch_suspended(policy: &RelayFailoverPolicy) -> bool {
    policy.last_result.as_deref() == Some("exhausted")
}

async fn observe_probe(runtime: &GroupRuntime, node_id: &str, healthy: bool) {
    runtime.transient.lock().await.probes.insert(
        node_id.to_string(),
        ProbeObservation {
            healthy,
            observed_at: chrono::Utc::now().to_rfc3339(),
        },
    );
}

async fn probe_backups_if_due(
    runtime: &GroupRuntime,
    nodes: &[RelayReadyNode],
    current_node_id: &str,
    excluded: &BTreeSet<String>,
    port: u16,
    now: Instant,
) {
    {
        let mut transient = runtime.transient.lock().await;
        if transient
            .last_backup_probe_at
            .is_some_and(|last| now.duration_since(last) < BACKUP_PROBE_INTERVAL)
        {
            return;
        }
        transient.last_backup_probe_at = Some(now);
    }
    let candidates = candidate_nodes(nodes, current_node_id, excluded);
    let results = stream::iter(
        candidates
            .into_iter()
            .map(|(node_id, ip)| async move { (node_id, tcp_probe(ip, port).await) }),
    )
    .buffer_unordered(MAX_CONCURRENT_PROBES)
    .collect::<Vec<_>>()
    .await;
    for (node_id, healthy) in results {
        observe_probe(runtime, &node_id, healthy).await;
    }
}

fn failure_threshold_reached(
    failure_started_at: &mut Option<Instant>,
    healthy: bool,
    now: Instant,
    threshold: Duration,
) -> bool {
    if healthy {
        *failure_started_at = None;
        return false;
    }
    let started_at = failure_started_at.get_or_insert(now);
    now.duration_since(*started_at) >= threshold
}

async fn mark_failed_node_excluded(
    db: &dyn Repository,
    group_id: i64,
    node_id: &str,
    expected_policy: &RelayFailoverPolicy,
) -> Result<Option<RelayFailoverPolicy>, RelayFailoverError> {
    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    let mut policy = load_policy(db, group_id).await?;
    if !policy.enabled
        || policy.health_check_port != expected_policy.health_check_port
        || policy.failure_after_seconds != expected_policy.failure_after_seconds
    {
        return Ok(None);
    }
    if policy.excluded_failed_node_ids.insert(node_id.to_string()) {
        store_policy(db, group_id, &policy).await?;
    }
    Ok(Some(policy))
}

async fn persist_outcome(
    db: &dyn Repository,
    group_id: i64,
    expected_policy: &RelayFailoverPolicy,
    from_node_id: &str,
    to_node_id: Option<&str>,
    result: &str,
    error: Option<&str>,
) -> Result<bool, RelayFailoverError> {
    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    let mut policy = load_policy(db, group_id).await?;
    if !policy.enabled
        || policy.health_check_port != expected_policy.health_check_port
        || policy.failure_after_seconds != expected_policy.failure_after_seconds
    {
        return Ok(false);
    }
    let changed = policy.last_from_node_id.as_deref() != Some(from_node_id)
        || policy.last_to_node_id.as_deref() != to_node_id
        || policy.last_result.as_deref() != Some(result)
        || policy.last_error.as_deref() != error;
    if !changed {
        return Ok(false);
    }
    if result == "started" {
        policy.last_switch_at = Some(chrono::Utc::now().to_rfc3339());
    }
    policy.last_from_node_id = Some(from_node_id.to_string());
    policy.last_to_node_id = to_node_id.map(str::to_string);
    policy.last_result = Some(result.to_string());
    policy.last_error = error.map(str::to_string);
    store_policy(db, group_id, &policy).await?;
    Ok(true)
}

async fn notify_failover(state: &AppState, group_id: i64, subject: &str, text: &str, event: &str) {
    let raw = state
        .db
        .get(crate::service::notify::NOTIFY_CONFIG_KEY)
        .await
        .ok()
        .flatten();
    let cfg = crate::service::notify::NotifyConfig::from_json(raw.as_deref());
    if !cfg.any_channel_enabled() {
        return;
    }
    let report = crate::service::notify::send_all(&cfg, subject, text).await;
    crate::service::notify::record_report(
        state.db.as_ref(),
        event,
        Some(&format!("group:{group_id}")),
        &report,
    )
    .await;
}

async fn process_group(state: &AppState, group_id: i64, policy: RelayFailoverPolicy) {
    let runtime = runtime_for(group_id);
    let Ok(_operation_guard) = runtime.operation.try_lock() else {
        return;
    };
    let preference = match crate::service::relay_preference::load_preference(
        state.db.as_ref(),
        group_id,
    )
    .await
    {
        Ok(preference) => preference,
        Err(error) => {
            tracing::warn!(group_id, "failover preference read failed: {error}");
            return;
        }
    };
    match relay_attempt_disposition(&policy, &preference) {
        RelayAttemptDisposition::Wait => return,
        RelayAttemptDisposition::Succeeded => {
            if persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                policy.last_from_node_id.as_deref().unwrap_or("unknown"),
                policy.last_to_node_id.as_deref(),
                "success",
                None,
            )
            .await
            .unwrap_or(false)
            {
                let mut transient = runtime.transient.lock().await;
                reset_retry(&mut transient);
                drop(transient);
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_FAILOVER_SUCCEEDED",
                    "device_group",
                    group_id,
                    &format!(
                        "from_node_id={} to_node_id={}",
                        policy.last_from_node_id.as_deref().unwrap_or("none"),
                        policy.last_to_node_id.as_deref().unwrap_or("none")
                    ),
                )
                .await;
            }
            return;
        }
        RelayAttemptDisposition::RolledBack => {
            let error = preference
                .last_error
                .as_deref()
                .unwrap_or("DNS_TRANSACTION_ROLLED_BACK");
            if persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                policy.last_from_node_id.as_deref().unwrap_or("unknown"),
                policy.last_to_node_id.as_deref(),
                "failed",
                Some(error),
            )
            .await
            .unwrap_or(false)
            {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_FAILOVER_FAILED",
                    "device_group",
                    group_id,
                    &format!("error={error}"),
                )
                .await;
            }
            let mut transient = runtime.transient.lock().await;
            schedule_retry(&mut transient, Instant::now());
        }
        RelayAttemptDisposition::ManualIntervention => {
            let error = preference
                .rollback_error
                .as_deref()
                .or(preference.last_error.as_deref())
                .unwrap_or("DNS_MANUAL_INTERVENTION_REQUIRED");
            let _ = persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                policy.last_from_node_id.as_deref().unwrap_or("unknown"),
                policy.last_to_node_id.as_deref(),
                "failed",
                Some(error),
            )
            .await;
            return;
        }
        RelayAttemptDisposition::Aborted => {
            let _ = persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                policy.last_from_node_id.as_deref().unwrap_or("unknown"),
                policy.last_to_node_id.as_deref(),
                "aborted",
                Some("RELAY_TRANSACTION_STATE_CHANGED"),
            )
            .await;
            return;
        }
        RelayAttemptDisposition::None => {}
    }
    if automatic_switch_suspended(&policy) {
        return;
    }
    let Some(current_node_id) = preference.preferred_node_id else {
        runtime.transient.lock().await.failure_started_at = None;
        return;
    };
    let nodes = match crate::service::relay_preference::evaluate_group_ready_nodes(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::warn!(group_id, "failover Ready evaluation failed: {error}");
            return;
        }
    };
    let current_ip = nodes
        .iter()
        .find(|node| node.node_id == current_node_id)
        .and_then(|node| valid_probe_ipv4(node.public_ipv4.as_deref()));
    let current_healthy = match current_ip {
        Some(ip) => tcp_probe(ip, policy.health_check_port).await,
        None => false,
    };
    observe_probe(&runtime, &current_node_id, current_healthy).await;

    let now = Instant::now();
    let threshold_reached = {
        let mut transient = runtime.transient.lock().await;
        if transient.current_node_id.as_deref() != Some(current_node_id.as_str()) {
            let replacing_known_current = transient.current_node_id.is_some();
            transient.current_node_id = Some(current_node_id.clone());
            transient.failure_started_at = None;
            transient.last_decision_at = None;
            if replacing_known_current {
                reset_retry(&mut transient);
            }
        }
        failure_threshold_reached(
            &mut transient.failure_started_at,
            current_healthy,
            now,
            Duration::from_secs(policy.failure_after_seconds),
        )
    };

    probe_backups_if_due(
        &runtime,
        &nodes,
        &current_node_id,
        &policy.excluded_failed_node_ids,
        policy.health_check_port,
        now,
    )
    .await;
    if current_healthy || !threshold_reached {
        if current_healthy {
            let mut transient = runtime.transient.lock().await;
            reset_retry(&mut transient);
        }
        return;
    }

    {
        let mut transient = runtime.transient.lock().await;
        if !retry_ready(&transient, now) {
            return;
        }
        if transient
            .last_decision_at
            .is_some_and(|last| now.duration_since(last) < BACKUP_PROBE_INTERVAL)
        {
            return;
        }
        transient.last_decision_at = Some(now);
    }
    if !runtime_is_current(group_id, &runtime) {
        return;
    }
    let policy =
        match mark_failed_node_excluded(state.db.as_ref(), group_id, &current_node_id, &policy)
            .await
        {
            Ok(Some(policy)) => policy,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(group_id, "failover exclusion persistence failed: {error}");
                return;
            }
        };

    // The decision uses a fresh Ready snapshot and fresh parallel TCP probes.
    let nodes = match crate::service::relay_preference::evaluate_group_ready_nodes(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::warn!(group_id, "failover candidate evaluation failed: {error}");
            return;
        }
    };
    let candidates = candidate_nodes(&nodes, &current_node_id, &policy.excluded_failed_node_ids);
    let health_check_port = policy.health_check_port;
    let probe_results = stream::iter(
        candidates
            .into_iter()
            .map(|(node_id, ip)| async move { (node_id, tcp_probe(ip, health_check_port).await) }),
    )
    .buffer_unordered(MAX_CONCURRENT_PROBES)
    .collect::<Vec<_>>()
    .await;
    let mut healthy_ids = Vec::new();
    for (node_id, healthy) in probe_results {
        observe_probe(&runtime, &node_id, healthy).await;
        if healthy {
            healthy_ids.push(node_id);
        }
    }
    if !runtime_is_current(group_id, &runtime) {
        return;
    }
    let Some(target_node_id) = choose_candidate(&mut healthy_ids).map(str::to_string) else {
        if persist_outcome(
            state.db.as_ref(),
            group_id,
            &policy,
            &current_node_id,
            None,
            "exhausted",
            Some("NO_AVAILABLE_CANDIDATES"),
        )
        .await
        .unwrap_or(false)
        {
            crate::service::audit::record(
                state,
                None,
                "RELAY_FAILOVER_FAILED",
                "device_group",
                group_id,
                &format!("from_node_id={current_node_id} error=NO_AVAILABLE_CANDIDATES"),
            )
            .await;
            notify_failover(
                state,
                group_id,
                "Reality Panel 故障切换失败",
                &format!(
                    "分组 {group_id} 的当前节点 {current_node_id} 不可达，且没有可用备选节点。"
                ),
                "relay_failover_failed",
            )
            .await;
        }
        return;
    };

    match crate::service::relay_preference::start_relay_switch_if_current(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        &current_node_id,
        &target_node_id,
    )
    .await
    {
        Ok(Some(StartRelaySwitchOutcome::Started { .. })) => {
            if persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                &current_node_id,
                Some(&target_node_id),
                "started",
                None,
            )
            .await
            .unwrap_or(false)
            {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_FAILOVER_REQUESTED",
                    "device_group",
                    group_id,
                    &format!("from_node_id={current_node_id} to_node_id={target_node_id}"),
                )
                .await;
                notify_failover(
                    state,
                    group_id,
                    "Reality Panel 自动故障切换",
                    &format!("分组 {group_id} 已从故障节点 {current_node_id} 开始切换到 {target_node_id}。"),
                    "relay_failover_started",
                )
                .await;
            }
        }
        Ok(Some(_)) | Ok(None) => {
            let _ = persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                &current_node_id,
                Some(&target_node_id),
                "aborted",
                Some("PREFERRED_NODE_CHANGED_OR_BUSY"),
            )
            .await;
        }
        Err(error) => {
            let detail = error.to_string();
            if !runtime_is_current(group_id, &runtime) {
                return;
            }
            let changed = persist_outcome(
                state.db.as_ref(),
                group_id,
                &policy,
                &current_node_id,
                Some(&target_node_id),
                "failed",
                Some(&detail),
            )
            .await
            .unwrap_or(false);
            let mut transient = runtime.transient.lock().await;
            schedule_retry(&mut transient, Instant::now());
            drop(transient);
            if changed {
                crate::service::audit::record(
                    state,
                    None,
                    "RELAY_FAILOVER_FAILED",
                    "device_group",
                    group_id,
                    &format!(
                        "from_node_id={current_node_id} to_node_id={target_node_id} error={detail}"
                    ),
                )
                .await;
            }
        }
    }
}

pub async fn get_view(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
) -> Result<RelayFailoverView, RelayFailoverError> {
    ensure_inbound_group(db, group_id).await?;
    let policy = load_policy(db, group_id).await?;
    let preference = crate::service::relay_preference::load_preference(db, group_id).await?;
    let ready_nodes = crate::service::relay_preference::evaluate_group_ready_nodes(
        db,
        node_connections,
        group_id,
    )
    .await?;
    let current_node_id = preference.preferred_node_id;
    let runtime = {
        GROUP_RUNTIMES
            .lock()
            .expect("failover runtime map poisoned")
            .get(&group_id)
            .cloned()
    };
    let observations = match runtime {
        Some(runtime) => runtime.transient.lock().await.probes.clone(),
        None => HashMap::new(),
    };
    let nodes = ready_nodes
        .into_iter()
        .map(|node| {
            let observation = observations.get(&node.node_id);
            RelayFailoverNodeView {
                current: current_node_id.as_deref() == Some(node.node_id.as_str()),
                excluded: policy.excluded_failed_node_ids.contains(&node.node_id),
                probe_status: match observation.map(|observation| observation.healthy) {
                    Some(true) => RelayProbeStatus::Healthy,
                    Some(false) => RelayProbeStatus::Unhealthy,
                    None => RelayProbeStatus::Unknown,
                },
                last_probed_at: observation.map(|observation| observation.observed_at.clone()),
                node_id: node.node_id,
                public_ipv4: node.public_ipv4,
                ready: node.ready,
                ready_reasons: node.ready_reasons,
            }
        })
        .collect();
    Ok(RelayFailoverView {
        policy,
        group_id,
        current_node_id,
        nodes,
    })
}

async fn reinclude_with_probe<F, Fut>(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    node_id: &str,
    probe: F,
) -> Result<RelayFailoverPolicy, RelayFailoverError>
where
    F: FnOnce(Ipv4Addr, u16) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    ensure_inbound_group(db, group_id).await?;
    let policy = load_policy(db, group_id).await?;
    let nodes = crate::service::relay_preference::evaluate_group_ready_nodes(
        db,
        node_connections,
        group_id,
    )
    .await?;
    let node = nodes
        .iter()
        .find(|node| node.node_id == node_id)
        .ok_or(RelayFailoverError::NodeNotInGroup)?;
    if !node.ready {
        return Err(RelayFailoverError::NodeNotReady);
    }
    let ip = valid_probe_ipv4(node.public_ipv4.as_deref())
        .ok_or(RelayFailoverError::NodeProbeAddressInvalid)?;
    let probed_port = policy.health_check_port;
    if !probe(ip, probed_port).await {
        return Err(RelayFailoverError::NodeStillUnhealthy);
    }

    // Re-evaluate after the network await so a stale Ready observation cannot
    // reinclude a node which went offline while the probe was in flight.
    let nodes = crate::service::relay_preference::evaluate_group_ready_nodes(
        db,
        node_connections,
        group_id,
    )
    .await?;
    if !nodes.iter().any(|node| {
        node.node_id == node_id
            && node.ready
            && valid_probe_ipv4(node.public_ipv4.as_deref()) == Some(ip)
    }) {
        return Err(RelayFailoverError::NodeNotReady);
    }
    let _guard = FAILOVER_MUTATION_LOCK.lock().await;
    let mut policy = load_policy(db, group_id).await?;
    if policy.health_check_port != probed_port {
        return Err(RelayFailoverError::NodeStillUnhealthy);
    }
    policy.excluded_failed_node_ids.remove(node_id);
    if policy.last_result.as_deref() == Some("exhausted") {
        policy.last_result = None;
        policy.last_error = None;
    }
    store_policy(db, group_id, &policy).await?;
    let runtime = runtime_for(group_id);
    observe_probe(&runtime, node_id, true).await;
    Ok(policy)
}

pub async fn reinclude_node(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    node_id: &str,
) -> Result<RelayFailoverPolicy, RelayFailoverError> {
    reinclude_with_probe(db, node_connections, group_id, node_id, tcp_probe).await
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(WATCH_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!("relay failover watcher started");
        loop {
            ticker.tick().await;
            let rows = match state.db.scan_prefix(RELAY_FAILOVER_KEY_PREFIX).await {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::error!("relay failover policy scan failed: {error}");
                    continue;
                }
            };
            let policies = rows
                .into_iter()
                .filter_map(|(key, raw)| {
                    let group_id = key.strip_prefix(RELAY_FAILOVER_KEY_PREFIX)?.parse().ok()?;
                    match serde_json::from_str::<RelayFailoverPolicy>(&raw) {
                        Ok(policy) if validate_policy(&policy).is_ok() && policy.enabled => {
                            Some((group_id, policy))
                        }
                        Ok(_) => None,
                        Err(error) => {
                            tracing::error!(group_id, "invalid relay failover policy: {error}");
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();
            prune_runtimes(&policies.iter().map(|(group_id, _)| *group_id).collect());
            stream::iter(policies.into_iter().map(|(group_id, policy)| {
                let state = state.clone();
                async move { process_group(&state, group_id, policy).await }
            }))
            .buffer_unordered(MAX_CONCURRENT_GROUPS)
            .collect::<Vec<_>>()
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{GroupRepository, KvsRepository};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use relay_shared::protocol::{ReconciliationStatusState, CONFIG_PROTOCOL_VERSION};
    use sqlx::sqlite::SqlitePoolOptions;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    async fn test_repo() -> (SqliteRepository, NodeConnections) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let repo = SqliteRepository::new(pool);
        repo.insert_group("relay", "in", "token", 1, "", "1000-1001", 1.0, false)
            .await
            .unwrap();
        (repo, NodeConnections::new())
    }

    fn status(ip: &str, ready: bool) -> String {
        serde_json::json!({
            "last_seen": chrono::Utc::now().to_rfc3339(),
            "public_ipv4": ip,
            "config_protocol_version": CONFIG_PROTOCOL_VERSION,
            "active_listener_rule_ids": [],
            "reconciliation": {
                "state": if ready { ReconciliationStatusState::Converged } else { ReconciliationStatusState::ApplyFailed },
                "recovery_source": "NONE"
            }
        })
        .to_string()
    }

    async fn add_node(
        repo: &SqliteRepository,
        connections: &NodeConnections,
        group_id: i64,
        node_id: &str,
        ip: &str,
        ready: bool,
    ) {
        repo.set(
            &format!("node_status:{group_id}:{node_id}"),
            &status(ip, ready),
        )
        .await
        .unwrap();
        let _ = connections.register(group_id, Some(node_id.into())).await;
    }

    #[test]
    fn probe_address_rejects_special_ranges_but_allows_private_unicast() {
        for rejected in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(valid_probe_ipv4(Some(rejected)), None, "{rejected}");
        }
        assert_eq!(
            valid_probe_ipv4(Some("10.20.30.40")),
            Some("10.20.30.40".parse().unwrap())
        );
        assert_eq!(
            valid_probe_ipv4(Some("8.8.8.8")),
            Some("8.8.8.8".parse().unwrap())
        );
    }

    #[test]
    fn healthy_and_short_failures_do_not_reach_the_switch_threshold() {
        let now = Instant::now();
        let mut started = None;
        assert!(!failure_threshold_reached(
            &mut started,
            true,
            now,
            Duration::from_secs(5)
        ));
        assert_eq!(started, None);
        assert!(!failure_threshold_reached(
            &mut started,
            false,
            now,
            Duration::from_secs(5)
        ));
        assert!(!failure_threshold_reached(
            &mut started,
            false,
            now + Duration::from_secs(4),
            Duration::from_secs(5)
        ));
        assert!(failure_threshold_reached(
            &mut started,
            false,
            now + Duration::from_secs(5),
            Duration::from_secs(5)
        ));
        assert!(!failure_threshold_reached(
            &mut started,
            true,
            now + Duration::from_secs(6),
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn candidates_require_ready_valid_healthy_scope_and_exclusion_is_sticky() {
        let nodes = vec![
            RelayReadyNode {
                node_id: "current".into(),
                public_ipv4: Some("8.8.8.8".into()),
                online: true,
                ready: true,
                ready_reasons: vec![],
                preferred: true,
            },
            RelayReadyNode {
                node_id: "eligible".into(),
                public_ipv4: Some("1.1.1.1".into()),
                online: true,
                ready: true,
                ready_reasons: vec![],
                preferred: false,
            },
            RelayReadyNode {
                node_id: "excluded".into(),
                public_ipv4: Some("9.9.9.9".into()),
                online: true,
                ready: true,
                ready_reasons: vec![],
                preferred: false,
            },
            RelayReadyNode {
                node_id: "unready".into(),
                public_ipv4: Some("8.8.4.4".into()),
                online: false,
                ready: false,
                ready_reasons: vec!["STALE_STATUS".into()],
                preferred: false,
            },
            RelayReadyNode {
                node_id: "invalid".into(),
                public_ipv4: Some("127.0.0.1".into()),
                online: true,
                ready: true,
                ready_reasons: vec![],
                preferred: false,
            },
        ];
        let candidates =
            candidate_nodes(&nodes, "current", &BTreeSet::from(["excluded".to_string()]));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "eligible");
    }

    #[test]
    fn deterministic_selection_always_uses_lowest_node_id() {
        for mut candidates in [
            vec![
                "node-c".to_string(),
                "node-a".to_string(),
                "node-b".to_string(),
            ],
            vec![
                "node-b".to_string(),
                "node-c".to_string(),
                "node-a".to_string(),
            ],
            vec![
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string(),
            ],
        ] {
            assert_eq!(choose_candidate(&mut candidates), Some("node-a"));
        }
        assert_eq!(choose_candidate(&mut []), None);
    }

    fn started_policy() -> RelayFailoverPolicy {
        RelayFailoverPolicy {
            enabled: true,
            last_from_node_id: Some("node-a".into()),
            last_to_node_id: Some("node-b".into()),
            last_result: Some("started".into()),
            ..Default::default()
        }
    }

    fn preference(phase: RelayPreferencePhase, current: &str) -> RelayPreferenceState {
        RelayPreferenceState {
            preferred_node_id: Some(current.into()),
            state: phase,
            ..Default::default()
        }
    }

    #[test]
    fn relay_transaction_states_wait_commit_or_retry_without_guessing_success() {
        let policy = started_policy();
        assert_eq!(
            relay_attempt_disposition(
                &policy,
                &preference(RelayPreferencePhase::Switching, "node-a")
            ),
            RelayAttemptDisposition::Wait
        );
        assert_eq!(
            relay_attempt_disposition(
                &policy,
                &preference(RelayPreferencePhase::RollingBack, "node-a")
            ),
            RelayAttemptDisposition::Wait
        );
        assert_eq!(
            relay_attempt_disposition(&policy, &preference(RelayPreferencePhase::Idle, "node-b")),
            RelayAttemptDisposition::Succeeded
        );
        assert_eq!(
            relay_attempt_disposition(
                &policy,
                &preference(RelayPreferencePhase::FailedRolledBack, "node-a")
            ),
            RelayAttemptDisposition::RolledBack
        );
        assert_eq!(
            relay_attempt_disposition(
                &policy,
                &preference(RelayPreferencePhase::FailedManualIntervention, "node-a")
            ),
            RelayAttemptDisposition::ManualIntervention
        );
    }

    #[test]
    fn provider_failure_retry_backoff_is_bounded_and_resettable() {
        let now = Instant::now();
        let mut transient = TransientState::default();
        for (attempt, expected) in [5, 10, 20, 30, 30].into_iter().enumerate() {
            let attempt_at = now + Duration::from_secs((attempt as u64) * 60);
            schedule_retry(&mut transient, attempt_at);
            assert_eq!(
                transient.retry_not_before,
                Some(attempt_at + Duration::from_secs(expected))
            );
            assert!(!retry_ready(
                &transient,
                attempt_at + Duration::from_secs(expected - 1)
            ));
            assert!(retry_ready(
                &transient,
                attempt_at + Duration::from_secs(expected)
            ));
        }
        reset_retry(&mut transient);
        assert_eq!(transient.retry_attempts, 0);
        assert_eq!(transient.retry_not_before, None);
    }

    #[test]
    fn quarantined_current_still_requires_and_can_reach_a_fresh_failure_threshold() {
        let policy = RelayFailoverPolicy {
            excluded_failed_node_ids: BTreeSet::from(["node-a".to_string()]),
            ..Default::default()
        };
        assert!(policy.excluded_failed_node_ids.contains("node-a"));
        let now = Instant::now();
        let mut failure_started_at = None;
        assert!(!failure_threshold_reached(
            &mut failure_started_at,
            false,
            now,
            Duration::from_secs(5)
        ));
        assert!(failure_threshold_reached(
            &mut failure_started_at,
            false,
            now + Duration::from_secs(5),
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn exhausted_state_suspends_automatic_switching_without_reusing_quarantine() {
        let policy = RelayFailoverPolicy {
            enabled: true,
            last_result: Some("exhausted".into()),
            last_error: Some("NO_AVAILABLE_CANDIDATES".into()),
            excluded_failed_node_ids: BTreeSet::from(["node-a".to_string()]),
            ..Default::default()
        };
        assert!(automatic_switch_suspended(&policy));
        assert_eq!(
            policy.excluded_failed_node_ids,
            BTreeSet::from(["node-a".to_string()])
        );
    }

    #[tokio::test]
    async fn explicit_policy_save_resumes_exhausted_with_a_fresh_runtime() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let mut policy = RelayFailoverPolicy {
            enabled: true,
            last_result: Some("exhausted".into()),
            last_error: Some("NO_AVAILABLE_CANDIDATES".into()),
            ..Default::default()
        };
        policy.excluded_failed_node_ids.insert("node-a".into());
        store_policy(&repo, 1, &policy).await.unwrap();
        let old_runtime = runtime_for(1);

        let resumed = update_policy(&repo, 1, true, 443, 5).await.unwrap();
        assert_eq!(resumed.last_result, None);
        assert_eq!(resumed.last_error, None);
        assert!(resumed.excluded_failed_node_ids.contains("node-a"));
        assert!(!Arc::ptr_eq(&old_runtime, &runtime_for(1)));
    }

    #[tokio::test]
    async fn kvs_persists_only_policy_exclusions_and_results() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let mut policy = update_policy(&repo, 1, false, 8443, 13).await.unwrap();
        policy.excluded_failed_node_ids.insert("node-a".into());
        policy.last_result = Some("failed".into());
        store_policy(&repo, 1, &policy).await.unwrap();
        let raw = repo.get("relay_failover:1").await.unwrap().unwrap();
        assert!(raw.contains("\"model_version\":1"));
        assert!(raw.contains("\"health_check_port\":8443"));
        assert!(raw.contains("node-a"));
        for forbidden in [
            "current_node_id",
            "last_success_at",
            "failure_started_at",
            "probe",
            "retry_",
        ] {
            assert!(
                !raw.contains(forbidden),
                "unexpected persisted field {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn panel_restart_keeps_exclusions_but_restarts_failure_timing() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let mut policy = update_policy(&repo, 1, false, 443, 5).await.unwrap();
        policy.excluded_failed_node_ids.insert("node-a".into());
        store_policy(&repo, 1, &policy).await.unwrap();
        let runtime = runtime_for(1);
        runtime.transient.lock().await.failure_started_at = Some(Instant::now());
        remove_runtime(1);
        assert_eq!(
            load_policy(&repo, 1)
                .await
                .unwrap()
                .excluded_failed_node_ids,
            BTreeSet::from(["node-a".to_string()])
        );
        assert!(runtime_for(1)
            .transient
            .lock()
            .await
            .failure_started_at
            .is_none());
        let restarted = runtime_for(1);
        let now = Instant::now();
        assert!(!failure_threshold_reached(
            &mut restarted.transient.lock().await.failure_started_at,
            false,
            now,
            Duration::from_secs(5),
        ));
    }

    #[tokio::test]
    async fn stale_probe_configuration_cannot_exclude_a_node() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let current = update_policy(&repo, 1, true, 443, 5).await.unwrap();
        let mut stale = current.clone();
        stale.health_check_port = 8443;
        assert!(mark_failed_node_excluded(&repo, 1, "node-a", &stale)
            .await
            .unwrap()
            .is_none());
        assert!(load_policy(&repo, 1)
            .await
            .unwrap()
            .excluded_failed_node_ids
            .is_empty());
    }

    #[tokio::test]
    async fn dns_failure_never_quarantines_the_healthy_target_and_commit_marks_success() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let mut policy = update_policy(&repo, 1, true, 443, 5).await.unwrap();
        policy.excluded_failed_node_ids.insert("node-a".into());
        store_policy(&repo, 1, &policy).await.unwrap();

        persist_outcome(&repo, 1, &policy, "node-a", Some("node-b"), "started", None)
            .await
            .unwrap();
        let started = load_policy(&repo, 1).await.unwrap();
        assert_eq!(started.last_result.as_deref(), Some("started"));
        assert!(started.last_switch_at.is_some());

        persist_outcome(
            &repo,
            1,
            &started,
            "node-a",
            Some("node-b"),
            "failed",
            Some("DNS_TRANSACTION_ROLLED_BACK"),
        )
        .await
        .unwrap();
        let failed = load_policy(&repo, 1).await.unwrap();
        assert_eq!(
            failed.excluded_failed_node_ids,
            BTreeSet::from(["node-a".to_string()])
        );
        assert!(!failed.excluded_failed_node_ids.contains("node-b"));
        assert_eq!(failed.last_switch_at, started.last_switch_at);

        persist_outcome(&repo, 1, &failed, "node-a", Some("node-b"), "started", None)
            .await
            .unwrap();
        let restarted = load_policy(&repo, 1).await.unwrap();

        persist_outcome(
            &repo,
            1,
            &restarted,
            "node-a",
            Some("node-b"),
            "success",
            None,
        )
        .await
        .unwrap();
        let committed = load_policy(&repo, 1).await.unwrap();
        assert_eq!(committed.last_result.as_deref(), Some("success"));
        assert!(committed.last_switch_at.is_some());
        assert_eq!(
            committed.excluded_failed_node_ids,
            BTreeSet::from(["node-a".to_string()])
        );
    }

    #[tokio::test]
    async fn one_group_operation_lock_rejects_overlapping_ticks_but_other_groups_continue() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        remove_runtime(2);
        let first = runtime_for(1);
        let second = runtime_for(2);
        let _first_guard = first.operation.lock().await;
        assert!(first.operation.try_lock().is_err());
        assert!(second.operation.try_lock().is_ok());
    }

    #[tokio::test]
    async fn schedule_and_failover_are_mutually_exclusive_in_both_directions() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        add_node(&repo, &connections, 1, "node-a", "8.8.8.8", true).await;
        update_policy(&repo, 1, true, 443, 5).await.unwrap();
        let schedule = crate::service::relay_schedule::CreateRelayScheduleRequest {
            group_id: 1,
            target_node_id: "node-a".into(),
            schedule_type: "one_time".into(),
            enabled: Some(true),
            execute_at: Some("2099-01-01T00:00:00Z".into()),
            time: None,
            utc_offset_minutes: None,
            weekdays: None,
        };
        assert!(matches!(
            crate::service::relay_schedule::create_schedule(&repo, &connections, schedule).await,
            Err(crate::service::relay_schedule::RelayScheduleError::FailoverEnabled)
        ));

        update_policy(&repo, 1, false, 443, 5).await.unwrap();
        repo.set(
            crate::service::relay_schedule::RELAY_SWITCH_SCHEDULES_KEY,
            r#"[{"id":"s","group_id":1,"target_node_id":"node-a","schedule_type":"daily","enabled":true,"created_at":"x","updated_at":"x","execute_at":null,"time":"12:00","utc_offset_minutes":0,"weekdays":[],"last_run_at":null,"last_run_slot":null,"last_result":null,"last_error":null}]"#,
        )
        .await
        .unwrap();
        assert!(matches!(
            update_policy(&repo, 1, true, 443, 5).await,
            Err(RelayFailoverError::ScheduleEnabled)
        ));
    }

    #[tokio::test]
    async fn carrier_policy_and_failover_are_mutually_exclusive_in_both_directions() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        let preference = crate::service::relay_preference::RelayPreferenceState {
            carrier_policy: crate::service::relay_preference::CarrierPolicy {
                bindings: vec![crate::service::relay_preference::CarrierLineBinding {
                    line_id: "Dianxin".into(),
                    mode: crate::service::relay_preference::CarrierLineMode::FollowDefault,
                    node_id: None,
                }],
            },
            ..Default::default()
        };
        repo.set(
            "relay_preference:1",
            &serde_json::to_string(&preference).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            update_policy(&repo, 1, true, 443, 5).await,
            Err(RelayFailoverError::CarrierPolicyEnabled)
        ));

        repo.delete("relay_preference:1").await.unwrap();
        update_policy(&repo, 1, true, 443, 5).await.unwrap();
        assert!(matches!(
            crate::service::relay_preference::start_carrier_policy_apply(
                &repo,
                &connections,
                1,
                crate::service::relay_preference::CarrierPolicy {
                    bindings: vec![crate::service::relay_preference::CarrierLineBinding {
                        line_id: "Dianxin".into(),
                        mode: crate::service::relay_preference::CarrierLineMode::FollowDefault,
                        node_id: None,
                    }],
                },
            )
            .await,
            Err(crate::service::relay_preference::CarrierPolicyApplyError::FailoverEnabled)
        ));
    }

    #[tokio::test]
    async fn reinclude_requires_ready_and_healthy_then_keeps_current_unchanged() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        add_node(&repo, &connections, 1, "node-a", "8.8.8.8", true).await;
        let mut policy = update_policy(&repo, 1, false, 443, 5).await.unwrap();
        policy.excluded_failed_node_ids.insert("node-a".into());
        store_policy(&repo, 1, &policy).await.unwrap();
        let preference = crate::service::relay_preference::RelayPreferenceState {
            preferred_node_id: Some("node-other".into()),
            ..Default::default()
        };
        repo.set(
            "relay_preference:1",
            &serde_json::to_string(&preference).unwrap(),
        )
        .await
        .unwrap();

        assert!(matches!(
            reinclude_with_probe(&repo, &connections, 1, "node-a", |_, _| async { false }).await,
            Err(RelayFailoverError::NodeStillUnhealthy)
        ));
        assert!(load_policy(&repo, 1)
            .await
            .unwrap()
            .excluded_failed_node_ids
            .contains("node-a"));

        let policy = reinclude_with_probe(&repo, &connections, 1, "node-a", |_, _| async { true })
            .await
            .unwrap();
        assert!(!policy.excluded_failed_node_ids.contains("node-a"));
        assert_eq!(
            crate::service::relay_preference::load_preference(&repo, 1)
                .await
                .unwrap()
                .preferred_node_id
                .as_deref(),
            Some("node-other")
        );
    }

    #[tokio::test]
    async fn reinclude_rejects_not_ready_and_unknown_nodes() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        add_node(&repo, &connections, 1, "node-a", "8.8.8.8", false).await;
        assert!(matches!(
            reinclude_with_probe(&repo, &connections, 1, "node-a", |_, _| async { true }).await,
            Err(RelayFailoverError::NodeNotReady)
        ));
        assert!(matches!(
            reinclude_with_probe(&repo, &connections, 1, "missing", |_, _| async { true }).await,
            Err(RelayFailoverError::NodeNotInGroup)
        ));
    }

    #[tokio::test]
    async fn reinclude_rejects_a_probe_when_the_configured_port_changes_in_flight() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        add_node(&repo, &connections, 1, "node-a", "8.8.8.8", true).await;
        let mut policy = update_policy(&repo, 1, false, 443, 5).await.unwrap();
        policy.excluded_failed_node_ids.insert("node-a".into());
        store_policy(&repo, 1, &policy).await.unwrap();

        assert!(matches!(
            reinclude_with_probe(&repo, &connections, 1, "node-a", |_, _| async {
                update_policy(&repo, 1, false, 8443, 5).await.unwrap();
                true
            })
            .await,
            Err(RelayFailoverError::NodeStillUnhealthy)
        ));
        assert!(load_policy(&repo, 1)
            .await
            .unwrap()
            .excluded_failed_node_ids
            .contains("node-a"));
    }

    #[tokio::test]
    async fn node_and_group_cleanup_remove_only_failover_state_requested() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, _) = test_repo().await;
        let mut policy = update_policy(&repo, 1, false, 443, 5).await.unwrap();
        policy.excluded_failed_node_ids = BTreeSet::from(["node-a".into(), "node-b".into()]);
        store_policy(&repo, 1, &policy).await.unwrap();
        assert!(remove_excluded_node(&repo, 1, "node-a").await.unwrap());
        assert_eq!(
            load_policy(&repo, 1)
                .await
                .unwrap()
                .excluded_failed_node_ids,
            BTreeSet::from(["node-b".to_string()])
        );
        delete_failover(&repo, 1).await.unwrap();
        assert!(repo.get("relay_failover:1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ready_evaluation_never_imports_nodes_from_another_group() {
        let _test_guard = TEST_LOCK.lock().await;
        remove_runtime(1);
        let (repo, connections) = test_repo().await;
        repo.insert_group("other", "in", "token-2", 1, "", "1002-1003", 1.0, false)
            .await
            .unwrap();
        add_node(&repo, &connections, 1, "node-a", "8.8.8.8", true).await;
        add_node(&repo, &connections, 2, "node-b", "1.1.1.1", true).await;
        let nodes =
            crate::service::relay_preference::evaluate_group_ready_nodes(&repo, &connections, 1)
                .await
                .unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.node_id.as_str())
                .collect::<Vec<_>>(),
            vec!["node-a"]
        );
    }
}
