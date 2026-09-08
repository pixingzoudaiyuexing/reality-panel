use crate::api::middleware::AdminOnly;
use crate::api::node::extract_node_token;
use crate::api::provisioning::{NODE_ARTIFACT_ROOT, NODE_ARTIFACT_ROOT_ENV};
use crate::api::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use relay_shared::protocol::{
    lifecycle_artifact_architecture, ApiResponse, NodeLifecycleAck, NodeLifecycleAction,
    NodeLifecycleCommand, NodeLifecycleEvent, NodeLifecycleEventStatus, CONFIG_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_LOG_LINES: u16 = 500;
const OPERATION_IDLE_TIMEOUT_SECS: i64 = 300;
const OPERATION_HARD_TIMEOUT_SECS: i64 = 900;
const UNINSTALL_CONFIRMATION: &str = "UNINSTALL";
const MIN_ARTIFACT_BYTES: usize = 64 * 1024;
const DURABLE_UNINSTALL_PREFIX: &str = "node_uninstall_operation:";

static DURABLE_UNINSTALL_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationStatus {
    Pending,
    Sent,
    Accepted,
    Downloading,
    Validating,
    Installing,
    Restarting,
    Verifying,
    Success,
    Failed,
    Timeout,
}

impl OperationStatus {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::Timeout)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeOperation {
    pub id: String,
    pub group_id: i64,
    pub node_id: String,
    pub action: NodeLifecycleAction,
    pub status: OperationStatus,
    pub message: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    #[serde(skip)]
    actor_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableUninstallOperation {
    operation: NodeOperation,
    actor_id: Option<i64>,
    saw_disconnect: bool,
    cleanup_confirmed: bool,
    #[serde(default)]
    destructive_started: bool,
    panel_cleanup_complete: bool,
    result_audited: bool,
}

impl DurableUninstallOperation {
    fn new(operation: &NodeOperation) -> Self {
        Self {
            operation: operation.clone(),
            actor_id: operation.actor_id,
            saw_disconnect: false,
            cleanup_confirmed: false,
            destructive_started: false,
            panel_cleanup_complete: false,
            result_audited: false,
        }
    }

    fn operation(&self) -> NodeOperation {
        let mut operation = self.operation.clone();
        operation.actor_id = self.actor_id;
        operation
    }
}

#[derive(Debug, Clone)]
struct RegistryEntry {
    operation: NodeOperation,
    saw_disconnect: bool,
    matching_boot_confirmation: Option<BootConfirmation>,
    uninstall_final: bool,
    uninstall_panel_cleanup_complete: bool,
    result_audited: bool,
}

#[derive(Debug, Clone)]
struct BootConfirmation {
    message: String,
    architecture: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct LifecycleEventOutcome {
    pub operation: Option<NodeOperation>,
    pub boot_ack: Option<NodeLifecycleAck>,
}

#[derive(Clone, Default)]
pub struct NodeOperationRegistry {
    inner: Arc<Mutex<HashMap<String, RegistryEntry>>>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn durable_uninstall_key(operation_id: &str) -> String {
    format!("{DURABLE_UNINSTALL_PREFIX}{operation_id}")
}

async fn load_durable_uninstall(
    state: &AppState,
    operation_id: &str,
) -> Result<Option<DurableUninstallOperation>, String> {
    state
        .db
        .get(&durable_uninstall_key(operation_id))
        .await
        .map_err(|error| error.to_string())?
        .map(|raw| serde_json::from_str(&raw).map_err(|error| error.to_string()))
        .transpose()
}

async fn store_durable_uninstall(
    state: &AppState,
    durable: &DurableUninstallOperation,
) -> Result<(), String> {
    let raw = serde_json::to_string(durable).map_err(|error| error.to_string())?;
    state
        .db
        .set(&durable_uninstall_key(&durable.operation.id), &raw)
        .await
        .map_err(|error| error.to_string())
}

async fn has_active_durable_uninstall(
    state: &AppState,
    group_id: i64,
    node_id: &str,
) -> Result<bool, String> {
    let rows = state
        .db
        .scan_prefix(DURABLE_UNINSTALL_PREFIX)
        .await
        .map_err(|error| error.to_string())?;
    Ok(rows.into_iter().any(|(_, raw)| {
        serde_json::from_str::<DurableUninstallOperation>(&raw).is_ok_and(|durable| {
            durable.operation.group_id == group_id
                && durable.operation.node_id == node_id
                && !durable.operation.status.terminal()
        })
    }))
}

impl NodeOperationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        &self,
        group_id: i64,
        node_id: String,
        action: NodeLifecycleAction,
        current_version: Option<String>,
        target_version: Option<String>,
        architecture: Option<String>,
        sha256: Option<String>,
        actor_id: Option<i64>,
    ) -> Result<NodeOperation, ()> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        if action != NodeLifecycleAction::Logs
            && inner.values().any(|entry| {
                entry.operation.group_id == group_id
                    && entry.operation.node_id == node_id
                    && entry.operation.action != NodeLifecycleAction::Logs
                    && !entry.operation.status.terminal()
            })
        {
            return Err(());
        }
        let timestamp = now();
        let operation = NodeOperation {
            id: uuid::Uuid::new_v4().to_string(),
            group_id,
            node_id,
            action,
            status: OperationStatus::Pending,
            message: "operation created".into(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            current_version,
            target_version,
            architecture,
            sha256,
            logs: None,
            actor_id,
        };
        inner.insert(
            operation.id.clone(),
            RegistryEntry {
                operation: operation.clone(),
                saw_disconnect: false,
                matching_boot_confirmation: None,
                uninstall_final: false,
                uninstall_panel_cleanup_complete: false,
                result_audited: false,
            },
        );
        Ok(operation)
    }

    fn update(&self, id: &str, status: OperationStatus, message: impl Into<String>) {
        if let Some(entry) = self
            .inner
            .lock()
            .expect("node operation registry lock")
            .get_mut(id)
        {
            entry.operation.status = status;
            entry.operation.message = message.into();
            entry.operation.updated_at = now();
        }
    }

    fn remove(&self, id: &str) {
        self.inner
            .lock()
            .expect("node operation registry lock")
            .remove(id);
    }

    fn restore_uninstall(&self, durable: &DurableUninstallOperation) {
        let operation = durable.operation();
        self.inner
            .lock()
            .expect("node operation registry lock")
            .insert(
                operation.id.clone(),
                RegistryEntry {
                    operation,
                    saw_disconnect: durable.saw_disconnect,
                    matching_boot_confirmation: None,
                    uninstall_final: durable.cleanup_confirmed,
                    uninstall_panel_cleanup_complete: durable.panel_cleanup_complete,
                    result_audited: durable.result_audited,
                },
            );
    }

    fn mark_uninstall_panel_cleanup_complete(&self, id: &str) -> Option<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let entry = inner.get_mut(id)?;
        if entry.operation.action != NodeLifecycleAction::Uninstall {
            return None;
        }
        entry.uninstall_panel_cleanup_complete = true;
        if entry.saw_disconnect && entry.uninstall_final {
            entry.operation.status = OperationStatus::Success;
            if !entry.operation.message.contains("Panel state cleaned") {
                entry.operation.message =
                    format!("{}; Panel state cleaned", entry.operation.message);
            }
            entry.operation.updated_at = now();
        }
        Some(entry.operation.clone())
    }

    #[cfg(test)]
    pub fn event(&self, group_id: i64, event: NodeLifecycleEvent) -> Option<NodeOperation> {
        self.event_from_authenticated_node(group_id, None, event)
            .operation
    }

    pub(crate) fn event_from_authenticated_node(
        &self,
        group_id: i64,
        authenticated_node_id: Option<&str>,
        event: NodeLifecycleEvent,
    ) -> LifecycleEventOutcome {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let Some(entry) = inner.get_mut(&event.operation_id) else {
            return LifecycleEventOutcome::default();
        };
        if entry.operation.group_id != group_id
            || entry.operation.node_id != event.node_id
            || entry.operation.action != event.action
            || authenticated_node_id.is_some_and(|node_id| node_id != event.node_id)
        {
            return LifecycleEventOutcome::default();
        }
        let is_boot_confirmation = matches!(
            event.action,
            NodeLifecycleAction::Restart | NodeLifecycleAction::Upgrade
        ) && event.status == NodeLifecycleEventStatus::Completed;
        if entry.operation.status.terminal() {
            let version_matches = event.action != NodeLifecycleAction::Upgrade
                || event.node_version.as_deref() == entry.operation.target_version.as_deref();
            let boot_ack = (is_boot_confirmation
                && match entry.operation.status {
                    OperationStatus::Success | OperationStatus::Timeout => version_matches,
                    OperationStatus::Failed => true,
                    _ => false,
                })
            .then(|| lifecycle_ack(&event));
            return LifecycleEventOutcome {
                operation: None,
                boot_ack,
            };
        }
        if event.status == NodeLifecycleEventStatus::Completed {
            match entry.operation.action {
                NodeLifecycleAction::Restart | NodeLifecycleAction::Upgrade => {
                    if event.action == NodeLifecycleAction::Upgrade
                        && event.node_version.as_deref()
                            != entry.operation.target_version.as_deref()
                    {
                        entry.operation.status = OperationStatus::Failed;
                        entry.operation.message = format!(
                            "relay-node restarted with version {}, expected {}",
                            event.node_version.as_deref().unwrap_or("unknown"),
                            entry
                                .operation
                                .target_version
                                .as_deref()
                                .unwrap_or("unknown")
                        );
                        entry.operation.updated_at = now();
                        return LifecycleEventOutcome {
                            operation: Some(entry.operation.clone()),
                            boot_ack: Some(lifecycle_ack(&event)),
                        };
                    }
                    entry
                        .matching_boot_confirmation
                        .get_or_insert(BootConfirmation {
                            message: event.message.clone(),
                            architecture: event.architecture.clone(),
                        });
                    entry.operation.updated_at = now();
                    if let Some(confirmation) = entry.matching_boot_confirmation.as_ref() {
                        entry.operation.architecture = confirmation
                            .architecture
                            .clone()
                            .or(entry.operation.architecture.take());
                    }
                    if complete_if_ready(entry) {
                        return LifecycleEventOutcome {
                            operation: Some(entry.operation.clone()),
                            boot_ack: Some(lifecycle_ack(&event)),
                        };
                    }
                    entry.operation.status = OperationStatus::Verifying;
                    entry.operation.message = if entry.saw_disconnect {
                        "relay-node reconnected; waiting for correlated boot confirmation".into()
                    } else {
                        "matching boot confirmation received; waiting for disconnect".into()
                    };
                    return LifecycleEventOutcome {
                        operation: Some(entry.operation.clone()),
                        boot_ack: Some(lifecycle_ack(&event)),
                    };
                }
                _ => {}
            }
        }
        let operation = &mut entry.operation;
        operation.updated_at = now();
        operation.message = event.message;
        if operation.action != NodeLifecycleAction::Upgrade {
            operation.current_version = event.node_version.or(operation.current_version.take());
        }
        operation.architecture = event.architecture.or(operation.architecture.take());
        if let Some(logs) = event.logs {
            operation.logs = Some(logs);
        }
        operation.status = match event.status {
            NodeLifecycleEventStatus::Accepted => OperationStatus::Accepted,
            NodeLifecycleEventStatus::Downloading => OperationStatus::Downloading,
            NodeLifecycleEventStatus::Validating => OperationStatus::Validating,
            NodeLifecycleEventStatus::Installing => OperationStatus::Installing,
            NodeLifecycleEventStatus::Restarting => OperationStatus::Restarting,
            NodeLifecycleEventStatus::Failed => OperationStatus::Failed,
            NodeLifecycleEventStatus::Completed
                if operation.action == NodeLifecycleAction::Uninstall =>
            {
                operation.message = "legacy uninstall acknowledgement received; waiting for verified cleanup result".into();
                OperationStatus::Verifying
            }
            NodeLifecycleEventStatus::Completed => OperationStatus::Success,
        };
        LifecycleEventOutcome {
            operation: Some(operation.clone()),
            boot_ack: None,
        }
    }

    pub fn disconnected(&self, group_id: i64, node_id: &str) -> Vec<NodeOperation> {
        let mut transitioned = Vec::new();
        let mut inner = self.inner.lock().expect("node operation registry lock");
        for entry in inner.values_mut() {
            if entry.operation.group_id != group_id
                || entry.operation.node_id != node_id
                || entry.operation.status.terminal()
                || entry.operation.action == NodeLifecycleAction::Logs
            {
                continue;
            }
            entry.saw_disconnect = true;
            entry.operation.updated_at = now();
            if entry.operation.action == NodeLifecycleAction::Uninstall {
                entry.operation.status =
                    if entry.uninstall_final && entry.uninstall_panel_cleanup_complete {
                        OperationStatus::Success
                    } else {
                        OperationStatus::Verifying
                    };
                entry.operation.message = if entry.operation.status == OperationStatus::Success {
                    format!(
                        "{}; node disconnected and Panel state cleaned",
                        entry.operation.message
                    )
                } else if entry.uninstall_final {
                    format!(
                        "{}; node disconnected; waiting for Panel state cleanup",
                        entry.operation.message
                    )
                } else {
                    "node disconnected; waiting for verified cleanup and Panel state cleanup".into()
                };
                transitioned.push(entry.operation.clone());
            } else if complete_if_ready(entry) {
                transitioned.push(entry.operation.clone());
            } else {
                entry.operation.status = OperationStatus::Verifying;
                entry.operation.message =
                    "node disconnected; waiting for authenticated reconnect".into();
            }
        }
        transitioned
    }

    fn uninstall_result(
        &self,
        group_id: i64,
        node_id: &str,
        operation_id: &str,
        success: bool,
        message: String,
    ) -> Option<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let entry = inner.get_mut(operation_id)?;
        if entry.operation.group_id != group_id
            || entry.operation.node_id != node_id
            || entry.operation.action != NodeLifecycleAction::Uninstall
        {
            return None;
        }
        if entry.operation.status == OperationStatus::Success {
            return Some(entry.operation.clone());
        }
        entry.operation.updated_at = now();
        entry.operation.message = message;
        if !success {
            entry.operation.status = OperationStatus::Verifying;
        } else {
            entry.uninstall_final = true;
            entry.operation.status =
                if entry.saw_disconnect && entry.uninstall_panel_cleanup_complete {
                    OperationStatus::Success
                } else {
                    OperationStatus::Verifying
                };
        }
        Some(entry.operation.clone())
    }

    pub fn connected(
        &self,
        group_id: i64,
        node_id: &str,
        _version: Option<&str>,
        architecture: Option<&str>,
    ) -> Vec<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        for entry in inner.values_mut() {
            let operation = &mut entry.operation;
            if operation.group_id != group_id
                || operation.node_id != node_id
                || operation.status.terminal()
            {
                continue;
            }
            operation.updated_at = now();
            if !entry.saw_disconnect {
                continue;
            }
            match operation.action {
                NodeLifecycleAction::Restart => {
                    operation.status = OperationStatus::Verifying;
                    operation.message =
                        "relay-node reconnected; waiting for correlated boot confirmation".into();
                }
                NodeLifecycleAction::Upgrade => {
                    operation.status = OperationStatus::Verifying;
                    operation.message =
                        "relay-node reconnected; waiting for correlated boot confirmation".into();
                    operation.architecture = architecture.map(str::to_string);
                }
                NodeLifecycleAction::Logs | NodeLifecycleAction::Uninstall => continue,
            }
        }
        Vec::new()
    }

    pub fn get(&self, id: &str) -> Option<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let entry = inner.get_mut(id)?;
        if !entry.operation.status.terminal()
            && entry.operation.action != NodeLifecycleAction::Uninstall
        {
            let created = chrono::DateTime::parse_from_rfc3339(&entry.operation.created_at).ok()?;
            let updated = chrono::DateTime::parse_from_rfc3339(&entry.operation.updated_at).ok()?;
            let elapsed =
                chrono::Utc::now().signed_duration_since(created.with_timezone(&chrono::Utc));
            let idle =
                chrono::Utc::now().signed_duration_since(updated.with_timezone(&chrono::Utc));
            if elapsed.num_seconds() >= OPERATION_HARD_TIMEOUT_SECS {
                entry.operation.status = OperationStatus::Timeout;
                entry.operation.message = "relay-node 生命周期操作超过最长等待时间".into();
                entry.operation.updated_at = now();
            } else if idle.num_seconds() >= OPERATION_IDLE_TIMEOUT_SECS {
                entry.operation.status = OperationStatus::Timeout;
                entry.operation.message = if entry.operation.action == NodeLifecycleAction::Upgrade
                {
                    "等待 relay-node 重启并重新连接确认超时".into()
                } else {
                    "等待节点确认超时".into()
                };
                entry.operation.updated_at = now();
            }
        }
        Some(entry.operation.clone())
    }

    fn artifact_target(
        &self,
        group_id: i64,
        node_id: &str,
        operation_id: &str,
    ) -> Option<(String, String, String)> {
        let operation = self.get(operation_id)?;
        if operation.group_id != group_id
            || operation.node_id != node_id
            || operation.action != NodeLifecycleAction::Upgrade
            || operation.status.terminal()
        {
            return None;
        }
        Some((
            operation.architecture?,
            operation.target_version?,
            operation.sha256?,
        ))
    }

    fn claim_terminal_audit(&self, id: &str) -> bool {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let Some(entry) = inner.get_mut(id) else {
            return false;
        };
        if !entry.operation.status.terminal() || entry.result_audited {
            return false;
        }
        entry.result_audited = true;
        true
    }
}

fn lifecycle_ack(event: &NodeLifecycleEvent) -> NodeLifecycleAck {
    NodeLifecycleAck {
        msg_type: "node_lifecycle_ack".into(),
        operation_id: event.operation_id.clone(),
        node_id: event.node_id.clone(),
        action: event.action,
    }
}

fn complete_if_ready(entry: &mut RegistryEntry) -> bool {
    if entry.matching_boot_confirmation.is_none() {
        return false;
    }
    if !matches!(
        entry.operation.action,
        NodeLifecycleAction::Restart | NodeLifecycleAction::Upgrade
    ) {
        return false;
    }
    let confirmation = entry
        .matching_boot_confirmation
        .as_ref()
        .expect("matching confirmation was checked");
    entry.operation.status = OperationStatus::Success;
    entry.operation.message = confirmation.message.clone();
    entry.operation.updated_at = now();
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactMetadata {
    pub version: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactInfo {
    pub architecture: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactCatalog {
    pub config_protocol_version: u32,
    pub artifacts: [ArtifactInfo; 2],
}

#[derive(Debug)]
struct LoadedArtifact {
    metadata: ArtifactMetadata,
    bytes: Vec<u8>,
}

fn artifact_root() -> PathBuf {
    std::env::var_os(NODE_ARTIFACT_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(NODE_ARTIFACT_ROOT))
}

fn elf_machine(architecture: &str) -> Option<u16> {
    match lifecycle_artifact_architecture(architecture)? {
        "amd64" => Some(62),
        "arm64" => Some(183),
        _ => None,
    }
}

fn artifact_metadata_read_error(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::NotFound => "artifact metadata missing",
        std::io::ErrorKind::PermissionDenied => "artifact metadata not readable: permission denied",
        _ => "artifact metadata could not be read",
    }
}

fn load_artifact_from(root: &FsPath, architecture: &str) -> Result<LoadedArtifact, String> {
    let architecture = lifecycle_artifact_architecture(architecture)
        .ok_or_else(|| "unsupported artifact architecture".to_string())?;
    let directory = root.join(architecture);
    let metadata_bytes = std::fs::read(directory.join("metadata.json"))
        .map_err(|error| artifact_metadata_read_error(error.kind()).to_string())?;
    let metadata: ArtifactMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("invalid artifact metadata: {error}"))?;
    semver::Version::parse(&metadata.version).map_err(|_| "invalid artifact version")?;
    if metadata.sha256.len() != 64 || !metadata.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid artifact SHA-256 metadata".into());
    }
    let bytes = std::fs::read(directory.join("relay-node"))
        .map_err(|error| format!("artifact binary missing: {error}"))?;
    if metadata.size != bytes.len() as u64 {
        return Err("artifact size does not match metadata".into());
    }
    if bytes.len() < MIN_ARTIFACT_BYTES
        || bytes.get(..4) != Some(&[0x7f, b'E', b'L', b'F'])
        || bytes.get(4) != Some(&2)
        || bytes.get(5) != Some(&1)
        || u16::from_le_bytes([bytes[18], bytes[19]]) != elf_machine(architecture).unwrap()
    {
        return Err("artifact is not a matching 64-bit Linux ELF binary".into());
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(&metadata.sha256) {
        return Err("artifact SHA-256 does not match metadata".into());
    }
    Ok(LoadedArtifact { metadata, bytes })
}

fn load_artifact(architecture: &str) -> Result<LoadedArtifact, String> {
    load_artifact_from(&artifact_root(), architecture)
}

#[derive(Debug, Deserialize)]
pub struct OperationRequest {
    #[serde(default)]
    pub confirmation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    pub lines: Option<u16>,
}

fn requested_log_lines(lines: Option<u16>) -> Result<u16, ()> {
    let lines = lines.unwrap_or(200);
    if lines == 0 || lines > MAX_LOG_LINES {
        Err(())
    } else {
        Ok(lines)
    }
}

fn uninstall_confirmed(value: Option<&str>) -> bool {
    value == Some(UNINSTALL_CONFIRMATION)
}

fn response<T: Serialize>(status: StatusCode, code: i32, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiResponse::<T> {
            code,
            message: message.into(),
            data: None,
        }),
    )
        .into_response()
}

fn success<T: Serialize>(data: T) -> Response {
    Json(ApiResponse::success(data)).into_response()
}

fn parse_action(value: &str) -> Option<NodeLifecycleAction> {
    match value {
        "restart" => Some(NodeLifecycleAction::Restart),
        "upgrade" => Some(NodeLifecycleAction::Upgrade),
        "uninstall" => Some(NodeLifecycleAction::Uninstall),
        _ => None,
    }
}

async fn node_status(
    state: &AppState,
    group_id: i64,
    node_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    state
        .db
        .get(&format!("node_status:{group_id}:{node_id}"))
        .await
        .map_err(|error| error.to_string())?
        .map(|raw| serde_json::from_str(&raw).map_err(|error| error.to_string()))
        .transpose()
}

fn is_modern_reality_panel_release(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return false;
    };
    let normalized = version.trim().trim_start_matches('v');
    semver::Version::parse(normalized).is_ok_and(|version| version >= semver::Version::new(1, 0, 0))
}

fn status_supports_lifecycle(
    status: Option<&serde_json::Value>,
    current_version: Option<&str>,
) -> bool {
    // Cross-config-protocol upgrades MUST stay possible. Known shipped nodes
    // with lifecycle support therefore pass independently of the config gate.
    if relay_shared::control_protocol::legacy_node_supports_lifecycle(current_version)
        || relay_shared::protocol::node_supports_lifecycle(current_version)
    {
        return true;
    }
    // Preserve the historical current-protocol path for older modern builds.
    if !is_modern_reality_panel_release(current_version) {
        return false;
    }
    status
        .and_then(|value| value.get("config_protocol_version"))
        .and_then(|value| value.as_u64())
        == Some(CONFIG_PROTOCOL_VERSION as u64)
}

async fn operation_channel_online(
    connections: &crate::api::ws::NodeConnections,
    group_id: i64,
    node_id: &str,
    action: NodeLifecycleAction,
) -> bool {
    if action == NodeLifecycleAction::Upgrade {
        connections
            .lifecycle_online_node_ids(group_id)
            .await
            .contains(node_id)
    } else {
        connections
            .config_online_node_ids(group_id)
            .await
            .contains(node_id)
    }
}

async fn create_operation(
    state: &AppState,
    actor_id: i64,
    group_id: i64,
    node_id: String,
    action: NodeLifecycleAction,
    log_lines: Option<u16>,
) -> Result<NodeOperation, Response> {
    if action != NodeLifecycleAction::Logs {
        match has_active_durable_uninstall(state, group_id, &node_id).await {
            Ok(true) => {
                return Err(response::<()>(
                    StatusCode::CONFLICT,
                    409,
                    "NODE_OPERATION_IN_PROGRESS",
                ))
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(group_id, node_id, "durable uninstall preflight: {error}");
                return Err(response::<()>(
                    StatusCode::SERVICE_UNAVAILABLE,
                    503,
                    "UNINSTALL_STATE_UNAVAILABLE",
                ));
            }
        }
    }
    if !operation_channel_online(&state.node_connections, group_id, &node_id, action).await {
        return Err(response::<()>(StatusCode::CONFLICT, 409, "NODE_OFFLINE"));
    }
    let status = node_status(state, group_id, &node_id)
        .await
        .map_err(|error| {
            tracing::error!("lifecycle node status lookup: {error}");
            response::<()>(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        })?;
    let current_version = status
        .as_ref()
        .and_then(|value| value.get("node_version"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    if !status_supports_lifecycle(status.as_ref(), current_version.as_deref()) {
        return Err(response::<()>(
            StatusCode::CONFLICT,
            409,
            "NODE_LIFECYCLE_UNSUPPORTED",
        ));
    }
    let config_compatible = status
        .as_ref()
        .and_then(|value| value.get("config_protocol_version"))
        .and_then(|value| value.as_u64())
        == Some(CONFIG_PROTOCOL_VERSION as u64);
    if action != NodeLifecycleAction::Upgrade && !config_compatible {
        return Err(response::<()>(
            StatusCode::CONFLICT,
            409,
            "NODE_CONFIG_PROTOCOL_MISMATCH",
        ));
    }
    let mut target_version = None;
    let mut architecture = status
        .as_ref()
        .and_then(|value| value.get("architecture"))
        .and_then(|value| value.as_str())
        .and_then(lifecycle_artifact_architecture)
        .map(str::to_string);
    let mut sha256 = None;
    if action == NodeLifecycleAction::Upgrade {
        let arch = architecture.as_deref().ok_or_else(|| {
            response::<()>(StatusCode::CONFLICT, 409, "NODE_ARCHITECTURE_UNSUPPORTED")
        })?;
        let artifact = load_artifact(arch)
            .map_err(|error| response::<()>(StatusCode::SERVICE_UNAVAILABLE, 503, error))?;
        let current = current_version
            .as_deref()
            .and_then(|version| semver::Version::parse(version).ok())
            .ok_or_else(|| response::<()>(StatusCode::CONFLICT, 409, "NODE_VERSION_UNAVAILABLE"))?;
        let target =
            semver::Version::parse(&artifact.metadata.version).expect("validated artifact version");
        if target <= current {
            return Err(response::<()>(
                StatusCode::CONFLICT,
                409,
                "NO_NEWER_NODE_ARTIFACT",
            ));
        }
        target_version = Some(artifact.metadata.version);
        sha256 = Some(artifact.metadata.sha256);
    } else if architecture.is_none() {
        architecture = status
            .as_ref()
            .and_then(|value| value.get("architecture"))
            .and_then(|value| value.as_str())
            .map(str::to_string);
    }
    let operation = state
        .node_operations
        .start(
            group_id,
            node_id.clone(),
            action,
            current_version,
            target_version,
            architecture,
            sha256,
            Some(actor_id),
        )
        .map_err(|_| response::<()>(StatusCode::CONFLICT, 409, "NODE_OPERATION_IN_PROGRESS"))?;
    if action == NodeLifecycleAction::Uninstall {
        {
            let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
            let durable = DurableUninstallOperation::new(&operation);
            if let Err(error) = store_durable_uninstall(state, &durable).await {
                state.node_operations.remove(&operation.id);
                tracing::error!(group_id, node_id, "persist uninstall operation: {error}");
                return Err(response::<()>(
                    StatusCode::SERVICE_UNAVAILABLE,
                    503,
                    "UNINSTALL_STATE_PERSIST_FAILED",
                ));
            }
        }
        match crate::service::relay_preference::begin_uninstall_gate(
            state.db.as_ref(),
            group_id,
            &node_id,
            &operation.id,
        )
        .await
        {
            Ok(crate::service::relay_preference::BeginUninstallGateOutcome::Acquired) => {}
            Ok(crate::service::relay_preference::BeginUninstallGateOutcome::ActiveTransaction) => {
                state.node_operations.remove(&operation.id);
                let _ = state.db.delete(&durable_uninstall_key(&operation.id)).await;
                return Err(response::<()>(
                    StatusCode::CONFLICT,
                    409,
                    "该节点当前正在进行线路切换，请等待切换完成后再卸载。",
                ));
            }
            Ok(
                crate::service::relay_preference::BeginUninstallGateOutcome::AlreadyUninstalling,
            ) => {
                state.node_operations.remove(&operation.id);
                let _ = state.db.delete(&durable_uninstall_key(&operation.id)).await;
                return Err(response::<()>(
                    StatusCode::CONFLICT,
                    409,
                    "该节点正在卸载，请等待当前卸载完成。",
                ));
            }
            Err(error) => {
                state.node_operations.remove(&operation.id);
                let _ = state.db.delete(&durable_uninstall_key(&operation.id)).await;
                tracing::error!(group_id, node_id, "persist uninstall gate: {error}");
                return Err(response::<()>(
                    StatusCode::SERVICE_UNAVAILABLE,
                    503,
                    "UNINSTALL_GATE_UNAVAILABLE",
                ));
            }
        }
    }
    let action_name = format!("{:?}", action).to_ascii_lowercase();
    let audit_action = if action == NodeLifecycleAction::Logs {
        "node_logs".to_string()
    } else {
        format!("node_{action_name}_start")
    };
    crate::service::audit::record(
        state,
        Some(actor_id),
        &audit_action,
        "node",
        &node_id,
        &format!("group_id={group_id} operation_id={}", operation.id),
    )
    .await;
    let command = NodeLifecycleCommand {
        msg_type: "node_lifecycle".into(),
        operation_id: operation.id.clone(),
        node_id: node_id.clone(),
        action,
        target_version: operation.target_version.clone(),
        target_architecture: operation.architecture.clone(),
        sha256: operation.sha256.clone(),
        artifact_id: (action == NodeLifecycleAction::Upgrade).then(|| operation.id.clone()),
        log_lines,
    };
    let encoded = serde_json::to_string(&command).map_err(|_| {
        response::<()>(
            StatusCode::INTERNAL_SERVER_ERROR,
            500,
            "serialize lifecycle command failed",
        )
    })?;
    let delivered = if action == NodeLifecycleAction::Upgrade {
        state
            .node_connections
            .send_upgrade_node(group_id, &node_id, &encoded)
            .await
    } else {
        state
            .node_connections
            .send_node(group_id, &node_id, &encoded)
            .await
    };
    if delivered == 0 {
        state.node_operations.update(
            &operation.id,
            OperationStatus::Failed,
            "node disconnected before command delivery",
        );
        if let Some(failed) = state.node_operations.get(&operation.id) {
            if action == NodeLifecycleAction::Uninstall {
                let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
                if let Ok(Some(mut durable)) = load_durable_uninstall(state, &operation.id).await {
                    durable.operation = failed.clone();
                    let _ = store_durable_uninstall(state, &durable).await;
                }
                let _ = crate::service::relay_preference::release_uninstall_gate(
                    state.db.as_ref(),
                    group_id,
                    &node_id,
                    &operation.id,
                )
                .await;
            }
            audit_terminal_operation(state, &failed).await;
        }
        return Err(response::<()>(StatusCode::CONFLICT, 409, "NODE_OFFLINE"));
    }
    state
        .node_operations
        .update(&operation.id, OperationStatus::Sent, "command sent to node");
    let operation = state.node_operations.get(&operation.id).unwrap();
    if action == NodeLifecycleAction::Uninstall {
        let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
        if let Ok(Some(mut durable)) = load_durable_uninstall(state, &operation.id).await {
            durable.operation = operation.clone();
            let _ = store_durable_uninstall(state, &durable).await;
        }
    }
    Ok(operation)
}

pub async fn start_operation(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id, action)): Path<(i64, String, String)>,
    Json(request): Json<OperationRequest>,
) -> Response {
    let Some(action) = parse_action(&action) else {
        return response::<()>(StatusCode::BAD_REQUEST, 400, "unsupported lifecycle action");
    };
    let node_id = node_id.trim().to_string();
    if node_id.is_empty() || node_id.len() > 128 {
        return response::<()>(StatusCode::BAD_REQUEST, 400, "node_id required");
    }
    if action == NodeLifecycleAction::Uninstall
        && !uninstall_confirmed(request.confirmation.as_deref())
    {
        return response::<()>(
            StatusCode::BAD_REQUEST,
            400,
            "UNINSTALL_CONFIRMATION_REQUIRED",
        );
    }
    match create_operation(&state, admin.user_id, group_id, node_id, action, None).await {
        Ok(operation) => success(operation),
        Err(response) => response,
    }
}

pub async fn request_logs(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
    Query(query): Query<LogsQuery>,
) -> Response {
    let Ok(lines) = requested_log_lines(query.lines) else {
        return response::<()>(StatusCode::BAD_REQUEST, 400, "INVALID_LOG_LIMIT");
    };
    match create_operation(
        &state,
        admin.user_id,
        group_id,
        node_id.trim().to_string(),
        NodeLifecycleAction::Logs,
        Some(lines),
    )
    .await
    {
        Ok(operation) => success(operation),
        Err(response) => response,
    }
}

pub async fn get_operation(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id, operation_id)): Path<(i64, String, String)>,
) -> Response {
    let operation = state
        .node_operations
        .get(&operation_id)
        .filter(|operation| operation.group_id == group_id && operation.node_id == node_id);
    let operation = match operation {
        Some(operation) => Some(operation),
        None => match load_durable_uninstall(&state, &operation_id).await {
            Ok(Some(durable)) => {
                let operation = durable.operation();
                (operation.group_id == group_id && operation.node_id == node_id)
                    .then_some(operation)
            }
            _ => None,
        },
    };
    match operation {
        Some(operation) => {
            audit_terminal_operation(&state, &operation).await;
            success(operation)
        }
        None => response::<()>(StatusCode::NOT_FOUND, 404, "NODE_OPERATION_NOT_FOUND"),
    }
}

pub async fn list_artifacts(_admin: AdminOnly) -> Response {
    let artifacts = ["amd64", "arm64"].map(|architecture| match load_artifact(architecture) {
        Ok(artifact) => ArtifactInfo {
            architecture: architecture.into(),
            available: true,
            version: Some(artifact.metadata.version),
            sha256: Some(artifact.metadata.sha256),
            error: None,
        },
        Err(error) => ArtifactInfo {
            architecture: architecture.into(),
            available: false,
            version: None,
            sha256: None,
            error: Some(error),
        },
    });
    success(ArtifactCatalog {
        config_protocol_version: relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
        artifacts,
    })
}

pub async fn download_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Response {
    let Some(token) = extract_node_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::error!("lifecycle artifact token lookup: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let Some(node_id) = headers
        .get("X-Node-ID")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some((architecture, version, sha256)) =
        state
            .node_operations
            .artifact_target(group.id, node_id, &operation_id)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match load_artifact(&architecture) {
        Ok(artifact)
            if artifact.metadata.version == version
                && artifact.metadata.sha256.eq_ignore_ascii_case(&sha256) =>
        {
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                artifact.bytes,
            )
                .into_response()
        }
        _ => StatusCode::CONFLICT.into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct UninstallResultRequest {
    pub operation_id: String,
    pub node_id: String,
    pub success: bool,
    #[serde(default)]
    pub destructive_started: bool,
    pub message: String,
}

pub async fn receive_uninstall_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UninstallResultRequest>,
) -> Response {
    let Some(token) = extract_node_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let authenticated_node_id = headers
        .get("X-Node-ID")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if authenticated_node_id != Some(request.node_id.trim()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let operation_id = request.operation_id.trim();
    let node_id = request.node_id.trim();
    if request.success && !request.destructive_started {
        return StatusCode::FORBIDDEN.into_response();
    }
    {
        let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
        let Ok(Some(durable)) = load_durable_uninstall(&state, operation_id).await else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if durable.operation.group_id != group.id
            || durable.operation.node_id != node_id
            || durable.operation.action != NodeLifecycleAction::Uninstall
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        if durable.operation.status == OperationStatus::Success {
            state.node_operations.restore_uninstall(&durable);
            return success(durable.operation());
        }
        if durable.operation.status.terminal() {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    if request.destructive_started {
        match crate::service::relay_preference::mark_uninstall_gate_destructive(
            state.db.as_ref(),
            group.id,
            node_id,
            operation_id,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return StatusCode::FORBIDDEN.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    let currently_connected = state
        .node_connections
        .config_online_node_ids(group.id)
        .await
        .contains(node_id);
    {
        let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
        let Ok(Some(mut durable)) = load_durable_uninstall(&state, operation_id).await else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if durable.operation.group_id != group.id
            || durable.operation.node_id != node_id
            || durable.operation.action != NodeLifecycleAction::Uninstall
            || durable.operation.status.terminal()
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        durable.operation.updated_at = now();
        durable.operation.message = request.message.clone();
        durable.cleanup_confirmed = request.success;
        durable.destructive_started |= request.destructive_started;
        if !currently_connected {
            durable.saw_disconnect = true;
        }
        durable.operation.status = if !request.success && !request.destructive_started {
            OperationStatus::Failed
        } else {
            OperationStatus::Verifying
        };
        if store_durable_uninstall(&state, &durable).await.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        state.node_operations.restore_uninstall(&durable);
    }
    if !request.success && !request.destructive_started {
        let Some(operation) = state.node_operations.get(operation_id) else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        match crate::service::relay_preference::release_uninstall_gate(
            state.db.as_ref(),
            group.id,
            node_id,
            operation_id,
        )
        .await
        {
            Ok(true) => {
                audit_terminal_operation(&state, &operation).await;
                return success(operation);
            }
            _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    let _ = state.node_operations.uninstall_result(
        group.id,
        node_id,
        operation_id,
        request.success,
        request.message,
    );
    if !request.success {
        return response::<()>(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "NODE_CLEANUP_RETRY_REQUIRED",
        );
    }
    match finalize_durable_uninstall(&state, operation_id).await {
        Ok(operation) if operation.status == OperationStatus::Success => success(operation),
        Ok(_) => response::<()>(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "WAITING_FOR_DISCONNECT",
        ),
        Err(error) => {
            tracing::warn!(
                operation_id,
                "Panel uninstall cleanup retry required: {error}"
            );
            response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "PANEL_CLEANUP_RETRY_REQUIRED",
            )
        }
    }
}

async fn cleanup_uninstalled_node(
    state: &AppState,
    group_id: i64,
    node_id: &str,
) -> Result<(), String> {
    let status_key = format!("node_status:{group_id}:{node_id}");
    if let Some(raw) = state
        .db
        .get(&status_key)
        .await
        .map_err(|error| error.to_string())?
    {
        if let Some(ips) = crate::api::stats::public_ips_from_status_json(&raw) {
            for ip in ips {
                state
                    .db
                    .delete(&format!("geoip:{ip}"))
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    state
        .db
        .delete(&status_key)
        .await
        .map_err(|error| error.to_string())?;
    state
        .db
        .delete(&format!("node_config_revision:{group_id}:{node_id}"))
        .await
        .map_err(|error| error.to_string())?;
    crate::service::relay_preference::remove_node_assignment(state.db.as_ref(), group_id, node_id)
        .await?;
    crate::service::relay_failover::remove_excluded_node(state.db.as_ref(), group_id, node_id)
        .await
        .map_err(|error| error.to_string())?;
    crate::service::relay_schedule::delete_schedules_for_node(state.db.as_ref(), group_id, node_id)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn finalize_durable_uninstall(
    state: &AppState,
    operation_id: &str,
) -> Result<NodeOperation, String> {
    let operation = {
        let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
        let mut durable = load_durable_uninstall(state, operation_id)
            .await?
            .ok_or_else(|| "durable uninstall operation not found".to_string())?;
        if durable.operation.status == OperationStatus::Success {
            state.node_operations.restore_uninstall(&durable);
            return Ok(durable.operation());
        }
        if !durable.cleanup_confirmed || !durable.saw_disconnect {
            state.node_operations.restore_uninstall(&durable);
            return Ok(durable.operation());
        }
        if let Err(error) = cleanup_uninstalled_node(
            state,
            durable.operation.group_id,
            &durable.operation.node_id,
        )
        .await
        {
            durable.operation.status = OperationStatus::Verifying;
            durable.operation.message = format!("Panel state cleanup failed; retrying: {error}");
            durable.operation.updated_at = now();
            store_durable_uninstall(state, &durable).await?;
            state.node_operations.restore_uninstall(&durable);
            return Err(error);
        }
        match crate::service::relay_preference::release_uninstall_gate(
            state.db.as_ref(),
            durable.operation.group_id,
            &durable.operation.node_id,
            operation_id,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return Err("uninstall gate belongs to another operation".into()),
            Err(error) => return Err(error.to_string()),
        }
        durable.panel_cleanup_complete = true;
        durable.operation.status = OperationStatus::Success;
        durable.operation.message = format!("{}; Panel state cleaned", durable.operation.message);
        durable.operation.updated_at = now();
        store_durable_uninstall(state, &durable).await?;
        state.node_operations.restore_uninstall(&durable);
        let _ = state
            .node_operations
            .mark_uninstall_panel_cleanup_complete(operation_id);
        durable.operation()
    };
    audit_terminal_operation(state, &operation).await;
    Ok(operation)
}

pub async fn record_uninstall_disconnect(state: &AppState, group_id: i64, node_id: &str) {
    let mut operation_ids = Vec::new();
    {
        let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
        let rows = match state.db.scan_prefix(DURABLE_UNINSTALL_PREFIX).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(group_id, node_id, "persist uninstall disconnect: {error}");
                return;
            }
        };
        for (_, raw) in rows {
            let Ok(mut durable) = serde_json::from_str::<DurableUninstallOperation>(&raw) else {
                continue;
            };
            if durable.operation.group_id != group_id
                || durable.operation.node_id != node_id
                || durable.operation.status == OperationStatus::Success
            {
                continue;
            }
            durable.saw_disconnect = true;
            durable.operation.status = OperationStatus::Verifying;
            durable.operation.message = if durable.cleanup_confirmed {
                format!(
                    "{}; node disconnected; waiting for Panel state cleanup",
                    durable.operation.message
                )
            } else {
                "node disconnected; waiting for verified cleanup and Panel state cleanup".into()
            };
            durable.operation.updated_at = now();
            if store_durable_uninstall(state, &durable).await.is_ok() {
                state.node_operations.restore_uninstall(&durable);
                operation_ids.push(durable.operation.id.clone());
            }
        }
    }
    for operation_id in operation_ids {
        let _ = finalize_durable_uninstall(state, &operation_id).await;
    }
}

async fn claim_durable_uninstall_audit(state: &AppState, operation_id: &str) -> bool {
    let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
    let Ok(Some(mut durable)) = load_durable_uninstall(state, operation_id).await else {
        return false;
    };
    if !durable.operation.status.terminal() || durable.result_audited {
        return false;
    }
    durable.result_audited = true;
    store_durable_uninstall(state, &durable).await.is_ok()
}

async fn persist_pre_destructive_uninstall_failure(
    state: &AppState,
    operation: &NodeOperation,
) -> bool {
    let _guard = DURABLE_UNINSTALL_LOCK.lock().await;
    let Ok(Some(mut durable)) = load_durable_uninstall(state, &operation.id).await else {
        return false;
    };
    if durable.destructive_started {
        return false;
    }
    durable.operation = operation.clone();
    durable.operation.status = OperationStatus::Failed;
    if store_durable_uninstall(state, &durable).await.is_err() {
        return false;
    }
    drop(_guard);
    matches!(
        crate::service::relay_preference::release_uninstall_gate(
            state.db.as_ref(),
            operation.group_id,
            &operation.node_id,
            &operation.id,
        )
        .await,
        Ok(true)
    )
}

pub async fn audit_terminal_operation(state: &AppState, operation: &NodeOperation) {
    if !operation.status.terminal() || operation.action == NodeLifecycleAction::Logs {
        return;
    }
    if operation.action == NodeLifecycleAction::Uninstall
        && operation.status == OperationStatus::Failed
        && !persist_pre_destructive_uninstall_failure(state, operation).await
    {
        return;
    }
    let claimed = if operation.action == NodeLifecycleAction::Uninstall {
        claim_durable_uninstall_audit(state, &operation.id).await
    } else {
        state.node_operations.claim_terminal_audit(&operation.id)
    };
    if !claimed {
        return;
    }
    let action = format!("{:?}", operation.action).to_ascii_lowercase();
    crate::service::audit::record(
        state,
        operation.actor_id,
        &format!("node_{action}_result"),
        "node",
        &operation.node_id,
        &format!(
            "group_id={} operation_id={} status={:?}",
            operation.group_id, operation.id, operation.status
        ),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::Claims;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::body::Body;
    use axum::http::Request;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use tower::ServiceExt;

    fn test_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
    }

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (state, pool)
    }

    fn start(
        registry: &NodeOperationRegistry,
        node: &str,
        action: NodeLifecycleAction,
    ) -> NodeOperation {
        registry
            .start(
                1,
                node.into(),
                action,
                Some("1.2.3".into()),
                None,
                Some("amd64".into()),
                None,
                Some(1),
            )
            .unwrap()
    }

    fn lifecycle_event(
        operation: &NodeOperation,
        status: NodeLifecycleEventStatus,
    ) -> NodeLifecycleEvent {
        NodeLifecycleEvent {
            msg_type: "node_lifecycle_event".into(),
            operation_id: operation.id.clone(),
            node_id: operation.node_id.clone(),
            action: operation.action,
            status,
            message: "test".into(),
            node_version: Some("1.2.3".into()),
            architecture: Some("x86_64".into()),
            logs: None,
        }
    }

    async fn seed_durable_uninstall(
        state: &AppState,
        operation: &NodeOperation,
        saw_disconnect: bool,
        cleanup_confirmed: bool,
    ) {
        assert_eq!(
            crate::service::relay_preference::begin_uninstall_gate(
                state.db.as_ref(),
                operation.group_id,
                &operation.node_id,
                &operation.id,
            )
            .await
            .unwrap(),
            crate::service::relay_preference::BeginUninstallGateOutcome::Acquired
        );
        let mut durable = DurableUninstallOperation::new(operation);
        durable.saw_disconnect = saw_disconnect;
        durable.cleanup_confirmed = cleanup_confirmed;
        durable.destructive_started = cleanup_confirmed;
        durable.operation.status = OperationStatus::Verifying;
        store_durable_uninstall(state, &durable).await.unwrap();
    }

    #[test]
    fn log_limits_and_uninstall_confirmation_are_strict() {
        assert_eq!(requested_log_lines(None), Ok(200));
        assert_eq!(requested_log_lines(Some(500)), Ok(500));
        assert!(requested_log_lines(Some(0)).is_err());
        assert!(requested_log_lines(Some(501)).is_err());
        assert!(uninstall_confirmed(Some("UNINSTALL")));
        assert!(!uninstall_confirmed(Some("uninstall")));
        assert!(!uninstall_confirmed(None));
    }

    #[test]
    fn modern_reality_panel_lifecycle_uses_semver_and_current_protocol() {
        let compatible = serde_json::json!({
            "config_protocol_version": CONFIG_PROTOCOL_VERSION
        });
        for version in ["v1.0.0", "1.0.1", "1.1.0-rc.1", "1.1.0", "2.0.0-rc.1"] {
            assert!(
                status_supports_lifecycle(Some(&compatible), Some(version)),
                "expected {version} with current protocol to support lifecycle"
            );
        }
        assert!(!status_supports_lifecycle(
            Some(&compatible),
            Some("1.0.0-rc.4")
        ));
        assert!(!status_supports_lifecycle(
            Some(&compatible),
            Some("invalid")
        ));

        let legacy_protocol = serde_json::json!({
            "config_protocol_version": CONFIG_PROTOCOL_VERSION - 1
        });
        assert!(!status_supports_lifecycle(
            Some(&legacy_protocol),
            Some("1.0.0")
        ));
        assert!(!status_supports_lifecycle(
            Some(&legacy_protocol),
            Some("1.1.0-rc.1")
        ));
        assert!(!status_supports_lifecycle(None, Some("1.1.0-rc.1")));
        // rc.2/rc.3 already shipped node_lifecycle. A config protocol bump must
        // never make their one-click upgrade path disappear.
        assert!(status_supports_lifecycle(
            Some(&legacy_protocol),
            Some("1.1.0-rc.3")
        ));

        // Explicitly-known historical lifecycle versions keep their
        // compatibility path independently from config snapshot gates.
        assert!(status_supports_lifecycle(None, Some("1.2.3")));
        assert!(status_supports_lifecycle(None, Some("1.0.0-rc.5")));
    }

    #[test]
    fn destructive_lock_is_per_node_and_logs_do_not_take_it() {
        let registry = NodeOperationRegistry::new();
        start(&registry, "a", NodeLifecycleAction::Upgrade);
        assert!(registry
            .start(
                1,
                "a".into(),
                NodeLifecycleAction::Restart,
                None,
                None,
                None,
                None,
                None
            )
            .is_err());
        assert!(registry
            .start(
                1,
                "b".into(),
                NodeLifecycleAction::Restart,
                None,
                None,
                None,
                None,
                None
            )
            .is_ok());
        assert!(registry
            .start(
                1,
                "a".into(),
                NodeLifecycleAction::Logs,
                None,
                None,
                None,
                None,
                None
            )
            .is_ok());
    }

    #[test]
    fn wrong_operation_node_or_action_cannot_complete_operation() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Restart);
        let mut event = lifecycle_event(&operation, NodeLifecycleEventStatus::Completed);
        event.operation_id = "wrong".into();
        assert!(registry.event(1, event).is_none());
        let mut event = lifecycle_event(&operation, NodeLifecycleEventStatus::Completed);
        event.node_id = "b".into();
        assert!(registry.event(1, event).is_none());
        let mut event = lifecycle_event(&operation, NodeLifecycleEventStatus::Completed);
        event.action = NodeLifecycleAction::Upgrade;
        assert!(registry.event(1, event).is_none());
        assert!(!registry.get(&operation.id).unwrap().status.terminal());
    }

    #[test]
    fn restart_disconnect_waits_for_matching_reconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Restart);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Accepted),
        );
        assert!(registry.disconnected(1, "a").is_empty());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Verifying
        );
        assert!(registry
            .connected(1, "b", Some("1.2.3"), Some("x86_64"))
            .is_empty());
        assert!(registry
            .connected(1, "a", Some("1.2.3"), Some("x86_64"))
            .is_empty());
        assert_eq!(
            registry
                .event(
                    1,
                    lifecycle_event(&operation, NodeLifecycleEventStatus::Completed)
                )
                .unwrap()
                .status,
            OperationStatus::Success
        );
    }

    #[test]
    fn restart_exact_boot_confirmation_succeeds_without_observed_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Restart);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        let outcome = registry.event_from_authenticated_node(
            1,
            Some("a"),
            lifecycle_event(&operation, NodeLifecycleEventStatus::Completed),
        );
        assert_eq!(outcome.operation.unwrap().status, OperationStatus::Success);
        assert!(outcome.boot_ack.is_some());
        assert!(registry.disconnected(1, "a").is_empty());
    }

    #[test]
    fn upgrade_reconnect_requires_exact_target_version() {
        let registry = NodeOperationRegistry::new();
        let operation = registry
            .start(
                1,
                "a".into(),
                NodeLifecycleAction::Upgrade,
                Some("1.2.3".into()),
                Some("1.2.4".into()),
                Some("amd64".into()),
                Some("0".repeat(64)),
                Some(1),
            )
            .unwrap();
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        registry.disconnected(1, "a");
        registry.connected(1, "a", Some("1.2.3"), Some("x86_64"));
        assert_eq!(
            registry
                .event(
                    1,
                    lifecycle_event(&operation, NodeLifecycleEventStatus::Completed)
                )
                .unwrap()
                .status,
            OperationStatus::Failed
        );
    }

    #[test]
    fn upgrade_reconnect_with_exact_target_version_succeeds() {
        let registry = NodeOperationRegistry::new();
        let operation = registry
            .start(
                1,
                "a".into(),
                NodeLifecycleAction::Upgrade,
                Some("1.2.3".into()),
                Some("1.2.4".into()),
                Some("amd64".into()),
                Some("0".repeat(64)),
                Some(1),
            )
            .unwrap();
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        registry.disconnected(1, "a");
        registry.connected(1, "a", Some("1.2.4"), Some("x86_64"));
        let mut boot = lifecycle_event(&operation, NodeLifecycleEventStatus::Completed);
        boot.node_version = Some("1.2.4".into());
        assert_eq!(
            registry.event(1, boot).unwrap().status,
            OperationStatus::Success
        );
    }

    fn upgrade_operation(registry: &NodeOperationRegistry) -> NodeOperation {
        registry
            .start(
                1,
                "node-a".into(),
                NodeLifecycleAction::Upgrade,
                Some("1.2.3".into()),
                Some("1.2.4".into()),
                Some("amd64".into()),
                Some("0".repeat(64)),
                Some(1),
            )
            .unwrap()
    }

    fn matching_upgrade_boot(operation: &NodeOperation) -> NodeLifecycleEvent {
        let mut event = lifecycle_event(operation, NodeLifecycleEventStatus::Completed);
        event.node_version = Some("1.2.4".into());
        event
    }

    #[test]
    fn upgrade_boot_confirmation_and_disconnect_are_order_independent() {
        let confirmation_first = NodeOperationRegistry::new();
        let operation = upgrade_operation(&confirmation_first);
        confirmation_first.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        let outcome = confirmation_first.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(outcome.boot_ack.is_some());
        assert_eq!(
            outcome.operation.unwrap().status,
            OperationStatus::Success,
            "exact authenticated confirmation is decisive even if disconnect was not observed"
        );
        assert!(confirmation_first.disconnected(1, "node-a").is_empty());

        let disconnect_first = NodeOperationRegistry::new();
        let operation = upgrade_operation(&disconnect_first);
        disconnect_first.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        assert!(disconnect_first.disconnected(1, "node-a").is_empty());
        assert_eq!(
            disconnect_first.get(&operation.id).unwrap().status,
            OperationStatus::Verifying,
            "disconnect alone must not complete an upgrade"
        );
        assert_eq!(
            disconnect_first
                .event_from_authenticated_node(1, Some("node-a"), matching_upgrade_boot(&operation))
                .operation
                .unwrap()
                .status,
            OperationStatus::Success
        );
    }

    #[test]
    fn upgrade_boot_confirmation_wrong_version_fails_without_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = upgrade_operation(&registry);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        let mut wrong_version = matching_upgrade_boot(&operation);
        wrong_version.node_version = Some("9.9.9".into());
        let outcome = registry.event_from_authenticated_node(1, Some("node-a"), wrong_version);
        assert_eq!(outcome.operation.unwrap().status, OperationStatus::Failed);
        assert!(outcome.boot_ack.is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Failed
        );
    }

    #[test]
    fn early_upgrade_confirmation_rejects_wrong_correlation_and_is_idempotent() {
        let registry = NodeOperationRegistry::new();
        let operation = upgrade_operation(&registry);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );

        let mut wrong_operation = matching_upgrade_boot(&operation);
        wrong_operation.operation_id = "wrong".into();
        let outcome = registry.event_from_authenticated_node(1, Some("node-a"), wrong_operation);
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_none());
        let outcome = registry.event_from_authenticated_node(
            2,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_none());
        let mut wrong_node = matching_upgrade_boot(&operation);
        wrong_node.node_id = "node-b".into();
        let outcome = registry.event_from_authenticated_node(1, Some("node-b"), wrong_node);
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_none());
        let mut wrong_action = matching_upgrade_boot(&operation);
        wrong_action.action = NodeLifecycleAction::Restart;
        let outcome = registry.event_from_authenticated_node(1, Some("node-a"), wrong_action);
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_none());
        let first = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert_eq!(
            first.operation.as_ref().unwrap().status,
            OperationStatus::Success
        );
        assert!(first.boot_ack.is_some());
        let duplicate = registry.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(duplicate.operation.is_none());
        assert!(duplicate.boot_ack.is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );
        assert!(registry.disconnected(1, "node-a").is_empty());
        assert!(registry
            .event_from_authenticated_node(1, Some("node-a"), matching_upgrade_boot(&operation))
            .boot_ack
            .is_some());
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );
    }

    #[test]
    fn consumed_boot_confirmations_ack_failed_and_timeout_operations_without_reopening_them() {
        let failed = NodeOperationRegistry::new();
        let operation = upgrade_operation(&failed);
        failed.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        failed.disconnected(1, "node-a");
        let mut wrong_version = matching_upgrade_boot(&operation);
        wrong_version.node_version = Some("9.9.9".into());
        let outcome = failed.event_from_authenticated_node(1, Some("node-a"), wrong_version);
        assert_eq!(outcome.operation.unwrap().status, OperationStatus::Failed);
        assert!(outcome.boot_ack.is_some());
        let mut duplicate = matching_upgrade_boot(&operation);
        duplicate.node_version = Some("9.9.9".into());
        let outcome = failed.event_from_authenticated_node(1, Some("node-a"), duplicate);
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_some());
        assert_eq!(
            failed.get(&operation.id).unwrap().status,
            OperationStatus::Failed
        );

        let timed_out = NodeOperationRegistry::new();
        let operation = upgrade_operation(&timed_out);
        {
            let mut entries = timed_out.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_HARD_TIMEOUT_SECS + 1))
            .to_rfc3339();
        }
        assert_eq!(
            timed_out.get(&operation.id).unwrap().status,
            OperationStatus::Timeout
        );
        let outcome = timed_out.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        assert!(outcome.operation.is_none());
        assert!(outcome.boot_ack.is_some());
        assert_eq!(
            timed_out.get(&operation.id).unwrap().status,
            OperationStatus::Timeout
        );
    }

    #[test]
    fn lifecycle_progress_events_refresh_idle_timeout_without_moving_created_at() {
        let registry = NodeOperationRegistry::new();
        let operation = upgrade_operation(&registry);
        let created_at = (chrono::Utc::now()
            - chrono::Duration::seconds(OPERATION_IDLE_TIMEOUT_SECS + 1))
        .to_rfc3339();
        {
            let mut entries = registry.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = created_at.clone();
            entry.operation.updated_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_IDLE_TIMEOUT_SECS + 1))
            .to_rfc3339();
        }

        for status in [
            NodeLifecycleEventStatus::Accepted,
            NodeLifecycleEventStatus::Downloading,
            NodeLifecycleEventStatus::Validating,
            NodeLifecycleEventStatus::Installing,
            NodeLifecycleEventStatus::Restarting,
        ] {
            registry.event(1, lifecycle_event(&operation, status));
            let current = registry.get(&operation.id).unwrap();
            assert_ne!(
                current.status,
                OperationStatus::Timeout,
                "{status:?} is progress"
            );
            assert_eq!(
                current.created_at, created_at,
                "progress must not extend hard deadline"
            );
        }
    }

    #[test]
    fn lifecycle_timeout_uses_idle_and_hard_deadlines_without_rewriting_terminal_states() {
        let registry = NodeOperationRegistry::new();
        let operation = upgrade_operation(&registry);
        {
            let mut entries = registry.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_IDLE_TIMEOUT_SECS + 1))
            .to_rfc3339();
            entry.operation.updated_at = chrono::Utc::now().to_rfc3339();
        }
        assert_ne!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Timeout
        );

        {
            let mut entries = registry.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.updated_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_IDLE_TIMEOUT_SECS + 1))
            .to_rfc3339();
        }
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Timeout
        );

        let hard_deadline = NodeOperationRegistry::new();
        let operation = upgrade_operation(&hard_deadline);
        {
            let mut entries = hard_deadline.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_HARD_TIMEOUT_SECS + 1))
            .to_rfc3339();
            entry.operation.updated_at = chrono::Utc::now().to_rfc3339();
        }
        assert_eq!(
            hard_deadline.get(&operation.id).unwrap().status,
            OperationStatus::Timeout
        );

        let terminal = NodeOperationRegistry::new();
        let operation = upgrade_operation(&terminal);
        terminal.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        terminal.disconnected(1, "node-a");
        terminal.event_from_authenticated_node(
            1,
            Some("node-a"),
            matching_upgrade_boot(&operation),
        );
        {
            let mut entries = terminal.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_HARD_TIMEOUT_SECS + 1))
            .to_rfc3339();
        }
        assert_eq!(
            terminal.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );

        let failed = NodeOperationRegistry::new();
        let operation = upgrade_operation(&failed);
        failed.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Failed),
        );
        {
            let mut entries = failed.inner.lock().unwrap();
            let entry = entries.get_mut(&operation.id).unwrap();
            entry.operation.created_at = (chrono::Utc::now()
                - chrono::Duration::seconds(OPERATION_HARD_TIMEOUT_SECS + 1))
            .to_rfc3339();
        }
        assert_eq!(
            failed.get(&operation.id).unwrap().status,
            OperationStatus::Failed
        );
    }

    #[test]
    fn upgrade_preserves_source_version_after_reconnect_and_completion() {
        let registry = NodeOperationRegistry::new();
        let operation = registry
            .start(
                1,
                "a".into(),
                NodeLifecycleAction::Upgrade,
                Some("1.2.3".into()),
                Some("1.2.4-test".into()),
                Some("amd64".into()),
                Some("0".repeat(64)),
                Some(1),
            )
            .unwrap();

        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Accepted),
        );
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Downloading),
        );
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Restarting),
        );
        registry.disconnected(1, "a");
        registry.connected(1, "a", Some("1.2.4-test"), Some("x86_64"));

        let reconnected = registry.get(&operation.id).unwrap();
        assert_eq!(reconnected.current_version.as_deref(), Some("1.2.3"));
        assert_eq!(reconnected.target_version.as_deref(), Some("1.2.4-test"));

        let mut boot = lifecycle_event(&operation, NodeLifecycleEventStatus::Completed);
        boot.node_version = Some("1.2.4-test".into());
        let completed = registry.event(1, boot).unwrap();
        assert_eq!(completed.status, OperationStatus::Success);
        assert_eq!(completed.current_version.as_deref(), Some("1.2.3"));
        assert_eq!(completed.target_version.as_deref(), Some("1.2.4-test"));
    }

    #[test]
    fn uninstall_requires_verified_cleanup_result_and_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Uninstall);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Accepted),
        );
        assert_eq!(
            registry.disconnected(1, "a")[0].status,
            OperationStatus::Verifying
        );
        assert_ne!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );

        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Uninstall);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Completed),
        );
        assert_eq!(
            registry.disconnected(1, "a")[0].status,
            OperationStatus::Verifying
        );
        assert_ne!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Success
        );
    }

    #[test]
    fn uninstall_cleanup_result_and_disconnect_are_order_independent() {
        let confirmation_first = NodeOperationRegistry::new();
        let operation = confirmation_first
            .start(
                1,
                "node-a".into(),
                NodeLifecycleAction::Uninstall,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let waiting = confirmation_first
            .uninstall_result(1, "node-a", &operation.id, true, "cleanup complete".into())
            .unwrap();
        assert_eq!(waiting.status, OperationStatus::Verifying);
        assert_eq!(
            confirmation_first.disconnected(1, "node-a")[0].status,
            OperationStatus::Verifying
        );
        assert_eq!(
            confirmation_first
                .mark_uninstall_panel_cleanup_complete(&operation.id)
                .unwrap()
                .status,
            OperationStatus::Success
        );

        let disconnect_first = NodeOperationRegistry::new();
        let operation = disconnect_first
            .start(
                1,
                "node-a".into(),
                NodeLifecycleAction::Uninstall,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            disconnect_first.disconnected(1, "node-a")[0].status,
            OperationStatus::Verifying
        );
        let completed = disconnect_first
            .uninstall_result(1, "node-a", &operation.id, true, "cleanup complete".into())
            .unwrap();
        assert_eq!(completed.status, OperationStatus::Verifying);
        assert_eq!(
            disconnect_first
                .mark_uninstall_panel_cleanup_complete(&operation.id)
                .unwrap()
                .status,
            OperationStatus::Success
        );
    }

    #[test]
    fn uninstall_failure_is_terminal_and_wrong_correlation_is_rejected() {
        let registry = NodeOperationRegistry::new();
        let operation = registry
            .start(
                1,
                "node-a".into(),
                NodeLifecycleAction::Uninstall,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(registry
            .uninstall_result(2, "node-a", &operation.id, true, "wrong group".into())
            .is_none());
        assert!(registry
            .uninstall_result(1, "node-b", &operation.id, true, "wrong node".into())
            .is_none());
        let failed = registry
            .uninstall_result(
                1,
                "node-a",
                &operation.id,
                false,
                "nginx cleanup failed".into(),
            )
            .unwrap();
        assert_eq!(failed.status, OperationStatus::Verifying);
        assert_eq!(
            registry.disconnected(1, "node-a")[0].status,
            OperationStatus::Verifying
        );
        assert_eq!(
            registry.get(&operation.id).unwrap().status,
            OperationStatus::Verifying
        );
    }

    #[tokio::test]
    async fn durable_uninstall_survives_registry_restart_and_duplicate_completion() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (1, 'relay', 'in', 'node-token', 1, '192.0.2.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let operation = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &operation, true, false).await;
        let restarted = AppState {
            node_operations: NodeOperationRegistry::new(),
            ..state.clone()
        };
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer node-token".parse().unwrap());
        headers.insert("X-Node-ID", "node-a".parse().unwrap());
        let request = || UninstallResultRequest {
            operation_id: operation.id.clone(),
            node_id: "node-a".into(),
            success: true,
            destructive_started: true,
            message: "cleanup complete".into(),
        };
        let response =
            receive_uninstall_result(State(restarted.clone()), headers.clone(), Json(request()))
                .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            load_durable_uninstall(&restarted, &operation.id)
                .await
                .unwrap()
                .unwrap()
                .operation
                .status,
            OperationStatus::Success
        );
        assert!(
            !crate::service::relay_preference::mark_uninstall_gate_destructive(
                restarted.db.as_ref(),
                1,
                "node-a",
                &operation.id,
            )
            .await
            .unwrap()
        );

        let duplicate = receive_uninstall_result(State(restarted), headers, Json(request())).await;
        assert_eq!(duplicate.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn callback_first_waits_for_disconnect_then_duplicate_receives_ack() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (1, 'relay', 'in', 'node-token', 1, '192.0.2.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let operation = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &operation, false, false).await;
        let (_connection, receiver) = state
            .node_connections
            .register_with_capabilities(1, Some("node-a".into()), true, true)
            .await;
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer node-token".parse().unwrap());
        headers.insert("X-Node-ID", "node-a".parse().unwrap());
        let request = || UninstallResultRequest {
            operation_id: operation.id.clone(),
            node_id: "node-a".into(),
            success: true,
            destructive_started: true,
            message: "cleanup complete; OpenList ownership unknown, preserved".into(),
        };
        let waiting =
            receive_uninstall_result(State(state.clone()), headers.clone(), Json(request())).await;
        assert_eq!(waiting.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            load_durable_uninstall(&state, &operation.id)
                .await
                .unwrap()
                .unwrap()
                .operation
                .status,
            OperationStatus::Verifying
        );

        drop(receiver);
        state.node_connections.close_group(1).await;
        record_uninstall_disconnect(&state, 1, "node-a").await;
        let completed = load_durable_uninstall(&state, &operation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.operation.status, OperationStatus::Success);
        assert!(completed.operation.message.contains("ownership unknown"));

        let acknowledged = receive_uninstall_result(State(state), headers, Json(request())).await;
        assert_eq!(acknowledged.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn uninstall_callback_rejects_unauthenticated_and_wrong_correlation() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (1, 'relay', 'in', 'node-token', 1, '192.0.2.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let operation = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &operation, true, false).await;
        let body = |operation_id: String, node_id: &str| UninstallResultRequest {
            operation_id,
            node_id: node_id.into(),
            success: true,
            destructive_started: true,
            message: "cleanup complete".into(),
        };
        let unauthenticated = receive_uninstall_result(
            State(state.clone()),
            HeaderMap::new(),
            Json(body(operation.id.clone(), "node-a")),
        )
        .await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer node-token".parse().unwrap());
        headers.insert("X-Node-ID", "node-a".parse().unwrap());
        let wrong_operation = receive_uninstall_result(
            State(state.clone()),
            headers.clone(),
            Json(body("wrong-operation".into(), "node-a")),
        )
        .await;
        assert_eq!(wrong_operation.status(), StatusCode::FORBIDDEN);
        let mut wrong_action = load_durable_uninstall(&state, &operation.id)
            .await
            .unwrap()
            .unwrap();
        wrong_action.operation.action = NodeLifecycleAction::Restart;
        store_durable_uninstall(&state, &wrong_action)
            .await
            .unwrap();
        let wrong_action_response = receive_uninstall_result(
            State(state.clone()),
            headers.clone(),
            Json(body(operation.id.clone(), "node-a")),
        )
        .await;
        assert_eq!(wrong_action_response.status(), StatusCode::FORBIDDEN);
        wrong_action.operation.action = NodeLifecycleAction::Uninstall;
        store_durable_uninstall(&state, &wrong_action)
            .await
            .unwrap();
        headers.insert("X-Node-ID", "node-b".parse().unwrap());
        let wrong_node =
            receive_uninstall_result(State(state), headers, Json(body(operation.id, "node-b")))
                .await;
        assert_eq!(wrong_node.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn panel_cleanup_failure_stays_nonterminal_and_retry_converges() {
        let (state, _) = test_state().await;
        let operation = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &operation, true, true).await;
        state
            .db
            .set("relay_preference:1", "not-json")
            .await
            .unwrap();
        assert!(finalize_durable_uninstall(&state, &operation.id)
            .await
            .is_err());
        assert_eq!(
            load_durable_uninstall(&state, &operation.id)
                .await
                .unwrap()
                .unwrap()
                .operation
                .status,
            OperationStatus::Verifying
        );
        state
            .db
            .set(
                "relay_preference:1",
                &serde_json::to_string(
                    &crate::service::relay_preference::RelayPreferenceState::default(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            finalize_durable_uninstall(&state, &operation.id)
                .await
                .unwrap()
                .status,
            OperationStatus::Success
        );
    }

    #[tokio::test]
    async fn uninstall_gate_releases_only_for_explicit_pre_destructive_failure() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (1, 'relay', 'in', 'node-token', 1, '192.0.2.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer node-token".parse().unwrap());
        headers.insert("X-Node-ID", "node-a".parse().unwrap());

        let before = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &before, false, false).await;
        let failed_before = receive_uninstall_result(
            State(state.clone()),
            headers.clone(),
            Json(UninstallResultRequest {
                operation_id: before.id.clone(),
                node_id: "node-a".into(),
                success: false,
                destructive_started: false,
                message: "finalizer installation failed".into(),
            }),
        )
        .await;
        assert_eq!(failed_before.status(), StatusCode::OK);
        assert!(
            !crate::service::relay_preference::mark_uninstall_gate_destructive(
                state.db.as_ref(),
                1,
                "node-a",
                &before.id,
            )
            .await
            .unwrap()
        );

        let after = start(
            &state.node_operations,
            "node-b",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &after, false, false).await;
        headers.insert("X-Node-ID", "node-b".parse().unwrap());
        let failed_after = receive_uninstall_result(
            State(state.clone()),
            headers,
            Json(UninstallResultRequest {
                operation_id: after.id.clone(),
                node_id: "node-b".into(),
                success: false,
                destructive_started: true,
                message: "cleanup will retry".into(),
            }),
        )
        .await;
        assert_eq!(failed_after.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            crate::service::relay_preference::mark_uninstall_gate_destructive(
                state.db.as_ref(),
                1,
                "node-b",
                &after.id,
            )
            .await
            .unwrap()
        );
    }

    #[test]
    fn artifact_metadata_rejects_missing_sha_and_wrong_elf() {
        let root = test_dir("relay-artifacts");
        let dir = root.join("amd64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("metadata.json"),
            br#"{"version":"1.2.3","sha256":"bad"}"#,
        )
        .unwrap();
        std::fs::write(dir.join("relay-node"), vec![0_u8; MIN_ARTIFACT_BYTES]).unwrap();
        assert!(load_artifact_from(&root, "amd64").is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_metadata_read_errors_are_classified_without_paths() {
        assert_eq!(
            artifact_metadata_read_error(std::io::ErrorKind::NotFound),
            "artifact metadata missing"
        );
        assert_eq!(
            artifact_metadata_read_error(std::io::ErrorKind::PermissionDenied),
            "artifact metadata not readable: permission denied"
        );
        assert_eq!(
            artifact_metadata_read_error(std::io::ErrorKind::Interrupted),
            "artifact metadata could not be read"
        );
    }

    #[test]
    fn artifact_loader_rejects_missing_and_accepts_matching_metadata() {
        let root = test_dir("relay-artifacts");
        assert!(load_artifact_from(&root, "amd64").is_err());
        let dir = root.join("amd64");
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = vec![0_u8; MIN_ARTIFACT_BYTES];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let sha = format!("{:x}", Sha256::digest(&bytes));
        std::fs::write(dir.join("relay-node"), &bytes).unwrap();
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec(&ArtifactMetadata {
                version: "1.2.3".into(),
                sha256: sha,
                size: bytes.len() as u64,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(load_artifact_from(&root, "x86_64").is_ok());
        assert!(load_artifact_from(&root, "arm64").is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn offline_lifecycle_request_is_rejected_without_pending_operation() {
        let (state, _) = test_state().await;
        for action in [
            NodeLifecycleAction::Logs,
            NodeLifecycleAction::Restart,
            NodeLifecycleAction::Upgrade,
            NodeLifecycleAction::Uninstall,
        ] {
            let response = create_operation(
                &state,
                1,
                1,
                "offline".into(),
                action,
                (action == NodeLifecycleAction::Logs).then_some(200),
            )
            .await
            .unwrap_err();
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        assert!(state.node_operations.inner.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn uninstall_preflight_rejects_active_switching_and_rolling_back_references() {
        for phase in ["switching", "rolling_back"] {
            let (state, _) = test_state().await;
            state
                .db
                .set(
                    "node_status:1:node-a",
                    &serde_json::json!({
                        "node_id": "node-a",
                        "node_version": "1.1.6",
                        "config_protocol_version": CONFIG_PROTOCOL_VERSION,
                        "architecture": "x86_64"
                    })
                    .to_string(),
                )
                .await
                .unwrap();
            state.db.set("relay_preference:1", &format!(r#"{{"preferred_node_id":"node-a","pending_node_id":"node-b","state":"{phase}","started_at":"x","last_error":null,"rollback_error":null,"dns_records":[],"carrier_policy":{{"bindings":[]}},"pending_carrier_policy":null,"transaction_kind":"preferred_switch"}}"#)).await.unwrap();
            let (_connection, _receiver) = state
                .node_connections
                .register_with_capabilities(1, Some("node-a".into()), true, true)
                .await;
            let response = create_operation(
                &state,
                1,
                1,
                "node-a".into(),
                NodeLifecycleAction::Uninstall,
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(response.status(), StatusCode::CONFLICT, "{phase}");
            assert!(state.node_operations.inner.lock().unwrap().is_empty());
            assert!(state
                .db
                .scan_prefix(DURABLE_UNINSTALL_PREFIX)
                .await
                .unwrap()
                .is_empty());
        }

        let (state, _) = test_state().await;
        state
            .db
            .set(
                "node_status:1:node-a",
                &serde_json::json!({
                    "node_id": "node-a",
                    "node_version": "1.1.6",
                    "config_protocol_version": CONFIG_PROTOCOL_VERSION,
                    "architecture": "x86_64"
                })
                .to_string(),
            )
            .await
            .unwrap();
        state.db.set("relay_preference:1", r#"{"preferred_node_id":"node-a","pending_node_id":null,"state":"idle","started_at":null,"last_error":null,"rollback_error":null,"dns_records":[],"carrier_policy":{"bindings":[]},"pending_carrier_policy":null,"transaction_kind":null}"#).await.unwrap();
        let (_connection, _receiver) = state
            .node_connections
            .register_with_capabilities(1, Some("node-a".into()), true, true)
            .await;
        assert!(create_operation(
            &state,
            1,
            1,
            "node-a".into(),
            NodeLifecycleAction::Uninstall,
            None,
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn durable_uninstall_blocks_duplicate_destructive_operation_after_registry_restart() {
        let (state, _) = test_state().await;
        let operation = start(
            &state.node_operations,
            "node-a",
            NodeLifecycleAction::Uninstall,
        );
        seed_durable_uninstall(&state, &operation, false, false).await;
        let restarted = AppState {
            node_operations: NodeOperationRegistry::new(),
            ..state
        };
        for action in [
            NodeLifecycleAction::Restart,
            NodeLifecycleAction::Upgrade,
            NodeLifecycleAction::Uninstall,
        ] {
            let response = create_operation(&restarted, 1, 1, "node-a".into(), action, None)
                .await
                .unwrap_err();
            assert_eq!(response.status(), StatusCode::CONFLICT, "{action:?}");
        }
    }

    #[tokio::test]
    async fn upgrade_only_channel_allows_only_upgrade_and_disconnect_revokes_it() {
        let connections = NodeConnections::new();
        let (_, lifecycle_rx) = connections
            .register_with_capabilities(1, Some("old-node".into()), false, true)
            .await;

        assert!(
            operation_channel_online(&connections, 1, "old-node", NodeLifecycleAction::Upgrade,)
                .await
        );
        for action in [
            NodeLifecycleAction::Logs,
            NodeLifecycleAction::Restart,
            NodeLifecycleAction::Uninstall,
        ] {
            assert!(!operation_channel_online(&connections, 1, "old-node", action).await);
        }

        drop(lifecycle_rx);
        assert!(
            !operation_channel_online(&connections, 1, "old-node", NodeLifecycleAction::Upgrade,)
                .await
        );
    }

    #[tokio::test]
    async fn lifecycle_routes_reject_missing_auth_and_non_admin() {
        let (state, pool) = test_state().await;
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, token_version, banned, must_change_password) VALUES (2, 'user', 'hash', 0, 0, 0, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let token = encode(
            &Header::default(),
            &Claims {
                sub: 2,
                admin: false,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();
        let app = crate::api::routes().with_state(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/nodes/1/node-a/logs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/nodes/1/node-a/logs")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn artifact_download_is_bound_to_matching_upgrade_operation() {
        let registry = NodeOperationRegistry::new();
        let operation = registry
            .start(
                7,
                "node-a".into(),
                NodeLifecycleAction::Upgrade,
                Some("1.2.3".into()),
                Some("1.2.4".into()),
                Some("amd64".into()),
                Some("a".repeat(64)),
                Some(1),
            )
            .unwrap();
        assert!(registry
            .artifact_target(7, "node-a", &operation.id)
            .is_some());
        assert!(registry
            .artifact_target(8, "node-a", &operation.id)
            .is_none());
        assert!(registry
            .artifact_target(7, "node-b", &operation.id)
            .is_none());
        assert!(registry.artifact_target(7, "node-a", "wrong").is_none());
    }

    #[test]
    fn audit_detail_shape_contains_no_secret_fields() {
        let operation = start(
            &NodeOperationRegistry::new(),
            "node-a",
            NodeLifecycleAction::Restart,
        );
        let detail = format!(
            "group_id={} operation_id={} status={:?}",
            operation.group_id, operation.id, operation.status
        );
        for secret_name in ["NODE_TOKEN", "Authorization", "Bearer", "password"] {
            assert!(!detail.contains(secret_name));
        }
    }

    #[tokio::test]
    async fn successful_uninstall_cleans_only_node_scoped_panel_state() {
        let (state, _) = test_state().await;
        state
            .db
            .set("node_status:1:node-a", r#"{"public_ipv4":"192.0.2.10"}"#)
            .await
            .unwrap();
        state.db.set("geoip:192.0.2.10", "{}").await.unwrap();
        state
            .db
            .set(
                "node_config_revision:1:node-a",
                r#"{"revision":7,"fingerprint":"x"}"#,
            )
            .await
            .unwrap();
        state.db.set("relay_preference:1", r#"{"preferred_node_id":"node-a","pending_node_id":null,"state":"idle","started_at":null,"last_error":null,"rollback_error":null,"dns_records":[],"carrier_policy":{"bindings":[{"line_id":"Dianxin","mode":"node","node_id":"node-a"}]},"pending_carrier_policy":null,"transaction_kind":null}"#).await.unwrap();
        state.db.set("relay_failover:1", r#"{"model_version":1,"enabled":false,"health_check_port":443,"failure_after_seconds":5,"excluded_failed_node_ids":["node-a"],"last_switch_at":"x","last_from_node_id":"node-a","last_to_node_id":"node-a","last_result":"failed","last_error":"x"}"#).await.unwrap();
        state.db.set(crate::service::relay_schedule::RELAY_SWITCH_SCHEDULES_KEY, r#"[{"id":"a","group_id":1,"target_node_id":"node-a","schedule_type":"daily","enabled":true,"created_at":"x","updated_at":"x","execute_at":null,"time":"12:00","utc_offset_minutes":0,"weekdays":[],"last_run_at":null,"last_run_slot":null,"last_result":null,"last_error":null},{"id":"b","group_id":1,"target_node_id":"node-b","schedule_type":"daily","enabled":true,"created_at":"x","updated_at":"x","execute_at":null,"time":"12:00","utc_offset_minutes":0,"weekdays":[],"last_run_at":null,"last_run_slot":null,"last_result":null,"last_error":null}]"#).await.unwrap();
        state
            .db
            .set("global_certificate:sentinel", "keep")
            .await
            .unwrap();
        state.db.set("rule:sentinel", "keep").await.unwrap();
        state.db.set("group:sentinel", "keep").await.unwrap();

        cleanup_uninstalled_node(&state, 1, "node-a").await.unwrap();

        assert!(state
            .db
            .get("node_status:1:node-a")
            .await
            .unwrap()
            .is_none());
        assert!(state.db.get("geoip:192.0.2.10").await.unwrap().is_none());
        assert!(state
            .db
            .get("node_config_revision:1:node-a")
            .await
            .unwrap()
            .is_none());
        let preference = crate::service::relay_preference::load_preference(state.db.as_ref(), 1)
            .await
            .unwrap();
        assert!(preference.preferred_node_id.is_none());
        assert!(preference.pending_node_id.is_none());
        assert!(preference.carrier_policy.bindings.is_empty());
        let failover: crate::service::relay_failover::RelayFailoverPolicy =
            serde_json::from_str(&state.db.get("relay_failover:1").await.unwrap().unwrap())
                .unwrap();
        assert!(!failover.excluded_failed_node_ids.contains("node-a"));
        assert_eq!(failover.last_from_node_id, None);
        assert_eq!(failover.last_to_node_id, None);
        let schedules = crate::service::relay_schedule::list_schedules(state.db.as_ref())
            .await
            .unwrap();
        assert_eq!(schedules.len(), 1);
        assert_eq!(schedules[0].target_node_id, "node-b");
        for key in [
            "global_certificate:sentinel",
            "rule:sentinel",
            "group:sentinel",
        ] {
            assert_eq!(state.db.get(key).await.unwrap().as_deref(), Some("keep"));
        }
    }
}
