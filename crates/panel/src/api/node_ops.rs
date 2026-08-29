use crate::api::middleware::AdminOnly;
use crate::api::node::extract_node_token;
use crate::api::provisioning::{NODE_ARTIFACT_ROOT, NODE_ARTIFACT_ROOT_ENV};
use crate::api::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use relay_shared::protocol::{
    lifecycle_artifact_architecture, ApiResponse, NodeLifecycleAction, NodeLifecycleCommand,
    NodeLifecycleEvent, NodeLifecycleEventStatus, CONFIG_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};

const MAX_LOG_LINES: u16 = 500;
const OPERATION_TIMEOUT_SECS: i64 = 180;
const UNINSTALL_CONFIRMATION: &str = "UNINSTALL";
const MIN_ARTIFACT_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Clone)]
struct RegistryEntry {
    operation: NodeOperation,
    saw_disconnect: bool,
    uninstall_final: bool,
    result_audited: bool,
}

#[derive(Clone, Default)]
pub struct NodeOperationRegistry {
    inner: Arc<Mutex<HashMap<String, RegistryEntry>>>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
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
                uninstall_final: false,
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

    pub fn event(&self, group_id: i64, event: NodeLifecycleEvent) -> Option<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let entry = inner.get_mut(&event.operation_id)?;
        if entry.operation.group_id != group_id
            || entry.operation.node_id != event.node_id
            || entry.operation.action != event.action
            || entry.operation.status.terminal()
        {
            return None;
        }
        if event.status == NodeLifecycleEventStatus::Completed {
            match entry.operation.action {
                NodeLifecycleAction::Restart if !entry.saw_disconnect => return None,
                NodeLifecycleAction::Upgrade
                    if !entry.saw_disconnect
                        || event.node_version.as_deref()
                            != entry.operation.target_version.as_deref() =>
                {
                    if entry.saw_disconnect {
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
                        return Some(entry.operation.clone());
                    }
                    return None;
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
                entry.uninstall_final = true;
                OperationStatus::Verifying
            }
            NodeLifecycleEventStatus::Completed => OperationStatus::Success,
        };
        Some(operation.clone())
    }

    pub fn disconnected(&self, group_id: i64, node_id: &str) -> Vec<NodeOperation> {
        let mut transitioned = Vec::new();
        let mut inner = self.inner.lock().expect("node operation registry lock");
        for entry in inner.values_mut() {
            let operation = &mut entry.operation;
            if operation.group_id != group_id
                || operation.node_id != node_id
                || operation.status.terminal()
                || operation.action == NodeLifecycleAction::Logs
            {
                continue;
            }
            entry.saw_disconnect = true;
            operation.updated_at = now();
            if operation.action == NodeLifecycleAction::Uninstall && entry.uninstall_final {
                operation.status = OperationStatus::Success;
                operation.message = "uninstall confirmed and node disconnected".into();
                transitioned.push(operation.clone());
            } else {
                operation.status = OperationStatus::Verifying;
                operation.message = "node disconnected; waiting for authenticated reconnect".into();
            }
        }
        transitioned
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
                || !entry.saw_disconnect
            {
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
            operation.updated_at = now();
        }
        Vec::new()
    }

    pub fn get(&self, id: &str) -> Option<NodeOperation> {
        let mut inner = self.inner.lock().expect("node operation registry lock");
        let entry = inner.get_mut(id)?;
        if !entry.operation.status.terminal() {
            let created = chrono::DateTime::parse_from_rfc3339(&entry.operation.created_at).ok()?;
            if chrono::Utc::now()
                .signed_duration_since(created.with_timezone(&chrono::Utc))
                .num_seconds()
                >= OPERATION_TIMEOUT_SECS
            {
                entry.operation.status = OperationStatus::Timeout;
                entry.operation.message =
                    "operation timed out waiting for node confirmation".into();
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
    // Historical nodes with an explicitly known lifecycle wire capability
    // remain supported. All modern Reality Panel releases use the stable
    // semver floor plus the reported config protocol instead of adding a
    // new product-version exception for every future release line.
    if relay_shared::protocol::node_supports_lifecycle(current_version) {
        return true;
    }
    if !is_modern_reality_panel_release(current_version) {
        return false;
    }
    status
        .and_then(|value| value.get("config_protocol_version"))
        .and_then(|value| value.as_u64())
        == Some(CONFIG_PROTOCOL_VERSION as u64)
}

async fn create_operation(
    state: &AppState,
    actor_id: i64,
    group_id: i64,
    node_id: String,
    action: NodeLifecycleAction,
    log_lines: Option<u16>,
) -> Result<NodeOperation, Response> {
    if !state
        .node_connections
        .online_node_ids(group_id)
        .await
        .contains(&node_id)
    {
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
    if state
        .node_connections
        .send_node(group_id, &node_id, &encoded)
        .await
        == 0
    {
        state.node_operations.update(
            &operation.id,
            OperationStatus::Failed,
            "node disconnected before command delivery",
        );
        if let Some(failed) = state.node_operations.get(&operation.id) {
            audit_terminal_operation(state, &failed).await;
        }
        return Err(response::<()>(StatusCode::CONFLICT, 409, "NODE_OFFLINE"));
    }
    state
        .node_operations
        .update(&operation.id, OperationStatus::Sent, "command sent to node");
    Ok(state.node_operations.get(&operation.id).unwrap())
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
    match state
        .node_operations
        .get(&operation_id)
        .filter(|operation| operation.group_id == group_id && operation.node_id == node_id)
    {
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

pub async fn audit_terminal_operation(state: &AppState, operation: &NodeOperation) {
    if !operation.status.terminal()
        || operation.action == NodeLifecycleAction::Logs
        || !state.node_operations.claim_terminal_audit(&operation.id)
    {
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
    fn uninstall_requires_final_event_and_disconnect() {
        let registry = NodeOperationRegistry::new();
        let operation = start(&registry, "a", NodeLifecycleAction::Uninstall);
        registry.event(
            1,
            lifecycle_event(&operation, NodeLifecycleEventStatus::Accepted),
        );
        assert!(registry.disconnected(1, "a").is_empty());
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
            OperationStatus::Success
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
}
