use crate::api::middleware::AdminOnly;
use crate::api::node_ops::{
    create_operation, has_active_durable_uninstall, validated_artifact_version, OperationStatus,
};
use crate::api::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use relay_shared::protocol::{lifecycle_artifact_architecture, ApiResponse, NodeLifecycleAction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const BATCH_PREFIX: &str = "node_batch_upgrade:";
const RECENT_BATCH_LIMIT: usize = 10;

static BATCH_CREATE_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BatchUpgradeStatus {
    Pending,
    Running,
    Success,
    PartialSuccess,
    Failed,
    Interrupted,
}

impl BatchUpgradeStatus {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Success | Self::PartialSuccess | Self::Failed | Self::Interrupted
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BatchUpgradeItemStatus {
    Pending,
    Running,
    Success,
    Failed,
    Interrupted,
    SkippedAlreadyCurrent,
    SkippedOffline,
    SkippedUnsupportedArch,
    SkippedArtifactUnavailable,
    SkippedOperationInProgress,
    SkippedUninstallInProgress,
    SkippedVersionUnavailable,
}

impl BatchUpgradeItemStatus {
    fn skipped(self) -> bool {
        matches!(
            self,
            Self::SkippedAlreadyCurrent
                | Self::SkippedOffline
                | Self::SkippedUnsupportedArch
                | Self::SkippedArtifactUnavailable
                | Self::SkippedOperationInProgress
                | Self::SkippedUninstallInProgress
                | Self::SkippedVersionUnavailable
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchUpgradeItem {
    pub group_id: i64,
    pub node_id: String,
    pub current_version: Option<String>,
    pub target_version: Option<String>,
    pub architecture: Option<String>,
    pub status: BatchUpgradeItemStatus,
    pub reason: Option<String>,
    pub child_operation_id: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchUpgradeOperation {
    pub id: String,
    pub status: BatchUpgradeStatus,
    pub target_version: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: i64,
    pub total: usize,
    pub pending: usize,
    pub running: usize,
    pub success: usize,
    pub failed: usize,
    pub skipped: usize,
    pub current_item: Option<String>,
    pub items: Vec<BatchUpgradeItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchUpgradePreview {
    pub target_version: Option<String>,
    pub total: usize,
    pub pending: usize,
    pub already_current: usize,
    pub offline: usize,
    pub skipped: usize,
    pub items: Vec<BatchUpgradeItem>,
}

#[derive(Debug)]
struct Candidate {
    group_id: i64,
    node_id: String,
    current_version: Option<String>,
    architecture: Option<String>,
    online: bool,
    operation_active: bool,
    uninstall_active: bool,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn batch_key(id: &str) -> String {
    format!("{BATCH_PREFIX}{id}")
}

fn response<T: Serialize>(status: StatusCode, code: i32, message: &str) -> Response {
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
    Json(ApiResponse {
        code: 0,
        message: "ok".into(),
        data: Some(data),
    })
    .into_response()
}

fn parse_node_status_key(key: &str) -> Option<(i64, String)> {
    let rest = key.strip_prefix("node_status:")?;
    let (group_id, node_id) = rest.split_once(':')?;
    let group_id = group_id.parse().ok()?;
    let node_id = node_id.trim();
    (!node_id.is_empty()).then(|| (group_id, node_id.to_string()))
}

fn classify_candidate(
    candidate: Candidate,
    artifact_versions: &HashMap<String, Result<String, String>>,
) -> BatchUpgradeItem {
    let mut item = BatchUpgradeItem {
        group_id: candidate.group_id,
        node_id: candidate.node_id,
        current_version: candidate.current_version,
        target_version: None,
        architecture: None,
        status: BatchUpgradeItemStatus::Pending,
        reason: None,
        child_operation_id: None,
        started_at: None,
        finished_at: None,
    };
    let Some(architecture) = candidate
        .architecture
        .as_deref()
        .and_then(lifecycle_artifact_architecture)
        .map(str::to_string)
    else {
        item.status = BatchUpgradeItemStatus::SkippedUnsupportedArch;
        item.reason = Some("UNSUPPORTED_ARCHITECTURE".into());
        return item;
    };
    item.architecture = Some(architecture.clone());
    let Some(artifact) = artifact_versions.get(&architecture) else {
        item.status = BatchUpgradeItemStatus::SkippedArtifactUnavailable;
        item.reason = Some("ARTIFACT_UNAVAILABLE".into());
        return item;
    };
    let target_version = match artifact {
        Ok(version) => version.clone(),
        Err(_) => {
            item.status = BatchUpgradeItemStatus::SkippedArtifactUnavailable;
            item.reason = Some("ARTIFACT_UNAVAILABLE".into());
            return item;
        }
    };
    item.target_version = Some(target_version.clone());
    let Some(current) = item
        .current_version
        .as_deref()
        .and_then(|version| semver::Version::parse(version.trim_start_matches('v')).ok())
    else {
        item.status = BatchUpgradeItemStatus::SkippedVersionUnavailable;
        item.reason = Some("NODE_VERSION_UNAVAILABLE".into());
        return item;
    };
    let target = semver::Version::parse(&target_version).expect("validated artifact version");
    if current >= target {
        item.status = BatchUpgradeItemStatus::SkippedAlreadyCurrent;
        item.reason = Some("ALREADY_CURRENT".into());
    } else if candidate.uninstall_active {
        item.status = BatchUpgradeItemStatus::SkippedUninstallInProgress;
        item.reason = Some("UNINSTALL_IN_PROGRESS".into());
    } else if candidate.operation_active {
        item.status = BatchUpgradeItemStatus::SkippedOperationInProgress;
        item.reason = Some("NODE_OPERATION_IN_PROGRESS".into());
    } else if !candidate.online {
        item.status = BatchUpgradeItemStatus::SkippedOffline;
        item.reason = Some("NODE_OFFLINE".into());
    }
    item
}

fn target_version(items: &[BatchUpgradeItem]) -> Option<String> {
    let versions = items
        .iter()
        .filter_map(|item| item.target_version.clone())
        .collect::<HashSet<_>>();
    (versions.len() == 1)
        .then(|| versions.into_iter().next())
        .flatten()
}

fn refresh_counts(batch: &mut BatchUpgradeOperation) {
    batch.total = batch.items.len();
    batch.pending = batch
        .items
        .iter()
        .filter(|item| item.status == BatchUpgradeItemStatus::Pending)
        .count();
    batch.running = batch
        .items
        .iter()
        .filter(|item| item.status == BatchUpgradeItemStatus::Running)
        .count();
    batch.success = batch
        .items
        .iter()
        .filter(|item| item.status == BatchUpgradeItemStatus::Success)
        .count();
    batch.failed = batch
        .items
        .iter()
        .filter(|item| item.status == BatchUpgradeItemStatus::Failed)
        .count();
    batch.skipped = batch
        .items
        .iter()
        .filter(|item| item.status.skipped())
        .count();
}

fn final_status(batch: &BatchUpgradeOperation) -> BatchUpgradeStatus {
    if batch.failed == 0 {
        BatchUpgradeStatus::Success
    } else if batch.success > 0 {
        BatchUpgradeStatus::PartialSuccess
    } else {
        BatchUpgradeStatus::Failed
    }
}

async fn persist(state: &AppState, batch: &BatchUpgradeOperation) -> Result<(), String> {
    let raw = serde_json::to_string(batch).map_err(|error| error.to_string())?;
    state
        .db
        .set(&batch_key(&batch.id), &raw)
        .await
        .map_err(|error| error.to_string())
}

async fn load(state: &AppState, id: &str) -> Result<Option<BatchUpgradeOperation>, String> {
    state
        .db
        .get(&batch_key(id))
        .await
        .map_err(|error| error.to_string())?
        .map(|raw| serde_json::from_str(&raw).map_err(|error| error.to_string()))
        .transpose()
}

async fn collect_candidates(state: &AppState) -> Result<Vec<Candidate>, String> {
    let rows = state
        .db
        .scan_prefix("node_status:")
        .await
        .map_err(|error| error.to_string())?;
    let mut identities = HashSet::new();
    let mut candidates = Vec::new();
    for (key, raw) in rows {
        let Some((group_id, node_id)) = parse_node_status_key(&key) else {
            continue;
        };
        if !identities.insert((group_id, node_id.clone())) {
            continue;
        }
        let status = serde_json::from_str::<serde_json::Value>(&raw).unwrap_or_default();
        let lifecycle_online = state
            .node_connections
            .lifecycle_online_node_ids(group_id)
            .await
            .contains(&node_id);
        let uninstall_active = has_active_durable_uninstall(state, group_id, &node_id).await?;
        candidates.push(Candidate {
            group_id,
            operation_active: state
                .node_operations
                .has_active_for_node(group_id, &node_id),
            uninstall_active,
            online: lifecycle_online,
            current_version: status
                .get("node_version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            architecture: status
                .get("architecture")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            node_id,
        });
    }
    candidates.sort_by(|left, right| {
        (left.group_id, left.node_id.as_str()).cmp(&(right.group_id, right.node_id.as_str()))
    });
    Ok(candidates)
}

async fn preview_items(state: &AppState) -> Result<Vec<BatchUpgradeItem>, String> {
    let artifact_versions = ["amd64", "arm64"]
        .into_iter()
        .map(|architecture| {
            (
                architecture.to_string(),
                validated_artifact_version(architecture),
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(collect_candidates(state)
        .await?
        .into_iter()
        .map(|candidate| classify_candidate(candidate, &artifact_versions))
        .collect())
}

fn preview_from_items(items: Vec<BatchUpgradeItem>) -> BatchUpgradePreview {
    BatchUpgradePreview {
        target_version: target_version(&items),
        total: items.len(),
        pending: items
            .iter()
            .filter(|item| item.status == BatchUpgradeItemStatus::Pending)
            .count(),
        already_current: items
            .iter()
            .filter(|item| item.status == BatchUpgradeItemStatus::SkippedAlreadyCurrent)
            .count(),
        offline: items
            .iter()
            .filter(|item| item.status == BatchUpgradeItemStatus::SkippedOffline)
            .count(),
        skipped: items.iter().filter(|item| item.status.skipped()).count(),
        items,
    }
}

async fn active_batch(state: &AppState) -> Result<Option<BatchUpgradeOperation>, String> {
    let rows = state
        .db
        .scan_prefix(BATCH_PREFIX)
        .await
        .map_err(|error| error.to_string())?;
    Ok(rows.into_iter().find_map(|(_, raw)| {
        serde_json::from_str::<BatchUpgradeOperation>(&raw)
            .ok()
            .filter(|batch| !batch.status.terminal())
    }))
}

async fn run_batch(state: AppState, mut batch: BatchUpgradeOperation) {
    batch.status = BatchUpgradeStatus::Running;
    batch.updated_at = now();
    refresh_counts(&mut batch);
    if persist(&state, &batch).await.is_err() {
        return;
    }
    for index in 0..batch.items.len() {
        if batch.items[index].status != BatchUpgradeItemStatus::Pending {
            continue;
        }
        batch.items[index].status = BatchUpgradeItemStatus::Running;
        batch.items[index].started_at = Some(now());
        batch.current_item = Some(batch.items[index].node_id.clone());
        batch.updated_at = now();
        refresh_counts(&mut batch);
        if persist(&state, &batch).await.is_err() {
            return;
        }

        let group_id = batch.items[index].group_id;
        let node_id = batch.items[index].node_id.clone();
        match create_operation(
            &state,
            batch.created_by,
            group_id,
            node_id,
            NodeLifecycleAction::Upgrade,
            None,
        )
        .await
        {
            Ok(operation) => {
                batch.items[index].child_operation_id = Some(operation.id.clone());
                batch.updated_at = now();
                if persist(&state, &batch).await.is_err() {
                    return;
                }
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let Some(child) = state.node_operations.get(&operation.id) else {
                        batch.items[index].status = BatchUpgradeItemStatus::Failed;
                        batch.items[index].reason = Some("CHILD_OPERATION_MISSING".into());
                        break;
                    };
                    if !child.status.terminal() {
                        continue;
                    }
                    crate::api::node_ops::audit_terminal_operation(&state, &child).await;
                    match child.status {
                        OperationStatus::Success => {
                            batch.items[index].status = BatchUpgradeItemStatus::Success;
                        }
                        OperationStatus::Failed => {
                            batch.items[index].status = BatchUpgradeItemStatus::Failed;
                            batch.items[index].reason = Some("CHILD_OPERATION_FAILED".into());
                        }
                        OperationStatus::Timeout => {
                            batch.items[index].status = BatchUpgradeItemStatus::Failed;
                            batch.items[index].reason = Some("CHILD_OPERATION_TIMEOUT".into());
                        }
                        _ => unreachable!("terminal status checked"),
                    }
                    break;
                }
            }
            Err(_) => {
                batch.items[index].status = BatchUpgradeItemStatus::Failed;
                batch.items[index].reason = Some("CHILD_OPERATION_START_FAILED".into());
            }
        }
        batch.items[index].finished_at = Some(now());
        batch.current_item = None;
        batch.updated_at = now();
        refresh_counts(&mut batch);
        if persist(&state, &batch).await.is_err() {
            return;
        }
    }
    refresh_counts(&mut batch);
    batch.status = final_status(&batch);
    batch.current_item = None;
    batch.updated_at = now();
    let _ = persist(&state, &batch).await;
}

pub async fn preview(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match preview_items(&state).await {
        Ok(items) => success(preview_from_items(items)),
        Err(error) => {
            tracing::error!("batch upgrade preview failed: {error}");
            response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "BATCH_PREVIEW_UNAVAILABLE",
            )
        }
    }
}

pub async fn start(admin: AdminOnly, State(state): State<AppState>) -> Response {
    let _guard = BATCH_CREATE_LOCK.lock().await;
    match active_batch(&state).await {
        Ok(Some(_)) => {
            return response::<()>(StatusCode::CONFLICT, 409, "BATCH_UPGRADE_IN_PROGRESS")
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!("active batch lookup failed: {error}");
            return response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "BATCH_STATE_UNAVAILABLE",
            );
        }
    }
    let items = match preview_items(&state).await {
        Ok(items) => items,
        Err(error) => {
            tracing::error!("batch upgrade candidate snapshot failed: {error}");
            return response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "BATCH_PREVIEW_UNAVAILABLE",
            );
        }
    };
    let timestamp = now();
    let mut batch = BatchUpgradeOperation {
        id: uuid::Uuid::new_v4().to_string(),
        status: BatchUpgradeStatus::Pending,
        target_version: target_version(&items),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        created_by: admin.user_id,
        total: 0,
        pending: 0,
        running: 0,
        success: 0,
        failed: 0,
        skipped: 0,
        current_item: None,
        items,
    };
    refresh_counts(&mut batch);
    if let Err(error) = persist(&state, &batch).await {
        tracing::error!("persist batch upgrade: {error}");
        return response::<()>(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "BATCH_STATE_PERSIST_FAILED",
        );
    }
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "node_batch_upgrade_start",
        "node_batch_upgrade",
        &batch.id,
        &format!("total={} pending={}", batch.total, batch.pending),
    )
    .await;
    let worker_state = state.clone();
    let worker_batch = batch.clone();
    tokio::spawn(async move { run_batch(worker_state, worker_batch).await });
    success(batch)
}

pub async fn get(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match load(&state, &id).await {
        Ok(Some(batch)) => success(batch),
        Ok(None) => response::<()>(StatusCode::NOT_FOUND, 404, "BATCH_UPGRADE_NOT_FOUND"),
        Err(error) => {
            tracing::error!("load batch upgrade: {error}");
            response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "BATCH_STATE_UNAVAILABLE",
            )
        }
    }
}

pub async fn list(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    let rows = match state.db.scan_prefix(BATCH_PREFIX).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("list batch upgrades: {error}");
            return response::<()>(
                StatusCode::SERVICE_UNAVAILABLE,
                503,
                "BATCH_STATE_UNAVAILABLE",
            );
        }
    };
    let mut batches = rows
        .into_iter()
        .filter_map(|(_, raw)| serde_json::from_str::<BatchUpgradeOperation>(&raw).ok())
        .collect::<Vec<_>>();
    batches.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let mut terminal = 0usize;
    batches.retain(|batch| {
        if batch.status.terminal() {
            terminal += 1;
            terminal <= RECENT_BATCH_LIMIT
        } else {
            true
        }
    });
    success(batches)
}

pub async fn interrupt_incomplete_batches(state: &AppState) {
    let rows = match state.db.scan_prefix(BATCH_PREFIX).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!("recover batch upgrade state: {error}");
            return;
        }
    };
    for (_, raw) in rows {
        let Ok(mut batch) = serde_json::from_str::<BatchUpgradeOperation>(&raw) else {
            continue;
        };
        if batch.status.terminal() {
            continue;
        }
        for item in &mut batch.items {
            if item.status == BatchUpgradeItemStatus::Running {
                item.status = BatchUpgradeItemStatus::Interrupted;
                item.reason = Some("PANEL_RESTARTED_DURING_CHILD_OPERATION".into());
                item.finished_at = Some(now());
            }
        }
        batch.status = BatchUpgradeStatus::Interrupted;
        batch.current_item = None;
        batch.updated_at = now();
        refresh_counts(&mut batch);
        if let Err(error) = persist(state, &batch).await {
            tracing::error!(batch_id = batch.id, "interrupt batch upgrade: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::node_ops::NodeOperationRegistry;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use relay_shared::protocol::{
        NodeLifecycleCommand, NodeLifecycleEvent, NodeLifecycleEventStatus,
    };
    use sha2::{Digest, Sha256};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    fn candidate(group_id: i64, node_id: &str, version: &str, architecture: &str) -> Candidate {
        Candidate {
            group_id,
            node_id: node_id.into(),
            current_version: Some(version.into()),
            architecture: Some(architecture.into()),
            online: true,
            operation_active: false,
            uninstall_active: false,
        }
    }

    fn artifacts() -> HashMap<String, Result<String, String>> {
        HashMap::from([
            ("amd64".into(), Ok("1.1.12".into())),
            ("arm64".into(), Err("missing".into())),
        ])
    }

    async fn test_state() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        AppState {
            db: Arc::new(SqliteRepository::new(pool)),
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
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        }
    }

    fn write_artifact(root: &std::path::Path) {
        let directory = root.join("amd64");
        std::fs::create_dir_all(&directory).unwrap();
        let mut bytes = vec![0_u8; 64 * 1024];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        std::fs::write(directory.join("relay-node"), &bytes).unwrap();
        std::fs::write(
            directory.join("metadata.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": "1.1.12",
                "sha256": sha256,
                "size": bytes.len()
            }))
            .unwrap(),
        )
        .unwrap();
    }

    async fn wait_command(
        receiver: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> NodeLifecycleCommand {
        let payload = tokio::time::timeout(std::time::Duration::from_secs(3), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&payload).unwrap()
    }

    fn event(
        command: &NodeLifecycleCommand,
        status: NodeLifecycleEventStatus,
    ) -> NodeLifecycleEvent {
        NodeLifecycleEvent {
            msg_type: "node_lifecycle_event".into(),
            operation_id: command.operation_id.clone(),
            node_id: command.node_id.clone(),
            action: NodeLifecycleAction::Upgrade,
            status,
            message: "test result".into(),
            node_version: Some("1.1.12".into()),
            architecture: Some("x86_64".into()),
            logs: None,
        }
    }

    #[test]
    fn preview_classifies_every_eligibility_reason() {
        assert_eq!(
            classify_candidate(candidate(1, "old", "1.1.11", "x86_64"), &artifacts()).status,
            BatchUpgradeItemStatus::Pending
        );
        assert_eq!(
            classify_candidate(candidate(1, "latest", "1.1.12", "amd64"), &artifacts()).status,
            BatchUpgradeItemStatus::SkippedAlreadyCurrent
        );
        let mut offline = candidate(1, "offline", "1.1.11", "amd64");
        offline.online = false;
        assert_eq!(
            classify_candidate(offline, &artifacts()).status,
            BatchUpgradeItemStatus::SkippedOffline
        );
        assert_eq!(
            classify_candidate(candidate(1, "bad-arch", "1.1.11", "mips"), &artifacts()).status,
            BatchUpgradeItemStatus::SkippedUnsupportedArch
        );
        assert_eq!(
            classify_candidate(candidate(1, "no-artifact", "1.1.11", "arm64"), &artifacts()).status,
            BatchUpgradeItemStatus::SkippedArtifactUnavailable
        );
        let mut active = candidate(1, "active", "1.1.11", "amd64");
        active.operation_active = true;
        assert_eq!(
            classify_candidate(active, &artifacts()).status,
            BatchUpgradeItemStatus::SkippedOperationInProgress
        );
        let mut uninstall = candidate(1, "uninstall", "1.1.11", "amd64");
        uninstall.operation_active = true;
        uninstall.uninstall_active = true;
        assert_eq!(
            classify_candidate(uninstall, &artifacts()).status,
            BatchUpgradeItemStatus::SkippedUninstallInProgress
        );
    }

    #[test]
    fn batch_final_status_distinguishes_success_partial_and_failed() {
        let item = |status| BatchUpgradeItem {
            group_id: 1,
            node_id: uuid::Uuid::new_v4().to_string(),
            current_version: None,
            target_version: None,
            architecture: None,
            status,
            reason: None,
            child_operation_id: None,
            started_at: None,
            finished_at: None,
        };
        let batch = |items| {
            let mut batch = BatchUpgradeOperation {
                id: "batch".into(),
                status: BatchUpgradeStatus::Running,
                target_version: None,
                created_at: now(),
                updated_at: now(),
                created_by: 1,
                total: 0,
                pending: 0,
                running: 0,
                success: 0,
                failed: 0,
                skipped: 0,
                current_item: None,
                items,
            };
            refresh_counts(&mut batch);
            batch
        };
        assert_eq!(
            final_status(&batch(vec![item(BatchUpgradeItemStatus::Success)])),
            BatchUpgradeStatus::Success
        );
        assert_eq!(
            final_status(&batch(vec![
                item(BatchUpgradeItemStatus::Success),
                item(BatchUpgradeItemStatus::Failed)
            ])),
            BatchUpgradeStatus::PartialSuccess
        );
        assert_eq!(
            final_status(&batch(vec![item(BatchUpgradeItemStatus::Failed)])),
            BatchUpgradeStatus::Failed
        );
        assert_eq!(
            final_status(&batch(vec![item(BatchUpgradeItemStatus::SkippedOffline)])),
            BatchUpgradeStatus::Success
        );
    }

    #[test]
    fn candidate_identity_is_group_and_node() {
        assert_eq!(
            parse_node_status_key("node_status:1:same"),
            Some((1, "same".into()))
        );
        assert_eq!(
            parse_node_status_key("node_status:2:same"),
            Some((2, "same".into()))
        );
        assert_eq!(parse_node_status_key("node_status:1"), None);
    }

    #[tokio::test]
    async fn worker_runs_one_real_upgrade_at_a_time_and_continues_after_failure_and_timeout() {
        let _guard = BATCH_CREATE_LOCK.lock().await;
        let root = std::env::temp_dir().join(format!("batch-artifacts-{}", uuid::Uuid::new_v4()));
        write_artifact(&root);
        std::env::set_var(crate::api::provisioning::NODE_ARTIFACT_ROOT_ENV, &root);
        let state = test_state().await;
        let mut receivers = Vec::new();
        for node_id in ["node-a", "node-b", "node-c"] {
            state
                .db
                .set(
                    &format!("node_status:1:{node_id}"),
                    &serde_json::json!({
                        "node_version": "1.1.11",
                        "architecture": "x86_64",
                        "config_protocol_version": relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                    })
                    .to_string(),
                )
                .await
                .unwrap();
            let (_, receiver) = state
                .node_connections
                .register(1, Some(node_id.into()))
                .await;
            receivers.push(receiver);
        }
        let items = preview_items(&state).await.unwrap();
        assert!(items
            .iter()
            .all(|item| item.status == BatchUpgradeItemStatus::Pending));
        let timestamp = now();
        let mut batch = BatchUpgradeOperation {
            id: "batch-serial".into(),
            status: BatchUpgradeStatus::Pending,
            target_version: Some("1.1.12".into()),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            created_by: 1,
            total: 0,
            pending: 0,
            running: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            current_item: None,
            items,
        };
        refresh_counts(&mut batch);
        persist(&state, &batch).await.unwrap();
        let worker = tokio::spawn(run_batch(state.clone(), batch));

        let first = wait_command(&mut receivers[0]).await;
        assert!(receivers[1].try_recv().is_err());
        let persisted = load(&state, "batch-serial").await.unwrap().unwrap();
        assert_eq!(persisted.running, 1);
        assert_eq!(
            persisted.items[0].child_operation_id.as_deref(),
            Some(first.operation_id.as_str())
        );
        state
            .node_operations
            .event(1, event(&first, NodeLifecycleEventStatus::Completed));

        let second = wait_command(&mut receivers[1]).await;
        assert!(receivers[2].try_recv().is_err());
        state
            .node_operations
            .event(1, event(&second, NodeLifecycleEventStatus::Failed));

        let third = wait_command(&mut receivers[2]).await;
        state
            .node_operations
            .set_status_for_test(&third.operation_id, OperationStatus::Timeout);
        tokio::time::timeout(std::time::Duration::from_secs(4), worker)
            .await
            .unwrap()
            .unwrap();

        let completed = load(&state, "batch-serial").await.unwrap().unwrap();
        assert_eq!(completed.status, BatchUpgradeStatus::PartialSuccess);
        assert_eq!(completed.success, 1);
        assert_eq!(completed.failed, 2);
        assert_eq!(completed.running, 0);
        assert!(completed
            .items
            .iter()
            .all(|item| item.finished_at.is_some()));
        std::env::remove_var(crate::api::provisioning::NODE_ARTIFACT_ROOT_ENV);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn startup_marks_nonterminal_batch_interrupted_without_restarting_items() {
        let state = test_state().await;
        let timestamp = now();
        let mut batch = BatchUpgradeOperation {
            id: "batch-restart".into(),
            status: BatchUpgradeStatus::Running,
            target_version: Some("1.1.12".into()),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            created_by: 1,
            total: 0,
            pending: 0,
            running: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            current_item: Some("node-a".into()),
            items: vec![BatchUpgradeItem {
                group_id: 1,
                node_id: "node-a".into(),
                current_version: Some("1.1.11".into()),
                target_version: Some("1.1.12".into()),
                architecture: Some("amd64".into()),
                status: BatchUpgradeItemStatus::Running,
                reason: None,
                child_operation_id: Some("unknown-after-restart".into()),
                started_at: Some(now()),
                finished_at: None,
            }],
        };
        refresh_counts(&mut batch);
        persist(&state, &batch).await.unwrap();
        interrupt_incomplete_batches(&state).await;

        let interrupted = load(&state, "batch-restart").await.unwrap().unwrap();
        assert_eq!(interrupted.status, BatchUpgradeStatus::Interrupted);
        assert_eq!(
            interrupted.items[0].status,
            BatchUpgradeItemStatus::Interrupted
        );
        assert_eq!(
            interrupted.items[0].child_operation_id.as_deref(),
            Some("unknown-after-restart")
        );
        assert!(state.node_operations.active_and_recent().is_empty());
    }

    #[tokio::test]
    async fn second_active_batch_returns_conflict() {
        let state = test_state().await;
        let timestamp = now();
        let batch = BatchUpgradeOperation {
            id: "already-running".into(),
            status: BatchUpgradeStatus::Running,
            target_version: Some("1.1.12".into()),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            created_by: 1,
            total: 0,
            pending: 0,
            running: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            current_item: None,
            items: vec![],
        };
        persist(&state, &batch).await.unwrap();
        let response = start(AdminOnly { user_id: 1 }, State(state)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn request_return_does_not_own_worker_and_all_skipped_batch_finishes() {
        let state = test_state().await;
        let response = start(AdminOnly { user_id: 1 }, State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let batch_id = state
            .db
            .scan_prefix(BATCH_PREFIX)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .0
            .trim_start_matches(BATCH_PREFIX)
            .to_string();
        let completed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let batch = load(&state, &batch_id).await.unwrap().unwrap();
                if batch.status.terminal() {
                    break batch;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(completed.status, BatchUpgradeStatus::Success);
        assert_eq!(completed.total, 0);
        assert_eq!(completed.pending, 0);
    }
}
