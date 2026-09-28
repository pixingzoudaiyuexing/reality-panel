use crate::api::node_ops;
use crate::api::ws::{BootstrapError, UniqueConnectionError};
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::Repository;
use relay_shared::protocol::{NodeLifecycleAction, NodeLifecycleEvent, NodeLifecycleEventStatus};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "node_convergence:";
const CONVERGENCE_TIMEOUT_SECS: i64 = 900;
static START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    PreparingNode,
    Upgrading,
    Restarting,
    MigratingIdentity,
    Verifying,
    Complete,
    Failed,
}

impl Phase {
    fn terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Convergence {
    pub id: String,
    pub group_id: i64,
    pub node_id: String,
    pub phase: Phase,
    pub current_version: String,
    pub target_version: String,
    pub architecture: String,
    pub created_at: String,
    pub updated_at: String,
    pub started_by: i64,
    pub error: Option<String>,
}

impl Convergence {
    pub fn operation_view(&self) -> serde_json::Value {
        let status = match self.phase {
            Phase::PreparingNode => "PENDING",
            Phase::Upgrading => "INSTALLING",
            Phase::Restarting => "RESTARTING",
            Phase::MigratingIdentity | Phase::Verifying => "VERIFYING",
            Phase::Complete => "SUCCESS",
            Phase::Failed => "FAILED",
        };
        let message = match self.phase {
            Phase::PreparingNode => "准备节点",
            Phase::Upgrading => "升级中",
            Phase::Restarting => "重启中",
            Phase::MigratingIdentity => "正在迁移节点身份",
            Phase::Verifying => "正在验证",
            Phase::Complete => "已完成",
            Phase::Failed => "节点升级未完成",
        };
        serde_json::json!({
            "id": self.id, "group_id": self.group_id, "node_id": self.node_id,
            "action": "upgrade", "status": status, "message": message,
            "convergence_phase": self.phase,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "current_version": self.current_version, "target_version": self.target_version,
            "architecture": self.architecture, "error": self.error,
        })
    }
}

#[derive(Debug)]
pub enum ConvergenceError {
    Db(DbError),
    Missing,
    AlreadyReady,
    InProgress,
    Offline,
    Ambiguous,
    Unsupported,
    Unavailable,
    ArtifactNotNewer,
}

impl From<DbError> for ConvergenceError {
    fn from(value: DbError) -> Self {
        Self::Db(value)
    }
}

fn key(group_id: i64, node_id: &str) -> String {
    format!("{PREFIX}{group_id}:{node_id}")
}

fn target_version_for<F>(
    current_version: &str,
    panel_version: &str,
    automatic_migration_supported: bool,
    load_artifact: F,
) -> Result<(String, bool), ConvergenceError>
where
    F: FnOnce() -> Result<String, ConvergenceError>,
{
    let current =
        semver::Version::parse(current_version).map_err(|_| ConvergenceError::Unsupported)?;
    let panel = semver::Version::parse(panel_version).map_err(|_| ConvergenceError::Unavailable)?;
    if current >= panel && automatic_migration_supported {
        return Ok((current_version.into(), false));
    }
    let target_version = load_artifact()?;
    let target =
        semver::Version::parse(&target_version).map_err(|_| ConvergenceError::Unavailable)?;
    if target <= current {
        return Err(ConvergenceError::ArtifactNotNewer);
    }
    Ok((target_version, true))
}

pub async fn load(
    db: &dyn Repository,
    group_id: i64,
    node_id: &str,
) -> Result<Option<Convergence>, DbError> {
    db.get(&key(group_id, node_id))
        .await?
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|_| {
                DbError::Other(sqlx::Error::Protocol("invalid convergence state".into()))
            })
        })
        .transpose()
}

async fn store(db: &dyn Repository, record: &Convergence) -> Result<(), DbError> {
    db.set(
        &key(record.group_id, &record.node_id),
        &serde_json::to_string(record).expect("convergence state serializes"),
    )
    .await
}

async fn expire_incomplete(state: &AppState) -> Result<(), DbError> {
    let _guard = START_LOCK.lock().await;
    let now = chrono::Utc::now();
    for (stored_key, raw) in state.db.scan_prefix(PREFIX).await? {
        let mut record: Convergence = serde_json::from_str(&raw).map_err(|_| {
            DbError::Other(sqlx::Error::Protocol("invalid convergence state".into()))
        })?;
        if stored_key != key(record.group_id, &record.node_id) {
            return Err(DbError::Other(sqlx::Error::Protocol(
                "convergence identity mismatch".into(),
            )));
        }
        if record.phase.terminal() {
            continue;
        }
        let created = chrono::DateTime::parse_from_rfc3339(&record.created_at).map_err(|_| {
            DbError::Other(sqlx::Error::Protocol(
                "invalid convergence timestamp".into(),
            ))
        })?;
        if (now - created.with_timezone(&chrono::Utc)).num_seconds() < CONVERGENCE_TIMEOUT_SECS {
            continue;
        }
        record.phase = Phase::Failed;
        record.error = Some("NODE_CONVERGENCE_TIMEOUT".into());
        record.updated_at = now.to_rfc3339();
        store(state.db.as_ref(), &record).await?;
        let node =
            crate::node_identity::ReuseEligibleNodeId::parse(&record.node_id).map_err(|_| {
                DbError::Other(sqlx::Error::Protocol(
                    "invalid convergence node identity".into(),
                ))
            })?;
        state
            .db
            .expire_node_credential_claim(&record.id, record.group_id, &node, now)
            .await?;
    }
    Ok(())
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = expire_incomplete(&state).await {
                tracing::warn!("identity convergence expiry unavailable: {error}");
            }
        }
    });
}

pub async fn start(
    state: &AppState,
    admin_id: i64,
    group_id: i64,
    node_id: &str,
) -> Result<Convergence, ConvergenceError> {
    let _guard = START_LOCK.lock().await;
    if let Some(previous) = load(state.db.as_ref(), group_id, node_id).await? {
        if !previous.phase.terminal() {
            return Err(ConvergenceError::InProgress);
        }
    }
    let retirement_guard = crate::service::node_retirement::RETIREMENT_GATE
        .lock()
        .await;
    let node = crate::service::node_pool::list_nodes(state.db.as_ref())
        .await?
        .into_iter()
        .find(|node| node.identity_group_id == group_id && node.node_id == node_id)
        .ok_or(ConvergenceError::Missing)?;
    if node.safe_to_add || node.credential_active {
        return Err(ConvergenceError::AlreadyReady);
    }
    if node.migration_pending || state.node_operations.has_active_for_node(group_id, node_id) {
        return Err(ConvergenceError::InProgress);
    }
    if crate::api::provisioning::effective_public_panel_url(state)
        .await
        .is_none_or(|url| !url.starts_with("https://"))
    {
        return Err(ConvergenceError::Unavailable);
    }
    let selected = state
        .node_connections
        .unique_lifecycle_connection(group_id, node_id, true)
        .await;
    match selected {
        Err(UniqueConnectionError::Offline) => return Err(ConvergenceError::Offline),
        Err(UniqueConnectionError::Ambiguous) => return Err(ConvergenceError::Ambiguous),
        Ok(_) => {}
    }
    let raw = state
        .db
        .get(&format!("node_status:{group_id}:{node_id}"))
        .await?
        .ok_or(ConvergenceError::Unsupported)?;
    let status: serde_json::Value =
        serde_json::from_str(&raw).map_err(|_| ConvergenceError::Unsupported)?;
    let current_version = status
        .get("node_version")
        .and_then(|value| value.as_str())
        .ok_or(ConvergenceError::Unsupported)?
        .to_string();
    let architecture = status
        .get("architecture")
        .and_then(|value| value.as_str())
        .ok_or(ConvergenceError::Unsupported)?
        .to_string();
    let artifact_arch = relay_shared::protocol::lifecycle_artifact_architecture(&architecture)
        .ok_or(ConvergenceError::Unsupported)?;
    let (target_version, binary_upgrade) = target_version_for(
        &current_version,
        env!("CARGO_PKG_VERSION"),
        node.automatic_migration_supported,
        || {
            node_ops::validated_artifact_version(artifact_arch)
                .map_err(|_| ConvergenceError::Unavailable)
        },
    )?;
    if !binary_upgrade && !node.auth_reload_supported {
        return Err(ConvergenceError::Unsupported);
    }
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut record = Convergence {
        id: uuid::Uuid::new_v4().to_string(),
        group_id,
        node_id: node_id.into(),
        phase: if binary_upgrade {
            Phase::Upgrading
        } else {
            Phase::PreparingNode
        },
        current_version,
        target_version,
        architecture,
        created_at: timestamp.clone(),
        updated_at: timestamp,
        started_by: admin_id,
        error: None,
    };
    store(state.db.as_ref(), &record).await?;
    if binary_upgrade {
        drop(retirement_guard);
        if node_ops::create_operation_with_id(
            state,
            admin_id,
            group_id,
            node_id.into(),
            NodeLifecycleAction::Upgrade,
            None,
            Some(record.id.clone()),
        )
        .await
        .is_err()
        {
            record.phase = Phase::Failed;
            record.error = Some("binary upgrade could not start".into());
            record.updated_at = chrono::Utc::now().to_rfc3339();
            store(state.db.as_ref(), &record).await?;
            return Err(ConvergenceError::Unavailable);
        }
    } else {
        match state
            .node_connections
            .begin_bootstrap_with_id(group_id, node_id, admin_id, &record.id)
            .await
        {
            Ok(()) => {
                record.phase = Phase::MigratingIdentity;
                record.updated_at = chrono::Utc::now().to_rfc3339();
                store(state.db.as_ref(), &record).await?;
            }
            Err(error) => {
                record.phase = Phase::Failed;
                record.error = Some(format!("bootstrap unavailable: {error:?}"));
                record.updated_at = chrono::Utc::now().to_rfc3339();
                store(state.db.as_ref(), &record).await?;
                return Err(map_bootstrap_error(error));
            }
        }
        drop(retirement_guard);
    }
    Ok(record)
}

fn map_bootstrap_error(error: BootstrapError) -> ConvergenceError {
    match error {
        BootstrapError::Offline => ConvergenceError::Offline,
        BootstrapError::Ambiguous => ConvergenceError::Ambiguous,
        BootstrapError::Pending => ConvergenceError::InProgress,
        BootstrapError::Unavailable => ConvergenceError::Unavailable,
    }
}

pub async fn after_boot_event(
    state: &AppState,
    group_id: i64,
    event: &NodeLifecycleEvent,
    verified: bool,
) -> Result<bool, DbError> {
    let _guard = START_LOCK.lock().await;
    if verified
        || event.action != NodeLifecycleAction::Upgrade
        || event.status != NodeLifecycleEventStatus::Completed
    {
        return Ok(false);
    }
    let Some(mut record) = load(state.db.as_ref(), group_id, &event.node_id).await? else {
        return Ok(false);
    };
    if record.id != event.operation_id
        || record.phase != Phase::Upgrading
        || event.node_version.as_deref() != Some(record.target_version.as_str())
    {
        return Ok(false);
    }
    let _retirement_guard = crate::service::node_retirement::RETIREMENT_GATE
        .lock()
        .await;
    if state
        .db
        .find_node_pool_record(group_id, &event.node_id)
        .await?
        .is_none_or(|node| node.retirement_state != "ACTIVE")
    {
        return Ok(false);
    }
    match state
        .node_connections
        .begin_bootstrap_with_id(
            record.group_id,
            &record.node_id,
            record.started_by,
            &record.id,
        )
        .await
    {
        Ok(()) => {
            record.phase = Phase::MigratingIdentity;
            record.updated_at = chrono::Utc::now().to_rfc3339();
            store(state.db.as_ref(), &record).await?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

pub async fn mark_upgrade_failed(
    state: &AppState,
    group_id: i64,
    node_id: &str,
    operation_id: &str,
    message: &str,
) -> Result<(), DbError> {
    let _guard = START_LOCK.lock().await;
    let Some(mut record) = load(state.db.as_ref(), group_id, node_id).await? else {
        return Ok(());
    };
    if record.id == operation_id && record.phase == Phase::Upgrading {
        record.phase = Phase::Failed;
        record.error = Some(message.into());
        record.updated_at = chrono::Utc::now().to_rfc3339();
        store(state.db.as_ref(), &record).await?;
    }
    Ok(())
}

pub async fn mark_complete(
    state: &AppState,
    group_id: i64,
    node_id: &str,
    claim_id: &str,
) -> Result<(), DbError> {
    let _guard = START_LOCK.lock().await;
    let Some(mut record) = load(state.db.as_ref(), group_id, node_id).await? else {
        return Ok(());
    };
    if record.id != claim_id || record.phase == Phase::Complete {
        return Ok(());
    }
    record.phase = Phase::Complete;
    record.updated_at = chrono::Utc::now().to_rfc3339();
    store(state.db.as_ref(), &record).await
}

pub async fn mark_verifying(
    db: &dyn Repository,
    group_id: i64,
    node_id: &str,
    claim_id: &str,
) -> Result<(), DbError> {
    let _guard = START_LOCK.lock().await;
    let Some(mut record) = load(db, group_id, node_id).await? else {
        return Ok(());
    };
    if record.id == claim_id && record.phase == Phase::MigratingIdentity {
        record.phase = Phase::Verifying;
        record.updated_at = chrono::Utc::now().to_rfc3339();
        store(db, &record).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        diagnose::DiagnoseRegistry, node_deploy::DeploymentRegistry,
        node_ops::NodeOperationRegistry, system::ReleaseCache, ws::NodeConnections,
    };
    use crate::config::Config;
    use crate::db::repo::{KvsRepository, NodePoolRepository};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    #[test]
    fn current_legacy_skips_binary_artifact_and_old_legacy_requires_it() {
        let current = target_version_for("1.3.0", "1.3.0", true, || {
            panic!("artifact must not be read")
        })
        .unwrap();
        assert_eq!(current, ("1.3.0".into(), false));
        let old = target_version_for("1.1.26", "1.3.0", false, || Ok("1.3.0".into())).unwrap();
        assert_eq!(old, ("1.3.0".into(), true));
        assert!(target_version_for("1.1.26", "1.3.0", false, || Err(
            ConvergenceError::Unavailable
        ))
        .is_err());
        assert!(matches!(
            target_version_for("1.3.0", "1.3.0", false, || Ok("1.3.0".into())),
            Err(ConvergenceError::ArtifactNotNewer)
        ));
        assert_eq!(
            target_version_for("1.3.0", "1.4.0", false, || Ok("1.4.0".into())).unwrap(),
            ("1.4.0".into(), true)
        );
    }

    async fn fixture_state() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_groups (id,name,group_type,token,uid) VALUES (10,'home','in','legacy-token',1)")
            .execute(&pool).await.unwrap();
        let db = Arc::new(SqliteRepository::new(pool));
        db.register_node_pool_identity(10, "Node_A").await.unwrap();
        db.set(
            "node_status:10:Node_A",
            &serde_json::json!({
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "node_version": env!("CARGO_PKG_VERSION"), "architecture": "x86_64",
                "auth_reload_supported": true,
                "automatic_migration_supported": true,
            })
            .to_string(),
        )
        .await
        .unwrap();
        AppState {
            db,
            config: Config {
                database_path: "test".into(),
                listen: "127.0.0.1:0".into(),
                key: "key".into(),
                jwt_secret: "secret".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
                node_reuse_runtime_enabled: true,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: NodeOperationRegistry::new(),
            deployments: DeploymentRegistry::default(),
            diagnose: DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(Default::default())),
        }
    }

    #[tokio::test]
    async fn convergence_requires_unique_live_connection_and_excludes_retired_node() {
        let state = fixture_state().await;
        assert!(matches!(
            start(&state, 1, 10, "Node_A").await,
            Err(ConvergenceError::Offline)
        ));
        let (first, mut rx) = state
            .node_connections
            .register(10, Some("Node_A".into()))
            .await;
        let (second, _other_rx) = state
            .node_connections
            .register(10, Some("Node_A".into()))
            .await;
        assert!(matches!(
            start(&state, 1, 10, "Node_A").await,
            Err(ConvergenceError::Ambiguous)
        ));
        state.node_connections.unregister(10, second).await;
        let operation = start(&state, 1, 10, "Node_A").await.unwrap();
        assert_eq!(operation.phase, Phase::MigratingIdentity);
        let message: relay_shared::protocol::NodeMigrationBootstrap =
            serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(message.operation_id, operation.id);
        assert_eq!(
            load(state.db.as_ref(), 10, "Node_A")
                .await
                .unwrap()
                .unwrap()
                .id,
            operation.id
        );
        state.node_connections.unregister(10, first).await;

        let other = fixture_state().await;
        other
            .db
            .retire_node_pool_identity(10, "Node_A", 0, 1, "retired")
            .await
            .unwrap();
        let (_conn, _rx) = other
            .node_connections
            .register(10, Some("Node_A".into()))
            .await;
        assert!(matches!(
            start(&other, 1, 10, "Node_A").await,
            Err(ConvergenceError::Missing)
        ));
    }

    #[tokio::test]
    async fn convergence_completion_is_monotonic_and_timeout_preserves_runtime_authority() {
        let state = fixture_state().await;
        let (_connection, _receiver) = state
            .node_connections
            .register(10, Some("Node_A".into()))
            .await;
        let mut operation = start(&state, 1, 10, "Node_A").await.unwrap();
        mark_complete(&state, 10, "Node_A", &operation.id)
            .await
            .unwrap();
        mark_verifying(state.db.as_ref(), 10, "Node_A", &operation.id)
            .await
            .unwrap();
        assert_eq!(
            load(state.db.as_ref(), 10, "Node_A")
                .await
                .unwrap()
                .unwrap()
                .phase,
            Phase::Complete
        );
        operation.phase = Phase::MigratingIdentity;
        operation.created_at = (chrono::Utc::now()
            - chrono::Duration::seconds(CONVERGENCE_TIMEOUT_SECS + 1))
        .to_rfc3339();
        store(state.db.as_ref(), &operation).await.unwrap();
        let status_before = state.db.get("node_status:10:Node_A").await.unwrap();
        expire_incomplete(&state).await.unwrap();
        let expired = load(state.db.as_ref(), 10, "Node_A")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.phase, Phase::Failed);
        assert_eq!(expired.error.as_deref(), Some("NODE_CONVERGENCE_TIMEOUT"));
        assert_eq!(
            state.db.get("node_status:10:Node_A").await.unwrap(),
            status_before
        );
        assert!(state
            .db
            .get("node_pool_migration_completion:10:Node_A")
            .await
            .unwrap()
            .is_none());
    }
}
