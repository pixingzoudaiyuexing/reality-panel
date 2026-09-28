use crate::api::node_auth::{
    authenticate_node, verified_credential_still_active, VerifiedConcreteNode,
};
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::{NewNodeCredentialClaim, NodeCredentialClaimCreateResult, Repository};
use crate::node_claim::{NodeClaimSecret, NodeClaimSecretVerifier};
use crate::node_identity::ReuseEligibleNodeId;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use relay_shared::control_protocol::{
    legacy_node_supports_lifecycle, lifecycle_protocol_versions_compatible,
    LIFECYCLE_PROTOCOL_VERSION,
};
use relay_shared::protocol::NodeConfigSnapshot;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// One live connection's sender + its optional per-node identity (v0.4.14
/// X-Node-ID). `node_id` is None for an older node that didn't send the header;
/// such a connection still receives config_changed broadcasts but cannot be
/// targeted by directed diagnosis.
struct ConnEntry {
    tx: mpsc::UnboundedSender<String>,
    node_id: Option<String>,
    /// false = upgrade-only: never receive config snapshots/config_changed or
    /// ordinary control commands from a newer Panel.
    config_compatible: bool,
    /// Independent lifecycle capability. An upgrade-only connection must have
    /// this true or it is rejected during the WS handshake.
    lifecycle_capable: bool,
}
/// Per-group map of live connection senders.
type GroupConns = HashMap<u64, ConnEntry>;
/// Shared registry: group_id -> that group's live connections.
type ConnMap = Arc<RwLock<HashMap<i64, GroupConns>>>;
type ControlObservation = (Option<String>, Option<String>);
type ControlObservations = Arc<RwLock<HashMap<(i64, String), ControlObservation>>>;

#[derive(Clone, Default)]
pub(crate) struct ControlSnapshot {
    pub connected: HashSet<(i64, String)>,
    pub lifecycle_connected: HashSet<(i64, String)>,
    pub observations: HashMap<(i64, String), ControlObservation>,
}

impl ControlSnapshot {
    pub fn online_node_ids(&self, group_id: i64) -> HashSet<String> {
        self.connected
            .iter()
            .filter(|(identity_group_id, _)| *identity_group_id == group_id)
            .map(|(_, node_id)| node_id.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniqueConnectionError {
    Offline,
    Ambiguous,
}

struct PendingBootstrap {
    operation_id: String,
    claim_id: String,
    group_id: i64,
    node_id: String,
    connection_id: u64,
    approved_by: i64,
    secret: NodeClaimSecret,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    Offline,
    Ambiguous,
    Pending,
    Unavailable,
}

/// Tracks live WebSocket connections per group_id so the panel can push
/// `config_changed` notifications when an admin mutates rules or groups.
///
/// Each connection registers an mpsc sender; on disconnect it unregisters.
/// `broadcast` fans a message out to every live connection (we broadcast to
/// ALL groups on any admin mutation — correct and simple for small fleets).
#[derive(Clone, Default)]
pub struct NodeConnections {
    next_id: Arc<AtomicU64>,
    inner: ConnMap,
    observations: ControlObservations,
    bootstraps: Arc<RwLock<HashMap<String, PendingBootstrap>>>,
}

impl NodeConnections {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new connection. Returns (conn_id, receiver) — the caller
    /// owns the receiver and forwards anything it receives to the socket.
    /// `node_id` is the v0.4.14 X-Node-ID (None for older nodes).
    #[cfg(test)]
    pub async fn register(
        &self,
        group_id: i64,
        node_id: Option<String>,
    ) -> (u64, mpsc::UnboundedReceiver<String>) {
        self.register_with_capabilities(group_id, node_id, true, true)
            .await
    }

    pub(crate) async fn register_with_capabilities(
        &self,
        group_id: i64,
        node_id: Option<String>,
        config_compatible: bool,
        lifecycle_capable: bool,
    ) -> (u64, mpsc::UnboundedReceiver<String>) {
        let conn_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut map = self.inner.write().await;
        if let Some(id) = &node_id {
            let mut observations = self.observations.write().await;
            if observations.len() >= 10_000 && !observations.contains_key(&(group_id, id.clone())) {
                if let Some(oldest) = observations.keys().next().cloned() {
                    observations.remove(&oldest);
                }
            }
            observations.entry((group_id, id.clone())).or_default().0 =
                Some(chrono::Utc::now().to_rfc3339());
        }
        map.entry(group_id).or_default().insert(
            conn_id,
            ConnEntry {
                tx,
                node_id,
                config_compatible,
                lifecycle_capable,
            },
        );
        (conn_id, rx)
    }

    pub(crate) async fn capture(&self) -> ControlSnapshot {
        let map = self.inner.read().await;
        let observations = self.observations.read().await.clone();
        let mut snapshot = ControlSnapshot {
            observations,
            ..Default::default()
        };
        for (group_id, connections) in map.iter() {
            for entry in connections.values().filter(|entry| !entry.tx.is_closed()) {
                if let Some(node_id) = &entry.node_id {
                    let identity = (*group_id, node_id.clone());
                    snapshot.connected.insert(identity.clone());
                    if entry.lifecycle_capable {
                        snapshot.lifecycle_connected.insert(identity);
                    }
                }
            }
        }
        snapshot
    }

    /// Remove a connection. Called when the socket task exits.
    pub async fn unregister(&self, group_id: i64, conn_id: u64) {
        let mut map = self.inner.write().await;
        if let Some(conns) = map.get_mut(&group_id) {
            let removed = conns.remove(&conn_id).and_then(|entry| entry.node_id);
            if let Some(id) = removed {
                if !conns
                    .values()
                    .any(|entry| entry.node_id.as_deref() == Some(&id))
                {
                    if let Some(observation) =
                        self.observations.write().await.get_mut(&(group_id, id))
                    {
                        observation.1 = Some(chrono::Utc::now().to_rfc3339());
                    }
                }
            }
            if conns.is_empty() {
                map.remove(&group_id);
            }
        }
        self.bootstraps
            .write()
            .await
            .retain(|_, pending| pending.group_id != group_id || pending.connection_id != conn_id);
    }

    /// Fan a message out to every live connection across every group.
    /// Dead senders (receiver dropped) are pruned opportunistically.
    pub async fn broadcast_all(&self, msg: &str) {
        let mut map = self.inner.write().await;
        for conns in map.values_mut() {
            conns.retain(|_, e| {
                // Upgrade-only nodes intentionally keep their LKG and must not
                // even be told that a newer config exists. Dead upgrade-only
                // senders are still pruned so the registry cannot accumulate.
                if !e.config_compatible {
                    return !e.tx.is_closed();
                }
                e.tx.send(msg.to_string()).is_ok()
            });
        }
    }

    /// Send a message to every live connection in ONE group only (not all
    /// groups like broadcast_all). Returns the number of connections the message
    /// was handed to (dead senders pruned). Does NOT close the connections.
    ///
    /// v0.4.14: directed diagnosis now uses `send_node` instead; this group-wide
    /// send is retained as general infrastructure (no current caller).
    #[allow(dead_code)]
    pub async fn send_group(&self, group_id: i64, msg: &str) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.get_mut(&group_id) else {
            return 0;
        };
        let mut sent = 0usize;
        conns.retain(|_, e| {
            // 即使未来重新启用 group-wide 控制，也绝不能绕过 upgrade-only
            // 隔离边界。协议不兼容节点只允许收到 Upgrade。
            if !e.config_compatible {
                return !e.tx.is_closed();
            }
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    /// v0.4.14: send a message ONLY to the connection(s) in a group whose
    /// X-Node-ID matches `node_id`. Used by directed diagnosis to target a
    /// specific node instead of the whole group. Returns how many connections
    /// received it (0 = that node has no live WS connection right now). Dead
    /// senders are pruned.
    pub async fn send_node(&self, group_id: i64, node_id: &str, msg: &str) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.get_mut(&group_id) else {
            return 0;
        };
        let mut sent = 0usize;
        conns.retain(|_, e| {
            if e.node_id.as_deref() != Some(node_id) || !e.config_compatible {
                return true; // not target or upgrade-only — leave untouched
            }
            if e.tx.send(msg.to_string()).is_ok() {
                sent += 1;
                true
            } else {
                false // target but dead — prune
            }
        });
        if conns.is_empty() {
            map.remove(&group_id);
        }
        sent
    }

    pub async fn unique_lifecycle_connection(
        &self,
        group_id: i64,
        node_id: &str,
        upgrade: bool,
    ) -> Result<u64, UniqueConnectionError> {
        let map = self.inner.read().await;
        let matches = map
            .get(&group_id)
            .into_iter()
            .flat_map(|conns| conns.iter())
            .filter(|(_, entry)| {
                entry.node_id.as_deref() == Some(node_id)
                    && !entry.tx.is_closed()
                    && if upgrade {
                        entry.lifecycle_capable
                    } else {
                        entry.config_compatible
                    }
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(UniqueConnectionError::Offline),
            [id] => Ok(*id),
            _ => Err(UniqueConnectionError::Ambiguous),
        }
    }

    pub async fn send_exact_connection(
        &self,
        group_id: i64,
        node_id: &str,
        connection_id: u64,
        msg: &str,
    ) -> bool {
        self.inner
            .read()
            .await
            .get(&group_id)
            .and_then(|conns| conns.get(&connection_id))
            .is_some_and(|entry| {
                entry.node_id.as_deref() == Some(node_id) && entry.tx.send(msg.to_string()).is_ok()
            })
    }

    #[cfg(test)]
    pub async fn begin_bootstrap(
        &self,
        group_id: i64,
        node_id: &str,
        admin_id: i64,
    ) -> Result<String, BootstrapError> {
        let operation_id = uuid::Uuid::new_v4().to_string();
        self.begin_bootstrap_with_id(group_id, node_id, admin_id, &operation_id)
            .await?;
        Ok(operation_id)
    }

    pub async fn begin_bootstrap_with_id(
        &self,
        group_id: i64,
        node_id: &str,
        admin_id: i64,
        operation_id: &str,
    ) -> Result<(), BootstrapError> {
        if uuid::Uuid::parse_str(operation_id).is_err() {
            return Err(BootstrapError::Unavailable);
        }
        let map = self.inner.read().await;
        let matches = map
            .get(&group_id)
            .into_iter()
            .flat_map(|conns| conns.iter())
            .filter(|(_, entry)| {
                entry.node_id.as_deref() == Some(node_id)
                    && entry.lifecycle_capable
                    && !entry.tx.is_closed()
            })
            .collect::<Vec<_>>();
        let (connection_id, entry) = match matches.as_slice() {
            [] => return Err(BootstrapError::Offline),
            [selected] => *selected,
            _ => return Err(BootstrapError::Ambiguous),
        };
        if !entry.config_compatible {
            return Err(BootstrapError::Unavailable);
        }
        let secret = NodeClaimSecret::generate().map_err(|_| BootstrapError::Unavailable)?;
        let operation_id = operation_id.to_string();
        let claim_id = operation_id.clone();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        let mut pending = self.bootstraps.write().await;
        pending.retain(|_, item| item.expires_at > chrono::Utc::now());
        if pending
            .values()
            .any(|item| item.group_id == group_id && item.node_id == node_id)
        {
            return Err(BootstrapError::Pending);
        }
        let message = relay_shared::protocol::NodeMigrationBootstrap {
            msg_type: "node_migration_bootstrap".into(),
            operation_id: operation_id.clone(),
            identity_group_id: group_id,
            node_id: node_id.into(),
            claim_id: claim_id.clone(),
            claim_secret: secret.to_wire_value(),
            expires_at: expires_at.to_rfc3339(),
        };
        let payload = serde_json::to_string(&message).map_err(|_| BootstrapError::Unavailable)?;
        pending.insert(
            operation_id.clone(),
            PendingBootstrap {
                operation_id: operation_id.clone(),
                claim_id,
                group_id,
                node_id: node_id.into(),
                connection_id: *connection_id,
                approved_by: admin_id,
                secret,
                expires_at,
            },
        );
        if entry.tx.send(payload).is_err() {
            pending.remove(&operation_id);
            return Err(BootstrapError::Offline);
        }
        Ok(())
    }

    pub async fn acknowledge_bootstrap(
        &self,
        db: &dyn Repository,
        group_id: i64,
        node_id: &str,
        connection_id: u64,
        ack: &relay_shared::protocol::NodeMigrationBootstrapAck,
    ) -> Result<(), BootstrapError> {
        let map = self.inner.read().await;
        let connection = map
            .get(&group_id)
            .and_then(|conns| conns.get(&connection_id));
        if !connection
            .is_some_and(|entry| entry.node_id.as_deref() == Some(node_id) && !entry.tx.is_closed())
        {
            return Err(BootstrapError::Offline);
        }
        let live_matches = map
            .get(&group_id)
            .into_iter()
            .flat_map(|conns| conns.values())
            .filter(|entry| {
                entry.node_id.as_deref() == Some(node_id)
                    && entry.lifecycle_capable
                    && !entry.tx.is_closed()
            })
            .count();
        if live_matches != 1 {
            self.bootstraps.write().await.remove(&ack.operation_id);
            return Err(BootstrapError::Ambiguous);
        }
        let mut pending = self.bootstraps.write().await;
        let Some(item) = pending.remove(&ack.operation_id) else {
            return Err(BootstrapError::Pending);
        };
        if ack.msg_type != "node_migration_bootstrap_ack"
            || ack.node_id != node_id
            || item.operation_id != ack.operation_id
            || item.claim_id != ack.claim_id
            || item.group_id != group_id
            || item.node_id != node_id
            || item.connection_id != connection_id
            || item.expires_at <= chrono::Utc::now()
        {
            return Err(BootstrapError::Unavailable);
        }
        let exact = ReuseEligibleNodeId::parse(node_id).map_err(|_| BootstrapError::Unavailable)?;
        if db
            .find_node_pool_record(group_id, node_id)
            .await
            .map_err(|_| BootstrapError::Unavailable)?
            .is_some_and(|record| record.retirement_state != "ACTIVE")
        {
            return Err(BootstrapError::Unavailable);
        }
        let created = db
            .create_node_credential_claim(&NewNodeCredentialClaim {
                claim_id: item.claim_id.clone(),
                home_group_id: group_id,
                node_id: exact.clone(),
                secret_verifier: NodeClaimSecretVerifier::derive(
                    &item.claim_id,
                    group_id,
                    &exact,
                    &item.secret,
                ),
                approved_by: item.approved_by,
                approval_ref: format!("node-pool-migration:{}", item.claim_id),
                created_at: chrono::Utc::now(),
                expires_at: item.expires_at,
            })
            .await
            .map_err(|_| BootstrapError::Unavailable)?;
        if !matches!(created, NodeCredentialClaimCreateResult::Created(_)) {
            return Err(BootstrapError::Pending);
        }
        let claim_id = item.claim_id.clone();
        let authorized = relay_shared::protocol::NodeMigrationBootstrapAuthorized {
            msg_type: "node_migration_bootstrap_authorized".into(),
            operation_id: item.operation_id,
            claim_id,
            node_id: item.node_id,
        };
        let payload =
            serde_json::to_string(&authorized).map_err(|_| BootstrapError::Unavailable)?;
        if connection
            .expect("checked connection")
            .tx
            .send(payload)
            .is_err()
        {
            let _ = db
                .cancel_node_credential_claim(&item.claim_id, group_id, &exact, chrono::Utc::now())
                .await;
            return Err(BootstrapError::Offline);
        }
        drop(pending);
        drop(map);
        crate::service::node_convergence::mark_verifying(db, group_id, node_id, &item.claim_id)
            .await
            .map_err(|_| BootstrapError::Unavailable)?;
        Ok(())
    }

    pub async fn resume_bootstrap_authorization(
        &self,
        db: &dyn Repository,
        group_id: i64,
        node_id: &str,
        connection_id: u64,
    ) -> Result<(), DbError> {
        if self
            .unique_lifecycle_connection(group_id, node_id, true)
            .await
            != Ok(connection_id)
        {
            return Ok(());
        }
        let Some(record) = crate::service::node_convergence::load(db, group_id, node_id)
            .await?
            .filter(|record| {
                matches!(
                    record.phase,
                    crate::service::node_convergence::Phase::MigratingIdentity
                        | crate::service::node_convergence::Phase::Verifying
                )
            })
        else {
            return Ok(());
        };
        let Some(claim) = db.find_node_credential_claim(&record.id).await? else {
            return Ok(());
        };
        if claim.state != "APPROVED" {
            return Ok(());
        }
        let payload =
            serde_json::to_string(&relay_shared::protocol::NodeMigrationBootstrapAuthorized {
                msg_type: "node_migration_bootstrap_authorized".into(),
                operation_id: record.id,
                claim_id: claim.claim_id,
                node_id: node_id.into(),
            })
            .map_err(|_| {
                DbError::Other(sqlx::Error::Protocol(
                    "bootstrap authorization encode failed".into(),
                ))
            })?;
        let map = self.inner.read().await;
        if let Some(entry) = map
            .get(&group_id)
            .and_then(|connections| connections.get(&connection_id))
        {
            let _ = entry.tx.send(payload);
        }
        Ok(())
    }

    /// v0.4.14: the set of node_ids in a group that currently have a live WS
    /// connection AND advertised an X-Node-ID. This is the source of truth for
    /// "is this node's control channel online", replacing the stale kvs
    /// last_seen heuristic for diagnosis. Older nodes (no X-Node-ID) are NOT
    /// included — they can't be targeted by directed diagnosis.
    pub async fn online_node_ids(&self, group_id: i64) -> std::collections::HashSet<String> {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|conns| conns.values().filter_map(|e| e.node_id.clone()).collect())
            .unwrap_or_default()
    }

    /// Node identities with a currently live Lifecycle-compatible channel.
    /// This capability is independent of ordinary status freshness and config
    /// protocol compatibility so an upgrade-only node can still be upgraded.
    pub async fn lifecycle_online_node_ids(
        &self,
        group_id: i64,
    ) -> std::collections::HashSet<String> {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|conns| {
                conns
                    .values()
                    .filter(|entry| entry.lifecycle_capable && !entry.tx.is_closed())
                    .filter_map(|entry| entry.node_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Node identities whose live channel accepts ordinary config-bound
    /// lifecycle commands. Upgrade-only connections are deliberately absent.
    pub async fn config_online_node_ids(&self, group_id: i64) -> std::collections::HashSet<String> {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|conns| {
                conns
                    .values()
                    .filter(|entry| entry.config_compatible && !entry.tx.is_closed())
                    .filter_map(|entry| entry.node_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the groups where a node identity currently has a live WS.
    /// Used by enrollment verification to distinguish a transiently offline
    /// node from one authenticated with a different device-group token.
    pub async fn online_group_ids(&self, node_id: &str) -> std::collections::HashSet<i64> {
        self.inner
            .read()
            .await
            .iter()
            .filter_map(|(group_id, conns)| {
                conns
                    .values()
                    .any(|entry| entry.node_id.as_deref() == Some(node_id))
                    .then_some(*group_id)
            })
            .collect()
    }

    /// Number of live connections currently registered for a group. Used by
    /// diagnosis to decide "WS online" vs "control channel offline".
    #[allow(dead_code)]
    pub async fn group_conn_count(&self, group_id: i64) -> usize {
        self.inner
            .read()
            .await
            .get(&group_id)
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Force-close every live connection for ONE group. Used by token rotation:
    /// the old token is invalid immediately, so the old WS connection (which
    /// authenticated with it at upgrade time) must be torn down — otherwise the
    /// node keeps an authenticated socket open with a revoked credential until
    /// its next reconnect.
    ///
    /// Drops the group's senders; each connection's `push_rx.recv()` returns
    /// None and the socket task exits (handle_node_ws → unregister, a no-op
    /// since close_group already removed the entry). The node then reconnects
    /// and re-authenticates with the new token.
    pub async fn close_group(&self, group_id: i64) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.remove(&group_id) else {
            return 0;
        };
        let mut observations = self.observations.write().await;
        let now = chrono::Utc::now().to_rfc3339();
        for entry in conns.values() {
            if let Some(id) = &entry.node_id {
                if let Some(observation) = observations.get_mut(&(group_id, id.clone())) {
                    observation.1 = Some(now.clone());
                }
            }
        }
        conns.len()
    }

    pub async fn close_node(&self, group_id: i64, node_id: &str) -> usize {
        let mut map = self.inner.write().await;
        let Some(conns) = map.get_mut(&group_id) else {
            return 0;
        };
        let before = conns.len();
        conns.retain(|_, entry| entry.node_id.as_deref() != Some(node_id));
        let removed = before - conns.len();
        if removed > 0 {
            if let Some(observation) = self
                .observations
                .write()
                .await
                .get_mut(&(group_id, node_id.to_string()))
            {
                observation.1 = Some(chrono::Utc::now().to_rfc3339());
            }
        }
        if conns.is_empty() {
            map.remove(&group_id);
        }
        removed
    }

    #[cfg(test)]
    pub async fn observation(
        &self,
        group_id: i64,
        node_id: &str,
    ) -> (Option<String>, Option<String>) {
        self.observations
            .read()
            .await
            .get(&(group_id, node_id.to_string()))
            .cloned()
            .unwrap_or_default()
    }
}

/// 判断认证后的 Node 是否允许进入 WS 控制面。
///
/// 配置协议匹配时正常进入；配置协议不匹配时，只要有稳定 node_id 且具备
/// lifecycle upgrade 能力，就必须允许进入 upgrade-only 模式。这个门禁是
/// “未来配置协议升级永远不能封死一键升级”的核心不变量。
fn ws_connection_allowed(
    config_compatible: bool,
    has_node_id: bool,
    lifecycle_capable: bool,
) -> bool {
    config_compatible || (has_node_id && lifecycle_capable)
}

/// WebSocket endpoint for node control channel.
/// Node authenticates via Authorization: Bearer <NODE_TOKEN>.
/// The token is intentionally NOT accepted from `?token=` because query
/// parameters leak into access/proxy logs (Nginx/Caddy/CDN).
///
/// Protocol:
///   - On connect: server sends config_snapshot (NodeConfigResponse JSON)
///   - ping/pong: heartbeat
///   - config_changed: server pushes `{"type":"config_changed"}` to all
///     connections whenever an admin mutates rules/groups; the node then
///     re-fetches /node/config over HTTP.
pub async fn node_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error.status().into_response(),
    };
    let group_id = identity.group_id();
    let node_id = identity.node_id().map(str::to_string);
    let verified_credential = identity.verified().cloned();
    match crate::service::node_pool::legacy_config_authority_retired(
        state.db.as_ref(),
        group_id,
        node_id.as_deref(),
        verified_credential.is_some(),
    )
    .await
    {
        Ok(true) => return axum::http::StatusCode::FORBIDDEN.into_response(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Ok(false) => {}
    }
    let node_version = headers
        .get("X-Node-Version")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let node_architecture = headers
        .get("X-Node-Architecture")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let config_compatible = crate::api::node::config_protocol_compatible(&headers);
    let lifecycle_protocol = headers
        .get("X-Lifecycle-Protocol-Version")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u32>().ok());
    let lifecycle_capable = match lifecycle_protocol {
        Some(version) => {
            lifecycle_protocol_versions_compatible(LIFECYCLE_PROTOCOL_VERSION, version)
        }
        None => legacy_node_supports_lifecycle(node_version.as_deref()),
    };

    // Config mismatch is no longer allowed to kill the upgrade path. A known
    // lifecycle-capable node with a stable node_id is accepted as upgrade-only:
    // no config snapshot, no config_changed, no diagnose/restart/uninstall.
    if !ws_connection_allowed(config_compatible, node_id.is_some(), lifecycle_capable) {
        let received = crate::api::node::extract_config_protocol_version(&headers);
        return (
            axum::http::StatusCode::UPGRADE_REQUIRED,
            axum::Json(serde_json::json!({
                "code": "CONFIG_PROTOCOL_MISMATCH",
                "required": relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
                "received": received,
                "message": "relay-node configuration protocol is incompatible and this node has no compatible lifecycle upgrade channel"
            })),
        )
            .into_response();
    }
    if !config_compatible {
        tracing::warn!(
            node_id = ?node_id,
            node_version = ?node_version,
            config_protocol = ?crate::api::node::extract_config_protocol_version(&headers),
            lifecycle_protocol = ?lifecycle_protocol,
            "websocket accepted in upgrade-only mode due to config protocol mismatch"
        );
    }
    // Clone the Arc<dyn Repository> so the WS task can keep using it after the
    // upgrade handler returns. The pool snapshot is shared read-only.
    let db = state.db.clone();

    let node_connections = state.node_connections.clone();
    let node_operations = state.node_operations.clone();
    ws.on_upgrade(move |socket| {
        handle_node_ws(
            socket,
            group_id,
            node_id,
            node_version,
            node_architecture,
            config_compatible,
            lifecycle_capable,
            verified_credential,
            state,
            db,
            node_connections,
            node_operations,
        )
    })
}

// 连接处理需要同时携带认证后的节点元数据、协议能力与共享运行态。
// 这些参数属于同一个 WS 生命周期，当前保持显式传递以避免为 rc.5 引入无关重构。
#[allow(clippy::too_many_arguments)]
async fn handle_node_ws(
    socket: WebSocket,
    group_id: i64,
    node_id: Option<String>,
    node_version: Option<String>,
    node_architecture: Option<String>,
    config_compatible: bool,
    lifecycle_capable: bool,
    verified_credential: Option<VerifiedConcreteNode>,
    state: AppState,
    db: std::sync::Arc<dyn crate::db::Repository>,
    node_connections: NodeConnections,
    node_operations: crate::api::node_ops::NodeOperationRegistry,
) {
    tracing::info!(
        "websocket connected: group_id={} node_id={:?}",
        group_id,
        node_id
    );

    // Split so we can concurrently read ping/close from the socket AND write
    // broadcast pushes from the channel. Both halves borrow independent state.
    let (mut sender, mut receiver) = socket.split();
    let lifecycle_node_id = node_id.clone();
    let (conn_id, mut push_rx) = node_connections
        .register_with_capabilities(
            group_id,
            node_id.clone(),
            config_compatible,
            lifecycle_capable,
        )
        .await;
    if let Some(node_id) = lifecycle_node_id.as_deref() {
        if let Err(error) = node_connections
            .resume_bootstrap_authorization(db.as_ref(), group_id, node_id, conn_id)
            .await
        {
            tracing::warn!("automatic migration authorization resume unavailable: {error}");
        }
    }
    if let Some(node_id) = lifecycle_node_id.as_deref() {
        for operation in node_operations.connected(
            group_id,
            node_id,
            node_version.as_deref(),
            node_architecture.as_deref(),
        ) {
            crate::api::node_ops::audit_terminal_operation(&state, &operation).await;
        }
    }

    // Send initial config snapshot so a freshly-connected node has its config
    // immediately, without waiting for the first HTTP poll. None (DB error) →
    // skip the push; the node will get its config on the next HTTP poll.
    if config_compatible {
        let certificate_state_dir = std::path::PathBuf::from(state.config.certificate_state_dir());
        if let Some(config) = build_config_snapshot_for_node(
            db.as_ref(),
            &certificate_state_dir,
            group_id,
            node_id.as_deref(),
            verified_credential.is_some(),
            state.config.node_reuse_runtime_enabled,
        )
        .await
        {
            if let Ok(config_json) = serde_json::to_string(&config) {
                let _ = sender.send(Message::Text(config_json.into())).await;
            }
        }
    }

    use tokio::time::{timeout, Duration};

    // The read loop idles when the node neither pings nor sends data. We
    // cap idle at 120s so a silently-dropped connection (NAT timeout,
    // half-open TCP) is eventually cleaned up. The node's heartbeat is
    // expected well within this window.
    const READ_TIMEOUT: Duration = Duration::from_secs(120);
    const CREDENTIAL_RECHECK_INTERVAL: Duration = Duration::from_secs(5);
    let mut credential_recheck = tokio::time::interval(CREDENTIAL_RECHECK_INTERVAL);
    credential_recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Drive both halves. `receiver.recv()` (wrapped in a timeout) and
    // `push_rx.recv()` borrow different variables, so select! can hold both
    // pending at once; the branch bodies both use `sender` but only one
    // runs at a time.
    loop {
        tokio::select! {
            msg = timeout(READ_TIMEOUT, receiver.next()) => match msg {
                Err(_) => {
                    tracing::warn!(
                        "websocket idle timeout ({}s): group_id={}",
                        READ_TIMEOUT.as_secs(),
                        group_id
                    );
                    break;
                }
                Ok(Some(Ok(Message::Ping(data)))) => {
                    let _ = sender.send(Message::Pong(data)).await;
                }
                Ok(Some(Ok(Message::Pong(_)))) => {
                    // keepalive acknowledged
                }
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                    tracing::info!("websocket disconnected: group_id={}", group_id);
                    break;
                }
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Ok(ack) = serde_json::from_str::<
                        relay_shared::protocol::NodeMigrationBootstrapAck,
                    >(&text)
                    {
                        if ack.msg_type == "node_migration_bootstrap_ack" {
                            if verified_credential.is_none() {
                                if let Some(id) = lifecycle_node_id.as_deref() {
                                    if let Err(error) = node_connections
                                        .acknowledge_bootstrap(db.as_ref(), group_id, id, conn_id, &ack)
                                        .await
                                    {
                                        tracing::warn!("automatic migration acknowledgement rejected: {error:?}");
                                    }
                                }
                            }
                            continue;
                        }
                    }
                    if let Ok(event) = serde_json::from_str::<
                        relay_shared::protocol::NodeLifecycleEvent,
                    >(&text)
                    {
                        if event.msg_type == "node_lifecycle_event" {
                            let outcome = node_operations.event_from_authenticated_node(
                                group_id,
                                lifecycle_node_id.as_deref(),
                                event.clone(),
                            );
                            if let Some(ack) = outcome.boot_ack {
                                if let Ok(payload) = serde_json::to_string(&ack) {
                                    if sender.send(Message::Text(payload.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            let upgrade_confirmed = outcome.operation.as_ref().is_some_and(|operation| {
                                operation.action == relay_shared::protocol::NodeLifecycleAction::Upgrade
                                    && operation.status == crate::api::node_ops::OperationStatus::Success
                            });
                            if let Some(operation) = outcome.operation {
                                if operation.action == relay_shared::protocol::NodeLifecycleAction::Upgrade
                                    && matches!(operation.status, crate::api::node_ops::OperationStatus::Failed | crate::api::node_ops::OperationStatus::Timeout)
                                {
                                    if let Err(error) = crate::service::node_convergence::mark_upgrade_failed(
                                        &state, group_id, &operation.node_id, &operation.id, &operation.message,
                                    ).await {
                                        tracing::warn!("identity convergence failure observation unavailable: {error}");
                                    }
                                }
                                crate::api::node_ops::audit_terminal_operation(
                                    &state,
                                    &operation,
                                )
                                .await;
                            }
                            if upgrade_confirmed {
                                if let Err(error) = crate::service::node_convergence::after_boot_event(
                                    &state, group_id, &event, verified_credential.is_some(),
                                ).await {
                                    tracing::warn!("identity convergence boot correlation unavailable: {error}");
                                }
                            }
                        }
                    }
                }
                Ok(Some(Ok(_))) => {
                    // ignore other message types
                }
            },
            _ = credential_recheck.tick(), if verified_credential.is_some() => {
                let verified = verified_credential.as_ref().expect("guarded by select condition");
                match verified_credential_still_active(&state, verified).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            group_id,
                            node_id = %verified.node_id.as_str(),
                            credential_id = %verified.credential_id,
                            "websocket credential is no longer active; closing connection"
                        );
                        break;
                    }
                    Err(_) => {
                        tracing::warn!(
                            group_id,
                            node_id = %verified.node_id.as_str(),
                            "websocket credential revalidation unavailable; failing closed"
                        );
                        break;
                    }
                }
            },
            pushed = push_rx.recv() => match pushed {
                Some(text) => {
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        tracing::warn!(
                            "websocket send failed: group_id={}, closing",
                            group_id
                        );
                        break;
                    }
                }
                None => break, // all senders dropped — shouldn't happen here
            },
        }
    }

    node_connections.unregister(group_id, conn_id).await;
    if let Some(node_id) = lifecycle_node_id.as_deref() {
        for operation in node_operations.disconnected(group_id, node_id) {
            crate::api::node_ops::audit_terminal_operation(&state, &operation).await;
        }
        crate::api::node_ops::record_uninstall_disconnect(&state, group_id, node_id).await;
    }
}

pub(crate) async fn build_config_snapshot_for_node(
    db: &dyn crate::db::Repository,
    certificate_state_dir: &std::path::Path,
    group_id: i64,
    node_id: Option<&str>,
    verified_concrete_node: bool,
    runtime_enabled: bool,
) -> Option<NodeConfigSnapshot> {
    match crate::service::node_pool::legacy_config_authority_retired(
        db,
        group_id,
        node_id,
        verified_concrete_node,
    )
    .await
    {
        Ok(false) => {}
        Ok(true) | Err(_) => return None,
    }
    // v0.3.6: delegate to the shared `build_node_config` (same function
    // `get_config` uses). This fixes the v0.3.5 drift where the WS path queried
    // forward_rules WITHOUT joining users, so a reconnecting node could be
    // handed a banned / over-quota user's rules until the next HTTP poll. Now
    // both paths apply the identical filter (paused / banned / quota) and the
    // identical target resolution + listener assembly.
    //
    // Returns None on DB error so the caller skips the snapshot push (rather
    // than pushing an empty config that would incorrectly tear down the node's
    // listeners). An empty Ok is a legitimate "no rules" snapshot.
    match crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
        db,
        certificate_state_dir,
        group_id,
        node_id,
        verified_concrete_node,
        crate::service::node_config::runtime_delivery_mode(runtime_enabled, verified_concrete_node),
    )
    .await
    {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::error!(
                "build_config_snapshot: build_node_config failed for group {}: {}",
                group_id,
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::system::ReleaseCache;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::node_credential::{NodeCredentialSecret, NodeCredentialVerifier};
    use crate::node_identity::ReuseEligibleNodeId;
    use futures_util::StreamExt;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    async fn ws_credential_state() -> (AppState, NodeCredentialSecret, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'home', 'in', 'legacy-token', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let secret = NodeCredentialSecret::from_test_bytes([0x42; 32]);
        let verifier = NodeCredentialVerifier::derive("cred-ws", 10, &node_id, &secret);
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data, activated_at) \
             VALUES ('cred-ws', 10, 'Node_A', 1, 'rp-node-sha256', 1, ?, datetime('now'))",
        )
        .bind(verifier.data().as_slice())
        .execute(&pool)
        .await
        .unwrap();
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
                node_reuse_runtime_enabled: false,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (state, secret, pool)
    }

    fn credential_ws_request(
        addr: std::net::SocketAddr,
        secret: &NodeCredentialSecret,
    ) -> axum::http::Request<()> {
        let mut request = format!("ws://{addr}/node/ws")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Authorization",
            format!("RelayNodeCredential {}", secret.to_wire_value())
                .parse()
                .unwrap(),
        );
        request
            .headers_mut()
            .insert("X-Node-Credential-ID", "cred-ws".parse().unwrap());
        request
            .headers_mut()
            .insert("X-Node-ID", "Node_A".parse().unwrap());
        request.headers_mut().insert(
            "X-Config-Protocol-Version",
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                .to_string()
                .parse()
                .unwrap(),
        );
        request
    }

    #[tokio::test]
    async fn migrated_legacy_websocket_is_rejected_before_upgrade() {
        let (state, _secret, _pool) = ws_credential_state().await;
        state
            .db
            .set(
                "node_pool_migration_completion:10:Node_A",
                r#"{"claim_id":"claim-rt001","credential_id":"cred-ws"}"#,
            )
            .await
            .unwrap();
        let app = axum::Router::new()
            .route("/node/ws", axum::routing::get(node_ws_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut request = format!("ws://{addr}/node/ws")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Authorization", "Bearer legacy-token".parse().unwrap());
        request
            .headers_mut()
            .insert("X-Node-ID", "Node_A".parse().unwrap());
        request.headers_mut().insert(
            "X-Config-Protocol-Version",
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                .to_string()
                .parse()
                .unwrap(),
        );
        let error = tokio_tungstenite::connect_async(request.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == axum::http::StatusCode::FORBIDDEN)
        );
        request
            .headers_mut()
            .insert("X-Node-ID", "Node_B".parse().unwrap());
        let (socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("same-group unmigrated Node must retain WS access");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SWITCHING_PROTOCOLS
        );
        drop(socket);
        server.abort();
    }

    #[tokio::test]
    async fn verified_websocket_is_closed_after_credential_revocation_and_reconnect_is_rejected() {
        let (state, secret, pool) = ws_credential_state().await;
        let app = axum::Router::new()
            .route("/node/ws", axum::routing::get(node_ws_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (mut socket, response) =
            tokio_tungstenite::connect_async(credential_ws_request(addr, &secret))
                .await
                .expect("active permanent Credential must complete a real WS handshake");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SWITCHING_PROTOCOLS
        );
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("server must send initial config snapshot");
        assert!(first.is_some());

        sqlx::query(
            "UPDATE node_credentials SET revoked_at = datetime('now') WHERE credential_id = 'cred-ws'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let disconnected = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                match socket.next().await {
                    None | Some(Err(_)) => return true,
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => return true,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .expect("revoked Verified WebSocket retained control authority past recheck bound");
        assert!(disconnected);

        let reconnect =
            tokio_tungstenite::connect_async(credential_ws_request(addr, &secret)).await;
        match reconnect {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
            }
            other => panic!("revoked Credential reconnect must return HTTP 401, got {other:?}"),
        }
        server.abort();
    }

    /// register() must hand back a receiver that actually receives what
    /// broadcast_all sends. This is the contract every admin mutation
    /// relies on for the config_changed push.
    #[tokio::test]
    async fn register_then_broadcast_delivers() {
        let conns = NodeConnections::new();
        let (_id, mut rx) = conns.register(7, None).await;

        conns.broadcast_all(r#"{"type":"config_changed"}"#).await;

        let msg = rx.recv().await;
        assert_eq!(msg.as_deref(), Some(r#"{"type":"config_changed"}"#));
    }

    #[tokio::test]
    async fn control_observations_follow_exact_connections() {
        let conns = NodeConnections::new();
        let (first, _first_rx) = conns.register(7, Some("node-a".into())).await;
        let (_second, _second_rx) = conns.register(7, Some("node-b".into())).await;
        let observed = conns.observation(7, "node-a").await;
        assert!(observed.0.is_some());
        assert!(observed.1.is_none());
        conns.unregister(7, first).await;
        assert!(conns.observation(7, "node-a").await.1.is_some());
        assert!(conns.observation(7, "node-b").await.1.is_none());
        assert_eq!(conns.close_node(7, "node-b").await, 1);
        assert!(conns.observation(7, "node-b").await.1.is_some());
    }

    #[tokio::test]
    async fn captured_control_state_is_stable_until_the_next_request() {
        let connections = NodeConnections::new();
        let (connection_id, _receiver) = connections.register(7, Some("Node_A".into())).await;
        let first = connections.capture().await;
        assert!(first.connected.contains(&(7, "Node_A".into())));
        assert!(first.observations.contains_key(&(7, "Node_A".into())));
        connections.unregister(7, connection_id).await;
        assert!(first.connected.contains(&(7, "Node_A".into())));
        let second = connections.capture().await;
        assert!(!second.connected.contains(&(7, "Node_A".into())));
        assert!(second
            .observations
            .get(&(7, "Node_A".into()))
            .and_then(|observation| observation.1.as_ref())
            .is_some());
    }

    #[tokio::test]
    async fn lifecycle_selection_requires_one_exact_connection_and_never_resends_to_replacement() {
        let conns = NodeConnections::new();
        assert_eq!(
            conns.unique_lifecycle_connection(7, "Node_A", true).await,
            Err(UniqueConnectionError::Offline)
        );
        let (first, mut first_rx) = conns.register(7, Some("Node_A".into())).await;
        let (duplicate, mut duplicate_rx) = conns.register(7, Some("Node_A".into())).await;
        assert_eq!(
            conns.unique_lifecycle_connection(7, "Node_A", true).await,
            Err(UniqueConnectionError::Ambiguous)
        );
        assert!(first_rx.try_recv().is_err());
        assert!(duplicate_rx.try_recv().is_err());
        conns.unregister(7, duplicate).await;
        assert_eq!(
            conns.unique_lifecycle_connection(7, "Node_A", true).await,
            Ok(first)
        );
        assert!(
            conns
                .send_exact_connection(7, "Node_A", first, "bootstrap")
                .await
        );
        assert_eq!(first_rx.recv().await.as_deref(), Some("bootstrap"));
        conns.unregister(7, first).await;
        let (_replacement, mut replacement_rx) = conns.register(7, Some("Node_A".into())).await;
        assert!(
            !conns
                .send_exact_connection(7, "Node_A", first, "secret")
                .await
        );
        assert!(replacement_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn bootstrap_claim_requires_ack_from_selected_live_connection() {
        use crate::db::repo::{NodeCredentialClaimRepository, NodePoolRepository};
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_groups (id,name,group_type,token,uid) VALUES (7,'home','in','token-7',1)")
            .execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        db.register_node_pool_identity(7, "Node_A").await.unwrap();
        let conns = NodeConnections::new();
        assert_eq!(
            conns.begin_bootstrap(7, "Node_A", 1).await,
            Err(BootstrapError::Offline)
        );
        let (_first, mut first_rx) = conns.register(7, Some("Node_A".into())).await;
        let (duplicate, _dup_rx) = conns.register(7, Some("Node_A".into())).await;
        assert_eq!(
            conns.begin_bootstrap(7, "Node_A", 1).await,
            Err(BootstrapError::Ambiguous)
        );
        conns.unregister(7, duplicate).await;
        let operation = conns.begin_bootstrap(7, "Node_A", 1).await.unwrap();
        let message: relay_shared::protocol::NodeMigrationBootstrap =
            serde_json::from_str(&first_rx.recv().await.unwrap()).unwrap();
        assert_eq!(message.operation_id, operation);
        assert_eq!(message.node_id, "Node_A");
        let ack = relay_shared::protocol::NodeMigrationBootstrapAck {
            msg_type: "node_migration_bootstrap_ack".into(),
            operation_id: operation.clone(),
            claim_id: message.claim_id.clone(),
            node_id: "Node_A".into(),
        };
        let (intruder, _intruder_rx) = conns.register(7, Some("Node_A".into())).await;
        assert_eq!(
            conns
                .acknowledge_bootstrap(&db, 7, "Node_A", intruder, &ack)
                .await,
            Err(BootstrapError::Ambiguous)
        );
        assert!(db
            .find_node_credential_claim(&message.claim_id)
            .await
            .unwrap()
            .is_none());
        conns.unregister(7, intruder).await;
        let second = conns.begin_bootstrap(7, "Node_A", 1).await.unwrap();
        let delivered: relay_shared::protocol::NodeMigrationBootstrap =
            serde_json::from_str(&first_rx.recv().await.unwrap()).unwrap();
        assert_ne!(delivered.claim_secret, message.claim_secret);
        let selected = conns
            .unique_lifecycle_connection(7, "Node_A", true)
            .await
            .unwrap();
        let valid_ack = relay_shared::protocol::NodeMigrationBootstrapAck {
            msg_type: "node_migration_bootstrap_ack".into(),
            operation_id: second,
            claim_id: delivered.claim_id.clone(),
            node_id: "Node_A".into(),
        };
        conns
            .acknowledge_bootstrap(&db, 7, "Node_A", selected, &valid_ack)
            .await
            .unwrap();
        let authorized: relay_shared::protocol::NodeMigrationBootstrapAuthorized =
            serde_json::from_str(&first_rx.recv().await.unwrap()).unwrap();
        assert_eq!(authorized.msg_type, "node_migration_bootstrap_authorized");
        assert_eq!(authorized.claim_id, delivered.claim_id);
        assert_eq!(
            db.find_node_credential_claim(&delivered.claim_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "APPROVED"
        );
    }

    /// broadcast_all must fan out to EVERY registered connection, not just
    /// the first one — otherwise only one node per group would get pushes.
    #[tokio::test]
    async fn broadcast_fans_out_to_multiple_connections_same_group() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(1, None).await;
        let (_, mut rx_b) = conns.register(1, None).await;
        // Different group should also receive (broadcast_all hits all groups).
        let (_, mut rx_c) = conns.register(99, None).await;

        conns.broadcast_all("hi").await;

        assert_eq!(rx_a.recv().await.as_deref(), Some("hi"));
        assert_eq!(rx_b.recv().await.as_deref(), Some("hi"));
        assert_eq!(rx_c.recv().await.as_deref(), Some("hi"));
    }

    /// After unregister, a connection must no longer receive broadcasts.
    /// This is what prevents memory growth as nodes reconnect.
    #[tokio::test]
    async fn unregister_stops_delivery() {
        let conns = NodeConnections::new();
        let (id, mut rx) = conns.register(3, None).await;

        conns.unregister(3, id).await;
        conns.broadcast_all("late").await;

        // recv on an unregistered sender's receiver: either the sender was
        // removed (so nothing arrives) — either way, no "late" message.
        let leaked = rx.try_recv().ok();
        assert_ne!(leaked.as_deref(), Some("late"));
    }

    /// If a connection's receiver is dropped (node disconnected without
    /// cleanly unregistering), broadcast_all must prune the dead sender
    /// instead of leaking it forever. Verified by checking that the next
    /// broadcast doesn't panic and the live connection still gets the msg.
    #[tokio::test]
    async fn broadcast_prunes_dead_senders() {
        let conns = NodeConnections::new();

        // Register and immediately drop the receiver — simulates a node
        // whose socket died before unregister ran.
        let (_, rx_dead) = conns.register(5, None).await;
        drop(rx_dead);

        // Live connection on the same group.
        let (_, mut rx_live) = conns.register(5, None).await;

        // First broadcast hits the dead sender (send fails) and prunes it;
        // the live sender must still receive.
        conns.broadcast_all("after-death").await;
        assert_eq!(rx_live.recv().await.as_deref(), Some("after-death"));

        // Second broadcast must not error on the pruned entry.
        conns.broadcast_all("again").await;
        assert_eq!(rx_live.recv().await.as_deref(), Some("again"));
    }

    /// close_group must disconnect every connection of the targeted group by
    /// dropping their senders (receiver returns None). This is the token-
    /// rotation contract: the old token is invalid, so every socket that
    /// authenticated with it must be torn down.
    #[tokio::test]
    async fn close_group_disconnects_all_connections_in_group() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(3, None).await;
        let (_, mut rx_b) = conns.register(3, None).await;
        // A different group must be UNAFFECTED.
        let (_, mut rx_other) = conns.register(7, None).await;

        let closed = conns.close_group(3).await;

        // Both connections in group 3 see their receiver return None (sender
        // dropped) — the handle_node_ws loop breaks on this and the socket
        // closes, forcing the node to reconnect and re-auth with the new token.
        assert_eq!(closed, 2, "close_group must report the count closed");
        assert!(rx_a.recv().await.is_none(), "group-3 conn A must be closed");
        assert!(rx_b.recv().await.is_none(), "group-3 conn B must be closed");
        // The other group keeps working.
        conns.broadcast_all("still-here").await;
        assert_eq!(rx_other.recv().await.as_deref(), Some("still-here"));
    }

    /// close_group on a group with no connections returns 0 and is a no-op.
    #[tokio::test]
    async fn close_group_unknown_group_is_noop() {
        let conns = NodeConnections::new();
        let (_, mut rx) = conns.register(3, None).await;

        let closed = conns.close_group(999).await;

        assert_eq!(closed, 0);
        // The real group is untouched.
        conns.broadcast_all("ok").await;
        assert_eq!(rx.recv().await.as_deref(), Some("ok"));
    }

    /// v0.4.14: send_node delivers ONLY to the connection whose X-Node-ID
    /// matches; other nodes in the same group are untouched.
    #[tokio::test]
    async fn send_node_targets_only_matching_node() {
        let conns = NodeConnections::new();
        let (_, mut rx_a) = conns.register(1, Some("node-a".into())).await;
        let (_, mut rx_b) = conns.register(1, Some("node-b".into())).await;

        let sent = conns.send_node(1, "node-a", "probe").await;
        assert_eq!(sent, 1, "exactly one connection matched node-a");
        assert_eq!(rx_a.recv().await.as_deref(), Some("probe"));
        // node-b must NOT have received it.
        assert!(
            rx_b.try_recv().is_err(),
            "node-b must not receive node-a's probe"
        );
    }

    /// send_node to a node that has no live connection returns 0 (control
    /// channel offline) — the diagnose path turns this into an immediate
    /// "offline" instead of waiting for a timeout.
    #[tokio::test]
    async fn send_node_unknown_node_returns_zero() {
        let conns = NodeConnections::new();
        let (_, _rx) = conns.register(1, Some("node-a".into())).await;
        assert_eq!(conns.send_node(1, "ghost", "probe").await, 0);
        assert_eq!(conns.send_node(999, "node-a", "probe").await, 0);
    }

    #[tokio::test]
    async fn upgrade_only_connection_receives_upgrade_but_no_config_control() {
        let conns = NodeConnections::new();
        let (_, mut old_rx) = conns
            .register_with_capabilities(1, Some("old-node".into()), false, true)
            .await;
        let (_, mut current_rx) = conns
            .register_with_capabilities(1, Some("current-node".into()), true, true)
            .await;

        conns.broadcast_all(r#"{"type":"config_changed"}"#).await;
        assert!(
            old_rx.try_recv().is_err(),
            "upgrade-only node must not receive config_changed"
        );
        assert_eq!(
            current_rx.recv().await.as_deref(),
            Some(r#"{"type":"config_changed"}"#)
        );

        assert_eq!(conns.send_node(1, "old-node", "diagnose").await, 0);
        assert!(
            old_rx.try_recv().is_err(),
            "ordinary control must be blocked"
        );

        // 防御性覆盖废弃的 group-wide 通道：它也不能绕过 upgrade-only。
        assert_eq!(conns.send_group(1, "group-control").await, 1);
        assert!(old_rx.try_recv().is_err(), "group control must be blocked");
        assert_eq!(current_rx.recv().await.as_deref(), Some("group-control"));

        let selected = conns
            .unique_lifecycle_connection(1, "old-node", true)
            .await
            .unwrap();
        assert!(
            conns
                .send_exact_connection(1, "old-node", selected, "upgrade")
                .await
        );
        assert_eq!(old_rx.recv().await.as_deref(), Some("upgrade"));

        assert!(conns
            .lifecycle_online_node_ids(1)
            .await
            .contains("old-node"));
        assert!(!conns.config_online_node_ids(1).await.contains("old-node"));
        assert!(conns
            .config_online_node_ids(1)
            .await
            .contains("current-node"));

        drop(old_rx);
        assert!(
            !conns
                .lifecycle_online_node_ids(1)
                .await
                .contains("old-node"),
            "a closed Lifecycle channel must immediately lose Upgrade capability"
        );
    }

    #[test]
    fn config_mismatch_still_allows_known_upgrade_capable_node() {
        assert!(ws_connection_allowed(true, false, false));

        let rc3_lifecycle = legacy_node_supports_lifecycle(Some("1.1.0-rc.3"));
        assert!(rc3_lifecycle, "rc.3 is a shipped lifecycle-capable Node");
        assert!(
            ws_connection_allowed(false, true, rc3_lifecycle),
            "config mismatch must degrade to upgrade-only instead of HTTP 426"
        );

        assert!(!ws_connection_allowed(false, false, true));
        assert!(!ws_connection_allowed(false, true, false));
    }

    /// online_node_ids returns the node_ids with a live connection; older nodes
    /// (no X-Node-ID) are excluded so they don't get targeted.
    #[tokio::test]
    async fn online_node_ids_excludes_nodeless_connections() {
        let conns = NodeConnections::new();
        let (_, _a) = conns.register(1, Some("node-a".into())).await;
        let (_, _b) = conns.register(1, Some("node-b".into())).await;
        let (_, _legacy) = conns.register(1, None).await; // older node, no X-Node-ID

        let ids = conns.online_node_ids(1).await;
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("node-a"));
        assert!(ids.contains("node-b"));
        // An empty group → empty set.
        assert!(conns.online_node_ids(42).await.is_empty());
    }
}
