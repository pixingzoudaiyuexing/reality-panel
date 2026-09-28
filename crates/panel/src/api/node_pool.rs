use crate::api::{middleware::AdminOnly, AppState};
use crate::db::repo::{GroupRepository, ResourceScope};
use crate::node_identity::ReuseEligibleNodeId;
use crate::service::node_pool;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::protocol::ApiResponse;
use serde::Deserialize;

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiResponse::<()>::error(
            503,
            "节点池暂时不可用，请稍后重试",
        )),
    )
        .into_response()
}

pub(crate) async fn require_business_group(
    state: &AppState,
    group_id: i64,
) -> Result<(), Response> {
    match state.db.node_pool_system_group_id().await {
        Ok(Some(anchor)) if anchor == group_id => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(404, "业务分组不存在")),
        )
            .into_response()),
        Ok(_) => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

pub async fn node_identity(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    match crate::api::node_auth::authenticate_node(&state, &headers).await {
        Ok(identity) => match identity.verified() {
            Some(verified) => Json(serde_json::json!({
                "identity_group_id": verified.home_group_id,
                "node_id": verified.node_id.as_str(),
            }))
            .into_response(),
            None => StatusCode::FORBIDDEN.into_response(),
        },
        Err(error) => error.status().into_response(),
    }
}

pub async fn complete_migration(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let identity = match crate::api::node_auth::authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error.status().into_response(),
    };
    let Some(verified) = identity.verified() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match node_pool::record_migration_completion(
        state.db.as_ref(),
        verified.home_group_id,
        &verified.node_id,
        &claim_id,
        &verified.credential_id,
    )
    .await
    {
        Ok(true) => {
            state
                .node_connections
                .close_node(verified.home_group_id, verified.node_id.as_str())
                .await;
            match crate::service::node_convergence::mark_complete(
                &state,
                verified.home_group_id,
                verified.node_id.as_str(),
                &claim_id,
            )
            .await
            {
                Ok(()) => Json(ApiResponse::success(())).into_response(),
                Err(_) => unavailable(),
            }
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(409, "迁移身份与当前凭据不匹配")),
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

fn migration_command(origin: &str, claim_id: &str, group_id: i64, node_id: &str) -> String {
    format!(
        "curl --proto '=https' -fsS '{}' | python3 - --claim-id '{}' --identity-group-id {} --node-id '{}'",
        format!("{origin}/api/v1/node-pool/migrate.py").replace('\'', "'\\''"),
        claim_id,
        group_id,
        node_id,
    )
}

pub async fn start_migration(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((identity_group_id, node_id)): Path<(i64, String)>,
    peer: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !crate::api::node_claim::production_claim_transport_allowed(&state, peer.0, &headers).await {
        let reason =
            crate::api::node_claim::claim_transport_failure_message(&state, peer.0, &headers).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<()>::error(503, &reason)),
        )
            .into_response();
    }
    start_migration_after_transport(admin, state, identity_group_id, node_id, peer, headers).await
}

pub async fn start_identity_convergence(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
    peer: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !crate::api::node_claim::production_claim_transport_allowed(&state, peer.0, &headers).await {
        let reason =
            crate::api::node_claim::claim_transport_failure_message(&state, peer.0, &headers).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<()>::error(503, &reason)),
        )
            .into_response();
    }
    if ReuseEligibleNodeId::parse(&node_id).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let nodes = match node_pool::list_nodes(state.db.as_ref()).await {
        Ok(nodes) => nodes,
        Err(_) => return unavailable(),
    };
    let Some(node) = nodes
        .iter()
        .find(|node| node.identity_group_id == group_id && node.node_id == node_id)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !node.migration_required || node.credential_active {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(409, "节点当前无法开始身份迁移")),
        )
            .into_response();
    }
    match crate::service::node_convergence::start(&state, admin.user_id, group_id, &node_id).await {
        Ok(operation) => Json(ApiResponse::success(operation.operation_view())).into_response(),
        Err(error) => crate::api::node_ops::convergence_response(error),
    }
}

async fn start_migration_after_transport(
    admin: AdminOnly,
    state: AppState,
    identity_group_id: i64,
    node_id: String,
    peer: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    match state.db.node_pool_system_group_id().await {
        Ok(Some(anchor)) if anchor == identity_group_id => {
            return (
                StatusCode::CONFLICT,
                Json(ApiResponse::<()>::error(
                    409,
                    "节点池原生节点不能使用旧节点迁移",
                )),
            )
                .into_response();
        }
        Err(_) => return unavailable(),
        _ => {}
    }
    let nodes = match node_pool::list_nodes(state.db.as_ref()).await {
        Ok(nodes) => nodes,
        Err(_) => return unavailable(),
    };
    let Some(node) = nodes
        .iter()
        .find(|n| n.identity_group_id == identity_group_id && n.node_id == node_id)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if node.safe_to_add || !node.migration_required {
        return StatusCode::CONFLICT.into_response();
    }
    if node.recovery_available {
        let Some(claim_id) = node.migration_claim_id.as_deref() else {
            return unavailable();
        };
        let Some(origin) = super::provisioning::effective_public_panel_url(&state).await else {
            return unavailable();
        };
        return Json(ApiResponse::success(serde_json::json!({
            "claim": {"claim_id": claim_id},
            "claim_secret": null,
            "command": migration_command(&origin, claim_id, identity_group_id, &node_id),
            "recovery": true,
        })))
        .into_response();
    }
    if node.credential_active || !node.auth_reload_supported {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(
                409,
                "节点迁移尚未完成，请检查凭据状态或先升级节点",
            )),
        )
            .into_response();
    }
    let Some(origin) = super::provisioning::effective_public_panel_url(&state).await else {
        return unavailable();
    };
    let command_node_id = node_id.clone();
    let response = crate::api::node_claim::create_pool_migration_claim(
        admin,
        state,
        peer.0,
        headers,
        crate::api::node_claim::CreateNodeClaimRequest {
            home_group_id: identity_group_id,
            node_id,
        },
    )
    .await;
    if !response.status().is_success() {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 65536).await else {
        return unavailable();
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return unavailable();
    };
    let Some(claim_id) = value["data"]["claim"]["claim_id"].as_str() else {
        return unavailable();
    };
    let command = migration_command(&origin, claim_id, identity_group_id, &command_node_id);
    value["data"]["command"] = command.into();
    let mut response = Json(value).into_response();
    *response.headers_mut() = parts.headers;
    response
        .headers_mut()
        .remove(axum::http::header::CONTENT_LENGTH);
    response
}

pub async fn migration_script() -> Response {
    use sha2::{Digest, Sha256};
    let helper = include_str!("../../../../scripts/relay-node-credential-state.py");
    let script = include_str!("../../../../scripts/relay-node-pool-migrate.py").replace(
        "__STATE_HELPER_SHA256__",
        &format!("{:x}", Sha256::digest(helper.as_bytes())),
    );
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/x-python"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        script,
    )
        .into_response()
}

pub async fn credential_state_script() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/x-python")],
        include_str!("../../../../scripts/relay-node-credential-state.py"),
    )
        .into_response()
}

pub async fn list_nodes(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match node_pool::list_nodes(state.db.as_ref()).await {
        Ok(nodes) => Json(ApiResponse::success(nodes)).into_response(),
        Err(error) => {
            tracing::warn!("pool listing unavailable: {error}");
            unavailable()
        }
    }
}

pub async fn node_health(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match crate::service::node_health::snapshots(state.db.as_ref(), &state.node_connections).await {
        Ok(nodes) => Json(ApiResponse::success(nodes)).into_response(),
        Err(error) => {
            tracing::warn!("node health unavailable: {error}");
            unavailable()
        }
    }
}

pub async fn retirement_preview(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
) -> Response {
    if ReuseEligibleNodeId::parse(&node_id).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match crate::service::node_retirement::preview(&state, group_id, &node_id).await {
        Ok(Some(preview)) => Json(ApiResponse::success(preview)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!("retirement preview unavailable: {error}");
            unavailable()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireNodeRequest {
    expected_version: i64,
    confirm_node_id: String,
    confirm_online: bool,
    reason: String,
}

pub async fn retire_node(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
    Json(request): Json<RetireNodeRequest>,
) -> Response {
    if ReuseEligibleNodeId::parse(&node_id).is_err()
        || request.confirm_node_id != node_id
        || request.expected_version < 0
        || request.reason.trim().is_empty()
        || request.reason.len() > 500
        || request.reason.chars().any(char::is_control)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _gate = crate::service::node_retirement::RETIREMENT_GATE
        .lock()
        .await;
    let preview = match crate::service::node_retirement::preview(&state, group_id, &node_id).await {
        Ok(Some(preview)) => preview,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return unavailable(),
    };
    if preview.retirement_version != request.expected_version
        || !preview.blockers.is_empty()
        || (preview.online || preview.control_connected) && !request.confirm_online
    {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(
                409,
                "节点状态或引用已变化，请重新预检",
            )),
        )
            .into_response();
    }
    match state
        .db
        .retire_node_pool_identity(
            group_id,
            &node_id,
            request.expected_version,
            admin.user_id,
            request.reason.trim(),
        )
        .await
    {
        Ok(true) => {
            state.node_connections.close_node(group_id, &node_id).await;
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "node_retired",
                "node",
                &node_id,
                &format!("identity_group_id={group_id}"),
            )
            .await;
            Json(ApiResponse::success(())).into_response()
        }
        Ok(false) => StatusCode::CONFLICT.into_response(),
        Err(error) => {
            tracing::warn!("node retirement failed: {error}");
            unavailable()
        }
    }
}

pub async fn retired_nodes(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match crate::service::node_retirement::retired(state.db.as_ref()).await {
        Ok(nodes) => Json(ApiResponse::success(nodes)).into_response(),
        Err(_) => unavailable(),
    }
}

pub async fn credential_transport_diagnostics(
    _admin: AdminOnly,
    State(state): State<AppState>,
    peer: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    let reason =
        crate::api::node_claim::production_claim_transport_failure(&state, peer.0, &headers).await;
    Json(ApiResponse::success(serde_json::json!({
        "ready": reason.is_none(),
        "reason": reason,
        "hint": reason.map(|value| match value {
            "TRUSTED_PROXY_IPS_MISSING_OR_INVALID" => "设置 NODE_CLAIM_TRUSTED_PROXY_IPS 为直接连接 Panel 的反向代理 socket peer 地址",
            "PUBLIC_PANEL_URL_MISSING_OR_INVALID" => "设置有效的 PUBLIC_PANEL_URL 或站点公网面板地址",
            "PUBLIC_PANEL_URL_NOT_HTTPS" => "永久凭据交付需要 HTTPS 公网面板地址",
            "SOCKET_PEER_NOT_TRUSTED_PROXY" => "当前 socket peer 不在 NODE_CLAIM_TRUSTED_PROXY_IPS 中",
            "X_FORWARDED_PROTO_NOT_EXACTLY_HTTPS" => "受信代理必须覆盖为唯一 X-Forwarded-Proto: https",
            _ => "检查受信 HTTPS 反向代理配置",
        }),
    }))).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreNodeRequest {
    expected_version: i64,
    confirm_node_id: String,
}

pub async fn restore_node(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
    Json(request): Json<RestoreNodeRequest>,
) -> Response {
    if ReuseEligibleNodeId::parse(&node_id).is_err()
        || request.confirm_node_id != node_id
        || request.expected_version < 0
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _gate = crate::service::node_retirement::RETIREMENT_GATE
        .lock()
        .await;
    match state
        .db
        .restore_node_pool_identity(group_id, &node_id, request.expected_version)
        .await
    {
        Ok(true) => {
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "node_restored",
                "node",
                &node_id,
                &format!("identity_group_id={group_id}"),
            )
            .await;
            Json(ApiResponse::success(())).into_response()
        }
        Ok(false) => StatusCode::CONFLICT.into_response(),
        Err(_) => unavailable(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameNode {
    display_name: String,
}

pub async fn rename_node(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
    Json(request): Json<RenameNode>,
) -> Response {
    let name = request.display_name.trim();
    if ReuseEligibleNodeId::parse(&node_id).is_err()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::<()>::error(422, "节点名称或身份无效")),
        )
            .into_response();
    }
    match state
        .db
        .rename_node_pool_node(group_id, &node_id, name)
        .await
    {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(404, "节点不存在")),
        )
            .into_response(),
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(_) => unavailable(),
    }
}

pub async fn group_nodes(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match node_pool::list_nodes(state.db.as_ref()).await {
        Ok(nodes) => Json(ApiResponse::success(
            nodes
                .into_iter()
                .filter(|n| n.memberships.iter().any(|m| m.group_id == group_id))
                .collect::<Vec<_>>(),
        ))
        .into_response(),
        Err(_) => unavailable(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRequest {
    pub identity_group_id: i64,
    pub node_id: String,
}

async fn business_group_available(state: &AppState, group_id: i64) -> Result<bool, ()> {
    if state.db.node_pool_system_group_id().await.map_err(|_| ())? == Some(group_id) {
        return Ok(false);
    }
    Ok(
        GroupRepository::find_by_id(state.db.as_ref(), group_id, &ResourceScope::All)
            .await
            .map_err(|_| ())?
            .is_some_and(|g| g.group_type == "in"),
    )
}

pub async fn preview_member(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(req): Json<MembershipRequest>,
) -> Response {
    if business_group_available(&state, group_id).await != Ok(true) {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(409, "目标入口分组不可用")),
        )
            .into_response();
    }
    crate::api::admin::preview_candidate_binding(
        admin,
        State(state),
        Json(crate::api::admin::CreateNodeReuseBindingRequest {
            reusing_group_id: group_id,
            home_group_id: req.identity_group_id,
            node_id: req.node_id,
        }),
    )
    .await
}

pub async fn add_member(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(req): Json<MembershipRequest>,
) -> Response {
    if business_group_available(&state, group_id).await != Ok(true) {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(409, "目标入口分组不可用")),
        )
            .into_response();
    }
    crate::api::admin::create_binding(
        admin,
        State(state),
        Json(crate::api::admin::CreateNodeReuseBindingRequest {
            reusing_group_id: group_id,
            home_group_id: req.identity_group_id,
            node_id: req.node_id,
        }),
    )
    .await
}

pub async fn remove_member(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, identity_group_id, node_id)): Path<(i64, i64, String)>,
) -> Response {
    if group_id == identity_group_id {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(409, "此节点原有分组不能在此移除")),
        )
            .into_response();
    }
    crate::api::admin::delete_binding(
        admin,
        State(state),
        Path((group_id, identity_group_id, node_id)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        diagnose::DiagnoseRegistry, node_deploy::DeploymentRegistry,
        node_ops::NodeOperationRegistry, system::ReleaseCache, ws::NodeConnections,
    };
    use crate::config::Config;
    use crate::db::{repo::KvsRepository, schema::SCHEMA_SQL, sqlite_repo::SqliteRepository};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn fixture() -> (AppState, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("UPDATE users SET username='admin', password='hash', admin=1, must_change_password=0 WHERE id=1")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,username,password,admin) VALUES (2,'member','hash',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_groups(id,name,group_type,token,uid) VALUES (10,'home','in','test-group-token',1)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_groups(id,name,group_type,token,uid) VALUES (20,'candidate','in','candidate-token',1)")
            .execute(&pool).await.unwrap();
        let db = Arc::new(SqliteRepository::new(pool.clone()));
        db.set(
            "node_status:10:LEGACY",
            r#"{"public_ipv4":"192.0.2.10","last_seen":"2000-01-01T00:00:00Z"}"#,
        )
        .await
        .unwrap();
        db.set("node_config_revision:legacy:10:LEGACY", r#"{"revision":7}"#)
            .await
            .unwrap();
        let state = AppState {
            db,
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
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
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (state, pool)
    }

    #[tokio::test]
    async fn retirement_api_requires_confirmation_preserves_authority_and_restores_explicitly() {
        let (state, pool) = fixture().await;
        let preview_response = retirement_preview(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
        )
        .await;
        assert_eq!(preview_response.status(), StatusCode::OK);
        let preview_body = to_bytes(preview_response.into_body(), 65536).await.unwrap();
        let preview: serde_json::Value = serde_json::from_slice(&preview_body).unwrap();
        assert_eq!(preview["data"]["retirement_version"], 0);
        assert_eq!(preview["data"]["blockers"], serde_json::json!([]));
        assert_eq!(
            preview["data"]["warnings"][0],
            "LEGACY_TOKEN_CANNOT_REVOKE_PHYSICAL_NODE"
        );

        let rejected = retire_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(RetireNodeRequest {
                expected_version: 0,
                confirm_node_id: "wrong".into(),
                confirm_online: false,
                reason: "retired host".into(),
            }),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let accepted = retire_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(RetireNodeRequest {
                expected_version: 0,
                confirm_node_id: "LEGACY".into(),
                confirm_online: false,
                reason: "retired host".into(),
            }),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(
            state
                .db
                .get("node_config_revision:legacy:10:LEGACY")
                .await
                .unwrap()
                .as_deref(),
            Some(r#"{"revision":7}"#)
        );
        assert!(state
            .db
            .get("node_status:10:LEGACY")
            .await
            .unwrap()
            .is_some());
        assert!(crate::service::node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .is_empty());
        let retired: String = sqlx::query_scalar(
            "SELECT retirement_state FROM node_pool_nodes WHERE identity_group_id = 10 AND node_id = 'LEGACY'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(retired, "RETIRED");
        let restored = restore_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(RestoreNodeRequest {
                expected_version: 1,
                confirm_node_id: "LEGACY".into(),
            }),
        )
        .await;
        assert_eq!(restored.status(), StatusCode::OK);
        assert_eq!(
            crate::service::node_pool::list_nodes(state.db.as_ref())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn retirement_api_revalidates_version_and_online_confirmation() {
        let (state, _) = fixture().await;
        state
            .db
            .set(
                "node_status:10:LEGACY",
                &serde_json::json!({
                    "last_seen": chrono::Utc::now().to_rfc3339(), "public_ipv4": "203.0.113.5"
                })
                .to_string(),
            )
            .await
            .unwrap();
        let request = |expected_version, confirm_online| RetireNodeRequest {
            expected_version,
            confirm_node_id: "LEGACY".into(),
            confirm_online,
            reason: "decommissioned host".into(),
        };
        let stale = retire_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(request(1, true)),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let unconfirmed = retire_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(request(0, false)),
        )
        .await;
        assert_eq!(unconfirmed.status(), StatusCode::CONFLICT);
        let accepted = retire_node(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path((10, "LEGACY".into())),
            Json(request(0, true)),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert!(crate::service::node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .is_empty());
    }

    fn jwt(user_id: i64, admin: bool) -> String {
        encode(
            &Header::default(),
            &crate::api::middleware::Claims {
                sub: user_id,
                admin,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    async fn active_credential(
        pool: &sqlx::SqlitePool,
        group_id: i64,
        node_id: &str,
        credential_id: &str,
    ) -> crate::node_credential::NodeCredentialSecret {
        let secret = crate::node_credential::NodeCredentialSecret::from_test_bytes([0xa3; 32]);
        let node = ReuseEligibleNodeId::parse(node_id).unwrap();
        let verifier = crate::node_credential::NodeCredentialVerifier::derive(
            credential_id,
            group_id,
            &node,
            &secret,
        );
        sqlx::query("INSERT INTO node_credentials (credential_id,home_group_id,node_id,generation,verifier_format,verifier_version,verifier_data,activated_at)
            VALUES (?,?,?,1,'rp-node-sha256',1,?,datetime('now'))")
            .bind(credential_id).bind(group_id).bind(node_id).bind(verifier.data().as_slice())
            .execute(pool).await.unwrap();
        secret
    }

    async fn completed_claim_with_purpose(
        pool: &sqlx::SqlitePool,
        claim_id: &str,
        credential_id: &str,
        purpose: &str,
    ) {
        let now = "2026-09-27T00:00:00Z";
        sqlx::query("INSERT INTO node_credential_claims (
            claim_id,home_group_id,node_id,secret_verifier_format,secret_verifier_version,secret_verifier_data,
            state,expires_at,claimant_nonce_verifier_format,claimant_nonce_verifier_version,
            claimant_nonce_verifier_data,approved_by,approval_ref,created_at,updated_at,
            claimed_at,credential_pending_at,completed_at)
            VALUES (?,10,'LEGACY','rp-node-claim-sha256',1,?,'COMPLETED',?,
                'rp-node-claim-nonce-sha256',1,?,1,?,?,?, ?,?,?)")
            .bind(claim_id).bind(vec![1_u8;32]).bind(now).bind(vec![2_u8;32])
        .bind(format!("{purpose}:{claim_id}"))
            .bind(now).bind(now).bind(now).bind(now).bind(now)
            .execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO node_credential_deliveries (
            claim_id,home_group_id,node_id,credential_id,credential_verifier_format,
            credential_verifier_version,credential_verifier_data,delivery_nonce_verifier_format,
            delivery_nonce_verifier_version,delivery_nonce_verifier_data,state,authorized_at,
            expires_at,updated_at,credential_generation,proof_verified_at,completed_at)
            VALUES (?,10,'LEGACY',?,'rp-node-sha256',1,?,
                'rp-node-delivery-nonce-sha256',1,?,'COMPLETED',?,?,?,1,?,?)",
        )
        .bind(claim_id)
        .bind(credential_id)
        .bind(vec![3_u8; 32])
        .bind(vec![4_u8; 32])
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn completed_migration_claim(
        pool: &sqlx::SqlitePool,
        claim_id: &str,
        credential_id: &str,
    ) {
        completed_claim_with_purpose(pool, claim_id, credential_id, "node-pool-migration").await;
    }

    fn admin_post(path: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("Authorization", format!("Bearer {}", jwt(1, true)))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn activation_is_not_migration_completion_and_both_add_paths_revalidate() {
        let (state, pool) = fixture().await;
        let claim_id = "12345678-1234-1234-1234-123456789abc";
        let credential_id = "migration-credential";
        let secret = active_credential(&pool, 10, "LEGACY", credential_id).await;
        completed_migration_claim(&pool, claim_id, credential_id).await;
        let node_id = ReuseEligibleNodeId::parse("LEGACY").unwrap();
        let before = state.db.scan_prefix("node_config_").await.unwrap();
        let (_connection, mut broadcast) = state
            .node_connections
            .register(10, Some("LEGACY".into()))
            .await;
        let pending = node_pool::admission_state(state.db.as_ref(), 10, &node_id)
            .await
            .unwrap();
        assert!(pending.credential_active);
        assert!(pending.migration_incomplete);
        assert!(pending.recovery_available);
        assert!(!pending.safe_to_add);
        let listed = node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let legacy = listed.iter().find(|node| node.node_id == "LEGACY").unwrap();
        assert!(legacy.migration_required);
        assert!(legacy.credential_ready);
        assert!(!legacy.safe_to_add);

        let app = crate::api::routes().with_state(state.clone());
        let body = r#"{"identity_group_id":10,"node_id":"LEGACY"}"#;
        for path in ["/admin/groups/20/nodes/preview", "/admin/groups/20/nodes"] {
            let response = app.clone().oneshot(admin_post(path, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT, "{path}");
        }
        let old_api = r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"LEGACY"}"#;
        assert_eq!(
            app.clone()
                .oneshot(admin_post("/admin/node-reuse/bindings", old_api))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let bindings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_reuse_bindings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(bindings, 0);

        let complete_uri = format!("/node-pool/migrations/{claim_id}/complete");
        let complete =
            |claim: &str,
             credential: &str,
             secret: &crate::node_credential::NodeCredentialSecret| {
                Request::builder()
                    .method("POST")
                    .uri(format!("/node-pool/migrations/{claim}/complete"))
                    .header(
                        "Authorization",
                        format!("RelayNodeCredential {}", secret.to_wire_value()),
                    )
                    .header("X-Node-Credential-ID", credential)
                    .header("X-Node-ID", "LEGACY")
                    .body(Body::empty())
                    .unwrap()
            };
        let token_request = Request::builder()
            .method("POST")
            .uri(&complete_uri)
            .header("Authorization", "Bearer test-group-token")
            .header("X-Node-ID", "LEGACY")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(token_request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(complete("wrong-claim", credential_id, &secret))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let wrong_secret =
            crate::node_credential::NodeCredentialSecret::from_test_bytes([0xb4; 32]);
        assert_eq!(
            app.clone()
                .oneshot(complete(claim_id, credential_id, &wrong_secret))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            !node_pool::admission_state(state.db.as_ref(), 10, &node_id)
                .await
                .unwrap()
                .safe_to_add
        );
        sqlx::query(
            "CREATE TRIGGER fail_completion BEFORE INSERT ON kvs
            WHEN NEW.key LIKE 'node_pool_migration_completion:%'
            BEGIN SELECT RAISE(ABORT, 'completion unavailable'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(complete(claim_id, credential_id, &secret))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            !node_pool::admission_state(state.db.as_ref(), 10, &node_id)
                .await
                .unwrap()
                .safe_to_add
        );
        sqlx::query("DROP TRIGGER fail_completion")
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                app.clone()
                    .oneshot(complete(claim_id, credential_id, &secret))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        let ready = node_pool::admission_state(state.db.as_ref(), 10, &node_id)
            .await
            .unwrap();
        assert!(ready.safe_to_add);
        assert!(!ready.migration_incomplete);
        assert_eq!(state.db.scan_prefix("node_config_").await.unwrap(), before);
        assert!(broadcast.try_recv().is_err());

        let fresh = chrono::Utc::now().to_rfc3339();
        state
            .db
            .set(
                "node_status:10:LEGACY",
                &serde_json::json!({
                    "last_seen":fresh,"verified_concrete_node":true,"auth_reload_supported":true
                })
                .to_string(),
            )
            .await
            .unwrap();
        assert!(
            node_pool::list_nodes(state.db.as_ref())
                .await
                .unwrap()
                .iter()
                .find(|node| node.node_id == "LEGACY")
                .unwrap()
                .runtime_verified
        );
        state
            .db
            .set(
                "node_status:10:LEGACY",
                r#"{"last_seen":"2000-01-01T00:00:00Z","verified_concrete_node":true}"#,
            )
            .await
            .unwrap();
        let offline = node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let offline = offline
            .iter()
            .find(|node| node.node_id == "LEGACY")
            .unwrap();
        assert!(!offline.online);
        assert!(!offline.runtime_verified);
        assert!(offline.safe_to_add);
        assert_eq!(
            app.clone()
                .oneshot(admin_post("/admin/groups/20/nodes/preview", body))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(admin_post("/admin/groups/20/nodes", body))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        let bindings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_reuse_bindings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(bindings, 1);
    }

    #[tokio::test]
    async fn recovery_returns_existing_claim_command_without_new_credential() {
        let (state, pool) = fixture().await;
        let claim_id = "12345678-1234-1234-1234-123456789abd";
        active_credential(&pool, 10, "LEGACY", "migration-recovery").await;
        completed_migration_claim(&pool, claim_id, "migration-recovery").await;
        let response = start_migration_after_transport(
            AdminOnly { user_id: 1 },
            state.clone(),
            10,
            "LEGACY".into(),
            axum::extract::ConnectInfo("127.0.0.1:40500".parse().unwrap()),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["claim"]["claim_id"], claim_id);
        assert_eq!(value["data"]["recovery"], true);
        assert!(value["data"]["claim_secret"].is_null());
        assert!(value["data"]["command"]
            .as_str()
            .unwrap()
            .contains(claim_id));
        let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_credential_claims")
            .fetch_one(&pool)
            .await
            .unwrap();
        let credentials: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_credentials")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((claims, credentials), (1, 1));
        assert!(state
            .db
            .get("node_pool_migration_completion:10:LEGACY")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn old_verified_and_new_pool_native_nodes_need_no_historical_migration_record() {
        let (state, pool) = fixture().await;
        let legacy = ReuseEligibleNodeId::parse("LEGACY").unwrap();
        let missing = node_pool::admission_state(state.db.as_ref(), 10, &legacy)
            .await
            .unwrap();
        assert!(!missing.credential_active);
        assert!(!missing.safe_to_add);
        active_credential(&pool, 10, "OLD_VERIFIED", "old-credential").await;
        let old = ReuseEligibleNodeId::parse("OLD_VERIFIED").unwrap();
        assert!(
            !node_pool::admission_state(state.db.as_ref(), 10, &old)
                .await
                .unwrap()
                .safe_to_add,
            "ACTIVE alone is not prior runtime proof"
        );
        state
            .db
            .set(
                "node_status:10:OLD_VERIFIED",
                r#"{"verified_concrete_node":true,"last_seen":"2000-01-01T00:00:00Z"}"#,
            )
            .await
            .unwrap();
        let prior = node_pool::admission_state(state.db.as_ref(), 10, &old)
            .await
            .unwrap();
        assert!(prior.safe_to_add);
        assert!(!prior.migration_incomplete);

        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        active_credential(&pool, anchor.id, "POOL_NEW", "pool-credential").await;
        let pool_node = ReuseEligibleNodeId::parse("POOL_NEW").unwrap();
        let pool_ready = node_pool::admission_state(state.db.as_ref(), anchor.id, &pool_node)
            .await
            .unwrap();
        assert!(pool_ready.safe_to_add);
        assert!(!pool_ready.migration_incomplete);
        assert!(state
            .db
            .get("node_pool_migration_completion:10:OLD_VERIFIED")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn previous_pool_claim_without_purpose_is_recoverable_but_prior_verified_credential_remains_ready(
    ) {
        let (state, pool) = fixture().await;
        let claim_id = "12345678-1234-1234-1234-123456789abe";
        active_credential(&pool, 10, "LEGACY", "old-pool-credential").await;
        completed_claim_with_purpose(&pool, claim_id, "old-pool-credential", "admin-api").await;
        let node = ReuseEligibleNodeId::parse("LEGACY").unwrap();
        let incomplete = node_pool::admission_state(state.db.as_ref(), 10, &node)
            .await
            .unwrap();
        assert!(incomplete.credential_active);
        assert!(!incomplete.safe_to_add);
        assert!(incomplete.recovery_available);
        assert_eq!(incomplete.migration_claim_id.as_deref(), Some(claim_id));
        sqlx::query("INSERT INTO node_reuse_bindings(reusing_group_id,home_group_id,node_id) VALUES (20,10,'LEGACY')")
            .execute(&pool).await.unwrap();
        assert!(
            !node_pool::admission_state(state.db.as_ref(), 10, &node)
                .await
                .unwrap()
                .safe_to_add,
            "an existing Binding is not proof of the new Credential"
        );
        let offer = start_migration_after_transport(
            AdminOnly { user_id: 1 },
            state.clone(),
            10,
            "LEGACY".into(),
            axum::extract::ConnectInfo("127.0.0.1:40500".parse().unwrap()),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert_eq!(offer.status(), StatusCode::OK);
        let offer: serde_json::Value =
            serde_json::from_slice(&to_bytes(offer.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(offer["data"]["claim"]["claim_id"], claim_id);
        assert!(offer["data"]["claim_secret"].is_null());
        assert!(node_pool::record_migration_completion(
            state.db.as_ref(),
            10,
            &node,
            claim_id,
            "old-pool-credential"
        )
        .await
        .unwrap());
        assert!(
            node_pool::admission_state(state.db.as_ref(), 10, &node)
                .await
                .unwrap()
                .safe_to_add
        );

        let (prior_state, prior_pool) = fixture().await;
        active_credential(&prior_pool, 10, "LEGACY", "historical-credential").await;
        completed_claim_with_purpose(&prior_pool, claim_id, "historical-credential", "admin-api")
            .await;
        prior_state
            .db
            .set(
                "node_config_revision:10:LEGACY",
                &serde_json::json!({
                    "revision":3,"fingerprint":"a".repeat(64)
                })
                .to_string(),
            )
            .await
            .unwrap();
        let prior = node_pool::admission_state(prior_state.db.as_ref(), 10, &node)
            .await
            .unwrap();
        assert!(prior.safe_to_add);
        assert!(!prior.migration_incomplete);
        assert!(prior_state
            .db
            .get("node_pool_migration_completion:10:LEGACY")
            .await
            .unwrap()
            .is_none());
        for _ in 0..2 {
            assert!(
                node_pool::record_migration_completion(
                    prior_state.db.as_ref(),
                    10,
                    &node,
                    claim_id,
                    "historical-credential"
                )
                .await
                .unwrap(),
                "verified report/config may race the completion ACK"
            );
        }
    }

    #[tokio::test]
    async fn metadata_api_is_admin_only_and_does_not_touch_config_or_broadcast() {
        let (state, _) = fixture().await;
        let before = state.db.scan_prefix("node_config_").await.unwrap();
        let (_connection, mut broadcast) = state
            .node_connections
            .register(10, Some("LEGACY".into()))
            .await;
        let app = crate::api::routes().with_state(state.clone());
        let request = |path: &str, token: &str| {
            Request::builder()
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request("/admin/node-pool/nodes", &jwt(2, false)))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = app
            .clone()
            .oneshot(request("/admin/node-pool/nodes", &jwt(1, true)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"][0]["node_id"], "LEGACY");
        assert_eq!(value["data"][0]["credential_ready"], false);
        let rename = Request::builder()
            .method("PATCH")
            .uri("/admin/node-pool/nodes/10/LEGACY")
            .header("Authorization", format!("Bearer {}", jwt(1, true)))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"display_name":"Tokyo relay"}"#))
            .unwrap();
        assert_eq!(app.oneshot(rename).await.unwrap().status(), StatusCode::OK);
        assert_eq!(state.db.scan_prefix("node_config_").await.unwrap(), before);
        assert!(
            broadcast.try_recv().is_err(),
            "metadata must not broadcast config_changed"
        );
    }

    #[tokio::test]
    async fn legacy_migration_requires_reported_reload_capability() {
        let (state, pool) = fixture().await;
        let response = start_migration_after_transport(
            AdminOnly { user_id: 1 },
            state,
            10,
            "LEGACY".into(),
            axum::extract::ConnectInfo("127.0.0.1:40500".parse().unwrap()),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_credential_claims")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(claims, 0);
    }

    #[tokio::test]
    async fn system_anchor_is_rejected_by_business_routing_endpoints() {
        let (state, _) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-test-token")
            .await
            .unwrap();
        let app = crate::api::routes().with_state(state.clone());
        for suffix in [
            "relay-preference",
            "routing-mode",
            "carrier-lines",
            "carrier-affinity",
            "relay-failover",
        ] {
            let request = Request::builder()
                .uri(format!("/groups/{}/{suffix}", anchor.id))
                .header("Authorization", format!("Bearer {}", jwt(1, true)))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "{suffix}"
            );
        }
        assert!(state
            .db
            .get(&format!("relay_preference:{}", anchor.id))
            .await
            .unwrap()
            .is_none());
    }
}
