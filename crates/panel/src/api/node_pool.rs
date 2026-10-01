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
        Ok(true) => Json(ApiResponse::success(())).into_response(),
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
        return unavailable();
    }
    start_migration_after_transport(admin, state, identity_group_id, node_id, peer, headers).await
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

/// Admin-only local retirement. This works for an offline server and never
/// claims that software on the remote host has been uninstalled.
pub async fn delete_node(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((group_id, node_id)): Path<(i64, String)>,
) -> Response {
    if ReuseEligibleNodeId::parse(&node_id).is_err() {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    match state.db.node_pool_system_group_id().await {
        Ok(Some(anchor)) if anchor == group_id => {}
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return unavailable(),
    }
    match node_pool::retire_node(&state, group_id, &node_id).await {
        Ok(Some(needs_attention)) => {
            crate::api::node_ops::supersede_uninstall_after_admin_delete(
                &state, group_id, &node_id,
            )
            .await;
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "delete_pool_node",
                "node",
                &node_id,
                &format!("identity_group_id={group_id}"),
            )
            .await;
            Json(ApiResponse::success(serde_json::json!({
                "warnings": ["EXTERNAL_DNS_NEEDS_ATTENTION"],
                "routing_interrupted": needs_attention
            })))
            .into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!(group_id, node_id, "node retirement failed: {error}");
            unavailable()
        }
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
    async fn deleting_offline_pool_node_revokes_auth_and_cannot_resurrect_from_status() {
        let (state, pool) = fixture().await;
        sqlx::query("INSERT INTO device_groups(id,name,group_type,token,uid) VALUES (30,'z3','in','z3-token',1)")
            .execute(&pool).await.unwrap();
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let id = "12345678-1234-1234-1234-123456789abc";
        let secret = active_credential(&pool, anchor.id, id, "retired-credential").await;
        for group in [20, 30] {
            crate::service::node_reuse::create_binding(state.db.as_ref(), group, anchor.id, id)
                .await
                .unwrap();
        }
        state
            .db
            .set(
                "relay_preference:20",
                &serde_json::json!({
                    "preferred_node_id": id, "pending_node_id": id, "state": "switching",
                    "started_at": "2026-09-30T00:00:00Z", "last_error": null,
                    "dns_records": [], "carrier_policy": {"default_node_id":id, "bindings":[]},
                    "pending_carrier_policy": null, "transaction_kind":"preferred_switch"
                })
                .to_string(),
            )
            .await
            .unwrap();
        state
            .db
            .set(
                &format!("node_status:{}:{id}", anchor.id),
                r#"{"last_seen":"2000-01-01T00:00:00Z","verified_concrete_node":true}"#,
            )
            .await
            .unwrap();
        state
            .db
            .set(
                &format!("node_config_revision:{}:{id}", anchor.id),
                "current",
            )
            .await
            .unwrap();
        let historical = format!("node_config_rule_sources:{}:{id}:7", anchor.id);
        state.db.set(&historical, r#"{"100":20}"#).await.unwrap();
        let before = node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let node = before.iter().find(|node| node.node_id == id).unwrap();
        assert!(node.pool_native && !node.online && node.safe_to_add);
        assert_eq!(node.memberships.len(), 2);
        let (_other_conn, mut other_rx) = state
            .node_connections
            .register(anchor.id, Some("other-node".into()))
            .await;
        let (_retired_conn, mut retired_rx) = state
            .node_connections
            .register(anchor.id, Some(id.into()))
            .await;

        let app = crate::api::routes().with_state(state.clone());
        let delete = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/node-pool/nodes/{}/{id}", anchor.id))
            .header("Authorization", format!("Bearer {}", jwt(1, true)))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(delete).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(
            retired_rx.recv().await.is_none(),
            "retired WS sender is closed"
        );
        assert!(
            other_rx.try_recv().is_err(),
            "sibling WS remains registered"
        );
        assert!(node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .iter()
            .all(|n| n.node_id != id));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM node_reuse_bindings WHERE home_group_id=? AND node_id=?"
            )
            .bind(anchor.id)
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert!(state.db.get(&historical).await.unwrap().is_some());
        let preference = crate::service::relay_preference::load_preference(state.db.as_ref(), 20)
            .await
            .unwrap();
        assert_eq!(preference.preferred_node_id, None);
        assert_eq!(preference.pending_node_id, None);
        assert_eq!(preference.carrier_policy.default_node_id, None);
        assert!(state
            .db
            .get(&format!("node_config_revision:{}:{id}", anchor.id))
            .await
            .unwrap()
            .is_none());
        let parsed = ReuseEligibleNodeId::parse(id).unwrap();
        assert!(
            !state
                .db
                .set_verified_node_status_if_active(
                    anchor.id,
                    &parsed,
                    "retired-credential",
                    r#"{"last_seen":"2026-09-30T00:00:00Z"}"#
                )
                .await
                .unwrap(),
            "a report authenticated before retirement cannot write after it"
        );
        assert!(state
            .db
            .get(&format!("node_status:{}:{id}", anchor.id))
            .await
            .unwrap()
            .is_none());
        let credential_headers = |builder: axum::http::request::Builder| {
            builder
                .header(
                    "Authorization",
                    format!("RelayNodeCredential {}", secret.to_wire_value()),
                )
                .header("X-Node-Credential-ID", "retired-credential")
                .header("X-Node-ID", id)
        };
        let config = credential_headers(Request::builder())
            .uri("/node/config")
            .header(
                "X-Config-Protocol-Version",
                relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(config).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let status = credential_headers(Request::builder()).method("POST").uri("/node/report_status")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"cpu_usage":0,"mem_usage":0,"active_connections":0,"uptime_secs":1,"node_id":"12345678-1234-1234-1234-123456789abc"}"#)).unwrap();
        let response = app.clone().oneshot(status).await.unwrap();
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
            401
        );
        // WS and HTTP share authenticate_node; the route's WebSocketUpgrade
        // extractor needs a real socket and rejects an in-memory oneshot with 426.
        let ws_headers = credential_headers(Request::builder())
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
            .headers;
        assert!(matches!(
            crate::api::node_auth::authenticate_node(&state, &ws_headers).await,
            Err(crate::api::node_auth::NodeAuthError::Unauthorized)
        ));

        // Simulate an already-authenticated report finishing after retirement.
        state
            .db
            .set(&format!("node_status:{}:{id}", anchor.id), "{}")
            .await
            .unwrap();
        node_pool::reconcile_metadata(state.db.as_ref())
            .await
            .unwrap();
        assert!(node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .iter()
            .all(|n| n.node_id != id));
        assert!(state
            .db
            .find_active_node_credential_for_runtime("retired-credential")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn retirement_cancels_pending_bootstrap_and_reinstall_uses_fresh_identity() {
        let (state, pool) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let old_id = "12345678-1234-1234-1234-123456789abc";
        let new_id = "12345678-1234-1234-1234-123456789abd";
        active_credential(&pool, anchor.id, old_id, "old-credential").await;
        node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let now = "2026-09-30T00:00:00Z";
        sqlx::query("INSERT INTO manual_bootstrap_enrollments(id,secret_verifier,group_id,profile,state,created_by,created_at,updated_at,expires_at)
                     VALUES (?, 'test-verifier', ?, 'reality_camouflage','CLAIMED',1,?,?,?)")
            .bind(old_id).bind(anchor.id).bind(now).bind(now).bind(now)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO node_credential_claims(claim_id,home_group_id,node_id,secret_verifier_format,secret_verifier_version,secret_verifier_data,state,expires_at,claimant_nonce_verifier_format,claimant_nonce_verifier_version,claimant_nonce_verifier_data,approved_by,approval_ref,created_at,updated_at,claimed_at,credential_pending_at)
                     VALUES (?, ?, ?, 'rp-node-claim-sha256',1,?, 'CREDENTIAL_PENDING',?, 'rp-node-claim-nonce-sha256',1,?,1,?,?,?, ?,?)")
            .bind(old_id).bind(anchor.id).bind(old_id).bind(vec![1_u8;32]).bind(now)
            .bind(vec![2_u8;32]).bind(format!("node-pool-bootstrap:{old_id}"))
            .bind(now).bind(now).bind(now).bind(now)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO node_credential_deliveries(claim_id,home_group_id,node_id,credential_id,credential_verifier_format,credential_verifier_version,credential_verifier_data,delivery_nonce_verifier_format,delivery_nonce_verifier_version,delivery_nonce_verifier_data,state,authorized_at,expires_at,updated_at)
                     VALUES (?,?,?,'pending-credential','rp-node-sha256',1,?,'rp-node-delivery-nonce-sha256',1,?,'PREPARED',?,?,?)")
            .bind(old_id).bind(anchor.id).bind(old_id).bind(vec![3_u8;32]).bind(vec![4_u8;32])
            .bind(now).bind(now).bind(now).execute(&pool).await.unwrap();

        assert!(node_pool::retire_node(&state, anchor.id, old_id)
            .await
            .unwrap()
            .is_some());
        let claim: String =
            sqlx::query_scalar("SELECT state FROM node_credential_claims WHERE claim_id=?")
                .bind(old_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let delivery: String =
            sqlx::query_scalar("SELECT state FROM node_credential_deliveries WHERE claim_id=?")
                .bind(old_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let enrollment: String =
            sqlx::query_scalar("SELECT state FROM manual_bootstrap_enrollments WHERE id=?")
                .bind(old_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (claim.as_str(), delivery.as_str(), enrollment.as_str()),
            ("CANCELLED", "CANCELLED", "FAILED")
        );
        assert!(state
            .db
            .find_active_node_credential_for_runtime("old-credential")
            .await
            .unwrap()
            .is_none());
        assert!(node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .iter()
            .all(|node| node.node_id != old_id));
        active_credential(&pool, anchor.id, new_id, "new-credential").await;
        let current = node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        assert!(current
            .iter()
            .any(|node| node.node_id == new_id && node.pool_native && node.safe_to_add));
        assert!(current.iter().all(|node| node.node_id != old_id));
        assert!(
            node_pool::retire_node(&state, anchor.id, old_id)
                .await
                .unwrap()
                .is_none(),
            "repeated retirement must not touch the reinstalled Node"
        );
    }

    #[tokio::test]
    async fn online_pool_node_can_be_deleted_without_remote_ack() {
        let (state, pool) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let id = "POOL_ONLINE";
        active_credential(&pool, anchor.id, id, "online-credential").await;
        state.db.set(&format!("node_status:{}:{id}", anchor.id),
            &serde_json::json!({"last_seen":chrono::Utc::now().to_rfc3339(),"verified_concrete_node":true}).to_string())
            .await.unwrap();
        let before = node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        assert!(before.iter().any(|node| node.node_id == id && node.online));
        let (_, mut channel) = state
            .node_connections
            .register(anchor.id, Some(id.into()))
            .await;
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/node-pool/nodes/{}/{id}", anchor.id))
            .header("Authorization", format!("Bearer {}", jwt(1, true)))
            .body(Body::empty())
            .unwrap();
        let response = crate::api::routes()
            .with_state(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(channel.recv().await.is_none());
        assert!(state
            .db
            .find_active_node_credential_for_runtime("online-credential")
            .await
            .unwrap()
            .is_none());
        assert!(node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .iter()
            .all(|node| node.node_id != id));
    }

    #[tokio::test]
    async fn retirement_database_error_rolls_back_credential_and_membership() {
        let (state, pool) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let id = "POOL_ROLLBACK";
        active_credential(&pool, anchor.id, id, "rollback-credential").await;
        crate::service::node_reuse::create_binding(state.db.as_ref(), 20, anchor.id, id)
            .await
            .unwrap();
        node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let routing =
            serde_json::to_string(&crate::service::relay_preference::RelayPreferenceState {
                preferred_node_id: Some(id.into()),
                ..Default::default()
            })
            .unwrap();
        state.db.set("relay_preference:20", &routing).await.unwrap();
        let failover =
            serde_json::to_string(&crate::service::relay_failover::RelayFailoverPolicy {
                excluded_failed_node_ids: [id.to_string()].into(),
                last_to_node_id: Some(id.into()),
                ..Default::default()
            })
            .unwrap();
        state.db.set("relay_failover:20", &failover).await.unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_pool_retire BEFORE DELETE ON node_pool_nodes
                     BEGIN SELECT RAISE(ABORT, 'injected pool deletion error'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/node-pool/nodes/{}/{id}", anchor.id))
            .header("Authorization", format!("Bearer {}", jwt(1, true)))
            .body(Body::empty())
            .unwrap();
        let response = crate::api::routes()
            .with_state(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            state.db.get("relay_preference:20").await.unwrap(),
            Some(routing)
        );
        assert_eq!(
            state.db.get("relay_failover:20").await.unwrap(),
            Some(failover)
        );
        assert!(state
            .db
            .find_active_node_credential_for_runtime("rollback-credential")
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            state
                .db
                .list_reusing_group_ids_for_node(anchor.id, id)
                .await
                .unwrap(),
            vec![20]
        );
        assert!(node_pool::list_nodes(state.db.as_ref())
            .await
            .unwrap()
            .iter()
            .any(|node| node.node_id == id));
    }

    #[tokio::test]
    async fn retirement_preserves_same_node_id_in_another_identity() {
        let (state, pool) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let id = "POOL_COLLISION";
        active_credential(&pool, anchor.id, id, "pool-collision").await;
        active_credential(&pool, 10, id, "legacy-collision").await;
        state.db.register_node_pool_identity(10, id).await.unwrap();
        crate::service::node_reuse::create_binding(state.db.as_ref(), 20, anchor.id, id)
            .await
            .unwrap();
        node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let routing =
            serde_json::to_string(&crate::service::relay_preference::RelayPreferenceState {
                preferred_node_id: Some(id.into()),
                ..Default::default()
            })
            .unwrap();
        for group in [10, 20] {
            state
                .db
                .set(&format!("relay_preference:{group}"), &routing)
                .await
                .unwrap();
        }
        crate::service::node_reuse::delete_binding(state.db.as_ref(), 20, anchor.id, id)
            .await
            .unwrap();
        assert!(node_pool::retire_node(&state, anchor.id, id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            state.db.get("relay_preference:10").await.unwrap(),
            Some(routing)
        );
        assert_eq!(
            crate::service::relay_preference::load_preference(state.db.as_ref(), 20)
                .await
                .unwrap()
                .preferred_node_id,
            None
        );
        assert!(state
            .db
            .find_active_node_credential_for_runtime("legacy-collision")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn retirement_preserves_ambiguous_routing_for_a_surviving_member() {
        let (state, pool) = fixture().await;
        let anchor = state
            .db
            .ensure_node_pool_system_group(1, "pool-token")
            .await
            .unwrap();
        let id = "POOL_SHARED_ID";
        active_credential(&pool, anchor.id, id, "pool-shared").await;
        active_credential(&pool, 10, id, "legacy-shared").await;
        sqlx::query("INSERT INTO node_reuse_bindings(reusing_group_id,home_group_id,node_id) VALUES (20,?,?),(20,10,?)")
            .bind(anchor.id).bind(id).bind(id).execute(&pool).await.unwrap();
        node_pool::list_nodes(state.db.as_ref()).await.unwrap();
        let routing =
            serde_json::to_string(&crate::service::relay_preference::RelayPreferenceState {
                preferred_node_id: Some(id.into()),
                ..Default::default()
            })
            .unwrap();
        state.db.set("relay_preference:20", &routing).await.unwrap();
        assert_eq!(
            node_pool::retire_node(&state, anchor.id, id).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            state.db.get("relay_preference:20").await.unwrap(),
            Some(routing)
        );
        assert!(state
            .db
            .find_node_reuse_binding(20, anchor.id, id)
            .await
            .unwrap()
            .is_none());
        assert!(state
            .db
            .find_node_reuse_binding(20, 10, id)
            .await
            .unwrap()
            .is_some());
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
