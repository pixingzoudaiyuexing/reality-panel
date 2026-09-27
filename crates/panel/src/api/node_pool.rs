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

pub async fn start_migration(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path((identity_group_id, node_id)): Path<(i64, String)>,
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
    if !nodes.iter().any(|n| {
        n.identity_group_id == identity_group_id
            && n.node_id == node_id
            && n.migration_required
            && n.auth_reload_supported
    }) {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()>::error(
                409,
                "请先升级节点到支持安全迁移的版本",
            )),
        )
            .into_response();
    }
    let Some(origin) = super::provisioning::effective_public_panel_url(&state).await else {
        return unavailable();
    };
    let command_node_id = node_id.clone();
    let response = crate::api::node_claim::create_claim(
        admin,
        State(state),
        peer,
        headers,
        Json(crate::api::node_claim::CreateNodeClaimRequest {
            home_group_id: identity_group_id,
            node_id,
        }),
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
    let command = format!(
        "curl --proto '=https' -fsS '{}' | python3 - --claim-id '{}' --identity-group-id {} --node-id '{}'",
        format!("{origin}/api/v1/node-pool/migrate.py").replace('\'', "'\\''"),
        claim_id,
        identity_group_id,
        command_node_id,
    );
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
        let response = start_migration(
            AdminOnly { user_id: 1 },
            State(state),
            Path((10, "LEGACY".into())),
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
