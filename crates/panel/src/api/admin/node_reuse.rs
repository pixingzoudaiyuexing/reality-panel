use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::NodeReuseBindingCreateRejection;
use crate::service::node_reuse::{
    self, BindingMutationOutcome, BindingMutationResult, EffectiveConfigPreview,
    NodeReuseBindingStatus, NodeReuseIdentityError, NodeReuseServiceError,
};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeReuseBindingRequest {
    pub reusing_group_id: i64,
    pub home_group_id: i64,
    pub node_id: String,
}

fn error_response(error: NodeReuseServiceError) -> Response {
    let (status, code, message) = match error {
        NodeReuseServiceError::Identity(NodeReuseIdentityError::SelfReuse) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            422,
            "SELF_REUSE_NOT_ALLOWED".to_string(),
        ),
        NodeReuseServiceError::Identity(NodeReuseIdentityError::InvalidNodeId(_)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            422,
            "INVALID_NODE_ID".to_string(),
        ),
        NodeReuseServiceError::AdmissionRejected(reason) => match reason {
            NodeReuseBindingCreateRejection::ReusingGroupMissing => (
                StatusCode::NOT_FOUND,
                404,
                "REUSING_GROUP_NOT_FOUND".to_string(),
            ),
            NodeReuseBindingCreateRejection::HomeGroupMissing => (
                StatusCode::NOT_FOUND,
                404,
                "HOME_GROUP_NOT_FOUND".to_string(),
            ),
            NodeReuseBindingCreateRejection::ReusingGroupNotInbound => (
                StatusCode::CONFLICT,
                409,
                "REUSING_GROUP_NOT_INBOUND".to_string(),
            ),
            NodeReuseBindingCreateRejection::HomeGroupNotInbound => (
                StatusCode::CONFLICT,
                409,
                "HOME_GROUP_NOT_INBOUND".to_string(),
            ),
            NodeReuseBindingCreateRejection::ActiveCredentialMissing => (
                StatusCode::CONFLICT,
                409,
                "CURRENT_ACTIVE_CREDENTIAL_REQUIRED".to_string(),
            ),
        },
        NodeReuseServiceError::BindingChangedDuringRead => (
            StatusCode::CONFLICT,
            409,
            "BINDING_CHANGED_DURING_READ".to_string(),
        ),
        NodeReuseServiceError::InvalidStoredSource { group_id, reason } => (
            StatusCode::CONFLICT,
            409,
            format!("INVALID_STORED_SOURCE:{group_id}:{reason}"),
        ),
        NodeReuseServiceError::PreviewSourceConfigInvalid { group_id, reason } => {
            tracing::warn!(group_id, reason = %reason, "node reuse preview source config is invalid");
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                422,
                format!("PREVIEW_SOURCE_CONFIG_INVALID:{group_id}"),
            )
        }
        NodeReuseServiceError::Database(error) => {
            tracing::error!("node reuse management database failure: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                500,
                "NODE_REUSE_DATABASE_ERROR".to_string(),
            )
        }
    };
    (status, Json(ApiResponse::<()>::error(code, &message))).into_response()
}

fn success_response<T: Serialize>(status: StatusCode, data: T) -> Response {
    (status, Json(ApiResponse::success(data))).into_response()
}

pub async fn create_binding(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<CreateNodeReuseBindingRequest>,
) -> Response {
    match node_reuse::create_binding(
        state.db.as_ref(),
        request.reusing_group_id,
        request.home_group_id,
        &request.node_id,
    )
    .await
    {
        Ok(result) => {
            let status = if result.outcome == BindingMutationOutcome::Created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            success_response(status, result)
        }
        Err(error) => error_response(error),
    }
}

pub async fn delete_binding(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((reusing_group_id, home_group_id, node_id)): Path<(i64, i64, String)>,
) -> Response {
    match node_reuse::delete_binding(state.db.as_ref(), reusing_group_id, home_group_id, &node_id)
        .await
    {
        Ok(result) => success_response(StatusCode::OK, result),
        Err(error) => error_response(error),
    }
}

pub async fn get_binding(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((reusing_group_id, home_group_id, node_id)): Path<(i64, i64, String)>,
) -> Response {
    match node_reuse::get_binding_status(
        state.db.as_ref(),
        reusing_group_id,
        home_group_id,
        &node_id,
    )
    .await
    {
        Ok(Some(status)) => success_response(StatusCode::OK, status),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<NodeReuseBindingStatus>::error(
                404,
                "BINDING_NOT_FOUND",
            )),
        )
            .into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn list_bindings_for_node(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((home_group_id, node_id)): Path<(i64, String)>,
) -> Response {
    match node_reuse::list_bindings_for_node(state.db.as_ref(), home_group_id, &node_id).await {
        Ok(bindings) => success_response(StatusCode::OK, bindings),
        Err(error) => error_response(error),
    }
}

pub async fn list_reused_nodes_for_group(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(reusing_group_id): Path<i64>,
) -> Response {
    match node_reuse::list_bindings_for_reusing_group(state.db.as_ref(), reusing_group_id).await {
        Ok(bindings) => success_response(StatusCode::OK, bindings),
        Err(error) => error_response(error),
    }
}

pub async fn preview_effective_config(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((home_group_id, node_id)): Path<(i64, String)>,
) -> Response {
    match node_reuse::preview_effective_config_for_node(state.db.as_ref(), home_group_id, &node_id)
        .await
    {
        Ok(preview) => success_response(StatusCode::OK, preview),
        Err(error) => error_response(error),
    }
}

// Pin the response types in this module so accidental future changes that make
// them non-serializable fail compilation before reaching a public admin route.
#[allow(dead_code)]
fn _response_type_contract(
    _mutation: BindingMutationResult,
    _status: NodeReuseBindingStatus,
    _preview: EffectiveConfigPreview,
) {
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
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn test_state() -> (AppState, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        for (id, admin) in [(101_i64, 1_i64), (102_i64, 0_i64)] {
            sqlx::query(
                "INSERT INTO users (id, username, password, admin)
                 VALUES (?, ?, 'hash', ?)",
            )
            .bind(id)
            .bind(format!("u{id}"))
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        }
        for gid in [10_i64, 20, 30] {
            sqlx::query(
                "INSERT INTO device_groups (id, name, group_type, token, uid)
                 VALUES (?, ?, 'in', ?, 1)",
            )
            .bind(gid)
            .bind(format!("g{gid}"))
            .bind(format!("tok-{gid}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO node_credentials
             (credential_id, home_group_id, node_id, generation,
              verifier_format, verifier_version, verifier_data, activated_at)
             VALUES ('router-active', 10, 'NODE_A', 1,
                     'rp-node-sha256', 1, ?, datetime('now'))",
        )
        .bind(vec![9_u8; 32])
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
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (state, pool)
    }

    fn token(sub: i64, admin: bool) -> String {
        encode(
            &Header::default(),
            &Claims {
                sub,
                admin,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    fn create_request(auth: Option<&str>, body: String) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/admin/node-reuse/bindings")
            .header("content-type", "application/json");
        if let Some(auth) = auth {
            builder = builder.header("Authorization", auth);
        }
        builder.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn admin_router_auth_and_exact_binding_lifecycle_contract() {
        let (state, pool) = test_state().await;
        for (credential_id, node_id, generation, activated, revoked) in [
            ("router-inactive", "NODE_INACTIVE", 1_i64, false, false),
            ("router-revoked", "NODE_REVOKED", 1, true, true),
            ("router-history", "NODE_HISTORY", 1, true, true),
            ("router-current-old", "NODE_CURRENT", 1, true, true),
            ("router-current-new", "NODE_CURRENT", 2, true, false),
            ("router-db", "NODE_DB", 1, true, false),
        ] {
            sqlx::query(
                "INSERT INTO node_credentials
                 (credential_id, home_group_id, node_id, generation,
                  verifier_format, verifier_version, verifier_data, activated_at, revoked_at)
                 VALUES (?, 10, ?, ?, 'rp-node-sha256', 1, ?,
                         CASE WHEN ? THEN datetime('now') ELSE NULL END,
                         CASE WHEN ? THEN datetime('now') ELSE NULL END)",
            )
            .bind(credential_id)
            .bind(node_id)
            .bind(generation)
            .bind(vec![generation as u8; 32])
            .bind(activated)
            .bind(revoked)
            .execute(&pool)
            .await
            .unwrap();
        }
        state
            .db
            .set(
                "node_status:10:LEGACY_ONLY",
                r#"{"public_ipv4":"198.51.100.77"}"#,
            )
            .await
            .unwrap();

        let (_conn_id, mut config_rx) = state
            .node_connections
            .register(10, Some("NODE_A".into()))
            .await;
        let app = crate::api::routes().with_state(state);
        let body = r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"NODE_A"}"#;

        assert_eq!(
            app.clone()
                .oneshot(create_request(None, body.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(create_request(
                    Some(&format!("Bearer {}", token(102, false))),
                    body.into(),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(create_request(Some("Bearer tok-10"), body.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(create_request(
                    Some("RelayNodeCredential rpn1_not-an-admin-session"),
                    body.into(),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let admin = format!("Bearer {}", token(101, true));
        assert_eq!(
            app.clone()
                .oneshot(create_request(Some(&admin), body.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            app.clone()
                .oneshot(create_request(Some(&admin), body.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(
            config_rx.try_recv().is_err(),
            "Binding create/duplicate must not broadcast config_changed"
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/node-reuse/bindings/20/10/NODE_A")
                    .header("Authorization", &admin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        for forbidden in ["tok-10", "rpn1_", "verifier_data", "NODE_TOKEN"] {
            assert!(!response_body.contains(forbidden));
        }

        for uri in [
            "/admin/node-reuse/nodes/10/NODE_A/bindings",
            "/admin/node-reuse/groups/20/nodes",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("Authorization", &admin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["data"].as_array().unwrap().len(), 1);
        }

        for expected in [
            BindingMutationOutcome::Deleted,
            BindingMutationOutcome::Missing,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/admin/node-reuse/bindings/20/10/NODE_A")
                        .header("Authorization", &admin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value["data"]["outcome"],
                serde_json::to_value(expected).unwrap()
            );
        }
        assert!(
            config_rx.try_recv().is_err(),
            "Binding delete/idempotent delete must not broadcast config_changed"
        );

        let self_reuse = r#"{"reusing_group_id":10,"home_group_id":10,"node_id":"NODE_A"}"#;
        assert_eq!(
            app.clone()
                .oneshot(create_request(Some(&admin), self_reuse.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        for (body, expected) in [
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_X"}"#,
                StatusCode::CONFLICT,
            ),
            (
                r#"{"reusing_group_id":999,"home_group_id":10,"node_id":"NODE_A"}"#,
                StatusCode::NOT_FOUND,
            ),
            (
                r#"{"reusing_group_id":20,"home_group_id":999,"node_id":"NODE_A"}"#,
                StatusCode::NOT_FOUND,
            ),
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":" bad id "}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_INACTIVE"}"#,
                StatusCode::CONFLICT,
            ),
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_REVOKED"}"#,
                StatusCode::CONFLICT,
            ),
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_HISTORY"}"#,
                StatusCode::CONFLICT,
            ),
            (
                r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"LEGACY_ONLY"}"#,
                StatusCode::CONFLICT,
            ),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(create_request(Some(&admin), body.into()))
                    .await
                    .unwrap()
                    .status(),
                expected,
                "unexpected status for {body}"
            );
        }

        sqlx::query("UPDATE device_groups SET group_type = 'out' WHERE id = 30")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(create_request(
                    Some(&admin),
                    r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_CURRENT"}"#.into(),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        sqlx::query("UPDATE device_groups SET group_type = 'in' WHERE id = 30")
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            app.clone()
                .oneshot(create_request(
                    Some(&admin),
                    r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_CURRENT"}"#.into(),
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );

        sqlx::query(
            "CREATE TRIGGER fail_s4a_binding_insert
             BEFORE INSERT ON node_reuse_bindings
             WHEN NEW.node_id = 'NODE_DB'
             BEGIN SELECT RAISE(ABORT, 'forced-secret-db-detail'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        let response = app
            .clone()
            .oneshot(create_request(
                Some(&admin),
                r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"NODE_DB"}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let response_body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!response_body.contains("forced-secret-db-detail"));
        assert!(response_body.contains("NODE_REUSE_DATABASE_ERROR"));
        sqlx::query("DROP TRIGGER fail_s4a_binding_insert")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn admin_router_rejects_unknown_and_oversized_json() {
        let (state, _pool) = test_state().await;
        let app = crate::api::routes().with_state(state);
        let admin = format!("Bearer {}", token(101, true));

        let response = app
            .clone()
            .oneshot(create_request(
                Some(&admin),
                r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"NODE_A","credential_secret":"must-not-echo"}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("must-not-echo"));

        let oversized = serde_json::json!({
            "reusing_group_id": 20,
            "home_group_id": 10,
            "node_id": "A".repeat(5000),
        })
        .to_string();
        assert_eq!(
            app.oneshot(create_request(Some(&admin), oversized))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
