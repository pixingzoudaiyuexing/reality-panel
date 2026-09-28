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
            NodeReuseBindingCreateRejection::MigrationIncomplete => (
                StatusCode::CONFLICT,
                409,
                "NODE_POOL_MIGRATION_INCOMPLETE".to_string(),
            ),
            NodeReuseBindingCreateRejection::NodeRetired => {
                (StatusCode::CONFLICT, 409, "NODE_RETIRED".to_string())
            }
            NodeReuseBindingCreateRejection::AmbiguousGroupNodeId => (
                StatusCode::CONFLICT,
                409,
                "AMBIGUOUS_GROUP_NODE_ID".to_string(),
            ),
        },
        NodeReuseServiceError::BindingChangedDuringRead => (
            StatusCode::CONFLICT,
            409,
            "BINDING_CHANGED_DURING_READ".to_string(),
        ),
        NodeReuseServiceError::CandidateConflicts(conflicts) => {
            return (
                StatusCode::CONFLICT,
                Json(ApiResponse {
                    code: 409,
                    message: "CONFIG_CONFLICT".into(),
                    data: Some(conflicts),
                }),
            )
                .into_response();
        }
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

pub async fn preview_candidate_binding(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<CreateNodeReuseBindingRequest>,
) -> Response {
    match node_reuse::preview_candidate_binding(
        state.db.as_ref(),
        request.reusing_group_id,
        request.home_group_id,
        &request.node_id,
    )
    .await
    {
        Ok(preview) => success_response(StatusCode::OK, preview),
        Err(error) => error_response(error),
    }
}

pub async fn runtime_status_for_node(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((home_group_id, node_id)): Path<(i64, String)>,
) -> Response {
    if let Err(error) = crate::node_identity::ReuseEligibleNodeId::parse(&node_id) {
        return error_response(NodeReuseServiceError::Identity(
            NodeReuseIdentityError::InvalidNodeId(error),
        ));
    }
    let key = format!("node_status:{home_group_id}:{node_id}");
    let raw = match state.db.get(&key).await {
        Ok(raw) => raw,
        Err(error) => return error_response(NodeReuseServiceError::Database(error)),
    };
    let online = raw
        .as_deref()
        .is_some_and(|value| crate::api::stats::status_is_online(value, chrono::Utc::now()));
    let certificate_state_dir = std::path::PathBuf::from(state.config.certificate_state_dir());
    match node_reuse::runtime_status_for_node(
        state.db.as_ref(),
        &certificate_state_dir,
        state.config.node_reuse_runtime_enabled,
        home_group_id,
        &node_id,
        raw.as_deref(),
        online,
    )
    .await
    {
        Ok(status) => success_response(StatusCode::OK, status),
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
        sqlx::query("INSERT INTO kvs(key,value) VALUES ('node_status:10:NODE_A', ?)")
            .bind(r#"{"verified_concrete_node":true}"#)
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

    async fn config_authority_rows(state: &AppState) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        for prefix in [
            "node_config_revision:",
            "node_config_rule_sources:",
            "node_config_rule_owners:",
        ] {
            rows.extend(state.db.scan_prefix(prefix).await.unwrap());
        }
        rows.sort();
        rows
    }

    async fn verified_snapshot(state: &AppState) -> relay_shared::protocol::NodeConfigSnapshot {
        crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
            state.db.as_ref(),
            &std::path::PathBuf::from(state.config.certificate_state_dir()),
            10,
            Some("NODE_A"),
            true,
            crate::service::node_config::NodeReuseRuntimeDeliveryMode::EffectiveConfig,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn revision_authority_survives_legacy_verified_and_reverse_transitions() {
        let (state, _) = test_state().await;
        let initial = verified_snapshot(&state).await;
        assert_eq!(initial.config_revision, 1);
        let concrete_key = "node_config_revision:10:NODE_A";
        let legacy_key = "node_config_revision:legacy:10:NODE_A";
        let mut lower: serde_json::Value =
            serde_json::from_str(&state.db.get(concrete_key).await.unwrap().unwrap()).unwrap();
        lower["revision"] = serde_json::json!(15);
        state
            .db
            .set(concrete_key, &lower.to_string())
            .await
            .unwrap();
        let mut higher = lower.clone();
        higher["revision"] = serde_json::json!(20);
        state.db.set(legacy_key, &higher.to_string()).await.unwrap();

        let before_plan = config_authority_rows(&state).await;
        let predicted_same =
            crate::service::node_config::plan_effective_config_snapshot_for_status(
                state.db.as_ref(),
                &std::path::PathBuf::from(state.config.certificate_state_dir()),
                10,
                "NODE_A",
            )
            .await
            .unwrap();
        assert_eq!(predicted_same.snapshot.config_revision, 20);
        assert!(!predicted_same.authority_committed);
        assert_eq!(config_authority_rows(&state).await, before_plan);
        let same = verified_snapshot(&state).await;
        assert_eq!(
            same.config_revision, 20,
            "same semantics may reuse the highest legacy revision"
        );
        assert_eq!(same.config_fingerprint, initial.config_fingerprint);

        node_reuse::create_binding(state.db.as_ref(), 20, 10, "NODE_A")
            .await
            .unwrap();
        let before_changed_plan = config_authority_rows(&state).await;
        let predicted_changed =
            crate::service::node_config::plan_effective_config_snapshot_for_status(
                state.db.as_ref(),
                &std::path::PathBuf::from(state.config.certificate_state_dir()),
                10,
                "NODE_A",
            )
            .await
            .unwrap();
        assert_eq!(predicted_changed.snapshot.config_revision, 21);
        assert!(!predicted_changed.authority_committed);
        assert_eq!(config_authority_rows(&state).await, before_changed_plan);
        let changed = verified_snapshot(&state).await;
        assert_eq!(changed.config_fingerprint, same.config_fingerprint);
        assert_eq!(
            changed.config_revision, 21,
            "membership-only change must exceed legacy high water mark"
        );

        let legacy = crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
            state.db.as_ref(),
            &std::path::PathBuf::from(state.config.certificate_state_dir()),
            10,
            Some("NODE_A"),
            false,
            crate::service::node_config::NodeReuseRuntimeDeliveryMode::HomeOnly,
        )
        .await
        .unwrap();
        assert_eq!(
            legacy.config_revision, 22,
            "reverse transition must also remain monotonic"
        );
        assert_eq!(verified_snapshot(&state).await.config_revision, 23);
    }

    #[tokio::test]
    async fn revision_authority_handles_single_namespace_and_rejects_corrupt_counterpart() {
        let (state, _) = test_state().await;
        let concrete_key = "node_config_revision:10:NODE_A";
        let legacy_key = "node_config_revision:legacy:10:NODE_A";
        assert_eq!(verified_snapshot(&state).await.config_revision, 1);
        let concrete_raw = state.db.get(concrete_key).await.unwrap().unwrap();
        assert_eq!(verified_snapshot(&state).await.config_revision, 1);

        let mut legacy_state: serde_json::Value = serde_json::from_str(&concrete_raw).unwrap();
        legacy_state["revision"] = serde_json::json!(20);
        state.db.delete(concrete_key).await.unwrap();
        state
            .db
            .set(legacy_key, &legacy_state.to_string())
            .await
            .unwrap();
        assert_eq!(verified_snapshot(&state).await.config_revision, 20);

        state.db.set(legacy_key, "not-json").await.unwrap();
        assert!(
            crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
                state.db.as_ref(),
                &std::path::PathBuf::from(state.config.certificate_state_dir()),
                10,
                Some("NODE_A"),
                true,
                crate::service::node_config::NodeReuseRuntimeDeliveryMode::EffectiveConfig,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_status_reads_do_not_commit_authority_and_predict_next_delivery() {
        let (state, pool) = test_state().await;
        let admin = format!("Bearer {}", token(101, true));
        let app = crate::api::routes().with_state(AppState {
            config: Config {
                node_reuse_runtime_enabled: true,
                ..state.config.clone()
            },
            ..state.clone()
        });
        let read = |app: axum::Router| async {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/admin/node-reuse/nodes/10/NODE_A/runtime-status")
                        .header("Authorization", &admin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };
        let bindings_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_reuse_bindings")
            .fetch_one(&pool)
            .await
            .unwrap();
        let status_before = state.db.get("node_status:10:NODE_A").await.unwrap();
        let authority_before = config_authority_rows(&state).await;
        let mut predicted = None;
        for _ in 0..3 {
            let response = read(app.clone()).await;
            assert_eq!(response["data"]["sync_state"], "OFFLINE");
            assert_eq!(config_authority_rows(&state).await, authority_before);
            assert_eq!(
                state.db.get("node_status:10:NODE_A").await.unwrap(),
                status_before
            );
            predicted = Some(response);
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            bindings_before
        );
        let predicted = predicted.unwrap();
        let delivered = verified_snapshot(&state).await;
        assert_eq!(
            predicted["data"]["expected_revision"],
            delivered.config_revision
        );
        assert_eq!(
            predicted["data"]["expected_fingerprint"],
            delivered.config_fingerprint
        );
        let committed = config_authority_rows(&state).await;
        assert_ne!(committed, authority_before);
        let after_delivery = read(app.clone()).await;
        assert_eq!(
            after_delivery["data"]["expected_revision"],
            delivered.config_revision
        );
        assert_eq!(config_authority_rows(&state).await, committed);

        node_reuse::create_binding(state.db.as_ref(), 20, 10, "NODE_A")
            .await
            .unwrap();
        let before_membership_read = config_authority_rows(&state).await;
        let membership_plan = read(app.clone()).await;
        assert_eq!(
            membership_plan["data"]["expected_fingerprint"],
            delivered.config_fingerprint
        );
        assert!(
            membership_plan["data"]["expected_revision"]
                .as_u64()
                .unwrap()
                > delivered.config_revision
        );
        assert_eq!(config_authority_rows(&state).await, before_membership_read);
        let membership_delivery = verified_snapshot(&state).await;
        assert_eq!(
            membership_plan["data"]["expected_revision"],
            membership_delivery.config_revision
        );
        assert_eq!(
            membership_plan["data"]["expected_fingerprint"],
            membership_delivery.config_fingerprint
        );
        let after_membership_delivery = config_authority_rows(&state).await;
        assert_eq!(
            read(app).await["data"]["expected_revision"],
            membership_delivery.config_revision
        );
        assert_eq!(
            config_authority_rows(&state).await,
            after_membership_delivery
        );
    }

    #[tokio::test]
    async fn uncommitted_status_prediction_cannot_claim_node_synchronized() {
        let (state, _) = test_state().await;
        let admin = format!("Bearer {}", token(101, true));
        let app = crate::api::routes().with_state(AppState {
            config: Config {
                node_reuse_runtime_enabled: true,
                ..state.config.clone()
            },
            ..state.clone()
        });
        let read = |app: axum::Router| async {
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/admin/node-reuse/nodes/10/NODE_A/runtime-status")
                        .header("Authorization", &admin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            serde_json::from_slice::<serde_json::Value>(
                &to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap()
        };
        let predicted = read(app.clone()).await;
        let revision = predicted["data"]["expected_revision"].as_u64().unwrap();
        let fingerprint = predicted["data"]["expected_fingerprint"].as_str().unwrap();
        state
            .db
            .set(
                "node_status:10:NODE_A",
                &serde_json::json!({
                    "last_seen": chrono::Utc::now().to_rfc3339(),
                    "verified_concrete_node": true,
                    "reconciliation": {
                        "state": "CONVERGED",
                        "desired_fingerprint": fingerprint,
                        "applied_fingerprint": fingerprint,
                        "observed_fingerprint": "runtime-observed",
                        "desired_config_revision": revision,
                        "applied_config_revision": revision,
                        "recovery_source": "PANEL"
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();
        assert_eq!(read(app.clone()).await["data"]["sync_state"], "WAITING");
        let delivered = verified_snapshot(&state).await;
        assert_eq!(delivered.config_revision, revision);
        assert_eq!(delivered.config_fingerprint, fingerprint);
        assert_eq!(read(app).await["data"]["sync_state"], "SYNCED");
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
                "node_status:10:NODE_CURRENT",
                r#"{"verified_concrete_node":true}"#,
            )
            .await
            .unwrap();
        state
            .db
            .set(
                "node_status:10:NODE_DB",
                r#"{"verified_concrete_node":true}"#,
            )
            .await
            .unwrap();
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
    async fn candidate_preflight_is_read_only_and_create_rejects_conflict() {
        let (state, pool) = test_state().await;
        for (id, group_id) in [(100_i64, 10_i64), (200, 20)] {
            sqlx::query(
                "INSERT INTO forward_rules
                 (id, name, uid, listen_port, device_group_in, target_addr, target_port)
                 VALUES (?, ?, 101, 21000, ?, '127.0.0.1', 81)",
            )
            .bind(id)
            .bind(format!("rule-{id}"))
            .bind(group_id)
            .execute(&pool)
            .await
            .unwrap();
        }
        let (_connection_id, mut config_rx) = state
            .node_connections
            .register(10, Some("NODE_A".into()))
            .await;
        let admin = format!("Bearer {}", token(101, true));
        let app = crate::api::routes().with_state(state.clone());
        let candidate = r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"NODE_A"}"#;
        let safe = r#"{"reusing_group_id":30,"home_group_id":10,"node_id":"NODE_A"}"#;
        let regular = format!("Bearer {}", token(102, false));
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/node-reuse/bindings/preview")
                        .header("Authorization", &regular)
                        .header("content-type", "application/json")
                        .body(Body::from(candidate))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/admin/node-reuse/nodes/10/NODE_A/runtime-status")
                        .header("Authorization", &regular)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(create_request(Some(&admin), safe.into()))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );

        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_reuse_bindings")
            .fetch_one(&pool)
            .await
            .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/node-reuse/bindings/preview")
                    .header("Authorization", &admin)
                    .header("content-type", "application/json")
                    .body(Body::from(candidate))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            body["data"]["source_group_ids"],
            serde_json::json!([10, 20, 30])
        );
        assert_eq!(body["data"]["known_runtime_prerequisites_satisfied"], false);
        assert!(!body["data"]["conflicts"].as_array().unwrap().is_empty());
        assert!(state
            .db
            .get("node_config_revision:10:NODE_A")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            before
        );
        assert!(config_rx.try_recv().is_err());

        let response = app
            .clone()
            .oneshot(create_request(Some(&admin), candidate.into()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["message"], "CONFIG_CONFLICT");
        assert!(!body["data"].as_array().unwrap().is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            before
        );
        assert!(state
            .db
            .find_node_reuse_binding(30, 10, "NODE_A")
            .await
            .unwrap()
            .is_some());
        assert!(config_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn runtime_status_requires_exact_fresh_verified_revision_even_for_empty_binding() {
        let (state, pool) = test_state().await;
        let admin = format!("Bearer {}", token(101, true));
        let app = crate::api::routes().with_state(AppState {
            config: Config {
                node_reuse_runtime_enabled: true,
                ..state.config.clone()
            },
            ..state.clone()
        });
        let uri = "/admin/node-reuse/nodes/10/NODE_A/runtime-status";
        let read = |app: axum::Router| async {
            let response = app
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
            serde_json::from_slice::<serde_json::Value>(
                &to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap()
        };
        let initial = read(app.clone()).await;
        assert_eq!(initial["data"]["sync_state"], "OFFLINE");
        let old_revision = initial["data"]["expected_revision"].as_u64().unwrap();
        let old_fingerprint = initial["data"]["expected_fingerprint"]
            .as_str()
            .unwrap()
            .to_string();
        let initial_delivery = verified_snapshot(&state).await;
        assert_eq!(initial_delivery.config_revision, old_revision);
        assert_eq!(initial_delivery.config_fingerprint, old_fingerprint);

        assert_eq!(
            app.clone()
                .oneshot(create_request(
                    Some(&admin),
                    r#"{"reusing_group_id":20,"home_group_id":10,"node_id":"NODE_A"}"#.into()
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        let after_create = read(app.clone()).await;
        assert_eq!(
            after_create["data"]["bindings"].as_array().unwrap().len(),
            1
        );
        let revision = after_create["data"]["expected_revision"].as_u64().unwrap();
        let fingerprint = after_create["data"]["expected_fingerprint"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            fingerprint, old_fingerprint,
            "empty Binding leaves config bytes unchanged"
        );
        assert!(
            revision > old_revision,
            "source membership must advance revision"
        );
        let membership_delivery = verified_snapshot(&state).await;
        assert_eq!(membership_delivery.config_revision, revision);
        assert_eq!(membership_delivery.config_fingerprint, fingerprint);

        let status = |verified: bool, reported_revision: u64, state_name: &str| {
            serde_json::json!({
                "last_seen": chrono::Utc::now().to_rfc3339(),
                "verified_concrete_node": verified,
                "reconciliation": {
                    "state": state_name,
                    "desired_fingerprint": fingerprint,
                    "applied_fingerprint": fingerprint,
                    "observed_fingerprint": "runtime-observed",
                    "desired_config_revision": reported_revision,
                    "applied_config_revision": reported_revision,
                    "recovery_source": "PANEL"
                }
            })
        };
        state
            .db
            .set(
                "node_status:10:NODE_A",
                &status(true, old_revision, "CONVERGED").to_string(),
            )
            .await
            .unwrap();
        assert_eq!(read(app.clone()).await["data"]["sync_state"], "WAITING");
        state
            .db
            .set(
                "node_status:10:NODE_A",
                &status(false, revision, "CONVERGED").to_string(),
            )
            .await
            .unwrap();
        let legacy = read(app.clone()).await;
        assert_eq!(legacy["data"]["sync_state"], "NOT_READY");
        assert_eq!(legacy["data"]["ready"], false);
        assert_eq!(
            legacy["data"]["blockers"],
            serde_json::json!(["NODE_NOT_VERIFIED_IN_LAST_REPORT"])
        );
        let mut wrong_applied = status(true, revision, "CONVERGED");
        wrong_applied["reconciliation"]["applied_fingerprint"] = serde_json::json!("b".repeat(64));
        state
            .db
            .set("node_status:10:NODE_A", &wrong_applied.to_string())
            .await
            .unwrap();
        assert_eq!(read(app.clone()).await["data"]["sync_state"], "WAITING");
        let mut local_recovery = status(true, revision, "CONVERGED");
        local_recovery["reconciliation"]["recovery_source"] = serde_json::json!("LKG_PRIMARY");
        state
            .db
            .set("node_status:10:NODE_A", &local_recovery.to_string())
            .await
            .unwrap();
        assert_eq!(read(app.clone()).await["data"]["sync_state"], "WAITING");
        state
            .db
            .set(
                "node_status:10:NODE_A",
                &status(true, revision, "APPLY_FAILED").to_string(),
            )
            .await
            .unwrap();
        assert_eq!(
            read(app.clone()).await["data"]["sync_state"],
            "APPLY_FAILED"
        );
        state
            .db
            .set(
                "node_status:10:NODE_A",
                &status(true, revision, "CONVERGED").to_string(),
            )
            .await
            .unwrap();
        assert_eq!(read(app.clone()).await["data"]["sync_state"], "SYNCED");

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
        let after_delete = read(app).await;
        assert!(after_delete["data"]["bindings"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(after_delete["data"]["sync_state"], "WAITING");
        assert!(after_delete["data"]["expected_revision"].as_u64().unwrap() > revision);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
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
