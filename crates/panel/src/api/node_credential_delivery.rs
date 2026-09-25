//! B2-02B first-time permanent Node Credential delivery HTTP surface.
//!
//! These endpoints establish a permanent credential record only. They do not
//! authenticate normal HTTP/WS runtime traffic and grant no Node Reuse authority.

use crate::api::node::extract_node_token;
use crate::api::node_claim::production_claim_transport_allowed;
use crate::api::AppState;
use crate::db::repo::{
    ActivateInitialNodeCredentialFromDelivery, GroupRepository,
    NodeCredentialDeliveryActivateResult, NodeCredentialDeliveryPrepareResult,
    NodeCredentialDeliveryRecord, NodeCredentialRecord, PrepareInitialNodeCredentialDelivery,
};
use crate::node_claim::{NodeClaimSecret, NodeClaimantNonce};
use crate::node_credential::{
    NodeCredentialDeliveryNonce, NodeCredentialSecret, PresentedNodeCredentialVerifier,
};
use crate::node_identity::ReuseEligibleNodeId;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use once_cell::sync::Lazy;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DELIVERY_ATTEMPT_LIMIT: u32 = 10;
const DELIVERY_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const DELIVERY_ATTEMPT_LIMITER_CAP: usize = 10_000;
const DELIVERY_ATTEMPT_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct AttemptWindow {
    count: u32,
    window_start: Instant,
}

#[derive(Debug)]
struct AttemptLimiter {
    entries: HashMap<String, AttemptWindow>,
    last_cleanup: Instant,
    #[cfg(test)]
    cleanup_runs: usize,
}

impl AttemptLimiter {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: now,
            #[cfg(test)]
            cleanup_runs: 0,
        }
    }

    fn check(&mut self, key: &str, now: Instant) -> bool {
        if let Some(entry) = self.entries.get_mut(key) {
            if now.saturating_duration_since(entry.window_start) < DELIVERY_ATTEMPT_WINDOW {
                entry.count = entry.count.saturating_add(1);
                return entry.count > DELIVERY_ATTEMPT_LIMIT;
            }
            entry.count = 1;
            entry.window_start = now;
            return false;
        }

        if self.entries.len() >= DELIVERY_ATTEMPT_LIMITER_CAP {
            if now.saturating_duration_since(self.last_cleanup) >= DELIVERY_ATTEMPT_CLEANUP_INTERVAL
            {
                self.entries.retain(|_, entry| {
                    now.saturating_duration_since(entry.window_start) < DELIVERY_ATTEMPT_WINDOW
                });
                self.last_cleanup = now;
                #[cfg(test)]
                {
                    self.cleanup_runs += 1;
                }
            }
            if self.entries.len() >= DELIVERY_ATTEMPT_LIMITER_CAP {
                return true;
            }
        }

        self.entries.insert(
            key.to_string(),
            AttemptWindow {
                count: 1,
                window_start: now,
            },
        );
        false
    }
}

static DELIVERY_ATTEMPT_LIMITER: Lazy<Mutex<AttemptLimiter>> =
    Lazy::new(|| Mutex::new(AttemptLimiter::new(Instant::now())));

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCredentialDeliveryRequest {
    pub home_group_id: i64,
    pub node_id: String,
    pub claim_secret: String,
    pub claimant_nonce: String,
    pub delivery_nonce: String,
    pub credential_id: String,
    pub verifier_format: String,
    pub verifier_version: i64,
    pub verifier_data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateCredentialDeliveryRequest {
    pub home_group_id: i64,
    pub node_id: String,
    pub credential_id: String,
    pub delivery_nonce: String,
    pub credential_secret: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct CredentialDeliveryView {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    pub credential_id: String,
    pub state: String,
    pub authorized_at: String,
    pub expires_at: String,
    pub updated_at: String,
    pub credential_generation: Option<i64>,
    pub proof_verified_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
    pub expired_at: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct PermanentCredentialView {
    pub credential_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    pub generation: i64,
    pub state: &'static str,
    pub activated_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PrepareCredentialDeliveryResponse {
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<CredentialDeliveryView>,
}

#[derive(Debug, Serialize)]
pub struct ActivateCredentialDeliveryResponse {
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<CredentialDeliveryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<PermanentCredentialView>,
}

fn delivery_view(record: &NodeCredentialDeliveryRecord) -> CredentialDeliveryView {
    CredentialDeliveryView {
        claim_id: record.claim_id.clone(),
        home_group_id: record.home_group_id,
        node_id: record.node_id.clone(),
        credential_id: record.credential_id.clone(),
        state: record.state.clone(),
        authorized_at: record.authorized_at.clone(),
        expires_at: record.expires_at.clone(),
        updated_at: record.updated_at.clone(),
        credential_generation: record.credential_generation,
        proof_verified_at: record.proof_verified_at.clone(),
        completed_at: record.completed_at.clone(),
        cancelled_at: record.cancelled_at.clone(),
        expired_at: record.expired_at.clone(),
    }
}

fn credential_view(record: &NodeCredentialRecord) -> PermanentCredentialView {
    let state = if record.revoked_at.is_some() {
        "REVOKED"
    } else if record.activated_at.is_some() {
        "ACTIVE"
    } else {
        "INACTIVE"
    };
    PermanentCredentialView {
        credential_id: record.credential_id.clone(),
        home_group_id: record.home_group_id,
        node_id: record.node_id.clone(),
        generation: record.generation,
        state,
        activated_at: record.activated_at.clone(),
        revoked_at: record.revoked_at.clone(),
    }
}

fn apply_sensitive_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

fn sensitive_json<T: Serialize>(status: StatusCode, body: ApiResponse<T>) -> Response {
    let mut response = (status, Json(body)).into_response();
    apply_sensitive_headers(&mut response);
    response
}

fn sensitive_error(status: StatusCode, code: i32, message: &str) -> Response {
    sensitive_json(
        status,
        ApiResponse::<()> {
            code,
            message: message.to_string(),
            data: None,
        },
    )
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .map(|parsed| parsed.to_string() == value)
        .unwrap_or(false)
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn attempt_rate_limited(phase: &str, group_id: i64, claim_id: &str) -> bool {
    let key = format!("{phase}:{group_id}:{claim_id}");
    DELIVERY_ATTEMPT_LIMITER
        .lock()
        .unwrap()
        .check(&key, Instant::now())
}

async fn authenticated_group(
    state: &AppState,
    headers: &HeaderMap,
    requested_group: i64,
) -> Result<i64, Response> {
    let token = match extract_node_token(headers) {
        Some(token) if !token.is_empty() => token,
        _ => {
            return Err(sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            ))
        }
    };
    match GroupRepository::find_by_token(state.db.as_ref(), &token).await {
        Ok(Some(group)) if group.group_type == "in" && group.id == requested_group => Ok(group.id),
        Ok(_) => Err(sensitive_error(
            StatusCode::UNAUTHORIZED,
            401,
            "credential delivery authentication failed",
        )),
        Err(error) => {
            tracing::error!("credential delivery token lookup failed: {error}");
            Err(sensitive_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                500,
                "database error",
            ))
        }
    }
}

pub async fn prepare_credential(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PrepareCredentialDeliveryRequest>,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Node Credential delivery requires the configured trusted HTTPS ingress",
        );
    }
    prepare_credential_after_transport(state, claim_id, headers, req).await
}

async fn prepare_credential_after_transport(
    state: AppState,
    claim_id: String,
    headers: HeaderMap,
    req: PrepareCredentialDeliveryRequest,
) -> Response {
    let group_id = match authenticated_group(&state, &headers, req.home_group_id).await {
        Ok(group_id) => group_id,
        Err(response) => return response,
    };
    if !canonical_uuid(&claim_id) || !valid_credential_id(&req.credential_id) {
        return sensitive_error(
            StatusCode::UNAUTHORIZED,
            401,
            "credential delivery authentication failed",
        );
    }
    let node_id = match ReuseEligibleNodeId::parse(&req.node_id) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let claim_secret = match NodeClaimSecret::parse(&req.claim_secret) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let claimant_nonce = match NodeClaimantNonce::parse(&req.claimant_nonce) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let delivery_nonce = match NodeCredentialDeliveryNonce::parse(&req.delivery_nonce) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let presented_verifier = match PresentedNodeCredentialVerifier::parse(
        &req.verifier_format,
        req.verifier_version,
        &req.verifier_data,
    ) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };

    if attempt_rate_limited("prepare", group_id, &claim_id) {
        return sensitive_json(
            StatusCode::TOO_MANY_REQUESTS,
            ApiResponse {
                code: 429,
                message: "too many credential delivery attempts; retry later".into(),
                data: Some(PrepareCredentialDeliveryResponse {
                    outcome: "RATE_LIMITED",
                    delivery: None,
                }),
            },
        );
    }

    let request = PrepareInitialNodeCredentialDelivery {
        claim_id: claim_id.clone(),
        home_group_id: group_id,
        node_id,
        claim_secret,
        claimant_nonce,
        delivery_nonce,
        credential_id: req.credential_id,
        presented_verifier,
        now: chrono::Utc::now(),
    };

    match state
        .db
        .prepare_initial_node_credential_delivery(&request)
        .await
    {
        Ok(NodeCredentialDeliveryPrepareResult::Prepared(record)) => {
            crate::service::audit::record(
                &state,
                None,
                "node_credential_delivery_prepare",
                "node_credential_delivery",
                &record.claim_id,
                &format!(
                    "home_group_id={} node_id={} credential_id={} state=PREPARED",
                    record.home_group_id, record.node_id, record.credential_id
                ),
            )
            .await;
            sensitive_json(
                StatusCode::OK,
                ApiResponse::success(PrepareCredentialDeliveryResponse {
                    outcome: "PREPARED",
                    delivery: Some(delivery_view(&record)),
                }),
            )
        }
        Ok(NodeCredentialDeliveryPrepareResult::Existing(record)) => sensitive_json(
            StatusCode::OK,
            ApiResponse::success(PrepareCredentialDeliveryResponse {
                outcome: "EXISTING",
                delivery: Some(delivery_view(&record)),
            }),
        ),
        Ok(NodeCredentialDeliveryPrepareResult::Expired) => prepare_failure(
            StatusCode::GONE,
            410,
            "EXPIRED",
            "credential delivery authorization expired",
        ),
        Ok(NodeCredentialDeliveryPrepareResult::Cancelled) => prepare_failure(
            StatusCode::GONE,
            410,
            "CANCELLED",
            "credential delivery authorization cancelled",
        ),
        Ok(NodeCredentialDeliveryPrepareResult::Replay) => prepare_failure(
            StatusCode::CONFLICT,
            409,
            "REPLAY",
            "credential delivery material conflicts with existing state",
        ),
        Ok(NodeCredentialDeliveryPrepareResult::AlreadyActive) => prepare_failure(
            StatusCode::CONFLICT,
            409,
            "ALREADY_ACTIVE",
            "this Node already has an active permanent Credential",
        ),
        Ok(NodeCredentialDeliveryPrepareResult::RecoveryRequired) => prepare_failure(
            StatusCode::CONFLICT,
            409,
            "RECOVERY_REQUIRED",
            "this Node has permanent Credential activation history",
        ),
        Ok(NodeCredentialDeliveryPrepareResult::Invalid) => prepare_failure(
            StatusCode::UNAUTHORIZED,
            401,
            "INVALID",
            "credential delivery authentication failed",
        ),
        Err(error) => {
            tracing::error!("credential delivery PREPARE failed: {error}");
            sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        }
    }
}

fn prepare_failure(
    status: StatusCode,
    code: i32,
    outcome: &'static str,
    message: &str,
) -> Response {
    sensitive_json(
        status,
        ApiResponse {
            code,
            message: message.into(),
            data: Some(PrepareCredentialDeliveryResponse {
                outcome,
                delivery: None,
            }),
        },
    )
}

pub async fn activate_credential(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ActivateCredentialDeliveryRequest>,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Node Credential delivery requires the configured trusted HTTPS ingress",
        );
    }
    activate_credential_after_transport(state, claim_id, headers, req).await
}

async fn activate_credential_after_transport(
    state: AppState,
    claim_id: String,
    headers: HeaderMap,
    req: ActivateCredentialDeliveryRequest,
) -> Response {
    let group_id = match authenticated_group(&state, &headers, req.home_group_id).await {
        Ok(group_id) => group_id,
        Err(response) => return response,
    };
    if !canonical_uuid(&claim_id) || !valid_credential_id(&req.credential_id) {
        return sensitive_error(
            StatusCode::UNAUTHORIZED,
            401,
            "credential delivery authentication failed",
        );
    }
    let node_id = match ReuseEligibleNodeId::parse(&req.node_id) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let delivery_nonce = match NodeCredentialDeliveryNonce::parse(&req.delivery_nonce) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };
    let credential_secret = match NodeCredentialSecret::parse(&req.credential_secret) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::UNAUTHORIZED,
                401,
                "credential delivery authentication failed",
            )
        }
    };

    if attempt_rate_limited("activate", group_id, &claim_id) {
        return activate_failure(
            StatusCode::TOO_MANY_REQUESTS,
            429,
            "RATE_LIMITED",
            "too many credential activation attempts; retry later",
        );
    }

    let request = ActivateInitialNodeCredentialFromDelivery {
        claim_id: claim_id.clone(),
        home_group_id: group_id,
        node_id,
        credential_id: req.credential_id,
        delivery_nonce,
        credential_secret,
        now: chrono::Utc::now(),
    };

    match state
        .db
        .activate_initial_node_credential_from_delivery(&request)
        .await
    {
        Ok(NodeCredentialDeliveryActivateResult::Activated {
            delivery,
            credential,
        }) => {
            crate::service::audit::record(
                &state,
                None,
                "node_credential_delivery_activate",
                "node_credential",
                &credential.credential_id,
                &format!(
                    "home_group_id={} node_id={} generation={} state=ACTIVE",
                    credential.home_group_id, credential.node_id, credential.generation
                ),
            )
            .await;
            activate_success("ACTIVATED", delivery, credential)
        }
        Ok(NodeCredentialDeliveryActivateResult::Existing {
            delivery,
            credential,
        }) => activate_success("EXISTING", delivery, credential),
        Ok(NodeCredentialDeliveryActivateResult::Expired) => activate_failure(
            StatusCode::GONE,
            410,
            "EXPIRED",
            "credential delivery authorization expired",
        ),
        Ok(NodeCredentialDeliveryActivateResult::Cancelled) => activate_failure(
            StatusCode::GONE,
            410,
            "CANCELLED",
            "credential delivery authorization cancelled",
        ),
        Ok(NodeCredentialDeliveryActivateResult::Invalid)
        | Ok(NodeCredentialDeliveryActivateResult::InvalidProof) => activate_failure(
            StatusCode::UNAUTHORIZED,
            401,
            "INVALID",
            "credential activation proof was rejected",
        ),
        Ok(NodeCredentialDeliveryActivateResult::AlreadyActive) => activate_failure(
            StatusCode::CONFLICT,
            409,
            "ALREADY_ACTIVE",
            "this Node already has an active permanent Credential",
        ),
        Ok(NodeCredentialDeliveryActivateResult::RecoveryRequired) => activate_failure(
            StatusCode::CONFLICT,
            409,
            "RECOVERY_REQUIRED",
            "this Node requires a separately authorized recovery flow",
        ),
        Ok(NodeCredentialDeliveryActivateResult::CredentialRevoked) => activate_failure(
            StatusCode::CONFLICT,
            409,
            "CREDENTIAL_REVOKED",
            "the linked permanent Credential is revoked",
        ),
        Err(error) => {
            tracing::error!("credential delivery ACTIVATE failed: {error}");
            sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        }
    }
}

fn activate_success(
    outcome: &'static str,
    delivery: NodeCredentialDeliveryRecord,
    credential: NodeCredentialRecord,
) -> Response {
    sensitive_json(
        StatusCode::OK,
        ApiResponse::success(ActivateCredentialDeliveryResponse {
            outcome,
            delivery: Some(delivery_view(&delivery)),
            credential: Some(credential_view(&credential)),
        }),
    )
}

fn activate_failure(
    status: StatusCode,
    code: i32,
    outcome: &'static str,
    message: &str,
) -> Response {
    sensitive_json(
        status,
        ApiResponse {
            code,
            message: message.into(),
            data: Some(ActivateCredentialDeliveryResponse {
                outcome,
                delivery: None,
                credential: None,
            }),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::diagnose::DiagnoseRegistry;
    use crate::api::middleware::Claims;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::pg_repo::PgRepository;
    use crate::db::pg_schema::{apply_pg_schema, run_pg_migrations};
    use crate::db::repo::Repository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::node_credential::NodeCredentialVerifier;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::postgres::PgPoolOptions;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    static DELIVERY_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> =
        Lazy::new(|| tokio::sync::Mutex::new(()));

    struct TrustedProxyEnvGuard;
    impl TrustedProxyEnvGuard {
        fn install(value: &str) -> Self {
            std::env::set_var("NODE_CLAIM_TRUSTED_PROXY_IPS", value);
            Self
        }
    }
    impl Drop for TrustedProxyEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("NODE_CLAIM_TRUSTED_PROXY_IPS");
        }
    }

    fn app_state(db: Arc<dyn Repository>) -> AppState {
        AppState {
            db,
            config: Config {
                database_path: "test".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "credential-delivery-test-jwt-key".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
                node_reuse_runtime_enabled: false,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    async fn sqlite_state() -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "UPDATE users SET username='admin-one',password='hash',admin=1,banned=0,\
             token_version=0,must_change_password=0 WHERE id=1",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id,name,group_type,token,uid) \
             VALUES (7,'delivery-group','in','delivery-group-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        app_state(Arc::new(SqliteRepository::new(pool)))
    }

    fn replace_db_in_url(url: &str, db_name: &str) -> String {
        let (base, query) = match url.split_once('?') {
            Some((base, query)) => (base, Some(query)),
            None => (url, None),
        };
        let head = base.rsplit_once('/').map(|(head, _)| head).unwrap_or(base);
        match query {
            Some(query) => format!("{head}/{db_name}?{query}"),
            None => format!("{head}/{db_name}"),
        }
    }

    async fn pg_state() -> Option<AppState> {
        let url = std::env::var("TEST_PG_URL")
            .ok()
            .filter(|v| !v.is_empty())?;
        let db_name = format!("test_b202b_api_{}", uuid::Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&replace_db_in_url(&url, "postgres"))
            .await
            .expect("connect PG admin DB");
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin)
            .await
            .expect("create B2-02B API DB");
        admin.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&replace_db_in_url(&url, &db_name))
            .await
            .expect("connect B2-02B API DB");
        apply_pg_schema(&pool).await.expect("apply PG schema");
        run_pg_migrations(&pool).await.expect("run PG migrations");
        let updated = sqlx::query(
            "UPDATE users SET username='admin-one',password='hash',admin=TRUE,banned=FALSE,\
             token_version=0,must_change_password=FALSE WHERE id=1",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(updated.rows_affected(), 1);
        sqlx::query(
            "INSERT INTO device_groups (id,name,group_type,token,uid) \
             VALUES (7,'delivery-group','in','delivery-group-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        Some(app_state(Arc::new(PgRepository::new(pool))))
    }

    fn admin_token(state: &AppState) -> String {
        encode(
            &Header::default(),
            &Claims {
                sub: 1,
                admin: true,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    async fn json_response(response: Response) -> (StatusCode, HeaderMap, serde_json::Value) {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, value)
    }

    async fn post_json(
        router: axum::Router,
        uri: &str,
        body: serde_json::Value,
        bearer: Option<&str>,
        peer: SocketAddr,
        proto: &str,
    ) -> Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-proto", proto);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        router.oneshot(request).await.unwrap()
    }

    async fn create_and_claim(state: &AppState, node_id: &str) -> (String, String, String) {
        let router = crate::api::routes().with_state(state.clone());
        let peer: SocketAddr = "127.0.0.1:42000".parse().unwrap();
        let created = post_json(
            router.clone(),
            "/admin/node-credential-claims",
            serde_json::json!({"home_group_id":7,"node_id":node_id}),
            Some(&admin_token(state)),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(created).await;
        assert_eq!(status, StatusCode::OK);
        let claim_id = body["data"]["claim"]["claim_id"]
            .as_str()
            .unwrap()
            .to_string();
        let claim_secret = body["data"]["claim_secret"].as_str().unwrap().to_string();
        let claimant_nonce = NodeClaimantNonce::generate().unwrap().to_wire_value();
        let claimed = post_json(
            router,
            &format!("/node-credential-claims/{claim_id}/claim"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":node_id,
                "secret":claim_secret,
                "claimant_nonce":claimant_nonce,
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(claimed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "CLAIMED");
        (claim_id, claim_secret, claimant_nonce)
    }

    async fn exercise_http_delivery_contract(state: AppState) {
        let router = crate::api::routes().with_state(state.clone());
        let peer: SocketAddr = "127.0.0.1:42001".parse().unwrap();
        let node_id = "Delivery_Node";
        let (claim_id, claim_secret, claimant_nonce) = create_and_claim(&state, node_id).await;
        let credential_id = uuid::Uuid::new_v4().to_string();
        let secret = NodeCredentialSecret::generate().unwrap();
        let delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let parsed_node = ReuseEligibleNodeId::parse(node_id).unwrap();
        let verifier = NodeCredentialVerifier::derive(&credential_id, 7, &parsed_node, &secret);
        let verifier_data = URL_SAFE_NO_PAD.encode(verifier.data());
        let prepare_body = serde_json::json!({
            "home_group_id":7,
            "node_id":node_id,
            "claim_secret":claim_secret,
            "claimant_nonce":claimant_nonce,
            "delivery_nonce":delivery_nonce.to_wire_value(),
            "credential_id":credential_id,
            "verifier_format":verifier.format(),
            "verifier_version":verifier.version(),
            "verifier_data":verifier_data,
        });
        let prepare_uri = format!("/node-credential-claims/{claim_id}/credential/prepare");

        let wrong_token = post_json(
            router.clone(),
            &prepare_uri,
            prepare_body.clone(),
            Some("wrong-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

        let prepared = post_json(
            router.clone(),
            &prepare_uri,
            prepare_body.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, headers, body) = json_response(prepared).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        assert_eq!(body["data"]["outcome"], "PREPARED");
        assert_eq!(body["data"]["delivery"]["state"], "PREPARED");
        assert_eq!(body["data"]["delivery"]["claim_id"], claim_id);
        assert_eq!(body["data"]["delivery"]["node_id"], node_id);
        assert_eq!(body["data"]["delivery"]["credential_id"], credential_id);
        assert!(body["data"]["delivery"]["credential_generation"].is_null());
        let response_text = body.to_string();
        for forbidden in [
            claim_secret.as_str(),
            claimant_nonce.as_str(),
            verifier_data.as_str(),
            "credential_verifier_data",
            "delivery_nonce_verifier_data",
        ] {
            assert!(
                !response_text.contains(forbidden),
                "response leaked sensitive material"
            );
        }
        assert!(state
            .db
            .find_node_credential(&credential_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            state
                .db
                .find_node_credential_claim(&claim_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "CREDENTIAL_PENDING"
        );

        let duplicate = post_json(
            router.clone(),
            &prepare_uri,
            prepare_body.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(duplicate).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "EXISTING");

        let mut conflict = prepare_body;
        conflict["delivery_nonce"] = serde_json::Value::String(
            NodeCredentialDeliveryNonce::generate()
                .unwrap()
                .to_wire_value(),
        );
        let conflict = post_json(
            router.clone(),
            &prepare_uri,
            conflict,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(conflict).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["data"]["outcome"], "REPLAY");

        let activate_uri = format!("/node-credential-claims/{claim_id}/credential/activate");
        let activation_body = serde_json::json!({
            "home_group_id":7,
            "node_id":node_id,
            "credential_id":credential_id,
            "delivery_nonce":delivery_nonce.to_wire_value(),
            "credential_secret":secret.to_wire_value(),
        });
        let mut bad_proof = activation_body.clone();
        bad_proof["credential_secret"] =
            serde_json::Value::String(NodeCredentialSecret::generate().unwrap().to_wire_value());
        let invalid = post_json(
            router.clone(),
            &activate_uri,
            bad_proof,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(invalid).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["data"]["outcome"], "INVALID");
        assert!(state
            .db
            .find_node_credential(&credential_id)
            .await
            .unwrap()
            .is_none());

        let activated = post_json(
            router.clone(),
            &activate_uri,
            activation_body.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(activated).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "ACTIVATED");
        assert_eq!(body["data"]["delivery"]["state"], "COMPLETED");
        assert_eq!(body["data"]["credential"]["state"], "ACTIVE");
        assert_eq!(body["data"]["credential"]["credential_id"], credential_id);
        assert_eq!(body["data"]["credential"]["generation"], 1);
        assert!(!body.to_string().contains(&secret.to_wire_value()));
        assert!(!body.to_string().contains(&delivery_nonce.to_wire_value()));

        let retry = post_json(
            router,
            &activate_uri,
            activation_body,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(retry).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "EXISTING");
        assert_eq!(body["data"]["credential"]["generation"], 1);
    }

    async fn exercise_http_security_and_terminal_contract(state: AppState) {
        let router = crate::api::routes().with_state(state.clone());
        let peer: SocketAddr = "127.0.0.1:42003".parse().unwrap();

        let node_id = "Security_Node";
        let (claim_id, claim_secret, claimant_nonce) = create_and_claim(&state, node_id).await;
        let credential_id = uuid::Uuid::new_v4().to_string();
        let secret = NodeCredentialSecret::generate().unwrap();
        let delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let node = ReuseEligibleNodeId::parse(node_id).unwrap();
        let verifier = NodeCredentialVerifier::derive(&credential_id, 7, &node, &secret);
        let prepare_uri = format!("/node-credential-claims/{claim_id}/credential/prepare");
        let prepare_body = serde_json::json!({
            "home_group_id":7,
            "node_id":node_id,
            "claim_secret":claim_secret,
            "claimant_nonce":claimant_nonce,
            "delivery_nonce":delivery_nonce.to_wire_value(),
            "credential_id":credential_id,
            "verifier_format":verifier.format(),
            "verifier_version":verifier.version(),
            "verifier_data":URL_SAFE_NO_PAD.encode(verifier.data()),
        });

        let mut no_claim_proof = prepare_body.clone();
        no_claim_proof
            .as_object_mut()
            .unwrap()
            .remove("claim_secret");
        let response = post_json(
            router.clone(),
            &prepare_uri,
            no_claim_proof,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let response = post_json(
            router.clone(),
            &format!(
                "/node-credential-claims/{}/credential/prepare",
                uuid::Uuid::new_v4()
            ),
            prepare_body.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut wrong_group = prepare_body.clone();
        wrong_group["home_group_id"] = serde_json::json!(8);
        let response = post_json(
            router.clone(),
            &prepare_uri,
            wrong_group,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut wrong_node = prepare_body.clone();
        wrong_node["node_id"] = serde_json::Value::String("Other_Node".into());
        let response = post_json(
            router.clone(),
            &prepare_uri,
            wrong_node,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["data"]["outcome"], "INVALID");

        let mut wrong_claimant = prepare_body.clone();
        wrong_claimant["claimant_nonce"] =
            serde_json::Value::String(NodeClaimantNonce::generate().unwrap().to_wire_value());
        let response = post_json(
            router.clone(),
            &prepare_uri,
            wrong_claimant,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["data"]["outcome"], "INVALID");

        let prepared = post_json(
            router.clone(),
            &prepare_uri,
            prepare_body,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(prepared.status(), StatusCode::OK);

        let activate_uri = format!("/node-credential-claims/{claim_id}/credential/activate");
        let activation_body = serde_json::json!({
            "home_group_id":7,
            "node_id":node_id,
            "credential_id":credential_id,
            "delivery_nonce":delivery_nonce.to_wire_value(),
            "credential_secret":secret.to_wire_value(),
        });

        let mut wrong_delivery_nonce = activation_body.clone();
        wrong_delivery_nonce["delivery_nonce"] = serde_json::Value::String(
            NodeCredentialDeliveryNonce::generate()
                .unwrap()
                .to_wire_value(),
        );
        let response = post_json(
            router.clone(),
            &activate_uri,
            wrong_delivery_nonce,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["data"]["outcome"], "INVALID");

        assert_eq!(
            state
                .db
                .cancel_node_credential_claim(&claim_id, 7, &node, chrono::Utc::now(),)
                .await
                .unwrap(),
            crate::db::repo::NodeCredentialClaimMutationResult::Applied
        );
        let response = post_json(
            router.clone(),
            &activate_uri,
            activation_body,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["data"]["outcome"], "CANCELLED");
        assert!(state
            .db
            .find_node_credential(&credential_id)
            .await
            .unwrap()
            .is_none());

        let expiry_node = "Expiry_Node";
        let (expiry_claim, expiry_secret, expiry_claimant) =
            create_and_claim(&state, expiry_node).await;
        let expiry_node_id = ReuseEligibleNodeId::parse(expiry_node).unwrap();
        let expiry_credential_id = uuid::Uuid::new_v4().to_string();
        let expiry_permanent = NodeCredentialSecret::generate().unwrap();
        let expiry_delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let expiry_verifier = NodeCredentialVerifier::derive(
            &expiry_credential_id,
            7,
            &expiry_node_id,
            &expiry_permanent,
        );
        let expiry_prepare_uri =
            format!("/node-credential-claims/{expiry_claim}/credential/prepare");
        let response = post_json(
            router.clone(),
            &expiry_prepare_uri,
            serde_json::json!({
                "home_group_id":7,
                "node_id":expiry_node,
                "claim_secret":expiry_secret,
                "claimant_nonce":expiry_claimant,
                "delivery_nonce":expiry_delivery_nonce.to_wire_value(),
                "credential_id":expiry_credential_id,
                "verifier_format":expiry_verifier.format(),
                "verifier_version":expiry_verifier.version(),
                "verifier_data":URL_SAFE_NO_PAD.encode(expiry_verifier.data()),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state
                .db
                .expire_node_credential_delivery(
                    &expiry_claim,
                    7,
                    &expiry_node_id,
                    chrono::Utc::now() + chrono::Duration::minutes(11),
                )
                .await
                .unwrap(),
            crate::db::repo::NodeCredentialDeliveryMutationResult::Applied
        );
        let response = post_json(
            router.clone(),
            &format!("/node-credential-claims/{expiry_claim}/credential/activate"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":expiry_node,
                "credential_id":expiry_credential_id,
                "delivery_nonce":expiry_delivery_nonce.to_wire_value(),
                "credential_secret":expiry_permanent.to_wire_value(),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["data"]["outcome"], "EXPIRED");

        let forged_node = "Forged_Verifier_Node";
        let (forged_claim, forged_claim_secret, forged_claimant) =
            create_and_claim(&state, forged_node).await;
        let forged_node_id = ReuseEligibleNodeId::parse(forged_node).unwrap();
        let forged_credential_id = uuid::Uuid::new_v4().to_string();
        let actual_secret = NodeCredentialSecret::generate().unwrap();
        let unrelated_secret = NodeCredentialSecret::generate().unwrap();
        let forged_delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let forged_verifier = NodeCredentialVerifier::derive(
            &forged_credential_id,
            7,
            &forged_node_id,
            &unrelated_secret,
        );
        let response = post_json(
            router.clone(),
            &format!("/node-credential-claims/{forged_claim}/credential/prepare"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":forged_node,
                "claim_secret":forged_claim_secret,
                "claimant_nonce":forged_claimant,
                "delivery_nonce":forged_delivery_nonce.to_wire_value(),
                "credential_id":forged_credential_id,
                "verifier_format":forged_verifier.format(),
                "verifier_version":forged_verifier.version(),
                "verifier_data":URL_SAFE_NO_PAD.encode(forged_verifier.data()),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = post_json(
            router.clone(),
            &format!("/node-credential-claims/{forged_claim}/credential/activate"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":forged_node,
                "credential_id":forged_credential_id,
                "delivery_nonce":forged_delivery_nonce.to_wire_value(),
                "credential_secret":actual_secret.to_wire_value(),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["data"]["outcome"], "INVALID");
        assert!(state
            .db
            .find_node_credential(&forged_credential_id)
            .await
            .unwrap()
            .is_none());

        let history_node = "History_Node";
        let (history_claim, history_claim_secret, history_claimant) =
            create_and_claim(&state, history_node).await;
        let history_node_id = ReuseEligibleNodeId::parse(history_node).unwrap();
        let history_credential_id = uuid::Uuid::new_v4().to_string();
        let history_secret = NodeCredentialSecret::generate().unwrap();
        let history_delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let history_verifier = NodeCredentialVerifier::derive(
            &history_credential_id,
            7,
            &history_node_id,
            &history_secret,
        );
        let history_prepare = serde_json::json!({
            "home_group_id":7,
            "node_id":history_node,
            "claim_secret":history_claim_secret,
            "claimant_nonce":history_claimant,
            "delivery_nonce":history_delivery_nonce.to_wire_value(),
            "credential_id":history_credential_id,
            "verifier_format":history_verifier.format(),
            "verifier_version":history_verifier.version(),
            "verifier_data":URL_SAFE_NO_PAD.encode(history_verifier.data()),
        });
        let history_prepare_uri =
            format!("/node-credential-claims/{history_claim}/credential/prepare");
        assert_eq!(
            post_json(
                router.clone(),
                &history_prepare_uri,
                history_prepare,
                Some("delivery-group-token"),
                peer,
                "https",
            )
            .await
            .status(),
            StatusCode::OK
        );
        let history_activate_uri =
            format!("/node-credential-claims/{history_claim}/credential/activate");
        let history_activate = serde_json::json!({
            "home_group_id":7,
            "node_id":history_node,
            "credential_id":history_credential_id,
            "delivery_nonce":history_delivery_nonce.to_wire_value(),
            "credential_secret":history_secret.to_wire_value(),
        });
        let response = post_json(
            router.clone(),
            &history_activate_uri,
            history_activate.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "ACTIVATED");

        let (new_claim, new_claim_secret, new_claimant) =
            create_and_claim(&state, history_node).await;
        let new_credential_id = uuid::Uuid::new_v4().to_string();
        let new_secret = NodeCredentialSecret::generate().unwrap();
        let new_delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let new_verifier =
            NodeCredentialVerifier::derive(&new_credential_id, 7, &history_node_id, &new_secret);
        let new_prepare_uri = format!("/node-credential-claims/{new_claim}/credential/prepare");
        let new_prepare = serde_json::json!({
            "home_group_id":7,
            "node_id":history_node,
            "claim_secret":new_claim_secret,
            "claimant_nonce":new_claimant,
            "delivery_nonce":new_delivery_nonce.to_wire_value(),
            "credential_id":new_credential_id,
            "verifier_format":new_verifier.format(),
            "verifier_version":new_verifier.version(),
            "verifier_data":URL_SAFE_NO_PAD.encode(new_verifier.data()),
        });
        let response = post_json(
            router.clone(),
            &new_prepare_uri,
            new_prepare.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["data"]["outcome"], "ALREADY_ACTIVE");

        assert_eq!(
            state
                .db
                .revoke_node_credential(&history_credential_id, 7, &history_node_id, 1,)
                .await
                .unwrap(),
            crate::db::repo::NodeCredentialMutationResult::Applied
        );
        let response = post_json(
            router.clone(),
            &history_activate_uri,
            history_activate,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["data"]["outcome"], "CREDENTIAL_REVOKED");

        let response = post_json(
            router,
            &new_prepare_uri,
            new_prepare,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["data"]["outcome"], "RECOVERY_REQUIRED");
    }

    async fn exercise_original_claim_ttl_is_not_delivery_ttl(state: AppState) {
        let peer: SocketAddr = "127.0.0.1:42004".parse().unwrap();
        let router = crate::api::routes().with_state(state.clone());
        let node_id = ReuseEligibleNodeId::parse("Short_Claim_Node").unwrap();
        let claim_id = uuid::Uuid::new_v4().to_string();
        let claim_secret = NodeClaimSecret::generate().unwrap();
        let created_at = chrono::Utc::now();
        let claim = crate::db::repo::NewNodeCredentialClaim {
            claim_id: claim_id.clone(),
            home_group_id: 7,
            node_id: node_id.clone(),
            secret_verifier: crate::node_claim::NodeClaimSecretVerifier::derive(
                &claim_id,
                7,
                &node_id,
                &claim_secret,
            ),
            approved_by: 1,
            approval_ref: format!("test:{claim_id}"),
            created_at,
            expires_at: created_at + chrono::Duration::seconds(6),
        };
        assert!(matches!(
            state.db.create_node_credential_claim(&claim).await.unwrap(),
            crate::db::repo::NodeCredentialClaimCreateResult::Created(_)
        ));

        let claimant_nonce = NodeClaimantNonce::generate().unwrap();
        let response = post_json(
            router.clone(),
            &format!("/node-credential-claims/{claim_id}/claim"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":node_id.as_str(),
                "secret":claim_secret.to_wire_value(),
                "claimant_nonce":claimant_nonce.to_wire_value(),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let credential_id = uuid::Uuid::new_v4().to_string();
        let permanent_secret = NodeCredentialSecret::generate().unwrap();
        let delivery_nonce = NodeCredentialDeliveryNonce::generate().unwrap();
        let verifier =
            NodeCredentialVerifier::derive(&credential_id, 7, &node_id, &permanent_secret);
        let response = post_json(
            router.clone(),
            &format!("/node-credential-claims/{claim_id}/credential/prepare"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":node_id.as_str(),
                "claim_secret":claim_secret.to_wire_value(),
                "claimant_nonce":claimant_nonce.to_wire_value(),
                "delivery_nonce":delivery_nonce.to_wire_value(),
                "credential_id":credential_id,
                "verifier_format":verifier.format(),
                "verifier_version":verifier.version(),
                "verifier_data":URL_SAFE_NO_PAD.encode(verifier.data()),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(Duration::from_secs(7)).await;

        let response = post_json(
            router,
            &format!("/node-credential-claims/{claim_id}/credential/activate"),
            serde_json::json!({
                "home_group_id":7,
                "node_id":node_id.as_str(),
                "credential_id":credential_id,
                "delivery_nonce":delivery_nonce.to_wire_value(),
                "credential_secret":permanent_secret.to_wire_value(),
            }),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        let (status, _, body) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["outcome"], "ACTIVATED");
    }

    #[tokio::test]
    async fn credential_delivery_http_contract_sqlite() {
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_http_delivery_contract(sqlite_state().await).await;
    }

    #[tokio::test]
    async fn credential_delivery_http_contract_real_postgres() {
        let Some(state) = pg_state().await else {
            return;
        };
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_http_delivery_contract(state).await;
    }

    #[tokio::test]
    async fn credential_delivery_http_security_terminal_contract_sqlite() {
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_http_security_and_terminal_contract(sqlite_state().await).await;
    }

    #[tokio::test]
    async fn credential_delivery_http_security_terminal_contract_real_postgres() {
        let Some(state) = pg_state().await else {
            return;
        };
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_http_security_and_terminal_contract(state).await;
    }

    #[tokio::test]
    async fn credential_delivery_original_claim_ttl_is_independent_sqlite() {
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_original_claim_ttl_is_not_delivery_ttl(sqlite_state().await).await;
    }

    #[tokio::test]
    async fn credential_delivery_original_claim_ttl_is_independent_real_postgres() {
        let Some(state) = pg_state().await else {
            return;
        };
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        exercise_original_claim_ttl_is_not_delivery_ttl(state).await;
    }

    #[tokio::test]
    async fn credential_delivery_routes_fail_closed_on_transport_shape_and_body_limit() {
        let _lock = DELIVERY_ENV_LOCK.lock().await;
        let _guard = TrustedProxyEnvGuard::install("127.0.0.1");
        let state = sqlite_state().await;
        let router = crate::api::routes().with_state(state.clone());
        let peer: SocketAddr = "127.0.0.1:42002".parse().unwrap();
        let (claim_id, claim_secret, claimant_nonce) =
            create_and_claim(&state, "Transport_Node").await;
        let credential_id = uuid::Uuid::new_v4().to_string();
        let secret = NodeCredentialSecret::generate().unwrap();
        let node = ReuseEligibleNodeId::parse("Transport_Node").unwrap();
        let verifier = NodeCredentialVerifier::derive(&credential_id, 7, &node, &secret);
        let valid = serde_json::json!({
            "home_group_id":7,
            "node_id":"Transport_Node",
            "claim_secret":claim_secret,
            "claimant_nonce":claimant_nonce,
            "delivery_nonce":NodeCredentialDeliveryNonce::generate().unwrap().to_wire_value(),
            "credential_id":credential_id,
            "verifier_format":verifier.format(),
            "verifier_version":verifier.version(),
            "verifier_data":URL_SAFE_NO_PAD.encode(verifier.data()),
        });
        let uri = format!("/node-credential-claims/{claim_id}/credential/prepare");

        let untrusted = post_json(
            router.clone(),
            &uri,
            valid.clone(),
            Some("delivery-group-token"),
            "203.0.113.9:42002".parse().unwrap(),
            "https",
        )
        .await;
        assert_eq!(untrusted.status(), StatusCode::SERVICE_UNAVAILABLE);

        let plain = post_json(
            router.clone(),
            &uri,
            valid.clone(),
            Some("delivery-group-token"),
            peer,
            "http",
        )
        .await;
        assert_eq!(plain.status(), StatusCode::SERVICE_UNAVAILABLE);

        std::env::remove_var("NODE_CLAIM_TRUSTED_PROXY_IPS");
        let missing_proxy_config = post_json(
            router.clone(),
            &uri,
            valid.clone(),
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(
            missing_proxy_config.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        std::env::set_var("NODE_CLAIM_TRUSTED_PROXY_IPS", "127.0.0.1");

        let mut unknown = valid.clone();
        unknown["now"] = serde_json::Value::String("2099-01-01T00:00:00Z".into());
        let unknown = post_json(
            router.clone(),
            &uri,
            unknown,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            unknown.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let oversized = serde_json::json!({
            "home_group_id":7,
            "node_id":"Transport_Node",
            "claim_secret":"x".repeat(5000),
            "claimant_nonce":"x",
            "delivery_nonce":"x",
            "credential_id":credential_id,
            "verifier_format":"rp-node-sha256",
            "verifier_version":1,
            "verifier_data":"x",
        });
        let oversized = post_json(
            router,
            &uri,
            oversized,
            Some("delivery-group-token"),
            peer,
            "https",
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            oversized.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[test]
    fn credential_delivery_dtos_deny_client_time_and_missing_claim_proof() {
        assert!(
            serde_json::from_value::<PrepareCredentialDeliveryRequest>(serde_json::json!({
                "home_group_id":7,"node_id":"Node_A",
                "claim_secret":"rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "claimant_nonce":"rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "delivery_nonce":"rpdn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "credential_id":"00000000-0000-4000-8000-000000000000",
                "verifier_format":"rp-node-sha256","verifier_version":1,
                "verifier_data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "now":"2099-01-01T00:00:00Z"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<PrepareCredentialDeliveryRequest>(serde_json::json!({
                "home_group_id":7,"node_id":"Node_A",
                "claimant_nonce":"rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "delivery_nonce":"rpdn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "credential_id":"00000000-0000-4000-8000-000000000000",
                "verifier_format":"rp-node-sha256","verifier_version":1,
                "verifier_data":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ActivateCredentialDeliveryRequest>(serde_json::json!({
                "home_group_id":7,"node_id":"Node_A",
                "credential_id":"00000000-0000-4000-8000-000000000000",
                "delivery_nonce":"rpdn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "credential_secret":"rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "proof_verified":true
            }))
            .is_err()
        );
    }

    #[test]
    fn credential_delivery_limiter_has_hard_cap_and_public_keys() {
        let start = Instant::now();
        let mut limiter = AttemptLimiter::new(start);
        for i in 0..DELIVERY_ATTEMPT_LIMITER_CAP {
            assert!(!limiter.check(&format!("prepare:7:{i}"), start));
        }
        assert!(limiter.check("prepare:7:unknown", start));
        assert_eq!(limiter.entries.len(), DELIVERY_ATTEMPT_LIMITER_CAP);
        let key = "activate:7:public-claim-id";
        for secret_marker in ["rpc1_", "rpcn1_", "rpdn1_", "rpn1_", "group-token"] {
            assert!(!key.contains(secret_marker));
        }
    }
}
