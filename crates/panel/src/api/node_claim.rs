//! Node Reuse V1 S2-A2B2 one-time Concrete Node Claim HTTP surface.
//!
//! This is deliberately narrower than permanent Node authentication. A successful
//! request can only transition a previously-approved Claim to CLAIMED. It never
//! allocates, returns, activates, rotates, or authenticates a permanent
//! Node Credential and it grants no runtime Node Reuse authority.
//!
//! Claim creation and claim submission are sensitive operations. Reality Panel's
//! primary listener is plain HTTP and may sit behind a TLS-terminating reverse
//! proxy, so a configured `https://` public URL alone is not evidence that the
//! current request arrived over HTTPS. These handlers therefore require all of:
//! - an effective public Panel URL using `https://`;
//! - the socket peer to be one of NODE_CLAIM_TRUSTED_PROXY_IPS;
//! - exactly one `X-Forwarded-Proto: https` value from that trusted peer.
//!
//! NODE_CLAIM_TRUSTED_PROXY_IPS is an explicit deployment trust boundary, not a
//! convenience switch. The trusted ingress must strip/overwrite client-supplied
//! forwarding headers and the Panel listener must not be publicly bypassable.

use crate::api::middleware::AdminOnly;
use crate::api::node::extract_node_token;
use crate::api::provisioning::effective_public_panel_url;
use crate::api::AppState;
use crate::db::repo::{
    GroupRepository, NewNodeCredentialClaim, NodeCredentialClaimAttempt,
    NodeCredentialClaimCreateResult, NodeCredentialClaimMutationResult, NodeCredentialClaimRecord,
    NodeCredentialClaimResult, ResourceScope,
};
use crate::node_claim::{NodeClaimSecret, NodeClaimSecretVerifier, NodeClaimantNonce};
use crate::node_identity::ReuseEligibleNodeId;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use once_cell::sync::Lazy;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CLAIM_TTL_SECS: i64 = 10 * 60;
const CLAIM_TRUSTED_PROXY_IPS_ENV: &str = "NODE_CLAIM_TRUSTED_PROXY_IPS";
const CLAIM_ATTEMPT_LIMIT: u32 = 10;
const CLAIM_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const CLAIM_ATTEMPT_LIMITER_CAP: usize = 10_000;
const CLAIM_ATTEMPT_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ClaimAttemptWindow {
    count: u32,
    window_start: Instant,
}

#[derive(Debug)]
struct ClaimAttemptLimiter {
    entries: HashMap<String, ClaimAttemptWindow>,
    last_cleanup: Instant,
    #[cfg(test)]
    cleanup_runs: usize,
}

impl ClaimAttemptLimiter {
    fn new(now: Instant) -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: now,
            #[cfg(test)]
            cleanup_runs: 0,
        }
    }

    fn check(
        &mut self,
        key: &str,
        now: Instant,
        cap: usize,
        window: Duration,
        cleanup_interval: Duration,
    ) -> bool {
        if let Some(entry) = self.entries.get_mut(key) {
            if now.saturating_duration_since(entry.window_start) < window {
                entry.count = entry.count.saturating_add(1);
                return entry.count > CLAIM_ATTEMPT_LIMIT;
            }
            entry.count = 1;
            entry.window_start = now;
            return false;
        }

        if self.entries.len() >= cap {
            if now.saturating_duration_since(self.last_cleanup) >= cleanup_interval {
                self.entries
                    .retain(|_, entry| now.saturating_duration_since(entry.window_start) < window);
                self.last_cleanup = now;
                #[cfg(test)]
                {
                    self.cleanup_runs += 1;
                }
            }
            if self.entries.len() >= cap {
                return true;
            }
        }

        self.entries.insert(
            key.to_string(),
            ClaimAttemptWindow {
                count: 1,
                window_start: now,
            },
        );
        false
    }
}

static CLAIM_ATTEMPT_LIMITER: Lazy<Mutex<ClaimAttemptLimiter>> =
    Lazy::new(|| Mutex::new(ClaimAttemptLimiter::new(Instant::now())));

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeClaimRequest {
    pub home_group_id: i64,
    pub node_id: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct NodeClaimView {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    pub state: String,
    pub expires_at: String,
    pub approved_by: i64,
    pub approval_ref: String,
    pub created_at: String,
    pub updated_at: String,
    pub claimed_at: Option<String>,
    pub credential_pending_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
    pub expired_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreatedNodeClaim {
    pub claim: NodeClaimView,
    pub claim_secret: String,
}

#[derive(Debug, Serialize)]
pub struct NodeClaimStatus {
    pub claim: NodeClaimView,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimNodeRequest {
    pub home_group_id: i64,
    pub node_id: String,
    pub secret: String,
    pub claimant_nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ClaimNodeResult {
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<NodeClaimView>,
}

fn claim_view(record: &NodeCredentialClaimRecord) -> NodeClaimView {
    NodeClaimView {
        claim_id: record.claim_id.clone(),
        home_group_id: record.home_group_id,
        node_id: record.node_id.clone(),
        state: record.state.clone(),
        expires_at: record.expires_at.clone(),
        approved_by: record.approved_by,
        approval_ref: record.approval_ref.clone(),
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
        claimed_at: record.claimed_at.clone(),
        credential_pending_at: record.credential_pending_at.clone(),
        completed_at: record.completed_at.clone(),
        cancelled_at: record.cancelled_at.clone(),
        expired_at: record.expired_at.clone(),
    }
}

fn apply_sensitive_response_headers(response: &mut Response) {
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

pub async fn claim_response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_sensitive_response_headers(&mut response);
    response
}

fn sensitive_json<T: Serialize>(status: StatusCode, body: ApiResponse<T>) -> Response {
    let mut response = (status, Json(body)).into_response();
    apply_sensitive_response_headers(&mut response);
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

fn trusted_proxy_ips_from_env() -> Option<Vec<IpAddr>> {
    let raw = std::env::var(CLAIM_TRUSTED_PROXY_IPS_ENV).ok()?;
    let mut ips = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        ips.push(part.parse().ok()?);
    }
    (!ips.is_empty()).then_some(ips)
}

fn exactly_https_forwarded_proto(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all("x-forwarded-proto").iter();
    let Some(first) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    first
        .to_str()
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

fn configured_public_url_is_https(public_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(public_url) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().is_empty() || url.path() == "/")
}

fn claim_transport_allowed(
    public_url: &str,
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxy_ips: &[IpAddr],
) -> bool {
    configured_public_url_is_https(public_url)
        && trusted_proxy_ips.contains(&peer.ip())
        && exactly_https_forwarded_proto(headers)
}

pub(crate) async fn production_claim_transport_allowed(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> bool {
    let Some(trusted_proxy_ips) = trusted_proxy_ips_from_env() else {
        return false;
    };
    let Some(public_url) = effective_public_panel_url(state).await else {
        return false;
    };
    claim_transport_allowed(&public_url, peer, headers, &trusted_proxy_ips)
}

fn valid_claim_id(claim_id: &str) -> bool {
    uuid::Uuid::parse_str(claim_id)
        .map(|parsed| parsed.to_string() == claim_id)
        .unwrap_or(false)
}

fn rate_limit_key(home_group_id: i64, claim_id: &str) -> String {
    format!("{home_group_id}:{claim_id}")
}

fn claim_attempt_rate_limited(key: &str) -> bool {
    let now = Instant::now();
    CLAIM_ATTEMPT_LIMITER.lock().unwrap().check(
        key,
        now,
        CLAIM_ATTEMPT_LIMITER_CAP,
        CLAIM_ATTEMPT_WINDOW,
        CLAIM_ATTEMPT_CLEANUP_INTERVAL,
    )
}

pub async fn create_claim(
    admin: AdminOnly,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateNodeClaimRequest>,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Concrete Node Claim requires the configured trusted HTTPS ingress",
        );
    }
    create_claim_after_transport(admin, state, req).await
}

async fn create_claim_after_transport(
    admin: AdminOnly,
    state: AppState,
    req: CreateNodeClaimRequest,
) -> Response {
    let node_id = match ReuseEligibleNodeId::parse(&req.node_id) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(
                StatusCode::BAD_REQUEST,
                400,
                "node_id is not eligible for Node Reuse",
            )
        }
    };
    let group = match GroupRepository::find_by_id(
        state.db.as_ref(),
        req.home_group_id,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(Some(_)) => {
            return sensitive_error(
                StatusCode::BAD_REQUEST,
                400,
                "Home Group must be an inbound group",
            )
        }
        Ok(None) => return sensitive_error(StatusCode::NOT_FOUND, 404, "Home Group not found"),
        Err(error) => {
            tracing::error!("node claim Home Group lookup failed: {error}");
            return sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error");
        }
    };

    let claim_id = uuid::Uuid::new_v4().to_string();
    let secret = match NodeClaimSecret::generate() {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!("node claim secret generation failed: {error}");
            return sensitive_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                500,
                "could not generate Claim Secret",
            );
        }
    };
    let created_at = chrono::Utc::now();
    let expires_at = created_at + chrono::Duration::seconds(CLAIM_TTL_SECS);
    let secret_verifier = NodeClaimSecretVerifier::derive(&claim_id, group.id, &node_id, &secret);
    let new_claim = NewNodeCredentialClaim {
        claim_id: claim_id.clone(),
        home_group_id: group.id,
        node_id,
        secret_verifier,
        approved_by: admin.user_id,
        approval_ref: format!("admin-api:{claim_id}"),
        created_at,
        expires_at,
    };

    match state.db.create_node_credential_claim(&new_claim).await {
        Ok(NodeCredentialClaimCreateResult::Created(record)) => {
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "node_credential_claim_create",
                "node_credential_claim",
                &record.claim_id,
                &format!(
                    "home_group_id={} node_id={} state=APPROVED expires_at={}",
                    record.home_group_id, record.node_id, record.expires_at
                ),
            )
            .await;
            sensitive_json(
                StatusCode::OK,
                ApiResponse::success(CreatedNodeClaim {
                    claim: claim_view(&record),
                    claim_secret: secret.to_wire_value(),
                }),
            )
        }
        Ok(NodeCredentialClaimCreateResult::Existing(record)) => sensitive_json(
            StatusCode::CONFLICT,
            ApiResponse {
                code: 409,
                message: "an active Claim already exists; cancel it before creating a new Claim"
                    .into(),
                data: Some(NodeClaimStatus {
                    claim: claim_view(&record),
                }),
            },
        ),
        Ok(NodeCredentialClaimCreateResult::Rejected) => {
            sensitive_error(StatusCode::BAD_REQUEST, 400, "Claim request was rejected")
        }
        Err(error) => {
            tracing::error!("node claim create failed: {error}");
            sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        }
    }
}

pub async fn claim_status(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Concrete Node Claim requires the configured trusted HTTPS ingress",
        );
    }
    claim_status_after_transport(admin, state, claim_id).await
}

async fn claim_status_after_transport(
    _admin: AdminOnly,
    state: AppState,
    claim_id: String,
) -> Response {
    if !valid_claim_id(&claim_id) {
        return sensitive_error(StatusCode::NOT_FOUND, 404, "Claim not found");
    }
    let mut record = match state.db.find_node_credential_claim(&claim_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return sensitive_error(StatusCode::NOT_FOUND, 404, "Claim not found"),
        Err(error) => {
            tracing::error!("node claim status lookup failed: {error}");
            return sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error");
        }
    };

    if matches!(record.state.as_str(), "APPROVED" | "CLAIMED") {
        if let Ok(node_id) = ReuseEligibleNodeId::parse(&record.node_id) {
            match state
                .db
                .expire_node_credential_claim(
                    &record.claim_id,
                    record.home_group_id,
                    &node_id,
                    chrono::Utc::now(),
                )
                .await
            {
                Ok(NodeCredentialClaimMutationResult::Applied) => {
                    if let Ok(Some(refreshed)) =
                        state.db.find_node_credential_claim(&claim_id).await
                    {
                        record = refreshed;
                    }
                }
                Ok(NodeCredentialClaimMutationResult::Rejected) => {}
                Err(error) => {
                    tracing::error!("node claim status expiry check failed: {error}");
                    return sensitive_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        500,
                        "database error",
                    );
                }
            }
        }
    }

    sensitive_json(
        StatusCode::OK,
        ApiResponse::success(NodeClaimStatus {
            claim: claim_view(&record),
        }),
    )
}

pub async fn cancel_claim(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Concrete Node Claim requires the configured trusted HTTPS ingress",
        );
    }
    cancel_claim_after_transport(admin, state, claim_id).await
}

async fn cancel_claim_after_transport(
    admin: AdminOnly,
    state: AppState,
    claim_id: String,
) -> Response {
    if !valid_claim_id(&claim_id) {
        return sensitive_error(StatusCode::NOT_FOUND, 404, "Claim not found");
    }
    let record = match state.db.find_node_credential_claim(&claim_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return sensitive_error(StatusCode::NOT_FOUND, 404, "Claim not found"),
        Err(error) => {
            tracing::error!("node claim cancel lookup failed: {error}");
            return sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error");
        }
    };
    let node_id = match ReuseEligibleNodeId::parse(&record.node_id) {
        Ok(node_id) => node_id,
        Err(_) => {
            tracing::error!("persisted node claim contains invalid node_id");
            return sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error");
        }
    };

    match state
        .db
        .cancel_node_credential_claim(
            &record.claim_id,
            record.home_group_id,
            &node_id,
            chrono::Utc::now(),
        )
        .await
    {
        Ok(NodeCredentialClaimMutationResult::Applied) => {
            let refreshed = match state.db.find_node_credential_claim(&claim_id).await {
                Ok(Some(value)) => value,
                _ => {
                    return sensitive_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        500,
                        "could not load cancelled Claim",
                    )
                }
            };
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "node_credential_claim_cancel",
                "node_credential_claim",
                &claim_id,
                &format!(
                    "home_group_id={} node_id={} state=CANCELLED",
                    refreshed.home_group_id, refreshed.node_id
                ),
            )
            .await;
            sensitive_json(
                StatusCode::OK,
                ApiResponse::success(NodeClaimStatus {
                    claim: claim_view(&refreshed),
                }),
            )
        }
        Ok(NodeCredentialClaimMutationResult::Rejected) => {
            let latest = state
                .db
                .find_node_credential_claim(&claim_id)
                .await
                .ok()
                .flatten();
            sensitive_json(
                StatusCode::CONFLICT,
                ApiResponse {
                    code: 409,
                    message: "Claim is already terminal".into(),
                    data: latest.map(|record| NodeClaimStatus {
                        claim: claim_view(&record),
                    }),
                },
            )
        }
        Err(error) => {
            tracing::error!("node claim cancellation failed: {error}");
            sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        }
    }
}

pub async fn claim_node(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ClaimNodeRequest>,
) -> Response {
    if !production_claim_transport_allowed(&state, peer, &headers).await {
        return sensitive_error(
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "Concrete Node Claim requires the configured trusted HTTPS ingress",
        );
    }
    claim_node_after_transport(state, claim_id, headers, req).await
}

async fn claim_node_after_transport(
    state: AppState,
    claim_id: String,
    headers: HeaderMap,
    req: ClaimNodeRequest,
) -> Response {
    let token = match extract_node_token(&headers) {
        Some(token) if !token.is_empty() => token,
        _ => return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed"),
    };
    let group = match GroupRepository::find_by_token(state.db.as_ref(), &token).await {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => {
            return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed")
        }
        Err(error) => {
            tracing::error!("node claim token lookup failed: {error}");
            return sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error");
        }
    };

    if !valid_claim_id(&claim_id) || req.home_group_id != group.id {
        return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed");
    }
    let node_id = match ReuseEligibleNodeId::parse(&req.node_id) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed")
        }
    };
    let secret = match NodeClaimSecret::parse(&req.secret) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed")
        }
    };
    let claimant_nonce = match NodeClaimantNonce::parse(&req.claimant_nonce) {
        Ok(value) => value,
        Err(_) => {
            return sensitive_error(StatusCode::UNAUTHORIZED, 401, "claim authentication failed")
        }
    };

    let limiter_key = rate_limit_key(group.id, &claim_id);
    if claim_attempt_rate_limited(&limiter_key) {
        return sensitive_json(
            StatusCode::TOO_MANY_REQUESTS,
            ApiResponse {
                code: 429,
                message: "too many Claim attempts; retry later".into(),
                data: Some(ClaimNodeResult {
                    outcome: "RATE_LIMITED",
                    claim: None,
                }),
            },
        );
    }

    let attempt = NodeCredentialClaimAttempt {
        claim_id: claim_id.clone(),
        home_group_id: group.id,
        node_id,
        secret,
        claimant_nonce,
        now: chrono::Utc::now(),
    };

    match state.db.claim_node_credential(&attempt).await {
        Ok(NodeCredentialClaimResult::Claimed(record)) => {
            crate::service::audit::record(
                &state,
                None,
                "node_credential_claim_claimed",
                "node_credential_claim",
                &record.claim_id,
                &format!(
                    "home_group_id={} node_id={} state=CLAIMED",
                    record.home_group_id, record.node_id
                ),
            )
            .await;
            sensitive_json(
                StatusCode::OK,
                ApiResponse::success(ClaimNodeResult {
                    outcome: "CLAIMED",
                    claim: Some(claim_view(&record)),
                }),
            )
        }
        Ok(NodeCredentialClaimResult::Existing(record)) => sensitive_json(
            StatusCode::OK,
            ApiResponse::success(ClaimNodeResult {
                outcome: "EXISTING",
                claim: Some(claim_view(&record)),
            }),
        ),
        Ok(NodeCredentialClaimResult::Replay) => sensitive_json(
            StatusCode::CONFLICT,
            ApiResponse {
                code: 409,
                message: "Claim is already bound to a different claimant".into(),
                data: Some(ClaimNodeResult {
                    outcome: "REPLAY",
                    claim: None,
                }),
            },
        ),
        Ok(NodeCredentialClaimResult::Expired) => sensitive_json(
            StatusCode::GONE,
            ApiResponse {
                code: 410,
                message: "Claim has expired".into(),
                data: Some(ClaimNodeResult {
                    outcome: "EXPIRED",
                    claim: None,
                }),
            },
        ),
        Ok(NodeCredentialClaimResult::Cancelled) => sensitive_json(
            StatusCode::GONE,
            ApiResponse {
                code: 410,
                message: "Claim has been cancelled".into(),
                data: Some(ClaimNodeResult {
                    outcome: "CANCELLED",
                    claim: None,
                }),
            },
        ),
        Ok(NodeCredentialClaimResult::Invalid) => sensitive_json(
            StatusCode::UNAUTHORIZED,
            ApiResponse {
                code: 401,
                message: "claim authentication failed".into(),
                data: Some(ClaimNodeResult {
                    outcome: "INVALID",
                    claim: None,
                }),
            },
        ),
        Err(error) => {
            tracing::error!("node credential Claim transition failed: {error}");
            sensitive_error(StatusCode::INTERNAL_SERVER_ERROR, 500, "database error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::diagnose::DiagnoseRegistry;
    use crate::api::middleware::Claims;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::Value;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::sync::Arc;
    use tower::ServiceExt;

    static CLAIM_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    struct TrustedProxyEnvGuard;

    impl TrustedProxyEnvGuard {
        fn install(value: &str) -> Self {
            std::env::set_var(CLAIM_TRUSTED_PROXY_IPS_ENV, value);
            Self
        }
    }

    impl Drop for TrustedProxyEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(CLAIM_TRUSTED_PROXY_IPS_ENV);
        }
    }

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "UPDATE users SET username='admin-one', password='hash', admin=1, \
             token_version=0, must_change_password=0 WHERE id=1",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (id, username, admin) in [(2_i64, "member", false), (3_i64, "admin-three", true)] {
            sqlx::query(
                "INSERT INTO users (id, username, password, admin, token_version, must_change_password) \
                 VALUES (?, ?, 'hash', ?, 0, 0)",
            )
            .bind(id)
            .bind(username)
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        }
        for (id, token) in [
            (7_i64, "group-token-secret-7"),
            (8_i64, "group-token-secret-8"),
        ] {
            sqlx::query(
                "INSERT INTO device_groups (id, name, group_type, token, uid) \
                 VALUES (?, ?, 'in', ?, 1)",
            )
            .bind(id)
            .bind(format!("group-{id}"))
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (9, 'outbound', 'out', 'group-token-secret-9', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "node-claim-test-jwt-key".into(),
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
        };
        (state, pool)
    }

    fn auth_token(state: &AppState, user_id: i64, admin: bool) -> String {
        encode(
            &Header::default(),
            &Claims {
                sub: user_id,
                admin,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    fn node_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    async fn response_json(response: Response) -> (StatusCode, HeaderMap, Value) {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        (status, headers, value)
    }

    async fn create_for(
        state: &AppState,
        admin_id: i64,
        group_id: i64,
        node_id: &str,
    ) -> (StatusCode, HeaderMap, Value) {
        response_json(
            create_claim_after_transport(
                AdminOnly { user_id: admin_id },
                state.clone(),
                CreateNodeClaimRequest {
                    home_group_id: group_id,
                    node_id: node_id.to_string(),
                },
            )
            .await,
        )
        .await
    }

    fn extract_created(value: &Value) -> (String, String) {
        (
            value["data"]["claim"]["claim_id"]
                .as_str()
                .unwrap()
                .to_string(),
            value["data"]["claim_secret"].as_str().unwrap().to_string(),
        )
    }

    fn nonce() -> String {
        NodeClaimantNonce::generate().unwrap().to_wire_value()
    }

    fn claim_request(group: i64, node: &str, secret: &str, nonce: &str) -> ClaimNodeRequest {
        ClaimNodeRequest {
            home_group_id: group,
            node_id: node.to_string(),
            secret: secret.to_string(),
            claimant_nonce: nonce.to_string(),
        }
    }

    #[test]
    fn trusted_https_gate_requires_https_url_trusted_peer_and_single_proxy_header() {
        let trusted_peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let untrusted_peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let trusted = vec!["127.0.0.1".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());

        assert!(claim_transport_allowed(
            "https://panel.example",
            trusted_peer,
            &headers,
            &trusted
        ));
        assert!(!claim_transport_allowed(
            "http://panel.example",
            trusted_peer,
            &headers,
            &trusted
        ));
        assert!(!claim_transport_allowed(
            "https://panel.example",
            untrusted_peer,
            &headers,
            &trusted
        ));

        let mut spoofed = HeaderMap::new();
        spoofed.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(!claim_transport_allowed(
            "https://panel.example",
            untrusted_peer,
            &spoofed,
            &trusted
        ));

        let mut duplicated = HeaderMap::new();
        duplicated.append("x-forwarded-proto", "https".parse().unwrap());
        duplicated.append("x-forwarded-proto", "https".parse().unwrap());
        assert!(!claim_transport_allowed(
            "https://panel.example",
            trusted_peer,
            &duplicated,
            &trusted
        ));

        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!claim_transport_allowed(
            "https://panel.example",
            trusted_peer,
            &headers,
            &trusted
        ));
    }

    #[test]
    fn client_payload_cannot_supply_approval_identity_or_server_time() {
        assert!(
            serde_json::from_value::<CreateNodeClaimRequest>(serde_json::json!({
                "home_group_id": 7,
                "node_id": "Node_A",
                "approved_by": 999
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ClaimNodeRequest>(serde_json::json!({
                "home_group_id": 7,
                "node_id": "Node_A",
                "secret": "rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "claimant_nonce": "rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "now": "2099-01-01T00:00:00Z"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ClaimNodeRequest>(serde_json::json!({
                "home_group_id": 7,
                "node_id": "Node_A",
                "claimant_nonce": "rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }))
            .is_err(),
            "Group token plus self-reported identity cannot replace the Claim Secret"
        );
    }

    #[tokio::test]
    async fn admin_create_is_one_time_redacted_and_binds_authenticated_actor() {
        let (state, _pool) = test_state().await;
        let (status, headers, first) = create_for(&state, 1, 7, "Case_Sensitive").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        let (claim_id, secret) = extract_created(&first);
        assert!(secret.starts_with(crate::node_claim::NODE_CLAIM_SECRET_PREFIX));

        let stored = state
            .db
            .find_node_credential_claim(&claim_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.approved_by, 1);
        assert_eq!(stored.home_group_id, 7);
        assert_eq!(stored.node_id, "Case_Sensitive");
        assert!(!serde_json::to_string(&claim_view(&stored))
            .unwrap()
            .contains("verifier"));

        let (second_status, _, second) = create_for(&state, 3, 7, "Case_Sensitive").await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert_eq!(second["code"], 409);
        assert_eq!(second["data"]["claim"]["claim_id"], claim_id);
        assert!(
            second.get("claim_secret").is_none() && second["data"].get("claim_secret").is_none(),
            "Existing must never expose the newly-generated unpersisted Secret"
        );

        let rows = state
            .db
            .list_node_credential_claims_for_identity(
                7,
                &ReuseEligibleNodeId::parse("Case_Sensitive").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| matches!(row.state.as_str(), "APPROVED" | "CLAIMED"))
                .count(),
            1
        );

        let audits = state.db.query_audit_log(None, 100, 0).await.unwrap();
        let audit_json = serde_json::to_string(&audits).unwrap();
        assert!(!audit_json.contains(&secret));
        assert!(audits.iter().any(|entry| {
            entry.action == "node_credential_claim_create"
                && entry.actor_id == Some(1)
                && entry.target_id == claim_id
        }));
    }

    #[tokio::test]
    async fn admin_routes_require_real_admin_auth_and_cannot_forge_approved_by() {
        let _env_lock = CLAIM_ENV_LOCK.lock().await;
        let _env = TrustedProxyEnvGuard::install("127.0.0.1");
        let (state, _pool) = test_state().await;
        let router = crate::api::routes().with_state(state.clone());
        let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let body = serde_json::json!({
            "home_group_id": 7,
            "node_id": "Node_Route"
        })
        .to_string();

        let mut unauth = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-proto", "https")
            .body(Body::from(body.clone()))
            .unwrap();
        unauth.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.clone().oneshot(unauth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut member = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 2, false)),
            )
            .header("x-forwarded-proto", "https")
            .body(Body::from(body.clone()))
            .unwrap();
        member.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.clone().oneshot(member).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let forged = serde_json::json!({
            "home_group_id": 7,
            "node_id": "Node_Route",
            "approved_by": 999
        })
        .to_string();
        let mut forged_request = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 1, true)),
            )
            .header("x-forwarded-proto", "https")
            .body(Body::from(forged))
            .unwrap();
        forged_request.extensions_mut().insert(ConnectInfo(peer));
        let forged_response = router.clone().oneshot(forged_request).await.unwrap();
        assert_eq!(forged_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            forged_response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store",
            "route middleware must protect extractor-generated Claim responses too"
        );

        let mut untrusted_proxy = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 1, true)),
            )
            .header("x-forwarded-proto", "https")
            .body(Body::from(body.clone()))
            .unwrap();
        untrusted_proxy.extensions_mut().insert(ConnectInfo(
            "203.0.113.9:41000".parse::<SocketAddr>().unwrap(),
        ));
        assert_eq!(
            router
                .clone()
                .oneshot(untrusted_proxy)
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a client cannot spoof HTTPS merely by supplying X-Forwarded-Proto"
        );

        let mut plain_from_trusted_proxy = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 1, true)),
            )
            .header("x-forwarded-proto", "http")
            .body(Body::from(body.clone()))
            .unwrap();
        plain_from_trusted_proxy
            .extensions_mut()
            .insert(ConnectInfo(peer));
        assert_eq!(
            router
                .clone()
                .oneshot(plain_from_trusted_proxy)
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let mut admin = Request::builder()
            .method("POST")
            .uri("/admin/node-credential-claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 1, true)),
            )
            .header("x-forwarded-proto", "https")
            .body(Body::from(body))
            .unwrap();
        admin.extensions_mut().insert(ConnectInfo(peer));
        let response = router.clone().oneshot(admin).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (_, _, value) = response_json(response).await;
        let (claim_id, _) = extract_created(&value);
        let stored = state
            .db
            .find_node_credential_claim(&claim_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.approved_by, 1);

        let mut unauth_cancel = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/node-credential-claims/{claim_id}"))
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        unauth_cancel.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router
                .clone()
                .oneshot(unauth_cancel)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut member_cancel = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/node-credential-claims/{claim_id}"))
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", auth_token(&state, 2, false)),
            )
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        member_cancel.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(
            router.oneshot(member_cancel).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn node_claim_requires_group_secret_exact_identity_and_pins_nonce() {
        let (state, pool) = test_state().await;
        let (_, _, created) = create_for(&state, 1, 7, "Node_A").await;
        let (claim_id, secret) = extract_created(&created);
        let nonce_a = nonce();
        let nonce_b = nonce();

        let wrong_secret = NodeClaimSecret::generate().unwrap().to_wire_value();
        let (_, _, wrong) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Node_A", &wrong_secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(wrong["data"]["outcome"], "INVALID");

        let (_, _, wrong_case) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "node_A", &secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(wrong_case["data"]["outcome"], "INVALID");

        let (wrong_group_status, _, _) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-8"),
                claim_request(7, "Node_A", &secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(wrong_group_status, StatusCode::UNAUTHORIZED);

        let (claimed_status, claimed_headers, claimed) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Node_A", &secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(claimed_status, StatusCode::OK);
        assert_eq!(claimed["data"]["outcome"], "CLAIMED");
        assert_eq!(
            claimed_headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let claimed_text = claimed.to_string();
        assert!(!claimed_text.contains(&secret));
        assert!(!claimed_text.contains(&nonce_a));
        assert!(!claimed_text.contains("verifier"));

        let (_, _, retry) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Node_A", &secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(retry["data"]["outcome"], "EXISTING");

        let (replay_status, _, replay) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Node_A", &secret, &nonce_b),
            )
            .await,
        )
        .await;
        assert_eq!(replay_status, StatusCode::CONFLICT);
        assert_eq!(replay["data"]["outcome"], "REPLAY");

        let (_, _, wrong_after_claim) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Node_A", &wrong_secret, &nonce_a),
            )
            .await,
        )
        .await;
        assert_eq!(wrong_after_claim["data"]["outcome"], "INVALID");

        let credential_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_credentials")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            credential_count, 0,
            "real Claim flow must not issue or activate permanent credentials"
        );

        let audits = state.db.query_audit_log(None, 100, 0).await.unwrap();
        let audit_json = serde_json::to_string(&audits).unwrap();
        assert!(!audit_json.contains(&secret));
        assert!(!audit_json.contains(&nonce_a));
    }

    #[tokio::test]
    async fn node_claim_cancel_and_expiry_keep_secret_non_authoritative() {
        let (state, _pool) = test_state().await;

        let (_, _, created) = create_for(&state, 1, 7, "Cancel_Node").await;
        let (cancel_id, cancel_secret) = extract_created(&created);
        let cancelled = cancel_claim_after_transport(
            AdminOnly { user_id: 1 },
            state.clone(),
            cancel_id.clone(),
        )
        .await;
        assert_eq!(cancelled.status(), StatusCode::OK);
        let (_, _, cancelled_body) = response_json(cancelled).await;
        assert_eq!(cancelled_body["data"]["claim"]["state"], "CANCELLED");

        let (_, _, cancelled_attempt) = response_json(
            claim_node_after_transport(
                state.clone(),
                cancel_id.clone(),
                node_headers("group-token-secret-7"),
                claim_request(7, "Cancel_Node", &cancel_secret, &nonce()),
            )
            .await,
        )
        .await;
        assert_eq!(cancelled_attempt["data"]["outcome"], "CANCELLED");

        let wrong_secret = NodeClaimSecret::generate().unwrap().to_wire_value();
        let (_, _, hidden_terminal) = response_json(
            claim_node_after_transport(
                state.clone(),
                cancel_id,
                node_headers("group-token-secret-7"),
                claim_request(7, "Cancel_Node", &wrong_secret, &nonce()),
            )
            .await,
        )
        .await;
        assert_eq!(
            hidden_terminal["data"]["outcome"], "INVALID",
            "wrong Secret must not enumerate terminal state"
        );

        let claim_id = uuid::Uuid::new_v4().to_string();
        let node_id = ReuseEligibleNodeId::parse("Expired_Node").unwrap();
        let secret = NodeClaimSecret::generate().unwrap();
        let created_at = chrono::Utc::now() - chrono::Duration::minutes(20);
        let row = NewNodeCredentialClaim {
            claim_id: claim_id.clone(),
            home_group_id: 7,
            node_id: node_id.clone(),
            secret_verifier: NodeClaimSecretVerifier::derive(&claim_id, 7, &node_id, &secret),
            approved_by: 1,
            approval_ref: format!("test:{claim_id}"),
            created_at,
            expires_at: created_at + chrono::Duration::minutes(10),
        };
        assert!(matches!(
            state.db.create_node_credential_claim(&row).await.unwrap(),
            NodeCredentialClaimCreateResult::Created(_)
        ));
        let (_, _, expired) = response_json(
            claim_node_after_transport(
                state.clone(),
                claim_id,
                node_headers("group-token-secret-7"),
                claim_request(7, "Expired_Node", &secret.to_wire_value(), &nonce()),
            )
            .await,
        )
        .await;
        assert_eq!(expired["data"]["outcome"], "EXPIRED");
    }

    #[tokio::test]
    async fn status_view_never_exposes_secret_nonce_or_verifier_material() {
        let (state, _pool) = test_state().await;
        let (_, _, created) = create_for(&state, 1, 7, "Status_Node").await;
        let (claim_id, secret) = extract_created(&created);
        let status = claim_status_after_transport(AdminOnly { user_id: 1 }, state, claim_id).await;
        let (_, _, body) = response_json(status).await;
        let raw = body.to_string();
        assert_eq!(body["code"], 0);
        for forbidden in [
            "claim_secret",
            "secret_verifier",
            "claimant_nonce",
            "verifier_data",
            secret.as_str(),
        ] {
            assert!(!raw.contains(forbidden), "status leaked {forbidden}");
        }
    }

    #[tokio::test]
    async fn concurrent_api_claimants_have_one_first_claimant_and_one_replay() {
        let (state, _pool) = test_state().await;
        let (_, _, created) = create_for(&state, 1, 7, "Race_Node").await;
        let (claim_id, secret) = extract_created(&created);
        let nonce_a = nonce();
        let nonce_b = nonce();

        let a = claim_node_after_transport(
            state.clone(),
            claim_id.clone(),
            node_headers("group-token-secret-7"),
            claim_request(7, "Race_Node", &secret, &nonce_a),
        );
        let b = claim_node_after_transport(
            state.clone(),
            claim_id,
            node_headers("group-token-secret-7"),
            claim_request(7, "Race_Node", &secret, &nonce_b),
        );
        let (a, b) = tokio::join!(a, b);
        let (_, _, a) = response_json(a).await;
        let (_, _, b) = response_json(b).await;
        let outcomes = [
            a["data"]["outcome"].as_str().unwrap(),
            b["data"]["outcome"].as_str().unwrap(),
        ];
        assert!(outcomes.contains(&"CLAIMED"));
        assert!(outcomes.contains(&"REPLAY"));
    }

    #[tokio::test]
    async fn concurrent_admin_creates_return_one_secret_and_one_existing_status() {
        let (state, _pool) = test_state().await;
        let a = create_claim_after_transport(
            AdminOnly { user_id: 1 },
            state.clone(),
            CreateNodeClaimRequest {
                home_group_id: 7,
                node_id: "Admin_Race".into(),
            },
        );
        let b = create_claim_after_transport(
            AdminOnly { user_id: 3 },
            state.clone(),
            CreateNodeClaimRequest {
                home_group_id: 7,
                node_id: "Admin_Race".into(),
            },
        );
        let (a, b) = tokio::join!(a, b);
        let (sa, _, va) = response_json(a).await;
        let (sb, _, vb) = response_json(b).await;
        let created_count = [sa, sb]
            .into_iter()
            .filter(|status| *status == StatusCode::OK)
            .count();
        assert_eq!(created_count, 1);
        let conflict = if sa == StatusCode::CONFLICT { va } else { vb };
        assert_eq!(conflict["code"], 409);
        assert!(conflict["data"].get("claim_secret").is_none());
    }

    #[test]
    fn claim_attempt_limiter_enforces_window_and_hard_capacity() {
        let start = Instant::now();
        let mut limiter = ClaimAttemptLimiter::new(start);

        for _ in 0..CLAIM_ATTEMPT_LIMIT {
            assert!(!limiter.check(
                "7:known",
                start,
                3,
                CLAIM_ATTEMPT_WINDOW,
                CLAIM_ATTEMPT_CLEANUP_INTERVAL,
            ));
        }
        assert!(limiter.check(
            "7:known",
            start,
            3,
            CLAIM_ATTEMPT_WINDOW,
            CLAIM_ATTEMPT_CLEANUP_INTERVAL,
        ));

        assert!(!limiter.check(
            "7:second",
            start,
            3,
            CLAIM_ATTEMPT_WINDOW,
            CLAIM_ATTEMPT_CLEANUP_INTERVAL,
        ));
        assert!(!limiter.check(
            "7:third",
            start,
            3,
            CLAIM_ATTEMPT_WINDOW,
            CLAIM_ATTEMPT_CLEANUP_INTERVAL,
        ));
        assert_eq!(limiter.entries.len(), 3);

        assert!(
            limiter.check(
                "7:unknown",
                start,
                3,
                CLAIM_ATTEMPT_WINDOW,
                CLAIM_ATTEMPT_CLEANUP_INTERVAL,
            ),
            "unknown keys must fail closed when the hard cap is full"
        );
        assert_eq!(limiter.entries.len(), 3);
        assert!(
            limiter.check(
                "7:known",
                start,
                3,
                CLAIM_ATTEMPT_WINDOW,
                CLAIM_ATTEMPT_CLEANUP_INTERVAL,
            ),
            "full-cap rejection must not reset an existing key's window"
        );

        let key = rate_limit_key(7, "claim-public-id");
        assert_eq!(key, "7:claim-public-id");
        assert!(!key.contains("rpc1_"));
        assert!(!key.contains("rpcn1_"));
        assert!(!key.contains("group-token"));
    }

    #[test]
    fn claim_attempt_limiter_reclaims_expired_entries_without_scan_per_request() {
        let start = Instant::now();
        let mut limiter = ClaimAttemptLimiter::new(start);
        for key in ["7:a", "7:b", "7:c"] {
            assert!(!limiter.check(
                key,
                start,
                3,
                CLAIM_ATTEMPT_WINDOW,
                CLAIM_ATTEMPT_CLEANUP_INTERVAL,
            ));
        }

        let first_cleanup = start + CLAIM_ATTEMPT_CLEANUP_INTERVAL;
        assert!(limiter.check(
            "7:blocked-0",
            first_cleanup,
            3,
            CLAIM_ATTEMPT_WINDOW,
            CLAIM_ATTEMPT_CLEANUP_INTERVAL,
        ));
        assert_eq!(limiter.cleanup_runs, 1);

        for i in 1..=256 {
            assert!(limiter.check(
                &format!("7:blocked-{i}"),
                first_cleanup + Duration::from_millis(1),
                3,
                CLAIM_ATTEMPT_WINDOW,
                CLAIM_ATTEMPT_CLEANUP_INTERVAL,
            ));
        }
        assert_eq!(
            limiter.cleanup_runs, 1,
            "a full active map must not trigger an O(N) retain on every new key"
        );
        assert_eq!(limiter.entries.len(), 3);

        let after_expiry = start + CLAIM_ATTEMPT_WINDOW + CLAIM_ATTEMPT_CLEANUP_INTERVAL;
        assert!(!limiter.check(
            "7:after-expiry",
            after_expiry,
            3,
            CLAIM_ATTEMPT_WINDOW,
            CLAIM_ATTEMPT_CLEANUP_INTERVAL,
        ));
        assert_eq!(limiter.cleanup_runs, 2);
        assert_eq!(limiter.entries.len(), 1);
        assert!(limiter.entries.contains_key("7:after-expiry"));
    }

    #[test]
    fn claim_attempt_limiter_concurrency_never_exceeds_capacity() {
        const CAP: usize = 32;
        const ATTEMPTS: usize = 128;
        let start = Instant::now();
        let limiter = Arc::new(Mutex::new(ClaimAttemptLimiter::new(start)));
        let mut workers = Vec::new();

        for i in 0..ATTEMPTS {
            let limiter = Arc::clone(&limiter);
            workers.push(std::thread::spawn(move || {
                !limiter.lock().unwrap().check(
                    &format!("7:concurrent-{i}"),
                    start,
                    CAP,
                    CLAIM_ATTEMPT_WINDOW,
                    CLAIM_ATTEMPT_CLEANUP_INTERVAL,
                )
            }));
        }

        let admitted = workers.into_iter().fold(0_usize, |count, worker| {
            count + usize::from(worker.join().unwrap())
        });
        let limiter = limiter.lock().unwrap();
        assert_eq!(admitted, CAP);
        assert_eq!(limiter.entries.len(), CAP);
    }

    #[tokio::test]
    async fn claim_attempt_rate_limit_is_bounded_and_never_uses_secret_as_key() {
        let (state, _pool) = test_state().await;
        let (_, _, created) = create_for(&state, 1, 7, "Rate_Node").await;
        let (claim_id, _) = extract_created(&created);
        let wrong_secret = NodeClaimSecret::generate().unwrap().to_wire_value();
        let nonce = nonce();

        for _ in 0..CLAIM_ATTEMPT_LIMIT {
            let (status, _, body) = response_json(
                claim_node_after_transport(
                    state.clone(),
                    claim_id.clone(),
                    node_headers("group-token-secret-7"),
                    claim_request(7, "Rate_Node", &wrong_secret, &nonce),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["data"]["outcome"], "INVALID");
        }
        let (status, _, body) = response_json(
            claim_node_after_transport(
                state,
                claim_id,
                node_headers("group-token-secret-7"),
                claim_request(7, "Rate_Node", &wrong_secret, &nonce),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["data"]["outcome"], "RATE_LIMITED");
    }
}
