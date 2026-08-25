//! Durable Manual Bootstrap enrollment state.
//!
//! This module orchestrates enrollment and Panel-side verification only. It
//! never mutates a Relay host; `relay-node-bootstrap.sh` remains the sole
//! provisioning mutation engine.

use crate::api::middleware::AdminOnly;
use crate::api::provisioning::{
    bootstrap_session_lifetime_secs, capabilities_satisfy, load_artifact, normalize_architecture,
    ProvisioningBundle, ProvisioningProfile, ENROLLMENT_CLAIM_WINDOW_SECS,
};
use crate::api::stats::{status_last_seen, NODE_ONLINE_WINDOW_SECS};
use crate::api::AppState;
use crate::db::repo::{
    GroupRepository, ManualBootstrapClaim, ManualBootstrapClaimResult, ManualBootstrapEnrollment,
    NewManualBootstrapEnrollment, ResourceScope,
};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
const MANUAL_BOOTSTRAP_WRAPPER: &str =
    include_str!("../../../../scripts/relay-node-manual-bootstrap.sh");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnrollmentState {
    Pending,
    Claimed,
    Verifying,
    LocalCommitted,
    Success,
    Failed,
    Expired,
}

impl EnrollmentState {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "PENDING" => Some(Self::Pending),
            "CLAIMED" => Some(Self::Claimed),
            "VERIFYING" => Some(Self::Verifying),
            "LOCAL_COMMITTED" => Some(Self::LocalCommitted),
            "SUCCESS" => Some(Self::Success),
            "FAILED" => Some(Self::Failed),
            "EXPIRED" => Some(Self::Expired),
            _ => None,
        }
    }

    fn rollback_allowed(self) -> bool {
        matches!(self, Self::Claimed | Self::Verifying | Self::Failed)
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateEnrollmentRequest {
    pub group_id: i64,
    #[serde(default)]
    pub profile: ProvisioningProfile,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnrollmentView {
    pub id: String,
    pub group_id: i64,
    pub profile: ProvisioningProfile,
    pub state: EnrollmentState,
    pub architecture: Option<String>,
    pub node_id: Option<String>,
    pub observed_at: Option<String>,
    pub last_error_category: Option<String>,
    pub created_by: i64,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub session_expires_at: Option<String>,
    pub claimed_at: Option<String>,
    pub verified_at: Option<String>,
    pub local_committed_at: Option<String>,
    pub completed_at: Option<String>,
    pub rollback_allowed: bool,
}

#[derive(Debug, Serialize)]
pub struct CreatedEnrollment {
    pub enrollment: EnrollmentView,
    pub enrollment_secret: String,
    pub launcher_command: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimEnrollmentRequest {
    pub secret: String,
    pub architecture: String,
    pub client_nonce: String,
    pub profile: ProvisioningProfile,
}

#[derive(Debug, Serialize)]
pub struct ClaimedEnrollment {
    pub enrollment: EnrollmentView,
    pub bootstrap_session: String,
    pub session_expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct NodeIdentityRequest {
    pub node_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationErrorCategory {
    NodeOffline,
    NodeNotFound,
    NodeStatusStale,
    WrongGroup,
    InvalidObservedState,
    ArchitectureMismatch,
    CapabilityNotReported,
    CapabilityPayloadInvalid,
    CapabilityUnsupported,
    ProfileInvalid,
}

impl VerificationErrorCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::NodeOffline => "NODE_OFFLINE",
            Self::NodeNotFound => "NODE_NOT_FOUND",
            Self::NodeStatusStale => "STALE_OBSERVED_STATE",
            Self::WrongGroup => "WRONG_GROUP",
            Self::InvalidObservedState => "INVALID_OBSERVED_STATE",
            Self::ArchitectureMismatch => "ARCHITECTURE_MISMATCH",
            Self::CapabilityNotReported => "CAPABILITY_NOT_REPORTED",
            Self::CapabilityPayloadInvalid => "CAPABILITY_PAYLOAD_INVALID",
            Self::CapabilityUnsupported => "CAPABILITY_UNSUPPORTED",
            Self::ProfileInvalid => "PROFILE_INVALID",
        }
    }

    #[cfg(test)]
    fn is_transient(self) -> bool {
        matches!(
            self,
            Self::NodeOffline
                | Self::NodeNotFound
                | Self::NodeStatusStale
                | Self::CapabilityNotReported
        )
    }
}

#[derive(Debug, Serialize)]
struct VerificationApiResponse<T: Serialize> {
    code: i32,
    message: String,
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_category: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentFailureCategory {
    ProvisioningFailed,
    VerificationFailed,
    LocalCommitFailed,
    ClientAbandoned,
}

impl EnrollmentFailureCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProvisioningFailed => "PROVISIONING_FAILED",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::LocalCommitFailed => "LOCAL_COMMIT_FAILED",
            Self::ClientAbandoned => "CLIENT_ABANDONED",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FailEnrollmentRequest {
    pub category: EnrollmentFailureCategory,
}

#[derive(Debug, Serialize)]
pub struct FailedEnrollment {
    pub enrollment: EnrollmentView,
    pub rollback_required: bool,
}

pub async fn create_enrollment(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateEnrollmentRequest>,
) -> Json<ApiResponse<CreatedEnrollment>> {
    let group =
        match GroupRepository::find_by_id(state.db.as_ref(), req.group_id, &ResourceScope::All)
            .await
        {
            Ok(Some(group)) if group.group_type == "in" => group,
            Ok(Some(_)) => return api_error(400, "target device group must be inbound"),
            Ok(None) => return api_error(404, "device group not found"),
            Err(error) => {
                tracing::error!("manual enrollment group lookup failed: {error}");
                return api_error(500, "database error");
            }
        };
    if !valid_panel_url(&state.config.public_panel_url) {
        return api_error(409, "PUBLIC_PANEL_URL must use http:// or https://");
    }

    let id = uuid::Uuid::new_v4().to_string();
    let secret = random_token();
    let created_at = chrono::Utc::now();
    let expires_at = created_at + chrono::Duration::seconds(ENROLLMENT_CLAIM_WINDOW_SECS);
    let row = NewManualBootstrapEnrollment {
        id: id.clone(),
        secret_verifier: secret_verifier(&state, &id, &secret),
        group_id: group.id,
        profile: req.profile.as_str().into(),
        created_by: admin.user_id,
        created_at: created_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };
    if let Err(error) = state.db.create_manual_bootstrap_enrollment(&row).await {
        tracing::error!("manual enrollment create failed: {error}");
        return api_error(500, "database error");
    }
    let enrollment = match state.db.find_manual_bootstrap_enrollment(&id).await {
        Ok(Some(value)) => value,
        _ => return api_error(500, "could not load created enrollment"),
    };
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "node_enrollment_create",
        "node_enrollment",
        &id,
        &format!(
            "group_id={} profile={} state=PENDING",
            group.id,
            req.profile.as_str()
        ),
    )
    .await;

    Json(ApiResponse::success(CreatedEnrollment {
        enrollment: enrollment_view(&enrollment),
        enrollment_secret: secret,
        launcher_command: launcher_command(&state.config.public_panel_url, &id),
    }))
}

pub async fn manual_bootstrap_launcher() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        MANUAL_BOOTSTRAP_WRAPPER,
    )
        .into_response()
}

pub async fn enrollment_bundle(
    State(state): State<AppState>,
    Path((id, requested_architecture)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (enrollment, _session_verifier) =
        match authenticated_enrollment(&state, &id, &headers).await {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    if !matches!(enrollment.state.as_str(), "CLAIMED" | "VERIFYING") {
        return bundle_error(409, "enrollment is not eligible for a bootstrap bundle");
    }
    let Some(architecture) = normalize_architecture(&requested_architecture) else {
        return bundle_error(400, "unsupported architecture");
    };
    if enrollment.architecture.as_deref() != Some(architecture) {
        return bundle_error(409, "bundle architecture does not match enrollment claim");
    }
    let group = match GroupRepository::find_by_id(
        state.db.as_ref(),
        enrollment.group_id,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => return bundle_error(409, "enrollment device group is unavailable"),
        Err(error) => {
            tracing::error!("manual enrollment bundle group lookup failed: {error}");
            return bundle_error(500, "database error");
        }
    };
    let artifact = match load_artifact(architecture) {
        Ok(artifact) => artifact,
        Err(error) => return bundle_error(503, error.message),
    };
    let bundle = ProvisioningBundle::new(&state.config.public_panel_url, &group.token, artifact);
    match render_bundle(
        &id,
        enrollment.group_id,
        enrollment.profile.as_str(),
        &bundle,
    ) {
        Ok(bytes) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/x-tar"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=relay-panel-bootstrap.tar"),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => {
            tracing::error!("manual enrollment bundle render failed: {error}");
            bundle_error(500, "could not build bootstrap bundle")
        }
    }
}

pub async fn enrollment_status(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<EnrollmentView>> {
    let now = chrono::Utc::now().to_rfc3339();
    if let Err(error) = state.db.expire_manual_bootstrap_enrollment(&id, &now).await {
        tracing::error!("manual enrollment expiry check failed: {error}");
        return api_error(500, "database error");
    }
    match state.db.find_manual_bootstrap_enrollment(&id).await {
        Ok(Some(enrollment)) => Json(ApiResponse::success(enrollment_view(&enrollment))),
        Ok(None) => api_error(404, "enrollment not found"),
        Err(error) => {
            tracing::error!("manual enrollment status failed: {error}");
            api_error(500, "database error")
        }
    }
}

pub async fn claim_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ClaimEnrollmentRequest>,
) -> Json<ApiResponse<ClaimedEnrollment>> {
    if !valid_id(&id) || !valid_secret(&req.secret) || !valid_nonce(&req.client_nonce) {
        return api_error(401, "invalid or expired enrollment credential");
    }
    let Some(architecture) = normalize_architecture(req.architecture.trim()) else {
        return api_error(400, "unsupported architecture");
    };
    let existing = match state.db.find_manual_bootstrap_enrollment(&id).await {
        Ok(Some(value)) => value,
        Ok(None) => return api_error(401, "invalid or expired enrollment credential"),
        Err(error) => {
            tracing::error!("manual enrollment claim lookup failed: {error}");
            return api_error(500, "database error");
        }
    };
    if req.profile.as_str() != existing.profile
        || !verify_secret(&state, &id, &req.secret, &existing.secret_verifier)
    {
        return api_error(401, "invalid or expired enrollment credential");
    }

    let now = chrono::Utc::now();
    let session_expires_at = now + chrono::Duration::seconds(bootstrap_session_lifetime_secs());
    let nonce_verifier = keyed_verifier(&state, "client-nonce", &[&id, &req.client_nonce]);
    let session = derived_session(&state, &id, &req.secret, &req.client_nonce);
    let session_verifier = keyed_verifier(&state, "bootstrap-session", &[&session]);
    let claim = ManualBootstrapClaim {
        id: id.clone(),
        secret_verifier: existing.secret_verifier,
        profile: req.profile.as_str().into(),
        architecture: architecture.into(),
        client_nonce_verifier: nonce_verifier,
        session_verifier,
        session_expires_at: session_expires_at.to_rfc3339(),
        now: now.to_rfc3339(),
    };
    match state.db.claim_manual_bootstrap_enrollment(&claim).await {
        Ok(ManualBootstrapClaimResult::Claimed(enrollment)) => {
            audit_transition(&state, &enrollment, "node_enrollment_claim", None).await;
            Json(ApiResponse::success(ClaimedEnrollment {
                enrollment: enrollment_view(&enrollment),
                bootstrap_session: session,
                session_expires_at: enrollment.session_expires_at.clone().unwrap_or_default(),
            }))
        }
        Ok(ManualBootstrapClaimResult::Existing(enrollment)) => {
            Json(ApiResponse::success(ClaimedEnrollment {
                enrollment: enrollment_view(&enrollment),
                bootstrap_session: session,
                session_expires_at: enrollment.session_expires_at.clone().unwrap_or_default(),
            }))
        }
        Ok(ManualBootstrapClaimResult::Expired) => {
            api_error(410, "enrollment or bootstrap session expired")
        }
        Ok(ManualBootstrapClaimResult::Invalid) => {
            api_error(401, "invalid or expired enrollment credential")
        }
        Ok(ManualBootstrapClaimResult::Replay) => {
            api_error(409, "enrollment is already bound to another client")
        }
        Err(error) => {
            tracing::error!("manual enrollment claim failed: {error}");
            api_error(500, "database error")
        }
    }
}

pub async fn verify_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<NodeIdentityRequest>,
) -> Response {
    let node_id = match validated_node_id(&req.node_id) {
        Some(value) => value,
        None => return api_error::<()>(400, "invalid node ID").into_response(),
    };
    let (enrollment, session_verifier) =
        match authenticated_enrollment_for_local_commit(&state, &id, &headers).await {
            Ok(value) => value,
            Err(error) => return error.into_json::<()>().into_response(),
        };
    if !matches!(enrollment.state.as_str(), "CLAIMED" | "VERIFYING") {
        return api_error::<()>(409, "enrollment is not awaiting verification").into_response();
    }

    let verification = verify_node_state(&state, &enrollment, node_id).await;
    let observed_at = match verification {
        Ok(value) => value,
        Err((category, message)) => {
            let now = chrono::Utc::now().to_rfc3339();
            let _ = state
                .db
                .record_manual_bootstrap_verification_error(
                    &id,
                    &session_verifier,
                    category.as_str(),
                    &now,
                )
                .await;
            return verification_api_error(409, category, message);
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    match state
        .db
        .mark_manual_bootstrap_verifying(&id, &session_verifier, node_id, &observed_at, &now)
        .await
    {
        Ok(1) => {
            let updated = load_enrollment(&state, &id).await;
            match updated {
                Ok(value) => {
                    if enrollment.state == "CLAIMED" {
                        audit_transition(&state, &value, "node_enrollment_verified", Some(node_id))
                            .await;
                    }
                    Json(ApiResponse::success(enrollment_view(&value))).into_response()
                }
                Err(error) => error.into_json::<()>().into_response(),
            }
        }
        Ok(_) => {
            api_error::<()>(409, "enrollment verification transition rejected").into_response()
        }
        Err(error) => {
            tracing::error!("manual enrollment verify transition failed: {error}");
            api_error::<()>(500, "database error").into_response()
        }
    }
}

pub async fn mark_local_committed(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<NodeIdentityRequest>,
) -> Json<ApiResponse<EnrollmentView>> {
    let Some(node_id) = validated_node_id(&req.node_id) else {
        return api_error(400, "invalid node ID");
    };
    let (enrollment, session_verifier) =
        match authenticated_enrollment_for_local_commit(&state, &id, &headers).await {
            Ok(value) => value,
            Err(error) => return error.into_json(),
        };
    if matches!(enrollment.state.as_str(), "LOCAL_COMMITTED" | "SUCCESS")
        && enrollment.node_id.as_deref() == Some(node_id)
    {
        return Json(ApiResponse::success(enrollment_view(&enrollment)));
    }
    if enrollment.state != "VERIFYING" || enrollment.node_id.as_deref() != Some(node_id) {
        return api_error(
            409,
            "local commit requires successful verification for this node",
        );
    }
    if let Err((category, message)) = verify_node_state(&state, &enrollment, node_id).await {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = state
            .db
            .record_manual_bootstrap_verification_error(
                &id,
                &session_verifier,
                category.as_str(),
                &now,
            )
            .await;
        return api_error(409, message);
    }
    let now = chrono::Utc::now().to_rfc3339();
    match state
        .db
        .mark_manual_bootstrap_local_committed(&id, &session_verifier, node_id, &now)
        .await
    {
        Ok(1) => match load_enrollment(&state, &id).await {
            Ok(value) => {
                audit_transition(
                    &state,
                    &value,
                    "node_enrollment_local_committed",
                    Some(node_id),
                )
                .await;
                Json(ApiResponse::success(enrollment_view(&value)))
            }
            Err(error) => error.into_json(),
        },
        Ok(_) => api_error(409, "local commit transition rejected"),
        Err(error) => {
            tracing::error!("manual enrollment local commit failed: {error}");
            api_error(500, "database error")
        }
    }
}

pub async fn complete_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Json<ApiResponse<EnrollmentView>> {
    let (enrollment, session_verifier) =
        match authenticated_enrollment_for_completion(&state, &id, &headers).await {
            Ok(value) => value,
            Err(error) => return error.into_json(),
        };
    if enrollment.state == "SUCCESS" {
        return Json(ApiResponse::success(enrollment_view(&enrollment)));
    }
    if enrollment.state != "LOCAL_COMMITTED" {
        return api_error(409, "completion requires a locally committed enrollment");
    }
    let Some(node_id) = enrollment.node_id.as_deref() else {
        return api_error(409, "locally committed enrollment has no verified node ID");
    };
    if let Err((category, message)) = verify_node_state(&state, &enrollment, node_id).await {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = state
            .db
            .fail_manual_bootstrap_enrollment(&id, &session_verifier, category.as_str(), &now)
            .await;
        return api_error(409, message);
    }
    let now = chrono::Utc::now().to_rfc3339();
    match state
        .db
        .complete_manual_bootstrap_enrollment(&id, &session_verifier, &now)
        .await
    {
        Ok(1) => match load_enrollment(&state, &id).await {
            Ok(value) => {
                audit_transition(
                    &state,
                    &value,
                    "node_enrollment_complete",
                    value.node_id.as_deref(),
                )
                .await;
                Json(ApiResponse::success(enrollment_view(&value)))
            }
            Err(error) => error.into_json(),
        },
        Ok(_) => match load_enrollment(&state, &id).await {
            Ok(value) if value.state == "SUCCESS" => {
                Json(ApiResponse::success(enrollment_view(&value)))
            }
            Ok(_) => api_error(409, "completion transition rejected"),
            Err(error) => error.into_json(),
        },
        Err(error) => {
            tracing::error!("manual enrollment completion failed: {error}");
            api_error(500, "database error")
        }
    }
}

pub async fn fail_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<FailEnrollmentRequest>,
) -> Json<ApiResponse<FailedEnrollment>> {
    let (before, session_verifier) = match authenticated_enrollment(&state, &id, &headers).await {
        Ok(value) => value,
        Err(error) => return error.into_json(),
    };
    let now = chrono::Utc::now().to_rfc3339();
    if let Err(error) = state
        .db
        .fail_manual_bootstrap_enrollment(&id, &session_verifier, req.category.as_str(), &now)
        .await
    {
        tracing::error!("manual enrollment failure transition failed: {error}");
        return api_error(500, "database error");
    }
    let enrollment = match load_enrollment(&state, &id).await {
        Ok(value) => value,
        Err(error) => return error.into_json(),
    };
    let rollback_required = matches!(before.state.as_str(), "CLAIMED" | "VERIFYING" | "FAILED");
    audit_transition(
        &state,
        &enrollment,
        "node_enrollment_failed",
        enrollment.node_id.as_deref(),
    )
    .await;
    Json(ApiResponse::success(FailedEnrollment {
        enrollment: enrollment_view(&enrollment),
        rollback_required,
    }))
}

async fn verify_node_state(
    state: &AppState,
    enrollment: &ManualBootstrapEnrollment,
    node_id: &str,
) -> Result<String, (VerificationErrorCategory, &'static str)> {
    if !state
        .node_connections
        .online_node_ids(enrollment.group_id)
        .await
        .contains(node_id)
    {
        if state
            .node_connections
            .online_group_ids(node_id)
            .await
            .iter()
            .any(|group_id| *group_id != enrollment.group_id)
        {
            return Err((
                VerificationErrorCategory::WrongGroup,
                "node is authenticated to a different device group",
            ));
        }
        return Err((
            VerificationErrorCategory::NodeOffline,
            "node is not authenticated and online",
        ));
    }
    let key = format!("node_status:{}:{node_id}", enrollment.group_id);
    let raw = state.db.get(&key).await.ok().flatten().ok_or((
        VerificationErrorCategory::NodeNotFound,
        "fresh node observed state was not found",
    ))?;
    let observed = status_last_seen(&raw).ok_or((
        VerificationErrorCategory::NodeStatusStale,
        "node observed state is missing a valid timestamp",
    ))?;
    let now = chrono::Utc::now();
    let claimed_at = enrollment
        .claimed_at
        .as_deref()
        .and_then(parse_timestamp)
        .ok_or((
            VerificationErrorCategory::NodeStatusStale,
            "enrollment claim timestamp is invalid",
        ))?;
    if observed < claimed_at
        || (now - observed).num_seconds() > NODE_ONLINE_WINDOW_SECS
        || observed > now + chrono::Duration::seconds(5)
    {
        return Err((
            VerificationErrorCategory::NodeStatusStale,
            "node observed state is not fresh",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|_| {
        (
            VerificationErrorCategory::InvalidObservedState,
            "node observed state is invalid",
        )
    })?;
    let observed_architecture = value
        .get("architecture")
        .and_then(|value| value.as_str())
        .and_then(normalize_architecture);
    if observed_architecture != enrollment.architecture.as_deref() {
        return Err((
            VerificationErrorCategory::ArchitectureMismatch,
            "node architecture does not match the claim",
        ));
    }
    let capability_value = value.get("provisioning_capabilities").ok_or((
        VerificationErrorCategory::CapabilityNotReported,
        "node did not report provisioning capabilities",
    ))?;
    let capabilities = serde_json::from_value(capability_value.clone()).map_err(|_| {
        (
            VerificationErrorCategory::CapabilityPayloadInvalid,
            "node provisioning capabilities payload is invalid",
        )
    })?;
    let profile = ProvisioningProfile::parse(&enrollment.profile).ok_or((
        VerificationErrorCategory::ProfileInvalid,
        "enrollment profile is invalid",
    ))?;
    if !capabilities_satisfy(capabilities, profile.required_capabilities()) {
        return Err((
            VerificationErrorCategory::CapabilityUnsupported,
            "node did not report the requested provisioning capabilities",
        ));
    }
    Ok(observed.to_rfc3339())
}

async fn authenticated_enrollment(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<(ManualBootstrapEnrollment, String), EnrollmentApiError> {
    authenticated_enrollment_with_policy(state, id, headers, false, false).await
}

async fn authenticated_enrollment_for_completion(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<(ManualBootstrapEnrollment, String), EnrollmentApiError> {
    authenticated_enrollment_with_policy(state, id, headers, true, false).await
}

async fn authenticated_enrollment_for_local_commit(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<(ManualBootstrapEnrollment, String), EnrollmentApiError> {
    authenticated_enrollment_with_policy(state, id, headers, false, true).await
}

async fn authenticated_enrollment_with_policy(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    allow_committed_expiry: bool,
    allow_verifying_expiry: bool,
) -> Result<(ManualBootstrapEnrollment, String), EnrollmentApiError> {
    if !valid_id(id) {
        return Err(EnrollmentApiError::new(401, "invalid bootstrap session"));
    }
    let session = bearer(headers)
        .filter(|value| valid_secret(value))
        .ok_or_else(|| EnrollmentApiError::new(401, "invalid bootstrap session"))?;
    let now = chrono::Utc::now().to_rfc3339();
    state
        .db
        .expire_manual_bootstrap_enrollment(id, &now)
        .await
        .map_err(|error| {
            tracing::error!("manual enrollment session expiry failed: {error}");
            EnrollmentApiError::new(500, "database error")
        })?;
    let enrollment = load_enrollment(state, id).await?;
    let stored = enrollment
        .session_verifier
        .as_deref()
        .ok_or_else(|| EnrollmentApiError::new(401, "invalid bootstrap session"))?;
    let verifier = keyed_verifier(state, "bootstrap-session", &[session]);
    if !constant_time_hex_eq(stored, &verifier) {
        return Err(EnrollmentApiError::new(401, "invalid bootstrap session"));
    }
    let committed_completion = allow_committed_expiry
        && matches!(enrollment.state.as_str(), "LOCAL_COMMITTED" | "SUCCESS");
    let verifying_local_commit = allow_verifying_expiry && enrollment.state == "VERIFYING";
    if enrollment.state == "EXPIRED"
        || (!committed_completion
            && !verifying_local_commit
            && enrollment.session_expires_at.as_deref() <= Some(now.as_str()))
    {
        return Err(EnrollmentApiError::new(410, "bootstrap session expired"));
    }
    Ok((enrollment, verifier))
}

async fn load_enrollment(
    state: &AppState,
    id: &str,
) -> Result<ManualBootstrapEnrollment, EnrollmentApiError> {
    state
        .db
        .find_manual_bootstrap_enrollment(id)
        .await
        .map_err(|error| {
            tracing::error!("manual enrollment lookup failed: {error}");
            EnrollmentApiError::new(500, "database error")
        })?
        .ok_or_else(|| EnrollmentApiError::new(404, "enrollment not found"))
}

async fn audit_transition(
    state: &AppState,
    enrollment: &ManualBootstrapEnrollment,
    action: &str,
    node_id: Option<&str>,
) {
    let detail = match node_id {
        Some(node_id) => format!(
            "group_id={} profile={} state={} node_id={node_id}",
            enrollment.group_id, enrollment.profile, enrollment.state
        ),
        None => format!(
            "group_id={} profile={} state={}",
            enrollment.group_id, enrollment.profile, enrollment.state
        ),
    };
    crate::service::audit::record(
        state,
        None,
        action,
        "node_enrollment",
        &enrollment.id,
        &detail,
    )
    .await;
}

fn enrollment_view(enrollment: &ManualBootstrapEnrollment) -> EnrollmentView {
    let state = EnrollmentState::parse(&enrollment.state).unwrap_or(EnrollmentState::Failed);
    EnrollmentView {
        id: enrollment.id.clone(),
        group_id: enrollment.group_id,
        profile: ProvisioningProfile::parse(&enrollment.profile).unwrap_or_default(),
        state,
        architecture: enrollment.architecture.clone(),
        node_id: enrollment.node_id.clone(),
        observed_at: enrollment.observed_at.clone(),
        last_error_category: enrollment.last_error_category.clone(),
        created_by: enrollment.created_by,
        created_at: enrollment.created_at.clone(),
        updated_at: enrollment.updated_at.clone(),
        expires_at: enrollment.expires_at.clone(),
        session_expires_at: enrollment.session_expires_at.clone(),
        claimed_at: enrollment.claimed_at.clone(),
        verified_at: enrollment.verified_at.clone(),
        local_committed_at: enrollment.local_committed_at.clone(),
        completed_at: enrollment.completed_at.clone(),
        rollback_allowed: state.rollback_allowed(),
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn launcher_command(panel_url: &str, enrollment_id: &str) -> String {
    let panel_url = panel_url.trim_end_matches('/');
    format!(
        "curl --proto '=http,https' --fail --silent --show-error {} | bash -s -- --panel-url {} --enrollment-id {}",
        shell_quote(&format!(
            "{panel_url}/api/v1/node-enrollments/manual-bootstrap-launcher.sh"
        )),
        shell_quote(panel_url),
        shell_quote(enrollment_id),
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn valid_panel_url(url: &str) -> bool {
    let url = url.trim();
    url.starts_with("http://") || url.starts_with("https://")
}

fn bundle_error(status: u16, message: &'static str) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(ApiResponse::<()> {
            code: status as i32,
            message: message.into(),
            data: None,
        }),
    )
        .into_response()
}

fn render_bundle(
    enrollment_id: &str,
    group_id: i64,
    profile: &str,
    bundle: &ProvisioningBundle,
) -> io::Result<Vec<u8>> {
    let script = bundle.install_script.as_bytes();
    let config = bundle.config.as_bytes();
    let artifact = &bundle.artifact.bytes;
    let manifest = format!(
        "BUNDLE_VERSION=1\nENROLLMENT_ID={}\nGROUP_ID={}\nPROFILE={}\nARCHITECTURE={}\nARTIFACT_SHA256={}\nBOOTSTRAP_SCRIPT_SHA256={}\nBOOTSTRAP_CONFIG_SHA256={}\n",
        enrollment_id,
        group_id,
        profile,
        bundle.artifact.architecture,
        bundle.artifact.sha256,
        sha256_hex(script),
        sha256_hex(config),
    );
    let mut archive = tar::Builder::new(Vec::new());
    append_bundle_file(&mut archive, "manifest.env", manifest.as_bytes(), 0o600)?;
    append_bundle_file(&mut archive, "relay-node-bootstrap.sh", script, 0o700)?;
    append_bundle_file(
        &mut archive,
        &format!("relay-node-linux-{}", bundle.artifact.architecture),
        artifact,
        0o700,
    )?;
    append_bundle_file(&mut archive, "config.env", config, 0o600)?;
    archive.into_inner()
}

fn append_bundle_file(
    archive: &mut tar::Builder<Vec<u8>>,
    name: &str,
    contents: &[u8],
    mode: u32,
) -> io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    archive.append_data(&mut header, name, contents)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn secret_verifier(state: &AppState, id: &str, secret: &str) -> String {
    keyed_verifier(state, "enrollment-secret", &[id, secret])
}

fn verify_secret(state: &AppState, id: &str, secret: &str, expected: &str) -> bool {
    constant_time_hex_eq(expected, &secret_verifier(state, id, secret))
}

fn derived_session(state: &AppState, id: &str, secret: &str, nonce: &str) -> String {
    let bytes = keyed_digest(state, "bootstrap-session-token", &[id, secret, nonce]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn keyed_verifier(state: &AppState, purpose: &str, values: &[&str]) -> String {
    hex::encode(keyed_digest(state, purpose, values))
}

fn keyed_digest(state: &AppState, purpose: &str, values: &[&str]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(state.config.jwt_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(b"relay-panel/manual-bootstrap/v1\0");
    mac.update(purpose.as_bytes());
    for value in values {
        mac.update(&[0]);
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

fn constant_time_hex_eq(expected: &str, actual: &str) -> bool {
    let Ok(expected) = hex::decode(expected) else {
        return false;
    };
    let Ok(actual) = hex::decode(actual) else {
        return false;
    };
    expected.len() == actual.len() && bool::from(expected.ct_eq(&actual))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

fn valid_secret(value: &str) -> bool {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

fn valid_nonce(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validated_node_id(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        None
    } else {
        Some(value)
    }
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

struct EnrollmentApiError {
    code: i32,
    message: &'static str,
}

impl EnrollmentApiError {
    fn new(code: i32, message: &'static str) -> Self {
        Self { code, message }
    }

    fn into_json<T: Serialize>(self) -> Json<ApiResponse<T>> {
        api_error(self.code, self.message)
    }

    fn into_response(self) -> Response {
        bundle_error(self.code as u16, self.message)
    }
}

fn api_error<T: Serialize>(code: i32, message: impl Into<String>) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        code,
        message: message.into(),
        data: None,
    })
}

fn verification_api_error(
    code: i32,
    category: VerificationErrorCategory,
    message: &str,
) -> Response {
    Json(VerificationApiResponse::<EnrollmentView> {
        code,
        message: message.into(),
        data: None,
        error_category: Some(category.as_str()),
    })
    .into_response()
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use relay_shared::protocol::ProvisioningCapabilities;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::io::Read;
    use std::sync::Arc;
    use tower::ServiceExt;

    const NONCE_A: &str = "client_nonce_aaaaaaaaaaaaaaaa";
    const NONCE_B: &str = "client_nonce_bbbbbbbbbbbbbbbb";

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, token_version) \
             VALUES (2, 'member', 'hash', 0, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (id, token) in [(7_i64, "group-token-secret-7"), (8, "group-token-secret-8")] {
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
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "stable-enrollment-test-key".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
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

    async fn create_test_enrollment(state: &AppState) -> CreatedEnrollment {
        let Json(response) = create_enrollment(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(CreateEnrollmentRequest {
                group_id: 7,
                profile: ProvisioningProfile::RealityCamouflage,
            }),
        )
        .await;
        assert_eq!(response.code, 0, "{}", response.message);
        response.data.unwrap()
    }

    async fn claim(
        state: &AppState,
        id: &str,
        secret: &str,
        nonce: &str,
        architecture: &str,
        profile: ProvisioningProfile,
    ) -> ApiResponse<ClaimedEnrollment> {
        let Json(response) = claim_enrollment(
            State(state.clone()),
            Path(id.to_string()),
            Json(ClaimEnrollmentRequest {
                secret: secret.into(),
                architecture: architecture.into(),
                client_nonce: nonce.into(),
                profile,
            }),
        )
        .await;
        response
    }

    async fn claimed(state: &AppState) -> (CreatedEnrollment, ClaimedEnrollment) {
        let created = create_test_enrollment(state).await;
        let response = claim(
            state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "x86_64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(response.code, 0, "{}", response.message);
        (created, response.data.unwrap())
    }

    fn session_headers(session: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {session}").parse().unwrap(),
        );
        headers
    }

    async fn seed_observed(
        state: &AppState,
        group_id: i64,
        node_id: &str,
        architecture: &str,
        capabilities: ProvisioningCapabilities,
        last_seen: chrono::DateTime<chrono::Utc>,
        online: bool,
    ) {
        state
            .db
            .set(
                &format!("node_status:{group_id}:{node_id}"),
                &serde_json::json!({
                    "last_seen": last_seen.to_rfc3339(),
                    "architecture": architecture,
                    "provisioning_capabilities": capabilities,
                })
                .to_string(),
            )
            .await
            .unwrap();
        if online {
            let _ = state
                .node_connections
                .register(group_id, Some(node_id.into()))
                .await;
        }
    }

    async fn verify_json(
        state: &AppState,
        id: &str,
        session: &str,
        node_id: &str,
    ) -> serde_json::Value {
        let response = verify_enrollment(
            State(state.clone()),
            Path(id.into()),
            session_headers(session),
            Json(NodeIdentityRequest {
                node_id: node_id.into(),
            }),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn verify(
        state: &AppState,
        id: &str,
        session: &str,
        node_id: &str,
    ) -> ApiResponse<EnrollmentView> {
        serde_json::from_value(verify_json(state, id, session, node_id).await).unwrap()
    }

    async fn verify_healthy(
        state: &AppState,
        enrollment: &ClaimedEnrollment,
        node_id: &str,
    ) -> EnrollmentView {
        seed_observed(
            state,
            enrollment.enrollment.group_id,
            node_id,
            "x86_64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let response = verify(
            state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            node_id,
        )
        .await;
        assert_eq!(response.code, 0, "{}", response.message);
        response.data.unwrap()
    }

    async fn local_commit(
        state: &AppState,
        enrollment: &ClaimedEnrollment,
        node_id: &str,
    ) -> ApiResponse<EnrollmentView> {
        let Json(response) = mark_local_committed(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
            Json(NodeIdentityRequest {
                node_id: node_id.into(),
            }),
        )
        .await;
        response
    }

    #[tokio::test]
    async fn creation_returns_secret_once_and_persists_only_keyed_verifiers() {
        let (state, pool) = test_state().await;
        let created = create_test_enrollment(&state).await;
        let enrollment_id = created.enrollment.id.clone();
        assert!(valid_secret(&created.enrollment_secret));
        assert_eq!(created.enrollment.state, EnrollmentState::Pending);

        let stored: (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT secret_verifier, session_verifier, client_nonce_verifier \
             FROM manual_bootstrap_enrollments WHERE id = ?",
        )
        .bind(&enrollment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(stored.0, created.enrollment_secret);
        assert_eq!(stored.0.len(), 64);
        assert!(stored.1.is_none());
        assert!(stored.2.is_none());

        let Json(status) = enrollment_status(
            AdminOnly { user_id: 1 },
            State(state),
            Path(enrollment_id.clone()),
        )
        .await;
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains(&created.enrollment_secret));
        assert!(!serialized.contains(&stored.0));
        assert!(!serialized.contains("secret_verifier"));
        assert!(!serialized.contains("session_verifier"));
        assert!(created.launcher_command.contains(&enrollment_id));
        assert!(created.launcher_command.contains("https://panel.test"));
        assert!(!created
            .launcher_command
            .contains(&created.enrollment_secret));
        assert!(!created.launcher_command.contains("-d "));
        assert!(created.launcher_command.contains("--proto '=http,https'"));
        assert!(created
            .launcher_command
            .contains("https://panel.test/api/v1/node-enrollments/manual-bootstrap-launcher.sh"));
    }

    #[tokio::test]
    async fn http_panel_url_allows_enrollment_and_launcher_generation() {
        let (mut state, _) = test_state().await;
        state.config.public_panel_url = "http://panel.test:18888".into();
        let created = create_test_enrollment(&state).await;
        assert!(created.launcher_command.contains("http://panel.test:18888"));
        assert!(created.launcher_command.contains("--proto '=http,https'"));
        assert!(created.launcher_command.contains(
            "http://panel.test:18888/api/v1/node-enrollments/manual-bootstrap-launcher.sh"
        ));
        assert!(!created
            .launcher_command
            .contains(&created.enrollment_secret));
    }

    #[tokio::test]
    async fn non_admin_cannot_create_enrollment() {
        let (state, _) = test_state().await;
        let token = encode(
            &Header::default(),
            &Claims {
                sub: 2,
                admin: false,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        )
        .unwrap();
        let app = crate::api::routes().with_state(state);
        let response = app
            .oneshot(
                Request::post("/admin/node-enrollments")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"group_id":7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_pending_and_wrong_secret_are_rejected() {
        let (state, pool) = test_state().await;
        let created = create_test_enrollment(&state).await;
        let wrong = random_token();
        let response = claim(
            &state,
            &created.enrollment.id,
            &wrong,
            NONCE_A,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(response.code, 401);

        sqlx::query("UPDATE manual_bootstrap_enrollments SET expires_at = ? WHERE id = ?")
            .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
            .bind(&created.enrollment.id)
            .execute(&pool)
            .await
            .unwrap();
        let response = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(response.code, 410);
        assert_eq!(
            state
                .db
                .find_manual_bootstrap_enrollment(&created.enrollment.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "EXPIRED"
        );
    }

    #[tokio::test]
    async fn nonce_claim_retry_is_idempotent_but_replay_and_binding_changes_fail() {
        let (state, _) = test_state().await;
        let created = create_test_enrollment(&state).await;
        let first = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "x86_64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(first.code, 0);
        let first = first.data.unwrap();

        let retry = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(retry.code, 0);
        assert_eq!(
            retry.data.unwrap().bootstrap_session,
            first.bootstrap_session
        );

        let replay = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_B,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(replay.code, 409);

        let architecture_change = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "arm64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(architecture_change.code, 409);
    }

    #[tokio::test]
    async fn claimed_session_expiry_is_terminal_before_local_commit() {
        let (state, pool) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        sqlx::query("UPDATE manual_bootstrap_enrollments SET session_expires_at = ? WHERE id = ?")
            .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
            .bind(&enrollment.enrollment.id)
            .execute(&pool)
            .await
            .unwrap();

        let response = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-1",
        )
        .await;
        assert_eq!(response.code, 410);
        assert_eq!(
            state
                .db
                .find_manual_bootstrap_enrollment(&enrollment.enrollment.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "EXPIRED"
        );
    }

    #[tokio::test]
    async fn profile_binding_is_enforced_before_claim() {
        let (state, _) = test_state().await;
        let created = create_test_enrollment(&state).await;
        let row = state
            .db
            .find_manual_bootstrap_enrollment(&created.enrollment.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.profile, ProvisioningProfile::RealityCamouflage.as_str());
        assert!(serde_json::from_str::<ClaimEnrollmentRequest>(
            r#"{"secret":"value","architecture":"amd64","client_nonce":"client_nonce_aaaaaaaaaaaaaaaa","profile":"unsupported"}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn concurrent_claim_has_exactly_one_client_winner() {
        let (state, _) = test_state().await;
        let created = create_test_enrollment(&state).await;
        let id_a = created.enrollment.id.clone();
        let id_b = id_a.clone();
        let secret_a = created.enrollment_secret.clone();
        let secret_b = secret_a.clone();
        let state_a = state.clone();
        let state_b = state.clone();
        let (a, b) = tokio::join!(
            claim(
                &state_a,
                &id_a,
                &secret_a,
                NONCE_A,
                "amd64",
                ProvisioningProfile::RealityCamouflage,
            ),
            claim(
                &state_b,
                &id_b,
                &secret_b,
                NONCE_B,
                "amd64",
                ProvisioningProfile::RealityCamouflage,
            )
        );
        let mut codes = vec![a.code, b.code];
        codes.sort();
        assert_eq!(codes, vec![0, 409]);
    }

    #[tokio::test]
    async fn verify_rejects_wrong_group_node_and_offline_node() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        seed_observed(
            &state,
            8,
            "node-wrong-group",
            "amd64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let response = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-wrong-group",
        )
        .await;
        assert_eq!(response.code, 409);
        assert!(response.message.contains("different device group"));

        seed_observed(
            &state,
            7,
            "node-offline",
            "amd64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            false,
        )
        .await;
        let response = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-offline",
        )
        .await;
        assert_eq!(response.code, 409);
        assert!(response.message.contains("not authenticated"));
    }

    #[tokio::test]
    async fn verify_rejects_stale_architecture_and_missing_capabilities() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        seed_observed(
            &state,
            7,
            "node-stale",
            "amd64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now() - chrono::Duration::seconds(120),
            true,
        )
        .await;
        let stale = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-stale",
        )
        .await;
        assert_eq!(stale.code, 409);
        assert!(stale.message.contains("not fresh"));

        seed_observed(
            &state,
            7,
            "node-wrong-arch",
            "arm64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let wrong_arch = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-wrong-arch",
        )
        .await;
        assert_eq!(wrong_arch.code, 409);
        assert!(wrong_arch.message.contains("architecture"));

        seed_observed(
            &state,
            7,
            "node-no-capability",
            "amd64",
            ProvisioningCapabilities::default(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let missing = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-no-capability",
        )
        .await;
        assert_eq!(missing.code, 409);
        assert!(missing
            .message
            .contains("requested provisioning capabilities"));
    }

    #[test]
    fn verification_categories_separate_transient_convergence_from_terminal_failure() {
        assert!(VerificationErrorCategory::NodeNotFound.is_transient());
        assert!(VerificationErrorCategory::NodeStatusStale.is_transient());
        assert!(VerificationErrorCategory::CapabilityNotReported.is_transient());
        assert!(!VerificationErrorCategory::WrongGroup.is_transient());
        assert!(!VerificationErrorCategory::ArchitectureMismatch.is_transient());
        assert!(!VerificationErrorCategory::CapabilityPayloadInvalid.is_transient());
        assert!(!VerificationErrorCategory::CapabilityUnsupported.is_transient());
    }

    #[tokio::test]
    async fn verify_error_body_exposes_stable_transient_category() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        let json = verify_json(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-not-yet-reported",
        )
        .await;
        assert_eq!(json["code"], 409);
        assert_eq!(json["error_category"], "NODE_OFFLINE");
    }

    #[tokio::test]
    async fn verify_categories_cover_status_convergence_and_terminal_states() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        let (_, _receiver) = state
            .node_connections
            .register(7, Some("node-converging".into()))
            .await;

        let missing_status = verify_json(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-converging",
        )
        .await;
        assert_eq!(missing_status["error_category"], "NODE_NOT_FOUND");

        state
            .db
            .set(
                "node_status:7:node-converging",
                &serde_json::json!({
                    "last_seen": chrono::Utc::now().to_rfc3339(),
                    "architecture": "amd64",
                })
                .to_string(),
            )
            .await
            .unwrap();
        let missing_capabilities = verify_json(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-converging",
        )
        .await;
        assert_eq!(
            missing_capabilities["error_category"],
            "CAPABILITY_NOT_REPORTED"
        );

        state
            .db
            .set(
                "node_status:7:node-converging",
                &serde_json::json!({
                    "last_seen": chrono::Utc::now().to_rfc3339(),
                    "architecture": "amd64",
                    "provisioning_capabilities": ProvisioningCapabilities::default(),
                })
                .to_string(),
            )
            .await
            .unwrap();
        let unsupported = verify_json(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-converging",
        )
        .await;
        assert_eq!(unsupported["error_category"], "CAPABILITY_UNSUPPORTED");

        let (_, _wrong_group_receiver) = state
            .node_connections
            .register(8, Some("node-wrong-group".into()))
            .await;
        let wrong_group = verify_json(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-wrong-group",
        )
        .await;
        assert_eq!(wrong_group["error_category"], "WRONG_GROUP");
    }

    #[tokio::test]
    async fn verify_local_commit_and_complete_enforce_the_transaction_boundary() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;

        let Json(too_early) = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(too_early.code, 409);

        let before_verify = local_commit(&state, &enrollment, "node-1").await;
        assert_eq!(before_verify.code, 409);

        let verified = verify_healthy(&state, &enrollment, "node-1").await;
        assert_eq!(verified.state, EnrollmentState::Verifying);
        assert_ne!(verified.state, EnrollmentState::Success);

        seed_observed(
            &state,
            7,
            "node-2",
            "amd64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let rebound = verify(
            &state,
            &enrollment.enrollment.id,
            &enrollment.bootstrap_session,
            "node-2",
        )
        .await;
        assert_eq!(rebound.code, 409);

        let committed = local_commit(&state, &enrollment, "node-1").await;
        assert_eq!(committed.code, 0);
        assert_eq!(
            committed.data.unwrap().state,
            EnrollmentState::LocalCommitted
        );

        let Json(completed) = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(completed.code, 0);
        assert_eq!(completed.data.unwrap().state, EnrollmentState::Success);

        let Json(repeated) = complete_enrollment(
            State(state),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(repeated.code, 0);
        assert_eq!(repeated.data.unwrap().state, EnrollmentState::Success);
    }

    #[tokio::test]
    async fn post_commit_failure_never_requests_rollback_or_loses_local_commit() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        verify_healthy(&state, &enrollment, "node-1").await;
        assert_eq!(local_commit(&state, &enrollment, "node-1").await.code, 0);

        let Json(failed) = fail_enrollment(
            State(state),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
            Json(FailEnrollmentRequest {
                category: EnrollmentFailureCategory::LocalCommitFailed,
            }),
        )
        .await;
        assert_eq!(failed.code, 0);
        let failed = failed.data.unwrap();
        assert!(!failed.rollback_required);
        assert_eq!(failed.enrollment.state, EnrollmentState::LocalCommitted);
        assert_eq!(
            failed.enrollment.last_error_category.as_deref(),
            Some("LOCAL_COMMIT_FAILED")
        );
    }

    #[tokio::test]
    async fn complete_rechecks_online_capabilities_without_rolling_back_local_commit() {
        let (state, pool) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        verify_healthy(&state, &enrollment, "node-final-gate").await;
        assert_eq!(
            local_commit(&state, &enrollment, "node-final-gate")
                .await
                .code,
            0
        );
        sqlx::query("UPDATE kvs SET value = ? WHERE key = ?")
            .bind(
                serde_json::json!({
                    "last_seen": (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339(),
                    "architecture": "amd64",
                    "provisioning_capabilities": ProvisioningCapabilities::reality_camouflage(),
                })
                .to_string(),
            )
            .bind("node_status:7:node-final-gate")
            .execute(&pool)
            .await
            .unwrap();

        let Json(blocked) = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(blocked.code, 409);
        let persisted = state
            .db
            .find_manual_bootstrap_enrollment(&enrollment.enrollment.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.state, "LOCAL_COMMITTED");
        assert_eq!(
            persisted.last_error_category.as_deref(),
            Some("STALE_OBSERVED_STATE")
        );

        seed_observed(
            &state,
            7,
            "node-final-gate",
            "amd64",
            ProvisioningCapabilities::reality_camouflage(),
            chrono::Utc::now(),
            true,
        )
        .await;
        let Json(completed) = complete_enrollment(
            State(state),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(completed.code, 0, "{}", completed.message);
        assert_eq!(completed.data.unwrap().state, EnrollmentState::Success);
    }

    #[tokio::test]
    async fn concurrent_complete_requests_are_idempotent() {
        let (state, _) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        verify_healthy(&state, &enrollment, "node-concurrent-complete").await;
        assert_eq!(
            local_commit(&state, &enrollment, "node-concurrent-complete")
                .await
                .code,
            0
        );

        let complete_a = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        );
        let complete_b = complete_enrollment(
            State(state),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
        );
        let (Json(a), Json(b)) = tokio::join!(complete_a, complete_b);

        for response in [a, b] {
            assert_eq!(response.code, 0, "{}", response.message);
            assert_eq!(response.data.unwrap().state, EnrollmentState::Success);
        }
    }

    #[tokio::test]
    async fn expired_session_can_durably_finalize_a_locally_committed_enrollment() {
        let (state, pool) = test_state().await;
        let (_, enrollment) = claimed(&state).await;
        verify_healthy(&state, &enrollment, "node-committed-expiry").await;
        assert_eq!(
            local_commit(&state, &enrollment, "node-committed-expiry")
                .await
                .code,
            0
        );
        sqlx::query("UPDATE manual_bootstrap_enrollments SET session_expires_at = ? WHERE id = ?")
            .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
            .bind(&enrollment.enrollment.id)
            .execute(&pool)
            .await
            .unwrap();

        let Json(status) = enrollment_status(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
        )
        .await;
        let status = status.data.unwrap();
        assert_eq!(status.state, EnrollmentState::LocalCommitted);
        assert!(!status.rollback_allowed);

        let Json(completed) = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(completed.code, 0, "{}", completed.message);
        assert_eq!(completed.data.unwrap().state, EnrollmentState::Success);

        let Json(repeated) = complete_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id.clone()),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(repeated.code, 0, "{}", repeated.message);
        assert_eq!(repeated.data.unwrap().state, EnrollmentState::Success);
        assert_eq!(
            state
                .db
                .find_manual_bootstrap_enrollment(&enrollment.enrollment.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "SUCCESS"
        );
    }

    #[tokio::test]
    async fn precommit_failure_is_terminal_and_requests_rollback() {
        let (state, _) = test_state().await;
        let (created, enrollment) = claimed(&state).await;
        let Json(failed) = fail_enrollment(
            State(state.clone()),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
            Json(FailEnrollmentRequest {
                category: EnrollmentFailureCategory::ProvisioningFailed,
            }),
        )
        .await;
        assert_eq!(failed.code, 0);
        let failed = failed.data.unwrap();
        assert!(failed.rollback_required);
        assert_eq!(failed.enrollment.state, EnrollmentState::Failed);

        let replay = claim(
            &state,
            &created.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(replay.code, 409);
    }

    #[tokio::test]
    async fn restart_persistence_keeps_claim_and_session_state() {
        let (state, pool) = test_state().await;
        let (created, enrollment) = claimed(&state).await;
        verify_healthy(&state, &enrollment, "node-restart").await;
        assert_eq!(
            local_commit(&state, &enrollment, "node-restart").await.code,
            0
        );
        let restarted = AppState {
            db: Arc::new(SqliteRepository::new(pool)),
            config: state.config.clone(),
            release_cache: ReleaseCache::new(),
            node_connections: state.node_connections.clone(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        let Json(status) = enrollment_status(
            AdminOnly { user_id: 1 },
            State(restarted.clone()),
            Path(enrollment.enrollment.id.clone()),
        )
        .await;
        assert_eq!(status.data.unwrap().state, EnrollmentState::LocalCommitted);

        let retry = claim(
            &restarted,
            &enrollment.enrollment.id,
            &created.enrollment_secret,
            NONCE_A,
            "amd64",
            ProvisioningProfile::RealityCamouflage,
        )
        .await;
        assert_eq!(retry.code, 0, "{}", retry.message);
        assert_eq!(
            retry.data.unwrap().bootstrap_session,
            enrollment.bootstrap_session
        );

        let Json(completed) = complete_enrollment(
            State(restarted),
            Path(enrollment.enrollment.id),
            session_headers(&enrollment.bootstrap_session),
        )
        .await;
        assert_eq!(completed.code, 0, "{}", completed.message);
        assert_eq!(completed.data.unwrap().state, EnrollmentState::Success);
    }

    #[tokio::test]
    async fn enrollment_and_group_apis_do_not_serialize_permanent_or_temporary_secrets() {
        let (state, _) = test_state().await;
        let (created, enrollment) = claimed(&state).await;
        let Json(groups) = crate::api::admin::list_groups(
            crate::api::middleware::AuthUser {
                user_id: 1,
                admin: true,
            },
            State(state.clone()),
        )
        .await;
        let groups_json = serde_json::to_string(&groups).unwrap();
        assert!(!groups_json.contains("group-token-secret"));
        assert!(!groups_json.contains("\"token\""));

        let Json(status) = enrollment_status(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Path(enrollment.enrollment.id),
        )
        .await;
        let status_json = serde_json::to_string(&status).unwrap();
        for secret in [
            created.enrollment_secret.as_str(),
            enrollment.bootstrap_session.as_str(),
            "group-token-secret-7",
        ] {
            assert!(!status_json.contains(secret));
        }

        let audit = state.db.query_audit_log(None, 100, 0).await.unwrap();
        let audit_json = serde_json::to_string(&audit).unwrap();
        for secret in [
            created.enrollment_secret.as_str(),
            enrollment.bootstrap_session.as_str(),
            "group-token-secret-7",
            NONCE_A,
        ] {
            assert!(!audit_json.contains(secret));
        }
    }

    #[tokio::test]
    async fn keyed_verifiers_require_the_same_persisted_panel_secret_after_restart() {
        let (state, _) = test_state().await;
        let enrollment_id = uuid::Uuid::new_v4().to_string();
        let secret = random_token();
        let verifier = secret_verifier(&state, &enrollment_id, &secret);

        assert!(verify_secret(&state, &enrollment_id, &secret, &verifier));
        assert!(!verify_secret(
            &state,
            &enrollment_id,
            &random_token(),
            &verifier
        ));

        let mut different_key_state = state;
        different_key_state.config.jwt_secret = "different-panel-secret".into();
        assert!(!verify_secret(
            &different_key_state,
            &enrollment_id,
            &secret,
            &verifier
        ));
    }

    #[test]
    fn protected_bundle_has_only_expected_files_and_hashes() {
        let artifact = crate::api::provisioning::ProvisioningArtifact {
            architecture: "amd64".into(),
            bytes: b"ELF fixture".to_vec(),
            sha256: sha256_hex(b"ELF fixture"),
        };
        let bundle = ProvisioningBundle::new("https://panel.test", "group-token-secret", artifact);
        let bytes = render_bundle(
            "11111111-1111-1111-1111-111111111111",
            7,
            "reality_camouflage",
            &bundle,
        )
        .unwrap();
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
        let mut names = Vec::new();
        let mut manifest = String::new();
        let mut config = String::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            if name == "manifest.env" {
                entry.read_to_string(&mut manifest).unwrap();
            }
            if name == "config.env" {
                entry.read_to_string(&mut config).unwrap();
            }
            names.push(name);
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                "config.env",
                "manifest.env",
                "relay-node-bootstrap.sh",
                "relay-node-linux-amd64",
            ]
        );
        assert!(manifest.contains("ARCHITECTURE=amd64"));
        assert!(manifest.contains("ARTIFACT_SHA256="));
        assert!(!manifest.contains("group-token-secret"));
        assert!(config.contains("NODE_TOKEN='group-token-secret'"));
    }

    #[test]
    fn manual_wrapper_keeps_mutation_in_the_existing_bootstrap_engine() {
        for forbidden in [
            "apt-get ",
            "systemctl ",
            "docker ",
            "nginx ",
            "certbot ",
            "CAMOUFLAGE_SITES",
        ] {
            assert!(
                !MANUAL_BOOTSTRAP_WRAPPER.contains(forbidden),
                "wrapper must not own mutation: {forbidden}"
            );
        }
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("< \"$tty\""));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("curl --config \"$config\""));
        assert!(!MANUAL_BOOTSTRAP_WRAPPER.contains("curl -d"));
        assert!(!MANUAL_BOOTSTRAP_WRAPPER.contains("export ENROLLMENT_SECRET"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("unset ENROLLMENT_SECRET"));
        assert!(!MANUAL_BOOTSTRAP_WRAPPER.contains("set -x"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("http://*|https://*)"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("proto = \"=http,https\""));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("API_BASE=\"$PANEL_URL/api/v1\""));
        assert!(!MANUAL_BOOTSTRAP_WRAPPER.contains("requires an HTTPS Panel URL"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("trap 'on_signal 130' INT"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("trap 'on_signal 143' TERM"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER
            .contains("[ \"$status\" -ne 0 ] && [ \"$ENGINE_COMMITTED\" = 0 ]"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("rm -rf -- \"$STATE_DIR\""));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("--rollback"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("--commit"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("engine_committed"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("Never rerun the"));
        assert!(MANUAL_BOOTSTRAP_WRAPPER.contains("local_committed"));
    }

    #[test]
    fn session_lifetime_is_derived_from_transaction_timeout_plus_grace() {
        assert_eq!(
            bootstrap_session_lifetime_secs(),
            crate::api::provisioning::MAX_MANUAL_BOOTSTRAP_TRANSACTION_SECS
                + crate::api::provisioning::BOOTSTRAP_FINALIZATION_GRACE_SECS
        );
        assert!(bootstrap_session_lifetime_secs() > 20 * 60);
    }
}
