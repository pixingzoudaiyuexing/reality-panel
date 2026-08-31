use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::{GroupRepository, ResourceScope};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::protocol::ApiResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SetRelayPreferenceRequest {
    pub node_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SetCarrierAffinityRequest {
    #[serde(default)]
    pub bindings: Vec<crate::service::relay_preference::CarrierLineBinding>,
}

pub async fn get_relay_preference(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match GroupRepository::find_by_id(state.db.as_ref(), group_id, &ResourceScope::All).await {
        Ok(Some(group)) if group.group_type == "in" => {}
        Ok(Some(_)) | Ok(None) => {
            return (axum::http::StatusCode::NOT_FOUND, "Inbound group not found").into_response();
        }
        Err(error) => {
            tracing::error!("get_relay_preference: group lookup failed: {}", error);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    match crate::service::relay_preference::get_relay_preference(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(error) => {
            tracing::error!("get_relay_preference {}: {}", group_id, error);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn set_relay_preference(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<SetRelayPreferenceRequest>,
) -> Response {
    use crate::service::relay_preference::{StartRelaySwitchError, StartRelaySwitchOutcome};

    let outcome = match crate::service::relay_preference::start_relay_switch(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        &request.node_id,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let (status, code, message) = match &error {
                StartRelaySwitchError::InboundGroupNotFound => {
                    (StatusCode::NOT_FOUND, 404, error.to_string())
                }
                StartRelaySwitchError::NodeNotInGroup => {
                    (StatusCode::BAD_REQUEST, 400, error.to_string())
                }
                StartRelaySwitchError::TargetNotReady(_)
                | StartRelaySwitchError::TargetPublicIpv4Invalid
                | StartRelaySwitchError::DnsMgrUnavailable
                | StartRelaySwitchError::NoEligibleDnsRules => {
                    (StatusCode::UNPROCESSABLE_ENTITY, 422, error.to_string())
                }
                StartRelaySwitchError::SwitchInProgress { .. } => {
                    (StatusCode::CONFLICT, 409, error.to_string())
                }
                StartRelaySwitchError::Database(_)
                | StartRelaySwitchError::InvalidPreference(_)
                | StartRelaySwitchError::DnsSchedulingFailed(_) => {
                    tracing::error!(
                        "set_relay_preference {} to {} failed: {}",
                        group_id,
                        request.node_id,
                        error
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        500,
                        "relay switch could not be started".into(),
                    )
                }
            };
            if matches!(error, StartRelaySwitchError::DnsSchedulingFailed(_)) {
                crate::service::audit::record(
                    &state,
                    Some(admin.user_id),
                    "RELAY_SWITCH_FAILED",
                    "device_group",
                    group_id,
                    &format!(
                        "group_id={} to_node_id={} error=DNS_SCHEDULING_FAILED",
                        group_id, request.node_id
                    ),
                )
                .await;
            }
            return (status, Json(ApiResponse::<()>::error(code, &message))).into_response();
        }
    };

    if let StartRelaySwitchOutcome::Started {
        from_node_id,
        to_node_id,
    } = &outcome
    {
        crate::service::audit::record(
            &state,
            Some(admin.user_id),
            "RELAY_SWITCH_REQUESTED",
            "device_group",
            group_id,
            &format!(
                "group_id={} from_node_id={} to_node_id={}",
                group_id,
                from_node_id.as_deref().unwrap_or("none"),
                to_node_id
            ),
        )
        .await;
    }

    match crate::service::relay_preference::get_relay_preference(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(error) => {
            tracing::error!(
                "set_relay_preference {} response failed: {}",
                group_id,
                error
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn get_carrier_affinity(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match crate::service::relay_preference::get_carrier_affinity(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(crate::service::relay_preference::RelayPreferenceError::Database(
            crate::db::error::DbError::NotFound,
        )) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(404, "Inbound group not found")),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(group_id, "get carrier affinity failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn set_carrier_affinity(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<SetCarrierAffinityRequest>,
) -> Response {
    use crate::service::relay_preference::CarrierPolicyApplyError;
    let policy = crate::service::relay_preference::CarrierPolicy {
        bindings: request.bindings,
    };
    let outcome = match crate::service::relay_preference::start_carrier_policy_apply(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        policy,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let (status, code, message) = match &error {
                CarrierPolicyApplyError::InboundGroupNotFound => {
                    (StatusCode::NOT_FOUND, 404, error.to_string())
                }
                CarrierPolicyApplyError::TransactionInProgress => {
                    (StatusCode::CONFLICT, 409, error.to_string())
                }
                CarrierPolicyApplyError::InvalidPolicy(_)
                | CarrierPolicyApplyError::LineUnavailable(_)
                | CarrierPolicyApplyError::NodeNotInGroup(_)
                | CarrierPolicyApplyError::TargetNotReady { .. }
                | CarrierPolicyApplyError::TargetPublicIpv4Invalid(_)
                | CarrierPolicyApplyError::OwnershipUnverified { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, 422, error.to_string())
                }
                CarrierPolicyApplyError::CatalogUnavailable
                | CarrierPolicyApplyError::CatalogStale
                | CarrierPolicyApplyError::DnsMgrUnavailable
                | CarrierPolicyApplyError::ProviderPreflight(_) => {
                    tracing::warn!(group_id, "carrier policy preflight unavailable: {error}");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        503,
                        "carrier policy preflight is unavailable".into(),
                    )
                }
                CarrierPolicyApplyError::Database(_)
                | CarrierPolicyApplyError::InvalidPreference(_)
                | CarrierPolicyApplyError::DnsSchedulingFailed => {
                    tracing::error!(group_id, "set carrier affinity failed: {error}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        500,
                        "carrier policy could not be applied".into(),
                    )
                }
            };
            return (status, Json(ApiResponse::<()>::error(code, &message))).into_response();
        }
    };
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "CARRIER_POLICY_REQUESTED",
        "device_group",
        group_id,
        &format!("group_id={group_id} outcome={outcome:?}"),
    )
    .await;
    match crate::service::relay_preference::get_carrier_affinity(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
    )
    .await
    {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(error) => {
            tracing::error!(group_id, "carrier affinity response failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
