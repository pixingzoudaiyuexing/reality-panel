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
    pub default_node_id: Option<String>,
    #[serde(default)]
    pub bindings: Vec<crate::service::relay_preference::CarrierLineBinding>,
}

#[derive(Debug, Deserialize)]
pub struct SetRoutingModeRequest {
    pub mode: crate::service::relay_preference::RoutingMode,
}

fn routing_apply_status(code: &str) -> StatusCode {
    match code {
        "INBOUND_GROUP_NOT_FOUND" => StatusCode::NOT_FOUND,
        "ROUTING_MODE_CONFLICT" | "ROUTING_TRANSACTION_IN_PROGRESS" | "ROUTING_MODE_CHANGED" => {
            StatusCode::CONFLICT
        }
        "DNSMGR_UNAVAILABLE" | "DNS_PROVIDER_PREFLIGHT_FAILED" | "CARRIER_CATALOG_UNAVAILABLE" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        "ROUTING_APPLY_FAILED" | "DNS_SCHEDULING_FAILED" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

fn safe_carrier_preflight_detail(detail: &str) -> String {
    detail
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}

fn carrier_apply_error_response(
    error: &crate::service::relay_preference::CarrierPolicyApplyError,
) -> (StatusCode, i32, String) {
    use crate::service::relay_preference::CarrierPolicyApplyError;
    match error {
        CarrierPolicyApplyError::InboundGroupNotFound => {
            (StatusCode::NOT_FOUND, 404, error.to_string())
        }
        CarrierPolicyApplyError::DefaultLineOwnedByRelayPreference => (
            StatusCode::CONFLICT,
            409,
            "DEFAULT_LINE_OWNED_BY_RELAY_PREFERENCE".into(),
        ),
        CarrierPolicyApplyError::RoutingModeConflict(_) => {
            (StatusCode::CONFLICT, 409, "ROUTING_MODE_CONFLICT".into())
        }
        CarrierPolicyApplyError::TransactionInProgress => {
            (StatusCode::CONFLICT, 409, "TRANSACTION_IN_PROGRESS".into())
        }
        CarrierPolicyApplyError::NodeUninstalling(_) => {
            (StatusCode::CONFLICT, 409, error.to_string())
        }
        CarrierPolicyApplyError::InvalidPolicy(_)
        | CarrierPolicyApplyError::LineUnavailable(_)
        | CarrierPolicyApplyError::NodeNotInGroup(_)
        | CarrierPolicyApplyError::TargetPublicIpv4Invalid(_)
        | CarrierPolicyApplyError::CarrierDefaultRequired
        | CarrierPolicyApplyError::CarrierDefaultNotReady(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, 422, error.to_string())
        }
        CarrierPolicyApplyError::OwnershipUnverified { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            422,
            "OWNERSHIP_UNVERIFIED".into(),
        ),
        CarrierPolicyApplyError::CatalogStale => {
            (StatusCode::SERVICE_UNAVAILABLE, 503, "CATALOG_STALE".into())
        }
        CarrierPolicyApplyError::DnsMgrUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "DNSMGR_UNAVAILABLE".into(),
        ),
        CarrierPolicyApplyError::CatalogUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            "CATALOG_UNAVAILABLE".into(),
        ),
        CarrierPolicyApplyError::ProviderPreflight(detail) => (
            StatusCode::SERVICE_UNAVAILABLE,
            503,
            format!(
                "PROVIDER_PREFLIGHT: {}",
                safe_carrier_preflight_detail(detail)
            ),
        ),
        CarrierPolicyApplyError::Database(_)
        | CarrierPolicyApplyError::InvalidPreference(_)
        | CarrierPolicyApplyError::DnsSchedulingFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            500,
            "carrier policy could not be applied".into(),
        ),
    }
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

pub async fn get_routing_mode(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match crate::service::relay_preference::get_routing_mode(state.db.as_ref(), group_id).await {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(crate::service::relay_preference::RelayPreferenceError::Database(
            crate::db::error::DbError::NotFound,
        )) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(404, "Inbound group not found")),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(group_id, "get routing mode failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn set_routing_mode(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<SetRoutingModeRequest>,
) -> Response {
    use crate::service::relay_preference::RoutingModeTransitionError;
    match crate::service::relay_preference::transition_routing_mode(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        request.mode,
    )
    .await
    {
        Ok(outcome) => {
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "ROUTING_MODE_REQUESTED",
                "device_group",
                group_id,
                &format!("target_mode={:?} outcome={outcome:?}", request.mode),
            )
            .await;
            match crate::service::relay_preference::get_routing_mode(state.db.as_ref(), group_id)
                .await
            {
                Ok(view) => Json(ApiResponse::success(view)).into_response(),
                Err(error) => {
                    tracing::error!(group_id, "routing mode response failed: {error}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(error) => {
            let (status, code, message) = match &error {
                RoutingModeTransitionError::InboundGroupNotFound => {
                    (StatusCode::NOT_FOUND, 404, error.to_string())
                }
                RoutingModeTransitionError::Conflict(_)
                | RoutingModeTransitionError::TransactionInProgress => {
                    (StatusCode::CONFLICT, 409, error.to_string())
                }
                RoutingModeTransitionError::CarrierDefaultRequired
                | RoutingModeTransitionError::CarrierDefaultNotReady(_)
                | RoutingModeTransitionError::NormalDefaultRequired
                | RoutingModeTransitionError::NormalDefaultNotReady(_)
                | RoutingModeTransitionError::ScheduleConfigurationMissing
                | RoutingModeTransitionError::OwnershipUnverified { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, 422, error.to_string())
                }
                RoutingModeTransitionError::DnsMgrUnavailable
                | RoutingModeTransitionError::ProviderPreflight(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, 503, error.to_string())
                }
                RoutingModeTransitionError::Database(_)
                | RoutingModeTransitionError::InvalidPreference(_)
                | RoutingModeTransitionError::DnsSchedulingFailed => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    500,
                    "routing mode could not be changed".into(),
                ),
            };
            (status, Json(ApiResponse::<()>::error(code, &message))).into_response()
        }
    }
}

pub async fn apply_routing(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<crate::service::relay_preference::RoutingApplyRequest>,
) -> Response {
    let target_mode = request.target_mode();
    match crate::service::relay_preference::apply_routing_configuration(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        request,
    )
    .await
    {
        Ok(result) => {
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "ROUTING_CONFIGURATION_APPLIED",
                "device_group",
                group_id,
                &format!(
                    "target_mode={target_mode:?} config_saved={} activation_requested={} activation_succeeded={} transition_state={:?}",
                    result.config_saved,
                    result.activation_requested,
                    result.activation_succeeded,
                    result.transition_state,
                ),
            )
            .await;
            Json(ApiResponse::success(result)).into_response()
        }
        Err(failure) => {
            let code = failure
                .result
                .business_error_code
                .as_deref()
                .unwrap_or("ROUTING_APPLY_FAILED");
            let status = routing_apply_status(code);
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "ROUTING_CONFIGURATION_APPLY_FAILED",
                "device_group",
                group_id,
                &format!(
                    "target_mode={target_mode:?} config_saved={} error_code={code}",
                    failure.result.config_saved,
                ),
            )
            .await;
            (
                status,
                Json(ApiResponse {
                    code: i32::from(status.as_u16()),
                    message: code.into(),
                    data: Some(failure.result),
                }),
            )
                .into_response()
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
                StartRelaySwitchError::CarrierDnsPreflightFailed(_) => {
                    tracing::warn!(group_id, "relay carrier DNS preflight failed: {error}");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        503,
                        "carrier DNS preflight is unavailable".into(),
                    )
                }
                StartRelaySwitchError::SwitchInProgress { .. }
                | StartRelaySwitchError::NodeUninstalling(_)
                | StartRelaySwitchError::RoutingModeConflict(_)
                | StartRelaySwitchError::SourceNotAuthorized { .. } => {
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
        default_node_id: request.default_node_id,
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
            if matches!(
                error,
                CarrierPolicyApplyError::CatalogUnavailable
                    | CarrierPolicyApplyError::CatalogStale
                    | CarrierPolicyApplyError::DnsMgrUnavailable
                    | CarrierPolicyApplyError::ProviderPreflight(_)
            ) {
                tracing::warn!(group_id, "carrier policy preflight unavailable: {error}");
            } else if matches!(
                error,
                CarrierPolicyApplyError::Database(_)
                    | CarrierPolicyApplyError::InvalidPreference(_)
                    | CarrierPolicyApplyError::DnsSchedulingFailed
            ) {
                tracing::error!(group_id, "set carrier affinity failed: {error}");
            }
            let (status, code, message) = carrier_apply_error_response(&error);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::relay_preference::CarrierPolicyApplyError;

    #[test]
    fn default_carrier_authority_conflict_is_a_semantic_409() {
        let (status, code, message) = carrier_apply_error_response(
            &CarrierPolicyApplyError::DefaultLineOwnedByRelayPreference,
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(code, 409);
        assert_eq!(message, "DEFAULT_LINE_OWNED_BY_RELAY_PREFERENCE");
    }

    #[test]
    fn provider_preflight_detail_is_bounded_and_control_free() {
        let detail = format!("line unavailable\n{}", "x".repeat(250));
        let (_, _, message) =
            carrier_apply_error_response(&CarrierPolicyApplyError::ProviderPreflight(detail));
        assert!(message.starts_with("PROVIDER_PREFLIGHT: line unavailable"));
        assert!(!message.contains('\n'));
        assert!(message.len() <= "PROVIDER_PREFLIGHT: ".len() + 200);
    }

    #[test]
    fn routing_apply_business_codes_map_to_stable_http_categories() {
        assert_eq!(
            routing_apply_status("SCHEDULE_ENABLED_RULE_REQUIRED"),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            routing_apply_status("ROUTING_TRANSACTION_IN_PROGRESS"),
            StatusCode::CONFLICT
        );
        assert_eq!(
            routing_apply_status("DNSMGR_UNAVAILABLE"),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            routing_apply_status("ROUTING_APPLY_FAILED"),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
