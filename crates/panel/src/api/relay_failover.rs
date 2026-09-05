use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::service::relay_failover::{self, RelayFailoverError, RelayFailoverView};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::protocol::ApiResponse;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UpdateRelayFailoverRequest {
    pub enabled: bool,
    pub health_check_port: u16,
    pub failure_after_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct ReincludeRelayNodeRequest {
    pub node_id: String,
}

fn error_response(error: RelayFailoverError) -> Response {
    let (status, code) = match error {
        RelayFailoverError::InboundGroupNotFound => (StatusCode::NOT_FOUND, 404),
        RelayFailoverError::ScheduleEnabled | RelayFailoverError::CarrierPolicyEnabled => {
            (StatusCode::CONFLICT, 409)
        }
        RelayFailoverError::InvalidInput(_)
        | RelayFailoverError::NodeNotInGroup
        | RelayFailoverError::NodeNotReady
        | RelayFailoverError::NodeProbeAddressInvalid
        | RelayFailoverError::NodeStillUnhealthy => (StatusCode::UNPROCESSABLE_ENTITY, 422),
        RelayFailoverError::Database(_) | RelayFailoverError::InvalidStoredData(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, 500)
        }
    };
    let message = error.to_string();
    (status, Json(ApiResponse::<()>::error(code, &message))).into_response()
}

pub async fn get(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match relay_failover::get_view(state.db.as_ref(), &state.node_connections, group_id).await {
        Ok(view) => Json(ApiResponse::success(view)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn update(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<UpdateRelayFailoverRequest>,
) -> Response {
    if let Err(error) = relay_failover::update_policy(
        state.db.as_ref(),
        group_id,
        request.enabled,
        request.health_check_port,
        request.failure_after_seconds,
    )
    .await
    {
        return error_response(error);
    }
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "RELAY_FAILOVER_UPDATED",
        "device_group",
        group_id,
        &format!(
            "enabled={} health_check_port={} failure_after_seconds={}",
            request.enabled, request.health_check_port, request.failure_after_seconds
        ),
    )
    .await;
    match relay_failover::get_view(state.db.as_ref(), &state.node_connections, group_id).await {
        Ok(view) => Json(ApiResponse::<RelayFailoverView>::success(view)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn reinclude(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(request): Json<ReincludeRelayNodeRequest>,
) -> Response {
    let node_id = request.node_id.trim();
    if node_id.is_empty() {
        return error_response(RelayFailoverError::InvalidInput(
            "node_id must not be empty".into(),
        ));
    }
    if let Err(error) = relay_failover::reinclude_node(
        state.db.as_ref(),
        &state.node_connections,
        group_id,
        node_id,
    )
    .await
    {
        return error_response(error);
    }
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "RELAY_FAILOVER_NODE_REINCLUDED",
        "device_group",
        group_id,
        &format!("node_id={node_id}"),
    )
    .await;
    match relay_failover::get_view(state.db.as_ref(), &state.node_connections, group_id).await {
        Ok(view) => Json(ApiResponse::<RelayFailoverView>::success(view)).into_response(),
        Err(error) => error_response(error),
    }
}
