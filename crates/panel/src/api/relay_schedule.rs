use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::service::relay_schedule::{
    self, CreateRelayScheduleRequest, RelaySchedule, RelayScheduleError, UpdateRelayScheduleRequest,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::protocol::ApiResponse;

fn error_response(error: RelayScheduleError) -> Response {
    let (status, code) = match error {
        RelayScheduleError::GroupNotFound | RelayScheduleError::ScheduleNotFound => {
            (StatusCode::NOT_FOUND, 404)
        }
        RelayScheduleError::GroupNotRelayInbound
        | RelayScheduleError::TargetNodeNotFound
        | RelayScheduleError::InvalidInput(_) => (StatusCode::UNPROCESSABLE_ENTITY, 422),
        RelayScheduleError::Database(_) | RelayScheduleError::InvalidStoredData(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, 500)
        }
    };
    let message = error.to_string();
    (status, Json(ApiResponse::<()>::error(code, &message))).into_response()
}

pub async fn list(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match relay_schedule::list_schedules(state.db.as_ref()).await {
        Ok(schedules) => Json(ApiResponse::success(schedules)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn create(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<CreateRelayScheduleRequest>,
) -> Response {
    match relay_schedule::create_schedule(state.db.as_ref(), &state.node_connections, request).await
    {
        Ok(schedule) => Json(ApiResponse::success(schedule)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn update(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateRelayScheduleRequest>,
) -> Response {
    match relay_schedule::update_schedule(state.db.as_ref(), &state.node_connections, &id, request)
        .await
    {
        Ok(schedule) => Json(ApiResponse::success(schedule)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn delete(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match relay_schedule::delete_schedule(state.db.as_ref(), &id).await {
        Ok(true) => Json(ApiResponse::<()>::success(())).into_response(),
        Ok(false) => error_response(RelayScheduleError::ScheduleNotFound),
        Err(error) => error_response(error),
    }
}

async fn set_enabled(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
    enabled: bool,
) -> Response {
    match relay_schedule::set_schedule_enabled(state.db.as_ref(), &id, enabled).await {
        Ok(schedule) => Json(ApiResponse::<RelaySchedule>::success(schedule)).into_response(),
        Err(error) => error_response(error),
    }
}

pub async fn enable(admin: AdminOnly, state: State<AppState>, id: Path<String>) -> Response {
    set_enabled(admin, state, id, true).await
}

pub async fn disable(admin: AdminOnly, state: State<AppState>, id: Path<String>) -> Response {
    set_enabled(admin, state, id, false).await
}
