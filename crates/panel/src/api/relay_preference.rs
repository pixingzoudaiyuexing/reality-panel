use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::{GroupRepository, ResourceScope};
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    Json,
};
use relay_shared::protocol::ApiResponse;

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
