use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::service::carrier_lines::CarrierLineCatalogError;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use relay_shared::protocol::ApiResponse;

pub async fn get_group_carrier_lines(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Response {
    match crate::service::carrier_lines::group_catalog(state.db.as_ref(), group_id).await {
        Ok(catalog) => Json(ApiResponse::success(catalog)).into_response(),
        Err(CarrierLineCatalogError::GroupNotFound) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(404, "Inbound group not found")),
        )
            .into_response(),
        Err(
            CarrierLineCatalogError::DnsMgrUnavailable
            | CarrierLineCatalogError::Provider(_)
            | CarrierLineCatalogError::NoMatchingZone
            | CarrierLineCatalogError::InvalidProviderLine,
        ) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiResponse::<()>::error(
                503,
                "Carrier line catalog is unavailable",
            )),
        )
            .into_response(),
        Err(CarrierLineCatalogError::Database(error)) => {
            tracing::error!(group_id, "carrier line catalog database failure: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
