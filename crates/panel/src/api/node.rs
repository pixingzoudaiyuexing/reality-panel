use crate::api::node_auth::{authenticate_node, AuthenticatedNodeIdentity, NodeAuthError};
use crate::api::AppState;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use relay_shared::protocol::*;

/// Extract the node token from the `Authorization: Bearer <NODE_TOKEN>` header.
/// The token is accepted ONLY from this header — never from the query string
/// (leaks into access/proxy logs) nor from the request body. All currently
/// shipped nodes send the header.
pub(crate) fn extract_node_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

#[allow(dead_code)] // Retained for the legacy token-extraction compatibility pin tests.
pub(crate) fn extract_node_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Node-ID")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// v0.4.0: read the node's config-protocol version from the
/// `X-Config-Protocol-Version` request header. Returns None if absent (treated
/// as incompatible — the node is too old to know about the gate).
pub(crate) fn extract_config_protocol_version(headers: &HeaderMap) -> Option<u32> {
    headers
        .get("X-Config-Protocol-Version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
}

/// v0.4.0: the config-protocol compatibility gate. Returns true if the node's
/// reported version matches the panel's `CONFIG_PROTOCOL_VERSION`. A missing
/// header (old node) is treated as incompatible. Used by both get_config (HTTP)
/// and the WS upgrade path so both paths refuse consistently.
pub(crate) fn config_protocol_compatible(headers: &HeaderMap) -> bool {
    match extract_config_protocol_version(headers) {
        Some(v) => config_protocol_versions_compatible(CONFIG_PROTOCOL_VERSION, v),
        None => false,
    }
}

pub async fn get_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // v0.4.0: protocol-version gate. A node reporting a different
    // config_protocol_version (or none at all — pre-v0.4.0 node) must NOT
    // receive config it can't deserialize (e.g. the renamed node_transport
    // field). Return 426 (Upgrade Required) — NOT 503 — so the node treats it
    // as a permanent config error and backs off, not as a transient outage.
    // The structured JSON lets the node log "requires v1, has v0".
    if !config_protocol_compatible(&headers) {
        let received = extract_config_protocol_version(&headers);
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(serde_json::json!({
                "code": "CONFIG_PROTOCOL_MISMATCH",
                "required": CONFIG_PROTOCOL_VERSION,
                "received": received,
                "message": "relay-node configuration protocol is incompatible; \
                            upgrade relay-node to match the panel"
            })),
        )
            .into_response();
    }

    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(NodeAuthError::Unavailable) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "config unavailable: transient database error",
            )
                .into_response()
        }
        Err(error) => return error.status().into_response(),
    };
    let group_id = identity.group_id();
    let node_id = identity.node_id().map(str::to_string);
    let verified_concrete_node = identity.verified().is_some();

    // v0.3.6: delegate to the shared `build_node_config`. This path and the WS
    // push path (ws.rs) now use the SAME function.
    //
    // Only an inbound group with genuinely no active rules yields Ok(empty).
    let certificate_state_dir = std::path::PathBuf::from(state.config.certificate_state_dir());
    match crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
        state.db.as_ref(),
        &certificate_state_dir,
        group_id,
        node_id.as_deref(),
        verified_concrete_node,
        crate::service::node_config::NodeReuseRuntimeDeliveryMode::HomeOnly,
    )
    .await
    {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(crate::service::node_config::NodeConfigBuildError::NotInboundGroup) => {
            StatusCode::FORBIDDEN.into_response()
        }
        Err(crate::service::node_config::NodeConfigBuildError::GroupNotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!(
                "get_config: build_node_config failed for group {}: {}",
                group_id,
                e
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "config unavailable: transient database error",
            )
                .into_response()
        }
    }
}

pub async fn get_certificates(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error.status().into_response(),
    };
    if identity.node_id().is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let group_id = identity.group_id();
    let manager = match crate::service::panel_certificate::PanelCertificateManager::new(
        state.db.clone(),
        &state.config,
    ) {
        Ok(manager) => manager,
        Err(error) => {
            tracing::error!("get_certificates: manager unavailable: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let manifest = match manager.group_manifest(group_id).await {
        Ok(manifest) => manifest,
        Err(error) => {
            tracing::warn!(group_id, "get_certificates failed: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let not_modified = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == manifest.etag);
    let Ok(etag) = axum::http::HeaderValue::from_str(&manifest.etag) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if not_modified {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (axum::http::header::CACHE_CONTROL, "no-store"),
                (axum::http::header::ETAG, etag.to_str().unwrap_or_default()),
            ],
        )
            .into_response();
    }
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::ETAG, etag.to_str().unwrap_or_default()),
        ],
        Json(manifest.response),
    )
        .into_response()
}

pub async fn present_acme_dns01(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<crate::service::acme_dns01::AcmeDns01Request>,
) -> Response {
    acme_dns01_operation(state, headers, request, true).await
}

pub async fn cleanup_acme_dns01(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<crate::service::acme_dns01::AcmeDns01Request>,
) -> Response {
    acme_dns01_operation(state, headers, request, false).await
}

async fn acme_dns01_operation(
    state: AppState,
    headers: HeaderMap,
    request: crate::service::acme_dns01::AcmeDns01Request,
    present: bool,
) -> Response {
    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error.status().into_response(),
    };
    let group_id = identity.group_id();
    let node_id = request.node_id.trim();
    let node_mismatch = match &identity {
        AuthenticatedNodeIdentity::LegacyHomeGroup {
            reported_node_id, ..
        } => reported_node_id
            .as_deref()
            .is_some_and(|reported| reported != node_id),
        AuthenticatedNodeIdentity::VerifiedConcreteNode { verified, .. } => {
            verified.node_id.as_str() != node_id
        }
    };
    if node_id.is_empty() || node_mismatch {
        return StatusCode::FORBIDDEN.into_response();
    }
    if present {
        let scopes =
            match crate::service::node_config::issuance_authorized_certificate_scopes_for_group(
                state.db.as_ref(),
                group_id,
            )
            .await
            {
                Ok(scopes) => scopes,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
        let requested_domain = request.sni.trim_end_matches('.');
        let authorized = scopes.iter().any(|scope| {
            let certificate_domain = scope.domain.trim_end_matches('.');
            certificate_domain.eq_ignore_ascii_case(requested_domain)
                || certificate_domain
                    .strip_prefix("*.")
                    .is_some_and(|base| base.eq_ignore_ascii_case(requested_domain))
        });
        if !authorized {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"code": "ACME_DNS01_SNI_NOT_AUTHORIZED"})),
            )
                .into_response();
        }
    }

    let result = if present {
        crate::service::acme_dns01::present(state.db.as_ref(), group_id, &request).await
    } else {
        crate::service::acme_dns01::cleanup(state.db.as_ref(), group_id, &request).await
    };
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => {
            let code = error.code();
            tracing::warn!(
                operation = if present { "present" } else { "cleanup" },
                node_id = %request.node_id,
                domain = %request.sni,
                code,
                "ACME DNS-01 operation failed"
            );
            let status = match &error {
                crate::service::acme_dns01::AcmeDns01Error::InvalidRequest => {
                    StatusCode::BAD_REQUEST
                }
                crate::service::acme_dns01::AcmeDns01Error::Conflict => StatusCode::CONFLICT,
                crate::service::acme_dns01::AcmeDns01Error::Unavailable => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                crate::service::acme_dns01::AcmeDns01Error::Provider
                | crate::service::acme_dns01::AcmeDns01Error::PropagationTimeout
                | crate::service::acme_dns01::AcmeDns01Error::Database => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            };
            (status, Json(serde_json::json!({"code": code}))).into_response()
        }
    }
}

fn traffic_business_error(code: i32, message: &str) -> Json<ApiResponse<TrafficBatchAck>> {
    Json(ApiResponse::<TrafficBatchAck> {
        code,
        message: message.into(),
        data: None,
    })
}

pub async fn report_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TrafficReport>,
) -> Json<ApiResponse<TrafficBatchAck>> {
    // Keep the node-facing HTTP-200/business-code compatibility contract.
    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => identity,
        Err(NodeAuthError::Unavailable) => {
            tracing::error!("report_traffic: node authentication database lookup failed");
            return traffic_business_error(500, "database error");
        }
        Err(_) => return traffic_business_error(401, "Invalid token"),
    };

    if let Some(batch) = req.batch.as_ref() {
        // Strict idempotency is intentionally available only to a cryptographically
        // authenticated concrete Node. A legacy Bearer token's X-Node-ID remains
        // self-reported and never becomes a dedupe identity.
        let Some(verified) = identity.verified() else {
            return traffic_business_error(
                403,
                "strict traffic batches require verified concrete-node authentication",
            );
        };
        let computed = traffic_batch_payload_sha256(&req.reports);
        if batch.version != TRAFFIC_BATCH_PROTOCOL_VERSION
            || !valid_traffic_batch_id(&batch.batch_id)
            || !valid_traffic_payload_sha256(&batch.payload_sha256)
            || computed != batch.payload_sha256
        {
            return traffic_business_error(409, "traffic batch identity or payload conflict");
        }

        let scope = crate::db::repo::TrafficBatchScope {
            home_group_id: verified.home_group_id,
            node_id: verified.node_id.as_str().to_string(),
            credential_id: verified.credential_id.clone(),
            credential_generation: verified.generation,
            batch_id: batch.batch_id.clone(),
            payload_sha256: batch.payload_sha256.clone(),
        };
        return match crate::service::traffic::apply_idempotent_traffic_report(
            state.db.as_ref(),
            &scope,
            &req.reports,
        )
        .await
        {
            Ok(status) => {
                let status = match status {
                    crate::service::traffic::StrictTrafficReportStatus::Applied => {
                        TrafficBatchAckStatus::Applied
                    }
                    crate::service::traffic::StrictTrafficReportStatus::AlreadyApplied => {
                        TrafficBatchAckStatus::AlreadyApplied
                    }
                };
                Json(ApiResponse::success(TrafficBatchAck {
                    version: TRAFFIC_BATCH_PROTOCOL_VERSION,
                    batch_id: batch.batch_id.clone(),
                    payload_sha256: batch.payload_sha256.clone(),
                    status,
                }))
            }
            Err(crate::service::traffic::TrafficReportError::Unavailable) => {
                traffic_business_error(403, "one or more rules are unavailable for this node")
            }
            Err(crate::service::traffic::TrafficReportError::Overflow) => {
                traffic_business_error(400, "one or more traffic entries are out of range")
            }
            Err(crate::service::traffic::TrafficReportError::PayloadConflict) => {
                traffic_business_error(409, "traffic batch identity or payload conflict")
            }
            Err(crate::service::traffic::TrafficReportError::IdentityUnavailable) => {
                traffic_business_error(401, "verified node credential is no longer active")
            }
            Err(crate::service::traffic::TrafficReportError::Database(error)) => {
                tracing::error!("report_traffic: idempotent settlement failed: {}", error);
                traffic_business_error(500, "database error")
            }
        };
    }

    // Legacy clients deliberately retain the pre-T1 at-least-once behavior.
    // Missing/foreign rule IDs remain uniformly indistinguishable.
    match crate::service::traffic::apply_traffic_report(
        state.db.as_ref(),
        identity.group_id(),
        &req.reports,
    )
    .await
    {
        Ok(()) => Json(ApiResponse {
            code: 0,
            message: "ok".into(),
            data: None,
        }),
        Err(crate::service::traffic::TrafficReportError::Unavailable) => {
            traffic_business_error(403, "one or more rules are unavailable for this node")
        }
        Err(crate::service::traffic::TrafficReportError::Overflow) => {
            traffic_business_error(400, "one or more traffic entries are out of range")
        }
        Err(crate::service::traffic::TrafficReportError::Database(error)) => {
            tracing::error!("report_traffic: apply_traffic_batch failed: {}", error);
            traffic_business_error(500, "database error")
        }
        Err(crate::service::traffic::TrafficReportError::PayloadConflict)
        | Err(crate::service::traffic::TrafficReportError::IdentityUnavailable) => {
            traffic_business_error(500, "database error")
        }
    }
}

fn merge_reported_public_ipv4(
    incoming: Option<String>,
    previous_status: Option<&str>,
) -> (Option<String>, bool) {
    if incoming.is_some() {
        return (incoming, true);
    }
    let previous = previous_status
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|status| {
            status
                .get("public_ipv4")
                .and_then(serde_json::Value::as_str)
                .or_else(|| status.get("public_ip").and_then(serde_json::Value::as_str))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
                .filter(|address| !address.is_loopback() && !address.is_unspecified())
                .map(|address| address.to_string())
        });
    (previous, false)
}

pub async fn report_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StatusReport>,
) -> Json<ApiResponse<()>> {
    let identity = match authenticate_node(&state, &headers).await {
        Ok(identity) => Some(identity),
        Err(NodeAuthError::Unavailable) => {
            tracing::error!("report_status: node authentication database lookup failed");
            None
        }
        Err(_) => {
            return Json(ApiResponse {
                code: 401,
                message: "Invalid token".into(),
                data: None,
            })
        }
    };

    if let Some(identity) = identity {
        if let AuthenticatedNodeIdentity::VerifiedConcreteNode { verified, .. } = &identity {
            if req.node_id.as_deref().map(str::trim) != Some(verified.node_id.as_str()) {
                return Json(ApiResponse {
                    code: 403,
                    message: "node identity mismatch".into(),
                    data: None,
                });
            }
        }
        let g = identity.group();
        // v0.3.0: key node status by (group_id, node_id) so multiple nodes
        // sharing one group token no longer overwrite each other. The node_id
        // is a stable per-node identity generated on first start (see
        // poller::get_or_create_node_id). Older nodes that don't send node_id
        // fall back to the legacy per-group key (no regression — a single-node
        // group behaves exactly as before).
        let status_key = match &req.node_id {
            Some(nid) if !nid.trim().is_empty() => format!("node_status:{}:{}", g.id, nid.trim()),
            _ => format!("node_status:{}", g.id), // legacy fallback
        };
        let incoming_public_ipv4 = req.public_ipv4.clone().or_else(|| req.public_ip.clone());
        let previous_status = if incoming_public_ipv4.is_none() {
            state.db.get(&status_key).await.ok().flatten()
        } else {
            None
        };
        let (public_ipv4, public_ipv4_reported) =
            merge_reported_public_ipv4(incoming_public_ipv4, previous_status.as_deref());
        let node_id_for_json = req.node_id.clone();
        // Store every reported metric in the status JSON. New optional fields
        // are only included when the node actually reported them (older nodes
        // omit them and the panel renders "-" for missing values).
        let status = serde_json::json!({
            "node_id": node_id_for_json,
            "cpu": req.cpu_usage,
            "mem": req.mem_usage,
            "connections": req.active_connections,
            "tcp_connections": req.active_tcp_connections,
            "udp_sessions": req.active_udp_sessions,
            // v0.3.2: "uptime" is SYSTEM uptime (since OS boot). process uptime
            // is separate below; older nodes don't send it and it renders as "-".
            "uptime": req.uptime_secs,
            "process_uptime": req.process_uptime_secs,
            // v0.3.4: the node binary's version (for the "stale node" upgrade
            // hint). Older nodes don't send it; the panel renders "-".
            "node_version": req.node_version,
            // v0.4.0: config-protocol version (mirrors the
            // X-Config-Protocol-Version header). The frontend uses this to show
            // "配置协议不兼容，请升级节点" when it doesn't match the panel's.
            "config_protocol_version": req.config_protocol_version,
            "last_seen": chrono::Utc::now().to_rfc3339(),
            "public_ip": req.public_ip,
            // v0.4.15: dual-stack public IPs. Falls back to public_ip (legacy
            // IPv4) when the node hasn't upgraded yet.
            "public_ipv4": public_ipv4,
            // False means the displayed value is last-known-good telemetry,
            // not a value supplied by this report. Safety-sensitive consumers
            // must reject preserved-only values.
            "public_ipv4_reported": public_ipv4_reported,
            "public_ipv6": req.public_ipv6,
            "disk_total": req.disk_total,
            "disk_used": req.disk_used,
            "disk_usage_percent": req.disk_usage_percent,
            "disk_mount": req.disk_mount,
            "upload_bps": req.upload_bps,
            "download_bps": req.download_bps,
            "boot_upload_bytes": req.boot_upload_bytes,
            "boot_download_bytes": req.boot_download_bytes,
            // v0.4.6: the interface machine traffic is counted on, so the panel
            // can show "统计网卡: eth0". Missing on older nodes → "-".
            "network_interface": req.network_interface,
            // v0.3.6: listener bind failures (port in use, permission denied,
            // etc.) so the operator can see WHY a rule isn't forwarding.
            // Missing on older nodes; the frontend renders "ok".
            "listener_errors": req.listener_errors,
            // v1.1.x: how the node is installed ("systemd" | "docker" | "manual").
            // The node reports this so the panel's node-status UI knows whether a
            // one-click self-upgrade is possible (only systemd can safely restart
            // after replacing its own binary). Without persisting it here the
            // frontend saw `undefined` and wrongly showed every node as "manual",
            // hiding the upgrade button on legitimately systemd-managed nodes.
            "install_method": req.install_method,
            "architecture": req.architecture,
            "camouflage_sites": req.camouflage_sites,
            "active_listener_rule_ids": req.active_listener_rule_ids,
            "provisioning_capabilities": req.provisioning_capabilities,
            "reconciliation": req.reconciliation,
        });
        // Status persistence is best-effort: the original used .ok() to swallow
        // any DB error so a transient failure never broke the report cycle.
        let status_persisted = match state.db.set(&status_key, &status.to_string()).await {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!("report_status: kvs set failed: {}", error);
                false
            }
        };
        if status_persisted && g.group_type == "in" {
            if let Err(error) = crate::service::relay_preference::ensure_preference_initialized(
                state.db.as_ref(),
                &state.node_connections,
                g.id,
            )
            .await
            {
                tracing::warn!(
                    "report_status: relay preference initialization failed for group {}: {}",
                    g.id,
                    error
                );
            }
        }

        // v1.2.4: fold this report into the node's hourly metrics bucket. The
        // status written above is a snapshot each report overwrites; this is the
        // only thing that survives to answer "what was it doing last night".
        //
        // Best-effort like the status write — a metrics failure must never break
        // the report cycle, or the node would stop reporting traffic too.
        //
        // Skipped for legacy nodes that send no node_id: the series is keyed by
        // node, and bucketing anonymous reports under a synthetic key would
        // silently merge several machines into one line.
        if let Some(nid) = req
            .node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let sample = crate::db::repo::NodeMetricSample {
                node_id: nid.to_string(),
                group_id: g.id,
                hour_ts: chrono::Utc::now().format("%Y-%m-%d %H:00:00").to_string(),
                cpu: req.cpu_usage as f64,
                mem: req.mem_usage as f64,
                connections: req.active_connections as i64,
            };
            let _ = state
                .db
                .record_node_metrics(&sample)
                .await
                .map_err(|e| tracing::warn!("report_status: node metrics failed: {}", e));
        }

        // v0.4.19: async GeoIP enrichment — fire-and-forget, never blocks the
        // status report or node forwarding. Only runs when GEOIP_ENABLED=true.
        // Uses built-in primary + fallback providers (ipinfo.io → ipwho.is).
        // Each public IP is looked up independently; the geoip module handles
        // caching + concurrent de-duplication + private-IP rejection.
        if state.config.geoip_enabled {
            let db = state.db.clone();
            let ttl = state.config.geoip_cache_ttl as i64;
            let inflight = state.geoip_in_flight.clone();
            let v4 = req.public_ipv4.clone().or(req.public_ip.clone());
            let v6 = req.public_ipv6.clone();
            tokio::spawn(async move {
                if let Some(ip) = v4 {
                    let _ = crate::api::geoip::lookup(db.as_ref(), ttl, &inflight, &ip).await;
                }
                if let Some(ip) = v6 {
                    let _ = crate::api::geoip::lookup(db.as_ref(), ttl, &inflight, &ip).await;
                }
            });
        }

        // ── v0.3.2: legacy status cleanup ──
        // When a node upgraded to v0.3.1+ starts reporting with its new
        // node_id key, its OLD legacy entry ("node_status:{group_id}", no
        // node_id suffix) is left behind forever, showing as a permanently-
        // offline ghost node. We clean it up HERE: if this report has a
        // node_id AND a public_ip, delete the legacy key for the same group
        // IF AND ONLY IF its stored public_ip matches (so a different-IP node
        // sharing the group isn't wrongly deleted).
        if let (Some(nid), Some(ref ip)) = (&req.node_id, &req.public_ip) {
            if !nid.trim().is_empty() && !ip.is_empty() {
                crate::service::traffic::cleanup_legacy_status(state.db.as_ref(), g.id, ip).await;
            }
        }
    }

    // ── v0.3.2: stale status sweep ──
    // Also runs on READ (get_node_status), so ghost rows get cleaned even when
    // no node in the group is still reporting. Threshold is 2 min (frontend
    // marks offline at 30s; we keep the row a bit longer to ride out blips).
    let _ = crate::service::traffic::sweep_stale_status(state.db.as_ref()).await;

    Json(ApiResponse::success(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

    // ── report_traffic transactional correctness (v0.3.6) ──
    //
    // These exercise the atomicity contract: rule + user totals must move
    // together or not at all; an unauthorized rule must reject the whole batch;
    // a stale rule_id is skipped; overflow is rejected up front.

    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::api::AppState;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use relay_shared::protocol::{
        traffic_batch_payload_sha256, ApiResponse, TrafficBatchAck, TrafficBatchAckStatus,
        TrafficBatchMetadata, TrafficEntry, TrafficReport, TRAFFIC_BATCH_PROTOCOL_VERSION,
    };
    use std::sync::Arc;

    async fn full_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
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
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
        };
        (state, pool)
    }

    /// Seed: user 2 (non-admin), inbound group 10 with token "tok-A", rule 100
    /// owned by user 2 on group 10, port 20000. Returns the AppState + pool.
    async fn seeded_state() -> (AppState, SqlitePool) {
        let (state, pool) = full_state().await;
        let hash = bcrypt::hash("pw-2", 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'alice', ?, 0)")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'gin', 'in', 'tok-A', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (100, 'r100', 2, 20000, 10, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();
        (state, pool)
    }

    fn report(_token: &str, entries: &[TrafficEntry]) -> TrafficReport {
        TrafficReport {
            batch: None,
            reports: entries.to_vec(),
        }
    }

    fn auth_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    fn ready_status(node_id: &str) -> StatusReport {
        StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            active_tcp_connections: Some(0),
            active_udp_sessions: Some(0),
            uptime_secs: 60,
            public_ip: Some("203.0.113.10".into()),
            public_ipv4: Some("203.0.113.10".into()),
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: Some(node_id.into()),
            process_uptime_secs: Some(60),
            node_version: Some("1.0.0".into()),
            config_protocol_version: Some(CONFIG_PROTOCOL_VERSION),
            listener_errors: Some(Vec::new()),
            install_method: Some("systemd".into()),
            architecture: Some("linux-amd64".into()),
            camouflage_sites: Some(Vec::new()),
            active_listener_rule_ids: Some(vec![100]),
            provisioning_capabilities: None,
            reconciliation: Some(ReconciliationStatus {
                state: ReconciliationStatusState::Converged,
                desired_fingerprint: None,
                applied_fingerprint: None,
                observed_fingerprint: None,
                desired_config_revision: None,
                applied_config_revision: None,
                last_success_at: Some(chrono::Utc::now().to_rfc3339()),
                last_error: None,
                recovery_source: ReconciliationRecoverySource::Panel,
            }),
        }
    }

    async fn stored_preference(state: &AppState, group_id: i64) -> Option<String> {
        let raw = state
            .db
            .get(&format!("relay_preference:{group_id}"))
            .await
            .unwrap()?;
        serde_json::from_str::<crate::service::relay_preference::RelayPreferenceState>(&raw)
            .unwrap()
            .preferred_node_id
    }

    fn config_headers(token: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Config-Protocol-Version",
            relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                .to_string()
                .parse()
                .unwrap(),
        );
        if let Some(token) = token {
            headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        }
        headers
    }

    fn config_headers_for_node(token: &str, node_id: &str) -> HeaderMap {
        let mut headers = config_headers(Some(token));
        headers.insert("X-Node-ID", node_id.parse().unwrap());
        headers
    }

    async fn install_active_runtime_credential(
        pool: &SqlitePool,
        credential_id: &str,
        group_id: i64,
        node_id: &str,
        secret_byte: u8,
    ) -> crate::node_credential::NodeCredentialSecret {
        let node = crate::node_identity::ReuseEligibleNodeId::parse(node_id).unwrap();
        let secret =
            crate::node_credential::NodeCredentialSecret::from_test_bytes([secret_byte; 32]);
        let verifier = crate::node_credential::NodeCredentialVerifier::derive(
            credential_id,
            group_id,
            &node,
            &secret,
        );
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data, activated_at) \
             VALUES (?, ?, ?, 1, 'rp-node-sha256', 1, ?, datetime('now'))",
        )
        .bind(credential_id)
        .bind(group_id)
        .bind(node_id)
        .bind(verifier.data().as_slice())
        .execute(pool)
        .await
        .unwrap();
        secret
    }

    fn credential_config_headers(
        credential_id: &str,
        secret: &crate::node_credential::NodeCredentialSecret,
        node_id: &str,
    ) -> HeaderMap {
        let mut headers = config_headers(None);
        headers.insert(
            "Authorization",
            format!("RelayNodeCredential {}", secret.to_wire_value())
                .parse()
                .unwrap(),
        );
        headers.insert("X-Node-Credential-ID", credential_id.parse().unwrap());
        headers.insert("X-Node-ID", node_id.parse().unwrap());
        headers
    }

    #[test]
    fn config_protocol_v8_is_rejected_and_v10_is_accepted() {
        let mut v8 = HeaderMap::new();
        v8.insert("X-Config-Protocol-Version", "8".parse().unwrap());
        assert!(!config_protocol_compatible(&v8));

        let mut v10 = HeaderMap::new();
        v10.insert("X-Config-Protocol-Version", "10".parse().unwrap());
        assert!(config_protocol_compatible(&v10));
        assert!(!config_protocol_compatible(&HeaderMap::new()));
    }

    async fn user_traffic(pool: &SqlitePool, uid: i64) -> i64 {
        let (v,): (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id=?")
            .bind(uid)
            .fetch_one(pool)
            .await
            .unwrap();
        v
    }

    async fn rule_traffic(pool: &SqlitePool, rid: i64) -> i64 {
        let (v,): (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id=?")
            .bind(rid)
            .fetch_one(pool)
            .await
            .unwrap();
        v
    }

    async fn router_post_traffic(
        app: axum::Router,
        headers: HeaderMap,
        report: &TrafficReport,
    ) -> ApiResponse<TrafficBatchAck> {
        use tower::ServiceExt as _;

        let mut request = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/node/report_traffic")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(report).unwrap()))
            .unwrap();
        for (name, value) in headers.iter() {
            request.headers_mut().insert(name, value.clone());
        }
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn traffic_report_router_strict_idempotency_and_legacy_compat() {
        let (state, pool) = seeded_state().await;
        let secret =
            install_active_runtime_credential(&pool, "cred-t1-router", 10, "NODE_T1", 0xa1).await;
        let app = crate::api::routes().with_state(state);

        let entries = vec![TrafficEntry {
            rule_id: 100,
            upload: 11,
            download: 19,
        }];
        let payload_sha256 = traffic_batch_payload_sha256(&entries);
        let strict_report = TrafficReport {
            batch: Some(TrafficBatchMetadata {
                version: TRAFFIC_BATCH_PROTOCOL_VERSION,
                batch_id: "router-batch-1".into(),
                payload_sha256: payload_sha256.clone(),
            }),
            reports: entries.clone(),
        };
        let headers = credential_config_headers("cred-t1-router", &secret, "NODE_T1");

        let first = router_post_traffic(app.clone(), headers.clone(), &strict_report).await;
        assert_eq!(first.code, 0);
        let first_ack = first.data.expect("strict Applied ACK");
        assert_eq!(first_ack.status, TrafficBatchAckStatus::Applied);
        assert_eq!(first_ack.batch_id, "router-batch-1");
        assert_eq!(first_ack.payload_sha256, payload_sha256);

        let replay = router_post_traffic(app.clone(), headers.clone(), &strict_report).await;
        assert_eq!(replay.code, 0);
        assert_eq!(
            replay.data.expect("strict AlreadyApplied ACK").status,
            TrafficBatchAckStatus::AlreadyApplied
        );
        assert_eq!(rule_traffic(&pool, 100).await, 30);
        assert_eq!(user_traffic(&pool, 2).await, 30);

        // Model "server commit succeeded, ACK was lost": deliberately discard
        // the first response after the real Router/Repository path returns.
        // Retrying the same immutable batch must only acknowledge the committed
        // ledger row, never charge the bytes again.
        let lost_ack_entries = vec![TrafficEntry {
            rule_id: 100,
            upload: 4,
            download: 6,
        }];
        let lost_ack_report = TrafficReport {
            batch: Some(TrafficBatchMetadata {
                version: TRAFFIC_BATCH_PROTOCOL_VERSION,
                batch_id: "router-batch-lost-ack".into(),
                payload_sha256: traffic_batch_payload_sha256(&lost_ack_entries),
            }),
            reports: lost_ack_entries,
        };
        let _discarded = router_post_traffic(app.clone(), headers.clone(), &lost_ack_report).await;
        let recovered = router_post_traffic(app.clone(), headers.clone(), &lost_ack_report).await;
        assert_eq!(recovered.code, 0);
        assert_eq!(
            recovered
                .data
                .expect("lost-ACK retry must be confirmable")
                .status,
            TrafficBatchAckStatus::AlreadyApplied
        );
        assert_eq!(rule_traffic(&pool, 100).await, 40);
        assert_eq!(user_traffic(&pool, 2).await, 40);

        let changed_entries = vec![TrafficEntry {
            rule_id: 100,
            upload: 99,
            download: 1,
        }];
        let changed = TrafficReport {
            batch: Some(TrafficBatchMetadata {
                version: TRAFFIC_BATCH_PROTOCOL_VERSION,
                batch_id: "router-batch-1".into(),
                payload_sha256: traffic_batch_payload_sha256(&changed_entries),
            }),
            reports: changed_entries,
        };
        let conflict = router_post_traffic(app.clone(), headers, &changed).await;
        assert_eq!(conflict.code, 409);
        assert!(conflict.data.is_none());
        assert_eq!(rule_traffic(&pool, 100).await, 40);

        // A legacy Group Token's X-Node-ID remains self-reported; attaching
        // strict metadata cannot upgrade it to a verified concrete identity.
        let mut legacy_headers = auth_headers("tok-A");
        legacy_headers.insert("X-Node-ID", "NODE_T1".parse().unwrap());
        let legacy_strict = router_post_traffic(app.clone(), legacy_headers, &strict_report).await;
        assert_eq!(legacy_strict.code, 403);
        assert_eq!(rule_traffic(&pool, 100).await, 40);

        // Old clients that omit batch metadata retain the original settlement
        // contract and wire shape (code=0, data=null).
        let legacy_report = TrafficReport {
            batch: None,
            reports: vec![TrafficEntry {
                rule_id: 100,
                upload: 2,
                download: 3,
            }],
        };
        let legacy = router_post_traffic(app, auth_headers("tok-A"), &legacy_report).await;
        assert_eq!(legacy.code, 0);
        assert!(legacy.data.is_none());
        assert_eq!(rule_traffic(&pool, 100).await, 45);
        assert_eq!(user_traffic(&pool, 2).await, 45);
    }

    /// Normal batch: rule and user totals both move, atomically.
    #[tokio::test]
    async fn traffic_report_updates_rule_and_user() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[TrafficEntry {
                    rule_id: 100,
                    upload: 1000,
                    download: 2000,
                }],
            )),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        assert_eq!(rule_traffic(&pool, 100).await, 3000);
        assert_eq!(user_traffic(&pool, 2).await, 3000);
    }

    /// Multi-entry batch updates every rule and the shared user once each.
    #[tokio::test]
    async fn traffic_report_multi_entry_all_applied() {
        let (state, pool) = seeded_state().await;
        // second rule on the same group + user
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (101, 'r101', 2, 20001, 10, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 100,
                        upload: 100,
                        download: 0,
                    },
                    TrafficEntry {
                        rule_id: 101,
                        upload: 0,
                        download: 200,
                    },
                ],
            )),
        )
        .await;
        assert_eq!(resp.code, 0, "{}", resp.message);
        assert_eq!(rule_traffic(&pool, 100).await, 100);
        assert_eq!(rule_traffic(&pool, 101).await, 200);
        assert_eq!(user_traffic(&pool, 2).await, 300);
    }

    /// A rule belonging to ANOTHER group is unauthorized — the whole batch is
    /// rejected and rolled back, including the legitimate entry in the same batch.
    #[tokio::test]
    async fn traffic_report_other_group_rule_rejects_whole_batch() {
        let (state, pool) = seeded_state().await;
        // rule 200 belongs to group 20 (different group), same user
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (20, 'g20', 'in', 'tok-B', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (200, 'r200', 2, 20002, 20, '127.0.0.1', 80)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 100,
                        upload: 500,
                        download: 0,
                    },
                    TrafficEntry {
                        rule_id: 200,
                        upload: 0,
                        download: 999,
                    },
                ],
            )),
        )
        .await;
        assert_eq!(resp.code, 403, "unauthorized rule must reject batch");
        // Rollback: even the legitimate rule 100 entry must NOT have landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    /// v0.4.9: a rule_id that does NOT exist must be treated EXACTLY like a
    /// foreign rule (uniform 403 + whole-batch rollback) — it can no longer be
    /// told apart by the response. This closes the rule-id existence oracle.
    #[tokio::test]
    async fn traffic_report_unknown_rule_is_unavailable_not_skipped() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[
                    TrafficEntry {
                        rule_id: 99999, // does not exist
                        upload: 1,
                        download: 2,
                    },
                    TrafficEntry {
                        rule_id: 100,
                        upload: 10,
                        download: 20,
                    },
                ],
            )),
        )
        .await;
        // Same code + same generic message as the foreign-rule case.
        assert_eq!(
            resp.code, 403,
            "unknown rule must be rejected like a foreign rule"
        );
        assert_eq!(
            resp.message, "one or more rules are unavailable for this node",
            "message must be generic — no rule_id, no reason"
        );
        // Rollback: even rule 100 must NOT have landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    /// Overflow in upload+download is rejected up front with a 400 (no DB write).
    #[tokio::test]
    async fn traffic_report_overflow_rejected() {
        let (state, pool) = seeded_state().await;
        let Json(resp) = report_traffic(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(report(
                "tok-A",
                &[TrafficEntry {
                    rule_id: 100,
                    upload: u64::MAX,
                    download: 1,
                }],
            )),
        )
        .await;
        assert_eq!(resp.code, 400);
        // Nothing landed.
        assert_eq!(rule_traffic(&pool, 100).await, 0);
        assert_eq!(user_traffic(&pool, 2).await, 0);
    }

    // ── v0.4.9: node HTTP-status compatibility pins ──
    //
    // The three node-facing endpoints have DELIBERATELY DIFFERENT auth-failure
    // behaviors, preserved for backward compat with all shipped nodes:
    //   - report_traffic / report_status: missing token → HTTP 200, business
    //     code 401 INSIDE the JSON body (nodes read `code`, not the HTTP status).
    //   - get_config: auth and group errors are real non-2xx responses; only a
    //     valid inbound group with no active rules receives an empty config.
    //   - WebSocket upgrade: missing/invalid token → real HTTP 401 (WS upgrades
    //     must fail at the HTTP layer — the client never reads a JSON body).
    //
    // These tests PIN that behavior so a future "let's normalize to real HTTP
    // 401s" change can't land silently and break old nodes. Changing any of
    // these requires a coordinated major-version node upgrade.

    /// report_traffic with NO Authorization header → HTTP 200, JSON code 401.
    #[tokio::test]
    async fn node_http_status_compat_traffic_missing_token_is_http200_business401() {
        let (state, _pool) = seeded_state().await;
        let mut h = HeaderMap::new();
        // No Authorization header. (Also need the config-protocol header? No —
        // report_traffic doesn't gate on it, only get_config / WS do.)
        let _ = &mut h;
        let Json(resp) = report_traffic(State(state.clone()), h, Json(report("", &[]))).await;
        // The Json wrapper always serializes as HTTP 200; the business code is
        // the signal. Pin both: status is 200 (Implicit via Json), code is 401.
        assert_eq!(resp.code, 401, "missing token → business 401, not HTTP 401");
        assert_eq!(resp.message, "Invalid token");
    }

    /// report_status with NO Authorization header → HTTP 200, JSON code 401.
    #[tokio::test]
    async fn node_http_status_compat_status_missing_token_is_http200_business401() {
        use relay_shared::protocol::StatusReport;
        let (state, _pool) = seeded_state().await;
        let h = HeaderMap::new(); // no Authorization
        let req = StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            active_tcp_connections: None,
            active_udp_sessions: None,
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: None,
            process_uptime_secs: None,
            node_version: None,
            config_protocol_version: None,
            listener_errors: None,
            install_method: None,
            architecture: None,
            camouflage_sites: None,
            active_listener_rule_ids: None,
            provisioning_capabilities: None,
            reconciliation: None,
        };
        let Json(resp) = report_status(State(state.clone()), h, Json(req)).await;
        assert_eq!(resp.code, 401, "missing token → business 401, not HTTP 401");
    }

    #[tokio::test]
    async fn acme_dns01_present_requires_verified_issuance_scope() {
        let (state, pool) = seeded_state().await;
        sqlx::query("UPDATE device_groups SET connect_host='192.0.2.10' WHERE id=10")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='site.example.com', camouflage_enabled=1 WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        state
            .db
            .set("node_status:10:node-a", r#"{"public_ipv4":"192.0.2.10"}"#)
            .await
            .unwrap();
        state
            .db
            .set(
                crate::service::dnsmgr::DNSMGR_CONFIG_KEY,
                &serde_json::json!({
                    "enabled": true,
                    "base_url": "http://127.0.0.1:9",
                    "uid": 7,
                    "api_key": "panel-only-test-key"
                })
                .to_string(),
            )
            .await
            .unwrap();
        let unrelated = crate::service::acme_dns01::AcmeDns01Request {
            node_id: "node-a".into(),
            sni: "unrelated.example.com".into(),
            value: "challenge-token-123456".into(),
        };
        let denied =
            present_acme_dns01(State(state.clone()), auth_headers("tok-A"), Json(unrelated)).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let pending = crate::service::acme_dns01::AcmeDns01Request {
            node_id: "node-a".into(),
            sni: "site.example.com".into(),
            value: "challenge-token-123456".into(),
        };
        let ownership_required =
            present_acme_dns01(State(state.clone()), auth_headers("tok-A"), Json(pending)).await;
        assert_eq!(ownership_required.status(), StatusCode::FORBIDDEN);
        assert!(
            state
                .db
                .scan_prefix("acme:dns01:")
                .await
                .unwrap()
                .is_empty(),
            "unauthorized present must not create challenge state or TXT work"
        );

        sqlx::query(
            "INSERT INTO dns_record_syncs \
             (rule_id, fqdn, record_type, expected_value, line, line_key, desired_action, \
              state, ownership, mutation_verified_at, created_at, updated_at) \
             VALUES (100, 'site.example.com', 'A', '192.0.2.10', 'default', 'default', \
                     'UPSERT', 'MUTATION_VERIFIED', 'PANEL', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00', '2026-09-04 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO dns_record_bindings \
             (rule_id, fqdn, zone_id, zone_name, host, record_type, line, line_key, \
              record_id, desired_value, state, last_observed_at, created_at, updated_at) \
             VALUES (100, 'site.example.com', 7, 'example.com', 'site', 'A', 'default', \
                     'default', 'record-100', '192.0.2.10', 'BOUND', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00', '2026-09-04 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let authorized = crate::service::acme_dns01::AcmeDns01Request {
            node_id: "node-a".into(),
            sni: "example.com".into(),
            value: "challenge-token-123456".into(),
        };
        let provider_unavailable = present_acme_dns01(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(authorized),
        )
        .await;
        assert_eq!(
            provider_unavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let missing_auth = present_acme_dns01(
            State(state),
            HeaderMap::new(),
            Json(crate::service::acme_dns01::AcmeDns01Request {
                node_id: "node-a".into(),
                sni: "site.example.com".into(),
                value: "challenge-token-123456".into(),
            }),
        )
        .await;
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);
    }

    /// A missing token must never be presented as an authoritative empty plan.
    #[tokio::test]
    async fn get_config_missing_token_is_not_authoritative_empty() {
        let (state, _pool) = seeded_state().await;
        let resp = get_config(State(state.clone()), config_headers(None)).await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn certificate_endpoint_requires_node_identity_and_is_no_store_etagged() {
        let (state, _pool) = seeded_state().await;
        assert_eq!(
            get_certificates(State(state.clone()), HeaderMap::new())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_certificates(State(state.clone()), auth_headers("tok-A"))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut headers = auth_headers("tok-A");
        headers.insert("X-Node-ID", "node-a".parse().unwrap());
        let response = get_certificates(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store"))
        );
        let etag = response
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .clone();
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let payload: NodeCertificatesResponse = serde_json::from_slice(&body).unwrap();
        assert!(payload.certificates.is_empty());
        assert!(payload.missing_domains.is_empty());

        let (state, _pool) = seeded_state().await;
        let mut headers = auth_headers("tok-A");
        headers.insert("X-Node-ID", "node-a".parse().unwrap());
        headers.insert(axum::http::header::IF_NONE_MATCH, etag);
        let response = get_certificates(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store"))
        );
    }

    #[tokio::test]
    async fn get_config_invalid_token_is_not_authoritative_empty() {
        let (state, _pool) = seeded_state().await;
        let resp = get_config(State(state.clone()), config_headers(Some("invalid"))).await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_config_accepts_verified_credential_but_rejects_wrong_secret_and_forged_node() {
        let (state, pool) = seeded_state().await;
        let secret =
            install_active_runtime_credential(&pool, "cred-http", 10, "Node_A", 0x42).await;

        let ok = get_config(
            State(state.clone()),
            credential_config_headers("cred-http", &secret, "Node_A"),
        )
        .await;
        assert_eq!(ok.status(), axum::http::StatusCode::OK);

        let wrong_secret =
            crate::node_credential::NodeCredentialSecret::from_test_bytes([0x55; 32]);
        let rejected = get_config(
            State(state.clone()),
            credential_config_headers("cred-http", &wrong_secret, "Node_A"),
        )
        .await;
        assert_eq!(rejected.status(), axum::http::StatusCode::UNAUTHORIZED);

        let forged_node = get_config(
            State(state.clone()),
            credential_config_headers("cred-http", &secret, "Other_Node"),
        )
        .await;
        assert_eq!(forged_node.status(), axum::http::StatusCode::UNAUTHORIZED);

        let legacy = get_config(
            State(state),
            config_headers_for_node("tok-A", "self-reported-legacy"),
        )
        .await;
        assert_eq!(
            legacy.status(),
            axum::http::StatusCode::OK,
            "legacy Group Token path must remain compatible"
        );
    }

    #[tokio::test]
    async fn get_config_non_inbound_group_is_not_authoritative_empty() {
        let (state, pool) = seeded_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (20, 'outbound', 'out', 'tok-out', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let resp = get_config(State(state.clone()), config_headers(Some("tok-out"))).await;
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_config_database_error_is_not_authoritative_empty() {
        let (state, pool) = seeded_state().await;
        sqlx::query("DROP TABLE forward_rules")
            .execute(&pool)
            .await
            .unwrap();

        let resp = get_config(State(state.clone()), config_headers(Some("tok-A"))).await;
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn valid_inbound_group_with_no_rules_returns_empty_config() {
        let (state, pool) = seeded_state().await;
        sqlx::query("DELETE FROM forward_rules")
            .execute(&pool)
            .await
            .unwrap();

        let resp = get_config(State(state.clone()), config_headers(Some("tok-A"))).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let response: NodeConfigResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.listeners.is_empty());
    }

    #[tokio::test]
    async fn deleting_last_rule_returns_authoritative_empty_config() {
        let (state, pool) = seeded_state().await;
        let before = get_config(State(state.clone()), config_headers(Some("tok-A"))).await;
        let before_body = axum::body::to_bytes(before.into_body(), 65536)
            .await
            .unwrap();
        let before_config: NodeConfigResponse = serde_json::from_slice(&before_body).unwrap();
        assert_eq!(before_config.listeners.len(), 1);

        sqlx::query("DELETE FROM forward_rules WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        let after = get_config(State(state.clone()), config_headers(Some("tok-A"))).await;
        assert_eq!(after.status(), axum::http::StatusCode::OK);
        let after_body = axum::body::to_bytes(after.into_body(), 65536)
            .await
            .unwrap();
        let after_config: NodeConfigResponse = serde_json::from_slice(&after_body).unwrap();
        assert!(after_config.listeners.is_empty());
    }

    #[tokio::test]
    async fn http_and_ws_use_identical_typed_camouflage_config() {
        let (state, pool) = seeded_state().await;
        sqlx::query("UPDATE device_groups SET connect_host='' WHERE id=10")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE forward_rules SET listen_port=443, protocol='tcp', \
             public_transport='nginx_sni', node_transport='nginx_sni', \
             entry_transport='nginx_sni', sni='op1.example.com', \
             camouflage_enabled=1, target_addr='198.51.100.20', target_port=55443 \
             WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        state
            .db
            .set("node_status:10:node-a", r#"{"public_ipv4":"203.0.113.10"}"#)
            .await
            .unwrap();

        let http = get_config(
            State(state.clone()),
            config_headers_for_node("tok-A", "node-a"),
        )
        .await;
        assert_eq!(http.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(http.into_body(), 65536).await.unwrap();
        let http_snapshot: NodeConfigSnapshot = serde_json::from_slice(&body).unwrap();
        let http_config = &http_snapshot.config;
        let certificate_state_dir = std::path::PathBuf::from(state.config.certificate_state_dir());
        let ws_config = crate::api::ws::build_config_snapshot_for_node(
            state.db.as_ref(),
            &certificate_state_dir,
            10,
            Some("node-a"),
            false,
        )
        .await
        .expect("WS snapshot");

        assert_eq!(
            serde_json::to_value(http_config).unwrap(),
            serde_json::to_value(&ws_config.config).unwrap()
        );
        assert_eq!(
            relay_shared::reconciliation::config_fingerprint(http_config),
            relay_shared::reconciliation::config_fingerprint(&ws_config.config),
            "HTTP and WS snapshots must have one canonical desired fingerprint"
        );
        assert_eq!(http_config.camouflage_sites.len(), 1);
        assert!(http_config.listeners[0].camouflage_required);
        assert_eq!(http_snapshot.config_revision, ws_config.config_revision);
        assert_eq!(
            http_snapshot.config_fingerprint,
            ws_config.config_fingerprint
        );
        let serialized = serde_json::to_string(&http_snapshot).unwrap();
        for forbidden in ["PRIVATE KEY", "privkey.pem", "NODE_TOKEN", "Bearer", "uuid"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn node_reuse_binding_does_not_change_http_or_ws_home_only_config() {
        let (state, pool) = seeded_state().await;
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid)
             VALUES (20, 'reuse-source', 'in', 'tok-B', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules
             (id, name, uid, listen_port, device_group_in, target_addr, target_port)
             VALUES (200, 'reuse-rule', 2, 21000, 20, '127.0.0.1', 81)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO node_reuse_bindings (reusing_group_id, home_group_id, node_id)
             VALUES (20, 10, 'node-a')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let http = get_config(
            State(state.clone()),
            config_headers_for_node("tok-A", "node-a"),
        )
        .await;
        assert_eq!(http.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(http.into_body(), 65536).await.unwrap();
        let http_snapshot: NodeConfigSnapshot = serde_json::from_slice(&body).unwrap();
        let http_rule_ids = http_snapshot
            .config
            .listeners
            .iter()
            .map(|listener| listener.rule_id)
            .collect::<Vec<_>>();
        assert_eq!(http_rule_ids, vec![100]);

        let certificate_state_dir = std::path::PathBuf::from(state.config.certificate_state_dir());
        let ws_snapshot = crate::api::ws::build_config_snapshot_for_node(
            state.db.as_ref(),
            &certificate_state_dir,
            10,
            Some("node-a"),
            false,
        )
        .await
        .expect("WS snapshot");
        let ws_rule_ids = ws_snapshot
            .config
            .listeners
            .iter()
            .map(|listener| listener.rule_id)
            .collect::<Vec<_>>();
        assert_eq!(ws_rule_ids, vec![100]);
        assert!(!http_rule_ids.contains(&200));
        assert!(!ws_rule_ids.contains(&200));

        // Even a fully VerifiedConcreteNode with a current ACTIVE Credential
        // remains Home-only on the live HTTP/WS delivery mode.
        let secret =
            install_active_runtime_credential(&pool, "cred-reuse", 10, "node-a", 0x62).await;
        let verified_http = get_config(
            State(state.clone()),
            credential_config_headers("cred-reuse", &secret, "node-a"),
        )
        .await;
        assert_eq!(verified_http.status(), axum::http::StatusCode::OK);
        let verified_body = axum::body::to_bytes(verified_http.into_body(), 65536)
            .await
            .unwrap();
        let verified_snapshot: NodeConfigSnapshot = serde_json::from_slice(&verified_body).unwrap();
        assert_eq!(
            verified_snapshot
                .config
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100]
        );

        let verified_ws = crate::api::ws::build_config_snapshot_for_node(
            state.db.as_ref(),
            &certificate_state_dir,
            10,
            Some("node-a"),
            true,
        )
        .await
        .expect("verified WS snapshot");
        assert_eq!(
            verified_ws
                .config
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100]
        );

        // The isolated test-only mode proves the exact same snapshot machinery
        // can compose the guarded candidate without making that mode available
        // to production callers.
        let guarded_candidate =
            crate::service::node_config::build_guarded_node_config_snapshot_for_delivery(
                state.db.as_ref(),
                &certificate_state_dir,
                10,
                Some("node-a"),
                true,
                crate::service::node_config::NodeReuseRuntimeDeliveryMode::GuardedCandidate,
            )
            .await
            .expect("test-only guarded candidate snapshot");
        assert_eq!(
            guarded_candidate
                .config
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100, 200]
        );
        assert!(guarded_candidate.config_revision > 0);
        assert_eq!(
            guarded_candidate.config_fingerprint,
            relay_shared::reconciliation::config_fingerprint(&guarded_candidate.config).as_str()
        );
    }

    /// WebSocket upgrade with NO Authorization header → real HTTP 401 (the one
    /// exception to the "business code in JSON" rule — WS upgrades must fail at
    /// the HTTP layer). We assert via node_ws_handler's IntoResponse output,
    /// WITHOUT performing a real WS upgrade (the handler returns 401 before
    /// touching the socket).
    #[tokio::test]
    async fn node_http_status_compat_ws_missing_token_is_real_http401() {
        // We can't easily build a WebSocketUpgrade in a unit test, so this pin
        // documents + guards the contract via the token-extraction primitive the
        // handler uses: no Authorization header → extract_node_token returns
        // None, and node_ws_handler returns StatusCode::UNAUTHORIZED on None.
        // (A full WS-upgrade integration test would need an HTTP server; the
        // primitive-level pin is sufficient to catch a regression here.)
        let h = HeaderMap::new(); // no Authorization
        assert!(
            extract_node_token(&h).is_none(),
            "no Authorization header → no token → WS handler returns real HTTP 401"
        );
        // And a malformed header (not "Bearer ...") also yields None.
        let mut h2 = HeaderMap::new();
        h2.insert("Authorization", "notabearer".parse().unwrap());
        assert!(extract_node_token(&h2).is_none());
    }

    /// Regression: report_status MUST persist `install_method` into the stored
    /// node-status JSON. It was dropped from the status builder, so the panel
    /// served `install_method: undefined` and the frontend wrongly resolved
    /// every node to the "manual" upgrade state ("手动运行：不支持一键升级"),
    /// hiding the one-click upgrade button on legitimately systemd-managed nodes.
    #[tokio::test]
    async fn report_status_persists_install_method() {
        use relay_shared::protocol::StatusReport;
        let (state, _pool) = seeded_state().await;
        let req = StatusReport {
            cpu_usage: 0.0,
            mem_usage: 0.0,
            active_connections: 0,
            active_tcp_connections: Some(0),
            active_udp_sessions: Some(0),
            uptime_secs: 0,
            public_ip: None,
            public_ipv4: None,
            public_ipv6: None,
            disk_total: None,
            disk_used: None,
            disk_usage_percent: None,
            disk_mount: None,
            upload_bps: None,
            download_bps: None,
            boot_upload_bytes: None,
            boot_download_bytes: None,
            network_interface: None,
            node_id: Some("n1".into()),
            process_uptime_secs: None,
            node_version: Some("1.1.1".into()),
            config_protocol_version: None,
            listener_errors: None,
            install_method: Some("systemd".into()),
            architecture: Some("x86_64".into()),
            camouflage_sites: Some(vec![relay_shared::protocol::CamouflageSiteStatus {
                site_id: "op1_example_com".into(),
                sni: "op1.example.com".into(),
                site_status: "active".into(),
                certificate_status: "active".into(),
                issuer: Some("CN=Test CA".into()),
                valid_from: Some("2026-08-01T00:00:00Z".into()),
                valid_until: Some("2026-11-01T00:00:00Z".into()),
                last_success: None,
                last_attempt: None,
                last_error: None,
                active_generation: Some("generation-1".into()),
            }]),
            active_listener_rule_ids: Some(vec![42]),
            provisioning_capabilities: Some(
                relay_shared::protocol::ProvisioningCapabilities::reality_camouflage(),
            ),
            reconciliation: Some(relay_shared::protocol::ReconciliationStatus {
                state: relay_shared::protocol::ReconciliationStatusState::Converged,
                desired_fingerprint: Some("a".repeat(64)),
                applied_fingerprint: Some("b".repeat(64)),
                observed_fingerprint: Some("c".repeat(64)),
                desired_config_revision: None,
                applied_config_revision: None,
                last_success_at: Some("2026-08-26T00:00:00Z".into()),
                last_error: None,
                recovery_source: relay_shared::protocol::ReconciliationRecoverySource::Panel,
            }),
        };
        let Json(resp) =
            report_status(State(state.clone()), auth_headers("tok-A"), Json(req)).await;
        assert_eq!(resp.code, 0, "valid report → success");

        // The per-node status key is node_status:{group_id}:{node_id}.
        let raw = state
            .db
            .get("node_status:10:n1")
            .await
            .expect("kvs get")
            .expect("status row must exist after a successful report");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("stored status is JSON");
        assert_eq!(
            v["camouflage_sites"][0]["sni"].as_str(),
            Some("op1.example.com")
        );
        assert_eq!(v["active_listener_rule_ids"][0].as_i64(), Some(42));
        assert_eq!(
            v["provisioning_capabilities"]["reality_camouflage"].as_bool(),
            Some(true)
        );
        assert_eq!(v["reconciliation"]["state"].as_str(), Some("CONVERGED"));
        assert_eq!(v["tcp_connections"].as_u64(), Some(0));
        assert_eq!(v["udp_sessions"].as_u64(), Some(0));
        for forbidden in ["PRIVATE KEY", "privkey.pem", "NODE_TOKEN", "Bearer"] {
            assert!(!raw.contains(forbidden));
        }
        assert_eq!(
            v.get("install_method").and_then(|x| x.as_str()),
            Some("systemd"),
            "install_method must be persisted so the upgrade UI can offer a self-upgrade"
        );
    }

    #[tokio::test]
    async fn report_status_preserves_unknown_split_connection_telemetry() {
        let (state, _) = seeded_state().await;
        let mut req = ready_status("node-unknown");
        req.active_connections = 7;
        req.active_tcp_connections = None;
        req.active_udp_sessions = None;
        let Json(response) =
            report_status(State(state.clone()), auth_headers("tok-A"), Json(req)).await;
        assert_eq!(response.code, 0);
        let raw = state
            .db
            .get("node_status:10:node-unknown")
            .await
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["connections"].as_u64(), Some(7));
        assert!(value["tcp_connections"].is_null());
        assert!(value["udp_sessions"].is_null());
    }

    #[tokio::test]
    async fn report_status_preserves_but_distrusts_last_known_public_ipv4() {
        let (state, _) = seeded_state().await;
        state
            .db
            .set(
                "node_status:10:node-ip",
                r#"{"public_ipv4":"203.0.113.10","public_ipv4_reported":true}"#,
            )
            .await
            .unwrap();

        let mut missing = ready_status("node-ip");
        missing.public_ip = None;
        missing.public_ipv4 = None;
        let Json(response) =
            report_status(State(state.clone()), auth_headers("tok-A"), Json(missing)).await;
        assert_eq!(response.code, 0);
        let raw = state
            .db
            .get("node_status:10:node-ip")
            .await
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["public_ipv4"], "203.0.113.10");
        assert_eq!(value["public_ipv4_reported"], false);

        let mut updated = ready_status("node-ip");
        updated.public_ip = Some("203.0.113.11".into());
        updated.public_ipv4 = Some("203.0.113.11".into());
        let Json(response) =
            report_status(State(state.clone()), auth_headers("tok-A"), Json(updated)).await;
        assert_eq!(response.code, 0);
        let raw = state
            .db
            .get("node_status:10:node-ip")
            .await
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["public_ipv4"], "203.0.113.11");
        assert_eq!(value["public_ipv4_reported"], true);
    }

    #[tokio::test]
    async fn report_status_initializes_preference_without_get_request() {
        let (state, _pool) = seeded_state().await;
        let (_connection, _rx) = state
            .node_connections
            .register(10, Some("node-a".into()))
            .await;

        let Json(response) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-a")),
        )
        .await;
        assert_eq!(response.code, 0);
        assert_eq!(
            stored_preference(&state, 10).await.as_deref(),
            Some("node-a")
        );
    }

    #[tokio::test]
    async fn new_ready_node_report_does_not_replace_existing_preference() {
        let (state, _pool) = seeded_state().await;
        let (_a_connection, _a_rx) = state
            .node_connections
            .register(10, Some("node-a".into()))
            .await;
        let Json(a_response) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-a")),
        )
        .await;
        assert_eq!(a_response.code, 0);

        let (_b_connection, _b_rx) = state
            .node_connections
            .register(10, Some("node-b".into()))
            .await;
        let Json(b_response) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-b")),
        )
        .await;
        assert_eq!(b_response.code, 0);

        assert_eq!(
            stored_preference(&state, 10).await.as_deref(),
            Some("node-a")
        );
    }

    #[tokio::test]
    async fn offline_preferred_node_is_not_replaced_by_ready_reporter() {
        let (state, _pool) = seeded_state().await;
        let preference = crate::service::relay_preference::RelayPreferenceState {
            preferred_node_id: Some("node-a".into()),
            ..Default::default()
        };
        state
            .db
            .set(
                "relay_preference:10",
                &serde_json::to_string(&preference).unwrap(),
            )
            .await
            .unwrap();
        let (_b_connection, _b_rx) = state
            .node_connections
            .register(10, Some("node-b".into()))
            .await;

        let Json(response) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-b")),
        )
        .await;
        assert_eq!(response.code, 0);

        assert_eq!(
            stored_preference(&state, 10).await.as_deref(),
            Some("node-a")
        );
    }

    #[tokio::test]
    async fn near_simultaneous_node_reports_never_rewrite_initialized_preference() {
        let (state, _pool) = seeded_state().await;
        let (_a_connection, _a_rx) = state
            .node_connections
            .register(10, Some("node-a".into()))
            .await;
        let (_b_connection, _b_rx) = state
            .node_connections
            .register(10, Some("node-b".into()))
            .await;

        let a = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-a")),
        );
        let b = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-b")),
        );
        let (a_response, b_response) = tokio::join!(a, b);
        assert_eq!(a_response.0.code, 0);
        assert_eq!(b_response.0.code, 0);

        let first = stored_preference(&state, 10).await;
        assert!(matches!(
            first.as_deref(),
            None | Some("node-a") | Some("node-b")
        ));
        let Json(a_again) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-a")),
        )
        .await;
        let Json(b_again) = report_status(
            State(state.clone()),
            auth_headers("tok-A"),
            Json(ready_status("node-b")),
        )
        .await;
        assert_eq!(a_again.code, 0);
        assert_eq!(b_again.code, 0);
        assert_eq!(stored_preference(&state, 10).await, first);
    }
}
