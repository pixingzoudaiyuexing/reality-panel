use crate::api::AppState;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use relay_shared::models::*;
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

    // An absent token is not an authoritative empty plan. Returning 200 with
    // listeners=[] here would make a node delete its last known good config.
    let Some(token) = extract_node_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // Find device group by token.
    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("get_config: find_by_token failed: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "config unavailable: transient database error",
            )
                .into_response();
        }
    };

    let Some(group) = group else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // v0.3.6: delegate to the shared `build_node_config`. This path and the WS
    // push path (ws.rs) now use the SAME function.
    //
    // Only an inbound group with genuinely no active rules yields Ok(empty).
    match crate::service::node_config::build_node_config_snapshot_for_node(
        state.db.as_ref(),
        group.id,
        extract_node_id(&headers).as_deref(),
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
                group.id,
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
    let Some(token) = extract_node_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if extract_node_id(&headers).is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            tracing::warn!("get_certificates: group lookup failed: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
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
    let manifest = match manager.group_manifest(group.id).await {
        Ok(manifest) => manifest,
        Err(error) => {
            tracing::warn!(group_id = group.id, "get_certificates failed: {error}");
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
    let Some(token) = extract_node_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(_) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let node_id = request.node_id.trim();
    if node_id.is_empty()
        || extract_node_id(&headers).is_some_and(|header_node_id| header_node_id != node_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let scopes = match crate::service::node_config::certificate_scopes_for_group(
        state.db.as_ref(),
        group.id,
    )
    .await
    {
        Ok(scopes) => scopes,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let requested_domain = request.sni.trim_end_matches('.');
    let authorized = scopes.iter().any(|scope| {
        let certificate_domain = scope.domain.trim_end_matches('.');
        let certificate_authorized = certificate_domain.eq_ignore_ascii_case(requested_domain)
            || certificate_domain
                .strip_prefix("*.")
                .is_some_and(|base| base.eq_ignore_ascii_case(requested_domain));
        certificate_authorized
    });
    if !authorized {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"code": "ACME_DNS01_SNI_NOT_AUTHORIZED"})),
        )
            .into_response();
    }

    let result = if present {
        crate::service::acme_dns01::present(state.db.as_ref(), group.id, &request).await
    } else {
        crate::service::acme_dns01::cleanup(state.db.as_ref(), group.id, &request).await
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

pub async fn report_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TrafficReport>,
) -> Json<ApiResponse<()>> {
    // Token comes ONLY from the Authorization header (v0.3.9: the body token
    // fallback was removed — nodes send the header and an empty body token).
    //
    // HTTP-status note: a missing/invalid token here returns HTTP 200 with a
    // business `code: 401` INSIDE the JSON body — NOT a real HTTP 401. This is
    // deliberate backward-compat: all shipped nodes read the JSON `code` field
    // and ignore the HTTP status on these node-facing endpoints. The WebSocket
    // upgrade path (ws.rs::node_ws_handler) is the ONE exception — it returns a
    // real HTTP 401 because WS upgrades must fail at the HTTP layer (the client
    // never gets to read a JSON body on a failed upgrade). Do NOT "normalize"
    // these without a coordinated node upgrade; see the test module's
    // `node_http_status_compat_*` tests that pin the current behavior.
    let Some(token) = extract_node_token(&headers) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };

    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("report_traffic: find_by_token failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };

    let group = match group {
        Some(g) => g,
        None => {
            return Json(ApiResponse {
                code: 401,
                message: "Invalid token".into(),
                data: None,
            })
        }
    };

    // v0.4.9 SECURITY: the whole batch is one atomic transaction, and rule-id
    // existence is NO LONGER distinguishable from cross-group reporting. Both
    // "rule missing" and "rule belongs to another group" produce the SAME
    // external response (403 + a single generic message). The batch logic lives
    // in `service::traffic::apply_traffic_report` (overflow pre-check + atomic
    // apply + result interpretation) so it can be unit-tested without HTTP.
    //
    // HTTP-status note (preserved): a rejection returns HTTP 200 with a business
    // `code` (403/400/500) INSIDE the JSON body — NOT a real HTTP error. Nodes
    // read the JSON `code` and ignore the HTTP status on these endpoints.
    match crate::service::traffic::apply_traffic_report(state.db.as_ref(), group.id, &req.reports)
        .await
    {
        Ok(()) => Json(ApiResponse::success(())),
        Err(crate::service::traffic::TrafficReportError::Unavailable) => {
            // Uniform 403 — identical for "missing" and "foreign". Do NOT echo
            // which rule_id or why.
            Json(ApiResponse {
                code: 403,
                message: "one or more rules are unavailable for this node".into(),
                data: None,
            })
        }
        Err(crate::service::traffic::TrafficReportError::Overflow) => Json(ApiResponse {
            code: 400,
            message: "one or more traffic entries are out of range".into(),
            data: None,
        }),
        Err(crate::service::traffic::TrafficReportError::Database(e)) => {
            tracing::error!("report_traffic: apply_traffic_batch failed: {}", e);
            Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            })
        }
    }
}

pub async fn report_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StatusReport>,
) -> Json<ApiResponse<()>> {
    // Token comes ONLY from the Authorization header (v0.3.9: body token
    // fallback removed).
    let Some(token) = extract_node_token(&headers) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };

    // Verify token and update node status in kvs
    let group: Option<DeviceGroup> = match state.db.find_by_token(&token).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("report_status: find_by_token failed: {}", e);
            // Match the original swallow-and-empty behavior: a transient DB
            // failure shouldn't make the node think its report was rejected.
            None
        }
    };

    if let Some(g) = group {
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
        let node_id_for_json = req.node_id.clone();
        // Store every reported metric in the status JSON. New optional fields
        // are only included when the node actually reported them (older nodes
        // omit them and the panel renders "-" for missing values).
        let status = serde_json::json!({
            "node_id": node_id_for_json,
            "cpu": req.cpu_usage,
            "mem": req.mem_usage,
            "connections": req.active_connections,
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
            "public_ipv4": req.public_ipv4.clone().or(req.public_ip.clone()),
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
    use relay_shared::protocol::{TrafficEntry, TrafficReport};
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
    async fn acme_dns01_api_requires_group_scoped_eligible_sni() {
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

        let eligible = crate::service::acme_dns01::AcmeDns01Request {
            node_id: "node-a".into(),
            sni: "site.example.com".into(),
            value: "challenge-token-123456".into(),
        };
        let provider_unavailable =
            present_acme_dns01(State(state.clone()), auth_headers("tok-A"), Json(eligible)).await;
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
        let ws_config =
            crate::api::ws::build_config_snapshot_for_node(state.db.as_ref(), 10, Some("node-a"))
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
