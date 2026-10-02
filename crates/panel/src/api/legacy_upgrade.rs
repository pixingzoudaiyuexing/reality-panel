//! Administrative one-time official v1.3.0 single-node replacement.
use super::{middleware::AdminOnly, AppState};
use crate::db::repo::{ConcreteNodeIdentity, GroupRepository, ResourceScope};
use crate::service::legacy_upgrade::{self as upgrade, Operation, Probe};
use axum::{
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub identity_group_id: i64,
    pub node_id: String,
    pub official_sha256: String,
    pub probes: Vec<Probe>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRequest {
    pub action: String,
}

fn error(message: &str) -> Response {
    let status = if matches!(message, "DATABASE_ERROR" | "INVALID_MIGRATION_STATE") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::CONFLICT
    };
    (
        status,
        Json(serde_json::json!({"code":status.as_u16(),"message":message})),
    )
        .into_response()
}
fn view(op: &Operation) -> serde_json::Value {
    let mut v = serde_json::to_value(op).expect("serializable operation");
    v.as_object_mut().expect("object").remove("token_hash");
    v
}
fn success(data: serde_json::Value) -> Response {
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"code":0,"message":"ok","data":data})),
    )
        .into_response()
}

pub async fn capabilities() -> Response {
    success(
        serde_json::json!({"operation_protocol":1,"target_version":env!("CARGO_PKG_VERSION"),"single_node_only":true,"supported_old_version":"1.3.0","official_amd64_sha256":upgrade::OFFICIAL_AMD64_SHA256}),
    )
}
pub async fn script() -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/x-shellscript; charset=utf-8",
        )],
        include_str!("../../../../scripts/reality-node-v1.3.0-to-v1.4.2.sh"),
    )
        .into_response()
}
pub async fn start(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<StartRequest>,
) -> Response {
    match upgrade::start(
        &state,
        admin.user_id,
        ConcreteNodeIdentity {
            home_group_id: req.identity_group_id,
            node_id: req.node_id,
        },
        req.probes,
        &req.official_sha256,
    )
    .await
    {
        Ok(op) => success(
            serde_json::json!({"operation":view(&op),"migration_token":upgrade::token(&state,&op.id)}),
        ),
        Err(e) => error(&e),
    }
}
// Explicit administrator recovery after a start response was lost. No new operation.
pub async fn current(_admin: AdminOnly, State(state): State<AppState>) -> Response {
    match upgrade::load(state.db.as_ref()).await {
        Ok(Some((_, op))) => success(
            serde_json::json!({"operation":view(&op),"migration_token":upgrade::token(&state,&op.id)}),
        ),
        Ok(None) => error("MIGRATION_NOT_FOUND"),
        Err(e) => error(&e),
    }
}
async fn authorized(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
) -> Result<(String, Operation), Response> {
    if uuid::Uuid::parse_str(id).is_err() {
        return Err(error("INVALID_OPERATION_ID"));
    }
    let raw = state
        .db
        .get(&format!("legacy_v130_upgrade:operation:{id}"))
        .await
        .map_err(|_| error("DATABASE_ERROR"))?
        .ok_or_else(|| error("MIGRATION_NOT_FOUND"))?;
    let op: Operation = serde_json::from_str(&raw).map_err(|_| error("INVALID_MIGRATION_STATE"))?;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !bool::from(
        upgrade::hash(bearer.as_bytes())
            .as_bytes()
            .ct_eq(op.token_hash.as_bytes()),
    ) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":401,"message":"invalid migration authorization"})),
        )
            .into_response());
    }
    Ok((raw, op))
}
pub async fn status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match authorized(&state, &id, &headers).await {
        Ok((_, op)) => success(view(&op)),
        Err(e) => e,
    }
}
pub async fn bundle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let _lease = upgrade::MUTATIONS.read().await;
    let (raw, op) = match authorized(&state, &id, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if upgrade::load(state.db.as_ref())
        .await
        .ok()
        .flatten()
        .map(|(r, _)| r)
        != Some(raw)
    {
        return error("MIGRATION_STATE_CHANGED");
    }
    if op.state != "PREPARED" {
        return error("BUNDLE_ONLY_BEFORE_DESTRUCTIVE_STAGE");
    }
    let Some(public) = super::provisioning::effective_public_panel_url(&state)
        .await
        .filter(|u| u.starts_with("https://"))
    else {
        return error("HTTPS_PANEL_REQUIRED");
    };
    let group = match GroupRepository::find_by_id(
        state.db.as_ref(),
        op.new.home_group_id,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(g)) => g,
        _ => return error("POOL_ANCHOR_UNAVAILABLE"),
    };
    let artifact = match super::provisioning::load_artifact("amd64") {
        Ok(a) => a,
        Err(_) => return error("ARTIFACT_UNAVAILABLE"),
    };
    let mut bundle =
        super::provisioning::ProvisioningBundle::new(&public, &group.token, artifact, true);
    let cfg = match super::provisioning::pool_credential_bootstrap_config(
        &state,
        &op.new.node_id,
        op.new.home_group_id,
        op.created_by,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return error("NEW_BOOTSTRAP_AUTH_UNAVAILABLE"),
    };
    bundle.config.push_str(&cfg);
    match super::node_enrollment::render_bundle(
        &op.new.node_id,
        op.new.home_group_id,
        "lite",
        &bundle,
    ) {
        Ok(bytes) => {
            let sha = upgrade::hash(&bytes);
            (
                [
                    (axum::http::header::CACHE_CONTROL, "no-store"),
                    (axum::http::header::CONTENT_TYPE, "application/x-tar"),
                    (
                        axum::http::header::HeaderName::from_static("x-content-sha256"),
                        sha.as_str(),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(_) => error("BUNDLE_UNAVAILABLE"),
    }
}
pub async fn step(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<StepRequest>,
) -> Response {
    let (raw, op) = match authorized(&state, &id, &headers).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let result = match req.action.as_str() {
        "preflight" if op.state == "PREPARED" => upgrade::probe(&state, &op).await.map(|()| op),
        "restore" => upgrade::restore(&state, raw, op).await,
        "finalize" => upgrade::finalize(&state, raw, op).await,
        "rollback-begin" => upgrade::begin_rollback(&state, raw, op).await,
        "rollback" => upgrade::abort(&state, raw, op).await,
        _ => Err("INVALID_MIGRATION_ACTION".into()),
    };
    match result {
        Ok(op) => success(view(&op)),
        Err(e) => error(&e),
    }
}

fn touches(value: &serde_json::Value, op: &Operation) -> bool {
    match value {
        serde_json::Value::Object(m) => {
            if m.get("node_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == op.old.node_id || id == op.new.node_id)
            {
                return true;
            }
            if m.get("host").and_then(|v| v.as_str()) == Some(op.public_ipv4.as_str()) {
                return true;
            }
            m.iter().any(|(k, v)| {
                (matches!(
                    k.as_str(),
                    "device_group_in" | "group_id" | "reusing_group_id"
                ) && v.as_i64().is_some_and(|g| op.groups().contains(&g)))
                    || touches(v, op)
            })
        }
        serde_json::Value::Array(a) => a.iter().any(|v| touches(v, op)),
        _ => false,
    }
}

/// Short read leases serialize snapshot creation/finalization against requests;
/// the durable operation blocks only its Node and business Groups between requests.
pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let route = request
        .uri()
        .path()
        .strip_prefix("/api/v1")
        .unwrap_or(request.uri().path())
        .to_string();
    if matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) || route.starts_with("/legacy-node-upgrade-v130/")
        || route.starts_with("/admin/legacy-node-upgrade-v130/")
        || route.starts_with("/node/")
        || route.starts_with("/node-enrollments/")
        || route == "/admin/rules/domain-preflight"
    {
        return next.run(request).await;
    }
    let _lease = upgrade::MUTATIONS.read().await;
    let op = match upgrade::load(state.db.as_ref()).await {
        Ok(Some((_, op))) if op.active() => op,
        Ok(_) => return next.run(request).await,
        Err(e) => return error(&e),
    };
    let parts: Vec<_> = route.split('/').filter(|p| !p.is_empty()).collect();
    let ids = [op.old.node_id.as_str(), op.new.node_id.as_str()];
    if let Some(i) = parts.iter().position(|p| *p == "node-credential-claims") {
        if let Some(id) = parts.get(i + 1) {
            match state.db.find_node_credential_claim(id).await {
                Ok(Some(c))
                    if c.home_group_id == op.old.home_group_id && c.node_id == op.old.node_id =>
                {
                    return error("MIGRATION_IN_PROGRESS")
                }
                Ok(Some(c))
                    if request.method() == axum::http::Method::POST
                        && c.home_group_id == op.new.home_group_id
                        && c.node_id == op.new.node_id
                        && c.claim_id == op.new.node_id
                        && c.approval_ref == format!("node-pool-bootstrap:{}", op.new.node_id)
                        && ["claim", "credential/prepare", "credential/activate"]
                            .iter()
                            .any(|action| {
                                route == format!("/node-credential-claims/{}/{action}", c.claim_id)
                            }) =>
                {
                    // This operation's own Bootstrap still passes through the existing
                    // Claim authentication and delivery handlers. Keep other writes held.
                    return next.run(request).await;
                }
                Ok(_) => {}
                Err(_) => return error("DATABASE_ERROR"),
            }
        }
    }

    let mut blocked = parts.iter().any(|p| ids.contains(p));
    if let Some(i) = parts.iter().position(|p| *p == "groups") {
        blocked |= parts
            .get(i + 1)
            .and_then(|g| g.parse().ok())
            .is_some_and(|g| op.groups().contains(&g));
    }
    if let Some(i) = parts.iter().position(|p| *p == "rules") {
        if let Some(id) = parts.get(i + 1).and_then(|s| s.parse::<i64>().ok()) {
            use crate::db::repo::RuleRepository;
            match RuleRepository::find_rule_by_id(state.db.as_ref(), id, &ResourceScope::All).await
            {
                Ok(Some(r)) => blocked |= op.groups().contains(&r.device_group_in),
                Ok(None) => {}
                Err(_) => return error("DATABASE_ERROR"),
            }
        }
    }
    if route.starts_with("/admin/nodes/batch-upgrade") && !route.ends_with("/preview") {
        blocked = true;
    }
    if let Some(q) = request.uri().query() {
        let u = reqwest::Url::parse(&format!("http://localhost/?{q}"));
        blocked |= u
            .ok()
            .is_some_and(|u| u.query_pairs().any(|(_, v)| ids.contains(&v.as_ref())));
    }
    blocked |= route == "/admin/settings/dnsmgr";
    if route.starts_with("/node-credential-claims/") {
        return if blocked {
            error("MIGRATION_IN_PROGRESS")
        } else {
            next.run(request).await
        };
    }
    if blocked && !route.ends_with("/logs") {
        return error("MIGRATION_IN_PROGRESS");
    }
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };
    if serde_json::from_slice(&bytes)
        .ok()
        .is_some_and(|v| touches(&v, &op))
    {
        return error("MIGRATION_IN_PROGRESS");
    }
    next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[test]
    fn single_node_request_rejects_batches_and_unknown_keys() {
        let valid = serde_json::json!({"identity_group_id":10,"node_id":"OLD_NODE","official_sha256":upgrade::OFFICIAL_AMD64_SHA256,"probes":[]});
        assert!(serde_json::from_value::<StartRequest>(valid.clone()).is_ok());
        let mut array = valid.clone();
        array["node_id"] = serde_json::json!(["OLD_NODE", "OTHER_NODE"]);
        assert!(serde_json::from_value::<StartRequest>(array).is_err());
        let mut batch = valid;
        batch["node_ids"] = serde_json::json!(["OLD_NODE"]);
        assert!(serde_json::from_value::<StartRequest>(batch).is_err());
    }
    #[tokio::test]
    async fn active_operation_blocks_related_mutations_and_allows_other_groups() {
        let state = upgrade::tests::fixture().await;
        let probes = [100, 200]
            .into_iter()
            .map(|rule_id| Probe {
                rule_id,
                path: "/marker".into(),
                expected_marker: "marker".into(),
            })
            .collect();
        upgrade::start(
            &state,
            1,
            ConcreteNodeIdentity {
                home_group_id: 10,
                node_id: "OLD_NODE".into(),
            },
            probes,
            upgrade::OFFICIAL_AMD64_SHA256,
        )
        .await
        .unwrap();
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(state, guard));
        for (method, url, body, expected) in [
            (
                "DELETE",
                "/groups/10/node-pool/members/10/OLD_NODE",
                "",
                StatusCode::CONFLICT,
            ),
            (
                "DELETE",
                "/node-pool/nodes/10/OLD_NODE",
                "",
                StatusCode::CONFLICT,
            ),
            (
                "POST",
                "/admin/nodes/operations",
                r#"{"group_id":10,"node_id":"OLD_NODE","action":"uninstall"}"#,
                StatusCode::CONFLICT,
            ),
            (
                "DELETE",
                "/nodes?node_id=OLD%5fNODE",
                "",
                StatusCode::CONFLICT,
            ),
            (
                "PUT",
                "/rules/100",
                r#"{"name":"changed"}"#,
                StatusCode::CONFLICT,
            ),
            (
                "PUT",
                "/groups/30/routing-apply",
                r#"{"mode":"normal"}"#,
                StatusCode::NO_CONTENT,
            ),
            (
                "POST",
                "/admin/node-deployments",
                r#"{"host":"192.0.2.1"}"#,
                StatusCode::CONFLICT,
            ),
            ("GET", "/groups/10/routing-mode", "", StatusCode::NO_CONTENT),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(url)
                .body(axum::body::Body::from(body))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                expected,
                "{method} {url}"
            );
        }
    }
    #[tokio::test]
    async fn active_operation_allows_only_its_new_bootstrap_claim_transitions() {
        let state = upgrade::tests::fixture().await;
        let probes = [100, 200]
            .into_iter()
            .map(|rule_id| Probe {
                rule_id,
                path: "/marker".into(),
                expected_marker: "marker".into(),
            })
            .collect();
        let op = upgrade::start(
            &state,
            1,
            ConcreteNodeIdentity {
                home_group_id: 10,
                node_id: "OLD_NODE".into(),
            },
            probes,
            upgrade::OFFICIAL_AMD64_SHA256,
        )
        .await
        .unwrap();
        super::super::provisioning::pool_credential_bootstrap_config(
            &state,
            &op.new.node_id,
            op.new.home_group_id,
            1,
        )
        .await
        .unwrap();
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(state.clone(), guard));
        for suffix in ["claim", "credential/prepare", "credential/activate"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/api/v1/node-credential-claims/{}/{suffix}",
                            op.new.node_id
                        ))
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{suffix}");
        }
        for suffix in ["claim", "credential/prepare", "credential/activate"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("PUT")
                        .uri(format!(
                            "/api/v1/node-credential-claims/{}/{suffix}",
                            op.new.node_id
                        ))
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT, "non-POST {suffix}");
        }
        let claim_app = axum::Router::new()
            .route(
                "/api/v1/node-credential-claims/{claim_id}/claim",
                axum::routing::post(super::super::node_claim::claim_node),
            )
            .layer(axum::middleware::from_fn_with_state(state.clone(), guard))
            .with_state(state.clone());
        let unauthenticated = claim_app.oneshot(axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/v1/node-credential-claims/{}/claim", op.new.node_id))
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127,0,0,1],443))))
            .body(axum::body::Body::from(serde_json::json!({"home_group_id":op.new.home_group_id,"node_id":op.new.node_id,"secret":"invalid","claimant_nonce":"invalid"}).to_string())).unwrap()).await.unwrap();
        assert_ne!(unauthenticated.status(), StatusCode::OK);
        // Administrative cancellation and unrelated writes to the staged Node stay blocked.
        for (method, route) in [
            (
                "POST",
                format!(
                    "/api/v1/admin/node-credential-claims/{}/cancel",
                    op.new.node_id
                ),
            ),
            (
                "DELETE",
                format!(
                    "/api/v1/admin/node-pool/nodes/{}/{}",
                    op.new.home_group_id, op.new.node_id
                ),
            ),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .method(method)
                            .uri(route)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::CONFLICT
            );
        }
    }
}
