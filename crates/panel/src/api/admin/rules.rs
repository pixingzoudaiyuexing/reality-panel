use super::err;
use crate::api::middleware::AuthUser;
use crate::api::AppState;
use crate::service::rules::{CreateRuleError, UpdateRuleError};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use relay_shared::models::*;
use relay_shared::protocol::*;

/// Query params for list_rules (v0.4.20).
#[derive(serde::Deserialize, Default)]
pub struct ListRulesQuery {
    /// Admin-only: filter rules by owner. Non-admin is ignored.
    pub owner_uid: Option<i64>,
}

// === Forward Rules ===
pub async fn list_rules(
    user: AuthUser,
    Query(query): Query<ListRulesQuery>,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<ForwardRule>>> {
    // v0.4.20: admin can filter rules by owner_uid for user rule management.
    let scope = match (user.admin, query.owner_uid) {
        (true, Some(owner_uid)) => crate::db::repo::ResourceScope::Owner(owner_uid),
        _ => user.resource_scope(),
    };
    let rules: Vec<ForwardRule> = state.db.list_rules(&scope).await.unwrap_or_else(|e| {
        tracing::error!("list_rules: db error: {}", e);
        Vec::new()
    });
    Json(ApiResponse::success(rules))
}

pub async fn create_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Json<ApiResponse<()>> {
    if req.camouflage_enabled && !user.admin {
        return Json(err(
            403,
            "camouflage-enabled Reality relay rules are admin-only",
        ));
    }
    if req.send_proxy_protocol && !user.admin {
        return Json(err(403, "upstream Proxy Protocol is admin-only"));
    }
    // v1.0.4: non-admin users with a RESTRICTED permission group (group set +
    // allow_all_groups=false) can only create rules on authorized device
    // groups. An empty authorized list means "no groups allowed" → deny. Legacy
    // (group_id NULL) and allow-all users skip this and defer to the service
    // layer's normal group validation. A DB error returns 500.
    if !user.admin {
        let restricted = match state.db.is_user_restricted(user.user_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("create_rule: restriction lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        };
        if restricted {
            let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("create_rule: authz lookup failed: {}", e);
                    return Json(err(500, "数据库错误"));
                }
            };
            if !allowed.contains(&req.device_group_in) {
                return Json(err(403, "device_group_in 不在您允许的分组列表中"));
            }
        }
    }
    match crate::service::rules::create_rule(state.db.as_ref(), user.user_id, user.admin, &req)
        .await
    {
        Ok(rule_id) => {
            if let Err(error) =
                crate::service::dnsmgr::schedule_rule(state.db.as_ref(), rule_id).await
            {
                tracing::error!(
                    "create_rule {}: DNS reconciliation scheduling failed: {}",
                    rule_id,
                    error
                );
            } else {
                crate::service::dnsmgr::audit_sync_scheduled(&state, Some(user.user_id), rule_id)
                    .await;
            }
            if req.camouflage_enabled {
                let detail = format!(
                    "sni={} public_port={} remote={}:{} camouflage=enabled result=success",
                    req.sni.as_deref().unwrap_or_default(),
                    req.listen_port.unwrap_or_default(),
                    req.target_addr,
                    req.target_port
                );
                crate::service::audit::record(
                    &state,
                    Some(user.user_id),
                    "create_reality_relay_rule",
                    "rule",
                    rule_id,
                    &detail,
                )
                .await;
            }
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(CreateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(CreateRuleError::PortConflict(port)) => Json(err(
            409,
            format!("监听端口 {} 在此入口分组上已被占用", port),
        )),
        Err(CreateRuleError::Database(e)) => {
            tracing::error!("create_rule: service failed: {}", e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn update_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleRequest>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    let existing_snapshot = match state.db.find_rule_by_id(id, &scope).await {
        Ok(rule) => rule,
        Err(e) => {
            tracing::error!("update_rule: rule lookup failed: {}", e);
            return Json(err(500, "数据库错误"));
        }
    };
    if !user.admin
        && (existing_snapshot
            .as_ref()
            .map(|rule| rule.camouflage_enabled)
            .unwrap_or(false)
            || req.camouflage_enabled == Some(true))
    {
        return Json(err(
            403,
            "camouflage-enabled Reality relay rules are admin-only",
        ));
    }
    if !user.admin
        && (existing_snapshot
            .as_ref()
            .map(|rule| rule.send_proxy_protocol)
            .unwrap_or(false)
            || req.send_proxy_protocol == Some(true))
    {
        return Json(err(403, "upstream Proxy Protocol is admin-only"));
    }
    // v1.0.4: restricted non-admin users can only switch to authorized device
    // groups. Legacy/allow-all users skip this. DB error → 500.
    if !user.admin {
        if let Some(dgi) = req.device_group_in {
            let restricted = match state.db.is_user_restricted(user.user_id).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("update_rule: restriction lookup failed: {}", e);
                    return Json(err(500, "数据库错误"));
                }
            };
            if restricted {
                let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("update_rule: authz lookup failed: {}", e);
                        return Json(err(500, "数据库错误"));
                    }
                };
                if !allowed.contains(&dgi) {
                    return Json(err(
                        403,
                        "device_group_in is not in your allowed device groups",
                    ));
                }
            }
        }
    }
    // v1.0.7: resuming a rule (paused → false) is ALSO gated on authorization.
    // A restricted user whose plan was removed has their rules auto-paused; they
    // must not be able to re-enable a rule pointing at a now-unauthorized group
    // by sending only {paused:false} — the device_group_in check above is
    // skipped when that field is absent. Only needed when not switching groups
    // in the same request (that path is already covered above).
    if !user.admin && req.paused == Some(false) && req.device_group_in.is_none() {
        let restricted = match state.db.is_user_restricted(user.user_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("update_rule: restriction lookup failed: {}", e);
                return Json(err(500, "数据库错误"));
            }
        };
        if restricted {
            match state.db.find_rule_by_id(id, &scope).await {
                Ok(Some(rule)) => {
                    let allowed = match state.db.authorized_device_group_ids(user.user_id).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::error!("update_rule: authz lookup failed: {}", e);
                            return Json(err(500, "数据库错误"));
                        }
                    };
                    if !allowed.contains(&rule.device_group_in) {
                        return Json(err(403, "无法启动未被授权设备分组下的规则"));
                    }
                }
                Ok(None) => return Json(err(404, "规则不存在")),
                Err(e) => {
                    tracing::error!("update_rule: rule lookup failed: {}", e);
                    return Json(err(500, "数据库错误"));
                }
            }
        }
    }
    match crate::service::rules::update_rule(state.db.as_ref(), id, &scope, &req).await {
        Ok(()) => {
            if let Err(error) = crate::service::dnsmgr::schedule_rule(state.db.as_ref(), id).await {
                tracing::error!(
                    "update_rule {}: DNS reconciliation scheduling failed: {}",
                    id,
                    error
                );
            } else {
                crate::service::dnsmgr::audit_sync_scheduled(&state, Some(user.user_id), id).await;
            }
            if user.admin
                && (existing_snapshot
                    .as_ref()
                    .map(|rule| rule.camouflage_enabled)
                    .unwrap_or(false)
                    || req.camouflage_enabled == Some(true))
            {
                if let Ok(Some(rule)) = state.db.find_rule_by_id(id, &scope).await {
                    let detail = format!(
                        "sni={} public_port={} remote={}:{} camouflage={} result=success",
                        rule.sni.as_deref().unwrap_or_default(),
                        rule.listen_port,
                        rule.target_addr,
                        rule.target_port,
                        if rule.camouflage_enabled {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                    crate::service::audit::record(
                        &state,
                        Some(user.user_id),
                        "update_reality_relay_rule",
                        "rule",
                        id,
                        &detail,
                    )
                    .await;
                }
            }
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(UpdateRuleError::BadRequest(msg)) => Json(err(400, msg)),
        Err(UpdateRuleError::NotFound) => Json(err(404, "规则不存在")),
        Err(UpdateRuleError::PortConflict) => Json(err(409, "监听端口在此入口分组上已被占用")),
        Err(UpdateRuleError::Internal(msg)) => Json(err(500, msg)),
        Err(UpdateRuleError::Database(e)) => {
            tracing::error!("update_rule {}: service failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_rule(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    let scope = user.resource_scope();
    // Snapshot the name before the delete — afterwards there is no row to read
    // it from, and "rule 12" alone doesn't answer "who deleted my rule".
    let rule_snapshot = match state.db.find_rule_by_id(id, &scope).await {
        Ok(rule) => rule,
        Err(_) => None,
    };
    if !user.admin
        && rule_snapshot
            .as_ref()
            .map(|rule| rule.camouflage_enabled)
            .unwrap_or(false)
    {
        return Json(err(
            403,
            "camouflage-enabled Reality relay rules are admin-only",
        ));
    }
    let rule_name = rule_snapshot
        .as_ref()
        .map(|rule| rule.name.clone())
        .unwrap_or_default();
    // v0.3.6: check rows_affected(). A non-existent rule previously returned
    // success AND broadcast config_changed — a no-op mutation that needlessly
    // triggered a node re-fetch. Now 404 + no broadcast when nothing was deleted.
    match crate::service::groups::delete_rule(state.db.as_ref(), id, &scope).await {
        // v0.3.6: nothing existed at that id. Return 404 and do NOT broadcast
        // config_changed — a no-op delete shouldn't trigger a node re-fetch.
        Ok(false) => Json(err(404, "规则不存在")),
        Ok(true) => {
            tracing::warn!(
                action = "delete_rule",
                rule_id = id,
                actor_id = user.user_id,
                actor_admin = user.admin,
                "destructive op"
            );
            // Recorded for non-admins too: a rule can be deleted by its owner,
            // and "it wasn't an admin" is itself the answer sometimes.
            crate::service::audit::record(
                &state,
                Some(user.user_id),
                "delete_rule",
                "rule",
                id,
                &rule_name,
            )
            .await;
            if let Some(rule) = rule_snapshot.filter(|rule| rule.camouflage_enabled) {
                let detail = format!(
                    "sni={} public_port={} remote={}:{} camouflage=enabled result=success",
                    rule.sni.as_deref().unwrap_or_default(),
                    rule.listen_port,
                    rule.target_addr,
                    rule.target_port
                );
                crate::service::audit::record(
                    &state,
                    Some(user.user_id),
                    "delete_reality_relay_rule",
                    "rule",
                    id,
                    &detail,
                )
                .await;
            }
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("delete_rule {}: delete_rule failed: {}", id, e);
            Json(err(500, "数据库错误"))
        }
    }
}
