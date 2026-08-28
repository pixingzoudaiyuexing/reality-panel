//! Admin/user-facing control operation for rebuilding one node's shared
//! nginx_sni plan. It waits for an authenticated node result instead of
//! reporting success merely because a WS sender accepted the message.

use crate::api::diagnose::{group_node_statuses, NodeStatusRow, DIAGNOSE_TIMEOUT};
use crate::api::middleware::AuthUser;
use crate::api::node::extract_node_token;
use crate::api::AppState;
use crate::db::repo::ResourceScope;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use relay_shared::protocol::{
    node_supports_restart_rule, ApiResponse, ReapplyNginxSniMessage, ReapplyNginxSniResult,
};
use serde::Serialize;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NodeReapplyStatus {
    Result {
        node_id: String,
        group_name: String,
        public_ip: Option<String>,
        success: bool,
        error: Option<String>,
    },
    Unsupported {
        node_id: String,
        group_name: String,
        public_ip: Option<String>,
        node_version: Option<String>,
    },
    ControlChannelOffline {
        node_id: String,
        group_name: String,
        public_ip: Option<String>,
    },
    Timeout {
        node_id: String,
        group_name: String,
        public_ip: Option<String>,
    },
}

#[derive(Debug, Serialize)]
pub struct ReapplyResponse {
    pub rule_id: i64,
    pub applied: usize,
    pub nodes: Vec<NodeReapplyStatus>,
}

pub async fn reapply_nginx_sni(
    user: AuthUser,
    State(state): State<AppState>,
    Path(rule_id): Path<i64>,
) -> Json<ApiResponse<ReapplyResponse>> {
    let scope = user.resource_scope();
    let rule = match state.db.find_rule_by_id(rule_id, &scope).await {
        Ok(Some(rule)) => rule,
        Ok(None) => {
            return Json(ApiResponse {
                code: 404,
                message: "Rule not found".into(),
                data: None,
            })
        }
        Err(error) => {
            tracing::error!(
                "reapply_nginx_sni {}: rule lookup failed: {}",
                rule_id,
                error
            );
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };
    if rule.paused {
        return Json(ApiResponse {
            code: 400,
            message: "规则已暂停，无法重新应用".into(),
            data: None,
        });
    }
    if rule.public_transport != "nginx_sni" && rule.node_transport != "nginx_sni" {
        return Json(ApiResponse {
            code: 400,
            message: "只有 nginx_sni Reality 规则支持重新应用".into(),
            data: None,
        });
    }

    let group_name = match crate::db::repo::GroupRepository::find_by_id(
        state.db.as_ref(),
        rule.device_group_in,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(group)) => group.name,
        Ok(None) => format!("#{}", rule.device_group_in),
        Err(error) => {
            tracing::error!(
                "reapply_nginx_sni {}: group lookup failed: {}",
                rule_id,
                error
            );
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };
    let nodes = match group_node_statuses(&state, rule.device_group_in, group_name).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::error!(
                "reapply_nginx_sni {}: node status lookup failed: {}",
                rule_id,
                error
            );
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    };
    let online = state
        .node_connections
        .online_node_ids(rule.device_group_in)
        .await;
    let mut statuses = Vec::new();
    let mut candidates = Vec::<NodeStatusRow>::new();
    for node in nodes {
        if !node_supports_restart_rule(node.node_version.as_deref()) {
            statuses.push(NodeReapplyStatus::Unsupported {
                node_id: node.node_id,
                group_name: node.group_name,
                public_ip: node.public_ip,
                node_version: node.node_version,
            });
        } else if online.contains(&node.node_id) {
            candidates.push(node);
        } else {
            statuses.push(NodeReapplyStatus::ControlChannelOffline {
                node_id: node.node_id,
                group_name: node.group_name,
                public_ip: node.public_ip,
            });
        }
    }
    if candidates.is_empty() {
        return Json(ApiResponse::success(ReapplyResponse {
            rule_id,
            applied: 0,
            nodes: statuses,
        }));
    }

    let ids: Vec<String> = candidates.iter().map(|node| node.node_id.clone()).collect();
    let (request_id, challenge) = state.diagnose.start_reapply(rule_id, ids.clone()).await;
    let by_id = candidates
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<std::collections::HashMap<_, _>>();
    let mut sent = HashSet::new();
    for node in &candidates {
        let message = serde_json::to_string(&ReapplyNginxSniMessage::new(
            node.node_id.clone(),
            rule_id,
            request_id.clone(),
            challenge.clone(),
        ))
        .expect("reapply message serializes");
        if state
            .node_connections
            .send_node(rule.device_group_in, &node.node_id, &message)
            .await
            > 0
        {
            sent.insert(node.node_id.clone());
        } else {
            statuses.push(NodeReapplyStatus::ControlChannelOffline {
                node_id: node.node_id.clone(),
                group_name: node.group_name.clone(),
                public_ip: node.public_ip.clone(),
            });
        }
    }
    state
        .diagnose
        .retain_reapply_expected(&request_id, &sent)
        .await;
    if sent.is_empty() {
        state.diagnose.remove_reapply(&request_id).await;
        return Json(ApiResponse::success(ReapplyResponse {
            rule_id,
            applied: 0,
            nodes: statuses,
        }));
    }
    let deadline = Instant::now() + DIAGNOSE_TIMEOUT;
    while Instant::now() < deadline {
        if state.diagnose.all_reapply_received(&request_id).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (_, results) = state
        .diagnose
        .snapshot_reapply(&request_id)
        .await
        .unwrap_or((rule_id, Vec::new()));
    let mut replied = HashSet::new();
    let mut applied = 0;
    for result in results {
        replied.insert(result.node_id.clone());
        if result.success {
            applied += 1;
        }
        if let Some(node) = by_id.get(result.node_id.as_str()) {
            statuses.push(NodeReapplyStatus::Result {
                node_id: result.node_id,
                group_name: node.group_name.clone(),
                public_ip: node.public_ip.clone(),
                success: result.success,
                error: result.error,
            });
        }
    }
    for node_id in sent {
        if !replied.contains(&node_id) {
            if let Some(node) = by_id.get(node_id.as_str()) {
                statuses.push(NodeReapplyStatus::Timeout {
                    node_id,
                    group_name: node.group_name.clone(),
                    public_ip: node.public_ip.clone(),
                });
            }
        }
    }
    state.diagnose.remove_reapply(&request_id).await;
    state.diagnose.sweep().await;
    crate::service::audit::record(
        &state,
        Some(user.user_id),
        "reapply_nginx_sni",
        "rule",
        rule_id,
        &format!(
            "{} — 成功 {}/{} 个节点",
            rule.name,
            applied,
            candidates.len()
        ),
    )
    .await;
    Json(ApiResponse::success(ReapplyResponse {
        rule_id,
        applied,
        nodes: statuses,
    }))
}

pub async fn receive_reapply_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(result): Json<ReapplyNginxSniResult>,
) -> Json<ApiResponse<()>> {
    let Some(token) = extract_node_token(&headers) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };
    let Some(group) = (match state.db.find_by_token(&token).await {
        Ok(group) => group,
        Err(error) => {
            tracing::error!("reapply result group lookup failed: {}", error);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    }) else {
        return Json(ApiResponse {
            code: 401,
            message: "Invalid token".into(),
            data: None,
        });
    };
    let Some(rule) = (match state
        .db
        .find_rule_by_id(result.rule_id, &ResourceScope::All)
        .await
    {
        Ok(rule) => rule,
        Err(error) => {
            tracing::error!("reapply result rule lookup failed: {}", error);
            return Json(ApiResponse {
                code: 500,
                message: "database error".into(),
                data: None,
            });
        }
    }) else {
        return Json(ApiResponse {
            code: 404,
            message: "Rule not found".into(),
            data: None,
        });
    };
    if rule.device_group_in != group.id
        || (rule.public_transport != "nginx_sni" && rule.node_transport != "nginx_sni")
    {
        return Json(ApiResponse {
            code: 403,
            message: "rule does not belong to this nginx_sni group".into(),
            data: None,
        });
    }
    let request_id = result.request_id.clone();
    if !state.diagnose.record_reapply(&request_id, result).await {
        return Json(ApiResponse {
            code: 409,
            message: "reapply task unknown, expired, or unexpected node".into(),
            data: None,
        });
    }
    Json(ApiResponse::success(()))
}
