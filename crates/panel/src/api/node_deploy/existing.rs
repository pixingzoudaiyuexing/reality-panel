//! Exact SSH installation evidence and a separate secret-free administrator DTO.
use super::*;
use crate::node_identity::ReuseEligibleNodeId;
use crate::service::node_pool;

#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct HostFacts {
    #[serde(default)]
    pub candidate_node_ids: Vec<String>,
    pub node_id: Option<String>,
    pub version: Option<String>,
    pub profile: Option<String>,
    pub service_active: bool,
    pub panel_url: Option<String>,
    pub identity_group_id: Option<i64>,
    pub credential_id: Option<String>,
    pub credential_verifier: Option<String>,
    pub runtime_valid: bool,
    pub state_phase: Option<String>,
    pub residue_owned: bool,
    pub ambiguity: Option<String>,
    #[serde(default)]
    pub retry_snapshot: Option<String>,
    #[serde(default)]
    pub retry_node_ids: Vec<String>,
    #[serde(default)]
    pub retry_failed_ids: Vec<String>,
    #[serde(default)]
    pub retry_blocker: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ExistingInstallation {
    pub classification: &'static str,
    pub old_node_id: Option<String>,
    pub version: Option<String>,
    pub profile: Option<String>,
    pub service_active: bool,
    pub panel_present: bool,
    pub online: bool,
    pub credential_active: bool,
    pub group_count: usize,
    pub carrier_reference_count: usize,
    pub reason: Option<String>,
    pub confirmation: String,
    pub retry_confirmation: Option<String>,
    pub retry_blocker: Option<String>,
    #[serde(skip)]
    pub(super) retry_authorized: bool,
    #[serde(skip)]
    pub(super) identity_group_id: Option<i64>,
}

pub(super) async fn detect(
    state: &AppState,
    facts: &HostFacts,
    fingerprint: &str,
    target_lite: bool,
) -> Result<ExistingInstallation, DeployError> {
    let mut view = detect_installation(state, facts, fingerprint, target_lite).await?;
    let failed_task = state.deployments.tasks.lock().await.values().any(|task| {
        task.status.status == "FAILED"
            && task.ssh_fingerprint.as_deref() == Some(fingerprint)
            && task
                .status
                .candidate_node_id
                .as_ref()
                .is_some_and(|id| facts.retry_node_ids.contains(id))
    });
    let failed_retry = view.classification == "AMBIGUOUS_STATE"
        || !facts.retry_failed_ids.is_empty()
        || failed_task;
    if facts.retry_snapshot.is_some() && failed_retry {
        match retry_authority(state, facts, fingerprint, target_lite).await {
            Ok(confirmation) => view.retry_confirmation = Some(confirmation),
            Err(_) => {
                view.retry_blocker =
                    Some("残留关联已使用的节点身份或资源，不能按失败安装重试清理".into())
            }
        }
    }
    Ok(view)
}

/// Only locally inspected candidates, never deployments matching a hostname.
pub(super) async fn retry_authority(
    state: &AppState,
    facts: &HostFacts,
    fingerprint: &str,
    lite: bool,
) -> Result<String, DeployError> {
    let snapshot = facts
        .retry_snapshot
        .as_deref()
        .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(retry_error)?;
    if facts.retry_blocker.is_some()
        || facts.retry_node_ids.len() > 1
        || facts
            .retry_failed_ids
            .iter()
            .any(|id| !facts.retry_node_ids.contains(id))
    {
        return Err(retry_error());
    }
    let anchor = state
        .db
        .node_pool_system_group_id()
        .await
        .map_err(db_error)?;
    let identities = state
        .db
        .discover_node_pool_identities()
        .await
        .map_err(db_error)?;
    let pool = node_pool::list_nodes(state.db.as_ref())
        .await
        .map_err(db_error)?;
    let mut claim_states = Vec::new();
    for id in &facts.retry_node_ids {
        let failed_task = state.deployments.tasks.lock().await.values().any(|task| {
            task.status.status == "FAILED"
                && task.ssh_fingerprint.as_deref() == Some(fingerprint)
                && task.status.candidate_node_id.as_deref() == Some(id.as_str())
        });
        let failed_candidate = facts.retry_failed_ids.contains(id) || failed_task;
        let node = ReuseEligibleNodeId::parse(id).map_err(|_| retry_error())?;
        if identities
            .iter()
            .any(|identity| identity.node_id == *id && Some(identity.home_group_id) != anchor)
        {
            return Err(retry_error());
        }
        if pool.iter().any(|record| {
            record.node_id == *id
                && (Some(record.identity_group_id) != anchor
                    || (record.online && !failed_candidate)
                    || !record.memberships.is_empty())
        }) {
            return Err(retry_error());
        }
        let Some(group) = anchor else {
            continue;
        };
        if (state
            .node_connections
            .online_node_ids(group)
            .await
            .contains(id)
            && !failed_candidate)
            || state.node_operations.has_active_for_node(group, id)
            || crate::api::node_ops::has_active_durable_uninstall(state, group, id)
                .await
                .map_err(|_| retry_error())?
        {
            return Err(retry_error());
        }
        if crate::service::legacy_upgrade::load(state.db.as_ref())
            .await
            .map_err(|_| retry_error())?
            .is_some_and(|(_, op)| {
                op.active()
                    && ((op.old.home_group_id == group && op.old.node_id == *id)
                        || (op.new.home_group_id == group && op.new.node_id == *id))
            })
        {
            return Err(retry_error());
        }
        // Routing references are checked with the same parser as exact retirement.
        for prefix in [
            crate::service::relay_preference::RELAY_PREFERENCE_KEY_PREFIX,
            crate::service::relay_failover::RELAY_FAILOVER_KEY_PREFIX,
        ] {
            for (key, raw) in state.db.scan_prefix(prefix).await.map_err(db_error)? {
                if !node_pool::routing_reference_groups(&key, &raw, id)
                    .map_err(db_error)?
                    .is_empty()
                {
                    return Err(retry_error());
                }
            }
        }
        if let Some(raw) = state
            .db
            .get(crate::service::relay_schedule::RELAY_SWITCH_SCHEDULES_KEY)
            .await
            .map_err(db_error)?
        {
            if !node_pool::routing_reference_groups(
                crate::service::relay_schedule::RELAY_SWITCH_SCHEDULES_KEY,
                &raw,
                id,
            )
            .map_err(db_error)?
            .is_empty()
            {
                return Err(retry_error());
            }
        }
        let active = state
            .db
            .find_current_active_node_credential_for_identity(group, &node)
            .await
            .map_err(db_error)?
            .is_some();
        if active && !failed_candidate {
            return Err(retry_error());
        }
        if let Some(claim) = state
            .db
            .find_node_credential_claim(id)
            .await
            .map_err(db_error)?
        {
            if claim.node_id != *id
                || claim.home_group_id != group
                || claim.approval_ref != format!("node-pool-bootstrap:{id}")
            {
                return Err(retry_error());
            }
            claim_states.push((id, claim.state, active));
        } else if active {
            return Err(retry_error());
        }
    }
    let raw = serde_json::to_vec(&(
        "failed-install-retry/v1",
        fingerprint,
        lite,
        snapshot,
        &facts.retry_node_ids,
        claim_states,
    ))
    .map_err(|_| retry_error())?;
    Ok(hex::encode(Sha256::digest(raw)))
}

pub(super) async fn cancel_retry_candidates(
    state: &AppState,
    facts: &HostFacts,
    fingerprint: &str,
    lite: bool,
    actor: i64,
) -> Result<(), DeployError> {
    retry_authority(state, facts, fingerprint, lite).await?;
    let Some(group) = state
        .db
        .node_pool_system_group_id()
        .await
        .map_err(db_error)?
    else {
        return Ok(());
    };
    for id in &facts.retry_node_ids {
        let Some(claim) = state
            .db
            .find_node_credential_claim(id)
            .await
            .map_err(db_error)?
        else {
            continue;
        };
        if claim.node_id != *id
            || claim.home_group_id != group
            || claim.approval_ref != format!("node-pool-bootstrap:{id}")
        {
            return Err(retry_error());
        }
        let node = ReuseEligibleNodeId::parse(id).map_err(|_| retry_error())?;
        state
            .db
            .cancel_node_credential_claim(id, group, &node, chrono::Utc::now())
            .await
            .map_err(db_error)?;
        // Cancellation arbitrates activation; an activation that won must still
        // satisfy the same failed-candidate and no-business-reference checks.
        retry_authority(state, facts, fingerprint, lite).await?;
        retire_host_identity(state, group, id, actor).await?;
    }
    Ok(())
}

fn retry_error() -> DeployError {
    DeployError::new(
        "FAILED_RETRY_PROTECTED",
        "仅可清理当前失败安装残留；已使用或其他节点身份受到保护",
    )
}

async fn detect_installation(
    state: &AppState,
    facts: &HostFacts,
    fingerprint: &str,
    target_lite: bool,
) -> Result<ExistingInstallation, DeployError> {
    let mut result = ExistingInstallation {
        classification: "AMBIGUOUS_STATE",
        old_node_id: facts.node_id.clone(),
        version: facts.version.clone(),
        profile: facts.profile.clone(),
        service_active: facts.service_active,
        panel_present: false,
        online: false,
        credential_active: false,
        group_count: 0,
        carrier_reference_count: 0,
        reason: facts.ambiguity.clone(),
        confirmation: String::new(),
        retry_confirmation: None,
        retry_blocker: facts.retry_blocker.clone(),
        retry_authorized: false,
        identity_group_id: None,
    };
    if facts.ambiguity.is_some() {
        return Ok(result);
    }
    let Some(id) = facts.node_id.as_deref() else {
        if facts.retry_snapshot.is_none() {
            result.classification = "CLEAN_HOST";
        } else {
            result.reason = Some("存在失败安装残留，尚无完整节点身份".into());
        }
        return Ok(result);
    };
    let id = match ReuseEligibleNodeId::parse(id) {
        Ok(id) => id,
        Err(_) => {
            result.reason = Some("旧节点身份格式无法确认".into());
            return Ok(result);
        }
    };
    let pool = node_pool::list_nodes(state.db.as_ref())
        .await
        .map_err(db_error)?;
    let matches: Vec<_> = pool.iter().filter(|n| n.node_id == id.as_str()).collect();
    let identities = state
        .db
        .discover_node_pool_identities()
        .await
        .map_err(db_error)?;
    if matches.len() > 1
        || identities.iter().any(|n| {
            n.node_id == id.as_str()
                && Some(n.home_group_id) != facts.identity_group_id
                && !matches
                    .iter()
                    .any(|m| m.identity_group_id == n.home_group_id)
        })
    {
        result.reason = Some("旧身份对应多个或相互冲突的 Panel 记录".into());
        return Ok(result);
    }
    let anchor = state
        .db
        .node_pool_system_group_id()
        .await
        .map_err(db_error)?;
    let group = facts
        .identity_group_id
        .or_else(|| matches.first().map(|n| n.identity_group_id))
        .or(anchor);
    let Some(group) = group else {
        result.reason = Some("无法确认旧身份所属面板".into());
        return Ok(result);
    };
    result.identity_group_id = Some(group);
    if state
        .node_operations
        .has_active_for_node(group, id.as_str())
        || crate::api::node_ops::has_active_durable_uninstall(state, group, id.as_str())
            .await
            .map_err(|_| DeployError::new("EXISTING_STATE_UNAVAILABLE", "无法读取卸载状态"))?
    {
        result.reason = Some("旧节点仍有未完成的生命周期操作，保留现有安装".into());
        return Ok(result);
    }
    if crate::service::legacy_upgrade::load(state.db.as_ref())
        .await
        .map_err(|_| DeployError::new("EXISTING_STATE_AMBIGUOUS", "迁移状态无法确认"))?
        .is_some_and(|(_, op)| {
            op.active()
                && ((op.old.home_group_id == group && op.old.node_id == id.as_str())
                    || (op.new.home_group_id == group && op.new.node_id == id.as_str()))
        })
    {
        result.reason = Some("此身份仍在迁移中；不能覆盖安装".into());
        return Ok(result);
    }

    let credential = state
        .db
        .find_current_active_node_credential_for_identity(group, &id)
        .await
        .map_err(db_error)?;
    result.credential_active = credential.is_some();
    if let Some(node) = matches.first() {
        result.panel_present = true;
        result.online = node.online;
        result.group_count = node.memberships.len();
        if !node.pool_native || node.identity_group_id != group {
            result.reason = Some("现有身份无法使用节点池的精确退休路径；保留旧节点".into());
            return Ok(result);
        }
    }
    let url = effective_public_panel_url(state).await.unwrap_or_default();
    let same_panel = facts.panel_url.as_deref().map(|u| u.trim_end_matches('/'))
        == Some(url.trim_end_matches('/'));
    let proof = if let Some(credential_id) = facts.credential_id.as_deref() {
        state
            .db
            .find_node_credential(credential_id)
            .await
            .map_err(db_error)?
            .filter(|c| {
                c.verifier_format == crate::node_credential::NODE_CREDENTIAL_VERIFIER_FORMAT
                    && c.verifier_version
                        == crate::node_credential::NODE_CREDENTIAL_VERIFIER_VERSION
                    && c.home_group_id == group
                    && c.node_id == id.as_str()
                    && facts.credential_verifier.as_deref()
                        == Some(hex::encode(&c.verifier_data).as_str())
            })
    } else {
        None
    };
    let rows = state
        .db
        .scan_prefix(crate::service::relay_preference::RELAY_PREFERENCE_KEY_PREFIX)
        .await
        .map_err(db_error)?;
    for (_, raw) in &rows {
        let preference: serde_json::Value = serde_json::from_str(raw).map_err(|_| {
            DeployError::new("EXISTING_STATE_AMBIGUOUS", "存储的运营商状态无法确认")
        })?;
        for key in ["carrier_policy", "pending_carrier_policy"] {
            let default = preference[key]["default_node_id"]
                .as_str()
                .or(preference["preferred_node_id"].as_str());
            let configured = !preference[key]["default_node_id"].is_null()
                || preference[key]["bindings"]
                    .as_array()
                    .is_some_and(|b| !b.is_empty());
            if !configured {
                continue;
            }
            let mut lines = std::collections::BTreeSet::new();
            if default == Some(id.as_str()) {
                lines.insert("default");
            }
            if let Some(bindings) = preference[key]["bindings"].as_array() {
                for binding in bindings {
                    if binding["node_id"].as_str() == Some(id.as_str())
                        || (binding["mode"] == "follow_default" && default == Some(id.as_str()))
                    {
                        if let Some(line) = binding["line_id"].as_str() {
                            lines.insert(line);
                        }
                    }
                }
            }
            if !preference[key].is_null() {
                result.carrier_reference_count += lines.len();
            }
        }
    }
    if !same_panel || (facts.credential_id.is_some() && proof.is_none()) {
        result.reason = Some("SSH 主机的面板地址或 credential 与旧身份记录不匹配".into());
        return Ok(result);
    }
    let claims = state
        .db
        .list_node_credential_claims_for_identity(group, &id)
        .await
        .map_err(db_error)?;
    let pending_claim = claims.iter().any(|c| {
        !matches!(c.state.as_str(), "COMPLETED" | "CANCELLED" | "EXPIRED")
            && chrono::DateTime::parse_from_rfc3339(&c.expires_at)
                .map_or(true, |date| date > chrono::Utc::now())
    });
    if result.credential_active {
        if !result.panel_present
            || !facts.runtime_valid
            || proof.as_ref().map(|p| p.credential_id.as_str())
                != credential.as_ref().map(|c| c.credential_id.as_str())
        {
            result.reason = Some("ACTIVE credential 的主机身份或持久认证不完整".into());
            return Ok(result);
        }
        result.classification = "MANAGED_EXISTING_NODE";
    } else if (!facts.service_active || proof.as_ref().is_some_and(|p| p.revoked_at.is_some()))
        && !pending_claim
        && facts.residue_owned
        && result.group_count == 0
        && result.carrier_reference_count == 0
    {
        result.classification = "STALE_INACTIVE_RESIDUE";
    } else {
        result.reason = Some("仍存在运行服务、未结束授权或业务关系，不能按无效残留清理".into());
        return Ok(result);
    }
    // Includes private evidence, but only its digest crosses the admin API.
    // Execution re-reads both host and Panel state and rejects changed snapshots.
    let evidence = serde_json::to_vec(&(
        facts,
        fingerprint,
        target_lite,
        &rows,
        matches.first().map(|node| {
            node.memberships
                .iter()
                .map(|m| m.group_id)
                .collect::<Vec<_>>()
        }),
        &claims
            .iter()
            .map(|c| (&c.claim_id, &c.state, &c.updated_at))
            .collect::<Vec<_>>(),
        &result.old_node_id,
        result.credential_active,
        result.group_count,
        result.carrier_reference_count,
    ))
    .map_err(|_| DeployError::new("EXISTING_STATE_AMBIGUOUS", "检测快照无法生成"))?;
    result.confirmation = hex::encode(Sha256::digest(evidence));
    Ok(result)
}

fn db_error(_: crate::db::error::DbError) -> DeployError {
    DeployError::new(
        "EXISTING_STATE_UNAVAILABLE",
        "无法读取旧身份状态；旧节点未被修改",
    )
}

/// Only host-local product identities and prior deployments to this exact SSH
/// target are retired. Public IP alone is not evidence of installation ownership.
pub(super) async fn host_candidates(
    state: &AppState,
    facts: &HostFacts,
    host: &str,
    fingerprint: &str,
) -> Vec<String> {
    let mut nodes: std::collections::BTreeSet<String> =
        facts.candidate_node_ids.iter().cloned().collect();
    nodes.extend(facts.node_id.iter().cloned());
    for task in state.deployments.tasks.lock().await.values() {
        if task.status.host == host || task.ssh_fingerprint.as_deref() == Some(fingerprint) {
            nodes.extend(task.status.candidate_node_id.iter().cloned());
            nodes.extend(task.status.node_id.iter().cloned());
        }
    }
    nodes.retain(|id| ReuseEligibleNodeId::parse(id).is_ok());
    nodes.into_iter().collect()
}

pub(super) async fn resolve_host_identities(
    state: &AppState,
    ids: Vec<String>,
    fallback_group: i64,
) -> Result<Vec<(i64, String)>, DeployError> {
    let mut known = state
        .db
        .discover_node_pool_identities()
        .await
        .map_err(db_error)?;
    known.extend(
        state
            .db
            .list_node_pool_records()
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|r| crate::db::repo::ConcreteNodeIdentity {
                home_group_id: r.identity_group_id,
                node_id: r.node_id,
            }),
    );
    for (key, _) in state
        .db
        .scan_prefix("node_status:")
        .await
        .map_err(db_error)?
    {
        if let Some((home_group_id, Some(node_id))) = crate::api::stats::parse_status_key(&key) {
            known.push(crate::db::repo::ConcreteNodeIdentity {
                home_group_id,
                node_id: node_id.into(),
            });
        }
    }
    let mut out = std::collections::BTreeSet::new();
    for id in ids {
        if let Some(claim) = state
            .db
            .find_node_credential_claim(&id)
            .await
            .map_err(db_error)?
        {
            if claim.node_id == id {
                known.push(crate::db::repo::ConcreteNodeIdentity {
                    home_group_id: claim.home_group_id,
                    node_id: id.clone(),
                });
            }
        }
        let groups: Vec<_> = known
            .iter()
            .filter(|n| n.node_id == id)
            .map(|n| n.home_group_id)
            .collect();
        if groups.is_empty() {
            out.insert((fallback_group, id));
        } else {
            for group in groups {
                out.insert((group, id.clone()));
            }
        }
    }
    Ok(out.into_iter().collect())
}

pub(super) async fn retire_host_identity(
    state: &AppState,
    group: i64,
    id: &str,
    actor: i64,
) -> Result<(), DeployError> {
    let node = ReuseEligibleNodeId::parse(id).map_err(|_| retirement_error())?;
    // Existing atomic Pool delete preserves independent history and schedules DNS.
    node_pool::retire_installation_identity(state, group, id)
        .await
        .map_err(|_| retirement_error())?;
    for claim in state
        .db
        .list_node_credential_claims_for_identity(group, &node)
        .await
        .map_err(db_error)?
    {
        if !matches!(claim.state.as_str(), "COMPLETED" | "CANCELLED" | "EXPIRED") {
            state
                .db
                .cancel_node_credential_claim(&claim.claim_id, group, &node, chrono::Utc::now())
                .await
                .map_err(db_error)?;
        }
    }
    // Cancellation serializes with activation. An activation that won the race
    // is retired through the same authority transaction before local cleanup.
    node_pool::retire_installation_identity(state, group, id)
        .await
        .map_err(|_| retirement_error())?;
    if state
        .db
        .find_current_active_node_credential_for_identity(group, &node)
        .await
        .map_err(db_error)?
        .is_some()
    {
        return Err(retirement_error());
    }
    crate::api::node_ops::supersede_uninstall_after_admin_delete(state, group, id).await;
    crate::service::audit::record(
        state,
        Some(actor),
        "node_deploy_old_identity_retired",
        "node",
        id,
        "SSH destructive fresh reset",
    )
    .await;
    Ok(())
}

fn retirement_error() -> DeployError {
    DeployError::new(
        "IDENTITY_RETIREMENT_FAILED",
        "旧身份退休未完成；重新部署将继续清理",
    )
}
