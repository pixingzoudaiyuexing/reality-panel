//! Node Reuse V1 exact-node management and S4-A read-only preview.
//!
//! A persisted Binding is admin authorization history only. Every preview
//! revalidates the concrete Home identity's current ACTIVE Credential and every
//! source Group. Nothing in this module is wired into the live Node config
//! delivery paths; S4-A preview is intentionally read-only.

use crate::db::error::DbError;
use crate::db::repo::{
    ConcreteNodeIdentity, NodeReuseBinding, NodeReuseBindingCreateRejection,
    NodeReuseBindingCreateResult, Repository, ResourceScope,
};
use crate::node_identity::{ReuseEligibleNodeId, ReuseEligibleNodeIdError};
use crate::service::node_config::NodeConfigBuildError;
use relay_shared::protocol::{NodeConfigResponse, NodeTransport, Protocol};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeReuseIdentityError {
    SelfReuse,
    InvalidNodeId(ReuseEligibleNodeIdError),
}

#[derive(Debug)]
pub enum NodeReuseServiceError {
    Identity(NodeReuseIdentityError),
    Database(DbError),
    AdmissionRejected(NodeReuseBindingCreateRejection),
    BindingChangedDuringRead,
    InvalidStoredSource { group_id: i64, reason: &'static str },
    PreviewSourceConfigInvalid { group_id: i64, reason: String },
}

impl From<DbError> for NodeReuseServiceError {
    fn from(value: DbError) -> Self {
        Self::Database(value)
    }
}

impl From<NodeReuseIdentityError> for NodeReuseServiceError {
    fn from(value: NodeReuseIdentityError) -> Self {
        Self::Identity(value)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingMutationOutcome {
    Created,
    Existing,
    Deleted,
    Missing,
}

#[derive(Debug, Clone, Serialize)]
pub struct BindingMutationResult {
    pub outcome: BindingMutationOutcome,
    pub binding: Option<NodeReuseBinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeReuseBindingStatus {
    pub binding: NodeReuseBinding,
    pub current_active_credential: bool,
    pub home_group_inbound: bool,
    pub reusing_group_inbound: bool,
    pub preview_eligible: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfigPreviewSource {
    pub group_id: i64,
    pub is_home: bool,
    pub rule_ids: Vec<i64>,
    pub listener_count: usize,
    pub camouflage_site_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfigPreviewListener {
    pub source_group_id: i64,
    pub rule_id: i64,
    pub port: u16,
    pub protocol: Protocol,
    pub node_transport: NodeTransport,
    pub sni: Option<String>,
    pub camouflage_required: bool,
    pub send_proxy_protocol: bool,
    pub target_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfigPreviewCamouflage {
    pub source_group_id: i64,
    pub sni: String,
    pub tls_listener_port: u16,
    pub certificate_domain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfigPreviewConflict {
    pub kind: String,
    pub source_group_id: i64,
    pub rule_id: Option<i64>,
    pub other_source_group_id: Option<i64>,
    pub other_rule_id: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EffectiveConfigPreview {
    pub home_group_id: i64,
    pub node_id: String,
    pub source_group_ids: Vec<i64>,
    pub sources: Vec<EffectiveConfigPreviewSource>,
    pub listeners: Vec<EffectiveConfigPreviewListener>,
    pub camouflage_sites: Vec<EffectiveConfigPreviewCamouflage>,
    pub conflicts: Vec<EffectiveConfigPreviewConflict>,
    pub known_runtime_prerequisites_satisfied: bool,
    /// Always false in S4-A. The preview is not a runtime config source.
    pub runtime_delivery_enabled: bool,
}

/// Read-only S4-B foundation: the exact config payload produced from the same
/// source reads used to build EffectiveConfigPreview.
///
/// This is deliberately a candidate, not runtime authority. Callers must
/// inspect preview.known_runtime_prerequisites_satisfied, and live HTTP/WS
/// delivery remains Home-only while traffic replay and offline-LKG revocation
/// contracts are unresolved.
#[derive(Debug, Clone)]
pub struct EffectiveConfigCandidate {
    pub preview: EffectiveConfigPreview,
    pub config: NodeConfigResponse,
}

/// Pure identity validation used before every mutation.
pub fn validate_binding_identity(
    reusing_group_id: i64,
    home_group_id: i64,
    node_id: &str,
) -> Result<(), NodeReuseIdentityError> {
    if reusing_group_id == home_group_id {
        return Err(NodeReuseIdentityError::SelfReuse);
    }
    ReuseEligibleNodeId::parse(node_id).map_err(NodeReuseIdentityError::InvalidNodeId)?;
    Ok(())
}

/// Home Group first, followed by explicit reusing/source Groups in stable
/// ascending order.
pub async fn effective_source_groups(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<Vec<i64>, DbError> {
    let mut reusing = db
        .list_reusing_group_ids_for_node(home_group_id, node_id)
        .await?;
    reusing.retain(|group_id| *group_id != home_group_id);
    reusing.sort_unstable();
    reusing.dedup();

    let mut groups = Vec::with_capacity(reusing.len() + 1);
    groups.push(home_group_id);
    groups.extend(reusing);
    Ok(groups)
}

/// Stable reverse resolver for the concrete nodes explicitly authorized for one
/// reusing/source Group. Each item retains its Home Group namespace.
pub async fn reused_concrete_nodes_for_group(
    db: &dyn Repository,
    reusing_group_id: i64,
) -> Result<Vec<ConcreteNodeIdentity>, DbError> {
    let mut nodes = db
        .list_reused_concrete_nodes_for_group(reusing_group_id)
        .await?;
    nodes.sort();
    nodes.dedup();
    Ok(nodes)
}

pub async fn create_binding(
    db: &dyn Repository,
    reusing_group_id: i64,
    home_group_id: i64,
    node_id: &str,
) -> Result<BindingMutationResult, NodeReuseServiceError> {
    validate_binding_identity(reusing_group_id, home_group_id, node_id)?;
    let node_id =
        ReuseEligibleNodeId::parse(node_id).map_err(NodeReuseIdentityError::InvalidNodeId)?;

    match db
        .create_node_reuse_binding_if_active(reusing_group_id, home_group_id, &node_id)
        .await?
    {
        NodeReuseBindingCreateResult::Created(binding) => Ok(BindingMutationResult {
            outcome: BindingMutationOutcome::Created,
            binding: Some(binding),
        }),
        NodeReuseBindingCreateResult::Existing(binding) => Ok(BindingMutationResult {
            outcome: BindingMutationOutcome::Existing,
            binding: Some(binding),
        }),
        NodeReuseBindingCreateResult::Rejected(reason) => {
            Err(NodeReuseServiceError::AdmissionRejected(reason))
        }
    }
}

pub async fn delete_binding(
    db: &dyn Repository,
    reusing_group_id: i64,
    home_group_id: i64,
    node_id: &str,
) -> Result<BindingMutationResult, NodeReuseServiceError> {
    validate_binding_identity(reusing_group_id, home_group_id, node_id)?;
    let deleted = db
        .delete_node_reuse_binding(reusing_group_id, home_group_id, node_id)
        .await?;
    Ok(BindingMutationResult {
        outcome: if deleted == 0 {
            BindingMutationOutcome::Missing
        } else {
            BindingMutationOutcome::Deleted
        },
        binding: None,
    })
}

async fn status_for_binding(
    db: &dyn Repository,
    binding: NodeReuseBinding,
) -> Result<NodeReuseBindingStatus, NodeReuseServiceError> {
    let home = crate::db::repo::GroupRepository::find_by_id(
        db,
        binding.home_group_id,
        &ResourceScope::All,
    )
    .await?;
    let reusing = crate::db::repo::GroupRepository::find_by_id(
        db,
        binding.reusing_group_id,
        &ResourceScope::All,
    )
    .await?;

    let home_group_inbound = home.as_ref().is_some_and(|group| group.group_type == "in");
    let reusing_group_inbound = reusing
        .as_ref()
        .is_some_and(|group| group.group_type == "in");
    let parsed_node = ReuseEligibleNodeId::parse(&binding.node_id).ok();
    let current_active_credential = match parsed_node.as_ref() {
        Some(node_id) => db
            .find_current_active_node_credential_for_identity(binding.home_group_id, node_id)
            .await?
            .is_some(),
        None => false,
    };

    let mut blockers = Vec::new();
    if home.is_none() {
        blockers.push("HOME_GROUP_MISSING".into());
    } else if !home_group_inbound {
        blockers.push("HOME_GROUP_NOT_INBOUND".into());
    }
    if reusing.is_none() {
        blockers.push("REUSING_GROUP_MISSING".into());
    } else if !reusing_group_inbound {
        blockers.push("REUSING_GROUP_NOT_INBOUND".into());
    }
    if parsed_node.is_none() {
        blockers.push("INVALID_STORED_NODE_ID".into());
    }
    if !current_active_credential {
        blockers.push("ACTIVE_CREDENTIAL_MISSING".into());
    }

    Ok(NodeReuseBindingStatus {
        binding,
        current_active_credential,
        home_group_inbound,
        reusing_group_inbound,
        preview_eligible: blockers.is_empty(),
        blockers,
    })
}

pub async fn get_binding_status(
    db: &dyn Repository,
    reusing_group_id: i64,
    home_group_id: i64,
    node_id: &str,
) -> Result<Option<NodeReuseBindingStatus>, NodeReuseServiceError> {
    validate_binding_identity(reusing_group_id, home_group_id, node_id)?;
    let binding = db
        .find_node_reuse_binding(reusing_group_id, home_group_id, node_id)
        .await?;
    match binding {
        Some(binding) => Ok(Some(status_for_binding(db, binding).await?)),
        None => Ok(None),
    }
}

pub async fn list_bindings_for_node(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<Vec<NodeReuseBindingStatus>, NodeReuseServiceError> {
    let node_id =
        ReuseEligibleNodeId::parse(node_id).map_err(NodeReuseIdentityError::InvalidNodeId)?;
    let group_ids = db
        .list_reusing_group_ids_for_node(home_group_id, node_id.as_str())
        .await?;
    let mut result = Vec::with_capacity(group_ids.len());
    for reusing_group_id in group_ids {
        let Some(binding) = db
            .find_node_reuse_binding(reusing_group_id, home_group_id, node_id.as_str())
            .await?
        else {
            return Err(NodeReuseServiceError::BindingChangedDuringRead);
        };
        result.push(status_for_binding(db, binding).await?);
    }
    Ok(result)
}

pub async fn list_bindings_for_reusing_group(
    db: &dyn Repository,
    reusing_group_id: i64,
) -> Result<Vec<NodeReuseBindingStatus>, NodeReuseServiceError> {
    let identities = reused_concrete_nodes_for_group(db, reusing_group_id).await?;
    let mut result = Vec::with_capacity(identities.len());
    for identity in identities {
        let Some(binding) = db
            .find_node_reuse_binding(reusing_group_id, identity.home_group_id, &identity.node_id)
            .await?
        else {
            return Err(NodeReuseServiceError::BindingChangedDuringRead);
        };
        result.push(status_for_binding(db, binding).await?);
    }
    Ok(result)
}

fn map_config_error(source_group_id: i64, error: NodeConfigBuildError) -> NodeReuseServiceError {
    match error {
        NodeConfigBuildError::Database(error) => NodeReuseServiceError::Database(error),
        NodeConfigBuildError::GroupNotFound => NodeReuseServiceError::InvalidStoredSource {
            group_id: source_group_id,
            reason: "GROUP_MISSING",
        },
        NodeConfigBuildError::NotInboundGroup => NodeReuseServiceError::InvalidStoredSource {
            group_id: source_group_id,
            reason: "GROUP_NOT_INBOUND",
        },
        NodeConfigBuildError::InvalidConfig(reason) => {
            NodeReuseServiceError::PreviewSourceConfigInvalid {
                group_id: source_group_id,
                reason,
            }
        }
    }
}

fn listener_conflict_kind(
    left: &EffectiveConfigPreviewListener,
    right: &EffectiveConfigPreviewListener,
) -> Option<&'static str> {
    if left.port != right.port {
        return None;
    }
    match (left.protocol, right.protocol) {
        (Protocol::Udp, Protocol::Udp) => Some("UDP_PORT_COLLISION"),
        (Protocol::Udp, _) | (_, Protocol::Udp) => None,
        _ => match (left.node_transport, right.node_transport) {
            (NodeTransport::NginxSni, NodeTransport::NginxSni) => {
                if left.send_proxy_protocol != right.send_proxy_protocol {
                    Some("PROXY_PROTOCOL_MISMATCH")
                } else if left
                    .sni
                    .as_deref()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case(right.sni.as_deref().unwrap_or_default())
                {
                    Some("NGINX_SNI_COLLISION")
                } else {
                    None
                }
            }
            (NodeTransport::NginxSni, _) | (_, NodeTransport::NginxSni) => {
                Some("TCP_TRANSPORT_COLLISION")
            }
            _ => Some("TCP_PORT_COLLISION"),
        },
    }
}

fn detect_preview_conflicts(
    _home_group_id: i64,
    listeners: &[EffectiveConfigPreviewListener],
    camouflage_sites: &[EffectiveConfigPreviewCamouflage],
) -> Vec<EffectiveConfigPreviewConflict> {
    let mut conflicts = Vec::new();

    let mut first_rule_source = BTreeMap::<i64, i64>::new();
    for listener in listeners {
        if let Some(first_source) =
            first_rule_source.insert(listener.rule_id, listener.source_group_id)
        {
            if first_source != listener.source_group_id {
                conflicts.push(EffectiveConfigPreviewConflict {
                    kind: "DUPLICATE_RULE_COLLECTION".into(),
                    source_group_id: listener.source_group_id,
                    rule_id: Some(listener.rule_id),
                    other_source_group_id: Some(first_source),
                    other_rule_id: Some(listener.rule_id),
                    message: "one rule was collected from more than one source Group".into(),
                });
            }
        }
    }

    for (index, left) in listeners.iter().enumerate() {
        for right in listeners.iter().skip(index + 1) {
            if left.source_group_id == right.source_group_id && left.rule_id == right.rule_id {
                continue;
            }
            if let Some(kind) = listener_conflict_kind(left, right) {
                conflicts.push(EffectiveConfigPreviewConflict {
                    kind: kind.into(),
                    source_group_id: left.source_group_id,
                    rule_id: Some(left.rule_id),
                    other_source_group_id: Some(right.source_group_id),
                    other_rule_id: Some(right.rule_id),
                    message: "listeners cannot safely coexist on the same concrete Node".into(),
                });
            }
        }
    }

    let mut camouflage_by_sni = BTreeMap::<String, (i64, u16, String)>::new();
    for site in camouflage_sites {
        let key = site.sni.to_ascii_lowercase();
        if let Some((first_group, first_port, first_domain)) = camouflage_by_sni.get(&key) {
            if *first_group != site.source_group_id
                || *first_port != site.tls_listener_port
                || !first_domain.eq_ignore_ascii_case(&site.certificate_domain)
            {
                conflicts.push(EffectiveConfigPreviewConflict {
                    kind: "CAMOUFLAGE_SNI_COLLISION".into(),
                    source_group_id: site.source_group_id,
                    rule_id: None,
                    other_source_group_id: Some(*first_group),
                    other_rule_id: None,
                    message: "camouflage site ownership or TLS settings conflict across sources"
                        .into(),
                });
            }
        } else {
            camouflage_by_sni.insert(
                key,
                (
                    site.source_group_id,
                    site.tls_listener_port,
                    site.certificate_domain.clone(),
                ),
            );
        }
    }

    conflicts.sort_by(|a, b| {
        (
            &a.kind,
            a.source_group_id,
            a.rule_id,
            a.other_source_group_id,
            a.other_rule_id,
        )
            .cmp(&(
                &b.kind,
                b.source_group_id,
                b.rule_id,
                b.other_source_group_id,
                b.other_rule_id,
            ))
    });
    conflicts.dedup_by(|a, b| {
        a.kind == b.kind
            && a.source_group_id == b.source_group_id
            && a.rule_id == b.rule_id
            && a.other_source_group_id == b.other_source_group_id
            && a.other_rule_id == b.other_rule_id
    });
    conflicts
}

async fn collect_effective_config_for_node(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<(EffectiveConfigPreview, NodeConfigResponse), NodeReuseServiceError> {
    let node_id =
        ReuseEligibleNodeId::parse(node_id).map_err(NodeReuseIdentityError::InvalidNodeId)?;

    let home = crate::db::repo::GroupRepository::find_by_id(db, home_group_id, &ResourceScope::All)
        .await?;
    let Some(home) = home else {
        return Err(NodeReuseServiceError::InvalidStoredSource {
            group_id: home_group_id,
            reason: "HOME_GROUP_MISSING",
        });
    };
    if home.group_type != "in" {
        return Err(NodeReuseServiceError::InvalidStoredSource {
            group_id: home_group_id,
            reason: "HOME_GROUP_NOT_INBOUND",
        });
    }
    if db
        .find_current_active_node_credential_for_identity(home_group_id, &node_id)
        .await?
        .is_none()
    {
        return Err(NodeReuseServiceError::AdmissionRejected(
            NodeReuseBindingCreateRejection::ActiveCredentialMissing,
        ));
    }

    let source_group_ids = effective_source_groups(db, home_group_id, node_id.as_str()).await?;
    let mut sources = Vec::with_capacity(source_group_ids.len());
    let mut listeners = Vec::new();
    let mut camouflage_sites = Vec::new();
    let mut merged_listeners = Vec::new();
    let mut merged_camouflage_sites = Vec::new();

    for source_group_id in source_group_ids.iter().copied() {
        let source =
            crate::db::repo::GroupRepository::find_by_id(db, source_group_id, &ResourceScope::All)
                .await?;
        let Some(source) = source else {
            return Err(NodeReuseServiceError::InvalidStoredSource {
                group_id: source_group_id,
                reason: "GROUP_MISSING",
            });
        };
        if source.group_type != "in" {
            return Err(NodeReuseServiceError::InvalidStoredSource {
                group_id: source_group_id,
                reason: "GROUP_NOT_INBOUND",
            });
        }
        if source_group_id != home_group_id
            && db
                .find_node_reuse_binding(source_group_id, home_group_id, node_id.as_str())
                .await?
                .is_none()
        {
            return Err(NodeReuseServiceError::BindingChangedDuringRead);
        }

        let config = crate::service::node_config::build_node_config_for_source_group_on_home_node(
            db,
            source_group_id,
            home_group_id,
            Some(node_id.as_str()),
        )
        .await
        .map_err(|error| map_config_error(source_group_id, error))?;

        let mut rule_ids = BTreeSet::new();
        for listener in config.listeners {
            rule_ids.insert(listener.rule_id);
            merged_listeners.push(listener.clone());
            listeners.push(EffectiveConfigPreviewListener {
                source_group_id,
                rule_id: listener.rule_id,
                port: listener.port,
                protocol: listener.protocol,
                node_transport: listener.node_transport,
                sni: listener.sni,
                camouflage_required: listener.camouflage_required,
                send_proxy_protocol: listener.send_proxy_protocol,
                target_count: listener.targets.len(),
            });
        }
        let camouflage_site_count = config.camouflage_sites.len();
        for site in config.camouflage_sites {
            merged_camouflage_sites.push(site.clone());
            camouflage_sites.push(EffectiveConfigPreviewCamouflage {
                source_group_id,
                sni: site.sni,
                tls_listener_port: site.tls_listener_port,
                certificate_domain: site.certificate.domain,
            });
        }
        sources.push(EffectiveConfigPreviewSource {
            group_id: source_group_id,
            is_home: source_group_id == home_group_id,
            rule_ids: rule_ids.into_iter().collect(),
            listener_count: listeners
                .iter()
                .filter(|listener| listener.source_group_id == source_group_id)
                .count(),
            camouflage_site_count,
        });
    }

    listeners.sort_by(|a, b| {
        (
            a.source_group_id,
            a.rule_id,
            a.port,
            format!("{:?}", a.protocol),
            format!("{:?}", a.node_transport),
        )
            .cmp(&(
                b.source_group_id,
                b.rule_id,
                b.port,
                format!("{:?}", b.protocol),
                format!("{:?}", b.node_transport),
            ))
    });
    camouflage_sites.sort_by(|a, b| {
        (a.source_group_id, &a.sni, a.tls_listener_port).cmp(&(
            b.source_group_id,
            &b.sni,
            b.tls_listener_port,
        ))
    });
    let conflicts = detect_preview_conflicts(home_group_id, &listeners, &camouflage_sites);

    // Re-check the credential and exact Bindings after all source reads. This
    // does not make the candidate a transactionally stable authorization
    // snapshot, but a mutation observed during collection fails closed.
    if db
        .find_current_active_node_credential_for_identity(home_group_id, &node_id)
        .await?
        .is_none()
    {
        return Err(NodeReuseServiceError::AdmissionRejected(
            NodeReuseBindingCreateRejection::ActiveCredentialMissing,
        ));
    }
    for source_group_id in source_group_ids.iter().copied() {
        if source_group_id != home_group_id
            && db
                .find_node_reuse_binding(source_group_id, home_group_id, node_id.as_str())
                .await?
                .is_none()
        {
            return Err(NodeReuseServiceError::BindingChangedDuringRead);
        }
    }

    let preview = EffectiveConfigPreview {
        home_group_id,
        node_id: node_id.as_str().to_string(),
        source_group_ids,
        sources,
        listeners,
        camouflage_sites,
        known_runtime_prerequisites_satisfied: conflicts.is_empty(),
        conflicts,
        runtime_delivery_enabled: false,
    };
    Ok((
        preview,
        NodeConfigResponse {
            listeners: merged_listeners,
            camouflage_sites: merged_camouflage_sites,
        },
    ))
}

pub async fn preview_effective_config_for_node(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<EffectiveConfigPreview, NodeReuseServiceError> {
    build_effective_config_candidate_for_node(db, home_group_id, node_id)
        .await
        .map(|candidate| {
            let EffectiveConfigCandidate { preview, config } = candidate;
            let _ = config;
            preview
        })
}

/// Build the exact-node EffectiveConfig candidate using the same source reads
/// and conflict checks as the S4-A preview.
///
/// The returned config MUST NOT be sent to a live Node solely because this
/// function succeeds. runtime_delivery_enabled remains false and the broader
/// S4-B activation gate is intentionally blocked until traffic-report
/// idempotency and offline-LKG revocation semantics are approved.
pub async fn build_effective_config_candidate_for_node(
    db: &dyn Repository,
    home_group_id: i64,
    node_id: &str,
) -> Result<EffectiveConfigCandidate, NodeReuseServiceError> {
    let (preview, config) = collect_effective_config_for_node(db, home_group_id, node_id).await?;
    Ok(EffectiveConfigCandidate { preview, config })
}

/// Helper used by tests to pin conflict semantics without creating runtime side
/// effects.
#[cfg(test)]
fn preview_conflicts_for_test(
    home_group_id: i64,
    listeners: &[EffectiveConfigPreviewListener],
    camouflage_sites: &[EffectiveConfigPreviewCamouflage],
) -> Vec<EffectiveConfigPreviewConflict> {
    detect_preview_conflicts(home_group_id, listeners, camouflage_sites)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::KvsRepository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn preview_repo() -> (SqliteRepository, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();

        for (id, banned, traffic_used, traffic_limit) in [
            (2_i64, 0_i64, 0_i64, 0_i64),
            (3_i64, 1_i64, 0_i64, 0_i64),
            (4_i64, 0_i64, 10_i64, 10_i64),
        ] {
            sqlx::query(
                "INSERT INTO users
                 (id, username, password, admin, banned, traffic_used, traffic_limit)
                 VALUES (?, ?, 'hash', 0, ?, ?, ?)",
            )
            .bind(id)
            .bind(format!("u{id}"))
            .bind(banned)
            .bind(traffic_used)
            .bind(traffic_limit)
            .execute(&pool)
            .await
            .unwrap();
        }
        for gid in [10_i64, 20, 30] {
            sqlx::query(
                "INSERT INTO device_groups (id, name, group_type, token, uid)
                 VALUES (?, ?, 'in', ?, 2)",
            )
            .bind(gid)
            .bind(format!("g{gid}"))
            .bind(format!("tok-{gid}"))
            .execute(&pool)
            .await
            .unwrap();
        }

        for (id, uid, group_id, port, paused) in [
            (100_i64, 2_i64, 10_i64, 10000_i64, 0_i64),
            (200, 2, 20, 20000, 0),
            (201, 2, 20, 20001, 1),
            (202, 3, 20, 20002, 0),
            (203, 4, 20, 20003, 0),
            (300, 2, 30, 30000, 0),
        ] {
            sqlx::query(
                "INSERT INTO forward_rules
                 (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused)
                 VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80, ?)",
            )
            .bind(id)
            .bind(format!("r{id}"))
            .bind(uid)
            .bind(port)
            .bind(group_id)
            .bind(paused)
            .execute(&pool)
            .await
            .unwrap();
        }

        for (credential_id, node_id) in [("preview-e", "NODE_E"), ("preview-f", "NODE_F")] {
            sqlx::query(
                "INSERT INTO node_credentials
                 (credential_id, home_group_id, node_id, generation,
                  verifier_format, verifier_version, verifier_data, activated_at)
                 VALUES (?, 10, ?, 1, 'rp-node-sha256', 1, ?, datetime('now'))",
            )
            .bind(credential_id)
            .bind(node_id)
            .bind(vec![7_u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        }

        (SqliteRepository::new(pool.clone()), pool)
    }

    #[tokio::test]
    async fn preview_is_exact_node_read_only_filtered_and_home_runtime_stays_home_only() {
        let (db, _pool) = preview_repo().await;

        let runtime_before =
            crate::service::node_config::build_node_config_for_node(&db, 10, Some("NODE_E"))
                .await
                .unwrap();
        assert_eq!(
            runtime_before
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100]
        );
        assert!(db
            .get("node_config_revision:10:NODE_E")
            .await
            .unwrap()
            .is_none());

        assert!(matches!(
            create_binding(&db, 20, 10, "NODE_E").await.unwrap().outcome,
            BindingMutationOutcome::Created
        ));
        assert!(matches!(
            create_binding(&db, 30, 10, "NODE_E").await.unwrap().outcome,
            BindingMutationOutcome::Created
        ));

        let preview = preview_effective_config_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert_eq!(preview.source_group_ids, vec![10, 20, 30]);
        assert_eq!(
            preview
                .listeners
                .iter()
                .map(|listener| (listener.source_group_id, listener.rule_id))
                .collect::<Vec<_>>(),
            vec![(10, 100), (20, 200), (30, 300)]
        );
        assert!(!preview.runtime_delivery_enabled);
        assert!(preview.conflicts.is_empty());

        // Paused, banned-user and exhausted-quota rules from Group 20 are absent.
        assert_eq!(preview.sources[1].rule_ids, vec![200]);

        let candidate = build_effective_config_candidate_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert_eq!(candidate.preview.source_group_ids, vec![10, 20, 30]);
        assert!(candidate.preview.known_runtime_prerequisites_satisfied);
        assert!(!candidate.preview.runtime_delivery_enabled);
        assert_eq!(
            candidate
                .config
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100, 200, 300]
        );

        let sibling = preview_effective_config_for_node(&db, 10, "NODE_F")
            .await
            .unwrap();
        assert_eq!(sibling.source_group_ids, vec![10]);
        assert_eq!(sibling.sources[0].rule_ids, vec![100]);

        // The live builder remains Home-only despite persisted bindings.
        let runtime_after =
            crate::service::node_config::build_node_config_for_node(&db, 10, Some("NODE_E"))
                .await
                .unwrap();
        assert_eq!(
            serde_json::to_value(&runtime_before.listeners).unwrap(),
            serde_json::to_value(&runtime_after.listeners).unwrap()
        );

        // Repeated preview never allocates a live revision/fingerprint.
        let replay = preview_effective_config_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert_eq!(replay.source_group_ids, preview.source_group_ids);
        assert!(db
            .get("node_config_revision:10:NODE_E")
            .await
            .unwrap()
            .is_none());

        delete_binding(&db, 20, 10, "NODE_E").await.unwrap();
        let after_delete = preview_effective_config_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert_eq!(after_delete.source_group_ids, vec![10, 30]);
        assert_eq!(
            after_delete
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100, 300]
        );
    }

    #[tokio::test]
    async fn preview_blocks_port_conflicts_and_revoked_identity() {
        let (db, pool) = preview_repo().await;
        create_binding(&db, 20, 10, "NODE_E").await.unwrap();
        create_binding(&db, 30, 10, "NODE_E").await.unwrap();
        sqlx::query("UPDATE forward_rules SET listen_port = 20000 WHERE id = 300")
            .execute(&pool)
            .await
            .unwrap();

        let preview = preview_effective_config_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert!(!preview.known_runtime_prerequisites_satisfied);
        assert!(preview
            .conflicts
            .iter()
            .any(|conflict| conflict.kind == "TCP_PORT_COLLISION"));
        let candidate = build_effective_config_candidate_for_node(&db, 10, "NODE_E")
            .await
            .unwrap();
        assert!(!candidate.preview.known_runtime_prerequisites_satisfied);
        assert_eq!(
            candidate
                .config
                .listeners
                .iter()
                .map(|listener| listener.rule_id)
                .collect::<Vec<_>>(),
            vec![100, 200, 300],
            "candidate assembly may be inspected, but a conflict keeps it non-deliverable"
        );

        sqlx::query(
            "UPDATE node_credentials SET revoked_at = datetime('now')
             WHERE credential_id = 'preview-e'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            preview_effective_config_for_node(&db, 10, "NODE_E").await,
            Err(NodeReuseServiceError::AdmissionRejected(
                NodeReuseBindingCreateRejection::ActiveCredentialMissing
            ))
        ));
    }

    #[test]
    fn preview_conflicts_fail_closed_on_cross_group_certificate_scope() {
        let listener = EffectiveConfigPreviewListener {
            source_group_id: 20,
            rule_id: 200,
            port: 443,
            protocol: Protocol::Tcp,
            node_transport: NodeTransport::NginxSni,
            sni: Some("reuse.example.com".into()),
            camouflage_required: true,
            send_proxy_protocol: true,
            target_count: 1,
        };
        let site = EffectiveConfigPreviewCamouflage {
            source_group_id: 20,
            sni: "reuse.example.com".into(),
            tls_listener_port: 443,
            certificate_domain: "*.example.com".into(),
        };
        let conflicts = preview_conflicts_for_test(10, &[listener], &[site]);
        assert!(!conflicts
            .iter()
            .any(|conflict| conflict.kind == "CROSS_GROUP_CERTIFICATE_SCOPE_UNRESOLVED"));
    }
}
