//! Shared node-config builder for the HTTP poll path (`get_config`) and the
//! WebSocket push path (`build_config_snapshot`).
//!
//! **Why this exists (v0.3.6 fix):** v0.3.5 had TWO copies of "turn a device
//! group into a NodeConfigResponse". They drifted — the HTTP path JOINed
//! `users` (to drop banned / over-quota rules) but the WS path did NOT, so a
//! freshly-(re)connected node could be handed a banned user's rules until the
//! next HTTP poll corrected it. There was also duplicated target resolution +
//! `build_listeners_for_rule` wiring in both files.
//!
//! This module is the single source of truth. Both callers go through
//! [`build_node_config`], so the filter, target resolution, protocol expansion,
//! transport derivation and ws_path passthrough are identical by construction.
//!
//! Error policy: only a real inbound group with no active rules returns an
//! empty config. Authentication, group state, and build failures are explicit
//! errors so they can never tear down a node by masquerading as an empty plan.

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, ProfileScope, ResourceScope, TunnelProfileRepository};
use crate::db::Repository;
use relay_shared::models::{DeviceGroup, ForwardRule};
use relay_shared::protocol::{
    validate_proxy_protocol_invariants, AcmeChallengeMethod, CamouflageCertificatePolicy,
    CamouflageLocalBackend, CamouflageSiteDesired, NodeConfigResponse, NodeConfigSnapshot,
};
use relay_shared::reconciliation::certificate_domain_covers_sni;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::Mutex;

const REVISION_PREFIX: &str = "node_config_revision:";
static CONFIG_BUILD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedConfigRevision {
    revision: u64,
    fingerprint: String,
}

#[derive(Debug)]
pub enum NodeConfigBuildError {
    Database(DbError),
    GroupNotFound,
    NotInboundGroup,
    InvalidConfig(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupCertificateScope {
    pub domain: String,
    pub snis: Vec<String>,
}

struct CertificateDomainResolution {
    domain: String,
    issuance_authorized: bool,
}

impl std::fmt::Display for NodeConfigBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database error: {}", e),
            Self::GroupNotFound => write!(f, "device group no longer exists"),
            Self::NotInboundGroup => write!(f, "device group is not inbound"),
            Self::InvalidConfig(message) => write!(f, "invalid node config: {message}"),
        }
    }
}

impl std::error::Error for NodeConfigBuildError {}

impl From<DbError> for NodeConfigBuildError {
    fn from(value: DbError) -> Self {
        Self::Database(value)
    }
}

/// Build the full [`NodeConfigResponse`] for a device group.
///
/// This is the ONE function both `get_config` (HTTP) and `build_config_snapshot`
/// (WS) call. It performs, in order:
///
/// 1. Group lookup + "only `in` groups receive listeners" gate.
/// 2. Rule query with the unified filter:
///    - `device_group_in` matches the group
///    - `paused = 0`
///    - owning user `banned = 0`
///    - quota: `traffic_limit = 0` (unlimited) OR `traffic_used < traffic_limit`
/// 3. Per-rule target resolution (direct addr vs outbound group connect_host).
/// 4. [`relay_shared::protocol::build_listeners_for_rule`] for protocol
///    expansion + transport derivation + ws_path passthrough.
///
/// Returns `Ok(empty)` only for an existing inbound group with no matching
/// rules. Any other state is an explicit error.
#[cfg(test)]
pub async fn build_node_config(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigResponse, NodeConfigBuildError> {
    build_node_config_for_node(db, group_id, None).await
}

/// Build a config for one concrete Relay.  Inbound camouflage certificate
/// ownership is node-local, so a multi-Relay group must never inherit another
/// node's `connect_host` as its expected public IP.
pub async fn build_node_config_for_node(
    db: &dyn Repository,
    group_id: i64,
    node_id: Option<&str>,
) -> Result<NodeConfigResponse, NodeConfigBuildError> {
    // 1. Group + "in" gate. Non-`in` groups (out / monitor / chained_outbound)
    //    never receive listeners — they are egress/observation only.
    // find_by_id exists on both UserRepository and GroupRepository; we want the
    // group one, so qualify the call.
    let group = match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(g) if g.group_type == "in" => g,
        Some(_) => return Err(NodeConfigBuildError::NotInboundGroup),
        None => return Err(NodeConfigBuildError::GroupNotFound),
    };

    // 2. Filtered rule query. The JOIN on users is the fix for the v0.3.5 WS
    //    drift: without it a banned / over-quota user's rules would still be
    //    pushed to a reconnecting node. Both paths now share this exact query.
    //
    //    Quota note (unchanged from v0.3.0, documented): there is a leak window
    //    of up to one poll cycle (default 10s) because quota is re-checked only
    //    when the node fetches config, not per-packet. Offline nodes serve an
    //    unfiltered cached config ("forward over bill" trade-off). Do not change
    //    without a product decision.
    let rules: Vec<ForwardRule> = db.list_active_for_config(group.id).await?;
    // 3 + 4. Resolve targets and build listener configs. Target resolution needs
    //    a DB lookup (outbound group's connect_host), so it stays async and lives
    //    here; the pure ListenerConfig assembly (transport/ws_path/protocol) is
    //    delegated to the shared `build_listeners_for_rule` so that part can never
    //    drift between paths.
    let mut listeners = Vec::new();
    let mut camouflage_by_sni = BTreeMap::<String, CamouflageSiteDesired>::new();
    for rule in &rules {
        // v0.4.7: if the rule is bound to a tunnel profile, the profile is the
        // source of transport config (node_transport + ws_path). We resolve it
        // here and override the rule's stored columns for this build only — the
        // DB row is NOT rewritten. A NULL/missing profile falls back to the
        // rule's own public_transport/ws_path (legacy behavior, zero break).
        //
        // If a bound profile no longer exists (deleted out from under the rule,
        // or a stale FK), we skip the rule's listeners rather than emit a
        // half-resolved config. The admin sees no listener for that rule.
        let Some(effective_rule) = effective_rule_for_config(db, rule).await? else {
            continue;
        };
        let targets = resolve_targets(db, rule).await?;
        listeners.extend(relay_shared::protocol::build_listeners_for_rule(
            &effective_rule,
            targets,
        ));
        let camouflage_sni = effective_rule
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|sni| !sni.is_empty())
            .map(str::to_ascii_lowercase);
        if effective_rule.camouflage_enabled && effective_rule.node_transport == "nginx_sni" {
            if let Some(sni) = camouflage_sni {
                let certificate_domain =
                    certificate_domain_resolution_for_rule(db, effective_rule.id, &sni)
                        .await?
                        .domain;
                let expected_public_ip =
                    expected_camouflage_public_ipv4(db, &group, node_id).await?;
                camouflage_by_sni
                    .entry(sni.clone())
                    .or_insert_with(|| CamouflageSiteDesired {
                        site_id: relay_shared::reconciliation::stable_camouflage_site_id(&sni),
                        sni: sni.clone(),
                        tls_listener_port: 8443,
                        local_backend: CamouflageLocalBackend::OpenList,
                        certificate: CamouflageCertificatePolicy {
                            domain: certificate_domain,
                            expected_public_ip,
                            renew_before_days: 30,
                            // Reality Panel 的证书权威路径固定使用 Panel DNS-01。
                            // DNSMgr 未就绪时由依赖状态阻塞签发，不降级到 :80 HTTP-01。
                            challenge_method: AcmeChallengeMethod::Dns01,
                        },
                        enabled: true,
                    });
            }
        }
    }

    validate_proxy_protocol_invariants(&listeners).map_err(NodeConfigBuildError::InvalidConfig)?;
    for site in camouflage_by_sni.values() {
        if !certificate_domain_covers_sni(&site.certificate.domain, &site.sni) {
            return Err(NodeConfigBuildError::InvalidConfig(format!(
                "certificate domain {} does not cover camouflage SNI {}",
                site.certificate.domain, site.sni
            )));
        }
    }

    Ok(NodeConfigResponse {
        listeners,
        camouflage_sites: camouflage_by_sni.into_values().collect(),
    })
}

/// 返回一个 inbound group 当前实际需要的证书 scope。该函数与 Node config
/// 共用 active-rule、profile transport 和 DNS ownership 解析，避免 Panel
/// certificate worker、download API 与 Node desired 产生三套不同语义。
pub async fn certificate_scopes_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<Vec<GroupCertificateScope>, NodeConfigBuildError> {
    let (scopes, _) = certificate_scope_maps_for_group(db, group_id).await?;
    Ok(group_certificate_scopes(scopes))
}

pub async fn issuance_authorized_certificate_scopes_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<Vec<GroupCertificateScope>, NodeConfigBuildError> {
    let (scopes, authorized_domains) = certificate_scope_maps_for_group(db, group_id).await?;
    Ok(group_certificate_scopes(
        scopes
            .into_iter()
            .filter(|(domain, _)| authorized_domains.contains(domain))
            .collect(),
    ))
}

async fn certificate_scope_maps_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<(BTreeMap<String, BTreeSet<String>>, BTreeSet<String>), NodeConfigBuildError> {
    let group = GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?;
    match group {
        Some(group) if group.group_type == "in" => {}
        Some(_) => return Err(NodeConfigBuildError::NotInboundGroup),
        None => return Err(NodeConfigBuildError::GroupNotFound),
    }

    let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
    let mut authorized_domains = BTreeSet::new();
    for rule in db.list_active_for_config(group_id).await? {
        let Some(rule) = effective_rule_for_config(db, &rule).await? else {
            continue;
        };
        if !rule.camouflage_enabled || rule.node_transport != "nginx_sni" {
            continue;
        }
        let Some(sni) = rule
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
        else {
            continue;
        };
        let resolution = certificate_domain_resolution_for_rule(db, rule.id, &sni).await?;
        if !certificate_domain_covers_sni(&resolution.domain, &sni) {
            return Err(NodeConfigBuildError::InvalidConfig(format!(
                "certificate domain {} does not cover camouflage SNI {sni}",
                resolution.domain
            )));
        }
        if resolution.issuance_authorized {
            authorized_domains.insert(resolution.domain.clone());
        }
        scopes.entry(resolution.domain).or_default().insert(sni);
    }

    Ok((scopes, authorized_domains))
}

fn group_certificate_scopes(
    scopes: BTreeMap<String, BTreeSet<String>>,
) -> Vec<GroupCertificateScope> {
    scopes
        .into_iter()
        .map(|(domain, snis)| GroupCertificateScope {
            domain,
            snis: snis.into_iter().collect(),
        })
        .collect()
}

async fn effective_rule_for_config(
    db: &dyn Repository,
    rule: &ForwardRule,
) -> Result<Option<ForwardRule>, DbError> {
    let mut effective_rule = rule.clone();
    let Some(profile_id) = rule.tunnel_profile_id else {
        return Ok(Some(effective_rule));
    };
    let Some(profile) =
        TunnelProfileRepository::find_profile_by_id(db, profile_id, &ProfileScope::All).await?
    else {
        tracing::warn!(
            "rule {} bound to missing tunnel_profile_id {}; skipping (rebind or pause the rule)",
            rule.id,
            profile_id
        );
        return Ok(None);
    };
    effective_rule.node_transport = match profile.transport.as_str() {
        "direct" => "raw",
        "ws" => "ws",
        "tls_simple" => "tls_simple",
        other => other,
    }
    .to_string();
    effective_rule.ws_path = (profile.transport == "ws").then_some(profile.ws_path);
    Ok(Some(effective_rule))
}

/// Build the Panel-authoritative snapshot shared by HTTP and WS delivery.
/// Revision state is stored in KVS so process restarts cannot reuse an older
/// revision or race two transports into different ordering metadata.
#[cfg(test)]
pub async fn build_node_config_snapshot(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigSnapshot, NodeConfigBuildError> {
    build_node_config_snapshot_for_node(db, group_id, None).await
}

#[cfg(test)]
pub async fn build_node_config_snapshot_for_node(
    db: &dyn Repository,
    group_id: i64,
    node_id: Option<&str>,
) -> Result<NodeConfigSnapshot, NodeConfigBuildError> {
    build_node_config_snapshot_for_node_inner(db, None, group_id, node_id).await
}

pub async fn build_node_config_snapshot_for_node_with_certificate_inventory(
    db: &dyn Repository,
    certificate_state_dir: &Path,
    group_id: i64,
    node_id: Option<&str>,
) -> Result<NodeConfigSnapshot, NodeConfigBuildError> {
    build_node_config_snapshot_for_node_inner(db, Some(certificate_state_dir), group_id, node_id)
        .await
}

async fn build_node_config_snapshot_for_node_inner(
    db: &dyn Repository,
    certificate_state_dir: Option<&Path>,
    group_id: i64,
    node_id: Option<&str>,
) -> Result<NodeConfigSnapshot, NodeConfigBuildError> {
    let lock = CONFIG_BUILD_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;
    let mut config = build_node_config_for_node(db, group_id, node_id).await?;
    if let Some(state_dir) = certificate_state_dir {
        let mut requested = BTreeMap::<String, BTreeSet<String>>::new();
        for site in &config.camouflage_sites {
            requested
                .entry(site.certificate.domain.clone())
                .or_default()
                .insert(site.sni.clone());
        }
        let scopes = requested
            .into_iter()
            .map(|(domain, snis)| GroupCertificateScope {
                domain,
                snis: snis.into_iter().collect(),
            })
            .collect();
        let resolved = crate::service::panel_certificate::resolve_managed_certificate_scopes(
            state_dir, group_id, scopes,
        )
        .await
        .map_err(NodeConfigBuildError::InvalidConfig)?;
        let domains_by_sni = resolved
            .into_iter()
            .flat_map(|scope| {
                scope
                    .snis
                    .into_iter()
                    .map(move |sni| (sni, scope.domain.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        for site in &mut config.camouflage_sites {
            if let Some(domain) = domains_by_sni.get(&site.sni) {
                site.certificate.domain = domain.clone();
            }
        }
    }
    let fingerprint = relay_shared::reconciliation::config_fingerprint(&config)
        .as_str()
        .to_string();
    let key = match node_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(node_id) => format!("{REVISION_PREFIX}{group_id}:{node_id}"),
        None => format!("{REVISION_PREFIX}{group_id}"),
    };
    let previous = db
        .get(&key)
        .await?
        .map(|raw| serde_json::from_str::<PersistedConfigRevision>(&raw))
        .transpose()
        .map_err(|error| {
            NodeConfigBuildError::InvalidConfig(format!("invalid revision state: {error}"))
        })?;
    let revision = match previous {
        Some(previous) if previous.fingerprint == fingerprint && previous.revision > 0 => {
            previous.revision
        }
        Some(previous) if previous.revision > 0 => previous.revision.saturating_add(1),
        Some(_) | None => 1,
    };
    let state = serde_json::to_string(&PersistedConfigRevision {
        revision,
        fingerprint: fingerprint.clone(),
    })
    .map_err(|error| NodeConfigBuildError::InvalidConfig(error.to_string()))?;
    db.set(&key, &state).await?;
    Ok(NodeConfigSnapshot {
        config_revision: revision,
        config_fingerprint: fingerprint,
        config,
    })
}

async fn expected_camouflage_public_ipv4(
    db: &dyn Repository,
    group: &DeviceGroup,
    node_id: Option<&str>,
) -> Result<String, NodeConfigBuildError> {
    if let Some(node_id) = node_id.map(str::trim).filter(|id| !id.is_empty()) {
        let key = format!("node_status:{}:{}", group.id, node_id);
        let raw = db.get(&key).await?.ok_or_else(|| {
            NodeConfigBuildError::InvalidConfig(format!("node status unavailable for {node_id}"))
        })?;
        let status: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
            NodeConfigBuildError::InvalidConfig(format!("invalid node status: {error}"))
        })?;
        let value = status
            .get("public_ipv4")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                NodeConfigBuildError::InvalidConfig(format!(
                    "node {node_id} has no public IPv4 telemetry"
                ))
            })?;
        let address = value.parse::<std::net::Ipv4Addr>().map_err(|_| {
            NodeConfigBuildError::InvalidConfig(format!("node {node_id} has invalid public IPv4"))
        })?;
        if address.is_loopback() || address.is_unspecified() {
            return Err(NodeConfigBuildError::InvalidConfig(format!(
                "node {node_id} has unusable public IPv4"
            )));
        }
        return Ok(address.to_string());
    }

    let legacy = group.connect_host.trim();
    if legacy.is_empty() {
        return Err(NodeConfigBuildError::InvalidConfig(
            "node identity is required for inbound camouflage config".into(),
        ));
    }
    Ok(legacy.to_string())
}

/// 根据已经验证过的 Panel DNS ownership 计算证书作用域。
/// 没有 ownership binding 时保持单域名证书；绝不靠“最后两段域名”猜 zone。
async fn certificate_domain_resolution_for_rule(
    db: &dyn Repository,
    rule_id: i64,
    sni: &str,
) -> Result<CertificateDomainResolution, DbError> {
    let exact = sni.trim_end_matches('.').to_ascii_lowercase();
    let pending = || CertificateDomainResolution {
        domain: exact.clone(),
        issuance_authorized: false,
    };
    let Some(sync) = db
        .find_dns_record_sync(rule_id, crate::service::dnsmgr::DEFAULT_LINE_KEY)
        .await?
    else {
        return Ok(pending());
    };
    if !sync.fqdn.trim_end_matches('.').eq_ignore_ascii_case(&exact)
        || sync.record_type != "A"
        || sync.line_key != crate::service::dnsmgr::DEFAULT_LINE_KEY
        || sync.desired_action != "UPSERT"
        || sync.ownership != "PANEL"
        || !matches!(
            sync.state.as_str(),
            "MUTATION_VERIFIED" | "PROPAGATING" | "PROPAGATED"
        )
        || sync.mutation_verified_at.is_none()
        || sync.expected_value.is_none()
    {
        return Ok(pending());
    }
    let Some(binding) = db
        .find_dns_record_binding_for_rule(rule_id, &sync.fqdn, &sync.record_type, &sync.line_key)
        .await?
    else {
        return Ok(pending());
    };
    let binding_authorized = binding.rule_id == Some(rule_id)
        && binding
            .fqdn
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&exact)
        && binding.record_type == sync.record_type
        && binding.line_key == sync.line_key
        && binding.desired_value == sync.expected_value.as_deref().unwrap_or_default()
        && binding.state == "BOUND"
        && binding.last_observed_at.is_some()
        && binding.last_error_category.is_none()
        && binding.zone_id > 0
        && !binding.zone_name.trim().is_empty()
        && !binding.record_id.trim().is_empty();
    if !binding_authorized {
        return Ok(pending());
    }
    Ok(CertificateDomainResolution {
        domain: wildcard_domain_for_managed_sni(&exact, &binding.zone_name).unwrap_or(exact),
        issuance_authorized: true,
    })
}

fn wildcard_domain_for_managed_sni(sni: &str, zone_name: &str) -> Option<String> {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone_name.trim_end_matches('.').to_ascii_lowercase();
    if sni == zone || zone.is_empty() {
        return None;
    }
    let zone_suffix = format!(".{zone}");
    if !sni.ends_with(&zone_suffix) {
        return None;
    }
    let (_, parent) = sni.split_once('.')?;
    if parent == zone || parent.ends_with(&zone_suffix) {
        Some(format!("*.{parent}"))
    } else {
        None
    }
}

/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own
///   `target_addr:target_port`.
/// - otherwise → the outbound group's `connect_host:target_port`, falling back
///   to the rule's own `target_addr` when the outbound group is missing or has
///   no `connect_host` configured.
///
/// `targets` is the single place target resolution happens — both config paths
/// used to duplicate this `match` block.
async fn resolve_targets(db: &dyn Repository, rule: &ForwardRule) -> Result<Vec<String>, DbError> {
    let mut targets = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await?;
    if targets.is_empty() {
        targets.push(relay_shared::models::ForwardRuleTarget {
            id: 0,
            rule_id: rule.id,
            host: rule.target_addr.clone(),
            port: rule.target_port,
            position: 1,
            enabled: true,
            created_at: String::new(),
        });
    }

    match (rule.forward_mode.as_str(), rule.device_group_out) {
        ("direct", _) | (_, None) => Ok(targets
            .into_iter()
            .map(|t| format_target_endpoint(&t.host, t.port))
            .collect()),
        (_, Some(out_id)) => {
            // Qualify: find_by_id is on both UserRepository and GroupRepository.
            let og = GroupRepository::find_by_id(db, out_id, &ResourceScope::All).await?;
            Ok(match og {
                Some(DeviceGroup { connect_host, .. }) if !connect_host.is_empty() => targets
                    .into_iter()
                    .map(|t| format_target_endpoint(&connect_host, t.port))
                    .collect(),
                _ => targets
                    .into_iter()
                    .map(|t| format_target_endpoint(&t.host, t.port))
                    .collect(),
            })
        }
    }
}

fn format_target_endpoint(host: &str, port: i32) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::KvsRepository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        pool
    }

    /// Wrap the pool in a SqliteRepository so build_node_config can be invoked
    /// the same way the real callers (get_config, build_config_snapshot) do.
    fn repo(pool: &SqlitePool) -> SqliteRepository {
        SqliteRepository::new(pool.clone())
    }

    async fn add_user(pool: &SqlitePool, id: i64) {
        let hash = bcrypt::hash(format!("pw-{id}"), 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(format!("u{id}"))
            .bind(&hash)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_group(pool: &SqlitePool, id: i64, gtype: &str, uid: i64) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(format!("g{id}"))
        .bind(gtype)
        .bind(format!("tok-{id}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_rule(pool: &SqlitePool, id: i64, uid: i64, in_group: i64, port: i64) {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80)",
        )
        .bind(id)
        .bind(format!("r{id}"))
        .bind(uid)
        .bind(port)
        .bind(in_group)
        .execute(pool)
        .await
        .unwrap();
    }

    #[test]
    fn wildcard_scope_uses_direct_parent_inside_managed_zone() {
        assert_eq!(
            wildcard_domain_for_managed_sni("o1.13886.xyz", "13886.xyz").as_deref(),
            Some("*.13886.xyz")
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("a.b.example.com", "example.com").as_deref(),
            Some("*.b.example.com")
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("example.com", "example.com"),
            None
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("evil-example.com", "example.com"),
            None
        );
    }

    #[test]
    fn one_wildcard_scope_deduplicates_multiple_snis() {
        let scopes = group_certificate_scopes(BTreeMap::from([(
            "*.13886.xyz".to_string(),
            BTreeSet::from([
                "op1.13886.xyz".to_string(),
                "op2.13886.xyz".to_string(),
                "op3.13886.xyz".to_string(),
            ]),
        )]));
        assert_eq!(
            scopes,
            vec![GroupCertificateScope {
                domain: "*.13886.xyz".into(),
                snis: vec![
                    "op1.13886.xyz".into(),
                    "op2.13886.xyz".into(),
                    "op3.13886.xyz".into(),
                ],
            }]
        );
    }

    #[tokio::test]
    async fn exact_fallback_is_pending_until_verified_binding_authorizes_issuance() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='b.example.com', camouflage_enabled=1 WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        let repository = repo(&pool);

        assert_eq!(
            certificate_scopes_for_group(&repository, 10).await.unwrap(),
            vec![GroupCertificateScope {
                domain: "b.example.com".into(),
                snis: vec!["b.example.com".into()],
            }]
        );
        assert!(
            issuance_authorized_certificate_scopes_for_group(&repository, 10)
                .await
                .unwrap()
                .is_empty()
        );

        sqlx::query(
            "INSERT INTO dns_record_syncs \
             (rule_id, fqdn, record_type, expected_value, line, line_key, desired_action, \
              state, ownership, created_at, updated_at) \
             VALUES (100, 'b.example.com', 'A', '192.0.2.10', 'default', 'default', \
                     'UPSERT', 'PENDING', 'UNKNOWN', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO dns_record_bindings \
             (rule_id, fqdn, zone_id, zone_name, host, record_type, line, line_key, \
              record_id, desired_value, state, last_observed_at, created_at, updated_at) \
             VALUES (100, 'b.example.com', 7, 'example.com', 'b', 'A', 'default', \
                     'default', 'record-100', '192.0.2.10', 'BOUND', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00', '2026-09-04 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            issuance_authorized_certificate_scopes_for_group(&repository, 10)
                .await
                .unwrap()
                .is_empty(),
            "a binding alone is not enough before mutation read-back state is committed"
        );

        sqlx::query(
            "UPDATE dns_record_syncs SET state='MUTATION_VERIFIED', ownership='PANEL', \
             mutation_verified_at='2026-09-04 00:00:01' WHERE rule_id=100 AND line_key='default'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            issuance_authorized_certificate_scopes_for_group(&repository, 10)
                .await
                .unwrap(),
            vec![GroupCertificateScope {
                domain: "*.example.com".into(),
                snis: vec!["b.example.com".into()],
            }]
        );
    }

    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]
    async fn active_rule_produces_listener() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].port, 20000);
    }

    #[tokio::test]
    async fn dns_reconciliation_state_never_changes_node_config_authority() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        let before = build_node_config(&repo(&pool), 10).await.unwrap();

        sqlx::query(
            "INSERT INTO dns_record_syncs \
             (rule_id, fqdn, record_type, expected_value, line, line_key, state, ownership, \
              last_error_category, next_attempt_at, created_at, updated_at) \
             VALUES (100, 'op1.example.com', 'A', '192.0.2.10', 'default', 'default', \
                     'FAILED', 'UNKNOWN', 'DNSMGR_TIMEOUT', NULL, \
                     '2026-08-26 00:00:00', '2026-08-26 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let after = build_node_config(&repo(&pool), 10).await.unwrap();

        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    }

    /// A banned user's rule must NOT appear — this is the regression the WS path
    /// was missing (v0.3.5 drift). Both paths now share this query, so the test
    /// pins the filter itself.
    #[tokio::test]
    async fn banned_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET banned = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "banned user rule must be filtered"
        );
    }

    /// An over-quota user's rule must be filtered.
    #[tokio::test]
    async fn over_quota_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 100, traffic_used = 100 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "over-quota rule must be filtered");
    }

    /// A paused rule must be filtered.
    #[tokio::test]
    async fn paused_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET paused = 1 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "paused rule must be filtered");
    }

    /// A non-inbound group is not an authoritative empty configuration. The
    /// caller must reject it instead of telling a node to tear down listeners.
    #[tokio::test]
    async fn non_in_group_is_explicit_error() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "out", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        assert!(matches!(
            build_node_config(&repo(&pool), 10).await,
            Err(NodeConfigBuildError::NotInboundGroup)
        ));
    }

    /// traffic_limit = 0 means unlimited — never filtered by quota even if
    /// traffic_used is huge.
    #[tokio::test]
    async fn unlimited_quota_never_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 0, traffic_used = 999999999 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
    }

    /// v0.4.7: a rule bound to a WS tunnel profile must take its node_transport
    /// and ws_path FROM the profile (the rule's own columns are ignored).
    #[tokio::test]
    async fn profile_overrides_transport_and_ws_path() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // The test pool only runs SCHEMA_SQL (no builtin seeds), so insert a ws
        // profile explicitly rather than rely on the Migration 6 seed.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (50, 'ws-relay', 'ws', 'none', '/relay', '', '', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 50 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Ws,
            "profile transport must override the rule's stored raw transport"
        );
        assert_eq!(
            cfg.listeners[0].ws_path.as_deref(),
            Some("/relay"),
            "ws_path must come from the profile"
        );
    }

    /// v0.4.7: a rule with NO profile (tunnel_profile_id NULL) keeps using its
    /// own stored public_transport/ws_path — legacy behavior, zero break.
    #[tokio::test]
    async fn null_profile_falls_back_to_rule_transport() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // A raw rule, no profile binding.
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Raw
        );
        assert!(cfg.listeners[0].ws_path.is_none());
    }

    /// v0.4.7: a rule bound to a DELETED profile is skipped (no listener), not
    /// silently downgraded to raw.
    #[tokio::test]
    async fn missing_profile_skips_rule() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        // Point at a profile id that doesn't exist. Disable FK enforcement for
        // this insert so SQLite accepts the dangling reference (production code
        // prevents this via Migration 22's NULL-out + delete usage count, but
        // we want to pin the builder's defensive skip behavior).
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 99999 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "a rule bound to a missing profile must be skipped, not downgraded"
        );
    }

    #[tokio::test]
    async fn camouflage_rule_builds_typed_site_and_dependent_listener_without_secrets() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        add_rule(&pool, 101, 2, 10, 444).await;
        sqlx::query("UPDATE device_groups SET connect_host = '203.0.113.10' WHERE id = 10")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='op1.example.com', camouflage_enabled=1, \
             target_addr='198.51.100.20', target_port=55443 WHERE id IN (100, 101)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 2);
        assert!(cfg.listeners[0].camouflage_required);
        assert_eq!(cfg.listeners[0].targets, vec!["198.51.100.20:55443"]);
        assert_eq!(cfg.camouflage_sites.len(), 1);
        let site = &cfg.camouflage_sites[0];
        assert_eq!(
            site.site_id,
            relay_shared::reconciliation::stable_camouflage_site_id("op1.example.com")
        );
        assert_eq!(site.sni, "op1.example.com");
        assert_eq!(site.tls_listener_port, 8443);
        assert_eq!(site.certificate.expected_public_ip, "203.0.113.10");
        assert_eq!(site.certificate.renew_before_days, 30);
        assert_eq!(
            site.certificate.challenge_method,
            AcmeChallengeMethod::Dns01
        );

        let json = serde_json::to_string(&cfg).unwrap();
        for forbidden in [
            "private_key",
            "privkey",
            "certificate_pem",
            "uuid",
            "short_id",
            "flow",
            "xray",
            "NODE_TOKEN",
        ] {
            assert!(!json.contains(forbidden), "wire config leaked {forbidden}");
        }

        sqlx::query(
            "UPDATE forward_rules SET target_addr='198.51.100.21', target_port=55444 WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        let backend_update = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(
            backend_update.camouflage_sites, cfg.camouflage_sites,
            "same-SNI backend changes must not recreate certificate desired state"
        );

        let repository = repo(&pool);
        let dns01 = build_node_config(&repository, 10).await.unwrap();
        assert_eq!(
            dns01.camouflage_sites[0].certificate.challenge_method,
            AcmeChallengeMethod::Dns01
        );
        let wire = serde_json::to_string(&dns01).unwrap();
        assert!(!wire.contains("api_key"));
    }

    #[tokio::test]
    async fn inbound_camouflage_uses_node_status_ip_when_connect_host_is_empty() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        sqlx::query("UPDATE device_groups SET connect_host='' WHERE id=10")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='long.example.com', camouflage_enabled=1 WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        repo(&pool)
            .set(
                "node_status:10:node-a",
                r#"{"public_ipv4":"198.51.100.20"}"#,
            )
            .await
            .unwrap();

        let config = build_node_config_for_node(&repo(&pool), 10, Some("node-a"))
            .await
            .unwrap();
        assert_eq!(
            config.camouflage_sites[0].certificate.expected_public_ip,
            "198.51.100.20"
        );
        assert_eq!(
            config.camouflage_sites[0].site_id,
            relay_shared::reconciliation::stable_camouflage_site_id("long.example.com")
        );
        repo(&pool)
            .set(
                "node_status:10:node-b",
                r#"{"public_ipv4":"198.51.100.21"}"#,
            )
            .await
            .unwrap();
        let other = build_node_config_for_node(&repo(&pool), 10, Some("node-b"))
            .await
            .unwrap();
        assert_eq!(
            other.camouflage_sites[0].certificate.expected_public_ip,
            "198.51.100.21"
        );
        assert_ne!(
            config.camouflage_sites[0].certificate.expected_public_ip,
            other.camouflage_sites[0].certificate.expected_public_ip
        );
    }

    #[tokio::test]
    async fn mixed_proxy_protocol_state_fails_canonical_config_build() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='op1.example.com' WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 101, 2, 10, 443).await;
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni=CASE id WHEN 100 THEN 'op1.example.com' ELSE 'op2.example.com' END, \
             send_proxy_protocol=CASE id WHEN 100 THEN 1 ELSE 0 END, \
             target_addr='198.51.100.20', target_port=55443 WHERE id IN (100, 101)",
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(matches!(
            build_node_config(&repo(&pool), 10).await,
            Err(NodeConfigBuildError::InvalidConfig(message))
                if message.contains("mixed upstream Proxy Protocol modes")
        ));
    }

    #[tokio::test]
    async fn config_snapshot_revision_is_stable_for_replay_and_increments_on_change() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        let repository = repo(&pool);

        let first = build_node_config_snapshot(&repository, 10).await.unwrap();
        let replay = build_node_config_snapshot(&repository, 10).await.unwrap();
        assert_eq!(first.config_revision, replay.config_revision);
        assert_eq!(first.config_fingerprint, replay.config_fingerprint);

        sqlx::query("UPDATE forward_rules SET target_port=81 WHERE id=100")
            .execute(&pool)
            .await
            .unwrap();
        let changed = build_node_config_snapshot(&repository, 10).await.unwrap();
        assert!(changed.config_revision > first.config_revision);
        assert_ne!(changed.config_fingerprint, first.config_fingerprint);
    }
}
