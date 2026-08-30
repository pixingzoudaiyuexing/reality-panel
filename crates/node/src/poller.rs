use crate::config::NodeConfig;
use crate::forwarder::camouflage_site::CamouflageSiteManager;
use crate::forwarder::ForwarderManager;
use relay_shared::protocol::{
    NodeConfigResponse, NodeConfigSnapshot, NodeTransport, CONFIG_PROTOCOL_VERSION,
};
use relay_shared::reconciliation::{fingerprint_bytes, ConfigFingerprint};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Path for the config cache file. Used when the panel is unreachable.
const CACHE_FILE: &str = "config-cache.json";

/// File holding this node's stable identity. Generated once on first start
/// (a random hex string) and reused forever after, so the panel can tell
/// multiple nodes sharing one group token apart (fixes status overwrite:
/// node_status:{group_id} was a single key overwritten by every node).
const NODE_ID_FILE: &str = "node-id";

/// v0.4.0: outcome of a config fetch, distinguishing a permanent protocol
/// mismatch (426) from a transient failure (network/5xx). The caller uses this
/// to decide the poll interval: 426 → long backoff (upgrade needed), transient
/// → keep the normal interval.
pub enum FetchResult {
    /// A valid config was received. It is cached only after the manager applies it.
    Ok(NodeConfigSnapshot),
    /// The panel reports a permanent config-protocol mismatch (426). The node
    /// keeps its cached config; the caller should back off (the only fix is an
    /// upgrade, so polling fast is pointless).
    ProtocolMismatch,
    /// Transient failure (network error, 5xx, non-JSON body). The caller keeps
    /// the cached config and retries on the normal interval.
    Transient,
}

pub async fn fetch_config(config: &NodeConfig) -> FetchResult {
    let url = format!("{}/api/v1/node/config", config.panel_url);
    let client = reqwest::Client::new();

    let resp = match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", config.token))
        .header("X-Node-ID", get_or_create_node_id())
        // v0.4.0: send our config-protocol version so the panel can refuse to
        // send config we can't deserialize (keeps old nodes on their cached
        // config instead of crashing on unknown fields/enum variants).
        .header("X-Config-Protocol-Version", CONFIG_PROTOCOL_VERSION)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("fetch_config: network error: {}", e);
            return FetchResult::Transient;
        }
    };

    let status = resp.status();
    if status == reqwest::StatusCode::UPGRADE_REQUIRED {
        // Permanent: the panel's config protocol doesn't match ours. Parse the
        // structured body for a clear log line, then back off.
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let required = body.get("required").and_then(|v| v.as_u64());
        tracing::warn!(
            required = ?required,
            "fetch_config: config protocol mismatch (panel requires v{:?}, node has v{}); \
             keeping cached config — upgrade relay-node",
            required,
            CONFIG_PROTOCOL_VERSION
        );
        return FetchResult::ProtocolMismatch;
    }
    if !status.is_success() {
        tracing::warn!(status = %status, "fetch_config: non-2xx response; keeping cached config");
        return FetchResult::Transient;
    }

    match resp.json::<NodeConfigSnapshot>().await {
        Ok(snapshot)
            if snapshot.config_revision > 0
                && snapshot.config_fingerprint
                    == relay_shared::reconciliation::config_fingerprint(&snapshot.config)
                        .as_str()
                && validate_config(&snapshot.config).is_ok() =>
        {
            FetchResult::Ok(snapshot)
        }
        Ok(e) => {
            let reason = validate_config(&e.config)
                .err()
                .unwrap_or_else(|| "invalid snapshot metadata".into());
            tracing::warn!("fetch_config: response validation failed: {}", reason);
            FetchResult::Transient
        }
        Err(e) => {
            tracing::warn!("fetch_config: response parse failed: {}", e);
            FetchResult::Transient
        }
    }
}

/// The three files that make the last-known-good cache durable.
#[derive(Clone, Debug)]
pub(crate) struct CachePaths {
    pub primary: PathBuf,
    pub backup: PathBuf,
    pub tmp: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheRecoverySource {
    PrimaryLkg,
    RepairedFromBackup,
    BackupFallback,
    #[allow(dead_code)] // 无可信 LKG 的显式降级类别为 fail-safe 兼容状态。
    DegradedNoTrustedLkg,
}

#[derive(Debug)]
pub(crate) struct CacheLoad {
    pub config: NodeConfigResponse,
    pub source: CacheRecoverySource,
    pub config_revision: u64,
    pub config_fingerprint: ConfigFingerprint,
}

#[derive(Debug)]
pub(crate) struct CoordinatedApplyOutcome {
    pub success: bool,
    pub effective: Option<NodeConfigResponse>,
    pub dependency_withheld: bool,
    pub pending: Option<PendingFinalization>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeInspection {
    pub observed_fingerprint: ConfigFingerprint,
    pub healthy: bool,
    pub drifted_listener_keys:
        std::collections::HashSet<(u16, relay_shared::protocol::Protocol, NodeTransport)>,
    pub nginx_drift: bool,
    pub camouflage_drift: bool,
}

#[derive(Debug)]
pub(crate) struct PendingFinalization {
    pub effective: NodeConfigResponse,
    pub referenced_snis: std::collections::HashSet<String>,
    pub lkg_committed: bool,
    pub config_revision: u64,
    pub config_fingerprint: ConfigFingerprint,
}

impl CoordinatedApplyOutcome {
    fn rejected() -> Self {
        Self {
            success: false,
            effective: None,
            dependency_withheld: false,
            pending: None,
        }
    }

    fn applied(effective: NodeConfigResponse, dependency_withheld: bool) -> Self {
        Self {
            success: true,
            effective: Some(effective),
            dependency_withheld,
            pending: None,
        }
    }

    fn failed(
        effective: NodeConfigResponse,
        dependency_withheld: bool,
        pending: Option<PendingFinalization>,
    ) -> Self {
        Self {
            success: false,
            effective: Some(effective),
            dependency_withheld,
            pending,
        }
    }
}

/// Apply first, then commit the snapshot as LKG while holding the same manager
/// mutex. HTTP polls and WebSocket snapshots both use this path so an older
/// snapshot cannot finish its cache write after a newer one.
#[allow(dead_code)] // 保留无 revision 调用入口，便于旧缓存与故障注入复用同一事务。
pub(crate) async fn apply_and_commit_coordinated(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    config: &NodeConfigResponse,
) -> CoordinatedApplyOutcome {
    apply_and_commit_coordinated_at(manager, camouflage, config, &cache_paths()).await
}

#[allow(dead_code)] // 测试路径可注入独立缓存目录，生产路径使用 versioned snapshot。
pub(crate) async fn apply_and_commit_coordinated_at(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    config: &NodeConfigResponse,
    paths: &CachePaths,
) -> CoordinatedApplyOutcome {
    let fingerprint = relay_shared::reconciliation::config_fingerprint(config);
    let snapshot = NodeConfigSnapshot {
        config_revision: 0,
        config_fingerprint: fingerprint.as_str().to_string(),
        config: config.clone(),
    };
    apply_and_commit_coordinated_snapshot_at(manager, camouflage, &snapshot, paths).await
}

pub(crate) async fn apply_and_commit_coordinated_snapshot_at(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    snapshot: &NodeConfigSnapshot,
    paths: &CachePaths,
) -> CoordinatedApplyOutcome {
    let previous = load_cache_at(paths);
    apply_coordinated(
        manager,
        camouflage,
        &snapshot.config,
        previous.as_ref(),
        Some(paths),
        true,
        snapshot.config_revision,
        &snapshot.config_fingerprint,
    )
    .await
}

pub(crate) async fn apply_cached_coordinated(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    config: &NodeConfigResponse,
) -> CoordinatedApplyOutcome {
    let fingerprint = relay_shared::reconciliation::config_fingerprint(config);
    apply_coordinated(
        manager,
        camouflage,
        config,
        Some(config),
        None,
        false,
        0,
        fingerprint.as_str(),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // 事务边界参数保持显式，避免 rc.7 改写 LKG 调用架构。
async fn apply_coordinated(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    desired: &NodeConfigResponse,
    previous: Option<&NodeConfigResponse>,
    commit_paths: Option<&CachePaths>,
    allow_cleanup: bool,
    config_revision: u64,
    config_fingerprint: &str,
) -> CoordinatedApplyOutcome {
    if let Err(error) = validate_config(desired) {
        tracing::warn!("refusing invalid node config: {}", error);
        return CoordinatedApplyOutcome::rejected();
    }

    // Certificate work snapshots desired state and runs independently. The
    // apply gate below preserves listener/LKG/finalization ordering without
    // retaining the camouflage state mutex through external work.
    let active_snis = crate::forwarder::camouflage_site::prepare_desired_shared(
        camouflage,
        &desired.camouflage_sites,
        allow_cleanup,
    )
    .await;
    // Serialize cross-resource runtime changes without holding camouflage
    // state. Certificate/status work can still read the state mutex freely.
    let _camouflage_apply_guard =
        crate::forwarder::camouflage_site::runtime_apply_guard(camouflage).await;
    let (effective, referenced_snis, dependency_withheld) =
        build_effective_config(desired, previous, &active_snis);

    let mut forwarders = manager.lock().await;
    let applied = if allow_cleanup {
        forwarders.apply_config(&effective).await
    } else {
        forwarders
            .apply_config_scoped(&effective, &std::collections::HashSet::new(), false, false)
            .await
    };
    if !applied {
        tracing::warn!("coordinated listener apply failed; preserving listener LKG");
        return CoordinatedApplyOutcome::failed(effective, dependency_withheld, None);
    }
    if let Some(paths) = commit_paths {
        if let Err(error) =
            commit_cache_with_metadata_at(&effective, paths, config_revision, config_fingerprint)
        {
            tracing::error!(
                "coordinated config applied but LKG commit failed: {}",
                error
            );
            return CoordinatedApplyOutcome::failed(
                effective.clone(),
                dependency_withheld,
                Some(PendingFinalization {
                    effective,
                    referenced_snis,
                    lkg_committed: false,
                    config_revision,
                    config_fingerprint: ConfigFingerprint::from_string(config_fingerprint),
                }),
            );
        }
    }
    drop(forwarders);

    if !allow_cleanup {
        return CoordinatedApplyOutcome::applied(effective, dependency_withheld);
    }
    if !crate::forwarder::camouflage_site::finalize_for_listener_snis_shared_under_apply_gate(
        camouflage,
        &referenced_snis,
    )
    .await
    {
        tracing::warn!("listener applied, but stale camouflage finalization failed");
        return CoordinatedApplyOutcome::failed(
            effective.clone(),
            dependency_withheld,
            Some(PendingFinalization {
                effective,
                referenced_snis,
                lkg_committed: true,
                config_revision,
                config_fingerprint: ConfigFingerprint::from_string(config_fingerprint),
            }),
        );
    }
    CoordinatedApplyOutcome::applied(effective, dependency_withheld)
}

pub(crate) async fn inspect_runtime(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    effective: &NodeConfigResponse,
) -> RuntimeInspection {
    let forwarder = manager.lock().await.inspect_runtime(effective);
    let expected_camouflage_snis = effective_camouflage_snis(effective);
    let camouflage = crate::forwarder::camouflage_site::runtime_observation_shared(
        camouflage,
        &expected_camouflage_snis,
    )
    .await;
    tracing::debug!(
        ownership = ?camouflage.ownership,
        healthy = camouflage.healthy,
        "inspected camouflage runtime ownership"
    );
    let mut evidence = b"runtime-observation-v1\0".to_vec();
    evidence.extend_from_slice(forwarder.fingerprint.as_str().as_bytes());
    evidence.extend_from_slice(camouflage.fingerprint.as_str().as_bytes());
    let drifted_listener_keys = forwarder
        .drifted_listener_keys
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let nginx_drift = forwarder.nginx_drift;
    let camouflage_drift = !camouflage.healthy;
    let mut sorted_drift: Vec<_> = drifted_listener_keys.iter().copied().collect();
    sorted_drift.sort_by_key(|(port, protocol, transport)| {
        (
            *port,
            runtime_protocol_tag(*protocol),
            runtime_transport_tag(*transport),
        )
    });
    for (port, protocol, transport) in sorted_drift {
        evidence.extend_from_slice(&port.to_be_bytes());
        evidence.extend_from_slice(runtime_protocol_tag(protocol).as_bytes());
        evidence.push(b'/');
        evidence.extend_from_slice(runtime_transport_tag(transport).as_bytes());
    }
    evidence.push(nginx_drift as u8);
    evidence.push(camouflage_drift as u8);
    let healthy = forwarder.healthy && camouflage.healthy;
    RuntimeInspection {
        observed_fingerprint: fingerprint_bytes(&evidence),
        healthy,
        drifted_listener_keys,
        nginx_drift,
        camouflage_drift,
    }
}

fn runtime_protocol_tag(protocol: relay_shared::protocol::Protocol) -> &'static str {
    match protocol {
        relay_shared::protocol::Protocol::Tcp => "tcp",
        relay_shared::protocol::Protocol::Udp => "udp",
        relay_shared::protocol::Protocol::TcpUdp => "tcp_udp",
    }
}

fn runtime_transport_tag(transport: NodeTransport) -> &'static str {
    transport.to_db_str()
}

pub(crate) async fn repair_runtime(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    effective: &NodeConfigResponse,
    inspection: &RuntimeInspection,
    allow_cleanup: bool,
) -> bool {
    if inspection.camouflage_drift {
        let expected_camouflage_snis = effective_camouflage_snis(effective);
        if !crate::forwarder::camouflage_site::repair_active_runtime_shared(
            camouflage,
            &expected_camouflage_snis,
        )
        .await
        {
            tracing::warn!("camouflage runtime repair failed");
            return false;
        }
    }
    let mut forwarders = manager.lock().await;
    forwarders
        .apply_config_scoped(
            effective,
            &inspection.drifted_listener_keys,
            inspection.nginx_drift,
            allow_cleanup,
        )
        .await
}

fn effective_camouflage_snis(effective: &NodeConfigResponse) -> std::collections::HashSet<String> {
    effective
        .listeners
        .iter()
        .filter(|listener| listener.camouflage_required)
        .filter_map(|listener| listener.sni.clone())
        .collect()
}

pub(crate) async fn camouflage_dependencies_ready(
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    desired: &NodeConfigResponse,
) -> bool {
    let required: std::collections::HashSet<_> = desired
        .listeners
        .iter()
        .filter(|listener| listener.camouflage_required)
        .filter_map(|listener| listener.sni.clone())
        .collect();
    if required.is_empty() {
        return true;
    }
    let active = crate::forwarder::camouflage_site::active_snis_shared(camouflage).await;
    required.is_subset(&active)
}

pub(crate) async fn retry_pending_finalization(
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    pending: &mut PendingFinalization,
    paths: &CachePaths,
) -> bool {
    if !pending.lkg_committed {
        if let Err(error) = commit_cache_with_metadata_at(
            &pending.effective,
            paths,
            pending.config_revision,
            pending.config_fingerprint.as_str(),
        ) {
            tracing::warn!("pending listener LKG commit still unavailable: {}", error);
            return false;
        }
        pending.lkg_committed = true;
    }

    let _apply_guard = crate::forwarder::camouflage_site::runtime_apply_guard(camouflage).await;
    if !crate::forwarder::camouflage_site::finalize_for_listener_snis_shared_under_apply_gate(
        camouflage,
        &pending.referenced_snis,
    )
    .await
    {
        tracing::warn!("pending camouflage finalization still unavailable");
        return false;
    }
    true
}

fn build_effective_config(
    desired: &NodeConfigResponse,
    previous: Option<&NodeConfigResponse>,
    active_snis: &std::collections::HashSet<String>,
) -> (NodeConfigResponse, std::collections::HashSet<String>, bool) {
    let mut listeners = Vec::new();
    let mut preserved_rules = std::collections::HashSet::new();
    let mut dependency_withheld = false;
    for listener in &desired.listeners {
        let ready = !listener.camouflage_required
            || listener
                .sni
                .as_deref()
                .map(|sni| active_snis.contains(sni))
                .unwrap_or(false);
        if ready {
            listeners.push(listener.clone());
            continue;
        }
        dependency_withheld = true;
        if !preserved_rules.insert(listener.rule_id) {
            continue;
        }
        if let Some(previous) = previous {
            listeners.extend(
                previous
                    .listeners
                    .iter()
                    .filter(|old| {
                        old.rule_id == listener.rule_id
                            && old.camouflage_required
                            && old
                                .sni
                                .as_deref()
                                .map(|sni| active_snis.contains(sni))
                                .unwrap_or(false)
                    })
                    .cloned(),
            );
        }
    }
    let referenced_snis: std::collections::HashSet<String> = listeners
        .iter()
        .filter(|listener| listener.camouflage_required)
        .filter_map(|listener| listener.sni.clone())
        .collect();
    let mut camouflage_sites = desired.camouflage_sites.clone();
    if let Some(previous) = previous {
        for sni in &referenced_snis {
            if camouflage_sites
                .iter()
                .any(|site| site.enabled && site.sni == *sni)
            {
                continue;
            }
            if let Some(site) = previous
                .camouflage_sites
                .iter()
                .find(|site| site.enabled && site.sni == *sni)
            {
                camouflage_sites.push(site.clone());
            }
        }
    }
    (
        NodeConfigResponse {
            listeners,
            camouflage_sites,
        },
        referenced_snis,
        dependency_withheld,
    )
}

#[cfg(test)]
pub(crate) async fn apply_and_commit_at(
    manager: &Arc<Mutex<ForwarderManager>>,
    config: &NodeConfigResponse,
    paths: &CachePaths,
) -> bool {
    if let Err(e) = validate_config(config) {
        tracing::warn!("refusing invalid node config: {}", e);
        return false;
    }

    // Keep the lock through the durable commit. This is intentionally small
    // serialisation, not a revision system: apply order and LKG commit order
    // must be identical.
    let mut mgr = manager.lock().await;
    if !mgr.apply_config(config).await {
        tracing::warn!("config apply failed; preserving existing LKG");
        return false;
    }
    match commit_cache_at(config, paths) {
        Ok(()) => true,
        Err(e) => {
            tracing::error!("config applied but LKG commit failed: {}", e);
            false
        }
    }
}

/// Load the primary cache if valid, otherwise fall back to the last healthy
/// backup. A startup load is deliberately not committed again.
#[allow(dead_code)] // 保留旧调用入口；现代启动路径读取带 revision 的 CacheLoad。
pub fn load_cache() -> Option<NodeConfigResponse> {
    load_cache_state_at(&cache_paths()).map(|state| state.config)
}

pub(crate) fn load_cache_at(paths: &CachePaths) -> Option<NodeConfigResponse> {
    load_cache_state_at(paths).map(|state| state.config)
}

pub(crate) fn load_cache_state_at(paths: &CachePaths) -> Option<CacheLoad> {
    if let Ok((config, config_revision, config_fingerprint)) =
        read_valid_cache_snapshot(&paths.primary)
    {
        remove_tmp_if_safe(&paths.tmp);
        tracing::info!(
            "Loaded cached config from primary {} ({} listeners)",
            paths.primary.display(),
            config.listeners.len()
        );
        return Some(CacheLoad {
            config,
            source: CacheRecoverySource::PrimaryLkg,
            config_revision,
            config_fingerprint,
        });
    }

    if let Ok((config, config_revision, config_fingerprint)) =
        read_valid_cache_snapshot(&paths.backup)
    {
        let source = match repair_primary_from_backup(paths) {
            Ok(()) => CacheRecoverySource::RepairedFromBackup,
            Err(error) => {
                tracing::warn!(
                    "valid listener LKG backup loaded but primary repair failed: {}",
                    error
                );
                remove_tmp_if_safe(&paths.tmp);
                CacheRecoverySource::BackupFallback
            }
        };
        tracing::info!(
            "Loaded cached config from backup {} ({} listeners)",
            paths.backup.display(),
            config.listeners.len()
        );
        return Some(CacheLoad {
            config,
            source,
            config_revision,
            config_fingerprint,
        });
    }

    remove_tmp_if_safe(&paths.tmp);
    tracing::warn!("no usable cached config; waiting for panel configuration");
    None
}

fn repair_primary_from_backup(paths: &CachePaths) -> Result<(), String> {
    let bytes = fs::read(&paths.backup).map_err(|error| error.to_string())?;
    let config = serde_json::from_slice::<NodeConfigResponse>(&bytes).map_err(|e| e.to_string())?;
    validate_config(&config)?;
    replace_durably(&paths.primary, &bytes).map_err(|error| error.to_string())?;
    read_valid_cache(&paths.primary).map(|_| ())
}

fn remove_tmp_if_safe(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if let Err(error) = fs::remove_file(path) {
                tracing::warn!(
                    "could not remove stale LKG tmp {}: {}",
                    path.display(),
                    error
                );
            }
        }
        Ok(_) => tracing::warn!("leaving non-file LKG tmp residue {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!("could not inspect LKG tmp {}: {}", path.display(), error),
    }
}

#[allow(dead_code)] // 故障注入使用无 revision 提交入口验证 primary/backup 事务。
pub(crate) fn commit_cache_at(
    config: &NodeConfigResponse,
    paths: &CachePaths,
) -> Result<(), String> {
    let fingerprint = relay_shared::reconciliation::config_fingerprint(config);
    commit_cache_with_metadata_at(config, paths, 0, fingerprint.as_str())
}

pub(crate) fn commit_cache_with_metadata_at(
    config: &NodeConfigResponse,
    paths: &CachePaths,
    config_revision: u64,
    config_fingerprint: &str,
) -> Result<(), String> {
    validate_config(config)?;
    let snapshot = NodeConfigSnapshot {
        config_revision,
        config_fingerprint: config_fingerprint.to_string(),
        config: config.clone(),
    };
    let json = serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?;
    // Validate the serialized representation before it can replace any LKG.
    let _: NodeConfigSnapshot = serde_json::from_slice(&json).map_err(|e| e.to_string())?;

    write_durable(&paths.tmp, &json).map_err(|e| e.to_string())?;
    if let Err(e) = read_valid_cache(&paths.tmp) {
        let _ = fs::remove_file(&paths.tmp);
        return Err(format!("temporary cache validation failed: {}", e));
    }

    // A corrupt primary is never promoted into backup. Preserve any healthy
    // backup for recovery before replacing the primary.
    if read_valid_cache(&paths.primary).is_ok() {
        let old_primary = fs::read(&paths.primary).map_err(|e| e.to_string())?;
        if let Err(e) = replace_durably(&paths.backup, &old_primary) {
            let _ = fs::remove_file(&paths.tmp);
            return Err(e.to_string());
        }
    }

    if let Err(e) = fs::rename(&paths.tmp, &paths.primary).and_then(|_| sync_parent(&paths.primary))
    {
        let _ = fs::remove_file(&paths.tmp);
        return Err(e.to_string());
    }
    Ok(())
}

pub(crate) fn validate_config(config: &NodeConfigResponse) -> Result<(), String> {
    relay_shared::protocol::validate_proxy_protocol_invariants(&config.listeners)?;
    for listener in &config.listeners {
        if listener.port == 0 {
            return Err(format!("rule {} has port 0", listener.rule_id));
        }
        if listener.targets.is_empty()
            || listener
                .targets
                .iter()
                .any(|target| target.trim().is_empty())
        {
            return Err(format!("rule {} has no valid target", listener.rule_id));
        }
        if listener.node_transport == NodeTransport::NginxSni
            && listener
                .sni
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        {
            return Err(format!("nginx_sni rule {} has no SNI", listener.rule_id));
        }
    }
    let mut site_ids = std::collections::HashSet::new();
    let mut site_snis = std::collections::HashSet::new();
    for site in &config.camouflage_sites {
        if !site.enabled {
            continue;
        }
        if site.site_id.is_empty()
            || site.site_id.len() > 64
            || !site
                .site_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            || !valid_domain(&site.sni)
            || site.tls_listener_port != 8443
            // wildcard 证书只要能覆盖当前 SNI 就是合法配置；这里必须和证书生命周期
            // 共用同一套匹配规则，避免“证书已签发但 desired 被拒绝”的分裂状态。
            || !relay_shared::reconciliation::certificate_domain_covers_sni(
                &site.certificate.domain,
                &site.sni,
            )
            || site
                .certificate
                .expected_public_ip
                .parse::<std::net::IpAddr>()
                .is_err()
            || !(1..=365).contains(&site.certificate.renew_before_days)
        {
            return Err("invalid camouflage desired state".into());
        }
        if !site_ids.insert(site.site_id.clone()) || !site_snis.insert(site.sni.clone()) {
            return Err("duplicate camouflage desired state".into());
        }
    }
    for listener in &config.listeners {
        if listener.camouflage_required
            && !listener
                .sni
                .as_ref()
                .map(|sni| site_snis.contains(sni))
                .unwrap_or(false)
        {
            return Err(format!(
                "rule {} requires missing camouflage desired state",
                listener.rule_id
            ));
        }
    }
    Ok(())
}

fn valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

fn read_valid_cache(path: &Path) -> Result<NodeConfigResponse, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let config = serde_json::from_slice::<NodeConfigResponse>(&data).map_err(|e| e.to_string())?;
    validate_config(&config)?;
    Ok(config)
}

fn read_valid_cache_snapshot(
    path: &Path,
) -> Result<(NodeConfigResponse, u64, ConfigFingerprint), String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    if let Ok(snapshot) = serde_json::from_slice::<NodeConfigSnapshot>(&data) {
        validate_config(&snapshot.config)?;
        let fingerprint = relay_shared::reconciliation::config_fingerprint(&snapshot.config);
        if snapshot.config_revision > 0 && snapshot.config_fingerprint != fingerprint.as_str() {
            return Err("cached config fingerprint mismatch".into());
        }
        return Ok((snapshot.config, snapshot.config_revision, fingerprint));
    }
    let config = serde_json::from_slice::<NodeConfigResponse>(&data).map_err(|e| e.to_string())?;
    validate_config(&config)?;
    let fingerprint = relay_shared::reconciliation::config_fingerprint(&config);
    Ok((config, 0, fingerprint))
}

fn write_durable(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(parent_dir(path))?;
    let mut file = File::create(path)?;
    file.write_all(contents)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn replace_durably(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    write_durable(&temp, contents)?;
    fs::rename(&temp, path)?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(parent_dir(path))?.sync_all()
}

/// `Path::parent()` is an empty path for a filename in the current directory.
/// Treat that as `.` so development-mode caches remain durable too.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn cache_paths() -> CachePaths {
    let primary = cache_path();
    let parent = primary
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    CachePaths {
        primary,
        backup: parent.join("config-cache.backup.json"),
        tmp: parent.join("config-cache.json.tmp"),
    }
}

pub(crate) fn current_cache_paths() -> CachePaths {
    cache_paths()
}

fn cache_path() -> PathBuf {
    // Try /opt/relay-node first (production path), then current dir (dev)
    let prod = PathBuf::from("/opt/relay-node").join(CACHE_FILE);
    if prod.parent().map(|p| p.exists()).unwrap_or(false) {
        return prod;
    }
    PathBuf::from(CACHE_FILE)
}

/// Resolve where the node-id file lives — same directory logic as cache_path
/// so the two files sit together (production: /opt/relay-node/, dev: cwd).
fn node_id_path() -> PathBuf {
    let prod = PathBuf::from("/opt/relay-node").join(NODE_ID_FILE);
    if prod.parent().map(|p| p.exists()).unwrap_or(false) {
        return prod;
    }
    PathBuf::from(NODE_ID_FILE)
}

/// Get this node's stable identity, generating + persisting it on first call.
///
/// The id is a random hex string generated once and reused across restarts, so
/// the panel can distinguish multiple physical nodes that share one inbound
/// group token (each gets its own node_status:{group_id}:{node_id} key instead
/// of all overwriting node_status:{group_id}).
///
/// Generation uses the OS random source via std; we deliberately do NOT derive
/// it from hostname/MAC (those can change/DHCP) — a stable random id is the
/// contract the panel's status dedup depends on.
pub fn get_or_create_node_id() -> String {
    get_or_create_node_id_at(&node_id_path())
}

/// Inner implementation taking an explicit path, so it's unit-testable without
/// touching the real /opt/relay-node or cwd.
fn get_or_create_node_id_at(path: &std::path::Path) -> String {
    // Try to load an existing id first.
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    // No id yet: generate one (16 random bytes → 32 hex chars). std's
    // fill_bytes uses the OS CSPRNG; we don't need cryptographic strength but
    // it's the most portable "good enough random" available without extra deps.
    let mut bytes = [0u8; 16];
    use std::io::Read;
    // /dev/urandom on Linux (the only supported platform); fall back to a
    // time+pid-based id if unavailable so the node still boots.
    let id = match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => hex_encode(&bytes),
        Err(_) => {
            tracing::warn!("could not read /dev/urandom for node_id; using fallback");
            fallback_id()
        }
    };
    if let Err(e) = std::fs::write(path, &id) {
        tracing::warn!("failed to persist node_id to {}: {}", path.display(), e);
        // Non-fatal: we return the in-memory id; it'll regenerate next start,
        // which means status may flap for this node until the file is writable.
    } else {
        tracing::info!("generated node_id {} -> {}", id, path.display());
    }
    id
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Fallback id when /dev/urandom is unavailable. Not random, but unique enough
/// per (host, pid, time) to avoid collisions in practice — and only used on
/// broken systems where /dev/urandom is missing (shouldn't happen on Linux).
fn fallback_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("node-{}-{}", std::process::id(), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-panel-poller-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    /// A node_id generated once must be reused verbatim on every subsequent
    /// call — this stability is the contract the panel's status dedup depends
    /// on. If this breaks, a restarting node would look like a NEW node and its
    /// old status entry would stale forever.
    #[test]
    fn node_id_is_stable_across_calls() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "relaypanel-test-nodeid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = get_or_create_node_id_at(&path);
        let second = get_or_create_node_id_at(&path);
        assert!(!first.is_empty(), "first id must be non-empty");
        assert_eq!(
            first, second,
            "node_id must be stable: a restart must reuse the persisted id"
        );
        // The file must exist and hold exactly the id (so it survives a real
        // process restart, not just in-memory caching).
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim(), first);
        let _ = std::fs::remove_file(&path);
    }

    /// Two different nodes (different id files) must get DIFFERENT ids. This is
    /// what lets the panel tell them apart — if they collided, the status
    /// overwrite bug would be back.
    #[test]
    fn distinct_nodes_get_distinct_ids() {
        let dir = std::env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path_a = dir.join(format!("relaypanel-test-nodeid-a-{}", stamp));
        let path_b = dir.join(format!("relaypanel-test-nodeid-b-{}", stamp));
        let a = get_or_create_node_id_at(&path_a);
        let b = get_or_create_node_id_at(&path_b);
        assert_ne!(a, b, "two fresh nodes must not share an id");
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    /// A pre-existing node-id file must be honored as-is (an operator who set
    /// a specific id, or a node restored from backup, keeps that identity).
    #[test]
    fn existing_node_id_file_is_honored() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "relaypanel-test-nodeid-existing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "my-fixed-id-12345").unwrap();
        let id = get_or_create_node_id_at(&path);
        assert_eq!(id, "my-fixed-id-12345");
        let _ = std::fs::remove_file(&path);
    }

    fn cache_paths_for_test(label: &str) -> CachePaths {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "relay-panel-lkg-{label}-{}-{stamp}",
            std::process::id()
        ));
        CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        }
    }

    fn cache_config(rule_id: i64) -> NodeConfigResponse {
        NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![relay_shared::protocol::ListenerConfig {
                camouflage_required: false,
                send_proxy_protocol: false,
                rule_id,
                port: 20000 + rule_id as u16,
                protocol: relay_shared::protocol::Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                sni: None,
                targets: vec!["127.0.0.1:9".to_string()],
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
        }
    }

    fn cleanup_cache(paths: &CachePaths) {
        let _ = std::fs::remove_dir_all(paths.primary.parent().unwrap());
    }

    #[test]
    fn relative_cache_paths_sync_the_current_directory() {
        assert_eq!(parent_dir(Path::new("config-cache.json")), Path::new("."));
    }

    #[tokio::test]
    async fn apply_success_commits_lkg_and_removes_tmp() {
        let paths = cache_paths_for_test("apply-success");
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        )));
        let empty = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![],
        };

        assert!(apply_and_commit_at(&manager, &empty, &paths).await);
        assert!(paths.primary.exists());
        assert!(
            !paths.tmp.exists(),
            "successful cache commit must not leave tmp"
        );
        assert!(load_cache_at(&paths).unwrap().listeners.is_empty());
        cleanup_cache(&paths);
    }

    #[tokio::test]
    async fn apply_failure_preserves_old_lkg() {
        let paths = cache_paths_for_test("apply-failure");
        let old = cache_config(1);
        commit_cache_at(&old, &paths).unwrap();
        let mut inner = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        inner.set_nginx_sni_config_for_test(crate::forwarder::nginx_sni::NginxSniConfig {
            enabled: true,
            conf_path: paths.primary.parent().unwrap().join("relay.conf"),
            test_cmd: "false".to_string(),
            reload_cmd: "true".to_string(),
            default_backend: "127.0.0.1:9".to_string(),
            access_log_path: "/tmp/relay-panel-test.log".to_string(),
        });
        let manager = Arc::new(Mutex::new(inner));
        let failed = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![relay_shared::protocol::ListenerConfig {
                camouflage_required: false,
                send_proxy_protocol: false,
                rule_id: 2,
                port: 443,
                protocol: relay_shared::protocol::Protocol::Tcp,
                node_transport: NodeTransport::NginxSni,
                ws_path: None,
                sni: Some("failed.example.com".to_string()),
                targets: vec!["127.0.0.1:55443".to_string()],
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
        };

        assert!(!apply_and_commit_at(&manager, &failed, &paths).await);
        assert_eq!(load_cache_at(&paths).unwrap().listeners[0].rule_id, 1);
        cleanup_cache(&paths);
    }

    #[tokio::test]
    async fn mixed_proxy_protocol_config_is_rejected_without_overwriting_lkg() {
        let paths = cache_paths_for_test("mixed-proxy-protocol");
        let old = cache_config(1);
        commit_cache_at(&old, &paths).unwrap();
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        )));
        let mut first = cache_config(2).listeners.remove(0);
        first.port = 443;
        first.node_transport = NodeTransport::NginxSni;
        first.sni = Some("op1.example.com".into());
        first.send_proxy_protocol = true;
        let mut second = first.clone();
        second.rule_id = 3;
        second.sni = Some("op2.example.com".into());
        second.send_proxy_protocol = false;
        let invalid = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![first, second],
        };

        assert!(!apply_and_commit_at(&manager, &invalid, &paths).await);
        assert_eq!(
            serde_json::to_value(load_cache_at(&paths).unwrap()).unwrap(),
            serde_json::to_value(old).unwrap()
        );
        cleanup_cache(&paths);
    }

    #[tokio::test]
    async fn raw_bind_failure_does_not_commit_lkg() {
        let paths = cache_paths_for_test("raw-bind-failure");
        let old = cache_config(1);
        commit_cache_at(&old, &paths).unwrap();
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = blocker.local_addr().unwrap().port();
        let mut inner = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        inner.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(inner));
        let mut failed = cache_config(2);
        failed.listeners[0].port = port;

        assert!(!apply_and_commit_at(&manager, &failed, &paths).await);
        assert_eq!(load_cache_at(&paths).unwrap().listeners[0].rule_id, 1);
        cleanup_cache(&paths);
    }

    #[tokio::test]
    async fn successful_raw_bind_can_commit_lkg() {
        let paths = cache_paths_for_test("raw-bind-success");
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let mut inner = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        inner.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(inner));
        let mut config = cache_config(3);
        config.listeners[0].port = port;

        assert!(apply_and_commit_at(&manager, &config, &paths).await);
        assert_eq!(load_cache_at(&paths).unwrap().listeners[0].rule_id, 3);
        assert!(
            manager
                .lock()
                .await
                .apply_config(&NodeConfigResponse {
                    camouflage_sites: vec![],
                    listeners: vec![]
                })
                .await
        );
        cleanup_cache(&paths);
    }

    #[test]
    fn primary_is_preferred_and_corrupt_primary_falls_back_to_backup() {
        let paths = cache_paths_for_test("primary-backup");
        commit_cache_at(&cache_config(1), &paths).unwrap();
        commit_cache_at(&cache_config(2), &paths).unwrap();
        assert_eq!(load_cache_at(&paths).unwrap().listeners[0].rule_id, 2);

        std::fs::write(&paths.primary, b"not json").unwrap();
        assert_eq!(load_cache_at(&paths).unwrap().listeners[0].rule_id, 1);
        cleanup_cache(&paths);
    }

    #[test]
    fn corrupt_primary_cannot_overwrite_healthy_backup() {
        let paths = cache_paths_for_test("corrupt-primary");
        commit_cache_at(&cache_config(1), &paths).unwrap();
        commit_cache_at(&cache_config(2), &paths).unwrap();
        std::fs::write(&paths.primary, b"corrupt").unwrap();

        commit_cache_at(&cache_config(3), &paths).unwrap();
        assert_eq!(
            read_valid_cache(&paths.backup).unwrap().listeners[0].rule_id,
            1,
            "a corrupt primary must not replace the healthy backup"
        );
        cleanup_cache(&paths);
    }

    #[test]
    fn missing_primary_is_repaired_from_backup_without_changing_backup() {
        let paths = cache_paths_for_test("repair-missing-primary");
        commit_cache_at(&cache_config(1), &paths).unwrap();
        commit_cache_at(&cache_config(2), &paths).unwrap();
        let backup = std::fs::read(&paths.backup).unwrap();
        std::fs::remove_file(&paths.primary).unwrap();

        let loaded = load_cache_state_at(&paths).unwrap();
        assert_eq!(loaded.source, CacheRecoverySource::RepairedFromBackup);
        assert_eq!(std::fs::read(&paths.primary).unwrap(), backup);
        assert_eq!(std::fs::read(&paths.backup).unwrap(), backup);
        cleanup_cache(&paths);
    }

    #[test]
    fn corrupt_primary_and_stale_tmp_use_backup_and_repair_primary() {
        let paths = cache_paths_for_test("repair-corrupt-primary");
        commit_cache_at(&cache_config(1), &paths).unwrap();
        commit_cache_at(&cache_config(2), &paths).unwrap();
        let backup = std::fs::read(&paths.backup).unwrap();
        std::fs::write(&paths.primary, b"corrupt").unwrap();
        std::fs::write(&paths.tmp, b"valid-looking-but-uncommitted").unwrap();

        let loaded = load_cache_state_at(&paths).unwrap();
        assert_eq!(loaded.source, CacheRecoverySource::RepairedFromBackup);
        assert_eq!(std::fs::read(&paths.primary).unwrap(), backup);
        assert_eq!(std::fs::read(&paths.backup).unwrap(), backup);
        assert!(!paths.tmp.exists());
        cleanup_cache(&paths);
    }

    #[test]
    fn failed_primary_repair_keeps_backup_available() {
        let paths = cache_paths_for_test("repair-failure");
        commit_cache_at(&cache_config(1), &paths).unwrap();
        commit_cache_at(&cache_config(2), &paths).unwrap();
        let backup = std::fs::read(&paths.backup).unwrap();
        std::fs::remove_file(&paths.primary).unwrap();
        std::fs::create_dir(&paths.primary).unwrap();

        let loaded = load_cache_state_at(&paths).unwrap();
        assert_eq!(loaded.source, CacheRecoverySource::BackupFallback);
        assert_eq!(std::fs::read(&paths.backup).unwrap(), backup);
        std::fs::remove_dir(&paths.primary).unwrap();
        cleanup_cache(&paths);
    }

    #[test]
    fn valid_tmp_is_never_promoted_without_primary_or_backup() {
        let paths = cache_paths_for_test("tmp-not-authority");
        std::fs::create_dir_all(paths.primary.parent().unwrap()).unwrap();
        std::fs::write(&paths.primary, b"corrupt-primary").unwrap();
        std::fs::write(&paths.backup, b"corrupt-backup").unwrap();
        std::fs::write(&paths.tmp, serde_json::to_vec(&cache_config(9)).unwrap()).unwrap();

        assert!(load_cache_state_at(&paths).is_none());
        assert!(!paths.tmp.exists());
        cleanup_cache(&paths);
    }

    #[test]
    fn fault_injection_restart_before_and_after_lkg_rename_preserves_authority() {
        let paths = cache_paths_for_test("fault-lkg-rename");
        let old = cache_config(1);
        let new = cache_config(2);
        commit_cache_with_metadata_at(
            &old,
            &paths,
            10,
            relay_shared::reconciliation::config_fingerprint(&old).as_str(),
        )
        .unwrap();

        // 模拟新快照已经 durable 写入 tmp、但进程在 rename 前退出。tmp 不是
        // 权威状态，重启必须继续加载旧 primary LKG，并清理未提交结果。
        let new_fingerprint = relay_shared::reconciliation::config_fingerprint(&new);
        let uncommitted = NodeConfigSnapshot {
            config_revision: 11,
            config_fingerprint: new_fingerprint.as_str().to_string(),
            config: new.clone(),
        };
        std::fs::write(&paths.tmp, serde_json::to_vec_pretty(&uncommitted).unwrap()).unwrap();
        let before_rename = load_cache_state_at(&paths).unwrap();
        assert_eq!(before_rename.config.listeners[0].rule_id, 1);
        assert_eq!(before_rename.config_revision, 10);
        assert!(!paths.tmp.exists());

        // 模拟 rename 与父目录 fsync 已完成后退出。重启必须加载新 primary，
        // 同时保留旧 primary 作为 backup，而不是回退或进入 Unknown。
        commit_cache_with_metadata_at(&new, &paths, 11, new_fingerprint.as_str()).unwrap();
        let after_rename = load_cache_state_at(&paths).unwrap();
        assert_eq!(after_rename.config.listeners[0].rule_id, 2);
        assert_eq!(after_rename.config_revision, 11);
        assert_eq!(
            read_valid_cache(&paths.backup).unwrap().listeners[0].rule_id,
            1
        );
        assert!(!paths.tmp.exists());
        cleanup_cache(&paths);
    }

    #[tokio::test]
    async fn runtime_apply_can_remain_healthy_when_lkg_commit_fails() {
        let paths = cache_paths_for_test("runtime-lkg-pending");
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        )));
        std::fs::create_dir_all(paths.primary.parent().unwrap()).unwrap();
        std::fs::create_dir(&paths.tmp).unwrap();
        let config = cache_config(12);
        let mut config = config;
        config.listeners[0].port = port;

        assert!(!apply_and_commit_at(&manager, &config, &paths).await);
        assert!(manager
            .lock()
            .await
            .listener_info_for_rule_tcp(config.listeners[0].rule_id)
            .is_some());
        assert!(paths.tmp.is_dir());
        std::fs::remove_dir(&paths.tmp).unwrap();
        cleanup_cache(&paths);
    }

    fn camouflage_site(sni: &str) -> relay_shared::protocol::CamouflageSiteDesired {
        relay_shared::protocol::CamouflageSiteDesired {
            site_id: sni.replace('.', "_"),
            sni: sni.into(),
            tls_listener_port: 8443,
            local_backend: relay_shared::protocol::CamouflageLocalBackend::OpenList,
            certificate: relay_shared::protocol::CamouflageCertificatePolicy {
                domain: sni.into(),
                expected_public_ip: "203.0.113.10".into(),
                renew_before_days: 30,
                challenge_method: Default::default(),
            },
            enabled: true,
        }
    }

    #[test]
    fn wildcard_certificate_domain_covering_sni_is_valid_config() {
        let mut site = camouflage_site("p1.13886.xyz");
        site.certificate.domain = "*.13886.xyz".into();
        let config = NodeConfigResponse {
            camouflage_sites: vec![site],
            listeners: vec![],
        };

        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn wildcard_certificate_domain_does_not_cover_nested_sni() {
        let mut site = camouflage_site("deep.p1.13886.xyz");
        site.certificate.domain = "*.13886.xyz".into();
        let config = NodeConfigResponse {
            camouflage_sites: vec![site],
            listeners: vec![],
        };

        assert_eq!(
            validate_config(&config).unwrap_err(),
            "invalid camouflage desired state"
        );
    }

    fn dependent_listener(
        rule_id: i64,
        sni: &str,
        target: &str,
    ) -> relay_shared::protocol::ListenerConfig {
        relay_shared::protocol::ListenerConfig {
            camouflage_required: true,
            send_proxy_protocol: false,
            rule_id,
            port: 443,
            protocol: relay_shared::protocol::Protocol::Tcp,
            node_transport: NodeTransport::NginxSni,
            ws_path: None,
            sni: Some(sni.into()),
            targets: vec![target.into()],
            load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
        }
    }

    #[test]
    fn new_route_is_withheld_until_camouflage_is_active() {
        let desired = NodeConfigResponse {
            camouflage_sites: vec![camouflage_site("op1.example.com")],
            listeners: vec![dependent_listener(
                1,
                "op1.example.com",
                "198.51.100.1:55443",
            )],
        };
        let (waiting, refs, withheld) = build_effective_config(&desired, None, &Default::default());
        assert!(waiting.listeners.is_empty());
        assert!(refs.is_empty());
        assert!(withheld);

        let active = std::collections::HashSet::from(["op1.example.com".to_string()]);
        let (ready, refs, withheld) = build_effective_config(&desired, None, &active);
        assert_eq!(ready.listeners.len(), 1);
        assert!(refs.contains("op1.example.com"));
        assert!(!withheld);
    }

    #[test]
    fn preparing_second_sni_does_not_disturb_active_route_on_shared_port() {
        let desired = NodeConfigResponse {
            camouflage_sites: vec![
                camouflage_site("op1.example.com"),
                camouflage_site("op2.example.com"),
            ],
            listeners: vec![
                dependent_listener(1, "op1.example.com", "198.51.100.1:55443"),
                dependent_listener(2, "op2.example.com", "198.51.100.2:55443"),
            ],
        };
        let active = std::collections::HashSet::from(["op1.example.com".to_string()]);

        let (effective, refs, withheld) = build_effective_config(&desired, None, &active);

        assert_eq!(effective.listeners.len(), 1);
        assert_eq!(effective.listeners[0].rule_id, 1);
        assert_eq!(effective.listeners[0].port, 443);
        assert_eq!(
            effective.listeners[0].sni.as_deref(),
            Some("op1.example.com")
        );
        assert_eq!(effective.listeners[0].targets, vec!["198.51.100.1:55443"]);
        assert_eq!(effective.camouflage_sites.len(), 2);
        assert_eq!(
            refs,
            std::collections::HashSet::from(["op1.example.com".to_string()])
        );
        assert!(validate_config(&effective).is_ok());
        assert!(withheld);
    }

    #[test]
    fn failed_sni_change_preserves_previous_route_until_new_site_is_active() {
        let previous = NodeConfigResponse {
            camouflage_sites: vec![camouflage_site("old.example.com")],
            listeners: vec![dependent_listener(
                7,
                "old.example.com",
                "198.51.100.1:55443",
            )],
        };
        let desired = NodeConfigResponse {
            camouflage_sites: vec![camouflage_site("new.example.com")],
            listeners: vec![dependent_listener(
                7,
                "new.example.com",
                "198.51.100.2:55444",
            )],
        };
        let active = std::collections::HashSet::from(["old.example.com".to_string()]);
        let (effective, refs, withheld) =
            build_effective_config(&desired, Some(&previous), &active);
        assert_eq!(effective.listeners.len(), 1);
        assert_eq!(
            effective.listeners[0].sni.as_deref(),
            Some("old.example.com")
        );
        assert_eq!(effective.listeners[0].targets, vec!["198.51.100.1:55443"]);
        assert!(refs.contains("old.example.com"));
        assert_eq!(effective.camouflage_sites.len(), 2);
        assert!(effective
            .camouflage_sites
            .iter()
            .any(|site| site.sni == "old.example.com"));
        assert!(validate_config(&effective).is_ok());
        assert!(withheld);
    }

    #[test]
    fn delete_removes_route_before_site_finalization() {
        let previous = NodeConfigResponse {
            camouflage_sites: vec![camouflage_site("op1.example.com")],
            listeners: vec![dependent_listener(
                9,
                "op1.example.com",
                "198.51.100.1:55443",
            )],
        };
        let desired = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![],
        };
        let active = std::collections::HashSet::from(["op1.example.com".to_string()]);
        let (effective, refs, withheld) =
            build_effective_config(&desired, Some(&previous), &active);
        assert!(effective.listeners.is_empty());
        assert!(
            refs.is_empty(),
            "site removal is finalized only after this route apply"
        );
        assert!(!withheld);
    }

    #[test]
    fn cache_round_trip_preserves_config_revision_and_fingerprint() {
        let dir = unique_dir("cache-revision");
        let paths = CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        let config = cache_config(77);
        let fingerprint = relay_shared::reconciliation::config_fingerprint(&config);
        commit_cache_with_metadata_at(&config, &paths, 12, fingerprint.as_str()).unwrap();
        let loaded = load_cache_state_at(&paths).expect("revision-bearing cache");
        assert_eq!(loaded.config_revision, 12);
        assert_eq!(loaded.config_fingerprint, fingerprint);
        let _ = fs::remove_dir_all(dir);
    }
}
