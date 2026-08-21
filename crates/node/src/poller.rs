use crate::config::NodeConfig;
use crate::forwarder::ForwarderManager;
use relay_shared::protocol::{NodeConfigResponse, NodeTransport, CONFIG_PROTOCOL_VERSION};
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
    Ok(NodeConfigResponse),
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

    match resp.json::<NodeConfigResponse>().await {
        Ok(cfg) if validate_config(&cfg).is_ok() => FetchResult::Ok(cfg),
        Ok(e) => {
            tracing::warn!(
                "fetch_config: response validation failed: {}",
                validate_config(&e).unwrap_err()
            );
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

/// Apply first, then commit the snapshot as LKG while holding the same manager
/// mutex. HTTP polls and WebSocket snapshots both use this path so an older
/// snapshot cannot finish its cache write after a newer one.
pub async fn apply_and_commit(
    manager: &Arc<Mutex<ForwarderManager>>,
    config: &NodeConfigResponse,
) -> bool {
    apply_and_commit_at(manager, config, &cache_paths()).await
}

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
pub fn load_cache() -> Option<NodeConfigResponse> {
    load_cache_at(&cache_paths())
}

pub(crate) fn load_cache_at(paths: &CachePaths) -> Option<NodeConfigResponse> {
    for path in [&paths.primary, &paths.backup] {
        match read_valid_cache(path) {
            Ok(config) => {
                tracing::info!(
                    "Loaded cached config from {} ({} listeners)",
                    path.display(),
                    config.listeners.len()
                );
                return Some(config);
            }
            Err(e) => {
                tracing::warn!("cached config {} unavailable: {}", path.display(), e);
            }
        }
    }
    tracing::warn!("no usable cached config; waiting for panel configuration");
    None
}

pub(crate) fn commit_cache_at(
    config: &NodeConfigResponse,
    paths: &CachePaths,
) -> Result<(), String> {
    validate_config(config)?;
    let json = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    // Validate the serialized representation before it can replace any LKG.
    let _: NodeConfigResponse = serde_json::from_slice(&json).map_err(|e| e.to_string())?;

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

fn validate_config(config: &NodeConfigResponse) -> Result<(), String> {
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
    Ok(())
}

fn read_valid_cache(path: &Path) -> Result<NodeConfigResponse, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let config = serde_json::from_slice::<NodeConfigResponse>(&data).map_err(|e| e.to_string())?;
    validate_config(&config)?;
    Ok(config)
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
            listeners: vec![relay_shared::protocol::ListenerConfig {
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
        let empty = NodeConfigResponse { listeners: vec![] };

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
            listeners: vec![relay_shared::protocol::ListenerConfig {
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
                .apply_config(&NodeConfigResponse { listeners: vec![] })
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
}
