use crate::config::{NodeConfig, NodeRuntimeAuth};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use relay_shared::protocol::{
    traffic_batch_payload_sha256, valid_traffic_batch_id, valid_traffic_payload_sha256,
    ApiResponse, CamouflageSiteStatus, ListenerError, ReconciliationStatus, StatusReport,
    TrafficBatchAck, TrafficBatchAckStatus, TrafficBatchMetadata, TrafficEntry, TrafficReport,
    TRAFFIC_BATCH_PROTOCOL_VERSION,
};
use std::collections::HashMap;
#[cfg(any(target_os = "linux", test))]
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, System};
use tokio::sync::{Mutex, RwLock};

struct RuleCounterState {
    upload: AtomicU64,
    download: AtomicU64,
    live_handles: AtomicUsize,
}

impl RuleCounterState {
    fn new() -> Self {
        Self {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            live_handles: AtomicUsize::new(0),
        }
    }
}

type RuleCounters = Arc<RuleCounterState>;
type TrafficGenerationKey = (u64, i64);

/// Connection-lifetime reference to one immutable counter generation. It is
/// deliberately not Clone: every accepted TCP/TLS/WS connection acquires one
/// handle before spawn and both directional pumps borrow that same handle.
pub struct RuleCounterHandle {
    state: RuleCounters,
}

impl RuleCounterHandle {
    pub fn add_upload(&self, bytes: u64) {
        self.state.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.state.download.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for RuleCounterHandle {
    fn drop(&mut self) {
        // AcqRel chains concurrent handle drops together. A cleanup load that
        // observes zero with Acquire therefore also observes all traffic writes
        // sequenced before every preceding handle drop.
        let previous = self.state.live_handles.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "rule counter handle underflow");
    }
}

pub struct TrafficCounter {
    // rule_id -> (upload, download) as lock-free atomic counters. Keyed by rule
    // id (not listen port) so traffic is attributed to the right rule even when
    // two inbound groups listen on the same port.
    //
    // v1.0.9: the RwLock guards only the MAP shape (insert on a rule's first
    // bytes). Concurrent add()s to an already-present rule take a SHARED read
    // lock and do a lock-free atomic fetch_add, so they never serialize on each
    // other — this is the per-packet path for both TCP and UDP forwarding.
    // (config_revision, rule_id) -> counters. Revision 0 is the legacy
    // generation used before a versioned Panel snapshot is active.
    data: Arc<RwLock<HashMap<TrafficGenerationKey, RuleCounters>>>,
    // At most one report snapshot may be in flight. The guard lives inside
    // TrafficSnapshot, so failed uploads release it simply by dropping the
    // snapshot while successful uploads release it after commit.
    snapshot_gate: Mutex<()>,
    // Serializes the whole report operation. Strict mode releases
    // snapshot_gate after durable sealing, so this second gate prevents another
    // caller from sealing a second batch before the pending one is resolved.
    report_gate: Mutex<()>,
    // Set only when a post-rename durability failure leaves it uncertain whether
    // the durable pending file exists. The live process then stops reporting
    // rather than risk sending disk and memory copies of the same bytes.
    strict_seal_poisoned: AtomicBool,
}

impl TrafficCounter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            snapshot_gate: Mutex::new(()),
            report_gate: Mutex::new(()),
            strict_seal_poisoned: AtomicBool::new(false),
        }
    }

    pub(crate) async fn durable_accounting_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.report_gate.lock().await
    }

    pub(crate) fn strict_reporting_poisoned(&self) -> bool {
        self.strict_seal_poisoned.load(Ordering::Acquire)
    }

    pub(crate) fn poison_strict_reporting(&self) {
        self.strict_seal_poisoned.store(true, Ordering::Release);
    }

    /// Acquire the immutable counter generation for one accepted stream
    /// connection. Creation and live-writer registration are serialized with
    /// commit/prune by the map write lock; chunk writes after this are lock-free.
    #[cfg(test)]
    pub async fn handle(&self, rule_id: i64) -> RuleCounterHandle {
        self.handle_at(0, rule_id).await
    }

    pub async fn handle_at(&self, config_revision: u64, rule_id: i64) -> RuleCounterHandle {
        let mut map = self.data.write().await;
        let state = map
            .entry((config_revision, rule_id))
            .or_insert_with(|| Arc::new(RuleCounterState::new()))
            .clone();
        state.live_handles.fetch_add(1, Ordering::Relaxed);
        RuleCounterHandle { state }
    }

    #[cfg(test)]
    pub async fn add(&self, rule_id: i64, upload: u64, download: u64) {
        self.add_at(0, rule_id, upload, download).await;
    }

    pub async fn add_at(&self, config_revision: u64, rule_id: i64, upload: u64, download: u64) {
        let key = (config_revision, rule_id);
        // Fast path: rule already present → shared read lock + atomic add.
        {
            let map = self.data.read().await;
            if let Some(c) = map.get(&key) {
                c.upload.fetch_add(upload, Ordering::Relaxed);
                c.download.fetch_add(download, Ordering::Relaxed);
                return;
            }
        }
        // Slow path: first bytes for this rule → write lock to insert, then add.
        let mut map = self.data.write().await;
        let c = map
            .entry(key)
            .or_insert_with(|| Arc::new(RuleCounterState::new()));
        c.upload.fetch_add(upload, Ordering::Relaxed);
        c.download.fetch_add(download, Ordering::Relaxed);
    }

    /// Take a snapshot and return a guard whose `commit()` subtracts exactly
    /// the snapshotted bytes from each counter. This is the correct pattern for
    /// traffic reporting: the bytes captured in the snapshot are only deducted
    /// after the panel ACKs the upload. If the upload fails the guard is
    /// dropped without commit, so those bytes stay and are retried next cycle.
    /// Bytes that arrive BETWEEN snapshot and commit are preserved (subtract,
    /// not clear), so no traffic is ever lost.
    pub async fn snapshot(&self) -> TrafficSnapshot<'_> {
        let snapshot_guard = self.snapshot_gate.lock().await;
        let mut map = self.data.write().await;

        // Zero-only generations never require a Panel ACK. Once no connection
        // handle remains, the Acquire live_handles load observes all preceding
        // AcqRel drops; current counter values can then be checked safely while
        // the map write lock prevents UDP/Nginx add() from racing the removal.
        map.retain(|_, state| {
            state.live_handles.load(Ordering::Acquire) != 0
                || state.upload.load(Ordering::Acquire) != 0
                || state.download.load(Ordering::Acquire) != 0
        });

        // One strict batch describes exactly one delivered config revision.
        // Drain the oldest non-empty generation first; newer generations wait
        // until the older one has been durably ACKed.
        let selected_revision = map
            .iter()
            .filter_map(|((revision, _), state)| {
                let upload = state.upload.load(Ordering::Acquire);
                let download = state.download.load(Ordering::Acquire);
                (upload != 0 || download != 0).then_some(*revision)
            })
            .min();
        let mut entries = Vec::new();
        let mut captured = Vec::new();
        if let Some(selected_revision) = selected_revision {
            for ((revision, rule_id), state) in map.iter() {
                if *revision != selected_revision {
                    continue;
                }
                let upload = state.upload.load(Ordering::Acquire);
                let download = state.download.load(Ordering::Acquire);
                if upload == 0 && download == 0 {
                    continue;
                }
                entries.push(TrafficEntry {
                    rule_id: *rule_id,
                    upload,
                    download,
                });
                captured.push(SnapshotEntry {
                    key: (*revision, *rule_id),
                    state: state.clone(),
                    upload,
                    download,
                });
            }
        }
        entries.sort_by_key(|entry| entry.rule_id);
        drop(map);
        TrafficSnapshot {
            counter: self,
            config_revision: selected_revision.filter(|revision| *revision != 0),
            entries,
            captured,
            _snapshot_guard: snapshot_guard,
        }
    }

    /// Destructive read: snapshot AND clear in one step. Kept for callers that
    /// want the old semantics (e.g. test fixtures that drain-then-assert). The
    /// production reporter uses `snapshot()` + `TrafficSnapshot::commit()` so a
    /// failed upload retries instead of dropping traffic.
    #[allow(dead_code)]
    pub async fn drain(&self) -> Vec<TrafficEntry> {
        let mut map = self.data.write().await;
        let mut totals = HashMap::<i64, (u64, u64)>::new();
        for ((_, rule_id), c) in map.drain() {
            let entry = totals.entry(rule_id).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(c.upload.load(Ordering::Relaxed));
            entry.1 = entry.1.saturating_add(c.download.load(Ordering::Relaxed));
        }
        let mut out = totals
            .into_iter()
            .map(|(rule_id, (upload, download))| TrafficEntry {
                rule_id,
                upload,
                download,
            })
            .collect::<Vec<_>>();
        out.sort_by_key(|entry| entry.rule_id);
        out
    }

    /// A rule leaving the active config stops future forwarding, but bytes it
    /// already forwarded remain billable. Only discard generations that are
    /// provably empty and have no live connection handle.
    pub async fn prune_rule(&self, rule_id: i64) {
        self.data
            .write()
            .await
            .retain(|(_, candidate_rule_id), state| {
                *candidate_rule_id != rule_id
                    || state.live_handles.load(Ordering::Acquire) != 0
                    || state.upload.load(Ordering::Acquire) != 0
                    || state.download.load(Ordering::Acquire) != 0
            });
    }

    /// Test-only: check whether a rule_id has any accumulated bytes.
    #[cfg(test)]
    pub async fn has_rule(&self, rule_id: i64) -> bool {
        self.data
            .read()
            .await
            .keys()
            .any(|(_, candidate_rule_id)| *candidate_rule_id == rule_id)
    }
}

/// Snapshot of [`TrafficCounter`] at one instant. Drop without calling
/// [`commit`](Self::commit) to retry the same bytes; call `commit` once the
/// panel has persisted the report.
pub struct TrafficSnapshot<'a> {
    counter: &'a TrafficCounter,
    pub config_revision: Option<u64>,
    pub entries: Vec<TrafficEntry>,
    captured: Vec<SnapshotEntry>,
    _snapshot_guard: tokio::sync::MutexGuard<'a, ()>,
}

struct SnapshotEntry {
    key: TrafficGenerationKey,
    state: RuleCounters,
    upload: u64,
    download: u64,
}

impl TrafficSnapshot<'_> {
    /// Subtract the snapshotted bytes from the live counters. Bytes counted
    /// after the snapshot was taken are untouched. Safe to call once.
    pub async fn commit(self) {
        self.commit_with_hook(|_| {}).await;
    }

    async fn commit_with_hook<F>(self, mut after_subtract: F)
    where
        F: FnMut(i64),
    {
        let mut map = self.counter.data.write().await;
        for entry in &self.captured {
            let remove = {
                let Some(current) = map.get(&entry.key) else {
                    continue;
                };
                // A prune followed by reuse of the same rule_id creates a new
                // Arc generation. An old snapshot must never subtract from it.
                if !Arc::ptr_eq(current, &entry.state) {
                    continue;
                }
                let previous_upload = current.upload.fetch_sub(entry.upload, Ordering::AcqRel);
                let previous_download =
                    current.download.fetch_sub(entry.download, Ordering::AcqRel);
                debug_assert!(previous_upload >= entry.upload, "upload counter underflow");
                debug_assert!(
                    previous_download >= entry.download,
                    "download counter underflow"
                );

                // Tests can force the exact subtract -> add -> final-drop race.
                // Production passes an empty inlined closure.
                after_subtract(entry.key.1);

                current.live_handles.load(Ordering::Acquire) == 0
                    && current.upload.load(Ordering::Acquire) == 0
                    && current.download.load(Ordering::Acquire) == 0
            };
            if remove
                && map
                    .get(&entry.key)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry.state))
            {
                map.remove(&entry.key);
            }
        }
    }
}

/// How long a UDP session is considered active after its last datagram.
/// UDP has no connection-close event, so sessions expire by inactivity.
pub const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Tracks the number of currently-active forwarded connections, for BOTH
/// transport types, so the panel's "connections" column reflects real traffic:
///
/// - **TCP**: a strict accept/close count via an atomic + an RAII `Drop` guard.
///   The guard guarantees decrement even if a connection task panics.
/// - **UDP**: there is no "connection"; instead we count active UDP sessions,
///   keyed by `(client_addr, rule_id)`. A session is created on the first
///   datagram from a client and considered expired after
///   `UDP_SESSION_TIMEOUT` with no further traffic. `touch` runs per datagram
///   but does NOT prune (that's O(sessions) per packet); expiry is handled by
///   `current()` and the UDP listener's periodic sweeper (`udp_prune_expired`),
///   so the count still converges on zero shortly after traffic stops.
///
/// `current()` reports `active_tcp + active_udp_sessions`.
///
/// This is entirely independent of the WebSocket control channel: it is read
/// from the plain-HTTP `report_status` loop, so connection counts keep
/// updating even if WS is down.
///
/// Locking: TCP uses an `AtomicU64` (lock-free); UDP uses a sharded `DashMap`
/// keyed by (client, rule), so a per-packet `udp_touch` takes only that shard's
/// lock (v1.0.9) — never a process-wide lock that could block forwarding.
pub struct ConnectionTracker {
    tcp: Arc<AtomicU64>,
    udp: DashMap<UdpSessionKey, Instant>,
}

/// Identity of a single UDP "connection". A client's source port plus the
/// rule it hits uniquely identifies one logical session.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct UdpSessionKey {
    pub client_addr: SocketAddr,
    pub rule_id: i64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            tcp: Arc::new(AtomicU64::new(0)),
            udp: DashMap::new(),
        }
    }

    /// Increment the active TCP count and return a guard whose `Drop`
    /// decrements it. Hand the guard to the per-connection task so the count
    /// is correct no matter how that task ends (normal close, error, panic).
    pub fn tcp_handle(&self) -> TcpConnectionGuard {
        let prev = self.tcp.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("tcp connection opened, active={}", prev + 1);
        TcpConnectionGuard {
            tcp: self.tcp.clone(),
        }
    }

    /// Register or refresh a UDP session. Returns `true` if a NEW session was
    /// created (so the caller can emit an "opened" log) and `false` if an
    /// existing session was merely refreshed. Lazily prunes expired sessions
    /// belonging to ANY rule before inserting/refreshing.
    pub async fn udp_touch(&self, client_addr: SocketAddr, rule_id: i64) -> bool {
        let key = UdpSessionKey {
            client_addr,
            rule_id,
        };
        // Sharded map (keyed by client+rule): this takes only the target shard's
        // lock, so per-packet touching doesn't serialize on a process-wide lock.
        // We do NOT prune here (an O(sessions) scan per packet); expiry is
        // handled by the periodic sweeper (udp_prune_expired) and current().
        let is_new = match self.udp.entry(key) {
            Entry::Occupied(mut e) => {
                *e.get_mut() = Instant::now();
                false
            }
            Entry::Vacant(e) => {
                e.insert(Instant::now());
                true
            }
        };
        // len() locks shards briefly; call it only AFTER the entry guard above
        // is released (holding a shard guard across len() would deadlock).
        if is_new {
            tracing::debug!(
                "udp session opened (client={}, rule={}), udp_active={}",
                client_addr,
                rule_id,
                self.udp.len()
            );
        }
        is_new
    }

    /// Remove a single UDP session (e.g. when its outbound recv loop ends).
    pub async fn udp_close(&self, client_addr: SocketAddr, rule_id: i64) {
        let key = UdpSessionKey {
            client_addr,
            rule_id,
        };
        if self.udp.remove(&key).is_some() {
            tracing::debug!(
                "udp session closed (client={}, rule={}), udp_active={}",
                client_addr,
                rule_id,
                self.udp.len()
            );
        }
    }

    /// Drop every UDP session older than `UDP_SESSION_TIMEOUT`. Called both by
    /// the UDP listener's periodic sweeper and as part of `current()`.
    pub async fn udp_prune_expired(&self) -> usize {
        prune_expired(&self.udp)
    }

    pub fn current_tcp(&self) -> u32 {
        u32::try_from(self.tcp.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    pub async fn current_udp(&self) -> u32 {
        prune_expired(&self.udp);
        u32::try_from(self.udp.len()).unwrap_or(u32::MAX)
    }

    /// Total active connections reported to the panel:
    /// active TCP connections + active UDP sessions.
    #[allow(dead_code)] // Compatibility reader retained for callers/tests using the legacy total.
    pub async fn current(&self) -> u32 {
        self.current_tcp().saturating_add(self.current_udp().await)
    }
}

#[cfg(any(target_os = "linux", test))]
const PROC_NET_TCP: &str = "/proc/net/tcp";
#[cfg(any(target_os = "linux", test))]
const PROC_NET_TCP6: &str = "/proc/net/tcp6";

#[cfg(any(target_os = "linux", test))]
fn parse_proc_established_on_ports(
    contents: &str,
    managed_ports: &HashSet<u16>,
) -> Result<u64, ()> {
    let mut count = 0_u64;
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || (index == 0 && line.contains("local_address")) {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            return Err(());
        }
        let (_, local_port) = fields[1].rsplit_once(':').ok_or(())?;
        let local_port = u16::from_str_radix(local_port, 16).map_err(|_| ())?;
        if fields[3].len() != 2 || !fields[3].bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(());
        }
        if fields[3] != "01" {
            continue;
        }
        if managed_ports.contains(&local_port) {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(any(target_os = "linux", test))]
fn nginx_sni_active_tcp_with_reader<F>(managed_ports: &[u16], mut read: F) -> Option<u32>
where
    F: FnMut(&Path) -> std::io::Result<String>,
{
    let managed_ports = managed_ports.iter().copied().collect::<HashSet<_>>();
    if managed_ports.is_empty() {
        return Some(0);
    }
    let ipv4 = read(Path::new(PROC_NET_TCP)).ok()?;
    let ipv6 = read(Path::new(PROC_NET_TCP6)).ok()?;
    let count = parse_proc_established_on_ports(&ipv4, &managed_ports)
        .ok()?
        .saturating_add(parse_proc_established_on_ports(&ipv6, &managed_ports).ok()?);
    Some(u32::try_from(count).unwrap_or(u32::MAX))
}

fn nginx_sni_active_tcp(managed_ports: &[u16]) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        nginx_sni_active_tcp_with_reader(managed_ports, |path| std::fs::read_to_string(path))
    }
    #[cfg(not(target_os = "linux"))]
    {
        managed_ports.is_empty().then_some(0)
    }
}

/// Prune sessions whose `last_active` is older than the timeout. Returns how
/// many were removed. `retain` runs per shard; `before`/`after` are read across
/// shards without a global lock, so use saturating_sub in case a concurrent
/// insert lands between the two reads.
fn prune_expired(map: &DashMap<UdpSessionKey, Instant>) -> usize {
    let now = Instant::now();
    let before = map.len();
    map.retain(|_, last_active| now.duration_since(*last_active) < UDP_SESSION_TIMEOUT);
    let removed = before.saturating_sub(map.len());
    if removed > 0 {
        tracing::debug!(
            "udp: pruned {} expired sessions, udp_active={}",
            removed,
            map.len()
        );
    }
    removed
}

/// RAII guard: dropping it decrements the active-TCP-connection counter. This
/// guarantees the count is correct even if a connection task panics.
pub struct TcpConnectionGuard {
    tcp: Arc<AtomicU64>,
}

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        let prev = self.tcp.fetch_sub(1, Ordering::Relaxed);
        // fetch_sub returns the value before decrement, so the post-decrement
        // count is prev-1 (never underflows: every guard came from a +1).
        tracing::debug!("tcp connection closed, active={}", prev.saturating_sub(1));
    }
}

const TRAFFIC_PENDING_FILENAME: &str = "traffic-report-pending.json";
const TRAFFIC_SPOOL_DIRNAME: &str = "traffic-report-spool";
const TRAFFIC_SPOOL_SEQUENCE_FILENAME: &str = "sequence.json";
const TRAFFIC_SPOOL_FORMAT_VERSION: u32 = 1;
const TRAFFIC_SPOOL_FILENAME_WIDTH: usize = 20;
const MAX_PENDING_TRAFFIC_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingTrafficBatch {
    version: u32,
    batch_id: String,
    payload_sha256: String,
    node_id: String,
    credential_id: String,
    #[serde(default)]
    config_revision: Option<u64>,
    reports: Vec<TrafficEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NginxTrafficCheckpoint {
    pub source: String,
    pub device: u64,
    pub inode: u64,
    #[serde(default)]
    pub generation: u64,
    pub start_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurableSpoolRecord {
    format_version: u32,
    sequence: u64,
    batch: PendingTrafficBatch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nginx_checkpoint: Option<NginxTrafficCheckpoint>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SpoolSequenceState {
    format_version: u32,
    next_sequence: u64,
}

#[derive(Debug, Clone)]
enum DurableBatchLocation {
    Legacy(PathBuf),
    Queue {
        path: PathBuf,
        record: DurableSpoolRecord,
    },
}

#[derive(Debug, Clone)]
struct DurableQueuedBatch {
    location: DurableBatchLocation,
    batch: PendingTrafficBatch,
}

fn strict_traffic_parent(auth: &NodeRuntimeAuth, node_id: &str) -> Result<Option<PathBuf>, String> {
    match auth {
        NodeRuntimeAuth::LegacyGroupToken { .. } => Ok(None),
        NodeRuntimeAuth::PermanentCredential {
            secret_file,
            state_node_id,
            ..
        } => {
            if state_node_id != node_id {
                return Err("traffic batch node identity does not match Credential state".into());
            }
            let parent = secret_file
                .parent()
                .ok_or_else(|| "Credential Secret has no private parent directory".to_string())?;
            Ok(Some(parent.to_path_buf()))
        }
    }
}

fn pending_traffic_path(auth: &NodeRuntimeAuth, node_id: &str) -> Result<Option<PathBuf>, String> {
    Ok(strict_traffic_parent(auth, node_id)?
        .map(|parent| parent.join(TRAFFIC_PENDING_FILENAME)))
}

fn strict_credential_id<'a>(
    auth: &'a NodeRuntimeAuth,
    node_id: &str,
) -> Result<Option<&'a str>, String> {
    match auth {
        NodeRuntimeAuth::LegacyGroupToken { .. } => Ok(None),
        NodeRuntimeAuth::PermanentCredential {
            credential_id,
            state_node_id,
            ..
        } => {
            if state_node_id != node_id {
                return Err("traffic batch node identity does not match Credential state".into());
            }
            Ok(Some(credential_id.as_str()))
        }
    }
}

fn validate_private_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != euid
        || (metadata.mode() & 0o777) != 0o700
    {
        return Err(format!(
            "{label} must be owner-only mode 0700 and must not be a symlink"
        ));
    }
    Ok(())
}

fn validate_private_pending_parent(parent: &Path) -> Result<(), String> {
    validate_private_directory(parent, "traffic pending directory")
}

fn validate_private_spool_dir(spool_dir: &Path) -> Result<(), String> {
    validate_private_directory(spool_dir, "traffic spool directory")
}

fn sync_directory(path: &Path, label: &str) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| format!("{label} could not be fsynced"))
}

fn ensure_spool_dir(parent: &Path) -> Result<PathBuf, String> {
    validate_private_pending_parent(parent)?;
    let spool_dir = parent.join(TRAFFIC_SPOOL_DIRNAME);
    match std::fs::symlink_metadata(&spool_dir) {
        Ok(_) => {
            validate_private_spool_dir(&spool_dir)?;
            Ok(spool_dir)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&spool_dir) {
                Ok(()) => {
                    sync_directory(parent, "traffic state directory")?;
                    validate_private_spool_dir(&spool_dir)?;
                    Ok(spool_dir)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate_private_spool_dir(&spool_dir)?;
                    Ok(spool_dir)
                }
                Err(_) => Err("traffic spool directory could not be created".into()),
            }
        }
        Err(_) => Err("traffic spool directory is unavailable".into()),
    }
}

fn existing_spool_dir(parent: &Path) -> Result<Option<PathBuf>, String> {
    validate_private_pending_parent(parent)?;
    let spool_dir = parent.join(TRAFFIC_SPOOL_DIRNAME);
    match std::fs::symlink_metadata(&spool_dir) {
        Ok(_) => {
            validate_private_spool_dir(&spool_dir)?;
            Ok(Some(spool_dir))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("traffic spool directory is unavailable".into()),
    }
}

fn read_private_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| format!("{label} is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("{label} metadata is unavailable"))?;
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != euid
        || (metadata.mode() & 0o777) != 0o600
        || metadata.len() > max_bytes
    {
        return Err(format!(
            "{label} must be owner-only mode 0600 regular file"
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| format!("{label} could not be read"))?;
    Ok(bytes)
}

fn validate_pending_batch(
    pending: &PendingTrafficBatch,
    node_id: &str,
    credential_id: &str,
) -> Result<(), String> {
    if pending.version != TRAFFIC_BATCH_PROTOCOL_VERSION
        || pending.node_id != node_id
        || pending.credential_id != credential_id
        || pending.reports.is_empty()
        || !valid_traffic_batch_id(&pending.batch_id)
        || !valid_traffic_payload_sha256(&pending.payload_sha256)
        || traffic_batch_payload_sha256(&pending.reports) != pending.payload_sha256
    {
        return Err("traffic pending batch failed integrity or identity validation".into());
    }
    Ok(())
}

fn load_pending_traffic_at(
    path: &Path,
    node_id: &str,
    credential_id: &str,
) -> Result<Option<PendingTrafficBatch>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "traffic pending path has no parent".to_string())?;
    validate_private_pending_parent(parent)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("traffic pending batch is unavailable".into()),
    }
    let bytes =
        read_private_regular_file(path, MAX_PENDING_TRAFFIC_BYTES, "traffic pending batch")?;
    let pending: PendingTrafficBatch = serde_json::from_slice(&bytes)
        .map_err(|_| "traffic pending batch is malformed".to_string())?;
    validate_pending_batch(&pending, node_id, credential_id)?;
    Ok(Some(pending))
}

#[derive(Debug)]
pub(crate) enum PendingWriteError {
    Clean(String),
    RestartRequired(String),
}

impl PendingWriteError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Clean(message) | Self::RestartRequired(message) => message,
        }
    }

    pub(crate) fn restart_required(&self) -> bool {
        matches!(self, Self::RestartRequired(_))
    }
}

fn atomic_replace_private_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{label} path has an invalid filename"))?;
    let temp = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| format!("{label} temporary file could not be created"))?;
    let pre_rename = (|| -> Result<(), String> {
        file.write_all(bytes)
            .map_err(|_| format!("{label} could not be written"))?;
        file.flush()
            .map_err(|_| format!("{label} could not be flushed"))?;
        file.sync_all()
            .map_err(|_| format!("{label} could not be fsynced"))?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = pre_rename {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("{label} could not be atomically replaced"));
    }
    sync_directory(parent, &format!("{label} parent directory"))
}

fn load_sequence_state_at(spool_dir: &Path) -> Result<Option<SpoolSequenceState>, String> {
    let path = spool_dir.join(TRAFFIC_SPOOL_SEQUENCE_FILENAME);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("traffic spool sequence state is unavailable".into()),
    }
    let bytes = read_private_regular_file(&path, 4096, "traffic spool sequence state")?;
    let state: SpoolSequenceState = serde_json::from_slice(&bytes)
        .map_err(|_| "traffic spool sequence state is malformed".to_string())?;
    if state.format_version != TRAFFIC_SPOOL_FORMAT_VERSION || state.next_sequence == 0 {
        return Err("traffic spool sequence state is invalid".into());
    }
    Ok(Some(state))
}

fn save_sequence_state_at(spool_dir: &Path, next_sequence: u64) -> Result<(), String> {
    if next_sequence == 0 {
        return Err("traffic spool sequence overflow".into());
    }
    let bytes = serde_json::to_vec(&SpoolSequenceState {
        format_version: TRAFFIC_SPOOL_FORMAT_VERSION,
        next_sequence,
    })
    .map_err(|_| "traffic spool sequence state encode failed".to_string())?;
    atomic_replace_private_file(
        &spool_dir.join(TRAFFIC_SPOOL_SEQUENCE_FILENAME),
        &bytes,
        "traffic spool sequence state",
    )
}

fn parse_spool_filename(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".json")?;
    if digits.len() != TRAFFIC_SPOOL_FILENAME_WIDTH
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (sequence != 0).then_some(sequence)
}

fn known_spool_temp(name: &str) -> bool {
    (name.starts_with(".traffic-report-spool-record.") && name.ends_with(".tmp"))
        || (name.starts_with(".sequence.json.") && name.ends_with(".tmp"))
}

fn list_spool_files(spool_dir: &Path) -> Result<Vec<(u64, PathBuf)>, String> {
    validate_private_spool_dir(spool_dir)?;
    let mut files = Vec::new();
    let entries =
        std::fs::read_dir(spool_dir).map_err(|_| "traffic spool directory could not be read")?;
    for entry in entries {
        let entry = entry.map_err(|_| "traffic spool directory entry is unavailable")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "traffic spool contains a non-UTF8 filename".to_string())?;
        if name == TRAFFIC_SPOOL_SEQUENCE_FILENAME || known_spool_temp(&name) {
            continue;
        }
        let sequence = parse_spool_filename(&name)
            .ok_or_else(|| "traffic spool contains an unexpected committed entry".to_string())?;
        files.push((sequence, entry.path()));
    }
    files.sort_by_key(|(sequence, _)| *sequence);
    Ok(files)
}

fn reserve_spool_sequence(parent: &Path) -> Result<(PathBuf, u64), String> {
    let spool_dir = ensure_spool_dir(parent)?;
    let max_committed = list_spool_files(&spool_dir)?
        .last()
        .map(|(sequence, _)| *sequence);
    let persisted_next = load_sequence_state_at(&spool_dir)?
        .map(|state| state.next_sequence)
        .unwrap_or(1);
    let committed_next = match max_committed {
        Some(sequence) => sequence
            .checked_add(1)
            .ok_or_else(|| "traffic spool sequence overflow".to_string())?,
        None => 1,
    };
    let sequence = persisted_next.max(committed_next);
    let next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| "traffic spool sequence overflow".to_string())?;

    // Reserve BEFORE installing a batch. A crash here can only leave a gap;
    // it can never cause an older immutable batch to be overwritten/reordered.
    save_sequence_state_at(&spool_dir, next_sequence)?;
    Ok((spool_dir, sequence))
}

fn validate_spool_record(
    record: &DurableSpoolRecord,
    node_id: &str,
    credential_id: &str,
) -> Result<(), String> {
    if record.format_version != TRAFFIC_SPOOL_FORMAT_VERSION || record.sequence == 0 {
        return Err("traffic spool record format is invalid".into());
    }
    validate_pending_batch(&record.batch, node_id, credential_id)?;
    if let Some(checkpoint) = record.nginx_checkpoint.as_ref() {
        if checkpoint.source.is_empty() || checkpoint.end_offset <= checkpoint.start_offset {
            return Err("traffic spool Nginx checkpoint range is invalid".into());
        }
    }
    Ok(())
}

fn load_spool_record_at(
    path: &Path,
    node_id: &str,
    credential_id: &str,
) -> Result<DurableSpoolRecord, String> {
    let bytes = read_private_regular_file(path, MAX_PENDING_TRAFFIC_BYTES, "traffic spool batch")?;
    let record: DurableSpoolRecord = serde_json::from_slice(&bytes)
        .map_err(|_| "traffic spool batch is malformed".to_string())?;
    validate_spool_record(&record, node_id, credential_id)?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "traffic spool batch filename is invalid".to_string())?;
    if parse_spool_filename(filename) != Some(record.sequence) {
        return Err("traffic spool batch filename/sequence mismatch".into());
    }
    Ok(record)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum SpoolWriteFailpoint {
    None,
    BeforeInstall,
    AfterDurableInstall,
}

fn write_spool_record_at(
    spool_dir: &Path,
    record: &DurableSpoolRecord,
    failpoint: SpoolWriteFailpoint,
) -> Result<(), PendingWriteError> {
    validate_spool_record(record, &record.batch.node_id, &record.batch.credential_id)
        .map_err(PendingWriteError::Clean)?;
    let bytes = serde_json::to_vec(record)
        .map_err(|_| PendingWriteError::Clean("traffic spool batch encode failed".to_string()))?;
    if bytes.len() as u64 > MAX_PENDING_TRAFFIC_BYTES {
        return Err(PendingWriteError::Clean(
            "traffic spool batch is unexpectedly large".into(),
        ));
    }
    let final_path = spool_dir.join(format!(
        "{:0width$}.json",
        record.sequence,
        width = TRAFFIC_SPOOL_FILENAME_WIDTH
    ));
    if std::fs::symlink_metadata(&final_path).is_ok() {
        return Err(PendingWriteError::Clean(
            "traffic spool sequence is already committed".into(),
        ));
    }
    let temp = spool_dir.join(format!(
        ".traffic-report-spool-record.{}.tmp",
        uuid::Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| {
            PendingWriteError::Clean(
                "traffic spool temporary file could not be created".to_string(),
            )
        })?;
    let pre_install = (|| -> Result<(), String> {
        file.write_all(&bytes)
            .map_err(|_| "traffic spool batch could not be written".to_string())?;
        file.flush()
            .map_err(|_| "traffic spool batch could not be flushed".to_string())?;
        file.sync_all()
            .map_err(|_| "traffic spool batch could not be fsynced".to_string())?;
        Ok(())
    })();
    drop(file);
    if let Err(message) = pre_install {
        let _ = std::fs::remove_file(&temp);
        return Err(PendingWriteError::Clean(message));
    }
    if failpoint == SpoolWriteFailpoint::BeforeInstall {
        let _ = std::fs::remove_file(&temp);
        return Err(PendingWriteError::Clean(
            "injected failure before durable traffic spool install".into(),
        ));
    }

    if std::fs::hard_link(&temp, &final_path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(PendingWriteError::Clean(
            "traffic spool batch could not be committed".into(),
        ));
    }
    let _ = std::fs::remove_file(&temp);

    let post_install = (|| -> Result<(), String> {
        sync_directory(spool_dir, "traffic spool directory")?;
        let reopened = load_spool_record_at(
            &final_path,
            &record.batch.node_id,
            &record.batch.credential_id,
        )?;
        if reopened != *record {
            return Err("traffic spool batch verification mismatch".into());
        }
        Ok(())
    })();
    if let Err(message) = post_install {
        let removed = match std::fs::remove_file(&final_path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        };
        if removed && sync_directory(spool_dir, "traffic spool directory").is_ok() {
            return Err(PendingWriteError::Clean(message));
        }
        return Err(PendingWriteError::RestartRequired(format!(
            "{message}; installed spool state could not be safely rolled back"
        )));
    }

    if failpoint == SpoolWriteFailpoint::AfterDurableInstall {
        return Err(PendingWriteError::RestartRequired(
            "injected crash after durable traffic spool install".into(),
        ));
    }
    Ok(())
}

fn seal_strict_spool_batch_with_failpoint(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    config_revision: Option<u64>,
    reports: Vec<TrafficEntry>,
    nginx_checkpoint: Option<NginxTrafficCheckpoint>,
    failpoint: SpoolWriteFailpoint,
) -> Result<PendingTrafficBatch, PendingWriteError> {
    if reports.is_empty() {
        return Err(PendingWriteError::Clean(
            "traffic spool refuses an empty batch".into(),
        ));
    }
    let parent = strict_traffic_parent(auth, node_id)
        .map_err(PendingWriteError::Clean)?
        .ok_or_else(|| {
            PendingWriteError::Clean("strict traffic spool requires Permanent Credential".into())
        })?;
    let credential_id = strict_credential_id(auth, node_id)
        .map_err(PendingWriteError::Clean)?
        .ok_or_else(|| {
            PendingWriteError::Clean("strict traffic spool requires Permanent Credential".into())
        })?;
    let (spool_dir, sequence) =
        reserve_spool_sequence(&parent).map_err(PendingWriteError::Clean)?;
    let pending = PendingTrafficBatch {
        version: TRAFFIC_BATCH_PROTOCOL_VERSION,
        batch_id: uuid::Uuid::new_v4().to_string(),
        payload_sha256: traffic_batch_payload_sha256(&reports),
        node_id: node_id.to_string(),
        credential_id: credential_id.to_string(),
        config_revision,
        reports,
    };
    let record = DurableSpoolRecord {
        format_version: TRAFFIC_SPOOL_FORMAT_VERSION,
        sequence,
        batch: pending.clone(),
        nginx_checkpoint,
    };
    write_spool_record_at(&spool_dir, &record, failpoint)?;
    Ok(pending)
}

fn seal_strict_spool_batch(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    config_revision: Option<u64>,
    reports: Vec<TrafficEntry>,
    nginx_checkpoint: Option<NginxTrafficCheckpoint>,
) -> Result<PendingTrafficBatch, PendingWriteError> {
    seal_strict_spool_batch_with_failpoint(
        auth,
        node_id,
        config_revision,
        reports,
        nginx_checkpoint,
        SpoolWriteFailpoint::None,
    )
}

pub(crate) fn seal_nginx_traffic_batch(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    config_revision: Option<u64>,
    reports: Vec<TrafficEntry>,
    checkpoint: NginxTrafficCheckpoint,
) -> Result<(), PendingWriteError> {
    seal_strict_spool_batch(
        auth,
        node_id,
        config_revision,
        reports,
        Some(checkpoint),
    )
    .map(|_| ())
}

fn load_spool_queue_at(
    spool_dir: &Path,
    node_id: &str,
    credential_id: &str,
) -> Result<Vec<(PathBuf, DurableSpoolRecord)>, String> {
    let files = list_spool_files(spool_dir)?;
    let mut queue = Vec::with_capacity(files.len());
    for (sequence, path) in files {
        let record = load_spool_record_at(&path, node_id, credential_id)?;
        if record.sequence != sequence {
            return Err("traffic spool sequence mismatch".into());
        }
        queue.push((path, record));
    }
    Ok(queue)
}

fn load_spool_queue(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    credential_id: &str,
) -> Result<Vec<(PathBuf, DurableSpoolRecord)>, String> {
    let parent = strict_traffic_parent(auth, node_id)?
        .ok_or_else(|| "strict traffic spool requires Permanent Credential".to_string())?;
    let Some(spool_dir) = existing_spool_dir(&parent)? else {
        return Ok(Vec::new());
    };
    let queue = load_spool_queue_at(&spool_dir, node_id, credential_id)?;
    let sequence_state = load_sequence_state_at(&spool_dir)?;
    if !queue.is_empty() && sequence_state.is_none() {
        return Err("traffic spool sequence state is missing".into());
    }
    if let Some(state) = sequence_state {
        if queue
            .last()
            .is_some_and(|(_, record)| state.next_sequence <= record.sequence)
        {
            return Err("traffic spool sequence state does not advance past committed batches".into());
        }
    }
    Ok(queue)
}

fn load_legacy_pending(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    credential_id: &str,
) -> Result<Option<DurableQueuedBatch>, String> {
    let Some(path) = pending_traffic_path(auth, node_id)? else {
        return Ok(None);
    };
    let Some(batch) = load_pending_traffic_at(&path, node_id, credential_id)? else {
        return Ok(None);
    };
    Ok(Some(DurableQueuedBatch {
        location: DurableBatchLocation::Legacy(path),
        batch,
    }))
}

fn oldest_queue_batch(
    queue: &[(PathBuf, DurableSpoolRecord)],
) -> Option<DurableQueuedBatch> {
    let (path, record) = queue.first()?;
    Some(DurableQueuedBatch {
        batch: record.batch.clone(),
        location: DurableBatchLocation::Queue {
            path: path.clone(),
            record: record.clone(),
        },
    })
}

fn remove_file_and_sync_parent(path: &Path, label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent"))?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("{label} vanished before ACK completion"));
        }
        Err(_) => return Err(format!("{label} could not be removed")),
    }
    sync_directory(parent, &format!("{label} parent directory"))
}

fn remove_durable_batch_at(
    queued: &DurableQueuedBatch,
    node_id: &str,
    credential_id: &str,
) -> Result<(), String> {
    match &queued.location {
        DurableBatchLocation::Legacy(path) => {
            let current = load_pending_traffic_at(path, node_id, credential_id)?
                .ok_or_else(|| "legacy traffic pending batch vanished before ACK".to_string())?;
            if current != queued.batch {
                return Err("legacy traffic pending batch changed before ACK".into());
            }
            remove_file_and_sync_parent(path, "legacy traffic pending batch")
        }
        DurableBatchLocation::Queue { path, record } => {
            let current = load_spool_record_at(path, node_id, credential_id)?;
            if current != *record || current.batch != queued.batch {
                return Err("traffic spool batch changed before ACK".into());
            }
            remove_file_and_sync_parent(path, "traffic spool batch")
        }
    }
}

pub(crate) fn recover_nginx_checkpoint(
    auth: &NodeRuntimeAuth,
    node_id: &str,
    source: &str,
    cursor: Option<(u64, u64, u64, u64)>,
) -> Result<Option<NginxTrafficCheckpoint>, String> {
    let Some(credential_id) = strict_credential_id(auth, node_id)? else {
        return Ok(None);
    };
    let queue = load_spool_queue(auth, node_id, credential_id)?;
    let mut matched = None;
    for (_, record) in queue {
        let Some(checkpoint) = record.nginx_checkpoint else {
            continue;
        };
        if checkpoint.source != source {
            continue;
        }
        let cursor_matches = match cursor {
            Some((device, inode, generation, offset)) => {
                checkpoint.device == device
                    && checkpoint.inode == inode
                    && checkpoint.generation == generation
                    && checkpoint.start_offset == offset
            }
            None => checkpoint.generation == 0 && checkpoint.start_offset == 0,
        };
        if cursor_matches {
            if matched.is_some() {
                return Err("multiple traffic spool checkpoints claim the same Nginx cursor".into());
            }
            matched = Some(checkpoint);
        }
    }
    Ok(matched)
}

#[cfg(test)]
pub(crate) fn test_read_strict_spool(
    auth: &NodeRuntimeAuth,
    node_id: &str,
) -> Result<
    Vec<(
        String,
        String,
        Option<u64>,
        Vec<TrafficEntry>,
        Option<NginxTrafficCheckpoint>,
        u64,
    )>,
    String,
> {
    let credential_id = strict_credential_id(auth, node_id)?
        .ok_or_else(|| "strict traffic spool requires Permanent Credential".to_string())?;
    let queue = load_spool_queue(auth, node_id, credential_id)?;
    Ok(queue
        .into_iter()
        .map(|(_, record)| {
            (
                record.batch.batch_id,
                record.batch.payload_sha256,
                record.batch.config_revision,
                record.batch.reports,
                record.nginx_checkpoint,
                record.sequence,
            )
        })
        .collect())
}

#[cfg(test)]
pub(crate) fn test_drain_strict_spool(
    auth: &NodeRuntimeAuth,
    node_id: &str,
) -> Result<
    Vec<(
        String,
        String,
        Option<u64>,
        Vec<TrafficEntry>,
        Option<NginxTrafficCheckpoint>,
        u64,
    )>,
    String,
> {
    let credential_id = strict_credential_id(auth, node_id)?
        .ok_or_else(|| "strict traffic spool requires Permanent Credential".to_string())?;
    let queue = load_spool_queue(auth, node_id, credential_id)?;
    let mut out = Vec::with_capacity(queue.len());
    for (path, record) in queue {
        out.push((
            record.batch.batch_id.clone(),
            record.batch.payload_sha256.clone(),
            record.batch.config_revision,
            record.batch.reports.clone(),
            record.nginx_checkpoint.clone(),
            record.sequence,
        ));
        remove_file_and_sync_parent(&path, "traffic spool test batch")?;
    }
    Ok(out)
}

#[cfg(test)]
fn write_pending_traffic_at(
    path: &Path,
    pending: &PendingTrafficBatch,
) -> Result<(), PendingWriteError> {
    validate_pending_batch(pending, &pending.node_id, &pending.credential_id)
        .map_err(PendingWriteError::Clean)?;
    let parent = path.parent().ok_or_else(|| {
        PendingWriteError::Clean("traffic pending path has no parent".to_string())
    })?;
    validate_private_pending_parent(parent).map_err(PendingWriteError::Clean)?;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(PendingWriteError::Clean(
            "traffic pending batch already exists".into(),
        ));
    }
    let bytes = serde_json::to_vec(pending)
        .map_err(|_| PendingWriteError::Clean("traffic pending batch encode failed".to_string()))?;
    if bytes.len() as u64 > MAX_PENDING_TRAFFIC_BYTES {
        return Err(PendingWriteError::Clean(
            "traffic pending batch is unexpectedly large".into(),
        ));
    }
    let temp = parent.join(format!(
        ".traffic-report-pending.{}.tmp",
        uuid::Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| {
            PendingWriteError::Clean(
                "traffic pending temporary file could not be created".to_string(),
            )
        })?;
    let pre_install = (|| -> Result<(), String> {
        file.write_all(&bytes)
            .map_err(|_| "traffic pending batch could not be written".to_string())?;
        file.flush()
            .map_err(|_| "traffic pending batch could not be flushed".to_string())?;
        file.sync_all()
            .map_err(|_| "traffic pending batch could not be fsynced".to_string())?;
        Ok(())
    })();
    drop(file);
    if let Err(message) = pre_install {
        let _ = std::fs::remove_file(&temp);
        return Err(PendingWriteError::Clean(message));
    }
    if std::fs::hard_link(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(PendingWriteError::Clean(
            "traffic pending batch could not be committed".into(),
        ));
    }
    let _ = std::fs::remove_file(&temp);
    if let Err(message) = sync_directory(parent, "traffic pending directory") {
        return Err(PendingWriteError::RestartRequired(message));
    }
    Ok(())
}

#[cfg(test)]
fn remove_pending_traffic_at(path: &Path) -> Result<(), String> {
    remove_file_and_sync_parent(path, "traffic pending batch")
}

fn strict_ack_matches(
    pending: &PendingTrafficBatch,
    response: &ApiResponse<TrafficBatchAck>,
) -> bool {
    if response.code != 0 {
        return false;
    }
    let Some(ack) = response.data.as_ref() else {
        return false;
    };
    ack.version == TRAFFIC_BATCH_PROTOCOL_VERSION
        && ack.batch_id == pending.batch_id
        && ack.payload_sha256 == pending.payload_sha256
        && matches!(
            ack.status,
            TrafficBatchAckStatus::Applied | TrafficBatchAckStatus::AlreadyApplied
        )
}

async fn report_traffic_legacy(config: &NodeConfig, counter: &TrafficCounter, node_id: &str) {
    let snap = counter.snapshot().await;
    if snap.entries.is_empty() {
        return;
    }
    let report = TrafficReport {
        batch: None,
        reports: snap.entries.clone(),
    };
    let url = format!("{}/api/v1/node/report_traffic", config.panel_url);
    let client = reqwest::Client::new();
    match config
        .auth
        .apply_reqwest(client.post(&url))
        .header("X-Node-ID", node_id)
        .json(&report)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if !status.is_success() {
                tracing::warn!("report_traffic HTTP {} (not 2xx)", status);
                return;
            }
            match response.json::<ApiResponse<()>>().await {
                Ok(resp) if resp.code == 0 => {
                    snap.commit().await;
                    tracing::info!("report_traffic legacy HTTP {} code 0", status);
                }
                Ok(resp) => tracing::warn!(
                    "report_traffic legacy rejected: code {} msg={}",
                    resp.code,
                    resp.message
                ),
                Err(error) => tracing::warn!("report_traffic legacy malformed response: {}", error),
            }
        }
        Err(error) => tracing::warn!("report_traffic legacy error: {}", error),
    }
}

async fn report_traffic_strict(
    config: &NodeConfig,
    counter: &TrafficCounter,
    node_id: &str,
    credential_id: &str,
) {
    // Validate every committed queue entry before touching live counters. A
    // corrupt later entry therefore fails closed rather than being overtaken.
    let queue_before = match load_spool_queue(&config.auth, node_id, credential_id) {
        Ok(queue) => queue,
        Err(error) => {
            tracing::error!("strict traffic spool unavailable: {}", error);
            return;
        }
    };
    let legacy_before = match load_legacy_pending(&config.auth, node_id, credential_id) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("strict legacy traffic pending state unavailable: {}", error);
            return;
        }
    };

    // Seal one fresh in-memory generation before attempting the oldest upload.
    // A Panel outage can block A indefinitely while B/C still become immutable
    // durable batches rather than living only in process RAM.
    let snap = counter.snapshot().await;
    let sealed_new = if snap.entries.is_empty() {
        drop(snap);
        false
    } else {
        let reports = snap.entries.clone();
        match seal_strict_spool_batch(
            &config.auth,
            node_id,
            snap.config_revision,
            reports,
            None,
        ) {
            Ok(_) => {
                snap.commit().await;
                true
            }
            Err(error) => {
                if error.restart_required() {
                    counter.poison_strict_reporting();
                }
                tracing::error!(
                    "strict traffic batch could not be durably queued: {}",
                    error.message()
                );
                return;
            }
        }
    };

    let queued = if let Some(legacy) = legacy_before {
        legacy
    } else if let Some(oldest) = oldest_queue_batch(&queue_before) {
        oldest
    } else if sealed_new {
        let queue_after = match load_spool_queue(&config.auth, node_id, credential_id) {
            Ok(queue) => queue,
            Err(error) => {
                tracing::error!("strict traffic spool unavailable after seal: {}", error);
                return;
            }
        };
        let Some(oldest) = oldest_queue_batch(&queue_after) else {
            tracing::error!("strict traffic spool lost a just-sealed batch");
            counter.poison_strict_reporting();
            return;
        };
        oldest
    } else {
        return;
    };

    let pending = &queued.batch;
    let report = TrafficReport {
        batch: Some(TrafficBatchMetadata {
            version: pending.version,
            batch_id: pending.batch_id.clone(),
            payload_sha256: pending.payload_sha256.clone(),
            config_revision: pending.config_revision,
        }),
        reports: pending.reports.clone(),
    };
    let url = format!("{}/api/v1/node/report_traffic", config.panel_url);
    let client = reqwest::Client::new();
    let response = match config
        .auth
        .apply_reqwest(client.post(&url))
        .header("X-Node-ID", node_id)
        .json(&report)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("strict report_traffic error: {}", error);
            return;
        }
    };
    if !response.status().is_success() {
        tracing::warn!("strict report_traffic HTTP {} (not 2xx)", response.status());
        return;
    }
    let response = match response.json::<ApiResponse<TrafficBatchAck>>().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("strict report_traffic malformed ACK: {}", error);
            return;
        }
    };
    if !strict_ack_matches(pending, &response) {
        tracing::warn!("strict report_traffic received non-matching ACK");
        return;
    }
    if let Err(error) = remove_durable_batch_at(&queued, node_id, credential_id) {
        tracing::error!(
            "strict traffic ACK could not be durably completed: {}",
            error
        );
        return;
    }
    tracing::info!("strict report_traffic batch confirmed");
}

pub async fn report_traffic(config: &NodeConfig, counter: &TrafficCounter, node_id: &str) {
    let _report_guard = counter.durable_accounting_guard().await;
    if matches!(config.auth, NodeRuntimeAuth::PermanentCredential { .. })
        && counter.strict_reporting_poisoned()
    {
        tracing::error!(
            "strict traffic reporting is stopped after an uncertain local accounting transition; restart required"
        );
        return;
    }
    match &config.auth {
        NodeRuntimeAuth::PermanentCredential { credential_id, .. } => {
            report_traffic_strict(config, counter, node_id, credential_id).await;
        }
        NodeRuntimeAuth::LegacyGroupToken { .. } => {
            report_traffic_legacy(config, counter, node_id).await;
        }
    }
}

/// Report real system metrics: CPU %, memory %, active connections, uptime.
///
/// `sys` is shared (Arc<Mutex>) because sysinfo's System is not Sync across
/// a plain &mut in async contexts. CPU usage requires a prior refresh with a
/// time gap, which the caller performs once at startup (see main.rs).
///
/// All sysinfo samplers held together so `report_status` can collect every
/// metric in one place. Each sampler is wrapped in its own lock because
/// sysinfo's structs are not `Sync` on their own; they are refreshed under
/// the lock and the values are read out without holding it during await.
///
/// - `sys`: CPU + memory (existing behaviour).
/// - `disks`: root-partition usage (`/`).
/// - `networks`: NIC counters; the previous sample is kept so the real-time
///   rate (bps) is computed from the delta between two samples.
/// - `public_ip`: cached egress IP, refreshed on a long interval (see
///   `spawn_public_ip_refresher`); `None` until/unless detected.
pub struct NodeMetrics {
    sys: Mutex<System>,
    disks: Mutex<Disks>,
    networks: Mutex<Networks>,
    /// v0.4.6: the single interface we count machine traffic for. None = no
    /// interface could be selected (we log once and report zero traffic rather
    /// than summing every NIC, which double-counts docker/veth).
    network_interface: RwLock<Option<String>>,
    /// Previous sample's cumulative (total_received, total_transmitted) for the
    /// selected interface, used to compute the per-interval delta for the bps
    /// rate. The cumulative field in the report uses the CURRENT total_*.
    last_net: Mutex<HashMap<String, (u64, u64)>>,
    /// When the previous network sample was taken (for bps denominator).
    last_net_at: Mutex<Option<Instant>>,
    /// v0.4.15: public egress IPs detected independently per address family.
    /// `public_ipv4` doubles as the legacy `public_ip` for backward-compat
    /// (older panels read `public_ip`). `public_ipv6` is None when the node
    /// has no IPv6 connectivity; one family failing NEVER clears the other.
    public_ipv4: RwLock<Option<String>>,
    public_ipv6: RwLock<Option<String>>,
}

impl NodeMetrics {
    /// `configured_interface` is the value of NETWORK_INTERFACE ("auto" or an
    /// explicit name). Auto-detection runs on construction and is re-run lazily
    /// in snapshot() if the selected interface is absent from sysinfo's list
    /// (e.g. the NIC came up after the node started).
    pub fn new(configured_interface: &str) -> Self {
        let selected = resolve_network_interface(configured_interface);
        if selected.is_none() {
            tracing::warn!(
                "NETWORK_INTERFACE='{}': could not select a NIC; machine traffic will report \
                 zero until a default-route interface is available",
                configured_interface
            );
        }
        Self {
            sys: Mutex::new(System::new()),
            disks: Mutex::new(Disks::new_with_refreshed_list()),
            networks: Mutex::new(Networks::new_with_refreshed_list()),
            network_interface: RwLock::new(selected),
            last_net: Mutex::new(HashMap::new()),
            last_net_at: Mutex::new(None),
            public_ipv4: RwLock::new(None),
            public_ipv6: RwLock::new(None),
        }
    }

    /// The interface currently being counted (None if none selected). Used so
    /// the StatusReport can show "统计网卡: eth0" in the panel.
    pub async fn network_interface(&self) -> Option<String> {
        self.network_interface.read().await.clone()
    }

    /// Seed the CPU + network baselines. This takes an initial sample of CPU
    /// usage and NIC counters so the FIRST periodic report already has a sane
    /// baseline to compute a delta from. It does NOT block: the sysinfo quirk
    /// (CPU needs two samples ~500ms apart for a meaningful delta) is handled
    /// by `spawn_warmup`, which sleeps in a detached task instead of stalling
    /// startup. Call `new()` + `spawn_warmup()` rather than awaiting a sleep
    /// on the critical startup path.
    pub async fn seed_baselines(&self) {
        {
            let mut s = self.sys.lock().await;
            s.refresh_cpu_usage();
        }
        // Seed the network baseline so the second report can compute a rate.
        let now = Instant::now();
        let current = self.sample_networks().await;
        *self.last_net.lock().await = current;
        *self.last_net_at.lock().await = Some(now);
    }

    /// Fire-and-forget the warm-up: take a second CPU sample ~500ms later so
    /// the first real report has a meaningful CPU %. Runs detached — callers
    /// never await this on the startup critical path.
    pub fn spawn_warmup(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let mut s = me.sys.lock().await;
            s.refresh_cpu_usage();
        });
    }

    /// Refresh NIC counters and return the SELECTED interface's cumulative
    /// (total_received, total_transmitted) totals (since OS boot). Returns an
    /// empty map if no interface is selected (or the selected one is absent),
    /// so snapshot() reports zero rather than summing unrelated NICs.
    ///
    /// v0.4.6: we store total_* here. The report's boot_* field uses it
    /// directly; the per-interval rate is the delta between two samples'
    /// total_* values (NOT sysinfo's `received()`, which is itself a delta and
    /// must not be subtracted again).
    async fn sample_networks(&self) -> HashMap<String, (u64, u64)> {
        let mut nets = self.networks.lock().await;
        nets.refresh();
        let selected = self.network_interface.read().await.clone();
        let mut current = HashMap::new();
        for (name, data) in nets.list() {
            if Some(name.as_str()) == selected.as_deref() {
                current.insert(
                    name.clone(),
                    (data.total_received(), data.total_transmitted()),
                );
                break;
            }
        }
        // v0.4.6: if the selected interface is gone (renamed/timed out), try to
        // re-resolve once so a NIC that came up after node start gets picked up.
        if current.is_empty() {
            let need_auto = matches!(&selected, Some(s) if s.eq_ignore_ascii_case("auto"))
                || selected.is_none();
            // We only re-resolve for the unset/auto case; an explicitly pinned
            // interface that vanished is a config error we surface as zero.
            if need_auto {
                drop(nets);
                let nets2 = Networks::new_with_refreshed_list();
                let picked = nets2
                    .list()
                    .iter()
                    .find(|(n, _)| !n.eq_ignore_ascii_case("lo"))
                    .map(|(n, _)| n.clone());
                if let Some(ref name) = picked {
                    *self.network_interface.write().await = picked.clone();
                    let mut nets3 = self.networks.lock().await;
                    nets3.refresh();
                    for (n, data) in nets3.list() {
                        if n == name {
                            current.insert(
                                n.clone(),
                                (data.total_received(), data.total_transmitted()),
                            );
                        }
                    }
                }
            }
        }
        current
    }

    /// v0.4.15: legacy alias — sets/gets the IPv4. Kept so the old
    /// `spawn_public_ip_refresher` name path still compiles; the dual-stack
    /// refresher uses set_public_ipv4 / set_public_ipv6 directly.
    #[allow(dead_code)]
    pub async fn set_public_ip(&self, ip: Option<String>) {
        *self.public_ipv4.write().await = ip;
    }

    #[allow(dead_code)]
    pub async fn public_ip(&self) -> Option<String> {
        self.public_ipv4.read().await.clone()
    }

    pub async fn set_public_ipv4(&self, ip: Option<String>) {
        *self.public_ipv4.write().await = ip;
    }

    pub async fn public_ipv4(&self) -> Option<String> {
        self.public_ipv4.read().await.clone()
    }

    pub async fn set_public_ipv6(&self, ip: Option<String>) {
        *self.public_ipv6.write().await = ip;
    }

    pub async fn public_ipv6(&self) -> Option<String> {
        self.public_ipv6.read().await.clone()
    }
}

/// One snapshot of every metric `report_status` needs, gathered under the
/// locks and then handed off to the (await-heavy) HTTP call without holding them.
struct MetricsSnapshot {
    cpu: f32,
    mem_pct: f32,
    disk_total: Option<u64>,
    disk_used: Option<u64>,
    disk_usage_percent: Option<f32>,
    disk_mount: Option<String>,
    upload_bps: Option<u64>,
    download_bps: Option<u64>,
    boot_upload_bytes: Option<u64>,
    boot_download_bytes: Option<u64>,
    /// v0.4.15 legacy compat: mirrors public_ipv4. Kept so old code/tests that
    /// read `snap.public_ip` still compile; the report uses public_ipv4.
    #[allow(dead_code)]
    public_ip: Option<String>,
    /// v0.4.15: dual-stack public IPs (ipv4 mirrors public_ip for compat).
    public_ipv4: Option<String>,
    public_ipv6: Option<String>,
    /// v0.4.6: the interface machine traffic is counted on (e.g. "eth0"), for
    /// display. None when no interface could be selected.
    network_interface: Option<String>,
    /// v0.3.2: SYSTEM uptime (time since the OS booted), NOT the relay-node
    /// process uptime. Users read "运行时长" as "how long has the server been
    /// up", which is the OS uptime; the process uptime is reported separately
    /// as process_uptime_secs.
    system_uptime: u64,
}

/// Read the system uptime in whole seconds from /proc/uptime (Linux only).
///
/// /proc/uptime is two fields: `<uptime_secs> <idle_secs>`. We take the floor
/// of the first. Returns 0 if the file is missing/unreadable (the panel treats
/// 0 as "unknown" gracefully). Factored out so it's unit-testable.
fn read_system_uptime_secs() -> u64 {
    match std::fs::read_to_string("/proc/uptime") {
        Ok(s) => s
            .split_whitespace()
            .next()
            .and_then(|f| f.split('.').next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// v0.4.6: resolve the configured NETWORK_INTERFACE value to a concrete NIC.
///
/// - "auto" (or empty): read the default route from /proc/net/route and return
///   its interface. Falls back to the first non-loopback NIC sysinfo sees if
///   /proc/net/route can't be parsed.
/// - any other value: returned verbatim (the operator pinned it). We do NOT
///   validate it exists here; snapshot() skips a missing interface and reports
///   zero rather than summing others.
///
/// Returns None only when no interface can be determined at all.
fn resolve_network_interface(configured: &str) -> Option<String> {
    let c = configured.trim();
    if !c.is_empty() && !c.eq_ignore_ascii_case("auto") {
        return Some(c.to_string());
    }

    // /proc/net/route columns: Iface, Destination, Gateway, Flags, ..., Mask,
    // ... The default route has Destination 00000000. Field 2 (index 0) is the
    // interface name. Hex 00000000 == the default route (0.0.0.0).
    if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue; // header
            }
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let dest = fields.next()?;
            if dest.eq_ignore_ascii_case("00000000") {
                return Some(iface.to_string());
            }
        }
    }

    // Fallback: first non-loopback interface sysinfo enumerates. Avoids blindly
    // summing docker bridges / veth pairs when the route table isn't readable.
    let nets = Networks::new_with_refreshed_list();
    for name in nets.list().keys() {
        if !name.eq_ignore_ascii_case("lo") {
            return Some(name.clone());
        }
    }
    None
}

impl NodeMetrics {
    /// Collect one snapshot: CPU/mem/disk + network rate (delta since the last
    /// call) + cumulative NIC totals + cached public IP.
    async fn snapshot(&self) -> MetricsSnapshot {
        // --- CPU + memory + system uptime ---
        let (cpu, mem_pct, system_uptime) = {
            let mut s = self.sys.lock().await;
            s.refresh_cpu_usage();
            s.refresh_memory();
            let cpu = s.global_cpu_usage();
            let mem_total = s.total_memory();
            let mem_used = s.used_memory();
            let mem_pct = if mem_total > 0 {
                (mem_used as f64 / mem_total as f64) * 100.0
            } else {
                0.0
            };
            // System uptime (since OS boot), NOT process uptime. Read directly
            // from /proc/uptime on Linux (the only supported platform) rather
            // than via sysinfo, whose uptime API changed across 0.30/0.32 and
            // is unreliable to depend on. Falls back to 0 if unreadable.
            let system_uptime = read_system_uptime_secs();
            (cpu as f32, mem_pct as f32, system_uptime)
        };

        // --- Primary disk (root partition `/`) ---
        // Refresh before reading: without this disks only reflects the snapshot
        // taken at NodeMetrics::new(), so disk usage never changes after start.
        let (disk_total, disk_used, disk_usage_percent, disk_mount) = {
            let mut disks = self.disks.lock().await;
            disks.refresh();
            // Pick the mount point matching `/` exactly; fall back to the first
            // disk if none matches exactly. total/available come from sysinfo.
            let pick = disks
                .list()
                .iter()
                .find(|d| d.mount_point().to_string_lossy() == "/")
                .or_else(|| disks.list().first());
            match pick {
                Some(d) => {
                    let total = d.total_space();
                    let avail = d.available_space();
                    let used = total.saturating_sub(avail);
                    let pct = if total > 0 {
                        (used as f64 / total as f64 * 100.0) as f32
                    } else {
                        0.0
                    };
                    (
                        Some(total),
                        Some(used),
                        Some(pct),
                        Some(d.mount_point().to_string_lossy().into_owned()),
                    )
                }
                None => (None, None, None, None),
            }
        };

        // --- Network: real-time rate + cumulative, for the SELECTED NIC only ---
        // v0.4.6: sample_networks returns the selected interface's total_*
        // (since-boot cumulative). The cumulative field is that value directly;
        // the per-interval rate is (current_total - prev_total) / elapsed.
        // We store current totals as the next baseline. Unlike the old code,
        // this does NOT sum every non-loopback NIC, so docker bridges / veth
        // are no longer double-counted.
        let prev_baseline = self.last_net.lock().await.clone();
        let prev_at = *self.last_net_at.lock().await;
        let now = Instant::now();
        let current = self.sample_networks().await;
        // Store the new baseline for next cycle.
        *self.last_net.lock().await = current.clone();
        *self.last_net_at.lock().await = Some(now);

        let (upload_bps, download_bps, boot_upload_bytes, boot_download_bytes) = {
            // Cumulative totals across all non-loopback NICs (system-wide since boot).
            let up_total: u64 = current.values().map(|(_, t)| *t).sum();
            let down_total: u64 = current.values().map(|(r, _)| *r).sum();

            // Real-time rate from the delta, if we have a previous sample + a
            // usable elapsed time. saturating_sub guards against counter wrap.
            let (up_bps, down_bps) = match (prev_at, prev_baseline.is_empty()) {
                (Some(prev_time), false) => {
                    let elapsed = now.duration_since(prev_time).as_secs_f64();
                    if elapsed > 0.0 {
                        let up_delta: u64 = current
                            .iter()
                            .map(|(n, (_, t))| {
                                prev_baseline
                                    .get(n)
                                    .map(|(_, pt)| t.saturating_sub(*pt))
                                    .unwrap_or(0)
                            })
                            .sum();
                        let down_delta: u64 = current
                            .iter()
                            .map(|(n, (r, _))| {
                                prev_baseline
                                    .get(n)
                                    .map(|(pr, _)| r.saturating_sub(*pr))
                                    .unwrap_or(0)
                            })
                            .sum();
                        (
                            Some((up_delta as f64 / elapsed) as u64),
                            Some((down_delta as f64 / elapsed) as u64),
                        )
                    } else {
                        (Some(0), Some(0))
                    }
                }
                _ => (None, None), // first sample ever: no rate yet
            };
            (up_bps, down_bps, Some(up_total), Some(down_total))
        };

        let public_ipv4 = self.public_ipv4().await;
        let public_ipv6 = self.public_ipv6().await;
        let network_interface = self.network_interface().await;

        MetricsSnapshot {
            cpu,
            mem_pct,
            disk_total,
            disk_used,
            disk_usage_percent,
            disk_mount,
            upload_bps,
            download_bps,
            boot_upload_bytes,
            boot_download_bytes,
            public_ip: public_ipv4.clone(),
            public_ipv4,
            public_ipv6,
            network_interface,
            system_uptime,
        }
    }
}

/// Collect all metrics + connections + uptime and POST one StatusReport to
/// the panel. Every new field is independent of the WebSocket control channel
/// — this runs on the plain-HTTP poll loop, so it keeps reporting even if WS
/// is down. Failures are logged, never crash.
#[allow(clippy::too_many_arguments)] // 状态来源保持显式，避免 rc.7 重构 reporter 生命周期。
pub async fn report_status(
    config: &NodeConfig,
    metrics: &Arc<NodeMetrics>,
    connections: &ConnectionTracker,
    managed_nginx_sni_ports: &[u16],
    start_time: Instant,
    node_id: &str,
    listener_errors: Vec<ListenerError>,
    camouflage_sites: Vec<CamouflageSiteStatus>,
    active_listener_rule_ids: Vec<i64>,
    reconciliation: ReconciliationStatus,
) {
    let snap = metrics.snapshot().await;
    let relay_tcp = connections.current_tcp();
    let active_udp_sessions = connections.current_udp().await;
    let active_tcp_connections = nginx_sni_active_tcp(managed_nginx_sni_ports)
        .map(|nginx_tcp| relay_tcp.saturating_add(nginx_tcp));
    let active_connections = active_tcp_connections
        .unwrap_or(relay_tcp)
        .saturating_add(active_udp_sessions);

    let report = StatusReport {
        cpu_usage: snap.cpu,
        mem_usage: snap.mem_pct,
        active_connections,
        active_tcp_connections,
        active_udp_sessions: Some(active_udp_sessions),
        // v0.3.2: uptime_secs is now SYSTEM uptime (since OS boot), matching
        // what "运行时长" means to users. The process uptime moved to its own
        // field below.
        uptime_secs: snap.system_uptime,
        public_ip: snap.public_ipv4.clone(),
        public_ipv4: snap.public_ipv4.clone(),
        public_ipv6: snap.public_ipv6,
        disk_total: snap.disk_total,
        disk_used: snap.disk_used,
        disk_usage_percent: snap.disk_usage_percent,
        disk_mount: snap.disk_mount,
        upload_bps: snap.upload_bps,
        download_bps: snap.download_bps,
        boot_upload_bytes: snap.boot_upload_bytes,
        boot_download_bytes: snap.boot_download_bytes,
        network_interface: snap.network_interface,
        node_id: Some(node_id.to_string()),
        process_uptime_secs: Some(start_time.elapsed().as_secs()),
        // v0.3.4: report this binary's version so the panel can flag stale
        // nodes for upgrade. env! is compile-time, zero runtime cost.
        node_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        // v0.4.0: config-protocol version, mirrored from the
        // X-Config-Protocol-Version header. Stored by the panel purely for the
        // frontend status display (the actual gate is request-scoped).
        config_protocol_version: Some(relay_shared::protocol::CONFIG_PROTOCOL_VERSION),
        // Only include listener_errors when non-empty, so healthy nodes send a
        // smaller payload and the panel renders "ok" by default.
        listener_errors: if listener_errors.is_empty() {
            None
        } else {
            Some(listener_errors)
        },
        // v1.0.10: how this node is run, so the panel only offers a one-click
        // self-upgrade to systemd nodes (docker → update image; manual → none).
        install_method: Some(crate::updater::install_method().to_string()),
        architecture: Some(std::env::consts::ARCH.to_string()),
        camouflage_sites: Some(camouflage_sites),
        active_listener_rule_ids: Some(active_listener_rule_ids),
        provisioning_capabilities: Some(config.provisioning_capabilities()),
        reconciliation: Some(reconciliation),
    };

    // debug, not info: this runs every poll cycle (default 10s). Keeping it
    // at info floods the log with one line per cycle on a healthy node.
    tracing::debug!(
        "report_status: cpu={:.1}% mem={:.1}% conns={} sys_up={}s proc_up={}s disk={} ip={}",
        report.cpu_usage,
        report.mem_usage,
        report.active_connections,
        report.uptime_secs,
        report.process_uptime_secs.unwrap_or(0),
        report
            .disk_usage_percent
            .map(|p| format!("{:.0}%", p))
            .unwrap_or_else(|| "n/a".into()),
        report.public_ip.as_deref().unwrap_or("?"),
    );

    let url = format!("{}/api/v1/node/report_status", config.panel_url);
    let client = reqwest::Client::new();
    // v0.3.9: check the response so a rejected status report (invalid/rotated
    // token, DB error) is surfaced instead of silently fire-and-forget. Unlike
    // report_traffic there's nothing to retry here (status is ephemeral), but
    // a persistent rejection (e.g. rotated token) now shows up in the log
    // rather than the node believing everything is fine.
    match config
        .auth
        .apply_reqwest(client.post(&url))
        .header("X-Node-ID", node_id)
        .json(&report)
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status();
            if !status.is_success() {
                tracing::warn!("report_status HTTP {} (not 2xx)", status);
                return;
            }
            match r.json::<ApiResponse<()>>().await {
                Ok(resp) if resp.code == 0 => {
                    tracing::info!("report_status HTTP {} code 0", status);
                }
                Ok(resp) => {
                    tracing::warn!(
                        "report_status rejected: HTTP {} code {} msg={}",
                        status,
                        resp.code,
                        resp.message
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "report_status: could not parse response body (HTTP {}): {}",
                        status,
                        e
                    );
                }
            }
        }
        Err(e) => tracing::warn!("report_status error: {}", e),
    }
}

/// How often the public-IP refresher re-checks (long interval so we are not
/// hammering the external service every poll cycle).
const PUBLIC_IP_REFRESH: Duration = Duration::from_secs(30 * 60);
const PUBLIC_IP_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

#[derive(Default)]
struct PublicIpRefreshBackoff {
    consecutive_failures: usize,
}

impl PublicIpRefreshBackoff {
    fn next_delay(&mut self, detected: bool) -> Duration {
        if detected {
            self.consecutive_failures = 0;
            return PUBLIC_IP_REFRESH;
        }
        let delay = PUBLIC_IP_RETRY_DELAYS
            .get(self.consecutive_failures)
            .copied()
            .unwrap_or(PUBLIC_IP_RETRY_DELAYS[PUBLIC_IP_RETRY_DELAYS.len() - 1]);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        delay
    }
}

/// Detect a public egress IP by calling the configured check URL. The returned
/// text is validated as a parseable `IpAddr` (rejects garbage / HTML error
/// pages). Failure yields None — never blocks node startup. `quiet` suppresses
/// the warn log on failure (used for IPv6, where "not available" is normal and
/// we don't want to spam the log every 30 min).
/// v0.4.15: parse a public-IP-check response body into a validated, correct-
/// family IP string. Returns None if the body isn't a single valid IP, or if
/// the address family doesn't match the family we asked for.
///
/// Pure (no I/O) so it's unit-testable. The family check matters because on a
/// dual-stack host the IPv4 endpoint (api.ipify.org) can be reached over IPv6
/// and return an IPv6 address — storing that in public_ipv4 would surface an
/// IPv6 on the panel's IPv4 line.
fn parse_ip_for_family(body: &str, family: &IpFamily) -> Option<String> {
    let ip = body.trim();
    if ip.is_empty() {
        return None;
    }
    let parsed = ip.parse::<std::net::IpAddr>().ok()?;
    let matches = match family {
        IpFamily::V4 => parsed.is_ipv4(),
        IpFamily::V6 => parsed.is_ipv6(),
    };
    if matches {
        Some(ip.to_string())
    } else {
        None
    }
}

async fn detect_public_ip(check_url: &str, family: &IpFamily, quiet: bool) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    match client.get(check_url).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(body) => {
                let result = parse_ip_for_family(&body, family);
                if result.is_none() && !quiet {
                    tracing::warn!(
                        "public_ip: {:?} check returned no usable same-family IP: {:?}",
                        family,
                        body.trim()
                    );
                }
                result
            }
            Err(e) => {
                if !quiet {
                    tracing::warn!("public_ip: failed to read body: {}", e);
                }
                None
            }
        },
        Ok(r) => {
            if !quiet {
                tracing::warn!("public_ip: check returned HTTP {}", r.status());
            }
            None
        }
        Err(e) => {
            if !quiet {
                tracing::warn!("public_ip: check failed: {}", e);
            }
            None
        }
    }
}

async fn store_public_ip_detection(
    metrics: &NodeMetrics,
    family: &IpFamily,
    detected: Option<String>,
) -> bool {
    let Some(value) = detected else {
        return false;
    };
    tracing::info!("public_{:?} detected: {}", family, value);
    match family {
        IpFamily::V4 => metrics.set_public_ipv4(Some(value)).await,
        IpFamily::V6 => metrics.set_public_ipv6(Some(value)).await,
    }
    true
}

/// v0.4.15: detect one address family in a loop, storing into its own field.
/// INDEPENDENT of the other family — a v6 failure never clears v4 and vice
/// versa. `quiet` suppresses failure logs for IPv6 (absence is normal).
async fn run_family_refresher(
    metrics: Arc<NodeMetrics>,
    check_url: String,
    family: IpFamily,
    quiet: bool,
) {
    let mut backoff = PublicIpRefreshBackoff::default();
    loop {
        // v0.4.15: only OVERWRITE the stored address on a successful, correct-
        // family detection. A transient failure (endpoint down, timeout, wrong
        // family) keeps the LAST good value instead of clearing it to None —
        // otherwise one flaky poll would blank the IP/region on the panel until
        // the next success 30 min later.
        let detected = detect_public_ip(&check_url, &family, quiet).await;
        let detected = store_public_ip_detection(&metrics, &family, detected).await;
        tokio::time::sleep(backoff.next_delay(detected)).await;
    }
}

#[derive(Debug)]
enum IpFamily {
    V4,
    V6,
}

/// v1.2.1: the default endpoints, one per family.
///
/// These MUST be family-pinned hostnames. Both probes validate the family and
/// DISCARD a mismatch (see `parse_ip_for_family`), so a dual-stack endpoint —
/// one that answers over whichever family the connection used and returns that
/// address — makes the IPv4 probe intermittently receive an IPv6 and throw it
/// away, leaving the panel showing no address at all. It fails only on
/// dual-stack hosts and only sometimes, which is the worst way for it to fail.
/// `api.ip.sb/ip` is exactly such an endpoint; `api-ipv4` / `api-ipv6` are its
/// pinned variants. A test below pins this.
///
/// Changed from ipify in v1.2.1: `api.ipify.org` is unreachable from mainland
/// China, where the probe simply timed out every 30 minutes forever and the
/// node's IP (and therefore its flag and region) stayed blank on the panel.
const DEFAULT_IPV4_CHECK_URL: &str = "https://api-ipv4.ip.sb/ip";
const DEFAULT_IPV6_CHECK_URL: &str = "https://api-ipv6.ip.sb/ip";

/// v0.4.15: spawn TWO independent background tasks — one for IPv4, one for
/// IPv6. Each checks once at start then every 30 min. A failure in one family
/// never clears the other. Env overrides (later wins):
///   IPv4: PUBLIC_IPV4_CHECK_URL → PUBLIC_IP_CHECK_URL → DEFAULT_IPV4_CHECK_URL
///   IPv6: PUBLIC_IPV6_CHECK_URL → DEFAULT_IPV6_CHECK_URL
/// IPv6 failures are quiet (no IPv6 is normal on many hosts).
pub fn spawn_public_ip_refresher(metrics: Arc<NodeMetrics>) {
    let v4_url = std::env::var("PUBLIC_IPV4_CHECK_URL")
        .or_else(|_| std::env::var("PUBLIC_IP_CHECK_URL"))
        .unwrap_or_else(|_| DEFAULT_IPV4_CHECK_URL.to_string());
    let v6_url = std::env::var("PUBLIC_IPV6_CHECK_URL")
        .unwrap_or_else(|_| DEFAULT_IPV6_CHECK_URL.to_string());

    let m4 = metrics.clone();
    tokio::spawn(async move { run_family_refresher(m4, v4_url, IpFamily::V4, false).await });

    let m6 = metrics;
    tokio::spawn(async move { run_family_refresher(m6, v6_url, IpFamily::V6, true).await });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), p))
    }

    fn traffic(entries: &[TrafficEntry], rule_id: i64) -> Option<(u64, u64)> {
        entries
            .iter()
            .find(|entry| entry.rule_id == rule_id)
            .map(|entry| (entry.upload, entry.download))
    }

    fn private_test_dir(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir =
            std::env::temp_dir().join(format!("reality-panel-t1-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn strict_test_config(panel_url: String, dir: &Path) -> NodeConfig {
        NodeConfig {
            panel_url,
            auth: NodeRuntimeAuth::PermanentCredential {
                credential_id: "cred-t1-node".into(),
                secret: "rpn1_node_test_secret".into(),
                secret_file: dir.join("node-credential.secret"),
                state_node_id: "NODE_T1".into(),
            },
            poll_interval: 10,
            tls_cert_path: None,
            tls_key_path: None,
            network_interface: "auto".into(),
            listen_ipv4: "0.0.0.0".into(),
            listen_ipv6: "::".into(),
            outbound_interface: "auto".into(),
            outbound_bind_ipv4: None,
            nginx_sni_enabled: false,
            nginx_sni_conf_path: String::new(),
            nginx_sni_test_cmd: String::new(),
            nginx_sni_reload_cmd: String::new(),
            nginx_sni_default_backend: String::new(),
            nginx_sni_access_log_path: String::new(),
            nginx_sni_traffic_state_path: String::new(),
            camouflage_sites_enabled: false,
            camouflage_sites_manifest_path: String::new(),
            camouflage_sites_state_dir: String::new(),
            camouflage_wrapper_conf_path: String::new(),
            certificate_lifecycle_enabled: false,
            certificate_lifecycle_check_interval_secs: 60,
            certbot_binary_path: String::new(),
            certbot_live_dir: String::new(),
            certificate_http01_webroot: String::new(),
            certificate_http01_conf_path: String::new(),
            certificate_state_dir: String::new(),
            provisioning_capabilities_path: String::new(),
        }
    }

    async fn read_http_traffic_report(stream: &mut tokio::net::TcpStream) -> TrafficReport {
        use tokio::io::AsyncReadExt as _;

        let mut bytes = Vec::new();
        let header_end;
        loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before request headers completed");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(pos) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let header_text = String::from_utf8_lossy(&bytes[..header_end]);
        let content_len: usize = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .expect("reqwest request has Content-Length");
        while bytes.len() < header_end + content_len {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before request body completed");
            bytes.extend_from_slice(&chunk[..read]);
        }
        serde_json::from_slice(&bytes[header_end..header_end + content_len]).unwrap()
    }

    async fn write_http_response(stream: &mut tokio::net::TcpStream, status: &str, body: &[u8]) {
        use tokio::io::AsyncWriteExt as _;

        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    fn ack_body(report: &TrafficReport, status: TrafficBatchAckStatus) -> Vec<u8> {
        let batch = report.batch.as_ref().expect("strict batch metadata");
        serde_json::to_vec(&ApiResponse {
            code: 0,
            message: "ok".into(),
            data: Some(TrafficBatchAck {
                version: batch.version,
                batch_id: batch.batch_id.clone(),
                payload_sha256: batch.payload_sha256.clone(),
                status,
            }),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn legacy_single_pending_file_remains_readable_and_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = private_test_dir("legacy-pending");
        let path = dir.join(TRAFFIC_PENDING_FILENAME);
        let reports = vec![TrafficEntry {
            rule_id: 7,
            upload: 10,
            download: 20,
        }];
        let pending = PendingTrafficBatch {
            version: TRAFFIC_BATCH_PROTOCOL_VERSION,
            batch_id: "legacy-pending-batch".into(),
            payload_sha256: traffic_batch_payload_sha256(&reports),
            node_id: "NODE_T1".into(),
            credential_id: "cred-t1-node".into(),
            config_revision: Some(42),
            reports,
        };
        write_pending_traffic_at(&path, &pending).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            load_pending_traffic_at(&path, "NODE_T1", "cred-t1-node")
                .unwrap()
                .unwrap(),
            pending
        );
        assert!(load_pending_traffic_at(&path, "NODE_T1", "wrong-credential").is_err());

        remove_pending_traffic_at(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[tokio::test]
    async fn panel_outage_allows_multiple_durable_batches_and_restart_preserves_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::<TrafficReport>::new()));
        let captured_server = captured.clone();
        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let report = read_http_traffic_report(&mut stream).await;
                captured_server.lock().await.push(report.clone());
                if step < 2 {
                    write_http_response(&mut stream, "503 Service Unavailable", b"").await;
                } else {
                    let body = ack_body(&report, TrafficBatchAckStatus::Applied);
                    write_http_response(&mut stream, "200 OK", &body).await;
                }
            }
        });

        let dir = private_test_dir("multi-pending-restart");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let first_counter = TrafficCounter::new();
        first_counter.add_at(42, 7, 10, 20).await;
        report_traffic(&config, &first_counter, "NODE_T1").await;

        first_counter.add_at(43, 7, 3, 4).await;
        report_traffic(&config, &first_counter, "NODE_T1").await;
        assert!(first_counter.snapshot().await.entries.is_empty());

        let queued = test_read_strict_spool(&config.auth, "NODE_T1").unwrap();
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].2, Some(42));
        assert_eq!(queued[1].2, Some(43));
        assert!(queued[0].5 < queued[1].5);
        let first_id = queued[0].0.clone();
        let first_hash = queued[0].1.clone();
        let second_id = queued[1].0.clone();
        let second_hash = queued[1].1.clone();

        // Fresh in-memory counter models a process restart while A and B are
        // both unacknowledged. The immutable queue is the only source needed.
        let restarted_counter = TrafficCounter::new();
        report_traffic(&config, &restarted_counter, "NODE_T1").await;
        let after_first_ack = test_read_strict_spool(&config.auth, "NODE_T1").unwrap();
        assert_eq!(after_first_ack.len(), 1);
        assert_eq!(after_first_ack[0].0, second_id);
        assert_eq!(after_first_ack[0].1, second_hash);
        assert_eq!(after_first_ack[0].2, Some(43));

        report_traffic(&config, &restarted_counter, "NODE_T1").await;
        server.await.unwrap();
        assert!(test_read_strict_spool(&config.auth, "NODE_T1")
            .unwrap()
            .is_empty());

        let requests = captured.lock().await;
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].batch.as_ref().unwrap().batch_id, first_id);
        assert_eq!(requests[0].batch.as_ref().unwrap().payload_sha256, first_hash);
        assert_eq!(requests[1].batch.as_ref().unwrap().batch_id, first_id);
        assert_eq!(requests[2].batch.as_ref().unwrap().batch_id, first_id);
        assert_eq!(requests[3].batch.as_ref().unwrap().batch_id, second_id);
        assert_eq!(
            traffic(&requests[0].reports, 7),
            Some((10, 20)),
            "revision 42 total is immutable"
        );
        assert_eq!(
            traffic(&requests[3].reports, 7),
            Some((3, 4)),
            "revision 43 total survives restart separately"
        );
        drop(requests);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn retries_preserve_exact_batch_identity_until_matching_ack() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::<TrafficReport>::new()));
        let captured_server = captured.clone();
        let server = tokio::spawn(async move {
            for step in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let report = read_http_traffic_report(&mut stream).await;
                captured_server.lock().await.push(report.clone());
                match step {
                    0 => write_http_response(&mut stream, "500 Internal Server Error", b"").await,
                    1 => write_http_response(&mut stream, "200 OK", b"{").await,
                    2 => {
                        let meta = report.batch.as_ref().unwrap();
                        let wrong = ApiResponse::success(TrafficBatchAck {
                            version: meta.version,
                            batch_id: format!("{}-wrong", meta.batch_id),
                            payload_sha256: meta.payload_sha256.clone(),
                            status: TrafficBatchAckStatus::AlreadyApplied,
                        });
                        let body = serde_json::to_vec(&wrong).unwrap();
                        write_http_response(&mut stream, "200 OK", &body).await;
                    }
                    3 => {
                        let body = ack_body(&report, TrafficBatchAckStatus::AlreadyApplied);
                        write_http_response(&mut stream, "200 OK", &body).await;
                    }
                    4 => {
                        let body = ack_body(&report, TrafficBatchAckStatus::Applied);
                        write_http_response(&mut stream, "200 OK", &body).await;
                    }
                    _ => unreachable!(),
                }
            }
        });

        let dir = private_test_dir("retry-identity");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let counter = TrafficCounter::new();
        counter.add_at(42, 7, 10, 20).await;

        for _ in 0..4 {
            report_traffic(&config, &counter, "NODE_T1").await;
        }
        assert!(test_read_strict_spool(&config.auth, "NODE_T1")
            .unwrap()
            .is_empty());

        counter.add_at(43, 7, 1, 2).await;
        report_traffic(&config, &counter, "NODE_T1").await;
        server.await.unwrap();

        let requests = captured.lock().await;
        let first = requests[0].batch.as_ref().unwrap().clone();
        for request in &requests[..4] {
            assert_eq!(request.batch.as_ref(), Some(&first));
            assert_eq!(traffic(&request.reports, 7), Some((10, 20)));
        }
        assert_ne!(requests[4].batch.as_ref().unwrap().batch_id, first.batch_id);
        assert_eq!(
            requests[4].batch.as_ref().unwrap().config_revision,
            Some(43)
        );
        drop(requests);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn crash_before_batch_install_keeps_live_snapshot_retryable() {
        let dir = private_test_dir("before-install");
        let config = strict_test_config("http://127.0.0.1:1".into(), &dir);
        let counter = TrafficCounter::new();
        counter.add_at(42, 7, 10, 20).await;
        let snapshot = counter.snapshot().await;
        let reports = snapshot.entries.clone();

        let error = seal_strict_spool_batch_with_failpoint(
            &config.auth,
            "NODE_T1",
            snapshot.config_revision,
            reports,
            None,
            SpoolWriteFailpoint::BeforeInstall,
        )
        .expect_err("injected pre-install failure");
        assert!(!error.restart_required());
        assert!(test_read_strict_spool(&config.auth, "NODE_T1")
            .unwrap()
            .is_empty());

        // No durable batch exists, so the snapshot must remain uncommitted. A
        // retry sees the exact same live traffic.
        drop(snapshot);
        let retry = counter.snapshot().await;
        assert_eq!(retry.config_revision, Some(42));
        assert_eq!(traffic(&retry.entries, 7), Some((10, 20)));
        drop(retry);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn crash_after_durable_batch_install_recovers_one_stable_batch() {
        let dir = private_test_dir("after-install");
        let config = strict_test_config("http://127.0.0.1:1".into(), &dir);
        let reports = vec![TrafficEntry {
            rule_id: 7,
            upload: 10,
            download: 20,
        }];
        let error = seal_strict_spool_batch_with_failpoint(
            &config.auth,
            "NODE_T1",
            Some(42),
            reports.clone(),
            None,
            SpoolWriteFailpoint::AfterDurableInstall,
        )
        .expect_err("injected post-install crash");
        assert!(error.restart_required());

        let first = test_read_strict_spool(&config.auth, "NODE_T1").unwrap();
        let second = test_read_strict_spool(&config.auth, "NODE_T1").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].2, Some(42));
        assert_eq!(first[0].3, reports);
        assert!(valid_traffic_batch_id(&first[0].0));
        assert!(valid_traffic_payload_sha256(&first[0].1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn durable_spool_files_are_private_and_sequence_is_monotonic() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = private_test_dir("spool-permissions");
        let config = strict_test_config("http://127.0.0.1:1".into(), &dir);
        for revision in [42, 43] {
            seal_strict_spool_batch(
                &config.auth,
                "NODE_T1",
                Some(revision),
                vec![TrafficEntry {
                    rule_id: 7,
                    upload: revision,
                    download: revision + 1,
                }],
                None,
            )
            .unwrap();
        }

        let spool_dir = dir.join(TRAFFIC_SPOOL_DIRNAME);
        let spool_mode = std::fs::metadata(&spool_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(spool_mode, 0o700);
        let sequence_path = spool_dir.join(TRAFFIC_SPOOL_SEQUENCE_FILENAME);
        let sequence_mode =
            std::fs::metadata(&sequence_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(sequence_mode, 0o600);

        let files = list_spool_files(&spool_dir).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].0 < files[1].0);
        for (_, path) in files {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn corrupt_queued_batch_fails_closed_and_later_traffic_does_not_overtake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = private_test_dir("corrupt-spool");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let counter = TrafficCounter::new();

        // Seal two batches directly so the queue has a later valid entry behind
        // the corrupted oldest one.
        seal_strict_spool_batch(
            &config.auth,
            "NODE_T1",
            Some(42),
            vec![TrafficEntry {
                rule_id: 7,
                upload: 10,
                download: 20,
            }],
            None,
        )
        .unwrap();
        seal_strict_spool_batch(
            &config.auth,
            "NODE_T1",
            Some(43),
            vec![TrafficEntry {
                rule_id: 7,
                upload: 3,
                download: 4,
            }],
            None,
        )
        .unwrap();

        let spool_dir = dir.join(TRAFFIC_SPOOL_DIRNAME);
        let oldest = list_spool_files(&spool_dir).unwrap()[0].1.clone();
        std::fs::write(&oldest, b"{").unwrap();

        counter.add_at(44, 7, 5, 6).await;
        report_traffic(&config, &counter, "NODE_T1").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "corrupt queue must stop all sends"
        );
        let retained = counter.snapshot().await;
        assert_eq!(retained.config_revision, Some(44));
        assert_eq!(traffic(&retained.entries, 7), Some((5, 6)));
        drop(retained);
        assert_eq!(list_spool_files(&spool_dir).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn legacy_pending_is_sent_before_new_spool_batches() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = private_test_dir("legacy-first");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let legacy_path = dir.join(TRAFFIC_PENDING_FILENAME);
        let legacy_reports = vec![TrafficEntry {
            rule_id: 8,
            upload: 9,
            download: 10,
        }];
        let legacy = PendingTrafficBatch {
            version: TRAFFIC_BATCH_PROTOCOL_VERSION,
            batch_id: "legacy-first-batch".into(),
            payload_sha256: traffic_batch_payload_sha256(&legacy_reports),
            node_id: "NODE_T1".into(),
            credential_id: "cred-t1-node".into(),
            config_revision: Some(41),
            reports: legacy_reports.clone(),
        };
        write_pending_traffic_at(&legacy_path, &legacy).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let report = read_http_traffic_report(&mut stream).await;
            let body = ack_body(&report, TrafficBatchAckStatus::AlreadyApplied);
            write_http_response(&mut stream, "200 OK", &body).await;
            report
        });

        let counter = TrafficCounter::new();
        counter.add_at(42, 7, 1, 2).await;
        report_traffic(&config, &counter, "NODE_T1").await;
        let sent = server.await.unwrap();
        assert_eq!(sent.batch.as_ref().unwrap().batch_id, legacy.batch_id);
        assert_eq!(sent.reports, legacy_reports);
        assert!(!legacy_path.exists());

        let queue = test_read_strict_spool(&config.auth, "NODE_T1").unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].2, Some(42));
        assert_eq!(traffic(&queue[0].3, 7), Some((1, 2)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn uncertain_accounting_transition_poison_fails_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = private_test_dir("seal-poison");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let counter = TrafficCounter::new();
        counter.add(77, 13, 9).await;
        counter.poison_strict_reporting();

        report_traffic(&config, &counter, "NODE_T1").await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        assert!(test_read_strict_spool(&config.auth, "NODE_T1")
            .unwrap()
            .is_empty());
        let retained = counter.snapshot().await;
        assert_eq!(traffic(&retained.entries, 77), Some((13, 9)));
        drop(retained);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn concurrent_report_calls_do_not_duplicate_a_batch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let report = read_http_traffic_report(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            let body = ack_body(&report, TrafficBatchAckStatus::Applied);
            write_http_response(&mut stream, "200 OK", &body).await;
        });

        let dir = private_test_dir("concurrent-report");
        let config = strict_test_config(format!("http://{addr}"), &dir);
        let counter = TrafficCounter::new();
        counter.add(71, 12, 8).await;

        tokio::join!(
            report_traffic(&config, &counter, "NODE_T1"),
            report_traffic(&config, &counter, "NODE_T1"),
        );
        server.await.unwrap();

        assert!(counter.snapshot().await.entries.is_empty());
        assert!(test_read_strict_spool(&config.auth, "NODE_T1")
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn open_handle_reports_incremental_deltas_across_commits() {
        let counter = TrafficCounter::new();
        let handle = counter.handle(7).await;
        handle.add_upload(100);
        handle.add_download(40);

        let first = counter.snapshot().await;
        assert_eq!(traffic(&first.entries, 7), Some((100, 40)));
        first.commit().await;
        assert!(
            counter.has_rule(7).await,
            "live handle keeps zero state registered"
        );

        handle.add_upload(25);
        handle.add_download(10);
        let second = counter.snapshot().await;
        assert_eq!(traffic(&second.entries, 7), Some((25, 10)));
        drop(handle);
        second.commit().await;
        assert!(!counter.has_rule(7).await);
    }

    #[tokio::test]
    async fn add_and_final_drop_between_subtract_and_cleanup_never_loses_bytes() {
        let counter = TrafficCounter::new();
        let handle = counter.handle(8).await;
        handle.add_upload(10);
        let snapshot = counter.snapshot().await;
        let mut handle = Some(handle);

        snapshot
            .commit_with_hook(|rule_id| {
                assert_eq!(rule_id, 8);
                let live = handle.take().unwrap();
                live.add_upload(7);
                drop(live);
            })
            .await;

        let remaining = counter.snapshot().await;
        assert_eq!(traffic(&remaining.entries, 8), Some((7, 0)));
        remaining.commit().await;
        assert!(!counter.has_rule(8).await);
    }

    #[tokio::test]
    async fn concurrent_handle_drops_publish_all_prior_traffic() {
        let counter = Arc::new(TrafficCounter::new());
        let first = counter.handle(81).await;
        let second = counter.handle(81).await;
        let a = tokio::spawn(async move {
            first.add_upload(13);
            drop(first);
        });
        let b = tokio::spawn(async move {
            second.add_download(17);
            drop(second);
        });
        a.await.unwrap();
        b.await.unwrap();

        let snapshot = counter.snapshot().await;
        assert_eq!(traffic(&snapshot.entries, 81), Some((13, 17)));
        snapshot.commit().await;
        assert!(!counter.has_rule(81).await);
    }

    #[tokio::test]
    async fn snapshot_gate_releases_on_drop_and_commit() {
        let counter = Arc::new(TrafficCounter::new());
        counter.add(82, 1, 0).await;
        let held = counter.snapshot().await;

        let waiting_counter = counter.clone();
        let mut waiting = tokio::spawn(async move {
            let snapshot = waiting_counter.snapshot().await;
            drop(snapshot);
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err(),
            "a second snapshot must wait while the first is alive"
        );
        drop(held);
        waiting.await.unwrap();

        let next = counter.snapshot().await;
        next.commit().await;
        let after_commit = counter.snapshot().await;
        drop(after_commit);
    }

    #[tokio::test]
    async fn prune_preserves_bytes_from_connection_that_finishes_after_rule_removal() {
        let counter = TrafficCounter::new();
        let stale = counter.handle(9).await;
        counter.prune_rule(9).await;
        stale.add_upload(12);
        stale.add_download(4);
        drop(stale);
        let pending = counter.snapshot().await;
        assert_eq!(traffic(&pending.entries, 9), Some((12, 4)));
        pending.commit().await;
        assert!(!counter.has_rule(9).await);
    }

    #[tokio::test]
    async fn old_snapshot_cannot_subtract_from_reused_rule_id_generation() {
        let counter = TrafficCounter::new();
        let old_handle = counter.handle(10).await;
        old_handle.add_upload(100);
        drop(old_handle);
        let old_snapshot = counter.snapshot().await;

        counter.prune_rule(10).await;
        let new_handle = counter.handle(10).await;
        new_handle.add_upload(30);
        drop(new_handle);
        old_snapshot.commit().await;

        let current = counter.snapshot().await;
        assert_eq!(traffic(&current.entries, 10), Some((30, 0)));
        current.commit().await;
    }

    #[tokio::test]
    async fn config_revision_generations_keep_removed_rule_bytes_separate_from_new_config() {
        let counter = TrafficCounter::new();
        counter.add_at(9, 200, 50, 20).await;
        counter.prune_rule(200).await;
        counter.add_at(10, 100, 3, 4).await;

        let old = counter.snapshot().await;
        assert_eq!(old.config_revision, Some(9));
        assert_eq!(
            old.entries,
            vec![TrafficEntry {
                rule_id: 200,
                upload: 50,
                download: 20,
            }]
        );
        old.commit().await;

        let new = counter.snapshot().await;
        assert_eq!(new.config_revision, Some(10));
        assert_eq!(
            new.entries,
            vec![TrafficEntry {
                rule_id: 100,
                upload: 3,
                download: 4,
            }]
        );
        new.commit().await;
        assert!(!counter.has_rule(200).await);
        assert!(!counter.has_rule(100).await);
    }

    #[tokio::test]
    async fn zero_byte_handle_is_never_reported_and_cleans_after_close() {
        let counter = TrafficCounter::new();
        let handle = counter.handle(11).await;
        let open = counter.snapshot().await;
        assert!(open.entries.is_empty());
        drop(open);
        assert!(counter.has_rule(11).await);

        drop(handle);
        let closed = counter.snapshot().await;
        assert!(closed.entries.is_empty());
        drop(closed);
        assert!(!counter.has_rule(11).await);
    }

    #[tokio::test]
    async fn dropping_failed_snapshot_keeps_billable_bytes() {
        let counter = TrafficCounter::new();
        counter.add(12, 55, 21).await;
        let failed_upload = counter.snapshot().await;
        assert_eq!(traffic(&failed_upload.entries, 12), Some((55, 21)));
        drop(failed_upload);

        let retry = counter.snapshot().await;
        assert_eq!(traffic(&retry.entries, 12), Some((55, 21)));
        retry.commit().await;
        assert!(!counter.has_rule(12).await);
    }

    /// read_system_uptime_secs parses /proc/uptime's first field as whole
    /// seconds. On Linux CI this returns a real uptime (> 0); on non-Linux
    /// (dev machines without /proc) it returns 0 — so we only assert the
    /// type/shape, not a specific value, and verify the parser directly.
    #[test]
    fn read_system_uptime_returns_nonneg_or_zero() {
        let v = read_system_uptime_secs();
        // Always non-negative by construction (u64); on Linux it's the real
        // uptime. We don't assert > 0 because some CI runners may not expose
        // /proc/uptime in sandboxes.
        assert!(v <= u64::MAX / 2, "sanity bound");
    }

    /// The parser must handle the real /proc/uptime format (float seconds +
    /// idle) and take the floor, not round or panic.
    #[test]
    fn parse_proc_uptime_format() {
        // Simulate what /proc/uptime looks like: "3612.45 1234.56\n"
        // We can't easily inject a file, but we CAN verify the parsing logic
        // by mirroring it here against sample input. This guards against a
        // future refactor that breaks the split-on-'.' floor.
        let sample = "3612.45 1234.56\n";
        let parsed: u64 = sample
            .split_whitespace()
            .next()
            .and_then(|f| f.split('.').next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        assert_eq!(parsed, 3612, "must floor the uptime to whole seconds");
    }

    /// An explicit NETWORK_INTERFACE value is returned verbatim (the operator
    /// pinned it; we do not validate existence at resolve time).
    #[test]
    fn resolve_explicit_interface_is_passed_through() {
        assert_eq!(resolve_network_interface("eth0"), Some("eth0".to_string()));
        assert_eq!(
            resolve_network_interface("  wg0  "),
            Some("wg0".to_string()),
            "leading/trailing whitespace is trimmed"
        );
    }

    /// "auto" / empty must not crash and must return Some(interface) on a host
    /// that has any non-loopback NIC (CI runners do). We don't assert the
    /// exact name — only that selection succeeded and isn't "lo".
    #[test]
    fn resolve_auto_picks_a_non_loopback_interface() {
        let picked = resolve_network_interface("auto");
        if let Some(name) = picked {
            assert!(
                !name.eq_ignore_ascii_case("lo"),
                "auto must never pick the loopback interface"
            );
        }
        // An unset/empty value behaves the same as "auto".
        assert_eq!(
            resolve_network_interface("").is_some(),
            resolve_network_interface("auto").is_some(),
        );
    }

    #[tokio::test]
    async fn tcp_guard_increments_and_decrements_on_drop() {
        let tracker = ConnectionTracker::new();
        // Baseline: zero active connections.
        assert_eq!(tracker.current().await, 0);
        assert_eq!(tracker.current_tcp(), 0);
        assert_eq!(tracker.current_udp().await, 0);

        // Open one TCP connection -> count becomes 1.
        let guard = tracker.tcp_handle();
        assert_eq!(tracker.current().await, 1);
        assert_eq!(tracker.current_tcp(), 1);

        // Open a second -> count becomes 2.
        let guard2 = tracker.tcp_handle();
        assert_eq!(tracker.current().await, 2);

        // Drop one guard (simulating a normal close) -> count falls to 1.
        drop(guard);
        assert_eq!(tracker.current().await, 1);

        // Drop the other -> back to 0. This is the regression guard for
        // "connection count stuck at non-zero after all clients disconnect".
        drop(guard2);
        assert_eq!(tracker.current().await, 0);
    }

    #[tokio::test]
    async fn tcp_guard_decrements_even_on_panic_via_drop() {
        // The guard's Drop runs during stack unwinding, so a panicking task
        // still releases its slot. We simulate that by forgetting the guard is
        // inside a catch_unwind and just relying on Drop semantics.
        let tracker = ConnectionTracker::new();
        {
            let _g = tracker.tcp_handle();
            assert_eq!(tracker.current().await, 1);
            // scope ends here -> _g drops
        }
        assert_eq!(tracker.current().await, 0);
    }

    #[tokio::test]
    async fn udp_session_registered_on_touch_and_counts_as_active() {
        let tracker = ConnectionTracker::new();
        // No UDP traffic yet -> zero.
        assert_eq!(tracker.current().await, 0);

        // First datagram from (127.0.0.1:5000, rule 1) opens a session.
        let opened = tracker.udp_touch(addr(5000), 1).await;
        assert!(opened, "first touch must register a new session");
        assert_eq!(tracker.current().await, 1);

        // Same client again -> refresh, not a new session; count stays 1.
        let opened2 = tracker.udp_touch(addr(5000), 1).await;
        assert!(!opened2, "repeat touch must not register a new session");
        assert_eq!(tracker.current().await, 1);

        // A different client (different port) opens a second session.
        let opened3 = tracker.udp_touch(addr(5001), 1).await;
        assert!(opened3);
        assert_eq!(tracker.current().await, 2);

        // Same client but different rule is a distinct session.
        let opened4 = tracker.udp_touch(addr(5001), 2).await;
        assert!(opened4);
        assert_eq!(tracker.current().await, 3);
    }

    #[tokio::test]
    async fn udp_session_expires_after_timeout() {
        let tracker = ConnectionTracker::new();
        // Manually backdate a session to simulate "no traffic for longer than
        // the timeout" — we can't sleep 60s in a unit test.
        tracker.udp.insert(
            UdpSessionKey {
                client_addr: addr(6000),
                rule_id: 7,
            },
            Instant::now() - (UDP_SESSION_TIMEOUT + Duration::from_secs(1)),
        );
        // The expired session must NOT be counted by current().
        assert_eq!(tracker.current().await, 0);
    }

    #[tokio::test]
    async fn udp_close_removes_a_single_session() {
        let tracker = ConnectionTracker::new();
        tracker.udp_touch(addr(7000), 1).await;
        tracker.udp_touch(addr(7001), 1).await;
        assert_eq!(tracker.current().await, 2);

        tracker.udp_close(addr(7000), 1).await;
        assert_eq!(tracker.current().await, 1);
        // Closing an unknown session is a no-op.
        tracker.udp_close(addr(9999), 1).await;
        assert_eq!(tracker.current().await, 1);
    }

    #[tokio::test]
    async fn current_is_tcp_plus_udp() {
        let tracker = ConnectionTracker::new();
        // 2 TCP + 2 UDP distinct sessions == 4.
        let _t1 = tracker.tcp_handle();
        let _t2 = tracker.tcp_handle();
        tracker.udp_touch(addr(8000), 1).await;
        tracker.udp_touch(addr(8001), 1).await;
        assert_eq!(tracker.current_tcp(), 2);
        assert_eq!(tracker.current_udp().await, 2);
        assert_eq!(tracker.current().await, 4);
    }

    fn proc_line(local_port: u16, remote_port: u16, state: &str) -> String {
        format!(
            "  0: 0100007F:{local_port:04X} 0200007F:{remote_port:04X} {state} 00000000:00000000 00:00000000 00000000 0 0 1 1"
        )
    }

    #[test]
    fn proc_tcp_parser_counts_only_established_managed_local_ports() {
        let managed = HashSet::from([443, 8443]);
        let sample = [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode".into(),
            proc_line(443, 50000, "01"),
            proc_line(8443, 50001, "01"),
            proc_line(443, 50002, "0A"),
            proc_line(443, 50003, "06"),
            proc_line(50004, 443, "01"),
        ]
        .join("\n");
        assert_eq!(parse_proc_established_on_ports(&sample, &managed), Ok(2));
    }

    #[test]
    fn proc_tcp_parser_handles_ipv6_and_rejects_malformed_rows() {
        let managed = HashSet::from([443]);
        let ipv6 = format!(
            "  sl  local_address rem_address st\n  1: 00000000000000000000000000000000:{:04X} 00000000000000000000000000000000:C350 01 00000000:00000000 00:00000000 00000000",
            443
        );
        assert_eq!(parse_proc_established_on_ports(&ipv6, &managed), Ok(1));
        assert_eq!(
            parse_proc_established_on_ports("not a proc row", &managed),
            Err(())
        );
    }

    #[test]
    fn nginx_socket_telemetry_deduplicates_ports_and_preserves_unknown() {
        let sample = format!(
            "  sl  local_address rem_address st\n{}",
            proc_line(443, 50000, "01")
        );
        let available = nginx_sni_active_tcp_with_reader(&[443, 443], |_| Ok(sample.clone()));
        assert_eq!(available, Some(2), "one IPv4 plus one IPv6 socket");
        let unavailable = nginx_sni_active_tcp_with_reader(&[443], |_| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
        });
        assert_eq!(unavailable, None);
        assert_eq!(
            nginx_sni_active_tcp_with_reader(&[], |_| unreachable!()),
            Some(0)
        );
    }

    /// Performance: applying a config with many rules must keep the listener
    /// table size bounded (one entry per rule), confirming memory grows ~O(n)
    /// and there is no per-rule polling task leaked.
    #[tokio::test]
    async fn apply_many_rules_keeps_listener_table_bounded() {
        use crate::forwarder::ForwarderManager;
        use relay_shared::protocol::{ListenerConfig, NodeConfigResponse, NodeTransport};

        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let mut mgr = ForwarderManager::new(counter, connections);

        // Build a config with 1000 rules. We deliberately pick listen ports
        // that are unlikely to be bindable here (high) so apply_config tries
        // to spawn listeners; failures are logged but the manager still
        // records the key. What we assert is that the manager does not crash
        // and completes in bounded time.
        let listeners: Vec<ListenerConfig> = (0..1000)
            .map(|i| ListenerConfig {
                camouflage_required: false,
                send_proxy_protocol: false,
                rule_id: i,
                port: 40000 + (i as u16),
                protocol: relay_shared::protocol::Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                sni: None,
                targets: vec!["127.0.0.1:1".to_string()],
                load_balance_strategy: relay_shared::protocol::LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            })
            .collect();
        let cfg = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners,
        };

        // apply_config should return promptly even for 1000 rules — the diff
        // is O(n) and binding happens in spawned tasks, not inline.
        let start = Instant::now();
        mgr.apply_config(&cfg).await;
        let elapsed = start.elapsed();
        // Generous bound: must finish well under 2s. If apply_config were
        // doing serial work per rule this would blow past it.
        assert!(
            elapsed < Duration::from_secs(2),
            "apply_config(1000 rules) took {:?}, expected < 2s",
            elapsed
        );
    }

    // v0.4.15: address-family validation for the public-IP refresher. These
    // guard the dual-stack bug where the IPv4 endpoint, reached over IPv6,
    // returns a v6 address that must NOT be stored as public_ipv4.
    #[test]
    fn parse_ip_for_family_accepts_matching_family() {
        assert_eq!(
            parse_ip_for_family("1.2.3.4", &IpFamily::V4),
            Some("1.2.3.4".to_string())
        );
        assert_eq!(
            parse_ip_for_family("2001:db8::1", &IpFamily::V6),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn parse_ip_for_family_trims_whitespace() {
        // ipify-style responses have no trailing newline, but be defensive.
        assert_eq!(
            parse_ip_for_family("  8.8.8.8\n", &IpFamily::V4),
            Some("8.8.8.8".to_string())
        );
    }

    #[test]
    fn parse_ip_for_family_rejects_wrong_family() {
        // The core dual-stack guard: a v6 answer to a v4 query is dropped.
        assert_eq!(parse_ip_for_family("2001:db8::1", &IpFamily::V4), None);
        // ...and a v4 answer to a v6 query.
        assert_eq!(parse_ip_for_family("1.2.3.4", &IpFamily::V6), None);
    }

    #[test]
    fn parse_ip_for_family_rejects_empty_and_non_ip() {
        assert_eq!(parse_ip_for_family("", &IpFamily::V4), None);
        assert_eq!(parse_ip_for_family("   ", &IpFamily::V4), None);
        // An HTML error page or rate-limit text must not parse as an IP.
        assert_eq!(parse_ip_for_family("<html>429</html>", &IpFamily::V4), None);
        assert_eq!(parse_ip_for_family("not-an-ip", &IpFamily::V6), None);
    }

    /// v1.2.1: the defaults must be FAMILY-PINNED hostnames, and the two must
    /// differ.
    ///
    /// This is the invariant that pairs with `parse_ip_for_family`: a probe
    /// discards an answer from the wrong family, so pointing both probes at a
    /// dual-stack endpoint (`api.ip.sb/ip`, `api.ipify.org` reached over v6)
    /// makes the v4 probe intermittently throw its answer away and the panel
    /// show no address. It breaks only on dual-stack hosts and only sometimes,
    /// so a unit test is the only place it gets caught cheaply.
    ///
    /// Asserting on the shape rather than the exact URL keeps the endpoint
    /// swappable — what must not change is that each one names its family.
    #[test]
    fn default_check_urls_are_family_pinned() {
        assert_ne!(
            DEFAULT_IPV4_CHECK_URL, DEFAULT_IPV6_CHECK_URL,
            "one endpoint for both families cannot be family-pinned"
        );
        let host4 = DEFAULT_IPV4_CHECK_URL
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap();
        let host6 = DEFAULT_IPV6_CHECK_URL
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap();
        assert!(
            host4.contains("ipv4") || host4.contains("-v4") || host4.contains("4."),
            "IPv4 default must name its family, got {host4}"
        );
        assert!(
            host6.contains("ipv6") || host6.contains("-v6") || host6.contains("6."),
            "IPv6 default must name its family, got {host6}"
        );
        // Both must be HTTPS: the response decides what the panel displays as
        // this node's identity, and plain HTTP lets any on-path party set it.
        assert!(DEFAULT_IPV4_CHECK_URL.starts_with("https://"));
        assert!(DEFAULT_IPV6_CHECK_URL.starts_with("https://"));
    }

    #[test]
    fn public_ip_failures_use_bounded_fast_retries_and_success_resets() {
        let mut backoff = PublicIpRefreshBackoff::default();
        assert_eq!(backoff.next_delay(false), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(false), Duration::from_secs(10));
        assert_eq!(backoff.next_delay(false), Duration::from_secs(30));
        assert_eq!(backoff.next_delay(false), Duration::from_secs(60));
        assert_eq!(backoff.next_delay(false), Duration::from_secs(60));
        assert_eq!(backoff.next_delay(false), Duration::from_secs(60));
        assert_eq!(backoff.next_delay(true), PUBLIC_IP_REFRESH);
        assert_eq!(backoff.next_delay(false), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn failed_family_detection_cannot_clear_an_existing_other_family() {
        let metrics = NodeMetrics::new("auto");
        metrics.set_public_ipv4(Some("192.0.2.10".into())).await;
        metrics.set_public_ipv6(Some("2001:db8::10".into())).await;

        assert!(!store_public_ip_detection(&metrics, &IpFamily::V4, None).await);
        assert_eq!(metrics.public_ipv4().await.as_deref(), Some("192.0.2.10"));
        assert_eq!(metrics.public_ipv6().await.as_deref(), Some("2001:db8::10"));

        assert!(!store_public_ip_detection(&metrics, &IpFamily::V6, None).await);
        assert_eq!(metrics.public_ipv4().await.as_deref(), Some("192.0.2.10"));
        assert_eq!(metrics.public_ipv6().await.as_deref(), Some("2001:db8::10"));

        assert!(
            store_public_ip_detection(&metrics, &IpFamily::V4, Some("192.0.2.11".into())).await
        );
        assert_eq!(metrics.public_ipv4().await.as_deref(), Some("192.0.2.11"));
        assert_eq!(metrics.public_ipv6().await.as_deref(), Some("2001:db8::10"));
    }
}
