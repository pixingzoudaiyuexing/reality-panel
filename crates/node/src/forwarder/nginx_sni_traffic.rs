use super::ForwarderManager;
use crate::config::NodeRuntimeAuth;
use crate::reporter::{
    recover_nginx_checkpoint, seal_nginx_traffic_batch, NginxTrafficCheckpoint, TrafficCounter,
};
use relay_shared::protocol::TrafficEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct NginxSniTrafficConfig {
    pub enabled: bool,
    pub access_log_path: PathBuf,
    pub state_path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct LogState {
    offset: u64,
    #[serde(default)]
    device: Option<u64>,
    #[serde(default)]
    inode: Option<u64>,
    #[serde(default)]
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl LogState {
    fn file_identity(&self) -> Option<FileIdentity> {
        Some(FileIdentity {
            device: self.device?,
            inode: self.inode?,
        })
    }

    fn set_file_identity(&mut self, identity: FileIdentity) {
        self.device = Some(identity.device);
        self.inode = Some(identity.inode);
    }

    fn begin_new_generation(&mut self) -> std::io::Result<()> {
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "nginx_sni traffic generation overflow",
            )
        })?;
        self.offset = 0;
        Ok(())
    }
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedLogLine {
    port: u16,
    sni: String,
    rule_id: Option<i64>,
    config_revision: Option<u64>,
    bytes_sent: u64,
    bytes_received: u64,
}

pub async fn ingest_once(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &Arc<TrafficCounter>,
    auth: &NodeRuntimeAuth,
    node_id: &str,
) {
    match ingest_once_inner(cfg, manager, counter, auth, node_id).await {
        Ok(n) if n > 0 => tracing::info!("nginx_sni traffic: ingested {} log line(s)", n),
        Ok(_) => {}
        Err(e) => tracing::warn!("nginx_sni traffic ingest failed: {}", e),
    }
}

async fn ingest_once_inner(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &Arc<TrafficCounter>,
    auth: &NodeRuntimeAuth,
    node_id: &str,
) -> std::io::Result<usize> {
    ingest_once_inner_with_state_writer(cfg, manager, counter, auth, node_id, save_state).await
}

async fn ingest_once_inner_with_state_writer<F>(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &Arc<TrafficCounter>,
    auth: &NodeRuntimeAuth,
    node_id: &str,
    write_state: F,
) -> std::io::Result<usize>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    ingest_once_inner_with_failpoints(
        cfg,
        manager,
        counter,
        auth,
        node_id,
        None,
        write_state,
    )
    .await
}

async fn ingest_once_inner_with_failpoints<F>(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &Arc<TrafficCounter>,
    auth: &NodeRuntimeAuth,
    node_id: &str,
    read_error_after_complete_lines: Option<usize>,
    mut write_state: F,
) -> std::io::Result<usize>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    let _accounting_guard = counter.durable_accounting_guard().await;
    match auth {
        NodeRuntimeAuth::PermanentCredential { .. } => {
            if counter.strict_reporting_poisoned() {
                return Err(std::io::Error::other(
                    "strict traffic accounting is poisoned; restart required",
                ));
            }
            ingest_strict_locked(
                cfg,
                manager,
                counter,
                auth,
                node_id,
                read_error_after_complete_lines,
                &mut write_state,
            )
            .await
        }
        NodeRuntimeAuth::LegacyGroupToken { .. } => {
            if !cfg.enabled {
                return Ok(0);
            }
            ingest_legacy_locked(cfg, manager, counter, &mut write_state).await
        }
    }
}

fn prepare_state_for_file(
    state: &mut LogState,
    current_identity: FileIdentity,
    len: u64,
) -> std::io::Result<()> {
    match state.file_identity() {
        Some(persisted) if persisted != current_identity => {
            state.begin_new_generation()?;
            state.set_file_identity(current_identity);
        }
        _ if state.offset > len => {
            // copytruncate preserves dev+inode. Bump the logical generation so
            // old offset-0 checkpoints can never collide with the new contents.
            state.begin_new_generation()?;
            state.set_file_identity(current_identity);
        }
        _ => {
            // Legacy offset-only state is trusted once. Identity is recorded on
            // the next successful durable state write.
            state.set_file_identity(current_identity);
        }
    }
    Ok(())
}

async fn resolve_attribution(
    parsed: &ParsedLogLine,
    manager: &Arc<Mutex<ForwarderManager>>,
) -> Option<(u64, i64)> {
    if let (Some(revision), Some(rule_id)) = (parsed.config_revision, parsed.rule_id) {
        return Some((revision, rule_id));
    }
    let current_rule_id = {
        let mgr = manager.lock().await;
        mgr.nginx_sni_rule_id_for(parsed.port, &parsed.sni)
    };
    match (parsed.rule_id, current_rule_id) {
        (Some(logged), Some(current)) if logged == current => Some((0, current)),
        (None, Some(current)) => Some((0, current)),
        _ => None,
    }
}

fn add_segment_traffic(
    totals: &mut BTreeMap<i64, (u64, u64)>,
    rule_id: i64,
    upload: u64,
    download: u64,
) -> std::io::Result<()> {
    let entry = totals.entry(rule_id).or_insert((0, 0));
    entry.0 = entry.0.checked_add(upload).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "nginx_sni upload accounting overflow",
        )
    })?;
    entry.1 = entry.1.checked_add(download).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "nginx_sni download accounting overflow",
        )
    })?;
    Ok(())
}

fn source_key(cfg: &NginxSniTrafficConfig) -> String {
    cfg.state_path.to_string_lossy().into_owned()
}

fn cursor_tuple(state: &LogState) -> Option<(u64, u64, u64, u64)> {
    let identity = state.file_identity()?;
    Some((
        identity.device,
        identity.inode,
        state.generation,
        state.offset,
    ))
}

fn recover_committed_checkpoints<F>(
    cfg: &NginxSniTrafficConfig,
    counter: &TrafficCounter,
    auth: &NodeRuntimeAuth,
    node_id: &str,
    state: &mut Option<LogState>,
    write_state: &mut F,
) -> std::io::Result<()>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    let source = source_key(cfg);
    loop {
        let cursor = state.as_ref().and_then(cursor_tuple);
        let checkpoint =
            recover_nginx_checkpoint(auth, node_id, &source, cursor).map_err(std::io::Error::other)?;
        let Some(checkpoint) = checkpoint else {
            break;
        };
        let mut recovered = state.clone().unwrap_or_default();
        recovered.device = Some(checkpoint.device);
        recovered.inode = Some(checkpoint.inode);
        recovered.generation = checkpoint.generation;
        recovered.offset = checkpoint.end_offset;
        if let Err(error) = write_state(&cfg.state_path, &recovered) {
            counter.poison_strict_reporting();
            return Err(error);
        }
        *state = Some(recovered);
    }
    Ok(())
}

async fn flush_strict_segment<F>(
    cfg: &NginxSniTrafficConfig,
    counter: &TrafficCounter,
    auth: &NodeRuntimeAuth,
    node_id: &str,
    current_identity: FileIdentity,
    state: &mut LogState,
    persisted_state: &mut LogState,
    segment_start: u64,
    segment_end: u64,
    revision: u64,
    totals: &BTreeMap<i64, (u64, u64)>,
    write_state: &mut F,
) -> std::io::Result<()>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    if totals.is_empty() || segment_end <= segment_start {
        return Ok(());
    }
    let reports = totals
        .iter()
        .map(|(rule_id, (upload, download))| TrafficEntry {
            rule_id: *rule_id,
            upload: *upload,
            download: *download,
        })
        .collect::<Vec<_>>();
    let checkpoint = NginxTrafficCheckpoint {
        source: source_key(cfg),
        device: current_identity.device,
        inode: current_identity.inode,
        generation: state.generation,
        start_offset: segment_start,
        end_offset: segment_end,
    };

    if let Err(error) = seal_nginx_traffic_batch(
        auth,
        node_id,
        (revision != 0).then_some(revision),
        reports,
        checkpoint,
    ) {
        if error.restart_required() {
            counter.poison_strict_reporting();
        }
        return Err(std::io::Error::other(error.message().to_string()));
    }

    // Recoverable transition:
    //   durable source bytes -> durable immutable spool -> durable cursor.
    // The cursor never advances before the spool is complete+fsynced. If the
    // cursor write fails, the process is poisoned before reporting can delete
    // the batch. On restart recover_committed_checkpoints() advances the cursor
    // from the immutable checkpoint before any Panel send or source re-read.
    state.offset = segment_end;
    state.set_file_identity(current_identity);
    if let Err(error) = write_state(&cfg.state_path, state) {
        counter.poison_strict_reporting();
        return Err(error);
    }
    *persisted_state = state.clone();
    Ok(())
}

async fn ingest_strict_locked<F>(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &TrafficCounter,
    auth: &NodeRuntimeAuth,
    node_id: &str,
    read_error_after_complete_lines: Option<usize>,
    write_state: &mut F,
) -> std::io::Result<usize>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    // Existing malformed/unreadable state fails closed; genuine NotFound is the
    // only case allowed to begin with a default cursor.
    let mut state = load_state_optional(&cfg.state_path)?;
    recover_committed_checkpoints(cfg, counter, auth, node_id, &mut state, write_state)?;

    // Recovery is intentionally performed even when ingestion is disabled or
    // the access log is temporarily absent, so a spool->cursor half-transition
    // cannot be ACKed/deleted by the reporter while an old cursor remains.
    if !cfg.enabled {
        return Ok(0);
    }

    let file = match std::fs::File::open(&cfg.access_log_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let len = metadata.len();
    let current_identity = file_identity(&metadata);

    let mut state = state.unwrap_or_default();
    prepare_state_for_file(&mut state, current_identity, len)?;
    let mut persisted_state = load_state_optional(&cfg.state_path)?.unwrap_or_else(|| state.clone());

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(state.offset))?;

    let mut processed = 0usize;
    let mut cursor = state.offset;
    let mut segment_start = cursor;
    let mut active_revision: Option<u64> = None;
    let mut totals = BTreeMap::<i64, (u64, u64)>::new();
    let mut complete_lines_read = 0usize;
    let mut line = String::new();

    loop {
        if read_error_after_complete_lines == Some(complete_lines_read) {
            return Err(std::io::Error::other(
                "injected Nginx read error after complete records",
            ));
        }
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if !line.ends_with('\n') {
            // read_line may return a final partial record at EOF. It stays
            // entirely before the durable cursor until its terminating newline.
            break;
        }
        let line_start = cursor;
        let line_end = cursor
            .checked_add(bytes as u64)
            .ok_or_else(|| std::io::Error::other("nginx_sni cursor overflow"))?;

        let attributed = match parse_log_line(&line) {
            Some(parsed) => resolve_attribution(&parsed, manager)
                .await
                .map(|(revision, rule_id)| {
                    (
                        revision,
                        rule_id,
                        parsed.bytes_received,
                        parsed.bytes_sent,
                    )
                }),
            None => None,
        };

        if let Some((revision, _, _, _)) = attributed {
            if active_revision.is_some_and(|active| active != revision) {
                let previous_revision = active_revision.expect("active revision");
                flush_strict_segment(
                    cfg,
                    counter,
                    auth,
                    node_id,
                    current_identity,
                    &mut state,
                    &mut persisted_state,
                    segment_start,
                    line_start,
                    previous_revision,
                    &totals,
                    write_state,
                )
                .await?;
                segment_start = line_start;
                totals.clear();
                active_revision = None;
            }
        }

        if let Some((revision, rule_id, upload, download)) = attributed {
            active_revision.get_or_insert(revision);
            add_segment_traffic(&mut totals, rule_id, upload, download)?;
            processed = processed
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("nginx_sni processed count overflow"))?;
        }
        cursor = line_end;
        complete_lines_read = complete_lines_read
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("nginx_sni line count overflow"))?;
    }

    if let Some(revision) = active_revision {
        flush_strict_segment(
            cfg,
            counter,
            auth,
            node_id,
            current_identity,
            &mut state,
            &mut persisted_state,
            segment_start,
            cursor,
            revision,
            &totals,
            write_state,
        )
        .await?;
    } else if cursor != state.offset {
        // Complete malformed/unattributable lines carry no billable traffic, so
        // advancing past them does not need a traffic batch.
        state.offset = cursor;
        state.set_file_identity(current_identity);
    }

    if state != persisted_state {
        write_state(&cfg.state_path, &state)?;
    }
    Ok(processed)
}

async fn ingest_legacy_locked<F>(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &TrafficCounter,
    write_state: &mut F,
) -> std::io::Result<usize>
where
    F: FnMut(&Path, &LogState) -> std::io::Result<()>,
{
    let mut state = load_state_optional(&cfg.state_path)?.unwrap_or_default();
    let file = match std::fs::File::open(&cfg.access_log_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let len = metadata.len();
    let current_identity = file_identity(&metadata);
    prepare_state_for_file(&mut state, current_identity, len)?;

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(state.offset))?;
    let mut cursor = state.offset;
    let mut additions = Vec::<(u64, i64, u64, u64)>::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if !line.ends_with('\n') {
            break;
        }
        let line_end = cursor
            .checked_add(bytes as u64)
            .ok_or_else(|| std::io::Error::other("nginx_sni cursor overflow"))?;
        if let Some(parsed) = parse_log_line(&line) {
            if let Some((revision, rule_id)) = resolve_attribution(&parsed, manager).await {
                additions.push((
                    revision,
                    rule_id,
                    parsed.bytes_received,
                    parsed.bytes_sent,
                ));
            }
        }
        cursor = line_end;
    }

    // Legacy group-token mode lacks the strict idempotent Panel contract. This
    // path keeps legacy semantics but still fails closed on malformed state and
    // refuses to consume an incomplete trailing record.
    for (revision, rule_id, upload, download) in &additions {
        counter
            .add_at(*revision, *rule_id, *upload, *download)
            .await;
    }
    state.offset = cursor;
    state.set_file_identity(current_identity);
    write_state(&cfg.state_path, &state)?;
    Ok(additions.len())
}

fn parse_log_line(line: &str) -> Option<ParsedLogLine> {
    let parts = line
        .trim_end_matches(['\r', '\n'])
        .split('|')
        .collect::<Vec<_>>();
    if parts.len() < 7 {
        return None;
    }
    let port = parts[1].parse::<u16>().ok()?;
    let sni = parts[2].trim().to_ascii_lowercase();
    let raw_rule_id = parts[3].trim();
    let rule_id = raw_rule_id.parse::<i64>().ok().filter(|id| *id > 0);
    let (config_revision, bytes_sent_index) = if parts.len() >= 8 {
        (parts[4].parse::<u64>().ok(), 5)
    } else {
        (None, 4)
    };
    let bytes_sent = parts[bytes_sent_index].parse::<u64>().ok()?;
    let bytes_received = parts[bytes_sent_index + 1].parse::<u64>().ok()?;
    if sni.is_empty() || sni == "-" {
        return None;
    }
    Some(ParsedLogLine {
        port,
        sni,
        rule_id,
        config_revision,
        bytes_sent,
        bytes_received,
    })
}

fn load_state_optional(path: &Path) -> std::io::Result<Option<LogState>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn load_state(path: &Path) -> std::io::Result<LogState> {
    load_state_optional(path)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nginx_sni traffic state does not exist",
        )
    })
}

fn save_state(path: &Path, state: &LogState) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "nginx_sni traffic state path has no parent",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec(state)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "nginx_sni traffic state filename is invalid",
            )
        })?;
    let temp = parent.join(format!(".{filename}.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    let pre_rename = (|| -> std::io::Result<()> {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = pre_rename {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    std::fs::File::open(parent)?.sync_all()?;
    let reopened = load_state(path)?;
    if reopened != *state {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "nginx_sni traffic state verification mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::{
        test_drain_strict_spool, test_read_strict_spool, ConnectionTracker,
    };
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt as _;
    use uuid::Uuid;

    struct TestPaths {
        dir: PathBuf,
        log: PathBuf,
        state: PathBuf,
    }

    impl TestPaths {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "reality-panel-nginx-sni-traffic-{}",
                Uuid::new_v4()
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                log: dir.join("access.log"),
                state: dir.join("state.json"),
                dir,
            }
        }

        fn config(&self) -> NginxSniTrafficConfig {
            NginxSniTrafficConfig {
                enabled: true,
                access_log_path: self.log.clone(),
                state_path: self.state.clone(),
            }
        }

        fn auth(&self) -> NodeRuntimeAuth {
            NodeRuntimeAuth::PermanentCredential {
                credential_id: "cred-nginx-test".into(),
                secret: "rpn1_node_nginx_test_secret".into(),
                secret_file: self.dir.join("node-credential.secret"),
                state_node_id: "NODE_T1".into(),
            }
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn traffic_context() -> (Arc<Mutex<ForwarderManager>>, Arc<TrafficCounter>) {
        let counter = Arc::new(TrafficCounter::new());
        let connections = Arc::new(ConnectionTracker::new());
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::clone(&counter),
            connections,
        )));
        (manager, counter)
    }

    fn revision_line(bytes_sent: u64, bytes_received: u64) -> String {
        format!("1723550000.123|443|OP1.Example.COM|12|9|{bytes_sent}|{bytes_received}|1.2\n")
    }

    async fn ingest_test_once(
        paths: &TestPaths,
        manager: &Arc<Mutex<ForwarderManager>>,
        counter: &Arc<TrafficCounter>,
    ) -> std::io::Result<usize> {
        ingest_once_inner(
            &paths.config(),
            manager,
            counter,
            &paths.auth(),
            "NODE_T1",
        )
        .await
    }

    fn drain_single_spool(
        paths: &TestPaths,
        upload: u64,
        download: u64,
    ) -> NginxTrafficCheckpoint {
        let batches = test_drain_strict_spool(&paths.auth(), "NODE_T1").unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].2, Some(9));
        assert_eq!(batches[0].3.len(), 1);
        assert_eq!(batches[0].3[0].rule_id, 12);
        assert_eq!(batches[0].3[0].upload, upload);
        assert_eq!(batches[0].3[0].download, download);
        batches[0].4.clone().expect("Nginx checkpoint")
    }

    fn identity_at(path: &Path) -> FileIdentity {
        file_identity(&std::fs::metadata(path).unwrap())
    }

    fn replace_file_with_distinct_inode(path: &Path, contents: &str) -> FileIdentity {
        let old_identity = identity_at(path);
        let replacement = path.with_file_name(format!("replacement-{}.log", Uuid::new_v4()));
        std::fs::write(&replacement, contents).unwrap();
        let replacement_identity = identity_at(&replacement);
        assert_ne!(replacement_identity, old_identity);
        std::fs::rename(&replacement, path).unwrap();
        assert_eq!(identity_at(path), replacement_identity);
        replacement_identity
    }

    #[test]
    fn parse_log_line_reads_nginx_sni_fields() {
        let parsed = parse_log_line("1723550000.123|443|OP1.Example.COM|12|345|678|1.2\n").unwrap();
        assert_eq!(
            parsed,
            ParsedLogLine {
                port: 443,
                sni: "op1.example.com".to_string(),
                rule_id: Some(12),
                config_revision: None,
                bytes_sent: 345,
                bytes_received: 678,
            }
        );
    }

    #[test]
    fn parse_log_line_reads_revision_aware_nginx_sni_fields() {
        let parsed =
            parse_log_line("1723550000.123|443|OP1.Example.COM|12|9|345|678|1.2\n").unwrap();
        assert_eq!(parsed.config_revision, Some(9));
        assert_eq!(parsed.rule_id, Some(12));
        assert_eq!(parsed.bytes_sent, 345);
        assert_eq!(parsed.bytes_received, 678);
    }

    #[test]
    fn parse_log_line_ignores_blank_sni() {
        assert!(parse_log_line("1723550000.123|443|-|0|345|678|1.2\n").is_none());
    }

    #[tokio::test]
    async fn same_file_append_counts_only_new_lines_and_keeps_identity() {
        let paths = TestPaths::new();
        let first = revision_line(10, 20);
        std::fs::write(&paths.log, &first).unwrap();
        let original_identity = identity_at(&paths.log);
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let first_checkpoint = drain_single_spool(&paths, 20, 10);
        assert_eq!(first_checkpoint.start_offset, 0);
        assert_eq!(first_checkpoint.end_offset, first.len() as u64);
        let first_state = load_state(&paths.state).unwrap();
        assert_eq!(first_state.offset, first.len() as u64);
        assert_eq!(first_state.file_identity(), Some(original_identity));

        let second = revision_line(30, 40);
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&paths.log)
            .unwrap();
        log.write_all(second.as_bytes()).unwrap();
        drop(log);

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let second_checkpoint = drain_single_spool(&paths, 40, 30);
        assert_eq!(second_checkpoint.start_offset, first.len() as u64);
        assert_eq!(
            second_checkpoint.end_offset,
            (first.len() + second.len()) as u64
        );
        let second_state = load_state(&paths.state).unwrap();
        assert_eq!(second_state.offset, (first.len() + second.len()) as u64);
        assert_eq!(second_state.file_identity(), Some(original_identity));
        assert!(counter.snapshot().await.entries.is_empty());
    }

    #[tokio::test]
    async fn same_inode_copytruncate_starts_new_generation_and_counts_new_content() {
        let paths = TestPaths::new();
        let old_line = revision_line(10, 20);
        let old_contents = old_line.repeat(8);
        std::fs::write(&paths.log, &old_contents).unwrap();
        let original_identity = identity_at(&paths.log);
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 8);
        let old_checkpoint = drain_single_spool(&paths, 20 * 8, 10 * 8);
        assert_eq!(old_checkpoint.generation, 0);
        let old_state = load_state(&paths.state).unwrap();

        let new_line = revision_line(7, 11);
        let mut log = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&paths.log)
            .unwrap();
        log.write_all(new_line.as_bytes()).unwrap();
        drop(log);

        assert_eq!(identity_at(&paths.log), original_identity);
        assert!(std::fs::metadata(&paths.log).unwrap().len() < old_state.offset);
        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let new_checkpoint = drain_single_spool(&paths, 11, 7);
        assert_eq!(new_checkpoint.generation, 1);
        assert_eq!(new_checkpoint.start_offset, 0);
        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.generation, 1);
        assert_eq!(state.offset, new_line.len() as u64);
        assert_eq!(state.file_identity(), Some(original_identity));
    }

    #[tokio::test]
    async fn replacement_file_is_read_from_zero_even_when_new_length_exceeds_old_offset() {
        let paths = TestPaths::new();
        let old_line = revision_line(10, 20);
        let old_contents = old_line.repeat(6);
        std::fs::write(&paths.log, &old_contents).unwrap();
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 6);
        let _ = drain_single_spool(&paths, 20 * 6, 10 * 6);
        let old_state = load_state(&paths.state).unwrap();
        let old_identity = old_state.file_identity().unwrap();
        let old_offset = old_state.offset;

        let replacement_line = revision_line(13, 17);
        let mut replacement_contents = String::new();
        while replacement_contents.len() < old_offset as usize {
            replacement_contents.push_str(&replacement_line);
        }
        let replacement_lines = replacement_contents.lines().count() as u64;
        let replacement_identity =
            replace_file_with_distinct_inode(&paths.log, &replacement_contents);
        assert_ne!(replacement_identity, old_identity);
        assert!(replacement_contents.len() as u64 >= old_offset);

        assert_eq!(
            ingest_test_once(&paths, &manager, &counter).await.unwrap(),
            replacement_lines as usize
        );
        let checkpoint =
            drain_single_spool(&paths, 17 * replacement_lines, 13 * replacement_lines);
        assert_eq!(checkpoint.start_offset, 0);
        assert_eq!(checkpoint.generation, old_state.generation + 1);
        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.offset, replacement_contents.len() as u64);
        assert_eq!(state.file_identity(), Some(replacement_identity));
    }

    #[tokio::test]
    async fn legacy_offset_only_state_is_trusted_once_then_identity_is_persisted() {
        let paths = TestPaths::new();
        let already_accounted = revision_line(10, 20);
        let new_line = revision_line(30, 40);
        let contents = format!("{already_accounted}{new_line}");
        std::fs::write(&paths.log, &contents).unwrap();
        std::fs::write(
            &paths.state,
            format!(r#"{{"offset":{}}}"#, already_accounted.len()),
        )
        .unwrap();
        let (manager, counter) = traffic_context();

        let legacy = load_state(&paths.state).unwrap();
        assert_eq!(legacy.offset, already_accounted.len() as u64);
        assert_eq!(legacy.file_identity(), None);
        assert_eq!(legacy.generation, 0);

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let checkpoint = drain_single_spool(&paths, 40, 30);
        assert_eq!(checkpoint.start_offset, already_accounted.len() as u64);
        assert_eq!(checkpoint.generation, 0);

        let upgraded = load_state(&paths.state).unwrap();
        assert_eq!(upgraded.offset, contents.len() as u64);
        assert_eq!(upgraded.file_identity(), Some(identity_at(&paths.log)));
        assert_eq!(upgraded.generation, 0);
    }

    #[tokio::test]
    async fn persisted_state_resumes_after_restart_and_still_detects_replacement() {
        let paths = TestPaths::new();
        let first = revision_line(10, 20);
        std::fs::write(&paths.log, &first).unwrap();

        let (first_manager, first_counter) = traffic_context();
        assert_eq!(
            ingest_test_once(&paths, &first_manager, &first_counter)
                .await
                .unwrap(),
            1
        );
        let _ = drain_single_spool(&paths, 20, 10);
        drop(first_manager);
        drop(first_counter);

        let second = revision_line(30, 40);
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&paths.log)
            .unwrap();
        log.write_all(second.as_bytes()).unwrap();
        drop(log);

        let (second_manager, second_counter) = traffic_context();
        assert_eq!(
            ingest_test_once(&paths, &second_manager, &second_counter)
                .await
                .unwrap(),
            1
        );
        let _ = drain_single_spool(&paths, 40, 30);
        let before_replacement = load_state(&paths.state).unwrap();
        drop(second_manager);
        drop(second_counter);

        let replacement_line = revision_line(50, 60);
        let mut replacement_contents = String::new();
        while replacement_contents.len() < before_replacement.offset as usize {
            replacement_contents.push_str(&replacement_line);
        }
        let replacement_lines = replacement_contents.lines().count() as u64;
        let replacement_identity =
            replace_file_with_distinct_inode(&paths.log, &replacement_contents);

        let (third_manager, third_counter) = traffic_context();
        assert_eq!(
            ingest_test_once(&paths, &third_manager, &third_counter)
                .await
                .unwrap(),
            replacement_lines as usize
        );
        let _ = drain_single_spool(
            &paths,
            60 * replacement_lines,
            50 * replacement_lines,
        );
        let after_replacement = load_state(&paths.state).unwrap();
        assert_eq!(
            after_replacement.file_identity(),
            Some(replacement_identity)
        );
        assert_eq!(after_replacement.offset, replacement_contents.len() as u64);
    }

    #[tokio::test]
    async fn malformed_existing_state_fails_closed_without_replay() {
        let paths = TestPaths::new();
        std::fs::write(&paths.log, revision_line(10, 20)).unwrap();
        std::fs::write(&paths.state, "{").unwrap();
        let (manager, counter) = traffic_context();

        let error = ingest_test_once(&paths, &manager, &counter)
            .await
            .expect_err("malformed existing state must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(test_read_strict_spool(&paths.auth(), "NODE_T1")
            .unwrap()
            .is_empty());
        assert_eq!(std::fs::read_to_string(&paths.state).unwrap(), "{");
        assert!(counter.snapshot().await.entries.is_empty());
    }

    #[tokio::test]
    async fn missing_state_is_supported_on_first_boot() {
        let paths = TestPaths::new();
        let line = revision_line(10, 20);
        std::fs::write(&paths.log, &line).unwrap();
        let (manager, counter) = traffic_context();
        assert!(!paths.state.exists());

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let checkpoint = drain_single_spool(&paths, 20, 10);
        assert_eq!(checkpoint.start_offset, 0);
        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.offset, line.len() as u64);
        assert_eq!(state.file_identity(), Some(identity_at(&paths.log)));
    }

    #[tokio::test]
    async fn incomplete_final_line_stays_before_cursor_until_newline_arrives() {
        let paths = TestPaths::new();
        let first = revision_line(10, 20);
        let second = revision_line(30, 40);
        let partial = second.trim_end_matches('\n');
        std::fs::write(&paths.log, format!("{first}{partial}")).unwrap();
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let _ = drain_single_spool(&paths, 20, 10);
        assert_eq!(load_state(&paths.state).unwrap().offset, first.len() as u64);

        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&paths.log)
            .unwrap();
        log.write_all(b"\n").unwrap();
        drop(log);

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 1);
        let checkpoint = drain_single_spool(&paths, 40, 30);
        assert_eq!(checkpoint.start_offset, first.len() as u64);
        assert_eq!(
            load_state(&paths.state).unwrap().offset,
            (first.len() + second.len()) as u64
        );
    }

    #[tokio::test]
    async fn injected_read_error_leaves_source_retryable_and_retry_converges_once() {
        let paths = TestPaths::new();
        let first = revision_line(10, 20);
        let second = revision_line(30, 40);
        std::fs::write(&paths.log, format!("{first}{second}")).unwrap();
        let (manager, counter) = traffic_context();
        let auth = paths.auth();

        let error = ingest_once_inner_with_failpoints(
            &paths.config(),
            &manager,
            &counter,
            &auth,
            "NODE_T1",
            Some(1),
            save_state,
        )
        .await
        .expect_err("injected read error");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(!paths.state.exists());
        assert!(test_read_strict_spool(&auth, "NODE_T1").unwrap().is_empty());
        assert!(counter.snapshot().await.entries.is_empty());

        assert_eq!(ingest_test_once(&paths, &manager, &counter).await.unwrap(), 2);
        let checkpoint = drain_single_spool(&paths, 60, 40);
        assert_eq!(checkpoint.start_offset, 0);
        assert_eq!(checkpoint.end_offset, (first.len() + second.len()) as u64);
        assert_eq!(
            load_state(&paths.state).unwrap().offset,
            (first.len() + second.len()) as u64
        );
    }

    #[tokio::test]
    async fn cursor_write_failure_after_durable_spool_recovers_without_duplicate_enqueue() {
        let paths = TestPaths::new();
        let line = revision_line(10, 20);
        std::fs::write(&paths.log, &line).unwrap();
        let auth = paths.auth();
        let (manager, counter) = traffic_context();

        let error = ingest_once_inner_with_state_writer(
            &paths.config(),
            &manager,
            &counter,
            &auth,
            "NODE_T1",
            |_path, _state| Err(std::io::Error::other("injected cursor write failure")),
        )
        .await
        .expect_err("cursor write failure");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(counter.strict_reporting_poisoned());
        assert!(!paths.state.exists());

        let before = test_read_strict_spool(&auth, "NODE_T1").unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].2, Some(9));
        assert_eq!(before[0].3[0].upload, 20);
        assert_eq!(before[0].3[0].download, 10);
        let before_id = before[0].0.clone();
        let before_hash = before[0].1.clone();

        // Fresh process: checkpoint recovery persists the cursor first, then the
        // same source is already at EOF and cannot create a second queue item.
        let (restart_manager, restart_counter) = traffic_context();
        assert_eq!(
            ingest_once_inner(
                &paths.config(),
                &restart_manager,
                &restart_counter,
                &auth,
                "NODE_T1",
            )
            .await
            .unwrap(),
            0
        );
        let after = test_read_strict_spool(&auth, "NODE_T1").unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, before_id);
        assert_eq!(after[0].1, before_hash);
        assert_eq!(load_state(&paths.state).unwrap().offset, line.len() as u64);
        assert!(restart_counter.snapshot().await.entries.is_empty());
    }

    #[tokio::test]
    async fn checkpoint_recovery_runs_even_when_ingestion_is_disabled() {
        let paths = TestPaths::new();
        let line = revision_line(10, 20);
        std::fs::write(&paths.log, &line).unwrap();
        let auth = paths.auth();
        let (manager, counter) = traffic_context();

        let _ = ingest_once_inner_with_state_writer(
            &paths.config(),
            &manager,
            &counter,
            &auth,
            "NODE_T1",
            |_path, _state| Err(std::io::Error::other("injected cursor write failure")),
        )
        .await;
        assert!(!paths.state.exists());

        let mut disabled = paths.config();
        disabled.enabled = false;
        let (restart_manager, restart_counter) = traffic_context();
        assert_eq!(
            ingest_once_inner(
                &disabled,
                &restart_manager,
                &restart_counter,
                &auth,
                "NODE_T1",
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(load_state(&paths.state).unwrap().offset, line.len() as u64);
        assert_eq!(
            test_read_strict_spool(&auth, "NODE_T1").unwrap().len(),
            1,
            "recovery must not delete the durable batch"
        );
    }

    #[test]
    fn atomic_state_write_is_owner_only_and_round_trips() {
        let paths = TestPaths::new();
        let state = LogState {
            offset: 42,
            device: Some(1),
            inode: Some(2),
            generation: 3,
        };
        save_state(&paths.state, &state).unwrap();
        let metadata = std::fs::metadata(&paths.state).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(load_state(&paths.state).unwrap(), state);
    }
}
