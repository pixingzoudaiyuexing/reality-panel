use super::ForwarderManager;
use crate::reporter::TrafficCounter;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct NginxSniTrafficConfig {
    pub enabled: bool,
    pub access_log_path: PathBuf,
    pub state_path: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LogState {
    offset: u64,
    #[serde(default)]
    device: Option<u64>,
    #[serde(default)]
    inode: Option<u64>,
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
) {
    if !cfg.enabled {
        return;
    }
    match ingest_once_inner(cfg, manager, counter).await {
        Ok(n) if n > 0 => tracing::info!("nginx_sni traffic: ingested {} log line(s)", n),
        Ok(_) => {}
        Err(e) => tracing::warn!("nginx_sni traffic ingest failed: {}", e),
    }
}

async fn ingest_once_inner(
    cfg: &NginxSniTrafficConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    counter: &Arc<TrafficCounter>,
) -> std::io::Result<usize> {
    let mut state = load_state(&cfg.state_path).unwrap_or_default();
    let file = match std::fs::File::open(&cfg.access_log_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    let len = metadata.len();
    let current_identity = file_identity(&metadata);

    // Legacy state files contain only an offset. Trust that offset for the
    // first post-upgrade read so already-accounted traffic is not replayed and
    // double-counted; this successful ingest records identity for future polls.
    if state
        .file_identity()
        .is_some_and(|persisted| persisted != current_identity)
    {
        state.offset = 0;
    }
    // A matching inode can still be copy-truncated, so retain the existing
    // length-shrink protection independently of file replacement detection.
    if state.offset > len {
        state.offset = 0;
    }

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(state.offset))?;

    let mut processed = 0usize;
    let mut new_offset = state.offset;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        new_offset = new_offset.saturating_add(bytes as u64);
        let Some(parsed) = parse_log_line(&line) else {
            continue;
        };
        let attributed =
            if let (Some(revision), Some(rule_id)) = (parsed.config_revision, parsed.rule_id) {
                Some((revision, rule_id))
            } else {
                let current_rule_id = {
                    let mgr = manager.lock().await;
                    mgr.nginx_sni_rule_id_for(parsed.port, &parsed.sni)
                };
                match (parsed.rule_id, current_rule_id) {
                    (Some(logged), Some(current)) if logged == current => Some((0, current)),
                    (None, Some(current)) => Some((0, current)),
                    _ => None,
                }
            };
        if let Some((revision, rule_id)) = attributed {
            // Nginx stream: bytes_received = client -> proxy (upload),
            // bytes_sent = proxy -> client (download).
            counter
                .add_at(revision, rule_id, parsed.bytes_received, parsed.bytes_sent)
                .await;
            processed += 1;
        }
    }

    state.offset = new_offset;
    state.set_file_identity(current_identity);
    save_state(&cfg.state_path, &state)?;
    Ok(processed)
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

fn load_state(path: &Path) -> std::io::Result<LogState> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn save_state(path: &Path, state: &LogState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporter::ConnectionTracker;
    use std::io::Write;
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
            std::fs::create_dir_all(&dir).unwrap();
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
        format!(
            "1723550000.123|443|OP1.Example.COM|12|9|{bytes_sent}|{bytes_received}|1.2\n"
        )
    }

    async fn assert_only_traffic(
        counter: &Arc<TrafficCounter>,
        upload: u64,
        download: u64,
    ) {
        let entries = counter.drain().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_id, 12);
        assert_eq!(entries[0].upload, upload);
        assert_eq!(entries[0].download, download);
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
        let cfg = paths.config();
        let first = revision_line(10, 20);
        std::fs::write(&paths.log, &first).unwrap();
        let original_identity = identity_at(&paths.log);
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 1);
        assert_only_traffic(&counter, 20, 10).await;
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

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 1);
        assert_only_traffic(&counter, 40, 30).await;
        let second_state = load_state(&paths.state).unwrap();
        assert_eq!(second_state.offset, (first.len() + second.len()) as u64);
        assert_eq!(second_state.file_identity(), Some(original_identity));
    }

    #[tokio::test]
    async fn same_inode_truncation_resets_offset_and_counts_new_content() {
        let paths = TestPaths::new();
        let cfg = paths.config();
        let old_line = revision_line(10, 20);
        let old_contents = old_line.repeat(8);
        std::fs::write(&paths.log, &old_contents).unwrap();
        let original_identity = identity_at(&paths.log);
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 8);
        let _ = counter.drain().await;
        let old_state = load_state(&paths.state).unwrap();
        assert_eq!(old_state.offset, old_contents.len() as u64);

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

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 1);
        assert_only_traffic(&counter, 11, 7).await;
        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.offset, new_line.len() as u64);
        assert_eq!(state.file_identity(), Some(original_identity));
    }

    #[tokio::test]
    async fn replacement_file_is_read_from_zero_even_when_new_length_exceeds_old_offset() {
        let paths = TestPaths::new();
        let cfg = paths.config();
        let old_line = revision_line(10, 20);
        let old_contents = old_line.repeat(6);
        std::fs::write(&paths.log, &old_contents).unwrap();
        let (manager, counter) = traffic_context();

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 6);
        let _ = counter.drain().await;
        let old_state = load_state(&paths.state).unwrap();
        let old_identity = old_state.file_identity().unwrap();
        let old_offset = old_state.offset;

        let replacement_line = revision_line(13, 17);
        let mut replacement_contents = String::new();
        while replacement_contents.len() < old_offset as usize {
            replacement_contents.push_str(&replacement_line);
        }
        let replacement_lines = replacement_contents.lines().count() as u64;
        assert!(replacement_contents.len() as u64 >= old_offset);
        let replacement_identity =
            replace_file_with_distinct_inode(&paths.log, &replacement_contents);
        assert_ne!(replacement_identity, old_identity);

        assert_eq!(
            ingest_once_inner(&cfg, &manager, &counter).await.unwrap(),
            replacement_lines as usize
        );
        assert_only_traffic(
            &counter,
            17 * replacement_lines,
            13 * replacement_lines,
        )
        .await;
        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.offset, replacement_contents.len() as u64);
        assert_eq!(state.file_identity(), Some(replacement_identity));
    }

    #[tokio::test]
    async fn legacy_offset_only_state_is_trusted_once_then_identity_is_persisted() {
        let paths = TestPaths::new();
        let cfg = paths.config();
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

        assert_eq!(ingest_once_inner(&cfg, &manager, &counter).await.unwrap(), 1);
        assert_only_traffic(&counter, 40, 30).await;

        let upgraded = load_state(&paths.state).unwrap();
        assert_eq!(upgraded.offset, contents.len() as u64);
        assert_eq!(upgraded.file_identity(), Some(identity_at(&paths.log)));
    }

    #[tokio::test]
    async fn persisted_state_resumes_after_restart_and_still_detects_replacement() {
        let paths = TestPaths::new();
        let cfg = paths.config();
        let first = revision_line(10, 20);
        std::fs::write(&paths.log, &first).unwrap();

        let (first_manager, first_counter) = traffic_context();
        assert_eq!(
            ingest_once_inner(&cfg, &first_manager, &first_counter)
                .await
                .unwrap(),
            1
        );
        assert_only_traffic(&first_counter, 20, 10).await;
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
            ingest_once_inner(&cfg, &second_manager, &second_counter)
                .await
                .unwrap(),
            1
        );
        assert_only_traffic(&second_counter, 40, 30).await;
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
            ingest_once_inner(&cfg, &third_manager, &third_counter)
                .await
                .unwrap(),
            replacement_lines as usize
        );
        assert_only_traffic(
            &third_counter,
            60 * replacement_lines,
            50 * replacement_lines,
        )
        .await;
        let after_replacement = load_state(&paths.state).unwrap();
        assert_eq!(after_replacement.file_identity(), Some(replacement_identity));
        assert_eq!(after_replacement.offset, replacement_contents.len() as u64);
    }
}
