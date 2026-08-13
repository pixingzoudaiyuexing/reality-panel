use super::ForwarderManager;
use crate::reporter::TrafficCounter;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
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
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedLogLine {
    port: u16,
    sni: String,
    rule_id: Option<i64>,
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
    let len = file.metadata()?.len();
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
        let current_rule_id = {
            let mgr = manager.lock().await;
            mgr.nginx_sni_rule_id_for(parsed.port, &parsed.sni)
        };
        let rule_id = match (parsed.rule_id, current_rule_id) {
            (Some(logged), Some(current)) if logged == current => Some(current),
            (None, Some(current)) => Some(current),
            _ => None,
        };
        if let Some(rule_id) = rule_id {
            // Nginx stream: bytes_received = client -> proxy (upload),
            // bytes_sent = proxy -> client (download).
            counter
                .add(rule_id, parsed.bytes_received, parsed.bytes_sent)
                .await;
            processed += 1;
        }
    }

    state.offset = new_offset;
    save_state(&cfg.state_path, &state)?;
    Ok(processed)
}

fn parse_log_line(line: &str) -> Option<ParsedLogLine> {
    let mut parts = line.trim_end_matches(['\r', '\n']).split('|');
    let _msec = parts.next()?;
    let port = parts.next()?.parse::<u16>().ok()?;
    let sni = parts.next()?.trim().to_ascii_lowercase();
    let raw_rule_id = parts.next()?.trim();
    let rule_id = raw_rule_id.parse::<i64>().ok().filter(|id| *id > 0);
    let bytes_sent = parts.next()?.parse::<u64>().ok()?;
    let bytes_received = parts.next()?.parse::<u64>().ok()?;
    let _session_time = parts.next();
    if sni.is_empty() || sni == "-" {
        return None;
    }
    Some(ParsedLogLine {
        port,
        sni,
        rule_id,
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

    #[test]
    fn parse_log_line_reads_nginx_sni_fields() {
        let parsed = parse_log_line("1723550000.123|443|OP1.Example.COM|12|345|678|1.2\n").unwrap();
        assert_eq!(
            parsed,
            ParsedLogLine {
                port: 443,
                sni: "op1.example.com".to_string(),
                rule_id: Some(12),
                bytes_sent: 345,
                bytes_received: 678,
            }
        );
    }

    #[test]
    fn parse_log_line_ignores_blank_sni() {
        assert!(parse_log_line("1723550000.123|443|-|0|345|678|1.2\n").is_none());
    }
}
