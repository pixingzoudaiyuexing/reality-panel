//! Restricted lifecycle actions received over the authenticated Panel WS.

use crate::config::NodeConfig;
use relay_shared::protocol::{
    lifecycle_artifact_architecture, NodeLifecycleAck, NodeLifecycleAction, NodeLifecycleCommand,
    NodeLifecycleEvent, NodeLifecycleEventStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::sync::mpsc;

const MAX_LOG_LINES: u16 = 500;
const MIN_ARTIFACT_BYTES: usize = 64 * 1024;
const MANAGED_BINARY: &str = "/opt/relay-node/relay-node";
const UNINSTALL_REMOVE_FILES: &[&str] = &[
    "/etc/systemd/system/relay-node.service",
    "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
];
const UNINSTALL_REMOVE_DIRS: &[&str] = &["/etc/relay-node", "/opt/relay-node"];
const UNINSTALL_SYSTEMCTL_ARGS: &[&str] = &["disable", "--now", "relay-node.service"];

#[derive(Debug, Serialize, Deserialize)]
struct PendingBootOperation {
    operation_id: String,
    node_id: String,
    action: NodeLifecycleAction,
}

fn event(
    command: &NodeLifecycleCommand,
    status: NodeLifecycleEventStatus,
    message: impl Into<String>,
) -> NodeLifecycleEvent {
    NodeLifecycleEvent {
        msg_type: "node_lifecycle_event".into(),
        operation_id: command.operation_id.clone(),
        node_id: command.node_id.clone(),
        action: command.action,
        status,
        message: message.into(),
        node_version: Some(env!("CARGO_PKG_VERSION").into()),
        architecture: Some(std::env::consts::ARCH.into()),
        logs: None,
    }
}

pub(crate) fn failed_event(
    command: &NodeLifecycleCommand,
    message: impl Into<String>,
) -> NodeLifecycleEvent {
    event(command, NodeLifecycleEventStatus::Failed, message)
}

pub(crate) fn accepted_event(command: &NodeLifecycleCommand) -> NodeLifecycleEvent {
    event(
        command,
        NodeLifecycleEventStatus::Accepted,
        "command accepted",
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn pending_path(binary: &Path) -> PathBuf {
    binary
        .parent()
        .unwrap_or_else(|| Path::new("/opt/relay-node"))
        .join("lifecycle-pending.json")
}

fn write_pending_at(path: &Path, command: &NodeLifecycleCommand) -> Result<(), String> {
    let pending = PendingBootOperation {
        operation_id: command.operation_id.clone(),
        node_id: command.node_id.clone(),
        action: command.action,
    };
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(&pending).map_err(|error| error.to_string())?;
    let mut file = std::fs::File::create(&temp)
        .map_err(|error| format!("create lifecycle marker: {error}"))?;
    use std::io::Write;
    file.write_all(&bytes)
        .map_err(|error| format!("write lifecycle marker: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush lifecycle marker: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("fsync lifecycle marker: {error}"))?;
    std::fs::rename(&temp, path).map_err(|error| format!("commit lifecycle marker: {error}"))
}

fn write_pending(command: &NodeLifecycleCommand) -> Result<PathBuf, String> {
    let path = pending_path(Path::new(MANAGED_BINARY));
    write_pending_at(&path, command)?;
    Ok(path)
}

pub(crate) fn pending_boot_event() -> Option<(NodeLifecycleEvent, PathBuf)> {
    let path = pending_path(Path::new(MANAGED_BINARY));
    let pending: PendingBootOperation = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    let command = NodeLifecycleCommand {
        msg_type: "node_lifecycle".into(),
        operation_id: pending.operation_id,
        node_id: pending.node_id,
        action: pending.action,
        target_version: None,
        target_architecture: None,
        sha256: None,
        artifact_id: None,
        log_lines: None,
    };
    Some((
        event(
            &command,
            NodeLifecycleEventStatus::Completed,
            "relay-node restarted and restored its authenticated control channel",
        ),
        path,
    ))
}

pub(crate) fn clear_pending_boot_event(path: &Path) {
    let _ = std::fs::remove_file(path);
}

pub(crate) fn boot_ack_matches(event: &NodeLifecycleEvent, ack: &NodeLifecycleAck) -> bool {
    ack.msg_type == "node_lifecycle_ack"
        && event.status == NodeLifecycleEventStatus::Completed
        && ack.operation_id == event.operation_id
        && ack.node_id == event.node_id
        && ack.action == event.action
}

fn require_managed_systemd() -> Result<(), String> {
    if crate::updater::install_method() != "systemd"
        || !Path::new("/etc/systemd/system/relay-node.service").is_file()
    {
        return Err("lifecycle action requires an installer-managed systemd node".into());
    }
    Ok(())
}

fn schedule_systemd(args: &[&str], unit_suffix: &str, operation_id: &str) -> Result<(), String> {
    if !valid_id(operation_id) {
        return Err("invalid lifecycle operation id".into());
    }
    let unit = format!("relay-node-lifecycle-{unit_suffix}-{operation_id}");
    let output = Command::new("systemd-run")
        .args(["--quiet", "--collect", "--on-active=2s", "--unit"])
        .arg(unit)
        .args(args)
        .output()
        .map_err(|error| format!("schedule lifecycle action: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "schedule lifecycle action failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn redact_logs(input: &str, token: &str) -> String {
    input
        .lines()
        .map(|line| {
            let mut line = if token.is_empty() {
                line.to_string()
            } else {
                line.replace(token, "[REDACTED]")
            };
            let lower = line.to_ascii_lowercase();
            for marker in [
                "node_token=",
                "node_token:",
                "authorization:",
                "authorization=",
                "bearer ",
                "password=",
                "password:",
                "passwd=",
                "passwd:",
            ] {
                if let Some(index) = lower.find(marker) {
                    line.truncate(index + marker.len());
                    line.push_str("[REDACTED]");
                    break;
                }
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_logs(lines: u16, token: &str) -> Result<String, String> {
    if lines == 0 || lines > MAX_LOG_LINES {
        return Err(format!(
            "log line limit must be between 1 and {MAX_LOG_LINES}"
        ));
    }
    let output = Command::new("journalctl")
        .args([
            "-u",
            "relay-node",
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            &lines.to_string(),
        ])
        .output()
        .map_err(|error| format!("read relay-node journal: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read relay-node journal failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(redact_logs(&String::from_utf8_lossy(&output.stdout), token))
}

fn requested_log_lines(lines: Option<u16>) -> Result<u16, String> {
    let lines = lines.unwrap_or(200);
    if lines == 0 || lines > MAX_LOG_LINES {
        Err(format!(
            "log line limit must be between 1 and {MAX_LOG_LINES}"
        ))
    } else {
        Ok(lines)
    }
}

fn expected_elf_machine(architecture: &str) -> Option<u16> {
    match lifecycle_artifact_architecture(architecture)? {
        "amd64" => Some(62),
        "arm64" => Some(183),
        _ => None,
    }
}

fn validate_artifact_bytes(
    bytes: &[u8],
    architecture: &str,
    expected_sha256: &str,
) -> Result<(), String> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid artifact SHA-256 metadata".into());
    }
    if bytes.len() < MIN_ARTIFACT_BYTES {
        return Err("upgrade artifact is too small".into());
    }
    if bytes.get(..4) != Some(&[0x7f, b'E', b'L', b'F'])
        || bytes.get(4) != Some(&2)
        || bytes.get(5) != Some(&1)
    {
        return Err("upgrade artifact is not a 64-bit little-endian ELF binary".into());
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if Some(machine) != expected_elf_machine(architecture) {
        return Err("upgrade artifact ELF architecture mismatch".into());
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err("upgrade artifact SHA-256 verification failed".into());
    }
    Ok(())
}

fn reported_version(output: &[u8]) -> Option<&str> {
    std::str::from_utf8(output).ok()?.split_whitespace().last()
}

fn write_upgrade_temp(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("create upgrade temp file: {error}"))?;
    use std::io::Write;
    file.write_all(bytes)
        .map_err(|error| format!("write upgrade temp file: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush upgrade temp file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("fsync upgrade temp file: {error}"))?;
    Ok(())
}

fn install_artifact_with_probe<F>(
    binary: &Path,
    bytes: &[u8],
    architecture: &str,
    sha256: &str,
    target_version: &str,
    probe: F,
) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<Vec<u8>, String>,
{
    let target = semver::Version::parse(target_version).map_err(|_| "invalid target version")?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| "invalid running node version")?;
    if target <= current {
        return Err("upgrade target must be newer than the running node".into());
    }
    validate_artifact_bytes(bytes, architecture, sha256)?;
    let parent = binary.parent().ok_or("managed binary has no parent")?;
    let temp = parent.join(format!(".relay-node-{}.tmp", std::process::id()));
    let result = (|| {
        write_upgrade_temp(&temp, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| format!("chmod upgrade temp file: {error}"))?;
        }
        let version_output = probe(&temp)?;
        if reported_version(&version_output) != Some(target_version) {
            return Err("upgrade artifact reported a different version".into());
        }
        std::fs::rename(&temp, binary)
            .map_err(|error| format!("atomically replace relay-node: {error}"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync relay-node directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

async fn download_artifact(
    config: &NodeConfig,
    command: &NodeLifecycleCommand,
) -> Result<Vec<u8>, String> {
    let artifact_id = command
        .artifact_id
        .as_deref()
        .filter(|value| valid_id(value))
        .ok_or("invalid artifact identifier")?;
    let url = format!(
        "{}/api/v1/node/lifecycle-artifacts/{artifact_id}",
        config.panel_url.trim_end_matches('/')
    );
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .map_err(|error| format!("build artifact client: {error}"))?
        .get(url)
        .bearer_auth(&config.token)
        .header("X-Node-ID", &command.node_id)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("download Panel artifact: {error}"))?;
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|error| format!("read Panel artifact: {error}"))
}

fn probe_artifact_version(path: &Path) -> Result<Vec<u8>, String> {
    use std::process::Stdio;
    let mut child = Command::new(path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("execute artifact version check: {error}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("wait for artifact version check: {error}"))?
        {
            Some(status) if status.success() => {
                return child
                    .wait_with_output()
                    .map(|output| output.stdout)
                    .map_err(|error| format!("read artifact version output: {error}"));
            }
            Some(_) => return Err("upgrade artifact --version failed".into()),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("upgrade artifact --version timed out".into());
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

fn emit(
    tx: &mpsc::UnboundedSender<NodeLifecycleEvent>,
    command: &NodeLifecycleCommand,
    status: NodeLifecycleEventStatus,
    message: impl Into<String>,
) {
    let _ = tx.send(event(command, status, message));
}

pub(crate) async fn execute(
    config: NodeConfig,
    command: NodeLifecycleCommand,
    tx: mpsc::UnboundedSender<NodeLifecycleEvent>,
) {
    let result = match command.action {
        NodeLifecycleAction::Logs => {
            let logs = requested_log_lines(command.log_lines)
                .and_then(|lines| read_logs(lines, &config.token));
            match logs {
                Ok(logs) => {
                    let mut done = event(
                        &command,
                        NodeLifecycleEventStatus::Completed,
                        "logs collected",
                    );
                    done.logs = Some(logs);
                    let _ = tx.send(done);
                    return;
                }
                Err(error) => Err(error),
            }
        }
        NodeLifecycleAction::Restart => require_managed_systemd().and_then(|_| {
            let marker = write_pending(&command)?;
            let scheduled = schedule_systemd(
                &["/bin/systemctl", "restart", "relay-node"],
                "restart",
                &command.operation_id,
            );
            if scheduled.is_err() {
                clear_pending_boot_event(&marker);
            }
            scheduled
        }),
        NodeLifecycleAction::Upgrade => {
            let target_version = command.target_version.as_deref().unwrap_or_default();
            let target_arch = command.target_architecture.as_deref().unwrap_or_default();
            let sha256 = command.sha256.as_deref().unwrap_or_default();
            let local_arch = lifecycle_artifact_architecture(std::env::consts::ARCH);
            if lifecycle_artifact_architecture(target_arch) != local_arch || local_arch.is_none() {
                Err("upgrade target architecture does not match this node".into())
            } else if let Err(error) = require_managed_systemd() {
                Err(error)
            } else {
                emit(
                    &tx,
                    &command,
                    NodeLifecycleEventStatus::Downloading,
                    "downloading Panel-managed artifact",
                );
                match download_artifact(&config, &command).await {
                    Err(error) => Err(error),
                    Ok(bytes) => {
                        emit(
                            &tx,
                            &command,
                            NodeLifecycleEventStatus::Validating,
                            "validating SHA-256, ELF architecture, and version",
                        );
                        let install = install_artifact_with_probe(
                            Path::new(MANAGED_BINARY),
                            &bytes,
                            target_arch,
                            sha256,
                            target_version,
                            probe_artifact_version,
                        );
                        install.and_then(|_| {
                            emit(
                                &tx,
                                &command,
                                NodeLifecycleEventStatus::Installing,
                                "artifact installed atomically",
                            );
                            let marker = write_pending(&command)?;
                            let scheduled = schedule_systemd(
                                &["/bin/systemctl", "restart", "relay-node"],
                                "upgrade",
                                &command.operation_id,
                            );
                            if scheduled.is_err() {
                                clear_pending_boot_event(&marker);
                            }
                            scheduled
                        })
                    }
                }
            }
        }
        NodeLifecycleAction::Uninstall => require_managed_systemd().and_then(|_| {
            let binary = std::env::current_exe()
                .map_err(|error| format!("locate relay-node binary: {error}"))?;
            let binary = binary.to_string_lossy().into_owned();
            schedule_systemd(
                &[&binary, "--lifecycle-uninstall"],
                "uninstall",
                &command.operation_id,
            )
        }),
    };

    match result {
        Ok(()) if command.action == NodeLifecycleAction::Uninstall => emit(
            &tx,
            &command,
            NodeLifecycleEventStatus::Completed,
            "uninstall scheduled; persistent OpenList data will be retained",
        ),
        Ok(()) => emit(
            &tx,
            &command,
            NodeLifecycleEventStatus::Restarting,
            "relay-node restart scheduled",
        ),
        Err(error) => {
            let _ = tx.send(failed_event(&command, error));
        }
    }
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn uninstall_managed(root: &Path) -> Result<(), String> {
    let rooted = |path: &str| root.join(path.trim_start_matches('/'));
    if root == Path::new("/") {
        let status = Command::new("systemctl")
            .args(UNINSTALL_SYSTEMCTL_ARGS)
            .status();
        if !status.is_ok_and(|status| status.success()) {
            return Err("stop and disable relay-node.service failed".into());
        }
    }
    for path in UNINSTALL_REMOVE_FILES {
        remove_if_exists(&rooted(path))?;
    }
    for path in UNINSTALL_REMOVE_DIRS {
        let path = rooted(path);
        if path.exists() {
            std::fs::remove_dir_all(&path)
                .map_err(|error| format!("remove {}: {error}", path.display()))?;
        }
    }
    if root == Path::new("/") {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
    Ok(())
}

pub(crate) fn run_helper_from_args(args: &[String]) -> Option<Result<(), String>> {
    (args == ["--lifecycle-uninstall"]).then(|| uninstall_managed(Path::new("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(prefix: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()))
    }

    fn elf(arch: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8; MIN_ARTIFACT_BYTES];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        let machine = expected_elf_machine(arch).unwrap().to_le_bytes();
        bytes[18..20].copy_from_slice(&machine);
        bytes
    }

    #[test]
    fn architecture_aliases_and_elf_machine_are_strict() {
        assert_eq!(expected_elf_machine("amd64"), Some(62));
        assert_eq!(expected_elf_machine("x86_64"), Some(62));
        assert_eq!(expected_elf_machine("arm64"), Some(183));
        assert_eq!(expected_elf_machine("aarch64"), Some(183));
        assert_eq!(expected_elf_machine("riscv64"), None);
    }

    #[test]
    fn restart_command_ack_preserves_operation_identity() {
        let command = NodeLifecycleCommand {
            msg_type: "node_lifecycle".into(),
            operation_id: "operation-1".into(),
            node_id: "node-a".into(),
            action: NodeLifecycleAction::Restart,
            target_version: None,
            target_architecture: None,
            sha256: None,
            artifact_id: None,
            log_lines: None,
        };
        let ack = accepted_event(&command);
        assert_eq!(ack.operation_id, command.operation_id);
        assert_eq!(ack.node_id, command.node_id);
        assert_eq!(ack.action, NodeLifecycleAction::Restart);
        assert_eq!(ack.status, NodeLifecycleEventStatus::Accepted);
    }

    #[test]
    fn pending_marker_round_trips_operation_without_rollback_state() {
        let dir = test_dir("relay-lifecycle-marker");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lifecycle-pending.json");
        let command = NodeLifecycleCommand {
            msg_type: "node_lifecycle".into(),
            operation_id: "operation-1".into(),
            node_id: "node-a".into(),
            action: NodeLifecycleAction::Upgrade,
            target_version: Some("1.2.4".into()),
            target_architecture: Some("amd64".into()),
            sha256: Some("0".repeat(64)),
            artifact_id: Some("operation-1".into()),
            log_lines: None,
        };
        write_pending_at(&path, &command).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("operation-1"));
        assert!(!raw.contains("backup"));
        assert!(!raw.contains("rollback"));
        assert!(std::fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_boot_marker_requires_an_exact_panel_ack_before_removal() {
        let dir = test_dir("relay-lifecycle-ack");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lifecycle-pending.json");
        let command = NodeLifecycleCommand {
            msg_type: "node_lifecycle".into(),
            operation_id: "operation-ack".into(),
            node_id: "node-a".into(),
            action: NodeLifecycleAction::Upgrade,
            target_version: Some("1.2.4".into()),
            target_architecture: Some("amd64".into()),
            sha256: Some("0".repeat(64)),
            artifact_id: Some("operation-ack".into()),
            log_lines: None,
        };
        write_pending_at(&path, &command).unwrap();
        let boot = event(
            &command,
            NodeLifecycleEventStatus::Completed,
            "relay-node restarted",
        );
        let wrong = relay_shared::protocol::NodeLifecycleAck {
            msg_type: "node_lifecycle_ack".into(),
            operation_id: "other-operation".into(),
            node_id: command.node_id.clone(),
            action: command.action,
        };
        assert!(!boot_ack_matches(&boot, &wrong));
        assert!(path.exists(), "wrong ACK must retain the boot marker");

        let matching = relay_shared::protocol::NodeLifecycleAck {
            msg_type: "node_lifecycle_ack".into(),
            operation_id: command.operation_id.clone(),
            node_id: command.node_id.clone(),
            action: command.action,
        };
        assert!(boot_ack_matches(&boot, &matching));
        clear_pending_boot_event(&path);
        assert!(!path.exists(), "exact ACK may clear the boot marker");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn log_limits_default_to_200_allow_500_and_reject_invalid_values() {
        assert_eq!(requested_log_lines(None), Ok(200));
        assert_eq!(requested_log_lines(Some(500)), Ok(500));
        assert!(requested_log_lines(Some(0)).is_err());
        assert!(requested_log_lines(Some(501)).is_err());
    }

    #[test]
    fn sha_and_elf_failures_do_not_replace_live_binary() {
        let dir = test_dir("relay-lifecycle");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("relay-node");
        std::fs::write(&binary, b"old-binary").unwrap();
        let bytes = elf("amd64");
        assert!(install_artifact_with_probe(
            &binary,
            &bytes,
            "amd64",
            &"0".repeat(64),
            "1.2.4",
            |_| Ok(b"relay-node 1.2.4\n".to_vec()),
        )
        .is_err());
        assert_eq!(std::fs::read(&binary).unwrap(), b"old-binary");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn version_failure_does_not_replace_live_binary() {
        let dir = test_dir("relay-lifecycle");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("relay-node");
        std::fs::write(&binary, b"old-binary").unwrap();
        let bytes = elf("amd64");
        let sha = format!("{:x}", Sha256::digest(&bytes));
        assert!(
            install_artifact_with_probe(&binary, &bytes, "amd64", &sha, "1.2.4", |_| Ok(
                b"relay-node 9.9.9\n".to_vec()
            ),)
            .is_err()
        );
        assert_eq!(std::fs::read(&binary).unwrap(), b"old-binary");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn version_execution_failure_does_not_replace_live_binary() {
        let dir = test_dir("relay-lifecycle");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("relay-node");
        std::fs::write(&binary, b"old-binary").unwrap();
        let bytes = elf("amd64");
        let sha = format!("{:x}", Sha256::digest(&bytes));
        assert!(
            install_artifact_with_probe(&binary, &bytes, "amd64", &sha, "1.2.4", |_| Err(
                "execution failed".into()
            ),)
            .is_err()
        );
        assert_eq!(std::fs::read(&binary).unwrap(), b"old-binary");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn downloaded_artifact_is_executable_immediately_after_write() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("relay-lifecycle-exec");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("relay-node.new");
        write_upgrade_temp(&artifact, b"#!/bin/sh\nprintf 'relay-node 1.2.4-test\\n'\n").unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o755)).unwrap();

        let output = Command::new(&artifact).arg("--version").output().unwrap();
        assert!(output.status.success());
        assert_eq!(reported_version(&output.stdout), Some("1.2.4-test"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validated_artifact_replaces_atomically_without_backup() {
        let dir = test_dir("relay-lifecycle");
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("relay-node");
        std::fs::write(&binary, b"old-binary").unwrap();
        let bytes = elf("amd64");
        let sha = format!("{:x}", Sha256::digest(&bytes));
        install_artifact_with_probe(&binary, &bytes, "x86_64", &sha, "1.2.4", |_| {
            Ok(b"relay-node 1.2.4\n".to_vec())
        })
        .unwrap();
        assert_eq!(std::fs::read(&binary).unwrap(), bytes);
        assert!(!dir.join("relay-node.backup").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn logs_redact_tokens_bearer_and_passwords() {
        let output = redact_logs(
            "NODE_TOKEN=secret\nAuthorization: Bearer abc\npassword=hunter2\nrule failed",
            "secret",
        );
        for secret in ["secret", "abc", "hunter2"] {
            assert!(!output.contains(secret));
        }
        assert!(output.contains("rule failed"));
    }

    #[test]
    fn uninstall_scope_preserves_openlist_and_unknown_nginx_files() {
        let root = test_dir("relay-uninstall");
        for path in [
            "opt/relay-node",
            "etc/relay-node",
            "etc/systemd/system",
            "etc/nginx/relay-panel-stream.d",
            "etc/nginx/conf.d",
            "var/lib/relay-panel/openlist",
            "etc/letsencrypt",
        ] {
            std::fs::create_dir_all(root.join(path)).unwrap();
        }
        for path in [
            "opt/relay-node/relay-node",
            "etc/relay-node/relay-node.env",
            "etc/systemd/system/relay-node.service",
            "etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
            "etc/nginx/conf.d/unknown.conf",
            "var/lib/relay-panel/openlist/data.db",
            "etc/letsencrypt/account",
        ] {
            std::fs::write(root.join(path), b"keep-or-remove").unwrap();
        }
        uninstall_managed(&root).unwrap();
        assert!(!root.join("opt/relay-node").exists());
        assert!(!root.join("etc/relay-node").exists());
        assert!(root.join("var/lib/relay-panel/openlist/data.db").exists());
        assert!(root.join("etc/nginx/conf.d/unknown.conf").exists());
        assert!(root.join("etc/letsencrypt/account").exists());
        assert_eq!(
            UNINSTALL_SYSTEMCTL_ARGS,
            ["disable", "--now", "relay-node.service"]
        );
        for protected in [
            "/var/lib/relay-panel/openlist",
            "/etc/letsencrypt",
            "/etc/nginx/conf.d",
            "/usr/bin/docker",
            "/usr/sbin/nginx",
        ] {
            assert!(!UNINSTALL_REMOVE_FILES.contains(&protected));
            assert!(!UNINSTALL_REMOVE_DIRS.contains(&protected));
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
