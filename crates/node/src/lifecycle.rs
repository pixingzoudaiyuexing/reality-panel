//! Restricted lifecycle actions received over the authenticated Panel WS.

use crate::config::{NodeConfig, NodeRuntimeAuth, PersistedNodeAuth};
use relay_shared::protocol::{
    lifecycle_artifact_architecture, NodeLifecycleAck, NodeLifecycleAction, NodeLifecycleCommand,
    NodeLifecycleEvent, NodeLifecycleEventStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::sync::mpsc;

const MAX_LOG_LINES: u16 = 500;
const MIN_ARTIFACT_BYTES: usize = 64 * 1024;
const MANAGED_BINARY: &str = "/opt/relay-node/relay-node";
const UNINSTALL_REMOVE_FILES: &[&str] = &[
    "/etc/systemd/system/relay-node.service",
    "/etc/relay-panel/camouflage-sites.json",
    "/etc/nginx/relay-panel-certs/fallback.crt",
    "/etc/nginx/relay-panel-certs/fallback.key",
    "/var/log/nginx/relay-panel-sni.log",
    "/var/log/nginx/relay-panel-camouflage.log",
];
const UNINSTALL_REMOVE_DIRS: &[&str] = &[
    "/etc/relay-node",
    "/opt/relay-node",
    "/var/www/relay-panel-certbot",
    "/run/relay-node",
];
const UNINSTALL_SYSTEMCTL_ARGS: &[&str] = &["disable", "--now", "relay-node.service"];
const OPENLIST_IMAGE: &str =
    "openlistteam/openlist@sha256:3bfba7ab379594c3f140e61ecc9096d66360cd4654ccea9f6cb8164b679a669d";
const OPENLIST_CONTAINER: &str = "relay-panel-openlist";
const OPENLIST_DATA_PATH: &str = "/var/lib/relay-panel/openlist";
const OPENLIST_OWNERSHIP_PATH: &str = "/var/lib/relay-panel/openlist-ownership.json";
const UNINSTALL_RECEIPT_DIR: &str = "/var/lib/relay-panel/uninstall-completions";
const UNINSTALL_FINALIZER_DIR: &str = "/var/lib/relay-panel/uninstall-finalizer";
const UNINSTALL_FINALIZER_BINARY: &str =
    "/var/lib/relay-panel/uninstall-finalizer/relay-node-finalizer";
const UNINSTALL_FINALIZER_SERVICE: &str = "relay-node-uninstall-finalizer.service";
const UNINSTALL_FINALIZER_SERVICE_PATH: &str =
    "/etc/systemd/system/relay-node-uninstall-finalizer.service";
const UNINSTALL_FINALIZER_TIMER: &str = "relay-node-uninstall-finalizer.timer";
const UNINSTALL_FINALIZER_TIMER_PATH: &str =
    "/etc/systemd/system/relay-node-uninstall-finalizer.timer";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UninstallJob {
    operation_id: String,
    node_id: String,
    panel_url: String,
    auth: PersistedNodeAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OpenListOwnership {
    version: u8,
    container_name: String,
    image: String,
    data_path: String,
    container_created: bool,
    data_dir_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UninstallCompletionReceipt {
    job: UninstallJob,
    #[serde(default)]
    panel_acknowledged: bool,
    cleanup_success: bool,
    #[serde(default)]
    destructive_started: bool,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenListCleanupPlan {
    Remove { container: bool, data: bool },
    Preserve(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UninstallCleanupReport {
    message: String,
}

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

fn write_uninstall_job(
    config: &NodeConfig,
    command: &NodeLifecycleCommand,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(format!(
        "/run/relay-node-uninstall-{}.json",
        command.operation_id
    ));
    let job = UninstallJob {
        operation_id: command.operation_id.clone(),
        node_id: command.node_id.clone(),
        panel_url: config.panel_url.clone(),
        auth: config.auth.persistent_descriptor(),
    };
    let bytes = serde_json::to_vec(&job).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("create uninstall job: {error}"))?;
    use std::io::Write;
    file.write_all(&bytes)
        .map_err(|error| format!("write uninstall job: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync uninstall job: {error}"))?;
    Ok(path)
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
        .get(url);
    let response = config
        .auth
        .apply_reqwest(response)
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
                .and_then(|lines| read_logs(lines, config.auth.sensitive_value()));
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
            let job = write_uninstall_job(&config, &command)?;
            let job_arg = job.to_string_lossy().into_owned();
            let scheduled = schedule_systemd(
                &[&binary, "--lifecycle-uninstall", &job_arg],
                "uninstall",
                &command.operation_id,
            );
            if scheduled.is_err() {
                let _ = std::fs::remove_file(job);
            }
            scheduled
        }),
    };

    match result {
        Ok(()) if command.action == NodeLifecycleAction::Uninstall => emit(
            &tx,
            &command,
            NodeLifecycleEventStatus::Restarting,
            "uninstall helper scheduled; waiting for verified cleanup result",
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

// All cleanup paths are fixed product paths. Refuse a symlink at any
// component: a product-looking directory must never route deletion elsewhere.
fn validate_cleanup_path(root: &Path, path: &Path) -> Result<(), String> {
    if !path.starts_with(root) {
        return Err("cleanup path escaped root".into());
    }
    let mut current = root.to_path_buf();
    for component in path
        .strip_prefix(root)
        .map_err(|e| e.to_string())?
        .components()
    {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err("invalid cleanup path component".into());
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "refusing symlinked cleanup path {}",
                    current.display()
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("inspect cleanup path: {e}")),
        }
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

fn remove_marked_file(root: &Path, path: &str, markers: &[&str]) -> Result<bool, String> {
    let path = root.join(path.trim_start_matches('/'));
    validate_cleanup_path(root, &path)?;
    if !path.exists() {
        return Ok(false);
    }
    let contents =
        std::fs::read_to_string(&path).map_err(|e| format!("read managed configuration: {e}"))?;
    if !markers.iter().any(|marker| contents.contains(marker)) {
        return Ok(false);
    }
    remove_if_exists(&path)?;
    Ok(true)
}

fn remove_stream_include(root: &Path) -> Result<(), String> {
    let path = root.join("etc/nginx/nginx.conf");
    if !path.exists() {
        return Ok(());
    }
    let original =
        std::fs::read_to_string(&path).map_err(|error| format!("read nginx.conf: {error}"))?;
    let filtered = original
        .lines()
        .filter(|line| line.trim() != "include /etc/nginx/relay-panel-stream.conf;")
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    if filtered != original {
        let temp = path.with_extension(format!("rp-uninstall-{}.tmp", std::process::id()));
        let mode = std::fs::metadata(&path)
            .map_err(|error| format!("read nginx.conf metadata: {error}"))?
            .permissions()
            .mode();
        let result: Result<(), String> = (|| {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&temp)
                .map_err(|error| format!("create nginx.conf temporary file: {error}"))?;
            file.write_all(filtered.as_bytes())
                .map_err(|error| format!("write nginx.conf: {error}"))?;
            file.flush()
                .map_err(|error| format!("flush nginx.conf: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("fsync nginx.conf: {error}"))?;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
                .map_err(|error| format!("preserve nginx.conf permissions: {error}"))?;
            std::fs::rename(&temp, &path).map_err(|error| format!("commit nginx.conf: {error}"))?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| format!("fsync nginx.conf directory: {error}"))?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result?;
    }
    Ok(())
}

fn openlist_cleanup_plan(root: &Path, inspection: Option<&str>) -> OpenListCleanupPlan {
    let ownership_path = root.join(OPENLIST_OWNERSHIP_PATH.trim_start_matches('/'));
    let ownership = std::fs::read(&ownership_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<OpenListOwnership>(&bytes).ok());
    let Some(ownership) = ownership else {
        return OpenListCleanupPlan::Preserve(
            "OpenList ownership cannot be verified; existing container and data were preserved"
                .into(),
        );
    };
    if ownership.version != 1
        || ownership.container_name != OPENLIST_CONTAINER
        || ownership.image != OPENLIST_IMAGE
        || ownership.data_path != OPENLIST_DATA_PATH
    {
        return OpenListCleanupPlan::Preserve(
            "OpenList ownership marker is invalid; existing container and data were preserved"
                .into(),
        );
    }
    if ownership.container_created {
        let Some(inspection) = inspection else {
            return OpenListCleanupPlan::Preserve(
                "OpenList container ownership could not be revalidated; resources were preserved"
                    .into(),
            );
        };
        if inspection != "ABSENT"
            && (!inspection.contains(OPENLIST_IMAGE)
                || !inspection.contains(&format!("{OPENLIST_DATA_PATH}:/opt/openlist/data;")))
        {
            return OpenListCleanupPlan::Preserve(
                "OpenList container no longer matches its ownership marker; resources were preserved"
                    .into(),
            );
        }
    }
    if !ownership.container_created && !ownership.data_dir_created {
        return OpenListCleanupPlan::Preserve(
            "OpenList was pre-existing and reused; container and data were preserved".into(),
        );
    }
    OpenListCleanupPlan::Remove {
        container: ownership.container_created,
        data: ownership.data_dir_created,
    }
}

fn remove_owned_openlist(root: &Path) -> Result<Option<String>, String> {
    if root != Path::new("/") {
        return Ok(None);
    }
    let marker = rooted(root, OPENLIST_OWNERSHIP_PATH);
    validate_cleanup_path(root, &marker)?;
    let ownership = match std::fs::read(&marker) {
        Ok(raw) => serde_json::from_slice::<OpenListOwnership>(&raw)
            .map_err(|e| format!("invalid OpenList ownership: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read OpenList ownership: {e}")),
    };
    if ownership.version != 1
        || ownership.container_name != OPENLIST_CONTAINER
        || ownership.image != OPENLIST_IMAGE
        || ownership.data_path != OPENLIST_DATA_PATH
    {
        return Err("OpenList ownership marker does not match managed resources".into());
    }
    if !ownership.container_created && !ownership.data_dir_created {
        remove_if_exists(&marker)?;
        return Ok(Some(
            "pre-existing OpenList container and data preserved".into(),
        ));
    }
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{.Config.Image}}|{{range .Mounts}}{{.Source}}:{{.Destination}};{{end}}",
            OPENLIST_CONTAINER,
        ])
        .output();
    let mut inspection = output.as_ref().ok().and_then(|output| {
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    });
    if inspection.is_none() && ownership.container_created {
        let listed = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                &format!("name=^/{OPENLIST_CONTAINER}$"),
                "--format",
                "{{.Names}}",
            ])
            .output()
            .map_err(|e| format!("inspect OpenList presence: {e}"))?;
        if !listed.status.success() || !String::from_utf8_lossy(&listed.stdout).trim().is_empty() {
            return Err("cannot verify owned OpenList container cleanup; retry required".into());
        }
        inspection = Some("ABSENT".into());
    }
    match openlist_cleanup_plan(root, inspection.as_deref()) {
        OpenListCleanupPlan::Preserve(message) => Err(message),
        OpenListCleanupPlan::Remove { container, data } => {
            if container && inspection.as_deref().is_some_and(|value| value != "ABSENT") {
                let status = Command::new("docker")
                    .args(["rm", "-f", OPENLIST_CONTAINER])
                    .status();
                if !status.is_ok_and(|status| status.success()) {
                    return Err("remove owned OpenList container failed".into());
                }
            }
            if data {
                let data_path = Path::new(OPENLIST_DATA_PATH);
                if data_path.is_symlink() {
                    return Err("refusing to remove symlinked OpenList data directory".into());
                }
                if data_path.exists() {
                    std::fs::remove_dir_all(data_path)
                        .map_err(|error| format!("remove owned OpenList data: {error}"))?;
                }
            }
            remove_if_exists(Path::new(OPENLIST_OWNERSHIP_PATH))?;
            Ok(None)
        }
    }
}

fn restore_nginx_snapshot(snapshot: &[(PathBuf, Vec<u8>)]) -> Result<(), String> {
    for (path, bytes) in snapshot {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("restore Nginx directory: {error}"))?;
        }
        std::fs::write(path, bytes)
            .map_err(|error| format!("restore Nginx snapshot {}: {error}", path.display()))?;
    }
    Ok(())
}

fn validate_and_reload_nginx<F>(snapshot: &[(PathBuf, Vec<u8>)], mut run: F) -> Result<(), String>
where
    F: FnMut(&str, &[&str]) -> Result<(), String>,
{
    if let Err(error) = run("nginx", &["-t"]) {
        restore_nginx_snapshot(snapshot)?;
        return Err(format!(
            "nginx configuration is invalid after cleanup: {error}"
        ));
    }
    if let Err(error) = run("systemctl", &["reload", "nginx"]) {
        restore_nginx_snapshot(snapshot)?;
        run("nginx", &["-t"]).map_err(|restore| {
            format!("Nginx reload failed ({error}); restored config is invalid: {restore}")
        })?;
        run("systemctl", &["reload", "nginx"]).map_err(|restore| {
            format!("Nginx reload failed ({error}); restoring previous runtime failed: {restore}")
        })?;
        return Err(format!("Nginx reload failed after cleanup: {error}"));
    }
    Ok(())
}

fn managed_nginx_runtime_absent(config_dump: &str) -> bool {
    [
        "# generated by relay-node; do not edit",
        "# generated by relay-node; TLS camouflage sites",
        "# RelayPanel managed bootstrap camouflage fallback",
        "# RelayPanel managed stream root; do not edit",
        "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
        "/etc/nginx/stream.d/relay-panel-sni.conf",
        "# RelayPanel managed Lite fallback",
        "# generated by relay-node; global HTTP",
        "/etc/nginx/relay-panel-certs/fallback.crt",
        "/etc/nginx/relay-panel-certs/fallback.key",
    ]
    .iter()
    .all(|marker| !config_dump.contains(marker))
}

fn verify_nginx_runtime_cleanup(snapshot: &[(PathBuf, Vec<u8>)]) -> Result<(), String> {
    let output = Command::new("nginx")
        .arg("-T")
        .output()
        .map_err(|error| format!("inspect active Nginx configuration: {error}"))?;
    let mut dump = output.stdout;
    dump.extend_from_slice(&output.stderr);
    if output.status.success() && managed_nginx_runtime_absent(&String::from_utf8_lossy(&dump)) {
        return Ok(());
    }
    restore_nginx_snapshot(snapshot)?;
    validate_and_reload_nginx(snapshot, |program, args| {
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|error| format!("execute {program}: {error}"))?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("{program} {} exited unsuccessfully", args.join(" ")))
    })?;
    Err("Reality-managed Nginx listener or certificate reference remains in the active configuration".into())
}

fn managed_docker_nginx_name(env: &str) -> Result<Option<String>, String> {
    for line in env.lines() {
        let Some(value) = line.strip_prefix("NGINX_SNI_TEST_CMD=") else {
            continue;
        };
        let value = value.trim().trim_matches(['\'', '"']);
        if !value.starts_with("docker ") {
            return Ok(None);
        }
        let parts = value.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 5
            || parts[0] != "docker"
            || parts[1] != "exec"
            || parts[3..] != ["nginx", "-t"]
            || !parts[2]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err("unrecognized Docker Nginx runtime; resources preserved".into());
        }
        return Ok(Some(parts[2].into()));
    }
    Ok(None)
}

fn docker_nginx_owned(inspection: &str) -> bool {
    inspection.starts_with("nginx-sni|")
        && inspection.split('|').nth(1).is_some_and(|mounts| {
            mounts
                .split(';')
                .any(|mount| mount == "/opt/relay-node/nginx/nginx.conf:/etc/nginx/nginx.conf")
        })
}

fn inspect_docker_nginx(root: &Path) -> Result<Option<String>, String> {
    let env = match std::fs::read_to_string(rooted(root, "/etc/relay-node/relay-node.env")) {
        Ok(env) => env,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read Nginx runtime configuration: {e}")),
    };
    let Some(name) = managed_docker_nginx_name(&env)? else {
        return Ok(None);
    };
    if root != Path::new("/") {
        return Ok(Some(name));
    }
    let listed = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name=^/{name}$"),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .map_err(|e| format!("inspect Docker Nginx: {e}"))?;
    if !listed.status.success() {
        return Err("Docker Nginx presence could not be verified".into());
    }
    if String::from_utf8_lossy(&listed.stdout).trim().is_empty() {
        return Ok(Some(name));
    }
    let output = Command::new("docker").args(["inspect", "-f", "{{index .Config.Labels \"io.reality-panel.managed\"}}|{{range .Mounts}}{{.Source}}:{{.Destination}};{{end}}", &name]).output().map_err(|e| e.to_string())?;
    if !output.status.success()
        || !docker_nginx_owned(String::from_utf8_lossy(&output.stdout).trim())
    {
        return Err("Docker Nginx ownership is unproven; container and files preserved".into());
    }
    Ok(Some(name))
}

fn uninstall_managed(root: &Path) -> Result<UninstallCleanupReport, String> {
    let rooted = |path: &str| root.join(path.trim_start_matches('/'));
    let nginx_paths = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/relay-panel-stream.conf",
        "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
        "/etc/nginx/stream.d/relay-panel-sni.conf",
        "/etc/nginx/conf.d/relay-panel-fallback.conf",
        "/etc/nginx/conf.d/relay-panel-acme.conf",
        "/etc/nginx/conf.d/relay-panel-lite-fallback.conf",
    ];
    for path in nginx_paths
        .iter()
        .chain(UNINSTALL_REMOVE_FILES)
        .chain(UNINSTALL_REMOVE_DIRS)
        .chain(
            [
                "/var/lib/relay-panel/node-claims",
                "/var/lib/relay-panel/openlist",
                "/var/lib/relay-panel/xiaoya-byoa",
                "/var/lib/relay-panel/xiaoya-byoa-ownership.json",
                "/var/lib/relay-panel/uninstall-completions",
                "/var/lib/relay-panel/uninstall-finalizer",
                "/etc/sysctl.d/99-reality-panel-bbr.conf",
                "/etc/modules-load.d/reality-panel-bbr.conf",
            ]
            .iter(),
        )
    {
        validate_cleanup_path(root, &rooted(path))?;
    }
    let docker_nginx = inspect_docker_nginx(root)?;
    let nginx_snapshot = nginx_paths
        .iter()
        .filter_map(|path| {
            let path = rooted(path);
            std::fs::read(&path).ok().map(|bytes| (path, bytes))
        })
        .collect::<Vec<_>>();
    if root == Path::new("/") && rooted("/etc/systemd/system/relay-node.service").exists() {
        let status = Command::new("systemctl")
            .args(UNINSTALL_SYSTEMCTL_ARGS)
            .status();
        if !status.is_ok_and(|status| status.success()) {
            return Err("stop and disable relay-node.service failed".into());
        }
    }
    let removed_sni = remove_marked_file(
        root,
        "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
        &["# generated by relay-node; do not edit"],
    )?;
    let legacy_sni = remove_marked_file(
        root,
        "/etc/nginx/stream.d/relay-panel-sni.conf",
        &["# generated by relay-node; do not edit"],
    )?;
    if legacy_sni || removed_sni {
        validate_cleanup_path(root, &rooted("/var/log/nginx/sni-router.log"))?;
        remove_if_exists(&rooted("/var/log/nginx/sni-router.log"))?;
    }
    let removed_stream_root = remove_marked_file(
        root,
        "/etc/nginx/relay-panel-stream.conf",
        &["# RelayPanel managed stream root; do not edit"],
    )?;
    remove_marked_file(
        root,
        "/etc/nginx/conf.d/relay-panel-fallback.conf",
        &[
            "# generated by relay-node; TLS camouflage sites",
            "# RelayPanel managed bootstrap camouflage fallback",
        ],
    )?;
    remove_marked_file(
        root,
        "/etc/nginx/conf.d/relay-panel-acme.conf",
        &["# generated by relay-node;"],
    )?;
    remove_marked_file(
        root,
        "/etc/nginx/conf.d/relay-panel-lite-fallback.conf",
        &["# RelayPanel managed Lite fallback"],
    )?;
    remove_marked_file(
        root,
        "/var/www/fallback/index.html",
        &["<!-- RelayPanel managed Lite fallback -->"],
    )?;
    remove_marked_file(
        root,
        "/etc/letsencrypt/renewal-hooks/deploy/relay-panel-nginx-reload.sh",
        &["# managed by Reality Panel; renewal hook"],
    )?;
    remove_marked_file(
        root,
        "/etc/cron.d/relay-panel-certbot-renew",
        &["# managed by Reality Panel; certbot renewal"],
    )?;
    let lite_marker = rooted("/etc/relay-panel/lite-mode");
    if std::fs::read_to_string(&lite_marker).is_ok_and(|value| value.trim() == "lite") {
        remove_if_exists(&lite_marker)?;
    }
    if removed_stream_root || !rooted("/etc/nginx/relay-panel-stream.conf").exists() {
        // Also repair a retry after an interrupted deletion of the stream root.
        remove_stream_include(root)?;
    }
    // Validate/reload while certs and runtime files still exist so rollback
    // can restore a usable Nginx configuration on either test or reload failure.
    if root == Path::new("/") && !nginx_snapshot.is_empty() {
        validate_and_reload_nginx(&nginx_snapshot, run_checked)?;
        verify_nginx_runtime_cleanup(&nginx_snapshot)?;
    }
    if root == Path::new("/") {
        if let Some(name) = &docker_nginx {
            // docker rm -f is idempotent for an already absent verified target.
            let output = Command::new("docker")
                .args([
                    "ps",
                    "-a",
                    "--filter",
                    &format!("name=^/{name}$"),
                    "--format",
                    "{{.Names}}",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err("recheck Docker Nginx presence failed".into());
            }
            if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
                run_checked("docker", &["rm", "-f", name])?;
            }
        }
        crate::bbr::cleanup()?;
    }
    let openlist_note = remove_owned_openlist(root)?;
    if root == Path::new("/") {
        crate::xiaoya::uninstall_owned()?;
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
    for path in [
        "/etc/nginx/relay-panel-stream.d",
        "/etc/nginx/relay-panel-certs",
        "/var/www/fallback",
        "/etc/relay-panel",
        "/var/lib/relay-panel",
    ] {
        let path = rooted(path);
        if path.exists() {
            let _ = std::fs::remove_dir(&path);
        }
    }
    if root == Path::new("/") {
        let daemon_reload = Command::new("systemctl").arg("daemon-reload").status();
        if !daemon_reload.is_ok_and(|status| status.success()) {
            return Err("systemd daemon-reload failed after relay-node service removal".into());
        }
    }
    Ok(UninstallCleanupReport {
        message: openlist_note.map_or_else(
            || "Reality Panel managed node resources removed".into(),
            |note| format!("Reality Panel managed node resources removed; {note}"),
        ),
    })
}

fn uninstall_receipt_path(root: &Path, operation_id: &str) -> PathBuf {
    root.join(UNINSTALL_RECEIPT_DIR.trim_start_matches('/'))
        .join(format!("{operation_id}.json"))
}

fn rooted(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

fn finalizer_service(receipt_path: &Path) -> String {
    format!(
        "[Unit]\nDescription=Reality Panel uninstall completion finalizer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart={UNINSTALL_FINALIZER_BINARY} --lifecycle-uninstall-finalize {}\nRestart=on-failure\nRestartSec=10s\n",
        receipt_path.display()
    )
}

fn finalizer_timer() -> &'static str {
    "[Unit]\nDescription=Retry Reality Panel uninstall completion\n\n[Timer]\nOnBootSec=10s\nOnUnitActiveSec=10s\nPersistent=true\nUnit=relay-node-uninstall-finalizer.service\n\n[Install]\nWantedBy=timers.target\n"
}

fn write_atomic_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("managed file has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create managed directory: {error}"))?;
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let result: Result<(), String> = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|error| format!("create managed temporary file: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("write managed file: {error}"))?;
        file.flush()
            .map_err(|error| format!("flush managed file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync managed file: {error}"))?;
        std::fs::rename(&temp, path).map_err(|error| format!("commit managed file: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

fn install_uninstall_finalizer<F>(
    root: &Path,
    source_binary: &Path,
    receipt_path: &Path,
    mut run: F,
) -> Result<(), String>
where
    F: FnMut(&str, &[&str]) -> Result<(), String>,
{
    let binary = rooted(root, UNINSTALL_FINALIZER_BINARY);
    let service = rooted(root, UNINSTALL_FINALIZER_SERVICE_PATH);
    let timer = rooted(root, UNINSTALL_FINALIZER_TIMER_PATH);
    let bytes = std::fs::read(source_binary)
        .map_err(|error| format!("read uninstall finalizer binary: {error}"))?;
    write_atomic_file(&binary, &bytes, 0o700)?;
    write_atomic_file(&service, finalizer_service(receipt_path).as_bytes(), 0o644)?;
    write_atomic_file(&timer, finalizer_timer().as_bytes(), 0o644)?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", UNINSTALL_FINALIZER_TIMER])?;
    Ok(())
}

fn cleanup_uninstall_finalizer<F, C>(
    root: &Path,
    receipt_path: &Path,
    mut run: F,
    retire_credentials: C,
) -> Result<(), String>
where
    F: FnMut(&str, &[&str]) -> Result<(), String>,
    C: FnOnce() -> Result<(), String>,
{
    for path in [
        UNINSTALL_FINALIZER_SERVICE_PATH,
        UNINSTALL_FINALIZER_TIMER_PATH,
        UNINSTALL_FINALIZER_BINARY,
    ] {
        validate_cleanup_path(root, &rooted(root, path))?;
    }
    validate_cleanup_path(root, receipt_path)?;
    run(
        "systemctl",
        &["disable", "--now", UNINSTALL_FINALIZER_TIMER],
    )?;
    for path in [
        UNINSTALL_FINALIZER_SERVICE_PATH,
        UNINSTALL_FINALIZER_TIMER_PATH,
    ] {
        remove_if_exists(&rooted(root, path))?;
    }
    if let Err(error) = run("systemctl", &["daemon-reload"]).and_then(|_| retire_credentials()) {
        // Keep the receipt and executable; restore the retry entrypoints before
        // returning a partial failure. Never lose the only recovery material.
        write_atomic_file(
            &rooted(root, UNINSTALL_FINALIZER_SERVICE_PATH),
            finalizer_service(receipt_path).as_bytes(),
            0o644,
        )?;
        write_atomic_file(
            &rooted(root, UNINSTALL_FINALIZER_TIMER_PATH),
            finalizer_timer().as_bytes(),
            0o644,
        )?;
        let _ = run("systemctl", &["daemon-reload"]);
        let _ = run("systemctl", &["enable", "--now", UNINSTALL_FINALIZER_TIMER]);
        return Err(error);
    }
    let timer_stamp = rooted(
        root,
        "/var/lib/systemd/timers/stamp-relay-node-uninstall-finalizer.timer",
    );
    validate_cleanup_path(root, &timer_stamp)?;
    remove_if_exists(&timer_stamp)?;
    remove_if_exists(&rooted(root, UNINSTALL_FINALIZER_BINARY))?;
    remove_if_exists(receipt_path)?;
    for path in [
        UNINSTALL_RECEIPT_DIR,
        UNINSTALL_FINALIZER_DIR,
        "/var/lib/relay-panel/node-claims",
        "/var/lib/relay-panel",
    ] {
        let _ = std::fs::remove_dir(rooted(root, path));
    }
    Ok(())
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("private state path has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create private state directory: {error}"))?;
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let result: Result<(), String> = (|| {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| format!("create private state: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write private state: {error}"))?;
        file.flush()
            .map_err(|error| format!("flush private state: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync private state: {error}"))?;
        std::fs::rename(&temp, path).map_err(|error| format!("commit private state: {error}"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync private state directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

fn report_uninstall_once(
    job: &UninstallJob,
    success: bool,
    destructive_started: bool,
    message: &str,
) -> Result<(), String> {
    report_uninstall_phase(
        job,
        success,
        destructive_started,
        message,
        true,
        &job.auth.load_runtime()?,
    )
}
fn report_uninstall_phase(
    job: &UninstallJob,
    success: bool,
    destructive_started: bool,
    message: &str,
    host_cleanup_pending: bool,
    auth: &NodeRuntimeAuth,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v1/node/uninstall_result",
        job.panel_url.trim_end_matches('/')
    );
    if !auth.transport_allowed(&job.panel_url) {
        return Err("permanent Credential uninstall callback requires HTTPS".into());
    }
    let body = serde_json::json!({
        "operation_id": job.operation_id,
        "node_id": job.node_id,
        "success": success,
        "host_cleanup_pending": host_cleanup_pending,
        "destructive_started": destructive_started,
        "message": message
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build uninstall callback runtime: {error}"))?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("build uninstall callback client: {error}"))?;
        let response = auth
            .apply_reqwest(client.post(url))
            .header("X-Node-ID", &job.node_id)
            .json(&body)
            .send()
            .await
            .map_err(|_| "Panel uninstall callback failed".to_string())?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or_else(|| "Panel rejected uninstall result".into())
    })
}

fn completion_attempt<C, R>(
    receipt_path: &Path,
    mut cleanup: C,
    mut report: R,
) -> Result<bool, String>
where
    C: FnMut() -> Result<UninstallCleanupReport, String>,
    R: FnMut(&UninstallJob, bool, bool, &str, bool) -> Result<(), String>,
{
    let mut receipt: UninstallCompletionReceipt = serde_json::from_slice(
        &std::fs::read(receipt_path).map_err(|error| format!("read uninstall receipt: {error}"))?,
    )
    .map_err(|error| format!("parse uninstall receipt: {error}"))?;
    if receipt.panel_acknowledged {
        return Ok(true);
    }
    if !receipt.cleanup_success {
        receipt.destructive_started = true;
        write_private_json(receipt_path, &receipt)?;
        match cleanup() {
            Ok(cleanup) => {
                receipt.cleanup_success = true;
                receipt.message = cleanup.message;
            }
            Err(error) => {
                receipt.cleanup_success = false;
                receipt.message = error;
            }
        }
        write_private_json(receipt_path, &receipt)?;
    }
    if report(
        &receipt.job,
        receipt.cleanup_success,
        receipt.destructive_started,
        &receipt.message,
        true,
    )
    .is_err()
    {
        return Ok(false);
    }
    if !receipt.cleanup_success {
        return Ok(false);
    }
    receipt.panel_acknowledged = true;
    write_private_json(receipt_path, &receipt)?;
    Ok(true)
}

fn finalizer_tick<C, R, S>(
    root: &Path,
    receipt_path: &Path,
    cleanup: C,
    mut report: R,
    systemctl: S,
) -> Result<bool, String>
where
    C: FnMut() -> Result<UninstallCleanupReport, String>,
    R: FnMut(&UninstallJob, bool, bool, &str, bool) -> Result<(), String>,
    S: FnMut(&str, &[&str]) -> Result<(), String>,
{
    if !completion_attempt(receipt_path, cleanup, &mut report)? {
        return Ok(false);
    }
    let receipt: UninstallCompletionReceipt = serde_json::from_slice(
        &std::fs::read(receipt_path).map_err(|error| format!("read uninstall receipt: {error}"))?,
    )
    .map_err(|error| format!("parse uninstall receipt: {error}"))?;
    cleanup_uninstall_finalizer(root, receipt_path, systemctl, || {
        cleanup_uninstalled_credentials(root, &receipt.job)
    })?;
    // Success is acknowledged only after credentials, retry units and receipt
    // have actually disappeared. A lost final callback leaves Panel VERIFYING.
    Ok(report(&receipt.job, true, true, &receipt.message, false).is_ok())
}

fn cleanup_uninstalled_credentials(root: &Path, job: &UninstallJob) -> Result<(), String> {
    let PersistedNodeAuth::PermanentCredential {
        credential_id,
        secret_file,
    } = &job.auth
    else {
        return Ok(());
    };
    if job.node_id.is_empty()
        || !job
            .node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(());
    }
    let Some(managed_dir) = secret_file.parent() else {
        return Ok(());
    };
    let Ok(relative) = managed_dir.strip_prefix("/var/lib/relay-panel/node-claims") else {
        return Ok(());
    };
    let Some(claim_id) = relative.to_str() else {
        return Ok(());
    };
    if !valid_id(claim_id)
        || secret_file.file_name().and_then(|s| s.to_str()) != Some("node-credential.secret")
    {
        return Ok(());
    }
    let claims_root = rooted(root, "/var/lib/relay-panel/node-claims");
    let lock_path = claims_root.join("migration.lock");
    validate_cleanup_path(root, &lock_path)?;
    let migration_lock = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
    {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            // The existing bootstrap helper owns an empty private lock file.
            if !metadata.is_file()
                || metadata.len() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err("unexpected migration lock ownership".into());
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("credential migration is active; retry uninstall".into());
            }
            Some(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("read migration lock: {error}")),
    };
    let descriptor_path = rooted(root, crate::config::RUNTIME_AUTH_DESCRIPTOR);
    validate_cleanup_path(root, &descriptor_path)?;
    match std::fs::read(&descriptor_path) {
        Ok(raw) => {
            #[derive(Deserialize)]
            struct Descriptor {
                node_id: String,
                credential_id: String,
                secret_file: PathBuf,
            }
            let descriptor: Descriptor = serde_json::from_slice(&raw)
                .map_err(|error| format!("parse runtime auth during uninstall: {error}"))?;
            if descriptor.node_id == job.node_id {
                // An old receipt may finish after a newer installation.
                if descriptor.credential_id != *credential_id
                    || descriptor.secret_file != *secret_file
                {
                    return Ok(());
                }
                remove_if_exists(&descriptor_path)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("read runtime auth during uninstall: {error}")),
    }
    let managed_dir = rooted(root, &managed_dir.to_string_lossy());
    validate_cleanup_path(root, &managed_dir)?;
    match std::fs::remove_dir_all(&managed_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("remove uninstalled credential state: {error}")),
    }
    if migration_lock.is_some() {
        let only_lock = std::fs::read_dir(&claims_root)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .iter()
            .all(|entry| entry.file_name() == "migration.lock");
        if only_lock {
            remove_if_exists(&lock_path)?;
        }
    }
    Ok(())
}

fn run_checked(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("execute {program}: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("{program} {} exited unsuccessfully", args.join(" ")))
}

/// Root-only SSH replacement reuses uninstall ownership rules. Panel must first
/// retire the exact identity; this helper grants no Panel authentication authority.
fn existing_install_cleanup(root: &Path, expected: &str, check_only: bool) -> Result<(), String> {
    if !valid_id(expected) {
        return Err("invalid existing identity".into());
    }
    if root == Path::new("/") && unsafe { libc::geteuid() } != 0 {
        return Err("root is required".into());
    }
    let identity = rooted(root, "/opt/relay-node/node-id");
    validate_cleanup_path(root, &identity)?;
    if std::fs::read_to_string(&identity)
        .map_err(|_| "existing identity missing")?
        .trim()
        != expected
    {
        return Err("existing identity changed; all resources preserved".into());
    }
    for unit in [
        "/etc/systemd/system/relay-node-uninstall-finalizer.timer",
        "/etc/systemd/system/relay-node-uninstall-finalizer.service",
    ] {
        if rooted(root, unit).symlink_metadata().is_ok() {
            return Err("uninstall finalizer is pending; preserve installation".into());
        }
    }
    // Check before Panel retirement as well as cleanup: an active credential
    // bootstrap/migration must not be disrupted by replacement.
    let lock_path = rooted(root, "/var/lib/relay-panel/node-claims/migration.lock");
    validate_cleanup_path(root, &lock_path)?;
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
    {
        Ok(file) => {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file()
                || metadata.len() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err("unexpected migration lock ownership".into());
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("credential migration is active; preserve installation".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("read migration lock: {error}")),
    }
    for managed in UNINSTALL_REMOVE_FILES
        .iter()
        .chain(UNINSTALL_REMOVE_DIRS)
        .chain(
            [
                "/etc/nginx/nginx.conf",
                "/etc/nginx/relay-panel-stream.conf",
                "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
                "/etc/nginx/stream.d/relay-panel-sni.conf",
                "/etc/nginx/conf.d/relay-panel-fallback.conf",
                "/etc/nginx/conf.d/relay-panel-acme.conf",
                "/etc/nginx/conf.d/relay-panel-lite-fallback.conf",
                "/var/lib/relay-panel/node-claims",
                "/var/lib/relay-panel/openlist-ownership.json",
                "/var/lib/relay-panel/openlist",
                "/var/lib/relay-panel/xiaoya-byoa",
                "/var/lib/relay-panel/xiaoya-byoa-ownership.json",
                "/var/lib/relay-panel/uninstall-completions",
                "/var/lib/relay-panel/uninstall-finalizer",
                "/etc/sysctl.d/99-reality-panel-bbr.conf",
                "/etc/modules-load.d/reality-panel-bbr.conf",
            ]
            .iter(),
        )
    {
        validate_cleanup_path(root, &rooted(root, managed))?;
    }
    inspect_docker_nginx(root)?;
    if root == Path::new("/") {
        crate::xiaoya::validate_uninstall_owned()?;
    }
    let descriptor = rooted(root, crate::config::RUNTIME_AUTH_DESCRIPTOR);
    let auth = if descriptor.exists() {
        #[derive(Deserialize)]
        struct Descriptor {
            node_id: String,
            credential_id: String,
            secret_file: PathBuf,
        }
        let value: Descriptor = serde_json::from_slice(
            &std::fs::read(&descriptor).map_err(|_| "read runtime descriptor failed")?,
        )
        .map_err(|_| "invalid runtime descriptor")?;
        if value.node_id != expected || !valid_id(&value.credential_id) {
            return Err("runtime identity conflict".into());
        }
        let relative = value
            .secret_file
            .strip_prefix("/var/lib/relay-panel/node-claims")
            .map_err(|_| "unmanaged credential path")?;
        if relative.components().count() != 2
            || relative.file_name().and_then(|s| s.to_str()) != Some("node-credential.secret")
            || !valid_id(relative.parent().and_then(|s| s.to_str()).unwrap_or(""))
        {
            return Err("unmanaged credential path".into());
        }
        validate_cleanup_path(root, &rooted(root, &value.secret_file.to_string_lossy()))?;
        Some(PersistedNodeAuth::PermanentCredential {
            credential_id: value.credential_id,
            secret_file: value.secret_file,
        })
    } else {
        None
    };
    // Discover only state files naming this exact previous identity. An inactive
    // Fresh failure can leave a claim directory without runtime-auth.json.
    let claims = rooted(root, "/var/lib/relay-panel/node-claims");
    let mut orphan_credentials = Vec::new();
    let mut empty_residue_dirs = Vec::new();
    if claims.exists() {
        for entry in std::fs::read_dir(&claims).map_err(|_| "read credential residue failed")? {
            let entry = entry.map_err(|_| "read credential residue failed")?;
            if !entry
                .file_type()
                .map_err(|_| "read credential residue type failed")?
                .is_dir()
            {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !valid_id(name) {
                continue;
            }
            let state = entry.path().join("credential-pending.json");
            validate_cleanup_path(root, &state)?;
            let raw = match std::fs::read(&state) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if name == expected
                        && std::fs::read_dir(entry.path())
                            .map_err(|_| "read empty residue failed")?
                            .next()
                            .is_none()
                    {
                        empty_residue_dirs.push(entry.path());
                    }
                    continue;
                }
                Err(_) => return Err("read credential residue state failed".into()),
            };
            let state: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|_| "invalid credential residue state")?;
            if state["node_id"].as_str() != Some(expected) {
                continue;
            }
            let credential_id = state["credential_id"]
                .as_str()
                .filter(|id| valid_id(id))
                .ok_or("invalid residue credential identity")?;
            let secret_file = PathBuf::from(format!(
                "/var/lib/relay-panel/node-claims/{name}/node-credential.secret"
            ));
            validate_cleanup_path(root, &rooted(root, &secret_file.to_string_lossy()))?;
            orphan_credentials.push(PersistedNodeAuth::PermanentCredential {
                credential_id: credential_id.into(),
                secret_file,
            });
        }
    }
    if check_only {
        return Ok(());
    }
    // Credentials are removed before service/files only after exact identity and
    // path validation. No historical Panel data or unrelated claim is removed.
    if let Some(auth) = auth {
        cleanup_uninstalled_credentials(
            root,
            &UninstallJob {
                operation_id: expected.into(),
                node_id: expected.into(),
                panel_url: String::new(),
                auth,
            },
        )?;
    }
    for auth in orphan_credentials {
        cleanup_uninstalled_credentials(
            root,
            &UninstallJob {
                operation_id: expected.into(),
                node_id: expected.into(),
                panel_url: String::new(),
                auth,
            },
        )?;
    }
    for path in empty_residue_dirs {
        std::fs::remove_dir(path).map_err(|_| "empty identity residue changed; retry detection")?;
    }
    uninstall_managed(root)?;
    Ok(())
}

// SSH Fresh reset deliberately has no old identity/authentication gate. The
// original exact-identity uninstall/upgrade helpers retain their own contract.
const FRESH_REMOVE_FILES: &[&str] = &[
    "/etc/relay-panel/lite-mode",
    UNINSTALL_FINALIZER_SERVICE_PATH,
    UNINSTALL_FINALIZER_TIMER_PATH,
];
const FRESH_REMOVE_DIRS: &[&str] = &[
    "/var/lib/relay-panel/node-claims",
    UNINSTALL_RECEIPT_DIR,
    UNINSTALL_FINALIZER_DIR,
];

fn fresh_reset(root: &Path, phase: &str) -> Result<(), String> {
    if root == Path::new("/") && unsafe { libc::geteuid() } != 0 {
        return Err("root is required".into());
    }
    for path in UNINSTALL_REMOVE_FILES
        .iter()
        .chain(UNINSTALL_REMOVE_DIRS)
        .chain(FRESH_REMOVE_FILES)
        .chain(FRESH_REMOVE_DIRS)
        .chain(
            [
                "/etc/nginx/nginx.conf",
                "/etc/nginx/relay-panel-stream.conf",
                "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
                "/etc/nginx/stream.d/relay-panel-sni.conf",
                "/etc/nginx/conf.d/relay-panel-fallback.conf",
                "/etc/nginx/conf.d/relay-panel-acme.conf",
                "/etc/nginx/conf.d/relay-panel-lite-fallback.conf",
                "/var/lib/relay-panel/openlist-ownership.json",
                "/var/lib/relay-panel/openlist",
                "/var/lib/relay-panel/xiaoya-byoa",
                "/var/lib/relay-panel/xiaoya-byoa-ownership.json",
                "/etc/sysctl.d/99-reality-panel-bbr.conf",
                "/etc/modules-load.d/reality-panel-bbr.conf",
            ]
            .iter(),
        )
    {
        validate_cleanup_path(root, &rooted(root, path))?;
    }
    inspect_docker_nginx(root)?;
    if root == Path::new("/") {
        crate::xiaoya::validate_uninstall_owned()?;
    }
    if phase == "check" {
        return Ok(());
    }
    if root == Path::new("/") {
        for unit in [
            "relay-node-uninstall-finalizer.timer",
            "relay-node-uninstall-finalizer.service",
            "relay-node.service",
        ] {
            // Missing units are a normal clean-host case. A loaded unit must
            // stop successfully, including timers left by interrupted uninstall.
            let loaded = Command::new("systemctl")
                .args(["show", "--property=LoadState", "--value", unit])
                .output()
                .map_err(|e| e.to_string())?;
            if String::from_utf8_lossy(&loaded.stdout).trim() != "not-found" {
                run_checked("systemctl", &["disable", "--now", unit])?;
            }
        }
        stop_fresh_processes()?;
    }
    if phase == "stop" {
        return Ok(());
    }
    uninstall_managed(root)?;
    for path in FRESH_REMOVE_FILES {
        remove_if_exists(&rooted(root, path))?;
    }
    for path in FRESH_REMOVE_DIRS {
        let path = rooted(root, path);
        if path.exists() {
            std::fs::remove_dir_all(&path).map_err(|e| format!("remove Fresh residue: {e}"))?;
        }
    }
    // Only installer-owned UUID directories, never arbitrary /tmp contents.
    let tmp = rooted(root, "/tmp");
    if tmp.is_dir() {
        for entry in std::fs::read_dir(tmp).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let suffix = name
                .strip_prefix("relay-panel-bootstrap-")
                .or_else(|| name.strip_prefix("relay-panel-replacement-"));
            if suffix.is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()) {
                validate_cleanup_path(root, &entry.path())?;
                if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                    std::fs::remove_dir_all(entry.path()).map_err(|e| e.to_string())?;
                }
            }
        }
    }
    if root == Path::new("/") {
        run_checked("systemctl", &["daemon-reload"])?;
    }
    Ok(())
}

fn stop_fresh_processes() -> Result<(), String> {
    let mut targets = Vec::new();
    for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() as i32 {
            continue;
        }
        let exe = std::fs::read_link(entry.path().join("exe")).unwrap_or_default();
        let exe = exe.to_string_lossy();
        let runtime = exe.trim_end_matches(" (deleted)") == "/opt/relay-node/relay-node"
            || exe.trim_end_matches(" (deleted)") == UNINSTALL_FINALIZER_BINARY;
        let cmd = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let installer = cmd.split(|b| *b == 0).any(|arg| {
            std::str::from_utf8(arg)
                .ok()
                .and_then(|s| s.strip_prefix("/tmp/relay-panel-bootstrap-"))
                .and_then(|s| s.strip_suffix("/bootstrap.sh"))
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        });
        if runtime || installer {
            // SSH installer starts in its own setsid group; systemd services
            // are stopped above. Never signal the helper/SSH session group.
            let pgid = unsafe { libc::getpgid(pid) };
            let target = if installer && pgid == pid { -pgid } else { pid };
            targets.push(target);
            unsafe {
                libc::kill(target, libc::SIGTERM);
            }
        }
    }
    for _ in 0..50 {
        targets.retain(|pid| {
            if unsafe { libc::kill(*pid, 0) } != 0 {
                return false;
            }
            if *pid > 0 {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, state)| state.starts_with('Z'))
                {
                    return false;
                }
            }
            true
        });
        if targets.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    for pid in &targets {
        unsafe {
            libc::kill(*pid, libc::SIGKILL);
        }
    }
    for _ in 0..50 {
        targets.retain(|pid| {
            if unsafe { libc::kill(*pid, 0) } != 0 {
                return false;
            }
            if *pid > 0 {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, state)| state.starts_with('Z'))
                {
                    return false;
                }
            }
            true
        });
        if targets.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("old Reality Node processes could not be stopped".into())
}

pub(crate) fn run_helper_from_args(args: &[String]) -> Option<Result<(), String>> {
    if args.len() == 1 {
        let phase = match args[0].as_str() {
            "--fresh-reset-check" => "check",
            "--fresh-reset-stop" => "stop",
            "--fresh-reset-clean" => "clean",
            _ => return None,
        };
        return Some(fresh_reset(Path::new("/"), phase));
    }
    if args.len() == 2
        && matches!(
            args[0].as_str(),
            "--check-existing-install-cleanup" | "--cleanup-retired-install"
        )
    {
        return Some(existing_install_cleanup(
            Path::new("/"),
            &args[1],
            args[0] == "--check-existing-install-cleanup",
        ));
    }
    if args.len() != 2
        || !matches!(
            args[0].as_str(),
            "--lifecycle-uninstall" | "--lifecycle-uninstall-finalize"
        )
    {
        return None;
    }
    let path = PathBuf::from(&args[1]);
    if args[0] == "--lifecycle-uninstall-finalize" {
        let auth = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<UninstallCompletionReceipt>(&bytes)
                    .map_err(|error| error.to_string())
            })
            .and_then(|receipt| receipt.job.auth.load_runtime())
        {
            Ok(auth) => auth,
            Err(error) => return Some(Err(error)),
        };
        return Some(
            match finalizer_tick(
                Path::new("/"),
                &path,
                || uninstall_managed(Path::new("/")),
                |job, success, started, message, pending| {
                    let attempts = if pending { 1 } else { 6 };
                    for attempt in 0..attempts {
                        if report_uninstall_phase(job, success, started, message, pending, &auth)
                            .is_ok()
                        {
                            return Ok(());
                        }
                        if attempt + 1 < attempts {
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                    }
                    Err("Panel uninstall callback failed".into())
                },
                run_checked,
            ) {
                Ok(true) => Ok(()),
                Ok(false) => Err("Panel has not acknowledged uninstall completion".into()),
                Err(error) => Err(error),
            },
        );
    }
    let job = match std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<UninstallJob>(&bytes).ok())
    {
        Some(job) => job,
        None => return Some(Err("invalid uninstall job".into())),
    };
    let receipt_path = uninstall_receipt_path(Path::new("/"), &job.operation_id);
    if !valid_id(&job.operation_id) || !valid_id(&job.node_id) {
        return Some(Err("invalid uninstall job identity".into()));
    }
    for managed in UNINSTALL_REMOVE_FILES
        .iter()
        .chain(UNINSTALL_REMOVE_DIRS)
        .chain(
            [
                "/etc/nginx/nginx.conf",
                "/etc/nginx/relay-panel-stream.conf",
                "/etc/nginx/conf.d/relay-panel-fallback.conf",
                "/var/lib/relay-panel/node-claims",
            ]
            .iter(),
        )
    {
        if let Err(error) = validate_cleanup_path(Path::new("/"), Path::new(managed)) {
            let _ = report_uninstall_once(&job, false, false, &error);
            return Some(Err(error));
        }
    }
    if let Err(error) = inspect_docker_nginx(Path::new("/")) {
        let _ = report_uninstall_once(&job, false, false, &error);
        return Some(Err(error));
    }
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(error) => return Some(Err(format!("locate uninstall finalizer binary: {error}"))),
    };
    if let Err(error) =
        install_uninstall_finalizer(Path::new("/"), &binary, &receipt_path, run_checked)
    {
        let message = format!("install persistent uninstall finalizer failed: {error}");
        let _ = report_uninstall_once(&job, false, false, &message);
        return Some(Err(message));
    }
    if !receipt_path.exists() {
        let receipt = UninstallCompletionReceipt {
            job,
            panel_acknowledged: false,
            cleanup_success: false,
            destructive_started: false,
            message: "uninstall cleanup pending".into(),
        };
        if let Err(error) = write_private_json(&receipt_path, &receipt) {
            return Some(Err(error));
        }
    }
    // The timer is already durable before the receipt exists. Start one eager
    // attempt now; failures are retried by the enabled timer and after reboot.
    let _ = run_checked("systemctl", &["start", UNINSTALL_FINALIZER_SERVICE]);
    let _ = std::fs::remove_file(path);
    Some(Ok(()))
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
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let target = format!("{}.{}.{}", current.major, current.minor, current.patch + 1);
        install_artifact_with_probe(&binary, &bytes, "x86_64", &sha, &target, |_| {
            Ok(format!("relay-node {target}\n").into_bytes())
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

    fn write_openlist_ownership(root: &Path, container_created: bool, data_dir_created: bool) {
        let path = root.join(OPENLIST_OWNERSHIP_PATH.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_private_json(
            &path,
            &OpenListOwnership {
                version: 1,
                container_name: OPENLIST_CONTAINER.into(),
                image: OPENLIST_IMAGE.into(),
                data_path: OPENLIST_DATA_PATH.into(),
                container_created,
                data_dir_created,
            },
        )
        .unwrap();
    }

    #[test]
    fn openlist_cleanup_requires_durable_creation_ownership() {
        let root = test_dir("relay-openlist-ownership");
        std::fs::create_dir_all(&root).unwrap();
        let inspection = format!("{OPENLIST_IMAGE}|{OPENLIST_DATA_PATH}:/opt/openlist/data;");

        assert!(matches!(
            openlist_cleanup_plan(&root, Some(&inspection)),
            OpenListCleanupPlan::Preserve(message) if message.contains("cannot be verified")
        ));

        write_openlist_ownership(&root, false, false);
        assert!(matches!(
            openlist_cleanup_plan(&root, Some(&inspection)),
            OpenListCleanupPlan::Preserve(message) if message.contains("pre-existing and reused")
        ));

        write_openlist_ownership(&root, true, true);
        assert_eq!(
            openlist_cleanup_plan(&root, Some(&inspection)),
            OpenListCleanupPlan::Remove {
                container: true,
                data: true,
            }
        );
        assert!(matches!(
            openlist_cleanup_plan(&root, Some("other-image|other:/opt/openlist/data;")),
            OpenListCleanupPlan::Preserve(message) if message.contains("no longer matches")
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn container_ownership_does_not_imply_data_ownership() {
        let root = test_dir("relay-openlist-split-ownership");
        std::fs::create_dir_all(&root).unwrap();
        write_openlist_ownership(&root, true, false);
        let inspection = format!("{OPENLIST_IMAGE}|{OPENLIST_DATA_PATH}:/opt/openlist/data;");
        assert_eq!(
            openlist_cleanup_plan(&root, Some(&inspection)),
            OpenListCleanupPlan::Remove {
                container: true,
                data: false,
            }
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn completion_receipt_survives_callback_failure_until_ack() {
        let root = test_dir("relay-uninstall-receipt");
        let receipt_path = uninstall_receipt_path(&root, "operation-a");
        let receipt = UninstallCompletionReceipt {
            job: UninstallJob {
                operation_id: "operation-a".into(),
                node_id: "node-a".into(),
                panel_url: "https://panel.example".into(),
                auth: PersistedNodeAuth::LegacyGroupToken {
                    token: "secret".into(),
                },
            },
            panel_acknowledged: false,
            cleanup_success: false,
            destructive_started: false,
            message: "pending".into(),
        };
        write_private_json(&receipt_path, &receipt).unwrap();
        let mut cleanup_calls = 0;
        let retry = completion_attempt(
            &receipt_path,
            || {
                cleanup_calls += 1;
                Ok(UninstallCleanupReport {
                    message: "cleanup complete".into(),
                })
            },
            |_, _, _, _, _| Err("Panel unavailable".into()),
        )
        .unwrap();
        assert!(!retry);
        assert!(receipt_path.exists());
        assert_eq!(cleanup_calls, 1);

        let acknowledged = finalizer_tick(
            &root,
            &receipt_path,
            || panic!("successful cleanup must not repeat"),
            |job, success, destructive_started, message, pending| {
                assert_eq!(receipt_path.exists(), pending);
                assert_eq!(job.operation_id, "operation-a");
                assert!(success);
                assert!(destructive_started);
                assert_eq!(message, "cleanup complete");
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(acknowledged);
        assert!(!receipt_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn acknowledged_uninstall_cleans_only_its_own_credential_state() {
        for replaced in [false, true] {
            let root = test_dir(if replaced {
                "uninstall-new-auth"
            } else {
                "uninstall-old-auth"
            });
            let state_dir = root.join("var/lib/relay-panel/node-claims/claim-b");
            std::fs::create_dir_all(&state_dir).unwrap();
            std::fs::write(state_dir.join("node-credential.secret"), b"test-secret").unwrap();
            let lock_path = root.join("var/lib/relay-panel/node-claims/migration.lock");
            write_atomic_file(&lock_path, b"", 0o600).unwrap();
            let descriptor = root.join("var/lib/relay-panel/node-claims/runtime-auth.json");
            std::fs::write(
                &descriptor,
                serde_json::json!({
                    "node_id":"node-b", "identity_group_id":3,
                    "credential_id":if replaced {"new-credential"} else {"old-credential"},
                    "secret_file":"/var/lib/relay-panel/node-claims/claim-b/node-credential.secret"
                })
                .to_string(),
            )
            .unwrap();
            let receipt_path = uninstall_receipt_path(&root, "operation-credential");
            write_private_json(
                &receipt_path,
                &UninstallCompletionReceipt {
                    job: UninstallJob {
                        operation_id: "operation-credential".into(),
                        node_id: "node-b".into(),
                        panel_url: "https://panel.example".into(),
                        auth: PersistedNodeAuth::PermanentCredential {
                            credential_id: "old-credential".into(),
                            secret_file:
                                "/var/lib/relay-panel/node-claims/claim-b/node-credential.secret"
                                    .into(),
                        },
                    },
                    panel_acknowledged: false,
                    cleanup_success: true,
                    destructive_started: true,
                    message: "complete".into(),
                },
            )
            .unwrap();
            assert!(!finalizer_tick(
                &root,
                &receipt_path,
                || panic!("cleanup must not repeat"),
                |_, _, _, _, _| Err("Panel unavailable".into()),
                |_, _| Ok(())
            )
            .unwrap());
            assert!(state_dir.exists() && descriptor.exists());
            assert!(finalizer_tick(
                &root,
                &receipt_path,
                || panic!("cleanup must not repeat"),
                |_, _, _, _, _| Ok(()),
                |_, _| Err("injected systemctl failure after Panel ACK".into())
            )
            .is_err());
            assert!(state_dir.exists() && descriptor.exists());
            assert!(finalizer_tick(
                &root,
                &receipt_path,
                || panic!("cleanup must not repeat"),
                |_, _, _, _, pending| {
                    assert!(!pending);
                    Ok(())
                },
                |_, _| Ok(())
            )
            .unwrap());
            assert_eq!(lock_path.exists(), replaced);
            assert_eq!(state_dir.exists(), replaced);
            assert_eq!(descriptor.exists(), replaced);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn persistent_finalizer_resumes_existing_receipt_and_self_cleans_after_ack() {
        let root = test_dir("relay-uninstall-finalizer");
        let source_binary = root.join("source-relay-node");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&source_binary, b"finalizer-binary").unwrap();
        let receipt_path = uninstall_receipt_path(&root, "operation-b");
        write_private_json(
            &receipt_path,
            &UninstallCompletionReceipt {
                job: UninstallJob {
                    operation_id: "operation-b".into(),
                    node_id: "node-b".into(),
                    panel_url: "https://panel.example".into(),
                    auth: PersistedNodeAuth::LegacyGroupToken {
                        token: "secret".into(),
                    },
                },
                panel_acknowledged: false,
                cleanup_success: true,
                destructive_started: true,
                message: "cleanup complete".into(),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&receipt_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut install_commands = Vec::new();
        install_uninstall_finalizer(&root, &source_binary, &receipt_path, |program, args| {
            install_commands.push(format!("{program} {}", args.join(" ")));
            Ok(())
        })
        .unwrap();
        for managed in [
            UNINSTALL_FINALIZER_BINARY,
            UNINSTALL_FINALIZER_SERVICE_PATH,
            UNINSTALL_FINALIZER_TIMER_PATH,
        ] {
            assert!(rooted(&root, managed).exists(), "missing {managed}");
        }
        assert!(install_commands
            .iter()
            .any(|command| command.contains("enable --now relay-node-uninstall-finalizer.timer")));
        assert!(!install_commands
            .iter()
            .any(|command| command.contains("start relay-node-uninstall-finalizer.service")));
        assert!(finalizer_timer().contains("OnBootSec=10s"));
        assert!(finalizer_timer().contains("Persistent=true"));
        assert!(finalizer_service(&receipt_path).contains("Restart=on-failure"));
        assert!(finalizer_service(&receipt_path).contains(&receipt_path.display().to_string()));
        assert!(!finalizer_service(&receipt_path).contains("secret"));

        let no_ack = finalizer_tick(
            &root,
            &receipt_path,
            || panic!("completed cleanup must not repeat"),
            |_, _, _, _, _| Err("Panel unavailable".into()),
            |_, _| panic!("no ACK must not clean finalizer"),
        )
        .unwrap();
        assert!(!no_ack);
        assert!(receipt_path.exists());
        assert!(rooted(&root, UNINSTALL_FINALIZER_TIMER_PATH).exists());

        let mut cleanup_commands = Vec::new();
        let acknowledged = finalizer_tick(
            &root,
            &receipt_path,
            || panic!("restarted finalizer must reuse completed receipt"),
            |job, success, destructive_started, _, _| {
                assert_eq!(job.operation_id, "operation-b");
                assert!(success);
                assert!(destructive_started);
                Ok(())
            },
            |program, args| {
                cleanup_commands.push(format!("{program} {}", args.join(" ")));
                Ok(())
            },
        )
        .unwrap();
        assert!(acknowledged);
        assert!(!receipt_path.exists());
        for managed in [
            UNINSTALL_FINALIZER_BINARY,
            UNINSTALL_FINALIZER_SERVICE_PATH,
            UNINSTALL_FINALIZER_TIMER_PATH,
        ] {
            assert!(!rooted(&root, managed).exists(), "left {managed}");
        }
        assert!(cleanup_commands
            .iter()
            .any(|command| command.contains("disable --now relay-node-uninstall-finalizer.timer")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nginx_validation_or_reload_failure_restores_snapshot() {
        for failure in ["test", "reload"] {
            let root = test_dir("relay-uninstall-nginx");
            let config = root.join("nginx.conf");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(&config, "modified\n").unwrap();
            let snapshot = vec![(config.clone(), b"original\n".to_vec())];
            let mut reload_calls = 0;
            let result = validate_and_reload_nginx(&snapshot, |program, args| {
                if failure == "test" && program == "nginx" && args == ["-t"] {
                    return Err("invalid".into());
                }
                if program == "systemctl" && args == ["reload", "nginx"] {
                    reload_calls += 1;
                    if failure == "reload" && reload_calls == 1 {
                        return Err("reload failed".into());
                    }
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(std::fs::read_to_string(&config).unwrap(), "original\n");
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn successful_nginx_reload_keeps_the_cleaned_configuration() {
        let root = test_dir("relay-uninstall-nginx-success");
        let config = root.join("nginx.conf");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&config, "cleaned\n").unwrap();
        let snapshot = vec![(config.clone(), b"original\n".to_vec())];
        let mut commands = Vec::new();
        validate_and_reload_nginx(&snapshot, |program, args| {
            commands.push(format!("{program} {}", args.join(" ")));
            Ok(())
        })
        .unwrap();
        assert_eq!(commands, ["nginx -t", "systemctl reload nginx"]);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "cleaned\n");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn active_nginx_configuration_must_not_retain_reality_managed_listeners() {
        assert!(managed_nginx_runtime_absent(
            "events {}\nhttp { server { listen 443 ssl; } }\n"
        ));
        for managed in [
            "# generated by relay-node; do not edit",
            "# generated by relay-node; TLS camouflage sites",
            "/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
        ] {
            assert!(!managed_nginx_runtime_absent(managed));
        }
    }

    #[test]
    fn finalizer_reload_failure_preserves_executable_receipt_and_restores_retry_units() {
        let root = test_dir("finalizer-reload-failure");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source-node");
        std::fs::write(&source, b"test binary").unwrap();
        let path = uninstall_receipt_path(&root, "retry");
        write_private_json(
            &path,
            &UninstallCompletionReceipt {
                job: UninstallJob {
                    operation_id: "retry".into(),
                    node_id: "node-a".into(),
                    panel_url: "https://panel.example".into(),
                    auth: PersistedNodeAuth::LegacyGroupToken {
                        token: "test-token".into(),
                    },
                },
                panel_acknowledged: true,
                cleanup_success: true,
                destructive_started: true,
                message: "complete".into(),
            },
        )
        .unwrap();
        install_uninstall_finalizer(&root, &source, &path, |_, _| Ok(())).unwrap();
        let mut failed = false;
        assert!(cleanup_uninstall_finalizer(
            &root,
            &path,
            |_, args| {
                if args == ["daemon-reload"] && !failed {
                    failed = true;
                    return Err("injected reload failure".into());
                }
                Ok(())
            },
            || panic!("credentials must survive reload failure")
        )
        .is_err());
        for file in [
            UNINSTALL_FINALIZER_BINARY,
            UNINSTALL_FINALIZER_SERVICE_PATH,
            UNINSTALL_FINALIZER_TIMER_PATH,
        ] {
            assert!(rooted(&root, file).exists());
        }
        assert!(path.exists());
        cleanup_uninstall_finalizer(&root, &path, |_, _| Ok(()), || Ok(())).unwrap();
        assert!(!path.exists() && !rooted(&root, UNINSTALL_FINALIZER_BINARY).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_or_foreign_migration_lock_preserves_credentials_until_retry() {
        let root = test_dir("active-migration-lock");
        let secret = rooted(
            &root,
            "/var/lib/relay-panel/node-claims/claim-a/node-credential.secret",
        );
        write_atomic_file(&secret, b"test-secret", 0o600).unwrap();
        let lock_path = root.join("var/lib/relay-panel/node-claims/migration.lock");
        write_atomic_file(&lock_path, b"foreign state", 0o600).unwrap();
        let job = UninstallJob {
            operation_id: "operation-a".into(),
            node_id: "node-a".into(),
            panel_url: "https://panel.example".into(),
            auth: PersistedNodeAuth::PermanentCredential {
                credential_id: "credential-a".into(),
                secret_file: "/var/lib/relay-panel/node-claims/claim-a/node-credential.secret"
                    .into(),
            },
        };
        assert!(cleanup_uninstalled_credentials(&root, &job).is_err());
        assert!(secret.exists());
        write_atomic_file(&lock_path, b"", 0o600).unwrap();
        let held = std::fs::File::open(&lock_path).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(cleanup_uninstalled_credentials(&root, &job).is_err());
        assert!(secret.exists());
        drop(held);
        cleanup_uninstalled_credentials(&root, &job).unwrap();
        assert!(!secret.exists() && !lock_path.exists());
        cleanup_uninstalled_credentials(&root, &job).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_cleanup_failure_restores_finalizer_retry_units() {
        let root = test_dir("credential-retry-units");
        let receipt = uninstall_receipt_path(&root, "retry");
        write_atomic_file(&receipt, b"receipt", 0o600).unwrap();
        write_atomic_file(&rooted(&root, UNINSTALL_FINALIZER_BINARY), b"binary", 0o700).unwrap();
        assert!(cleanup_uninstall_finalizer(
            &root,
            &receipt,
            |_, _| Ok(()),
            || Err("migration busy".into())
        )
        .is_err());
        assert!(receipt.exists());
        assert!(rooted(&root, UNINSTALL_FINALIZER_SERVICE_PATH).exists());
        assert!(rooted(&root, UNINSTALL_FINALIZER_TIMER_PATH).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn docker_nginx_cleanup_requires_label_and_exact_product_mount() {
        assert!(docker_nginx_owned(
            "nginx-sni|/opt/relay-node/nginx/nginx.conf:/etc/nginx/nginx.conf;"
        ));
        assert!(!docker_nginx_owned(
            "|/opt/relay-node/nginx/nginx.conf:/etc/nginx/nginx.conf;"
        ));
        assert!(!docker_nginx_owned(
            "nginx-sni|/foreign/nginx.conf:/etc/nginx/nginx.conf;"
        ));
        assert_eq!(
            managed_docker_nginx_name("NGINX_SNI_TEST_CMD='docker exec relay-node-nginx nginx -t'")
                .unwrap(),
            Some("relay-node-nginx".into())
        );
        assert!(
            managed_docker_nginx_name("NGINX_SNI_TEST_CMD='docker exec ../foreign nginx -t'")
                .is_err()
        );
        assert!(
            managed_docker_nginx_name("NGINX_SNI_TEST_CMD='docker exec x nginx -t; rm -rf /'")
                .is_err()
        );
    }

    #[test]
    fn uninstall_rejects_foreign_symlink_before_deleting_runtime() {
        let root = test_dir("uninstall-symlink");
        let foreign = test_dir("foreign-node");
        std::fs::create_dir_all(root.join("opt")).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("keep"), "foreign").unwrap();
        std::os::unix::fs::symlink(&foreign, root.join("opt/relay-node")).unwrap();
        assert!(uninstall_managed(&root).unwrap_err().contains("symlink"));
        assert!(foreign.join("keep").exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(foreign).unwrap();
    }

    #[test]
    fn interrupted_stream_root_cleanup_is_repaired_on_retry() {
        let root = test_dir("uninstall-stream-retry");
        std::fs::create_dir_all(root.join("etc/nginx")).unwrap();
        std::fs::write(
            root.join("etc/nginx/nginx.conf"),
            "events {}\ninclude /etc/nginx/relay-panel-stream.conf;\nhttp {}\n",
        )
        .unwrap();
        uninstall_managed(&root).unwrap();
        assert!(!std::fs::read_to_string(root.join("etc/nginx/nginx.conf"))
            .unwrap()
            .contains("relay-panel-stream"));
        uninstall_managed(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acknowledged_partial_failure_keeps_receipt_and_retry_material() {
        let root = test_dir("uninstall-partial-ack");
        let path = uninstall_receipt_path(&root, "partial");
        write_private_json(
            &path,
            &UninstallCompletionReceipt {
                job: UninstallJob {
                    operation_id: "partial".into(),
                    node_id: "node-a".into(),
                    panel_url: "https://panel.example".into(),
                    auth: PersistedNodeAuth::LegacyGroupToken {
                        token: "test-token".into(),
                    },
                },
                panel_acknowledged: false,
                cleanup_success: false,
                destructive_started: true,
                message: "pending".into(),
            },
        )
        .unwrap();
        assert!(!finalizer_tick(
            &root,
            &path,
            || Err("injected partial failure".into()),
            |_, success, _, _, _| {
                assert!(!success);
                Ok(())
            },
            |_, _| panic!("do not remove finalizer after incomplete cleanup")
        )
        .unwrap());
        assert!(path.exists());
        assert!(finalizer_tick(
            &root,
            &path,
            || Ok(UninstallCleanupReport {
                message: "complete".into()
            }),
            |_, success, _, _, _| {
                assert!(success);
                Ok(())
            },
            |_, _| Ok(())
        )
        .unwrap());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(root);
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
            "etc/relay-panel",
            "var/www/fallback",
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
            "etc/nginx/relay-panel-stream.d/user-stream.conf",
            "etc/nginx/relay-panel-stream.conf",
            "etc/nginx/conf.d/relay-panel-fallback.conf",
            "etc/nginx/conf.d/relay-panel-acme.conf",
            "etc/nginx/conf.d/relay-panel-lite-fallback.conf",
            "etc/relay-panel/lite-mode",
            "var/www/fallback/index.html",
            "etc/nginx/conf.d/unknown.conf",
            "var/lib/relay-panel/openlist/data.db",
            "etc/letsencrypt/account",
        ] {
            std::fs::write(root.join(path), b"keep-or-remove").unwrap();
        }
        std::fs::write(
            root.join("etc/nginx/nginx.conf"),
            "events {}\ninclude /etc/nginx/relay-panel-stream.conf;\nhttp {}\n",
        )
        .unwrap();
        std::fs::set_permissions(
            root.join("etc/nginx/nginx.conf"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/relay-panel-stream.d/relay-panel-sni.conf"),
            "# generated by relay-node; do not edit\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/relay-panel-stream.conf"),
            "# RelayPanel managed stream root; do not edit\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/conf.d/relay-panel-fallback.conf"),
            "# generated by relay-node; TLS camouflage sites\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/conf.d/relay-panel-acme.conf"),
            "# generated by relay-node; global HTTP to HTTPS redirect\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/nginx/conf.d/relay-panel-lite-fallback.conf"),
            "# RelayPanel managed Lite fallback\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/relay-panel/lite-mode"), "lite\n").unwrap();
        std::fs::write(
            root.join("var/www/fallback/index.html"),
            "<!-- RelayPanel managed Lite fallback -->\n",
        )
        .unwrap();
        uninstall_managed(&root).unwrap();
        assert!(!root.join("opt/relay-node").exists());
        assert!(!root.join("etc/relay-node").exists());
        assert!(root.join("var/lib/relay-panel/openlist/data.db").exists());
        assert!(root.join("etc/nginx/conf.d/unknown.conf").exists());
        assert!(root
            .join("etc/nginx/relay-panel-stream.d/user-stream.conf")
            .exists());
        assert!(!root
            .join("etc/nginx/relay-panel-stream.d/relay-panel-sni.conf")
            .exists());
        assert!(root.join("etc/letsencrypt/account").exists());
        assert!(!root.join("etc/nginx/relay-panel-stream.conf").exists());
        assert!(!root
            .join("etc/nginx/conf.d/relay-panel-fallback.conf")
            .exists());
        assert!(!root.join("etc/nginx/conf.d/relay-panel-acme.conf").exists());
        assert!(!root
            .join("etc/nginx/conf.d/relay-panel-lite-fallback.conf")
            .exists());
        assert!(!root.join("etc/relay-panel/lite-mode").exists());
        assert!(!root.join("var/www/fallback").exists());
        assert!(!std::fs::read_to_string(root.join("etc/nginx/nginx.conf"))
            .unwrap()
            .contains("relay-panel-stream.conf"));
        assert_eq!(
            std::fs::metadata(root.join("etc/nginx/nginx.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
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
    #[test]
    fn fresh_reinstall_ignores_old_identity_and_clears_all_claim_residue() {
        let root = test_dir("fresh-reinstall-mismatch");
        std::fs::create_dir_all(root.join("opt/relay-node")).unwrap();
        std::fs::write(root.join("opt/relay-node/node-id"), "mismatched-old-id").unwrap();
        for id in [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ] {
            let dir = root.join("var/lib/relay-panel/node-claims").join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("credential-pending.json"),
                b"invalid stale metadata",
            )
            .unwrap();
            std::fs::write(dir.join("node-credential.secret"), b"old credential").unwrap();
        }
        std::fs::write(
            root.join("var/lib/relay-panel/node-claims/runtime-auth.json"),
            b"foreign panel / identity / credential",
        )
        .unwrap();
        std::fs::write(root.join("protected-data"), b"preserve").unwrap();
        fresh_reset(&root, "check").unwrap();
        assert!(root.join("opt/relay-node/node-id").exists());
        fresh_reset(&root, "clean").unwrap();
        assert!(!root.join("opt/relay-node").exists());
        assert!(!root.join("var/lib/relay-panel/node-claims").exists());
        assert_eq!(
            std::fs::read(root.join("protected-data")).unwrap(),
            b"preserve"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fresh_reset_checks_owned_paths_before_mutation_and_supports_clean_retry() {
        use std::os::unix::fs::symlink;
        let root = test_dir("fresh-reset-precheck");
        let dir = root.join("opt/relay-node");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("node-id"), "old-id").unwrap();
        let claims = root.join("var/lib/relay-panel/node-claims");
        std::fs::create_dir_all(claims.parent().unwrap()).unwrap();
        symlink(&dir, &claims).unwrap();
        assert!(fresh_reset(&root, "check").is_err());
        assert!(fresh_reset(&root, "clean").is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("node-id")).unwrap(),
            "old-id"
        );
        std::fs::remove_file(&claims).unwrap();
        std::fs::create_dir_all(root.join("etc/relay-panel")).unwrap();
        std::fs::write(root.join("etc/relay-panel/lite-mode"), "old invalid marker").unwrap();
        fresh_reset(&root, "clean").unwrap();
        assert!(!root.join("etc/relay-panel/lite-mode").exists());
        fresh_reset(&root, "check").unwrap();
        fresh_reset(&root, "clean").unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_cleanup_check_preserves_identity_and_rejects_mismatch() {
        let root = test_dir("existing-cleanup-check");
        let id = "11111111-1111-4111-8111-111111111111";
        std::fs::create_dir_all(root.join("opt/relay-node")).unwrap();
        std::fs::write(root.join("opt/relay-node/node-id"), id).unwrap();
        std::fs::write(root.join("opt/relay-node/relay-node"), b"test-binary").unwrap();
        std::fs::write(root.join("user-data"), b"preserve").unwrap();
        existing_install_cleanup(&root, id, true).unwrap();
        assert_eq!(
            std::fs::read(root.join("opt/relay-node/relay-node")).unwrap(),
            b"test-binary"
        );
        assert!(
            existing_install_cleanup(&root, "22222222-2222-4222-8222-222222222222", false).is_err()
        );
        assert_eq!(std::fs::read(root.join("user-data")).unwrap(), b"preserve");
        existing_install_cleanup(&root, id, false).unwrap();
        assert!(!root.join("opt/relay-node/node-id").exists());
        assert_eq!(std::fs::read(root.join("user-data")).unwrap(), b"preserve");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_cleanup_refuses_symlink_before_any_mutation() {
        let root = test_dir("existing-cleanup-symlink");
        let id = "11111111-1111-4111-8111-111111111111";
        std::fs::create_dir_all(root.join("opt/relay-node")).unwrap();
        std::fs::create_dir_all(root.join("etc/nginx/conf.d")).unwrap();
        std::fs::write(root.join("opt/relay-node/node-id"), id).unwrap();
        std::fs::write(root.join("user-config"), b"preserve").unwrap();
        std::os::unix::fs::symlink(
            root.join("user-config"),
            root.join("etc/nginx/conf.d/relay-panel-fallback.conf"),
        )
        .unwrap();
        assert!(existing_install_cleanup(&root, id, true).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("opt/relay-node/node-id")).unwrap(),
            id
        );
        assert_eq!(
            std::fs::read(root.join("user-config")).unwrap(),
            b"preserve"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn replacement_dry_check_blocks_active_migration_and_finalizer() {
        let root = test_dir("replacement-lock");
        let id = "11111111-1111-4111-8111-111111111111";
        std::fs::create_dir_all(root.join("opt/relay-node")).unwrap();
        std::fs::write(root.join("opt/relay-node/node-id"), id).unwrap();
        let claims = root.join("var/lib/relay-panel/node-claims");
        std::fs::create_dir_all(&claims).unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(claims.join("migration.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(existing_install_cleanup(&root, id, true).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("opt/relay-node/node-id")).unwrap(),
            id
        );
        drop(lock);
        existing_install_cleanup(&root, id, true).unwrap();
        std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        std::fs::write(
            root.join("etc/systemd/system/relay-node-uninstall-finalizer.timer"),
            b"pending",
        )
        .unwrap();
        assert!(existing_install_cleanup(&root, id, false).is_err());
        assert!(root.join("opt/relay-node/node-id").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
