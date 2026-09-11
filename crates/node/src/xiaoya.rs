use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub const XIAOYA_BACKEND: &str = "127.0.0.1:5245";
const XIAOYA_IMAGE: &str = "ghcr.io/pixingzoudaiyuexing/xiaoya-byoa:latest";
const XIAOYA_CONTAINER: &str = "relay-panel-xiaoya-byoa";
const XIAOYA_DATA_PATH: &str = "/var/lib/relay-panel/xiaoya-byoa";
const XIAOYA_CONTAINER_DATA_PATH: &str = "/opt/alist/data";
const XIAOYA_MARKER_PATH: &str = "/var/lib/relay-panel/xiaoya-byoa-ownership.json";
const XIAOYA_LABEL_KEY: &str = "io.reality-panel.managed";
const XIAOYA_LABEL_VALUE: &str = "xiaoya-byoa";
const XIAOYA_CONTAINER_PORT: &str = "5244/tcp";
const XIAOYA_HOST_PORT: &str = "5245";
const HEALTH_URL: &str = "http://127.0.0.1:5245/ping";
const HEALTH_DEADLINE: Duration = Duration::from_secs(85);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const HEALTH_RETRY_DELAY: Duration = Duration::from_secs(2);

const EXPECTED_ENV: &[&str] = &[
    "TZ=Asia/Shanghai",
    "BYOA_XIAOYA_BOOTSTRAP=true",
    "BYOA_XIAOYA_UPDATE=if-newer",
    "BYOA_XIAOYA_STRICT=false",
];

pub struct XiaoyaReady {
    _private: (),
}

#[derive(Clone, Debug)]
struct XiaoyaPaths {
    data: PathBuf,
    marker: PathBuf,
}

impl XiaoyaPaths {
    fn production() -> Self {
        Self {
            data: XIAOYA_DATA_PATH.into(),
            marker: XIAOYA_MARKER_PATH.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OwnershipMarker {
    version: u8,
    container_name: String,
    data_path: String,
    managed_label: String,
    #[serde(default)]
    last_successful_node_version: Option<String>,
}

impl OwnershipMarker {
    fn new() -> Self {
        Self {
            version: 1,
            container_name: XIAOYA_CONTAINER.into(),
            data_path: XIAOYA_DATA_PATH.into(),
            managed_label: format!("{XIAOYA_LABEL_KEY}={XIAOYA_LABEL_VALUE}"),
            last_successful_node_version: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.container_name != XIAOYA_CONTAINER
            || self.data_path != XIAOYA_DATA_PATH
            || self.managed_label != format!("{XIAOYA_LABEL_KEY}={XIAOYA_LABEL_VALUE}")
        {
            return Err("Xiaoya ownership marker does not match the managed resource".into());
        }
        Ok(())
    }

    fn pull_eligible(&self, node_version: &str) -> bool {
        self.last_successful_node_version.as_deref() != Some(node_version)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ContainerInspection {
    #[serde(rename = "Image")]
    image_id: String,
    #[serde(rename = "Config")]
    config: ContainerConfig,
    #[serde(rename = "HostConfig")]
    host_config: HostConfig,
    #[serde(rename = "State")]
    state: ContainerState,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<ContainerMount>,
}

#[derive(Clone, Debug, Deserialize)]
struct ContainerConfig {
    #[serde(rename = "Labels", default)]
    labels: HashMap<String, String>,
    #[serde(rename = "Env", default)]
    env: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct HostConfig {
    #[serde(rename = "RestartPolicy")]
    restart_policy: RestartPolicy,
    #[serde(rename = "PortBindings", default)]
    port_bindings: HashMap<String, Option<Vec<PortBinding>>>,
}

#[derive(Clone, Debug, Deserialize)]
struct RestartPolicy {
    #[serde(rename = "Name", default)]
    name: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct PortBinding {
    #[serde(rename = "HostIp", default)]
    host_ip: String,
    #[serde(rename = "HostPort", default)]
    host_port: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ContainerState {
    #[serde(rename = "Running", default)]
    running: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct ContainerMount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

impl ContainerInspection {
    fn validate_owned_identity(&self) -> Result<(), String> {
        if self.config.labels.get(XIAOYA_LABEL_KEY).map(String::as_str) != Some(XIAOYA_LABEL_VALUE)
        {
            return Err("same-name Xiaoya container lacks the Reality Panel label".into());
        }
        if !EXPECTED_ENV
            .iter()
            .all(|expected| self.config.env.iter().any(|actual| actual == expected))
        {
            return Err("same-name Xiaoya container has unexpected environment".into());
        }
        if self.host_config.restart_policy.name != "unless-stopped" {
            return Err("same-name Xiaoya container has unexpected restart policy".into());
        }
        let expected_binding = PortBinding {
            host_ip: "127.0.0.1".into(),
            host_port: XIAOYA_HOST_PORT.into(),
        };
        let bindings = self
            .host_config
            .port_bindings
            .get(XIAOYA_CONTAINER_PORT)
            .and_then(Option::as_ref)
            .ok_or("same-name Xiaoya container lacks the managed port binding")?;
        if self.host_config.port_bindings.len() != 1 || bindings.as_slice() != [expected_binding] {
            return Err("same-name Xiaoya container has unexpected port bindings".into());
        }
        if self.mounts.len() != 1
            || self.mounts[0].source != XIAOYA_DATA_PATH
            || self.mounts[0].destination != XIAOYA_CONTAINER_DATA_PATH
        {
            return Err("same-name Xiaoya container has unexpected persistent storage".into());
        }
        if self.image_id.trim().is_empty() {
            return Err("same-name Xiaoya container has no image identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerAction {
    Create,
    Start,
    Keep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReconcilePlan {
    action: ContainerAction,
    pull: bool,
}

fn reconcile_plan(
    marker: Option<&OwnershipMarker>,
    container: Option<&ContainerInspection>,
    data_exists: bool,
    port_available: bool,
    node_version: &str,
) -> Result<ReconcilePlan, String> {
    if let Some(marker) = marker {
        marker.validate()?;
    }
    if let Some(container) = container {
        if marker.is_none() {
            return Err("same-name Xiaoya container has no ownership marker".into());
        }
        container.validate_owned_identity()?;
        if !container.state.running && !port_available {
            return Err("127.0.0.1:5245 is occupied by an unknown resource".into());
        }
        return Ok(ReconcilePlan {
            action: if container.state.running {
                ContainerAction::Keep
            } else {
                ContainerAction::Start
            },
            pull: marker.is_some_and(|marker| marker.pull_eligible(node_version)),
        });
    }
    if marker.is_none() && data_exists {
        return Err("Xiaoya data path exists without an ownership marker".into());
    }
    if !port_available {
        return Err("127.0.0.1:5245 is occupied by an unknown resource".into());
    }
    Ok(ReconcilePlan {
        action: ContainerAction::Create,
        // A missing managed container is an install/recovery boundary. Pull
        // explicitly here, then force docker run to stay offline.
        pull: true,
    })
}

#[derive(Debug)]
struct CommandOutput {
    stdout: Vec<u8>,
}

trait DockerClient {
    fn execute(&mut self, args: &[String]) -> Result<CommandOutput, String>;
    fn port_available(&self) -> Result<bool, String>;
}

struct SystemDocker;

impl DockerClient for SystemDocker {
    fn execute(&mut self, args: &[String]) -> Result<CommandOutput, String> {
        let output = Command::new("docker")
            .args(args)
            .output()
            .map_err(|error| format!("execute docker: {error}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr)
                .replace(['\r', '\n'], " ")
                .chars()
                .take(300)
                .collect::<String>();
            return Err(format!("docker {} failed: {detail}", args.join(" ")));
        }
        Ok(CommandOutput {
            stdout: output.stdout,
        })
    }

    fn port_available(&self) -> Result<bool, String> {
        match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5245)) {
            Ok(listener) => {
                drop(listener);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Ok(false),
            Err(error) => Err(format!("inspect 127.0.0.1:5245: {error}")),
        }
    }
}

#[derive(Debug)]
struct PreparedRuntime {
    marker: OwnershipMarker,
    rollback_image: Option<String>,
}

pub async fn reconcile(node_version: &str) -> Result<XiaoyaReady, String> {
    let version = node_version.to_string();
    let prepared = tokio::task::spawn_blocking(move || {
        let mut docker = SystemDocker;
        prepare_runtime(&mut docker, &XiaoyaPaths::production(), &version)
    })
    .await
    .map_err(|error| format!("Xiaoya reconcile worker failed: {error}"))??;

    if let Err(error) = wait_until_healthy().await {
        rollback_update_if_needed(prepared.rollback_image.clone()).await;
        return Err(error);
    }

    let version = node_version.to_string();
    let marker = prepared.marker.clone();
    if let Err(error) = tokio::task::spawn_blocking(move || {
        let mut committed = marker;
        committed.last_successful_node_version = Some(version);
        write_marker(&XiaoyaPaths::production(), &committed)
    })
    .await
    .map_err(|error| format!("Xiaoya marker worker failed: {error}"))?
    {
        rollback_update_if_needed(prepared.rollback_image).await;
        return Err(error);
    }

    Ok(XiaoyaReady { _private: () })
}

pub async fn verify_lite_fallback() -> Result<(), String> {
    wait_until_healthy().await
}

async fn rollback_update_if_needed(image: Option<String>) {
    let Some(image) = image else {
        return;
    };
    match tokio::task::spawn_blocking(move || {
        let mut docker = SystemDocker;
        rollback_image(&mut docker, &XiaoyaPaths::production(), &image)
    })
    .await
    {
        Ok(Ok(())) => tracing::warn!("Xiaoya update failed; restored the prior managed image"),
        Ok(Err(error)) => tracing::error!("Xiaoya update rollback failed: {error}"),
        Err(error) => tracing::error!("Xiaoya update rollback worker failed: {error}"),
    }
}

fn prepare_runtime<D: DockerClient>(
    docker: &mut D,
    paths: &XiaoyaPaths,
    node_version: &str,
) -> Result<PreparedRuntime, String> {
    let marker = read_marker(paths)?;
    let container = inspect_container(docker)?;
    let data_exists = safe_data_path_exists(&paths.data)?;
    let needs_free_port = container.as_ref().is_none_or(|value| !value.state.running);
    let port_available = if needs_free_port {
        docker.port_available()?
    } else {
        true
    };
    let plan = reconcile_plan(
        marker.as_ref(),
        container.as_ref(),
        data_exists,
        port_available,
        node_version,
    )?;

    let latest_image = if plan.pull {
        docker.execute(&strings(&["pull", XIAOYA_IMAGE]))?;
        Some(inspect_image_id(docker)?)
    } else {
        None
    };

    let marker = match marker {
        Some(marker) => marker,
        None => {
            let marker = OwnershipMarker::new();
            write_marker(paths, &marker)?;
            marker
        }
    };
    ensure_data_dir(&paths.data)?;

    let mut rollback = None;
    match plan.action {
        ContainerAction::Create => run_container(docker, paths, XIAOYA_IMAGE)?,
        ContainerAction::Start => {
            if latest_image.as_deref().is_some_and(|latest| {
                Some(latest) != container.as_ref().map(|value| value.image_id.as_str())
            }) {
                let old_image = container.as_ref().unwrap().image_id.clone();
                replace_container(docker, paths, XIAOYA_IMAGE, &old_image)?;
                rollback = Some(old_image);
            } else {
                docker.execute(&strings(&["start", XIAOYA_CONTAINER]))?;
            }
        }
        ContainerAction::Keep => {
            if latest_image.as_deref().is_some_and(|latest| {
                Some(latest) != container.as_ref().map(|value| value.image_id.as_str())
            }) {
                let old_image = container.as_ref().unwrap().image_id.clone();
                replace_container(docker, paths, XIAOYA_IMAGE, &old_image)?;
                rollback = Some(old_image);
            }
        }
    }

    let postcheck = (|| {
        let current = inspect_container(docker)?
            .ok_or("managed Xiaoya container disappeared during reconciliation")?;
        current.validate_owned_identity()?;
        if !current.state.running {
            return Err("managed Xiaoya container is not running".into());
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = postcheck {
        if let Some(old_image) = rollback.as_deref() {
            return match rollback_image(docker, paths, old_image) {
                Ok(()) => Err(format!("{error}; prior managed Xiaoya image was restored")),
                Err(rollback_error) => Err(format!(
                    "{error}; prior managed Xiaoya rollback failed: {rollback_error}"
                )),
            };
        }
        return Err(error);
    }
    Ok(PreparedRuntime {
        marker,
        rollback_image: rollback,
    })
}

fn replace_container<D: DockerClient>(
    docker: &mut D,
    paths: &XiaoyaPaths,
    image: &str,
    rollback: &str,
) -> Result<(), String> {
    docker.execute(&strings(&["rm", "-f", XIAOYA_CONTAINER]))?;
    if let Err(error) = run_container(docker, paths, image) {
        let rollback_result = run_container(docker, paths, rollback);
        return Err(match rollback_result {
            Ok(()) => format!("{error}; prior managed Xiaoya image was restored"),
            Err(rollback_error) => format!("{error}; rollback failed: {rollback_error}"),
        });
    }
    Ok(())
}

fn rollback_image<D: DockerClient>(
    docker: &mut D,
    paths: &XiaoyaPaths,
    image: &str,
) -> Result<(), String> {
    let marker = read_marker(paths)?.ok_or("Xiaoya ownership marker is missing")?;
    marker.validate()?;
    let current = inspect_container(docker)?.ok_or("managed Xiaoya container is missing")?;
    current.validate_owned_identity()?;
    docker.execute(&strings(&["rm", "-f", XIAOYA_CONTAINER]))?;
    run_container(docker, paths, image)
}

fn run_container<D: DockerClient>(
    docker: &mut D,
    paths: &XiaoyaPaths,
    image: &str,
) -> Result<(), String> {
    docker.execute(&docker_run_args(paths, image)).map(|_| ())
}

fn docker_run_args(paths: &XiaoyaPaths, image: &str) -> Vec<String> {
    let mut args = strings(&[
        "run",
        "-d",
        "--name",
        XIAOYA_CONTAINER,
        "--restart",
        "unless-stopped",
        "--pull",
        "never",
        "--label",
        &format!("{XIAOYA_LABEL_KEY}={XIAOYA_LABEL_VALUE}"),
        "-p",
        "127.0.0.1:5245:5244",
    ]);
    for value in EXPECTED_ENV {
        args.push("-e".into());
        args.push((*value).into());
    }
    args.push("-v".into());
    args.push(format!(
        "{}:{XIAOYA_CONTAINER_DATA_PATH}",
        paths.data.display()
    ));
    args.push(image.into());
    args
}

fn inspect_container<D: DockerClient>(
    docker: &mut D,
) -> Result<Option<ContainerInspection>, String> {
    let listed = docker.execute(&strings(&[
        "container",
        "ls",
        "-a",
        "--filter",
        &format!("name=^/{XIAOYA_CONTAINER}$"),
        "--format",
        "{{.Names}}",
    ]))?;
    let names = String::from_utf8(listed.stdout)
        .map_err(|_| "docker returned a non-UTF-8 container list")?;
    let names = names
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(None);
    }
    if names.as_slice() != [XIAOYA_CONTAINER] {
        return Err("Docker returned an ambiguous Xiaoya container identity".into());
    }
    let inspected = docker.execute(&strings(&["container", "inspect", XIAOYA_CONTAINER]))?;
    let mut values: Vec<ContainerInspection> = serde_json::from_slice(&inspected.stdout)
        .map_err(|error| format!("parse Xiaoya Docker inspection: {error}"))?;
    if values.len() != 1 {
        return Err("Docker returned an ambiguous Xiaoya inspection".into());
    }
    Ok(values.pop())
}

fn inspect_image_id<D: DockerClient>(docker: &mut D) -> Result<String, String> {
    let output = docker.execute(&strings(&[
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        XIAOYA_IMAGE,
    ]))?;
    let image = String::from_utf8(output.stdout)
        .map_err(|_| "docker returned a non-UTF-8 image identity")?
        .trim()
        .to_string();
    if image.is_empty() {
        return Err("pulled Xiaoya image has no Docker identity".into());
    }
    Ok(image)
}

async fn wait_until_healthy() -> Result<(), String> {
    let client = reqwest::Client::builder()
        .connect_timeout(HEALTH_REQUEST_TIMEOUT)
        .timeout(HEALTH_REQUEST_TIMEOUT)
        .build()
        .map_err(|error| format!("build Xiaoya health client: {error}"))?;
    let deadline = Instant::now() + HEALTH_DEADLINE;
    loop {
        let last_error = match client.get(HEALTH_URL).send().await {
            Ok(response) => {
                let status = response.status();
                match response.bytes().await {
                    Ok(body) if health_response_is_ready(status.as_u16(), &body) => return Ok(()),
                    Ok(body) => {
                        let body = String::from_utf8_lossy(&body);
                        format!(
                            "Xiaoya /ping returned HTTP {} with body {:?}",
                            status.as_u16(),
                            body.chars().take(80).collect::<String>()
                        )
                    }
                    Err(error) => format!("read Xiaoya /ping response: {error}"),
                }
            }
            Err(error) => format!("request Xiaoya /ping: {error}"),
        };
        if Instant::now() >= deadline {
            return Err(format!("Xiaoya did not become healthy: {last_error}"));
        }
        tokio::time::sleep(HEALTH_RETRY_DELAY).await;
    }
}

fn health_response_is_ready(status: u16, body: &[u8]) -> bool {
    status == 200 && std::str::from_utf8(body).is_ok_and(|body| body.trim() == "pong")
}

fn read_marker(paths: &XiaoyaPaths) -> Result<Option<OwnershipMarker>, String> {
    let metadata = match fs::symlink_metadata(&paths.marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect Xiaoya ownership marker: {error}")),
    };
    if !metadata.file_type().is_file() {
        return Err("Xiaoya ownership marker is not a regular file".into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("Xiaoya ownership marker permissions are too broad".into());
    }
    if unsafe { libc::geteuid() } == 0 && metadata.uid() != 0 {
        return Err("Xiaoya ownership marker is not root-owned".into());
    }
    let marker: OwnershipMarker = serde_json::from_slice(
        &fs::read(&paths.marker).map_err(|error| format!("read Xiaoya marker: {error}"))?,
    )
    .map_err(|error| format!("parse Xiaoya ownership marker: {error}"))?;
    marker.validate()?;
    Ok(Some(marker))
}

fn write_marker(paths: &XiaoyaPaths, marker: &OwnershipMarker) -> Result<(), String> {
    marker.validate()?;
    if let Ok(metadata) = fs::symlink_metadata(&paths.marker) {
        if !metadata.file_type().is_file() {
            return Err("refusing to replace non-file Xiaoya ownership marker".into());
        }
    }
    let parent = paths.marker.parent().ok_or("Xiaoya marker has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("create Xiaoya marker parent: {error}"))?;
    let temp = paths.marker.with_extension("json.tmp");
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("clear Xiaoya marker staging file: {error}")),
    }
    let contents = serde_json::to_vec_pretty(marker)
        .map_err(|error| format!("serialize Xiaoya ownership marker: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| format!("create Xiaoya marker staging file: {error}"))?;
    if let Err(error) = file.write_all(&contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(format!("write Xiaoya ownership marker: {error}"));
    }
    drop(file);
    fs::rename(&temp, &paths.marker)
        .and_then(|_| File::open(parent)?.sync_all())
        .map_err(|error| format!("commit Xiaoya ownership marker: {error}"))
}

fn safe_data_path_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err("Xiaoya data path is not a regular directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect Xiaoya data path: {error}")),
    }
}

fn ensure_data_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create Xiaoya data path: {error}"))?;
    if !fs::symlink_metadata(path)
        .map_err(|error| format!("inspect Xiaoya data path: {error}"))?
        .file_type()
        .is_dir()
    {
        return Err("Xiaoya data path is not a regular directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o750))
        .map_err(|error| format!("set Xiaoya data path permissions: {error}"))
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[cfg(test)]
pub(crate) fn ready_for_test() -> XiaoyaReady {
    XiaoyaReady { _private: () }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;

    struct FakeDocker {
        outputs: VecDeque<Result<CommandOutput, String>>,
        commands: Vec<Vec<String>>,
        port_available: bool,
        port_checks: Cell<usize>,
    }

    impl FakeDocker {
        fn new(outputs: Vec<Result<CommandOutput, String>>, port_available: bool) -> Self {
            Self {
                outputs: outputs.into(),
                commands: Vec::new(),
                port_available,
                port_checks: Cell::new(0),
            }
        }
    }

    impl DockerClient for FakeDocker {
        fn execute(&mut self, args: &[String]) -> Result<CommandOutput, String> {
            self.commands.push(args.to_vec());
            self.outputs
                .pop_front()
                .unwrap_or_else(|| Err("unexpected Docker command".into()))
        }

        fn port_available(&self) -> Result<bool, String> {
            self.port_checks.set(self.port_checks.get() + 1);
            Ok(self.port_available)
        }
    }

    fn output(stdout: impl Into<Vec<u8>>) -> Result<CommandOutput, String> {
        Ok(CommandOutput {
            stdout: stdout.into(),
        })
    }

    fn test_paths(label: &str) -> (PathBuf, XiaoyaPaths) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "relay-panel-xiaoya-{label}-{}-{stamp}",
            std::process::id()
        ));
        let paths = XiaoyaPaths {
            data: root.join("data"),
            marker: root.join("ownership.json"),
        };
        (root, paths)
    }

    fn inspection(running: bool, image_id: &str) -> ContainerInspection {
        ContainerInspection {
            image_id: image_id.into(),
            config: ContainerConfig {
                labels: HashMap::from([(XIAOYA_LABEL_KEY.into(), XIAOYA_LABEL_VALUE.into())]),
                env: EXPECTED_ENV.iter().map(|value| (*value).into()).collect(),
            },
            host_config: HostConfig {
                restart_policy: RestartPolicy {
                    name: "unless-stopped".into(),
                },
                port_bindings: HashMap::from([(
                    XIAOYA_CONTAINER_PORT.into(),
                    Some(vec![PortBinding {
                        host_ip: "127.0.0.1".into(),
                        host_port: XIAOYA_HOST_PORT.into(),
                    }]),
                )]),
            },
            state: ContainerState { running },
            mounts: vec![ContainerMount {
                source: XIAOYA_DATA_PATH.into(),
                destination: XIAOYA_CONTAINER_DATA_PATH.into(),
            }],
        }
    }

    fn inspection_json(running: bool, image_id: &str, managed: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "Image": image_id,
            "Config": {
                "Labels": if managed {
                    serde_json::json!({ (XIAOYA_LABEL_KEY): XIAOYA_LABEL_VALUE })
                } else {
                    serde_json::json!({})
                },
                "Env": EXPECTED_ENV
            },
            "HostConfig": {
                "RestartPolicy": { "Name": "unless-stopped" },
                "PortBindings": {
                    "5244/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "5245" }]
                }
            },
            "State": { "Running": running },
            "Mounts": [{
                "Source": XIAOYA_DATA_PATH,
                "Destination": XIAOYA_CONTAINER_DATA_PATH
            }]
        }]))
        .unwrap()
    }

    #[test]
    fn runtime_contract_uses_fixed_loopback_port_env_and_data() {
        assert_eq!(XIAOYA_BACKEND, "127.0.0.1:5245");
        let args = docker_run_args(&XiaoyaPaths::production(), XIAOYA_IMAGE);
        for expected in [
            "127.0.0.1:5245:5244",
            "TZ=Asia/Shanghai",
            "BYOA_XIAOYA_BOOTSTRAP=true",
            "BYOA_XIAOYA_UPDATE=if-newer",
            "BYOA_XIAOYA_STRICT=false",
            "/var/lib/relay-panel/xiaoya-byoa:/opt/alist/data",
            "io.reality-panel.managed=xiaoya-byoa",
            "unless-stopped",
            "never",
        ] {
            assert!(
                args.iter().any(|value| value == expected),
                "missing {expected}"
            );
        }
        assert!(!args.iter().any(|value| value.contains("/openlist")));
        assert!(!args.iter().any(|value| value == "127.0.0.1:5244:5244"));
    }

    #[test]
    fn owned_container_identity_does_not_depend_on_image_digest() {
        let marker = OwnershipMarker::new();
        let old_image = inspection(true, "sha256:old-managed-image");
        let plan = reconcile_plan(Some(&marker), Some(&old_image), true, true, "1.1.18")
            .expect("old image remains owned");
        assert_eq!(plan.action, ContainerAction::Keep);
        assert!(plan.pull);
    }

    #[test]
    fn unknown_same_name_container_fails_closed() {
        let error = reconcile_plan(
            None,
            Some(&inspection(true, "sha256:any")),
            false,
            true,
            "1",
        )
        .unwrap_err();
        assert!(error.contains("no ownership marker"));

        let marker = OwnershipMarker::new();
        let mut unknown = inspection(true, "sha256:any");
        unknown.config.labels.clear();
        assert!(reconcile_plan(Some(&marker), Some(&unknown), true, true, "1").is_err());

        let mut unknown = inspection(true, "sha256:any");
        unknown.mounts.push(ContainerMount {
            source: "/unexpected".into(),
            destination: "/unexpected".into(),
        });
        assert!(reconcile_plan(Some(&marker), Some(&unknown), true, true, "1").is_err());

        let mut unknown = inspection(true, "sha256:any");
        unknown
            .host_config
            .port_bindings
            .insert("5245/tcp".into(), None);
        assert!(reconcile_plan(Some(&marker), Some(&unknown), true, true, "1").is_err());
    }

    #[test]
    fn unknown_port_occupation_fails_closed() {
        let error = reconcile_plan(None, None, false, false, "1").unwrap_err();
        assert!(error.contains("occupied by an unknown resource"));
    }

    #[test]
    fn actual_reconcile_does_not_mutate_an_unknown_same_name_container() {
        let (root, paths) = test_paths("unknown-container");
        fs::create_dir_all(&paths.data).unwrap();
        write_marker(&paths, &OwnershipMarker::new()).unwrap();
        let mut docker = FakeDocker::new(
            vec![
                output(format!("{XIAOYA_CONTAINER}\n").into_bytes()),
                output(inspection_json(true, "sha256:unknown", false)),
            ],
            true,
        );

        assert!(prepare_runtime(&mut docker, &paths, "1.1.18").is_err());
        assert_eq!(docker.commands.len(), 2);
        assert!(docker.commands.iter().all(|command| {
            !matches!(
                command.first().map(String::as_str),
                Some("pull" | "start" | "rm" | "run")
            )
        }));
        assert_eq!(docker.port_checks.get(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_reconcile_does_not_mutate_an_unknown_port_owner() {
        let (root, paths) = test_paths("unknown-port");
        let mut docker = FakeDocker::new(vec![output(Vec::new())], false);

        assert!(prepare_runtime(&mut docker, &paths, "1.1.18").is_err());
        assert_eq!(docker.commands.len(), 1);
        assert!(docker.commands[0].starts_with(&strings(&["container", "ls"])));
        assert_eq!(docker.port_checks.get(), 1);
        assert!(!paths.marker.exists());
        assert!(!paths.data.exists());
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn failed_updated_container_postcheck_restores_the_prior_managed_image() {
        let (root, paths) = test_paths("update-postcheck-rollback");
        fs::create_dir_all(&paths.data).unwrap();
        let mut marker = OwnershipMarker::new();
        marker.last_successful_node_version = Some("1.1.17".into());
        write_marker(&paths, &marker).unwrap();
        let present = output(format!("{XIAOYA_CONTAINER}\n").into_bytes());
        let empty = || output(Vec::new());
        let mut docker = FakeDocker::new(
            vec![
                present,
                output(inspection_json(true, "sha256:old", true)),
                empty(),
                output(b"sha256:new\n".to_vec()),
                empty(),
                empty(),
                output(format!("{XIAOYA_CONTAINER}\n").into_bytes()),
                output(inspection_json(false, "sha256:new", true)),
                output(format!("{XIAOYA_CONTAINER}\n").into_bytes()),
                output(inspection_json(false, "sha256:new", true)),
                empty(),
                empty(),
            ],
            true,
        );

        let error = prepare_runtime(&mut docker, &paths, "1.1.18").unwrap_err();
        assert!(error.contains("prior managed Xiaoya image was restored"));
        let runs = docker
            .commands
            .iter()
            .filter(|command| command.first().is_some_and(|value| value == "run"))
            .collect::<Vec<_>>();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].last().map(String::as_str), Some(XIAOYA_IMAGE));
        assert_eq!(runs[1].last().map(String::as_str), Some("sha256:old"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_same_version_does_not_pull_but_new_version_does() {
        let mut marker = OwnershipMarker::new();
        marker.last_successful_node_version = Some("1.1.18".into());
        let current = inspection(true, "sha256:managed");
        assert!(
            !reconcile_plan(Some(&marker), Some(&current), true, true, "1.1.18")
                .unwrap()
                .pull
        );
        assert!(
            reconcile_plan(Some(&marker), Some(&current), true, true, "1.1.19")
                .unwrap()
                .pull
        );
        assert!(
            reconcile_plan(Some(&marker), None, true, true, "1.1.18")
                .unwrap()
                .pull
        );
    }

    #[test]
    fn health_requires_http_200_and_trimmed_pong() {
        assert!(health_response_is_ready(200, b"pong\n"));
        assert!(!health_response_is_ready(200, b"ok"));
        assert!(!health_response_is_ready(503, b"pong"));
    }
}
