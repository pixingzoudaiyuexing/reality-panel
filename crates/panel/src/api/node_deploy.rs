//! Stage 1: administrator-initiated SSH bootstrap for a new relay node.
//!
//! Tasks intentionally live in memory. They contain progress and redacted
//! diagnostics only; the SSH password and node token exist solely in the
//! spawned worker's stack and are never serialised or persisted.

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::{GroupRepository, ResourceScope};
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const ONLINE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_LOGS: usize = 100;
const INSTALL_SCRIPT: &str = include_str!("../../../../scripts/relay-node-bootstrap.sh");

#[derive(Deserialize)]
pub struct TestSshRequest {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct StartDeploymentRequest {
    pub group_id: i64,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub username: String,
    pub password: String,
    pub confirmed_fingerprint: String,
}

#[derive(Clone, Serialize)]
pub struct SshProbe {
    pub fingerprint: String,
    pub os: String,
    pub architecture: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentStage {
    Pending,
    Connecting,
    Preflight,
    Installing,
    Configuring,
    Verifying,
    Success,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct DeploymentLog {
    pub stage: DeploymentStage,
    pub message: String,
    pub at: String,
}

#[derive(Clone, Serialize)]
pub struct DeploymentStatus {
    pub id: String,
    pub group_id: i64,
    pub host: String,
    pub stage: DeploymentStage,
    pub status: String,
    pub message: String,
    pub node_id: Option<String>,
    pub updated_at: String,
}

struct Task {
    status: DeploymentStatus,
    logs: Vec<DeploymentLog>,
}

#[derive(Clone)]
pub struct DeploymentRegistry {
    tasks: Arc<Mutex<HashMap<String, Task>>>,
    runner: Arc<dyn DeploymentRunner>,
    total_timeout: Duration,
    online_timeout: Duration,
}

impl Default for DeploymentRegistry {
    fn default() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            runner: Arc::new(SystemSshRunner),
            total_timeout: TOTAL_TIMEOUT,
            online_timeout: ONLINE_TIMEOUT,
        }
    }
}

impl DeploymentRegistry {
    async fn insert(&self, group_id: i64, host: String) -> DeploymentStatus {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now();
        let status = DeploymentStatus {
            id: id.clone(),
            group_id,
            host,
            stage: DeploymentStage::Pending,
            status: "PENDING".into(),
            message: "deployment task queued".into(),
            node_id: None,
            updated_at: now.clone(),
        };
        let log = DeploymentLog {
            stage: DeploymentStage::Pending,
            message: status.message.clone(),
            at: now,
        };
        self.tasks.lock().await.insert(
            id,
            Task {
                status: status.clone(),
                logs: vec![log],
            },
        );
        status
    }

    async fn status(&self, id: &str) -> Option<DeploymentStatus> {
        self.tasks
            .lock()
            .await
            .get(id)
            .map(|task| task.status.clone())
    }

    async fn logs(&self, id: &str) -> Option<Vec<DeploymentLog>> {
        self.tasks
            .lock()
            .await
            .get(id)
            .map(|task| task.logs.clone())
    }

    async fn update(
        &self,
        id: &str,
        stage: DeploymentStage,
        status: &str,
        message: impl Into<String>,
        secrets: &Secrets,
    ) {
        let message = redact(&message.into(), secrets);
        let now = now();
        if let Some(task) = self.tasks.lock().await.get_mut(id) {
            task.status.stage = stage;
            task.status.status = status.into();
            task.status.message = message.clone();
            task.status.updated_at = now.clone();
            task.logs.push(DeploymentLog {
                stage,
                message,
                at: now,
            });
            if task.logs.len() > MAX_LOGS {
                task.logs.remove(0);
            }
        }
    }

    async fn set_node_id(&self, id: &str, node_id: String) {
        if let Some(task) = self.tasks.lock().await.get_mut(id) {
            task.status.node_id = Some(node_id);
        }
    }
}

struct SshInput {
    host: String,
    port: u16,
    username: String,
    password: String,
}

struct Secrets {
    password: String,
    node_token: String,
}

struct NodeArtifact {
    architecture: String,
    bytes: Vec<u8>,
    sha256: String,
}

struct Preflight {
    os: String,
    architecture: String,
    root: bool,
    has_bash: bool,
    has_systemd: bool,
    free_kib: u64,
}

#[async_trait]
trait DeploymentRunner: Send + Sync {
    async fn probe(&self, ssh: &SshInput) -> Result<SshProbe, DeployError>;
    async fn preflight(&self, ssh: &SshInput, fingerprint: &str) -> Result<Preflight, DeployError>;
    async fn artifact(&self, architecture: &str) -> Result<NodeArtifact, DeployError>;
    async fn install(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
        artifact: &NodeArtifact,
        panel_url: &str,
        token: &str,
    ) -> Result<(), DeployError>;
    async fn verify(&self, ssh: &SshInput, fingerprint: &str) -> Result<String, DeployError>;
}

#[derive(Debug)]
struct DeployError {
    category: &'static str,
    message: String,
}

impl DeployError {
    fn new(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

struct SystemSshRunner;

#[async_trait]
impl DeploymentRunner for SystemSshRunner {
    async fn probe(&self, ssh: &SshInput) -> Result<SshProbe, DeployError> {
        let input = ssh.clone_without_secret_debug();
        tokio::task::spawn_blocking(move || {
            let mut session = connect(&input, None)?;
            let fingerprint = host_fingerprint(&session)?;
            authenticate(&mut session, &input)?;
            let output = exec(&mut session, "set -eu; . /etc/os-release; printf '%s|%s\\n' \"${PRETTY_NAME:-Linux}\" \"$(uname -m)\"")?;
            let (os, architecture) = output.trim().rsplit_once('|').ok_or_else(|| DeployError::new("SSH_FAILED", "remote host did not return OS facts"))?;
            Ok(SshProbe { fingerprint, os: os.into(), architecture: architecture.into() })
        }).await.map_err(|_| DeployError::new("SSH_FAILED", "SSH probe worker terminated"))?
    }

    async fn preflight(&self, ssh: &SshInput, fingerprint: &str) -> Result<Preflight, DeployError> {
        let input = ssh.clone_without_secret_debug();
        let fingerprint = fingerprint.to_string();
        tokio::task::spawn_blocking(move || {
            let mut session = connect(&input, Some(&fingerprint))?;
            authenticate(&mut session, &input)?;
            let output = exec(&mut session, "set -eu; . /etc/os-release; printf 'os=%s\\narch=%s\\nuid=%s\\nbash=%s\\nsystemd=%s\\nfree_kib=%s\\n' \"${ID:-}\" \"$(uname -m)\" \"$(id -u)\" \"$(command -v bash >/dev/null && echo yes || echo no)\" \"$(command -v systemctl >/dev/null && echo yes || echo no)\" \"$(df -Pk / | awk 'NR == 2 {print $4}')\"")?;
            parse_preflight(&output)
        }).await.map_err(|_| DeployError::new("PREFLIGHT_FAILED", "preflight worker terminated"))?
    }

    async fn artifact(&self, architecture: &str) -> Result<NodeArtifact, DeployError> {
        let architecture = architecture.to_string();
        tokio::task::spawn_blocking(move || load_artifact(&architecture))
            .await
            .map_err(|_| DeployError::new("ARTIFACT_FAILED", "artifact worker terminated"))?
    }

    async fn install(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
        artifact: &NodeArtifact,
        panel_url: &str,
        token: &str,
    ) -> Result<(), DeployError> {
        let input = ssh.clone_without_secret_debug();
        let fingerprint = fingerprint.to_string();
        let task_id = task_id.to_string();
        let artifact = NodeArtifact {
            architecture: artifact.architecture.clone(),
            bytes: artifact.bytes.clone(),
            sha256: artifact.sha256.clone(),
        };
        let panel_url = panel_url.to_string();
        let token = token.to_string();
        tokio::task::spawn_blocking(move || {
            let mut session = connect(&input, Some(&fingerprint))?;
            authenticate(&mut session, &input)?;
            let remote_dir = format!("/tmp/relay-panel-bootstrap-{task_id}");
            exec(
                &mut session,
                &format!(
                    "mkdir -p -- {} && chmod 700 -- {}",
                    shell_quote(&remote_dir),
                    shell_quote(&remote_dir)
                ),
            )?;
            let script_path = format!("{remote_dir}/bootstrap.sh");
            let artifact_path = format!("{remote_dir}/relay-node-linux-{}", artifact.architecture);
            let config_path = format!("{remote_dir}/config.env");
            let config = bootstrap_config(&panel_url, &token, &artifact);
            let result = (|| {
                upload(&mut session, &script_path, INSTALL_SCRIPT.as_bytes(), 0o700)?;
                upload(&mut session, &artifact_path, &artifact.bytes, 0o700)?;
                upload(&mut session, &config_path, config.as_bytes(), 0o600)?;
                exec(
                    &mut session,
                    &format!(
                        "bash {} {} {}",
                        shell_quote(&script_path),
                        shell_quote(&config_path),
                        shell_quote(&artifact_path)
                    ),
                )
                .map(|_| ())
            })();
            let _ = exec(
                &mut session,
                &format!("rm -rf -- {}", shell_quote(&remote_dir)),
            );
            result
        })
        .await
        .map_err(|_| DeployError::new("INSTALL_FAILED", "installer worker terminated"))?
    }

    async fn verify(&self, ssh: &SshInput, fingerprint: &str) -> Result<String, DeployError> {
        let input = ssh.clone_without_secret_debug();
        let fingerprint = fingerprint.to_string();
        tokio::task::spawn_blocking(move || {
            let mut session = connect(&input, Some(&fingerprint))?;
            authenticate(&mut session, &input)?;
            verify_command(
                &mut session,
                "RELAY_NODE_FAILED",
                "test -x /opt/relay-node/relay-node; /opt/relay-node/relay-node --version >/dev/null; systemctl is-enabled --quiet relay-node; systemctl is-active --quiet relay-node",
            )?;
            verify_command(&mut session, "DOCKER_FAILED", "systemctl is-active --quiet docker")?;
            verify_command(
                &mut session,
                "OPENLIST_FAILED",
                "docker inspect -f '{{.State.Running}}' relay-panel-openlist | grep -Fx true >/dev/null; docker port relay-panel-openlist 5244 | grep -Fx '127.0.0.1:5244' >/dev/null; curl -fsS --max-time 10 http://127.0.0.1:5244/ >/dev/null",
            )?;
            verify_command(&mut session, "NGINX_FAILED", "nginx -t")?;
            verify_command(
                &mut session,
                "FALLBACK_FAILED",
                "ss -H -ltn | grep -F '127.0.0.1:8443' >/dev/null; curl -kfsS --max-time 10 https://127.0.0.1:8443/ >/dev/null",
            )?;
            let output = exec(&mut session, "cat /opt/relay-node/node-id")
                .map_err(|_| DeployError::new("RELAY_NODE_FAILED", "could not read node-id"))?;
            let node_id = output.trim();
            if node_id.is_empty() { Err(DeployError::new("VERIFY_FAILED", "node-id is empty")) } else { Ok(node_id.to_string()) }
        }).await.map_err(|_| DeployError::new("VERIFY_FAILED", "verification worker terminated"))?
    }
}

impl SshInput {
    fn clone_without_secret_debug(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

pub async fn test_connection(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<TestSshRequest>,
) -> Json<ApiResponse<SshProbe>> {
    let ssh = match validate_ssh(req.host, req.port, req.username, req.password) {
        Ok(value) => value,
        Err(message) => return error(400, message),
    };
    match state.deployments.runner.probe(&ssh).await {
        Ok(probe) => Json(ApiResponse::success(probe)),
        Err(err) => error(
            400,
            public_error(
                &err,
                &Secrets {
                    password: ssh.password,
                    node_token: String::new(),
                },
            ),
        ),
    }
}

pub async fn start_deployment(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<StartDeploymentRequest>,
) -> Json<ApiResponse<DeploymentStatus>> {
    let ssh = match validate_ssh(req.host, req.port, req.username, req.password) {
        Ok(value) => value,
        Err(message) => return error(400, message),
    };
    let fingerprint = match validate_fingerprint(&req.confirmed_fingerprint) {
        Ok(value) => value,
        Err(message) => return error(400, message),
    };
    let group =
        match GroupRepository::find_by_id(state.db.as_ref(), req.group_id, &ResourceScope::All)
            .await
        {
            Ok(Some(group)) if group.group_type == "in" => group,
            Ok(Some(_)) => return error(400, "selected device group must be inbound"),
            Ok(None) => return error(404, "device group not found"),
            Err(err) => {
                tracing::error!("node deployment group lookup failed: {err}");
                return error(500, "database error");
            }
        };
    let panel_url = state.config.public_panel_url.trim().to_string();
    if panel_url.is_empty() {
        return error(
            409,
            "PUBLIC_PANEL_URL must be configured before node bootstrap",
        );
    }
    let status = state.deployments.insert(group.id, ssh.host.clone()).await;
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "node_deploy_start",
        "node",
        &status.id,
        &format!("host={} group_id={}", status.host, group.id),
    )
    .await;
    let task_state = state.clone();
    let task_id = status.id.clone();
    tokio::spawn(async move {
        run_task(
            task_state,
            task_id,
            ssh,
            fingerprint,
            group.token,
            panel_url,
            admin.user_id,
        )
        .await;
    });
    Json(ApiResponse::success(status))
}

pub async fn deployment_status(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<DeploymentStatus>> {
    match state.deployments.status(&id).await {
        Some(status) => Json(ApiResponse::success(status)),
        None => error(404, "deployment task not found"),
    }
}

pub async fn deployment_logs(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<Vec<DeploymentLog>>> {
    match state.deployments.logs(&id).await {
        Some(logs) => Json(ApiResponse::success(logs)),
        None => error(404, "deployment task not found"),
    }
}

async fn run_task(
    state: AppState,
    id: String,
    ssh: SshInput,
    fingerprint: String,
    token: String,
    panel_url: String,
    actor_id: i64,
) {
    let secrets = Secrets {
        password: ssh.password.clone(),
        node_token: token.clone(),
    };
    let host = ssh.host.clone();
    let group_id = state
        .deployments
        .status(&id)
        .await
        .map(|task| task.group_id)
        .unwrap_or_default();
    let work = async {
        state
            .deployments
            .update(
                &id,
                DeploymentStage::Connecting,
                "RUNNING",
                "validating confirmed SSH host key",
                &secrets,
            )
            .await;
        // Every real runner operation reconnects and verifies this fingerprint before auth.
        let preflight = state
            .deployments
            .runner
            .preflight(&ssh, &fingerprint)
            .await?;
        validate_preflight(&preflight)?;
        state
            .deployments
            .update(
                &id,
                DeploymentStage::Preflight,
                "RUNNING",
                "preflight checks passed",
                &secrets,
            )
            .await;
        let artifact = state
            .deployments
            .runner
            .artifact(&preflight.architecture)
            .await?;
        state
            .deployments
            .update(
                &id,
                DeploymentStage::Installing,
                "RUNNING",
                "uploading verified relay-node artifact",
                &secrets,
            )
            .await;
        state
            .deployments
            .runner
            .install(&id, &ssh, &fingerprint, &artifact, &panel_url, &token)
            .await?;
        state
            .deployments
            .update(
                &id,
                DeploymentStage::Configuring,
                "RUNNING",
                "relay-node, Docker, Nginx Stream, OpenList, fallback, and Certbot base configured",
                &secrets,
            )
            .await;
        state
            .deployments
            .update(
                &id,
                DeploymentStage::Verifying,
                "RUNNING",
                "checking remote services and Panel enrollment",
                &secrets,
            )
            .await;
        let node_id = state.deployments.runner.verify(&ssh, &fingerprint).await?;
        state.deployments.set_node_id(&id, node_id.clone()).await;
        wait_for_node(
            &state.node_connections,
            group_id,
            &node_id,
            state.deployments.online_timeout,
        )
        .await?;
        Ok::<(), DeployError>(())
    };
    let result = tokio::time::timeout(state.deployments.total_timeout, work).await;
    match result {
        Ok(Ok(())) => {
            state
                .deployments
                .update(
                    &id,
                    DeploymentStage::Success,
                    "SUCCESS",
                    "node bootstrap completed and node is online",
                    &secrets,
                )
                .await;
            crate::service::audit::record(
                &state,
                Some(actor_id),
                "node_deploy_success",
                "node",
                &id,
                &format!("host={host} group_id={group_id}"),
            )
            .await;
        }
        Ok(Err(err)) => {
            state
                .deployments
                .update(
                    &id,
                    DeploymentStage::Failed,
                    "FAILED",
                    public_error(&err, &secrets),
                    &secrets,
                )
                .await;
            crate::service::audit::record(
                &state,
                Some(actor_id),
                "node_deploy_failed",
                "node",
                &id,
                &format!("host={host} group_id={group_id} category={}", err.category),
            )
            .await;
        }
        Err(_) => {
            state
                .deployments
                .update(
                    &id,
                    DeploymentStage::Failed,
                    "FAILED",
                    "TOTAL_TIMEOUT: deployment exceeded the total timeout",
                    &secrets,
                )
                .await;
            crate::service::audit::record(
                &state,
                Some(actor_id),
                "node_deploy_failed",
                "node",
                &id,
                &format!("host={host} group_id={group_id} category=TOTAL_TIMEOUT"),
            )
            .await;
        }
    }
}

async fn wait_for_node(
    conns: &crate::api::ws::NodeConnections,
    group_id: i64,
    node_id: &str,
    timeout: Duration,
) -> Result<(), DeployError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if conns.online_node_ids(group_id).await.contains(node_id) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(DeployError::new(
                "NODE_ONLINE_TIMEOUT",
                "node did not appear online before the deployment timeout",
            ));
        }
        tokio::time::sleep(remaining.min(Duration::from_secs(1))).await;
    }
}

fn validate_ssh(
    host: String,
    port: u16,
    username: String,
    password: String,
) -> Result<SshInput, String> {
    let host = host.trim().to_string();
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return Err("host must be an IP address or hostname".into());
    }
    if port == 0 {
        return Err("SSH port must be between 1 and 65535".into());
    }
    if username.is_empty() || username.len() > 64 || username.chars().any(char::is_whitespace) {
        return Err("SSH user is invalid".into());
    }
    if password.is_empty() || password.len() > 512 || password.chars().any(char::is_control) {
        return Err("SSH password is invalid".into());
    }
    Ok(SshInput {
        host,
        port,
        username,
        password,
    })
}

fn validate_fingerprint(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.starts_with("SHA256:")
        && value.len() > 7
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        Ok(value.into())
    } else {
        Err("confirmed SSH fingerprint is invalid".into())
    }
}

fn parse_preflight(output: &str) -> Result<Preflight, DeployError> {
    let values: HashMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let architecture = map_arch(values.get("arch").copied().unwrap_or_default())
        .ok_or_else(|| DeployError::new("PREFLIGHT_FAILED", "unsupported CPU architecture"))?;
    let free_kib = values
        .get("free_kib")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Ok(Preflight {
        os: values.get("os").copied().unwrap_or_default().to_string(),
        architecture: architecture.into(),
        root: values.get("uid") == Some(&"0"),
        has_bash: values.get("bash") == Some(&"yes"),
        has_systemd: values.get("systemd") == Some(&"yes"),
        free_kib,
    })
}

fn validate_preflight(facts: &Preflight) -> Result<(), DeployError> {
    if facts.os != "debian" && facts.os != "ubuntu" {
        return Err(DeployError::new(
            "PREFLIGHT_FAILED",
            "unsupported Linux distribution",
        ));
    }
    if !facts.root {
        return Err(DeployError::new(
            "PREFLIGHT_FAILED",
            "remote user lacks required root privileges",
        ));
    }
    if !facts.has_bash || !facts.has_systemd {
        return Err(DeployError::new(
            "PREFLIGHT_FAILED",
            "remote host requires bash and systemd",
        ));
    }
    if facts.free_kib < 524_288 {
        return Err(DeployError::new(
            "PREFLIGHT_FAILED",
            "remote host has insufficient free disk space",
        ));
    }
    Ok(())
}

fn map_arch(raw: &str) -> Option<&'static str> {
    match raw {
        "amd64" | "x86_64" => Some("amd64"),
        "arm64" | "aarch64" => Some("arm64"),
        _ => None,
    }
}

fn load_artifact(architecture: &str) -> Result<NodeArtifact, DeployError> {
    let dir = std::env::var("NODE_BOOTSTRAP_BINARY_DIR")
        .unwrap_or_else(|_| "/opt/relay-panel/node-assets".into());
    let path = PathBuf::from(dir).join(format!("relay-node-linux-{architecture}"));
    let bytes = std::fs::read(&path)
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "Panel relay-node artifact is missing"))?;
    if bytes.is_empty() {
        return Err(DeployError::new(
            "ARTIFACT_FAILED",
            "Panel relay-node artifact is empty",
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(NodeArtifact {
        architecture: architecture.into(),
        bytes,
        sha256,
    })
}

fn connect(ssh: &SshInput, expected_fingerprint: Option<&str>) -> Result<Session, DeployError> {
    let address = if ssh.host.contains(':') && !ssh.host.starts_with('[') {
        format!("[{}]:{}", ssh.host, ssh.port)
    } else {
        format!("{}:{}", ssh.host, ssh.port)
    };
    let socket = address
        .to_socket_addrs()
        .map_err(|_| DeployError::new("SSH_FAILED", "unable to resolve SSH host"))?
        .next()
        .ok_or_else(|| DeployError::new("SSH_FAILED", "SSH host has no reachable address"))?;
    let tcp = TcpStream::connect_timeout(&socket, Duration::from_secs(15))
        .map_err(|_| DeployError::new("SSH_FAILED", "SSH connection failed"))?;
    tcp.set_read_timeout(Some(COMMAND_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(COMMAND_TIMEOUT)).ok();
    let mut session = Session::new()
        .map_err(|_| DeployError::new("SSH_FAILED", "could not create SSH session"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(COMMAND_TIMEOUT.as_millis() as u32);
    session
        .handshake()
        .map_err(|_| DeployError::new("SSH_FAILED", "SSH handshake failed"))?;
    if let Some(expected) = expected_fingerprint {
        if host_fingerprint(&session)? != expected {
            return Err(DeployError::new(
                "SSH_HOST_KEY_MISMATCH",
                "SSH host key changed since administrator confirmation",
            ));
        }
    }
    Ok(session)
}

fn host_fingerprint(session: &Session) -> Result<String, DeployError> {
    let (key, _) = session
        .host_key()
        .ok_or_else(|| DeployError::new("SSH_FAILED", "SSH server did not provide a host key"))?;
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(key))
    ))
}

fn authenticate(session: &mut Session, ssh: &SshInput) -> Result<(), DeployError> {
    session
        .userauth_password(&ssh.username, &ssh.password)
        .map_err(|_| DeployError::new("SSH_AUTH_FAILED", "SSH authentication failed"))?;
    if session.authenticated() {
        Ok(())
    } else {
        Err(DeployError::new(
            "SSH_AUTH_FAILED",
            "SSH authentication failed",
        ))
    }
}

fn exec(session: &mut Session, command: &str) -> Result<String, DeployError> {
    let mut channel = session.channel_session().map_err(|_| {
        DeployError::new("SSH_COMMAND_TIMEOUT", "could not open SSH command channel")
    })?;
    channel
        .exec(command)
        .map_err(|_| DeployError::new("SSH_COMMAND_TIMEOUT", "SSH command could not start"))?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    channel
        .read_to_string(&mut stdout)
        .map_err(|_| DeployError::new("SSH_COMMAND_TIMEOUT", "SSH command timed out"))?;
    channel.stderr().read_to_string(&mut stderr).ok();
    channel
        .wait_close()
        .map_err(|_| DeployError::new("SSH_COMMAND_TIMEOUT", "SSH command timed out"))?;
    if channel.exit_status().unwrap_or(1) == 0 {
        Ok(stdout)
    } else {
        Err(DeployError::new("REMOTE_COMMAND_FAILED", truncate(&stderr)))
    }
}

fn verify_command(
    session: &mut Session,
    category: &'static str,
    command: &str,
) -> Result<(), DeployError> {
    exec(session, command)
        .map(|_| ())
        .map_err(|_| DeployError::new(category, "remote verification check failed"))
}

fn upload(session: &mut Session, remote: &str, bytes: &[u8], mode: i32) -> Result<(), DeployError> {
    let mut file = session
        .scp_send(std::path::Path::new(remote), mode, bytes.len() as u64, None)
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "could not upload bootstrap file"))?;
    file.write_all(bytes)
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "bootstrap file upload failed"))?;
    file.send_eof()
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "bootstrap file upload failed"))?;
    file.wait_eof()
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "bootstrap file upload failed"))?;
    file.close()
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "bootstrap file upload failed"))?;
    file.wait_close()
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "bootstrap file upload failed"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn bootstrap_config(panel_url: &str, token: &str, artifact: &NodeArtifact) -> String {
    format!(
        "PANEL_URL={}\nNODE_TOKEN={}\nRELAY_NODE_ARCH={}\nRELAY_NODE_SHA256={}\n",
        shell_quote(panel_url),
        shell_quote(token),
        artifact.architecture,
        artifact.sha256
    )
}
fn truncate(value: &str) -> String {
    value.chars().take(512).collect()
}
fn default_port() -> u16 {
    22
}
fn default_user() -> String {
    "root".into()
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn error<T: Serialize>(code: i32, message: impl Into<String>) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        code,
        message: message.into(),
        data: None,
    })
}

fn public_error(error: &DeployError, secrets: &Secrets) -> String {
    format!("{}: {}", error.category, redact(&error.message, secrets))
}

fn redact(value: &str, secrets: &Secrets) -> String {
    let mut out = value.to_string();
    if !secrets.password.is_empty() {
        out = out.replace(&secrets.password, "[REDACTED]");
    }
    if !secrets.node_token.is_empty() {
        out = out.replace(&secrets.node_token, "[REDACTED]");
    }
    for marker in ["Bearer ", "bearer ", "Authorization:", "authorization:"] {
        while let Some(start) = out.find(marker) {
            let end = out[start + marker.len()..]
                .find(char::is_whitespace)
                .map(|offset| start + marker.len() + offset)
                .unwrap_or(out.len());
            out.replace_range(start..end, "[REDACTED]");
        }
    }
    redact_sensitive_query_values(&out)
}

fn redact_sensitive_query_values(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find(['?', '&']) {
        let (prefix, query) = rest.split_at(start + 1);
        out.push_str(prefix);
        let end = query
            .find(['&', '#', ' ', '\n', '\r', '\t'])
            .unwrap_or(query.len());
        let (pair, tail) = query.split_at(end);
        if let Some((key, _)) = pair.split_once('=') {
            if matches!(
                key.to_ascii_lowercase().as_str(),
                "token" | "node_token" | "access_token" | "password" | "authorization"
            ) {
                out.push_str(key);
                out.push_str("=[REDACTED]");
            } else {
                out.push_str(pair);
            }
        } else {
            out.push_str(pair);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::diagnose::DiagnoseRegistry;
    use crate::api::middleware::Claims;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    fn secrets() -> Secrets {
        Secrets {
            password: "wrong-password".into(),
            node_token: "node-token-secret".into(),
        }
    }

    #[derive(Clone, Copy)]
    enum FakeBehavior {
        Success,
        RejectPassword,
        HostKeyMismatch,
        InstallTimeout,
        InstallFailure(&'static str),
        SlowPreflight,
        VerifyFailure(&'static str),
    }

    struct FakeRunner {
        behavior: FakeBehavior,
        install_calls: Arc<AtomicUsize>,
    }

    impl FakeRunner {
        fn new(behavior: FakeBehavior) -> Self {
            Self {
                behavior,
                install_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl DeploymentRunner for FakeRunner {
        async fn probe(&self, _ssh: &SshInput) -> Result<SshProbe, DeployError> {
            Ok(SshProbe {
                fingerprint: "SHA256:fake".into(),
                os: "Debian GNU/Linux 12".into(),
                architecture: "x86_64".into(),
            })
        }

        async fn preflight(
            &self,
            ssh: &SshInput,
            _fingerprint: &str,
        ) -> Result<Preflight, DeployError> {
            match self.behavior {
                FakeBehavior::RejectPassword if ssh.password == "wrong-password" => Err(
                    DeployError::new("SSH_AUTH_FAILED", "SSH authentication failed"),
                ),
                FakeBehavior::HostKeyMismatch => Err(DeployError::new(
                    "SSH_HOST_KEY_MISMATCH",
                    "SSH host key changed since administrator confirmation",
                )),
                FakeBehavior::SlowPreflight => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(healthy_preflight())
                }
                _ => Ok(healthy_preflight()),
            }
        }

        async fn artifact(&self, architecture: &str) -> Result<NodeArtifact, DeployError> {
            Ok(NodeArtifact {
                architecture: architecture.into(),
                bytes: vec![1, 2, 3],
                sha256: "fake-sha256".into(),
            })
        }

        async fn install(
            &self,
            _task_id: &str,
            _ssh: &SshInput,
            _fingerprint: &str,
            _artifact: &NodeArtifact,
            _panel_url: &str,
            _token: &str,
        ) -> Result<(), DeployError> {
            self.install_calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                FakeBehavior::InstallTimeout => Err(DeployError::new(
                    "SSH_COMMAND_TIMEOUT",
                    "SSH command timed out",
                )),
                FakeBehavior::InstallFailure(category) => {
                    Err(DeployError::new(category, "bootstrap installer failed"))
                }
                _ => Ok(()),
            }
        }

        async fn verify(&self, _ssh: &SshInput, _fingerprint: &str) -> Result<String, DeployError> {
            match self.behavior {
                FakeBehavior::VerifyFailure(category) => {
                    Err(DeployError::new(category, "verification fixture failed"))
                }
                _ => Ok("node-test-1".into()),
            }
        }
    }

    fn healthy_preflight() -> Preflight {
        Preflight {
            os: "debian".into(),
            architecture: "amd64".into(),
            root: true,
            has_bash: true,
            has_systemd: true,
            free_kib: 524_288,
        }
    }

    fn unique_fixture_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-panel-bootstrap-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn bootstrap_script() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("scripts/relay-node-bootstrap.sh")
    }

    fn run_nginx_layout_fixture(root: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(bootstrap_script())
            .arg("--test-nginx-layout")
            .arg(root)
            .output()
            .expect("run bootstrap nginx layout fixture")
    }

    fn run_certbot_base_fixture(root: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(bootstrap_script())
            .arg("--test-certbot-base")
            .arg(root)
            .output()
            .expect("run bootstrap certbot base fixture")
    }

    fn write_fixture_nginx_conf(root: &Path) {
        let nginx_dir = root.join("etc/nginx");
        fs::create_dir_all(&nginx_dir).unwrap();
        fs::write(
            nginx_dir.join("nginx.conf"),
            "events { worker_connections 128; }\nhttp { }\n",
        )
        .unwrap();
    }

    fn count_stream_contexts(root: &Path) -> usize {
        fn visit(path: &Path, total: &mut usize) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, total);
                } else if let Ok(contents) = fs::read_to_string(path) {
                    *total += contents
                        .lines()
                        .filter(|line| line.trim_start().starts_with("stream {"))
                        .count();
                }
            }
        }

        let mut total = 0;
        visit(&root.join("etc/nginx"), &mut total);
        total
    }

    fn test_registry(
        runner: Arc<dyn DeploymentRunner>,
        total_timeout: Duration,
        online_timeout: Duration,
    ) -> DeploymentRegistry {
        DeploymentRegistry {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            runner,
            total_timeout,
            online_timeout,
        }
    }

    async fn test_state(registry: DeploymentRegistry) -> AppState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin, token_version) VALUES (2, 'member', 'hash', 0, 0)")
            .execute(&pool)
            .await
            .unwrap();
        AppState {
            db: Arc::new(SqliteRepository::new(pool)),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            deployments: registry,
            diagnose: DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    fn ssh_input() -> SshInput {
        SshInput {
            host: "node.example".into(),
            port: 22,
            username: "root".into(),
            password: "wrong-password".into(),
        }
    }

    async fn run_fake_task(state: AppState) -> DeploymentStatus {
        let task = state.deployments.insert(7, "node.example".into()).await;
        run_task(
            state.clone(),
            task.id.clone(),
            ssh_input(),
            "SHA256:confirmed".into(),
            "node-token-secret".into(),
            "https://panel.test".into(),
            1,
        )
        .await;
        state.deployments.status(&task.id).await.unwrap()
    }

    #[test]
    fn architecture_aliases_are_supported() {
        assert_eq!(map_arch("amd64"), Some("amd64"));
        assert_eq!(map_arch("x86_64"), Some("amd64"));
        assert_eq!(map_arch("arm64"), Some("arm64"));
        assert_eq!(map_arch("aarch64"), Some("arm64"));
        assert_eq!(map_arch("riscv64"), None);
    }

    #[test]
    fn password_token_and_bearer_are_redacted() {
        let value = redact("password=wrong-password token=node-token-secret Authorization: Bearer abc.def https://panel.test/api?access_token=other-secret", &secrets());
        assert!(!value.contains("wrong-password"));
        assert!(!value.contains("node-token-secret"));
        assert!(!value.contains("abc.def"));
        assert!(!value.contains("other-secret"));
    }

    #[test]
    fn bootstrap_config_has_separate_shell_quoted_lines() {
        let artifact = NodeArtifact {
            architecture: "amd64".into(),
            bytes: vec![],
            sha256: "abc123".into(),
        };
        let config = bootstrap_config("https://panel.test/api", "token with ' quote", &artifact);
        assert_eq!(
            config.lines().collect::<Vec<_>>(),
            vec![
                "PANEL_URL='https://panel.test/api'",
                "NODE_TOKEN='token with '\\'' quote'",
                "RELAY_NODE_ARCH=amd64",
                "RELAY_NODE_SHA256=abc123",
            ]
        );
    }

    #[test]
    fn preflight_rejects_unsupported_architecture_and_non_root() {
        assert!(parse_preflight(
            "os=debian\narch=riscv64\nuid=0\nbash=yes\nsystemd=yes\nfree_kib=999999\n"
        )
        .is_err());
        let facts = parse_preflight(
            "os=debian\narch=x86_64\nuid=1000\nbash=yes\nsystemd=yes\nfree_kib=999999\n",
        )
        .unwrap();
        assert!(validate_preflight(&facts).is_err());
    }

    #[test]
    fn minimal_preflight_does_not_require_curl() {
        let facts = parse_preflight(
            "os=debian\narch=x86_64\nuid=0\nbash=yes\nsystemd=yes\nfree_kib=524288\n",
        )
        .unwrap();
        assert!(validate_preflight(&facts).is_ok());
    }

    #[test]
    fn invalid_fingerprint_is_rejected() {
        assert!(validate_fingerprint("md5:bad").is_err());
        assert!(validate_fingerprint("SHA256:abc_def-123").is_ok());
    }

    #[test]
    fn bootstrap_script_preserves_p0_lkg_and_uses_loopback_only() {
        assert!(INSTALL_SCRIPT.contains("/opt/relay-node/node-id"));
        assert!(!INSTALL_SCRIPT.contains("touch /opt/relay-node/node-id"));
        assert!(!INSTALL_SCRIPT.contains("config-cache.json"));
        assert!(INSTALL_SCRIPT.contains("127.0.0.1:5244:5244"));
        assert!(INSTALL_SCRIPT.contains("listen 127.0.0.1:8443 ssl"));
        assert!(INSTALL_SCRIPT.contains("/var/lib/relay-panel/openlist"));
        assert!(INSTALL_SCRIPT.contains("/var/www/relay-panel-certbot/.well-known/acme-challenge"));
    }

    #[tokio::test]
    async fn task_state_transitions_are_visible_without_credentials() {
        let registry = DeploymentRegistry::default();
        let task = registry.insert(9, "node.example".into()).await;
        registry
            .update(
                &task.id,
                DeploymentStage::Connecting,
                "RUNNING",
                "connecting",
                &secrets(),
            )
            .await;
        registry
            .update(
                &task.id,
                DeploymentStage::Preflight,
                "RUNNING",
                "preflight",
                &secrets(),
            )
            .await;
        registry
            .update(
                &task.id,
                DeploymentStage::Success,
                "SUCCESS",
                "finished",
                &secrets(),
            )
            .await;
        let status = registry.status(&task.id).await.unwrap();
        assert_eq!(status.stage, DeploymentStage::Success);
        assert_eq!(status.status, "SUCCESS");
        assert_eq!(registry.logs(&task.id).await.unwrap().len(), 4);
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains("wrong-password"));
        assert!(!serialized.contains("node-token-secret"));
    }

    #[tokio::test]
    async fn concurrent_tasks_keep_logs_and_secrets_isolated() {
        let registry = DeploymentRegistry::default();
        let first = registry.insert(1, "one.example".into()).await;
        let second = registry.insert(2, "two.example".into()).await;
        registry
            .update(
                &first.id,
                DeploymentStage::Failed,
                "FAILED",
                "wrong-password Bearer abc",
                &secrets(),
            )
            .await;
        registry
            .update(
                &second.id,
                DeploymentStage::Verifying,
                "RUNNING",
                "checking OpenList",
                &secrets(),
            )
            .await;
        let first_logs = serde_json::to_string(&registry.logs(&first.id).await.unwrap()).unwrap();
        let second_logs = serde_json::to_string(&registry.logs(&second.id).await.unwrap()).unwrap();
        assert!(!first_logs.contains("wrong-password"));
        assert!(!first_logs.contains("abc"));
        assert!(!second_logs.contains("wrong-password"));
        assert!(second_logs.contains("checking OpenList"));
        assert!(!first_logs.contains("checking OpenList"));
    }

    #[test]
    fn deployment_errors_are_categorized_and_redacted() {
        let error = DeployError::new(
            "SSH_COMMAND_TIMEOUT",
            "password wrong-password token node-token-secret",
        );
        let message = public_error(&error, &secrets());
        assert!(message.starts_with("SSH_COMMAND_TIMEOUT:"));
        assert!(!message.contains("wrong-password"));
        assert!(!message.contains("node-token-secret"));
    }

    #[test]
    fn bootstrap_failure_step_is_visible_without_secrets() {
        let error = DeployError::new(
            "REMOTE_COMMAND_FAILED",
            "[bootstrap] verify-openlist: start\nBOOTSTRAP_FAILED_STEP=verify-openlist exit=7 password=wrong-password token=node-token-secret",
        );
        let message = public_error(&error, &secrets());
        assert!(message.contains("BOOTSTRAP_FAILED_STEP=verify-openlist exit=7"));
        assert!(!message.contains("wrong-password"));
        assert!(!message.contains("node-token-secret"));
    }

    #[test]
    fn bootstrap_script_is_idempotent_and_scoped_to_relaypanel_resources() {
        assert!(INSTALL_SCRIPT.contains("docker inspect relay-panel-openlist"));
        assert!(INSTALL_SCRIPT.contains("docker start relay-panel-openlist"));
        assert!(INSTALL_SCRIPT.contains("/etc/systemd/system/relay-node.service"));
        assert!(INSTALL_SCRIPT.contains("ensure_relay_panel_stream_layout"));
        assert!(INSTALL_SCRIPT.contains("/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf"));
        assert!(INSTALL_SCRIPT.contains("NGINX_STREAM_CONFLICT"));
        assert!(INSTALL_SCRIPT.contains("chown -R 1001:1001 /var/lib/relay-panel/openlist"));
        assert!(INSTALL_SCRIPT.contains("BOOTSTRAP_FAILED_STEP="));
        assert!(INSTALL_SCRIPT.contains("step verify-openlist"));
        assert!(!INSTALL_SCRIPT.contains("rm -rf /var/lib/relay-panel/openlist"));
        assert!(!INSTALL_SCRIPT.contains("rm -rf /etc/nginx"));
        assert!(!INSTALL_SCRIPT.contains("rm -f /opt/relay-node/config-cache"));
    }

    #[test]
    fn bootstrap_certbot_base_is_idempotent_without_certificate_issuance() {
        let root = unique_fixture_dir("certbot-base");

        let first = run_certbot_base_fixture(&root);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );

        for path in [
            "var/www/relay-panel-certbot/.well-known/acme-challenge",
            "etc/letsencrypt/renewal-hooks/deploy",
            "etc/letsencrypt/renewal-hooks/pre",
            "etc/letsencrypt/renewal-hooks/post",
        ] {
            assert!(root.join(path).is_dir(), "missing {path}");
        }

        let sentinel = root.join("etc/letsencrypt/renewal-hooks/deploy/existing-hook");
        fs::write(&sentinel, "preserve me\n").unwrap();
        let second = run_certbot_base_fixture(&root);
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(fs::read_to_string(sentinel).unwrap(), "preserve me\n");

        assert!(!INSTALL_SCRIPT.contains("certbot certonly"));
        assert!(!INSTALL_SCRIPT.contains("certbot renew"));
        assert!(!INSTALL_SCRIPT.contains("/etc/letsencrypt/renewal/"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_nginx_layout_has_one_managed_stream_and_rejects_external_streams() {
        let root = unique_fixture_dir("nginx-layout");
        write_fixture_nginx_conf(&root);

        let first = run_nginx_layout_fixture(&root);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(count_stream_contexts(&root), 1);
        let nginx_conf = root.join("etc/nginx/nginx.conf");
        let managed_root = root.join("etc/nginx/relay-panel-stream.conf");
        let expected_include = "include /etc/nginx/relay-panel-stream.conf;";
        assert_eq!(
            fs::read_to_string(&nginx_conf)
                .unwrap()
                .lines()
                .filter(|line| line.trim() == expected_include)
                .count(),
            1
        );
        assert!(fs::read_to_string(&managed_root)
            .unwrap()
            .contains("include /etc/nginx/relay-panel-stream.d/*.conf;"));

        // P0 nginx_sni owns a stream-context snippet, not the stream context.
        fs::write(
            root.join("etc/nginx/relay-panel-stream.d/relay-panel-sni.conf"),
            "# generated by relay-node\nupstream backend { server 127.0.0.1:9; }\n",
        )
        .unwrap();
        let second = run_nginx_layout_fixture(&root);
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(count_stream_contexts(&root), 1);

        // A RelayPanel-owned root is restored to the canonical layout, without
        // adding another include when bootstrap is repeated.
        fs::write(&managed_root, "stream { include /tmp/incorrect.conf; }\n").unwrap();
        let repeated = run_nginx_layout_fixture(&root);
        assert!(
            repeated.status.success(),
            "{}",
            String::from_utf8_lossy(&repeated.stderr)
        );
        assert_eq!(count_stream_contexts(&root), 1);
        assert_eq!(
            fs::read_to_string(&nginx_conf)
                .unwrap()
                .lines()
                .filter(|line| line.trim() == expected_include)
                .count(),
            1
        );

        let conflict = unique_fixture_dir("nginx-conflict");
        write_fixture_nginx_conf(&conflict);
        fs::write(
            conflict.join("etc/nginx/external-stream.conf"),
            "stream { server { listen 443; } }\n",
        )
        .unwrap();
        let rejected = run_nginx_layout_fixture(&conflict);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("NGINX_STREAM_CONFLICT"));
        assert!(!conflict.join("etc/nginx/relay-panel-stream.conf").exists());
        assert!(!fs::read_to_string(conflict.join("etc/nginx/nginx.conf"))
            .unwrap()
            .contains(expected_include));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(conflict);
    }

    #[tokio::test]
    async fn wrong_password_fails_without_running_installer_or_leaking_secrets() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::RejectPassword));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state.clone()).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("SSH_AUTH_FAILED:"));
        assert_eq!(runner.install_calls.load(Ordering::SeqCst), 0);
        let logs =
            serde_json::to_string(&state.deployments.logs(&status.id).await.unwrap()).unwrap();
        assert!(!logs.contains("wrong-password"));
        assert!(!logs.contains("node-token-secret"));
    }

    #[tokio::test]
    async fn host_key_mismatch_stops_before_installer_runs() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::HostKeyMismatch));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("SSH_HOST_KEY_MISMATCH:"));
        assert_eq!(runner.install_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn command_timeout_marks_task_failed() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::InstallTimeout));
        let state = test_state(test_registry(
            runner,
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("SSH_COMMAND_TIMEOUT:"));
    }

    #[tokio::test]
    async fn nginx_config_test_failure_during_install_never_reports_success() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::InstallFailure(
            "NGINX_CONFIG_INVALID",
        )));
        let state = test_state(test_registry(
            runner,
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("NGINX_CONFIG_INVALID:"));
    }

    #[tokio::test]
    async fn total_timeout_marks_task_failed() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::SlowPreflight));
        let state = test_state(test_registry(
            runner,
            Duration::from_millis(5),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert_eq!(
            status.message,
            "TOTAL_TIMEOUT: deployment exceeded the total timeout"
        );
    }

    #[tokio::test]
    async fn remote_service_verification_failures_never_report_success() {
        for category in ["RELAY_NODE_FAILED", "OPENLIST_FAILED", "NGINX_FAILED"] {
            let runner = Arc::new(FakeRunner::new(FakeBehavior::VerifyFailure(category)));
            let state = test_state(test_registry(
                runner,
                Duration::from_secs(1),
                Duration::from_millis(5),
            ))
            .await;
            let status = run_fake_task(state).await;
            assert_eq!(status.stage, DeploymentStage::Failed, "{category}");
            assert!(status.message.starts_with(category), "{}", status.message);
        }
    }

    #[tokio::test]
    async fn node_online_timeout_marks_task_failed() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner,
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("NODE_ONLINE_TIMEOUT:"));
    }

    #[tokio::test]
    async fn successful_task_reaches_success_after_node_enrollment() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner,
            Duration::from_secs(1),
            Duration::from_millis(50),
        ))
        .await;
        let (_connection_id, _receiver) = state
            .node_connections
            .register(7, Some("node-test-1".into()))
            .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Success);
        assert_eq!(status.node_id.as_deref(), Some("node-test-1"));
    }

    #[tokio::test]
    async fn non_admin_cannot_start_deployment() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ))
        .await;
        let token = encode(
            &Header::default(),
            &Claims {
                sub: 2,
                admin: false,
                token_version: 0,
                exp: 4_102_444_800,
            },
            &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        )
        .unwrap();
        let response = crate::api::routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/node-deployments")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"group_id":7,"host":"node.example","port":22,"username":"root","password":"wrong-password","confirmed_fingerprint":"SHA256:confirmed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
