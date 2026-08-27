//! Stage 1: administrator-initiated SSH bootstrap for a new relay node.
//!
//! Tasks intentionally live in memory. They contain progress and redacted
//! diagnostics only; the SSH password and node token exist solely in the
//! spawned worker's stack and are never serialised or persisted.

use crate::api::middleware::AdminOnly;
use crate::api::provisioning::{
    capabilities_satisfy, load_artifact, normalize_architecture, reported_capabilities,
    valid_public_panel_url, ProvisioningArtifact, ProvisioningBundle, ProvisioningProfile,
};
use crate::api::AppState;
use crate::db::repo::{GroupRepository, ResourceScope};
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use relay_shared::protocol::{ApiResponse, ProvisioningCapabilities};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Mutex;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const ONLINE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_LOGS: usize = 100;
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
    #[serde(default)]
    pub profile: ProvisioningProfile,
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
    pub profile: ProvisioningProfile,
    pub capabilities: Option<ProvisioningCapabilities>,
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
    async fn insert(
        &self,
        group_id: i64,
        host: String,
        profile: ProvisioningProfile,
    ) -> DeploymentStatus {
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
            profile,
            capabilities: None,
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

    async fn set_verified(
        &self,
        id: &str,
        node_id: String,
        capabilities: ProvisioningCapabilities,
    ) {
        if let Some(task) = self.tasks.lock().await.get_mut(id) {
            task.status.node_id = Some(node_id);
            task.status.capabilities = Some(capabilities);
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

struct VerifiedNode {
    node_id: String,
    capabilities: ProvisioningCapabilities,
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
    async fn artifact(&self, architecture: &str) -> Result<ProvisioningArtifact, DeployError>;
    async fn install(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
        artifact: &ProvisioningArtifact,
        panel_url: &str,
        token: &str,
    ) -> Result<(), DeployError>;
    async fn verify(&self, ssh: &SshInput, fingerprint: &str) -> Result<VerifiedNode, DeployError>;
    async fn commit(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
    ) -> Result<(), DeployError>;
    async fn rollback(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
    ) -> Result<(), DeployError>;
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

    async fn artifact(&self, architecture: &str) -> Result<ProvisioningArtifact, DeployError> {
        let architecture = architecture.to_string();
        tokio::task::spawn_blocking(move || {
            load_artifact(&architecture)
                .map_err(|error| DeployError::new(error.category, error.message))
        })
        .await
        .map_err(|_| DeployError::new("ARTIFACT_FAILED", "artifact worker terminated"))?
    }

    async fn install(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
        artifact: &ProvisioningArtifact,
        panel_url: &str,
        token: &str,
    ) -> Result<(), DeployError> {
        let input = ssh.clone_without_secret_debug();
        let fingerprint = fingerprint.to_string();
        let task_id = task_id.to_string();
        let bundle = ProvisioningBundle::new(panel_url, token, artifact.clone());
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
            let artifact_path = format!(
                "{remote_dir}/relay-node-linux-{}",
                bundle.artifact.architecture
            );
            let config_path = format!("{remote_dir}/config.env");
            let transaction_path = format!("{remote_dir}/transaction");
            let result = (|| {
                upload(
                    &mut session,
                    &script_path,
                    bundle.install_script.as_bytes(),
                    0o700,
                )?;
                upload(&mut session, &artifact_path, &bundle.artifact.bytes, 0o700)?;
                upload(&mut session, &config_path, bundle.config.as_bytes(), 0o600)?;
                exec(
                    &mut session,
                    &format!(
                        "bash {} {} {} {}",
                        shell_quote(&script_path),
                        shell_quote(&config_path),
                        shell_quote(&artifact_path),
                        shell_quote(&transaction_path)
                    ),
                )
                .map(|_| ())
            })();
            result
        })
        .await
        .map_err(|_| DeployError::new("INSTALL_FAILED", "installer worker terminated"))?
    }

    async fn verify(&self, ssh: &SshInput, fingerprint: &str) -> Result<VerifiedNode, DeployError> {
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
                "ss -H -ltn | awk '$4 ~ /:8443$/ { found=1 } END { exit !found }'; curl -kfsS --max-time 10 https://127.0.0.1:8443/ >/dev/null",
            )?;
            verify_command(
                &mut session,
                "CAPABILITY_FAILED",
                "test -f /etc/nginx/relay-panel-stream.conf; test -x /usr/bin/certbot; grep -Fx 'CAMOUFLAGE_SITES_ENABLED=1' /etc/relay-node/relay-node.env >/dev/null; grep -Fx 'CERTIFICATE_LIFECYCLE_ENABLED=1' /etc/relay-node/relay-node.env >/dev/null; test -s /opt/relay-node/provisioning-capabilities.json",
            )?;
            let output = exec(&mut session, "cat /opt/relay-node/node-id")
                .map_err(|_| DeployError::new("RELAY_NODE_FAILED", "could not read node-id"))?;
            let node_id = output.trim();
            if node_id.is_empty() {
                Err(DeployError::new("VERIFY_FAILED", "node-id is empty"))
            } else {
                Ok(VerifiedNode {
                    node_id: node_id.to_string(),
                    capabilities: ProvisioningCapabilities::reality_camouflage(),
                })
            }
        }).await.map_err(|_| DeployError::new("VERIFY_FAILED", "verification worker terminated"))?
    }

    async fn commit(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
    ) -> Result<(), DeployError> {
        finish_remote_transaction(task_id, ssh, fingerprint, "--commit", "COMMIT_FAILED").await
    }

    async fn rollback(
        &self,
        task_id: &str,
        ssh: &SshInput,
        fingerprint: &str,
    ) -> Result<(), DeployError> {
        finish_remote_transaction(task_id, ssh, fingerprint, "--rollback", "ROLLBACK_FAILED").await
    }
}

async fn finish_remote_transaction(
    task_id: &str,
    ssh: &SshInput,
    fingerprint: &str,
    mode: &'static str,
    category: &'static str,
) -> Result<(), DeployError> {
    let input = ssh.clone_without_secret_debug();
    let fingerprint = fingerprint.to_string();
    let task_id = task_id.to_string();
    tokio::task::spawn_blocking(move || {
        let remote_dir = format!("/tmp/relay-panel-bootstrap-{task_id}");
        let script_path = format!("{remote_dir}/bootstrap.sh");
        let transaction_path = format!("{remote_dir}/transaction");
        let finalize_command = if mode == "--rollback" {
            format!(
                "set -eu; if [ -x {script} ]; then bash {script} --rollback {transaction}; fi",
                script = shell_quote(&script_path),
                transaction = shell_quote(&transaction_path),
            )
        } else {
            format!(
                "set -eu; test -x {script}; test -f {transaction}/state; bash {script} --commit {transaction}",
                script = shell_quote(&script_path),
                transaction = shell_quote(&transaction_path),
            )
        };
        let finalize_once = || -> Result<(), DeployError> {
            let mut session = connect(&input, Some(&fingerprint))?;
            authenticate(&mut session, &input)?;
            exec(&mut session, &finalize_command)
                .map(|_| ())
                .map_err(|error| DeployError::new(category, error.message))
        };
        if finalize_once().is_err() {
            finalize_once()?;
        }

        let cleanup = || -> Result<(), DeployError> {
            let mut session = connect(&input, Some(&fingerprint))?;
            authenticate(&mut session, &input)?;
            exec(
                &mut session,
                &format!(
                    "rm -rf -- {}; test ! -e {}",
                    shell_quote(&remote_dir),
                    shell_quote(&remote_dir)
                ),
            )
            .map(|_| ())
            .map_err(|error| DeployError::new(category, error.message))
        };
        if mode == "--rollback" {
            cleanup()?;
        } else {
            let _ = cleanup();
        }
        Ok(())
    })
    .await
    .map_err(|_| DeployError::new(category, "transaction worker terminated"))?
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
    if !valid_public_panel_url(&panel_url) {
        return error(
            409,
            "PUBLIC_PANEL_URL must be a valid public http:// or https:// origin before node bootstrap",
        );
    }
    let status = state
        .deployments
        .insert(group.id, ssh.host.clone(), req.profile)
        .await;
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
    const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(120);

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
    let mutation_started = Arc::new(AtomicBool::new(false));
    let transaction_committed = Arc::new(AtomicBool::new(false));
    let work_mutation_started = mutation_started.clone();
    let work_transaction_committed = transaction_committed.clone();
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
        // From this point onward, the deterministic remote transaction path may
        // exist even if SSH reports a timeout before install returns.
        work_mutation_started.store(true, AtomicOrdering::SeqCst);
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
        let verified = state.deployments.runner.verify(&ssh, &fingerprint).await?;
        let profile = state
            .deployments
            .status(&id)
            .await
            .map(|task| task.profile)
            .unwrap_or_default();
        let required = profile.required_capabilities();
        if !capabilities_satisfy(verified.capabilities, required) {
            return Err(DeployError::new(
                "CAPABILITY_FAILED",
                "remote verification did not confirm requested provisioning capabilities",
            ));
        }
        let confirmed = wait_for_node_capabilities(
            &state,
            group_id,
            &verified.node_id,
            required,
            state.deployments.online_timeout,
        )
        .await?;
        state
            .deployments
            .runner
            .commit(&id, &ssh, &fingerprint)
            .await?;
        work_transaction_committed.store(true, AtomicOrdering::SeqCst);
        state
            .deployments
            .set_verified(&id, verified.node_id, confirmed)
            .await;
        Ok::<(), DeployError>(())
    };
    let result = tokio::time::timeout(state.deployments.total_timeout, work).await;
    let failure = match result {
        Ok(Ok(())) => {
            state
                .deployments
                .update(
                    &id,
                    DeploymentStage::Success,
                    "SUCCESS",
                    "node bootstrap completed and requested capabilities are online",
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
            None
        }
        Ok(Err(err)) => Some(err),
        Err(_) => Some(DeployError::new(
            "TOTAL_TIMEOUT",
            "deployment exceeded the total timeout",
        )),
    };

    if let Some(err) = failure {
        let mut message = public_error(&err, &secrets);
        if mutation_started.load(AtomicOrdering::SeqCst)
            && !transaction_committed.load(AtomicOrdering::SeqCst)
        {
            state
                .deployments
                .update(
                    &id,
                    DeploymentStage::Configuring,
                    "RUNNING",
                    "deployment failed; restoring previous managed runtime",
                    &secrets,
                )
                .await;
            match tokio::time::timeout(
                ROLLBACK_TIMEOUT,
                state.deployments.runner.rollback(&id, &ssh, &fingerprint),
            )
            .await
            {
                Ok(Ok(())) => {
                    state
                        .deployments
                        .update(
                            &id,
                            DeploymentStage::Configuring,
                            "RUNNING",
                            "previous managed runtime restored and verified",
                            &secrets,
                        )
                        .await;
                }
                Ok(Err(rollback_error)) => {
                    message.push_str("; ROLLBACK_FAILED: ");
                    message.push_str(&redact(&rollback_error.message, &secrets));
                }
                Err(_) => message.push_str("; ROLLBACK_FAILED: rollback timed out"),
            }
        }
        state
            .deployments
            .update(&id, DeploymentStage::Failed, "FAILED", &message, &secrets)
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
}

async fn wait_for_node_capabilities(
    state: &AppState,
    group_id: i64,
    node_id: &str,
    required: ProvisioningCapabilities,
    timeout: Duration,
) -> Result<ProvisioningCapabilities, DeployError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_online = false;
    loop {
        if state
            .node_connections
            .online_node_ids(group_id)
            .await
            .contains(node_id)
        {
            saw_online = true;
            let key = format!("node_status:{group_id}:{node_id}");
            if let Ok(Some(raw)) = state.db.get(&key).await {
                if let Some(capabilities) = reported_capabilities(&raw) {
                    if capabilities_satisfy(capabilities, required) {
                        return Ok(capabilities);
                    }
                }
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return if saw_online {
                Err(DeployError::new(
                    "CAPABILITY_CONFIRMATION_TIMEOUT",
                    "node connected but did not confirm requested provisioning capabilities",
                ))
            } else {
                Err(DeployError::new(
                    "NODE_ONLINE_TIMEOUT",
                    "node did not appear online before the deployment timeout",
                ))
            };
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
    let architecture = normalize_architecture(values.get("arch").copied().unwrap_or_default())
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
        Err(DeployError::new(
            "REMOTE_COMMAND_FAILED",
            truncate_tail(&stderr),
        ))
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

fn truncate_tail(value: &str) -> String {
    let length = value.chars().count();
    if length <= 512 {
        return value.to_string();
    }
    value.chars().skip(length - 512).collect()
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
    use crate::api::provisioning::INSTALL_SCRIPT;
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
    use std::os::unix::fs::PermissionsExt;
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
        SlowInstall,
        InstallFailure(&'static str),
        SlowPreflight,
        VerifyFailure(&'static str),
        CommitFailure,
        RollbackFailure,
    }

    struct FakeRunner {
        behavior: FakeBehavior,
        install_calls: Arc<AtomicUsize>,
        commit_calls: Arc<AtomicUsize>,
        rollback_calls: Arc<AtomicUsize>,
    }

    impl FakeRunner {
        fn new(behavior: FakeBehavior) -> Self {
            Self {
                behavior,
                install_calls: Arc::new(AtomicUsize::new(0)),
                commit_calls: Arc::new(AtomicUsize::new(0)),
                rollback_calls: Arc::new(AtomicUsize::new(0)),
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

        async fn artifact(&self, architecture: &str) -> Result<ProvisioningArtifact, DeployError> {
            Ok(ProvisioningArtifact {
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
            _artifact: &ProvisioningArtifact,
            _panel_url: &str,
            _token: &str,
        ) -> Result<(), DeployError> {
            self.install_calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                FakeBehavior::SlowInstall => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(())
                }
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

        async fn verify(
            &self,
            _ssh: &SshInput,
            _fingerprint: &str,
        ) -> Result<VerifiedNode, DeployError> {
            match self.behavior {
                FakeBehavior::VerifyFailure(category) => {
                    Err(DeployError::new(category, "verification fixture failed"))
                }
                _ => Ok(VerifiedNode {
                    node_id: "node-test-1".into(),
                    capabilities: ProvisioningCapabilities::reality_camouflage(),
                }),
            }
        }

        async fn commit(
            &self,
            _task_id: &str,
            _ssh: &SshInput,
            _fingerprint: &str,
        ) -> Result<(), DeployError> {
            self.commit_calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                FakeBehavior::CommitFailure => Err(DeployError::new(
                    "COMMIT_FAILED",
                    "transaction commit failed",
                )),
                _ => Ok(()),
            }
        }

        async fn rollback(
            &self,
            _task_id: &str,
            _ssh: &SshInput,
            _fingerprint: &str,
        ) -> Result<(), DeployError> {
            self.rollback_calls.fetch_add(1, Ordering::SeqCst);
            match self.behavior {
                FakeBehavior::RollbackFailure => Err(DeployError::new(
                    "ROLLBACK_FAILED",
                    "rollback failed token=node-token-secret password=wrong-password",
                )),
                _ => Ok(()),
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

    fn run_public_fallback_fixture(root: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(bootstrap_script())
            .arg("--test-public-fallback")
            .arg(root)
            .output()
            .expect("run bootstrap public fallback fixture")
    }

    fn run_port_preflight_fixture(root: &Path, listeners: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(bootstrap_script())
            .arg("--test-port-preflight")
            .arg(root)
            .arg(listeners)
            .output()
            .expect("run bootstrap port preflight fixture")
    }

    fn run_env_filter_fixture(input: &Path, output: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(bootstrap_script())
            .arg("--test-env-filter")
            .arg(input)
            .arg(output)
            .output()
            .expect("run bootstrap env filter fixture")
    }

    const MANAGED_TRANSACTION_FILES: &[(&str, &str)] = &[
        ("opt/relay-node/relay-node", "old relay-node binary\n"),
        (
            "etc/relay-node/relay-node.env",
            "PANEL_URL='https://old.panel'\nNODE_TOKEN='old-node-token'\n",
        ),
        (
            "etc/systemd/system/relay-node.service",
            "old relay-node unit\n",
        ),
        ("etc/nginx/nginx.conf", "events {}\nhttp {}\n"),
        (
            "etc/nginx/relay-panel-stream.conf",
            "old managed stream root\n",
        ),
        (
            "etc/nginx/relay-panel-stream.d/relay-panel-sni.conf",
            "old listener config\n",
        ),
        (
            "etc/nginx/conf.d/relay-panel-fallback.conf",
            "old camouflage wrapper\n",
        ),
        (
            "etc/nginx/conf.d/relay-panel-acme.conf",
            "old HTTP-01 config\n",
        ),
        (
            "etc/nginx/relay-panel-certs/fallback.crt",
            "old fallback certificate\n",
        ),
        (
            "etc/nginx/relay-panel-certs/fallback.key",
            "old fallback private key\n",
        ),
        (
            "opt/relay-node/provisioning-capabilities.json",
            "{\"old\":true}\n",
        ),
    ];

    const PERSISTENT_TRANSACTION_FILES: &[(&str, &str)] = &[
        ("opt/relay-node/node-id", "persistent-node-id\n"),
        (
            "opt/relay-node/config-cache.json",
            "{\"listener\":\"primary\"}\n",
        ),
        (
            "opt/relay-node/config-cache.json.backup",
            "{\"listener\":\"backup\"}\n",
        ),
        (
            "opt/relay-node/camouflage-sites/site-manifest.json",
            "{\"camouflage\":\"primary\"}\n",
        ),
        (
            "opt/relay-node/camouflage-sites/site-manifest.json.backup",
            "{\"camouflage\":\"backup\"}\n",
        ),
        (
            "opt/relay-node/certificates/op1/generations/g1/fullchain.pem",
            "active certificate generation\n",
        ),
        (
            "opt/relay-node/certificates/op1/generations/g1/privkey.pem",
            "active certificate private key\n",
        ),
        (
            "opt/relay-node/certificates/op1/active.json",
            "{\"generation\":\"g1\"}\n",
        ),
        (
            "var/lib/relay-panel/openlist/data.db",
            "persistent OpenList data\n",
        ),
    ];

    fn write_fixture_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn read_fixture_files(root: &Path, files: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
        files
            .iter()
            .map(|(relative, _)| {
                (
                    (*relative).to_string(),
                    fs::read(root.join(relative)).unwrap(),
                )
            })
            .collect()
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }

    struct TransactionFixture {
        root: PathBuf,
        transaction: PathBuf,
        systemctl: PathBuf,
        nginx: PathBuf,
        state_dir: PathBuf,
        command_log: PathBuf,
        managed_before: Vec<(String, Vec<u8>)>,
        managed_modes_before: Vec<(String, u32)>,
        persistent_before: Vec<(String, Vec<u8>)>,
    }

    impl TransactionFixture {
        fn new(label: &str) -> Self {
            let root = unique_fixture_dir(label);
            for (relative, contents) in MANAGED_TRANSACTION_FILES
                .iter()
                .chain(PERSISTENT_TRANSACTION_FILES.iter())
            {
                write_fixture_file(&root, relative, contents);
            }
            for (relative, mode) in [
                ("opt/relay-node/relay-node", 0o755),
                ("etc/relay-node/relay-node.env", 0o600),
                ("etc/nginx/relay-panel-certs/fallback.key", 0o600),
            ] {
                let mut permissions = fs::metadata(root.join(relative)).unwrap().permissions();
                permissions.set_mode(mode);
                fs::set_permissions(root.join(relative), permissions).unwrap();
            }
            let state_dir = root.join("fake-service-state");
            let bin_dir = root.join("fake-bin");
            fs::create_dir_all(&state_dir).unwrap();
            fs::create_dir_all(&bin_dir).unwrap();
            for unit in ["relay-node", "nginx"] {
                fs::write(state_dir.join(format!("{unit}.active")), "yes\n").unwrap();
                fs::write(state_dir.join(format!("{unit}.enabled")), "yes\n").unwrap();
            }
            let proc_exe = root.join("proc/4242/exe");
            fs::create_dir_all(proc_exe.parent().unwrap()).unwrap();
            fs::copy(root.join("opt/relay-node/relay-node"), &proc_exe).unwrap();

            let command_log = root.join("commands.log");
            let systemctl = bin_dir.join("systemctl");
            write_executable(
                &systemctl,
                r#"#!/usr/bin/env bash
set -eu
state="${FAKE_SERVICE_STATE_DIR:?}"
root="${TRANSACTION_ROOT:?}"
log="${FAKE_COMMAND_LOG:?}"
action="${1:?}"
shift
unit="${*: -1}"
printf 'systemctl %s %s\n' "$action" "$unit" >> "$log"
fail_key="${FAKE_FAIL_ONCE_ACTION:-}"
marker="$state/failed-once"
if [ "$fail_key" = "$action:$unit" ] && [ ! -e "$marker" ]; then
  : > "$marker"
  exit 1
fi
case "$action" in
  is-active) grep -Fx yes "$state/$unit.active" >/dev/null ;;
  is-enabled) grep -Fx yes "$state/$unit.enabled" >/dev/null ;;
  enable)
    printf 'yes\n' > "$state/$unit.enabled"
    ;;
  disable)
    printf 'no\n' > "$state/$unit.enabled"
    ;;
  start|restart)
    printf 'yes\n' > "$state/$unit.active"
    if [ "$unit" = relay-node ]; then
      mkdir -p "$root/proc/4242"
      cp "$root/opt/relay-node/relay-node" "$root/proc/4242/exe"
    fi
    ;;
  reload|daemon-reload) ;;
  stop) printf 'no\n' > "$state/$unit.active" ;;
  show) printf '4242\n' ;;
  *) exit 1 ;;
esac
"#,
            );
            let nginx = bin_dir.join("nginx");
            write_executable(
                &nginx,
                r#"#!/usr/bin/env bash
set -eu
printf 'nginx %s\n' "$*" >> "${FAKE_COMMAND_LOG:?}"
! grep -q BROKEN "${TRANSACTION_ROOT:?}/etc/nginx/nginx.conf"
"#,
            );
            let managed_before = read_fixture_files(&root, MANAGED_TRANSACTION_FILES);
            let managed_modes_before = MANAGED_TRANSACTION_FILES
                .iter()
                .map(|(relative, _)| {
                    (
                        (*relative).to_string(),
                        fs::metadata(root.join(relative))
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777,
                    )
                })
                .collect();
            let persistent_before = read_fixture_files(&root, PERSISTENT_TRANSACTION_FILES);
            Self {
                transaction: root.join("transaction"),
                root,
                systemctl,
                nginx,
                state_dir,
                command_log,
                managed_before,
                managed_modes_before,
                persistent_before,
            }
        }

        fn run_failure(
            &self,
            failure_point: &str,
            fail_once: Option<&str>,
        ) -> std::process::Output {
            let mut command = Command::new("bash");
            command
                .arg(bootstrap_script())
                .arg("--test-transaction-failure")
                .arg(&self.root)
                .arg(&self.transaction)
                .arg(failure_point)
                .env("TRANSACTION_ROOT", &self.root)
                .env("SYSTEMCTL_BIN", &self.systemctl)
                .env("NGINX_BIN", &self.nginx)
                .env("FAKE_SERVICE_STATE_DIR", &self.state_dir)
                .env("FAKE_COMMAND_LOG", &self.command_log);
            if let Some(value) = fail_once {
                command.env("FAKE_FAIL_ONCE_ACTION", value);
            }
            command.output().expect("run bootstrap rollback fixture")
        }

        fn run_noop(&self) -> std::process::Output {
            Command::new("bash")
                .arg(bootstrap_script())
                .arg("--test-transaction-noop")
                .arg(&self.root)
                .arg(&self.transaction)
                .env("TRANSACTION_ROOT", &self.root)
                .env("SYSTEMCTL_BIN", &self.systemctl)
                .env("NGINX_BIN", &self.nginx)
                .env("FAKE_SERVICE_STATE_DIR", &self.state_dir)
                .env("FAKE_COMMAND_LOG", &self.command_log)
                .output()
                .expect("run bootstrap no-op transaction fixture")
        }

        fn assert_restored(&self, relay_restarted: bool, nginx_reloaded: bool) {
            for (relative, expected) in &self.managed_before {
                assert_eq!(
                    fs::read(self.root.join(relative)).unwrap(),
                    *expected,
                    "{relative}"
                );
            }
            for (relative, expected) in &self.persistent_before {
                assert_eq!(
                    fs::read(self.root.join(relative)).unwrap(),
                    *expected,
                    "{relative}"
                );
            }
            for (relative, expected) in &self.managed_modes_before {
                assert_eq!(
                    fs::metadata(self.root.join(relative))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    *expected,
                    "mode for {relative}"
                );
            }
            assert_eq!(
                fs::read(self.root.join("proc/4242/exe")).unwrap(),
                fs::read(self.root.join("opt/relay-node/relay-node")).unwrap(),
                "running process must use the restored binary"
            );
            assert_eq!(
                fs::read_to_string(self.transaction.join("state")).unwrap(),
                "rolled_back\n"
            );
            assert!(!self.transaction.join("lock").exists());
            assert!(!self.transaction.join("candidate").exists());
            for relative in MANAGED_TRANSACTION_FILES
                .iter()
                .map(|(relative, _)| *relative)
            {
                for suffix in [".new", ".rollback", ".tmp"] {
                    assert!(!self.root.join(format!("{relative}{suffix}")).exists());
                }
            }
            let commands = fs::read_to_string(&self.command_log).unwrap();
            assert!(commands.contains("nginx -t"));
            assert_eq!(
                commands.contains("systemctl restart relay-node"),
                relay_restarted,
                "{commands}"
            );
            assert_eq!(
                commands.contains("systemctl reload nginx"),
                nginx_reloaded,
                "{commands}"
            );
            assert_eq!(
                fs::read_to_string(self.state_dir.join("relay-node.active")).unwrap(),
                "yes\n"
            );
            assert!(
                Command::new(&self.nginx)
                    .arg("-t")
                    .env("TRANSACTION_ROOT", &self.root)
                    .env("FAKE_COMMAND_LOG", &self.command_log)
                    .status()
                    .unwrap()
                    .success(),
                "restored Nginx configuration must validate"
            );
        }
    }

    impl Drop for TransactionFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
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
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
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
        let task = state
            .deployments
            .insert(
                7,
                "node.example".into(),
                ProvisioningProfile::RealityCamouflage,
            )
            .await;
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

    async fn seed_node_capabilities(state: &AppState, capabilities: ProvisioningCapabilities) {
        state
            .db
            .set(
                "node_status:7:node-test-1",
                &serde_json::json!({
                    "provisioning_capabilities": capabilities,
                })
                .to_string(),
            )
            .await
            .unwrap();
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
    fn ssh_bootstrap_uses_the_shared_bundle_config_unchanged() {
        let artifact = ProvisioningArtifact {
            architecture: "amd64".into(),
            bytes: vec![],
            sha256: "abc123".into(),
        };
        let bundle =
            ProvisioningBundle::new("https://panel.test/api", "token with ' quote", artifact);
        assert_eq!(
            bundle.config.lines().collect::<Vec<_>>(),
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
    fn bootstrap_preserves_lkg_and_uses_public_camouflage_with_loopback_openlist() {
        assert!(INSTALL_SCRIPT.contains("/opt/relay-node/node-id"));
        assert!(!INSTALL_SCRIPT.contains("touch /opt/relay-node/node-id"));
        assert!(!INSTALL_SCRIPT.contains("config-cache.json"));
        assert!(INSTALL_SCRIPT.contains("127.0.0.1:5244:5244"));
        assert!(INSTALL_SCRIPT.contains("listen 8443 ssl default_server"));
        assert!(INSTALL_SCRIPT.contains("listen [::]:8443 ssl default_server"));
        assert!(INSTALL_SCRIPT.contains("/var/lib/relay-panel/openlist"));
        assert!(INSTALL_SCRIPT.contains("/var/www/relay-panel-certbot/.well-known/acme-challenge"));
        assert!(INSTALL_SCRIPT.contains("existing_env_value CAMOUFLAGE_SITES_STATE_DIR"));
        assert!(INSTALL_SCRIPT.contains("existing_env_value CERTIFICATE_STATE_DIR"));
        assert!(
            INSTALL_SCRIPT.contains("cmp -s /opt/relay-node/provisioning-capabilities.json.tmp")
        );
    }

    #[tokio::test]
    async fn task_state_transitions_are_visible_without_credentials() {
        let registry = DeploymentRegistry::default();
        let task = registry
            .insert(
                9,
                "node.example".into(),
                ProvisioningProfile::RealityCamouflage,
            )
            .await;
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
        let first = registry
            .insert(
                1,
                "one.example".into(),
                ProvisioningProfile::RealityCamouflage,
            )
            .await;
        let second = registry
            .insert(
                2,
                "two.example".into(),
                ProvisioningProfile::RealityCamouflage,
            )
            .await;
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
    fn remote_error_truncation_preserves_failure_step_at_stderr_tail() {
        let stderr = format!(
            "{}\nBOOTSTRAP_FAILED_STEP=verify-fallback exit=7\nBOOTSTRAP_ROLLBACK=SUCCESS\n",
            "normal provisioning output\n".repeat(64)
        );
        let truncated = truncate_tail(&stderr);
        assert!(truncated.chars().count() <= 512);
        assert!(truncated.contains("BOOTSTRAP_FAILED_STEP=verify-fallback exit=7"));
        assert!(truncated.contains("BOOTSTRAP_ROLLBACK=SUCCESS"));
    }

    #[test]
    fn bootstrap_script_is_idempotent_and_scoped_to_relaypanel_resources() {
        assert!(INSTALL_SCRIPT.contains("docker inspect relay-panel-openlist"));
        assert!(INSTALL_SCRIPT.contains("docker start relay-panel-openlist"));
        assert!(INSTALL_SCRIPT.contains("/etc/systemd/system/relay-node.service"));
        assert!(INSTALL_SCRIPT.contains("ensure_relay_panel_stream_layout"));
        assert!(INSTALL_SCRIPT.contains("/etc/nginx/relay-panel-stream.d/relay-panel-sni.conf"));
        assert!(INSTALL_SCRIPT.contains("NGINX_STREAM_CONFLICT"));
        assert!(INSTALL_SCRIPT.contains("! -uid 1001 -o ! -gid 1001"));
        assert!(INSTALL_SCRIPT.contains("BOOTSTRAP_FAILED_STEP="));
        assert!(INSTALL_SCRIPT.contains("step verify-openlist"));
        assert!(INSTALL_SCRIPT.contains("current_sha"));
        assert!(INSTALL_SCRIPT.contains("RELAY_NODE_RESTART_REQUIRED"));
        assert!(INSTALL_SCRIPT.contains("is_managed_listener_config"));
        assert!(!INSTALL_SCRIPT.contains("rm -rf /var/lib/relay-panel/openlist"));
        assert!(!INSTALL_SCRIPT.contains("rm -rf /etc/nginx"));
        assert!(!INSTALL_SCRIPT.contains("rm -f /opt/relay-node/config-cache"));
        assert!(!INSTALL_SCRIPT.contains("find \"$(managed_path /opt/relay-node)\""));
    }

    #[test]
    fn bootstrap_env_filter_is_awk_compatible_and_preserves_unmanaged_values() {
        let root = unique_fixture_dir("env-filter");
        fs::create_dir_all(&root).unwrap();
        let input = root.join("relay-node.env");
        let output = root.join("relay-node.env.filtered");
        fs::write(
            &input,
            concat!(
                "PANEL_URL='https://old.panel'\n",
                "NODE_TOKEN='secret'\n",
                "NGINX_SNI_CONF_PATH=/old/path\n",
                "CUSTOM_SETTING=preserve-me\n",
            ),
        )
        .unwrap();

        let result = run_env_filter_fixture(&input, &output);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            "CUSTOM_SETTING=preserve-me\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_transaction_restores_binary_env_unit_nginx_and_persistent_state() {
        for failure_point in [
            "binary-activation",
            "env-mutation",
            "unit-mutation",
            "nginx-validation",
            "service-health",
        ] {
            let fixture = TransactionFixture::new(failure_point);
            let output = fixture.run_failure(failure_point, None);
            assert!(!output.status.success(), "{failure_point} must fail");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("BOOTSTRAP_ROLLBACK=SUCCESS"), "{stderr}");
            assert!(!stderr.contains("old-node-token"));
            assert!(!stderr.contains("injected-secret"));
            assert!(!stderr.contains("old fallback private key"));
            fixture.assert_restored(
                failure_point != "nginx-validation",
                failure_point == "nginx-validation",
            );
        }
    }

    #[test]
    fn bootstrap_transaction_retries_a_recoverable_rollback_error() {
        let fixture = TransactionFixture::new("rollback-retry");
        let output = fixture.run_failure("rollback-retry", Some("restart:relay-node"));
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed once; retrying rollback recovery"));
        assert!(stderr.contains("BOOTSTRAP_ROLLBACK=SUCCESS"));
        fixture.assert_restored(true, true);
        let commands = fs::read_to_string(&fixture.command_log).unwrap();
        assert_eq!(commands.matches("systemctl restart relay-node").count(), 2);
    }

    #[test]
    fn rollback_without_managed_mutation_preserves_running_services() {
        let fixture = TransactionFixture::new("rollback-no-mutation");
        let output = fixture.run_failure("no-mutation", None);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("BOOTSTRAP_ROLLBACK=SUCCESS"), "{stderr}");
        fixture.assert_restored(false, false);
        let commands = fs::read_to_string(&fixture.command_log).unwrap();
        assert!(!commands.contains("daemon-reload"), "{commands}");
        assert!(!commands.contains("systemctl enable"), "{commands}");
        assert!(!commands.contains("systemctl disable"), "{commands}");
    }

    #[test]
    fn identical_transaction_commit_is_a_runtime_noop() {
        let fixture = TransactionFixture::new("transaction-noop");
        let output = fixture.run_noop();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(fixture.transaction.join("state")).unwrap(),
            "committed\n"
        );
        for (relative, expected) in &fixture.managed_before {
            assert_eq!(fs::read(fixture.root.join(relative)).unwrap(), *expected);
        }
        for (relative, expected) in &fixture.persistent_before {
            assert_eq!(fs::read(fixture.root.join(relative)).unwrap(), *expected);
        }
        let commands = fs::read_to_string(&fixture.command_log).unwrap();
        assert!(!commands.contains(" restart "));
        assert!(!commands.contains(" reload "));
        assert!(!commands.contains(" enable "));
        assert!(!commands.contains(" disable "));
        assert!(!commands.contains("daemon-reload"));
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
    fn bootstrap_public_fallback_is_reachable_and_preserves_active_generated_config() {
        let root = unique_fixture_dir("public-fallback");
        let first = run_public_fallback_fixture(&root);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let conf = root.join("etc/nginx/conf.d/relay-panel-fallback.conf");
        let rendered = fs::read_to_string(&conf).unwrap();
        assert!(rendered.contains("listen 8443 ssl default_server;"));
        assert!(rendered.contains("listen [::]:8443 ssl default_server;"));
        assert!(!rendered.contains("listen 127.0.0.1:8443"));
        assert!(rendered.contains("proxy_pass http://127.0.0.1:5244;"));

        let active =
            "# generated by relay-node; TLS camouflage sites\n# preserve active generation\n";
        fs::write(&conf, active).unwrap();
        let repeated = run_public_fallback_fixture(&root);
        assert!(repeated.status.success());
        assert_eq!(fs::read_to_string(&conf).unwrap(), active);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_port_preflight_allows_managed_and_rejects_unknown_owners() {
        let root = unique_fixture_dir("port-preflight");
        fs::create_dir_all(root.join("etc/nginx/relay-panel-stream.d")).unwrap();
        let listeners = root.join("listeners.txt");
        fs::write(
            root.join("etc/nginx/relay-panel-stream.d/relay-panel-sni.conf"),
            "# generated by relay-node; do not edit\n",
        )
        .unwrap();
        fs::write(
            &listeners,
            concat!(
                "LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=1))\n",
                "LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=1,fd=2))\n",
            ),
        )
        .unwrap();
        let managed = run_port_preflight_fixture(&root, &listeners);
        assert!(
            managed.status.success(),
            "{}",
            String::from_utf8_lossy(&managed.stderr)
        );

        fs::write(
            &listeners,
            "LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=1))\n",
        )
        .unwrap();
        let shared_http = run_port_preflight_fixture(&root, &listeners);
        assert!(
            shared_http.status.success(),
            "{}",
            String::from_utf8_lossy(&shared_http.stderr)
        );

        fs::write(
            &listeners,
            "LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"otherd\",pid=2,fd=3))\n",
        )
        .unwrap();
        let unknown_process = run_port_preflight_fixture(&root, &listeners);
        assert!(!unknown_process.status.success());
        assert!(String::from_utf8_lossy(&unknown_process.stderr).contains("PORT_CONFLICT"));

        fs::write(
            &listeners,
            "LISTEN 0 511 0.0.0.0:8443 0.0.0.0:* users:((\"nginx\",pid=1,fd=1))\n",
        )
        .unwrap();
        let unknown_nginx = run_port_preflight_fixture(&root, &listeners);
        assert!(!unknown_nginx.status.success());
        assert!(String::from_utf8_lossy(&unknown_nginx.stderr).contains("PORT_CONFLICT"));
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
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("SSH_COMMAND_TIMEOUT:"));
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nginx_config_test_failure_during_install_never_reports_success() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::InstallFailure(
            "NGINX_CONFIG_INVALID",
        )));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("NGINX_CONFIG_INVALID:"));
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
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
    async fn total_timeout_after_mutation_attempts_rollback() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::SlowInstall));
        let state = test_state(test_registry(
            runner.clone(),
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
        assert_eq!(runner.install_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn remote_service_verification_failures_never_report_success() {
        for category in ["RELAY_NODE_FAILED", "OPENLIST_FAILED", "NGINX_FAILED"] {
            let runner = Arc::new(FakeRunner::new(FakeBehavior::VerifyFailure(category)));
            let state = test_state(test_registry(
                runner.clone(),
                Duration::from_secs(1),
                Duration::from_millis(5),
            ))
            .await;
            let status = run_fake_task(state).await;
            assert_eq!(status.stage, DeploymentStage::Failed, "{category}");
            assert!(status.message.starts_with(category), "{}", status.message);
            assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn node_online_timeout_marks_task_failed() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("NODE_ONLINE_TIMEOUT:"));
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_task_reaches_success_after_node_enrollment() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(50),
        ))
        .await;
        let (_connection_id, _receiver) = state
            .node_connections
            .register(7, Some("node-test-1".into()))
            .await;
        seed_node_capabilities(&state, ProvisioningCapabilities::reality_camouflage()).await;
        let status = run_fake_task(state).await;
        assert_eq!(status.stage, DeploymentStage::Success);
        assert_eq!(status.node_id.as_deref(), Some("node-test-1"));
        assert_eq!(
            status.capabilities,
            Some(ProvisioningCapabilities::reality_camouflage())
        );
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_ssh_task_preserves_stage_and_log_contract() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(50),
        ))
        .await;
        let task = state
            .deployments
            .insert(
                7,
                "node.example".into(),
                ProvisioningProfile::RealityCamouflage,
            )
            .await;
        let (_connection_id, _receiver) = state
            .node_connections
            .register(7, Some("node-test-1".into()))
            .await;
        seed_node_capabilities(&state, ProvisioningCapabilities::reality_camouflage()).await;

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

        let status = state.deployments.status(&task.id).await.unwrap();
        assert_eq!(status.stage, DeploymentStage::Success);
        assert_eq!(status.status, "SUCCESS");
        assert_eq!(
            status.message,
            "node bootstrap completed and requested capabilities are online"
        );
        assert_eq!(status.node_id.as_deref(), Some("node-test-1"));
        assert_eq!(
            status.capabilities,
            Some(ProvisioningCapabilities::reality_camouflage())
        );

        let logs = state.deployments.logs(&task.id).await.unwrap();
        assert_eq!(
            logs.iter()
                .map(|entry| (entry.stage, entry.message.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (DeploymentStage::Pending, "deployment task queued"),
                (
                    DeploymentStage::Connecting,
                    "validating confirmed SSH host key",
                ),
                (DeploymentStage::Preflight, "preflight checks passed"),
                (
                    DeploymentStage::Installing,
                    "uploading verified relay-node artifact",
                ),
                (
                    DeploymentStage::Configuring,
                    "relay-node, Docker, Nginx Stream, OpenList, fallback, and Certbot base configured",
                ),
                (
                    DeploymentStage::Verifying,
                    "checking remote services and Panel enrollment",
                ),
                (
                    DeploymentStage::Success,
                    "node bootstrap completed and requested capabilities are online",
                ),
            ]
        );
        assert_eq!(runner.install_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn online_node_without_requested_capabilities_never_reports_success() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::Success));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(15),
        ))
        .await;
        let (_connection_id, _receiver) = state
            .node_connections
            .register(7, Some("node-test-1".into()))
            .await;
        seed_node_capabilities(&state, ProvisioningCapabilities::default()).await;

        let status = run_fake_task(state).await;

        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status
            .message
            .starts_with("CAPABILITY_CONFIRMATION_TIMEOUT:"));
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn commit_failure_rolls_back_and_never_reports_success() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::CommitFailure));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(50),
        ))
        .await;
        let (_connection_id, _receiver) = state
            .node_connections
            .register(7, Some("node-test-1".into()))
            .await;
        seed_node_capabilities(&state, ProvisioningCapabilities::reality_camouflage()).await;

        let status = run_fake_task(state).await;

        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.starts_with("COMMIT_FAILED:"));
        assert_eq!(runner.commit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rollback_failure_is_redacted_and_never_reports_success() {
        let runner = Arc::new(FakeRunner::new(FakeBehavior::RollbackFailure));
        let state = test_state(test_registry(
            runner.clone(),
            Duration::from_secs(1),
            Duration::from_millis(5),
        ))
        .await;

        let status = run_fake_task(state.clone()).await;

        assert_eq!(status.stage, DeploymentStage::Failed);
        assert!(status.message.contains("ROLLBACK_FAILED:"));
        assert!(!status.message.contains("wrong-password"));
        assert!(!status.message.contains("node-token-secret"));
        assert_eq!(runner.rollback_calls.load(Ordering::SeqCst), 1);
        let logs =
            serde_json::to_string(&state.deployments.logs(&status.id).await.unwrap()).unwrap();
        assert!(!logs.contains("wrong-password"));
        assert!(!logs.contains("node-token-secret"));
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
