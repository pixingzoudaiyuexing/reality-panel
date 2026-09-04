use crate::config::Config;
use crate::db::repo::{GroupRepository, ResourceScope};
use crate::db::Repository;
use crate::service::acme_dns01::AcmeDns01Request;
use crate::service::node_config::{
    certificate_scopes_for_group, issuance_authorized_certificate_scopes_for_group,
    GroupCertificateScope,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use relay_shared::models::DeviceGroup;
use relay_shared::protocol::{NodeCertificatesResponse, PanelCertificateBundle};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

const HOOK_COMMAND: &str = "acme-dns01-hook";
const RENEW_BEFORE_DAYS: i64 = 30;
const MAX_HOOK_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_GROUP_CERTIFICATE_SCOPES: usize = 128;
const MAX_GROUP_CERTIFICATE_BYTES: usize = 2 * 1024 * 1024;
const CERTBOT_HARD_ABORT_ENV: &str = "RELAY_PANEL_CERTBOT_HARD_ABORT";
const ISSUANCE_ID_ENV: &str = "RELAY_PANEL_CERTIFICATE_ISSUANCE_ID";
const ISSUANCE_GROUP_ENV: &str = "RELAY_PANEL_CERTIFICATE_GROUP_ID";
const ISSUANCE_DOMAIN_ENV: &str = "RELAY_PANEL_CERTIFICATE_DOMAIN";
const ISSUANCE_RECEIPT_ENV: &str = "RELAY_PANEL_CERTIFICATE_AUTHORIZATION_RECEIPT";
const RETRY_DELAYS_SECS: &[i64] = &[30, 120, 300, 900, 1_800, 3_600];
static CERTIFICATE_ISSUANCE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static CERTIFICATE_RECONCILE_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();

#[derive(Clone)]
pub struct PanelCertificateManager {
    db: Arc<dyn Repository>,
    state_dir: PathBuf,
    certbot_binary: PathBuf,
    hook_binary: PathBuf,
    internal_panel_url: String,
    check_interval: Duration,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct CurrentCertificate {
    generation: u64,
    domain: String,
    expires_at: String,
    fingerprint: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct RetryState {
    attempt: usize,
    next_retry_unix_ms: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct IssuanceAuthorizationReceipt {
    issuance_id: String,
    group_id: i64,
    certificate_domain: String,
    challenge_sni: String,
    actor: String,
    challenge_id: String,
    value_sha256: String,
    state: String,
}

#[derive(Clone, Debug)]
struct IssuanceAttempt {
    issuance_id: String,
    group_id: i64,
    certificate_domain: String,
    challenge_sni: String,
    actor: String,
    receipt_path: PathBuf,
}

struct IssuedCertificateCandidate {
    attempt: IssuanceAttempt,
    cert_source: PathBuf,
    key_source: PathBuf,
}

pub struct GroupCertificateManifest {
    pub etag: String,
    pub response: NodeCertificatesResponse,
}

impl PanelCertificateManager {
    pub fn new(db: Arc<dyn Repository>, config: &Config) -> Result<Self, String> {
        let hook_binary = std::env::current_exe().map_err(|error| error.to_string())?;
        Ok(Self {
            db,
            state_dir: PathBuf::from(config.certificate_state_dir()),
            certbot_binary: PathBuf::from(config.certbot_binary_path()),
            hook_binary,
            internal_panel_url: internal_panel_url(&config.listen)?,
            check_interval: Duration::from_secs(config.certificate_check_interval_secs()),
        })
    }

    pub async fn group_manifest(&self, group_id: i64) -> Result<GroupCertificateManifest, String> {
        let scopes = self.certificate_scopes(group_id).await?;
        let state_dir = self.state_dir.clone();
        tokio::task::spawn_blocking(move || build_group_manifest(&state_dir, group_id, &scopes))
            .await
            .map_err(|error| error.to_string())?
    }

    async fn certificate_scopes(
        &self,
        group_id: i64,
    ) -> Result<Vec<GroupCertificateScope>, String> {
        let scopes = certificate_scopes_for_group(self.db.as_ref(), group_id)
            .await
            .map_err(|error| error.to_string())?;
        resolve_managed_certificate_scopes(&self.state_dir, group_id, scopes).await
    }

    async fn reconcile_all(&self) -> HashSet<i64> {
        let mut changed_groups = HashSet::new();
        let groups = match GroupRepository::list_groups(self.db.as_ref(), &ResourceScope::All).await
        {
            Ok(groups) => groups,
            Err(error) => {
                tracing::error!("panel certificate: group discovery failed: {error}");
                return changed_groups;
            }
        };
        for group in groups.into_iter().filter(|group| group.group_type == "in") {
            let scopes = match self.certificate_scopes(group.id).await {
                Ok(scopes) => scopes,
                Err(error) => {
                    tracing::warn!(
                        group_id = group.id,
                        "panel certificate: scope discovery failed: {error}"
                    );
                    continue;
                }
            };
            for scope in scopes {
                match self.reconcile_scope(&group, &scope).await {
                    Ok(true) => {
                        changed_groups.insert(group.id);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(
                            group_id = group.id,
                            domain = %scope.domain,
                            "panel certificate reconcile failed: {error}"
                        );
                    }
                }
            }
        }
        changed_groups
    }

    async fn reconcile_scope(
        &self,
        group: &DeviceGroup,
        scope: &GroupCertificateScope,
    ) -> Result<bool, String> {
        let scope_root = scope_root(&self.state_dir, group.id, &scope.domain);
        let current = recover_current(&scope_root, &scope.domain)?;
        if current
            .as_ref()
            .is_some_and(|current| !renewal_due(current))
        {
            clear_retry(&scope_root);
            return Ok(false);
        }
        if !self.issuance_authorized(group.id, &scope.domain).await? {
            clear_retry(&scope_root);
            return Ok(false);
        }
        if !retry_due(&scope_root)? {
            return Ok(false);
        }
        let issuance_lock = CERTIFICATE_ISSUANCE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
        let _issuance_guard = issuance_lock.lock().await;
        let current = recover_current(&scope_root, &scope.domain)?;
        if current
            .as_ref()
            .is_some_and(|current| !renewal_due(current))
        {
            clear_retry(&scope_root);
            return Ok(false);
        }
        if !self.issuance_authorized(group.id, &scope.domain).await? {
            clear_retry(&scope_root);
            return Ok(false);
        }
        if !retry_due(&scope_root)? {
            return Ok(false);
        }
        schedule_retry_before_attempt(&scope_root)?;

        let manager = self.clone();
        let group_id = group.id;
        let token = group.token.clone();
        let domain = scope.domain.clone();
        let current_for_issue = current.clone();
        let candidate = tokio::task::spawn_blocking(move || {
            manager.issue_candidate(group_id, &token, &domain, current_for_issue.as_ref())
        })
        .await
        .map_err(|error| error.to_string())??;
        if !self.issuance_authorized(group.id, &scope.domain).await? {
            remove_regular_file(&candidate.attempt.receipt_path);
            return Err("certificate issuance authorization changed before publish".into());
        }
        let state_dir = self.state_dir.clone();
        let publish_domain = scope.domain.clone();
        let issued = tokio::task::spawn_blocking(move || {
            let result =
                validate_issuance_receipt(&candidate.attempt.receipt_path, &candidate.attempt)
                    .and_then(|_| {
                        publish_candidate(
                            &state_dir,
                            group_id,
                            &publish_domain,
                            &candidate.cert_source,
                            &candidate.key_source,
                        )
                    });
            remove_regular_file(&candidate.attempt.receipt_path);
            result
        })
        .await
        .map_err(|error| error.to_string())??;
        if issued {
            tracing::info!(group_id, domain = %scope.domain, "published Panel certificate generation");
        }
        clear_retry(&scope_root);
        Ok(issued)
    }

    async fn issuance_authorized(&self, group_id: i64, domain: &str) -> Result<bool, String> {
        let scopes = issuance_authorized_certificate_scopes_for_group(self.db.as_ref(), group_id)
            .await
            .map_err(|error| error.to_string())?;
        Ok(scopes
            .iter()
            .any(|scope| scope.domain.eq_ignore_ascii_case(domain)))
    }

    fn issue_candidate(
        &self,
        group_id: i64,
        token: &str,
        domain: &str,
        current: Option<&CurrentCertificate>,
    ) -> Result<IssuedCertificateCandidate, String> {
        ensure_private_dir(&self.state_dir)?;
        let acme_root = self.state_dir.join("acme");
        let config_dir = acme_root.join("config");
        let work_dir = acme_root.join("work");
        let logs_dir = acme_root.join("logs");
        ensure_private_dir(&config_dir)?;
        ensure_private_dir(&work_dir)?;
        ensure_private_dir(&logs_dir)?;

        let certificate_name = format!("reality-panel-g{group_id}-{}", &scope_id(domain)[..16]);
        let actor = format!("panel-certificate-g{group_id}-{}", &scope_id(domain)[..16]);
        let issuance_id = uuid::Uuid::new_v4().to_string();
        let issuance_dir = self.state_dir.join("issuance");
        ensure_private_dir(&issuance_dir)?;
        let attempt = IssuanceAttempt {
            issuance_id: issuance_id.clone(),
            group_id,
            certificate_domain: domain.to_string(),
            challenge_sni: challenge_domain(domain)?,
            actor: actor.clone(),
            receipt_path: issuance_dir.join(format!("{issuance_id}.json")),
        };
        let mut args = vec![
            "certonly".to_string(),
            "--non-interactive".to_string(),
            "--agree-tos".to_string(),
            "--manual".to_string(),
            "--preferred-challenges".to_string(),
            "dns".to_string(),
            "--manual-auth-hook".to_string(),
            panel_certbot_hook_command(&self.hook_binary, "auth")?,
            "--manual-cleanup-hook".to_string(),
            panel_certbot_hook_command(&self.hook_binary, "cleanup")?,
            "--cert-name".to_string(),
            certificate_name.clone(),
            "-d".to_string(),
            domain.to_string(),
            "--config-dir".to_string(),
            config_dir.display().to_string(),
            "--work-dir".to_string(),
            work_dir.display().to_string(),
            "--logs-dir".to_string(),
            logs_dir.display().to_string(),
            "--register-unsafely-without-email".to_string(),
        ];
        if current.is_some() {
            args.push("--force-renewal".to_string());
        }
        let mut command = Command::new(&self.certbot_binary);
        command.process_group(0);
        let output = command
            .args(&args)
            .env("RELAY_PANEL_INTERNAL_URL", &self.internal_panel_url)
            .env("RELAY_PANEL_NODE_TOKEN", token)
            .env("RELAY_PANEL_CERTIFICATE_ACTOR", &actor)
            .env(ISSUANCE_ID_ENV, &attempt.issuance_id)
            .env(ISSUANCE_GROUP_ENV, group_id.to_string())
            .env(ISSUANCE_DOMAIN_ENV, domain)
            .env(ISSUANCE_RECEIPT_ENV, &attempt.receipt_path)
            .env(CERTBOT_HARD_ABORT_ENV, "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("cannot run Certbot: {error}"))?;
        if !output.status.success() {
            remove_regular_file(&attempt.receipt_path);
            return Err(
                "Panel ACME certificate command failed; retained current generation".into(),
            );
        }
        if let Err(error) = validate_issuance_receipt(&attempt.receipt_path, &attempt) {
            remove_regular_file(&attempt.receipt_path);
            return Err(error);
        }

        let live = config_dir.join("live").join(certificate_name);
        let cert_path = live.join("fullchain.pem");
        let key_path = live.join("privkey.pem");
        let cert_source = resolve_certbot_source(&cert_path, &config_dir)?;
        let key_source = resolve_certbot_source(&key_path, &config_dir)?;
        Ok(IssuedCertificateCandidate {
            attempt,
            cert_source,
            key_source,
        })
    }
}

pub fn spawn(manager: PanelCertificateManager, node_connections: crate::api::ws::NodeConnections) {
    tokio::spawn(async move {
        // HTTP listener先开始服务，Certbot manual hook才能通过本机现有端口复用
        // Panel DNS-01。该等待不创建新调度器，之后仍只有一个顺序worker。
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut ticker = tokio::time::interval(manager.check_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = certificate_reconcile_notify().notified() => {}
            }
            for group_id in manager.reconcile_all().await {
                node_connections
                    .send_group(group_id, r#"{"type":"config_changed"}"#)
                    .await;
            }
        }
    });
}

fn certificate_reconcile_notify() -> &'static tokio::sync::Notify {
    CERTIFICATE_RECONCILE_NOTIFY.get_or_init(tokio::sync::Notify::new)
}

pub(crate) fn notify_reconcile() {
    certificate_reconcile_notify().notify_one();
}

pub fn is_hook_command(args: &[String]) -> bool {
    args.first().is_some_and(|value| value == HOOK_COMMAND)
}

pub fn hard_abort_certbot_process_group() {
    if std::env::var(CERTBOT_HARD_ABORT_ENV).as_deref() != Ok("1")
        || std::env::var(ISSUANCE_ID_ENV)
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(&value).ok())
            .is_none()
    {
        return;
    }
    let process_group = unsafe { libc::getpgrp() };
    if process_group > 1 {
        unsafe {
            libc::killpg(process_group, libc::SIGKILL);
        }
    }
}

pub async fn run_hook(args: &[String]) -> Result<(), String> {
    let action = match args.get(1).map(String::as_str) {
        Some("auth") => "present",
        Some("cleanup") => "cleanup",
        _ => return Err("invalid hook action".into()),
    };
    if args.len() != 2 {
        return Err("unexpected hook arguments".into());
    }
    let panel_url = std::env::var("RELAY_PANEL_INTERNAL_URL")
        .map_err(|_| "Panel internal URL is unavailable")?;
    let token = std::env::var("RELAY_PANEL_NODE_TOKEN")
        .map_err(|_| "Panel certificate credential is unavailable")?;
    let node_id = std::env::var("RELAY_PANEL_CERTIFICATE_ACTOR")
        .map_err(|_| "Panel certificate actor is unavailable")?;
    let domain = std::env::var("CERTBOT_DOMAIN").map_err(|_| "challenge domain is unavailable")?;
    let sni = challenge_domain(&domain)?;
    let value =
        std::env::var("CERTBOT_VALIDATION").map_err(|_| "challenge value is unavailable")?;
    let endpoint = format!(
        "{}/api/v1/node/acme-dns01/{action}",
        panel_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(150))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "hook HTTP client is unavailable")?;
    let response = client
        .post(endpoint)
        .bearer_auth(token)
        .header("X-Node-ID", &node_id)
        .json(&AcmeDns01Request {
            node_id: node_id.clone(),
            sni: sni.clone(),
            value: value.clone(),
        })
        .send()
        .await
        .map_err(|_| "Panel challenge request failed")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|_| "Panel challenge response is unavailable")?;
    if body.len() > MAX_HOOK_RESPONSE_BYTES {
        return Err("Panel challenge response is too large".into());
    }
    if status.is_success() {
        if action == "present" {
            write_issuance_receipt_from_hook(&body, &node_id, &sni, &value)?;
        }
        Ok(())
    } else {
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("code")?.as_str().map(str::to_string))
            .unwrap_or_else(|| "UNKNOWN".to_string());
        Err(format!(
            "Panel challenge request returned HTTP {} code {code}",
            status.as_u16()
        ))
    }
}

fn write_issuance_receipt_from_hook(
    response_body: &[u8],
    actor: &str,
    challenge_sni: &str,
    value: &str,
) -> Result<(), String> {
    let issuance_id =
        std::env::var(ISSUANCE_ID_ENV).map_err(|_| "certificate issuance ID is unavailable")?;
    uuid::Uuid::parse_str(&issuance_id).map_err(|_| "certificate issuance ID is invalid")?;
    let group_id = std::env::var(ISSUANCE_GROUP_ENV)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or("certificate issuance group is invalid")?;
    let certificate_domain = std::env::var(ISSUANCE_DOMAIN_ENV)
        .map_err(|_| "certificate issuance domain is unavailable")?;
    if challenge_domain(&certificate_domain)? != challenge_sni {
        return Err("certificate issuance challenge domain mismatch".into());
    }
    let receipt_path = PathBuf::from(
        std::env::var(ISSUANCE_RECEIPT_ENV)
            .map_err(|_| "certificate issuance receipt path is unavailable")?,
    );
    if receipt_path.file_name().and_then(|name| name.to_str())
        != Some(&format!("{issuance_id}.json"))
    {
        return Err("certificate issuance receipt path is invalid".into());
    }
    let response: serde_json::Value =
        serde_json::from_slice(response_body).map_err(|_| "Panel challenge response is invalid")?;
    let challenge_id = response
        .get("challenge_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("Panel challenge authorization response is invalid")?;
    if response.get("state").and_then(serde_json::Value::as_str) != Some("presented")
        || challenge_id.len() != 64
        || !challenge_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Panel challenge authorization response is invalid".into());
    }
    write_json_private(
        &receipt_path,
        &IssuanceAuthorizationReceipt {
            issuance_id,
            group_id,
            certificate_domain,
            challenge_sni: challenge_sni.to_string(),
            actor: actor.to_string(),
            challenge_id: challenge_id.to_string(),
            value_sha256: hex::encode(Sha256::digest(value.as_bytes())),
            state: "propagation_succeeded".into(),
        },
    )
}

fn validate_issuance_receipt(path: &Path, attempt: &IssuanceAttempt) -> Result<(), String> {
    validate_private_file(path, true)
        .map_err(|_| "certificate issuance authorization receipt is unavailable")?;
    let receipt: IssuanceAuthorizationReceipt =
        read_json(path).map_err(|_| "certificate issuance authorization receipt is invalid")?;
    if receipt.issuance_id != attempt.issuance_id
        || receipt.group_id != attempt.group_id
        || receipt.certificate_domain != attempt.certificate_domain
        || receipt.challenge_sni != attempt.challenge_sni
        || receipt.actor != attempt.actor
        || receipt.state != "propagation_succeeded"
        || receipt.challenge_id.len() != 64
        || !receipt
            .challenge_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || receipt.value_sha256.len() != 64
        || !receipt
            .value_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("certificate issuance authorization receipt does not match attempt".into());
    }
    Ok(())
}

pub(crate) async fn resolve_managed_certificate_scopes(
    state_dir: &Path,
    group_id: i64,
    scopes: Vec<GroupCertificateScope>,
) -> Result<Vec<GroupCertificateScope>, String> {
    let state_dir = state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let inventory = managed_certificate_inventory(&state_dir, group_id)?;
        let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();
        for scope in scopes {
            for sni in scope.snis {
                let domain = best_managed_certificate_domain(&inventory, &sni)
                    .unwrap_or_else(|| scope.domain.clone());
                resolved.entry(domain).or_default().insert(sni);
            }
        }
        Ok(resolved
            .into_iter()
            .map(|(domain, snis)| GroupCertificateScope {
                domain,
                snis: snis.into_iter().collect(),
            })
            .collect())
    })
    .await
    .map_err(|error| error.to_string())?
}

fn managed_certificate_inventory(
    state_dir: &Path,
    group_id: i64,
) -> Result<Vec<CurrentCertificate>, String> {
    let scopes_root = state_dir
        .join("groups")
        .join(group_id.to_string())
        .join("scopes");
    let entries = match fs::read_dir(&scopes_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    let mut inventory = Vec::new();
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(link_metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.is_dir() || link_metadata.file_type().is_symlink() {
            continue;
        }
        let Some(scope_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let root = entry.path();
        let domain = ["current.json", "current.backup.json"]
            .into_iter()
            .find_map(|name| {
                let path = root.join(name);
                validate_private_file(&path, false).ok()?;
                let current = read_json::<CurrentCertificate>(&path).ok()?;
                (scope_id(&current.domain) == scope_name).then_some(current.domain)
            });
        let Some(domain) = domain else {
            continue;
        };
        if let Some(current) = recover_current(&root, &domain)? {
            inventory.push(current);
        }
    }
    Ok(inventory)
}

fn best_managed_certificate_domain(inventory: &[CurrentCertificate], sni: &str) -> Option<String> {
    let sni = sni.trim_end_matches('.');
    let mut candidates = inventory
        .iter()
        .filter(|current| {
            relay_shared::reconciliation::certificate_domain_covers_sni(&current.domain, sni)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_exact = left.domain.eq_ignore_ascii_case(sni);
        let right_exact = right.domain.eq_ignore_ascii_case(sni);
        right_exact
            .cmp(&left_exact)
            .then_with(|| right.domain.len().cmp(&left.domain.len()))
            .then_with(|| left.domain.cmp(&right.domain))
    });
    candidates.first().map(|current| current.domain.clone())
}

fn internal_panel_url(listen: &str) -> Result<String, String> {
    let address: SocketAddr = listen
        .parse()
        .map_err(|_| "invalid Panel listen address".to_string())?;
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(match ip {
        IpAddr::V4(ip) => format!("http://{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}", address.port()),
    })
}

fn build_group_manifest(
    state_dir: &Path,
    group_id: i64,
    scopes: &[GroupCertificateScope],
) -> Result<GroupCertificateManifest, String> {
    if scopes.len() > MAX_GROUP_CERTIFICATE_SCOPES {
        return Err("group has too many certificate scopes".into());
    }
    let mut certificates = Vec::new();
    let mut missing_domains = Vec::new();
    for scope in scopes {
        let root = scope_root(state_dir, group_id, &scope.domain);
        match recover_current(&root, &scope.domain)? {
            Some(current) => {
                let generation = root
                    .join("generations")
                    .join(current.generation.to_string());
                let cert_path = generation.join("fullchain.pem");
                let key_path = generation.join("privkey.pem");
                let inspected = validate_bundle_paths(&cert_path, &key_path, &scope.domain)?;
                if inspected.fingerprint != current.fingerprint
                    || inspected.expires_at != current.expires_at
                {
                    return Err(
                        "Panel certificate metadata does not match current generation".into(),
                    );
                }
                certificates.push(PanelCertificateBundle {
                    domain: current.domain,
                    generation: current.generation,
                    expires_at: current.expires_at,
                    fingerprint: current.fingerprint,
                    fullchain_pem: String::from_utf8(
                        fs::read(cert_path).map_err(|error| error.to_string())?,
                    )
                    .map_err(|_| "certificate PEM is not UTF-8")?,
                    privkey_pem: String::from_utf8(
                        fs::read(key_path).map_err(|error| error.to_string())?,
                    )
                    .map_err(|_| "private key PEM is not UTF-8")?,
                });
            }
            None => missing_domains.push(scope.domain.clone()),
        }
    }
    certificates.sort_by(|left, right| left.domain.cmp(&right.domain));
    missing_domains.sort();
    let response_bytes = certificates
        .iter()
        .try_fold(0_usize, |total, certificate| {
            total
                .checked_add(certificate.fullchain_pem.len())
                .and_then(|total| total.checked_add(certificate.privkey_pem.len()))
                .ok_or("group certificate response size overflow")
        })?;
    if response_bytes > MAX_GROUP_CERTIFICATE_BYTES {
        return Err("group certificate response is too large".into());
    }
    let etag_material = certificates
        .iter()
        .map(|certificate| {
            (
                certificate.domain.as_str(),
                certificate.generation,
                certificate.expires_at.as_str(),
                certificate.fingerprint.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let etag = format!(
        "\"{}\"",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(etag_material, &missing_domains))
                .map_err(|error| error.to_string())?
        ))
    );
    Ok(GroupCertificateManifest {
        etag,
        response: NodeCertificatesResponse {
            certificates,
            missing_domains,
        },
    })
}

fn publish_candidate(
    state_dir: &Path,
    group_id: i64,
    domain: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<bool, String> {
    let inspected = validate_bundle_paths(cert_path, key_path, domain)?;
    let candidate_expiry = DateTime::parse_from_rfc3339(&inspected.expires_at)
        .map_err(|_| "invalid candidate certificate expiry")?
        .with_timezone(&Utc);
    if candidate_expiry <= Utc::now() + ChronoDuration::days(RENEW_BEFORE_DAYS) {
        return Err("candidate certificate is inside the renewal threshold".into());
    }
    let root = scope_root(state_dir, group_id, domain);
    ensure_private_dir(&root)?;
    let current = recover_current(&root, domain)?;
    if let Some(current) = current.as_ref() {
        if current.fingerprint == inspected.fingerprint {
            return Ok(false);
        }
        let old_expiry = DateTime::parse_from_rfc3339(&current.expires_at)
            .map_err(|_| "invalid current certificate expiry")?
            .with_timezone(&Utc);
        if candidate_expiry <= old_expiry {
            return Err("candidate certificate expiry did not advance".into());
        }
    }

    let generation = next_generation(&root, current.as_ref().map(|value| value.generation))?;
    let generations = root.join("generations");
    ensure_private_dir(&generations)?;
    let staged = generations.join(format!(".{generation}.staging"));
    let final_dir = generations.join(generation.to_string());
    if staged.exists() {
        fs::remove_dir_all(&staged).map_err(|error| error.to_string())?;
    }
    ensure_private_dir(&staged)?;
    write_private_file(
        &staged.join("fullchain.pem"),
        &fs::read(cert_path).map_err(|e| e.to_string())?,
    )?;
    write_private_file(
        &staged.join("privkey.pem"),
        &fs::read(key_path).map_err(|e| e.to_string())?,
    )?;
    validate_bundle_paths(
        &staged.join("fullchain.pem"),
        &staged.join("privkey.pem"),
        domain,
    )?;
    fs::rename(&staged, &final_dir).map_err(|error| error.to_string())?;
    sync_parent(&final_dir).map_err(|error| error.to_string())?;

    let metadata = CurrentCertificate {
        generation,
        domain: domain.to_string(),
        expires_at: inspected.expires_at,
        fingerprint: inspected.fingerprint,
    };
    if let Some(current) = current.as_ref() {
        write_json_private(&root.join("current.backup.json"), current)?;
    } else {
        remove_regular_file(&root.join("current.backup.json"));
    }
    write_json_private(&root.join("current.json.tmp"), &metadata)?;
    fs::rename(root.join("current.json.tmp"), root.join("current.json"))
        .map_err(|error| error.to_string())?;
    sync_parent(&root.join("current.json")).map_err(|error| error.to_string())?;
    cleanup_generations(&root, &metadata)?;
    Ok(true)
}

struct InspectedCertificate {
    expires_at: String,
    fingerprint: String,
}

fn validate_bundle_paths(
    cert_path: &Path,
    key_path: &Path,
    domain: &str,
) -> Result<InspectedCertificate, String> {
    validate_private_file(cert_path, false)?;
    validate_private_file(key_path, true)?;
    let bytes = fs::read(cert_path).map_err(|_| "certificate is unavailable")?;
    let (_, pem) = parse_x509_pem(&bytes).map_err(|_| "invalid certificate PEM")?;
    let (_, certificate) =
        X509Certificate::from_der(&pem.contents).map_err(|_| "invalid certificate DER")?;
    let sans = certificate
        .subject_alternative_name()
        .map_err(|_| "certificate SAN unavailable")?
        .ok_or("certificate has no SAN")?;
    if !sans.value.general_names.iter().any(|name| {
        matches!(name, GeneralName::DNSName(value) if relay_shared::reconciliation::certificate_domain_covers_sni(value, domain))
    }) {
        return Err("certificate SAN does not match certificate scope".into());
    }
    let now = Utc::now().timestamp();
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    if not_before > now || not_after <= now || not_after <= not_before {
        return Err("certificate validity window is not currently usable".into());
    }
    cert_key_match(cert_path, key_path)?;
    let expires_at = DateTime::<Utc>::from_timestamp(not_after, 0)
        .ok_or("invalid certificate expiry")?
        .to_rfc3339();
    Ok(InspectedCertificate {
        expires_at,
        fingerprint: hex::encode(Sha256::digest(&pem.contents)),
    })
}

fn cert_key_match(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    let cert = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert_path)
        .args(["-pubkey", "-noout"])
        .output()
        .map_err(|error| error.to_string())?;
    let key = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key_path)
        .args(["-pubout"])
        .output()
        .map_err(|error| error.to_string())?;
    if !cert.status.success()
        || !key.status.success()
        || normalize_pem(&cert.stdout) != normalize_pem(&key.stdout)
    {
        return Err("certificate and private key do not match".into());
    }
    Ok(())
}

fn normalize_pem(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

fn recover_current(root: &Path, domain: &str) -> Result<Option<CurrentCertificate>, String> {
    match read_and_validate_current(root, &root.join("current.json"), domain) {
        Ok(current) => return Ok(Some(current)),
        Err(error) if error == "missing" => {}
        Err(error) => tracing::warn!(domain, "Panel current certificate is invalid: {error}"),
    }
    match read_and_validate_current(root, &root.join("current.backup.json"), domain) {
        Ok(backup) => {
            write_json_private(&root.join("current.json"), &backup)?;
            Ok(Some(backup))
        }
        Err(error) if error == "missing" => Ok(None),
        Err(error) => {
            tracing::warn!(domain, "Panel certificate backup is invalid: {error}");
            Ok(None)
        }
    }
}

fn read_and_validate_current(
    root: &Path,
    path: &Path,
    domain: &str,
) -> Result<CurrentCertificate, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("missing".into()),
        Err(error) => return Err(error.to_string()),
    };
    let current: CurrentCertificate =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if current.generation == 0 || current.domain != domain {
        return Err("invalid current certificate metadata".into());
    }
    let generation = root
        .join("generations")
        .join(current.generation.to_string());
    let inspected = validate_bundle_paths(
        &generation.join("fullchain.pem"),
        &generation.join("privkey.pem"),
        domain,
    )?;
    if inspected.fingerprint != current.fingerprint || inspected.expires_at != current.expires_at {
        return Err("current certificate metadata mismatch".into());
    }
    Ok(current)
}

fn renewal_due(current: &CurrentCertificate) -> bool {
    DateTime::parse_from_rfc3339(&current.expires_at)
        .map(|expires| {
            expires.with_timezone(&Utc) <= Utc::now() + ChronoDuration::days(RENEW_BEFORE_DAYS)
        })
        .unwrap_or(true)
}

fn scope_root(state_dir: &Path, group_id: i64, domain: &str) -> PathBuf {
    state_dir
        .join("groups")
        .join(group_id.to_string())
        .join("scopes")
        .join(scope_id(domain))
}

fn scope_id(domain: &str) -> String {
    hex::encode(Sha256::digest(
        domain.trim().trim_end_matches('.').to_ascii_lowercase(),
    ))
}

fn next_generation(root: &Path, current: Option<u64>) -> Result<u64, String> {
    let mut highest = current.unwrap_or_default();
    match fs::read_dir(root.join("generations")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Some(value) = entry
                    .file_name()
                    .to_str()
                    .and_then(|value| value.parse().ok())
                {
                    highest = highest.max(value);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    highest
        .checked_add(1)
        .filter(|value| *value > 0)
        .ok_or_else(|| "Panel certificate generation overflow".to_string())
}

fn cleanup_generations(root: &Path, current: &CurrentCertificate) -> Result<(), String> {
    let backup = read_json::<CurrentCertificate>(&root.join("current.backup.json")).ok();
    let keep: HashSet<u64> = HashSet::from_iter(
        [
            Some(current.generation),
            backup.map(|value| value.generation),
        ]
        .into_iter()
        .flatten(),
    );
    let generations = root.join("generations");
    let entries = match fs::read_dir(&generations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let generation = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u64>().ok());
        if generation.is_some_and(|value| !keep.contains(&value)) && path.is_dir() {
            fs::remove_dir_all(path).map_err(|error| error.to_string())?;
        }
    }
    sync_parent(&generations).map_err(|error| error.to_string())
}

fn retry_due(root: &Path) -> Result<bool, String> {
    match read_json::<RetryState>(&root.join("retry.json")) {
        Ok(retry) => Ok(Utc::now().timestamp_millis() >= retry.next_retry_unix_ms),
        Err(error) if error == "missing" => Ok(true),
        Err(error) => {
            tracing::warn!(
                "Panel certificate retry state is invalid; applying one-hour backoff: {error}"
            );
            write_json_private(
                &root.join("retry.json"),
                &RetryState {
                    attempt: RETRY_DELAYS_SECS.len(),
                    next_retry_unix_ms: Utc::now().timestamp_millis().saturating_add(3_600_000),
                },
            )?;
            Ok(false)
        }
    }
}

fn schedule_retry_before_attempt(root: &Path) -> Result<(), String> {
    ensure_private_dir(root)?;
    let previous = read_json::<RetryState>(&root.join("retry.json")).ok();
    let attempt = previous.map(|value| value.attempt).unwrap_or_default();
    let index = attempt.min(RETRY_DELAYS_SECS.len().saturating_sub(1));
    let delay = RETRY_DELAYS_SECS.get(index).copied().unwrap_or(3_600);
    write_json_private(
        &root.join("retry.json"),
        &RetryState {
            attempt: attempt.saturating_add(1),
            next_retry_unix_ms: Utc::now()
                .timestamp_millis()
                .saturating_add(delay.saturating_mul(1_000)),
        },
    )
}

fn clear_retry(root: &Path) {
    remove_regular_file(&root.join("retry.json"));
}

fn resolve_certbot_source(path: &Path, config_dir: &Path) -> Result<PathBuf, String> {
    let resolved = fs::canonicalize(path).map_err(|_| "Certbot candidate is unavailable")?;
    let config = fs::canonicalize(config_dir).map_err(|_| "Certbot config is unavailable")?;
    if !path.starts_with(config_dir) || !resolved.starts_with(config) {
        return Err("Certbot candidate escaped configured certificate directory".into());
    }
    Ok(resolved)
}

fn challenge_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    if domain.is_empty() || domain.contains('*') {
        return Err("challenge domain is invalid".into());
    }
    Ok(domain.to_ascii_lowercase())
}

fn quote_hook_command(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("hook binary path is not UTF-8")?;
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err("invalid hook binary path".into());
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn panel_certbot_hook_command(path: &Path, action: &str) -> Result<String, String> {
    if !matches!(action, "auth" | "cleanup") {
        return Err("invalid hook action".into());
    }
    Ok(format!(
        "/usr/bin/env {} {HOOK_COMMAND} {action}",
        quote_hook_command(path)?
    ))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err("missing".into()),
        Err(error) => Err(error.to_string()),
    }
}

fn write_json_private(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_private_file(path, &bytes)
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("private file has no parent")?;
    ensure_private_dir(parent)?;
    let temp = path.with_extension("tmp-write");
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    drop(file);
    fs::rename(&temp, path).map_err(|error| error.to_string())?;
    sync_parent(path).map_err(|error| error.to_string())
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    if fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("refusing symlink certificate directory".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

fn validate_private_file(path: &Path, key: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "certificate file is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("certificate file must be regular".into());
    }
    if key && metadata.permissions().mode() & 0o077 != 0 {
        return Err("certificate key must be private".into());
    }
    Ok(())
}

fn remove_regular_file(path: &Path) {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file()) {
        let _ = fs::remove_file(path).and_then(|_| sync_parent(path));
    }
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use ::time::{Duration as TimeDuration, OffsetDateTime};
    use axum::extract::{Path as AxumPath, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use rcgen::{CertificateParams, KeyPair};
    use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tokio::sync::Mutex as AsyncMutex;

    static HOOK_ENV_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

    const HOOK_ENV_KEYS: [&str; 10] = [
        "RELAY_PANEL_INTERNAL_URL",
        "RELAY_PANEL_NODE_TOKEN",
        "RELAY_PANEL_CERTIFICATE_ACTOR",
        ISSUANCE_ID_ENV,
        ISSUANCE_GROUP_ENV,
        ISSUANCE_DOMAIN_ENV,
        ISSUANCE_RECEIPT_ENV,
        CERTBOT_HARD_ABORT_ENV,
        "CERTBOT_DOMAIN",
        "CERTBOT_VALIDATION",
    ];

    struct HookEnvGuard {
        previous: Vec<(&'static str, Option<OsString>)>,
        receipt_path: PathBuf,
    }

    impl HookEnvGuard {
        fn set(panel_url: &str) -> Self {
            let previous = HOOK_ENV_KEYS
                .iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect();
            std::env::set_var("RELAY_PANEL_INTERNAL_URL", panel_url);
            std::env::set_var("RELAY_PANEL_NODE_TOKEN", "test-node-token");
            std::env::set_var("RELAY_PANEL_CERTIFICATE_ACTOR", "panel-certificate-test");
            let issuance_id = "01234567-89ab-4def-8123-456789abcdef";
            let receipt_dir = unique_dir("hook-receipt");
            let receipt_path = receipt_dir.join(format!("{issuance_id}.json"));
            std::env::set_var(ISSUANCE_ID_ENV, issuance_id);
            std::env::set_var(ISSUANCE_GROUP_ENV, "7");
            std::env::set_var(ISSUANCE_DOMAIN_ENV, "*.i4ktv.top");
            std::env::set_var(ISSUANCE_RECEIPT_ENV, &receipt_path);
            std::env::remove_var(CERTBOT_HARD_ABORT_ENV);
            std::env::set_var("CERTBOT_DOMAIN", "*.i4ktv.top");
            std::env::set_var("CERTBOT_VALIDATION", "validation-token-123456");
            Self {
                previous,
                receipt_path,
            }
        }
    }

    impl Drop for HookEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            if let Some(parent) = self.receipt_path.parent() {
                let _ = fs::remove_dir_all(parent);
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CapturedHookRequest {
        action: String,
        authorization: Option<String>,
        node_header: Option<String>,
        node_id: String,
        sni: String,
        value: String,
    }

    #[derive(Clone)]
    struct HookMockResponse {
        status: StatusCode,
        body: String,
    }

    #[derive(Clone)]
    struct HookMockState {
        requests: Arc<AsyncMutex<Vec<CapturedHookRequest>>>,
        response: Arc<AsyncMutex<HookMockResponse>>,
    }

    async fn hook_mock_handler(
        AxumPath(action): AxumPath<String>,
        State(state): State<HookMockState>,
        headers: HeaderMap,
        Json(request): Json<AcmeDns01Request>,
    ) -> Response {
        state.requests.lock().await.push(CapturedHookRequest {
            action,
            authorization: headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            node_header: headers
                .get("X-Node-ID")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            node_id: request.node_id,
            sni: request.sni,
            value: request.value,
        });
        let response = state.response.lock().await.clone();
        (response.status, response.body).into_response()
    }

    fn unique_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "panel-certificate-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn candidate(dir: &Path, name: &str, domain: &str, days: i64) -> (PathBuf, PathBuf) {
        let root = dir.join(name);
        ensure_private_dir(&root).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
        params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(days);
        let certificate = params.self_signed(&key).unwrap();
        let cert_path = root.join("fullchain.pem");
        let key_path = root.join("privkey.pem");
        write_private_file(&cert_path, certificate.pem().as_bytes()).unwrap();
        write_private_file(&key_path, key.serialize_pem().as_bytes()).unwrap();
        (cert_path, key_path)
    }

    fn scope(domain: &str, sni: &str) -> GroupCertificateScope {
        GroupCertificateScope {
            domain: domain.into(),
            snis: vec![sni.into()],
        }
    }

    async fn issuance_fixture(
        label: &str,
    ) -> (PanelCertificateManager, DeviceGroup, SqlitePool, PathBuf) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin) VALUES (2, 'owner', 'hash', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'inbound', 'in', 'group-token', 2)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, protocol, \
              public_transport, node_transport, entry_transport, sni, camouflage_enabled) \
             VALUES (100, 'reality', 2, 443, 10, '192.0.2.20', 443, 'tcp', \
                     'nginx_sni', 'nginx_sni', 'nginx_sni', 'b.example.com', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let dir = unique_dir(label);
        ensure_private_dir(&dir).unwrap();
        let marker = dir.join("certbot-called");
        let certbot = dir.join("certbot-mock.sh");
        fs::write(
            &certbot,
            format!(
                "#!/bin/sh\nprintf called > '{}'\nexit 1\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&certbot, fs::Permissions::from_mode(0o700)).unwrap();
        let db: Arc<dyn Repository> = Arc::new(SqliteRepository::new(pool.clone()));
        let group = GroupRepository::find_by_id(db.as_ref(), 10, &ResourceScope::All)
            .await
            .unwrap()
            .unwrap();
        let manager = PanelCertificateManager {
            db,
            state_dir: dir,
            certbot_binary: certbot,
            hook_binary: PathBuf::from("/usr/bin/false"),
            internal_panel_url: "http://127.0.0.1:1".into(),
            check_interval: Duration::from_secs(60),
        };
        (manager, group, pool, marker)
    }

    async fn authorize_fixture_scope(pool: &SqlitePool) {
        sqlx::query(
            "INSERT INTO dns_record_syncs \
             (rule_id, fqdn, record_type, expected_value, line, line_key, desired_action, \
              state, ownership, mutation_verified_at, created_at, updated_at) \
             VALUES (100, 'b.example.com', 'A', '192.0.2.10', 'default', 'default', \
                     'UPSERT', 'MUTATION_VERIFIED', 'PANEL', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00', '2026-09-04 00:00:00')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO dns_record_bindings \
             (rule_id, fqdn, zone_id, zone_name, host, record_type, line, line_key, \
              record_id, desired_value, state, last_observed_at, created_at, updated_at) \
             VALUES (100, 'b.example.com', 7, 'example.com', 'b', 'A', 'default', \
                     'default', 'record-100', '192.0.2.10', 'BOUND', '2026-09-04 00:00:00', \
                     '2026-09-04 00:00:00', '2026-09-04 00:00:00')",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn worker_never_issues_pending_exact_scope_but_reuses_managed_wildcard() {
        let (manager, group, _pool, marker) = issuance_fixture("issuance-pending").await;
        let scopes = manager.certificate_scopes(group.id).await.unwrap();
        assert_eq!(scopes, vec![scope("b.example.com", "b.example.com")]);
        assert!(!manager.reconcile_scope(&group, &scopes[0]).await.unwrap());
        assert!(
            !marker.exists(),
            "pending ownership must not execute Certbot"
        );

        let wildcard = candidate(&manager.state_dir, "wildcard", "*.example.com", 90);
        publish_candidate(
            &manager.state_dir,
            group.id,
            "*.example.com",
            &wildcard.0,
            &wildcard.1,
        )
        .unwrap();
        let scopes = manager.certificate_scopes(group.id).await.unwrap();
        assert_eq!(scopes, vec![scope("*.example.com", "b.example.com")]);
        assert!(!manager.reconcile_scope(&group, &scopes[0]).await.unwrap());
        assert!(
            !marker.exists(),
            "managed certificate reuse must not execute Certbot"
        );
        let _ = fs::remove_dir_all(&manager.state_dir);
    }

    #[tokio::test]
    async fn worker_enters_issuance_only_after_verified_binding() {
        let (manager, group, pool, marker) = issuance_fixture("issuance-authorized").await;
        authorize_fixture_scope(&pool).await;
        let scopes = manager.certificate_scopes(group.id).await.unwrap();
        assert_eq!(scopes, vec![scope("*.example.com", "b.example.com")]);
        assert!(manager.reconcile_scope(&group, &scopes[0]).await.is_err());
        assert!(
            marker.exists(),
            "verified ownership should reach the Certbot invocation"
        );
        let _ = fs::remove_dir_all(&manager.state_dir);
    }

    fn install_fake_successful_certbot(
        manager: &mut PanelCertificateManager,
        cert_path: &Path,
        key_path: &Path,
        write_receipt: bool,
    ) {
        let certificate_name = format!("reality-panel-g10-{}", &scope_id("*.example.com")[..16]);
        let script = manager.state_dir.join(if write_receipt {
            "certbot-with-receipt.sh"
        } else {
            "certbot-without-receipt.sh"
        });
        let receipt = if write_receipt {
            format!(
                r#"cat > "$RELAY_PANEL_CERTIFICATE_AUTHORIZATION_RECEIPT" <<EOF
{{"issuance_id":"$RELAY_PANEL_CERTIFICATE_ISSUANCE_ID","group_id":10,"certificate_domain":"*.example.com","challenge_sni":"example.com","actor":"$RELAY_PANEL_CERTIFICATE_ACTOR","challenge_id":"{}","value_sha256":"{}","state":"propagation_succeeded"}}
EOF
chmod 600 "$RELAY_PANEL_CERTIFICATE_AUTHORIZATION_RECEIPT"
"#,
                "a".repeat(64),
                "b".repeat(64),
            )
        } else {
            String::new()
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\nmkdir -p '{}/acme/config/live/{certificate_name}'\ncp '{}' '{}/acme/config/live/{certificate_name}/fullchain.pem'\ncp '{}' '{}/acme/config/live/{certificate_name}/privkey.pem'\n{receipt}exit 0\n",
                manager.state_dir.display(),
                cert_path.display(),
                manager.state_dir.display(),
                key_path.display(),
                manager.state_dir.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        manager.certbot_binary = script;
    }

    #[tokio::test]
    async fn publish_requires_current_propagation_receipt_even_if_certbot_reports_success() {
        let (mut manager, group, pool, _marker) = issuance_fixture("publish-hard-gate").await;
        authorize_fixture_scope(&pool).await;
        let certificate = candidate(&manager.state_dir, "fake-issued", "*.example.com", 90);
        install_fake_successful_certbot(&mut manager, &certificate.0, &certificate.1, false);
        let scopes = manager.certificate_scopes(group.id).await.unwrap();
        let error = manager
            .reconcile_scope(&group, &scopes[0])
            .await
            .unwrap_err();
        assert!(
            error.contains("authorization receipt"),
            "unexpected error: {error}"
        );
        assert!(recover_current(
            &scope_root(&manager.state_dir, group.id, "*.example.com"),
            "*.example.com"
        )
        .unwrap()
        .is_none());
        let _ = fs::remove_dir_all(&manager.state_dir);
    }

    #[tokio::test]
    async fn propagation_receipt_allows_valid_candidate_to_publish() {
        let (mut manager, group, pool, _marker) = issuance_fixture("publish-authorized").await;
        authorize_fixture_scope(&pool).await;
        let certificate = candidate(&manager.state_dir, "fake-issued", "*.example.com", 90);
        install_fake_successful_certbot(&mut manager, &certificate.0, &certificate.1, true);
        let scopes = manager.certificate_scopes(group.id).await.unwrap();
        assert!(manager.reconcile_scope(&group, &scopes[0]).await.unwrap());
        assert!(recover_current(
            &scope_root(&manager.state_dir, group.id, "*.example.com"),
            "*.example.com"
        )
        .unwrap()
        .is_some());
        let _ = fs::remove_dir_all(&manager.state_dir);
    }

    #[tokio::test]
    async fn managed_wildcard_inventory_is_reused_before_public_a_propagation() {
        let dir = unique_dir("managed-wildcard-reuse");
        let wildcard = candidate(&dir, "wildcard", "*.example.com", 90);
        publish_candidate(&dir, 7, "*.example.com", &wildcard.0, &wildcard.1).unwrap();

        let resolved = resolve_managed_certificate_scopes(
            &dir,
            7,
            vec![scope("b.example.com", "b.example.com")],
        )
        .await
        .unwrap();
        assert_eq!(resolved, vec![scope("*.example.com", "b.example.com")]);
        let manifest = build_group_manifest(&dir, 7, &resolved).unwrap();
        assert_eq!(manifest.response.certificates.len(), 1);
        assert_eq!(manifest.response.certificates[0].domain, "*.example.com");
        assert!(manifest.response.missing_domains.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn managed_inventory_never_guesses_or_reuses_unusable_certificates() {
        let empty = unique_dir("managed-empty");
        let requested = vec![scope("b.example.com", "b.example.com")];
        assert_eq!(
            resolve_managed_certificate_scopes(&empty, 7, requested.clone())
                .await
                .unwrap(),
            requested,
            "without trusted inventory the resolver must not guess a wildcard"
        );

        let wrong = candidate(&empty, "wrong", "*.other.example", 90);
        publish_candidate(&empty, 7, "*.other.example", &wrong.0, &wrong.1).unwrap();
        assert_eq!(
            resolve_managed_certificate_scopes(&empty, 7, requested.clone())
                .await
                .unwrap(),
            requested,
            "a managed certificate that does not cover the SNI is not reusable"
        );

        let wildcard = candidate(&empty, "valid", "*.example.com", 90);
        publish_candidate(&empty, 7, "*.example.com", &wildcard.0, &wildcard.1).unwrap();
        let root = scope_root(&empty, 7, "*.example.com");
        let current = recover_current(&root, "*.example.com").unwrap().unwrap();
        let key_path = root
            .join("generations")
            .join(current.generation.to_string())
            .join("privkey.pem");
        let mismatch = candidate(&empty, "mismatch", "*.example.com", 90);
        fs::copy(mismatch.1, &key_path).unwrap();
        assert_eq!(
            resolve_managed_certificate_scopes(&empty, 7, requested.clone())
                .await
                .unwrap(),
            requested,
            "a key mismatch invalidates the managed inventory entry"
        );

        let expired_dir = unique_dir("managed-expired");
        let expired = candidate(&expired_dir, "expired", "*.example.com", -1);
        let expired_root = scope_root(&expired_dir, 7, "*.example.com");
        let generation = expired_root.join("generations/1");
        ensure_private_dir(&generation).unwrap();
        fs::copy(&expired.0, generation.join("fullchain.pem")).unwrap();
        fs::copy(&expired.1, generation.join("privkey.pem")).unwrap();
        write_json_private(
            &expired_root.join("current.json"),
            &CurrentCertificate {
                generation: 1,
                domain: "*.example.com".into(),
                expires_at: (Utc::now() - ChronoDuration::days(1)).to_rfc3339(),
                fingerprint: "0".repeat(64),
            },
        )
        .unwrap();
        assert_eq!(
            resolve_managed_certificate_scopes(&expired_dir, 7, requested.clone())
                .await
                .unwrap(),
            requested,
            "an expired managed certificate is not reusable"
        );

        let _ = fs::remove_dir_all(empty);
        let _ = fs::remove_dir_all(expired_dir);
    }

    #[test]
    fn publish_starts_at_one_and_advances_only_for_newer_certificate() {
        let dir = unique_dir("generation");
        let first = candidate(&dir, "first", "*.example.com", 60);
        assert!(publish_candidate(&dir, 7, "*.example.com", &first.0, &first.1).unwrap());
        let root = scope_root(&dir, 7, "*.example.com");
        assert_eq!(
            recover_current(&root, "*.example.com")
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        assert!(!publish_candidate(&dir, 7, "*.example.com", &first.0, &first.1).unwrap());

        let second = candidate(&dir, "second", "*.example.com", 90);
        assert!(publish_candidate(&dir, 7, "*.example.com", &second.0, &second.1).unwrap());
        assert_eq!(
            recover_current(&root, "*.example.com")
                .unwrap()
                .unwrap()
                .generation,
            2
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_candidate_keeps_generation_and_backup_recovers_current() {
        let dir = unique_dir("failure-recovery");
        let first = candidate(&dir, "first", "*.example.com", 60);
        publish_candidate(&dir, 9, "*.example.com", &first.0, &first.1).unwrap();
        let root = scope_root(&dir, 9, "*.example.com");
        let bad_key = candidate(&dir, "mismatch", "*.example.com", 90).1;
        assert!(publish_candidate(&dir, 9, "*.example.com", &first.0, &bad_key).is_err());
        assert_eq!(
            recover_current(&root, "*.example.com")
                .unwrap()
                .unwrap()
                .generation,
            1
        );

        let second = candidate(&dir, "second", "*.example.com", 90);
        publish_candidate(&dir, 9, "*.example.com", &second.0, &second.1).unwrap();
        fs::write(root.join("current.json"), b"broken").unwrap();
        assert_eq!(
            recover_current(&root, "*.example.com")
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn certbot_live_symlinks_resolve_to_archive_and_publish_regular_generation() {
        let dir = unique_dir("certbot-live-symlink");
        let source = candidate(&dir, "source", "*.example.com", 90);
        let config_dir = dir.join("config");
        let archive_dir = config_dir.join("archive/test");
        let live_dir = config_dir.join("live/test");
        fs::create_dir_all(&archive_dir).unwrap();
        fs::create_dir_all(&live_dir).unwrap();
        let archive_cert = archive_dir.join("fullchain1.pem");
        let archive_key = archive_dir.join("privkey1.pem");
        fs::copy(&source.0, &archive_cert).unwrap();
        fs::copy(&source.1, &archive_key).unwrap();
        let live_cert = live_dir.join("fullchain.pem");
        let live_key = live_dir.join("privkey.pem");
        symlink("../../archive/test/fullchain1.pem", &live_cert).unwrap();
        symlink("../../archive/test/privkey1.pem", &live_key).unwrap();

        let cert_source = resolve_certbot_source(&live_cert, &config_dir).unwrap();
        let key_source = resolve_certbot_source(&live_key, &config_dir).unwrap();
        assert_eq!(cert_source, fs::canonicalize(&archive_cert).unwrap());
        assert_eq!(key_source, fs::canonicalize(&archive_key).unwrap());
        assert!(cert_source.is_file());
        assert!(key_source.is_file());

        assert!(publish_candidate(&dir, 7, "*.example.com", &cert_source, &key_source,).unwrap());
        let root = scope_root(&dir, 7, "*.example.com");
        let current = recover_current(&root, "*.example.com").unwrap().unwrap();
        let generation = root
            .join("generations")
            .join(current.generation.to_string());
        let published_cert = generation.join("fullchain.pem");
        let published_key = generation.join("privkey.pem");
        assert!(published_cert.is_file());
        assert!(published_key.is_file());
        assert!(!fs::symlink_metadata(&published_cert)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!fs::symlink_metadata(&published_key)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(&published_cert).unwrap(),
            fs::read(&archive_cert).unwrap()
        );
        assert_eq!(
            fs::read(&published_key).unwrap(),
            fs::read(&archive_key).unwrap()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn certbot_source_escape_and_broken_symlinks_are_rejected() {
        let dir = unique_dir("certbot-source-boundary");
        let config_dir = dir.join("config");
        let live_dir = config_dir.join("live/test");
        fs::create_dir_all(&live_dir).unwrap();
        let outside = dir.join("outside.pem");
        fs::write(&outside, b"outside").unwrap();
        let escape = live_dir.join("escape.pem");
        symlink(&outside, &escape).unwrap();
        assert_eq!(
            resolve_certbot_source(&escape, &config_dir).unwrap_err(),
            "Certbot candidate escaped configured certificate directory"
        );

        let broken = live_dir.join("broken.pem");
        symlink("../../archive/test/missing.pem", &broken).unwrap();
        assert_eq!(
            resolve_certbot_source(&broken, &config_dir).unwrap_err(),
            "Certbot candidate is unavailable"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn panel_generation_symlink_remains_rejected_after_certbot_fix() {
        let dir = unique_dir("panel-generation-symlink");
        let source = candidate(&dir, "source", "*.example.com", 90);
        publish_candidate(&dir, 8, "*.example.com", &source.0, &source.1).unwrap();
        let root = scope_root(&dir, 8, "*.example.com");
        let current = recover_current(&root, "*.example.com").unwrap().unwrap();
        let generation = root
            .join("generations")
            .join(current.generation.to_string());
        let outside = dir.join("outside.pem");
        fs::write(
            &outside,
            fs::read(&generation.join("fullchain.pem")).unwrap(),
        )
        .unwrap();
        fs::remove_file(generation.join("fullchain.pem")).unwrap();
        symlink(&outside, generation.join("fullchain.pem")).unwrap();
        assert!(validate_bundle_paths(
            &generation.join("fullchain.pem"),
            &generation.join("privkey.pem"),
            "*.example.com"
        )
        .is_err());
        assert!(recover_current(&root, "*.example.com").unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unusable_pointers_become_missing_and_invalid_retry_gets_bounded_backoff() {
        let dir = unique_dir("corrupt-state");
        let root = scope_root(&dir, 11, "*.example.com");
        ensure_private_dir(&root).unwrap();
        fs::write(root.join("current.json"), b"broken").unwrap();
        fs::write(root.join("current.backup.json"), b"also-broken").unwrap();
        assert!(recover_current(&root, "*.example.com").unwrap().is_none());

        fs::write(root.join("retry.json"), b"broken").unwrap();
        assert!(!retry_due(&root).unwrap());
        let retry: RetryState = read_json(&root.join("retry.json")).unwrap();
        assert!(retry.next_retry_unix_ms > Utc::now().timestamp_millis());
        assert!(retry.next_retry_unix_ms <= Utc::now().timestamp_millis() + 3_601_000);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn internal_hook_url_handles_ipv4_and_ipv6_listeners() {
        assert_eq!(
            internal_panel_url("0.0.0.0:18888").unwrap(),
            "http://127.0.0.1:18888"
        );
        assert_eq!(
            internal_panel_url("[::]:18888").unwrap(),
            "http://[::1]:18888"
        );
    }

    #[test]
    fn certbot_hooks_start_with_env_and_preserve_shell_quoting() {
        let simple = Path::new("/opt/relay-panel/current/relay-panel");
        assert_eq!(
            panel_certbot_hook_command(simple, "auth").unwrap(),
            "/usr/bin/env '/opt/relay-panel/current/relay-panel' acme-dns01-hook auth"
        );
        assert_eq!(
            panel_certbot_hook_command(simple, "cleanup").unwrap(),
            "/usr/bin/env '/opt/relay-panel/current/relay-panel' acme-dns01-hook cleanup"
        );

        let quoted = Path::new("/opt/Reality Panel/panel's binary");
        assert_eq!(
            panel_certbot_hook_command(quoted, "auth").unwrap(),
            "/usr/bin/env '/opt/Reality Panel/panel'\\''s binary' acme-dns01-hook auth"
        );
        assert!(panel_certbot_hook_command(simple, "unexpected").is_err());
    }

    #[tokio::test]
    async fn run_hook_uses_existing_runtime_and_preserves_http_contract() {
        let _env_lock = HOOK_ENV_LOCK.lock().await;
        let state = HookMockState {
            requests: Arc::new(AsyncMutex::new(Vec::new())),
            response: Arc::new(AsyncMutex::new(HookMockResponse {
                status: StatusCode::OK,
                body: format!(
                    r#"{{"challenge_id":"{}","state":"presented"}}"#,
                    "a".repeat(64)
                ),
            })),
        };
        let app = Router::new()
            .route("/api/v1/node/acme-dns01/{action}", post(hook_mock_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let panel_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let _env = HookEnvGuard::set(&panel_url);

        run_hook(&[HOOK_COMMAND.into(), "auth".into()])
            .await
            .unwrap();
        run_hook(&[HOOK_COMMAND.into(), "cleanup".into()])
            .await
            .unwrap();

        let attempt = IssuanceAttempt {
            issuance_id: "01234567-89ab-4def-8123-456789abcdef".into(),
            group_id: 7,
            certificate_domain: "*.i4ktv.top".into(),
            challenge_sni: "i4ktv.top".into(),
            actor: "panel-certificate-test".into(),
            receipt_path: _env.receipt_path.clone(),
        };
        validate_issuance_receipt(&_env.receipt_path, &attempt).unwrap();

        let requests = state.requests.lock().await.clone();
        assert_eq!(requests.len(), 2);
        for (request, action) in requests.iter().zip(["present", "cleanup"]) {
            assert_eq!(request.action, action);
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer test-node-token")
            );
            assert_eq!(
                request.node_header.as_deref(),
                Some("panel-certificate-test")
            );
            assert_eq!(request.node_id, "panel-certificate-test");
            assert_eq!(request.sni, "i4ktv.top");
            assert_eq!(request.value, "validation-token-123456");
        }

        *state.response.lock().await = HookMockResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: r#"{"code":"MOCK_UNAVAILABLE"}"#.into(),
        };
        let error = run_hook(&[HOOK_COMMAND.into(), "auth".into()])
            .await
            .unwrap_err();
        assert_eq!(
            error,
            "Panel challenge request returned HTTP 503 code MOCK_UNAVAILABLE"
        );

        *state.response.lock().await = HookMockResponse {
            status: StatusCode::OK,
            body: "x".repeat(MAX_HOOK_RESPONSE_BYTES + 1),
        };
        assert_eq!(
            run_hook(&[HOOK_COMMAND.into(), "cleanup".into()])
                .await
                .unwrap_err(),
            "Panel challenge response is too large"
        );

        server.abort();
        let _ = server.await;
    }
}
