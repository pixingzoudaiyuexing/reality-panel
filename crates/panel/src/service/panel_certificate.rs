use crate::config::Config;
use crate::db::repo::{GroupRepository, ResourceScope};
use crate::db::Repository;
use crate::service::acme_dns01::AcmeDns01Request;
use crate::service::node_config::{certificate_scopes_for_group, GroupCertificateScope};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use relay_shared::models::DeviceGroup;
use relay_shared::protocol::{NodeCertificatesResponse, PanelCertificateBundle};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
const RETRY_DELAYS_SECS: &[i64] = &[30, 120, 300, 900, 1_800, 3_600];
static CERTIFICATE_ISSUANCE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

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
        let scopes = certificate_scopes_for_group(self.db.as_ref(), group_id)
            .await
            .map_err(|error| error.to_string())?;
        let state_dir = self.state_dir.clone();
        tokio::task::spawn_blocking(move || build_group_manifest(&state_dir, group_id, &scopes))
            .await
            .map_err(|error| error.to_string())?
    }

    async fn reconcile_all(&self) {
        let groups = match GroupRepository::list_groups(self.db.as_ref(), &ResourceScope::All).await
        {
            Ok(groups) => groups,
            Err(error) => {
                tracing::error!("panel certificate: group discovery failed: {error}");
                return;
            }
        };
        for group in groups.into_iter().filter(|group| group.group_type == "in") {
            let scopes = match certificate_scopes_for_group(self.db.as_ref(), group.id).await {
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
                if let Err(error) = self.reconcile_scope(&group, &scope).await {
                    tracing::warn!(
                        group_id = group.id,
                        domain = %scope.domain,
                        "panel certificate reconcile failed: {error}"
                    );
                }
            }
        }
    }

    async fn reconcile_scope(
        &self,
        group: &DeviceGroup,
        scope: &GroupCertificateScope,
    ) -> Result<(), String> {
        let scope_root = scope_root(&self.state_dir, group.id, &scope.domain);
        let current = recover_current(&scope_root, &scope.domain)?;
        if current
            .as_ref()
            .is_some_and(|current| !renewal_due(current))
        {
            clear_retry(&scope_root);
            return Ok(());
        }
        if !retry_due(&scope_root)? {
            return Ok(());
        }
        let issuance_lock = CERTIFICATE_ISSUANCE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
        let _issuance_guard = issuance_lock.lock().await;
        let current = recover_current(&scope_root, &scope.domain)?;
        if current
            .as_ref()
            .is_some_and(|current| !renewal_due(current))
        {
            clear_retry(&scope_root);
            return Ok(());
        }
        if !retry_due(&scope_root)? {
            return Ok(());
        }
        schedule_retry_before_attempt(&scope_root)?;

        let manager = self.clone();
        let group_id = group.id;
        let token = group.token.clone();
        let domain = scope.domain.clone();
        let current_for_issue = current.clone();
        let issued = tokio::task::spawn_blocking(move || {
            manager.issue_and_publish(group_id, &token, &domain, current_for_issue.as_ref())
        })
        .await
        .map_err(|error| error.to_string())??;
        if issued {
            tracing::info!(group_id, domain = %scope.domain, "published Panel certificate generation");
        }
        clear_retry(&scope_root);
        Ok(())
    }

    fn issue_and_publish(
        &self,
        group_id: i64,
        token: &str,
        domain: &str,
        current: Option<&CurrentCertificate>,
    ) -> Result<bool, String> {
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
        let hook = quote_hook_command(&self.hook_binary)?;
        let mut args = vec![
            "certonly".to_string(),
            "--non-interactive".to_string(),
            "--agree-tos".to_string(),
            "--manual".to_string(),
            "--preferred-challenges".to_string(),
            "dns".to_string(),
            "--manual-auth-hook".to_string(),
            format!("{hook} {HOOK_COMMAND} auth"),
            "--manual-cleanup-hook".to_string(),
            format!("{hook} {HOOK_COMMAND} cleanup"),
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
        let output = Command::new(&self.certbot_binary)
            .args(&args)
            .env("RELAY_PANEL_INTERNAL_URL", &self.internal_panel_url)
            .env("RELAY_PANEL_NODE_TOKEN", token)
            .env("RELAY_PANEL_CERTIFICATE_ACTOR", actor)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("cannot run Certbot: {error}"))?;
        if !output.status.success() {
            return Err(
                "Panel ACME certificate command failed; retained current generation".into(),
            );
        }

        let live = config_dir.join("live").join(certificate_name);
        let cert_path = live.join("fullchain.pem");
        let key_path = live.join("privkey.pem");
        validate_certbot_source(&cert_path, &config_dir)?;
        validate_certbot_source(&key_path, &config_dir)?;
        publish_candidate(&self.state_dir, group_id, domain, &cert_path, &key_path)
    }
}

pub fn spawn(manager: PanelCertificateManager) {
    tokio::spawn(async move {
        // HTTP listener先开始服务，Certbot manual hook才能通过本机现有端口复用
        // Panel DNS-01。该等待不创建新调度器，之后仍只有一个顺序worker。
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut ticker = tokio::time::interval(manager.check_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            manager.reconcile_all().await;
        }
    });
}

pub fn is_hook_command(args: &[String]) -> bool {
    args.first().is_some_and(|value| value == HOOK_COMMAND)
}

pub fn run_hook(args: &[String]) -> Result<(), String> {
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "hook runtime is unavailable")?;
    runtime.block_on(async move {
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
                node_id,
                sni,
                value,
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
    })
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

fn validate_certbot_source(path: &Path, config_dir: &Path) -> Result<(), String> {
    let resolved = fs::canonicalize(path).map_err(|_| "Certbot candidate is unavailable")?;
    let config = fs::canonicalize(config_dir).map_err(|_| "Certbot config is unavailable")?;
    if !path.starts_with(config_dir) || !resolved.starts_with(config) {
        return Err("Certbot candidate escaped configured certificate directory".into());
    }
    Ok(())
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
    use ::time::{Duration as TimeDuration, OffsetDateTime};
    use rcgen::{CertificateParams, KeyPair};

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
}
