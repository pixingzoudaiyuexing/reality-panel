//! Node-local ACME certificate lifecycle for TLS camouflage sites.
//!
//! Certbot only produces a candidate. This module validates and installs a
//! private generation, while `CamouflageSiteManager` transactionally activates
//! the resulting :8443 vhost and advances its independent site LKG.

use super::camouflage_site::{CamouflageSite, CamouflageSitesManifest, CertificateReference};
use super::nginx_sni::{self, NginxSniConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

const DEFAULT_RENEW_BEFORE_DAYS: u32 = 30;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateLifecyclePolicy {
    /// Must exactly match the local TLS camouflage SNI.
    pub domain: String,
    #[serde(default)]
    pub email: Option<String>,
    pub expected_public_ip: String,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

fn default_renew_before_days() -> u32 {
    DEFAULT_RENEW_BEFORE_DAYS
}

#[derive(Clone, Debug)]
pub struct CertificateLifecycleConfig {
    pub enabled: bool,
    pub certbot_binary: PathBuf,
    pub certbot_live_dir: PathBuf,
    pub webroot: PathBuf,
    pub state_dir: PathBuf,
    pub http01_nginx: NginxSniConfig,
}

impl CertificateLifecycleConfig {
    #[cfg(test)]
    pub(crate) fn disabled_for_test(dir: &Path) -> Self {
        Self {
            enabled: false,
            certbot_binary: PathBuf::from("/bin/true"),
            certbot_live_dir: dir.join("letsencrypt/live"),
            webroot: dir.join("webroot"),
            state_dir: dir.join("certificates"),
            http01_nginx: NginxSniConfig {
                enabled: false,
                conf_path: dir.join("acme.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleAction {
    Unchanged,
    Issued,
    Renewed,
}

/// Local-only guard for scheduler work. A failed renewal drops its lease, so a
/// later tick can retry; concurrent work for the same camouflage site cannot
/// invoke Certbot twice.
#[derive(Debug, Default)]
pub(crate) struct RenewalGate {
    running: Mutex<HashSet<String>>,
}

pub(crate) struct RenewalLease<'a> {
    gate: &'a RenewalGate,
    site_ids: Vec<String>,
}

impl RenewalGate {
    pub(crate) fn try_acquire(&self, site_ids: Vec<String>) -> Option<RenewalLease<'_>> {
        let mut running = self.running.lock().ok()?;
        if site_ids.iter().any(|site_id| running.contains(site_id)) {
            return None;
        }
        for site_id in &site_ids {
            running.insert(site_id.clone());
        }
        Some(RenewalLease {
            gate: self,
            site_ids,
        })
    }
}

impl Drop for RenewalLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut running) = self.gate.running.lock() {
            for site_id in &self.site_ids {
                running.remove(site_id);
            }
        }
    }
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &Path, args: &[String]) -> Result<Output, String>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &Path, args: &[String]) -> Result<Output, String> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| error.to_string())
    }
}

pub struct CertificateLifecycle<R = SystemCommandRunner> {
    config: CertificateLifecycleConfig,
    runner: R,
}

impl CertificateLifecycle<SystemCommandRunner> {
    pub fn new(config: CertificateLifecycleConfig) -> Self {
        Self {
            config,
            runner: SystemCommandRunner,
        }
    }
}

impl<R: CommandRunner> CertificateLifecycle<R> {
    #[cfg(test)]
    fn with_runner(config: CertificateLifecycleConfig, runner: R) -> Self {
        Self { config, runner }
    }

    /// Returns a candidate manifest. The caller owns Nginx activation and LKG
    /// commit, ensuring lifecycle failures never replace a healthy runtime.
    pub fn reconcile(
        &self,
        source: &CamouflageSitesManifest,
    ) -> Result<(CamouflageSitesManifest, Vec<LifecycleAction>), String> {
        self.reconcile_with_dns(source, validate_dns)
    }

    fn reconcile_with_dns<F>(
        &self,
        source: &CamouflageSitesManifest,
        dns_validator: F,
    ) -> Result<(CamouflageSitesManifest, Vec<LifecycleAction>), String>
    where
        F: Fn(&str, &str) -> Result<(), String>,
    {
        if !self.config.enabled {
            return Ok((
                source.clone(),
                vec![LifecycleAction::Unchanged; source.sites.len()],
            ));
        }
        if !self.config.http01_nginx.enabled {
            return Err("certificate lifecycle requires managed Nginx for HTTP-01".into());
        }
        ensure_private_dir(&self.config.state_dir)?;
        ensure_directory(&self.config.webroot, 0o755)?;
        self.prepare_http01(source)?;

        let mut manifest = source.clone();
        let mut actions = Vec::with_capacity(manifest.sites.len());
        for site in &mut manifest.sites {
            let Some(policy) = site.certificate.lifecycle.clone() else {
                actions.push(LifecycleAction::Unchanged);
                continue;
            };
            validate_policy(site, &policy)?;
            dns_validator(&policy.domain, &policy.expected_public_ip)?;

            let active = site.certificate.clone();
            if validate_candidate(
                &active,
                &policy.domain,
                policy.renew_before_days,
                &self.runner,
                false,
            )
            .is_ok()
            {
                actions.push(LifecycleAction::Unchanged);
                continue;
            }

            let installed_root = self.config.state_dir.join("generations").join(&site.id);
            let renew = active.cert_path.starts_with(&installed_root)
                && has_certbot_renewal_config(&self.config.certbot_live_dir, &policy.domain)?;
            self.invoke_certbot(&policy, renew)?;

            let candidate = CertificateReference {
                cert_path: self
                    .config
                    .certbot_live_dir
                    .join(&policy.domain)
                    .join("fullchain.pem"),
                key_path: self
                    .config
                    .certbot_live_dir
                    .join(&policy.domain)
                    .join("privkey.pem"),
                lifecycle: Some(policy.clone()),
            };
            validate_certbot_source(&candidate, &self.config.certbot_live_dir)?;
            // Fresh candidates must be currently valid, but can be inside the
            // old generation's renewal window.
            validate_candidate(&candidate, &policy.domain, 0, &self.runner, true)?;
            site.certificate =
                install_candidate(&candidate, &self.config.state_dir, &site.id, &policy)?;
            actions.push(if renew {
                LifecycleAction::Renewed
            } else {
                LifecycleAction::Issued
            });
        }
        Ok((manifest, actions))
    }

    fn prepare_http01(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        let domains: Vec<&str> = manifest
            .sites
            .iter()
            .filter_map(|site| {
                site.certificate
                    .lifecycle
                    .as_ref()
                    .map(|policy| policy.domain.as_str())
            })
            .collect();
        if domains.is_empty() {
            return Ok(());
        }
        let rendered = render_http01_vhost(&domains, &self.config.webroot)?;
        nginx_sni::apply_rendered(rendered.as_bytes(), &self.config.http01_nginx)
            .map_err(|_| "HTTP-01 Nginx preflight failed (port 80 may be unavailable)".to_string())
    }

    fn invoke_certbot(
        &self,
        policy: &CertificateLifecyclePolicy,
        renew: bool,
    ) -> Result<(), String> {
        validate_absolute_path(&self.config.certbot_binary, "Certbot binary")?;
        reject_symlink(&self.config.certbot_binary)?;
        let output = self.runner.run(
            &self.config.certbot_binary,
            &certbot_args(policy, renew, &self.config.webroot),
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err("ACME certificate command failed; retained existing certificate".into())
        }
    }
}

fn certbot_args(policy: &CertificateLifecyclePolicy, renew: bool, webroot: &Path) -> Vec<String> {
    if renew {
        return vec![
            "renew".into(),
            "--non-interactive".into(),
            "--no-random-sleep-on-renew".into(),
            "--force-renewal".into(),
            "--cert-name".into(),
            policy.domain.clone(),
        ];
    }
    let mut args = vec![
        "certonly".into(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--webroot".into(),
        "--webroot-path".into(),
        webroot.display().to_string(),
        "--cert-name".into(),
        policy.domain.clone(),
        "-d".into(),
        policy.domain.clone(),
    ];
    match &policy.email {
        Some(email) => args.extend(["--email".into(), email.clone()]),
        None => args.push("--register-unsafely-without-email".into()),
    }
    args
}

fn has_certbot_renewal_config(live_dir: &Path, domain: &str) -> Result<bool, String> {
    let parent = live_dir
        .parent()
        .ok_or_else(|| "invalid Certbot live directory".to_string())?;
    let path = parent.join("renewal").join(format!("{domain}.conf"));
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("Certbot renewal configuration must not be a symlink".into())
        }
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "cannot inspect Certbot renewal configuration: {error}"
        )),
    }
}

fn validate_policy(
    site: &CamouflageSite,
    policy: &CertificateLifecyclePolicy,
) -> Result<(), String> {
    if policy.domain != site.sni || !is_valid_domain(&policy.domain) {
        return Err("certificate domain must exactly match camouflage SNI".into());
    }
    if let Some(email) = &policy.email {
        if !email.contains('@') || email.len() > 254 {
            return Err("invalid ACME contact email".into());
        }
    }
    if !(1..=365).contains(&policy.renew_before_days) {
        return Err("invalid renewal threshold".into());
    }
    policy
        .expected_public_ip
        .parse::<IpAddr>()
        .map_err(|_| "invalid expected public IP".to_string())?;
    Ok(())
}

fn validate_dns(domain: &str, expected: &str) -> Result<(), String> {
    let expected: IpAddr = expected.parse().map_err(|_| "invalid expected public IP")?;
    let resolved: Vec<IpAddr> = (domain, 443)
        .to_socket_addrs()
        .map_err(|_| "DNS lookup failed")?
        .map(|address| address.ip())
        .collect();
    if resolved.iter().any(|address| *address == expected) {
        Ok(())
    } else {
        Err("DNS does not resolve the certificate domain to this node".into())
    }
}

fn render_http01_vhost(domains: &[&str], webroot: &Path) -> Result<String, String> {
    validate_absolute_path(webroot, "HTTP-01 webroot")?;
    let mut out = String::from("# generated by relay-node; ACME HTTP-01 only\nserver {\n    listen 80;\n    listen [::]:80;\n    server_name");
    for domain in domains {
        if !is_valid_domain(domain) {
            return Err("invalid HTTP-01 domain".into());
        }
        out.push_str(&format!(" {domain}"));
    }
    out.push_str(&format!(
        ";\n    location ^~ /.well-known/acme-challenge/ {{ root {}; default_type text/plain; }}\n    location / {{ return 404; }}\n}}\n",
        quote_nginx_path(webroot)?
    ));
    Ok(out)
}

fn validate_candidate<R: CommandRunner>(
    reference: &CertificateReference,
    domain: &str,
    renew_before_days: u32,
    runner: &R,
    allow_source_symlinks: bool,
) -> Result<(), String> {
    validate_certificate_pem(
        &reference.cert_path,
        domain,
        renew_before_days,
        allow_source_symlinks,
    )?;
    validate_private_key(&reference.key_path, allow_source_symlinks)?;
    let cert = runner.run(
        Path::new("openssl"),
        &[
            "x509".into(),
            "-in".into(),
            reference.cert_path.display().to_string(),
            "-pubkey".into(),
            "-noout".into(),
        ],
    )?;
    let key = runner.run(
        Path::new("openssl"),
        &[
            "pkey".into(),
            "-in".into(),
            reference.key_path.display().to_string(),
            "-pubout".into(),
        ],
    )?;
    if !cert.status.success()
        || !key.status.success()
        || normalize_pem(&cert.stdout) != normalize_pem(&key.stdout)
    {
        return Err("certificate and private key do not match".into());
    }
    Ok(())
}

fn validate_certificate_pem(
    path: &Path,
    domain: &str,
    renew_before_days: u32,
    allow_symlink: bool,
) -> Result<(), String> {
    validate_absolute_path(path, "certificate")?;
    if !allow_symlink {
        reject_symlink(path)?;
    }
    let data = fs::read(path).map_err(|_| "certificate is unavailable")?;
    let (_, pem) = parse_x509_pem(&data).map_err(|_| "invalid certificate PEM")?;
    let (_, certificate) =
        X509Certificate::from_der(&pem.contents).map_err(|_| "invalid certificate DER")?;
    validate_certificate_validity(
        &certificate,
        domain,
        renew_before_days,
        current_unix_seconds()?,
    )
}

fn validate_certificate_validity(
    certificate: &X509Certificate<'_>,
    domain: &str,
    renew_before_days: u32,
    now: i64,
) -> Result<(), String> {
    let sans = certificate
        .subject_alternative_name()
        .map_err(|_| "certificate SAN unavailable")?
        .ok_or("certificate has no SAN")?;
    if !sans
        .value
        .general_names
        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(value) if *value == domain))
    {
        return Err("certificate SAN does not match camouflage SNI".into());
    }
    let remaining = certificate.validity().not_after.timestamp() - now;
    if remaining <= Duration::from_secs(u64::from(renew_before_days) * 86_400).as_secs() as i64 {
        return Err("certificate is expired or inside renewal threshold".into());
    }
    Ok(())
}

fn current_unix_seconds() -> Result<i64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?
        .as_secs() as i64)
}

fn validate_private_key(path: &Path, allow_symlink: bool) -> Result<(), String> {
    validate_absolute_path(path, "certificate key")?;
    if !allow_symlink {
        reject_symlink(path)?;
    }
    let metadata = fs::metadata(path).map_err(|_| "certificate key is unavailable")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("certificate key must be mode 0600".into());
    }
    if unsafe { libc::geteuid() } == 0 && metadata.uid() != 0 {
        return Err("certificate key must be root-owned".into());
    }
    Ok(())
}

fn validate_certbot_source(
    reference: &CertificateReference,
    live_dir: &Path,
) -> Result<(), String> {
    let live = fs::canonicalize(live_dir).map_err(|_| "Certbot live directory is unavailable")?;
    let archive = fs::canonicalize(
        live_dir
            .parent()
            .ok_or("Certbot live directory has no parent")?
            .join("archive"),
    )
    .map_err(|_| "Certbot archive directory is unavailable")?;
    for path in [&reference.cert_path, &reference.key_path] {
        let resolved = fs::canonicalize(path).map_err(|_| "Certbot candidate is unavailable")?;
        if !path.starts_with(live_dir)
            || (!resolved.starts_with(&live) && !resolved.starts_with(&archive))
        {
            return Err("Certbot candidate escaped configured certificate directories".into());
        }
    }
    Ok(())
}

fn install_candidate(
    candidate: &CertificateReference,
    state_dir: &Path,
    site_id: &str,
    policy: &CertificateLifecyclePolicy,
) -> Result<CertificateReference, String> {
    if !is_safe_id(site_id) {
        return Err("invalid camouflage site id".into());
    }
    let generations = state_dir.join("generations").join(site_id);
    ensure_private_dir(&generations)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?
        .as_nanos();
    let generation = generations.join(format!("generation-{stamp}"));
    ensure_private_dir(&generation)?;
    let cert_path = generation.join("fullchain.pem");
    let key_path = generation.join("privkey.pem");
    copy_private_file(&candidate.cert_path, &cert_path)?;
    copy_private_file(&candidate.key_path, &key_path)?;
    validate_private_key(&key_path, false)?;
    Ok(CertificateReference {
        cert_path,
        key_path,
        lifecycle: Some(policy.clone()),
    })
}

fn copy_private_file(source: &Path, destination: &Path) -> Result<(), String> {
    write_private_file(
        destination,
        &fs::read(source).map_err(|error| error.to_string())?,
    )
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    validate_absolute_path(path, "private file")?;
    reject_symlink(path)?;
    let parent = path.parent().ok_or("file has no parent")?;
    ensure_private_dir(parent)?;
    let temp = appended_temp_path(path);
    reject_symlink(&temp)?;
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
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
    if let Err(error) = fs::rename(&temp, path).and_then(|_| sync_parent(path)) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    ensure_directory(path, 0o700)
}

fn ensure_directory(path: &Path, mode: u32) -> Result<(), String> {
    validate_absolute_path(path, "directory")?;
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    reject_symlink(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err("refusing symlink path".into()),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn validate_absolute_path(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(format!("{name} path must be absolute without traversal"));
    }
    Ok(())
}

fn appended_temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    File::open(path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file has no parent")
    })?)?
    .sync_all()
}

fn quote_nginx_path(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("non-UTF8 path")?;
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn normalize_pem(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn is_valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeRunner(Mutex<VecDeque<Output>>);

    impl CommandRunner for FakeRunner {
        fn run(&self, _: &Path, _: &[String]) -> Result<Output, String> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "unexpected command".into())
        }
    }

    fn output(ok: bool, stdout: &[u8]) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(if ok { 0 } else { 1 }),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    fn unique_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-panel-cert-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn write_test_certificate(dir: &Path, names: Vec<String>) -> (PathBuf, PathBuf) {
        use rcgen::{CertificateParams, KeyPair};
        ensure_private_dir(dir).unwrap();
        let params = CertificateParams::new(names).unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let cert_path = dir.join("fullchain.pem");
        let key_path = dir.join("privkey.pem");
        write_private_file(&cert_path, certificate.pem().as_bytes()).unwrap();
        write_private_file(&key_path, key.serialize_pem().as_bytes()).unwrap();
        (cert_path, key_path)
    }

    fn policy(domain: &str) -> CertificateLifecyclePolicy {
        CertificateLifecyclePolicy {
            domain: domain.into(),
            email: Some("ops@example.com".into()),
            expected_public_ip: "127.0.0.1".into(),
            renew_before_days: 30,
        }
    }

    fn site(_dir: &Path, reference: CertificateReference) -> CamouflageSite {
        CamouflageSite {
            id: "site".into(),
            sni: "site.example.com".into(),
            tls_listener_port: 8443,
            local_backend: "127.0.0.1:5244".into(),
            certificate: reference,
        }
    }

    #[test]
    fn first_issuance_uses_certonly_without_a_renewal_record() {
        let args = certbot_args(&policy("site.example.com"), false, Path::new("/webroot"));
        assert_eq!(args[0], "certonly");
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-d", "site.example.com"]));
        assert!(!has_certbot_renewal_config(
            Path::new("/definitely/missing/live"),
            "site.example.com"
        )
        .unwrap());
    }

    #[test]
    fn renewal_policy_forces_renewal_independently_of_certbot_default() {
        let args = certbot_args(&policy("site.example.com"), true, Path::new("/unused"));
        assert_eq!(args[0], "renew");
        assert!(args.iter().any(|arg| arg == "--force-renewal"));
    }

    #[test]
    fn pem_san_key_match_and_validity_are_checked() {
        let dir = unique_dir("candidate");
        let (cert_path, key_path) = write_test_certificate(&dir, vec!["site.example.com".into()]);
        let reference = CertificateReference {
            cert_path,
            key_path,
            lifecycle: None,
        };
        let runner = FakeRunner(Mutex::new(VecDeque::from([
            output(true, b"same"),
            output(true, b"same"),
        ])));
        assert!(validate_candidate(&reference, "site.example.com", 0, &runner, false).is_ok());
        assert!(
            validate_certificate_pem(&reference.cert_path, "other.example.com", 0, false).is_err()
        );
        let data = fs::read(&reference.cert_path).unwrap();
        let (_, pem) = parse_x509_pem(&data).unwrap();
        let (_, parsed) = X509Certificate::from_der(&pem.contents).unwrap();
        let near_expiry = parsed.validity().not_after.timestamp() - 60;
        assert!(validate_certificate_validity(&parsed, "site.example.com", 0, near_expiry).is_ok());
        assert!(
            validate_certificate_validity(&parsed, "site.example.com", 1, near_expiry).is_err()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_pem_and_mismatched_key_are_rejected() {
        let dir = unique_dir("invalid");
        ensure_private_dir(&dir).unwrap();
        let invalid = dir.join("invalid.pem");
        write_private_file(&invalid, b"not a certificate").unwrap();
        assert!(validate_certificate_pem(&invalid, "site.example.com", 0, false).is_err());
        let (cert_path, key_path) =
            write_test_certificate(&dir.join("valid"), vec!["site.example.com".into()]);
        let reference = CertificateReference {
            cert_path,
            key_path,
            lifecycle: None,
        };
        let runner = FakeRunner(Mutex::new(VecDeque::from([
            output(true, b"cert"),
            output(true, b"other"),
        ])));
        assert!(validate_candidate(&reference, "site.example.com", 0, &runner, false).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dns_mismatch_is_rejected_before_any_acme_command() {
        let dir = unique_dir("dns");
        let reference = CertificateReference {
            cert_path: dir.join("missing.crt"),
            key_path: dir.join("missing.key"),
            lifecycle: Some(policy("does-not-resolve.invalid")),
        };
        let manifest = CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                sni: "does-not-resolve.invalid".into(),
                ..site(&dir, reference)
            }],
        };
        let config = CertificateLifecycleConfig {
            enabled: true,
            certbot_binary: "/bin/true".into(),
            certbot_live_dir: dir.join("letsencrypt/live"),
            webroot: dir.join("webroot"),
            state_dir: dir.join("state"),
            http01_nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("acme.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        };
        let lifecycle =
            CertificateLifecycle::with_runner(config, FakeRunner(Mutex::new(VecDeque::new())));
        assert!(lifecycle.reconcile(&manifest).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_acme_and_candidate_install_preserve_old_generation() {
        let dir = unique_dir("generation");
        let old = dir.join("state/generations/site/generation-old/fullchain.pem");
        write_private_file(&old, b"old-certificate").unwrap();
        let lifecycle = CertificateLifecycle::with_runner(
            CertificateLifecycleConfig::disabled_for_test(&dir),
            FakeRunner(Mutex::new(VecDeque::from([output(false, b"")]))),
        );
        assert!(lifecycle
            .invoke_certbot(&policy("site.example.com"), true)
            .is_err());
        assert_eq!(fs::read(&old).unwrap(), b"old-certificate");

        let source = dir.join("source");
        let (cert_path, key_path) =
            write_test_certificate(&source, vec!["site.example.com".into()]);
        let installed = install_candidate(
            &CertificateReference {
                cert_path,
                key_path,
                lifecycle: None,
            },
            &dir.join("state"),
            "site",
            &policy("site.example.com"),
        )
        .unwrap();
        assert_ne!(installed.cert_path, old);
        assert_eq!(fs::read(&old).unwrap(), b"old-certificate");
        assert_eq!(
            fs::metadata(installed.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn policy_must_match_camouflage_sni_and_http01_is_injection_safe() {
        let dir = unique_dir("policy");
        let reference = CertificateReference {
            cert_path: dir.join("a.crt"),
            key_path: dir.join("a.key"),
            lifecycle: None,
        };
        let mut candidate = site(&dir, reference);
        assert!(validate_policy(&candidate, &policy("other.example.com")).is_err());
        candidate.sni = "site.example.com".into();
        assert!(render_http01_vhost(&["bad;server"], Path::new("/webroot")).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = unique_dir("symlink");
        let (_, key) = write_test_certificate(&dir, vec!["site.example.com".into()]);
        let link = dir.join("key-link");
        symlink(&key, &link).unwrap();
        assert!(validate_private_key(&link, false).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn successful_renewal_installs_a_new_generation_without_overwriting_old() {
        let dir = unique_dir("renewal");
        let live = dir.join("letsencrypt/live/site.example.com");
        let (cert_path, key_path) = write_test_certificate(&live, vec!["site.example.com".into()]);
        ensure_private_dir(&dir.join("letsencrypt/archive")).unwrap();
        let old_cert = dir.join("state/generations/site/generation-old/fullchain.pem");
        let old_key = dir.join("state/generations/site/generation-old/privkey.pem");
        write_private_file(&old_cert, b"expired-old-certificate").unwrap();
        write_private_file(&old_key, b"expired-old-key").unwrap();
        let renewal = dir.join("letsencrypt/renewal/site.example.com.conf");
        write_private_file(&renewal, b"renewal-config").unwrap();
        let source = CamouflageSitesManifest {
            sites: vec![site(
                &dir,
                CertificateReference {
                    cert_path: old_cert.clone(),
                    key_path: old_key,
                    lifecycle: Some(policy("site.example.com")),
                },
            )],
        };
        let config = CertificateLifecycleConfig {
            enabled: true,
            certbot_binary: "/bin/true".into(),
            certbot_live_dir: dir.join("letsencrypt/live"),
            webroot: dir.join("webroot"),
            state_dir: dir.join("state"),
            http01_nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("acme.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        };
        let lifecycle = CertificateLifecycle::with_runner(
            config,
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b""),
                output(true, b"same"),
                output(true, b"same"),
            ]))),
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| Ok(()))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::Renewed]);
        assert_ne!(candidate.sites[0].certificate.cert_path, old_cert);
        assert_eq!(fs::read(old_cert).unwrap(), b"expired-old-certificate");
        assert_eq!(
            fs::read(candidate.sites[0].certificate.cert_path.clone()).unwrap(),
            fs::read(cert_path).unwrap()
        );
        assert_eq!(
            fs::metadata(candidate.sites[0].certificate.key_path.clone())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read(candidate.sites[0].certificate.key_path.clone()).unwrap(),
            fs::read(key_path).unwrap()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn same_site_renewal_is_serialized_and_failed_work_can_retry() {
        let gate = RenewalGate::default();
        let first = gate.try_acquire(vec!["op1".into()]).unwrap();
        assert!(gate.try_acquire(vec!["op1".into()]).is_none());
        drop(first);
        assert!(gate.try_acquire(vec!["op1".into()]).is_some());
    }
}
