//! Node-local ACME certificate lifecycle for TLS camouflage sites.
//!
//! Certbot only produces a candidate. This module validates and installs a
//! private generation, while `CamouflageSiteManager` transactionally activates
//! the resulting :8443 vhost and advances its independent site LKG.

use super::camouflage_site::{CamouflageSite, CamouflageSitesManifest, CertificateReference};
use super::nginx_sni::{self, NginxSniConfig};
use relay_shared::protocol::AcmeChallengeMethod;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

const DEFAULT_RENEW_BEFORE_DAYS: u32 = 30;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateLifecyclePolicy {
    /// Exact SNI or a one-label DNS-01 wildcard that covers the local SNI.
    pub domain: String,
    #[serde(default)]
    pub email: Option<String>,
    pub expected_public_ip: String,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    #[serde(default)]
    pub challenge_method: AcmeChallengeMethod,
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
    pub dns01_hook_binary: PathBuf,
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
            dns01_hook_binary: PathBuf::from("/opt/relay-node/relay-node"),
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
    RenewalWarning,
}

#[derive(Clone, Debug)]
pub(crate) struct CertificateMetadata {
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
}

pub(crate) fn inspect_certificate(path: &Path) -> Result<CertificateMetadata, String> {
    let data = fs::read(path).map_err(|_| "certificate is unavailable")?;
    let (_, pem) = parse_x509_pem(&data).map_err(|_| "invalid certificate PEM")?;
    let (_, certificate) =
        X509Certificate::from_der(&pem.contents).map_err(|_| "invalid certificate DER")?;
    Ok(CertificateMetadata {
        issuer: certificate.issuer().to_string(),
        valid_from: certificate
            .validity()
            .not_before
            .to_rfc2822()
            .map_err(|_| "invalid certificate not-before")?,
        valid_until: certificate
            .validity()
            .not_after
            .to_rfc2822()
            .map_err(|_| "invalid certificate not-after")?,
    })
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

    pub(crate) fn is_usable(reference: &CertificateReference, domain: &str) -> bool {
        validate_candidate(reference, domain, 0, &SystemCommandRunner, false).is_ok()
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
        self.reconcile_prepared_with_dns(source, validate_dns)
    }

    #[cfg(test)]
    fn reconcile_with_dns<F>(
        &self,
        source: &CamouflageSitesManifest,
        dns_validator: F,
    ) -> Result<(CamouflageSitesManifest, Vec<LifecycleAction>), String>
    where
        F: Fn(&str, &str) -> Result<(), String>,
    {
        self.reconcile_prepared_with_dns(source, dns_validator)
    }

    fn reconcile_prepared_with_dns<F>(
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
        self.ensure_https_redirect()?;
        let outcome = (|| {
            ensure_private_dir(&self.config.state_dir)?;

            let mut manifest = source.clone();
            let mut actions = Vec::with_capacity(manifest.sites.len());
            for site in &mut manifest.sites {
                let Some(policy) = site.certificate.lifecycle.clone() else {
                    actions.push(LifecycleAction::Unchanged);
                    continue;
                };
                validate_policy(site, &policy)?;

                let existing = self.discover_existing(site, &policy)?;
                if let Some(existing) = existing.as_ref() {
                    site.certificate = existing.reference.clone();
                }
                if existing
                    .as_ref()
                    .is_some_and(|existing| !existing.renewal_due)
                {
                    actions.push(LifecycleAction::Unchanged);
                    continue;
                }

                if policy.challenge_method == AcmeChallengeMethod::Http01 {
                    if !self.config.http01_nginx.enabled {
                        return Err(
                            "certificate lifecycle requires managed Nginx for HTTP-01".into()
                        );
                    }
                    dns_validator(&policy.domain, &policy.expected_public_ip)?;
                    let single = CamouflageSitesManifest {
                        sites: vec![site.clone()],
                    };
                    let mut prepared = None;
                    self.prepare_http01_once(&single, &mut prepared)?;
                }

                let renew = existing.is_some();
                if let Err(error) = self.invoke_certbot(&policy, renew) {
                    if existing.is_some() {
                        actions.push(LifecycleAction::RenewalWarning);
                        continue;
                    }
                    return Err(error);
                }

                let candidate = match self.best_certbot_candidate(&policy)? {
                    Some(candidate) => candidate,
                    None if existing.is_some() => {
                        actions.push(LifecycleAction::RenewalWarning);
                        continue;
                    }
                    None => return Err("ACME did not produce a usable certificate".into()),
                };
                if validate_candidate(
                    &candidate,
                    &policy.domain,
                    policy.renew_before_days,
                    &self.runner,
                    true,
                )
                .is_err()
                    || existing.as_ref().is_some_and(|existing| {
                        same_certificate(&candidate, &existing.reference).unwrap_or(true)
                    })
                {
                    if existing.is_some() {
                        actions.push(LifecycleAction::RenewalWarning);
                        continue;
                    }
                    return Err("ACME did not produce a new usable certificate".into());
                }
                match install_candidate(&candidate, &self.config.state_dir, &site.id, &policy) {
                    Ok(installed) => site.certificate = installed,
                    Err(_) if existing.is_some() => {
                        actions.push(LifecycleAction::RenewalWarning);
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                actions.push(if renew {
                    LifecycleAction::Renewed
                } else {
                    LifecycleAction::Issued
                });
            }
            Ok((manifest, actions))
        })();

        // HTTP-01 历史快照可能在兼容签发期间临时占用该托管文件；无论签发
        // 成功或失败都恢复全局跳转。当前 Panel desired 固定使用 DNS-01。
        let redirect = self.ensure_https_redirect();
        match (outcome, redirect) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(result), Ok(())) => Ok(result),
        }
    }

    fn discover_existing(
        &self,
        site: &CamouflageSite,
        policy: &CertificateLifecyclePolicy,
    ) -> Result<Option<ExistingCertificate>, String> {
        let mut candidates = vec![site.certificate.clone()];
        candidates.extend(installed_candidates(
            &self.config.state_dir,
            &site.id,
            policy,
        )?);
        for mut candidate in candidates {
            candidate.lifecycle = Some(policy.clone());
            if validate_candidate(&candidate, &policy.domain, 0, &self.runner, false).is_ok() {
                let renewal_due = validate_candidate(
                    &candidate,
                    &policy.domain,
                    policy.renew_before_days,
                    &self.runner,
                    false,
                )
                .is_err();
                return Ok(Some(ExistingCertificate {
                    reference: candidate,
                    renewal_due,
                }));
            }
        }
        let Some(candidate) = self.best_certbot_candidate(policy)? else {
            return Ok(None);
        };
        let installed = install_candidate(&candidate, &self.config.state_dir, &site.id, policy)?;
        let renewal_due = validate_candidate(
            &installed,
            &policy.domain,
            policy.renew_before_days,
            &self.runner,
            false,
        )
        .is_err();
        Ok(Some(ExistingCertificate {
            reference: installed,
            renewal_due,
        }))
    }

    fn best_certbot_candidate(
        &self,
        policy: &CertificateLifecyclePolicy,
    ) -> Result<Option<CertificateReference>, String> {
        let mut candidates = Vec::new();
        let entries = match fs::read_dir(&self.config.certbot_live_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot inspect Certbot certificates: {error}")),
        };
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let candidate = CertificateReference {
                cert_path: path.join("fullchain.pem"),
                key_path: path.join("privkey.pem"),
                lifecycle: Some(policy.clone()),
            };
            if validate_certbot_source(&candidate, &self.config.certbot_live_dir).is_ok()
                && validate_candidate(&candidate, &policy.domain, 0, &self.runner, true).is_ok()
            {
                let expires = certificate_not_after(&candidate.cert_path)?;
                candidates.push((expires, path, candidate));
            }
        }
        candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        Ok(candidates
            .into_iter()
            .next()
            .map(|(_, _, candidate)| candidate))
    }

    pub(crate) fn prepare_http01_once(
        &self,
        manifest: &CamouflageSitesManifest,
        prepared: &mut Option<String>,
    ) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }
        if !self.config.http01_nginx.enabled {
            return Err("certificate lifecycle requires managed Nginx for HTTP-01".into());
        }
        ensure_private_dir(&self.config.state_dir)?;
        ensure_directory(&self.config.webroot, 0o755)?;
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
        if prepared.as_deref() == Some(rendered.as_str()) {
            return Ok(());
        }
        nginx_sni::apply_rendered(rendered.as_bytes(), &self.config.http01_nginx).map_err(
            |_| "HTTP-01 Nginx preflight failed (port 80 may be unavailable)".to_string(),
        )?;
        *prepared = Some(rendered);
        Ok(())
    }

    /// 收敛 Node 托管的 :80 全局 HTTPS 跳转。只移除 Debian 标准 default
    /// site 链接；未知文件或链接一律 fail closed。Nginx preflight/reload 失败
    /// 时恢复该链接以及之前的托管片段。
    pub(crate) fn ensure_https_redirect(&self) -> Result<(), String> {
        if !self.config.enabled || !self.config.http01_nginx.enabled {
            return Ok(());
        }
        let rendered = render_https_redirect();
        let default_site = debian_default_site_path(&self.config.http01_nginx.conf_path);
        let removed_link = match default_site.as_deref() {
            Some(path) => disable_debian_default_site(path)?,
            None => None,
        };
        if removed_link.is_none()
            && fs::read(&self.config.http01_nginx.conf_path)
                .ok()
                .as_deref()
                == Some(rendered.as_bytes())
        {
            return Ok(());
        }
        let previous = fs::read(&self.config.http01_nginx.conf_path).ok();
        if let Err(error) =
            nginx_sni::apply_rendered(rendered.as_bytes(), &self.config.http01_nginx)
        {
            if let (Some(path), Some(target)) = (default_site.as_deref(), removed_link.as_deref()) {
                let _ = symlink(target, path);
                let _ = nginx_sni::restore_rendered(previous.as_deref(), &self.config.http01_nginx);
            }
            return Err(format!("HTTPS redirect Nginx preflight failed: {error}"));
        }
        Ok(())
    }

    fn invoke_certbot(
        &self,
        policy: &CertificateLifecyclePolicy,
        renew: bool,
    ) -> Result<(), String> {
        validate_absolute_path(&self.config.certbot_binary, "Certbot binary")?;
        reject_symlink(&self.config.certbot_binary)?;
        if policy.challenge_method == AcmeChallengeMethod::Dns01 {
            validate_absolute_path(&self.config.dns01_hook_binary, "DNS-01 hook binary")?;
            reject_symlink(&self.config.dns01_hook_binary)?;
        }
        let output = self.runner.run(
            &self.config.certbot_binary,
            &certbot_args(
                policy,
                renew,
                &self.config.webroot,
                &self.config.dns01_hook_binary,
            )?,
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err("ACME certificate command failed; retained existing certificate".into())
        }
    }
}

fn certbot_args(
    policy: &CertificateLifecyclePolicy,
    renew: bool,
    webroot: &Path,
    hook_binary: &Path,
) -> Result<Vec<String>, String> {
    let mut args = vec![
        "certonly".into(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--cert-name".into(),
        certbot_certificate_name(&policy.domain)?,
        "-d".into(),
        policy.domain.clone(),
    ];
    if renew {
        args.push("--force-renewal".into());
    }
    match policy.challenge_method {
        AcmeChallengeMethod::Http01 => args.extend([
            "--webroot".into(),
            "--webroot-path".into(),
            webroot.display().to_string(),
        ]),
        AcmeChallengeMethod::Dns01 => {
            let binary = quote_shell_arg(hook_binary)?;
            args.extend([
                "--manual".into(),
                "--preferred-challenges".into(),
                "dns".into(),
                "--manual-auth-hook".into(),
                format!("/usr/bin/env {binary} acme-dns01-hook auth"),
                "--manual-cleanup-hook".into(),
                format!("/usr/bin/env {binary} acme-dns01-hook cleanup"),
            ]);
        }
    }
    match &policy.email {
        Some(email) => args.extend(["--email".into(), email.clone()]),
        None => args.push("--register-unsafely-without-email".into()),
    }
    Ok(args)
}

#[derive(Clone)]
struct ExistingCertificate {
    reference: CertificateReference,
    renewal_due: bool,
}

fn installed_candidates(
    state_dir: &Path,
    site_id: &str,
    policy: &CertificateLifecyclePolicy,
) -> Result<Vec<CertificateReference>, String> {
    let root = state_dir.join("generations").join(site_id);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| right.cmp(left));
    Ok(paths
        .into_iter()
        .map(|path| CertificateReference {
            cert_path: path.join("fullchain.pem"),
            key_path: path.join("privkey.pem"),
            lifecycle: Some(policy.clone()),
        })
        .collect())
}

fn certificate_not_after(path: &Path) -> Result<i64, String> {
    let data = fs::read(path).map_err(|_| "certificate is unavailable")?;
    let (_, pem) = parse_x509_pem(&data).map_err(|_| "invalid certificate PEM")?;
    let (_, certificate) =
        X509Certificate::from_der(&pem.contents).map_err(|_| "invalid certificate DER")?;
    Ok(certificate.validity().not_after.timestamp())
}

fn validate_policy(
    site: &CamouflageSite,
    policy: &CertificateLifecyclePolicy,
) -> Result<(), String> {
    if !is_valid_certificate_domain(&policy.domain)
        || !certificate_name_matches_host(&policy.domain, &site.sni)
    {
        return Err("certificate domain must cover camouflage SNI".into());
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

fn render_https_redirect() -> String {
    "# generated by relay-node; global HTTP to HTTPS redirect\n\
server {\n\
    listen 80 default_server;\n\
    listen [::]:80 default_server;\n\
    server_name _;\n\
    return 301 https://$host$request_uri;\n\
}\n"
    .into()
}

fn debian_default_site_path(conf_path: &Path) -> Option<PathBuf> {
    conf_path
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "nginx"))
        .map(|nginx_root| nginx_root.join("sites-enabled/default"))
}

fn disable_debian_default_site(path: &Path) -> Result<Option<PathBuf>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect Debian Nginx default site: {error}")),
    };
    if !metadata.file_type().is_symlink() {
        return Err("refusing to remove non-symlink Nginx default site".into());
    }
    let target = fs::read_link(path)
        .map_err(|error| format!("cannot read Debian Nginx default site link: {error}"))?;
    let resolved = if target.is_absolute() {
        target.clone()
    } else {
        path.parent()
            .unwrap_or_else(|| Path::new("/"))
            .join(&target)
    };
    let expected = path
        .parent()
        .and_then(Path::parent)
        .map(|nginx_root| nginx_root.join("sites-available/default"))
        .ok_or("invalid Nginx default site path")?;
    let resolved =
        fs::canonicalize(&resolved).map_err(|_| "Nginx default site link target is unavailable")?;
    let expected = fs::canonicalize(&expected)
        .map_err(|_| "Debian Nginx default site target is unavailable")?;
    if resolved != expected {
        return Err("refusing to remove non-Debian Nginx default site link".into());
    }
    fs::remove_file(path).map_err(|error| format!("cannot disable Nginx default site: {error}"))?;
    Ok(Some(target))
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
        .any(|name| matches!(name, GeneralName::DNSName(value) if certificate_name_matches_host(value, domain)))
    {
        return Err("certificate SAN does not match camouflage SNI".into());
    }
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    if not_before > now || not_after <= not_before || not_after <= now {
        return Err("certificate validity window is not currently usable".into());
    }
    let remaining = not_after - now;
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

fn same_certificate(
    left: &CertificateReference,
    right: &CertificateReference,
) -> Result<bool, String> {
    let left = fs::read(&left.cert_path).map_err(|_| "certificate is unavailable")?;
    let right = fs::read(&right.cert_path).map_err(|_| "certificate is unavailable")?;
    Ok(normalize_pem(&left) == normalize_pem(&right))
}

fn quote_shell_arg(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("DNS-01 hook path is not UTF-8")?;
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn is_valid_certificate_domain(value: &str) -> bool {
    match value.strip_prefix("*.") {
        Some(base) => is_valid_domain(base) && base.split('.').count() >= 2,
        None => is_valid_domain(value),
    }
}

pub(crate) fn certificate_name_matches_host(certificate_name: &str, host: &str) -> bool {
    if certificate_name.eq_ignore_ascii_case(host) {
        return true;
    }
    let Some(base) = certificate_name.strip_prefix("*.") else {
        return false;
    };
    let suffix = format!(".{base}");
    let Some(label) = host.strip_suffix(&suffix) else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

fn certbot_certificate_name(domain: &str) -> Result<String, String> {
    if !is_valid_certificate_domain(domain) {
        return Err("invalid certificate domain".into());
    }
    Ok(match domain.strip_prefix("*.") {
        Some(base) => format!("wildcard-{base}"),
        None => domain.to_string(),
    })
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
    use ::time::{Duration as TimeDuration, OffsetDateTime};
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

    struct ReplacingRunner {
        live_cert: PathBuf,
        live_key: PathBuf,
        cert: Vec<u8>,
        key: Vec<u8>,
    }

    impl CommandRunner for ReplacingRunner {
        fn run(&self, program: &Path, _: &[String]) -> Result<Output, String> {
            if program == Path::new("/bin/true") {
                write_private_file(&self.live_cert, &self.cert)?;
                write_private_file(&self.live_key, &self.key)?;
                Ok(output(true, b""))
            } else {
                Ok(output(true, b"same"))
            }
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
        write_test_certificate_with_window(
            dir,
            names,
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(90),
        )
    }

    fn write_test_certificate_with_window(
        dir: &Path,
        names: Vec<String>,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (PathBuf, PathBuf) {
        use rcgen::{CertificateParams, KeyPair};
        ensure_private_dir(dir).unwrap();
        let mut params = CertificateParams::new(names).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
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
            challenge_method: AcmeChallengeMethod::Http01,
        }
    }

    fn enabled_config(dir: &Path) -> CertificateLifecycleConfig {
        CertificateLifecycleConfig {
            enabled: true,
            certbot_binary: "/bin/true".into(),
            certbot_live_dir: dir.join("letsencrypt/live"),
            webroot: dir.join("webroot"),
            state_dir: dir.join("state"),
            dns01_hook_binary: PathBuf::from("/opt/relay-node/relay-node"),
            http01_nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("acme.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        }
    }

    fn lifecycle_manifest(
        reference: CertificateReference,
        lifecycle_policy: CertificateLifecyclePolicy,
    ) -> CamouflageSitesManifest {
        let mut reference = reference;
        reference.lifecycle = Some(lifecycle_policy);
        CamouflageSitesManifest {
            sites: vec![site(Path::new("/unused"), reference)],
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
    fn wildcard_certificate_scope_covers_exactly_one_label() {
        assert!(certificate_name_matches_host(
            "*.example.com",
            "op1.example.com"
        ));
        assert!(!certificate_name_matches_host(
            "*.example.com",
            "a.b.example.com"
        ));
        assert!(!certificate_name_matches_host(
            "*.example.com",
            "example.com"
        ));
        assert!(is_valid_certificate_domain("*.example.com"));
        assert!(!is_valid_certificate_domain("*.com"));
    }

    #[test]
    fn wildcard_certbot_args_keep_wildcard_but_use_safe_cert_name() {
        let mut policy = policy("site.example.com");
        policy.domain = "*.example.com".into();
        policy.challenge_method = AcmeChallengeMethod::Dns01;
        let args = certbot_args(
            &policy,
            false,
            Path::new("/unused"),
            Path::new("/opt/relay-node/relay-node"),
        )
        .unwrap();
        assert!(args.windows(2).any(|pair| pair == ["-d", "*.example.com"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--cert-name", "wildcard-example.com"]));
    }

    #[test]
    fn first_issuance_uses_certonly_without_a_renewal_record() {
        let args = certbot_args(
            &policy("site.example.com"),
            false,
            Path::new("/webroot"),
            Path::new("/opt/relay-node/relay-node"),
        )
        .unwrap();
        assert_eq!(args[0], "certonly");
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-d", "site.example.com"]));
    }

    #[test]
    fn renewal_policy_forces_renewal_independently_of_certbot_default() {
        let args = certbot_args(
            &policy("site.example.com"),
            true,
            Path::new("/unused"),
            Path::new("/opt/relay-node/relay-node"),
        )
        .unwrap();
        assert_eq!(args[0], "certonly");
        assert!(args.iter().any(|arg| arg == "--force-renewal"));
    }

    #[test]
    fn dns01_hooks_quote_the_binary_and_never_embed_credentials() {
        let mut dns_policy = policy("site.example.com");
        dns_policy.challenge_method = AcmeChallengeMethod::Dns01;
        let args = certbot_args(
            &dns_policy,
            false,
            Path::new("/unused"),
            Path::new("/opt/relay node/relay-node's binary"),
        )
        .unwrap();
        let auth = args
            .windows(2)
            .find(|pair| pair[0] == "--manual-auth-hook")
            .map(|pair| pair[1].clone())
            .unwrap();
        assert_eq!(
            auth,
            "/usr/bin/env '/opt/relay node/relay-node'\"'\"'s binary' acme-dns01-hook auth"
        );
        assert_eq!(auth.split_whitespace().next(), Some("/usr/bin/env"));
        let serialized = args.join(" ");
        for forbidden in ["NODE_TOKEN", "DNSMGR", "api_key", "uid="] {
            assert!(!serialized.contains(forbidden));
        }
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
            dns01_hook_binary: PathBuf::from("/opt/relay-node/relay-node"),
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
    fn identical_http01_plan_reuses_successful_runtime_without_reload() {
        let dir = unique_dir("http01-noop");
        let marker = dir.join("reload-count");
        let manifest = CamouflageSitesManifest {
            sites: vec![site(
                &dir,
                CertificateReference {
                    cert_path: dir.join("missing.crt"),
                    key_path: dir.join("missing.key"),
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
            dns01_hook_binary: PathBuf::from("/opt/relay-node/relay-node"),
            http01_nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("acme.conf"),
                test_cmd: "true".into(),
                reload_cmd: format!("printf x >> {}", marker.display()),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        };
        let lifecycle =
            CertificateLifecycle::with_runner(config, FakeRunner(Mutex::new(VecDeque::new())));
        let mut prepared = None;
        lifecycle
            .prepare_http01_once(&manifest, &mut prepared)
            .unwrap();
        lifecycle
            .prepare_http01_once(&manifest, &mut prepared)
            .unwrap();
        assert_eq!(fs::read_to_string(marker).unwrap(), "x");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn global_https_redirect_preserves_host_uri_and_query() {
        let rendered = render_https_redirect();
        assert!(rendered.contains("listen 80 default_server;"));
        assert!(rendered.contains("listen [::]:80 default_server;"));
        assert!(rendered.contains("return 301 https://$host$request_uri;"));
        assert!(!rendered.contains("server_name site.example.com"));
        assert!(!rendered.contains("ssl_preread"));
        assert!(!rendered.contains("8443"));
    }

    #[test]
    fn https_redirect_removes_only_the_debian_default_site_link() {
        let dir = unique_dir("https-redirect");
        let nginx = dir.join("nginx");
        fs::create_dir_all(nginx.join("conf.d")).unwrap();
        fs::create_dir_all(nginx.join("sites-enabled")).unwrap();
        fs::create_dir_all(nginx.join("sites-available")).unwrap();
        fs::write(nginx.join("sites-available/default"), "stock default").unwrap();
        symlink(
            "../sites-available/default",
            nginx.join("sites-enabled/default"),
        )
        .unwrap();
        let mut config = enabled_config(&dir);
        config.http01_nginx.conf_path = nginx.join("conf.d/relay-panel-acme.conf");
        let lifecycle = CertificateLifecycle::new(config);
        lifecycle.ensure_https_redirect().unwrap();
        assert!(!nginx.join("sites-enabled/default").exists());
        assert_eq!(
            fs::read_to_string(nginx.join("conf.d/relay-panel-acme.conf")).unwrap(),
            render_https_redirect()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn https_redirect_refuses_an_unknown_default_site() {
        let dir = unique_dir("https-redirect-conflict");
        let nginx = dir.join("nginx");
        fs::create_dir_all(nginx.join("sites-enabled")).unwrap();
        fs::write(nginx.join("sites-enabled/default"), "custom config").unwrap();
        let error = disable_debian_default_site(&nginx.join("sites-enabled/default")).unwrap_err();
        assert!(error.contains("non-symlink"));
        assert!(nginx.join("sites-enabled/default").is_file());
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
    fn healthy_active_certificate_is_a_true_noop_without_http01_preparation() {
        let dir = unique_dir("healthy-noop");
        let (cert_path, key_path) =
            write_test_certificate(&dir.join("active"), vec!["site.example.com".into()]);
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: cert_path.clone(),
                key_path,
                lifecycle: None,
            },
            policy("site.example.com"),
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
            ]))),
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| panic!("healthy cert must skip DNS"))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::Unchanged]);
        assert_eq!(candidate.sites[0].certificate.cert_path, cert_path);
        assert_eq!(
            fs::read_to_string(dir.join("acme.conf")).unwrap(),
            render_https_redirect()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn healthy_managed_generation_and_certbot_candidate_are_reused_without_acme() {
        let dir = unique_dir("discovery");
        let managed = dir.join("state/generations/site/generation-2");
        let (managed_cert, managed_key) =
            write_test_certificate(&managed, vec!["site.example.com".into()]);
        let missing = CertificateReference {
            cert_path: dir.join("pending/fullchain.pem"),
            key_path: dir.join("pending/privkey.pem"),
            lifecycle: None,
        };
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
            ]))),
        );
        let (managed_result, actions) = lifecycle
            .reconcile_with_dns(
                &lifecycle_manifest(missing.clone(), policy("site.example.com")),
                |_, _| panic!("managed reuse must skip DNS"),
            )
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::Unchanged]);
        assert_eq!(managed_result.sites[0].certificate.cert_path, managed_cert);
        assert_eq!(managed_result.sites[0].certificate.key_path, managed_key);

        fs::remove_dir_all(dir.join("state/generations")).unwrap();
        let live = dir.join("letsencrypt/live/site.example.com-0001");
        let (certbot_cert, _) = write_test_certificate(&live, vec!["site.example.com".into()]);
        ensure_private_dir(&dir.join("letsencrypt/archive")).unwrap();
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
                output(true, b"same"),
            ]))),
        );
        let (adopted, actions) = lifecycle
            .reconcile_with_dns(
                &lifecycle_manifest(missing, policy("site.example.com")),
                |_, _| panic!("Certbot adoption must skip DNS"),
            )
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::Unchanged]);
        assert_ne!(adopted.sites[0].certificate.cert_path, certbot_cert);
        assert!(adopted.sites[0]
            .certificate
            .cert_path
            .starts_with(dir.join("state/generations/site")));
        assert_eq!(
            fs::read(&adopted.sites[0].certificate.cert_path).unwrap(),
            fs::read(certbot_cert).unwrap()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn near_expiry_dns01_failure_retains_the_usable_certificate_as_warning() {
        let dir = unique_dir("renewal-warning-dns01");
        let (old_cert, old_key) = write_test_certificate_with_window(
            &dir.join("old"),
            vec!["site.example.com".into()],
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(10),
        );
        let mut dns_policy = policy("site.example.com");
        dns_policy.challenge_method = AcmeChallengeMethod::Dns01;
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: old_cert.clone(),
                key_path: old_key,
                lifecycle: None,
            },
            dns_policy,
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b"same"),
                output(true, b"same"),
                output(false, b""),
            ]))),
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| panic!("DNS-01 must not require A lookup"))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::RenewalWarning]);
        assert_eq!(candidate.sites[0].certificate.cert_path, old_cert);
        assert_eq!(
            fs::read_to_string(dir.join("acme.conf")).unwrap(),
            render_https_redirect()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn near_expiry_http01_failure_retains_the_usable_certificate_as_warning() {
        let dir = unique_dir("renewal-warning-http01");
        let (old_cert, old_key) = write_test_certificate_with_window(
            &dir.join("old"),
            vec!["site.example.com".into()],
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(10),
        );
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: old_cert.clone(),
                key_path: old_key,
                lifecycle: None,
            },
            policy("site.example.com"),
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([
                output(true, b"same"),
                output(true, b"same"),
                output(false, b""),
            ]))),
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| Ok(()))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::RenewalWarning]);
        assert_eq!(candidate.sites[0].certificate.cert_path, old_cert);
        assert!(dir.join("acme.conf").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn no_usable_certificate_and_issuance_failure_is_hard_failure() {
        let dir = unique_dir("issuance-hard-failure");
        let mut dns_policy = policy("site.example.com");
        dns_policy.challenge_method = AcmeChallengeMethod::Dns01;
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: dir.join("missing/fullchain.pem"),
                key_path: dir.join("missing/privkey.pem"),
                lifecycle: None,
            },
            dns_policy,
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            FakeRunner(Mutex::new(VecDeque::from([output(false, b"")]))),
        );
        assert!(lifecycle
            .reconcile_with_dns(&source, |_, _| panic!("DNS-01 must not require A lookup"))
            .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn successful_renewal_installs_a_new_generation_without_overwriting_old() {
        let dir = unique_dir("renewal");
        let live = dir.join("letsencrypt/live/site.example.com");
        ensure_private_dir(&dir.join("letsencrypt/archive")).unwrap();
        let (old_cert, old_key) = write_test_certificate_with_window(
            &dir.join("old"),
            vec!["site.example.com".into()],
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(10),
        );
        let old_bytes = fs::read(&old_cert).unwrap();
        let (replacement_cert, replacement_key) =
            write_test_certificate(&dir.join("replacement"), vec!["site.example.com".into()]);
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: old_cert.clone(),
                key_path: old_key,
                lifecycle: None,
            },
            policy("site.example.com"),
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            ReplacingRunner {
                live_cert: live.join("fullchain.pem"),
                live_key: live.join("privkey.pem"),
                cert: fs::read(&replacement_cert).unwrap(),
                key: fs::read(&replacement_key).unwrap(),
            },
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| Ok(()))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::Renewed]);
        assert_ne!(candidate.sites[0].certificate.cert_path, old_cert);
        assert_eq!(fs::read(&old_cert).unwrap(), old_bytes);
        assert_eq!(
            fs::read(candidate.sites[0].certificate.cert_path.clone()).unwrap(),
            fs::read(replacement_cert).unwrap()
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
            fs::read(replacement_key).unwrap()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_renewal_output_retains_old_usable_certificate() {
        let dir = unique_dir("invalid-renewal-output");
        let live = dir.join("letsencrypt/live/site.example.com");
        ensure_private_dir(&dir.join("letsencrypt/archive")).unwrap();
        let (old_cert, old_key) = write_test_certificate_with_window(
            &dir.join("old"),
            vec!["site.example.com".into()],
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(10),
        );
        let (wrong_cert, wrong_key) =
            write_test_certificate(&dir.join("wrong"), vec!["other.example.com".into()]);
        let source = lifecycle_manifest(
            CertificateReference {
                cert_path: old_cert.clone(),
                key_path: old_key,
                lifecycle: None,
            },
            policy("site.example.com"),
        );
        let lifecycle = CertificateLifecycle::with_runner(
            enabled_config(&dir),
            ReplacingRunner {
                live_cert: live.join("fullchain.pem"),
                live_key: live.join("privkey.pem"),
                cert: fs::read(wrong_cert).unwrap(),
                key: fs::read(wrong_key).unwrap(),
            },
        );
        let (candidate, actions) = lifecycle
            .reconcile_with_dns(&source, |_, _| Ok(()))
            .unwrap();
        assert_eq!(actions, vec![LifecycleAction::RenewalWarning]);
        assert_eq!(candidate.sites[0].certificate.cert_path, old_cert);
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
