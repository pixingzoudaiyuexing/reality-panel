//! Relay-local TLS camouflage sites.
//!
//! Remote REALITY forwarding remains ordinary `ListenerConfig` state owned by
//! the Panel and listener LKG. This module owns only the public TLS wrapper
//! used by dedicated REALITY servers as their fallback target.

use super::certificate_lifecycle::{
    inspect_certificate, CertificateLifecycle, CertificateLifecycleConfig,
    CertificateLifecyclePolicy, LifecycleAction, RenewalGate,
};
use super::nginx_sni::{self, NginxSniConfig};
use relay_shared::protocol::{CamouflageLocalBackend, CamouflageSiteDesired, CamouflageSiteStatus};
use relay_shared::reconciliation::{fingerprint_bytes, ConfigFingerprint};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub const CAMOUFLAGE_TLS_PORT: u16 = 8443;
pub const OPENLIST_BACKEND: &str = "127.0.0.1:5244";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CamouflageSitesManifest {
    pub sites: Vec<CamouflageSite>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CamouflageSite {
    pub id: String,
    pub sni: String,
    pub tls_listener_port: u16,
    pub local_backend: String,
    pub certificate: CertificateReference,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateReference {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Lifecycle policy is Node-local and never crosses the Panel protocol.
    #[serde(default)]
    pub lifecycle: Option<super::certificate_lifecycle::CertificateLifecyclePolicy>,
}

#[derive(Clone, Debug)]
pub struct CamouflageSiteConfig {
    pub enabled: bool,
    pub manifest_path: PathBuf,
    pub state_dir: PathBuf,
    pub nginx: NginxSniConfig,
    pub certificate_lifecycle: CertificateLifecycleConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CamouflageRuntimeOwnership {
    Unowned,
    BootstrapCompatibility,
    ModernExpectedMissing,
    ModernManaged,
}

#[derive(Clone, Debug)]
pub struct CamouflageRuntimeObservation {
    pub fingerprint: ConfigFingerprint,
    pub healthy: bool,
    pub(crate) ownership: CamouflageRuntimeOwnership,
}

#[derive(Debug)]
pub struct CamouflageSiteManager {
    config: CamouflageSiteConfig,
    active: Option<CamouflageSitesManifest>,
    renewal_gate: Arc<RenewalGate>,
    desired: Vec<CamouflageSiteDesired>,
    last_errors: HashMap<String, String>,
    renewal_warnings: HashMap<String, (String, String)>,
    panel_authority_established: bool,
}

impl CamouflageSiteManager {
    pub fn new(config: CamouflageSiteConfig) -> Self {
        Self {
            config,
            active: None,
            renewal_gate: Arc::new(RenewalGate::default()),
            desired: Vec::new(),
            last_errors: HashMap::new(),
            renewal_warnings: HashMap::new(),
            panel_authority_established: false,
        }
    }

    /// Restore the camouflage LKG before the listener LKG is activated. This
    /// path has no dependency on Panel availability.
    pub fn restore_and_apply(&mut self) -> bool {
        if !self.config.enabled {
            return true;
        }

        let recovered = self.load_lkg().ok();
        let mut recovered_applied = false;
        if let Some(manifest) = recovered.as_ref() {
            match self.apply_runtime(manifest) {
                Ok(()) => {
                    self.active = Some(manifest.clone());
                    recovered_applied = true;
                }
                Err(error) => {
                    tracing::error!(
                        "camouflage site LKG runtime restore failed; preserving runtime: {}",
                        error
                    );
                }
            }
        }

        // A source manifest is not a substitute for the modern Panel-owned LKG.
        // If both LKG copies are unavailable, fail-preserve and wait for a
        // validated Panel snapshot instead of overwriting runtime from legacy
        // local state.
        if recovered_applied {
            return true;
        }
        tracing::warn!("camouflage sites unavailable; preserving runtime until Panel sync");
        false
    }

    /// Legacy source manifests are not an authority for runtime recovery.
    /// Certificate reconciliation begins only after a validated Panel snapshot
    /// has established an active modern LKG.
    pub fn reconcile_from_source(&mut self) -> bool {
        tracing::warn!(
            "legacy camouflage source manifest is not authoritative; waiting for Panel sync"
        );
        false
    }

    /// Scheduler path after Panel ownership has been established. The active
    /// LKG carries both the Node-owned generation and lifecycle policy, so it
    /// remains renewable while the Panel is unavailable.
    pub fn reconcile_active(&mut self) -> bool {
        let Some(manifest) = self.active.clone() else {
            return self.reconcile_from_source();
        };
        self.reconcile_and_apply_manifest(manifest)
    }

    /// Prepare all Panel-desired sites while retaining old active sites. The
    /// caller activates dependent :443 listeners only for the returned SNI set,
    /// then calls `finalize_for_listener_snis` to remove unreferenced wrappers.
    pub fn prepare_desired(
        &mut self,
        desired: &[CamouflageSiteDesired],
        panel_authoritative: bool,
    ) -> HashSet<String> {
        self.desired = desired
            .iter()
            .filter(|site| site.enabled)
            .cloned()
            .collect();
        if !panel_authoritative {
            return self.active_snis();
        }
        self.panel_authority_established = true;
        if self.desired.is_empty() && self.active.is_none() {
            return HashSet::new();
        }
        let mut candidate = self
            .active
            .clone()
            .unwrap_or(CamouflageSitesManifest { sites: Vec::new() });

        for desired_site in &self.desired {
            if let Err(error) = validate_desired(desired_site) {
                self.last_errors
                    .insert(desired_site.site_id.clone(), sanitize_error(&error));
                continue;
            }
            let previous = candidate
                .sites
                .iter()
                .find(|site| site.id == desired_site.site_id || site.sni == desired_site.sni)
                .cloned();
            let lifecycle = Some(CertificateLifecyclePolicy {
                domain: desired_site.certificate.domain.clone(),
                email: None,
                expected_public_ip: desired_site.certificate.expected_public_ip.clone(),
                renew_before_days: desired_site.certificate.renew_before_days,
                challenge_method: desired_site.certificate.challenge_method,
            });
            let certificate = previous
                .as_ref()
                .map(|site| {
                    let mut certificate = site.certificate.clone();
                    certificate.lifecycle = lifecycle.clone();
                    certificate
                })
                .or_else(|| {
                    latest_installed_certificate(
                        &self.config.certificate_lifecycle.state_dir,
                        &desired_site.site_id,
                        lifecycle.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    let pending = self
                        .config
                        .certificate_lifecycle
                        .state_dir
                        .join("pending")
                        .join(&desired_site.site_id);
                    CertificateReference {
                        cert_path: pending.join("fullchain.pem"),
                        key_path: pending.join("privkey.pem"),
                        lifecycle,
                    }
                });
            candidate
                .sites
                .retain(|site| site.id != desired_site.site_id && site.sni != desired_site.sni);
            candidate.sites.push(CamouflageSite {
                id: desired_site.site_id.clone(),
                sni: desired_site.sni.clone(),
                tls_listener_port: desired_site.tls_listener_port,
                local_backend: OPENLIST_BACKEND.to_string(),
                certificate,
            });
        }

        match self.try_reconcile_and_apply_manifest(candidate) {
            Ok(()) => {
                for site in &self.desired {
                    self.last_errors.remove(&site.site_id);
                }
            }
            Err(error) => {
                let error = sanitize_error(&error);
                for site in &self.desired {
                    if !self.active_snis().contains(&site.sni) {
                        self.last_errors.insert(site.site_id.clone(), error.clone());
                    }
                }
            }
        }
        self.active_snis()
    }

    /// Remove sites only after the effective listener transaction succeeded.
    pub fn finalize_for_listener_snis(&mut self, referenced_snis: &HashSet<String>) -> bool {
        if !self.panel_authority_established && self.desired.is_empty() {
            return true;
        }
        let Some(active) = self.active.clone() else {
            return referenced_snis.is_empty();
        };
        let candidate = CamouflageSitesManifest {
            sites: active
                .sites
                .into_iter()
                .filter(|site| referenced_snis.contains(&site.sni))
                .collect(),
        };
        if self.active.as_ref() == Some(&candidate) {
            return true;
        }
        self.apply_candidate(candidate)
    }

    pub fn active_snis(&self) -> HashSet<String> {
        self.active
            .as_ref()
            .map(|manifest| {
                manifest
                    .sites
                    .iter()
                    .filter(|site| {
                        !self.config.certificate_lifecycle.enabled
                            || site.certificate.lifecycle.is_none()
                            || CertificateLifecycle::is_usable(&site.certificate, &site.sni)
                    })
                    .map(|site| site.sni.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn set_nginx_commands_for_test(&mut self, test_cmd: &str, reload_cmd: &str) {
        self.config.nginx.test_cmd = test_cmd.to_string();
        self.config.nginx.reload_cmd = reload_cmd.to_string();
    }

    pub fn inspect_runtime(&self, expected_snis: &HashSet<String>) -> CamouflageRuntimeObservation {
        let Some(active) = self.active.as_ref() else {
            let wrapper_exists = self.config.enabled && self.config.nginx.conf_path.exists();
            let ownership = if !expected_snis.is_empty() {
                CamouflageRuntimeOwnership::ModernExpectedMissing
            } else if wrapper_exists {
                CamouflageRuntimeOwnership::BootstrapCompatibility
            } else {
                CamouflageRuntimeOwnership::Unowned
            };
            let mut evidence = format!("camouflage-runtime-{ownership:?}\0").into_bytes();
            let mut expected: Vec<_> = expected_snis.iter().collect();
            expected.sort();
            for sni in expected {
                evidence.extend_from_slice(sni.as_bytes());
                evidence.push(0);
            }
            return CamouflageRuntimeObservation {
                fingerprint: fingerprint_bytes(&evidence),
                healthy: expected_snis.is_empty(),
                ownership,
            };
        };
        let active_snis: HashSet<_> = active.sites.iter().map(|site| site.sni.clone()).collect();
        let healthy = expected_snis.is_subset(&active_snis) && self.runtime_matches(active);
        let mut evidence = b"camouflage-runtime-v1\0".to_vec();
        evidence.extend_from_slice(&serde_json::to_vec(active).unwrap_or_default());
        if let Ok(contents) = fs::read(&self.config.nginx.conf_path) {
            evidence.extend_from_slice(&contents);
        } else {
            evidence.extend_from_slice(b"<missing>");
        }
        evidence.push(healthy as u8);
        CamouflageRuntimeObservation {
            fingerprint: fingerprint_bytes(&evidence),
            healthy,
            ownership: CamouflageRuntimeOwnership::ModernManaged,
        }
    }

    pub fn repair_active_runtime(&mut self, expected_snis: &HashSet<String>) -> bool {
        let Some(active) = self.active.clone() else {
            return expected_snis.is_empty();
        };
        let active_snis: HashSet<_> = active.sites.iter().map(|site| site.sni.clone()).collect();
        if expected_snis.is_subset(&active_snis) && self.runtime_matches(&active) {
            return true;
        }
        if !expected_snis.is_subset(&active_snis) {
            return false;
        }
        self.apply_candidate(active)
    }

    pub fn status_snapshot(&self) -> Vec<CamouflageSiteStatus> {
        self.desired
            .iter()
            .map(|desired| {
                let active = self.active.as_ref().and_then(|manifest| {
                    manifest
                        .sites
                        .iter()
                        .find(|site| site.id == desired.site_id && site.sni == desired.sni)
                });
                let metadata =
                    active.and_then(|site| inspect_certificate(&site.certificate.cert_path).ok());
                let error = self.last_errors.get(&desired.site_id).cloned();
                let renewal_warning = self.renewal_warnings.get(&desired.site_id).cloned();
                let is_active = active.is_some_and(|site| {
                    metadata.is_some()
                        && (!self.config.certificate_lifecycle.enabled
                            || site.certificate.lifecycle.is_none()
                            || CertificateLifecycle::is_usable(&site.certificate, &site.sni))
                });
                let failed = !is_active && error.is_some();
                CamouflageSiteStatus {
                    site_id: desired.site_id.clone(),
                    sni: desired.sni.clone(),
                    site_status: if is_active {
                        "active"
                    } else if failed {
                        "failed"
                    } else {
                        "preparing"
                    }
                    .into(),
                    certificate_status: if is_active {
                        "active"
                    } else if failed {
                        "failed"
                    } else {
                        "pending"
                    }
                    .into(),
                    issuer: metadata.as_ref().map(|value| value.issuer.clone()),
                    valid_from: metadata.as_ref().map(|value| value.valid_from.clone()),
                    valid_until: metadata.as_ref().map(|value| value.valid_until.clone()),
                    // The certificate not-before is the durable Node-local
                    // issuance/renewal timestamp available after restart.
                    last_success: metadata.as_ref().map(|value| value.valid_from.clone()),
                    last_attempt: renewal_warning.as_ref().map(|(attempt, _)| attempt.clone()),
                    last_error: renewal_warning.map(|(_, warning)| warning).or(error),
                    active_generation: active.and_then(|site| {
                        site.certificate
                            .cert_path
                            .parent()
                            .and_then(Path::file_name)
                            .and_then(|value| value.to_str())
                            .map(str::to_string)
                    }),
                }
            })
            .collect()
    }

    pub fn active_site_for_sni(&self, sni: &str) -> Option<CamouflageSite> {
        self.active
            .as_ref()?
            .sites
            .iter()
            .find(|site| site.sni.eq_ignore_ascii_case(sni))
            .cloned()
    }

    fn reconcile_and_apply_manifest(&mut self, manifest: CamouflageSitesManifest) -> bool {
        match self.try_reconcile_and_apply_manifest(manifest) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(
                    "camouflage certificate lifecycle failed; retained current certificate: {}",
                    sanitize_error(&error)
                );
                false
            }
        }
    }

    fn try_reconcile_and_apply_manifest(
        &mut self,
        mut manifest: CamouflageSitesManifest,
    ) -> Result<(), String> {
        let site_ids = manifest
            .sites
            .iter()
            .filter(|site| site.certificate.lifecycle.is_some())
            .map(|site| site.id.clone())
            .collect();
        let renewal_gate = Arc::clone(&self.renewal_gate);
        let Some(_renewal_lease) = renewal_gate.try_acquire(site_ids) else {
            return Err("camouflage certificate renewal already in progress".into());
        };
        // The source manifest carries policy, while a healthy LKG carries the
        // active Node-owned generation. Do not regress a periodic check back
        // to a Certbot live path after a successful install.
        if let Some(active) = &self.active {
            for site in &mut manifest.sites {
                if let Some(previous) = active.sites.iter().find(|old| old.id == site.id) {
                    if site.certificate.lifecycle.is_some() {
                        let lifecycle = site.certificate.lifecycle.clone();
                        site.certificate = previous.certificate.clone();
                        site.certificate.lifecycle = lifecycle;
                    }
                }
            }
        }

        let lifecycle = CertificateLifecycle::new(self.config.certificate_lifecycle.clone());
        let (candidate, actions) = lifecycle.reconcile(&manifest)?;
        for (site, action) in candidate.sites.iter().zip(actions.iter()) {
            if *action == LifecycleAction::RenewalWarning {
                self.renewal_warnings.insert(
                    site.id.clone(),
                    (
                        chrono::Utc::now().to_rfc3339(),
                        "Certificate remains valid; automatic renewal failed and will be retried"
                            .into(),
                    ),
                );
            } else {
                self.renewal_warnings.remove(&site.id);
            }
        }
        if self.active.as_ref() == Some(&candidate) && self.runtime_matches(&candidate) {
            return Ok(());
        }
        if actions
            .iter()
            .any(|action| *action != LifecycleAction::Unchanged)
        {
            tracing::info!("camouflage certificate lifecycle installed a validated generation");
        }
        if self.apply_candidate(candidate) {
            Ok(())
        } else {
            Err("camouflage runtime validation or LKG commit failed".into())
        }
    }

    fn runtime_matches(&self, manifest: &CamouflageSitesManifest) -> bool {
        if !self.config.enabled {
            return true;
        }
        if manifest.sites.is_empty() && !self.config.nginx.conf_path.exists() {
            return true;
        }
        if self.prepare_candidate(manifest).is_err() {
            return false;
        }
        let Ok(rendered) = render_camouflage_config(manifest) else {
            return false;
        };
        nginx_sni::inspect_rendered(&rendered, &self.config.nginx).healthy
    }

    pub fn apply_candidate(&mut self, candidate: CamouflageSitesManifest) -> bool {
        if let Err(error) = self.prepare_candidate(&candidate) {
            tracing::warn!("camouflage site candidate rejected: {}", error);
            return false;
        }
        let rendered = match render_camouflage_config(&candidate) {
            Ok(rendered) => rendered,
            Err(error) => {
                tracing::warn!("camouflage site render rejected: {}", error);
                return false;
            }
        };

        let previous_wrapper = match fs::read(&self.config.nginx.conf_path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::error!("cannot read current camouflage runtime: {}", error);
                return false;
            }
        };
        if let Err(error) = nginx_sni::apply_rendered(&rendered, &self.config.nginx) {
            tracing::error!("camouflage Nginx apply failed: {}", error);
            return false;
        }
        if let Err(error) = self.commit_lkg(&candidate) {
            tracing::error!("camouflage LKG commit failed; restoring runtime: {}", error);
            if let Err(restore_error) =
                nginx_sni::restore_rendered(previous_wrapper.as_deref(), &self.config.nginx)
            {
                tracing::error!(
                    "camouflage runtime restore failed after LKG error: {}",
                    restore_error
                );
            }
            return false;
        }

        self.active = Some(candidate.clone());
        tracing::info!(
            sites = candidate.sites.len(),
            "camouflage sites applied and committed as local LKG"
        );
        true
    }

    fn apply_runtime(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        self.prepare_candidate(manifest)?;
        let rendered = render_camouflage_config(manifest)?;
        nginx_sni::apply_rendered(&rendered, &self.config.nginx).map_err(|e| e.to_string())
    }

    fn prepare_candidate(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        validate_absolute_path(&self.config.manifest_path, "camouflage manifest")?;
        validate_absolute_path(&self.config.state_dir, "camouflage state")?;
        validate_absolute_path(&self.config.nginx.conf_path, "camouflage Nginx config")?;
        reject_symlink(&self.config.state_dir)?;
        reject_symlink(&self.config.nginx.conf_path)?;
        validate_manifest(manifest)?;
        for site in &manifest.sites {
            validate_certificate_reference(&site.certificate)?;
        }
        Ok(())
    }

    fn load_lkg(&self) -> Result<CamouflageSitesManifest, String> {
        if let Ok(manifest) = read_manifest(&self.lkg_path()) {
            if self.prepare_candidate(&manifest).is_ok() {
                remove_tmp_if_safe(&self.lkg_tmp_path());
                return Ok(manifest);
            }
        }

        if let Ok(manifest) = read_manifest(&self.lkg_backup_path()) {
            if self.prepare_candidate(&manifest).is_ok() {
                let bytes = fs::read(self.lkg_backup_path()).map_err(|e| e.to_string())?;
                match write_private_file(&self.lkg_path(), &bytes)
                    .and_then(|_| read_manifest(&self.lkg_path()))
                    .and_then(|repaired| {
                        self.prepare_candidate(&repaired)?;
                        Ok(repaired)
                    }) {
                    Ok(repaired) => return Ok(repaired),
                    Err(error) => {
                        tracing::warn!(
                            "valid camouflage LKG backup loaded but primary repair failed: {}",
                            error
                        );
                        remove_tmp_if_safe(&self.lkg_tmp_path());
                        return Ok(manifest);
                    }
                }
            }
        }

        remove_tmp_if_safe(&self.lkg_tmp_path());
        Err("no valid camouflage site LKG".to_string())
    }

    fn commit_lkg(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        validate_manifest(manifest)?;
        create_private_dir(&self.config.state_dir)?;
        let serialized = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
        let _: CamouflageSitesManifest =
            serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;

        write_private_file(&self.lkg_tmp_path(), &serialized)?;
        let staged = read_manifest(&self.lkg_tmp_path())?;
        validate_manifest(&staged)?;

        if read_manifest(&self.lkg_path())
            .and_then(|current| {
                validate_manifest(&current)?;
                Ok(current)
            })
            .is_ok()
        {
            let previous = fs::read(self.lkg_path()).map_err(|e| e.to_string())?;
            write_private_file(&self.lkg_backup_path(), &previous)?;
        }
        if let Err(error) = fs::rename(self.lkg_tmp_path(), self.lkg_path())
            .and_then(|_| sync_parent(&self.lkg_path()))
        {
            let _ = fs::remove_file(self.lkg_tmp_path());
            return Err(error.to_string());
        }
        Ok(())
    }

    fn lkg_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.json")
    }

    fn lkg_backup_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.backup.json")
    }

    fn lkg_tmp_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.json.tmp")
    }
}

pub fn validate_manifest(manifest: &CamouflageSitesManifest) -> Result<(), String> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for site in &manifest.sites {
        if !is_safe_id(&site.id) {
            return Err("invalid camouflage site id".to_string());
        }
        if !is_valid_domain(&site.sni) {
            return Err("invalid camouflage SNI".to_string());
        }
        if site.tls_listener_port != CAMOUFLAGE_TLS_PORT {
            return Err("camouflage TLS listener must use port 8443".to_string());
        }
        if site.local_backend != OPENLIST_BACKEND {
            return Err("camouflage backend must be local OpenList".to_string());
        }
        if !ids.insert(site.id.clone()) {
            return Err("duplicate camouflage site id".to_string());
        }
        if !names.insert(site.sni.clone()) {
            return Err("duplicate camouflage SNI".to_string());
        }
        validate_absolute_path(&site.certificate.cert_path, "certificate")?;
        validate_absolute_path(&site.certificate.key_path, "certificate key")?;
        if site.certificate.cert_path == site.certificate.key_path {
            return Err("certificate and key paths must differ".to_string());
        }
    }
    Ok(())
}

fn validate_desired(site: &CamouflageSiteDesired) -> Result<(), String> {
    if !is_safe_id(&site.site_id) || !is_valid_domain(&site.sni) {
        return Err("invalid camouflage desired identity".into());
    }
    if site.tls_listener_port != CAMOUFLAGE_TLS_PORT
        || site.local_backend != CamouflageLocalBackend::OpenList
    {
        return Err("invalid camouflage desired endpoint".into());
    }
    if site.certificate.domain != site.sni
        || site
            .certificate
            .expected_public_ip
            .parse::<std::net::IpAddr>()
            .is_err()
        || !(1..=365).contains(&site.certificate.renew_before_days)
    {
        return Err("invalid camouflage certificate policy".into());
    }
    Ok(())
}

fn sanitize_error(error: &str) -> String {
    let compact = error.replace(['\r', '\n'], " ");
    compact.chars().take(240).collect()
}

fn latest_installed_certificate(
    state_dir: &Path,
    site_id: &str,
    lifecycle: Option<CertificateLifecyclePolicy>,
) -> Option<CertificateReference> {
    let generations = state_dir.join("generations").join(site_id);
    let mut entries: Vec<_> = fs::read_dir(generations)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    entries.into_iter().rev().find_map(|entry| {
        let cert_path = entry.path().join("fullchain.pem");
        let key_path = entry.path().join("privkey.pem");
        (cert_path.is_file() && key_path.is_file()).then_some(CertificateReference {
            cert_path,
            key_path,
            lifecycle: lifecycle.clone(),
        })
    })
}

pub fn render_camouflage_config(manifest: &CamouflageSitesManifest) -> Result<Vec<u8>, String> {
    validate_manifest(manifest)?;
    let mut sites = manifest.sites.clone();
    sites.sort_by(|a, b| (a.sni.as_str(), a.id.as_str()).cmp(&(b.sni.as_str(), b.id.as_str())));

    let mut out = String::from("# generated by relay-node; TLS camouflage sites\n");
    out.push_str("log_format relay_panel_camouflage '$msec|$remote_addr|$ssl_server_name|$status|$body_bytes_sent|$upstream_addr';\n\n");
    out.push_str("server {\n");
    out.push_str("    listen 8443 ssl default_server;\n");
    out.push_str("    listen [::]:8443 ssl default_server;\n");
    out.push_str("    ssl_reject_handshake on;\n");
    out.push_str("}\n\n");

    for site in sites {
        out.push_str("server {\n");
        out.push_str("    listen 8443 ssl;\n");
        out.push_str("    listen [::]:8443 ssl;\n");
        out.push_str(&format!("    server_name {};\n", quote_nginx(&site.sni)));
        out.push_str(&format!(
            "    ssl_certificate {};\n",
            quote_nginx_path(&site.certificate.cert_path)?
        ));
        out.push_str(&format!(
            "    ssl_certificate_key {};\n",
            quote_nginx_path(&site.certificate.key_path)?
        ));
        out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        out.push_str(
            "    access_log /var/log/nginx/relay-panel-camouflage.log relay_panel_camouflage;\n",
        );
        out.push_str("    location / {\n");
        out.push_str("        proxy_set_header Host $host;\n");
        out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
        out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
        out.push_str("        proxy_set_header X-Forwarded-Proto https;\n");
        out.push_str(&format!(
            "        proxy_pass http://{};\n",
            site.local_backend
        ));
        out.push_str("    }\n");
        out.push_str("}\n\n");
    }
    Ok(out.into_bytes())
}

fn validate_certificate_reference(reference: &CertificateReference) -> Result<(), String> {
    validate_certificate_file(&reference.cert_path, false)?;
    validate_certificate_file(&reference.key_path, true)
}

fn validate_certificate_file(path: &Path, private: bool) -> Result<(), String> {
    validate_absolute_path(
        path,
        if private {
            "certificate key"
        } else {
            "certificate"
        },
    )?;
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("certificate reference must be a regular file".to_string());
    }
    if private {
        if metadata.mode() & 0o077 != 0 {
            return Err("certificate key must not be group/world-readable".to_string());
        }
        if unsafe { libc::geteuid() } == 0 && metadata.uid() != 0 {
            return Err("certificate key must be root-owned".to_string());
        }
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<CamouflageSitesManifest, String> {
    validate_absolute_path(path, "camouflage manifest")?;
    reject_symlink(path)?;
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    validate_absolute_path(path, "private directory")?;
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    reject_symlink(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    validate_absolute_path(path, "private file")?;
    reject_symlink(path)?;
    let parent = path.parent().ok_or("file has no parent")?;
    create_private_dir(parent)?;
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
        .map_err(|e| e.to_string())?;
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

fn appended_temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn remove_tmp_if_safe(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if let Err(error) = fs::remove_file(path) {
                tracing::warn!("could not remove stale camouflage LKG tmp: {}", error);
            }
        }
        Ok(_) => tracing::warn!("leaving non-file camouflage LKG tmp residue"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!("could not inspect camouflage LKG tmp: {}", error),
    }
}

fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    File::open(path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file has no parent")
    })?)?
    .sync_all()
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("refusing symlink {}", path.display()))
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

fn validate_absolute_path(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("{} path must be absolute without traversal", name));
    }
    Ok(())
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

fn quote_nginx(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn quote_nginx_path(path: &Path) -> Result<String, String> {
    Ok(quote_nginx(path.to_str().ok_or("non-UTF8 path")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::time::{Duration as TimeDuration, OffsetDateTime};

    fn unique_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-panel-camouflage-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn certificate(dir: &Path, name: &str) -> CertificateReference {
        create_private_dir(dir).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        write_private_file(&cert_path, b"test certificate").unwrap();
        write_private_file(&key_path, b"test private key").unwrap();
        CertificateReference {
            cert_path,
            key_path,
            lifecycle: None,
        }
    }

    fn real_certificate(
        dir: &Path,
        name: &str,
        sni: &str,
        valid_for_days: i64,
    ) -> CertificateReference {
        use rcgen::{CertificateParams, KeyPair};
        create_private_dir(dir).unwrap();
        let mut params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
        params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(valid_for_days);
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        write_private_file(&cert_path, certificate.pem().as_bytes()).unwrap();
        write_private_file(&key_path, key.serialize_pem().as_bytes()).unwrap();
        CertificateReference {
            cert_path,
            key_path,
            lifecycle: None,
        }
    }

    fn site(dir: &Path, id: &str, sni: &str) -> CamouflageSite {
        CamouflageSite {
            id: id.into(),
            sni: sni.into(),
            tls_listener_port: CAMOUFLAGE_TLS_PORT,
            local_backend: OPENLIST_BACKEND.into(),
            certificate: certificate(dir, id),
        }
    }

    fn manifest(dir: &Path) -> CamouflageSitesManifest {
        CamouflageSitesManifest {
            sites: vec![site(dir, "op1", "op1.example.com")],
        }
    }

    fn manager(dir: &Path, test_cmd: &str, reload_cmd: &str) -> CamouflageSiteManager {
        CamouflageSiteManager::new(CamouflageSiteConfig {
            enabled: true,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("state"),
            nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("camouflage.conf"),
                test_cmd: test_cmd.into(),
                reload_cmd: reload_cmd.into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
            certificate_lifecycle: CertificateLifecycleConfig::disabled_for_test(dir),
        })
    }

    #[test]
    fn renders_one_public_listener_with_deterministic_multi_vhosts() {
        let dir = unique_dir("render");
        let first = site(&dir, "op1", "op1.example.com");
        let second = site(&dir, "op2", "op2.example.com");
        let a = CamouflageSitesManifest {
            sites: vec![second.clone(), first.clone()],
        };
        let b = CamouflageSitesManifest {
            sites: vec![first, second],
        };
        let rendered_a = String::from_utf8(render_camouflage_config(&a).unwrap()).unwrap();
        let rendered_b = String::from_utf8(render_camouflage_config(&b).unwrap()).unwrap();
        assert_eq!(rendered_a, rendered_b);
        assert_eq!(
            rendered_a.matches("listen 8443 ssl default_server").count(),
            1
        );
        assert_eq!(rendered_a.matches("listen 8443 ssl;").count(), 2);
        assert!(rendered_a.contains("server_name \"op1.example.com\""));
        assert!(rendered_a.contains("op1.crt"));
        assert!(rendered_a.contains("server_name \"op2.example.com\""));
        assert!(rendered_a.contains("op2.crt"));
        assert!(rendered_a.contains("ssl_reject_handshake on"));
        assert_eq!(
            rendered_a
                .matches("proxy_pass http://127.0.0.1:5244")
                .count(),
            2
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_inspection_detects_and_repairs_managed_camouflage_wrapper() {
        let dir = unique_dir("runtime-inspection");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        let expected = HashSet::from(["op1.example.com".to_string()]);
        let healthy = manager.inspect_runtime(&expected);
        assert!(healthy.healthy);
        assert_eq!(healthy.ownership, CamouflageRuntimeOwnership::ModernManaged);
        let healthy_fingerprint = healthy.fingerprint.clone();

        fs::remove_file(&manager.config.nginx.conf_path).unwrap();
        let drifted = manager.inspect_runtime(&expected);
        assert!(!drifted.healthy);
        assert_ne!(drifted.fingerprint, healthy_fingerprint);
        assert!(manager.repair_active_runtime(&expected));
        assert!(manager.inspect_runtime(&expected).healthy);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bootstrap_fallback_without_modern_intent_is_healthy_neutral() {
        let dir = unique_dir("bootstrap-compatibility");
        let mut manager = manager(&dir, "true", "true");
        fs::create_dir_all(manager.config.nginx.conf_path.parent().unwrap()).unwrap();
        fs::write(&manager.config.nginx.conf_path, b"bootstrap fallback\n").unwrap();
        let before = fs::read(&manager.config.nginx.conf_path).unwrap();
        let expected = HashSet::new();

        let observation = manager.inspect_runtime(&expected);
        assert!(observation.healthy);
        assert_eq!(
            observation.ownership,
            CamouflageRuntimeOwnership::BootstrapCompatibility
        );
        assert!(manager.repair_active_runtime(&expected));
        assert_eq!(fs::read(&manager.config.nginx.conf_path).unwrap(), before);
        assert!(!manager.panel_authority_established);
        assert!(manager.active.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn authoritative_empty_does_not_claim_bootstrap_fallback_runtime() {
        let dir = unique_dir("bootstrap-authoritative-empty");
        let mut manager = manager(&dir, "true", "true");
        fs::create_dir_all(manager.config.nginx.conf_path.parent().unwrap()).unwrap();
        fs::write(&manager.config.nginx.conf_path, b"bootstrap fallback\n").unwrap();

        assert!(manager.prepare_desired(&[], true).is_empty());
        assert!(manager.panel_authority_established);
        assert!(manager.active.is_none());
        assert!(manager.finalize_for_listener_snis(&HashSet::new()));
        assert_eq!(
            fs::read(&manager.config.nginx.conf_path).unwrap(),
            b"bootstrap fallback\n"
        );
        assert!(!manager.lkg_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn modern_effective_intent_without_active_manifest_is_drift() {
        let dir = unique_dir("modern-expected-missing");
        let mut manager = manager(&dir, "true", "true");
        fs::create_dir_all(manager.config.nginx.conf_path.parent().unwrap()).unwrap();
        fs::write(&manager.config.nginx.conf_path, b"bootstrap fallback\n").unwrap();
        let expected = HashSet::from(["op1.example.com".to_string()]);

        let observation = manager.inspect_runtime(&expected);
        assert!(!observation.healthy);
        assert_eq!(
            observation.ownership,
            CamouflageRuntimeOwnership::ModernExpectedMissing
        );
        assert!(!manager.repair_active_runtime(&expected));
        assert!(manager.active.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupted_managed_camouflage_wrapper_is_drift_and_repaired() {
        let dir = unique_dir("runtime-corrupt-wrapper");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        fs::write(&manager.config.nginx.conf_path, b"corrupt\n").unwrap();
        let expected = HashSet::from(["op1.example.com".to_string()]);

        assert!(!manager.inspect_runtime(&expected).healthy);
        assert!(manager.repair_active_runtime(&expected));
        assert!(manager.inspect_runtime(&expected).healthy);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_managed_certificate_reference_is_drift() {
        let dir = unique_dir("runtime-invalid-certificate");
        let mut manager = manager(&dir, "true", "true");
        let active = manifest(&dir);
        let cert_path = active.sites[0].certificate.cert_path.clone();
        assert!(manager.apply_candidate(active));
        fs::remove_file(cert_path).unwrap();
        let expected = HashSet::from(["op1.example.com".to_string()]);

        assert!(!manager.inspect_runtime(&expected).healthy);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn model_has_no_reality_or_route_authority() {
        let dir = unique_dir("ownership");
        let json = serde_json::to_string(&manifest(&dir)).unwrap();
        for forbidden in [
            "private_key",
            "public_key",
            "uuid",
            "short_id",
            "flow",
            "xray",
            "public_port",
            "remote_host",
            "remote_port",
            "targets",
        ] {
            assert!(!json.contains(forbidden), "unexpected field {forbidden}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_sni_port_backend_and_duplicates_are_rejected() {
        let dir = unique_dir("validation");
        let mut invalid = site(&dir, "op1", "UPPER.example.com");
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid.clone()]
        })
        .is_err());
        invalid.sni = "op1.example.com".into();
        invalid.tls_listener_port = 443;
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid.clone()]
        })
        .is_err());
        invalid.tls_listener_port = CAMOUFLAGE_TLS_PORT;
        invalid.local_backend = "127.0.0.1:443".into();
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid]
        })
        .is_err());
        let duplicate = site(&dir, "op2", "op1.example.com");
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![site(&dir, "op1", "op1.example.com"), duplicate]
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_candidate_validation_does_not_overwrite_lkg() {
        let dir = unique_dir("validation-lkg");
        let mut manager = manager(&dir, "true", "true");
        let healthy = manifest(&dir);
        assert!(manager.apply_candidate(healthy));
        let before = fs::read(manager.lkg_path()).unwrap();
        let mut invalid = manifest(&dir);
        invalid.sites[0].local_backend = "127.0.0.1:443".into();
        assert!(!manager.apply_candidate(invalid));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before);
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_renewal_keeps_route_active_and_does_not_replace_lkg() {
        let dir = unique_dir("renewal-warning-lkg");
        let mut manager = manager(&dir, "true", "true");
        manager.config.certificate_lifecycle = CertificateLifecycleConfig {
            enabled: true,
            certbot_binary: PathBuf::from("/bin/false"),
            certbot_live_dir: dir.join("letsencrypt/live"),
            webroot: dir.join("webroot"),
            state_dir: dir.join("certificates"),
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
        let lifecycle = CertificateLifecyclePolicy {
            domain: "op1.example.com".into(),
            email: None,
            expected_public_ip: "192.0.2.10".into(),
            renew_before_days: 30,
            challenge_method: relay_shared::protocol::AcmeChallengeMethod::Dns01,
        };
        let mut reference = real_certificate(&dir, "op1", "op1.example.com", 10);
        reference.lifecycle = Some(lifecycle);
        assert!(manager.apply_candidate(CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                id: "op1_example_com".into(),
                sni: "op1.example.com".into(),
                tls_listener_port: CAMOUFLAGE_TLS_PORT,
                local_backend: OPENLIST_BACKEND.into(),
                certificate: reference,
            }],
        }));
        let lkg_before = fs::read(manager.lkg_path()).unwrap();
        let active = manager.prepare_desired(
            &[CamouflageSiteDesired {
                site_id: "op1_example_com".into(),
                sni: "op1.example.com".into(),
                tls_listener_port: CAMOUFLAGE_TLS_PORT,
                local_backend: relay_shared::protocol::CamouflageLocalBackend::OpenList,
                certificate: relay_shared::protocol::CamouflageCertificatePolicy {
                    domain: "op1.example.com".into(),
                    expected_public_ip: "192.0.2.10".into(),
                    renew_before_days: 30,
                    challenge_method: relay_shared::protocol::AcmeChallengeMethod::Dns01,
                },
                enabled: true,
            }],
            true,
        );
        assert!(active.contains("op1.example.com"));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), lkg_before);
        let status = manager.status_snapshot();
        assert_eq!(status[0].site_status, "active");
        assert_eq!(status[0].certificate_status, "active");
        assert!(status[0]
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("automatic renewal failed")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nginx_test_failure_restores_runtime_and_preserves_lkg() {
        let dir = unique_dir("nginx-test");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        let before_lkg = fs::read(manager.lkg_path()).unwrap();
        let before_runtime = fs::read(&manager.config.nginx.conf_path).unwrap();
        manager.config.nginx.test_cmd = "false".into();
        let changed = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(!manager.apply_candidate(changed));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before_lkg);
        assert_eq!(
            fs::read(&manager.config.nginx.conf_path).unwrap(),
            before_runtime
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reload_failure_restores_runtime_and_preserves_lkg() {
        let dir = unique_dir("reload");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        let before_lkg = fs::read(manager.lkg_path()).unwrap();
        let before_runtime = fs::read(&manager.config.nginx.conf_path).unwrap();
        let path = manager.config.nginx.conf_path.clone();
        manager.config.nginx.reload_cmd = format!(
            "if grep -q op2.example.com {}; then exit 1; else exit 0; fi",
            path.display()
        );
        let changed = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(!manager.apply_candidate(changed));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before_lkg);
        assert_eq!(
            fs::read(&manager.config.nginx.conf_path).unwrap(),
            before_runtime
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn success_commits_lkg_and_corrupt_primary_recovers_backup() {
        let dir = unique_dir("backup");
        let mut manager = manager(&dir, "true", "true");
        let first = manifest(&dir);
        assert!(manager.apply_candidate(first.clone()));
        let second = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(manager.apply_candidate(second));
        let backup_before = fs::read(manager.lkg_backup_path()).unwrap();
        fs::write(manager.lkg_path(), b"not-json").unwrap();
        fs::write(manager.lkg_tmp_path(), b"stale-uncommitted-state").unwrap();
        assert_eq!(manager.load_lkg().unwrap(), first);
        assert_eq!(
            serde_json::from_slice::<CamouflageSitesManifest>(
                &fs::read(manager.lkg_path()).unwrap()
            )
            .unwrap(),
            first
        );
        assert_eq!(fs::read(manager.lkg_backup_path()).unwrap(), backup_before);
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn semantically_invalid_primary_recovers_backup() {
        let dir = unique_dir("semantic-backup");
        let mut manager = manager(&dir, "true", "true");
        let first = manifest(&dir);
        assert!(manager.apply_candidate(first.clone()));
        let second = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(manager.apply_candidate(second));

        let mut invalid = manifest(&dir);
        invalid.sites[0].local_backend = "127.0.0.1:443".into();
        fs::write(
            manager.lkg_path(),
            serde_json::to_vec_pretty(&invalid).unwrap(),
        )
        .unwrap();

        assert_eq!(manager.load_lkg().unwrap(), first);
        assert_eq!(
            serde_json::from_slice::<CamouflageSitesManifest>(
                &fs::read(manager.lkg_path()).unwrap()
            )
            .unwrap(),
            first
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_primary_repair_preserves_camouflage_backup() {
        let dir = unique_dir("repair-failure");
        let mut manager = manager(&dir, "true", "true");
        let first = manifest(&dir);
        assert!(manager.apply_candidate(first));
        let second = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(manager.apply_candidate(second));
        let backup_before = fs::read(manager.lkg_backup_path()).unwrap();
        fs::remove_file(manager.lkg_path()).unwrap();
        fs::create_dir(manager.lkg_path()).unwrap();

        assert_eq!(manager.load_lkg().unwrap().sites[0].id, "op1");
        assert_eq!(fs::read(manager.lkg_backup_path()).unwrap(), backup_before);
        assert!(manager.lkg_path().is_dir());
        assert!(!manager.lkg_path().with_extension("json.tmp").exists());
        fs::remove_dir(manager.lkg_path()).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_modern_lkg_does_not_promote_legacy_source_manifest() {
        let dir = unique_dir("legacy-not-authority");
        let mut manager = manager(&dir, "true", "true");
        fs::create_dir_all(&manager.config.state_dir).unwrap();
        fs::write(manager.lkg_path(), b"not-json").unwrap();
        fs::write(manager.lkg_backup_path(), b"not-json").unwrap();
        fs::write(
            manager.lkg_tmp_path(),
            serde_json::to_vec_pretty(&manifest(&dir)).unwrap(),
        )
        .unwrap();
        write_private_file(
            &manager.config.manifest_path,
            &serde_json::to_vec_pretty(&manifest(&dir)).unwrap(),
        )
        .unwrap();

        assert!(!manager.restore_and_apply());
        assert!(manager.active.is_none());
        assert!(!manager.config.nginx.conf_path.exists());
        assert!(!manager.reconcile_active());
        assert!(!manager.config.nginx.conf_path.exists());
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_restores_lkg_without_panel_or_source_manifest() {
        let dir = unique_dir("offline-restart");
        let mut first = manager(&dir, "true", "true");
        let expected = manifest(&dir);
        assert!(first.apply_candidate(expected.clone()));
        assert!(!first.config.manifest_path.exists());

        let mut restarted = manager(&dir, "true", "true");
        assert!(restarted.restore_and_apply());
        assert_eq!(restarted.active, Some(expected));
        let runtime = fs::read_to_string(&restarted.config.nginx.conf_path).unwrap();
        assert!(runtime.contains("op1.example.com"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_keeps_healthy_panel_lkg_when_source_manifest_is_stale() {
        let dir = unique_dir("stale-source-restart");
        let mut first = manager(&dir, "true", "true");
        let panel_lkg = CamouflageSitesManifest {
            sites: vec![site(&dir, "panel-site", "op1.example.com")],
        };
        assert!(first.apply_candidate(panel_lkg.clone()));
        let lkg_before = fs::read(first.lkg_path()).unwrap();

        let stale_source = CamouflageSitesManifest {
            sites: vec![site(&dir, "old-local-site", "op1.example.com")],
        };
        write_private_file(
            &first.config.manifest_path,
            &serde_json::to_vec_pretty(&stale_source).unwrap(),
        )
        .unwrap();

        let mut restarted = manager(&dir, "true", "true");
        assert!(restarted.restore_and_apply());
        assert_eq!(restarted.active, Some(panel_lkg.clone()));
        assert_eq!(fs::read(restarted.lkg_path()).unwrap(), lkg_before);
        assert_eq!(
            restarted.active.as_ref().unwrap().sites[0].certificate,
            panel_lkg.sites[0].certificate
        );
        let runtime = fs::read_to_string(&restarted.config.nginx.conf_path).unwrap();
        assert!(runtime.contains("panel-site.crt"));
        assert!(!runtime.contains("old-local-site.crt"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn certificate_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = unique_dir("symlink");
        let mut site = site(&dir, "op1", "op1.example.com");
        let link = dir.join("linked.key");
        symlink(&site.certificate.key_path, &link).unwrap();
        site.certificate.key_path = link;
        let mut manager = manager(&dir, "true", "true");
        assert!(!manager.apply_candidate(CamouflageSitesManifest { sites: vec![site] }));
        let _ = fs::remove_dir_all(dir);
    }
}
