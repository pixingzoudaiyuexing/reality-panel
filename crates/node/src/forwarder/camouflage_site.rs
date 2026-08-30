//! Relay-local TLS camouflage sites.
//!
//! Remote REALITY forwarding remains ordinary `ListenerConfig` state owned by
//! the Panel and listener LKG. This module owns only the public TLS wrapper
//! used by dedicated REALITY servers as their fallback target.

use super::certificate_lifecycle::{
    certificate_scope_key, inspect_certificate, CertificateLifecycle, CertificateLifecycleConfig,
    CertificateLifecyclePolicy, LifecycleAction, LifecycleReconcileReport, RenewalGate,
    ACME_RETRY_DEFERRED,
};
use super::nginx_sni::{self, NginxSniConfig};
use relay_shared::protocol::{
    CamouflageLocalBackend, CamouflageSiteDesired, CamouflageSiteStatus, NodeConfigResponse,
};
use relay_shared::reconciliation::{config_fingerprint, fingerprint_bytes, ConfigFingerprint};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Notify};

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

#[derive(Clone, Debug)]
pub struct CamouflageSiteManager {
    config: CamouflageSiteConfig,
    active: Option<CamouflageSitesManifest>,
    renewal_gate: Arc<RenewalGate>,
    acme_gate: Arc<std::sync::Mutex<()>>,
    apply_gate: Arc<AsyncMutex<()>>,
    desired: Vec<CamouflageSiteDesired>,
    desired_generation: u64,
    desired_fingerprint: ConfigFingerprint,
    runtime_revision: u64,
    last_errors: HashMap<String, String>,
    last_attempts: HashMap<String, String>,
    renewal_warnings: HashMap<String, (String, String)>,
    panel_authority_established: bool,
    desired_worker_in_flight: bool,
    desired_reconcile_pending: bool,
    reconcile_retry_attempt: usize,
    reconcile_retry_at: Option<Instant>,
    reconcile_retry_backoff: Vec<Duration>,
    acme_retries: HashMap<String, PersistedScopeAcmeRetry>,
    legacy_acme_retry: Option<PersistedDesiredAcmeRetry>,
    acme_retry_backoff: Vec<Duration>,
    acme_jitter_seed: u64,
    acme_jitter_percent: u32,
    dependency_notify: Arc<Notify>,
}

#[derive(Clone)]
struct CertificateReconcileSnapshot {
    generation: u64,
    fingerprint: ConfigFingerprint,
    manifest: CamouflageSitesManifest,
    active: Option<CamouflageSitesManifest>,
    config: CamouflageSiteConfig,
    renewal_gate: Arc<RenewalGate>,
    acme_gate: Arc<std::sync::Mutex<()>>,
    apply_gate: Arc<AsyncMutex<()>>,
    desired_request: bool,
    prepared_site_ids: HashSet<String>,
    allowed_acme_scope_keys: HashSet<String>,
}

struct CertificateReconcileResult {
    snapshot: CertificateReconcileSnapshot,
    outcome: Result<CertificateReconcileOutcome, String>,
}

struct CertificateReconcileOutcome {
    candidate: CamouflageSitesManifest,
    actions: HashMap<String, LifecycleAction>,
    successful_site_ids: HashSet<String>,
    failed_site_errors: HashMap<String, String>,
    attempted_scope_keys: HashSet<String>,
    successful_scope_keys: HashSet<String>,
    failed_scope_keys: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedDesiredAcmeRetry {
    attempt: usize,
    next_retry_unix_ms: i64,
    scope_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedScopeAcmeRetry {
    attempt: usize,
    next_retry_unix_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedDesiredAcmeRetries {
    version: u8,
    scopes: HashMap<String, PersistedScopeAcmeRetry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PersistedDesiredAcmeRetryFile {
    Scoped(PersistedDesiredAcmeRetries),
    Legacy(PersistedDesiredAcmeRetry),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReconcileCommit {
    Applied,
    Failed,
    InFlight,
    Stale,
}

impl CamouflageSiteManager {
    pub fn new(config: CamouflageSiteConfig) -> Self {
        let (acme_retries, legacy_acme_retry) = load_desired_acme_retry(&config.state_dir);
        let acme_jitter_seed = desired_acme_jitter_seed(&config.state_dir);
        Self {
            config,
            active: None,
            renewal_gate: Arc::new(RenewalGate::default()),
            acme_gate: Arc::new(std::sync::Mutex::new(())),
            apply_gate: Arc::new(AsyncMutex::new(())),
            desired: Vec::new(),
            desired_generation: 0,
            desired_fingerprint: camouflage_desired_fingerprint(&[]),
            runtime_revision: 0,
            last_errors: HashMap::new(),
            last_attempts: HashMap::new(),
            renewal_warnings: HashMap::new(),
            panel_authority_established: false,
            desired_worker_in_flight: false,
            desired_reconcile_pending: false,
            reconcile_retry_attempt: 0,
            reconcile_retry_at: None,
            reconcile_retry_backoff: vec![
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ],
            acme_retries,
            legacy_acme_retry,
            acme_retry_backoff: vec![
                Duration::from_secs(30),
                Duration::from_secs(2 * 60),
                Duration::from_secs(5 * 60),
                Duration::from_secs(15 * 60),
                Duration::from_secs(30 * 60),
                Duration::from_secs(60 * 60),
            ],
            acme_jitter_seed,
            acme_jitter_percent: 10,
            dependency_notify: Arc::new(Notify::new()),
        }
    }

    fn update_desired(&mut self, desired: &[CamouflageSiteDesired], panel_authoritative: bool) {
        let next: Vec<_> = desired
            .iter()
            .filter(|site| site.enabled)
            .cloned()
            .collect();
        let next_identities = next
            .iter()
            .map(|site| (site.site_id.as_str(), site.sni.as_str()))
            .collect::<HashSet<_>>();
        let previous_snis = self
            .desired
            .iter()
            .map(|site| (site.site_id.as_str(), site.sni.as_str()))
            .collect::<HashSet<_>>();
        if panel_authoritative {
            let keep_site_id = |site_id: &str| {
                previous_snis
                    .iter()
                    .any(|(id, sni)| *id == site_id && next_identities.contains(&(*id, *sni)))
            };
            self.last_errors.retain(|site_id, _| keep_site_id(site_id));
            self.last_attempts
                .retain(|site_id, _| keep_site_id(site_id));
            self.renewal_warnings
                .retain(|site_id, _| keep_site_id(site_id));
        }
        let next_fingerprint = camouflage_desired_fingerprint(&next);
        let next_scope_fingerprint = desired_acme_scope_fingerprint(&next);
        let next_scope_keys = next
            .iter()
            .filter_map(|site| desired_certificate_scope_key(site).ok())
            .collect::<HashSet<_>>();
        let retry_count = self.acme_retries.len();
        self.acme_retries
            .retain(|scope_key, _| next_scope_keys.contains(scope_key));
        let retry_set_changed = self.acme_retries.len() != retry_count;
        if let Some(legacy) = self.legacy_acme_retry.take() {
            if legacy.scope_fingerprint.is_empty()
                || legacy.scope_fingerprint == next_scope_fingerprint
            {
                for scope_key in next_scope_keys {
                    self.acme_retries
                        .entry(scope_key)
                        .or_insert(PersistedScopeAcmeRetry {
                            attempt: legacy.attempt,
                            next_retry_unix_ms: legacy.next_retry_unix_ms,
                        });
                }
            }
            self.persist_acme_retries();
        } else if retry_set_changed {
            self.persist_acme_retries();
        }
        let changed = next_fingerprint != self.desired_fingerprint;
        if changed {
            self.desired_generation = self.desired_generation.wrapping_add(1);
            self.desired_fingerprint = next_fingerprint;
            self.desired_reconcile_pending = true;
            self.reconcile_retry_attempt = 0;
            self.reconcile_retry_at = None;
        }
        self.desired = next;
        if panel_authoritative {
            self.panel_authority_established = true;
        }
    }

    /// Restore the camouflage LKG before the listener LKG is activated. This
    /// path has no dependency on Panel availability.
    pub fn restore_and_apply(&mut self) -> bool {
        if !self.config.enabled {
            return true;
        }

        if let Err(error) = CertificateLifecycle::new(self.config.certificate_lifecycle.clone())
            .ensure_https_redirect()
        {
            tracing::warn!("managed HTTP redirect is not converged: {}", error);
        }

        let recovered = self.load_lkg().ok();
        let mut recovered_applied = false;
        if let Some(manifest) = recovered.as_ref() {
            match self.apply_runtime(manifest) {
                Ok(()) => {
                    self.active = Some(manifest.clone());
                    self.runtime_revision = self.runtime_revision.wrapping_add(1);
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
    #[cfg(test)]
    pub fn reconcile_from_source(&mut self) -> bool {
        tracing::warn!(
            "legacy camouflage source manifest is not authoritative; waiting for Panel sync"
        );
        false
    }

    /// Scheduler path after Panel ownership has been established. The active
    /// LKG carries both the Node-owned generation and lifecycle policy, so it
    /// remains renewable while the Panel is unavailable.
    #[cfg(test)]
    pub fn reconcile_active(&mut self) -> bool {
        let Some(manifest) = self.active.clone() else {
            return self.reconcile_from_source();
        };
        self.reconcile_and_apply_manifest(manifest)
    }

    /// Prepare all Panel-desired sites while retaining old active sites. The
    /// caller activates dependent :443 listeners only for the returned SNI set,
    /// then calls `finalize_for_listener_snis` to remove unreferenced wrappers.
    #[cfg(test)]
    pub fn prepare_desired(
        &mut self,
        desired: &[CamouflageSiteDesired],
        panel_authoritative: bool,
    ) -> HashSet<String> {
        self.update_desired(desired, panel_authoritative);
        if !panel_authoritative {
            return self.active_snis();
        }
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

    fn active_reconcile_snapshot(&self) -> Option<CertificateReconcileSnapshot> {
        Some(CertificateReconcileSnapshot {
            generation: self.desired_generation,
            fingerprint: self.desired_fingerprint.clone(),
            manifest: self.active.clone()?,
            active: self.active.clone(),
            config: self.config.clone(),
            renewal_gate: Arc::clone(&self.renewal_gate),
            acme_gate: Arc::clone(&self.acme_gate),
            apply_gate: Arc::clone(&self.apply_gate),
            desired_request: false,
            prepared_site_ids: HashSet::new(),
            allowed_acme_scope_keys: HashSet::new(),
        })
    }

    fn desired_reconcile_snapshot(
        &mut self,
        desired: &[CamouflageSiteDesired],
        panel_authoritative: bool,
    ) -> Option<CertificateReconcileSnapshot> {
        self.update_desired(desired, panel_authoritative);
        if !panel_authoritative || self.desired.is_empty() {
            if panel_authoritative {
                self.desired_reconcile_pending = false;
            }
            return None;
        }
        if self.desired_worker_in_flight
            || (!self.desired_reconcile_pending && !self.desired_control_work_is_due())
        {
            return None;
        }
        let mut candidate = self
            .active
            .clone()
            .unwrap_or(CamouflageSitesManifest { sites: Vec::new() });
        let mut prepared_site_ids = HashSet::new();
        for desired_site in &self.desired {
            if let Err(error) = validate_desired(desired_site) {
                self.last_errors
                    .insert(desired_site.site_id.clone(), sanitize_error(&error));
                continue;
            }
            prepared_site_ids.insert(desired_site.site_id.clone());
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

        if prepared_site_ids.is_empty() {
            self.desired_reconcile_pending = false;
            return None;
        }
        let attempted_at = chrono::Utc::now().to_rfc3339();
        for site_id in &prepared_site_ids {
            self.last_attempts
                .insert(site_id.clone(), attempted_at.clone());
        }
        self.desired_worker_in_flight = true;
        self.desired_reconcile_pending = false;
        self.reconcile_retry_at = None;

        Some(CertificateReconcileSnapshot {
            generation: self.desired_generation,
            fingerprint: self.desired_fingerprint.clone(),
            manifest: candidate,
            active: self.active.clone(),
            config: self.config.clone(),
            renewal_gate: Arc::clone(&self.renewal_gate),
            acme_gate: Arc::clone(&self.acme_gate),
            apply_gate: Arc::clone(&self.apply_gate),
            desired_request: true,
            prepared_site_ids,
            allowed_acme_scope_keys: self
                .desired
                .iter()
                .filter_map(|site| desired_certificate_scope_key(site).ok())
                .filter(|scope_key| self.acme_scope_is_due(scope_key))
                .collect(),
        })
    }

    fn reconcile_retry_is_due(&self) -> bool {
        self.reconcile_retry_at
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }

    fn acme_scope_is_due(&self, scope_key: &str) -> bool {
        self.acme_retries
            .get(scope_key)
            .map(|retry| unix_time_millis() >= retry.next_retry_unix_ms)
            .unwrap_or(true)
    }

    fn acme_retry_is_due(&self) -> bool {
        self.acme_retries.iter().any(|(scope_key, retry)| {
            self.desired.iter().any(|site| {
                desired_certificate_scope_key(site).as_deref() == Ok(scope_key.as_str())
            }) && unix_time_millis() >= retry.next_retry_unix_ms
        })
    }

    fn desired_control_work_is_due(&self) -> bool {
        self.reconcile_retry_is_due() || self.acme_retry_is_due()
    }

    fn schedule_reconcile_retry(&mut self) {
        let index = self
            .reconcile_retry_attempt
            .min(self.reconcile_retry_backoff.len().saturating_sub(1));
        let delay = self
            .reconcile_retry_backoff
            .get(index)
            .copied()
            .unwrap_or_else(|| Duration::from_secs(60));
        self.reconcile_retry_attempt = self.reconcile_retry_attempt.saturating_add(1);
        self.reconcile_retry_at = Some(Instant::now() + delay);
    }

    fn schedule_acme_retry(&mut self, scope_key: &str) {
        let attempt = self
            .acme_retries
            .get(scope_key)
            .map(|retry| retry.attempt)
            .unwrap_or_default();
        let index = attempt.min(self.acme_retry_backoff.len().saturating_sub(1));
        let base = self
            .acme_retry_backoff
            .get(index)
            .copied()
            .unwrap_or_else(|| Duration::from_secs(60 * 60));
        let jitter_limit = base
            .as_millis()
            .saturating_mul(self.acme_jitter_percent as u128)
            / 100;
        let jitter_ms = if jitter_limit == 0 {
            0
        } else {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            scope_key.hash(&mut hasher);
            (self
                .acme_jitter_seed
                .wrapping_add(hasher.finish())
                .wrapping_add(attempt as u64)
                % (jitter_limit as u64 + 1)) as u128
        };
        let delay_ms = base.as_millis().saturating_add(jitter_ms);
        self.acme_retries.insert(
            scope_key.to_string(),
            PersistedScopeAcmeRetry {
                attempt: attempt.saturating_add(1),
                next_retry_unix_ms: unix_time_millis()
                    .saturating_add(delay_ms.min(i64::MAX as u128) as i64),
            },
        );
        self.persist_acme_retries();
    }

    fn clear_acme_retry(&mut self, scope_key: &str) {
        if self.acme_retries.remove(scope_key).is_some() {
            self.persist_acme_retries();
        }
    }

    fn persist_acme_retries(&self) {
        if let Err(error) = persist_desired_acme_retries(&self.config.state_dir, &self.acme_retries)
        {
            tracing::warn!("could not persist desired ACME retry protection: {error}");
        }
    }

    fn finish_desired_worker(&mut self, retry: bool) {
        self.desired_worker_in_flight = false;
        if retry {
            self.schedule_reconcile_retry();
        } else {
            self.reconcile_retry_attempt = 0;
            self.reconcile_retry_at = None;
        }
        self.dependency_notify.notify_one();
    }

    fn finish_desired_worker_with_scopes(
        &mut self,
        retry: bool,
        attempted_scope_keys: &HashSet<String>,
        successful_scope_keys: &HashSet<String>,
        failed_scope_keys: &HashSet<String>,
    ) {
        for scope_key in successful_scope_keys {
            self.clear_acme_retry(scope_key);
        }
        for scope_key in failed_scope_keys {
            if attempted_scope_keys.contains(scope_key) {
                self.schedule_acme_retry(scope_key);
            }
        }
        self.finish_desired_worker(retry);
    }

    fn desired_retry_delay(&self) -> Option<Duration> {
        if self.desired_worker_in_flight {
            return None;
        }
        let reconcile = self
            .reconcile_retry_at
            .map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let acme = self
            .acme_retries
            .values()
            .map(|retry| {
                Duration::from_millis(
                    retry
                        .next_retry_unix_ms
                        .saturating_sub(unix_time_millis())
                        .max(0) as u64,
                )
            })
            .min();
        match (reconcile, acme) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(delay), None) | (None, Some(delay)) => Some(delay),
            (None, None) => None,
        }
    }

    #[cfg(test)]
    fn set_desired_retry_backoff_for_test(&mut self, delays: Vec<Duration>) {
        self.reconcile_retry_backoff = delays.clone();
        self.acme_retry_backoff = delays;
        self.acme_jitter_percent = 0;
    }

    #[cfg(test)]
    pub(crate) fn record_renewal_warning_for_test(&mut self, site_id: &str, error: &str) {
        self.renewal_warnings.insert(
            site_id.to_string(),
            (chrono::Utc::now().to_rfc3339(), error.to_string()),
        );
    }

    /// Remove sites only after the effective listener transaction succeeded.
    #[cfg(test)]
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

    #[cfg(test)]
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
                        "failed_retrying"
                    } else {
                        "preparing"
                    }
                    .into(),
                    certificate_status: if is_active && renewal_warning.is_some() {
                        "renewal_warning"
                    } else if is_active {
                        "active"
                    } else if failed {
                        "failed_retrying"
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
                    last_attempt: renewal_warning
                        .as_ref()
                        .map(|(attempt, _)| attempt.clone())
                        .or_else(|| self.last_attempts.get(&desired.site_id).cloned()),
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

    #[cfg(test)]
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

    #[cfg(test)]
    fn try_reconcile_and_apply_manifest(
        &mut self,
        manifest: CamouflageSitesManifest,
    ) -> Result<(), String> {
        let report = run_certificate_reconcile(
            &self.config,
            &self.renewal_gate,
            &self.acme_gate,
            manifest,
            self.active.as_ref(),
            None,
        )?;
        if let Some(error) = report.failed_site_errors.values().next() {
            return Err(error.clone());
        }
        let candidate = report.manifest;
        let actions = candidate
            .sites
            .iter()
            .map(|site| {
                report
                    .actions
                    .get(&site.id)
                    .copied()
                    .unwrap_or(LifecycleAction::Unchanged)
            })
            .collect::<Vec<_>>();
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

        let previous = self.active.clone();
        self.active = Some(candidate.clone());
        self.cleanup_committed_state(previous.as_ref(), &candidate);
        self.runtime_revision = self.runtime_revision.wrapping_add(1);
        tracing::info!(
            sites = candidate.sites.len(),
            "camouflage sites applied and committed as local LKG"
        );
        true
    }

    /// Remove state that is no longer reachable from the current LKG while
    /// retaining the active and immediately previous certificate generations.
    /// This runs only after runtime activation and LKG commit have succeeded.
    fn cleanup_committed_state(
        &self,
        previous: Option<&CamouflageSitesManifest>,
        current: &CamouflageSitesManifest,
    ) {
        let mut protected_files = Vec::new();
        for manifest in [previous, Some(current)].into_iter().flatten() {
            for site in &manifest.sites {
                protected_files.push(site.certificate.cert_path.clone());
                protected_files.push(site.certificate.key_path.clone());
            }
        }

        let generations_root = self
            .config
            .certificate_lifecycle
            .state_dir
            .join("generations");
        let current_ids = current
            .sites
            .iter()
            .map(|site| site.id.as_str())
            .collect::<HashSet<_>>();
        if let Ok(entries) = fs::read_dir(&generations_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(site_id) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if current_ids.contains(site_id) {
                    prune_site_generations(&path, &protected_files);
                } else if !protected_files.iter().any(|file| file.starts_with(&path)) {
                    remove_private_directory(&path);
                }
            }
        }

        let pending_root = self.config.certificate_lifecycle.state_dir.join("pending");
        if let Ok(entries) = fs::read_dir(&pending_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !protected_files.iter().any(|file| file.starts_with(&path)) {
                    remove_private_directory(&path);
                }
            }
        }
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

const RECONCILE_IN_FLIGHT: &str = "camouflage certificate renewal already in progress";
const DESIRED_ACME_RETRY_FILE: &str = "desired-acme-retry.json";

fn unix_time_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn desired_acme_retry_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DESIRED_ACME_RETRY_FILE)
}

fn desired_acme_scope_fingerprint(desired: &[CamouflageSiteDesired]) -> String {
    let mut scopes: Vec<_> = desired
        .iter()
        .filter(|site| site.enabled)
        .map(|site| {
            site.certificate
                .domain
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .collect();
    scopes.sort();
    scopes.dedup();
    fingerprint_bytes(&serde_json::to_vec(&scopes).unwrap_or_default())
        .as_str()
        .to_string()
}

fn desired_certificate_scope_key(site: &CamouflageSiteDesired) -> Result<String, String> {
    certificate_scope_key(&CertificateLifecyclePolicy {
        domain: site.certificate.domain.clone(),
        email: None,
        expected_public_ip: site.certificate.expected_public_ip.clone(),
        renew_before_days: site.certificate.renew_before_days,
        challenge_method: site.certificate.challenge_method,
    })
}

fn desired_acme_jitter_seed(state_dir: &Path) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    state_dir.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    hasher.finish()
}

fn load_desired_acme_retry(
    state_dir: &Path,
) -> (
    HashMap<String, PersistedScopeAcmeRetry>,
    Option<PersistedDesiredAcmeRetry>,
) {
    let path = desired_acme_retry_path(state_dir);
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<PersistedDesiredAcmeRetryFile>(&bytes) {
            Ok(PersistedDesiredAcmeRetryFile::Scoped(mut state)) if state.version == 2 => {
                let now = unix_time_millis();
                let maximum = now.saturating_add(66 * 60 * 1000);
                for retry in state.scopes.values_mut() {
                    retry.next_retry_unix_ms = retry.next_retry_unix_ms.min(maximum);
                }
                (state.scopes, None)
            }
            Ok(PersistedDesiredAcmeRetryFile::Legacy(mut state)) => {
                let maximum = unix_time_millis().saturating_add(66 * 60 * 1000);
                state.next_retry_unix_ms = state.next_retry_unix_ms.min(maximum);
                (HashMap::new(), Some(state))
            }
            Ok(PersistedDesiredAcmeRetryFile::Scoped(_)) => {
                tracing::warn!(
                    "desired ACME retry state version is unsupported; applying conservative restart backoff"
                );
                (
                    HashMap::new(),
                    Some(PersistedDesiredAcmeRetry {
                        attempt: usize::MAX,
                        next_retry_unix_ms: unix_time_millis() + 60 * 60 * 1000,
                        scope_fingerprint: String::new(),
                    }),
                )
            }
            Err(error) => {
                tracing::warn!(
                    "desired ACME retry state is invalid; applying conservative restart backoff: {error}"
                );
                (
                    HashMap::new(),
                    Some(PersistedDesiredAcmeRetry {
                        attempt: usize::MAX,
                        next_retry_unix_ms: unix_time_millis() + 60 * 60 * 1000,
                        scope_fingerprint: String::new(),
                    }),
                )
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (HashMap::new(), None),
        Err(error) => {
            tracing::warn!(
                "desired ACME retry state is unreadable; applying conservative restart backoff: {error}"
            );
            (
                HashMap::new(),
                Some(PersistedDesiredAcmeRetry {
                    attempt: usize::MAX,
                    next_retry_unix_ms: unix_time_millis() + 60 * 60 * 1000,
                    scope_fingerprint: String::new(),
                }),
            )
        }
    }
}

fn persist_desired_acme_retries(
    state_dir: &Path,
    scopes: &HashMap<String, PersistedScopeAcmeRetry>,
) -> Result<(), String> {
    if scopes.is_empty() {
        remove_desired_acme_retry(state_dir);
        return Ok(());
    }
    let state = PersistedDesiredAcmeRetries {
        version: 2,
        scopes: scopes.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?;
    write_private_file(&desired_acme_retry_path(state_dir), &bytes)
}

fn remove_desired_acme_retry(state_dir: &Path) {
    let path = desired_acme_retry_path(state_dir);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if let Err(error) = fs::remove_file(&path).and_then(|_| sync_parent(&path)) {
                tracing::warn!("could not clear desired ACME retry protection: {error}");
            }
        }
        Ok(_) => tracing::warn!("leaving non-file desired ACME retry state untouched"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!("could not inspect desired ACME retry state: {error}"),
    }
}

fn camouflage_desired_fingerprint(desired: &[CamouflageSiteDesired]) -> ConfigFingerprint {
    config_fingerprint(&NodeConfigResponse {
        listeners: Vec::new(),
        camouflage_sites: desired.to_vec(),
    })
}

fn run_certificate_reconcile(
    config: &CamouflageSiteConfig,
    renewal_gate: &Arc<RenewalGate>,
    acme_gate: &Arc<std::sync::Mutex<()>>,
    mut manifest: CamouflageSitesManifest,
    active: Option<&CamouflageSitesManifest>,
    allowed_acme_scopes: Option<&HashSet<String>>,
) -> Result<LifecycleReconcileReport, String> {
    // Certbot uses its default shared config/work/log roots. Keep that tool
    // serialized independently from the state mutex; status reads remain free.
    let _acme_lease = acme_gate
        .lock()
        .map_err(|_| "certificate lifecycle gate is unavailable".to_string())?;
    let mut scope_keys = manifest
        .sites
        .iter()
        .filter_map(|site| site.certificate.lifecycle.as_ref())
        .filter_map(|policy| certificate_scope_key(policy).ok())
        .collect::<Vec<_>>();
    scope_keys.sort();
    scope_keys.dedup();
    let Some(_renewal_lease) = renewal_gate.try_acquire(scope_keys) else {
        return Err(RECONCILE_IN_FLIGHT.into());
    };

    // The source manifest carries policy, while a healthy LKG carries the
    // active Node-owned generation. Do not regress a periodic check back to a
    // Certbot live path after a successful install.
    if let Some(active) = active {
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

    CertificateLifecycle::new(config.certificate_lifecycle.clone())
        .reconcile_scoped(&manifest, allowed_acme_scopes)
}

fn run_snapshot(snapshot: CertificateReconcileSnapshot) -> CertificateReconcileResult {
    tracing::info!(
        generation = snapshot.generation,
        fingerprint = %snapshot.fingerprint,
        sites = snapshot.manifest.sites.len(),
        "camouflage certificate reconcile started"
    );
    let outcome = if snapshot.desired_request {
        Ok(run_desired_certificate_reconcile(&snapshot))
    } else {
        run_certificate_reconcile(
            &snapshot.config,
            &snapshot.renewal_gate,
            &snapshot.acme_gate,
            snapshot.manifest.clone(),
            snapshot.active.as_ref(),
            None,
        )
        .map(|report| CertificateReconcileOutcome {
            candidate: report.manifest,
            actions: report.actions,
            successful_site_ids: report.successful_site_ids,
            failed_site_errors: report.failed_site_errors,
            attempted_scope_keys: report.attempted_scope_keys,
            successful_scope_keys: report.successful_scope_keys,
            failed_scope_keys: report.failed_scope_keys,
        })
    };
    tracing::info!(
        generation = snapshot.generation,
        fingerprint = %snapshot.fingerprint,
        success = outcome.is_ok(),
        "camouflage certificate reconcile slow work completed"
    );
    CertificateReconcileResult { snapshot, outcome }
}

fn run_desired_certificate_reconcile(
    snapshot: &CertificateReconcileSnapshot,
) -> CertificateReconcileOutcome {
    let mut candidate = snapshot
        .active
        .clone()
        .unwrap_or(CamouflageSitesManifest { sites: Vec::new() });
    let desired_manifest = CamouflageSitesManifest {
        sites: snapshot
            .manifest
            .sites
            .iter()
            .filter(|site| snapshot.prepared_site_ids.contains(&site.id))
            .cloned()
            .collect(),
    };
    let report = run_certificate_reconcile(
        &snapshot.config,
        &snapshot.renewal_gate,
        &snapshot.acme_gate,
        desired_manifest,
        snapshot.active.as_ref(),
        Some(&snapshot.allowed_acme_scope_keys),
    );

    let report = match report {
        Ok(report) => report,
        Err(error) => {
            return CertificateReconcileOutcome {
                candidate,
                actions: HashMap::new(),
                successful_site_ids: HashSet::new(),
                failed_site_errors: snapshot
                    .prepared_site_ids
                    .iter()
                    .map(|site_id| (site_id.clone(), sanitize_error(&error)))
                    .collect(),
                attempted_scope_keys: HashSet::new(),
                successful_scope_keys: HashSet::new(),
                failed_scope_keys: HashSet::new(),
            };
        }
    };
    for reconciled_site in &report.manifest.sites {
        if !report.successful_site_ids.contains(&reconciled_site.id) {
            continue;
        }
        candidate
            .sites
            .retain(|site| site.id != reconciled_site.id && site.sni != reconciled_site.sni);
        candidate.sites.push(reconciled_site.clone());
    }

    CertificateReconcileOutcome {
        candidate,
        actions: report.actions,
        successful_site_ids: report.successful_site_ids,
        failed_site_errors: report.failed_site_errors,
        attempted_scope_keys: report.attempted_scope_keys,
        successful_scope_keys: report.successful_scope_keys,
        failed_scope_keys: report.failed_scope_keys,
    }
}

fn activate_candidate_external(
    config: CamouflageSiteConfig,
    active: Option<CamouflageSitesManifest>,
    candidate: CamouflageSitesManifest,
) -> bool {
    let mut detached = CamouflageSiteManager::new(config);
    detached.active = active;
    if detached.active.as_ref() == Some(&candidate) && detached.runtime_matches(&candidate) {
        return true;
    }
    detached.apply_candidate(candidate)
}

async fn commit_snapshot(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
    result: CertificateReconcileResult,
) -> ReconcileCommit {
    let CertificateReconcileResult { snapshot, outcome } = result;
    let _apply_lease = snapshot.apply_gate.lock().await;

    {
        let current = shared.lock().await;
        if current.desired_generation != snapshot.generation
            || current.desired_fingerprint != snapshot.fingerprint
            || current.active != snapshot.active
        {
            tracing::info!(
                old_generation = snapshot.generation,
                current_generation = current.desired_generation,
                old_fingerprint = %snapshot.fingerprint,
                current_fingerprint = %current.desired_fingerprint,
                "stale camouflage certificate reconcile result discarded"
            );
            drop(current);
            if snapshot.desired_request {
                shared.lock().await.finish_desired_worker(false);
            }
            return ReconcileCommit::Stale;
        }
    }

    let CertificateReconcileOutcome {
        candidate,
        actions,
        successful_site_ids,
        failed_site_errors,
        attempted_scope_keys,
        successful_scope_keys,
        failed_scope_keys,
    } = match outcome {
        Ok(value) => value,
        Err(error) if error == RECONCILE_IN_FLIGHT => {
            if snapshot.desired_request {
                shared.lock().await.finish_desired_worker(true);
            }
            return ReconcileCommit::InFlight;
        }
        Err(error) => {
            let current_snapshot = shared.lock().await.clone();
            let active_snis = tokio::task::spawn_blocking(move || current_snapshot.active_snis())
                .await
                .unwrap_or_default();
            let mut current = shared.lock().await;
            if current.desired_generation != snapshot.generation
                || current.desired_fingerprint != snapshot.fingerprint
                || current.active != snapshot.active
            {
                if snapshot.desired_request {
                    current.finish_desired_worker(false);
                }
                return ReconcileCommit::Stale;
            }
            if snapshot.desired_request {
                for site in current.desired.clone() {
                    if snapshot.prepared_site_ids.contains(&site.site_id)
                        && !active_snis.contains(&site.sni)
                    {
                        current
                            .last_errors
                            .insert(site.site_id.clone(), sanitize_error(&error));
                    }
                }
                current.finish_desired_worker_with_scopes(
                    true,
                    &snapshot.allowed_acme_scope_keys,
                    &HashSet::new(),
                    &snapshot.allowed_acme_scope_keys,
                );
            }
            return ReconcileCommit::Failed;
        }
    };

    let config = snapshot.config.clone();
    let active = snapshot.active.clone();
    let candidate_for_apply = candidate.clone();
    let activated = tokio::task::spawn_blocking(move || {
        activate_candidate_external(config, active, candidate_for_apply)
    })
    .await
    .unwrap_or(false);

    let mut current = shared.lock().await;
    if current.desired_generation != snapshot.generation
        || current.desired_fingerprint != snapshot.fingerprint
        || current.active != snapshot.active
    {
        tracing::error!(
            old_generation = snapshot.generation,
            current_generation = current.desired_generation,
            "camouflage generation changed while the apply gate was held"
        );
        if snapshot.desired_request {
            current.finish_desired_worker(false);
        }
        return ReconcileCommit::Stale;
    }
    if !activated {
        if snapshot.desired_request {
            let current_snapshot = current.clone();
            drop(current);
            let active_snis = tokio::task::spawn_blocking(move || current_snapshot.active_snis())
                .await
                .unwrap_or_default();
            current = shared.lock().await;
            for site in current.desired.clone() {
                if snapshot.prepared_site_ids.contains(&site.site_id)
                    && !active_snis.contains(&site.sni)
                {
                    current.last_errors.insert(
                        site.site_id.clone(),
                        "camouflage runtime validation or LKG commit failed".into(),
                    );
                }
            }
            current.finish_desired_worker_with_scopes(
                true,
                &attempted_scope_keys,
                &successful_scope_keys,
                &failed_scope_keys,
            );
        }
        return ReconcileCommit::Failed;
    }

    for site in &candidate.sites {
        let Some(action) = actions.get(&site.id) else {
            continue;
        };
        if *action == LifecycleAction::RenewalWarning {
            current.renewal_warnings.insert(
                site.id.clone(),
                (
                    chrono::Utc::now().to_rfc3339(),
                    "Certificate remains valid; automatic renewal failed and will be retried"
                        .into(),
                ),
            );
        } else {
            current.renewal_warnings.remove(&site.id);
        }
    }
    if snapshot.desired_request {
        for site_id in &successful_site_ids {
            current.last_errors.remove(site_id);
        }
        for (site_id, error) in &failed_site_errors {
            if error != ACME_RETRY_DEFERRED || !current.last_errors.contains_key(site_id) {
                current.last_errors.insert(site_id.clone(), error.clone());
            }
        }
    }
    if current.active.as_ref() != Some(&candidate) {
        current.runtime_revision = current.runtime_revision.wrapping_add(1);
    }
    current.active = Some(candidate);
    if snapshot.desired_request {
        current.finish_desired_worker_with_scopes(
            !failed_site_errors.is_empty(),
            &attempted_scope_keys,
            &successful_scope_keys,
            &failed_scope_keys,
        );
    }
    tracing::info!(
        generation = snapshot.generation,
        fingerprint = %snapshot.fingerprint,
        "camouflage certificate reconcile result committed"
    );
    if failed_site_errors.is_empty() {
        ReconcileCommit::Applied
    } else {
        ReconcileCommit::Failed
    }
}

pub async fn reconcile_active_shared(shared: &Arc<AsyncMutex<CamouflageSiteManager>>) -> bool {
    let snapshot = {
        let current = shared.lock().await;
        current.active_reconcile_snapshot()
    };
    let Some(snapshot) = snapshot else {
        tracing::warn!(
            "legacy camouflage source manifest is not authoritative; waiting for Panel sync"
        );
        return false;
    };
    let result = match tokio::task::spawn_blocking(move || run_snapshot(snapshot)).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!("camouflage certificate worker failed: {error}");
            return false;
        }
    };
    matches!(
        commit_snapshot(shared, result).await,
        ReconcileCommit::Applied | ReconcileCommit::InFlight | ReconcileCommit::Stale
    )
}

pub async fn prepare_desired_shared(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
    desired: &[CamouflageSiteDesired],
    panel_authoritative: bool,
) -> HashSet<String> {
    let apply_gate = {
        let current = shared.lock().await;
        Arc::clone(&current.apply_gate)
    };
    let snapshot = {
        let _apply_lease = apply_gate.lock().await;
        let mut current = shared.lock().await;
        current.desired_reconcile_snapshot(desired, panel_authoritative)
    };
    let Some(snapshot) = snapshot else {
        return active_snis_shared(shared).await;
    };

    if snapshot.config.certificate_lifecycle.enabled {
        let shared = Arc::clone(shared);
        let generation = snapshot.generation;
        let fingerprint = snapshot.fingerprint.clone();
        let prepared_site_ids = snapshot.prepared_site_ids.clone();
        tokio::spawn(async move {
            match tokio::task::spawn_blocking(move || run_snapshot(snapshot)).await {
                Ok(result) => {
                    let _ = commit_snapshot(&shared, result).await;
                }
                Err(error) => {
                    tracing::error!("camouflage certificate worker failed: {error}");
                    let mut current = shared.lock().await;
                    if current.desired_generation == generation
                        && current.desired_fingerprint == fingerprint
                    {
                        let error = sanitize_error(&error.to_string());
                        for site_id in prepared_site_ids {
                            current.last_errors.insert(site_id, error.clone());
                        }
                        current.finish_desired_worker(true);
                    } else {
                        current.finish_desired_worker(false);
                    }
                }
            }
        });
    } else {
        // Disabled lifecycle is a local, deterministic manifest transition and
        // is kept inline for startup/recovery compatibility.
        let result = run_snapshot(snapshot);
        let _ = commit_snapshot(shared, result).await;
    }
    active_snis_shared(shared).await
}

pub async fn desired_retry_due(shared: &Arc<AsyncMutex<CamouflageSiteManager>>) -> bool {
    let current = shared.lock().await;
    !current.desired_worker_in_flight
        && (current.desired_reconcile_pending || current.desired_control_work_is_due())
}

pub async fn desired_dependency_notify(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
) -> Arc<Notify> {
    Arc::clone(&shared.lock().await.dependency_notify)
}

pub async fn desired_retry_delay(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
) -> Option<Duration> {
    shared.lock().await.desired_retry_delay()
}

pub async fn active_snis_shared(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
) -> HashSet<String> {
    let snapshot = shared.lock().await.clone();
    tokio::task::spawn_blocking(move || snapshot.active_snis())
        .await
        .unwrap_or_default()
}

pub async fn runtime_apply_guard(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
) -> tokio::sync::OwnedMutexGuard<()> {
    let gate = {
        let current = shared.lock().await;
        Arc::clone(&current.apply_gate)
    };
    gate.lock_owned().await
}

pub async fn finalize_for_listener_snis_shared_under_apply_gate(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
    referenced_snis: &HashSet<String>,
) -> bool {
    let (config, active, candidate) = {
        let current = shared.lock().await;
        if !current.panel_authority_established && current.desired.is_empty() {
            return true;
        }
        let Some(active) = current.active.clone() else {
            return referenced_snis.is_empty();
        };
        let candidate = CamouflageSitesManifest {
            sites: active
                .sites
                .iter()
                .filter(|site| referenced_snis.contains(&site.sni))
                .cloned()
                .collect(),
        };
        if active == candidate {
            return true;
        }
        (current.config.clone(), Some(active), candidate)
    };
    let candidate_for_apply = candidate.clone();
    let applied = tokio::task::spawn_blocking(move || {
        activate_candidate_external(config, active, candidate_for_apply)
    })
    .await
    .unwrap_or(false);
    if applied {
        let mut current = shared.lock().await;
        current.active = Some(candidate);
        current.runtime_revision = current.runtime_revision.wrapping_add(1);
    }
    applied
}

pub async fn repair_active_runtime_shared(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
    expected_snis: &HashSet<String>,
) -> bool {
    let _apply_lease = runtime_apply_guard(shared).await;
    let (config, active) = {
        let current = shared.lock().await;
        let Some(active) = current.active.clone() else {
            return expected_snis.is_empty();
        };
        let active_snis: HashSet<_> = active.sites.iter().map(|site| site.sni.clone()).collect();
        if !expected_snis.is_subset(&active_snis) {
            return false;
        }
        (current.config.clone(), active)
    };
    let active_for_work = active.clone();
    let applied = tokio::task::spawn_blocking(move || {
        let detached = CamouflageSiteManager::new(config.clone());
        if detached.runtime_matches(&active_for_work) {
            return true;
        }
        activate_candidate_external(config, Some(active_for_work.clone()), active_for_work)
    })
    .await
    .unwrap_or(false);
    if !applied {
        return false;
    }
    shared.lock().await.active.as_ref() == Some(&active)
}

pub async fn status_snapshot_shared(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
) -> Vec<CamouflageSiteStatus> {
    let snapshot = shared.lock().await.clone();
    tokio::task::spawn_blocking(move || snapshot.status_snapshot())
        .await
        .unwrap_or_default()
}

pub async fn runtime_observation_shared(
    shared: &Arc<AsyncMutex<CamouflageSiteManager>>,
    expected_snis: &HashSet<String>,
) -> CamouflageRuntimeObservation {
    let snapshot = shared.lock().await.clone();
    let expected = expected_snis.clone();
    tokio::task::spawn_blocking(move || snapshot.inspect_runtime(&expected))
        .await
        .unwrap_or_else(|_| CamouflageRuntimeObservation {
            fingerprint: fingerprint_bytes(b"camouflage-runtime-inspection-failed"),
            healthy: false,
            ownership: CamouflageRuntimeOwnership::ModernExpectedMissing,
        })
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
    if !relay_shared::reconciliation::certificate_domain_covers_sni(
        &site.certificate.domain,
        &site.sni,
    ) || site
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

const MAX_RETAINED_CERTIFICATE_GENERATIONS: usize = 3;

fn prune_site_generations(site_root: &Path, protected_files: &[PathBuf]) {
    let Ok(metadata) = fs::symlink_metadata(site_root) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }
    let mut generations = fs::read_dir(site_root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            fs::symlink_metadata(path)
                .map(|value| value.is_dir() && !value.file_type().is_symlink())
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    generations.sort_by(|left, right| right.cmp(left));

    let mut keep = generations
        .iter()
        .take(MAX_RETAINED_CERTIFICATE_GENERATIONS)
        .cloned()
        .collect::<HashSet<_>>();
    for file in protected_files {
        if let Some(parent) = file.parent() {
            if parent.parent() == Some(site_root) {
                keep.insert(parent.to_path_buf());
            }
        }
    }
    for generation in generations {
        if !keep.contains(&generation) {
            remove_private_directory(&generation);
        }
    }
}

fn remove_private_directory(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }
    if let Err(error) = fs::remove_dir_all(path) {
        tracing::warn!(path = %path.display(), "could not remove stale camouflage state: {error}");
    }
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
        real_certificate_with_window(
            dir,
            name,
            sni,
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(valid_for_days),
        )
    }

    fn real_certificate_with_window(
        dir: &Path,
        name: &str,
        sni: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> CertificateReference {
        use rcgen::{CertificateParams, KeyPair};
        create_private_dir(dir).unwrap();
        let mut params = CertificateParams::new(vec![sni.to_string()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
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
    fn committed_generation_cleanup_keeps_active_rollback_and_removes_old_state() {
        let dir = unique_dir("generation-cleanup");
        let root = dir.join("state/generations/site");
        fs::create_dir_all(&root).unwrap();
        for number in 0..6 {
            let generation = root.join(format!("generation-{number}"));
            fs::create_dir_all(&generation).unwrap();
            fs::write(generation.join("fullchain.pem"), b"cert").unwrap();
            fs::write(generation.join("privkey.pem"), b"key").unwrap();
        }
        let protected = vec![
            root.join("generation-0/fullchain.pem"),
            root.join("generation-0/privkey.pem"),
            root.join("generation-5/fullchain.pem"),
            root.join("generation-5/privkey.pem"),
        ];

        prune_site_generations(&root, &protected);

        assert!(root.join("generation-0").is_dir());
        assert!(root.join("generation-3").is_dir());
        assert!(root.join("generation-4").is_dir());
        assert!(root.join("generation-5").is_dir());
        assert!(!root.join("generation-1").exists());
        assert!(!root.join("generation-2").exists());
        let _ = fs::remove_dir_all(dir);
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
        assert_eq!(status[0].certificate_status, "renewal_warning");
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

    fn desired_site(site_id: &str, sni: &str) -> CamouflageSiteDesired {
        CamouflageSiteDesired {
            site_id: site_id.into(),
            sni: sni.into(),
            tls_listener_port: CAMOUFLAGE_TLS_PORT,
            local_backend: CamouflageLocalBackend::OpenList,
            certificate: relay_shared::protocol::CamouflageCertificatePolicy {
                domain: sni.into(),
                expected_public_ip: "192.0.2.10".into(),
                renew_before_days: 30,
                challenge_method: relay_shared::protocol::AcmeChallengeMethod::Dns01,
            },
            enabled: true,
        }
    }

    #[test]
    fn authoritative_desired_update_clears_obsolete_site_diagnostics() {
        let dir = unique_dir("diagnostic-ghost-cleanup");
        let mut state = manager(&dir, "true", "true");
        state.last_errors.insert("old-site".into(), "stale".into());
        state
            .last_attempts
            .insert("old-site".into(), "stale".into());
        state
            .renewal_warnings
            .insert("old-site".into(), ("stale".into(), "stale".into()));

        state.update_desired(&[desired_site("new-site", "new.example.com")], true);

        assert!(state.last_errors.is_empty());
        assert!(state.last_attempts.is_empty());
        assert!(state.renewal_warnings.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stable_site_id_migration_reuses_old_lkg_certificate_until_commit() {
        let dir = unique_dir("site-id-migration");
        let mut state = manager(&dir, "true", "true");
        let old_certificate = real_certificate(&dir.join("old"), "old", "q1.example.com", 90);
        state.active = Some(CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                id: "q1_example_com".into(),
                sni: "q1.example.com".into(),
                tls_listener_port: CAMOUFLAGE_TLS_PORT,
                local_backend: OPENLIST_BACKEND.into(),
                certificate: old_certificate.clone(),
            }],
        });
        let desired = desired_site(
            &relay_shared::reconciliation::stable_camouflage_site_id("q1.example.com"),
            "q1.example.com",
        );

        let snapshot = state.desired_reconcile_snapshot(&[desired], true).unwrap();
        let migrated = &snapshot.manifest.sites[0];
        assert_eq!(
            migrated.id,
            relay_shared::reconciliation::stable_camouflage_site_id("q1.example.com")
        );
        assert_eq!(
            migrated.certificate.cert_path, old_certificate.cert_path,
            "site-id migration must reuse the old LKG certificate generation"
        );
        assert_eq!(migrated.certificate.key_path, old_certificate.key_path);
        assert_eq!(
            migrated
                .certificate
                .lifecycle
                .as_ref()
                .map(|policy| policy.domain.as_str()),
            Some("q1.example.com")
        );
        let _ = fs::remove_dir_all(dir);
    }

    fn successful_result(snapshot: CertificateReconcileSnapshot) -> CertificateReconcileResult {
        let candidate = snapshot.manifest.clone();
        let actions = candidate
            .sites
            .iter()
            .map(|site| (site.id.clone(), LifecycleAction::Unchanged))
            .collect();
        let successful_site_ids = snapshot.prepared_site_ids.clone();
        let successful_scope_keys = candidate
            .sites
            .iter()
            .filter_map(|site| site.certificate.lifecycle.as_ref())
            .filter_map(|policy| certificate_scope_key(policy).ok())
            .collect();
        CertificateReconcileResult {
            snapshot,
            outcome: Ok(CertificateReconcileOutcome {
                candidate,
                actions,
                successful_site_ids,
                failed_site_errors: HashMap::new(),
                attempted_scope_keys: HashSet::new(),
                successful_scope_keys,
                failed_scope_keys: HashSet::new(),
            }),
        }
    }

    fn retry_for_desired<'a>(
        state: &'a CamouflageSiteManager,
        desired: &CamouflageSiteDesired,
    ) -> Option<&'a PersistedScopeAcmeRetry> {
        state
            .acme_retries
            .get(&desired_certificate_scope_key(desired).unwrap())
    }

    async fn wait_for_desired_worker(shared: &Arc<AsyncMutex<CamouflageSiteManager>>) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !shared.lock().await.desired_worker_in_flight {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("desired certificate worker must finish");
    }

    fn certbot_invocation_count(path: &Path) -> usize {
        fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_default()
    }

    #[test]
    fn desired_acme_retry_policy_is_hour_capped_and_separate_from_reconciliation() {
        let dir = unique_dir("desired-acme-policy");
        let state = manager(&dir, "true", "true");
        assert_eq!(
            state.reconcile_retry_backoff,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ]
        );
        assert_eq!(
            state.acme_retry_backoff,
            vec![
                Duration::from_secs(30),
                Duration::from_secs(2 * 60),
                Duration::from_secs(5 * 60),
                Duration::from_secs(15 * 60),
                Duration::from_secs(30 * 60),
                Duration::from_secs(60 * 60),
            ]
        );
        assert_eq!(state.acme_jitter_percent, 10);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persistent_acme_failure_limits_real_certbot_invocations_and_survives_restart() {
        let dir = unique_dir("desired-acme-expensive-backoff");
        fs::create_dir_all(&dir).unwrap();
        let counter = dir.join("certbot-count");
        let certbot = dir.join("certbot-fail");
        fs::write(
            &certbot,
            format!(
                "#!/bin/sh\ncount=0\n[ ! -f '{0}' ] || count=$(cat '{0}')\nprintf '%s\\n' $((count + 1)) > '{0}'\nexit 1\n",
                counter.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&certbot, fs::Permissions::from_mode(0o700)).unwrap();

        let mut state = manager(&dir, "true", "true");
        state.config.certificate_lifecycle.enabled = true;
        state.config.certificate_lifecycle.certbot_binary = certbot;
        state.config.certificate_lifecycle.dns01_hook_binary = dir.join("dns-hook");
        fs::write(
            &state.config.certificate_lifecycle.dns01_hook_binary,
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(
            &state.config.certificate_lifecycle.dns01_hook_binary,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        state.reconcile_retry_backoff = vec![Duration::ZERO];
        state.acme_retry_backoff = vec![Duration::from_secs(1)];
        state.acme_jitter_percent = 0;
        let config = state.config.clone();
        let desired = desired_site("q1", "q1.example.com");
        let shared = Arc::new(AsyncMutex::new(state));

        prepare_desired_shared(&shared, std::slice::from_ref(&desired), true).await;
        wait_for_desired_worker(&shared).await;
        assert_eq!(certbot_invocation_count(&counter), 1);

        for _ in 0..20 {
            prepare_desired_shared(&shared, std::slice::from_ref(&desired), true).await;
        }
        assert_eq!(certbot_invocation_count(&counter), 1);
        {
            let state = shared.lock().await;
            assert_eq!(retry_for_desired(&state, &desired).unwrap().attempt, 1);
        }
        assert!(desired_acme_retry_path(&config.state_dir).exists());

        let mut restarted = CamouflageSiteManager::new(config);
        restarted.reconcile_retry_backoff = vec![Duration::ZERO];
        restarted.acme_retry_backoff = vec![Duration::from_secs(1)];
        restarted.acme_jitter_percent = 0;
        assert_eq!(retry_for_desired(&restarted, &desired).unwrap().attempt, 1);
        assert!(!restarted.acme_scope_is_due(&desired_certificate_scope_key(&desired).unwrap()));
        let restarted = Arc::new(AsyncMutex::new(restarted));
        prepare_desired_shared(&restarted, std::slice::from_ref(&desired), true).await;
        assert_eq!(certbot_invocation_count(&counter), 1);

        tokio::time::sleep(Duration::from_millis(1_050)).await;
        prepare_desired_shared(&restarted, &[desired], true).await;
        wait_for_desired_worker(&restarted).await;
        assert_eq!(certbot_invocation_count(&counter), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_multi_site_result_isolates_success_and_failure_errors() {
        let dir = unique_dir("desired-multi-site-isolation");
        let mut state = manager(&dir, "true", "true");
        let q1 = CamouflageSite {
            id: "q1".into(),
            sni: "q1.example.com".into(),
            tls_listener_port: CAMOUFLAGE_TLS_PORT,
            local_backend: OPENLIST_BACKEND.into(),
            certificate: real_certificate(&dir, "q1-active", "q1.example.com", 90),
        };
        let q3 = CamouflageSite {
            id: "q3".into(),
            sni: "q3.example.com".into(),
            tls_listener_port: CAMOUFLAGE_TLS_PORT,
            local_backend: OPENLIST_BACKEND.into(),
            certificate: real_certificate(&dir, "q3-active", "q3.example.com", 90),
        };
        assert!(state.apply_candidate(CamouflageSitesManifest {
            sites: vec![q1, q3],
        }));
        state.config.certificate_lifecycle.enabled = true;
        state.config.certificate_lifecycle.certbot_binary = PathBuf::from("/bin/false");
        state.config.certificate_lifecycle.dns01_hook_binary = PathBuf::from("/bin/false");
        state.last_errors.insert("q1".into(), "stale q1".into());
        state.last_errors.insert("q2".into(), "original q2".into());
        state.last_errors.insert("q3".into(), "stale q3".into());
        state.set_desired_retry_backoff_for_test(vec![Duration::from_secs(60)]);
        let desired = vec![
            desired_site("q1", "q1.example.com"),
            desired_site("q2", "q2.example.com"),
            desired_site("q3", "q3.example.com"),
        ];
        let snapshot = state.desired_reconcile_snapshot(&desired, true).unwrap();
        let result = run_snapshot(snapshot);
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, result).await,
            ReconcileCommit::Failed
        );
        let state = shared.lock().await;
        let statuses: HashMap<_, _> = state
            .status_snapshot()
            .into_iter()
            .map(|status| (status.site_id.clone(), status))
            .collect();
        assert_eq!(statuses["q1"].site_status, "active");
        assert!(statuses["q1"].last_error.is_none());
        assert_eq!(statuses["q2"].site_status, "failed_retrying");
        assert!(statuses["q2"].last_error.is_some());
        assert_eq!(statuses["q3"].site_status, "active");
        assert!(statuses["q3"].last_error.is_none());
        assert!(!state.last_errors.contains_key("q1"));
        assert!(state.last_errors.contains_key("q2"));
        assert!(!state.last_errors.contains_key("q3"));
        let failed_scope = desired_certificate_scope_key(&desired[1]).unwrap();
        assert_eq!(state.acme_retries[&failed_scope].attempt, 1);
        assert!(state.acme_retries[&failed_scope].next_retry_unix_ms > unix_time_millis());
        let persisted: PersistedDesiredAcmeRetries = serde_json::from_slice(
            &fs::read(desired_acme_retry_path(&state.config.state_dir)).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.version, 2);
        assert_eq!(persisted.scopes.len(), 1);
        assert_eq!(persisted.scopes[&failed_scope].attempt, 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_acme_backoff_identity_follows_certificate_scope_not_sni() {
        let dir = unique_dir("desired-acme-scope-identity");
        let mut state = manager(&dir.join("different-scope"), "true", "true");
        state.set_desired_retry_backoff_for_test(vec![Duration::from_secs(60)]);
        let mut scope_a = desired_site("q1", "q1.a.example.com");
        scope_a.certificate.domain = "*.a.example.com".into();
        let snapshot = state
            .desired_reconcile_snapshot(std::slice::from_ref(&scope_a), true)
            .unwrap();
        let shared = Arc::new(AsyncMutex::new(state));
        assert_eq!(
            commit_snapshot(
                &shared,
                CertificateReconcileResult {
                    snapshot,
                    outcome: Err("controlled scope A failure".into()),
                },
            )
            .await,
            ReconcileCommit::Failed
        );
        let config = shared.lock().await.config.clone();
        let mut restarted = CamouflageSiteManager::new(config);
        restarted.set_desired_retry_backoff_for_test(vec![Duration::from_secs(60)]);
        assert_eq!(retry_for_desired(&restarted, &scope_a).unwrap().attempt, 1);
        let mut scope_b = desired_site("q2", "q2.b.example.com");
        scope_b.certificate.domain = "*.b.example.com".into();
        let next = restarted.desired_reconcile_snapshot(std::slice::from_ref(&scope_b), true);
        assert!(
            next.is_some(),
            "new certificate scope must not inherit old backoff"
        );
        assert!(restarted.acme_retries.is_empty());
        assert!(!desired_acme_retry_path(&restarted.config.state_dir).exists());

        let mut state = manager(&dir.join("same-scope"), "true", "true");
        state.set_desired_retry_backoff_for_test(vec![Duration::from_secs(60)]);
        let mut q1 = desired_site("q1", "q1.example.com");
        q1.certificate.domain = "*.example.com".into();
        let snapshot = state
            .desired_reconcile_snapshot(std::slice::from_ref(&q1), true)
            .unwrap();
        let shared = Arc::new(AsyncMutex::new(state));
        assert_eq!(
            commit_snapshot(
                &shared,
                CertificateReconcileResult {
                    snapshot,
                    outcome: Err("controlled wildcard scope failure".into()),
                },
            )
            .await,
            ReconcileCommit::Failed
        );
        let config = shared.lock().await.config.clone();
        let mut restarted = CamouflageSiteManager::new(config);
        restarted.set_desired_retry_backoff_for_test(vec![Duration::from_secs(60)]);
        assert_eq!(retry_for_desired(&restarted, &q1).unwrap().attempt, 1);
        let mut q2 = desired_site("q2", "q2.example.com");
        q2.certificate.domain = "*.example.com".into();
        let next = restarted.desired_reconcile_snapshot(std::slice::from_ref(&q2), true);
        let next = next.expect("cheap reconciliation must continue during ACME backoff");
        assert!(next.allowed_acme_scope_keys.is_empty());
        assert_eq!(retry_for_desired(&restarted, &q2).unwrap().attempt, 1);
        assert!(desired_acme_retry_path(&restarted.config.state_dir).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn renewal_warning_never_marks_invalid_certificate_references_usable() {
        let dir = unique_dir("renewal-warning-invalid-certificates");
        let now = OffsetDateTime::now_utc();
        let valid = real_certificate(&dir, "valid-key-source", "q1.example.com", 90);
        let mut mismatch = real_certificate(&dir, "mismatch", "q1.example.com", 90);
        mismatch.key_path = valid.key_path.clone();
        let cases = vec![
            (
                "expired",
                real_certificate_with_window(
                    &dir,
                    "expired",
                    "q1.example.com",
                    now - TimeDuration::days(10),
                    now - TimeDuration::days(1),
                ),
            ),
            (
                "san-mismatch",
                real_certificate(&dir, "san-mismatch", "other.example.com", 90),
            ),
            ("key-mismatch", mismatch),
            (
                "not-yet-valid",
                real_certificate_with_window(
                    &dir,
                    "not-yet-valid",
                    "q1.example.com",
                    now + TimeDuration::days(1),
                    now + TimeDuration::days(90),
                ),
            ),
        ];

        for (label, mut reference) in cases {
            let mut state = manager(&dir.join(label), "true", "true");
            state.config.certificate_lifecycle.enabled = true;
            reference.lifecycle = Some(CertificateLifecyclePolicy {
                domain: "q1.example.com".into(),
                email: None,
                expected_public_ip: "192.0.2.10".into(),
                renew_before_days: 30,
                challenge_method: relay_shared::protocol::AcmeChallengeMethod::Dns01,
            });
            state.active = Some(CamouflageSitesManifest {
                sites: vec![CamouflageSite {
                    id: "q1".into(),
                    sni: "q1.example.com".into(),
                    tls_listener_port: CAMOUFLAGE_TLS_PORT,
                    local_backend: OPENLIST_BACKEND.into(),
                    certificate: reference,
                }],
            });
            state.update_desired(&[desired_site("q1", "q1.example.com")], true);
            state.record_renewal_warning_for_test("q1", "renewal failed");

            let status = state.status_snapshot().remove(0);
            assert_ne!(status.site_status, "active", "{label}");
            assert_ne!(status.certificate_status, "renewal_warning", "{label}");
            assert!(!state.active_snis().contains("q1.example.com"), "{label}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn slow_certificate_work_does_not_hold_camouflage_state_lock() {
        let dir = unique_dir("slow-work-short-lock");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        state.update_desired(&[desired_site("op1", "op1.example.com")], true);
        let shared = Arc::new(AsyncMutex::new(state));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());

        let task = {
            let shared = Arc::clone(&shared);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let snapshot = shared.lock().await.active_reconcile_snapshot().unwrap();
                entered.notify_one();
                release.notified().await;
                commit_snapshot(&shared, successful_result(snapshot)).await
            })
        };

        entered.notified().await;
        let status = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            status_snapshot_shared(&shared),
        )
        .await
        .expect("status reporting must not wait for certificate work");
        assert_eq!(status.len(), 1);
        release.notify_one();
        assert_eq!(task.await.unwrap(), ReconcileCommit::Applied);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unchanged_generation_accepts_certificate_result() {
        let dir = unique_dir("unchanged-generation");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        state.update_desired(&[desired_site("op1", "op1.example.com")], true);
        let snapshot = state.active_reconcile_snapshot().unwrap();
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Applied
        );
        assert_eq!(
            shared.lock().await.active.as_ref().unwrap().sites[0].id,
            "op1"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn changed_generation_discards_success_without_overwriting_new_state() {
        let dir = unique_dir("stale-success");
        let mut state = manager(&dir, "true", "true");
        let old = manifest(&dir);
        assert!(state.apply_candidate(old));
        let old_desired = desired_site("op1", "op1.example.com");
        let snapshot = state
            .desired_reconcile_snapshot(&[old_desired], true)
            .unwrap();
        let new = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        state.update_desired(&[desired_site("op2", "op2.example.com")], true);
        state.active = Some(new.clone());
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Stale
        );
        assert_eq!(shared.lock().await.active, Some(new));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn changed_generation_discards_failure_without_marking_new_state() {
        let dir = unique_dir("stale-failure");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        let old_desired = desired_site("op1", "op1.example.com");
        let snapshot = state
            .desired_reconcile_snapshot(&[old_desired], true)
            .unwrap();
        assert!(snapshot.desired_request);
        state.update_desired(&[desired_site("op2", "op2.example.com")], true);
        let shared = Arc::new(AsyncMutex::new(state));
        let result = CertificateReconcileResult {
            snapshot,
            outcome: Err("controlled old-generation failure".into()),
        };

        assert_eq!(
            commit_snapshot(&shared, result).await,
            ReconcileCommit::Stale
        );
        assert!(shared.lock().await.last_errors.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn stale_completion_keeps_new_desired_due_without_scheduling_failure_retry() {
        let dir = unique_dir("stale-completion-keeps-pending");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        let old_desired = desired_site("op1", "op1.example.com");
        let stale = state
            .desired_reconcile_snapshot(&[old_desired], true)
            .unwrap();
        state.update_desired(&[desired_site("op2", "op2.example.com")], true);
        let shared = Arc::new(AsyncMutex::new(state));

        assert!(
            !desired_retry_due(&shared).await,
            "in-flight work must not duplicate"
        );
        assert_eq!(
            commit_snapshot(&shared, successful_result(stale)).await,
            ReconcileCommit::Stale
        );
        {
            let state = shared.lock().await;
            assert!(state.desired_reconcile_pending);
            assert!(!state.desired_worker_in_flight);
            assert_eq!(state.reconcile_retry_attempt, 0);
            assert!(state.reconcile_retry_at.is_none());
            assert!(state.acme_retries.is_empty());
        }
        assert!(desired_retry_due(&shared).await);

        let mut stable = manager(&dir.join("stable"), "true", "true");
        stable.desired_reconcile_pending = false;
        stable.reconcile_retry_at = None;
        stable.acme_retries.clear();
        assert!(!desired_retry_due(&Arc::new(AsyncMutex::new(stable))).await);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn runtime_finalization_makes_older_certificate_result_stale() {
        let dir = unique_dir("stale-after-finalization");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        state.update_desired(&[desired_site("op1", "op1.example.com")], true);
        let snapshot = state.active_reconcile_snapshot().unwrap();
        let shared = Arc::new(AsyncMutex::new(state));
        {
            let _apply_guard = runtime_apply_guard(&shared).await;
            assert!(
                finalize_for_listener_snis_shared_under_apply_gate(&shared, &HashSet::new(),).await
            );
        }
        assert!(shared.lock().await.active_snis().is_empty());

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Stale
        );
        assert!(shared.lock().await.active_snis().is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unrelated_runtime_revision_does_not_discard_certificate_result() {
        let dir = unique_dir("runtime-revision-not-stale");
        let mut state = manager(&dir, "true", "true");
        assert!(state.apply_candidate(manifest(&dir)));
        state.update_desired(&[desired_site("op1", "op1.example.com")], true);
        let snapshot = state.active_reconcile_snapshot().unwrap();
        state.runtime_revision = state.runtime_revision.wrapping_add(1);
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Applied
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn shared_reconcile_keeps_active_certificate_and_records_renewal_warning() {
        let dir = unique_dir("shared-renewal-warning");
        let mut state = manager(&dir, "true", "true");
        state.config.certificate_lifecycle = CertificateLifecycleConfig {
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
        let desired = desired_site("op1", "op1.example.com");
        let mut reference = real_certificate(&dir, "op1", "op1.example.com", 10);
        reference.lifecycle = Some(CertificateLifecyclePolicy {
            domain: desired.certificate.domain.clone(),
            email: None,
            expected_public_ip: desired.certificate.expected_public_ip.clone(),
            renew_before_days: desired.certificate.renew_before_days,
            challenge_method: desired.certificate.challenge_method,
        });
        assert!(state.apply_candidate(CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                id: "op1".into(),
                sni: "op1.example.com".into(),
                tls_listener_port: CAMOUFLAGE_TLS_PORT,
                local_backend: OPENLIST_BACKEND.into(),
                certificate: reference,
            }],
        }));
        let shared = Arc::new(AsyncMutex::new(state));

        let active = prepare_desired_shared(&shared, &[desired], true).await;
        assert!(active.contains("op1.example.com"));
        let status = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let status = status_snapshot_shared(&shared).await;
                if status[0].last_error.is_some() {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background renewal result must commit");
        assert_eq!(status[0].site_status, "active");
        assert_eq!(status[0].certificate_status, "renewal_warning");
        assert!(status[0]
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("automatic renewal failed")));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_reconcile_returns_and_reports_while_acme_gate_is_blocked() {
        let dir = unique_dir("blocked-acme-status");
        let mut state = manager(&dir, "true", "true");
        state.config.certificate_lifecycle.enabled = true;
        state.config.certificate_lifecycle.certbot_binary = PathBuf::from("/bin/false");
        let acme_gate = Arc::clone(&state.acme_gate);
        let shared = Arc::new(AsyncMutex::new(state));
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = std::thread::spawn(move || {
            let _guard = acme_gate.lock().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        locked_rx.recv().unwrap();

        let desired = desired_site("op1", "op1.example.com");
        let active = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            prepare_desired_shared(&shared, &[desired], true),
        )
        .await
        .expect("desired reconciliation must not wait for ACME");
        assert!(active.is_empty());
        let status = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            status_snapshot_shared(&shared),
        )
        .await
        .expect("status must remain available while ACME is blocked");
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].certificate_status, "pending");

        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !shared.lock().await.last_errors.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocked worker must finish before test cleanup");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn repeated_identical_desired_does_not_queue_duplicate_certificate_jobs() {
        let dir = unique_dir("identical-desired-single-worker");
        let mut state = manager(&dir, "true", "true");
        state.config.certificate_lifecycle.enabled = true;
        state.config.certificate_lifecycle.certbot_binary = PathBuf::from("/bin/false");
        let acme_gate = Arc::clone(&state.acme_gate);
        let shared = Arc::new(AsyncMutex::new(state));
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = std::thread::spawn({
            let acme_gate = Arc::clone(&acme_gate);
            move || {
                let _guard = acme_gate.lock().unwrap();
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }
        });
        locked_rx.recv().unwrap();

        let desired = desired_site("same_site", "op1.example.com");
        assert!(
            prepare_desired_shared(&shared, std::slice::from_ref(&desired), true)
                .await
                .is_empty()
        );
        let first_attempt = shared.lock().await.last_attempts["same_site"].clone();
        assert!(
            prepare_desired_shared(&shared, std::slice::from_ref(&desired), true)
                .await
                .is_empty()
        );
        assert!(
            prepare_desired_shared(&shared, std::slice::from_ref(&desired), true)
                .await
                .is_empty()
        );
        {
            let state = shared.lock().await;
            assert!(state.desired_worker_in_flight);
            assert_eq!(state.last_attempts["same_site"], first_attempt);
        }

        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let state = shared.lock().await;
                if state.last_errors.contains_key("same_site") {
                    assert!(!state.desired_worker_in_flight);
                    assert_eq!(state.reconcile_retry_attempt, 1);
                    assert_eq!(retry_for_desired(&state, &desired).unwrap().attempt, 1);
                    break;
                }
                drop(state);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the single desired worker must finish after the ACME gate releases");
        tokio::task::spawn_blocking(move || drop(acme_gate.lock().unwrap()))
            .await
            .unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_failure_retries_then_commits_new_site_and_lkg() {
        let dir = unique_dir("desired-fail-retry-success");
        let mut state = manager(&dir, "true", "true");
        let mut p1 = site(&dir, "p1", "p1.example.com");
        p1.certificate = real_certificate(&dir, "p1-real", "p1.example.com", 90);
        assert!(state.apply_candidate(CamouflageSitesManifest {
            sites: vec![p1.clone()],
        }));
        state.set_desired_retry_backoff_for_test(vec![Duration::ZERO]);
        let desired = desired_site("q1", "q1.example.com");
        let first = state
            .desired_reconcile_snapshot(std::slice::from_ref(&desired), true)
            .unwrap();
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(
                &shared,
                CertificateReconcileResult {
                    snapshot: first,
                    outcome: Err("controlled first ACME failure".into()),
                },
            )
            .await,
            ReconcileCommit::Failed
        );
        {
            let state = shared.lock().await;
            assert_eq!(state.active.as_ref().unwrap().sites, vec![p1.clone()]);
            assert_eq!(state.status_snapshot()[0].site_status, "failed_retrying");
            assert_eq!(
                state.status_snapshot()[0].certificate_status,
                "failed_retrying"
            );
            assert!(state.desired_control_work_is_due());
        }

        let mut retry = shared
            .lock()
            .await
            .desired_reconcile_snapshot(&[desired], true)
            .unwrap();
        let q1 = retry
            .manifest
            .sites
            .iter_mut()
            .find(|site| site.id == "q1")
            .unwrap();
        let lifecycle = q1.certificate.lifecycle.clone();
        q1.certificate = real_certificate(&dir, "q1-real", "q1.example.com", 90);
        q1.certificate.lifecycle = lifecycle;
        assert_eq!(
            commit_snapshot(&shared, successful_result(retry)).await,
            ReconcileCommit::Applied
        );
        {
            let mut state = shared.lock().await;
            assert!(state.active_snis().contains("q1.example.com"));
            assert!(!state.last_errors.contains_key("q1"));
            assert_eq!(state.reconcile_retry_attempt, 0);
            assert!(state.acme_retries.is_empty());
            assert!(!desired_acme_retry_path(&state.config.state_dir).exists());
            assert!(
                state.finalize_for_listener_snis(&HashSet::from(["q1.example.com".to_string()]))
            );
            assert_eq!(state.active.as_ref().unwrap().sites[0].id, "q1");
            assert_eq!(state.status_snapshot()[0].site_status, "active");
            let lkg: CamouflageSitesManifest =
                serde_json::from_slice(&fs::read(state.lkg_path()).unwrap()).unwrap();
            assert_eq!(lkg.sites[0].id, "q1");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn permanent_desired_failure_keeps_old_site_healthy_and_reports_retrying() {
        let dir = unique_dir("desired-permanent-failure");
        let mut state = manager(&dir, "true", "true");
        let mut p1 = site(&dir, "p1", "p1.example.com");
        p1.certificate = real_certificate(&dir, "p1-real", "p1.example.com", 90);
        assert!(state.apply_candidate(CamouflageSitesManifest {
            sites: vec![p1.clone()],
        }));
        state.set_desired_retry_backoff_for_test(vec![Duration::ZERO]);
        let desired = desired_site("q1", "q1.example.com");
        let first = state
            .desired_reconcile_snapshot(std::slice::from_ref(&desired), true)
            .unwrap();
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(
                &shared,
                CertificateReconcileResult {
                    snapshot: first,
                    outcome: Err("controlled ACME failure one".into()),
                },
            )
            .await,
            ReconcileCommit::Failed
        );
        let second = shared
            .lock()
            .await
            .desired_reconcile_snapshot(&[desired], true)
            .unwrap();
        assert_eq!(
            commit_snapshot(
                &shared,
                CertificateReconcileResult {
                    snapshot: second,
                    outcome: Err("controlled ACME failure two".into()),
                },
            )
            .await,
            ReconcileCommit::Failed
        );

        let state = shared.lock().await;
        assert_eq!(state.active.as_ref().unwrap().sites, vec![p1]);
        assert!(!state.last_errors.contains_key("p1"));
        let status = state.status_snapshot();
        assert_eq!(status[0].site_status, "failed_retrying");
        assert_eq!(status[0].certificate_status, "failed_retrying");
        assert!(status[0].last_error.is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_certificate_success_notifies_convergence_driver() {
        let dir = unique_dir("certificate-success-wakeup");
        let mut state = manager(&dir, "true", "true");
        let desired = desired_site("q1", "q1.example.com");
        let mut snapshot = state.desired_reconcile_snapshot(&[desired], true).unwrap();
        let q1 = snapshot
            .manifest
            .sites
            .iter_mut()
            .find(|site| site.id == "q1")
            .unwrap();
        let lifecycle = q1.certificate.lifecycle.clone();
        q1.certificate = real_certificate(&dir, "q1-real", "q1.example.com", 90);
        q1.certificate.lifecycle = lifecycle;
        let notify = Arc::clone(&state.dependency_notify);
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Applied
        );
        tokio::time::timeout(Duration::from_millis(100), notify.notified())
            .await
            .expect("certificate completion must wake convergence");
        assert!(shared.lock().await.active_snis().contains("q1.example.com"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn successful_candidate_only_clears_errors_for_prepared_sites() {
        let dir = unique_dir("prepared-site-error-clearing");
        let mut state = manager(&dir, "true", "true");
        let valid = desired_site("valid", "valid.example.com");
        let mut invalid = desired_site("invalid", "invalid.example.com");
        invalid.certificate.domain = "unrelated.example.net".into();
        let mut snapshot = state
            .desired_reconcile_snapshot(&[valid, invalid], true)
            .unwrap();
        assert_eq!(
            snapshot.prepared_site_ids,
            HashSet::from(["valid".to_string()])
        );
        let valid_site = snapshot
            .manifest
            .sites
            .iter_mut()
            .find(|site| site.id == "valid")
            .unwrap();
        let lifecycle = valid_site.certificate.lifecycle.clone();
        valid_site.certificate = real_certificate(&dir, "valid-real", "valid.example.com", 90);
        valid_site.certificate.lifecycle = lifecycle;
        let shared = Arc::new(AsyncMutex::new(state));

        assert_eq!(
            commit_snapshot(&shared, successful_result(snapshot)).await,
            ReconcileCommit::Applied
        );
        let state = shared.lock().await;
        assert!(!state.last_errors.contains_key("valid"));
        assert!(state.last_errors.contains_key("invalid"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn blocked_op1_work_does_not_block_other_site_state_access() {
        let dir = unique_dir("multi-site-short-lock");
        let mut state = manager(&dir, "true", "true");
        let three = vec![
            desired_site("op1", "op1.example.com"),
            desired_site("op2", "op2.example.com"),
            desired_site("op3", "op3.example.com"),
        ];
        state.update_desired(&three, true);
        let shared = Arc::new(AsyncMutex::new(state));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let task = {
            let shared = Arc::clone(&shared);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let snapshot = shared
                    .lock()
                    .await
                    .desired_reconcile_snapshot(&three, true)
                    .unwrap();
                entered.notify_one();
                release.notified().await;
                snapshot.generation
            })
        };

        entered.notified().await;
        let status = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            status_snapshot_shared(&shared),
        )
        .await
        .expect("op2/op3 status must remain readable while op1 work is blocked");
        assert_eq!(status.len(), 3);
        release.notify_one();
        assert!(task.await.unwrap() > 0);
        let _ = fs::remove_dir_all(dir);
    }
}
