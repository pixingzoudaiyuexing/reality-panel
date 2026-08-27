use crate::forwarder::camouflage_site::CamouflageSiteManager;
use crate::forwarder::ForwarderManager;
use crate::poller;
use crate::poller::PendingFinalization;
use relay_shared::protocol::{
    NodeConfigResponse, ReconciliationRecoverySource, ReconciliationStatus,
    ReconciliationStatusState,
};
use relay_shared::reconciliation::{config_fingerprint, ConfigFingerprint};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritySource {
    ValidatedPanel,
    LocalRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRecoverySource {
    PrimaryLkg,
    RepairedFromBackup,
    BackupFallback,
    DegradedNoTrustedLkg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Later transport adapters will preserve these categories.
pub enum UntrustedInputKind {
    Timeout,
    HttpError,
    AuthenticationFailure,
    ProtocolMismatch,
    MalformedPayload,
    SemanticValidation,
    Disconnected,
}

#[derive(Clone, Debug)]
pub struct TrustedSnapshot {
    source: AuthoritySource,
    recovery_source: Option<LocalRecoverySource>,
    config: NodeConfigResponse,
    fingerprint: ConfigFingerprint,
}

impl TrustedSnapshot {
    pub fn validated_panel(config: NodeConfigResponse) -> Result<Self, String> {
        Self::new(AuthoritySource::ValidatedPanel, config)
    }

    pub fn local_recovery(config: NodeConfigResponse) -> Result<Self, String> {
        Self::local_recovery_from(config, LocalRecoverySource::PrimaryLkg)
    }

    pub fn local_recovery_from(
        config: NodeConfigResponse,
        recovery_source: LocalRecoverySource,
    ) -> Result<Self, String> {
        Self::new_with_recovery(
            AuthoritySource::LocalRecovery,
            Some(recovery_source),
            config,
        )
    }

    fn new(source: AuthoritySource, config: NodeConfigResponse) -> Result<Self, String> {
        Self::new_with_recovery(source, None, config)
    }

    fn new_with_recovery(
        source: AuthoritySource,
        recovery_source: Option<LocalRecoverySource>,
        config: NodeConfigResponse,
    ) -> Result<Self, String> {
        poller::validate_config(&config)?;
        let fingerprint = config_fingerprint(&config);
        Ok(Self {
            source,
            recovery_source,
            config,
            fingerprint,
        })
    }

    #[cfg(test)]
    fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let config = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        Self::validated_panel(config)
    }

    pub fn source(&self) -> AuthoritySource {
        self.source
    }

    pub fn config(&self) -> &NodeConfigResponse {
        &self.config
    }

    pub fn fingerprint(&self) -> &ConfigFingerprint {
        &self.fingerprint
    }

    pub fn is_panel_authoritative(&self) -> bool {
        self.source == AuthoritySource::ValidatedPanel
    }

    pub fn recovery_source(&self) -> Option<LocalRecoverySource> {
        self.recovery_source
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Error transport adapters are wired incrementally.
pub enum ReconciliationInput {
    Trusted(TrustedSnapshot),
    DegradedLocalRecovery(LocalRecoverySource),
    Untrusted(UntrustedInputKind),
}

impl ReconciliationInput {
    pub fn validated_panel(config: NodeConfigResponse) -> Result<Self, String> {
        TrustedSnapshot::validated_panel(config).map(Self::Trusted)
    }

    pub fn local_recovery(config: NodeConfigResponse) -> Result<Self, String> {
        TrustedSnapshot::local_recovery(config).map(Self::Trusted)
    }

    pub fn local_recovery_from(
        config: NodeConfigResponse,
        recovery_source: LocalRecoverySource,
    ) -> Result<Self, String> {
        TrustedSnapshot::local_recovery_from(config, recovery_source).map(Self::Trusted)
    }

    pub fn degraded_local_recovery() -> Self {
        Self::DegradedLocalRecovery(LocalRecoverySource::DegradedNoTrustedLkg)
    }

    #[allow(dead_code)]
    pub fn untrusted(kind: UntrustedInputKind) -> Self {
        Self::Untrusted(kind)
    }
}

/// Slice 1 accepts observed fingerprints but does not manufacture them from
/// remembered desired state. Slice 3 will provide managed runtime inspectors.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // Slice 3 supplies the managed-runtime inspector.
pub enum ObservedRuntimeEvidence {
    #[default]
    Unknown,
    Fingerprint(ConfigFingerprint),
}

impl ObservedRuntimeEvidence {
    #[cfg(test)]
    fn matching(config: &NodeConfigResponse) -> Self {
        Self::Fingerprint(config_fingerprint(config))
    }

    #[allow(dead_code)]
    fn fingerprint(&self) -> Option<&ConfigFingerprint> {
        match self {
            Self::Unknown => None,
            Self::Fingerprint(value) => Some(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // ApplyRequired is emitted by the Slice 3 planning path.
pub enum ReconciliationState {
    Converged,
    ApplyRequired,
    DependencyWithheld,
    DegradedLocalRecovery,
    InvalidUntrustedInput,
    ApplyFailed,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Status wiring is intentionally deferred to Slice 5.
pub struct ReconciliationResult {
    pub state: ReconciliationState,
    pub source: Option<AuthoritySource>,
    pub desired_fingerprint: Option<ConfigFingerprint>,
    pub applied_fingerprint: Option<ConfigFingerprint>,
    pub observed_fingerprint: Option<ConfigFingerprint>,
    pub cleanup_authorized: bool,
    pub apply_required: bool,
    pub dependency_withheld: bool,
    pub recovery_source: Option<LocalRecoverySource>,
}

impl ReconciliationResult {
    fn untrusted() -> Self {
        Self {
            state: ReconciliationState::InvalidUntrustedInput,
            source: None,
            desired_fingerprint: None,
            applied_fingerprint: None,
            observed_fingerprint: None,
            cleanup_authorized: false,
            apply_required: false,
            dependency_withheld: false,
            recovery_source: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Reconciler {
    last_panel_desired: Option<ConfigFingerprint>,
    last_applied: Option<ConfigFingerprint>,
    pending: Option<PendingApply>,
    status: ReconciliationStatus,
}

#[derive(Debug)]
struct PendingApply {
    desired_fingerprint: ConfigFingerprint,
    dependency_withheld: bool,
    finalization: PendingFinalization,
    cache_paths: poller::CachePaths,
}

impl Reconciler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status_snapshot(&self) -> ReconciliationStatus {
        self.status.clone()
    }

    /// Pure foundation decision. Runtime callers currently pass Unknown
    /// observed evidence, so Slice 1 never skips an apply based on assumptions.
    #[allow(dead_code)]
    pub fn plan(
        &self,
        input: &ReconciliationInput,
        effective: Option<&NodeConfigResponse>,
        observed: &ObservedRuntimeEvidence,
        dependency_withheld: bool,
    ) -> ReconciliationResult {
        let ReconciliationInput::Trusted(snapshot) = input else {
            let recovery_source = match input {
                ReconciliationInput::DegradedLocalRecovery(source) => Some(source),
                _ => None,
            };
            if recovery_source.is_some() {
                return ReconciliationResult {
                    state: ReconciliationState::DegradedLocalRecovery,
                    source: Some(AuthoritySource::LocalRecovery),
                    desired_fingerprint: None,
                    applied_fingerprint: None,
                    observed_fingerprint: None,
                    cleanup_authorized: false,
                    apply_required: false,
                    dependency_withheld: false,
                    recovery_source: recovery_source.copied(),
                };
            }
            return ReconciliationResult::untrusted();
        };
        let effective_fingerprint =
            config_fingerprint(effective.unwrap_or_else(|| snapshot.config()));
        let no_op = self.last_applied.as_ref() == Some(&effective_fingerprint)
            && observed.fingerprint() == Some(&effective_fingerprint);
        let state = match snapshot.source() {
            AuthoritySource::LocalRecovery => ReconciliationState::DegradedLocalRecovery,
            AuthoritySource::ValidatedPanel if no_op && dependency_withheld => {
                ReconciliationState::DependencyWithheld
            }
            AuthoritySource::ValidatedPanel if no_op => ReconciliationState::Converged,
            AuthoritySource::ValidatedPanel => ReconciliationState::ApplyRequired,
        };
        ReconciliationResult {
            state,
            source: Some(snapshot.source()),
            desired_fingerprint: Some(snapshot.fingerprint().clone()),
            applied_fingerprint: Some(effective_fingerprint),
            observed_fingerprint: observed.fingerprint().cloned(),
            cleanup_authorized: snapshot.is_panel_authoritative(),
            apply_required: !no_op,
            dependency_withheld,
            recovery_source: snapshot.recovery_source(),
        }
    }

    /// The single mutation entry used by startup recovery, HTTP and WS. Slice 3
    /// also uses this path for runtime inspection and targeted repair, without
    /// introducing a second mutation control plane.
    pub async fn reconcile(
        &mut self,
        manager: &Arc<Mutex<ForwarderManager>>,
        camouflage: &Arc<Mutex<CamouflageSiteManager>>,
        input: ReconciliationInput,
    ) -> ReconciliationResult {
        let result = self
            .reconcile_with_paths(manager, camouflage, input, poller::current_cache_paths())
            .await;
        self.record_status(&result);
        result
    }

    #[cfg(test)]
    async fn reconcile_with_test_paths(
        &mut self,
        manager: &Arc<Mutex<ForwarderManager>>,
        camouflage: &Arc<Mutex<CamouflageSiteManager>>,
        input: ReconciliationInput,
        paths: poller::CachePaths,
    ) -> ReconciliationResult {
        let result = self
            .reconcile_with_paths(manager, camouflage, input, paths)
            .await;
        self.record_status(&result);
        result
    }

    fn record_status(&mut self, result: &ReconciliationResult) {
        let state = match result.state {
            ReconciliationState::Converged => ReconciliationStatusState::Converged,
            ReconciliationState::ApplyRequired => ReconciliationStatusState::Reconciling,
            ReconciliationState::DependencyWithheld => {
                ReconciliationStatusState::DependencyWithheld
            }
            ReconciliationState::DegradedLocalRecovery => {
                ReconciliationStatusState::DegradedLocalRecovery
            }
            ReconciliationState::InvalidUntrustedInput => {
                ReconciliationStatusState::WaitingForAuthority
            }
            ReconciliationState::ApplyFailed => ReconciliationStatusState::ApplyFailed,
        };
        let last_success_at = if state == ReconciliationStatusState::Converged {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            self.status.last_success_at.clone()
        };
        self.status = ReconciliationStatus {
            state,
            desired_fingerprint: result
                .desired_fingerprint
                .as_ref()
                .map(|value| value.as_str().to_string()),
            applied_fingerprint: result
                .applied_fingerprint
                .as_ref()
                .map(|value| value.as_str().to_string()),
            observed_fingerprint: result
                .observed_fingerprint
                .as_ref()
                .map(|value| value.as_str().to_string()),
            last_success_at,
            // Failure details are deliberately fixed and do not accept raw
            // command output, generated config, tokens, or certificate data.
            last_error: (state == ReconciliationStatusState::ApplyFailed)
                .then(|| "runtime reconciliation failed".to_string()),
            recovery_source: recovery_source(result),
        };
    }

    fn record_repairing(
        &mut self,
        snapshot: &TrustedSnapshot,
        applied: &ConfigFingerprint,
        observed: &ConfigFingerprint,
    ) {
        self.status = ReconciliationStatus {
            state: ReconciliationStatusState::Repairing,
            desired_fingerprint: Some(snapshot.fingerprint().as_str().to_string()),
            applied_fingerprint: Some(applied.as_str().to_string()),
            observed_fingerprint: Some(observed.as_str().to_string()),
            last_success_at: self.status.last_success_at.clone(),
            last_error: None,
            recovery_source: if snapshot.source() == AuthoritySource::ValidatedPanel {
                ReconciliationRecoverySource::Panel
            } else {
                local_recovery_source(snapshot.recovery_source())
            },
        };
    }

    async fn reconcile_with_paths(
        &mut self,
        manager: &Arc<Mutex<ForwarderManager>>,
        camouflage: &Arc<Mutex<CamouflageSiteManager>>,
        input: ReconciliationInput,
        paths: poller::CachePaths,
    ) -> ReconciliationResult {
        let snapshot = match input {
            ReconciliationInput::Trusted(snapshot) => snapshot,
            ReconciliationInput::DegradedLocalRecovery(source) => {
                return ReconciliationResult {
                    state: ReconciliationState::DegradedLocalRecovery,
                    source: Some(AuthoritySource::LocalRecovery),
                    desired_fingerprint: None,
                    applied_fingerprint: None,
                    observed_fingerprint: None,
                    cleanup_authorized: false,
                    apply_required: false,
                    dependency_withheld: false,
                    recovery_source: Some(source),
                };
            }
            ReconciliationInput::Untrusted(_) => return ReconciliationResult::untrusted(),
        };

        // A failed durable finalization still owns the runtime that was
        // successfully applied from a validated Panel snapshot. If the Panel
        // becomes unreachable before that finalization can be retried, an
        // older listener LKG must not replace the healthy pending runtime or
        // discard its retry state.
        if snapshot.source() == AuthoritySource::LocalRecovery {
            if let Some(pending) = self.pending.as_ref() {
                let effective = pending.finalization.effective.clone();
                let desired_fingerprint = pending.desired_fingerprint.clone();
                let dependency_withheld = pending.dependency_withheld;
                let applied_fingerprint = config_fingerprint(&effective);
                let inspection = poller::inspect_runtime(manager, camouflage, &effective).await;
                return ReconciliationResult {
                    state: if inspection.healthy {
                        ReconciliationState::DegradedLocalRecovery
                    } else {
                        ReconciliationState::ApplyFailed
                    },
                    source: Some(AuthoritySource::LocalRecovery),
                    desired_fingerprint: Some(desired_fingerprint),
                    applied_fingerprint: Some(applied_fingerprint),
                    observed_fingerprint: Some(inspection.observed_fingerprint),
                    cleanup_authorized: false,
                    apply_required: !inspection.healthy,
                    dependency_withheld,
                    recovery_source: snapshot.recovery_source(),
                };
            }
        }

        if self
            .pending
            .as_ref()
            .map(|pending| pending.desired_fingerprint == *snapshot.fingerprint())
            .unwrap_or(false)
        {
            let mut pending = self.pending.take().expect("pending apply checked above");
            let retry = poller::retry_pending_finalization(
                camouflage,
                &mut pending.finalization,
                &pending.cache_paths,
            )
            .await;
            let applied_fingerprint = config_fingerprint(&pending.finalization.effective);
            if !retry {
                let dependency_withheld = pending.dependency_withheld;
                self.pending = Some(pending);
                return ReconciliationResult {
                    state: ReconciliationState::ApplyFailed,
                    source: Some(snapshot.source()),
                    desired_fingerprint: Some(snapshot.fingerprint().clone()),
                    applied_fingerprint: Some(applied_fingerprint),
                    observed_fingerprint: None,
                    cleanup_authorized: snapshot.is_panel_authoritative(),
                    apply_required: true,
                    dependency_withheld,
                    recovery_source: snapshot.recovery_source(),
                };
            }
            let dependency_withheld = pending.dependency_withheld;
            self.last_applied = Some(applied_fingerprint.clone());
            if snapshot.is_panel_authoritative() {
                self.last_panel_desired = Some(snapshot.fingerprint().clone());
            }
            return ReconciliationResult {
                state: if dependency_withheld {
                    ReconciliationState::DependencyWithheld
                } else {
                    ReconciliationState::Converged
                },
                source: Some(snapshot.source()),
                desired_fingerprint: Some(snapshot.fingerprint().clone()),
                applied_fingerprint: Some(applied_fingerprint),
                observed_fingerprint: None,
                cleanup_authorized: snapshot.is_panel_authoritative(),
                apply_required: false,
                dependency_withheld,
                recovery_source: snapshot.recovery_source(),
            };
        }
        self.pending = None;

        // Once a validated snapshot has been applied, periodic snapshots with
        // the same desired fingerprint inspect the actual runtime first. This
        // is the Slice 3 NO-OP/repair boundary: desired state is compared with
        // the effective config already running, so DNS-dependent withheld
        // sites are not mistaken for drift.
        let current_effective = manager.lock().await.current_config();
        if let Some(effective) = current_effective {
            let effective_fingerprint = config_fingerprint(&effective);
            let panel_unchanged = snapshot.source() == AuthoritySource::ValidatedPanel
                && self.last_panel_desired.as_ref() == Some(snapshot.fingerprint())
                && self.last_applied.as_ref() == Some(&effective_fingerprint);
            let local_recovery = snapshot.source() == AuthoritySource::LocalRecovery;
            if panel_unchanged || local_recovery {
                let inspection = poller::inspect_runtime(manager, camouflage, &effective).await;
                if inspection.healthy {
                    return ReconciliationResult {
                        state: if local_recovery {
                            ReconciliationState::DegradedLocalRecovery
                        } else if effective_fingerprint != *snapshot.fingerprint() {
                            ReconciliationState::DependencyWithheld
                        } else {
                            ReconciliationState::Converged
                        },
                        source: Some(snapshot.source()),
                        desired_fingerprint: Some(snapshot.fingerprint().clone()),
                        applied_fingerprint: Some(effective_fingerprint.clone()),
                        observed_fingerprint: Some(inspection.observed_fingerprint),
                        cleanup_authorized: snapshot.is_panel_authoritative(),
                        apply_required: false,
                        dependency_withheld: effective_fingerprint != *snapshot.fingerprint(),
                        recovery_source: snapshot.recovery_source(),
                    };
                }

                self.record_repairing(
                    &snapshot,
                    &effective_fingerprint,
                    &inspection.observed_fingerprint,
                );

                let repaired = poller::repair_runtime(
                    manager,
                    camouflage,
                    &effective,
                    &inspection,
                    snapshot.is_panel_authoritative(),
                )
                .await;
                let after = poller::inspect_runtime(manager, camouflage, &effective).await;
                if repaired && after.healthy {
                    return ReconciliationResult {
                        state: if local_recovery {
                            ReconciliationState::DegradedLocalRecovery
                        } else if effective_fingerprint != *snapshot.fingerprint() {
                            ReconciliationState::DependencyWithheld
                        } else {
                            ReconciliationState::Converged
                        },
                        source: Some(snapshot.source()),
                        desired_fingerprint: Some(snapshot.fingerprint().clone()),
                        applied_fingerprint: Some(effective_fingerprint.clone()),
                        observed_fingerprint: Some(after.observed_fingerprint),
                        cleanup_authorized: snapshot.is_panel_authoritative(),
                        apply_required: false,
                        dependency_withheld: effective_fingerprint != *snapshot.fingerprint(),
                        recovery_source: snapshot.recovery_source(),
                    };
                }

                return ReconciliationResult {
                    state: ReconciliationState::ApplyFailed,
                    source: Some(snapshot.source()),
                    desired_fingerprint: Some(snapshot.fingerprint().clone()),
                    applied_fingerprint: Some(effective_fingerprint.clone()),
                    observed_fingerprint: Some(after.observed_fingerprint),
                    cleanup_authorized: snapshot.is_panel_authoritative(),
                    apply_required: true,
                    dependency_withheld: effective_fingerprint != *snapshot.fingerprint(),
                    recovery_source: snapshot.recovery_source(),
                };
            }
        }

        let outcome = match snapshot.source() {
            AuthoritySource::ValidatedPanel => {
                poller::apply_and_commit_coordinated_at(
                    manager,
                    camouflage,
                    snapshot.config(),
                    &paths,
                )
                .await
            }
            AuthoritySource::LocalRecovery => {
                poller::apply_cached_coordinated(manager, camouflage, snapshot.config()).await
            }
        };
        let applied_fingerprint = outcome.effective.as_ref().map(config_fingerprint);
        if !outcome.success {
            if let Some(pending) = outcome.pending {
                self.pending = Some(PendingApply {
                    desired_fingerprint: snapshot.fingerprint().clone(),
                    dependency_withheld: outcome.dependency_withheld,
                    finalization: pending,
                    cache_paths: paths,
                });
            }
            return ReconciliationResult {
                state: ReconciliationState::ApplyFailed,
                source: Some(snapshot.source()),
                desired_fingerprint: Some(snapshot.fingerprint().clone()),
                applied_fingerprint,
                observed_fingerprint: None,
                cleanup_authorized: snapshot.is_panel_authoritative(),
                apply_required: true,
                dependency_withheld: outcome.dependency_withheld,
                recovery_source: snapshot.recovery_source(),
            };
        }

        self.last_applied = applied_fingerprint.clone();
        if snapshot.is_panel_authoritative() {
            self.last_panel_desired = Some(snapshot.fingerprint().clone());
        }
        let observed = if let Some(effective) = outcome.effective.as_ref() {
            Some(
                poller::inspect_runtime(manager, camouflage, effective)
                    .await
                    .observed_fingerprint,
            )
        } else {
            None
        };
        ReconciliationResult {
            state: match snapshot.source() {
                AuthoritySource::LocalRecovery => ReconciliationState::DegradedLocalRecovery,
                AuthoritySource::ValidatedPanel if outcome.dependency_withheld => {
                    ReconciliationState::DependencyWithheld
                }
                AuthoritySource::ValidatedPanel => ReconciliationState::Converged,
            },
            source: Some(snapshot.source()),
            desired_fingerprint: Some(snapshot.fingerprint().clone()),
            observed_fingerprint: observed,
            applied_fingerprint,
            cleanup_authorized: snapshot.is_panel_authoritative(),
            apply_required: false,
            dependency_withheld: outcome.dependency_withheld,
            recovery_source: snapshot.recovery_source(),
        }
    }

    #[cfg(test)]
    fn record_success(&mut self, result: &ReconciliationResult) {
        self.last_applied = result.applied_fingerprint.clone();
        if result.source == Some(AuthoritySource::ValidatedPanel) {
            self.last_panel_desired = result.desired_fingerprint.clone();
        }
    }
}

fn local_recovery_source(source: Option<LocalRecoverySource>) -> ReconciliationRecoverySource {
    match source {
        Some(LocalRecoverySource::PrimaryLkg) => ReconciliationRecoverySource::LkgPrimary,
        Some(LocalRecoverySource::RepairedFromBackup) => {
            ReconciliationRecoverySource::LkgBackupRepaired
        }
        Some(LocalRecoverySource::BackupFallback) => ReconciliationRecoverySource::LocalRecovery,
        Some(LocalRecoverySource::DegradedNoTrustedLkg) | None => {
            ReconciliationRecoverySource::None
        }
    }
}

fn recovery_source(result: &ReconciliationResult) -> ReconciliationRecoverySource {
    match result.source {
        Some(AuthoritySource::ValidatedPanel) => ReconciliationRecoverySource::Panel,
        Some(AuthoritySource::LocalRecovery) => local_recovery_source(result.recovery_source),
        None => ReconciliationRecoverySource::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::camouflage_site::{
        CamouflageSite, CamouflageSiteConfig, CamouflageSitesManifest, CertificateReference,
        OPENLIST_BACKEND,
    };
    use crate::forwarder::certificate_lifecycle::CertificateLifecycleConfig;
    use crate::forwarder::nginx_sni::NginxSniConfig;
    use relay_shared::protocol::{
        CamouflageCertificatePolicy, CamouflageLocalBackend, CamouflageSiteDesired, ListenerConfig,
        LoadBalanceStrategy, NodeTransport, Protocol,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn empty() -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![],
            camouflage_sites: vec![],
        }
    }

    fn desired() -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 1,
                port: 443,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::NginxSni,
                ws_path: None,
                sni: Some("op1.example.com".into()),
                camouflage_required: true,
                send_proxy_protocol: false,
                targets: vec!["192.0.2.1:55443".into()],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
            camouflage_sites: vec![CamouflageSiteDesired {
                site_id: "op1_example_com".into(),
                sni: "op1.example.com".into(),
                tls_listener_port: 8443,
                local_backend: CamouflageLocalBackend::OpenList,
                certificate: CamouflageCertificatePolicy {
                    domain: "op1.example.com".into(),
                    expected_public_ip: "192.0.2.10".into(),
                    renew_before_days: 30,
                    challenge_method: Default::default(),
                },
                enabled: true,
            }],
        }
    }

    fn raw_config(port: u16) -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 7,
                port,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                sni: None,
                camouflage_required: false,
                send_proxy_protocol: false,
                targets: vec!["127.0.0.1:9".into()],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
            camouflage_sites: vec![],
        }
    }

    fn test_camouflage_manager(dir: &Path) -> CamouflageSiteManager {
        CamouflageSiteManager::new(CamouflageSiteConfig {
            enabled: false,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("camouflage-state"),
            nginx: NginxSniConfig {
                enabled: false,
                conf_path: dir.join("camouflage.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
            certificate_lifecycle: CertificateLifecycleConfig::disabled_for_test(dir),
        })
    }

    fn compatibility_camouflage_manager(dir: &Path) -> CamouflageSiteManager {
        CamouflageSiteManager::new(CamouflageSiteConfig {
            enabled: true,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("camouflage-state"),
            nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("camouflage.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("camouflage.log").display().to_string(),
            },
            certificate_lifecycle: CertificateLifecycleConfig::disabled_for_test(dir),
        })
    }

    fn test_nginx_config(dir: &Path) -> NginxSniConfig {
        NginxSniConfig {
            enabled: true,
            conf_path: dir.join("relay.conf"),
            test_cmd: "true".into(),
            reload_cmd: "true".into(),
            default_backend: "127.0.0.1:9".into(),
            access_log_path: dir.join("sni.log").display().to_string(),
        }
    }

    fn modern_camouflage_manifest(dir: &Path) -> CamouflageSitesManifest {
        let cert_path = dir.join("certificates/op1/fullchain.pem");
        let key_path = dir.join("certificates/op1/privkey.pem");
        std::fs::create_dir_all(cert_path.parent().unwrap()).unwrap();
        std::fs::write(&cert_path, b"test certificate").unwrap();
        std::fs::write(&key_path, b"test private key").unwrap();
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                id: "op1_example_com".into(),
                sni: "op1.example.com".into(),
                tls_listener_port: 8443,
                local_backend: OPENLIST_BACKEND.into(),
                certificate: CertificateReference {
                    cert_path,
                    key_path,
                    lifecycle: None,
                },
            }],
        }
    }

    fn runtime_paths(dir: &Path) -> poller::CachePaths {
        poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        }
    }

    fn raw_listener(rule_id: i64, port: u16, protocol: Protocol) -> ListenerConfig {
        ListenerConfig {
            rule_id,
            port,
            protocol,
            node_transport: NodeTransport::Raw,
            ws_path: None,
            sni: None,
            camouflage_required: false,
            send_proxy_protocol: false,
            targets: vec!["127.0.0.1:9".into()],
            load_balance_strategy: LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
        }
    }

    fn nginx_listener(rule_id: i64, sni: &str) -> ListenerConfig {
        ListenerConfig {
            rule_id,
            port: 443,
            protocol: Protocol::Tcp,
            node_transport: NodeTransport::NginxSni,
            ws_path: None,
            sni: Some(sni.into()),
            camouflage_required: false,
            send_proxy_protocol: false,
            targets: vec!["127.0.0.1:55443".into()],
            load_balance_strategy: LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
        }
    }

    fn unique_runtime_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "relaypanel-slice4-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn valid_empty_panel_snapshot_is_authoritative() {
        let input = ReconciliationInput::validated_panel(empty()).unwrap();
        let result = Reconciler::new().plan(&input, None, &ObservedRuntimeEvidence::Unknown, false);
        assert_eq!(result.source, Some(AuthoritySource::ValidatedPanel));
        assert!(result.cleanup_authorized);
        assert!(result.desired_fingerprint.is_some());
    }

    #[test]
    fn transport_failures_never_become_authoritative_empty() {
        for kind in [
            UntrustedInputKind::Timeout,
            UntrustedInputKind::HttpError,
            UntrustedInputKind::AuthenticationFailure,
            UntrustedInputKind::ProtocolMismatch,
            UntrustedInputKind::Disconnected,
        ] {
            let result = Reconciler::new().plan(
                &ReconciliationInput::untrusted(kind),
                None,
                &ObservedRuntimeEvidence::Unknown,
                false,
            );
            assert_eq!(result.state, ReconciliationState::InvalidUntrustedInput);
            assert!(!result.cleanup_authorized);
            assert!(result.desired_fingerprint.is_none());
        }
    }

    #[test]
    fn malformed_or_semantically_invalid_panel_payload_is_untrusted() {
        assert!(TrustedSnapshot::from_json(b"{not-json").is_err());
        let invalid = br#"{"listeners":[{"rule_id":1,"port":0,"protocol":"tcp","targets":["x"],"node_transport":"raw"}],"camouflage_sites":[]}"#;
        assert!(TrustedSnapshot::from_json(invalid).is_err());
    }

    #[test]
    fn local_recovery_is_continuity_not_panel_authority() {
        let input = ReconciliationInput::local_recovery(empty()).unwrap();
        let result = Reconciler::new().plan(&input, None, &ObservedRuntimeEvidence::Unknown, false);
        assert_eq!(result.state, ReconciliationState::DegradedLocalRecovery);
        assert!(!result.cleanup_authorized);
    }

    #[test]
    fn desired_and_dependency_gated_effective_fingerprints_can_differ() {
        let desired = desired();
        let effective = NodeConfigResponse {
            listeners: vec![],
            camouflage_sites: desired.camouflage_sites.clone(),
        };
        let input = ReconciliationInput::validated_panel(desired).unwrap();
        let result = Reconciler::new().plan(
            &input,
            Some(&effective),
            &ObservedRuntimeEvidence::Unknown,
            true,
        );
        assert_ne!(result.desired_fingerprint, result.applied_fingerprint);
        assert!(result.dependency_withheld);
    }

    #[test]
    fn identical_trusted_snapshot_has_deterministic_no_op_plan() {
        let config = desired();
        let input = ReconciliationInput::validated_panel(config.clone()).unwrap();
        let observed = ObservedRuntimeEvidence::matching(&config);
        let mut reconciler = Reconciler::new();
        let first = reconciler.plan(&input, Some(&config), &observed, false);
        assert!(first.apply_required);
        reconciler.record_success(&first);

        let second = reconciler.plan(&input, Some(&config), &observed, false);
        let third = reconciler.plan(&input, Some(&config), &observed, false);
        assert_eq!(second.state, ReconciliationState::Converged);
        assert!(!second.apply_required);
        assert_eq!(second.state, third.state);
        assert_eq!(second.applied_fingerprint, third.applied_fingerprint);
    }

    #[tokio::test]
    async fn pending_lkg_finalization_retries_without_reapplying_runtime() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("relaypanel-reconciler-pending-{stamp}"));
        let paths = poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir(&paths.tmp).unwrap();

        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        )));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let config = raw_config(port);
        let mut reconciler = Reconciler::new();

        let first = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(config.clone()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(first.state, ReconciliationState::ApplyFailed);
        assert!(manager.lock().await.listener_info_for_rule_tcp(7).is_some());

        std::fs::remove_dir(&paths.tmp).unwrap();
        let second = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(config).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(second.state, ReconciliationState::Converged);
        assert!(!second.apply_required);
        assert!(paths.primary.exists());
        assert!(manager.lock().await.listener_info_for_rule_tcp(7).is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn local_recovery_does_not_replace_runtime_with_pending_panel_finalization() {
        let dir = unique_runtime_dir("pending-offline");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let old_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let old_port = old_reserve.local_addr().unwrap().port();
        drop(old_reserve);
        let new_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let new_port = new_reserve.local_addr().unwrap().port();
        drop(new_reserve);

        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();
        let old = raw_config(old_port);
        let new = raw_config(new_port);

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(old.clone()).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        std::fs::create_dir(&paths.tmp).unwrap();

        let failed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(new.clone()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(failed.state, ReconciliationState::ApplyFailed);
        assert!(manager.lock().await.listener_info_for_rule_tcp(7).is_some());
        assert_eq!(
            manager
                .lock()
                .await
                .current_config()
                .as_ref()
                .map(config_fingerprint),
            Some(config_fingerprint(&new))
        );
        assert_eq!(
            poller::load_cache_at(&paths)
                .as_ref()
                .map(config_fingerprint),
            Some(config_fingerprint(&old))
        );

        let offline = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::local_recovery(old).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(offline.state, ReconciliationState::DegradedLocalRecovery);
        assert!(!offline.cleanup_authorized);
        assert_eq!(
            manager
                .lock()
                .await
                .current_config()
                .as_ref()
                .map(config_fingerprint),
            Some(config_fingerprint(&new))
        );

        std::fs::remove_dir(&paths.tmp).unwrap();
        let completed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(new).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(completed.state, ReconciliationState::Converged);
        assert!(!completed.apply_required);
        assert_eq!(
            poller::load_cache_at(&paths)
                .as_ref()
                .map(config_fingerprint),
            manager
                .lock()
                .await
                .current_config()
                .as_ref()
                .map(config_fingerprint)
        );

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn healthy_repeated_snapshot_is_observed_noop() {
        let dir = std::env::temp_dir().join(format!(
            "relaypanel-reconciler-noop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let config = raw_config(port);
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();
        let input = ReconciliationInput::validated_panel(config.clone()).unwrap();

        let first = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input.clone(), paths.clone())
            .await;
        assert_eq!(first.state, ReconciliationState::Converged);
        assert!(first.observed_fingerprint.is_some());
        let second = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input, paths.clone())
            .await;
        assert_eq!(second.state, ReconciliationState::Converged);
        assert!(!second.apply_required);
        assert!(second.observed_fingerprint.is_some());
        assert_eq!(first.observed_fingerprint, second.observed_fingerprint);

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bootstrap_fallback_with_withheld_dependency_is_repeated_noop() {
        let dir = std::env::temp_dir().join(format!(
            "relaypanel-reconciler-bootstrap-compat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        std::fs::create_dir_all(&dir).unwrap();
        let wrapper = dir.join("camouflage.conf");
        std::fs::write(&wrapper, b"bootstrap fallback\n").unwrap();
        let manager = Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        )));
        let camouflage = Arc::new(Mutex::new(compatibility_camouflage_manager(&dir)));
        let input = ReconciliationInput::validated_panel(desired()).unwrap();
        let mut reconciler = Reconciler::new();

        let first = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input.clone(), paths.clone())
            .await;
        assert_eq!(first.state, ReconciliationState::DependencyWithheld);
        assert!(first.dependency_withheld);
        assert_eq!(std::fs::read(&wrapper).unwrap(), b"bootstrap fallback\n");
        let cache_before = std::fs::metadata(&paths.primary)
            .unwrap()
            .modified()
            .unwrap();

        let second = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input, paths.clone())
            .await;
        assert_eq!(second.state, ReconciliationState::DependencyWithheld);
        assert!(!second.apply_required);
        assert_eq!(first.observed_fingerprint, second.observed_fingerprint);
        assert_eq!(std::fs::read(&wrapper).unwrap(), b"bootstrap fallback\n");
        assert_eq!(
            std::fs::metadata(&paths.primary)
                .unwrap()
                .modified()
                .unwrap(),
            cache_before
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn local_recovery_preserves_unowned_bootstrap_fallback() {
        let dir = std::env::temp_dir().join(format!(
            "relaypanel-reconciler-local-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        std::fs::create_dir_all(&dir).unwrap();
        let wrapper = dir.join("camouflage.conf");
        std::fs::write(&wrapper, b"bootstrap fallback\n").unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(compatibility_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();

        let result = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::local_recovery(raw_config(port)).unwrap(),
                paths,
            )
            .await;
        assert_eq!(result.state, ReconciliationState::DegradedLocalRecovery);
        assert!(!result.cleanup_authorized);
        assert_eq!(std::fs::read(&wrapper).unwrap(), b"bootstrap fallback\n");
        assert!(camouflage.lock().await.active_snis().is_empty());

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn authoritative_empty_removes_managed_raw_tcp_and_udp() {
        let dir = unique_runtime_dir("raw-empty");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tcp_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp_reserve.local_addr().unwrap().port();
        drop(tcp_reserve);
        let udp_reserve = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp_reserve.local_addr().unwrap().port();
        drop(udp_reserve);
        let config = NodeConfigResponse {
            listeners: vec![
                raw_listener(31, tcp_port, Protocol::Tcp),
                raw_listener(32, udp_port, Protocol::Udp),
            ],
            camouflage_sites: vec![],
        };
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();

        let initial = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(config).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(initial.state, ReconciliationState::Converged);
        assert!(std::net::TcpListener::bind(("127.0.0.1", tcp_port)).is_err());
        assert!(std::net::UdpSocket::bind(("127.0.0.1", udp_port)).is_err());

        let removed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(removed.state, ReconciliationState::Converged);
        assert!(removed.cleanup_authorized);
        assert!(std::net::TcpListener::bind(("127.0.0.1", tcp_port)).is_ok());
        assert!(std::net::UdpSocket::bind(("127.0.0.1", udp_port)).is_ok());
        assert!(poller::load_cache_at(&paths).unwrap().listeners.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn authoritative_empty_removes_managed_nginx_route_only() {
        let dir = unique_runtime_dir("nginx-empty");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let unmanaged = dir.join("operator.conf");
        std::fs::write(&unmanaged, b"operator-owned\n").unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();
        let config = NodeConfigResponse {
            listeners: vec![nginx_listener(41, "stale.example.com")],
            camouflage_sites: vec![],
        };

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(config).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "stale.example.com"),
            Some(41)
        );

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(empty()).unwrap(),
                    paths,
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "stale.example.com"),
            None
        );
        let managed = std::fs::read_to_string(dir.join("relay.conf")).unwrap();
        assert!(!managed.contains("stale.example.com"));
        assert!(!managed.contains("listen 443;"));
        assert_eq!(std::fs::read(&unmanaged).unwrap(), b"operator-owned\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn untrusted_and_local_recovery_inputs_never_delete_managed_runtime() {
        let dir = unique_runtime_dir("untrusted-preserve");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();
        let config = NodeConfigResponse {
            listeners: vec![raw_listener(51, port, Protocol::Tcp)],
            camouflage_sites: vec![],
        };
        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(config).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );

        for kind in [
            UntrustedInputKind::Timeout,
            UntrustedInputKind::HttpError,
            UntrustedInputKind::AuthenticationFailure,
            UntrustedInputKind::ProtocolMismatch,
            UntrustedInputKind::MalformedPayload,
            UntrustedInputKind::SemanticValidation,
            UntrustedInputKind::Disconnected,
        ] {
            let result = reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::untrusted(kind),
                    paths.clone(),
                )
                .await;
            assert_eq!(result.state, ReconciliationState::InvalidUntrustedInput);
            assert!(!result.cleanup_authorized);
            assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
        }

        let local = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::local_recovery(empty()).unwrap(),
                paths,
            )
            .await;
        assert_eq!(local.state, ReconciliationState::DegradedLocalRecovery);
        assert!(!local.cleanup_authorized);
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn listener_lkg_finalization_precedes_camouflage_cleanup_and_retries() {
        let dir = unique_runtime_dir("ordered-finalization");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let manager = Arc::new(Mutex::new(manager));
        let mut sites = compatibility_camouflage_manager(&dir);
        assert!(sites.apply_candidate(modern_camouflage_manifest(&dir)));
        let camouflage = Arc::new(Mutex::new(sites));
        let mut reconciler = Reconciler::new();
        let config = desired();

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(config).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "op1.example.com"),
            Some(1)
        );
        assert!(camouflage
            .lock()
            .await
            .active_snis()
            .contains("op1.example.com"));

        std::fs::create_dir(&paths.tmp).unwrap();
        let failed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(failed.state, ReconciliationState::ApplyFailed);
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "op1.example.com"),
            None,
            "listener runtime must be removed before stale camouflage"
        );
        assert!(camouflage
            .lock()
            .await
            .active_snis()
            .contains("op1.example.com"));
        assert_eq!(poller::load_cache_at(&paths).unwrap().listeners.len(), 1);

        std::fs::remove_dir(&paths.tmp).unwrap();
        let completed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(completed.state, ReconciliationState::Converged);
        assert!(!completed.apply_required);
        assert!(camouflage.lock().await.active_snis().is_empty());
        assert!(poller::load_cache_at(&paths).unwrap().listeners.is_empty());
        assert!(!std::fs::read_to_string(dir.join("camouflage.conf"))
            .unwrap()
            .contains("op1.example.com"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_camouflage_cleanup_converges_without_listener_reapply() {
        let dir = unique_runtime_dir("camouflage-cleanup-retry");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let manager = Arc::new(Mutex::new(manager));
        let mut sites = compatibility_camouflage_manager(&dir);
        assert!(sites.apply_candidate(modern_camouflage_manifest(&dir)));
        let camouflage = Arc::new(Mutex::new(sites));
        let mut reconciler = Reconciler::new();

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(desired()).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        camouflage
            .lock()
            .await
            .set_nginx_commands_for_test("true", "false");

        let failed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(failed.state, ReconciliationState::ApplyFailed);
        assert!(poller::load_cache_at(&paths).unwrap().listeners.is_empty());
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "op1.example.com"),
            None
        );
        assert!(camouflage
            .lock()
            .await
            .active_snis()
            .contains("op1.example.com"));
        let listener_fragment = dir.join("relay.conf");
        let listener_fragment_before = std::fs::read(&listener_fragment).unwrap();
        let listener_mtime_before = std::fs::metadata(&listener_fragment)
            .unwrap()
            .modified()
            .unwrap();

        camouflage
            .lock()
            .await
            .set_nginx_commands_for_test("true", "true");
        let completed = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths,
            )
            .await;
        assert_eq!(completed.state, ReconciliationState::Converged);
        assert!(!completed.apply_required);
        assert!(camouflage.lock().await.active_snis().is_empty());
        assert_eq!(
            std::fs::read(&listener_fragment).unwrap(),
            listener_fragment_before
        );
        assert_eq!(
            std::fs::metadata(&listener_fragment)
                .unwrap()
                .modified()
                .unwrap(),
            listener_mtime_before
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn corrupt_listener_and_camouflage_lkg_do_not_authorize_cleanup() {
        let dir = unique_runtime_dir("corrupt-lkg-preserve");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let config = NodeConfigResponse {
            listeners: vec![raw_listener(61, port, Protocol::Tcp)],
            camouflage_sites: vec![],
        };
        assert!(manager.apply_config(&config).await);
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(compatibility_camouflage_manager(&dir)));
        std::fs::write(&paths.primary, b"corrupt").unwrap();
        std::fs::write(&paths.backup, b"corrupt").unwrap();
        let camouflage_state = dir.join("camouflage-state");
        std::fs::create_dir_all(&camouflage_state).unwrap();
        std::fs::write(camouflage_state.join("site-manifest.json"), b"corrupt").unwrap();
        std::fs::write(
            camouflage_state.join("site-manifest.backup.json"),
            b"corrupt",
        )
        .unwrap();

        assert!(poller::load_cache_state_at(&paths).is_none());
        assert!(!camouflage.lock().await.restore_and_apply());
        let result = Reconciler::new()
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::degraded_local_recovery(),
                paths,
            )
            .await;
        assert_eq!(result.state, ReconciliationState::DegradedLocalRecovery);
        assert!(!result.cleanup_authorized);
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn dependency_withheld_update_preserves_previous_active_route() {
        let dir = unique_runtime_dir("dependency-withheld-preserve");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let manager = Arc::new(Mutex::new(manager));
        let mut sites = compatibility_camouflage_manager(&dir);
        assert!(sites.apply_candidate(modern_camouflage_manifest(&dir)));
        let camouflage = Arc::new(Mutex::new(sites));
        let mut reconciler = Reconciler::new();
        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(desired()).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );

        let mut next = desired();
        next.camouflage_sites[0].site_id = "op2_example_com".into();
        next.camouflage_sites[0].sni = "op2.example.com".into();
        next.camouflage_sites[0].certificate.domain = "op2.example.com".into();
        next.listeners[0].sni = Some("op2.example.com".into());
        next.listeners[0].targets = vec!["192.0.2.2:55443".into()];
        let withheld = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(next).unwrap(),
                paths,
            )
            .await;
        assert_eq!(withheld.state, ReconciliationState::DependencyWithheld);
        assert!(withheld.dependency_withheld);
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "op1.example.com"),
            Some(1)
        );
        assert_eq!(
            manager
                .lock()
                .await
                .nginx_sni_rule_id_for(443, "op2.example.com"),
            None
        );
        assert!(camouflage
            .lock()
            .await
            .active_snis()
            .contains("op1.example.com"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn authoritative_empty_after_restart_does_not_resurrect_state() {
        let dir = unique_runtime_dir("empty-restart");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let manager = Arc::new(Mutex::new(manager));
        let mut sites = compatibility_camouflage_manager(&dir);
        assert!(sites.apply_candidate(modern_camouflage_manifest(&dir)));
        let camouflage = Arc::new(Mutex::new(sites));
        let mut reconciler = Reconciler::new();

        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(desired()).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        assert_eq!(
            reconciler
                .reconcile_with_test_paths(
                    &manager,
                    &camouflage,
                    ReconciliationInput::validated_panel(empty()).unwrap(),
                    paths.clone(),
                )
                .await
                .state,
            ReconciliationState::Converged
        );
        let listener_lkg_before = std::fs::read(&paths.primary).unwrap();
        let camouflage_lkg = dir.join("camouflage-state/site-manifest.json");
        let camouflage_lkg_before = std::fs::read(&camouflage_lkg).unwrap();
        assert!(poller::load_cache_at(&paths).unwrap().listeners.is_empty());
        assert!(camouflage.lock().await.active_snis().is_empty());

        drop(reconciler);
        drop(camouflage);
        drop(manager);

        let mut restarted_sites = compatibility_camouflage_manager(&dir);
        assert!(restarted_sites.restore_and_apply());
        assert!(restarted_sites.active_snis().is_empty());
        let restarted_camouflage = Arc::new(Mutex::new(restarted_sites));
        let mut restarted_manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        restarted_manager.set_nginx_sni_config_for_test(test_nginx_config(&dir));
        let restarted_manager = Arc::new(Mutex::new(restarted_manager));
        let mut restarted_reconciler = Reconciler::new();
        let recovered = poller::load_cache_at(&paths).unwrap();

        let local = restarted_reconciler
            .reconcile_with_test_paths(
                &restarted_manager,
                &restarted_camouflage,
                ReconciliationInput::local_recovery(recovered).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(local.state, ReconciliationState::DegradedLocalRecovery);
        assert!(restarted_manager
            .lock()
            .await
            .current_config()
            .unwrap()
            .listeners
            .is_empty());
        assert!(restarted_camouflage.lock().await.active_snis().is_empty());

        let authoritative = restarted_reconciler
            .reconcile_with_test_paths(
                &restarted_manager,
                &restarted_camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(authoritative.state, ReconciliationState::Converged);
        let listener_lkg_converged = std::fs::read(&paths.primary).unwrap();
        let camouflage_lkg_converged = std::fs::read(&camouflage_lkg).unwrap();

        let repeated = restarted_reconciler
            .reconcile_with_test_paths(
                &restarted_manager,
                &restarted_camouflage,
                ReconciliationInput::validated_panel(empty()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(repeated.state, ReconciliationState::Converged);
        assert!(!repeated.apply_required);
        assert_eq!(
            std::fs::read(&paths.primary).unwrap(),
            listener_lkg_converged
        );
        assert_eq!(
            std::fs::read(&camouflage_lkg).unwrap(),
            camouflage_lkg_converged
        );
        assert_eq!(listener_lkg_before, listener_lkg_converged);
        assert_eq!(camouflage_lkg_before, camouflage_lkg_converged);
        assert!(!std::fs::read_to_string(dir.join("camouflage.conf"))
            .unwrap()
            .contains("op1.example.com"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn panel_snapshot_after_local_recovery_replaces_stale_runtime_and_lkg() {
        let dir = unique_runtime_dir("offline-config-change");
        let paths = runtime_paths(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let old_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let old_port = old_reserve.local_addr().unwrap().port();
        drop(old_reserve);
        let new_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let new_port = new_reserve.local_addr().unwrap().port();
        drop(new_reserve);
        let old = raw_config(old_port);
        let mut new = raw_config(new_port);
        new.listeners[0].rule_id = 8;

        poller::commit_cache_at(&old, &paths).unwrap();
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_listen_addresses_for_test("127.0.0.1", "");
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let mut reconciler = Reconciler::new();

        let local = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::local_recovery(old.clone()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(local.state, ReconciliationState::DegradedLocalRecovery);
        assert!(std::net::TcpListener::bind(("127.0.0.1", old_port)).is_err());

        let authoritative = reconciler
            .reconcile_with_test_paths(
                &manager,
                &camouflage,
                ReconciliationInput::validated_panel(new.clone()).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(authoritative.state, ReconciliationState::Converged);
        assert!(authoritative.cleanup_authorized);
        assert!(std::net::TcpListener::bind(("127.0.0.1", old_port)).is_ok());
        assert!(std::net::TcpListener::bind(("127.0.0.1", new_port)).is_err());
        assert_eq!(
            poller::load_cache_at(&paths)
                .as_ref()
                .map(config_fingerprint),
            Some(config_fingerprint(&new))
        );

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        let mut restarted_manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        restarted_manager.set_listen_addresses_for_test("127.0.0.1", "");
        let restarted_manager = Arc::new(Mutex::new(restarted_manager));
        let restarted_camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let recovered = poller::load_cache_at(&paths).unwrap();
        let restarted = Reconciler::new()
            .reconcile_with_test_paths(
                &restarted_manager,
                &restarted_camouflage,
                ReconciliationInput::local_recovery(recovered).unwrap(),
                paths.clone(),
            )
            .await;
        assert_eq!(restarted.state, ReconciliationState::DegradedLocalRecovery);
        assert!(std::net::TcpListener::bind(("127.0.0.1", old_port)).is_ok());
        assert!(std::net::TcpListener::bind(("127.0.0.1", new_port)).is_err());

        restarted_manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn managed_nginx_drift_is_repaired_without_panel_change() {
        let dir = std::env::temp_dir().join(format!(
            "relaypanel-reconciler-nginx-drift-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = poller::CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        };
        let mut manager = ForwarderManager::new(
            Arc::new(crate::reporter::TrafficCounter::new()),
            Arc::new(crate::reporter::ConnectionTracker::new()),
        );
        manager.set_nginx_sni_config_for_test(NginxSniConfig {
            enabled: true,
            conf_path: dir.join("relay.conf"),
            test_cmd: "true".into(),
            reload_cmd: "true".into(),
            default_backend: "127.0.0.1:9".into(),
            access_log_path: dir.join("sni.log").display().to_string(),
        });
        let manager = Arc::new(Mutex::new(manager));
        let camouflage = Arc::new(Mutex::new(test_camouflage_manager(&dir)));
        let config = NodeConfigResponse {
            listeners: vec![ListenerConfig {
                rule_id: 22,
                port: 443,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::NginxSni,
                ws_path: None,
                sni: Some("drift.example.com".into()),
                camouflage_required: false,
                send_proxy_protocol: false,
                targets: vec!["127.0.0.1:55443".into()],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
            camouflage_sites: vec![],
        };
        let input = ReconciliationInput::validated_panel(config).unwrap();
        let mut reconciler = Reconciler::new();
        let first = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input.clone(), paths.clone())
            .await;
        assert_eq!(first.state, ReconciliationState::Converged);
        let managed_path = dir.join("relay.conf");
        assert!(managed_path.exists());
        std::fs::remove_file(&managed_path).unwrap();

        let repaired = reconciler
            .reconcile_with_test_paths(&manager, &camouflage, input, paths.clone())
            .await;
        assert_eq!(repaired.state, ReconciliationState::Converged);
        assert!(repaired.observed_fingerprint.is_some());
        assert!(managed_path.exists());
        assert!(std::fs::read_to_string(&managed_path)
            .unwrap()
            .contains("drift"));

        manager
            .lock()
            .await
            .apply_config(&NodeConfigResponse {
                listeners: vec![],
                camouflage_sites: vec![],
            })
            .await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn status_result(
        state: ReconciliationState,
        source: Option<AuthoritySource>,
        recovery_source: Option<LocalRecoverySource>,
    ) -> ReconciliationResult {
        let desired = config_fingerprint(&empty());
        let applied = config_fingerprint(&raw_config(32001));
        let observed = relay_shared::reconciliation::fingerprint_bytes(b"runtime evidence");
        ReconciliationResult {
            state,
            source,
            desired_fingerprint: Some(desired),
            applied_fingerprint: Some(applied),
            observed_fingerprint: Some(observed),
            cleanup_authorized: source == Some(AuthoritySource::ValidatedPanel),
            apply_required: matches!(
                state,
                ReconciliationState::ApplyRequired | ReconciliationState::ApplyFailed
            ),
            dependency_withheld: state == ReconciliationState::DependencyWithheld,
            recovery_source,
        }
    }

    #[test]
    fn status_reports_fingerprints_failure_and_later_convergence() {
        let mut reconciler = Reconciler::new();
        assert_eq!(
            reconciler.status_snapshot().state,
            ReconciliationStatusState::WaitingForAuthority
        );

        let failed = status_result(
            ReconciliationState::ApplyFailed,
            Some(AuthoritySource::ValidatedPanel),
            None,
        );
        reconciler.record_status(&failed);
        let failed_status = reconciler.status_snapshot();
        assert_eq!(failed_status.state, ReconciliationStatusState::ApplyFailed);
        assert_eq!(
            failed_status.last_error.as_deref(),
            Some("runtime reconciliation failed")
        );
        assert_eq!(
            failed_status.recovery_source,
            ReconciliationRecoverySource::Panel
        );
        assert_eq!(
            failed_status.desired_fingerprint.as_deref(),
            failed
                .desired_fingerprint
                .as_ref()
                .map(ConfigFingerprint::as_str)
        );
        assert_eq!(
            failed_status.applied_fingerprint.as_deref(),
            failed
                .applied_fingerprint
                .as_ref()
                .map(ConfigFingerprint::as_str)
        );
        assert_eq!(
            failed_status.observed_fingerprint.as_deref(),
            failed
                .observed_fingerprint
                .as_ref()
                .map(ConfigFingerprint::as_str)
        );

        let serialized = serde_json::to_string(&failed_status).unwrap();
        for forbidden in [
            "group-token-secret",
            "enrollment-secret",
            "PRIVATE KEY",
            "reality-private-key",
        ] {
            assert!(!serialized.contains(forbidden));
        }

        let converged = status_result(
            ReconciliationState::Converged,
            Some(AuthoritySource::ValidatedPanel),
            None,
        );
        reconciler.record_status(&converged);
        let healthy = reconciler.status_snapshot();
        assert_eq!(healthy.state, ReconciliationStatusState::Converged);
        assert!(healthy.last_success_at.is_some());
        assert!(healthy.last_error.is_none());
    }

    #[test]
    fn status_distinguishes_repair_withholding_and_recovery_sources() {
        let snapshot = TrustedSnapshot::validated_panel(desired()).unwrap();
        let applied = config_fingerprint(&desired());
        let observed = relay_shared::reconciliation::fingerprint_bytes(b"drifted runtime");
        let mut reconciler = Reconciler::new();
        reconciler.record_repairing(&snapshot, &applied, &observed);
        assert_eq!(
            reconciler.status_snapshot().state,
            ReconciliationStatusState::Repairing
        );

        let withheld = status_result(
            ReconciliationState::DependencyWithheld,
            Some(AuthoritySource::ValidatedPanel),
            None,
        );
        reconciler.record_status(&withheld);
        let status = reconciler.status_snapshot();
        assert_eq!(status.state, ReconciliationStatusState::DependencyWithheld);
        assert!(status.last_error.is_none());

        let backup = status_result(
            ReconciliationState::DegradedLocalRecovery,
            Some(AuthoritySource::LocalRecovery),
            Some(LocalRecoverySource::RepairedFromBackup),
        );
        reconciler.record_status(&backup);
        let status = reconciler.status_snapshot();
        assert_eq!(
            status.state,
            ReconciliationStatusState::DegradedLocalRecovery
        );
        assert_eq!(
            status.recovery_source,
            ReconciliationRecoverySource::LkgBackupRepaired
        );

        let primary = status_result(
            ReconciliationState::DegradedLocalRecovery,
            Some(AuthoritySource::LocalRecovery),
            Some(LocalRecoverySource::PrimaryLkg),
        );
        reconciler.record_status(&primary);
        assert_eq!(
            reconciler.status_snapshot().recovery_source,
            ReconciliationRecoverySource::LkgPrimary
        );
    }
}
