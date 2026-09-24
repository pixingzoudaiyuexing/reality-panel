// v0.4.8: node-side rule diagnosis.  v0.4.9: secure-diagnose challenge + TCP-only.
//
// When the panel sends `{"type":"diagnose_rule", request_id, rule_id,
// challenge}` over the WS control channel, the node:
//   1. looks up the rule's TCP listener (port/transport/targets/running)
//   2. runs SIDE-CHANNEL TCP reachability probes against each target — a fresh
//      TcpStream per target, NOT through the forwarder, so the probe:
//        - doesn't count against rule traffic (TrafficCounter untouched)
//        - isn't throttled by the rate limiter
//        - doesn't increment the active-connection count
//        - closes immediately on success
//   3. POSTs a DiagnoseResult back to the panel over the normal HTTP node→panel
//      channel (same auth as report_status), ECHOING the challenge verbatim.
//      The panel rejects the result if the challenge is empty or doesn't match
//      (v0.4.9), so a forged POST that guesses request_id+node_id fails.
//
// v0.4.9: diagnosis is TCP-ONLY. The old UDP "route-only" check is gone — UDP
// can't be verified cheaply and a "resolved but not probed" result misled
// operators. The panel rejects pure-UDP rules before dispatch (HTTP 400), so
// this code only ever runs for tcp / tcp_udp rules. For a tcp_udp rule we
// select the TCP listener explicitly (listener_info_for_rule_tcp) rather than
// relying on HashMap iteration order, which would be nondeterministic.
//
// Limits: max 32 targets, connect deadline 3s each, at most 8 concurrent probes.

use crate::config::NodeConfig;
use crate::forwarder::camouflage_site::{CamouflageSite, CamouflageSiteManager};
use crate::forwarder::ForwarderManager;
use crate::reconciler::Reconciler;
use relay_shared::protocol::{
    DiagnoseResult, DiagnoseTargetResult, RealityBackendDiagnosis, RealityCamouflageDiagnosis,
    RealityCertificateDiagnosis, RealityCheck, RealityConfigDiagnosis, RealityConvergenceDiagnosis,
    RealityDiagnosis, RealityFallbackDiagnosis, RealityNginxDiagnosis, RealityRuntimeDiagnosis,
    TargetProbeErrorKind, TargetProbeOutcome,
};
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use x509_parser::prelude::FromDer;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_PROBES: usize = 8;
const MAX_TARGETS: usize = 32;

/// Run a diagnosis for one rule and POST the result to the panel.
/// Fire-and-forget from the WS loop's perspective: errors are logged, never
/// propagated (a failed probe must not crash the control channel).
///
/// `challenge` is the opaque per-run string the panel sent in the probe; we
/// MUST echo it back verbatim in DiagnoseResult.challenge or the panel rejects
/// the result (v0.4.9 secure-diagnose protocol).
#[allow(clippy::too_many_arguments)] // 诊断请求绑定字段保持显式，避免改变现有安全调用链。
pub async fn run_and_report(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    reconciler: &Arc<Mutex<Reconciler>>,
    config: &NodeConfig,
    node_id: &str,
    request_id: String,
    rule_id: i64,
    desired_sni: Option<String>,
    desired_config_revision: u64,
    desired_fingerprint: String,
    targets: Vec<String>,
    protocol: String,
    challenge: String,
) {
    let result = diagnose(
        manager,
        camouflage,
        reconciler,
        &request_id,
        rule_id,
        desired_sni,
        desired_config_revision,
        desired_fingerprint,
        targets,
        protocol,
        challenge,
    )
    .await;
    let mut result = result;
    result.node_id = node_id.to_string();
    if let Err(e) = report(config, result).await {
        tracing::warn!("diagnose {}: failed to report result: {}", request_id, e);
    }
}

/// Build the DiagnoseResult for a rule (probe targets, capture listener state).
#[allow(clippy::too_many_arguments)] // 参数逐项对应 wire identity，rc.7 不引入包装结构。
async fn diagnose(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    reconciler: &Arc<Mutex<Reconciler>>,
    request_id: &str,
    rule_id: i64,
    desired_sni: Option<String>,
    desired_config_revision: u64,
    desired_fingerprint: String,
    desired_targets: Vec<String>,
    desired_protocol: String,
    challenge: String,
) -> DiagnoseResult {
    // v0.4.9: select the rule's TCP listener explicitly. For a tcp_udp rule
    // the generic lookup returns an arbitrary (Tcp OR Udp) listener because
    // self.listeners is a HashMap; the TCP selector is deterministic. The
    // panel rejects pure-UDP rules before dispatch, so rule_id here is tcp or
    // tcp_udp — both have a TCP listener.
    let (info, reality) = {
        let manager = manager.lock().await;
        let config = manager.current_config();
        let reality = config
            .as_ref()
            .and_then(|config| {
                config
                    .listeners
                    .iter()
                    .find(|listener| listener.rule_id == rule_id)
            })
            .filter(|listener| {
                listener.node_transport == relay_shared::protocol::NodeTransport::NginxSni
            })
            .cloned()
            .map(|listener| (config.clone(), listener));
        let info = if desired_protocol == "udp" {
            manager.listener_info_for_rule_udp(rule_id)
        } else {
            manager.listener_info_for_rule_tcp(rule_id)
        };
        (info, reality)
    };
    let reality = if let Some((config, listener)) = reality {
        // Certificate/OpenSSL inspection uses an immutable snapshot so a
        // diagnosis never retains the shared camouflage state mutex.
        let camouflage = camouflage.lock().await.clone();
        let manager = manager.lock().await;
        let active_revision = reconciler
            .lock()
            .await
            .status_snapshot()
            .applied_config_revision
            .unwrap_or_default();
        let mut diagnosis = build_reality_diagnosis(
            &manager,
            config.as_ref(),
            &listener,
            &camouflage,
            desired_sni.as_deref(),
            desired_config_revision,
            &desired_fingerprint,
            active_revision,
        );
        drop(manager);
        if let Some(sni) = diagnosis.config.sni.as_deref() {
            match probe_local_camouflage(sni, diagnosis.camouflage.tls_listener_port).await {
                Ok(status) => {
                    diagnosis.camouflage.http_status = Some(status);
                    diagnosis.camouflage.check = if (200..400).contains(&status) {
                        check("pass", format!("local HTTPS returned HTTP {status}"))
                    } else {
                        check("warning", format!("local HTTPS returned HTTP {status}"))
                    };
                    diagnosis.certificate.tls_handshake = check(
                        "pass",
                        "local TLS handshake succeeded with hostname verification",
                    );
                }
                Err(error) => {
                    diagnosis.camouflage.check = check("fail", error.clone());
                    diagnosis.certificate.tls_handshake = check("fail", error);
                }
            }
        }
        Some(diagnosis)
    } else {
        None
    };

    let (listener_running, listen_port, protocol, transport, targets) = match &info {
        Some(i) => (
            i.running,
            i.port,
            i.protocol.clone(),
            i.transport.clone(),
            i.targets.clone(),
        ),
        None => (false, 0, String::new(), String::new(), Vec::new()),
    };

    // Cap targets; probe in bounded-concurrency batches. TCP-only (v0.4.9).
    let targets_to_probe: Vec<String> = if desired_targets.is_empty() {
        targets
    } else {
        desired_targets
    }
    .into_iter()
    .take(MAX_TARGETS)
    .collect();
    let results = if desired_protocol == "udp" {
        targets_to_probe
            .iter()
            .map(|address| DiagnoseTargetResult {
                address: address.clone(),
                hostname: split_target(address).and_then(|(host, _)| {
                    host.parse::<std::net::IpAddr>().is_err().then_some(host)
                }),
                resolved_ip: None,
                actual_address: None,
                port: split_target(address).map_or(0, |(_, port)| port),
                protocol: "udp".into(),
                error_kind: None,
                outcome: TargetProbeOutcome::NotTested {
                    reason: "generic UDP reachability cannot be verified reliably".into(),
                },
            })
            .collect()
    } else {
        probe_targets(&targets_to_probe).await
    };
    let mut reality = reality;
    if let Some(diagnosis) = reality.as_mut() {
        diagnosis.backends = reality_backend_results(&results);
    }

    DiagnoseResult {
        msg_type: "diagnose_result".into(),
        request_id: request_id.to_string(),
        rule_id,
        node_id: String::new(), // filled by caller
        diagnosed_sni: reality
            .as_ref()
            .and_then(|d| d.convergence.active_sni.clone()),
        config_revision: reality
            .as_ref()
            .map(|d| d.convergence.active_config_revision)
            .unwrap_or_default(),
        config_fingerprint: reality
            .as_ref()
            .map(|d| d.convergence.active_fingerprint.clone())
            .unwrap_or_default(),
        // Echoed back verbatim; the panel rejects the result without an exact
        // match (v0.4.9 secure-diagnose challenge).
        challenge,
        listener_running,
        listen_port,
        protocol: if desired_protocol.is_empty() {
            protocol
        } else {
            desired_protocol
        },
        transport,
        results,
        reality,
    }
}

fn check(state: &str, detail: impl Into<String>) -> RealityCheck {
    RealityCheck {
        state: state.into(),
        detail: Some(detail.into()),
    }
}

fn nginx_sni_mapping_matches(
    rule: &crate::forwarder::nginx_sni::NginxSniRule,
    listener: &relay_shared::protocol::ListenerConfig,
    sni: Option<&str>,
) -> bool {
    let configured_targets = listener
        .targets
        .iter()
        .map(|target| target.trim())
        .filter(|target| !target.is_empty())
        .collect::<Vec<_>>();
    rule.listen_port == listener.port
        && sni.is_some_and(|value| rule.sni == value.trim().to_ascii_lowercase())
        && rule
            .configured_targets
            .iter()
            .map(String::as_str)
            .eq(configured_targets)
        && rule.send_proxy_protocol == listener.send_proxy_protocol
}

#[allow(clippy::too_many_arguments)] // desired/effective identity 必须独立传入以防旧状态误判。
fn build_reality_diagnosis(
    manager: &ForwarderManager,
    config: Option<&relay_shared::protocol::NodeConfigResponse>,
    listener: &relay_shared::protocol::ListenerConfig,
    camouflage: &CamouflageSiteManager,
    desired_sni: Option<&str>,
    desired_config_revision: u64,
    desired_fingerprint: &str,
    active_config_revision: u64,
) -> RealityDiagnosis {
    let sni = listener.sni.clone().filter(|s| !s.trim().is_empty());
    let config_ok = sni.is_some() && !listener.targets.is_empty() && listener.port > 0;
    let config_status = if config_ok {
        check("pass", "accepted nginx_sni configuration")
    } else {
        check("fail", "missing SNI, listen port, or backend target")
    };

    let plan_rule = manager.nginx_sni_rule_for_id(listener.rule_id);
    let plan_contains_rule = plan_rule.is_some();
    let mapping_matches = plan_rule
        .as_ref()
        .is_some_and(|rule| nginx_sni_mapping_matches(rule, listener, sni.as_deref()));
    let observation = manager.nginx_sni_runtime_observation();
    let expected_fingerprint = manager.nginx_sni_expected_fingerprint();
    let deployed_fingerprint = observation
        .as_ref()
        .and_then(|observation| observation.deployed_fingerprint.as_ref())
        .map(ToString::to_string);
    let managed_file_matches = observation.as_ref().is_some_and(|value| value.file_matches);
    let config_valid = observation.as_ref().is_some_and(|value| value.config_valid);
    let service_healthy = observation
        .as_ref()
        .is_some_and(|value| value.service_healthy);
    let nginx_ok = plan_contains_rule
        && mapping_matches
        && managed_file_matches
        && config_valid
        && service_healthy;
    let nginx = RealityNginxDiagnosis {
        check: if nginx_ok {
            check("pass", "managed plan and deployed fragment agree")
        } else {
            check("fail", "managed Nginx fragment or plan is not converged")
        },
        plan_contains_rule,
        mapping_matches,
        expected_fingerprint,
        deployed_fingerprint,
        managed_file_matches,
        config_valid,
        service_healthy,
    };

    let listen_443 = ForwarderManager::nginx_sni_tcp_port_listening(listener.port);
    let listen_8443 = ForwarderManager::nginx_sni_tcp_port_listening(8443);
    let runtime = RealityRuntimeDiagnosis {
        check: if listen_443 && listen_8443 && config_valid && service_healthy {
            check(
                "pass",
                "Nginx is active, valid, and required ports are listening",
            )
        } else {
            check("fail", "Nginx runtime or required listener is unavailable")
        },
        listen_443,
        listen_8443,
    };

    let backends = Vec::new();

    let site = sni.as_deref().and_then(|sni| {
        config.and_then(|config| {
            config
                .camouflage_sites
                .iter()
                .find(|site| site.sni == sni)
                .cloned()
        })
    });
    let (certificate, camouflage_status) =
        certificate_and_camouflage(camouflage, sni.as_deref(), site.as_ref());
    RealityDiagnosis {
        convergence: RealityConvergenceDiagnosis {
            check: if desired_config_revision > 0
                && desired_sni == sni.as_deref()
                && desired_config_revision == active_config_revision
                && !desired_fingerprint.is_empty()
                && config
                    .map(|value| {
                        relay_shared::reconciliation::config_fingerprint(value).as_str()
                            == desired_fingerprint
                    })
                    .unwrap_or(false)
            {
                check(
                    "pass",
                    "active rule matches current desired SNI and config revision",
                )
            } else {
                check(
                    "fail",
                    "active rule does not match current desired configuration",
                )
            },
            desired_sni: desired_sni.map(str::to_string),
            active_sni: sni.clone(),
            desired_config_revision,
            active_config_revision,
            desired_fingerprint: desired_fingerprint.to_string(),
            active_fingerprint: config
                .map(relay_shared::reconciliation::config_fingerprint)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
        },
        config: RealityConfigDiagnosis {
            check: config_status,
            listen_port: listener.port,
            sni,
            targets: listener.targets.clone(),
            send_proxy_protocol: listener.send_proxy_protocol,
        },
        nginx,
        runtime,
        backends,
        certificate,
        camouflage: camouflage_status,
        fallback: fallback_diagnosis(),
        vless_authentication: check(
            "not_tested",
            "relay-node does not possess client UUID or Reality credentials",
        ),
    }
}

fn fallback_diagnosis() -> RealityFallbackDiagnosis {
    RealityFallbackDiagnosis {
        check: check(
            "not_tested",
            "the full :443 -> remote Reality -> :8443 fallback path is not probed by relay-node",
        ),
        http_status: None,
        authenticated_reality_path: false,
    }
}

fn reality_backend_results(results: &[DiagnoseTargetResult]) -> Vec<RealityBackendDiagnosis> {
    results
        .iter()
        .cloned()
        .map(|result| match result.outcome {
            TargetProbeOutcome::Reachable { elapsed_ms } => RealityBackendDiagnosis {
                address: result.address,
                check: check("pass", "TCP connection succeeded"),
                elapsed_ms: Some(elapsed_ms),
            },
            TargetProbeOutcome::Failed { error } => RealityBackendDiagnosis {
                address: result.address,
                check: check("fail", error),
                elapsed_ms: None,
            },
            TargetProbeOutcome::Timeout => RealityBackendDiagnosis {
                address: result.address,
                check: check("fail", "TCP connection timed out"),
                elapsed_ms: None,
            },
            TargetProbeOutcome::NotTested { reason } => RealityBackendDiagnosis {
                address: result.address,
                check: check("not_tested", reason),
                elapsed_ms: None,
            },
        })
        .collect()
}

async fn probe_local_camouflage(domain: &str, port: u16) -> Result<u16, String> {
    let socket: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|_| "invalid local camouflage address".to_string())?;
    let client = reqwest::Client::builder()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        .resolve(domain, socket)
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(format!("https://{domain}:{port}/"))
        .header("Host", domain)
        .send()
        .await
        .map_err(|error| format!("local HTTPS probe failed: {error}"))?;
    Ok(response.status().as_u16())
}

fn certificate_and_camouflage(
    manager: &CamouflageSiteManager,
    sni: Option<&str>,
    desired: Option<&relay_shared::protocol::CamouflageSiteDesired>,
) -> (RealityCertificateDiagnosis, RealityCamouflageDiagnosis) {
    let status = manager
        .status_snapshot()
        .into_iter()
        .find(|status| status.sni.eq_ignore_ascii_case(sni.unwrap_or_default()))
        .unwrap_or_else(|| relay_shared::protocol::CamouflageSiteStatus {
            site_id: sni.unwrap_or_default().into(),
            sni: sni.unwrap_or_default().into(),
            site_status: "unknown".into(),
            certificate_status: "pending".into(),
            issuer: None,
            valid_from: None,
            valid_until: None,
            last_success: None,
            last_attempt: None,
            last_error: Some("no active camouflage site status".into()),
            active_generation: None,
        });
    let site = manager.active_site_for_sni(sni.unwrap_or_default());
    let (
        cert_path,
        key_path,
        san_match,
        cert_key_match,
        issuer,
        valid_until,
        remaining_days,
        cert_error,
    ) = inspect_certificate(site.as_ref(), sni.unwrap_or_default());
    let cert_ok = matches!(
        status.certificate_status.as_str(),
        "active" | "renewal_warning"
    ) && san_match
        && cert_key_match
        && cert_error.is_none();
    let renewal = renewal_diagnosis(&status);
    let certificate = RealityCertificateDiagnosis {
        check: if cert_ok {
            check("pass", "certificate is usable")
        } else {
            check(
                "fail",
                cert_error.unwrap_or_else(|| "certificate is not currently usable".into()),
            )
        },
        renewal,
        certificate_status: status.certificate_status.clone(),
        certificate_domain: desired.map(|site| site.certificate.domain.clone()),
        cert_path,
        key_path,
        san_match,
        cert_key_match,
        issuer: issuer.or(status.issuer.clone()),
        valid_until: valid_until.or(status.valid_until.clone()),
        remaining_days,
        tls_handshake: check(
            "not_tested",
            "TLS handshake probe is not performed without client credentials",
        ),
    };
    let camouflage_ok = status.site_status == "active";
    let camouflage = RealityCamouflageDiagnosis {
        check: if camouflage_ok {
            check("pass", "camouflage site is active")
        } else {
            check("fail", "camouflage site is not active")
        },
        site_status: status.site_status,
        tls_listener_port: desired.map(|site| site.tls_listener_port).unwrap_or(8443),
        local_backend: site
            .as_ref()
            .map(|site| site.local_backend.clone())
            .unwrap_or_else(|| "unknown".into()),
        http_status: None,
    };
    (certificate, camouflage)
}

fn renewal_diagnosis(status: &relay_shared::protocol::CamouflageSiteStatus) -> RealityCheck {
    match status.certificate_status.as_str() {
        "active" | "renewal_warning" => match status.last_error.as_deref() {
            Some(error) => check("warning", error),
            None => check("pass", "no renewal warning reported"),
        },
        "failed" | "failed_retrying" => check(
            "fail",
            status
                .last_error
                .as_deref()
                .unwrap_or("certificate issuance or renewal failed"),
        ),
        _ => check("not_tested", "certificate issuance has not completed"),
    }
}

#[allow(clippy::type_complexity)] // 返回项直接映射公开 diagnosis 字段，避免 lint 改动 wire 类型。
fn inspect_certificate(
    site: Option<&CamouflageSite>,
    domain: &str,
) -> (
    Option<String>,
    Option<String>,
    bool,
    bool,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
) {
    let Some(site) = site else {
        return (
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            Some("certificate reference is unavailable".into()),
        );
    };
    let cert_path = site.certificate.cert_path.display().to_string();
    let key_path = site.certificate.key_path.display().to_string();
    let key_match = openssl_key_matches(&cert_path, &key_path);
    let inspected = fs::read(&site.certificate.cert_path).ok().and_then(|bytes| {
        let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes).ok()?;
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&pem.contents).ok()?;
        let san_match = cert.subject_alternative_name().ok().flatten().is_some_and(|san| {
            san.value.general_names.iter().any(|name| {
                matches!(
                    name,
                    x509_parser::extensions::GeneralName::DNSName(value)
                        if relay_shared::reconciliation::certificate_domain_covers_sni(value, domain)
                )
            })
        });
        let issuer = cert.issuer().to_string();
        let valid_until = cert.validity().not_after.to_rfc2822().ok();
        let remaining_days = (cert.validity().not_after.timestamp()
            - chrono::Utc::now().timestamp())
            / 86_400;
        let now = chrono::Utc::now().timestamp();
        let currently_valid = cert.validity().not_before.timestamp() <= now
            && cert.validity().not_after.timestamp() > now;
        Some((san_match, issuer, valid_until, remaining_days, currently_valid))
    });
    let Some((san_match, issuer, valid_until, remaining_days, currently_valid)) = inspected else {
        return (
            Some(cert_path),
            Some(key_path),
            false,
            key_match,
            None,
            None,
            None,
            Some("invalid certificate".into()),
        );
    };
    let error = if !currently_valid {
        Some("certificate is expired or not yet valid".into())
    } else if !san_match {
        Some("certificate SAN does not match SNI".into())
    } else if !key_match {
        Some("certificate and private key do not match".into())
    } else {
        None
    };
    (
        Some(cert_path),
        Some(key_path),
        san_match,
        key_match,
        Some(issuer),
        valid_until,
        Some(remaining_days),
        error,
    )
}

fn openssl_key_matches(cert_path: &str, key_path: &str) -> bool {
    let cert = Command::new("openssl")
        .args(["x509", "-in", cert_path, "-pubkey", "-noout"])
        .output();
    let key = Command::new("openssl")
        .args(["pkey", "-in", key_path, "-pubout"])
        .output();
    match (cert, key) {
        (Ok(cert), Ok(key)) if cert.status.success() && key.status.success() => {
            normalize_pem(&cert.stdout) == normalize_pem(&key.stdout)
        }
        _ => false,
    }
}

fn normalize_pem(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

/// Probe each target with a TCP connect (3s deadline). Concurrency capped at
/// MAX_CONCURRENT_PROBES via a semaphore. Input is capped at MAX_TARGETS
/// (defensive — callers should already cap, but this guarantees the contract
/// regardless). v0.4.9: TCP-only; the old UDP route-only branch is gone.
async fn probe_targets(targets: &[String]) -> Vec<DiagnoseTargetResult> {
    let targets_capped: Vec<&String> = targets.iter().take(MAX_TARGETS).collect();
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut handles = Vec::with_capacity(targets_capped.len());
    for addr in targets_capped {
        let addr = addr.clone();
        let permit = sem.clone();
        handles.push(tokio::spawn(async move {
            let _p = permit.acquire_owned().await.unwrap();
            probe_target(&addr).await
        }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(r) => out.push(r),
            Err(e) => tracing::warn!("diagnose probe task panicked: {}", e),
        }
    }
    out
}

fn split_target(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse().ok()?;
        return (!host.is_empty() && port > 0).then(|| (host.to_string(), port));
    }
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse().ok()?;
    (!host.is_empty() && port > 0).then(|| (host.to_string(), port))
}

fn connect_error_kind(error: &std::io::Error) -> TargetProbeErrorKind {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => TargetProbeErrorKind::ConnectionRefused,
        std::io::ErrorKind::TimedOut => TargetProbeErrorKind::Timeout,
        std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
            TargetProbeErrorKind::NetworkUnreachable
        }
        _ => TargetProbeErrorKind::Other,
    }
}

async fn probe_target(address: &str) -> DiagnoseTargetResult {
    let Some((host, port)) = split_target(address) else {
        return DiagnoseTargetResult {
            address: address.into(),
            hostname: None,
            resolved_ip: None,
            actual_address: None,
            port: 0,
            protocol: "tcp".into(),
            error_kind: Some(TargetProbeErrorKind::InvalidTarget),
            outcome: TargetProbeOutcome::Failed {
                error: "invalid target address".into(),
            },
        };
    };
    let parsed_ip = host.parse::<std::net::IpAddr>().ok();
    let hostname = parsed_ip.is_none().then(|| host.clone());
    let resolved = if let Some(ip) = parsed_ip {
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        match tokio::time::timeout(
            PROBE_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses.collect::<Vec<_>>(),
            Ok(Err(error)) => {
                return DiagnoseTargetResult {
                    address: address.into(),
                    hostname,
                    resolved_ip: None,
                    actual_address: None,
                    port,
                    protocol: "tcp".into(),
                    error_kind: Some(TargetProbeErrorKind::DnsResolveFailed),
                    outcome: TargetProbeOutcome::Failed {
                        error: format!("resolve: {error}"),
                    },
                }
            }
            Err(_) => {
                return DiagnoseTargetResult {
                    address: address.into(),
                    hostname,
                    resolved_ip: None,
                    actual_address: None,
                    port,
                    protocol: "tcp".into(),
                    error_kind: Some(TargetProbeErrorKind::DnsResolveFailed),
                    outcome: TargetProbeOutcome::Failed {
                        error: "DNS resolution timed out".into(),
                    },
                }
            }
        }
    };
    if resolved.is_empty() {
        return DiagnoseTargetResult {
            address: address.into(),
            hostname,
            resolved_ip: None,
            actual_address: None,
            port,
            protocol: "tcp".into(),
            error_kind: Some(TargetProbeErrorKind::DnsResolveFailed),
            outcome: TargetProbeOutcome::Failed {
                error: "DNS returned no addresses".into(),
            },
        };
    }
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let mut last_error = None;
    let mut last_address = resolved[0];
    for socket in resolved {
        last_address = socket;
        match tokio::time::timeout_at(deadline, TcpStream::connect(socket)).await {
            Ok(Ok(_)) => {
                return DiagnoseTargetResult {
                    address: address.into(),
                    hostname,
                    resolved_ip: Some(socket.ip().to_string()),
                    actual_address: Some(socket.to_string()),
                    port,
                    protocol: "tcp".into(),
                    error_kind: None,
                    outcome: TargetProbeOutcome::Reachable {
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                }
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                return DiagnoseTargetResult {
                    address: address.into(),
                    hostname,
                    resolved_ip: Some(socket.ip().to_string()),
                    actual_address: Some(socket.to_string()),
                    port,
                    protocol: "tcp".into(),
                    error_kind: Some(TargetProbeErrorKind::Timeout),
                    outcome: TargetProbeOutcome::Timeout,
                }
            }
        }
    }
    let error = last_error.expect("non-empty resolved targets produced an error");
    DiagnoseTargetResult {
        address: address.into(),
        hostname,
        resolved_ip: Some(last_address.ip().to_string()),
        actual_address: Some(last_address.to_string()),
        port,
        protocol: "tcp".into(),
        error_kind: Some(connect_error_kind(&error)),
        outcome: TargetProbeOutcome::Failed {
            error: format!("connect: {error}"),
        },
    }
}

/// Test-only direct socket helper. Production probes resolve on the Relay and
/// report the actual connected address through `probe_target`.
#[cfg(test)]
async fn probe_tcp(addr: &str) -> TargetProbeOutcome {
    let start = std::time::Instant::now();
    match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => TargetProbeOutcome::Reachable {
            elapsed_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(e)) => TargetProbeOutcome::Failed {
            error: format!("connect: {e}"),
        },
        Err(_) => TargetProbeOutcome::Timeout,
    }
}

/// POST the result to the panel (same channel/auth as report_status).
async fn report(config: &NodeConfig, result: DiagnoseResult) -> Result<(), String> {
    let url = format!("{}/api/v1/node/diagnose_result", config.panel_url);
    let client = reqwest::Client::new();
    let resp = config
        .auth
        .apply_reqwest(client.post(&url))
        .header("X-Node-ID", &result.node_id)
        .json(&result)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarder::camouflage_site::{
        CamouflageSiteConfig, CamouflageSitesManifest, CertificateReference, OPENLIST_BACKEND,
        XIAOYA_BACKEND,
    };
    use crate::forwarder::certificate_lifecycle::CertificateLifecycleConfig;
    use crate::forwarder::nginx_sni::NginxSniConfig;
    use relay_shared::protocol::{
        AcmeChallengeMethod, CamouflageCertificatePolicy, CamouflageLocalBackend,
        CamouflageSiteDesired, ListenerConfig, LoadBalanceStrategy, NodeTransport, Protocol,
    };
    use std::os::unix::fs::PermissionsExt;

    fn diagnosis_test_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "relay-node-diagnosis-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn diagnosis_certificate(
        dir: &std::path::Path,
        name: &str,
        san: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> CertificateReference {
        use rcgen::{CertificateParams, KeyPair};
        std::fs::create_dir_all(dir).unwrap();
        let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        CertificateReference {
            cert_path,
            key_path,
            lifecycle: None,
        }
    }

    fn diagnosis_manager(
        dir: &std::path::Path,
        certificate: CertificateReference,
    ) -> (CamouflageSiteManager, CamouflageSiteDesired) {
        let mut manager = CamouflageSiteManager::new(CamouflageSiteConfig {
            enabled: false,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("state"),
            nginx: NginxSniConfig {
                enabled: false,
                conf_path: dir.join("camouflage.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("camouflage.log").display().to_string(),
            },
            certificate_lifecycle: CertificateLifecycleConfig::disabled_for_test(dir),
        });
        assert!(manager.apply_candidate(CamouflageSitesManifest {
            sites: vec![CamouflageSite {
                id: "q1".into(),
                sni: "q1.example.com".into(),
                tls_listener_port: 8443,
                local_backend: OPENLIST_BACKEND.into(),
                certificate,
            }],
        }));
        let desired = CamouflageSiteDesired {
            site_id: "q1".into(),
            sni: "q1.example.com".into(),
            tls_listener_port: 8443,
            local_backend: CamouflageLocalBackend::OpenList,
            certificate: CamouflageCertificatePolicy {
                domain: "q1.example.com".into(),
                expected_public_ip: "192.0.2.10".into(),
                renew_before_days: 30,
                challenge_method: AcmeChallengeMethod::Dns01,
            },
            enabled: true,
        };
        manager.prepare_desired(std::slice::from_ref(&desired), true);
        manager.record_renewal_warning_for_test("q1", "renewal failed");
        (manager, desired)
    }

    #[test]
    fn target_probe_outcome_serializes_snake_case() {
        // The enum must serialize to the wire vocab the panel/frontend expect.
        // v0.4.9: RouteOnly is gone; only reachable/failed/timeout remain.
        let r = serde_json::to_string(&TargetProbeOutcome::Timeout).unwrap();
        assert_eq!(r, "\"timeout\"");
        let r = serde_json::to_string(&TargetProbeOutcome::Reachable { elapsed_ms: 12 }).unwrap();
        assert!(r.contains("reachable"));
        assert!(r.contains("12"));
        let r = serde_json::to_string(&TargetProbeOutcome::Failed { error: "x".into() }).unwrap();
        assert!(r.contains("failed"));
        let r = serde_json::to_string(&TargetProbeOutcome::NotTested {
            reason: "UDP cannot be confirmed".into(),
        })
        .unwrap();
        assert!(r.contains("not_tested"));
    }

    #[tokio::test]
    async fn probe_tcp_unreachable_returns_failed() {
        // 127.0.0.1:1 is almost never listening → connection refused.
        let o = probe_tcp("127.0.0.1:1").await;
        match o {
            TargetProbeOutcome::Failed { .. } | TargetProbeOutcome::Timeout => {}
            TargetProbeOutcome::Reachable { .. } | TargetProbeOutcome::NotTested { .. } => {
                panic!("port 1 should not be reachable")
            }
        }
    }

    #[tokio::test]
    async fn probe_tcp_to_listener_succeeds() {
        // Bind a throwaway listener, probe its address, expect Reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let o = probe_tcp(&addr).await;
        assert!(
            matches!(o, TargetProbeOutcome::Reachable { .. }),
            "local listener should be reachable: {:?}",
            o
        );
    }

    #[tokio::test]
    async fn hostname_is_resolved_by_the_relay_and_actual_socket_is_reported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = probe_target(&format!("localhost:{port}")).await;
        assert_eq!(result.hostname.as_deref(), Some("localhost"));
        assert_eq!(result.port, port);
        assert_eq!(result.protocol, "tcp");
        assert!(result.resolved_ip.is_some());
        assert!(result.actual_address.is_some());
        assert!(matches!(
            result.outcome,
            TargetProbeOutcome::Reachable { .. }
        ));
    }

    #[tokio::test]
    async fn refused_target_returns_a_machine_readable_reason() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let result = probe_target(&address.to_string()).await;
        assert_eq!(result.hostname, None);
        assert_eq!(
            result.actual_address.as_deref(),
            Some(address.to_string().as_str())
        );
        assert_eq!(
            result.error_kind,
            Some(TargetProbeErrorKind::ConnectionRefused)
        );
    }

    #[tokio::test]
    async fn probe_targets_caps_concurrency_and_count() {
        // 50 dummy targets; must return at most MAX_TARGETS (32) results. We
        // don't assert outcomes — port availability is environment-dependent —
        // only the cap and that it returns without hanging.
        let addrs: Vec<String> = (0..50).map(|i| format!("127.0.0.1:{}", 1000 + i)).collect();
        let out = probe_targets(&addrs).await;
        assert!(
            out.len() <= MAX_TARGETS,
            "must cap at MAX_TARGETS, got {}",
            out.len()
        );
        assert!(!out.is_empty(), "should return some results");
    }

    #[test]
    fn renewal_warning_does_not_make_active_certificate_unusable() {
        let status = relay_shared::protocol::CamouflageSiteStatus {
            site_id: "op1".into(),
            sni: "op1.example.com".into(),
            site_status: "active".into(),
            certificate_status: "renewal_warning".into(),
            issuer: None,
            valid_from: None,
            valid_until: None,
            last_success: None,
            last_attempt: Some("2026-08-28T00:00:00Z".into()),
            last_error: Some("renewal failed; will retry".into()),
            active_generation: None,
        };
        let renewal = renewal_diagnosis(&status);
        assert_eq!(renewal.state, "warning");
        assert_eq!(
            renewal.detail.as_deref(),
            Some("renewal failed; will retry")
        );
    }

    #[test]
    fn renewal_warning_diagnosis_rejects_invalid_certificate_counterexamples() {
        use time::{Duration as TimeDuration, OffsetDateTime};

        let dir = diagnosis_test_dir("renewal-warning-strict");
        let now = OffsetDateTime::now_utc();
        let valid = diagnosis_certificate(
            &dir,
            "valid",
            "q1.example.com",
            now - TimeDuration::days(1),
            now + TimeDuration::days(90),
        );
        let mut key_mismatch = diagnosis_certificate(
            &dir,
            "key-mismatch",
            "q1.example.com",
            now - TimeDuration::days(1),
            now + TimeDuration::days(90),
        );
        key_mismatch.key_path = valid.key_path;
        let cases = vec![
            diagnosis_certificate(
                &dir,
                "expired",
                "q1.example.com",
                now - TimeDuration::days(10),
                now - TimeDuration::days(1),
            ),
            diagnosis_certificate(
                &dir,
                "san-mismatch",
                "other.example.com",
                now - TimeDuration::days(1),
                now + TimeDuration::days(90),
            ),
            key_mismatch,
            diagnosis_certificate(
                &dir,
                "not-yet-valid",
                "q1.example.com",
                now + TimeDuration::days(1),
                now + TimeDuration::days(90),
            ),
        ];

        for certificate in cases {
            let case_dir = diagnosis_test_dir("renewal-warning-case");
            let (manager, desired) = diagnosis_manager(&case_dir, certificate);
            assert_eq!(
                manager.status_snapshot()[0].certificate_status,
                "renewal_warning"
            );
            let (certificate, _) =
                certificate_and_camouflage(&manager, Some("q1.example.com"), Some(&desired));
            assert_eq!(certificate.check.state, "fail");
            assert_eq!(
                certificate.certificate_domain.as_deref(),
                Some("q1.example.com")
            );
            std::fs::remove_dir_all(case_dir).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn diagnosis_san_matching_uses_shared_wildcard_semantics() {
        use time::{Duration as TimeDuration, OffsetDateTime};

        let dir = diagnosis_test_dir("san-matching");
        let now = OffsetDateTime::now_utc();
        let cases = [
            ("wildcard", "*.example.com", "q1.example.com", true),
            ("exact", "q1.example.com", "q1.example.com", true),
            ("apex", "*.example.com", "example.com", false),
            (
                "multiple-labels",
                "*.example.com",
                "deep.q1.example.com",
                false,
            ),
            ("wrong-domain", "*.example.net", "q1.example.com", false),
        ];

        for (name, san, sni, expected) in cases {
            let certificate = diagnosis_certificate(
                &dir,
                name,
                san,
                now - TimeDuration::days(1),
                now + TimeDuration::days(90),
            );
            let site = CamouflageSite {
                id: name.into(),
                sni: sni.into(),
                tls_listener_port: 8443,
                local_backend: OPENLIST_BACKEND.into(),
                certificate,
            };
            let (_, _, san_match, key_match, _, _, _, error) =
                inspect_certificate(Some(&site), sni);
            assert_eq!(san_match, expected, "SAN {san} against SNI {sni}");
            assert!(key_match, "generated certificate and key must match");
            assert_eq!(error.is_none(), expected, "SAN {san} against SNI {sni}");
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn diagnosis_reports_the_actual_active_camouflage_backend() {
        use time::{Duration as TimeDuration, OffsetDateTime};

        let dir = diagnosis_test_dir("active-backend");
        let certificate = diagnosis_certificate(
            &dir,
            "xiaoya",
            "q1.example.com",
            OffsetDateTime::now_utc() - TimeDuration::days(1),
            OffsetDateTime::now_utc() + TimeDuration::days(90),
        );
        let (mut manager, desired) = diagnosis_manager(&dir, certificate);
        let mut site = manager.active_site_for_sni("q1.example.com").unwrap();
        site.local_backend = XIAOYA_BACKEND.into();
        assert!(manager.apply_candidate(CamouflageSitesManifest { sites: vec![site] }));

        let (_, camouflage) =
            certificate_and_camouflage(&manager, Some("q1.example.com"), Some(&desired));
        assert_eq!(camouflage.local_backend, XIAOYA_BACKEND);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fallback_probe_is_not_conflated_with_vless_client_authentication() {
        let fallback = fallback_diagnosis();
        assert_eq!(fallback.check.state, "not_tested");
        assert_eq!(fallback.http_status, None);
        assert!(!fallback.authenticated_reality_path);
        let detail = fallback.check.detail.as_deref().unwrap();
        assert!(detail.contains(":443 -> remote Reality -> :8443"));
        assert!(!detail.contains("credential"));
    }

    #[test]
    fn nginx_sni_mapping_compares_configured_identity_not_resolved_runtime_targets() {
        let listener = ListenerConfig {
            rule_id: 1,
            port: 443,
            protocol: Protocol::Tcp,
            node_transport: NodeTransport::NginxSni,
            ws_path: None,
            sni: Some("Host.Example".into()),
            camouflage_required: false,
            send_proxy_protocol: true,
            targets: vec!["host.example:20209".into()],
            load_balance_strategy: LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
        };
        let plan_rule = crate::forwarder::nginx_sni::NginxSniRule {
            rule_id: 1,
            listen_port: 443,
            sni: "host.example".into(),
            configured_targets: vec!["host.example:20209".into()],
            targets: vec!["1.2.3.4:20209".into()],
            load_balance_strategy: LoadBalanceStrategy::First,
            send_proxy_protocol: true,
        };

        assert!(nginx_sni_mapping_matches(
            &plan_rule,
            &listener,
            listener.sni.as_deref()
        ));

        let mut changed = plan_rule.clone();
        changed.targets = vec!["5.6.7.8:20209".into()];
        assert!(
            nginx_sni_mapping_matches(&changed, &listener, listener.sni.as_deref()),
            "runtime DNS refresh must not change configured identity"
        );

        changed.configured_targets = vec!["host-b.example:20209".into()];
        assert!(!nginx_sni_mapping_matches(
            &changed,
            &listener,
            listener.sni.as_deref()
        ));

        let mut changed = plan_rule.clone();
        changed.listen_port = 8443;
        assert!(!nginx_sni_mapping_matches(
            &changed,
            &listener,
            listener.sni.as_deref()
        ));

        let mut changed = plan_rule.clone();
        changed.sni = "other.example".into();
        assert!(!nginx_sni_mapping_matches(
            &changed,
            &listener,
            listener.sni.as_deref()
        ));

        let mut changed = plan_rule;
        changed.send_proxy_protocol = false;
        assert!(!nginx_sni_mapping_matches(
            &changed,
            &listener,
            listener.sni.as_deref()
        ));
    }
}
