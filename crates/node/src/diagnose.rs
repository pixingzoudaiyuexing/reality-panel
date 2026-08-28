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
use relay_shared::protocol::{
    DiagnoseResult, DiagnoseTargetResult, RealityBackendDiagnosis, RealityCamouflageDiagnosis,
    RealityCertificateDiagnosis, RealityCheck, RealityConfigDiagnosis, RealityDiagnosis,
    RealityFallbackDiagnosis, RealityNginxDiagnosis, RealityRuntimeDiagnosis, TargetProbeOutcome,
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
pub async fn run_and_report(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    config: &NodeConfig,
    node_id: &str,
    request_id: String,
    rule_id: i64,
    challenge: String,
) {
    let result = diagnose(manager, camouflage, &request_id, rule_id, challenge).await;
    let mut result = result;
    result.node_id = node_id.to_string();
    if let Err(e) = report(config, result).await {
        tracing::warn!("diagnose {}: failed to report result: {}", request_id, e);
    }
}

/// Build the DiagnoseResult for a rule (probe targets, capture listener state).
async fn diagnose(
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    request_id: &str,
    rule_id: i64,
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
        (manager.listener_info_for_rule_tcp(rule_id), reality)
    };
    let reality = if let Some((config, listener)) = reality {
        let camouflage = camouflage.lock().await;
        let manager = manager.lock().await;
        let mut diagnosis =
            build_reality_diagnosis(&manager, config.as_ref(), &listener, &camouflage);
        drop(camouflage);
        diagnosis.backends = reality_backend_results(&listener.targets).await;
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
    let targets_to_probe: Vec<String> = targets.into_iter().take(MAX_TARGETS).collect();
    let results = probe_targets(&targets_to_probe).await;

    DiagnoseResult {
        msg_type: "diagnose_result".into(),
        request_id: request_id.to_string(),
        rule_id,
        node_id: String::new(), // filled by caller
        // Echoed back verbatim; the panel rejects the result without an exact
        // match (v0.4.9 secure-diagnose challenge).
        challenge,
        listener_running,
        listen_port,
        protocol,
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

fn build_reality_diagnosis(
    manager: &ForwarderManager,
    config: Option<&relay_shared::protocol::NodeConfigResponse>,
    listener: &relay_shared::protocol::ListenerConfig,
    camouflage: &CamouflageSiteManager,
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
    let mapping_matches = plan_rule.as_ref().is_some_and(|rule| {
        rule.listen_port == listener.port
            && sni
                .as_deref()
                .is_some_and(|value| rule.sni == value.trim().to_ascii_lowercase())
            && rule.targets == listener.targets
            && rule.send_proxy_protocol == listener.send_proxy_protocol
    });
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
        fallback: RealityFallbackDiagnosis {
            check: check(
                "not_tested",
                "requires a VLESS client credential and does not run from relay-node",
            ),
            http_status: None,
            authenticated_reality_path: false,
        },
        vless_authentication: check(
            "not_tested",
            "relay-node does not possess client UUID or Reality credentials",
        ),
    }
}

async fn reality_backend_results(targets: &[String]) -> Vec<RealityBackendDiagnosis> {
    probe_targets(targets)
        .await
        .into_iter()
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
    let cert_ok = status.certificate_status == "active"
        && san_match
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
        local_backend: "127.0.0.1:5244".into(),
        http_status: None,
    };
    (certificate, camouflage)
}

fn renewal_diagnosis(status: &relay_shared::protocol::CamouflageSiteStatus) -> RealityCheck {
    match status.certificate_status.as_str() {
        "active" => match status.last_error.as_deref() {
            Some(error) => check("warning", error),
            None => check("pass", "no renewal warning reported"),
        },
        "failed" => check(
            "fail",
            status
                .last_error
                .as_deref()
                .unwrap_or("certificate issuance or renewal failed"),
        ),
        _ => check("not_tested", "certificate issuance has not completed"),
    }
}

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
                matches!(name, x509_parser::extensions::GeneralName::DNSName(value) if *value == domain)
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
            let outcome = probe_tcp(&addr).await;
            DiagnoseTargetResult {
                address: addr,
                outcome,
            }
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

/// TCP reachability: connect with a 3s deadline. Success → close immediately.
/// Recorded time is the connect latency.
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
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.token))
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
    }

    #[tokio::test]
    async fn probe_tcp_unreachable_returns_failed() {
        // 127.0.0.1:1 is almost never listening → connection refused.
        let o = probe_tcp("127.0.0.1:1").await;
        match o {
            TargetProbeOutcome::Failed { .. } | TargetProbeOutcome::Timeout => {}
            TargetProbeOutcome::Reachable { .. } => {
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
    async fn probe_targets_caps_concurrency_and_count() {
        // 50 dummy targets; must return at most MAX_TARGETS (32) results. We
        // don't assert outcomes — port availability is environment-dependent —
        // only the cap and that it returns without hanging. v0.4.9: TCP-only,
        // no is_udp flag.
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
            certificate_status: "active".into(),
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
}
