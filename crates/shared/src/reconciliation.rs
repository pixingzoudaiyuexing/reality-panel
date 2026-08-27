use crate::protocol::{AcmeChallengeMethod, CamouflageLocalBackend, NodeConfigResponse, Protocol};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// Deterministic SHA-256 over a canonical typed Node configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConfigFingerprint(String);

impl ConfigFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fingerprint opaque runtime evidence without exposing the evidence itself.
/// Runtime inspectors use this for deterministic observed-state reporting;
/// desired configuration fingerprints continue to use `config_fingerprint`.
pub fn fingerprint_bytes(bytes: &[u8]) -> ConfigFingerprint {
    let digest = Sha256::digest(bytes);
    ConfigFingerprint(hex_encode(&digest))
}

impl fmt::Display for ConfigFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Serialize)]
struct CanonicalConfig {
    listeners: Vec<CanonicalListener>,
    camouflage_sites: Vec<CanonicalCamouflageSite>,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalListener {
    rule_id: i64,
    port: u16,
    protocol: &'static str,
    node_transport: &'static str,
    ws_path: Option<String>,
    sni: Option<String>,
    camouflage_required: bool,
    send_proxy_protocol: bool,
    // Target order is intentionally preserved because it affects routing.
    targets: Vec<String>,
    load_balance_strategy: &'static str,
    upload_limit_bps: Option<u64>,
    download_limit_bps: Option<u64>,
    max_connections: Option<u32>,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalCamouflageSite {
    site_id: String,
    sni: String,
    tls_listener_port: u16,
    local_backend: &'static str,
    certificate_domain: String,
    expected_public_ip: String,
    renew_before_days: u32,
    challenge_method: &'static str,
    enabled: bool,
}

/// Top-level entries are treated as sets with deterministic ordering. Ordering
/// inside a listener, especially `targets`, remains behaviorally significant.
pub fn config_fingerprint(config: &NodeConfigResponse) -> ConfigFingerprint {
    let mut listeners: Vec<_> = config
        .listeners
        .iter()
        .map(|listener| CanonicalListener {
            rule_id: listener.rule_id,
            port: listener.port,
            protocol: protocol_name(listener.protocol),
            node_transport: listener.node_transport.to_db_str(),
            ws_path: listener.ws_path.clone(),
            sni: listener.sni.clone(),
            camouflage_required: listener.camouflage_required,
            send_proxy_protocol: listener.send_proxy_protocol,
            targets: listener.targets.clone(),
            load_balance_strategy: listener.load_balance_strategy.to_db_str(),
            upload_limit_bps: listener.upload_limit_bps,
            download_limit_bps: listener.download_limit_bps,
            max_connections: listener.max_connections,
        })
        .collect();
    listeners.sort();

    let mut camouflage_sites: Vec<_> = config
        .camouflage_sites
        .iter()
        .map(|site| CanonicalCamouflageSite {
            site_id: site.site_id.clone(),
            sni: site.sni.clone(),
            tls_listener_port: site.tls_listener_port,
            local_backend: match site.local_backend {
                CamouflageLocalBackend::OpenList => "openlist",
            },
            certificate_domain: site.certificate.domain.clone(),
            expected_public_ip: site.certificate.expected_public_ip.clone(),
            renew_before_days: site.certificate.renew_before_days,
            challenge_method: match site.certificate.challenge_method {
                AcmeChallengeMethod::Http01 => "http01",
                AcmeChallengeMethod::Dns01 => "dns01",
            },
            enabled: site.enabled,
        })
        .collect();
    camouflage_sites.sort();

    let canonical = CanonicalConfig {
        listeners,
        camouflage_sites,
    };
    let encoded = serde_json::to_vec(&canonical).expect("canonical config serialization");
    fingerprint_bytes(&encoded)
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::TcpUdp => "tcp_udp",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        CamouflageCertificatePolicy, CamouflageSiteDesired, ListenerConfig, LoadBalanceStrategy,
        NodeTransport,
    };

    fn listener(rule_id: i64, port: u16, targets: &[&str]) -> ListenerConfig {
        ListenerConfig {
            rule_id,
            port,
            protocol: Protocol::Tcp,
            node_transport: NodeTransport::NginxSni,
            ws_path: None,
            sni: Some(format!("op{rule_id}.example.com")),
            camouflage_required: true,
            send_proxy_protocol: false,
            targets: targets.iter().map(|target| (*target).to_string()).collect(),
            load_balance_strategy: LoadBalanceStrategy::First,
            upload_limit_bps: None,
            download_limit_bps: None,
            max_connections: None,
        }
    }

    fn site(id: &str) -> CamouflageSiteDesired {
        CamouflageSiteDesired {
            site_id: id.to_string(),
            sni: format!("{id}.example.com"),
            tls_listener_port: 8443,
            local_backend: CamouflageLocalBackend::OpenList,
            certificate: CamouflageCertificatePolicy {
                domain: format!("{id}.example.com"),
                expected_public_ip: "192.0.2.10".to_string(),
                renew_before_days: 30,
                challenge_method: Default::default(),
            },
            enabled: true,
        }
    }

    fn config() -> NodeConfigResponse {
        NodeConfigResponse {
            listeners: vec![
                listener(2, 443, &["192.0.2.2:55443"]),
                listener(1, 443, &["192.0.2.1:55443"]),
            ],
            camouflage_sites: vec![site("op2"), site("op1")],
        }
    }

    #[test]
    fn identical_configs_have_identical_fingerprints() {
        let config = config();
        assert_eq!(config_fingerprint(&config), config_fingerprint(&config));
    }

    #[test]
    fn listener_order_does_not_change_fingerprint() {
        let first = config();
        let mut reordered = config();
        reordered.listeners.reverse();
        assert_eq!(config_fingerprint(&first), config_fingerprint(&reordered));
    }

    #[test]
    fn camouflage_order_does_not_change_fingerprint() {
        let first = config();
        let mut reordered = config();
        reordered.camouflage_sites.reverse();
        assert_eq!(config_fingerprint(&first), config_fingerprint(&reordered));
    }

    #[test]
    fn target_order_changes_fingerprint() {
        let mut first = config();
        first.listeners[0].targets = vec!["192.0.2.2:1".into(), "192.0.2.3:1".into()];
        let mut reversed = config();
        reversed.listeners[0].targets = vec!["192.0.2.3:1".into(), "192.0.2.2:1".into()];
        assert_ne!(config_fingerprint(&first), config_fingerprint(&reversed));
    }

    #[test]
    fn meaningful_listener_change_changes_fingerprint() {
        let first = config();
        let mut changed = config();
        changed.listeners[0].max_connections = Some(10);
        assert_ne!(config_fingerprint(&first), config_fingerprint(&changed));
    }

    #[test]
    fn proxy_protocol_change_changes_fingerprint_and_unchanged_state_is_stable() {
        let off = config();
        let mut on = config();
        on.listeners[0].send_proxy_protocol = true;

        assert_ne!(config_fingerprint(&off), config_fingerprint(&on));
        assert_eq!(config_fingerprint(&off), config_fingerprint(&off));
        assert_eq!(config_fingerprint(&on), config_fingerprint(&on));
    }

    #[test]
    fn acme_challenge_method_change_changes_fingerprint() {
        let http01 = config();
        let mut dns01 = config();
        dns01.camouflage_sites[0].certificate.challenge_method = AcmeChallengeMethod::Dns01;

        assert_ne!(config_fingerprint(&http01), config_fingerprint(&dns01));
    }
}
