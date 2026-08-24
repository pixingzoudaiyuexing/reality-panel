use serde::Deserialize;
use std::path::PathBuf;

const INSECURE_NODE_TOKEN: &str = "default-token";

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub panel_url: String,
    pub token: String,
    pub poll_interval: u64,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    /// v0.4.6: NIC for traffic stats. "auto" = auto-detect default route.
    pub network_interface: String,
    /// v1.0.4: IPv4 listen address. Empty = disabled. Default "0.0.0.0".
    pub listen_ipv4: String,
    /// v1.0.4: IPv6 listen address. Empty = disabled. Default "::".
    pub listen_ipv6: String,
    /// v1.0.4: NIC for outbound IPv4 egress. "auto" = system routing.
    pub outbound_interface: String,
    /// v1.0.4: Exact IPv4 source for outbound connections.
    pub outbound_bind_ipv4: Option<String>,
    /// Reality/SNI fork: generate and reload an Nginx Stream ssl_preread router.
    pub nginx_sni_enabled: bool,
    pub nginx_sni_conf_path: String,
    pub nginx_sni_test_cmd: String,
    pub nginx_sni_reload_cmd: String,
    pub nginx_sni_default_backend: String,
    pub nginx_sni_access_log_path: String,
    pub nginx_sni_traffic_state_path: String,
    /// Stage 3.1: Node-local REALITY site manifest and fixed Xray runtime.
    /// No Panel protocol field carries site secrets.
    pub reality_sites_enabled: bool,
    pub reality_sites_manifest_path: String,
    pub reality_sites_state_dir: String,
    pub xray_binary_path: String,
    pub xray_expected_version: String,
    pub reality_wrapper_conf_path: String,
}

impl NodeConfig {
    pub fn load() -> Self {
        let panel_url =
            std::env::var("PANEL_URL").unwrap_or_else(|_| "http://127.0.0.1:18888".into());
        let token = std::env::var("NODE_TOKEN").unwrap_or_else(|_| String::new());
        let poll_interval = std::env::var("POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let cfg = Self {
            panel_url,
            token,
            poll_interval,
            tls_cert_path: std::env::var("TLS_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            tls_key_path: std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty()),
            network_interface: std::env::var("NETWORK_INTERFACE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "auto".to_string()),
            // v1.0.4: distinguish UNSET (use default, backward compatible) from
            // EXPLICITLY EMPTY (LISTEN_IPV6= → disable that family). std::env::var
            // returns Err only when unset; Ok("") when set to empty.
            listen_ipv4: match std::env::var("LISTEN_IPV4") {
                Ok(v) => v.trim().to_string(),
                Err(_) => "0.0.0.0".to_string(),
            },
            listen_ipv6: match std::env::var("LISTEN_IPV6") {
                Ok(v) => v.trim().to_string(),
                Err(_) => "::".to_string(),
            },
            outbound_interface: std::env::var("OUTBOUND_INTERFACE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "auto".to_string()),
            outbound_bind_ipv4: std::env::var("OUTBOUND_BIND_IPV4")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            nginx_sni_enabled: parse_bool_env("NGINX_SNI_ENABLED", false),
            nginx_sni_conf_path: std::env::var("NGINX_SNI_CONF_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/etc/nginx/stream.d/relay-panel-sni.conf".to_string()),
            nginx_sni_test_cmd: std::env::var("NGINX_SNI_TEST_CMD")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "nginx -t".to_string()),
            nginx_sni_reload_cmd: std::env::var("NGINX_SNI_RELOAD_CMD")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "systemctl reload nginx".to_string()),
            nginx_sni_default_backend: std::env::var("NGINX_SNI_DEFAULT_BACKEND")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:9".to_string()),
            nginx_sni_access_log_path: std::env::var("NGINX_SNI_ACCESS_LOG_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/var/log/nginx/sni-router.log".to_string()),
            nginx_sni_traffic_state_path: std::env::var("NGINX_SNI_TRAFFIC_STATE_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/nginx-sni-log.offset".to_string()),
            reality_sites_enabled: parse_bool_env("REALITY_SITES_ENABLED", false),
            reality_sites_manifest_path: std::env::var("REALITY_SITES_MANIFEST_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/etc/relay-panel/reality-sites.json".to_string()),
            reality_sites_state_dir: std::env::var("REALITY_SITES_STATE_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/reality-sites".to_string()),
            xray_binary_path: std::env::var("XRAY_BINARY_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/xray".to_string()),
            xray_expected_version: crate::forwarder::reality_site::FIXED_XRAY_VERSION.to_string(),
            reality_wrapper_conf_path: std::env::var("REALITY_WRAPPER_CONF_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/etc/nginx/conf.d/relay-panel-reality-sites.conf".to_string()),
        };
        cfg.validate();
        cfg
    }

    pub fn nginx_sni_config(&self) -> crate::forwarder::nginx_sni::NginxSniConfig {
        crate::forwarder::nginx_sni::NginxSniConfig {
            enabled: self.nginx_sni_enabled,
            conf_path: PathBuf::from(&self.nginx_sni_conf_path),
            test_cmd: self.nginx_sni_test_cmd.clone(),
            reload_cmd: self.nginx_sni_reload_cmd.clone(),
            default_backend: self.nginx_sni_default_backend.clone(),
            access_log_path: self.nginx_sni_access_log_path.clone(),
        }
    }

    pub fn reality_site_config(&self) -> crate::forwarder::reality_site::RealitySiteConfig {
        crate::forwarder::reality_site::RealitySiteConfig {
            enabled: self.reality_sites_enabled,
            manifest_path: PathBuf::from(&self.reality_sites_manifest_path),
            state_dir: PathBuf::from(&self.reality_sites_state_dir),
            xray_binary: PathBuf::from(&self.xray_binary_path),
            expected_xray_version: self.xray_expected_version.clone(),
            nginx: crate::forwarder::nginx_sni::NginxSniConfig {
                enabled: self.nginx_sni_enabled,
                conf_path: PathBuf::from(&self.reality_wrapper_conf_path),
                test_cmd: self.nginx_sni_test_cmd.clone(),
                reload_cmd: self.nginx_sni_reload_cmd.clone(),
                default_backend: self.nginx_sni_default_backend.clone(),
                access_log_path: self.nginx_sni_access_log_path.clone(),
            },
            openlist_upstream: "127.0.0.1:5244".to_string(),
        }
    }

    fn validate(&self) {
        if self.token.trim().is_empty() {
            eprintln!(
                "FATAL: NODE_TOKEN is not set.\n  \
                 Set it to a real inbound-group token from the panel UI, e.g.:\n  \
                 NODE_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            );
            std::process::exit(1);
        }
        if self.token == INSECURE_NODE_TOKEN {
            eprintln!(
                "FATAL: NODE_TOKEN is still set to the insecure default \"{}\".\n  \
                 Set it to a real inbound-group token from the panel UI.",
                INSECURE_NODE_TOKEN
            );
            std::process::exit(1);
        }
    }
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
