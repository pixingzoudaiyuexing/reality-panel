use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const INSECURE_NODE_TOKEN: &str = "default-token";
const CREDENTIAL_AUTH_SCHEME: &str = "RelayNodeCredential";
const CREDENTIAL_ID_HEADER: &str = "X-Node-Credential-ID";
const CREDENTIAL_STATE_ROOT: &str = "/var/lib/relay-panel/node-claims";
const CREDENTIAL_SECRET_FILENAME: &str = "node-credential.secret";
const CREDENTIAL_STATE_FILENAME: &str = "credential-pending.json";

#[derive(Clone)]
pub enum NodeRuntimeAuth {
    LegacyGroupToken {
        token: String,
    },
    PermanentCredential {
        credential_id: String,
        secret: String,
        secret_file: PathBuf,
        state_node_id: String,
    },
}

impl std::fmt::Debug for NodeRuntimeAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyGroupToken { .. } => f.write_str("LegacyGroupToken([REDACTED])"),
            Self::PermanentCredential {
                credential_id,
                secret_file,
                state_node_id,
                ..
            } => f
                .debug_struct("PermanentCredential")
                .field("credential_id", credential_id)
                .field("secret", &"[REDACTED]")
                .field("secret_file", secret_file)
                .field("state_node_id", state_node_id)
                .finish(),
        }
    }
}

impl NodeRuntimeAuth {
    pub fn load() -> Result<Self, String> {
        match std::env::var("NODE_AUTH_MODE")
            .unwrap_or_else(|_| "group-token".into())
            .trim()
        {
            "" | "group-token" | "legacy" => {
                let token = std::env::var("NODE_TOKEN").unwrap_or_default();
                if token.trim().is_empty() {
                    return Err("NODE_TOKEN is not set".into());
                }
                if token == INSECURE_NODE_TOKEN {
                    return Err("NODE_TOKEN is still the insecure default".into());
                }
                Ok(Self::LegacyGroupToken { token })
            }
            "credential" => {
                let credential_id = std::env::var("NODE_CREDENTIAL_ID")
                    .map_err(|_| "NODE_CREDENTIAL_ID is required in credential mode")?;
                if !valid_credential_id(&credential_id) {
                    return Err("NODE_CREDENTIAL_ID is invalid".into());
                }
                let secret_file =
                    PathBuf::from(std::env::var("NODE_CREDENTIAL_SECRET_FILE").map_err(|_| {
                        "NODE_CREDENTIAL_SECRET_FILE is required in credential mode"
                    })?);
                let state_file = std::env::var("NODE_CREDENTIAL_STATE_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        secret_file
                            .parent()
                            .unwrap_or_else(|| Path::new("."))
                            .join(CREDENTIAL_STATE_FILENAME)
                    });
                validate_credential_storage_paths(&secret_file, &state_file)?;
                let secret = read_private_credential_secret(&secret_file)?;
                let state = read_private_file(&state_file, "Credential state")?;
                let state: serde_json::Value = serde_json::from_slice(&state)
                    .map_err(|_| "Credential state is malformed".to_string())?;
                let state_credential_id = state
                    .get("credential_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "Credential state has no credential_id".to_string())?;
                let state_node_id = state
                    .get("node_id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| valid_node_id(value))
                    .ok_or_else(|| "Credential state has invalid node_id".to_string())?;
                if state_credential_id != credential_id {
                    return Err("Credential ID does not match durable Credential state".into());
                }
                if state.get("secret_file").and_then(serde_json::Value::as_str)
                    != secret_file.file_name().and_then(|name| name.to_str())
                {
                    return Err(
                        "Credential Secret path does not match durable Credential state".into(),
                    );
                }
                Ok(Self::PermanentCredential {
                    credential_id,
                    secret,
                    secret_file,
                    state_node_id: state_node_id.to_string(),
                })
            }
            _ => Err("NODE_AUTH_MODE must be group-token or credential".into()),
        }
    }

    pub fn validate_startup_node_id(&self, node_id: &str) -> Result<(), String> {
        if let Self::PermanentCredential { state_node_id, .. } = self {
            if state_node_id != node_id {
                return Err(
                    "persistent Node ID does not match permanent Credential identity".into(),
                );
            }
        }
        Ok(())
    }

    pub fn authorization_value(&self) -> String {
        match self {
            Self::LegacyGroupToken { token } => format!("Bearer {token}"),
            Self::PermanentCredential { secret, .. } => {
                format!("{CREDENTIAL_AUTH_SCHEME} {secret}")
            }
        }
    }

    pub fn credential_id(&self) -> Option<&str> {
        match self {
            Self::LegacyGroupToken { .. } => None,
            Self::PermanentCredential { credential_id, .. } => Some(credential_id),
        }
    }

    pub fn transport_allowed(&self, panel_url: &str) -> bool {
        match self {
            Self::LegacyGroupToken { .. } => true,
            Self::PermanentCredential { .. } => panel_url.trim().starts_with("https://"),
        }
    }

    pub fn sensitive_value(&self) -> &str {
        match self {
            Self::LegacyGroupToken { token } => token,
            Self::PermanentCredential { secret, .. } => secret,
        }
    }

    pub fn persistent_descriptor(&self) -> PersistedNodeAuth {
        match self {
            Self::LegacyGroupToken { token } => PersistedNodeAuth::LegacyGroupToken {
                token: token.clone(),
            },
            Self::PermanentCredential {
                credential_id,
                secret_file,
                ..
            } => PersistedNodeAuth::PermanentCredential {
                credential_id: credential_id.clone(),
                secret_file: secret_file.clone(),
            },
        }
    }

    pub fn apply_reqwest(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let builder = builder.header("Authorization", self.authorization_value());
        match self.credential_id() {
            Some(credential_id) => builder.header(CREDENTIAL_ID_HEADER, credential_id),
            None => builder,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PersistedNodeAuth {
    LegacyGroupToken {
        token: String,
    },
    PermanentCredential {
        credential_id: String,
        secret_file: PathBuf,
    },
}

impl PersistedNodeAuth {
    pub fn load_runtime(&self) -> Result<NodeRuntimeAuth, String> {
        match self {
            Self::LegacyGroupToken { token } => Ok(NodeRuntimeAuth::LegacyGroupToken {
                token: token.clone(),
            }),
            Self::PermanentCredential {
                credential_id,
                secret_file,
            } => {
                validate_credential_secret_path(secret_file)?;
                Ok(NodeRuntimeAuth::PermanentCredential {
                    credential_id: credential_id.clone(),
                    secret: read_private_credential_secret(secret_file)?,
                    secret_file: secret_file.clone(),
                    state_node_id: String::new(),
                })
            }
        }
    }
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn credential_path_has_no_dot_segments(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn credential_claim_dir(secret_file: &Path) -> Result<&Path, String> {
    if !credential_path_has_no_dot_segments(secret_file)
        || secret_file.file_name().and_then(|name| name.to_str())
            != Some(CREDENTIAL_SECRET_FILENAME)
    {
        return Err(
            "permanent Credential Secret path is outside the approved storage layout".into(),
        );
    }
    let claim_dir = secret_file
        .parent()
        .ok_or_else(|| "permanent Credential Secret path has no Claim directory".to_string())?;
    if claim_dir.parent() != Some(Path::new(CREDENTIAL_STATE_ROOT)) {
        return Err("permanent Credential Secret path is outside the approved storage root".into());
    }
    Ok(claim_dir)
}

fn private_directory_metadata_is_safe(metadata: &std::fs::Metadata, expected_uid: u32) -> bool {
    !metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == expected_uid
        && (metadata.mode() & 0o777) == 0o700
}

fn validate_private_credential_directory(path: &Path, label: &str) -> Result<(), String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(format!("{label} requires root"));
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
    if !private_directory_metadata_is_safe(&metadata, euid) {
        return Err(format!(
            "{label} must be a root-owned directory with mode 0700 and must not be a symlink"
        ));
    }
    Ok(())
}

fn validate_credential_secret_path(secret_file: &Path) -> Result<(), String> {
    let claim_dir = credential_claim_dir(secret_file)?;
    validate_private_credential_directory(
        Path::new(CREDENTIAL_STATE_ROOT),
        "Credential state root",
    )?;
    validate_private_credential_directory(claim_dir, "Credential Claim directory")
}

fn validate_credential_storage_paths(secret_file: &Path, state_file: &Path) -> Result<(), String> {
    let claim_dir = credential_claim_dir(secret_file)?;
    if !credential_path_has_no_dot_segments(state_file)
        || state_file.file_name().and_then(|name| name.to_str()) != Some(CREDENTIAL_STATE_FILENAME)
        || state_file.parent() != Some(claim_dir)
    {
        return Err(
            "Credential state and Secret must be the approved sibling files in one Claim directory"
                .into(),
        );
    }
    validate_credential_secret_path(secret_file)
}

fn private_metadata_is_safe(metadata: &std::fs::Metadata, expected_uid: u32) -> bool {
    !metadata.file_type().is_symlink()
        && metadata.is_file()
        && metadata.uid() == expected_uid
        && (metadata.mode() & 0o777) == 0o600
}

fn read_private_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(format!("{label} requires root"));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| format!("{label} is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| format!("{label} metadata is unavailable"))?;
    if !private_metadata_is_safe(&metadata, euid) {
        return Err(format!(
            "{label} must be a root-owned regular file with mode 0600"
        ));
    }
    if metadata.len() > 65_536 {
        return Err(format!("{label} is unexpectedly large"));
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut data)
        .map_err(|_| format!("{label} could not be read"))?;
    Ok(data)
}

fn parse_credential_secret_value(value: String) -> Result<String, String> {
    let payload = value
        .strip_prefix("rpn1_")
        .ok_or_else(|| "permanent Credential Secret has invalid format".to_string())?;
    if payload.len() != 43
        || !payload
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("permanent Credential Secret has invalid format".into());
    }
    Ok(value)
}

pub fn read_private_credential_secret(path: &Path) -> Result<String, String> {
    let bytes = read_private_file(path, "permanent Credential Secret")?;
    let value = String::from_utf8(bytes)
        .map_err(|_| "permanent Credential Secret has invalid encoding".to_string())?;
    parse_credential_secret_value(value)
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub panel_url: String,
    pub auth: NodeRuntimeAuth,
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
    /// Corrected Stage 3.1: Node-local TLS camouflage sites. Remote REALITY
    /// routes remain ordinary Panel listener config; the Relay owns no Xray.
    pub camouflage_sites_enabled: bool,
    pub camouflage_sites_manifest_path: String,
    pub camouflage_sites_state_dir: String,
    pub camouflage_wrapper_conf_path: String,
    pub certificate_lifecycle_enabled: bool,
    #[allow(dead_code)] // 旧Node-local ACME调度配置暂留，集中证书主路径不再读取。
    pub certificate_lifecycle_check_interval_secs: u64,
    pub certbot_binary_path: String,
    pub certbot_live_dir: String,
    pub certificate_http01_webroot: String,
    pub certificate_http01_conf_path: String,
    pub certificate_state_dir: String,
    pub provisioning_capabilities_path: String,
}

impl NodeConfig {
    pub fn load() -> Self {
        let panel_url =
            std::env::var("PANEL_URL").unwrap_or_else(|_| "http://127.0.0.1:18888".into());
        let auth = NodeRuntimeAuth::load().unwrap_or_else(|error| {
            eprintln!("FATAL: invalid Node authentication configuration: {error}");
            std::process::exit(1);
        });
        let poll_interval = std::env::var("POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let cfg = Self {
            panel_url,
            auth,
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
            camouflage_sites_enabled: parse_bool_env("CAMOUFLAGE_SITES_ENABLED", false),
            camouflage_sites_manifest_path: std::env::var("CAMOUFLAGE_SITES_MANIFEST_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/etc/relay-panel/camouflage-sites.json".to_string()),
            camouflage_sites_state_dir: std::env::var("CAMOUFLAGE_SITES_STATE_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/camouflage-sites".to_string()),
            camouflage_wrapper_conf_path: std::env::var("CAMOUFLAGE_WRAPPER_CONF_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/etc/nginx/conf.d/relay-panel-fallback.conf".to_string()),
            certificate_lifecycle_enabled: parse_bool_env("CERTIFICATE_LIFECYCLE_ENABLED", false),
            certificate_lifecycle_check_interval_secs: std::env::var(
                "CERTIFICATE_LIFECYCLE_CHECK_INTERVAL_SECS",
            )
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value >= 60)
            .unwrap_or(43_200),
            certbot_binary_path: std::env::var("CERTBOT_BINARY_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/usr/bin/certbot".to_string()),
            certbot_live_dir: std::env::var("CERTBOT_LIVE_DIR")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/etc/letsencrypt/live".to_string()),
            certificate_http01_webroot: std::env::var("CERTIFICATE_HTTP01_WEBROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/var/www/relay-panel-acme".to_string()),
            certificate_http01_conf_path: std::env::var("CERTIFICATE_HTTP01_CONF_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/etc/nginx/conf.d/relay-panel-acme.conf".to_string()),
            certificate_state_dir: std::env::var("CERTIFICATE_STATE_DIR")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/certificates".to_string()),
            provisioning_capabilities_path: std::env::var("PROVISIONING_CAPABILITIES_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/opt/relay-node/provisioning-capabilities.json".to_string()),
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

    pub fn camouflage_site_config(
        &self,
    ) -> crate::forwarder::camouflage_site::CamouflageSiteConfig {
        crate::forwarder::camouflage_site::CamouflageSiteConfig {
            enabled: self.camouflage_sites_enabled,
            manifest_path: PathBuf::from(&self.camouflage_sites_manifest_path),
            state_dir: PathBuf::from(&self.camouflage_sites_state_dir),
            nginx: crate::forwarder::nginx_sni::NginxSniConfig {
                enabled: self.nginx_sni_enabled,
                conf_path: PathBuf::from(&self.camouflage_wrapper_conf_path),
                test_cmd: self.nginx_sni_test_cmd.clone(),
                reload_cmd: self.nginx_sni_reload_cmd.clone(),
                default_backend: self.nginx_sni_default_backend.clone(),
                access_log_path: self.nginx_sni_access_log_path.clone(),
            },
            certificate_lifecycle:
                crate::forwarder::certificate_lifecycle::CertificateLifecycleConfig {
                    enabled: self.certificate_lifecycle_enabled,
                    certbot_binary: PathBuf::from(&self.certbot_binary_path),
                    certbot_live_dir: PathBuf::from(&self.certbot_live_dir),
                    webroot: PathBuf::from(&self.certificate_http01_webroot),
                    state_dir: PathBuf::from(&self.certificate_state_dir),
                    dns01_hook_binary: std::env::current_exe()
                        .unwrap_or_else(|_| PathBuf::from("/opt/relay-node/relay-node")),
                    http01_nginx: crate::forwarder::nginx_sni::NginxSniConfig {
                        enabled: self.nginx_sni_enabled,
                        conf_path: PathBuf::from(&self.certificate_http01_conf_path),
                        test_cmd: self.nginx_sni_test_cmd.clone(),
                        reload_cmd: self.nginx_sni_reload_cmd.clone(),
                        default_backend: self.nginx_sni_default_backend.clone(),
                        access_log_path: self.nginx_sni_access_log_path.clone(),
                    },
                },
        }
    }

    pub fn provisioning_capabilities(&self) -> relay_shared::protocol::ProvisioningCapabilities {
        let Ok(contents) = std::fs::read(&self.provisioning_capabilities_path) else {
            return relay_shared::protocol::ProvisioningCapabilities::default();
        };
        let Ok(mut capabilities) =
            serde_json::from_slice::<relay_shared::protocol::ProvisioningCapabilities>(&contents)
        else {
            return relay_shared::protocol::ProvisioningCapabilities::default();
        };

        capabilities.nginx_stream &= self.nginx_sni_enabled;
        capabilities.http01 &= self.certificate_lifecycle_enabled;
        capabilities.certificate_lifecycle &= self.certificate_lifecycle_enabled;
        capabilities.reality_camouflage &=
            self.camouflage_sites_enabled && self.certificate_lifecycle_enabled;
        capabilities
    }

    fn validate(&self) {
        if self.panel_url.trim().is_empty() {
            eprintln!("FATAL: PANEL_URL is empty");
            std::process::exit(1);
        }
        if !self.auth.transport_allowed(&self.panel_url) {
            eprintln!("FATAL: permanent Credential authentication requires an https:// PANEL_URL");
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

#[cfg(test)]
mod auth_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn permanent_auth(secret: &str) -> NodeRuntimeAuth {
        NodeRuntimeAuth::PermanentCredential {
            credential_id: "cred-test".into(),
            secret: secret.into(),
            secret_file: PathBuf::from(
                "/var/lib/relay-panel/node-claims/test/node-credential.secret",
            ),
            state_node_id: "Node_A".into(),
        }
    }

    #[test]
    fn runtime_auth_debug_and_persistence_never_duplicate_raw_secret() {
        let secret = "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let auth = permanent_auth(secret);
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(secret));

        let persisted = serde_json::to_string(&auth.persistent_descriptor()).unwrap();
        assert!(persisted.contains("cred-test"));
        assert!(persisted.contains("node-credential.secret"));
        assert!(!persisted.contains(secret));
        assert!(auth.validate_startup_node_id("Node_A").is_ok());
        assert!(auth.validate_startup_node_id("Other_Node").is_err());
    }

    #[test]
    fn auth_headers_use_explicit_non_fallback_modes() {
        let legacy = NodeRuntimeAuth::LegacyGroupToken {
            token: "legacy-token".into(),
        };
        let legacy_request = legacy
            .apply_reqwest(reqwest::Client::new().get("http://127.0.0.1/"))
            .build()
            .unwrap();
        assert_eq!(
            legacy_request.headers()["Authorization"],
            "Bearer legacy-token"
        );
        assert!(legacy_request.headers().get(CREDENTIAL_ID_HEADER).is_none());
        assert!(legacy.transport_allowed("http://127.0.0.1:18888"));

        let secret = "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let credential = permanent_auth(secret);
        let request = credential
            .apply_reqwest(reqwest::Client::new().get("http://127.0.0.1/"))
            .build()
            .unwrap();
        assert_eq!(
            request.headers()["Authorization"],
            format!("RelayNodeCredential {secret}")
        );
        assert_eq!(request.headers()[CREDENTIAL_ID_HEADER], "cred-test");
        assert!(!request.url().as_str().contains(secret));
        assert!(credential.transport_allowed("https://panel.example"));
        assert!(!credential.transport_allowed("http://panel.example"));
    }

    #[test]
    fn credential_secret_parser_is_canonical() {
        let valid = "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            parse_credential_secret_value(valid.to_string()).unwrap(),
            valid
        );
        for invalid in [
            "rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        ] {
            assert!(parse_credential_secret_value(invalid.to_string()).is_err());
        }
    }

    #[test]
    fn credential_storage_layout_is_fixed_to_the_b2_02b_claim_directory() {
        let secret = Path::new("/var/lib/relay-panel/node-claims/claim-a/node-credential.secret");
        let state = Path::new("/var/lib/relay-panel/node-claims/claim-a/credential-pending.json");
        assert_eq!(
            credential_claim_dir(secret).unwrap(),
            Path::new("/var/lib/relay-panel/node-claims/claim-a")
        );
        assert!(credential_path_has_no_dot_segments(secret));
        assert!(!credential_path_has_no_dot_segments(Path::new(
            "/var/lib/relay-panel/node-claims/claim-a/../claim-b/node-credential.secret"
        )));
        assert!(credential_claim_dir(Path::new("/tmp/claim-a/node-credential.secret")).is_err());

        // The shape check precedes root-only metadata checks, so invalid layouts
        // fail deterministically even in non-root unit-test processes.
        let wrong_state =
            Path::new("/var/lib/relay-panel/node-claims/claim-b/credential-pending.json");
        assert!(state.parent() == secret.parent());
        assert!(wrong_state.parent() != secret.parent());
        assert_eq!(
            state.file_name().and_then(|name| name.to_str()),
            Some(CREDENTIAL_STATE_FILENAME)
        );
    }

    #[test]
    fn private_directory_metadata_requires_owner_and_exact_0700() {
        let root = std::env::temp_dir().join(format!(
            "relay-node-auth-directory-metadata-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(private_directory_metadata_is_safe(
            &metadata,
            metadata.uid()
        ));
        assert!(!private_directory_metadata_is_safe(
            &metadata,
            metadata.uid().wrapping_add(1)
        ));

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert!(!private_directory_metadata_is_safe(
            &metadata,
            metadata.uid()
        ));

        let link = root.with_extension("link");
        let _ = std::fs::remove_file(&link);
        symlink(&root, &link).unwrap();
        let metadata = std::fs::symlink_metadata(&link).unwrap();
        assert!(!private_directory_metadata_is_safe(
            &metadata,
            metadata.uid()
        ));
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn private_file_metadata_rejects_mode_and_symlink() {
        let root =
            std::env::temp_dir().join(format!("relay-node-auth-metadata-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("secret");
        std::fs::write(&file, b"secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = std::fs::symlink_metadata(&file).unwrap();
        assert!(private_metadata_is_safe(&metadata, metadata.uid()));
        assert!(!private_metadata_is_safe(
            &metadata,
            metadata.uid().wrapping_add(1)
        ));

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let metadata = std::fs::symlink_metadata(&file).unwrap();
        assert!(!private_metadata_is_safe(&metadata, metadata.uid()));

        let link = root.join("secret-link");
        symlink(&file, &link).unwrap();
        let link_metadata = std::fs::symlink_metadata(&link).unwrap();
        assert!(!private_metadata_is_safe(
            &link_metadata,
            link_metadata.uid()
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
