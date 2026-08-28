use relay_shared::protocol::ProvisioningCapabilities;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::path::Path;

pub(crate) const INSTALL_SCRIPT: &str = include_str!("../../../../scripts/relay-node-bootstrap.sh");
pub(crate) const NODE_ARTIFACT_ROOT_ENV: &str = "NODE_ARTIFACT_DIR";
pub(crate) const NODE_ARTIFACT_ROOT: &str = "/opt/relay-panel/node-assets";
const MIN_ARTIFACT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningProfile {
    #[default]
    RealityCamouflage,
}

impl ProvisioningProfile {
    pub(crate) fn required_capabilities(self) -> ProvisioningCapabilities {
        match self {
            Self::RealityCamouflage => ProvisioningCapabilities::reality_camouflage(),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RealityCamouflage => "reality_camouflage",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "reality_camouflage" => Some(Self::RealityCamouflage),
            _ => None,
        }
    }
}

pub(crate) const ENROLLMENT_CLAIM_WINDOW_SECS: i64 = 10 * 60;
pub(crate) const MAX_MANUAL_BOOTSTRAP_TRANSACTION_SECS: i64 = 45 * 60;
pub(crate) const BOOTSTRAP_FINALIZATION_GRACE_SECS: i64 = 15 * 60;

pub(crate) fn bootstrap_session_lifetime_secs() -> i64 {
    MAX_MANUAL_BOOTSTRAP_TRANSACTION_SECS + BOOTSTRAP_FINALIZATION_GRACE_SECS
}

#[derive(Clone)]
pub(crate) struct ProvisioningArtifact {
    pub(crate) architecture: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: String,
}

pub(crate) struct ProvisioningBundle {
    pub(crate) install_script: &'static str,
    pub(crate) artifact: ProvisioningArtifact,
    pub(crate) config: String,
}

impl ProvisioningBundle {
    pub(crate) fn new(panel_url: &str, node_token: &str, artifact: ProvisioningArtifact) -> Self {
        let config = render_bootstrap_config(panel_url, node_token, &artifact);
        Self {
            install_script: INSTALL_SCRIPT,
            artifact,
            config,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProvisioningError {
    pub(crate) category: &'static str,
    pub(crate) message: &'static str,
}

pub(crate) fn normalize_architecture(raw: &str) -> Option<&'static str> {
    match raw {
        "amd64" | "x86_64" => Some("amd64"),
        "arm64" | "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// Accept only a plain public HTTP(S) origin for remote Relay bootstrap.
pub(crate) fn valid_public_panel_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && (parsed.path().is_empty() || parsed.path() == "/")
}

pub(crate) fn load_artifact(architecture: &str) -> Result<ProvisioningArtifact, ProvisioningError> {
    let root = std::env::var(NODE_ARTIFACT_ROOT_ENV).unwrap_or_else(|_| NODE_ARTIFACT_ROOT.into());
    load_artifact_from(Path::new(&root), architecture)
}

fn artifact_metadata_read_message(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::NotFound => "Panel relay-node artifact metadata is missing",
        ErrorKind::PermissionDenied => {
            "Panel relay-node artifact metadata is not readable: permission denied"
        }
        _ => "Panel relay-node artifact metadata could not be read",
    }
}

fn load_artifact_from(
    root: &Path,
    architecture: &str,
) -> Result<ProvisioningArtifact, ProvisioningError> {
    let architecture = normalize_architecture(architecture).ok_or(ProvisioningError {
        category: "ARTIFACT_FAILED",
        message: "unsupported artifact architecture",
    })?;
    let directory = root.join(architecture);
    let metadata_bytes =
        std::fs::read(directory.join("metadata.json")).map_err(|error| ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: artifact_metadata_read_message(error.kind()),
        })?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata_bytes).map_err(|_| ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact metadata is invalid",
        })?;
    let version = metadata
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if semver::Version::parse(version).is_err() {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact version is invalid",
        });
    }
    let expected_sha = metadata
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact SHA-256 metadata is invalid",
        });
    }
    let expected_size = metadata
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact size metadata is invalid",
        })?;
    let path = directory.join("relay-node");
    let bytes = std::fs::read(&path).map_err(|_| ProvisioningError {
        category: "ARTIFACT_FAILED",
        message: "Panel relay-node artifact is missing",
    })?;
    if expected_size != bytes.len() as u64 {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact size does not match metadata",
        });
    }
    if bytes.len() < MIN_ARTIFACT_BYTES || bytes.get(..6) != Some(&[0x7f, b'E', b'L', b'F', 2, 1]) {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact is not a 64-bit Linux ELF binary",
        });
    }
    let expected_machine = match architecture {
        "amd64" => 62u16,
        "arm64" => 183u16,
        _ => unreachable!("normalize_architecture accepts only supported values"),
    };
    if u16::from_le_bytes([bytes[18], bytes[19]]) != expected_machine {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact architecture does not match",
        });
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if !sha256.eq_ignore_ascii_case(expected_sha) {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact SHA-256 does not match metadata",
        });
    }
    Ok(ProvisioningArtifact {
        architecture: architecture.into(),
        bytes,
        sha256,
    })
}

pub(crate) fn reported_capabilities(raw: &str) -> Option<ProvisioningCapabilities> {
    let value = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    serde_json::from_value(value.get("provisioning_capabilities")?.clone()).ok()
}

pub(crate) fn capabilities_satisfy(
    available: ProvisioningCapabilities,
    required: ProvisioningCapabilities,
) -> bool {
    available.satisfies(required)
}

fn render_bootstrap_config(
    panel_url: &str,
    node_token: &str,
    artifact: &ProvisioningArtifact,
) -> String {
    format!(
        "PANEL_URL={}\nNODE_TOKEN={}\nRELAY_NODE_ARCH={}\nRELAY_NODE_SHA256={}\n",
        shell_quote(panel_url),
        shell_quote(node_token),
        artifact.architecture,
        artifact.sha256
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_matches_the_existing_ssh_bootstrap_contract() {
        let artifact = ProvisioningArtifact {
            architecture: "amd64".into(),
            bytes: vec![0x7f, b'E', b'L', b'F'],
            sha256: "abc123".into(),
        };

        let bundle =
            ProvisioningBundle::new("https://panel.test/api", "token with ' quote", artifact);

        assert_eq!(bundle.install_script, INSTALL_SCRIPT);
        assert_eq!(bundle.artifact.architecture, "amd64");
        assert_eq!(bundle.artifact.bytes, vec![0x7f, b'E', b'L', b'F']);
        assert_eq!(bundle.artifact.sha256, "abc123");
        assert_eq!(
            bundle.config.as_bytes(),
            b"PANEL_URL='https://panel.test/api'\nNODE_TOKEN='token with '\\'' quote'\nRELAY_NODE_ARCH=amd64\nRELAY_NODE_SHA256=abc123\n"
        );
    }

    #[test]
    fn architecture_aliases_match_the_existing_ssh_preflight_contract() {
        assert_eq!(normalize_architecture("amd64"), Some("amd64"));
        assert_eq!(normalize_architecture("x86_64"), Some("amd64"));
        assert_eq!(normalize_architecture("arm64"), Some("arm64"));
        assert_eq!(normalize_architecture("aarch64"), Some("arm64"));
        assert_eq!(normalize_architecture("riscv64"), None);
    }

    #[test]
    fn public_panel_url_accepts_http_https_origins_and_rejects_credentials() {
        assert!(valid_public_panel_url("http://1.2.3.4:18888"));
        assert!(valid_public_panel_url("https://panel.example.com"));
        assert!(!valid_public_panel_url(
            "https://user:pass@panel.example.com"
        ));
        assert!(!valid_public_panel_url("http://panel.example.com/path"));
        assert!(!valid_public_panel_url("ftp://panel.example.com"));
    }

    #[test]
    fn capability_helpers_require_all_five_typed_capabilities() {
        let required = ProvisioningProfile::RealityCamouflage.required_capabilities();
        let raw = serde_json::json!({
            "provisioning_capabilities": ProvisioningCapabilities::reality_camouflage(),
        })
        .to_string();
        let available = reported_capabilities(&raw).expect("typed capabilities");

        assert!(capabilities_satisfy(available, required));
        assert!(!capabilities_satisfy(
            ProvisioningCapabilities::default(),
            required
        ));
        assert!(reported_capabilities("{\"other\":true}").is_none());
    }

    #[test]
    fn canonical_artifact_layout_validates_elf_architecture_and_sha() {
        let root = std::env::temp_dir().join(format!("relay-node-assets-{}", uuid::Uuid::new_v4()));
        let dir = root.join("amd64");
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = vec![0_u8; 64 * 1024];
        bytes[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let sha = hex::encode(Sha256::digest(&bytes));
        std::fs::write(dir.join("relay-node"), &bytes).unwrap();
        std::fs::write(
            dir.join("metadata.json"),
            format!(
                r#"{{"version":"1.2.3","sha256":"{sha}","size":{}}}"#,
                bytes.len()
            ),
        )
        .unwrap();
        assert_eq!(load_artifact_from(&root, "x86_64").unwrap().sha256, sha);
        std::fs::write(
            dir.join("metadata.json"),
            format!(r#"{{"version":"1.2.3","sha256":"{sha}","size":1}}"#),
        )
        .unwrap();
        assert!(load_artifact_from(&root, "amd64").is_err());
        std::fs::write(
            dir.join("metadata.json"),
            r#"{"version":"1.2.3","sha256":"bad"}"#,
        )
        .unwrap();
        assert!(load_artifact_from(&root, "amd64").is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_metadata_read_errors_are_classified_without_paths() {
        assert_eq!(
            artifact_metadata_read_message(ErrorKind::NotFound),
            "Panel relay-node artifact metadata is missing"
        );
        assert_eq!(
            artifact_metadata_read_message(ErrorKind::PermissionDenied),
            "Panel relay-node artifact metadata is not readable: permission denied"
        );
        assert_eq!(
            artifact_metadata_read_message(ErrorKind::Interrupted),
            "Panel relay-node artifact metadata could not be read"
        );
    }
}
