use relay_shared::protocol::ProvisioningCapabilities;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub(crate) const INSTALL_SCRIPT: &str = include_str!("../../../../scripts/relay-node-bootstrap.sh");

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

pub(crate) fn load_artifact(architecture: &str) -> Result<ProvisioningArtifact, ProvisioningError> {
    let dir = std::env::var("NODE_BOOTSTRAP_BINARY_DIR")
        .unwrap_or_else(|_| "/opt/relay-panel/node-assets".into());
    let path = PathBuf::from(dir).join(format!("relay-node-linux-{architecture}"));
    let bytes = std::fs::read(&path).map_err(|_| ProvisioningError {
        category: "ARTIFACT_FAILED",
        message: "Panel relay-node artifact is missing",
    })?;
    if bytes.is_empty() {
        return Err(ProvisioningError {
            category: "ARTIFACT_FAILED",
            message: "Panel relay-node artifact is empty",
        });
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
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
}
