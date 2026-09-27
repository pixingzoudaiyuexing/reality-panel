use crate::config::{NodeConfig, NodeRuntimeAuth, RUNTIME_AUTH_DESCRIPTOR};
use std::path::Path;
use tokio::sync::watch;

fn startup_auth_at<F>(
    environment_auth: &NodeRuntimeAuth,
    panel_url: &str,
    node_id: &str,
    descriptor_path: &Path,
    load_descriptor: F,
) -> Result<NodeRuntimeAuth, String>
where
    F: FnOnce(&str) -> Result<(NodeRuntimeAuth, i64), String>,
{
    match std::fs::symlink_metadata(descriptor_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(environment_auth.clone())
        }
        Err(_) => return Err("runtime authentication descriptor cannot be inspected".into()),
        Ok(_) => {}
    }
    let (auth, _) = load_descriptor(node_id)?;
    if !auth.transport_allowed(panel_url) {
        return Err("runtime authentication requires an HTTPS Panel URL".into());
    }
    Ok(auth)
}

/// LKG is already restored when this runs. No HTTP or WS config task may start
/// until a present durable descriptor is valid; a failed read never restores
/// the Group Token as config authority.
pub async fn wait_for_startup_auth(config: NodeConfig, node_id: &str) -> NodeConfig {
    let descriptor_path = Path::new(RUNTIME_AUTH_DESCRIPTOR);
    let mut blocked = false;
    loop {
        match startup_auth_at(
            &config.auth,
            &config.panel_url,
            node_id,
            descriptor_path,
            NodeRuntimeAuth::load_reload_descriptor,
        ) {
            Ok(auth) => {
                if blocked {
                    tracing::info!("durable control-plane authentication recovered");
                }
                let mut next = config;
                next.auth = auth;
                return next;
            }
            Err(error) => {
                if !blocked {
                    tracing::warn!(
                        "control-plane authentication blocked: {error}; retaining LKG forwarding"
                    );
                    blocked = true;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

fn matches_exact_identity(identity: &serde_json::Value, group_id: i64, node_id: &str) -> bool {
    identity
        .get("identity_group_id")
        .and_then(serde_json::Value::as_i64)
        == Some(group_id)
        && identity.get("node_id").and_then(serde_json::Value::as_str) == Some(node_id)
}

/// Only the control-plane config is replaced; forwarding managers and LKG
/// are owned outside this task and cannot be restarted here.
pub async fn watch_auth(config: NodeConfig, node_id: String, sender: watch::Sender<NodeConfig>) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return,
    };
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if sender.is_closed() {
            return;
        }
        let Ok((auth, group_id)) = NodeRuntimeAuth::load_reload_descriptor(&node_id) else {
            continue;
        };
        if !auth.transport_allowed(&config.panel_url) {
            continue;
        }
        if sender.borrow().auth.credential_id() == auth.credential_id() {
            continue;
        }
        let response = auth
            .apply_reqwest(client.get(format!("{}/api/v1/node/identity", config.panel_url)))
            .header("X-Node-ID", &node_id)
            .send()
            .await;
        let Ok(response) = response else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(identity) = response.json::<serde_json::Value>().await else {
            continue;
        };
        if !matches_exact_identity(&identity, group_id, &node_id) {
            continue;
        }
        let mut next = config.clone();
        next.auth = auth;
        sender.send_replace(next);
        tracing::info!("control-plane authentication updated from durable verified identity");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_auth_requires_valid_descriptor_before_control_plane_can_start() {
        let legacy = NodeRuntimeAuth::LegacyGroupToken {
            token: "legacy".into(),
        };
        let descriptor = std::env::temp_dir().join(format!(
            "relay-node-rt001-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let no_descriptor = startup_auth_at(
            &legacy,
            "https://panel.example",
            "Node_A",
            &descriptor,
            |_| panic!("must not load"),
        )
        .unwrap();
        assert!(no_descriptor.credential_id().is_none());

        std::fs::write(&descriptor, b"present").unwrap();
        assert!(startup_auth_at(
            &legacy,
            "https://panel.example",
            "Node_A",
            &descriptor,
            |_| Err("invalid descriptor".into())
        )
        .is_err());
        let credential = NodeRuntimeAuth::PermanentCredential {
            credential_id: "cred-a".into(),
            secret: "test-secret".into(),
            secret_file: descriptor.clone(),
            state_node_id: "Node_A".into(),
        };
        let ready = startup_auth_at(
            &legacy,
            "https://panel.example",
            "Node_A",
            &descriptor,
            |_| Ok((credential, 10)),
        )
        .unwrap();
        assert_eq!(ready.credential_id(), Some("cred-a"));
        assert!(legacy.credential_id().is_none());
        assert!(startup_auth_at(
            &legacy,
            "https://panel.example",
            "Node_B",
            &descriptor,
            |_| Err("identity mismatch".into())
        )
        .is_err());
        std::fs::remove_file(descriptor).unwrap();
    }

    #[test]
    fn authentication_transition_requires_exact_server_proof() {
        assert!(matches_exact_identity(
            &serde_json::json!({"identity_group_id": 7, "node_id": "NODE_A"}),
            7,
            "NODE_A"
        ));
        for invalid in [
            serde_json::json!({"identity_group_id": 8, "node_id": "NODE_A"}),
            serde_json::json!({"identity_group_id": 7, "node_id": "NODE_B"}),
            serde_json::json!({"group_id": 7, "node_id": "NODE_A"}),
            serde_json::json!({"identity_group_id": "7", "node_id": "NODE_A"}),
        ] {
            assert!(!matches_exact_identity(&invalid, 7, "NODE_A"));
        }
    }
}
