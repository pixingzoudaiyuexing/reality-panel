use crate::config::{NodeConfig, NodeRuntimeAuth};
use tokio::sync::watch;

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
