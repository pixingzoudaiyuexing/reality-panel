//! Node-side read-only-command-compatible reapplication of the shared
//! nginx_sni plan. The operation only rebuilds and safely reloads the managed
//! stream fragment; certificate, DNS, camouflage, and relay-node restart are
//! intentionally outside this path.

use crate::config::NodeConfig;
use crate::forwarder::ForwarderManager;
use relay_shared::protocol::ReapplyNginxSniResult;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn run_and_report(
    manager: &Arc<Mutex<ForwarderManager>>,
    config: &NodeConfig,
    node_id: &str,
    request_id: String,
    rule_id: i64,
    challenge: String,
) {
    let result = {
        let mut manager = manager.lock().await;
        manager.reapply_nginx_sni(rule_id).await
    };
    let response = ReapplyNginxSniResult {
        msg_type: "reapply_nginx_sni_result".into(),
        request_id,
        rule_id,
        node_id: node_id.to_string(),
        challenge,
        success: result.is_ok(),
        error: result.err(),
    };
    if let Err(error) = report(config, &response).await {
        tracing::warn!(
            "reapply_nginx_sni {}: failed to report result: {}",
            response.request_id,
            error
        );
    }
}

async fn report(config: &NodeConfig, result: &ReapplyNginxSniResult) -> Result<(), String> {
    let url = format!("{}/api/v1/node/reapply_nginx_sni_result", config.panel_url);
    let response = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {}", config.token))
        .json(result)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", response.status()))
    }
}
