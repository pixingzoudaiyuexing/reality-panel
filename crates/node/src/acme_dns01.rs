use relay_shared::protocol::CONFIG_PROTOCOL_VERSION;
use reqwest::StatusCode;
use serde::Serialize;
use std::time::Duration;

const COMMAND: &str = "acme-dns01-hook";

#[derive(Serialize)]
struct ChallengeRequest {
    node_id: String,
    sni: String,
    value: String,
}

pub(crate) fn is_hook_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == COMMAND)
}

pub(crate) fn run_hook(args: &[String]) -> Result<(), String> {
    let action = match args.get(1).map(String::as_str) {
        Some("auth") => "present",
        Some("cleanup") => "cleanup",
        _ => return Err("invalid hook action".into()),
    };
    if args.len() != 2 {
        return Err("unexpected hook arguments".into());
    }
    let panel_url = std::env::var("PANEL_URL").map_err(|_| "Panel URL is unavailable")?;
    let token = std::env::var("NODE_TOKEN").map_err(|_| "Node credential is unavailable")?;
    if token.trim().is_empty() || token == "default-token" {
        return Err("Node credential is unavailable".into());
    }
    let sni = std::env::var("CERTBOT_DOMAIN").map_err(|_| "challenge domain is unavailable")?;
    let value =
        std::env::var("CERTBOT_VALIDATION").map_err(|_| "challenge value is unavailable")?;
    let node_id = crate::poller::get_or_create_node_id();
    if node_id.trim().is_empty() {
        return Err("Node identity is unavailable".into());
    }
    let endpoint = format!(
        "{}/api/v1/node/acme-dns01/{action}",
        panel_url.trim_end_matches('/')
    );
    let request = ChallengeRequest {
        node_id,
        sni,
        value,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "hook runtime is unavailable")?;
    runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(150))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "HTTP client is unavailable")?;
        let response = client
            .post(endpoint)
            .bearer_auth(token)
            .header("X-Config-Protocol-Version", CONFIG_PROTOCOL_VERSION)
            .json(&request)
            .send()
            .await
            .map_err(|_| "Panel challenge request failed")?;
        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(format!(
                "Panel challenge request returned HTTP {}",
                response.status().as_u16()
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_detection_is_exact() {
        assert!(is_hook_command(&[COMMAND.into(), "auth".into()]));
        assert!(!is_hook_command(&["--version".into()]));
    }

    #[test]
    fn challenge_request_serializes_no_panel_credentials() {
        let value = serde_json::to_value(ChallengeRequest {
            node_id: "node-a".into(),
            sni: "op1.example.com".into(),
            value: "validation-token-1234".into(),
        })
        .unwrap();
        assert!(value.get("token").is_none());
        assert!(value.get("panel_url").is_none());
    }
}
