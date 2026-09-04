#![cfg(unix)]

use axum::{http::StatusCode, routing::post, Json, Router};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::Command;

fn unique_dir() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "panel-acme-hard-gate-{}-{stamp}",
        std::process::id()
    ))
}

#[tokio::test]
async fn failed_auth_hook_kills_certbot_group_before_parent_can_continue() {
    let app = Router::new().route(
        "/api/v1/node/acme-dns01/present",
        post(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "code": "ACME_DNS01_PROPAGATION_TIMEOUT"
                })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let panel_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = unique_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let continued = dir.join("authorization-continued");
    let receipt = dir.join("01234567-89ab-4def-8123-456789abcdef.json");
    let panel_binary = env!("CARGO_BIN_EXE_relay-panel");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("\"$PANEL_BIN\" acme-dns01-hook auth; printf continued > \"$CONTINUED\"")
        .env("PANEL_BIN", panel_binary)
        .env("CONTINUED", &continued)
        .env("RELAY_PANEL_INTERNAL_URL", &panel_url)
        .env("RELAY_PANEL_NODE_TOKEN", "test-token")
        .env("RELAY_PANEL_CERTIFICATE_ACTOR", "panel-certificate-test")
        .env(
            "RELAY_PANEL_CERTIFICATE_ISSUANCE_ID",
            "01234567-89ab-4def-8123-456789abcdef",
        )
        .env("RELAY_PANEL_CERTIFICATE_GROUP_ID", "7")
        .env("RELAY_PANEL_CERTIFICATE_DOMAIN", "*.example.com")
        .env("RELAY_PANEL_CERTIFICATE_AUTHORIZATION_RECEIPT", &receipt)
        .env("RELAY_PANEL_CERTBOT_HARD_ABORT", "1")
        .env("CERTBOT_DOMAIN", "*.example.com")
        .env("CERTBOT_VALIDATION", "validation-token-123456")
        .process_group(0);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();

    assert_eq!(output.status.signal(), Some(libc::SIGKILL));
    assert!(
        !continued.exists(),
        "the simulated Certbot parent continued after the failed auth hook"
    );
    assert!(!receipt.exists());

    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(dir);
}
