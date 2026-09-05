use crate::config::NodeConfig;
use crate::forwarder::camouflage_site::CamouflageSiteManager;
use crate::forwarder::ForwarderManager;
use crate::panel_certificate::PanelCertificateSync;
use crate::poller;
use crate::reconciler::{Reconciler, ReconciliationInput, ReconciliationState};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Instant};
use tokio_tungstenite::tungstenite::Message;

/// Send a Ping every this many seconds. Must be comfortably shorter than the
/// panel's READ_TIMEOUT (120s) and any reverse-proxy/CDN idle timeout (often
/// 60s), so the connection is never seen as idle and dropped.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
/// If no Pong arrives within this many seconds after a Ping, assume the
/// connection is dead and force a reconnect (rather than waiting for the
/// panel's 120s timeout to notice).
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

fn spawn_lifecycle_work<F>(work: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(work)
}

fn boot_confirmation_ack(text: &str) -> Option<relay_shared::protocol::NodeLifecycleAck> {
    serde_json::from_str(text)
        .ok()
        .filter(|ack: &relay_shared::protocol::NodeLifecycleAck| {
            ack.msg_type == "node_lifecycle_ack"
        })
}

/// Derive the WebSocket URL from PANEL_URL.
/// http://ip:port -> ws://ip:port/api/v1/node/ws
/// https://domain -> wss://domain/api/v1/node/ws
fn derive_ws_url(panel_url: &str) -> String {
    let url = panel_url.trim_end_matches('/');
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{}/api/v1/node/ws", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{}/api/v1/node/ws", rest)
    } else {
        // No scheme — assume ws://
        format!("ws://{}/api/v1/node/ws", url)
    }
}

/// Run the WebSocket control channel with automatic reconnection.
/// Exponential backoff: 1s initial, 30s max for transient errors.
/// Permanent errors (426 protocol mismatch, 401/403 auth) use a 5-minute
/// backoff — polling fast is pointless because the only fix is an upgrade or
/// reconfiguration.
///
/// This runs in a separate tokio task alongside the HTTP poller.
/// If WS fails (panel down, bad reverse proxy, CDN blocking), the node
/// continues forwarding with the last known config.
pub async fn run_ws_loop(
    config: &NodeConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    reconciler: &Arc<Mutex<Reconciler>>,
    panel_certificate_sync: &Arc<Mutex<PanelCertificateSync>>,
    node_id: &str,
) {
    let ws_url = derive_ws_url(&config.panel_url);
    let mut backoff = 1u64;
    const PERMANENT_BACKOFF_SECS: u64 = 300; // 5 minutes
                                             // Log dedup: avoid re-logging the SAME permanent error every backoff cycle.
                                             // The message is stored; if the next exit is the same, we skip the log.
    let mut last_permanent_msg: Option<String> = None;

    loop {
        tracing::info!("websocket connecting to {} ...", ws_url);

        let exit = connect_and_run(
            &ws_url,
            &config.token,
            config,
            manager,
            camouflage,
            reconciler,
            panel_certificate_sync,
            node_id,
        )
        .await;
        match exit {
            WsExit::ConfigChanged => {
                tracing::info!("websocket: config_changed received, reconnecting immediately");
                backoff = 1;
                last_permanent_msg = None;
            }
            WsExit::Disconnected => {
                tracing::warn!(
                    "websocket disconnected, reconnecting in {} seconds",
                    backoff
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                last_permanent_msg = None;
            }
            WsExit::PermanentError(msg) => {
                // 426 / 401 / 403: configuration or version problem that won't
                // fix itself. Back off 5 minutes. Dedup the log so it doesn't
                // repeat every cycle.
                if last_permanent_msg.as_deref() != Some(msg.as_str()) {
                    tracing::warn!(
                        "websocket permanent error: {} — backing off {}s (upgrade or reconfigure to fix)",
                        msg,
                        PERMANENT_BACKOFF_SECS
                    );
                    last_permanent_msg = Some(msg);
                }
                tokio::time::sleep(Duration::from_secs(PERMANENT_BACKOFF_SECS)).await;
                // Don't touch `backoff` — it's for transient errors only.
            }
            WsExit::Error(e) => {
                tracing::warn!(
                    "websocket error: {}, reconnecting in {} seconds",
                    e,
                    backoff
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                last_permanent_msg = None;
            }
        }
    }
}

enum WsExit {
    ConfigChanged,
    Disconnected,
    /// A permanent error (426 protocol mismatch, 401/403 auth). The node backs
    /// off 5 minutes — the only fix is an upgrade or reconfiguration.
    PermanentError(String),
    /// A transient error (network, 5xx, proxy hiccup). Standard exponential
    /// backoff.
    Error(String),
}

/// Classify a tungstenite connect error into PermanentError (426/401/403) or
/// transient Error. 426 = config protocol mismatch; 401/403 = auth. These
/// won't fix themselves on retry, so the caller backs off 5 minutes. 5xx and
/// network errors are transient (standard exponential backoff).
fn classify_ws_connect_error(e: tokio_tungstenite::tungstenite::Error) -> WsExit {
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use tokio_tungstenite::tungstenite::Error;

    if let Error::Http(resp) = &e {
        let status = resp.status();
        match status {
            StatusCode::UPGRADE_REQUIRED => {
                // Try to parse the structured body for a better message.
                let required = resp
                    .body()
                    .as_ref()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                    .as_ref()
                    .and_then(|d| d.get("required"))
                    .and_then(|v| v.as_u64());
                WsExit::PermanentError(format!(
                    "config protocol mismatch (panel requires v{:?}, node has v{}) — upgrade relay-node",
                    required,
                    relay_shared::protocol::CONFIG_PROTOCOL_VERSION
                ))
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => WsExit::PermanentError(format!(
                "authentication rejected (HTTP {}): invalid or revoked token",
                status.as_u16()
            )),
            _ => WsExit::Error(format!("connect: HTTP {} from panel", status.as_u16())),
        }
    } else {
        WsExit::Error(format!("connect: {}", e))
    }
}

async fn connect_and_run(
    ws_url: &str,
    token: &str,
    config: &NodeConfig,
    manager: &Arc<Mutex<ForwarderManager>>,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    reconciler: &Arc<Mutex<Reconciler>>,
    panel_certificate_sync: &Arc<Mutex<PanelCertificateSync>>,
    node_id: &str,
) -> WsExit {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    // Build the WebSocket handshake request from the URL. `IntoClientRequest`
    // (implemented for &str/String) generates ALL the standard handshake
    // headers tungstenite requires: Host, Upgrade, Connection,
    // Sec-WebSocket-Key, Sec-WebSocket-Version. We must NOT set any of those
    // manually — overriding them (especially the per-request random
    // Sec-WebSocket-Key) is exactly what produced
    //   "WebSocket protocol error: Missing, duplicated or incorrect header
    //    sec-websocket-key"
    // against the OpenResty reverse proxy. Only add our app-level headers.
    let mut request = match ws_url.into_client_request() {
        Ok(req) => req,
        Err(e) => return WsExit::Error(format!("request build: {}", e)),
    };

    // Authorization: Bearer <token> is REQUIRED by the panel's
    // node_ws_handler; without it the upgrade returns 401.
    if let Ok(v) = format!("Bearer {}", token).parse() {
        request.headers_mut().insert("Authorization", v);
    }
    // v0.4.0: config-protocol version gate. The panel refuses the upgrade
    // (426) if this is absent or mismatches, so an old node keeps its cached
    // config instead of receiving fields it can't deserialize.
    if let Ok(v) = relay_shared::protocol::CONFIG_PROTOCOL_VERSION
        .to_string()
        .parse()
    {
        request.headers_mut().insert("X-Config-Protocol-Version", v);
    }
    // Lifecycle protocol is intentionally independent from config protocol. A
    // future config bump may put this connection into upgrade-only mode, but
    // the Panel must still be able to deliver a signed/validated Node upgrade.
    if let Ok(v) = relay_shared::control_protocol::LIFECYCLE_PROTOCOL_VERSION
        .to_string()
        .parse()
    {
        request
            .headers_mut()
            .insert("X-Lifecycle-Protocol-Version", v);
    }
    if let Ok(v) = "relay-node-ws".parse() {
        request.headers_mut().insert("User-Agent", v);
    }
    // v0.4.14: optional per-node identity so the panel can target diagnosis at a
    // SPECIFIC node (not the whole group). This is an OPTIONAL extension — it
    // does NOT change the config structure, so CONFIG_PROTOCOL_VERSION is
    // unchanged. An older node that omits this still connects fine; it just
    // can't be targeted by directed diagnosis (the panel surfaces "upgrade").
    if !node_id.is_empty() {
        if let Ok(v) = node_id.parse() {
            request.headers_mut().insert("X-Node-ID", v);
        }
    }
    if let Ok(value) = env!("CARGO_PKG_VERSION").parse() {
        request.headers_mut().insert("X-Node-Version", value);
    }
    if let Ok(value) = std::env::consts::ARCH.parse() {
        request.headers_mut().insert("X-Node-Architecture", value);
    }

    let ws_result = connect_async(request).await;

    let (mut ws_stream, _response) = match ws_result {
        Ok(c) => {
            tracing::info!("websocket connected");
            c
        }
        Err(e) => {
            // v0.4.0: distinguish permanent HTTP errors (426/401/403) from
            // transient ones. tungstenite gives us the HTTP response for non-101
            // upgrades via Error::Http(response).
            return classify_ws_connect_error(e);
        }
    };

    let mut pending_boot_confirmation = None;
    if let Some((event, marker)) = crate::lifecycle::pending_boot_event() {
        if event.node_id == node_id {
            let payload = match serde_json::to_string(&event) {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::error!("serialize lifecycle boot event: {error}");
                    return WsExit::Disconnected;
                }
            };
            if ws_stream.send(Message::Text(payload.into())).await.is_err() {
                return WsExit::Disconnected;
            }
            pending_boot_confirmation = Some((event, marker));
        } else {
            tracing::error!(
                "lifecycle marker belongs to node {}, current node is {}; preserving marker",
                event.node_id,
                node_id
            );
        }
    }

    // ── Heartbeat state ──
    // All timestamps are millis relative to `session_start` (a monotonic
    // Instant captured once per connection). We avoid SystemTime (can jump
    // backwards on NTP sync) and Instant::now() confusion. AtomicU64 so the
    // heartbeat arm and message arm read/write without a lock.
    let session_start = Instant::now();
    let now_ms = || session_start.elapsed().as_millis() as u64;
    let last_pong = AtomicU64::new(now_ms()); // last time we got a Pong
    let last_ping = AtomicU64::new(0u64); // last time we sent a Ping; 0 = none outstanding
    let mut heartbeat = interval(HEARTBEAT_INTERVAL);
    // Don't fire immediately on the first tick (we just connected).
    heartbeat.reset();
    let mut boot_confirmation_retry = interval(Duration::from_secs(10));
    boot_confirmation_retry.reset();
    let (lifecycle_tx, mut lifecycle_rx) =
        mpsc::unbounded_channel::<relay_shared::protocol::NodeLifecycleEvent>();
    let lifecycle_lock = Arc::new(Mutex::new(()));

    loop {
        tokio::select! {
            // ── Incoming messages ──
            msg_result = ws_stream.next() => {
                let Some(msg_result) = msg_result else {
                    // Stream ended (server closed without a Close frame).
                    return WsExit::Disconnected;
                };
                match msg_result {
                    Ok(Message::Text(text)) => {
                        if let Some(ack) = boot_confirmation_ack(&text) {
                            if let Some((event, marker)) = pending_boot_confirmation.as_ref() {
                                if crate::lifecycle::boot_ack_matches(event, &ack) {
                                    crate::lifecycle::clear_pending_boot_event(marker);
                                    pending_boot_confirmation = None;
                                    tracing::info!(
                                        "websocket: lifecycle boot confirmation acknowledged"
                                    );
                                }
                            }
                            continue;
                        }
                        if let Ok(resp) =
                            serde_json::from_str::<relay_shared::protocol::NodeConfigSnapshot>(&text)
                        {
                            tracing::info!(
                                "websocket: received config ({} listeners), applying",
                                resp.listeners.len()
                            );
                            if apply_snapshot(manager, camouflage, reconciler, resp).await {
                                tracing::info!("websocket: config applied and committed as LKG");
                                sync_panel_certificates(
                                    panel_certificate_sync,
                                    config,
                                    node_id,
                                    camouflage,
                                )
                                .await;
                            } else {
                                tracing::warn!("websocket: config apply/commit failed; preserving LKG");
                            }
                        } else if text.contains("config_changed") {
                            tracing::info!("websocket: config_changed received, re-fetching");
                            match poller::fetch_config(config).await {
                                poller::FetchResult::Ok(resp) => {
                                    if apply_snapshot(manager, camouflage, reconciler, resp).await {
                                        tracing::info!("websocket: config applied after config_changed");
                                        sync_panel_certificates(
                                            panel_certificate_sync,
                                            config,
                                            node_id,
                                            camouflage,
                                        )
                                        .await;
                                    } else {
                                        tracing::warn!("websocket: config_changed apply/commit failed; preserving LKG");
                                    }
                                }
                                poller::FetchResult::ProtocolMismatch => {
                                    tracing::warn!("websocket: config fetch returned protocol mismatch; keeping cached config");
                                }
                                poller::FetchResult::Transient => {
                                    tracing::warn!("websocket: config fetch failed transiently; keeping cached config");
                                }
                            }
                            return WsExit::ConfigChanged;
                        } else if let Some(rm) =
                            serde_json::from_str::<relay_shared::protocol::RestartRuleMessage>(&text)
                                .ok()
                                .filter(|rm| rm.msg_type == "restart_rule")
                        {
                            // v1.2.0: restart ONE rule's listeners and drop its
                            // connections.
                            //
                            // This arm MUST stay ABOVE the diagnose arm, and MUST
                            // check msg_type. DiagnoseRuleMessage defaults its
                            // `challenge` field and ignores unknown fields, so a
                            // restart_rule payload deserializes into it cleanly
                            // (rule_id + request_id are both present) — order it
                            // after diagnose and every restart silently becomes a
                            // target probe instead.
                            //
                            // send_node already routed this to us; re-check as
                            // defence in depth (same as upgrade_node below).
                            if rm.node_id != node_id {
                                tracing::warn!(
                                    "websocket: ignoring restart of rule {} for node {} (I am {})",
                                    rm.rule_id,
                                    rm.node_id,
                                    node_id
                                );
                            } else {
                                tracing::info!(
                                    "websocket: restart_rule request_id={} rule_id={}",
                                    rm.request_id,
                                    rm.rule_id
                                );
                                // Held across the restart: apply_config takes the
                                // same lock, so a concurrent config push cannot
                                // interleave with the teardown/rebuild.
                                let mut mgr = manager.lock().await;
                                let (dropped, restarted) = mgr.restart_rule(rm.rule_id).await;
                                tracing::info!(
                                    "websocket: restart_rule request_id={} rule_id={} done \
                                     ({} connection(s) dropped, {} listener(s) rebuilt)",
                                    rm.request_id,
                                    rm.rule_id,
                                    dropped,
                                    restarted
                                );
                            }
                        } else if let Some(command) = serde_json::from_str::<
                            relay_shared::protocol::ReapplyNginxSniMessage,
                        >(&text)
                        .ok()
                        .filter(|command| command.msg_type == "reapply_nginx_sni")
                        {
                            if command.node_id != node_id {
                                tracing::warn!(
                                    "websocket: ignoring nginx_sni reapply for another node"
                                );
                            } else {
                                tracing::info!(
                                    "websocket: reapply_nginx_sni request_id={} rule_id={}",
                                    command.request_id,
                                    command.rule_id
                                );
                                let mgr = manager.clone();
                                let cfg = config.clone();
                                let nid = node_id.to_string();
                                tokio::spawn(async move {
                                    crate::reapply::run_and_report(
                                        &mgr,
                                        &cfg,
                                        &nid,
                                        command.request_id,
                                        command.rule_id,
                                        command.challenge,
                                    )
                                    .await;
                                });
                            }
                        } else if let Some(command) = serde_json::from_str::<
                            relay_shared::protocol::NodeLifecycleCommand,
                        >(&text)
                        .ok()
                        .filter(|command| command.msg_type == "node_lifecycle")
                        {
                            if command.node_id != node_id {
                                tracing::warn!(
                                    operation_id = %command.operation_id,
                                    "websocket: lifecycle command targeted another node"
                                );
                                continue;
                            }
                            let guard = if command.action
                                == relay_shared::protocol::NodeLifecycleAction::Logs
                            {
                                None
                            } else {
                                match lifecycle_lock.clone().try_lock_owned() {
                                    Ok(guard) => Some(guard),
                                    Err(_) => {
                                        let _ = lifecycle_tx.send(
                                            crate::lifecycle::failed_event(
                                                &command,
                                                "another destructive lifecycle action is running",
                                            ),
                                        );
                                        continue;
                                    }
                                }
                            };
                            if command.action
                                != relay_shared::protocol::NodeLifecycleAction::Logs
                            {
                                let accepted = crate::lifecycle::accepted_event(&command);
                                if ws_stream
                                    .send(Message::Text(
                                        serde_json::to_string(&accepted)
                                            .expect("lifecycle event serializes")
                                            .into(),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    return WsExit::Disconnected;
                                }
                            }
                            let tx = lifecycle_tx.clone();
                            let config = config.clone();
                            spawn_lifecycle_work(async move {
                                crate::lifecycle::execute(config, command, tx).await;
                                drop(guard);
                            });
                        } else if let Ok(dm) =
                            serde_json::from_str::<relay_shared::protocol::DiagnoseRuleMessage>(&text)
                        {
                            // v0.4.8: rule diagnosis request from the panel.
                            // Run the probe on a detached task so the WS loop
                            // keeps draining messages; the result is POSTed back
                            // over HTTP by diagnose::run_and_report.
                            // v0.4.9: the message carries a per-run `challenge`
                            // the node MUST echo back verbatim; the panel rejects
                            // a result without an exact match.
                            tracing::info!(
                                "websocket: diagnose_rule request_id={} rule_id={}",
                                dm.request_id,
                                dm.rule_id
                            );
                            let cfg = config.clone();
                            let mgr = manager.clone();
                            let sites = camouflage.clone();
                            let nid = node_id.to_string();
                            let req_id = dm.request_id.clone();
                            let rid = dm.rule_id;
                            let desired_sni = dm.desired_sni.clone();
                            let desired_revision = dm.config_revision;
                            let desired_fingerprint = dm.config_fingerprint.clone();
                            let challenge = dm.challenge.clone();
                            let reconciler = reconciler.clone();
                            tokio::spawn(async move {
                                crate::diagnose::run_and_report(
                                    &mgr, &sites, &reconciler, &cfg, &nid, req_id, rid,
                                    desired_sni, desired_revision, desired_fingerprint, challenge,
                                )
                                .await;
                            });
                        } else {
                            tracing::debug!("websocket: received text: {}", &text[..text.len().min(100)]);
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        // Server replied to our Ping — connection is alive.
                        last_pong.store(now_ms(), Ordering::Relaxed);
                        last_ping.store(0, Ordering::Relaxed);
                        tracing::debug!("websocket: pong received");
                    }
                    Ok(Message::Ping(_)) => {
                        // tungstenite auto-responds to server pings with a pong.
                    }
                    Ok(Message::Close(_)) => {
                        return WsExit::Disconnected;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return WsExit::Error(format!("stream: {}", e));
                    }
                }
            }

            lifecycle_event = lifecycle_rx.recv() => {
                let Some(event) = lifecycle_event else {
                    return WsExit::Disconnected;
                };
                let payload = match serde_json::to_string(&event) {
                    Ok(payload) => payload,
                    Err(error) => {
                        tracing::error!("serialize lifecycle event: {error}");
                        continue;
                    }
                };
                if ws_stream.send(Message::Text(payload.into())).await.is_err() {
                    return WsExit::Disconnected;
                }
            }

            _ = boot_confirmation_retry.tick(), if pending_boot_confirmation.is_some() => {
                let (event, _) = pending_boot_confirmation
                    .as_ref()
                    .expect("pending boot confirmation was checked");
                let payload = match serde_json::to_string(event) {
                    Ok(payload) => payload,
                    Err(error) => {
                        tracing::error!("serialize lifecycle boot confirmation: {error}");
                        continue;
                    }
                };
                if ws_stream.send(Message::Text(payload.into())).await.is_err() {
                    return WsExit::Disconnected;
                }
            }

            // ── Heartbeat tick (every HEARTBEAT_INTERVAL) ──
            _ = heartbeat.tick() => {
                // Before sending this ping, check if the PREVIOUS ping is still
                // unanswered past PONG_TIMEOUT. We capture the old last_ping
                // value BEFORE overwriting it with the new one.
                let prev_ping = last_ping.load(Ordering::Relaxed);
                let last_pong_val = last_pong.load(Ordering::Relaxed);
                let now = now_ms();

                if prev_ping != 0
                    && last_pong_val < prev_ping
                    && now.saturating_sub(prev_ping) > PONG_TIMEOUT.as_millis() as u64
                {
                    // The previous ping (sent HEARTBEAT_INTERVAL ago) never got
                    // a Pong within PONG_TIMEOUT — the connection is dead.
                    tracing::warn!(
                        "websocket: heartbeat timeout (no pong within {}s), reconnecting",
                        PONG_TIMEOUT.as_secs()
                    );
                    return WsExit::Disconnected;
                }

                // Send a fresh Ping and record when we sent it.
                if let Err(e) = ws_stream.send(Message::Ping(Vec::new().into())).await {
                    return WsExit::Error(format!("ping send: {}", e));
                }
                last_ping.store(now, Ordering::Relaxed);
                tracing::debug!("websocket: ping sent");
            }
        }
    }
}

async fn sync_panel_certificates(
    sync: &Arc<Mutex<PanelCertificateSync>>,
    config: &NodeConfig,
    node_id: &str,
    camouflage: &Arc<Mutex<CamouflageSiteManager>>,
) {
    if let Err(error) = sync.lock().await.sync(config, node_id, camouflage).await {
        tracing::warn!(
            "websocket: Panel certificate sync failed; retaining active certificate and LKG: {error}"
        );
    }
}

/// WebSocket snapshots intentionally share the HTTP poll's apply-then-commit
/// path. The cache is never updated merely because a socket delivered JSON.
async fn apply_snapshot(
    manager: &std::sync::Arc<tokio::sync::Mutex<crate::forwarder::ForwarderManager>>,
    camouflage: &std::sync::Arc<tokio::sync::Mutex<CamouflageSiteManager>>,
    reconciler: &std::sync::Arc<tokio::sync::Mutex<Reconciler>>,
    config: relay_shared::protocol::NodeConfigSnapshot,
) -> bool {
    let input = match ReconciliationInput::validated_panel_snapshot(config) {
        Ok(input) => input,
        Err(error) => {
            tracing::warn!("websocket: refusing untrusted config snapshot: {}", error);
            return false;
        }
    };
    reconciler
        .lock()
        .await
        .reconcile(manager, camouflage, input)
        .await
        .state
        != ReconciliationState::ApplyFailed
}

#[cfg(test)]
async fn apply_snapshot_at(
    manager: &std::sync::Arc<tokio::sync::Mutex<crate::forwarder::ForwarderManager>>,
    config: &relay_shared::protocol::NodeConfigResponse,
    paths: &poller::CachePaths,
) -> bool {
    poller::apply_and_commit_at(manager, config, paths).await
}

#[cfg(test)]
mod tests {
    use super::{apply_snapshot_at, boot_confirmation_ack, derive_ws_url, spawn_lifecycle_work};
    use crate::forwarder::ForwarderManager;
    use crate::poller::{self, CachePaths};
    use crate::reporter::{ConnectionTracker, TrafficCounter};
    use relay_shared::protocol::{
        ListenerConfig, LoadBalanceStrategy, NodeConfigResponse, NodeLifecycleAck,
        NodeLifecycleAction, NodeLifecycleCommand, NodeTransport, Protocol,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    /// v0.4.16: the WSS control-channel URL is derived from PANEL_URL. The
    /// https→wss mapping is the half that crosses the TLS provider, so pin it
    /// — a regression here would make every WSS node fail to connect even with
    /// the provider fixed.
    #[test]
    fn derive_ws_url_maps_schemes() {
        assert_eq!(
            derive_ws_url("https://panel.example.com"),
            "wss://panel.example.com/api/v1/node/ws"
        );
        assert_eq!(
            derive_ws_url("https://panel.example.com/"),
            "wss://panel.example.com/api/v1/node/ws"
        );
        assert_eq!(
            derive_ws_url("http://127.0.0.1:18888"),
            "ws://127.0.0.1:18888/api/v1/node/ws"
        );
        // No scheme → assume ws:// (matches the node's default PANEL_URL).
        assert_eq!(
            derive_ws_url("127.0.0.1:18888"),
            "ws://127.0.0.1:18888/api/v1/node/ws"
        );
    }

    #[test]
    fn only_explicit_boot_ack_messages_are_consumed_as_acknowledgements() {
        let command = NodeLifecycleCommand {
            msg_type: "node_lifecycle".into(),
            operation_id: "operation-1".into(),
            node_id: "node-a".into(),
            action: NodeLifecycleAction::Upgrade,
            target_version: Some("1.2.4".into()),
            target_architecture: Some("amd64".into()),
            sha256: Some("0".repeat(64)),
            artifact_id: Some("operation-1".into()),
            log_lines: None,
        };
        assert!(boot_confirmation_ack(&serde_json::to_string(&command).unwrap()).is_none());

        let ack = NodeLifecycleAck {
            msg_type: "node_lifecycle_ack".into(),
            operation_id: command.operation_id,
            node_id: command.node_id,
            action: command.action,
        };
        assert_eq!(
            boot_confirmation_ack(&serde_json::to_string(&ack).unwrap())
                .unwrap()
                .msg_type,
            "node_lifecycle_ack"
        );
    }

    #[tokio::test]
    async fn lifecycle_work_is_detached_from_the_websocket_reader() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let task = spawn_lifecycle_work(async move {
            let _ = started_tx.send(());
            let _ = release_rx.await;
        });
        tokio::time::timeout(Duration::from_millis(100), started_rx)
            .await
            .expect("lifecycle task must start without blocking the reader")
            .expect("lifecycle task reports readiness");
        let _ = release_tx.send(());
        task.await.unwrap();
    }

    fn cache_paths(label: &str) -> CachePaths {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "relay-panel-ws-lkg-{label}-{}-{stamp}",
            std::process::id()
        ));
        CachePaths {
            primary: dir.join("config-cache.json"),
            backup: dir.join("config-cache.backup.json"),
            tmp: dir.join("config-cache.json.tmp"),
        }
    }

    fn manager() -> Arc<Mutex<ForwarderManager>> {
        Arc::new(Mutex::new(ForwarderManager::new(
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
        )))
    }

    #[tokio::test]
    async fn ws_successful_snapshot_persists_lkg() {
        let paths = cache_paths("success");
        let snapshot = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![],
        };

        assert!(apply_snapshot_at(&manager(), &snapshot, &paths).await);
        assert!(paths.primary.exists());
        assert!(poller::load_cache_at(&paths).unwrap().listeners.is_empty());
        let _ = std::fs::remove_dir_all(paths.primary.parent().unwrap());
    }

    #[tokio::test]
    async fn ws_failed_apply_does_not_replace_lkg() {
        let paths = cache_paths("failure");
        let old = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![ListenerConfig {
                camouflage_required: false,
                send_proxy_protocol: false,
                rule_id: 1,
                port: 22001,
                protocol: Protocol::Tcp,
                node_transport: NodeTransport::Raw,
                ws_path: None,
                sni: None,
                targets: vec!["127.0.0.1:9".to_string()],
                load_balance_strategy: LoadBalanceStrategy::First,
                upload_limit_bps: None,
                download_limit_bps: None,
                max_connections: None,
            }],
        };
        poller::commit_cache_at(&old, &paths).unwrap();
        let invalid = NodeConfigResponse {
            camouflage_sites: vec![],
            listeners: vec![ListenerConfig {
                camouflage_required: false,
                send_proxy_protocol: false,
                port: 0,
                ..old.listeners[0].clone()
            }],
        };

        assert!(!apply_snapshot_at(&manager(), &invalid, &paths).await);
        assert_eq!(
            poller::load_cache_at(&paths).unwrap().listeners[0].rule_id,
            1
        );
        let _ = std::fs::remove_dir_all(paths.primary.parent().unwrap());
    }
}
