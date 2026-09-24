// UDP forwarding engine with session-based routing.
//
// Architecture per listen port:
//   - One bound UdpSocket `inbound`  (clients send to this)
//   - Per-client source addr, a dedicated UdpSocket `outbound` connected to the
//     chosen target. The outbound socket is used to both send datagrams to the
//     target AND receive the target's replies; replies are then forwarded back
//     to the client through `inbound`.
//
// This yields correct bidirectional UDP for protocols like DNS/QUIC where the
// reply comes from the target. A periodic task expires idle sessions.
//
// Session accounting: each unique (client_addr, rule_id) is one "connection"
// from the panel's point of view. We register/refresh it on every datagram
// via ConnectionTracker::udp_touch, and the tracker expires it after
// UDP_SESSION_TIMEOUT (60s) of inactivity. This makes the panel's
// "connections" column reflect real UDP activity instead of always 0.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::fmt::Display;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;

use super::limiter::RateLimit;
use super::selector::TargetSelector;
use crate::reporter::{ConnectionTracker, TrafficCounter, UDP_SESSION_TIMEOUT};

const UDP_BUF_SIZE: usize = 65535;
/// How often the periodic sweeper runs. Sessions themselves expire on the
/// shared UDP_SESSION_TIMEOUT; this just controls how quickly an idle node
// converges back to 0 in the absence of new datagrams.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);

struct UdpSession {
    outbound: Arc<UdpSocket>,
    last_active: tokio::time::Instant,
}

/// v1.0.4: serve an ALREADY-BOUND UDP socket. Binding happens in the manager
/// (synchronously, so errors surface immediately and per-family success is
/// known). This function only runs the receive loop.
#[allow(clippy::too_many_arguments)]
pub async fn serve_udp_listener(
    inbound: Arc<UdpSocket>,
    targets: Vec<String>,
    selector: Arc<TargetSelector>,
    rate_limit: RateLimit,
    counter: Arc<TrafficCounter>,
    connections: Arc<ConnectionTracker>,
    config_revision: u64,
    rule_id: i64,
    source_ipv4: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr = inbound
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    if targets.is_empty() {
        tracing::warn!("UDP listener on {}: no targets configured", listen_addr);
    }
    tracing::info!("UDP listening on {} (rule {})", listen_addr, rule_id);

    let port = listen_addr.port();

    // v1.2.x: targets are resolved LAZILY per new session (see
    // open_udp_session) rather than once here at listener start. The old
    // boot-time resolution pinned a DDNS target to whatever IP it had when the
    // rule was pushed; the IP never refreshed until the rule/node restarted,
    // silently blackholing UDP (WireGuard / game / DNS-forward) traffic after a
    // DDNS update. Session-time resolution goes through the shared 30s DNS cache
    // so new sessions follow IP changes automatically.

    // v1.0.9: sharded concurrent map — per-packet lookups take a per-shard lock
    // (keyed by client addr) instead of one listener-wide mutex, so datagrams
    // from different clients don't serialize on each other.
    let sessions: Arc<DashMap<SocketAddr, UdpSession>> = Arc::new(DashMap::new());

    // Background cleanup of expired local session entries (outbound sockets).
    // This mirrors the ConnectionTracker's own expiry; together they make sure
    // idle UDP state is reclaimed promptly.
    let sessions_clone = sessions.clone();
    let connections_clone = connections.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            // Prune the tracker's session table (drops expired (addr,rule)
            // entries, which is what the panel's count ultimately reads).
            connections_clone.udp_prune_expired().await;
            // Drop our local outbound sockets for clients whose local entry is
            // older than the timeout. The tracker already stopped counting
            // them; here we release the socket resources too.
            let before = sessions_clone.len();
            sessions_clone.retain(|_, s| s.last_active.elapsed() < UDP_SESSION_TIMEOUT);
            // saturating: len() is read across shards without a global lock, so a
            // concurrent insert between the two reads must not underflow usize.
            let removed = before.saturating_sub(sessions_clone.len());
            if removed > 0 {
                tracing::debug!(
                    "UDP port {}: cleaned up {} expired outbound sockets",
                    port,
                    removed
                );
            }
        }
    });

    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        // v0.3.6: recv_from resilience. A transient error used to `?`-propagate
        // and kill the listener task, leaving the UDP port dead. Now transient
        // errors back off and retry; only a permanent error ends the task (and
        // the manager's is_finished recovery can restart it).
        let (n, src) = match inbound.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if is_transient_recv_error(&e) => {
                tracing::warn!(
                    "UDP listener on {} (rule {}): transient recv_from error: {}; retrying in 100ms",
                    listen_addr,
                    rule_id,
                    e
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        };

        // Register/refresh this client with the tracker on EVERY datagram. The
        // tracker is a sharded DashMap (keyed by client+rule), so this is a cheap
        // per-shard op — not a process-wide lock — and keeps the panel's count
        // accurate without any throttling.
        connections.udp_touch(src, rule_id).await;

        // Fast path: existing session. The session map is a sharded DashMap, so
        // this per-packet lookup takes only a per-shard lock (sync guard, dropped
        // before any .await).
        let existing = sessions.get_mut(&src).map(|mut s| {
            s.last_active = tokio::time::Instant::now();
            s.outbound.clone()
        });

        let outbound_sock = if let Some(sock) = existing {
            sock
        } else {
            // New session: bind one ephemeral outbound socket, then resolve and
            // connect candidates in selector order, all without a map guard.
            let (outbound, target) =
                match open_udp_session(source_ipv4, &targets, &selector, port).await {
                    Ok(Some(session)) => session,
                    Ok(None) => {
                        tracing::warn!("UDP port {}: no connectable target for session", port);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("UDP port {}: failed to bind outbound: {}", port, e);
                        continue;
                    }
                };
            let outbound = Arc::new(outbound);

            // Publish via the entry API (per-shard lock, sync — no .await while
            // the guard is held). Double-check for a concurrent datagram from the
            // same client that won the race while we were connecting: if one did,
            // use the winner and drop ours.
            let now = tokio::time::Instant::now();
            let (chosen, we_won) = match sessions.entry(src) {
                Entry::Occupied(mut e) => {
                    e.get_mut().last_active = now;
                    (e.get().outbound.clone(), false)
                }
                Entry::Vacant(e) => {
                    e.insert(UdpSession {
                        outbound: outbound.clone(),
                        last_active: now,
                    });
                    (outbound.clone(), true)
                }
            };

            if we_won {
                // The tracker was already refreshed at the top of the loop; just
                // log the new session (the target is known only on this path).
                tracing::debug!(
                    "UDP port {}: new session {} -> {} (rule {})",
                    port,
                    src,
                    target,
                    rule_id
                );
                // Spawn the target -> client reader for OUR socket.
                let inbound_c = inbound.clone();
                let sessions_c = sessions.clone();
                let connections_c = connections.clone();
                let counter_c = counter.clone();
                let rl_c = rate_limit.clone();
                let src_c = src;
                let outbound_c = outbound.clone();
                let port_c = port;
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; UDP_BUF_SIZE];
                    loop {
                        match outbound_c.recv(&mut rbuf).await {
                            Ok(m) => {
                                // v0.4.6: throttle target→client (download) bytes
                                // through the shared per-rule limiter BEFORE
                                // forwarding back to the client.
                                rl_c.acquire_download(m as u64).await;
                                counter_c
                                    .add_at(config_revision, rule_id, 0, m as u64)
                                    .await;
                                // A reply is activity too: refresh the tracker
                                // (cheap, sharded) and the session's last_active
                                // so a long request/response flow isn't expired.
                                connections_c.udp_touch(src_c, rule_id).await;
                                if inbound_c.send_to(&rbuf[..m], src_c).await.is_err() {
                                    break;
                                }
                                if let Some(mut s) = sessions_c.get_mut(&src_c) {
                                    s.last_active = tokio::time::Instant::now();
                                }
                            }
                            Err(e) => {
                                tracing::debug!("UDP port {}: outbound recv ended: {}", port_c, e);
                                break;
                            }
                        }
                    }
                    // Outbound side ended (target closed / error): release this
                    // client's session immediately rather than waiting for timeout.
                    sessions_c.remove(&src_c);
                    connections_c.udp_close(src_c, rule_id).await;
                });
            }
            chosen
        };

        // Forward client datagram to target via the connected outbound socket.
        // v0.4.6: throttle client→target (upload) bytes through the shared
        // per-rule limiter BEFORE sending.
        rate_limit.acquire_upload(n as u64).await;
        if let Err(e) = outbound_sock.send(&buf[..n]).await {
            tracing::debug!("UDP port {}: send to target failed: {}", port, e);
        } else {
            counter.add_at(config_revision, rule_id, n as u64, 0).await;
        }
    }
}

/// Bind and connect the outbound socket for one NEW UDP session. Binding occurs
/// before selector.order(), so a local bind failure neither advances a
/// round-robin cursor nor changes target health.
async fn open_udp_session(
    source_ipv4: Option<Ipv4Addr>,
    targets: &[String],
    selector: &TargetSelector,
    port: u16,
) -> Result<Option<(UdpSocket, SocketAddr)>, super::outbound::OutboundError> {
    open_udp_session_with(
        source_ipv4,
        targets,
        selector,
        port,
        super::outbound::udp_outbound_socket,
        |target| async move { super::outbound::resolve_cached(&target).await },
        |socket, target| async move {
            match socket.connect(target).await {
                Ok(()) => Ok(socket),
                Err(error) => Err((socket, error)),
            }
        },
    )
    .await
}

/// Testable new-session state machine. The socket is returned after a failed
/// connect so the same single bind is reused for every candidate.
#[allow(clippy::too_many_arguments)]
async fn open_udp_session_with<
    S,
    Bind,
    BindFuture,
    Resolve,
    ResolveFuture,
    Connect,
    ConnectFuture,
    BindError,
    ResolveError,
    ConnectError,
>(
    source_ipv4: Option<Ipv4Addr>,
    targets: &[String],
    selector: &TargetSelector,
    port: u16,
    bind: Bind,
    mut resolve: Resolve,
    mut connect: Connect,
) -> Result<Option<(S, SocketAddr)>, BindError>
where
    Bind: FnOnce(Option<Ipv4Addr>) -> BindFuture,
    BindFuture: Future<Output = Result<S, BindError>>,
    Resolve: FnMut(String) -> ResolveFuture,
    ResolveFuture: Future<Output = Result<Vec<SocketAddr>, ResolveError>>,
    Connect: FnMut(S, SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<S, (S, ConnectError)>>,
    ResolveError: Display,
    ConnectError: Display,
{
    let mut socket = bind(source_ipv4).await?;
    for idx in selector.order() {
        let Some(target) = targets.get(idx) else {
            continue;
        };
        let addresses = match resolve(target.clone()).await {
            Ok(addresses) => addresses,
            Err(error) => {
                tracing::debug!(
                    "UDP port {}: failed to resolve target {}: {}",
                    port,
                    target,
                    error
                );
                continue;
            }
        };
        let Some(address) = addresses.into_iter().next() else {
            tracing::debug!(
                "UDP port {}: target {} resolved to no address",
                port,
                target
            );
            continue;
        };
        match connect(socket, address).await {
            Ok(connected) => {
                selector.report(idx, true);
                return Ok(Some((connected, address)));
            }
            Err((returned, error)) => {
                selector.report(idx, false);
                tracing::warn!(
                    "UDP port {}: failed to connect to target {} ({}): {}",
                    port,
                    target,
                    address,
                    error
                );
                socket = returned;
            }
        }
    }
    Ok(None)
}

/// Classify whether a `recv_from` error is worth retrying (mirrors the TCP
/// accept classifier). Transient OS-level resource exhaustion clears on its
/// own; retrying keeps the listener alive. A bad-fd / closed-socket error is
/// permanent and ends the task (the manager can restart it).
fn is_transient_recv_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ResourceBusy
    ) || e.raw_os_error().is_some_and(|c| {
        // EMFILE (24) / ENFILE (23) / ENOBUFS (105) / ENOMEM (12).
        matches!(c, 24 | 23 | 105 | 12)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::LoadBalanceStrategy;
    use std::io;
    use std::sync::Mutex;

    fn addr(index: u8) -> SocketAddr {
        format!("127.0.0.{index}:9").parse().unwrap()
    }

    #[tokio::test]
    async fn first_candidate_success_avoids_later_candidates() {
        let targets = vec!["first".to_string(), "second".to_string()];
        let selector = TargetSelector::new(LoadBalanceStrategy::Failover, 2);
        let resolved = Arc::new(Mutex::new(Vec::new()));
        let observed = resolved.clone();
        let result = open_udp_session_with(
            None,
            &targets,
            &selector,
            5000,
            |_| async { Ok::<_, io::Error>(7_u8) },
            move |target| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(target.clone());
                    Ok::<_, io::Error>(vec![if target == "first" { addr(1) } else { addr(2) }])
                }
            },
            |socket, _| async move { Ok::<_, (u8, io::Error)>(socket) },
        )
        .await
        .unwrap();
        assert_eq!(result.map(|(_, target)| target), Some(addr(1)));
        assert_eq!(*resolved.lock().unwrap(), vec!["first"]);
    }

    #[tokio::test]
    async fn connect_failure_falls_through_and_updates_selector_health() {
        let targets = vec!["first".to_string(), "second".to_string()];
        let selector = TargetSelector::new(LoadBalanceStrategy::Failover, 2);
        for _ in 0..3 {
            let result = open_udp_session_with(
                None,
                &targets,
                &selector,
                5000,
                |_| async { Ok::<_, io::Error>(()) },
                |target| async move {
                    Ok::<_, io::Error>(vec![if target == "first" { addr(1) } else { addr(2) }])
                },
                |socket, target| async move {
                    if target == addr(1) {
                        Err((
                            socket,
                            io::Error::new(io::ErrorKind::ConnectionRefused, "refused"),
                        ))
                    } else {
                        Ok(socket)
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(result.map(|(_, target)| target), Some(addr(2)));
        }
        assert_eq!(
            selector.order(),
            vec![1],
            "failed primary must enter circuit break"
        );
    }

    #[tokio::test]
    async fn resolve_failure_falls_through_without_circuit_penalty() {
        let targets = vec!["bad-dns".to_string(), "second".to_string()];
        let selector = TargetSelector::new(LoadBalanceStrategy::Failover, 2);
        for _ in 0..4 {
            let result = open_udp_session_with(
                None,
                &targets,
                &selector,
                5000,
                |_| async { Ok::<_, io::Error>(()) },
                |target| async move {
                    if target == "bad-dns" {
                        Err(io::Error::new(io::ErrorKind::NotFound, "dns failed"))
                    } else {
                        Ok(vec![addr(2)])
                    }
                },
                |socket, _| async move { Ok::<_, ((), io::Error)>(socket) },
            )
            .await
            .unwrap();
            assert_eq!(result.map(|(_, target)| target), Some(addr(2)));
            assert_eq!(selector.order(), vec![0, 1]);
        }
    }

    #[tokio::test]
    async fn local_bind_failure_does_not_advance_or_penalize_targets() {
        let targets = vec!["first".to_string(), "second".to_string()];
        let selector = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 2);
        let result = open_udp_session_with(
            None,
            &targets,
            &selector,
            5000,
            |_| async {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "bind failed",
                ))
            },
            |_| async { Ok::<_, io::Error>(vec![addr(1)]) },
            |socket, _| async move { Ok::<_, ((), io::Error)>(socket) },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(selector.order(), vec![0, 1]);
    }

    #[tokio::test]
    async fn round_robin_order_and_single_bind_are_preserved() {
        let targets = vec!["first".to_string(), "second".to_string()];
        let selector = TargetSelector::new(LoadBalanceStrategy::RoundRobin, 2);
        let binds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut selected = Vec::new();
        for _ in 0..2 {
            let binds = binds.clone();
            let result = open_udp_session_with(
                None,
                &targets,
                &selector,
                5000,
                move |_| {
                    let binds = binds.clone();
                    async move {
                        binds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok::<_, io::Error>(())
                    }
                },
                |target| async move {
                    Ok::<_, io::Error>(vec![if target == "first" { addr(1) } else { addr(2) }])
                },
                |socket, _| async move { Ok::<_, ((), io::Error)>(socket) },
            )
            .await
            .unwrap()
            .unwrap();
            selected.push(result.1);
        }
        assert_eq!(selected, vec![addr(1), addr(2)]);
        assert_eq!(binds.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn existing_session_stays_pinned_while_new_session_advances_round_robin() {
        let inbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let inbound_addr = inbound.local_addr().unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let targets = vec![
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ];
        let listener = tokio::spawn(serve_udp_listener(
            inbound,
            targets,
            Arc::new(TargetSelector::new(LoadBalanceStrategy::RoundRobin, 2)),
            RateLimit::new(None, None),
            Arc::new(TrafficCounter::new()),
            Arc::new(ConnectionTracker::new()),
            0,
            9,
            None,
        ));

        let client_one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_one.send_to(b"one", inbound_addr).await.unwrap();
        client_one.send_to(b"two", inbound_addr).await.unwrap();
        let mut buffer = [0_u8; 16];
        let first_len = time::timeout(Duration::from_secs(1), first.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..first_len], b"one");
        let second_len = time::timeout(Duration::from_secs(1), first.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..second_len], b"two");
        assert!(
            time::timeout(Duration::from_millis(50), second.recv(&mut buffer))
                .await
                .is_err(),
            "an existing session must not reselect its target"
        );

        let client_two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_two.send_to(b"three", inbound_addr).await.unwrap();
        let third_len = time::timeout(Duration::from_secs(1), second.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..third_len], b"three");

        listener.abort();
        let _ = listener.await;
    }
}
