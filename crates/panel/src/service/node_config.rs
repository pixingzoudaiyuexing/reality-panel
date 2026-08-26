//! Shared node-config builder for the HTTP poll path (`get_config`) and the
//! WebSocket push path (`build_config_snapshot`).
//!
//! **Why this exists (v0.3.6 fix):** v0.3.5 had TWO copies of "turn a device
//! group into a NodeConfigResponse". They drifted — the HTTP path JOINed
//! `users` (to drop banned / over-quota rules) but the WS path did NOT, so a
//! freshly-(re)connected node could be handed a banned user's rules until the
//! next HTTP poll corrected it. There was also duplicated target resolution +
//! `build_listeners_for_rule` wiring in both files.
//!
//! This module is the single source of truth. Both callers go through
//! [`build_node_config`], so the filter, target resolution, protocol expansion,
//! transport derivation and ws_path passthrough are identical by construction.
//!
//! Error policy: only a real inbound group with no active rules returns an
//! empty config. Authentication, group state, and build failures are explicit
//! errors so they can never tear down a node by masquerading as an empty plan.

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, ProfileScope, ResourceScope, TunnelProfileRepository};
use crate::db::Repository;
use relay_shared::models::{DeviceGroup, ForwardRule};
use relay_shared::protocol::{
    CamouflageCertificatePolicy, CamouflageLocalBackend, CamouflageSiteDesired, NodeConfigResponse,
};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum NodeConfigBuildError {
    Database(DbError),
    GroupNotFound,
    NotInboundGroup,
}

impl std::fmt::Display for NodeConfigBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database error: {}", e),
            Self::GroupNotFound => write!(f, "device group no longer exists"),
            Self::NotInboundGroup => write!(f, "device group is not inbound"),
        }
    }
}

impl std::error::Error for NodeConfigBuildError {}

impl From<DbError> for NodeConfigBuildError {
    fn from(value: DbError) -> Self {
        Self::Database(value)
    }
}

/// Build the full [`NodeConfigResponse`] for a device group.
///
/// This is the ONE function both `get_config` (HTTP) and `build_config_snapshot`
/// (WS) call. It performs, in order:
///
/// 1. Group lookup + "only `in` groups receive listeners" gate.
/// 2. Rule query with the unified filter:
///    - `device_group_in` matches the group
///    - `paused = 0`
///    - owning user `banned = 0`
///    - quota: `traffic_limit = 0` (unlimited) OR `traffic_used < traffic_limit`
/// 3. Per-rule target resolution (direct addr vs outbound group connect_host).
/// 4. [`relay_shared::protocol::build_listeners_for_rule`] for protocol
///    expansion + transport derivation + ws_path passthrough.
///
/// Returns `Ok(empty)` only for an existing inbound group with no matching
/// rules. Any other state is an explicit error.
pub async fn build_node_config(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigResponse, NodeConfigBuildError> {
    // 1. Group + "in" gate. Non-`in` groups (out / monitor / chained_outbound)
    //    never receive listeners — they are egress/observation only.
    // find_by_id exists on both UserRepository and GroupRepository; we want the
    // group one, so qualify the call.
    let group = match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(g) if g.group_type == "in" => g,
        Some(_) => return Err(NodeConfigBuildError::NotInboundGroup),
        None => return Err(NodeConfigBuildError::GroupNotFound),
    };

    // 2. Filtered rule query. The JOIN on users is the fix for the v0.3.5 WS
    //    drift: without it a banned / over-quota user's rules would still be
    //    pushed to a reconnecting node. Both paths now share this exact query.
    //
    //    Quota note (unchanged from v0.3.0, documented): there is a leak window
    //    of up to one poll cycle (default 10s) because quota is re-checked only
    //    when the node fetches config, not per-packet. Offline nodes serve an
    //    unfiltered cached config ("forward over bill" trade-off). Do not change
    //    without a product decision.
    let rules: Vec<ForwardRule> = db.list_active_for_config(group.id).await?;

    // 3 + 4. Resolve targets and build listener configs. Target resolution needs
    //    a DB lookup (outbound group's connect_host), so it stays async and lives
    //    here; the pure ListenerConfig assembly (transport/ws_path/protocol) is
    //    delegated to the shared `build_listeners_for_rule` so that part can never
    //    drift between paths.
    let mut listeners = Vec::new();
    let mut camouflage_by_sni = BTreeMap::<String, CamouflageSiteDesired>::new();
    for rule in &rules {
        // v0.4.7: if the rule is bound to a tunnel profile, the profile is the
        // source of transport config (node_transport + ws_path). We resolve it
        // here and override the rule's stored columns for this build only — the
        // DB row is NOT rewritten. A NULL/missing profile falls back to the
        // rule's own public_transport/ws_path (legacy behavior, zero break).
        //
        // If a bound profile no longer exists (deleted out from under the rule,
        // or a stale FK), we skip the rule's listeners rather than emit a
        // half-resolved config. The admin sees no listener for that rule.
        let mut effective_rule = rule.clone();
        if let Some(pid) = rule.tunnel_profile_id {
            // v0.4.10: profile lookup here is a system-internal config build (no
            // user context), so it uses ProfileScope::All to resolve the real
            // binding. The dirty-data migration + list_active_for_config filter
            // (this PR) ensure a regular user's rule can't reach this point bound
            // to a non-builtin profile.
            match TunnelProfileRepository::find_profile_by_id(db, pid, &ProfileScope::All).await? {
                Some(profile) => {
                    // Profile transport vocab: "direct" → node "raw"; "ws" → "ws";
                    // "tls_simple" → "tls_simple".
                    let node_transport = match profile.transport.as_str() {
                        "direct" => "raw",
                        "ws" => "ws",
                        "tls_simple" => "tls_simple",
                        other => other,
                    };
                    effective_rule.node_transport = node_transport.to_string();
                    effective_rule.ws_path = if profile.transport == "ws" {
                        Some(profile.ws_path.clone())
                    } else {
                        None
                    };
                }
                None => {
                    tracing::warn!(
                        "rule {} bound to missing tunnel_profile_id {}; skipping (rebind or pause the rule)",
                        rule.id,
                        pid
                    );
                    continue;
                }
            }
        }
        let targets = resolve_targets(db, rule).await?;
        listeners.extend(relay_shared::protocol::build_listeners_for_rule(
            &effective_rule,
            targets,
        ));
        let camouflage_sni = effective_rule
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|sni| !sni.is_empty())
            .map(str::to_ascii_lowercase);
        if effective_rule.camouflage_enabled && effective_rule.node_transport == "nginx_sni" {
            if let Some(sni) = camouflage_sni {
                camouflage_by_sni
                    .entry(sni.clone())
                    .or_insert_with(|| CamouflageSiteDesired {
                        site_id: sni.replace('.', "_"),
                        sni: sni.clone(),
                        tls_listener_port: 8443,
                        local_backend: CamouflageLocalBackend::OpenList,
                        certificate: CamouflageCertificatePolicy {
                            domain: sni,
                            expected_public_ip: group.connect_host.trim().to_string(),
                            renew_before_days: 30,
                        },
                        enabled: true,
                    });
            }
        }
    }

    Ok(NodeConfigResponse {
        listeners,
        camouflage_sites: camouflage_by_sni.into_values().collect(),
    })
}

/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own
///   `target_addr:target_port`.
/// - otherwise → the outbound group's `connect_host:target_port`, falling back
///   to the rule's own `target_addr` when the outbound group is missing or has
///   no `connect_host` configured.
///
/// `targets` is the single place target resolution happens — both config paths
/// used to duplicate this `match` block.
async fn resolve_targets(db: &dyn Repository, rule: &ForwardRule) -> Result<Vec<String>, DbError> {
    let mut targets = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await?;
    if targets.is_empty() {
        targets.push(relay_shared::models::ForwardRuleTarget {
            id: 0,
            rule_id: rule.id,
            host: rule.target_addr.clone(),
            port: rule.target_port,
            position: 1,
            enabled: true,
            created_at: String::new(),
        });
    }

    match (rule.forward_mode.as_str(), rule.device_group_out) {
        ("direct", _) | (_, None) => Ok(targets
            .into_iter()
            .map(|t| format_target_endpoint(&t.host, t.port))
            .collect()),
        (_, Some(out_id)) => {
            // Qualify: find_by_id is on both UserRepository and GroupRepository.
            let og = GroupRepository::find_by_id(db, out_id, &ResourceScope::All).await?;
            Ok(match og {
                Some(DeviceGroup { connect_host, .. }) if !connect_host.is_empty() => targets
                    .into_iter()
                    .map(|t| format_target_endpoint(&connect_host, t.port))
                    .collect(),
                _ => targets
                    .into_iter()
                    .map(|t| format_target_endpoint(&t.host, t.port))
                    .collect(),
            })
        }
    }
}

fn format_target_endpoint(host: &str, port: i32) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        pool
    }

    /// Wrap the pool in a SqliteRepository so build_node_config can be invoked
    /// the same way the real callers (get_config, build_config_snapshot) do.
    fn repo(pool: &SqlitePool) -> SqliteRepository {
        SqliteRepository::new(pool.clone())
    }

    async fn add_user(pool: &SqlitePool, id: i64) {
        let hash = bcrypt::hash(format!("pw-{id}"), 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(format!("u{id}"))
            .bind(&hash)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_group(pool: &SqlitePool, id: i64, gtype: &str, uid: i64) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(format!("g{id}"))
        .bind(gtype)
        .bind(format!("tok-{id}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_rule(pool: &SqlitePool, id: i64, uid: i64, in_group: i64, port: i64) {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80)",
        )
        .bind(id)
        .bind(format!("r{id}"))
        .bind(uid)
        .bind(port)
        .bind(in_group)
        .execute(pool)
        .await
        .unwrap();
    }

    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]
    async fn active_rule_produces_listener() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].port, 20000);
    }

    #[tokio::test]
    async fn dns_reconciliation_state_never_changes_node_config_authority() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        let before = build_node_config(&repo(&pool), 10).await.unwrap();

        sqlx::query(
            "INSERT INTO dns_record_syncs \
             (rule_id, fqdn, record_type, expected_value, line, line_key, state, ownership, \
              last_error_category, next_attempt_at, created_at, updated_at) \
             VALUES (100, 'op1.example.com', 'A', '192.0.2.10', 'default', 'default', \
                     'FAILED', 'UNKNOWN', 'DNSMGR_TIMEOUT', NULL, \
                     '2026-08-26 00:00:00', '2026-08-26 00:00:00')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let after = build_node_config(&repo(&pool), 10).await.unwrap();

        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    }

    /// A banned user's rule must NOT appear — this is the regression the WS path
    /// was missing (v0.3.5 drift). Both paths now share this query, so the test
    /// pins the filter itself.
    #[tokio::test]
    async fn banned_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET banned = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "banned user rule must be filtered"
        );
    }

    /// An over-quota user's rule must be filtered.
    #[tokio::test]
    async fn over_quota_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 100, traffic_used = 100 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "over-quota rule must be filtered");
    }

    /// A paused rule must be filtered.
    #[tokio::test]
    async fn paused_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET paused = 1 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "paused rule must be filtered");
    }

    /// A non-inbound group is not an authoritative empty configuration. The
    /// caller must reject it instead of telling a node to tear down listeners.
    #[tokio::test]
    async fn non_in_group_is_explicit_error() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "out", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        assert!(matches!(
            build_node_config(&repo(&pool), 10).await,
            Err(NodeConfigBuildError::NotInboundGroup)
        ));
    }

    /// traffic_limit = 0 means unlimited — never filtered by quota even if
    /// traffic_used is huge.
    #[tokio::test]
    async fn unlimited_quota_never_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 0, traffic_used = 999999999 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
    }

    /// v0.4.7: a rule bound to a WS tunnel profile must take its node_transport
    /// and ws_path FROM the profile (the rule's own columns are ignored).
    #[tokio::test]
    async fn profile_overrides_transport_and_ws_path() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // The test pool only runs SCHEMA_SQL (no builtin seeds), so insert a ws
        // profile explicitly rather than rely on the Migration 6 seed.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (50, 'ws-relay', 'ws', 'none', '/relay', '', '', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 50 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Ws,
            "profile transport must override the rule's stored raw transport"
        );
        assert_eq!(
            cfg.listeners[0].ws_path.as_deref(),
            Some("/relay"),
            "ws_path must come from the profile"
        );
    }

    /// v0.4.7: a rule with NO profile (tunnel_profile_id NULL) keeps using its
    /// own stored public_transport/ws_path — legacy behavior, zero break.
    #[tokio::test]
    async fn null_profile_falls_back_to_rule_transport() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // A raw rule, no profile binding.
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Raw
        );
        assert!(cfg.listeners[0].ws_path.is_none());
    }

    /// v0.4.7: a rule bound to a DELETED profile is skipped (no listener), not
    /// silently downgraded to raw.
    #[tokio::test]
    async fn missing_profile_skips_rule() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        // Point at a profile id that doesn't exist. Disable FK enforcement for
        // this insert so SQLite accepts the dangling reference (production code
        // prevents this via Migration 22's NULL-out + delete usage count, but
        // we want to pin the builder's defensive skip behavior).
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 99999 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "a rule bound to a missing profile must be skipped, not downgraded"
        );
    }

    #[tokio::test]
    async fn camouflage_rule_builds_typed_site_and_dependent_listener_without_secrets() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 443).await;
        add_rule(&pool, 101, 2, 10, 444).await;
        sqlx::query("UPDATE device_groups SET connect_host = '203.0.113.10' WHERE id = 10")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE forward_rules SET protocol='tcp', public_transport='nginx_sni', \
             node_transport='nginx_sni', entry_transport='nginx_sni', \
             sni='op1.example.com', camouflage_enabled=1, \
             target_addr='198.51.100.20', target_port=55443 WHERE id IN (100, 101)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 2);
        assert!(cfg.listeners[0].camouflage_required);
        assert_eq!(cfg.listeners[0].targets, vec!["198.51.100.20:55443"]);
        assert_eq!(cfg.camouflage_sites.len(), 1);
        let site = &cfg.camouflage_sites[0];
        assert_eq!(site.site_id, "op1_example_com");
        assert_eq!(site.sni, "op1.example.com");
        assert_eq!(site.tls_listener_port, 8443);
        assert_eq!(site.certificate.expected_public_ip, "203.0.113.10");
        assert_eq!(site.certificate.renew_before_days, 30);

        let json = serde_json::to_string(&cfg).unwrap();
        for forbidden in [
            "private_key",
            "privkey",
            "certificate_pem",
            "uuid",
            "short_id",
            "flow",
            "xray",
            "NODE_TOKEN",
        ] {
            assert!(!json.contains(forbidden), "wire config leaked {forbidden}");
        }

        sqlx::query(
            "UPDATE forward_rules SET target_addr='198.51.100.21', target_port=55444 WHERE id=100",
        )
        .execute(&pool)
        .await
        .unwrap();
        let backend_update = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(
            backend_update.camouflage_sites, cfg.camouflage_sites,
            "same-SNI backend changes must not recreate certificate desired state"
        );
    }
}
