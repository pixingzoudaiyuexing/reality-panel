//! Pool metadata is independent of config delivery and credential authority.
use crate::db::error::DbError;
use crate::db::repo::{ConcreteNodeIdentity, GroupRepository, Repository, ResourceScope};
use crate::node_identity::ReuseEligibleNodeId;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
pub struct PoolMembership {
    pub group_id: i64,
    pub group_name: String,
    pub native: bool,
}

#[derive(Debug, Serialize)]
pub struct PoolNode {
    pub identity_group_id: i64,
    pub node_id: String,
    pub display_name: String,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub online: bool,
    pub node_version: Option<String>,
    pub last_seen: Option<String>,
    pub credential_ready: bool,
    pub migration_required: bool,
    pub migration_pending: bool,
    pub migration_claim_id: Option<String>,
    pub auth_reload_supported: bool,
    pub memberships: Vec<PoolMembership>,
}

pub async fn reconcile_metadata(db: &dyn Repository) -> Result<(), DbError> {
    let mut identities: BTreeSet<ConcreteNodeIdentity> = db
        .discover_node_pool_identities()
        .await?
        .into_iter()
        .collect();
    for (key, _) in db.scan_prefix("node_status:").await? {
        if let Some((home_group_id, Some(node_id))) = crate::api::stats::parse_status_key(&key) {
            if ReuseEligibleNodeId::parse(node_id).is_ok() {
                identities.insert(ConcreteNodeIdentity {
                    home_group_id,
                    node_id: node_id.into(),
                });
            }
        }
    }
    for identity in identities {
        if ReuseEligibleNodeId::parse(&identity.node_id).is_ok() {
            db.register_node_pool_identity(identity.home_group_id, &identity.node_id)
                .await?;
        }
    }
    Ok(())
}

pub async fn list_nodes(db: &dyn Repository) -> Result<Vec<PoolNode>, DbError> {
    reconcile_metadata(db).await?;
    let system_group = db.node_pool_system_group_id().await?;
    let mut result = Vec::new();
    for record in db.list_node_pool_records().await? {
        let raw = db
            .get(&format!(
                "node_status:{}:{}",
                record.identity_group_id, record.node_id
            ))
            .await?;
        let status = raw
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
        let field = |key: &str| {
            status
                .as_ref()
                .and_then(|v| v.get(key))
                .and_then(serde_json::Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let mut memberships = Vec::new();
        let mut groups = db
            .list_reusing_group_ids_for_node(record.identity_group_id, &record.node_id)
            .await?;
        groups.push(record.identity_group_id);
        groups.sort_unstable();
        groups.dedup();
        for group_id in groups {
            if Some(group_id) == system_group {
                continue;
            }
            if let Some(group) =
                GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await?
            {
                memberships.push(PoolMembership {
                    group_id,
                    group_name: group.name,
                    native: group_id == record.identity_group_id,
                });
            }
        }
        let credential_ready = match ReuseEligibleNodeId::parse(&record.node_id) {
            Ok(id) => db
                .find_current_active_node_credential_for_identity(record.identity_group_id, &id)
                .await?
                .is_some(),
            Err(_) => false,
        };
        let migration_required =
            !credential_ready && Some(record.identity_group_id) != system_group;
        let pending = if migration_required {
            let id =
                ReuseEligibleNodeId::parse(&record.node_id).expect("validated registry identity");
            db.list_node_credential_claims_for_identity(record.identity_group_id, &id)
                .await?
                .into_iter()
                .find(|claim| {
                    claim.state == "CREDENTIAL_PENDING"
                        || (matches!(claim.state.as_str(), "APPROVED" | "CLAIMED")
                            && chrono::DateTime::parse_from_rfc3339(&claim.expires_at)
                                .is_ok_and(|expiry| expiry > chrono::Utc::now()))
                })
        } else {
            None
        };
        result.push(PoolNode {
            identity_group_id: record.identity_group_id,
            node_id: record.node_id,
            display_name: record.display_name,
            public_ipv4: field("public_ipv4").or_else(|| field("public_ip")),
            public_ipv6: field("public_ipv6"),
            online: raw
                .as_deref()
                .is_some_and(|v| crate::api::stats::status_is_online(v, chrono::Utc::now())),
            node_version: field("node_version"),
            last_seen: field("last_seen"),
            credential_ready,
            migration_required,
            migration_pending: pending.is_some(),
            migration_claim_id: pending.map(|claim| claim.claim_id),
            auth_reload_supported: status
                .as_ref()
                .and_then(|v| v.get("auth_reload_supported"))
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            memberships,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{KvsRepository, NodePoolRepository};
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn metadata_backfill_and_rename_preserve_runtime_authority_and_membership() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        let db = SqliteRepository::new(pool.clone());
        for id in [10, 20, 30] {
            sqlx::query(
                "INSERT INTO device_groups (id,name,group_type,token,uid) VALUES (?,?,'in',?,1)",
            )
            .bind(id)
            .bind(format!("g{id}"))
            .bind(format!("t{id}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        db.set(
            "node_status:10:LEGACY",
            r#"{"last_seen":"2000-01-01T00:00:00Z","public_ipv4":"192.0.2.1"}"#,
        )
        .await
        .unwrap();
        db.set("node_status:10", r#"{"public_ipv4":"192.0.2.2"}"#)
            .await
            .unwrap();
        db.set("node_config_revision:10:LEGACY", "unchanged-authority")
            .await
            .unwrap();
        db.set("node_config_rule_sources:10:LEGACY:8", "{}")
            .await
            .unwrap();
        db.set("node_config_rule_owners:10:LEGACY:8", "{}")
            .await
            .unwrap();
        sqlx::query("INSERT INTO node_reuse_bindings(reusing_group_id,home_group_id,node_id) VALUES (20,10,'VERIFIED'),(30,10,'VERIFIED')")
            .execute(&pool).await.unwrap();
        let before = db.scan_prefix("node_").await.unwrap();
        let nodes = list_nodes(&db).await.unwrap();
        assert_eq!(nodes.len(), 2);
        let legacy = nodes.iter().find(|n| n.node_id == "LEGACY").unwrap();
        assert!(!legacy.credential_ready);
        assert!(legacy.migration_required);
        assert!(!legacy.online);
        assert_eq!(legacy.memberships.len(), 1);
        let reused = nodes.iter().find(|n| n.node_id == "VERIFIED").unwrap();
        assert_eq!(
            reused
                .memberships
                .iter()
                .map(|m| m.group_id)
                .collect::<Vec<_>>(),
            vec![10, 20, 30]
        );
        assert_eq!(
            db.rename_node_pool_node(10, "LEGACY", "North relay")
                .await
                .unwrap(),
            1
        );
        let replay = list_nodes(&db).await.unwrap();
        assert_eq!(replay.len(), 2);
        assert_eq!(
            replay
                .iter()
                .find(|n| n.node_id == "LEGACY")
                .unwrap()
                .display_name,
            "North relay"
        );
        assert_eq!(
            before,
            db.scan_prefix("node_").await.unwrap(),
            "Pool metadata operations must not write config or status keys"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        assert!(db.node_pool_system_group_id().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn system_anchor_is_singleton_hidden_and_not_editable() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        let db = SqliteRepository::new(pool);
        let anchor = db
            .ensure_node_pool_system_group(1, "pool-test-token")
            .await
            .unwrap();
        let again = db
            .ensure_node_pool_system_group(1, "ignored-test-token")
            .await
            .unwrap();
        assert_eq!(anchor.id, again.id);
        assert_eq!(anchor.token, again.token);
        assert!(db
            .list_groups(&ResourceScope::All)
            .await
            .unwrap()
            .is_empty());
        assert!(crate::service::groups::rotate_group_token(&db, anchor.id)
            .await
            .unwrap()
            .is_none());
        assert!(!crate::service::groups::delete_group(&db, anchor.id)
            .await
            .unwrap());
        assert!(matches!(
            crate::service::groups::update_group(
                &db,
                anchor.id,
                Some("edited"),
                None,
                None,
                None,
                None,
                None
            )
            .await,
            Err(crate::service::groups::UpdateGroupError::NotFound)
        ));
        assert!(db.scan_prefix("node_config_").await.unwrap().is_empty());
        db.register_node_pool_identity(anchor.id, "POOL_NEW")
            .await
            .unwrap();
        let nodes = list_nodes(&db).await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(!nodes[0].migration_required);
        assert!(!nodes[0].credential_ready);
    }

    #[tokio::test]
    async fn additive_upgrade_keeps_legacy_verified_offline_and_reused_authority() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(crate::db::schema::SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        let db = SqliteRepository::new(pool.clone());
        for id in [10, 20, 30] {
            sqlx::query(
                "INSERT INTO device_groups(id,name,group_type,token,uid) VALUES (?,?,'in',?,1)",
            )
            .bind(id)
            .bind(format!("g{id}"))
            .bind(format!("g-token-{id}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        for node in ["LEGACY", "VERIFIED", "REUSED", "OFFLINE"] {
            db.set(
                &format!("node_status:10:{node}"),
                r#"{"last_seen":"2000-01-01T00:00:00Z"}"#,
            )
            .await
            .unwrap();
            db.set(
                &format!("node_config_revision:10:{node}"),
                r#"{"revision":20,"fingerprint":"preserved"}"#,
            )
            .await
            .unwrap();
            if node != "LEGACY" {
                sqlx::query("INSERT INTO node_credentials(credential_id,home_group_id,node_id,generation,verifier_format,verifier_version,verifier_data,activated_at) VALUES (?,10,?,1,'rp-node-sha256',1,?,datetime('now'))")
                    .bind(format!("cred-{node}")).bind(node).bind(vec![9_u8;32]).execute(&pool).await.unwrap();
            }
        }
        sqlx::query("INSERT INTO node_reuse_bindings(reusing_group_id,home_group_id,node_id) VALUES (20,10,'REUSED'),(30,10,'REUSED')")
            .execute(&pool).await.unwrap();
        let before = db.scan_prefix("node_").await.unwrap();
        let before_reused = crate::service::node_reuse::effective_source_groups(&db, 10, "REUSED")
            .await
            .unwrap();
        let before_legacy = crate::service::node_reuse::effective_source_groups(&db, 10, "LEGACY")
            .await
            .unwrap();
        let credentials: Vec<(String, i64)> = sqlx::query_as(
            "SELECT credential_id,generation FROM node_credentials ORDER BY credential_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        sqlx::query("DROP TABLE node_pool_nodes")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP TABLE node_pool_system_anchor")
            .execute(&pool)
            .await
            .unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        let nodes = list_nodes(&db).await.unwrap();
        assert_eq!(nodes.len(), 4);
        assert_eq!(
            nodes
                .iter()
                .find(|n| n.node_id == "REUSED")
                .unwrap()
                .memberships
                .len(),
            3
        );
        assert!(
            nodes
                .iter()
                .find(|n| n.node_id == "LEGACY")
                .unwrap()
                .migration_required
        );
        assert!(
            nodes
                .iter()
                .find(|n| n.node_id == "OFFLINE")
                .unwrap()
                .credential_ready
        );
        assert_eq!(db.scan_prefix("node_").await.unwrap(), before);
        assert_eq!(
            crate::service::node_reuse::effective_source_groups(&db, 10, "REUSED")
                .await
                .unwrap(),
            before_reused
        );
        assert_eq!(
            crate::service::node_reuse::effective_source_groups(&db, 10, "LEGACY")
                .await
                .unwrap(),
            before_legacy
        );
        assert_eq!(
            sqlx::query_as::<_, (String, i64)>(
                "SELECT credential_id,generation FROM node_credentials ORDER BY credential_id"
            )
            .fetch_all(&pool)
            .await
            .unwrap(),
            credentials
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM node_reuse_bindings")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
    }
}
