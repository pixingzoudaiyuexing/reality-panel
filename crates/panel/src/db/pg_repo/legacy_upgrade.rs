use super::PgRepository;
use crate::db::{error::DbError, repo::*};

impl PgRepository {
    pub(super) async fn legacy_upgrade_commit_inner(
        &self,
        change: &LegacyUpgradeCommit,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(1380996432)")
            .execute(&mut *tx)
            .await?;
        let current: Option<String> =
            sqlx::query_scalar("SELECT value FROM kvs WHERE key='legacy_v130_upgrade:singleton'")
                .fetch_optional(&mut *tx)
                .await?;
        if current != change.expected_operation {
            return Ok(false);
        }
        for (key, expected, replacement) in &change.routing {
            let current: Option<String> = sqlx::query_scalar("SELECT value FROM kvs WHERE key=$1")
                .bind(key)
                .fetch_optional(&mut *tx)
                .await?;
            if current.as_deref() != Some(expected) {
                return Ok(false);
            }
            sqlx::query("UPDATE kvs SET value=$1 WHERE key=$2")
                .bind(replacement)
                .bind(key)
                .execute(&mut *tx)
                .await?;
        }
        if let Some(r) = &change.replacement {
            let current: Option<String> = sqlx::query_scalar("SELECT credential_id FROM node_credentials WHERE home_group_id=$1 AND node_id=$2 AND activated_at IS NOT NULL AND revoked_at IS NULL ORDER BY generation DESC LIMIT 1").bind(r.new.home_group_id).bind(&r.new.node_id).fetch_optional(&mut *tx).await?;
            if current.as_deref() != Some(&r.new_credential_id) {
                return Ok(false);
            }
            for group in &r.memberships {
                let present: Option<i32> = sqlx::query_scalar("SELECT 1 FROM node_reuse_bindings WHERE reusing_group_id=$1 AND home_group_id=$2 AND node_id=$3").bind(group).bind(r.new.home_group_id).bind(&r.new.node_id).fetch_optional(&mut *tx).await?;
                if present.is_none() {
                    return Ok(false);
                }
            }
            sqlx::query("UPDATE node_credentials SET revoked_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND revoked_at IS NULL").bind(r.old.home_group_id).bind(&r.old.node_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE node_credential_claims SET state='CANCELLED',cancelled_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND state IN ('APPROVED','CLAIMED','CREDENTIAL_PENDING')").bind(r.old.home_group_id).bind(&r.old.node_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE node_credential_deliveries SET state='CANCELLED',cancelled_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND state='PREPARED'").bind(r.old.home_group_id).bind(&r.old.node_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE manual_bootstrap_enrollments SET state='FAILED',last_error_category='NODE_RETIRED',updated_at=now()::text WHERE group_id=$1 AND id=$2 AND state IN ('PENDING','CLAIMED','VERIFYING','LOCAL_COMMITTED')").bind(r.old.home_group_id).bind(&r.old.node_id).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM node_reuse_bindings WHERE home_group_id=$1 AND node_id=$2")
                .bind(r.old.home_group_id)
                .bind(&r.old.node_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM node_pool_nodes WHERE identity_group_id=$1 AND node_id=$2")
                .bind(r.old.home_group_id)
                .bind(&r.old.node_id)
                .execute(&mut *tx)
                .await?;
            for key in [
                format!("node_status:{}:{}", r.old.home_group_id, r.old.node_id),
                format!(
                    "node_config_revision:{}:{}",
                    r.old.home_group_id, r.old.node_id
                ),
            ] {
                sqlx::query("DELETE FROM kvs WHERE key=$1")
                    .bind(key)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO kvs(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(format!("legacy_v130_upgrade:retired:{}:{}",r.old.home_group_id,r.old.node_id)).bind(&change.operation_id).execute(&mut *tx).await?;
        }
        if let Some(r) = &change.rollback {
            sqlx::query("UPDATE node_credentials SET revoked_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND revoked_at IS NULL").bind(r.home_group_id).bind(&r.node_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE node_credential_claims SET state='CANCELLED',cancelled_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND state IN ('APPROVED','CLAIMED','CREDENTIAL_PENDING')").bind(r.home_group_id).bind(&r.node_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE node_credential_deliveries SET state='CANCELLED',cancelled_at=now()::text,updated_at=now()::text WHERE home_group_id=$1 AND node_id=$2 AND state='PREPARED'").bind(r.home_group_id).bind(&r.node_id).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM node_reuse_bindings WHERE home_group_id=$1 AND node_id=$2")
                .bind(r.home_group_id)
                .bind(&r.node_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM node_pool_nodes WHERE identity_group_id=$1 AND node_id=$2")
                .bind(r.home_group_id)
                .bind(&r.node_id)
                .execute(&mut *tx)
                .await?;
            for key in [
                format!("node_status:{}:{}", r.home_group_id, r.node_id),
                format!("node_config_revision:{}:{}", r.home_group_id, r.node_id),
            ] {
                sqlx::query("DELETE FROM kvs WHERE key=$1")
                    .bind(key)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO kvs(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(format!("legacy_v130_upgrade:retired:{}:{}",r.home_group_id,r.node_id)).bind(&change.operation_id).execute(&mut *tx).await?;
        }
        for key in [
            "legacy_v130_upgrade:singleton".to_string(),
            format!("legacy_v130_upgrade:operation:{}", change.operation_id),
        ] {
            sqlx::query("INSERT INTO kvs(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key).bind(&change.operation).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(true)
    }
}
