use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::DeviceGroup;

#[async_trait]
impl NodePoolRepository for PgRepository {
    async fn list_node_pool_records(&self) -> Result<Vec<NodePoolRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM node_pool_nodes ORDER BY identity_group_id, node_id")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn discover_node_pool_identities(&self) -> Result<Vec<ConcreteNodeIdentity>, DbError> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT home_group_id, node_id FROM node_credentials WHERE activated_at IS NOT NULL AND revoked_at IS NULL
             UNION SELECT home_group_id, node_id FROM node_reuse_bindings ORDER BY home_group_id, node_id"
        ).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|(home_group_id, node_id)| ConcreteNodeIdentity {
                home_group_id,
                node_id,
            })
            .collect())
    }

    async fn register_node_pool_identity(
        &self,
        group_id: i64,
        node_id: &str,
    ) -> Result<(), DbError> {
        crate::node_identity::ReuseEligibleNodeId::parse(node_id).map_err(|_| {
            DbError::Other(sqlx::Error::Protocol("invalid pool node identity".into()))
        })?;
        let mut tx = self.pool.begin().await?;
        // Serialize with Claim/credential activation and retirement. The INSERT
        // runs with a fresh READ COMMITTED snapshot after this group lock.
        sqlx::query("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO node_pool_nodes (identity_group_id, node_id)
            SELECT id, $1 FROM device_groups WHERE id = $2 AND (
                id != COALESCE((SELECT group_id FROM node_pool_system_anchor WHERE singleton = 1), -1)
                OR EXISTS (SELECT 1 FROM node_credentials
                           WHERE home_group_id = id AND node_id = $1
                             AND activated_at IS NOT NULL AND revoked_at IS NULL)
                OR EXISTS (SELECT 1 FROM node_reuse_bindings
                           WHERE home_group_id = id AND node_id = $1))
            ON CONFLICT (identity_group_id, node_id) DO NOTHING",
        )
        .bind(node_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn rename_node_pool_node(
        &self,
        group_id: i64,
        node_id: &str,
        name: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE node_pool_nodes SET display_name = $1, updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
            WHERE identity_group_id = $2 AND node_id = $3")
            .bind(name).bind(group_id).bind(node_id).execute(&self.pool).await?.rows_affected())
    }

    async fn retire_pool_native_node(
        &self,
        group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let locked: Option<i64> =
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(false);
        }
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM node_pool_nodes WHERE identity_group_id = $1 AND node_id = $2
             AND identity_group_id = (SELECT group_id FROM node_pool_system_anchor WHERE singleton = 1)",
        )
        .bind(group_id)
        .bind(node_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET state='FAILED',
             last_error_category='NODE_RETIRED', updated_at=$1
             WHERE id=$2 AND group_id=$3 AND state IN ('PENDING','CLAIMED','VERIFYING','LOCAL_COMMITTED')",
        )
        .bind(&now)
        .bind(node_id.as_str())
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credential_deliveries SET state='CANCELLED', cancelled_at=$1, updated_at=$1
             WHERE home_group_id=$2 AND node_id=$3 AND state='PREPARED'",
        )
        .bind(&now)
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credential_claims SET state='CANCELLED', cancelled_at=$1, updated_at=$1
             WHERE home_group_id=$2 AND node_id=$3 AND state IN ('APPROVED','CLAIMED','CREDENTIAL_PENDING')",
        )
        .bind(&now)
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credentials SET revoked_at=to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
             updated_at=to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
             WHERE home_group_id=$1 AND node_id=$2 AND revoked_at IS NULL",
        )
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM node_reuse_bindings WHERE home_group_id=$1 AND node_id=$2")
            .bind(group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
        for key in [
            format!("node_status:{group_id}:{}", node_id.as_str()),
            format!("node_config_revision:{group_id}:{}", node_id.as_str()),
        ] {
            sqlx::query("DELETE FROM kvs WHERE key=$1")
                .bind(key)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM node_pool_nodes WHERE identity_group_id=$1 AND node_id=$2")
            .bind(group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn set_verified_node_status_if_active(
        &self,
        group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        credential_id: &str,
        status: &str,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM device_groups WHERE id=$1 FOR UPDATE")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
        let written = sqlx::query(
            "INSERT INTO kvs (key,value)
             SELECT $1,$2 WHERE EXISTS (
                 SELECT 1 FROM node_credentials AS current
                 WHERE current.home_group_id=$3 AND current.node_id=$4 AND current.credential_id=$5
                   AND current.activated_at IS NOT NULL AND current.revoked_at IS NULL
                   AND current.generation=(SELECT MAX(history.generation) FROM node_credentials AS history
                       WHERE history.home_group_id=current.home_group_id AND history.node_id=current.node_id
                       AND history.activated_at IS NOT NULL))
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        )
        .bind(format!("node_status:{group_id}:{}", node_id.as_str()))
        .bind(status).bind(group_id).bind(node_id.as_str()).bind(credential_id)
        .execute(&mut *tx).await?.rows_affected() == 1;
        tx.commit().await?;
        Ok(written)
    }

    async fn node_pool_system_group_id(&self) -> Result<Option<i64>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT group_id FROM node_pool_system_anchor WHERE singleton = 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn ensure_node_pool_system_group(
        &self,
        admin_id: i64,
        token: &str,
    ) -> Result<DeviceGroup, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(7281192601)")
            .execute(&mut *tx)
            .await?;
        if let Some(group) = sqlx::query_as::<_, DeviceGroup>(
            "SELECT g.* FROM device_groups g JOIN node_pool_system_anchor p ON p.group_id = g.id WHERE p.singleton = 1")
            .fetch_optional(&mut *tx).await? {
            tx.commit().await?;
            return Ok(group);
        }
        let group_id: i64 = sqlx::query_scalar(
            "INSERT INTO device_groups (name, group_type, token, uid, hidden)
             SELECT '__node_pool__', 'in', $1, id, TRUE FROM users WHERE id = $2 AND admin = TRUE
             RETURNING id",
        )
        .bind(token)
        .bind(admin_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO node_pool_system_anchor (singleton, group_id) VALUES (1, $1)")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        let group = sqlx::query_as("SELECT * FROM device_groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(group)
    }
}
