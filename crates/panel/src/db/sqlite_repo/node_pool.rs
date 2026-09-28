use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::DeviceGroup;

#[async_trait]
impl NodePoolRepository for SqliteRepository {
    async fn list_node_pool_records(&self) -> Result<Vec<NodePoolRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM node_pool_nodes ORDER BY identity_group_id, node_id")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn find_node_pool_record(
        &self,
        group_id: i64,
        node_id: &str,
    ) -> Result<Option<NodePoolRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM node_pool_nodes WHERE identity_group_id = ? AND node_id = ?",
        )
        .bind(group_id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn retire_node_pool_identity(
        &self,
        group_id: i64,
        node_id: &str,
        expected_version: i64,
        admin_id: i64,
        reason: &str,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE node_pool_nodes SET node_id = node_id WHERE 0")
            .execute(&mut *tx)
            .await?;
        let bindings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_reuse_bindings WHERE home_group_id = ? AND node_id = ?",
        )
        .bind(group_id)
        .bind(node_id)
        .fetch_one(&mut *tx)
        .await?;
        if bindings != 0 {
            return Ok(false);
        }
        let pending_claims: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credential_claims WHERE home_group_id = ? AND node_id = ?
             AND state NOT IN ('COMPLETED', 'CANCELLED', 'EXPIRED')",
        )
        .bind(group_id)
        .bind(node_id)
        .fetch_one(&mut *tx)
        .await?;
        let pending_deliveries: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credential_deliveries WHERE home_group_id = ? AND node_id = ?
             AND state = 'PREPARED'",
        )
        .bind(group_id)
        .bind(node_id)
        .fetch_one(&mut *tx)
        .await?;
        if pending_claims != 0 || pending_deliveries != 0 {
            return Ok(false);
        }
        let changed = sqlx::query(
            "UPDATE node_pool_nodes SET retirement_state = 'RETIRED',
             retired_at = datetime('now'), retired_by = ?, retirement_reason = ?,
             retirement_version = retirement_version + 1, updated_at = datetime('now')
             WHERE identity_group_id = ? AND node_id = ?
               AND retirement_state = 'ACTIVE' AND retirement_version = ?",
        )
        .bind(admin_id)
        .bind(reason)
        .bind(group_id)
        .bind(node_id)
        .bind(expected_version)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE node_credentials SET revoked_at = datetime('now'), updated_at = datetime('now')
             WHERE home_group_id = ? AND node_id = ? AND activated_at IS NOT NULL AND revoked_at IS NULL",
        )
        .bind(group_id)
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn restore_node_pool_identity(
        &self,
        group_id: i64,
        node_id: &str,
        expected_version: i64,
    ) -> Result<bool, DbError> {
        let changed = sqlx::query(
            "UPDATE node_pool_nodes SET retirement_state = 'ACTIVE', retirement_version = retirement_version + 1,
             updated_at = datetime('now') WHERE identity_group_id = ? AND node_id = ?
             AND retirement_state = 'RETIRED' AND retirement_version = ?
             AND NOT EXISTS (SELECT 1 FROM node_credentials WHERE home_group_id = ? AND node_id = ?
             AND activated_at IS NOT NULL AND revoked_at IS NULL)",
        )
        .bind(group_id)
        .bind(node_id)
        .bind(expected_version)
        .bind(group_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(changed.rows_affected() == 1)
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
        sqlx::query(
            "INSERT INTO node_pool_nodes (identity_group_id, node_id)
            SELECT id, ? FROM device_groups WHERE id = ?
            ON CONFLICT (identity_group_id, node_id) DO NOTHING",
        )
        .bind(node_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn rename_node_pool_node(
        &self,
        group_id: i64,
        node_id: &str,
        name: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE node_pool_nodes SET display_name = ?, updated_at = datetime('now')
            WHERE identity_group_id = ? AND node_id = ? AND retirement_state = 'ACTIVE'",
        )
        .bind(name)
        .bind(group_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
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
        sqlx::query("UPDATE node_pool_system_anchor SET singleton = singleton WHERE 0")
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
             SELECT '__node_pool__', 'in', ?, id, 1 FROM users WHERE id = ? AND admin = 1
             RETURNING id",
        )
        .bind(token)
        .bind(admin_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO node_pool_system_anchor (singleton, group_id) VALUES (1, ?)")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        let group = sqlx::query_as("SELECT * FROM device_groups WHERE id = ?")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(group)
    }
}
