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
            SELECT id, ? FROM device_groups WHERE id = ? AND (
                id != COALESCE((SELECT group_id FROM node_pool_system_anchor WHERE singleton = 1), -1)
                OR EXISTS (SELECT 1 FROM node_credentials
                           WHERE home_group_id = id AND node_id = ?
                             AND activated_at IS NOT NULL AND revoked_at IS NULL)
                OR EXISTS (SELECT 1 FROM node_reuse_bindings
                           WHERE home_group_id = id AND node_id = ?))
            ON CONFLICT (identity_group_id, node_id) DO NOTHING",
        )
        .bind(node_id)
        .bind(group_id)
        .bind(node_id)
        .bind(node_id)
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
            WHERE identity_group_id = ? AND node_id = ?",
        )
        .bind(name)
        .bind(group_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn retire_pool_native_node(
        &self,
        group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
    ) -> Result<NodePoolRetirement, DbError> {
        let mut tx = self.pool.begin().await?;
        // Own the SQLite writer slot before inspecting any identity state.
        sqlx::query("UPDATE device_groups SET name = name WHERE id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM node_pool_nodes WHERE identity_group_id = ? AND node_id = ?
             AND identity_group_id = (SELECT group_id FROM node_pool_system_anchor WHERE singleton = 1)",
        )
        .bind(group_id)
        .bind(node_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(NodePoolRetirement::default());
        }
        let routing_rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key,value FROM kvs WHERE key LIKE 'relay_preference:%'
             OR key LIKE 'relay_failover:%' OR key='relay_switch_schedules:v1' ORDER BY key",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut referenced_groups = std::collections::BTreeSet::new();
        for (key, raw) in &routing_rows {
            referenced_groups.extend(crate::service::node_pool::routing_reference_groups(
                key,
                raw,
                node_id.as_str(),
            )?);
        }
        let mut routing_groups = Vec::new();
        let mut needs_attention = false;
        for business_group in referenced_groups {
            if business_group == group_id {
                routing_groups.push(business_group);
                continue;
            }
            // Bare Node IDs in routing must continue to name any surviving
            // identity in this Group. Never erase another identity's policy.
            let collision: Option<i64> = sqlx::query_scalar(
                "SELECT 1 WHERE EXISTS (SELECT 1 FROM node_reuse_bindings
                    WHERE reusing_group_id=? AND home_group_id<>? AND node_id=?)
                 OR EXISTS (SELECT 1 FROM node_pool_nodes WHERE identity_group_id=? AND node_id=?)
                 OR EXISTS (SELECT 1 FROM node_credentials WHERE home_group_id=? AND node_id=?
                    AND activated_at IS NOT NULL AND revoked_at IS NULL)
                 OR EXISTS (SELECT 1 FROM kvs WHERE key=?)",
            )
            .bind(business_group)
            .bind(group_id)
            .bind(node_id.as_str())
            .bind(business_group)
            .bind(node_id.as_str())
            .bind(business_group)
            .bind(node_id.as_str())
            .bind(format!("node_status:{business_group}:{}", node_id.as_str()))
            .fetch_optional(&mut *tx)
            .await?;
            if collision.is_some() {
                needs_attention = true;
            } else {
                routing_groups.push(business_group);
            }
        }
        for (key, raw) in routing_rows {
            if crate::service::node_pool::routing_reference_groups(&key, &raw, node_id.as_str())?
                .iter()
                .any(|id| routing_groups.contains(id))
            {
                let (updated, attention) = crate::service::node_pool::retire_routing_value(
                    &key,
                    &raw,
                    node_id.as_str(),
                    &routing_groups,
                )?;
                needs_attention |= attention;
                sqlx::query("UPDATE kvs SET value=? WHERE key=?")
                    .bind(updated)
                    .bind(key)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET state='FAILED',
             last_error_category='NODE_RETIRED', updated_at=?
             WHERE id=? AND group_id=? AND state IN ('PENDING','CLAIMED','VERIFYING','LOCAL_COMMITTED')",
        )
        .bind(&now)
        .bind(node_id.as_str())
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credential_deliveries SET state='CANCELLED', cancelled_at=?, updated_at=?
             WHERE home_group_id=? AND node_id=? AND state='PREPARED'",
        )
        .bind(&now)
        .bind(&now)
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credential_claims SET state='CANCELLED', cancelled_at=?, updated_at=?
             WHERE home_group_id=? AND node_id=? AND state IN ('APPROVED','CLAIMED','CREDENTIAL_PENDING')",
        )
        .bind(&now)
        .bind(&now)
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE node_credentials SET revoked_at=datetime('now'), updated_at=datetime('now')
             WHERE home_group_id=? AND node_id=? AND revoked_at IS NULL",
        )
        .bind(group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM node_reuse_bindings WHERE home_group_id=? AND node_id=?")
            .bind(group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
        for key in [
            format!("node_status:{group_id}:{}", node_id.as_str()),
            format!("node_config_revision:{group_id}:{}", node_id.as_str()),
        ] {
            sqlx::query("DELETE FROM kvs WHERE key=?")
                .bind(key)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM node_pool_nodes WHERE identity_group_id=? AND node_id=?")
            .bind(group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(NodePoolRetirement {
            retired: true,
            needs_attention,
        })
    }

    async fn set_verified_node_status_if_active(
        &self,
        group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        credential_id: &str,
        status: &str,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE device_groups SET name=name WHERE id=?")
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
        let written = sqlx::query(
            "INSERT INTO kvs (key,value)
             SELECT ?,? WHERE EXISTS (
                 SELECT 1 FROM node_credentials AS current
                 WHERE current.home_group_id=? AND current.node_id=? AND current.credential_id=?
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
