use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    ConcreteNodeIdentity, NodeReuseBinding, NodeReuseBindingCreateRejection,
    NodeReuseBindingCreateResult, NodeReuseRepository,
};
use crate::node_identity::ReuseEligibleNodeId;
use async_trait::async_trait;

#[async_trait]
impl NodeReuseRepository for PgRepository {
    async fn insert_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO node_reuse_bindings (reusing_group_id, home_group_id, node_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_node_reuse_binding_if_active(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
    ) -> Result<NodeReuseBindingCreateResult, DbError> {
        let mut tx = self.pool.begin().await?;

        let groups: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, group_type FROM device_groups \
             WHERE id = $1 OR id = $2 ORDER BY id FOR UPDATE",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .fetch_all(&mut *tx)
        .await?;

        let reusing_type = groups
            .iter()
            .find(|(id, _)| *id == reusing_group_id)
            .map(|(_, group_type)| group_type.as_str());
        let home_type = groups
            .iter()
            .find(|(id, _)| *id == home_group_id)
            .map(|(_, group_type)| group_type.as_str());

        if reusing_type.is_none() {
            tx.rollback().await?;
            return Ok(NodeReuseBindingCreateResult::Rejected(
                NodeReuseBindingCreateRejection::ReusingGroupMissing,
            ));
        }
        if home_type.is_none() {
            tx.rollback().await?;
            return Ok(NodeReuseBindingCreateResult::Rejected(
                NodeReuseBindingCreateRejection::HomeGroupMissing,
            ));
        }

        let existing = sqlx::query_as::<_, NodeReuseBinding>(
            "SELECT reusing_group_id, home_group_id, node_id, created_at \
             FROM node_reuse_bindings \
             WHERE reusing_group_id = $1 AND home_group_id = $2 AND node_id = $3 \
             FOR UPDATE",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(binding) = existing {
            tx.commit().await?;
            return Ok(NodeReuseBindingCreateResult::Existing(binding));
        }

        if reusing_type != Some("in") {
            tx.rollback().await?;
            return Ok(NodeReuseBindingCreateResult::Rejected(
                NodeReuseBindingCreateRejection::ReusingGroupNotInbound,
            ));
        }
        if home_type != Some("in") {
            tx.rollback().await?;
            return Ok(NodeReuseBindingCreateResult::Rejected(
                NodeReuseBindingCreateRejection::HomeGroupNotInbound,
            ));
        }

        let active: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM node_credentials AS current \
             WHERE current.home_group_id = $1 AND current.node_id = $2 \
               AND current.activated_at IS NOT NULL AND current.revoked_at IS NULL \
               AND current.generation = ( \
                   SELECT MAX(history.generation) FROM node_credentials AS history \
                   WHERE history.home_group_id = current.home_group_id \
                     AND history.node_id = current.node_id \
                     AND history.activated_at IS NOT NULL \
               ) FOR UPDATE",
        )
        .bind(home_group_id)
        .bind(node_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if active.is_none() {
            tx.rollback().await?;
            return Ok(NodeReuseBindingCreateResult::Rejected(
                NodeReuseBindingCreateRejection::ActiveCredentialMissing,
            ));
        }

        let binding = sqlx::query_as::<_, NodeReuseBinding>(
            "INSERT INTO node_reuse_bindings (reusing_group_id, home_group_id, node_id) \
             VALUES ($1, $2, $3) \
             RETURNING reusing_group_id, home_group_id, node_id, created_at",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(NodeReuseBindingCreateResult::Created(binding))
    }

    async fn find_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<Option<NodeReuseBinding>, DbError> {
        Ok(sqlx::query_as::<_, NodeReuseBinding>(
            "SELECT reusing_group_id, home_group_id, node_id, created_at \
             FROM node_reuse_bindings \
             WHERE reusing_group_id = $1 AND home_group_id = $2 AND node_id = $3",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn list_reusing_group_ids_for_node(
        &self,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT reusing_group_id FROM node_reuse_bindings \
             WHERE home_group_id = $1 AND node_id = $2 \
             ORDER BY reusing_group_id ASC",
        )
        .bind(home_group_id)
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_reused_concrete_nodes_for_group(
        &self,
        reusing_group_id: i64,
    ) -> Result<Vec<ConcreteNodeIdentity>, DbError> {
        Ok(sqlx::query_as::<_, ConcreteNodeIdentity>(
            "SELECT home_group_id, node_id FROM node_reuse_bindings \
             WHERE reusing_group_id = $1 \
             ORDER BY home_group_id ASC, node_id ASC",
        )
        .bind(reusing_group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn count_node_reuse_bindings_for_home_group(
        &self,
        home_group_id: i64,
    ) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM node_reuse_bindings WHERE home_group_id = $1")
                .bind(home_group_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn count_node_reuse_bindings_for_group(&self, group_id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_reuse_bindings \
             WHERE reusing_group_id = $1 OR home_group_id = $1",
        )
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn delete_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "DELETE FROM node_reuse_bindings \
             WHERE reusing_group_id = $1 AND home_group_id = $2 AND node_id = $3",
        )
        .bind(reusing_group_id)
        .bind(home_group_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
