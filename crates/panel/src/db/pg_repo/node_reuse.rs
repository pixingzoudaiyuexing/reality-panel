use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{ConcreteNodeIdentity, NodeReuseBinding, NodeReuseRepository};
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
