use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{NewNodeCredentialRecord, NodeCredentialRecord, NodeCredentialRepository};
use async_trait::async_trait;

#[async_trait]
impl NodeCredentialRepository for PgRepository {
    async fn insert_node_credential(
        &self,
        credential: &NewNodeCredentialRecord,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&credential.credential_id)
        .bind(credential.home_group_id)
        .bind(credential.node_id.as_str())
        .bind(credential.generation)
        .bind(&credential.verifier_format)
        .bind(credential.verifier_version)
        .bind(&credential.verifier_data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_node_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, revoked_at \
             FROM node_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn list_node_credentials_for_identity(
        &self,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
    ) -> Result<Vec<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, revoked_at \
             FROM node_credentials \
             WHERE home_group_id = $1 AND node_id = $2 \
             ORDER BY generation ASC, credential_id ASC",
        )
        .bind(home_group_id)
        .bind(node_id.as_str())
        .fetch_all(&self.pool)
        .await?)
    }
}
