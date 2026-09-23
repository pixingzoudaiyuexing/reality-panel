use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    NewNodeCredentialCandidate, NodeCredentialMutationResult, NodeCredentialRecord,
    NodeCredentialRepository,
};
use async_trait::async_trait;

#[async_trait]
impl NodeCredentialRepository for SqliteRepository {
    async fn allocate_node_credential_candidate(
        &self,
        candidate: &NewNodeCredentialCandidate,
    ) -> Result<NodeCredentialRecord, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data) \
             SELECT ?, ?, ?, COALESCE(MAX(generation), 0) + 1, ?, ?, ? \
             FROM node_credentials \
             WHERE home_group_id = ? AND node_id = ? \
             RETURNING credential_id, home_group_id, node_id, generation, verifier_format, \
                       verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at",
        )
        .bind(&candidate.credential_id)
        .bind(candidate.home_group_id)
        .bind(candidate.node_id.as_str())
        .bind(candidate.verifier.format())
        .bind(candidate.verifier.version())
        .bind(candidate.verifier.data().as_slice())
        .bind(candidate.home_group_id)
        .bind(candidate.node_id.as_str())
        .fetch_one(&self.pool)
        .await?)
    }

    async fn find_node_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials WHERE credential_id = ?",
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
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials \
             WHERE home_group_id = ? AND node_id = ? \
             ORDER BY generation ASC, credential_id ASC",
        )
        .bind(home_group_id)
        .bind(node_id.as_str())
        .fetch_all(&self.pool)
        .await?)
    }

    async fn activate_node_credential(
        &self,
        credential_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError> {
        let updated = sqlx::query(
            "UPDATE node_credentials AS candidate \
             SET activated_at = datetime('now'), updated_at = datetime('now') \
             WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
               AND activated_at IS NULL AND revoked_at IS NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM node_credentials AS active \
                   WHERE active.home_group_id = candidate.home_group_id \
                     AND active.node_id = candidate.node_id \
                     AND active.activated_at IS NOT NULL \
                     AND active.revoked_at IS NULL \
               )",
        )
        .bind(credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(generation)
        .execute(&self.pool)
        .await?;

        Ok(if updated.rows_affected() == 1 {
            NodeCredentialMutationResult::Applied
        } else {
            NodeCredentialMutationResult::Rejected
        })
    }

    async fn replace_active_node_credential(
        &self,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        expected_active_credential_id: &str,
        expected_active_generation: i64,
        candidate_credential_id: &str,
        candidate_generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError> {
        if candidate_generation <= expected_active_generation {
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: Result<NodeCredentialMutationResult, DbError> = async {
            let revoked = sqlx::query(
                "UPDATE node_credentials \
                 SET revoked_at = datetime('now'), updated_at = datetime('now') \
                 WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
                   AND activated_at IS NOT NULL AND revoked_at IS NULL",
            )
            .bind(expected_active_credential_id)
            .bind(home_group_id)
            .bind(node_id.as_str())
            .bind(expected_active_generation)
            .execute(&mut *conn)
            .await?;
            if revoked.rows_affected() != 1 {
                return Ok(NodeCredentialMutationResult::Rejected);
            }

            let activated = sqlx::query(
                "UPDATE node_credentials \
                 SET activated_at = datetime('now'), updated_at = datetime('now') \
                 WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
                   AND activated_at IS NULL AND revoked_at IS NULL",
            )
            .bind(candidate_credential_id)
            .bind(home_group_id)
            .bind(node_id.as_str())
            .bind(candidate_generation)
            .execute(&mut *conn)
            .await?;
            if activated.rows_affected() != 1 {
                return Ok(NodeCredentialMutationResult::Rejected);
            }

            Ok(NodeCredentialMutationResult::Applied)
        }
        .await;

        match result {
            Ok(NodeCredentialMutationResult::Applied) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(NodeCredentialMutationResult::Applied)
            }
            Ok(NodeCredentialMutationResult::Rejected) => {
                sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                Ok(NodeCredentialMutationResult::Rejected)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(error)
            }
        }
    }

    async fn revoke_node_credential(
        &self,
        credential_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError> {
        let updated = sqlx::query(
            "UPDATE node_credentials \
             SET revoked_at = datetime('now'), updated_at = datetime('now') \
             WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
               AND revoked_at IS NULL",
        )
        .bind(credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(generation)
        .execute(&self.pool)
        .await?;

        Ok(if updated.rows_affected() == 1 {
            NodeCredentialMutationResult::Applied
        } else {
            NodeCredentialMutationResult::Rejected
        })
    }
}
