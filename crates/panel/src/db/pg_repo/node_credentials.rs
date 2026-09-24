use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    NewNodeCredentialCandidate, NodeCredentialMutationResult, NodeCredentialRecord,
    NodeCredentialRepository,
};
use async_trait::async_trait;

#[async_trait]
impl NodeCredentialRepository for PgRepository {
    async fn allocate_node_credential_candidate(
        &self,
        candidate: &NewNodeCredentialCandidate,
    ) -> Result<NodeCredentialRecord, DbError> {
        let mut tx = self.pool.begin().await?;
        let group_exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
                .bind(candidate.home_group_id)
                .fetch_optional(&mut *tx)
                .await?;
        if group_exists.is_none() {
            return Err(DbError::ForeignKeyViolation);
        }

        let generation: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation), 0) + 1 \
             FROM node_credentials WHERE home_group_id = $1 AND node_id = $2",
        )
        .bind(candidate.home_group_id)
        .bind(candidate.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;

        let record = sqlx::query_as::<_, NodeCredentialRecord>(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING credential_id, home_group_id, node_id, generation, verifier_format, \
                       verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at",
        )
        .bind(&candidate.credential_id)
        .bind(candidate.home_group_id)
        .bind(candidate.node_id.as_str())
        .bind(generation)
        .bind(candidate.verifier.format())
        .bind(candidate.verifier.version())
        .bind(candidate.verifier.data().as_slice())
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(record)
    }

    async fn find_node_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn find_active_node_credential_for_runtime(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials AS current \
             WHERE current.credential_id = $1 \
               AND current.activated_at IS NOT NULL \
               AND current.revoked_at IS NULL \
               AND current.generation = ( \
                   SELECT MAX(history.generation) FROM node_credentials AS history \
                   WHERE history.home_group_id = current.home_group_id \
                     AND history.node_id = current.node_id \
                     AND history.activated_at IS NOT NULL \
               )",
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
             WHERE home_group_id = $1 AND node_id = $2 \
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
        let mut tx = self.pool.begin().await?;
        let locked: Option<i64> =
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
                .bind(home_group_id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        let updated = sqlx::query(
            "UPDATE node_credentials AS candidate \
             SET activated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), \
                 updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
             WHERE credential_id = $1 AND home_group_id = $2 AND node_id = $3 AND generation = $4 \
               AND activated_at IS NULL AND revoked_at IS NULL \
               AND NOT EXISTS ( \
                   SELECT 1 FROM node_credentials AS history \
                   WHERE history.home_group_id = candidate.home_group_id \
                     AND history.node_id = candidate.node_id \
                     AND history.activated_at IS NOT NULL \
               )",
        )
        .bind(credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(generation)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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

        let mut tx = self.pool.begin().await?;
        let locked: Option<i64> =
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
                .bind(home_group_id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        let revoked = sqlx::query(
            "UPDATE node_credentials \
             SET revoked_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), \
                 updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
             WHERE credential_id = $1 AND home_group_id = $2 AND node_id = $3 AND generation = $4 \
               AND activated_at IS NOT NULL AND revoked_at IS NULL",
        )
        .bind(expected_active_credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(expected_active_generation)
        .execute(&mut *tx)
        .await?;
        if revoked.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        let activated = sqlx::query(
            "UPDATE node_credentials AS candidate \
             SET activated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), \
                 updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
             WHERE credential_id = $1 AND home_group_id = $2 AND node_id = $3 AND generation = $4 \
               AND activated_at IS NULL AND revoked_at IS NULL \
               AND candidate.generation > COALESCE(( \
                   SELECT MAX(history.generation) FROM node_credentials AS history \
                   WHERE history.home_group_id = candidate.home_group_id \
                     AND history.node_id = candidate.node_id \
                     AND history.activated_at IS NOT NULL \
               ), 0)",
        )
        .bind(candidate_credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(candidate_generation)
        .execute(&mut *tx)
        .await?;
        if activated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        tx.commit().await?;
        Ok(NodeCredentialMutationResult::Applied)
    }

    async fn revoke_node_credential(
        &self,
        credential_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError> {
        let mut tx = self.pool.begin().await?;
        let locked: Option<i64> =
            sqlx::query_scalar("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
                .bind(home_group_id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Ok(NodeCredentialMutationResult::Rejected);
        }

        let updated = sqlx::query(
            "UPDATE node_credentials \
             SET revoked_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), \
                 updated_at = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') \
             WHERE credential_id = $1 AND home_group_id = $2 AND node_id = $3 AND generation = $4 \
               AND revoked_at IS NULL",
        )
        .bind(credential_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(generation)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(if updated.rows_affected() == 1 {
            NodeCredentialMutationResult::Applied
        } else {
            NodeCredentialMutationResult::Rejected
        })
    }
}
