use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    ManualBootstrapClaim, ManualBootstrapClaimResult, ManualBootstrapEnrollment,
    ManualBootstrapEnrollmentRepository, NewManualBootstrapEnrollment,
};
use async_trait::async_trait;

#[async_trait]
impl ManualBootstrapEnrollmentRepository for PgRepository {
    async fn create_manual_bootstrap_enrollment(
        &self,
        enrollment: &NewManualBootstrapEnrollment,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO manual_bootstrap_enrollments \
             (id, secret_verifier, group_id, profile, state, created_by, created_at, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7, $8)",
        )
        .bind(&enrollment.id)
        .bind(&enrollment.secret_verifier)
        .bind(enrollment.group_id)
        .bind(&enrollment.profile)
        .bind(enrollment.created_by)
        .bind(&enrollment.created_at)
        .bind(&enrollment.created_at)
        .bind(&enrollment.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_manual_bootstrap_enrollment(
        &self,
        id: &str,
    ) -> Result<Option<ManualBootstrapEnrollment>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM manual_bootstrap_enrollments WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn claim_manual_bootstrap_enrollment(
        &self,
        claim: &ManualBootstrapClaim,
    ) -> Result<ManualBootstrapClaimResult, DbError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET \
                 state = 'CLAIMED', architecture = $1, client_nonce_verifier = $2, \
                 session_verifier = $3, session_expires_at = $4, claimed_at = $5, \
                 updated_at = $6, last_error_category = NULL \
             WHERE id = $7 AND secret_verifier = $8 AND profile = $9 \
               AND state = 'PENDING' AND expires_at > $10",
        )
        .bind(&claim.architecture)
        .bind(&claim.client_nonce_verifier)
        .bind(&claim.session_verifier)
        .bind(&claim.session_expires_at)
        .bind(&claim.now)
        .bind(&claim.now)
        .bind(&claim.id)
        .bind(&claim.secret_verifier)
        .bind(&claim.profile)
        .bind(&claim.now)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if changed == 1 {
            let row = sqlx::query_as("SELECT * FROM manual_bootstrap_enrollments WHERE id = $1")
                .bind(&claim.id)
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(ManualBootstrapClaimResult::Claimed(row));
        }

        let Some(row): Option<ManualBootstrapEnrollment> =
            sqlx::query_as("SELECT * FROM manual_bootstrap_enrollments WHERE id = $1")
                .bind(&claim.id)
                .fetch_optional(&mut *tx)
                .await?
        else {
            tx.commit().await?;
            return Ok(ManualBootstrapClaimResult::Invalid);
        };

        if row.secret_verifier != claim.secret_verifier {
            tx.commit().await?;
            return Ok(ManualBootstrapClaimResult::Invalid);
        }
        if row.state == "PENDING" && row.expires_at <= claim.now {
            sqlx::query(
                "UPDATE manual_bootstrap_enrollments \
                 SET state = 'EXPIRED', updated_at = $1 \
                 WHERE id = $2 AND state = 'PENDING' AND expires_at <= $3",
            )
            .bind(&claim.now)
            .bind(&claim.id)
            .bind(&claim.now)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(ManualBootstrapClaimResult::Expired);
        }
        if row.state != "PENDING" && row.session_expires_at.as_deref() <= Some(claim.now.as_str()) {
            if matches!(row.state.as_str(), "CLAIMED" | "VERIFYING") {
                sqlx::query(
                    "UPDATE manual_bootstrap_enrollments \
                     SET state = 'EXPIRED', updated_at = $1 \
                     WHERE id = $2 AND state IN ('CLAIMED','VERIFYING')",
                )
                .bind(&claim.now)
                .bind(&claim.id)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            return Ok(ManualBootstrapClaimResult::Expired);
        }
        let retryable_state = matches!(
            row.state.as_str(),
            "CLAIMED" | "VERIFYING" | "LOCAL_COMMITTED" | "SUCCESS"
        );
        let same_client = row.profile == claim.profile
            && row.architecture.as_deref() == Some(claim.architecture.as_str())
            && row.client_nonce_verifier.as_deref() == Some(claim.client_nonce_verifier.as_str())
            && row.session_verifier.as_deref() == Some(claim.session_verifier.as_str());
        tx.commit().await?;
        if retryable_state && same_client {
            Ok(ManualBootstrapClaimResult::Existing(row))
        } else if row.state == "EXPIRED" {
            Ok(ManualBootstrapClaimResult::Expired)
        } else {
            Ok(ManualBootstrapClaimResult::Replay)
        }
    }

    async fn expire_manual_bootstrap_enrollment(
        &self,
        id: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET state = 'EXPIRED', updated_at = $1 \
             WHERE id = $2 AND (\
                 (state = 'PENDING' AND expires_at <= $3) OR \
                 (state IN ('CLAIMED','VERIFYING') AND session_expires_at <= $4)\
             )",
        )
        .bind(now)
        .bind(id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn record_manual_bootstrap_verification_error(
        &self,
        id: &str,
        session_verifier: &str,
        category: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments \
             SET last_error_category = $1, updated_at = $2 \
             WHERE id = $3 AND session_verifier = $4 AND state IN ('CLAIMED','VERIFYING')",
        )
        .bind(category)
        .bind(now)
        .bind(id)
        .bind(session_verifier)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn mark_manual_bootstrap_verifying(
        &self,
        id: &str,
        session_verifier: &str,
        node_id: &str,
        observed_at: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET \
                 state = 'VERIFYING', node_id = $1, observed_at = $2, verified_at = $3, \
                 updated_at = $4, last_error_category = NULL \
             WHERE id = $5 AND session_verifier = $6 \
               AND (state = 'CLAIMED' OR (state = 'VERIFYING' AND node_id = $7))",
        )
        .bind(node_id)
        .bind(observed_at)
        .bind(now)
        .bind(now)
        .bind(id)
        .bind(session_verifier)
        .bind(node_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn mark_manual_bootstrap_local_committed(
        &self,
        id: &str,
        session_verifier: &str,
        node_id: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET \
                 state = 'LOCAL_COMMITTED', local_committed_at = $1, updated_at = $2, \
                 last_error_category = NULL \
             WHERE id = $3 AND session_verifier = $4 AND state = 'VERIFYING' AND node_id = $5",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .bind(session_verifier)
        .bind(node_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn complete_manual_bootstrap_enrollment(
        &self,
        id: &str,
        session_verifier: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET \
                 state = 'SUCCESS', completed_at = $1, updated_at = $2, last_error_category = NULL \
             WHERE id = $3 AND session_verifier = $4 AND state = 'LOCAL_COMMITTED'",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .bind(session_verifier)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn fail_manual_bootstrap_enrollment(
        &self,
        id: &str,
        session_verifier: &str,
        category: &str,
        now: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE manual_bootstrap_enrollments SET \
                 state = CASE WHEN state IN ('CLAIMED','VERIFYING') THEN 'FAILED' ELSE state END, \
                 last_error_category = $1, updated_at = $2 \
             WHERE id = $3 AND session_verifier = $4 \
               AND state IN ('CLAIMED','VERIFYING','LOCAL_COMMITTED','FAILED')",
        )
        .bind(category)
        .bind(now)
        .bind(id)
        .bind(session_verifier)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
