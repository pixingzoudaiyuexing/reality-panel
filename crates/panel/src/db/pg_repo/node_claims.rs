use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    NewNodeCredentialClaim, NodeCredentialClaimCreateResult, NodeCredentialClaimMutationResult,
    NodeCredentialClaimRecord, NodeCredentialClaimRepository, NodeCredentialClaimResult,
};
use crate::node_claim::{NodeClaimNonceVerifier, NODE_CLAIM_MAX_TTL_SECS};
use async_trait::async_trait;
use chrono::SecondsFormat;

const CLAIM_COLUMNS: &str = "claim_id, home_group_id, node_id, secret_verifier_format, \
    secret_verifier_version, secret_verifier_data, state, expires_at, \
    claimant_nonce_verifier_format, claimant_nonce_verifier_version, \
    claimant_nonce_verifier_data, approved_by, approval_ref, created_at, updated_at, \
    claimed_at, credential_pending_at, completed_at, cancelled_at, expired_at";

fn canonical_time(value: chrono::DateTime<chrono::Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn valid_new_claim(claim: &NewNodeCredentialClaim) -> bool {
    if claim.claim_id.is_empty()
        || claim.claim_id.len() > 128
        || claim.approval_ref.is_empty()
        || claim.approval_ref.len() > 128
    {
        return false;
    }
    let ttl = claim.expires_at.signed_duration_since(claim.created_at);
    ttl > chrono::Duration::seconds(0) && ttl <= chrono::Duration::seconds(NODE_CLAIM_MAX_TTL_SECS)
}

async fn lock_home_group(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    home_group_id: i64,
) -> Result<bool, DbError> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
            .bind(home_group_id)
            .fetch_optional(&mut **tx)
            .await?
            .is_some(),
    )
}

async fn expire_identity_if_due(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    home_group_id: i64,
    node_id: &str,
    now: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE node_credential_deliveries d \
         SET state='EXPIRED', expired_at=$1, updated_at=$1 \
         WHERE home_group_id=$2 AND node_id=$3 AND state='PREPARED' AND expires_at <= $1 \
           AND EXISTS (SELECT 1 FROM node_credential_claims c \
                       WHERE c.claim_id=d.claim_id AND c.state='CREDENTIAL_PENDING')",
    )
    .bind(now)
    .bind(home_group_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE node_credential_claims c \
         SET state='EXPIRED', expired_at=$1, updated_at=$1 \
         WHERE home_group_id=$2 AND node_id=$3 AND state='CREDENTIAL_PENDING' \
           AND EXISTS (SELECT 1 FROM node_credential_deliveries d \
                       WHERE d.claim_id=c.claim_id AND d.state='EXPIRED')",
    )
    .bind(now)
    .bind(home_group_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE node_credential_claims \
         SET state = 'EXPIRED', expired_at = $1, updated_at = $1 \
         WHERE home_group_id = $2 AND node_id = $3 \
           AND state IN ('APPROVED','CLAIMED') AND expires_at <= $1",
    )
    .bind(now)
    .bind(home_group_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn fetch_claim_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim_id: &str,
) -> Result<Option<NodeCredentialClaimRecord>, DbError> {
    let sql = format!(
        "SELECT {CLAIM_COLUMNS} FROM node_credential_claims WHERE claim_id = $1 FOR UPDATE"
    );
    Ok(sqlx::query_as::<_, NodeCredentialClaimRecord>(&sql)
        .bind(claim_id)
        .fetch_optional(&mut **tx)
        .await?)
}

#[async_trait]
impl NodeCredentialClaimRepository for PgRepository {
    async fn create_node_credential_claim(
        &self,
        claim: &NewNodeCredentialClaim,
    ) -> Result<NodeCredentialClaimCreateResult, DbError> {
        if !valid_new_claim(claim) {
            return Ok(NodeCredentialClaimCreateResult::Rejected);
        }
        let created_at = canonical_time(claim.created_at);
        let expires_at = canonical_time(claim.expires_at);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, claim.home_group_id).await? {
            tx.rollback().await?;
            return Err(DbError::ForeignKeyViolation);
        }
        expire_identity_if_due(
            &mut tx,
            claim.home_group_id,
            claim.node_id.as_str(),
            &created_at,
        )
        .await?;

        let existing_sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM node_credential_claims \
             WHERE home_group_id = $1 AND node_id = $2 \
               AND state IN ('APPROVED','CLAIMED') FOR UPDATE"
        );
        if let Some(existing) = sqlx::query_as::<_, NodeCredentialClaimRecord>(&existing_sql)
            .bind(claim.home_group_id)
            .bind(claim.node_id.as_str())
            .fetch_optional(&mut *tx)
            .await?
        {
            tx.commit().await?;
            return Ok(NodeCredentialClaimCreateResult::Existing(existing));
        }

        let insert_sql = format!(
            "INSERT INTO node_credential_claims \
             (claim_id, home_group_id, node_id, secret_verifier_format, secret_verifier_version, \
              secret_verifier_data, state, expires_at, approved_by, approval_ref, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,'APPROVED',$7,$8,$9,$10,$10) \
             RETURNING {CLAIM_COLUMNS}"
        );
        let record = sqlx::query_as::<_, NodeCredentialClaimRecord>(&insert_sql)
            .bind(&claim.claim_id)
            .bind(claim.home_group_id)
            .bind(claim.node_id.as_str())
            .bind(claim.secret_verifier.format())
            .bind(claim.secret_verifier.version())
            .bind(claim.secret_verifier.data().as_slice())
            .bind(&expires_at)
            .bind(claim.approved_by)
            .bind(&claim.approval_ref)
            .bind(&created_at)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(NodeCredentialClaimCreateResult::Created(record))
    }

    async fn find_node_credential_claim(
        &self,
        claim_id: &str,
    ) -> Result<Option<NodeCredentialClaimRecord>, DbError> {
        let sql = format!("SELECT {CLAIM_COLUMNS} FROM node_credential_claims WHERE claim_id = $1");
        Ok(sqlx::query_as::<_, NodeCredentialClaimRecord>(&sql)
            .bind(claim_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn list_node_credential_claims_for_identity(
        &self,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
    ) -> Result<Vec<NodeCredentialClaimRecord>, DbError> {
        let sql = format!(
            "SELECT {CLAIM_COLUMNS} FROM node_credential_claims \
             WHERE home_group_id = $1 AND node_id = $2 ORDER BY created_at ASC, claim_id ASC"
        );
        Ok(sqlx::query_as::<_, NodeCredentialClaimRecord>(&sql)
            .bind(home_group_id)
            .bind(node_id.as_str())
            .fetch_all(&self.pool)
            .await?)
    }

    async fn claim_node_credential(
        &self,
        attempt: &crate::db::repo::NodeCredentialClaimAttempt,
    ) -> Result<NodeCredentialClaimResult, DbError> {
        let now = canonical_time(attempt.now);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, attempt.home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimResult::Invalid);
        }
        let Some(record) = fetch_claim_tx(&mut tx, &attempt.claim_id).await? else {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimResult::Invalid);
        };
        if record.home_group_id != attempt.home_group_id
            || record.node_id != attempt.node_id.as_str()
            || !record.secret_matches(&attempt.node_id, &attempt.secret)
        {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimResult::Invalid);
        }

        if matches!(record.state.as_str(), "APPROVED" | "CLAIMED") && record.expires_at <= now {
            sqlx::query(
                "UPDATE node_credential_claims SET state='EXPIRED', expired_at=$1, updated_at=$1 \
                 WHERE claim_id=$2 AND state IN ('APPROVED','CLAIMED')",
            )
            .bind(&now)
            .bind(&attempt.claim_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(NodeCredentialClaimResult::Expired);
        }

        match record.state.as_str() {
            "CANCELLED" => {
                tx.rollback().await?;
                Ok(NodeCredentialClaimResult::Cancelled)
            }
            "EXPIRED" => {
                tx.rollback().await?;
                Ok(NodeCredentialClaimResult::Expired)
            }
            "CLAIMED" => {
                let result =
                    if record.claimant_nonce_matches(&attempt.node_id, &attempt.claimant_nonce) {
                        NodeCredentialClaimResult::Existing(record)
                    } else {
                        NodeCredentialClaimResult::Replay
                    };
                tx.rollback().await?;
                Ok(result)
            }
            "APPROVED" => {
                let nonce = NodeClaimNonceVerifier::derive(
                    &attempt.claim_id,
                    attempt.home_group_id,
                    &attempt.node_id,
                    &attempt.claimant_nonce,
                );
                let update_sql = format!(
                    "UPDATE node_credential_claims \
                     SET state='CLAIMED', claimant_nonce_verifier_format=$1, \
                         claimant_nonce_verifier_version=$2, claimant_nonce_verifier_data=$3, \
                         claimed_at=$4, updated_at=$4 \
                     WHERE claim_id=$5 AND home_group_id=$6 AND node_id=$7 \
                       AND state='APPROVED' AND expires_at > $4 \
                     RETURNING {CLAIM_COLUMNS}"
                );
                let claimed = sqlx::query_as::<_, NodeCredentialClaimRecord>(&update_sql)
                    .bind(nonce.format())
                    .bind(nonce.version())
                    .bind(nonce.data().as_slice())
                    .bind(&now)
                    .bind(&attempt.claim_id)
                    .bind(attempt.home_group_id)
                    .bind(attempt.node_id.as_str())
                    .fetch_optional(&mut *tx)
                    .await?;
                let Some(claimed) = claimed else {
                    tx.rollback().await?;
                    return Ok(NodeCredentialClaimResult::Invalid);
                };
                tx.commit().await?;
                Ok(NodeCredentialClaimResult::Claimed(claimed))
            }
            _ => {
                tx.rollback().await?;
                Ok(NodeCredentialClaimResult::Invalid)
            }
        }
    }

    async fn cancel_node_credential_claim(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialClaimMutationResult, DbError> {
        let now = canonical_time(now);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimMutationResult::Rejected);
        }
        expire_identity_if_due(&mut tx, home_group_id, node_id.as_str(), &now).await?;

        let delivery = sqlx::query(
            "UPDATE node_credential_deliveries d SET state='CANCELLED', cancelled_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 AND state='PREPARED' \
               AND EXISTS (SELECT 1 FROM node_credential_claims c \
                           WHERE c.claim_id=d.claim_id AND c.state='CREDENTIAL_PENDING')",
        )
        .bind(&now)
        .bind(claim_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        if delivery.rows_affected() == 1 {
            let claim = sqlx::query(
                "UPDATE node_credential_claims SET state='CANCELLED', cancelled_at=$1, updated_at=$1 \
                 WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 AND state='CREDENTIAL_PENDING'",
            )
            .bind(&now)
            .bind(claim_id)
            .bind(home_group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
            if claim.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(NodeCredentialClaimMutationResult::Rejected);
            }
            tx.commit().await?;
            return Ok(NodeCredentialClaimMutationResult::Applied);
        }

        let updated = sqlx::query(
            "UPDATE node_credential_claims SET state='CANCELLED', cancelled_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 \
               AND state IN ('APPROVED','CLAIMED')",
        )
        .bind(&now)
        .bind(claim_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(if updated.rows_affected() == 1 {
            NodeCredentialClaimMutationResult::Applied
        } else {
            NodeCredentialClaimMutationResult::Rejected
        })
    }

    async fn expire_node_credential_claim(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialClaimMutationResult, DbError> {
        let now = canonical_time(now);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimMutationResult::Rejected);
        }

        let delivery = sqlx::query(
            "UPDATE node_credential_deliveries SET state='EXPIRED', expired_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 \
               AND state='PREPARED' AND expires_at <= $1",
        )
        .bind(&now)
        .bind(claim_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        if delivery.rows_affected() == 1 {
            let claim = sqlx::query(
                "UPDATE node_credential_claims SET state='EXPIRED', expired_at=$1, updated_at=$1 \
                 WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 AND state='CREDENTIAL_PENDING'",
            )
            .bind(&now)
            .bind(claim_id)
            .bind(home_group_id)
            .bind(node_id.as_str())
            .execute(&mut *tx)
            .await?;
            if claim.rows_affected() != 1 {
                tx.rollback().await?;
                return Ok(NodeCredentialClaimMutationResult::Rejected);
            }
            tx.commit().await?;
            return Ok(NodeCredentialClaimMutationResult::Applied);
        }

        let updated = sqlx::query(
            "UPDATE node_credential_claims SET state='EXPIRED', expired_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 \
               AND state IN ('APPROVED','CLAIMED') AND expires_at <= $1",
        )
        .bind(&now)
        .bind(claim_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(if updated.rows_affected() == 1 {
            NodeCredentialClaimMutationResult::Applied
        } else {
            NodeCredentialClaimMutationResult::Rejected
        })
    }
}
