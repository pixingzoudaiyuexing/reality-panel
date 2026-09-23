use super::SqliteRepository;
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
    claimed_at, cancelled_at, expired_at";

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

async fn lock_group_writer(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    home_group_id: i64,
) -> Result<bool, DbError> {
    // First statement after BEGIN is a write. This acquires SQLite's writer
    // serialization boundary before any read snapshot is established.
    let locked = sqlx::query("UPDATE device_groups SET name = name WHERE id = ?")
        .bind(home_group_id)
        .execute(&mut **tx)
        .await?;
    Ok(locked.rows_affected() == 1)
}

async fn expire_identity_if_due(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    home_group_id: i64,
    node_id: &str,
    now: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE node_credential_claims \
         SET state = 'EXPIRED', expired_at = ?, updated_at = ? \
         WHERE home_group_id = ? AND node_id = ? \
           AND state IN ('APPROVED','CLAIMED') AND expires_at <= ?",
    )
    .bind(now)
    .bind(now)
    .bind(home_group_id)
    .bind(node_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn fetch_claim_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    claim_id: &str,
) -> Result<Option<NodeCredentialClaimRecord>, DbError> {
    let sql = format!("SELECT {CLAIM_COLUMNS} FROM node_credential_claims WHERE claim_id = ?");
    Ok(sqlx::query_as::<_, NodeCredentialClaimRecord>(&sql)
        .bind(claim_id)
        .fetch_optional(&mut **tx)
        .await?)
}

#[async_trait]
impl NodeCredentialClaimRepository for SqliteRepository {
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
        if !lock_group_writer(&mut tx, claim.home_group_id).await? {
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
             WHERE home_group_id = ? AND node_id = ? \
               AND state IN ('APPROVED','CLAIMED')"
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
             VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?, ?, ?, ?) \
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
        let sql = format!("SELECT {CLAIM_COLUMNS} FROM node_credential_claims WHERE claim_id = ?");
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
             WHERE home_group_id = ? AND node_id = ? ORDER BY created_at ASC, claim_id ASC"
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
        if !lock_group_writer(&mut tx, attempt.home_group_id).await? {
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
                "UPDATE node_credential_claims SET state='EXPIRED', expired_at=?, updated_at=? \
                 WHERE claim_id=? AND state IN ('APPROVED','CLAIMED')",
            )
            .bind(&now)
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
                     SET state='CLAIMED', claimant_nonce_verifier_format=?, \
                         claimant_nonce_verifier_version=?, claimant_nonce_verifier_data=?, \
                         claimed_at=?, updated_at=? \
                     WHERE claim_id=? AND home_group_id=? AND node_id=? \
                       AND state='APPROVED' AND expires_at > ? \
                     RETURNING {CLAIM_COLUMNS}"
                );
                let claimed = sqlx::query_as::<_, NodeCredentialClaimRecord>(&update_sql)
                    .bind(nonce.format())
                    .bind(nonce.version())
                    .bind(nonce.data().as_slice())
                    .bind(&now)
                    .bind(&now)
                    .bind(&attempt.claim_id)
                    .bind(attempt.home_group_id)
                    .bind(attempt.node_id.as_str())
                    .bind(&now)
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
        if !lock_group_writer(&mut tx, home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimMutationResult::Rejected);
        }
        expire_identity_if_due(&mut tx, home_group_id, node_id.as_str(), &now).await?;
        let updated = sqlx::query(
            "UPDATE node_credential_claims SET state='CANCELLED', cancelled_at=?, updated_at=? \
             WHERE claim_id=? AND home_group_id=? AND node_id=? \
               AND state IN ('APPROVED','CLAIMED')",
        )
        .bind(&now)
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
        if !lock_group_writer(&mut tx, home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialClaimMutationResult::Rejected);
        }
        let updated = sqlx::query(
            "UPDATE node_credential_claims SET state='EXPIRED', expired_at=?, updated_at=? \
             WHERE claim_id=? AND home_group_id=? AND node_id=? \
               AND state IN ('APPROVED','CLAIMED') AND expires_at <= ?",
        )
        .bind(&now)
        .bind(&now)
        .bind(claim_id)
        .bind(home_group_id)
        .bind(node_id.as_str())
        .bind(&now)
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::db::repo::{
        NewNodeCredentialClaim, NodeCredentialClaimAttempt, NodeCredentialClaimCreateResult,
        NodeCredentialClaimRepository, NodeCredentialClaimResult,
    };
    use crate::db::schema::SCHEMA_SQL;
    use crate::node_claim::{NodeClaimSecret, NodeClaimSecretVerifier, NodeClaimantNonce};
    use crate::node_identity::ReuseEligibleNodeId;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use std::time::Duration;

    async fn claim_test_repo(
        name: &str,
    ) -> (
        SqliteRepository,
        std::path::PathBuf,
        String,
        NodeClaimSecret,
    ) {
        let path = std::env::temp_dir().join(format!(
            "reality-panel-claim-{name}-{}.db",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true)
            .busy_timeout(Duration::from_millis(250));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'gin', 'in', 'tok-claim', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let db = SqliteRepository::new(pool);
        let node_id = ReuseEligibleNodeId::parse("cancel-node").unwrap();
        let secret = NodeClaimSecret::from_test_bytes([0x31; 32]);
        let verifier = NodeClaimSecretVerifier::derive("claim-cancel", 10, &node_id, &secret);
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T18:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let claim = NewNodeCredentialClaim {
            claim_id: "claim-cancel".into(),
            home_group_id: 10,
            node_id,
            secret_verifier: verifier,
            approved_by: 1,
            approval_ref: "approval-cancel-test".into(),
            created_at,
            expires_at: created_at + chrono::Duration::minutes(10),
        };
        assert!(matches!(
            db.create_node_credential_claim(&claim).await.unwrap(),
            NodeCredentialClaimCreateResult::Created(_)
        ));
        (db, path, url, secret)
    }

    fn cleanup_sqlite_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn claim_transaction_cancellation_rolls_back_state_nonce_and_writer_lock() {
        let (db, path, url, _) = claim_test_repo("cancel").await;
        let task_pool = db.pool.clone();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            let mut tx = task_pool.begin().await.unwrap();
            sqlx::query("UPDATE device_groups SET name=name WHERE id=10")
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query(
                "UPDATE node_credential_claims \
                 SET state='CLAIMED', claimant_nonce_verifier_format='rp-node-claim-nonce-sha256', \
                     claimant_nonce_verifier_version=1, claimant_nonce_verifier_data=?, \
                     claimed_at='2026-09-23T18:00:01Z', updated_at='2026-09-23T18:00:01Z' \
                 WHERE claim_id='claim-cancel' AND state='APPROVED'",
            )
            .bind(vec![0x42_u8; 32])
            .execute(&mut *tx)
            .await
            .unwrap();
            let _ = reached_tx.send(());
            let _ = resume_rx.await;
            tx.commit().await.unwrap();
        });

        tokio::time::timeout(Duration::from_secs(2), reached_rx)
            .await
            .expect("claim transaction did not reach post-CAS cancellation point")
            .expect("claim transaction dropped cancellation signal");
        task.abort();
        let join_error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled claim transaction did not terminate")
            .expect_err("claim transaction unexpectedly completed");
        assert!(join_error.is_cancelled());

        tokio::time::timeout(Duration::from_secs(2), async {
            let tx = db.pool.begin().await.unwrap();
            tx.rollback().await.unwrap();
        })
        .await
        .expect("queued SQLx rollback did not complete on connection reuse");

        let row = db
            .find_node_credential_claim("claim-cancel")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "APPROVED");
        assert!(row.claimed_at.is_none());
        assert!(row.claimant_nonce_verifier_data.is_none());

        let other_options = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .busy_timeout(Duration::from_millis(250));
        let other_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(other_options)
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query("UPDATE device_groups SET name=name WHERE id=10").execute(&other_pool),
        )
        .await
        .expect("cancelled Claim transaction left a stale writer lock")
        .unwrap();
        other_pool.close().await;
        db.pool.close().await;
        cleanup_sqlite_files(&path);
    }

    #[tokio::test]
    async fn claim_database_error_rolls_back_and_valid_retry_succeeds() {
        let (db, path, _, secret) = claim_test_repo("db-error").await;
        sqlx::query(
            "CREATE TRIGGER fail_claim_transition \
             BEFORE UPDATE OF state ON node_credential_claims \
             WHEN OLD.claim_id='claim-cancel' AND NEW.state='CLAIMED' \
             BEGIN SELECT RAISE(ABORT, 'forced claim transition failure'); END",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        let now = chrono::DateTime::parse_from_rfc3339("2026-09-23T18:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let attempt = NodeCredentialClaimAttempt {
            claim_id: "claim-cancel".into(),
            home_group_id: 10,
            node_id: ReuseEligibleNodeId::parse("cancel-node").unwrap(),
            secret,
            claimant_nonce: NodeClaimantNonce::from_test_bytes([0x51; 32]),
            now,
        };
        assert!(db.claim_node_credential(&attempt).await.is_err());

        tokio::time::timeout(Duration::from_secs(2), async {
            let tx = db.pool.begin().await.unwrap();
            tx.rollback().await.unwrap();
        })
        .await
        .expect("rollback after Claim database error did not complete");

        let row = db
            .find_node_credential_claim("claim-cancel")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, "APPROVED");
        assert!(row.claimant_nonce_verifier_data.is_none());

        sqlx::query("DROP TRIGGER fail_claim_transition")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            db.claim_node_credential(&attempt).await.unwrap(),
            NodeCredentialClaimResult::Claimed(_)
        ));
        let credential_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_credentials")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(credential_count, 0);
        db.pool.close().await;
        cleanup_sqlite_files(&path);
    }
}
