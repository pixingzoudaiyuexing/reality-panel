use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    ActivateInitialNodeCredentialFromDelivery, NodeCredentialClaimRecord,
    NodeCredentialDeliveryActivateResult, NodeCredentialDeliveryMutationResult,
    NodeCredentialDeliveryPrepareResult, NodeCredentialDeliveryRecord,
    NodeCredentialDeliveryRepository, NodeCredentialRecord, PrepareInitialNodeCredentialDelivery,
    NODE_CREDENTIAL_DELIVERY_TTL_SECS,
};
use crate::node_credential::{
    NodeCredentialDeliveryNonceVerifier, NodeCredentialVerifier, NODE_CREDENTIAL_VERIFIER_FORMAT,
    NODE_CREDENTIAL_VERIFIER_VERSION,
};
use async_trait::async_trait;
use chrono::SecondsFormat;

const CLAIM_COLUMNS: &str = "claim_id, home_group_id, node_id, secret_verifier_format, \
    secret_verifier_version, secret_verifier_data, state, expires_at, \
    claimant_nonce_verifier_format, claimant_nonce_verifier_version, \
    claimant_nonce_verifier_data, approved_by, approval_ref, created_at, updated_at, \
    claimed_at, credential_pending_at, completed_at, cancelled_at, expired_at";

const DELIVERY_COLUMNS: &str = "claim_id, home_group_id, node_id, credential_id, \
    credential_verifier_format, credential_verifier_version, credential_verifier_data, \
    delivery_nonce_verifier_format, delivery_nonce_verifier_version, \
    delivery_nonce_verifier_data, state, authorized_at, expires_at, updated_at, \
    credential_generation, proof_verified_at, completed_at, cancelled_at, expired_at";

const CREDENTIAL_COLUMNS: &str = "credential_id, home_group_id, node_id, generation, \
    verifier_format, verifier_version, verifier_data, created_at, updated_at, \
    activated_at, revoked_at";

#[cfg(test)]
#[derive(Clone)]
pub(super) struct ActivationPauseHandle {
    pub reached: std::sync::Arc<tokio::sync::Notify>,
    pub resume: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
#[derive(Clone)]
struct ActivationPause {
    claim_id: String,
    handle: ActivationPauseHandle,
}

#[cfg(test)]
static TEST_ACTIVATION_PAUSE: once_cell::sync::Lazy<std::sync::Mutex<Option<ActivationPause>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(super) fn install_activation_pause_for_test(claim_id: &str) -> ActivationPauseHandle {
    let handle = ActivationPauseHandle {
        reached: std::sync::Arc::new(tokio::sync::Notify::new()),
        resume: std::sync::Arc::new(tokio::sync::Notify::new()),
    };
    *TEST_ACTIVATION_PAUSE.lock().unwrap() = Some(ActivationPause {
        claim_id: claim_id.to_string(),
        handle: handle.clone(),
    });
    handle
}

#[cfg(test)]
pub(super) fn clear_activation_pause_for_test() {
    *TEST_ACTIVATION_PAUSE.lock().unwrap() = None;
}

#[cfg(test)]
async fn maybe_pause_after_credential_insert_for_test(claim_id: &str) {
    let pause = TEST_ACTIVATION_PAUSE
        .lock()
        .unwrap()
        .as_ref()
        .filter(|pause| pause.claim_id == claim_id)
        .cloned();
    if let Some(pause) = pause {
        pause.handle.reached.notify_one();
        pause.handle.resume.notified().await;
    }
}

fn canonical_time(value: chrono::DateTime<chrono::Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

async fn lock_home_group(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    home_group_id: i64,
) -> Result<bool, DbError> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT id FROM device_groups WHERE id=$1 FOR UPDATE")
            .bind(home_group_id)
            .fetch_optional(&mut **tx)
            .await?
            .is_some(),
    )
}

async fn fetch_claim_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim_id: &str,
) -> Result<Option<NodeCredentialClaimRecord>, DbError> {
    let sql =
        format!("SELECT {CLAIM_COLUMNS} FROM node_credential_claims WHERE claim_id=$1 FOR UPDATE");
    Ok(sqlx::query_as::<_, NodeCredentialClaimRecord>(&sql)
        .bind(claim_id)
        .fetch_optional(&mut **tx)
        .await?)
}

async fn fetch_delivery_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim_id: &str,
) -> Result<Option<NodeCredentialDeliveryRecord>, DbError> {
    let sql = format!(
        "SELECT {DELIVERY_COLUMNS} FROM node_credential_deliveries WHERE claim_id=$1 FOR UPDATE"
    );
    Ok(sqlx::query_as::<_, NodeCredentialDeliveryRecord>(&sql)
        .bind(claim_id)
        .fetch_optional(&mut **tx)
        .await?)
}

async fn fetch_credential_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    credential_id: &str,
) -> Result<Option<NodeCredentialRecord>, DbError> {
    let sql = format!("SELECT {CREDENTIAL_COLUMNS} FROM node_credentials WHERE credential_id=$1");
    Ok(sqlx::query_as::<_, NodeCredentialRecord>(&sql)
        .bind(credential_id)
        .fetch_optional(&mut **tx)
        .await?)
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn prepare_material_matches(
    record: &NodeCredentialDeliveryRecord,
    request: &PrepareInitialNodeCredentialDelivery,
) -> bool {
    record.home_group_id == request.home_group_id
        && record.node_id == request.node_id.as_str()
        && record.credential_id == request.credential_id
        && record.delivery_nonce_matches(&request.node_id, &request.delivery_nonce)
        && record.presented_verifier_matches(&request.presented_verifier)
}

async fn expire_prepared_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim_id: &str,
    home_group_id: i64,
    node_id: &str,
    now: &str,
) -> Result<bool, DbError> {
    let delivery = sqlx::query(
        "UPDATE node_credential_deliveries SET state='EXPIRED', expired_at=$1, updated_at=$1 \
         WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 \
           AND state='PREPARED' AND expires_at <= $1",
    )
    .bind(now)
    .bind(claim_id)
    .bind(home_group_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    if delivery.rows_affected() == 0 {
        return Ok(false);
    }
    let claim = sqlx::query(
        "UPDATE node_credential_claims SET state='EXPIRED', expired_at=$1, updated_at=$1 \
         WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 AND state='CREDENTIAL_PENDING'",
    )
    .bind(now)
    .bind(claim_id)
    .bind(home_group_id)
    .bind(node_id)
    .execute(&mut **tx)
    .await?;
    Ok(claim.rows_affected() == 1)
}

#[async_trait]
impl NodeCredentialDeliveryRepository for PgRepository {
    async fn find_node_credential_delivery(
        &self,
        claim_id: &str,
    ) -> Result<Option<NodeCredentialDeliveryRecord>, DbError> {
        let sql =
            format!("SELECT {DELIVERY_COLUMNS} FROM node_credential_deliveries WHERE claim_id=$1");
        Ok(sqlx::query_as::<_, NodeCredentialDeliveryRecord>(&sql)
            .bind(claim_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn prepare_initial_node_credential_delivery(
        &self,
        request: &PrepareInitialNodeCredentialDelivery,
    ) -> Result<NodeCredentialDeliveryPrepareResult, DbError> {
        if !valid_credential_id(&request.credential_id) {
            return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
        }
        let now = canonical_time(request.now);
        let delivery_expires_at = canonical_time(
            request.now + chrono::Duration::seconds(NODE_CREDENTIAL_DELIVERY_TTL_SECS),
        );
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, request.home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
        }

        let Some(claim) = fetch_claim_tx(&mut tx, &request.claim_id).await? else {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
        };
        if claim.home_group_id != request.home_group_id
            || claim.node_id != request.node_id.as_str()
            || !claim.secret_matches(&request.node_id, &request.claim_secret)
            || !claim.claimant_nonce_matches(&request.node_id, &request.claimant_nonce)
        {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
        }

        if matches!(claim.state.as_str(), "APPROVED" | "CLAIMED") && claim.expires_at <= now {
            sqlx::query(
                "UPDATE node_credential_claims SET state='EXPIRED', expired_at=$1, updated_at=$1 \
                 WHERE claim_id=$2 AND state IN ('APPROVED','CLAIMED')",
            )
            .bind(&now)
            .bind(&request.claim_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Expired);
        }

        match claim.state.as_str() {
            "CANCELLED" => {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryPrepareResult::Cancelled);
            }
            "EXPIRED" => {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryPrepareResult::Expired);
            }
            "CREDENTIAL_PENDING" => {
                let Some(delivery) = fetch_delivery_tx(&mut tx, &request.claim_id).await? else {
                    tx.rollback().await?;
                    return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
                };
                if delivery.state == "PREPARED" && delivery.expires_at <= now {
                    if !expire_prepared_tx(
                        &mut tx,
                        &request.claim_id,
                        request.home_group_id,
                        request.node_id.as_str(),
                        &now,
                    )
                    .await?
                    {
                        tx.rollback().await?;
                        return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
                    }
                    tx.commit().await?;
                    return Ok(NodeCredentialDeliveryPrepareResult::Expired);
                }
                let result = if delivery.state == "PREPARED"
                    && prepare_material_matches(&delivery, request)
                {
                    NodeCredentialDeliveryPrepareResult::Existing(delivery)
                } else if delivery.state == "CANCELLED" {
                    NodeCredentialDeliveryPrepareResult::Cancelled
                } else if delivery.state == "EXPIRED" {
                    NodeCredentialDeliveryPrepareResult::Expired
                } else {
                    NodeCredentialDeliveryPrepareResult::Replay
                };
                tx.rollback().await?;
                return Ok(result);
            }
            "COMPLETED" => {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryPrepareResult::Replay);
            }
            "CLAIMED" => {}
            _ => {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
            }
        }

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credentials \
             WHERE home_group_id=$1 AND node_id=$2 \
               AND activated_at IS NOT NULL AND revoked_at IS NULL",
        )
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if active_count != 0 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::AlreadyActive);
        }
        let activation_history: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credentials \
             WHERE home_group_id=$1 AND node_id=$2 AND activated_at IS NOT NULL",
        )
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if activation_history != 0 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::RecoveryRequired);
        }
        let credential_id_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM node_credentials WHERE credential_id=$1")
                .bind(&request.credential_id)
                .fetch_one(&mut *tx)
                .await?;
        if credential_id_exists != 0
            || fetch_delivery_tx(&mut tx, &request.claim_id)
                .await?
                .is_some()
        {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Replay);
        }

        let nonce_verifier = NodeCredentialDeliveryNonceVerifier::derive(
            &request.claim_id,
            request.home_group_id,
            &request.node_id,
            &request.delivery_nonce,
        );
        let sql = format!(
            "INSERT INTO node_credential_deliveries (\
                 claim_id, home_group_id, node_id, credential_id, \
                 credential_verifier_format, credential_verifier_version, credential_verifier_data, \
                 delivery_nonce_verifier_format, delivery_nonce_verifier_version, delivery_nonce_verifier_data, \
                 state, authorized_at, expires_at, updated_at\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED',$11,$12,$11) \
             RETURNING {DELIVERY_COLUMNS}"
        );
        let delivery = sqlx::query_as::<_, NodeCredentialDeliveryRecord>(&sql)
            .bind(&request.claim_id)
            .bind(request.home_group_id)
            .bind(request.node_id.as_str())
            .bind(&request.credential_id)
            .bind(request.presented_verifier.format())
            .bind(request.presented_verifier.version())
            .bind(request.presented_verifier.data().as_slice())
            .bind(nonce_verifier.format())
            .bind(nonce_verifier.version())
            .bind(nonce_verifier.data().as_slice())
            .bind(&now)
            .bind(&delivery_expires_at)
            .fetch_one(&mut *tx)
            .await?;

        let claim_update = sqlx::query(
            "UPDATE node_credential_claims \
             SET state='CREDENTIAL_PENDING', credential_pending_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 \
               AND state='CLAIMED' AND expires_at > $1",
        )
        .bind(&now)
        .bind(&request.claim_id)
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .execute(&mut *tx)
        .await?;
        if claim_update.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryPrepareResult::Invalid);
        }

        tx.commit().await?;
        Ok(NodeCredentialDeliveryPrepareResult::Prepared(delivery))
    }

    async fn activate_initial_node_credential_from_delivery(
        &self,
        request: &ActivateInitialNodeCredentialFromDelivery,
    ) -> Result<NodeCredentialDeliveryActivateResult, DbError> {
        let now = canonical_time(request.now);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, request.home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        }

        let Some(claim) = fetch_claim_tx(&mut tx, &request.claim_id).await? else {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        };
        let Some(delivery) = fetch_delivery_tx(&mut tx, &request.claim_id).await? else {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        };
        if claim.home_group_id != request.home_group_id
            || claim.node_id != request.node_id.as_str()
            || delivery.home_group_id != request.home_group_id
            || delivery.node_id != request.node_id.as_str()
            || delivery.credential_id != request.credential_id
            || !delivery.delivery_nonce_matches(&request.node_id, &request.delivery_nonce)
        {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        }

        let derived = NodeCredentialVerifier::derive(
            &request.credential_id,
            request.home_group_id,
            &request.node_id,
            &request.credential_secret,
        );
        let proof_matches = delivery.credential_verifier_format == NODE_CREDENTIAL_VERIFIER_FORMAT
            && delivery.credential_verifier_version == NODE_CREDENTIAL_VERIFIER_VERSION
            && derived.verify_data(&delivery.credential_verifier_data);

        if claim.state == "COMPLETED" && delivery.state == "COMPLETED" {
            if !proof_matches {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::InvalidProof);
            }
            let Some(generation) = delivery.credential_generation else {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::Invalid);
            };
            let Some(credential) = fetch_credential_tx(&mut tx, &request.credential_id).await?
            else {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::Invalid);
            };
            if credential.home_group_id != request.home_group_id
                || credential.node_id != request.node_id.as_str()
                || credential.generation != generation
                || credential.activated_at.is_none()
                || !derived.verify_data(&credential.verifier_data)
            {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::InvalidProof);
            }
            if credential.revoked_at.is_some() {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::CredentialRevoked);
            }
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Existing {
                delivery,
                credential,
            });
        }

        if claim.state == "CANCELLED" || delivery.state == "CANCELLED" {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Cancelled);
        }
        if claim.state == "EXPIRED" || delivery.state == "EXPIRED" {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Expired);
        }
        if claim.state != "CREDENTIAL_PENDING" || delivery.state != "PREPARED" {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        }
        if delivery.expires_at <= now {
            if !expire_prepared_tx(
                &mut tx,
                &request.claim_id,
                request.home_group_id,
                request.node_id.as_str(),
                &now,
            )
            .await?
            {
                tx.rollback().await?;
                return Ok(NodeCredentialDeliveryActivateResult::Invalid);
            }
            tx.commit().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Expired);
        }
        if !proof_matches {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::InvalidProof);
        }

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credentials \
             WHERE home_group_id=$1 AND node_id=$2 \
               AND activated_at IS NOT NULL AND revoked_at IS NULL",
        )
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if active_count != 0 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::AlreadyActive);
        }
        let activation_history: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_credentials \
             WHERE home_group_id=$1 AND node_id=$2 AND activated_at IS NOT NULL",
        )
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if activation_history != 0 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::RecoveryRequired);
        }

        let generation: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation),0)+1 FROM node_credentials \
             WHERE home_group_id=$1 AND node_id=$2",
        )
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        let sql = format!(
            "INSERT INTO node_credentials (\
                 credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, \
                 verifier_data, created_at, updated_at, activated_at\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$8) RETURNING {CREDENTIAL_COLUMNS}"
        );
        let credential = sqlx::query_as::<_, NodeCredentialRecord>(&sql)
            .bind(&request.credential_id)
            .bind(request.home_group_id)
            .bind(request.node_id.as_str())
            .bind(generation)
            .bind(derived.format())
            .bind(derived.version())
            .bind(derived.data().as_slice())
            .bind(&now)
            .fetch_one(&mut *tx)
            .await?;

        #[cfg(test)]
        maybe_pause_after_credential_insert_for_test(&request.claim_id).await;

        let sql = format!(
            "UPDATE node_credential_deliveries \
             SET state='COMPLETED', credential_generation=$1, proof_verified_at=$2, \
                 completed_at=$2, updated_at=$2 \
             WHERE claim_id=$3 AND home_group_id=$4 AND node_id=$5 AND credential_id=$6 \
               AND state='PREPARED' AND expires_at > $2 \
             RETURNING {DELIVERY_COLUMNS}"
        );
        let completed = sqlx::query_as::<_, NodeCredentialDeliveryRecord>(&sql)
            .bind(generation)
            .bind(&now)
            .bind(&request.claim_id)
            .bind(request.home_group_id)
            .bind(request.node_id.as_str())
            .bind(&request.credential_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(delivery) = completed else {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        };
        let claim_update = sqlx::query(
            "UPDATE node_credential_claims \
             SET state='COMPLETED', completed_at=$1, updated_at=$1 \
             WHERE claim_id=$2 AND home_group_id=$3 AND node_id=$4 AND state='CREDENTIAL_PENDING'",
        )
        .bind(&now)
        .bind(&request.claim_id)
        .bind(request.home_group_id)
        .bind(request.node_id.as_str())
        .execute(&mut *tx)
        .await?;
        if claim_update.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryActivateResult::Invalid);
        }

        tx.commit().await?;
        Ok(NodeCredentialDeliveryActivateResult::Activated {
            delivery,
            credential,
        })
    }

    async fn expire_node_credential_delivery(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialDeliveryMutationResult, DbError> {
        let now = canonical_time(now);
        let mut tx = self.pool.begin().await?;
        if !lock_home_group(&mut tx, home_group_id).await? {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryMutationResult::Rejected);
        }
        let applied =
            expire_prepared_tx(&mut tx, claim_id, home_group_id, node_id.as_str(), &now).await?;
        if !applied {
            tx.rollback().await?;
            return Ok(NodeCredentialDeliveryMutationResult::Rejected);
        }
        tx.commit().await?;
        Ok(NodeCredentialDeliveryMutationResult::Applied)
    }
}
