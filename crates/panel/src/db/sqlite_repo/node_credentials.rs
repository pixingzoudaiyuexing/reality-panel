use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    NewNodeCredentialCandidate, NodeCredentialMutationResult, NodeCredentialRecord,
    NodeCredentialRepository,
};
use async_trait::async_trait;
use std::future::Future;

struct NodeCredentialReplacement<'a> {
    home_group_id: i64,
    node_id: &'a crate::node_identity::ReuseEligibleNodeId,
    expected_active_credential_id: &'a str,
    expected_active_generation: i64,
    candidate_credential_id: &'a str,
    candidate_generation: i64,
}

async fn replace_active_node_credential_transaction<F, Fut>(
    repo: &SqliteRepository,
    replacement: NodeCredentialReplacement<'_>,
    after_revoke: F,
) -> Result<NodeCredentialMutationResult, DbError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    if replacement.candidate_generation <= replacement.expected_active_generation {
        return Ok(NodeCredentialMutationResult::Rejected);
    }

    // SQLx 0.8.6 Transaction is the cancellation-safety boundary here. The
    // first statement is the revoke UPDATE, so SQLite's deferred BEGIN acquires
    // the writer lock before any read snapshot is established.
    let mut tx = repo.pool.begin().await?;

    let revoked = sqlx::query(
        "UPDATE node_credentials \
         SET revoked_at = datetime('now'), updated_at = datetime('now') \
         WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
           AND activated_at IS NOT NULL AND revoked_at IS NULL",
    )
    .bind(replacement.expected_active_credential_id)
    .bind(replacement.home_group_id)
    .bind(replacement.node_id.as_str())
    .bind(replacement.expected_active_generation)
    .execute(&mut *tx)
    .await?;
    if revoked.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(NodeCredentialMutationResult::Rejected);
    }

    after_revoke().await;

    let activated = sqlx::query(
        "UPDATE node_credentials AS candidate \
         SET activated_at = datetime('now'), updated_at = datetime('now') \
         WHERE credential_id = ? AND home_group_id = ? AND node_id = ? AND generation = ? \
           AND activated_at IS NULL AND revoked_at IS NULL \
           AND candidate.generation > COALESCE(( \
               SELECT MAX(history.generation) FROM node_credentials AS history \
               WHERE history.home_group_id = candidate.home_group_id \
                 AND history.node_id = candidate.node_id \
                 AND history.activated_at IS NOT NULL \
           ), 0)",
    )
    .bind(replacement.candidate_credential_id)
    .bind(replacement.home_group_id)
    .bind(replacement.node_id.as_str())
    .bind(replacement.candidate_generation)
    .execute(&mut *tx)
    .await?;
    if activated.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(NodeCredentialMutationResult::Rejected);
    }

    tx.commit().await?;
    Ok(NodeCredentialMutationResult::Applied)
}

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

    async fn find_active_node_credential_for_runtime(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials AS current \
             WHERE current.credential_id = ? \
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

    async fn find_current_active_node_credential_for_identity(
        &self,
        home_group_id: i64,
        node_id: &crate::node_identity::ReuseEligibleNodeId,
    ) -> Result<Option<NodeCredentialRecord>, DbError> {
        Ok(sqlx::query_as::<_, NodeCredentialRecord>(
            "SELECT credential_id, home_group_id, node_id, generation, verifier_format, \
                    verifier_version, verifier_data, created_at, updated_at, activated_at, revoked_at \
             FROM node_credentials AS current \
             WHERE current.home_group_id = ? AND current.node_id = ? \
               AND current.activated_at IS NOT NULL \
               AND current.revoked_at IS NULL \
               AND current.generation = ( \
                   SELECT MAX(history.generation) FROM node_credentials AS history \
                   WHERE history.home_group_id = current.home_group_id \
                     AND history.node_id = current.node_id \
                     AND history.activated_at IS NOT NULL \
               ) \
             LIMIT 1",
        )
        .bind(home_group_id)
        .bind(node_id.as_str())
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
        replace_active_node_credential_transaction(
            self,
            NodeCredentialReplacement {
                home_group_id,
                node_id,
                expected_active_credential_id,
                expected_active_generation,
                candidate_credential_id,
                candidate_generation,
            },
            || async {},
        )
        .await
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::db::schema::SCHEMA_SQL;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use std::time::Duration;

    async fn replacement_test_repo(name: &str) -> (SqliteRepository, std::path::PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "reality-panel-credential-{name}-{}.db",
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
             VALUES (10, 'gin', 'in', 'tok-cancel', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data, activated_at) \
             VALUES ('cred-old', 10, 'cancel-node', 1, 'rp-node-sha256', 1, ?, datetime('now'))",
        )
        .bind(vec![0x11_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data) \
             VALUES ('cred-new', 10, 'cancel-node', 2, 'rp-node-sha256', 1, ?)",
        )
        .bind(vec![0x22_u8; 32])
        .execute(&pool)
        .await
        .unwrap();

        (SqliteRepository::new(pool), path, url)
    }

    async fn assert_replacement_not_partially_committed(db: &SqliteRepository) {
        let old = db.find_node_credential("cred-old").await.unwrap().unwrap();
        let candidate = db.find_node_credential("cred-new").await.unwrap().unwrap();
        assert!(old.activated_at.is_some() && old.revoked_at.is_none());
        assert!(candidate.activated_at.is_none() && candidate.revoked_at.is_none());
    }

    fn cleanup_sqlite_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn replacement_cancellation_rolls_back_and_releases_connection_and_write_lock() {
        let (db, path, url) = replacement_test_repo("cancel").await;
        let task_db = SqliteRepository::new(db.pool.clone());
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (_resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            let node_id = crate::node_identity::ReuseEligibleNodeId::parse("cancel-node").unwrap();
            replace_active_node_credential_transaction(
                &task_db,
                NodeCredentialReplacement {
                    home_group_id: 10,
                    node_id: &node_id,
                    expected_active_credential_id: "cred-old",
                    expected_active_generation: 1,
                    candidate_credential_id: "cred-new",
                    candidate_generation: 2,
                },
                || async move {
                    let _ = reached_tx.send(());
                    let _ = resume_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(2), reached_rx)
            .await
            .expect("replacement did not reach the post-revoke cancellation point")
            .expect("replacement task dropped the cancellation signal");

        task.abort();
        let join_error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cancelled replacement task did not terminate")
            .expect_err("replacement task unexpectedly completed");
        assert!(join_error.is_cancelled());

        // This pool has exactly one connection. SQLx 0.8.6 queues rollback from
        // Transaction::drop; successfully beginning a new transaction on that
        // same pooled connection proves the queued rollback has been processed.
        tokio::time::timeout(Duration::from_secs(2), async {
            let tx = db.pool.begin().await.unwrap();
            tx.rollback().await.unwrap();
        })
        .await
        .expect("queued SQLx rollback did not complete on connection reuse");

        assert_replacement_not_partially_committed(&db).await;

        // A separate SQLite connection must also be able to write, proving the
        // cancelled transaction left no writer lock behind.
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
            sqlx::query("UPDATE device_groups SET name = name WHERE id = 10").execute(&other_pool),
        )
        .await
        .expect("separate SQLite connection remained blocked by a stale writer lock")
        .unwrap();

        other_pool.close().await;
        db.pool.close().await;
        cleanup_sqlite_files(&path);
    }

    #[tokio::test]
    async fn replacement_database_error_rolls_back_before_connection_reuse() {
        let (db, path, _) = replacement_test_repo("db-error").await;
        sqlx::query(
            "CREATE TRIGGER fail_candidate_activation \
             BEFORE UPDATE OF activated_at ON node_credentials \
             WHEN OLD.credential_id = 'cred-new' AND NEW.activated_at IS NOT NULL \
             BEGIN SELECT RAISE(ABORT, 'forced activation failure'); END",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        let node_id = crate::node_identity::ReuseEligibleNodeId::parse("cancel-node").unwrap();
        assert!(db
            .replace_active_node_credential(10, &node_id, "cred-old", 1, "cred-new", 2)
            .await
            .is_err());

        tokio::time::timeout(Duration::from_secs(2), async {
            let tx = db.pool.begin().await.unwrap();
            tx.rollback().await.unwrap();
        })
        .await
        .expect("queued rollback after database error did not complete");

        assert_replacement_not_partially_committed(&db).await;

        sqlx::query("DROP TRIGGER fail_candidate_activation")
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            db.replace_active_node_credential(10, &node_id, "cred-old", 1, "cred-new", 2)
                .await
                .unwrap(),
            NodeCredentialMutationResult::Applied
        );

        db.pool.close().await;
        cleanup_sqlite_files(&path);
    }
}
