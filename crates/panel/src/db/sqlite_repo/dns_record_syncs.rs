use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;

#[async_trait]
impl DnsRecordSyncRepository for SqliteRepository {
    async fn insert_dns_record_sync(&self, sync: &NewDnsRecordSync) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO dns_record_syncs (\
                 rule_id, fqdn, record_type, expected_value, line, line_key, desired_action,\
                 state, ownership, last_error_category, next_attempt_at, created_at, updated_at\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(sync.rule_id)
        .bind(&sync.fqdn)
        .bind(&sync.record_type)
        .bind(&sync.expected_value)
        .bind(&sync.line)
        .bind(&sync.line_key)
        .bind(&sync.desired_action)
        .bind(&sync.state)
        .bind(&sync.ownership)
        .bind(&sync.last_error_category)
        .bind(&sync.next_attempt_at)
        .bind(&sync.created_at)
        .bind(&sync.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_dns_record_sync(
        &self,
        rule_id: i64,
        line_key: &str,
    ) -> Result<Option<DnsRecordSync>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM dns_record_syncs WHERE rule_id = ? AND line_key = ?")
                .bind(rule_id)
                .bind(line_key)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn list_dns_record_syncs_for_rule(
        &self,
        rule_id: i64,
    ) -> Result<Vec<DnsRecordSync>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM dns_record_syncs WHERE rule_id = ? ORDER BY line_key")
                .bind(rule_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn update_dns_record_sync_desired(
        &self,
        rule_id: i64,
        fqdn: &str,
        record_type: &str,
        expected_value: Option<&str>,
        line: &str,
        line_key: &str,
        desired_action: &str,
        state: &str,
        ownership: &str,
        last_error_category: Option<&str>,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_syncs SET fqdn = ?, record_type = ?, expected_value = ?,\
                 line = ?, line_key = ?, desired_action = ?, state = ?, ownership = ?,\
                 mutation_verified_at = NULL, last_observed_at = NULL, propagated_at = NULL,\
                 last_error_category = ?, attempt_count = 0, next_attempt_at = ?, updated_at = ?\
             WHERE rule_id = ? AND line_key = ?",
        )
        .bind(fqdn)
        .bind(record_type)
        .bind(expected_value)
        .bind(line)
        .bind(line_key)
        .bind(desired_action)
        .bind(state)
        .bind(ownership)
        .bind(last_error_category)
        .bind(next_attempt_at)
        .bind(updated_at)
        .bind(rule_id)
        .bind(line_key)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn schedule_dns_record_sync(
        &self,
        rule_id: i64,
        line_key: &str,
        state: &str,
        ownership: &str,
        last_error_category: Option<&str>,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_syncs SET state = ?, ownership = ?,\
                 last_error_category = ?, attempt_count = 0, next_attempt_at = ?, updated_at = ?\
             WHERE rule_id = ? AND line_key = ?",
        )
        .bind(state)
        .bind(ownership)
        .bind(last_error_category)
        .bind(next_attempt_at)
        .bind(updated_at)
        .bind(rule_id)
        .bind(line_key)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn delete_dns_record_sync(&self, rule_id: i64, line_key: &str) -> Result<u64, DbError> {
        Ok(
            sqlx::query("DELETE FROM dns_record_syncs WHERE rule_id = ? AND line_key = ?")
                .bind(rule_id)
                .bind(line_key)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    async fn count_dns_record_syncs(&self) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM dns_record_syncs")
            .fetch_one(&self.pool)
            .await?)
    }

    async fn list_due_dns_record_syncs(
        &self,
        now: &str,
        limit: i64,
    ) -> Result<Vec<DnsRecordSync>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM dns_record_syncs \
             WHERE state IN ('PENDING','SYNCING','MUTATION_VERIFIED','FAILED','PROPAGATING') \
               AND next_attempt_at IS NOT NULL AND next_attempt_at <= ? \
             ORDER BY next_attempt_at, rule_id, line_key LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn update_dns_record_sync_observation(
        &self,
        expected: &DnsRecordSync,
        expected_state: &str,
        state: &str,
        ownership: &str,
        mutation_verified_at: Option<&str>,
        last_observed_at: Option<&str>,
        propagated_at: Option<&str>,
        last_error_category: Option<&str>,
        attempt_count: i32,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_syncs SET state = ?, ownership = ?,\
                 mutation_verified_at = ?, last_observed_at = ?, propagated_at = ?,\
                 last_error_category = ?, attempt_count = ?, next_attempt_at = ?, updated_at = ?\
             WHERE rule_id = ? AND fqdn = ? AND record_type = ? AND expected_value IS ?\
               AND line = ? AND line_key = ? AND desired_action = ? AND state = ?",
        )
        .bind(state)
        .bind(ownership)
        .bind(mutation_verified_at)
        .bind(last_observed_at)
        .bind(propagated_at)
        .bind(last_error_category)
        .bind(attempt_count)
        .bind(next_attempt_at)
        .bind(updated_at)
        .bind(expected.rule_id)
        .bind(&expected.fqdn)
        .bind(&expected.record_type)
        .bind(&expected.expected_value)
        .bind(&expected.line)
        .bind(&expected.line_key)
        .bind(&expected.desired_action)
        .bind(expected_state)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn mark_all_dns_record_syncs_disabled(
        &self,
        now: &str,
        error_category: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_syncs SET state = 'DISABLED', ownership = 'UNKNOWN',\
                 last_error_category = ?, next_attempt_at = NULL, updated_at = ?",
        )
        .bind(error_category)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn resume_dns_record_syncs_on_startup(&self, now: &str) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_syncs SET \
                 state = CASE \
                     WHEN state IN ('MUTATION_VERIFIED','PROPAGATING') THEN 'PROPAGATING' \
                     ELSE 'PENDING' \
                 END, \
                 attempt_count = 0, next_attempt_at = ?, updated_at = ? \
             WHERE state IN ('PENDING','SYNCING','MUTATION_VERIFIED','PROPAGATING') \
                OR (state = 'FAILED' AND last_error_category IN ( \
                    'DNSMGR_TRANSPORT','DNSMGR_TIMEOUT','DNSMGR_TEMPORARY', \
                    'DATABASE' \
                ))",
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
