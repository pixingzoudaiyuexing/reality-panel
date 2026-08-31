use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;

#[async_trait]
impl DnsRecordSyncRepository for PgRepository {
    async fn insert_dns_record_sync(&self, sync: &NewDnsRecordSync) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO dns_record_syncs (\
                 rule_id, fqdn, record_type, expected_value, line, line_key, desired_action,\
                 state, ownership, last_error_category, next_attempt_at, created_at, updated_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
            sqlx::query_as("SELECT * FROM dns_record_syncs WHERE rule_id = $1 AND line_key = $2")
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
            sqlx::query_as("SELECT * FROM dns_record_syncs WHERE rule_id = $1 ORDER BY line_key")
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
            "UPDATE dns_record_syncs SET fqdn = $1, record_type = $2, expected_value = $3,\
                 line = $4, line_key = $5, desired_action = $6, state = $7, ownership = $8,\
                 mutation_verified_at = NULL, last_observed_at = NULL, propagated_at = NULL,\
                 last_error_category = $9, attempt_count = 0, next_attempt_at = $10, updated_at = $11 \
             WHERE rule_id = $12 AND line_key = $13",
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
            "UPDATE dns_record_syncs SET state = $1, ownership = $2,\
                 last_error_category = $3, attempt_count = 0, next_attempt_at = $4, updated_at = $5 \
             WHERE rule_id = $6 AND line_key = $7",
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
            sqlx::query("DELETE FROM dns_record_syncs WHERE rule_id = $1 AND line_key = $2")
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
               AND next_attempt_at IS NOT NULL AND next_attempt_at <= $1 \
             ORDER BY next_attempt_at, rule_id, line_key LIMIT $2",
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
            "UPDATE dns_record_syncs SET state = $1, ownership = $2,\
                 mutation_verified_at = $3, last_observed_at = $4, propagated_at = $5,\
                 last_error_category = $6, attempt_count = $7, next_attempt_at = $8, updated_at = $9 \
             WHERE rule_id = $10 AND fqdn = $11 AND record_type = $12 \
               AND expected_value IS NOT DISTINCT FROM $13 \
               AND line = $14 AND line_key = $15 AND desired_action = $16 AND state = $17",
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
                 last_error_category = $1, next_attempt_at = NULL, updated_at = $2",
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
                 attempt_count = 0, next_attempt_at = $1, updated_at = $1 \
             WHERE state IN ('PENDING','SYNCING','MUTATION_VERIFIED','PROPAGATING') \
                OR (state = 'FAILED' AND last_error_category IN ( \
                    'DNSMGR_TRANSPORT','DNSMGR_TIMEOUT','DNSMGR_TEMPORARY', \
                    'DATABASE' \
                ))",
        )
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
