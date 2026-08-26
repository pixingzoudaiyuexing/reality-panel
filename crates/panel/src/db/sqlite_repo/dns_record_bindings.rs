use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::{DnsRecordBinding, DnsRecordBindingRepository, NewDnsRecordBinding};
use async_trait::async_trait;

#[async_trait]
impl DnsRecordBindingRepository for SqliteRepository {
    async fn insert_dns_record_binding(
        &self,
        binding: &NewDnsRecordBinding,
    ) -> Result<i64, DbError> {
        let result = sqlx::query(
            "INSERT INTO dns_record_bindings (\
                 rule_id, fqdn, zone_id, zone_name, host, record_type, line, line_key, \
                 record_id, desired_value, state, last_observed_at, created_at, updated_at\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(binding.rule_id)
        .bind(&binding.fqdn)
        .bind(binding.zone_id)
        .bind(&binding.zone_name)
        .bind(&binding.host)
        .bind(&binding.record_type)
        .bind(&binding.line)
        .bind(&binding.line_key)
        .bind(&binding.record_id)
        .bind(&binding.desired_value)
        .bind(&binding.state)
        .bind(&binding.last_observed_at)
        .bind(&binding.created_at)
        .bind(&binding.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn find_dns_record_binding_by_record(
        &self,
        zone_id: i64,
        record_id: &str,
    ) -> Result<Option<DnsRecordBinding>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM dns_record_bindings WHERE zone_id = ? AND record_id = ?")
                .bind(zone_id)
                .bind(record_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn find_dns_record_binding_for_rule(
        &self,
        rule_id: i64,
        fqdn: &str,
        record_type: &str,
        line_key: &str,
    ) -> Result<Option<DnsRecordBinding>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM dns_record_bindings \
             WHERE rule_id = ? AND fqdn = ? AND record_type = ? AND line_key = ?",
        )
        .bind(rule_id)
        .bind(fqdn)
        .bind(record_type)
        .bind(line_key)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn update_dns_record_binding_observation(
        &self,
        id: i64,
        state: &str,
        last_observed_at: Option<&str>,
        last_error_category: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_bindings SET state = ?, last_observed_at = ?, \
                 last_error_category = ?, updated_at = ? WHERE id = ?",
        )
        .bind(state)
        .bind(last_observed_at)
        .bind(last_error_category)
        .bind(updated_at)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn rebind_verified_dns_record(
        &self,
        id: i64,
        record_id: &str,
        line: &str,
        desired_value: &str,
        observed_at: &str,
        updated_at: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_bindings SET record_id = ?, line = ?, desired_value = ?, \
                 state = 'BOUND', last_observed_at = ?, last_error_category = NULL, \
                 updated_at = ? WHERE id = ?",
        )
        .bind(record_id)
        .bind(line)
        .bind(desired_value)
        .bind(observed_at)
        .bind(updated_at)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
