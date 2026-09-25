use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    AmbiguousDnsRecordBindingRebind, DetachedDnsRecordBindingAdoption, DnsRecordBinding,
    DnsRecordBindingRepository, NewDnsRecordBinding,
};
use async_trait::async_trait;

#[async_trait]
impl DnsRecordBindingRepository for PgRepository {
    async fn insert_dns_record_binding(
        &self,
        binding: &NewDnsRecordBinding,
    ) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "INSERT INTO dns_record_bindings (\
                 rule_id, fqdn, zone_id, zone_name, host, record_type, line, line_key, \
                 record_id, desired_value, state, last_observed_at, created_at, updated_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             RETURNING id",
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
        .fetch_one(&self.pool)
        .await?)
    }

    async fn find_dns_record_binding_by_record(
        &self,
        zone_id: i64,
        record_id: &str,
    ) -> Result<Option<DnsRecordBinding>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM dns_record_bindings WHERE zone_id = $1 AND record_id = $2",
        )
        .bind(zone_id)
        .bind(record_id)
        .fetch_optional(&self.pool)
        .await?)
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
             WHERE rule_id = $1 AND fqdn = $2 AND record_type = $3 AND line_key = $4",
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
            "UPDATE dns_record_bindings SET state = $1, last_observed_at = $2, \
                 last_error_category = $3, updated_at = $4 WHERE id = $5",
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
            "UPDATE dns_record_bindings SET record_id = $1, line = $2, desired_value = $3, \
                 state = 'BOUND', last_observed_at = $4, last_error_category = NULL, \
                 updated_at = $5 WHERE id = $6",
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


    async fn rebind_ambiguous_dns_record_binding(
        &self,
        rebind: &AmbiguousDnsRecordBindingRebind,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_bindings SET record_id = $1, state = 'BOUND', \
                 last_observed_at = $2, last_error_category = NULL, updated_at = $3 \
             WHERE id = $4 AND rule_id = $5 AND fqdn = $6 AND zone_id = $7 \
               AND zone_name = $8 AND host = $9 AND record_type = $10 AND line = $11 \
               AND line_key = $12 AND record_id = $13 AND desired_value = $14 \
               AND state = 'ERROR' AND last_error_category = 'MUTATION_UNKNOWN'",
        )
        .bind(&rebind.replacement_record_id)
        .bind(&rebind.observed_at)
        .bind(&rebind.updated_at)
        .bind(rebind.binding_id)
        .bind(rebind.rule_id)
        .bind(&rebind.fqdn)
        .bind(rebind.zone_id)
        .bind(&rebind.zone_name)
        .bind(&rebind.host)
        .bind(&rebind.record_type)
        .bind(&rebind.line)
        .bind(&rebind.line_key)
        .bind(&rebind.previous_record_id)
        .bind(&rebind.desired_value)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    async fn adopt_detached_dns_record_binding(
        &self,
        adoption: &DetachedDnsRecordBindingAdoption,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE dns_record_bindings SET rule_id = $1, desired_value = $2, state = 'BOUND', \
                 last_observed_at = $3, last_error_category = NULL, updated_at = $4 \
             WHERE id = $5 AND rule_id IS NULL AND fqdn = $6 AND zone_id = $7 \
               AND zone_name = $8 AND host = $9 AND record_type = $10 AND line = $11 \
               AND line_key = $12 AND record_id = $13 AND desired_value = $14 \
               AND state = 'BOUND' AND last_error_category IS NULL",
        )
        .bind(adoption.rule_id)
        .bind(&adoption.desired_value)
        .bind(&adoption.observed_at)
        .bind(&adoption.updated_at)
        .bind(adoption.binding_id)
        .bind(&adoption.fqdn)
        .bind(adoption.zone_id)
        .bind(&adoption.zone_name)
        .bind(&adoption.host)
        .bind(&adoption.record_type)
        .bind(&adoption.line)
        .bind(&adoption.line_key)
        .bind(&adoption.record_id)
        .bind(&adoption.previous_desired_value)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
