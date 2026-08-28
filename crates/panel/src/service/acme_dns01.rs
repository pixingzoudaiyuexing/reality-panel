//! Panel-owned DNSMgr mutations for short-lived ACME DNS-01 challenges.

use crate::db::Repository;
use crate::integrations::dnsmgr::{
    DnsMgrClient, DnsMgrError, DnsMgrRecord, DnsMgrRecordMutation, RecordListParams,
};
use crate::service::dnsmgr::{
    load_client, normalize_fqdn, resolve_mutation_line, resolve_zone, write_ttl, ProviderLine,
    ZoneResolution,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::future::join_all;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

const STATE_PREFIX: &str = "acme:dns01:";
const CHALLENGE_TTL_SECS: i64 = 900;
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);
const PROPAGATION_INTERVAL: Duration = Duration::from_secs(5);
const PAGE_LIMIT: u16 = 100;

static SNI_OPERATIONS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeDns01Request {
    pub node_id: String,
    pub sni: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeDns01Response {
    pub challenge_id: String,
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeState {
    challenge_id: String,
    node_id: String,
    group_id: i64,
    sni: String,
    txt_fqdn: String,
    zone_id: u64,
    host: String,
    line: String,
    provider_record_id: Option<String>,
    value_sha256: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    cleanup_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeDns01Error {
    InvalidRequest,
    Unavailable,
    Conflict,
    Provider,
    PropagationTimeout,
    Database,
}

impl AcmeDns01Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "ACME_DNS01_INVALID_REQUEST",
            Self::Unavailable => "ACME_DNS01_UNAVAILABLE",
            Self::Conflict => "ACME_DNS01_CONFLICT",
            Self::Provider => "ACME_DNS01_PROVIDER",
            Self::PropagationTimeout => "ACME_DNS01_PROPAGATION_TIMEOUT",
            Self::Database => "ACME_DNS01_DATABASE",
        }
    }
}

struct SniOperationLease(String);

impl Drop for SniOperationLease {
    fn drop(&mut self) {
        if let Ok(mut operations) = SNI_OPERATIONS.lock() {
            operations.remove(&self.0);
        }
    }
}

fn acquire_sni(sni: &str) -> Result<SniOperationLease, AcmeDns01Error> {
    let mut operations = SNI_OPERATIONS
        .lock()
        .map_err(|_| AcmeDns01Error::Conflict)?;
    if !operations.insert(sni.to_string()) {
        return Err(AcmeDns01Error::Conflict);
    }
    Ok(SniOperationLease(sni.to_string()))
}

pub async fn present(
    db: &dyn Repository,
    group_id: i64,
    request: &AcmeDns01Request,
) -> Result<AcmeDns01Response, AcmeDns01Error> {
    present_with_observer(db, group_id, request, &SystemTxtPropagation).await
}

async fn present_with_observer(
    db: &dyn Repository,
    group_id: i64,
    request: &AcmeDns01Request,
    propagation: &dyn TxtPropagationObserver,
) -> Result<AcmeDns01Response, AcmeDns01Error> {
    let sni = validate_request(request)?;
    let _lease = acquire_sni(&sni)?;
    let client = load_client(db)
        .await
        .map_err(|_| AcmeDns01Error::Provider)?
        .ok_or(AcmeDns01Error::Unavailable)?;
    cleanup_expired_for_sni(db, &client, &sni).await;

    let challenge_id = challenge_id(&request.node_id, &sni, &request.value);
    let key = state_key(&challenge_id);
    if let Some(raw) = db.get(&key).await.map_err(|_| AcmeDns01Error::Database)? {
        let state: ChallengeState =
            serde_json::from_str(&raw).map_err(|_| AcmeDns01Error::Database)?;
        if state.group_id != group_id || state.node_id != request.node_id || state.sni != sni {
            return Err(AcmeDns01Error::Conflict);
        }
        if state.cleanup_state == "ACTIVE" {
            return Ok(AcmeDns01Response {
                challenge_id,
                state: "presented",
            });
        }
    }

    reject_other_active_challenge(db, &sni, &challenge_id).await?;
    let txt_fqdn = format!("_acme-challenge.{sni}");
    let sni_fqdn = normalize_fqdn(&sni).map_err(|_| AcmeDns01Error::InvalidRequest)?;
    let zone = match resolve_zone(&client, &sni_fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => return Err(AcmeDns01Error::Unavailable),
        ZoneResolution::UpstreamFailure(_) => return Err(AcmeDns01Error::Provider),
    };
    let detail = client
        .get_domain(zone.domain_id)
        .await
        .map_err(|_| AcmeDns01Error::Provider)?;
    let line =
        resolve_mutation_line(&ProviderLine::default(), &detail).ok_or(AcmeDns01Error::Provider)?;
    let ttl = write_ttl(&detail).ok_or(AcmeDns01Error::Provider)?;
    let challenge_host = if zone.host == "@" {
        "_acme-challenge".to_string()
    } else {
        format!("_acme-challenge.{}", zone.host)
    };
    let now = Utc::now();
    let mut state = ChallengeState {
        challenge_id: challenge_id.clone(),
        node_id: request.node_id.clone(),
        group_id,
        sni: sni.clone(),
        txt_fqdn: txt_fqdn.clone(),
        zone_id: zone.domain_id,
        host: challenge_host,
        line: line.raw_id.clone(),
        provider_record_id: None,
        value_sha256: value_fingerprint(&request.value),
        created_at: now,
        expires_at: now + ChronoDuration::seconds(CHALLENGE_TTL_SECS),
        cleanup_state: "PRESENTING".into(),
    };
    persist_state(db, &state).await?;

    let result = present_provider_value(&client, &state, &request.value, ttl).await;
    let record_id = match result {
        Ok(record_id) => record_id,
        Err(error) => {
            state.cleanup_state = "CLEANUP_PENDING".into();
            let _ = persist_state(db, &state).await;
            return Err(error);
        }
    };
    state.provider_record_id = Some(record_id);
    state.cleanup_state = "PROPAGATING".into();
    persist_state(db, &state).await?;

    if propagation
        .wait_for_value(&txt_fqdn, &zone.zone_name, &request.value)
        .await
        .is_err()
    {
        let _ = cleanup_state(db, &client, &mut state).await;
        return Err(AcmeDns01Error::PropagationTimeout);
    }
    state.cleanup_state = "ACTIVE".into();
    persist_state(db, &state).await?;
    Ok(AcmeDns01Response {
        challenge_id,
        state: "presented",
    })
}

#[async_trait::async_trait]
trait TxtPropagationObserver: Send + Sync {
    async fn wait_for_value(&self, fqdn: &str, zone_name: &str, expected: &str) -> Result<(), ()>;
}

struct SystemTxtPropagation;

#[async_trait::async_trait]
impl TxtPropagationObserver for SystemTxtPropagation {
    async fn wait_for_value(&self, fqdn: &str, zone_name: &str, expected: &str) -> Result<(), ()> {
        wait_for_authoritative_txt(fqdn, zone_name, expected).await
    }
}

pub async fn cleanup(
    db: &dyn Repository,
    group_id: i64,
    request: &AcmeDns01Request,
) -> Result<AcmeDns01Response, AcmeDns01Error> {
    let sni = validate_request(request)?;
    let _lease = acquire_sni(&sni)?;
    let challenge_id = challenge_id(&request.node_id, &sni, &request.value);
    let key = state_key(&challenge_id);
    let Some(raw) = db.get(&key).await.map_err(|_| AcmeDns01Error::Database)? else {
        return Ok(AcmeDns01Response {
            challenge_id,
            state: "cleaned",
        });
    };
    let mut state: ChallengeState =
        serde_json::from_str(&raw).map_err(|_| AcmeDns01Error::Database)?;
    if state.group_id != group_id
        || state.node_id != request.node_id
        || state.sni != sni
        || state.value_sha256 != value_fingerprint(&request.value)
    {
        return Err(AcmeDns01Error::Conflict);
    }
    if state.cleanup_state == "CLEANED" {
        return Ok(AcmeDns01Response {
            challenge_id,
            state: "cleaned",
        });
    }
    let client = load_client(db)
        .await
        .map_err(|_| AcmeDns01Error::Provider)?
        .ok_or(AcmeDns01Error::Unavailable)?;
    cleanup_state(db, &client, &mut state).await?;
    Ok(AcmeDns01Response {
        challenge_id,
        state: "cleaned",
    })
}

pub async fn cleanup_expired(db: &dyn Repository) {
    let Ok(Some(client)) = load_client(db).await else {
        return;
    };
    let Ok(rows) = db.scan_prefix(STATE_PREFIX).await else {
        return;
    };
    for (_, raw) in rows {
        let Ok(mut state) = serde_json::from_str::<ChallengeState>(&raw) else {
            continue;
        };
        if state.cleanup_state != "CLEANED" && state.expires_at <= Utc::now() {
            let Ok(_lease) = acquire_sni(&state.sni) else {
                continue;
            };
            let _ = cleanup_state(db, &client, &mut state).await;
        }
    }
}

async fn cleanup_expired_for_sni(db: &dyn Repository, client: &DnsMgrClient, sni: &str) {
    let Ok(rows) = db.scan_prefix(STATE_PREFIX).await else {
        return;
    };
    for (_, raw) in rows {
        let Ok(mut state) = serde_json::from_str::<ChallengeState>(&raw) else {
            continue;
        };
        if state.sni == sni && state.cleanup_state != "CLEANED" && state.expires_at <= Utc::now() {
            let _ = cleanup_state(db, client, &mut state).await;
        }
    }
}

async fn reject_other_active_challenge(
    db: &dyn Repository,
    sni: &str,
    challenge_id: &str,
) -> Result<(), AcmeDns01Error> {
    for (_, raw) in db
        .scan_prefix(STATE_PREFIX)
        .await
        .map_err(|_| AcmeDns01Error::Database)?
    {
        let state: ChallengeState =
            serde_json::from_str(&raw).map_err(|_| AcmeDns01Error::Database)?;
        if state.sni == sni
            && state.challenge_id != challenge_id
            && state.cleanup_state != "CLEANED"
            && state.expires_at > Utc::now()
        {
            return Err(AcmeDns01Error::Conflict);
        }
    }
    Ok(())
}

async fn present_provider_value(
    client: &DnsMgrClient,
    state: &ChallengeState,
    value: &str,
    ttl: u32,
) -> Result<String, AcmeDns01Error> {
    let records = list_txt_records(client, state).await?;
    if let Some(record) = records
        .iter()
        .find(|record| contains_fingerprint(&record.values, &state.value_sha256))
    {
        return Ok(record.record_id.clone());
    }

    let mutation = if records.is_empty() {
        DnsMgrRecordMutation {
            host: state.host.clone(),
            record_type: "TXT".into(),
            value: value.to_string(),
            line: state.line.clone(),
            ttl,
        }
    } else if records.len() == 1 {
        let mut values = records[0].values.clone();
        values.push(value.to_string());
        DnsMgrRecordMutation {
            host: state.host.clone(),
            record_type: "TXT".into(),
            value: encode_provider_values(&values)?,
            line: state.line.clone(),
            ttl,
        }
    } else {
        return Err(AcmeDns01Error::Conflict);
    };

    if records.is_empty() {
        client
            .create_record(state.zone_id, &mutation)
            .await
            .map_err(map_provider_error)?;
    } else {
        client
            .update_record(state.zone_id, &records[0].record_id, &mutation)
            .await
            .map_err(map_provider_error)?;
    }

    let matching = list_txt_records(client, state)
        .await?
        .into_iter()
        .filter(|record| contains_fingerprint(&record.values, &state.value_sha256))
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [record] => Ok(record.record_id.clone()),
        _ => Err(AcmeDns01Error::Provider),
    }
}

async fn cleanup_state(
    db: &dyn Repository,
    client: &DnsMgrClient,
    state: &mut ChallengeState,
) -> Result<(), AcmeDns01Error> {
    state.cleanup_state = "CLEANUP_PENDING".into();
    persist_state(db, state).await?;
    let matching = list_txt_records(client, state)
        .await?
        .into_iter()
        .filter(|record| contains_fingerprint(&record.values, &state.value_sha256))
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(AcmeDns01Error::Conflict);
    }
    if let Some(record) = matching.first() {
        if state
            .provider_record_id
            .as_deref()
            .is_some_and(|expected| expected != record.record_id)
        {
            return Err(AcmeDns01Error::Conflict);
        }
        let remaining = record
            .values
            .iter()
            .filter(|value| value_fingerprint(&normalize_txt_value(value)) != state.value_sha256)
            .cloned()
            .collect::<Vec<_>>();
        if remaining.is_empty() {
            client
                .delete_record(state.zone_id, &record.record_id)
                .await
                .map_err(map_provider_error)?;
        } else {
            let mutation = DnsMgrRecordMutation {
                host: state.host.clone(),
                record_type: "TXT".into(),
                value: encode_provider_values(&remaining)?,
                line: state.line.clone(),
                ttl: u32::try_from(record.ttl).map_err(|_| AcmeDns01Error::Provider)?,
            };
            client
                .update_record(state.zone_id, &record.record_id, &mutation)
                .await
                .map_err(map_provider_error)?;
        }
    }
    if list_txt_records(client, state)
        .await?
        .iter()
        .any(|record| contains_fingerprint(&record.values, &state.value_sha256))
    {
        return Err(AcmeDns01Error::Provider);
    }
    state.cleanup_state = "CLEANED".into();
    persist_state(db, state).await
}

async fn list_txt_records(
    client: &DnsMgrClient,
    state: &ChallengeState,
) -> Result<Vec<DnsMgrRecord>, AcmeDns01Error> {
    let mut rows = Vec::new();
    let mut offset = 0_u32;
    loop {
        let page = client
            .list_records(
                state.zone_id,
                &RecordListParams {
                    offset,
                    limit: PAGE_LIMIT,
                    subdomain: Some(state.host.clone()),
                    record_type: Some("TXT".into()),
                    line: Some(state.line.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(map_provider_error)?;
        let count = page.rows.len();
        rows.extend(page.rows.into_iter().filter(|record| {
            record.host.eq_ignore_ascii_case(&state.host)
                && record.record_type.eq_ignore_ascii_case("TXT")
                && ProviderLine::from_provider(&record.line, record.line_name.as_deref()).key
                    == ProviderLine::from_provider(&state.line, None).key
        }));
        if count == 0
            || (page.authoritative_total
                && u64::from(offset).saturating_add(count as u64) >= page.total)
            || (!page.authoritative_total && count < PAGE_LIMIT as usize)
        {
            break;
        }
        offset = offset
            .checked_add(count as u32)
            .ok_or(AcmeDns01Error::Provider)?;
    }
    Ok(rows)
}

async fn wait_for_authoritative_txt(fqdn: &str, zone_name: &str, expected: &str) -> Result<(), ()> {
    let system_resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|_| ())?;
    let authoritative_resolvers = authoritative_resolvers(&system_resolver, zone_name).await?;
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    loop {
        let visible = join_all(authoritative_resolvers.iter().map(|resolver| async move {
            resolver
                .txt_lookup(fqdn)
                .await
                .is_ok_and(|lookup| txt_lookup_matches(&lookup, expected))
        }))
        .await;
        if visible.iter().all(|matched| *matched) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        tokio::time::sleep(PROPAGATION_INTERVAL).await;
    }
}

async fn authoritative_resolvers(
    system_resolver: &TokioAsyncResolver,
    zone_name: &str,
) -> Result<Vec<TokioAsyncResolver>, ()> {
    let nameservers = system_resolver.ns_lookup(zone_name).await.map_err(|_| ())?;
    let mut addresses = HashSet::<IpAddr>::new();
    for nameserver in nameservers.iter() {
        let ips = system_resolver
            .lookup_ip(nameserver.0.clone())
            .await
            .map_err(|_| ())?;
        addresses.extend(ips.iter());
    }
    if addresses.is_empty() {
        return Err(());
    }

    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_secs(3);
    options.recursion_desired = false;
    Ok(addresses
        .into_iter()
        .map(|address| {
            TokioAsyncResolver::tokio(
                ResolverConfig::from_parts(
                    None,
                    Vec::new(),
                    vec![NameServerConfig::new(
                        SocketAddr::new(address, 53),
                        Protocol::Udp,
                    )],
                ),
                options.clone(),
            )
        })
        .collect())
}

fn txt_lookup_matches(lookup: &hickory_resolver::lookup::TxtLookup, expected: &str) -> bool {
    lookup.iter().any(|txt| {
        let value = txt
            .txt_data()
            .iter()
            .flat_map(|part| part.iter().copied())
            .collect::<Vec<_>>();
        value == expected.as_bytes()
    })
}

fn validate_request(request: &AcmeDns01Request) -> Result<String, AcmeDns01Error> {
    let sni = normalize_fqdn(&request.sni)
        .map_err(|_| AcmeDns01Error::InvalidRequest)?
        .as_str()
        .to_string();
    if request.node_id.trim().is_empty()
        || request.node_id.len() > 128
        || request.value.len() < 16
        || request.value.len() > 512
        || !request
            .value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(AcmeDns01Error::InvalidRequest);
    }
    Ok(sni)
}

fn challenge_id(node_id: &str, sni: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(node_id.as_bytes());
    digest.update([0]);
    digest.update(sni.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    hex::encode(digest.finalize())
}

fn value_fingerprint(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn contains_fingerprint(values: &[String], fingerprint: &str) -> bool {
    values
        .iter()
        .any(|value| value_fingerprint(&normalize_txt_value(value)) == fingerprint)
}

fn normalize_txt_value(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

fn encode_provider_values(values: &[String]) -> Result<String, AcmeDns01Error> {
    if values.is_empty() || values.iter().any(|value| value.contains(',')) {
        return Err(AcmeDns01Error::Conflict);
    }
    Ok(values.join(","))
}

fn state_key(challenge_id: &str) -> String {
    format!("{STATE_PREFIX}{challenge_id}")
}

async fn persist_state(db: &dyn Repository, state: &ChallengeState) -> Result<(), AcmeDns01Error> {
    let raw = serde_json::to_string(state).map_err(|_| AcmeDns01Error::Database)?;
    db.set(&state_key(&state.challenge_id), &raw)
        .await
        .map_err(|_| AcmeDns01Error::Database)
}

fn map_provider_error(_error: DnsMgrError) -> AcmeDns01Error {
    AcmeDns01Error::Provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::KvsRepository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::service::dnsmgr::{DnsMgrSettings, DNSMGR_CONFIG_KEY};
    use axum::extract::Form;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex as AsyncMutex;

    #[derive(Default)]
    struct ProviderState {
        host: String,
        values: Vec<String>,
        creates: usize,
        updates: usize,
        deletes: usize,
    }

    struct FixedPropagation(bool);

    #[async_trait::async_trait]
    impl TxtPropagationObserver for FixedPropagation {
        async fn wait_for_value(&self, _: &str, _: &str, _: &str) -> Result<(), ()> {
            self.0.then_some(()).ok_or(())
        }
    }

    async fn test_db(base_url: &str) -> SqliteRepository {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool);
        let settings = DnsMgrSettings {
            enabled: true,
            base_url: base_url.into(),
            uid: 7,
            api_key: "test-key".into(),
        };
        db.set(
            DNSMGR_CONFIG_KEY,
            &serde_json::to_string(&settings).unwrap(),
        )
        .await
        .unwrap();
        db
    }

    async fn mock_provider(
        host: &str,
        initial_values: Vec<String>,
    ) -> (
        String,
        Arc<AsyncMutex<ProviderState>>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AsyncMutex::new(ProviderState {
            host: host.into(),
            values: initial_values,
            ..Default::default()
        }));
        let list_state = Arc::clone(&state);
        let add_state = Arc::clone(&state);
        let update_state = Arc::clone(&state);
        let delete_state = Arc::clone(&state);
        let router = Router::new()
            .route(
                "/api/domain",
                post(|| async {
                    Json(json!({
                        "total": 1,
                        "rows": [{"id": 7, "name": "example.com", "type": "huawei", "recordcount": 1}]
                    }))
                }),
            )
            .route(
                "/api/domain/7",
                post(|| async {
                    Json(json!({
                        "code": 0,
                        "data": {
                            "id": 7,
                            "name": "example.com",
                            "config": {"type": "huawei"},
                            "recordcount": 1,
                            "minTTL": 60,
                            "recordLine": [{"id": "default_view", "name": "Global default", "parent": null}]
                        }
                    }))
                }),
            )
            .route(
                "/api/record/data/7",
                post(move || {
                    let state = Arc::clone(&list_state);
                    async move {
                        let state = state.lock().await;
                        let rows = if state.values.is_empty() {
                            Vec::new()
                        } else {
                            vec![json!({
                                "RecordId": "txt-1",
                                "Domain": "example.com",
                                "Name": state.host,
                                "Type": "TXT",
                                "Value": state.values,
                                "Line": "default_view",
                                "LineName": "Global default",
                                "TTL": 60,
                                "Status": "1"
                            })]
                        };
                        Json(json!({"total": rows.len(), "rows": rows}))
                    }
                }),
            )
            .route(
                "/api/record/add/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let state = Arc::clone(&add_state);
                    async move {
                        let mut state = state.lock().await;
                        state.creates += 1;
                        state.values = form["value"].split(',').map(str::to_string).collect();
                        Json(json!({"code": 0}))
                    }
                }),
            )
            .route(
                "/api/record/update/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let state = Arc::clone(&update_state);
                    async move {
                        assert_eq!(form.get("recordid").map(String::as_str), Some("txt-1"));
                        assert_eq!(
                            form.get("line").map(String::as_str),
                            Some("default_view")
                        );
                        let mut state = state.lock().await;
                        state.updates += 1;
                        state.values = form["value"].split(',').map(str::to_string).collect();
                        Json(json!({"code": 0}))
                    }
                }),
            )
            .route(
                "/api/record/delete/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let state = Arc::clone(&delete_state);
                    async move {
                        assert_eq!(form.get("recordid").map(String::as_str), Some("txt-1"));
                        let mut state = state.lock().await;
                        state.deletes += 1;
                        state.values.clear();
                        Json(json!({"code": 0}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (base_url, state, handle)
    }

    fn request(sni: &str, value: &str) -> AcmeDns01Request {
        AcmeDns01Request {
            node_id: "node-a".into(),
            sni: sni.into(),
            value: value.into(),
        }
    }

    #[test]
    fn provider_values_preserve_every_entry_and_fail_closed_on_commas() {
        assert_eq!(
            encode_provider_values(&["old".into(), "challenge".into()]).unwrap(),
            "old,challenge"
        );
        assert_eq!(
            encode_provider_values(&["unrelated,content".into(), "challenge".into()]),
            Err(AcmeDns01Error::Conflict)
        );
    }

    #[test]
    fn txt_quotes_are_normalized_only_for_identity_comparison() {
        let fingerprint = value_fingerprint("challenge-token-1234");
        assert!(contains_fingerprint(
            &["\"challenge-token-1234\"".into(), "unrelated".into()],
            &fingerprint
        ));
    }

    #[test]
    fn challenge_ids_are_stable_without_storing_plaintext_values() {
        let first = challenge_id("node-a", "op1.example.com", "challenge-token-1234");
        let second = challenge_id("node-a", "op1.example.com", "challenge-token-1234");
        assert_eq!(first, second);
        assert!(!first.contains("challenge-token"));
    }

    #[test]
    fn same_sni_operations_are_serialized_and_the_lease_is_released() {
        let first = acquire_sni("serialized.example.com").unwrap();
        assert!(matches!(
            acquire_sni("serialized.example.com"),
            Err(AcmeDns01Error::Conflict)
        ));
        assert!(acquire_sni("other.example.com").is_ok());
        drop(first);
        assert!(acquire_sni("serialized.example.com").is_ok());
    }

    #[tokio::test]
    async fn present_verify_cleanup_preserves_unrelated_txt_and_is_idempotent() {
        let challenge = "challenge-token-123456";
        let sni = "roundtrip.example.com";
        let (base_url, provider, handle) =
            mock_provider("_acme-challenge.roundtrip", vec!["unrelated-token".into()]).await;
        let db = test_db(&base_url).await;
        let response =
            present_with_observer(&db, 10, &request(sni, challenge), &FixedPropagation(true))
                .await
                .unwrap();
        assert_eq!(response.state, "presented");
        {
            let state = provider.lock().await;
            assert_eq!(state.values, ["unrelated-token", challenge]);
            assert_eq!((state.creates, state.updates, state.deletes), (0, 1, 0));
        }

        let stored = db.scan_prefix(STATE_PREFIX).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].1.contains(challenge));
        assert!(stored[0].1.contains(&value_fingerprint(challenge)));

        cleanup(&db, 10, &request(sni, challenge)).await.unwrap();
        cleanup(&db, 10, &request(sni, challenge)).await.unwrap();
        let state = provider.lock().await;
        assert_eq!(state.values, ["unrelated-token"]);
        assert_eq!((state.creates, state.updates, state.deletes), (0, 2, 0));
        handle.abort();
    }

    #[tokio::test]
    async fn propagation_timeout_cleans_only_the_challenge_value() {
        let challenge = "timeout-token-123456";
        let sni = "timeout.example.com";
        let (base_url, provider, handle) =
            mock_provider("_acme-challenge.timeout", vec!["unrelated-token".into()]).await;
        let db = test_db(&base_url).await;
        assert!(matches!(
            present_with_observer(&db, 10, &request(sni, challenge), &FixedPropagation(false))
                .await,
            Err(AcmeDns01Error::PropagationTimeout)
        ));
        let state = provider.lock().await;
        assert_eq!(state.values, ["unrelated-token"]);
        assert_eq!(state.updates, 2);
        handle.abort();
    }

    #[tokio::test]
    async fn stale_challenge_cleanup_uses_persisted_fingerprint_and_provider_identity() {
        let challenge = "stale-token-12345678";
        let sni = "stale.example.com";
        let (base_url, provider, handle) = mock_provider("_acme-challenge.stale", Vec::new()).await;
        let db = test_db(&base_url).await;
        present_with_observer(&db, 10, &request(sni, challenge), &FixedPropagation(true))
            .await
            .unwrap();
        let (_, raw) = db.scan_prefix(STATE_PREFIX).await.unwrap().pop().unwrap();
        let mut state: ChallengeState = serde_json::from_str(&raw).unwrap();
        state.expires_at = Utc::now() - ChronoDuration::seconds(1);
        persist_state(&db, &state).await.unwrap();

        cleanup_expired(&db).await;
        let provider = provider.lock().await;
        assert!(provider.values.is_empty());
        assert_eq!((provider.creates, provider.deletes), (1, 1));
        let (_, raw) = db.scan_prefix(STATE_PREFIX).await.unwrap().pop().unwrap();
        let state: ChallengeState = serde_json::from_str(&raw).unwrap();
        assert_eq!(state.cleanup_state, "CLEANED");
        handle.abort();
    }
}
