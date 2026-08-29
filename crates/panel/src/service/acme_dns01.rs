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
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

const STATE_PREFIX: &str = "acme:dns01:";
const CHALLENGE_TTL_SECS: i64 = 900;
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);
const PROPAGATION_INTERVAL: Duration = Duration::from_secs(5);
const PAGE_LIMIT: u16 = 100;

// 同一个 SNI 的 TXT read-modify-write 必须串行，避免两个 Relay 同时读取旧值后
// 相互覆盖；但锁只覆盖 DNS 提交/清理的临界区，绝不能覆盖传播等待和 CA 验证。
// Weak 避免长期运行的 Panel 因历史 SNI 不断累积锁对象。
static SNI_OPERATIONS: Lazy<Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TxtMutationMode {
    SeparateRecords,
    HuaweiRecordSet,
}

fn txt_mutation_mode(provider_type: Option<&str>) -> TxtMutationMode {
    match provider_type.map(str::to_ascii_lowercase).as_deref() {
        Some("huawei") => TxtMutationMode::HuaweiRecordSet,
        _ => TxtMutationMode::SeparateRecords,
    }
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
    /// rc.4 起持久化 Provider 的 TXT mutation 语义。旧 rc.3 状态没有此字段，
    /// cleanup 时会从 DNSMgr domain detail 重新推导，避免升级时误删 RRset。
    #[serde(default)]
    txt_mode: Option<TxtMutationMode>,
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

fn sni_operation(sni: &str) -> Result<std::sync::Arc<tokio::sync::Mutex<()>>, AcmeDns01Error> {
    let mut operations = SNI_OPERATIONS
        .lock()
        .map_err(|_| AcmeDns01Error::Conflict)?;
    if let Some(operation) = operations.get(sni).and_then(std::sync::Weak::upgrade) {
        return Ok(operation);
    }
    operations.retain(|_, operation| operation.strong_count() > 0);
    let operation = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    operations.insert(sni.to_string(), std::sync::Arc::downgrade(&operation));
    Ok(operation)
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
    let client = load_client(db)
        .await
        .map_err(|_| AcmeDns01Error::Provider)?
        .ok_or(AcmeDns01Error::Unavailable)?;

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
    let txt_mode = txt_mutation_mode(detail.domain.provider_type.as_deref());
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
        txt_mode: Some(txt_mode),
        value_sha256: value_fingerprint(&request.value),
        created_at: now,
        expires_at: now + ChronoDuration::seconds(CHALLENGE_TTL_SECS),
        cleanup_state: "PRESENTING".into(),
    };
    persist_state(db, &state).await?;

    let operation = sni_operation(&sni)?;
    {
        let _guard = operation.lock().await;
        cleanup_expired_for_sni(db, &client, &sni).await;
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
    }

    if propagation
        .wait_for_value(&txt_fqdn, &zone.zone_name, &request.value)
        .await
        .is_err()
    {
        let _guard = operation.lock().await;
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
    let operation = sni_operation(&sni)?;
    let _guard = operation.lock().await;
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
            let Ok(operation) = sni_operation(&state.sni) else {
                continue;
            };
            let _guard = operation.lock().await;
            let _ = cleanup_state(db, &client, &mut state).await;
        }
    }
}

// 调用者必须持有对应 SNI 的 operation lock；这样过期清理和新的 present
// 共用同一段 TXT read-modify-write 临界区，不会误删其他 Relay 的 value。
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

    let mode = state.txt_mode.ok_or(AcmeDns01Error::Provider)?;
    match mode {
        TxtMutationMode::SeparateRecords => {
            // Cloudflare 等 Provider 的 TXT value 是单条 record 内容；并发 challenge
            // 必须创建多个同名 TXT，而不是把多个值拼成一个字符串。
            let mutation = DnsMgrRecordMutation {
                host: state.host.clone(),
                record_type: "TXT".into(),
                value: value.to_string(),
                line: state.line.clone(),
                ttl,
            };
            client
                .create_record(state.zone_id, &mutation)
                .await
                .map_err(map_provider_error)?;
        }
        TxtMutationMode::HuaweiRecordSet => {
            // DNSMgr Huawei wrapper 把一个 mutation value 用逗号拆成 records[]。
            // 每个成员必须自行带引号；`A,B` 会被错误变成 `"A` 与 `B"`。
            if records.len() > 1 {
                return Err(AcmeDns01Error::Conflict);
            }
            let mut values = records
                .first()
                .map(|record| record.values.clone())
                .unwrap_or_default();
            values.push(value.to_string());
            let mutation = DnsMgrRecordMutation {
                host: state.host.clone(),
                record_type: "TXT".into(),
                value: encode_huawei_recordset_values(&values)?,
                line: state.line.clone(),
                ttl,
            };
            if let Some(record) = records.first() {
                client
                    .update_record(state.zone_id, &record.record_id, &mutation)
                    .await
                    .map_err(map_provider_error)?;
            } else {
                client
                    .create_record(state.zone_id, &mutation)
                    .await
                    .map_err(map_provider_error)?;
            }
        }
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
    if state.txt_mode.is_none() {
        let detail = client
            .get_domain(state.zone_id)
            .await
            .map_err(map_provider_error)?;
        state.txt_mode = Some(txt_mutation_mode(detail.domain.provider_type.as_deref()));
    }
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
        match state.txt_mode.ok_or(AcmeDns01Error::Provider)? {
            TxtMutationMode::SeparateRecords => {
                // 每个 challenge 自己占一条 TXT，cleanup 只删除自己的 record。
                client
                    .delete_record(state.zone_id, &record.record_id)
                    .await
                    .map_err(map_provider_error)?;
            }
            TxtMutationMode::HuaweiRecordSet => {
                let remaining = record
                    .values
                    .iter()
                    .filter(|value| {
                        value_fingerprint(&normalize_txt_value(value)) != state.value_sha256
                    })
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
                        value: encode_huawei_recordset_values(&remaining)?,
                        line: state.line.clone(),
                        ttl: u32::try_from(record.ttl).map_err(|_| AcmeDns01Error::Provider)?,
                    };
                    client
                        .update_record(state.zone_id, &record.record_id, &mutation)
                        .await
                        .map_err(map_provider_error)?;
                }
            }
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
    let authorities = authoritative_resolvers(&system_resolver, zone_name).await?;
    let mut propagation =
        AuthoritativePropagation::new(authorities.iter().map(|authority| authority.name.clone()));
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    loop {
        let visible = join_all(authorities.iter().map(|authority| async move {
            let endpoint_results =
                join_all(authority.resolvers.iter().map(|resolver| async move {
                    resolver
                        .txt_lookup(fqdn)
                        .await
                        .is_ok_and(|lookup| txt_lookup_matches(&lookup, expected))
                }))
                .await;
            (
                authority.name.as_str(),
                endpoint_results.into_iter().any(|matched| matched),
            )
        }))
        .await;
        // 一个权威 NS 可能有多个地址，只要其中一个地址能权威返回目标值即可。
        // 不要求所有 NS 在同一轮同时可见，但每个 NS 都必须在超时窗口内至少
        // 观察到一次目标值，避免正常的分批传播被误判，同时不放宽权威覆盖。
        propagation.observe_round(visible);
        if propagation.complete() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        tokio::time::sleep(PROPAGATION_INTERVAL).await;
    }
}

struct AuthoritativeResolver {
    name: String,
    resolvers: Vec<TokioAsyncResolver>,
}

struct AuthoritativePropagation {
    pending: HashSet<String>,
}

impl AuthoritativePropagation {
    fn new(authorities: impl IntoIterator<Item = String>) -> Self {
        Self {
            pending: authorities.into_iter().collect(),
        }
    }

    fn observe_round<'a>(&mut self, observations: impl IntoIterator<Item = (&'a str, bool)>) {
        for (authority, visible) in observations {
            if visible {
                self.pending.remove(authority);
            }
        }
    }

    fn complete(&self) -> bool {
        self.pending.is_empty()
    }
}

async fn authoritative_resolvers(
    system_resolver: &TokioAsyncResolver,
    zone_name: &str,
) -> Result<Vec<AuthoritativeResolver>, ()> {
    let nameservers = system_resolver.ns_lookup(zone_name).await.map_err(|_| ())?;
    let mut authorities = HashMap::<String, HashSet<IpAddr>>::new();
    for nameserver in nameservers.iter() {
        let ips = system_resolver
            .lookup_ip(nameserver.0.clone())
            .await
            .map_err(|_| ())?;
        let name = nameserver.0.to_ascii().to_ascii_lowercase();
        authorities.entry(name).or_default().extend(ips.iter());
    }
    if authorities.is_empty() || authorities.values().any(HashSet::is_empty) {
        return Err(());
    }

    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_secs(3);
    options.recursion_desired = false;
    let mut authorities = authorities
        .into_iter()
        .map(|(name, addresses)| AuthoritativeResolver {
            name,
            resolvers: addresses
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
                .collect(),
        })
        .collect::<Vec<_>>();
    authorities.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(authorities)
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

fn encode_huawei_recordset_values(values: &[String]) -> Result<String, AcmeDns01Error> {
    if values.is_empty() {
        return Err(AcmeDns01Error::Conflict);
    }
    values
        .iter()
        .map(|value| normalize_txt_value(value))
        .map(|value| {
            if value.is_empty()
                || value.contains(',')
                || value.contains('"')
                || value.contains('\\')
            {
                Err(AcmeDns01Error::Conflict)
            } else {
                Ok(format!("\"{value}\""))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
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

    #[derive(Default)]
    struct SeparateRecordProviderState {
        host: String,
        records: HashMap<String, String>,
        next_id: usize,
        creates: usize,
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
                        state.values = decode_huawei_mutation(&form["value"]);
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
                        state.values = decode_huawei_mutation(&form["value"]);
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

    async fn mock_separate_record_provider(
        host: &str,
    ) -> (
        String,
        Arc<AsyncMutex<SeparateRecordProviderState>>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = Arc::new(AsyncMutex::new(SeparateRecordProviderState {
            host: host.into(),
            ..Default::default()
        }));
        let list_state = Arc::clone(&state);
        let add_state = Arc::clone(&state);
        let delete_state = Arc::clone(&state);
        let router = Router::new()
            .route(
                "/api/domain",
                post(|| async {
                    Json(json!({
                        "total": 1,
                        "rows": [{"id": 7, "name": "example.com", "type": "cloudflare", "recordcount": 0}]
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
                            "config": {"type": "cloudflare"},
                            "recordcount": 0,
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
                        let mut records = state.records.iter().collect::<Vec<_>>();
                        records.sort_by(|left, right| left.0.cmp(right.0));
                        let rows = records
                            .into_iter()
                            .map(|(record_id, value)| {
                                json!({
                                    "RecordId": record_id,
                                    "Domain": "example.com",
                                    "Name": state.host,
                                    "Type": "TXT",
                                    "Value": value,
                                    "Line": "default_view",
                                    "LineName": "Global default",
                                    "TTL": 60,
                                    "Status": "1"
                                })
                            })
                            .collect::<Vec<_>>();
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
                        state.next_id += 1;
                        let record_id = format!("txt-{}", state.next_id);
                        state.creates += 1;
                        state.records.insert(record_id, form["value"].clone());
                        Json(json!({"code": 0}))
                    }
                }),
            )
            .route(
                "/api/record/delete/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let state = Arc::clone(&delete_state);
                    async move {
                        let mut state = state.lock().await;
                        let record_id = &form["recordid"];
                        assert!(state.records.remove(record_id).is_some());
                        state.deletes += 1;
                        Json(json!({"code": 0}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (base_url, state, handle)
    }

    fn decode_huawei_mutation(value: &str) -> Vec<String> {
        let wrapped = if value.starts_with('"') {
            value.to_string()
        } else {
            format!("\"{value}\"")
        };
        wrapped
            .split(',')
            .map(normalize_txt_value)
            .collect::<Vec<_>>()
    }

    fn request_for(node_id: &str, sni: &str, value: &str) -> AcmeDns01Request {
        AcmeDns01Request {
            node_id: node_id.into(),
            sni: sni.into(),
            value: value.into(),
        }
    }

    fn request(sni: &str, value: &str) -> AcmeDns01Request {
        request_for("node-a", sni, value)
    }

    #[test]
    fn huawei_recordset_values_quote_each_member_and_fail_closed() {
        assert_eq!(
            encode_huawei_recordset_values(&["old".into(), "challenge".into()]).unwrap(),
            "\"old\",\"challenge\""
        );
        assert_eq!(
            encode_huawei_recordset_values(&["unrelated,content".into(), "challenge".into()]),
            Err(AcmeDns01Error::Conflict)
        );
        assert_eq!(
            txt_mutation_mode(Some("huawei")),
            TxtMutationMode::HuaweiRecordSet
        );
        assert_eq!(
            txt_mutation_mode(Some("cloudflare")),
            TxtMutationMode::SeparateRecords
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
    fn authoritative_propagation_accumulates_each_ns_without_same_round_unanimity() {
        let mut propagation =
            AuthoritativePropagation::new(["ns1.example.".into(), "ns2.example.".into()]);
        propagation.observe_round([("ns1.example.", true), ("ns2.example.", false)]);
        assert!(!propagation.complete());

        propagation.observe_round([("ns1.example.", false), ("ns2.example.", true)]);
        assert!(propagation.complete());
    }

    #[test]
    fn authoritative_propagation_never_ignores_a_stale_ns() {
        let mut propagation =
            AuthoritativePropagation::new(["ns1.example.".into(), "ns2.example.".into()]);
        for _ in 0..20 {
            propagation.observe_round([("ns1.example.", true), ("ns2.example.", false)]);
        }
        assert!(!propagation.complete());
    }

    #[tokio::test]
    async fn same_sni_operations_share_a_mutex_without_blocking_other_snis() {
        let first = sni_operation("serialized.example.com").unwrap();
        let same = sni_operation("serialized.example.com").unwrap();
        let other = sni_operation("other.example.com").unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));

        let guard = first.lock().await;
        let waiter_lock = Arc::clone(&same);
        let waiter = tokio::spawn(async move {
            let _guard = waiter_lock.lock().await;
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(guard);
        waiter.await.unwrap();
    }

    #[tokio::test]
    async fn huawei_rrset_contract_serializes_multi_relay_present_and_cleanup() {
        let first_value = "challenge-token-relay-a";
        let second_value = "challenge-token-relay-b";
        let third_value = "challenge-token-relay-c";
        let sni = "concurrent.example.com";
        let (base_url, provider, handle) =
            mock_provider("_acme-challenge.concurrent", Vec::new()).await;
        let db = test_db(&base_url).await;
        let first = request_for("node-a", sni, first_value);
        let second = request_for("node-b", sni, second_value);
        let third = request_for("node-c", sni, third_value);
        let propagation = FixedPropagation(true);

        let (first_result, second_result, third_result) = tokio::join!(
            present_with_observer(&db, 10, &first, &propagation),
            present_with_observer(&db, 10, &second, &propagation),
            present_with_observer(&db, 10, &third, &propagation),
        );
        first_result.unwrap();
        second_result.unwrap();
        third_result.unwrap();

        {
            let state = provider.lock().await;
            let mut actual = state.values.clone();
            actual.sort();
            let mut expected = vec![
                first_value.to_string(),
                second_value.to_string(),
                third_value.to_string(),
            ];
            expected.sort();
            assert_eq!(actual, expected);
            assert_eq!((state.creates, state.updates, state.deletes), (1, 2, 0));
        }

        let (first_cleanup, second_cleanup) =
            tokio::join!(cleanup(&db, 10, &first), cleanup(&db, 10, &second));
        first_cleanup.unwrap();
        second_cleanup.unwrap();
        {
            let state = provider.lock().await;
            assert_eq!(state.values, [third_value]);
        }
        cleanup(&db, 10, &third).await.unwrap();
        let state = provider.lock().await;
        assert!(state.values.is_empty());
        assert_eq!((state.creates, state.updates, state.deletes), (1, 4, 1));
        handle.abort();
    }

    #[tokio::test]
    async fn separate_record_provider_contract_keeps_multi_relay_values_independent() {
        let first_value = "challenge-token-relay-a";
        let second_value = "challenge-token-relay-b";
        let sni = "separate.example.com";
        let (base_url, provider, handle) =
            mock_separate_record_provider("_acme-challenge.separate").await;
        let db = test_db(&base_url).await;
        let first = request_for("node-a", sni, first_value);
        let second = request_for("node-b", sni, second_value);
        let propagation = FixedPropagation(true);

        let (first_result, second_result) = tokio::join!(
            present_with_observer(&db, 10, &first, &propagation),
            present_with_observer(&db, 10, &second, &propagation),
        );
        first_result.unwrap();
        second_result.unwrap();
        {
            let state = provider.lock().await;
            let mut values = state.records.values().cloned().collect::<Vec<_>>();
            values.sort();
            assert_eq!(values, [first_value.to_string(), second_value.to_string()]);
            assert_eq!((state.creates, state.deletes), (2, 0));
        }

        let (first_cleanup, second_cleanup) =
            tokio::join!(cleanup(&db, 10, &first), cleanup(&db, 10, &second));
        first_cleanup.unwrap();
        second_cleanup.unwrap();
        let state = provider.lock().await;
        assert!(state.records.is_empty());
        assert_eq!((state.creates, state.deletes), (2, 2));
        handle.abort();
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
