//! DNSMgr integration settings and their secret-safe public projection.
//!
//! The first integration version uses the existing KVS table rather than a
//! schema migration. The API key is stored with the other Panel secrets but is
//! never serialized through the Admin API or passed to Nodes.

use crate::api::AppState;
use crate::db::repo::GroupRepository;
use crate::db::repo::{
    DnsRecordBinding, DnsRecordSync, NewDnsRecordBinding, NewDnsRecordSync, ResourceScope,
    RuleRepository,
};
use crate::db::Repository;
use crate::integrations::dnsmgr::{
    DnsMgrClient, DnsMgrClientConfig, DnsMgrDomain, DnsMgrDomainDetail, DnsMgrError, DnsMgrRecord,
    DnsMgrRecordMutation, DomainListParams, RecordListParams,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

const DISCOVERY_PAGE_LIMIT: u16 = 100;
const DNSMGR_DEFAULT_WRITE_TTL: u32 = 600;
const DNS_SYNC_TICK: Duration = Duration::from_secs(30);
const DNS_SYNC_MAX_BATCH: i64 = 16;
const DNS_SYNC_MAX_ATTEMPTS: i32 = 6;
const DNS_SYNC_BASE_BACKOFF_SECS: u64 = 5;
const DNS_SYNC_MAX_BACKOFF_SECS: u64 = 300;
const PUBLIC_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROVIDER_LINE_ID_BYTES: usize = 256;

/// KVS key holding the single Panel-wide DNSMgr integration configuration.
pub const DNSMGR_CONFIG_KEY: &str = "dns:dnsmgr";
pub const DEFAULT_LINE_KEY: &str = "default";

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsMgrSettings {
    pub enabled: bool,
    pub base_url: String,
    pub uid: u64,
    pub api_key: String,
}

impl fmt::Debug for DnsMgrSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsMgrSettings")
            .field("enabled", &self.enabled)
            .field("base_url", &self.base_url)
            .field("uid", &self.uid)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl DnsMgrSettings {
    pub fn from_json(raw: Option<&str>) -> Self {
        raw.and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default()
    }

    pub fn configured(&self) -> bool {
        !self.base_url.is_empty() && self.uid > 0 && !self.api_key.is_empty()
    }
}

/// Safe Admin API response. The credential is intentionally represented only
/// by its presence, so a browser cannot replay or exfiltrate the stored key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsMgrSettingsPublic {
    pub enabled: bool,
    pub base_url: String,
    pub uid: Option<u64>,
    pub configured: bool,
    pub has_api_key: bool,
}

impl From<&DnsMgrSettings> for DnsMgrSettingsPublic {
    fn from(settings: &DnsMgrSettings) -> Self {
        Self {
            enabled: settings.enabled,
            base_url: settings.base_url.clone(),
            uid: (settings.uid > 0).then_some(settings.uid),
            configured: settings.configured(),
            has_api_key: !settings.api_key.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedFqdn(String);

impl NormalizedFqdn {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) enum DnsDiscoveryError {
    InvalidFqdn,
    InvalidRecordValue {
        record_type: DnsRecordType,
        value: String,
    },
    UnsupportedRecordType(DnsRecordType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) enum DnsRecordType {
    A,
    Aaaa,
    Cname,
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
impl DnsRecordType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) struct ProviderLine {
    /// Exact provider identity returned by DNSMgr. Default-equivalent values
    /// remain available here even though they share one internal key.
    pub raw_id: String,
    pub key: String,
    pub name: Option<String>,
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
impl ProviderLine {
    pub(crate) fn from_provider(raw_id: &str, name: Option<&str>) -> Self {
        let raw_id = raw_id.trim().to_string();
        let key = if raw_id.is_empty()
            || raw_id == "0"
            || raw_id.eq_ignore_ascii_case("default")
            || raw_id.eq_ignore_ascii_case("default_view")
        {
            "default".to_string()
        } else {
            format!("dnsmgr:{raw_id}")
        };
        Self {
            raw_id,
            key,
            name: name
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
        }
    }
}

impl Default for ProviderLine {
    fn default() -> Self {
        Self::from_provider("default", Some("default"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedZone {
    pub domain_id: u64,
    pub zone_name: String,
    pub host: String,
    pub provider_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) enum ZoneResolution {
    ZoneResolved(ResolvedZone),
    NoMatchingZone,
    UpstreamFailure(DnsMgrError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) struct DiscoveredRecord {
    pub record: DnsMgrRecord,
    pub line: ProviderLine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code, clippy::large_enum_variant)] // 保持发现结果的现有内部形态，不为 lint 改写状态机。
pub(crate) enum RecordDiscovery {
    NoRecord,
    SingleMatchingRecord(DiscoveredRecord),
    MultipleMatchingRecords(Vec<DiscoveredRecord>),
    ConflictingRecordType(Vec<DiscoveredRecord>),
    UpstreamFailure(DnsMgrError),
}

pub(crate) fn normalize_fqdn(input: &str) -> Result<NormalizedFqdn, DnsDiscoveryError> {
    if input != input.trim() {
        return Err(DnsDiscoveryError::InvalidFqdn);
    }
    let value = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(DnsDiscoveryError::InvalidFqdn);
    }

    let labels = value.split('.').collect::<Vec<_>>();
    if labels.iter().enumerate().any(|(index, label)| {
        label.is_empty()
            || label.len() > 63
            || (*label == "*" && index != 0)
            || (*label != "*"
                && (!label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || !label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)))
    }) {
        return Err(DnsDiscoveryError::InvalidFqdn);
    }

    Ok(NormalizedFqdn(value))
}

pub(crate) fn resolve_zone_from_inventory(
    fqdn: &NormalizedFqdn,
    domains: &[DnsMgrDomain],
) -> Option<ResolvedZone> {
    let mut best: Option<ResolvedZone> = None;
    for domain in domains {
        let Ok(zone) = normalize_fqdn(&domain.zone_name) else {
            continue;
        };
        if zone.as_str().starts_with("*.") {
            continue;
        }
        let exact = fqdn.as_str() == zone.as_str();
        let suffix = fqdn
            .as_str()
            .strip_suffix(zone.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'));
        if !exact && !suffix {
            continue;
        }
        let candidate = ResolvedZone {
            domain_id: domain.domain_id,
            zone_name: zone.as_str().to_string(),
            host: if exact {
                "@".to_string()
            } else {
                fqdn.as_str()[..fqdn.as_str().len() - zone.as_str().len() - 1].to_string()
            },
            provider_type: domain.provider_type.clone(),
        };
        let replace = best.as_ref().is_none_or(|current| {
            candidate.zone_name.len() > current.zone_name.len()
                || (candidate.zone_name.len() == current.zone_name.len()
                    && candidate.domain_id < current.domain_id)
        });
        if replace {
            best = Some(candidate);
        }
    }
    best
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) async fn resolve_zone(client: &DnsMgrClient, fqdn: &NormalizedFqdn) -> ZoneResolution {
    let mut domains = Vec::new();
    let mut offset = 0_u32;
    loop {
        let page = match client
            .list_domains(&DomainListParams {
                offset,
                limit: DISCOVERY_PAGE_LIMIT,
                keyword: None,
            })
            .await
        {
            Ok(page) => page,
            Err(error) => return ZoneResolution::UpstreamFailure(error),
        };
        let count = page.rows.len();
        domains.extend(page.rows);
        if count == 0 || u64::from(offset).saturating_add(count as u64) >= page.total {
            break;
        }
        let Some(next) = offset.checked_add(count as u32) else {
            return ZoneResolution::UpstreamFailure(DnsMgrError::ProtocolContractViolation(
                "domain pagination offset overflow".into(),
            ));
        };
        offset = next;
    }

    resolve_zone_from_inventory(fqdn, &domains)
        .map(ZoneResolution::ZoneResolved)
        .unwrap_or(ZoneResolution::NoMatchingZone)
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) async fn discover_records(
    client: &DnsMgrClient,
    zone: &ResolvedZone,
    expected_type: DnsRecordType,
    expected_line: &ProviderLine,
) -> RecordDiscovery {
    let mut records = Vec::new();
    let mut offset = 0_u32;
    loop {
        let page = match client
            .list_records(
                zone.domain_id,
                &RecordListParams {
                    offset,
                    limit: DISCOVERY_PAGE_LIMIT,
                    subdomain: Some(zone.host.clone()),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(page) => page,
            Err(error) => return RecordDiscovery::UpstreamFailure(error),
        };
        let count = page.rows.len();
        records.extend(page.rows);
        let reached_total = page.authoritative_total
            && u64::from(offset).saturating_add(count as u64) >= page.total;
        if count == 0
            || reached_total
            || (!page.authoritative_total && count < DISCOVERY_PAGE_LIMIT as usize)
        {
            break;
        }
        let Some(next) = offset.checked_add(count as u32) else {
            return RecordDiscovery::UpstreamFailure(DnsMgrError::ProtocolContractViolation(
                "record pagination offset overflow".into(),
            ));
        };
        offset = next;
    }

    classify_records(zone, expected_type, expected_line, records)
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
fn classify_records(
    zone: &ResolvedZone,
    expected_type: DnsRecordType,
    expected_line: &ProviderLine,
    records: Vec<DnsMgrRecord>,
) -> RecordDiscovery {
    let relevant = records
        .into_iter()
        .filter(|record| record.host.trim().eq_ignore_ascii_case(&zone.host))
        .map(|record| {
            let line = ProviderLine::from_provider(&record.line, record.line_name.as_deref());
            DiscoveredRecord { record, line }
        })
        .filter(|record| record.line.key == expected_line.key)
        .collect::<Vec<_>>();

    if matches!(expected_type, DnsRecordType::A | DnsRecordType::Aaaa) {
        let conflicts = relevant
            .iter()
            .filter(|record| record.record.record_type.eq_ignore_ascii_case("CNAME"))
            .cloned()
            .collect::<Vec<_>>();
        if !conflicts.is_empty() {
            return RecordDiscovery::ConflictingRecordType(conflicts);
        }
    }

    let mut matches = relevant
        .into_iter()
        .filter(|record| {
            record
                .record
                .record_type
                .eq_ignore_ascii_case(expected_type.as_str())
        })
        .collect::<Vec<_>>();
    match matches.len() {
        0 => RecordDiscovery::NoRecord,
        1 => RecordDiscovery::SingleMatchingRecord(matches.remove(0)),
        _ => RecordDiscovery::MultipleMatchingRecords(matches),
    }
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) fn validate_ip_family(
    record_type: DnsRecordType,
    value: &str,
) -> Result<IpAddr, DnsDiscoveryError> {
    if record_type == DnsRecordType::Cname {
        return Err(DnsDiscoveryError::UnsupportedRecordType(record_type));
    }
    let parsed = value
        .parse::<IpAddr>()
        .map_err(|_| DnsDiscoveryError::InvalidRecordValue {
            record_type,
            value: value.to_string(),
        })?;
    let valid = matches!(record_type, DnsRecordType::A) && parsed.is_ipv4()
        || matches!(record_type, DnsRecordType::Aaaa) && parsed.is_ipv6();
    if !valid {
        return Err(DnsDiscoveryError::InvalidRecordValue {
            record_type,
            value: value.to_string(),
        });
    }
    Ok(parsed)
}

#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
pub(crate) fn binding_matches_record(
    binding: Option<&DnsRecordBinding>,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    expected_type: DnsRecordType,
    record: &DiscoveredRecord,
) -> bool {
    let Some(binding) = binding else {
        return false;
    };
    let Ok(zone_id) = i64::try_from(zone.domain_id) else {
        return false;
    };
    binding.zone_id == zone_id
        && binding.record_id == record.record.record_id
        && binding.fqdn == fqdn.as_str()
        && binding.zone_name == zone.zone_name
        && binding.host == zone.host
        && binding.record_type == expected_type.as_str()
        && binding.line_key == record.line.key
        && record.record.host.trim().eq_ignore_ascii_case(&zone.host)
        && record
            .record
            .record_type
            .eq_ignore_ascii_case(expected_type.as_str())
        && (binding.line_key == "default" || binding.line == record.line.raw_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnsureRecordInput {
    pub rule_id: i64,
    pub fqdn: String,
    pub record_type: DnsRecordType,
    pub expected_value: String,
    pub line: ProviderLine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeleteRecordInput {
    pub rule_id: i64,
    pub fqdn: String,
    pub record_type: DnsRecordType,
    pub line: ProviderLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnsureRecordConflict {
    Cname,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnsureRecordFailure {
    InvalidInput(DnsDiscoveryError),
    InvalidRule,
    NoMatchingZone,
    ProviderLineUnavailable,
    TtlOutOfRange,
    Upstream(DnsMgrError),
    Database,
    PostWriteNotVerified,
    OwnershipUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnsureRecordResult {
    AlreadyCorrect {
        record_id: String,
    },
    Created {
        record_id: String,
    },
    Recreated {
        old_record_id: String,
        record_id: String,
    },
    Updated {
        record_id: String,
    },
    Conflict(EnsureRecordConflict),
    MutationOutcomeUnknown,
    Failed(EnsureRecordFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeleteRecordResult {
    Deleted { record_id: String },
    AlreadyAbsent,
    MutationOutcomeUnknown,
    Failed(EnsureRecordFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsMutationAuditOutcome {
    DnsRecordCreated,
    DnsRecordUpdated,
    DnsRecordRecreated,
    DnsRecordConflict,
    DnsMutationUnknown,
    DnsSyncFailed,
    NoMutation,
}

impl DnsMutationAuditOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DnsRecordCreated => "DNS_RECORD_CREATED",
            Self::DnsRecordUpdated => "DNS_RECORD_UPDATED",
            Self::DnsRecordRecreated => "DNS_RECORD_RECREATED",
            Self::DnsRecordConflict => "DNS_RECORD_CONFLICT",
            Self::DnsMutationUnknown => "DNS_MUTATION_OUTCOME_UNKNOWN",
            Self::DnsSyncFailed => "DNS_SYNC_FAILED",
            Self::NoMutation => "DNS_NO_MUTATION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAuditTransition {
    action: &'static str,
    rule_id: i64,
    fqdn: String,
    record_type: String,
    expected_value: String,
    line_key: String,
    desired_action: String,
    ownership: String,
    category: Option<String>,
}

impl DnsAuditTransition {
    fn from_sync(
        action: &'static str,
        sync: &DnsRecordSync,
        ownership: &str,
        category: Option<&str>,
    ) -> Self {
        Self {
            action,
            rule_id: sync.rule_id,
            fqdn: sync.fqdn.clone(),
            record_type: sync.record_type.clone(),
            expected_value: sync
                .expected_value
                .clone()
                .unwrap_or_else(|| "<absent>".into()),
            line_key: sync.line_key.clone(),
            desired_action: sync.desired_action.clone(),
            ownership: ownership.to_string(),
            category: category.map(str::to_string),
        }
    }

    async fn record(self, state: &AppState) {
        crate::service::audit::record(
            state,
            None,
            self.action,
            "rule",
            self.rule_id,
            &format!(
                "fqdn={} record_type={} line_key={} desired_action={} expected_value={} ownership={} category={}",
                self.fqdn,
                self.record_type,
                self.line_key,
                self.desired_action,
                self.expected_value,
                self.ownership,
                self.category.as_deref().unwrap_or("none"),
            ),
        )
        .await;
    }
}

impl EnsureRecordResult {
    pub(crate) fn audit_outcome(&self) -> DnsMutationAuditOutcome {
        match self {
            Self::Created { .. } => DnsMutationAuditOutcome::DnsRecordCreated,
            Self::Updated { .. } => DnsMutationAuditOutcome::DnsRecordUpdated,
            Self::Recreated { .. } => DnsMutationAuditOutcome::DnsRecordRecreated,
            Self::Conflict(_) => DnsMutationAuditOutcome::DnsRecordConflict,
            Self::MutationOutcomeUnknown => DnsMutationAuditOutcome::DnsMutationUnknown,
            Self::Failed(_) => DnsMutationAuditOutcome::DnsSyncFailed,
            Self::AlreadyCorrect { .. } => DnsMutationAuditOutcome::NoMutation,
        }
    }
}

/// Ensure the exact A record authorized by one eligible SNI Rule. Provider
/// bindings are bookkeeping only: the Rule-derived desired state grants write
/// authority. DNSMgr writes are single-attempt and always followed by read-back
/// verification; public DNS propagation is intentionally separate.
pub(crate) async fn ensure_record(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
) -> EnsureRecordResult {
    if input.rule_id <= 0 || !matches!(input.record_type, DnsRecordType::A | DnsRecordType::Aaaa) {
        return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidInput(
            DnsDiscoveryError::UnsupportedRecordType(input.record_type),
        ));
    }
    let fqdn = match normalize_fqdn(&input.fqdn) {
        Ok(fqdn) => fqdn,
        Err(error) => return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidInput(error)),
    };
    let expected_ip = match validate_ip_family(input.record_type, &input.expected_value) {
        Ok(ip) => ip,
        Err(error) => return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidInput(error)),
    };
    match upsert_is_authorized(db, input, &fqdn).await {
        Ok(true) => {}
        Ok(false) => return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidRule),
        Err(_) => return EnsureRecordResult::Failed(EnsureRecordFailure::Database),
    }
    if canonical_provider_line(&input.line.raw_id).is_none_or(|line| line.key != input.line.key) {
        return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidRule);
    }
    let zone = match resolve_zone(client, &fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => {
            return EnsureRecordResult::Failed(EnsureRecordFailure::NoMatchingZone)
        }
        ZoneResolution::UpstreamFailure(error) => {
            return EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error))
        }
    };
    let detail = match client.get_domain(zone.domain_id).await {
        Ok(detail) => detail,
        Err(error) => return EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error)),
    };
    let line = match resolve_mutation_line(&input.line, &detail) {
        Some(line) => line,
        None => return EnsureRecordResult::Failed(EnsureRecordFailure::ProviderLineUnavailable),
    };
    let ttl = match write_ttl(&detail) {
        Some(ttl) => ttl,
        None => return EnsureRecordResult::Failed(EnsureRecordFailure::TtlOutOfRange),
    };
    let binding = match db
        .find_dns_record_binding_for_rule(
            input.rule_id,
            fqdn.as_str(),
            input.record_type.as_str(),
            &line.key,
        )
        .await
    {
        Ok(binding) => binding,
        Err(_) => return EnsureRecordResult::Failed(EnsureRecordFailure::Database),
    };

    let discovery = discover_records(client, &zone, input.record_type, &line).await;
    if line.key != DEFAULT_LINE_KEY {
        return match discovery {
            RecordDiscovery::UpstreamFailure(error) => {
                EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error))
            }
            RecordDiscovery::ConflictingRecordType(_) => {
                EnsureRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
            }
            RecordDiscovery::NoRecord => {
                if let Some(binding) = binding.as_ref() {
                    if set_binding_state(db, binding.id, "MISSING", None)
                        .await
                        .is_err()
                    {
                        return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
                    }
                }
                create_and_verify(
                    db,
                    client,
                    input,
                    &fqdn,
                    &zone,
                    &line,
                    ttl,
                    binding.as_ref(),
                )
                .await
            }
            RecordDiscovery::SingleMatchingRecord(record)
                if binding_matches_record(
                    binding.as_ref(),
                    &fqdn,
                    &zone,
                    input.record_type,
                    &record,
                ) =>
            {
                handle_discovered_records(
                    db,
                    client,
                    input,
                    &fqdn,
                    &zone,
                    &line,
                    ttl,
                    expected_ip,
                    binding.as_ref(),
                    std::slice::from_ref(&record),
                )
                .await
            }
            RecordDiscovery::SingleMatchingRecord(_)
            | RecordDiscovery::MultipleMatchingRecords(_) => {
                EnsureRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
            }
        };
    }
    match discovery {
        RecordDiscovery::UpstreamFailure(error) => {
            EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error))
        }
        RecordDiscovery::ConflictingRecordType(_) => {
            binding_conflict(db, binding.as_ref(), EnsureRecordConflict::Cname).await
        }
        RecordDiscovery::NoRecord => {
            if let Some(binding) = binding.as_ref() {
                if set_binding_state(db, binding.id, "MISSING", None)
                    .await
                    .is_err()
                {
                    return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
                }
            }
            create_and_verify(
                db,
                client,
                input,
                &fqdn,
                &zone,
                &line,
                ttl,
                binding.as_ref(),
            )
            .await
        }
        RecordDiscovery::SingleMatchingRecord(record) => {
            handle_discovered_records(
                db,
                client,
                input,
                &fqdn,
                &zone,
                &line,
                ttl,
                expected_ip,
                binding.as_ref(),
                std::slice::from_ref(&record),
            )
            .await
        }
        RecordDiscovery::MultipleMatchingRecords(records) => {
            handle_discovered_records(
                db,
                client,
                input,
                &fqdn,
                &zone,
                &line,
                ttl,
                expected_ip,
                binding.as_ref(),
                &records,
            )
            .await
        }
    }
}

pub(crate) async fn ensure_record_absent(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &DeleteRecordInput,
) -> DeleteRecordResult {
    if input.rule_id <= 0 || !matches!(input.record_type, DnsRecordType::A | DnsRecordType::Aaaa) {
        return DeleteRecordResult::Failed(EnsureRecordFailure::InvalidInput(
            DnsDiscoveryError::UnsupportedRecordType(input.record_type),
        ));
    }
    let fqdn = match normalize_fqdn(&input.fqdn) {
        Ok(fqdn) => fqdn,
        Err(error) => return DeleteRecordResult::Failed(EnsureRecordFailure::InvalidInput(error)),
    };
    match delete_is_authorized(db, input, &fqdn).await {
        Ok(true) => {}
        Ok(false) => return DeleteRecordResult::Failed(EnsureRecordFailure::InvalidRule),
        Err(_) => return DeleteRecordResult::Failed(EnsureRecordFailure::Database),
    }
    let zone = match resolve_zone(client, &fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => {
            return DeleteRecordResult::Failed(EnsureRecordFailure::NoMatchingZone)
        }
        ZoneResolution::UpstreamFailure(error) => {
            return DeleteRecordResult::Failed(EnsureRecordFailure::Upstream(error))
        }
    };
    let detail = match client.get_domain(zone.domain_id).await {
        Ok(detail) => detail,
        Err(error) => return DeleteRecordResult::Failed(EnsureRecordFailure::Upstream(error)),
    };
    let line = resolve_mutation_line(&input.line, &detail).unwrap_or_else(|| input.line.clone());
    let binding = match db
        .find_dns_record_binding_for_rule(
            input.rule_id,
            fqdn.as_str(),
            input.record_type.as_str(),
            &line.key,
        )
        .await
    {
        Ok(binding) => binding,
        Err(_) => return DeleteRecordResult::Failed(EnsureRecordFailure::Database),
    };
    let discovery = discover_records(client, &zone, input.record_type, &line).await;
    let records = match discovery {
        RecordDiscovery::NoRecord => Vec::new(),
        RecordDiscovery::SingleMatchingRecord(record) => vec![record],
        RecordDiscovery::MultipleMatchingRecords(records) => records,
        RecordDiscovery::ConflictingRecordType(_) => {
            return DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        }
        RecordDiscovery::UpstreamFailure(error) => {
            return DeleteRecordResult::Failed(EnsureRecordFailure::Upstream(error))
        }
    };
    let Some(binding) = binding else {
        return if records.is_empty() {
            DeleteRecordResult::AlreadyAbsent
        } else {
            DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        };
    };
    if records.len() > 1 {
        return DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified);
    }
    if records.is_empty() {
        return match set_binding_state(db, binding.id, "MISSING", None).await {
            Ok(()) => DeleteRecordResult::AlreadyAbsent,
            Err(()) => DeleteRecordResult::Failed(EnsureRecordFailure::Database),
        };
    }
    let record = &records[0];
    if record.record.record_id != binding.record_id {
        return DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified);
    }
    if !binding_matches_record(Some(&binding), &fqdn, &zone, input.record_type, record) {
        return DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified);
    }

    let ambiguous = match client
        .delete_record(zone.domain_id, &binding.record_id)
        .await
    {
        Ok(_) => false,
        Err(error) if error.is_ambiguous_write() => true,
        Err(error) => return DeleteRecordResult::Failed(EnsureRecordFailure::Upstream(error)),
    };
    let readback = discover_records(client, &zone, input.record_type, &line).await;
    let line_record_remains = match readback {
        RecordDiscovery::NoRecord => false,
        RecordDiscovery::SingleMatchingRecord(_) | RecordDiscovery::MultipleMatchingRecords(_) => {
            true
        }
        RecordDiscovery::ConflictingRecordType(_) => true,
        RecordDiscovery::UpstreamFailure(_) => return DeleteRecordResult::MutationOutcomeUnknown,
    };
    if line_record_remains {
        return if ambiguous {
            DeleteRecordResult::MutationOutcomeUnknown
        } else {
            DeleteRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified)
        };
    }
    if set_binding_state(db, binding.id, "MISSING", None)
        .await
        .is_err()
    {
        return DeleteRecordResult::MutationOutcomeUnknown;
    }
    DeleteRecordResult::Deleted {
        record_id: binding.record_id,
    }
}

async fn upsert_is_authorized(
    db: &dyn Repository,
    input: &EnsureRecordInput,
    fqdn: &NormalizedFqdn,
) -> Result<bool, crate::db::error::DbError> {
    let Some(rule) =
        RuleRepository::find_rule_by_id(db, input.rule_id, &ResourceScope::All).await?
    else {
        return Ok(false);
    };
    if input.line.key == DEFAULT_LINE_KEY {
        if !rule_is_dns_eligible(&rule)
            || normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim())
                .ok()
                .as_ref()
                != Some(fqdn)
        {
            return Ok(false);
        }
        return Ok(matches!(
            derive_dns_desired(db, input.rule_id).await?,
            DnsDesiredResolution::Eligible(desired)
                if desired.fqdn == fqdn.as_str()
                    && desired.record_type == input.record_type
                    && desired.expected_value == input.expected_value
        ));
    }
    if (!rule_is_dns_eligible(&rule)
        || normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim())
            .ok()
            .as_ref()
            != Some(fqdn))
        && !crate::service::relay_preference::dns_transaction_authorizes(
            db,
            input.rule_id,
            fqdn.as_str(),
            &input.line.key,
            "UPSERT",
            Some(&input.expected_value),
        )
        .await?
    {
        return Ok(false);
    }
    let Some(sync) = db
        .find_dns_record_sync(input.rule_id, &input.line.key)
        .await?
    else {
        return Ok(false);
    };
    Ok(sync.desired_action == "UPSERT"
        && sync.fqdn == fqdn.as_str()
        && sync.record_type == input.record_type.as_str()
        && sync.expected_value.as_deref() == Some(input.expected_value.as_str())
        && sync.line == input.line.raw_id)
}

async fn delete_is_authorized(
    db: &dyn Repository,
    input: &DeleteRecordInput,
    fqdn: &NormalizedFqdn,
) -> Result<bool, crate::db::error::DbError> {
    let Some(rule) =
        RuleRepository::find_rule_by_id(db, input.rule_id, &ResourceScope::All).await?
    else {
        return Ok(false);
    };
    if input.line.key == DEFAULT_LINE_KEY {
        return Ok(false);
    }
    if (!rule_is_dns_eligible(&rule)
        || normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim())
            .ok()
            .as_ref()
            != Some(fqdn))
        && !crate::service::relay_preference::dns_transaction_authorizes(
            db,
            input.rule_id,
            fqdn.as_str(),
            &input.line.key,
            "DELETE",
            None,
        )
        .await?
    {
        return Ok(false);
    }
    let Some(sync) = db
        .find_dns_record_sync(input.rule_id, &input.line.key)
        .await?
    else {
        return Ok(false);
    };
    Ok(sync.desired_action == "DELETE"
        && sync.expected_value.is_none()
        && sync.fqdn == fqdn.as_str()
        && sync.record_type == input.record_type.as_str()
        && sync.line == input.line.raw_id
        && canonical_provider_line(&input.line.raw_id)
            .is_some_and(|line| line.key == input.line.key))
}

fn canonical_provider_line(raw_id: &str) -> Option<ProviderLine> {
    if raw_id.is_empty()
        || raw_id != raw_id.trim()
        || raw_id.len() > MAX_PROVIDER_LINE_ID_BYTES
        || raw_id.chars().any(char::is_control)
    {
        return None;
    }
    Some(ProviderLine::from_provider(raw_id, None))
}

pub(crate) fn resolve_mutation_line(
    requested: &ProviderLine,
    detail: &DnsMgrDomainDetail,
) -> Option<ProviderLine> {
    if requested.key == "default" {
        return detail
            .record_lines
            .iter()
            .map(|line| ProviderLine::from_provider(&line.id, Some(&line.name)))
            .find(|line| line.key == "default")
            .or_else(|| detail.record_lines.is_empty().then(|| requested.clone()));
    }
    detail
        .record_lines
        .iter()
        .find(|line| line.id.trim() == requested.raw_id)
        .map(|line| ProviderLine::from_provider(&line.id, Some(&line.name)))
}

pub(crate) fn write_ttl(detail: &DnsMgrDomainDetail) -> Option<u32> {
    let minimum = detail.min_ttl.unwrap_or(1);
    u32::try_from(minimum)
        .ok()
        .map(|minimum| minimum.max(DNSMGR_DEFAULT_WRITE_TTL))
}

#[allow(clippy::too_many_arguments)]
async fn handle_discovered_records(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    ttl: u32,
    expected_ip: IpAddr,
    binding: Option<&DnsRecordBinding>,
    records: &[DiscoveredRecord],
) -> EnsureRecordResult {
    let bound = binding.and_then(|binding| {
        records.iter().find(|record| {
            binding_matches_record(Some(binding), fqdn, zone, input.record_type, record)
        })
    });
    let canonical = bound.unwrap_or(&records[0]);
    let mut updated = false;
    for record in records {
        if record_value_matches(&record.record.values, expected_ip) {
            continue;
        }
        if let Err(result) =
            update_provider_record_and_verify(db, client, input, zone, line, ttl, binding, record)
                .await
        {
            return result;
        }
        updated = true;
    }

    let binding_is_current = binding.is_some_and(|binding| {
        binding_matches_record(Some(binding), fqdn, zone, input.record_type, canonical)
            && binding.desired_value == input.expected_value
            && binding.state == "BOUND"
            && binding.last_error_category.is_none()
    });
    if (!binding_is_current || updated)
        && persist_verified_binding(
            db,
            input,
            fqdn,
            zone,
            line,
            &canonical.record.record_id,
            binding,
        )
        .await
        .is_err()
    {
        return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
    }

    if updated {
        EnsureRecordResult::Updated {
            record_id: canonical.record.record_id.clone(),
        }
    } else {
        EnsureRecordResult::AlreadyCorrect {
            record_id: canonical.record.record_id.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_and_verify(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    ttl: u32,
    stale_binding: Option<&DnsRecordBinding>,
) -> EnsureRecordResult {
    let mutation = mutation_request(input, zone, line, ttl);
    match client.create_record(zone.domain_id, &mutation).await {
        Ok(_) => {}
        Err(error) if error.is_ambiguous_write() => {
            // Re-read once to avoid a duplicate create, but never claim the
            // resulting identity: another actor may have won the race.
            let _ = discover_records(client, zone, input.record_type, line).await;
            if let Some(binding) = stale_binding {
                let _ = set_binding_state(db, binding.id, "ERROR", Some("MUTATION_UNKNOWN")).await;
            }
            return EnsureRecordResult::MutationOutcomeUnknown;
        }
        Err(error) => {
            if let Some(binding) = stale_binding {
                if set_binding_state(db, binding.id, "ERROR", Some("UPSTREAM_FAILURE"))
                    .await
                    .is_err()
                {
                    return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
                }
            }
            return EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error));
        }
    }

    let verified = match discover_records(client, zone, input.record_type, line).await {
        RecordDiscovery::SingleMatchingRecord(record)
            if record_value_matches(
                &record.record.values,
                validate_ip_family(input.record_type, &input.expected_value)
                    .expect("prevalidated IP"),
            ) =>
        {
            record
        }
        _ => {
            if let Some(binding) = stale_binding {
                if set_binding_state(db, binding.id, "ERROR", Some("POST_WRITE_NOT_VERIFIED"))
                    .await
                    .is_err()
                {
                    return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
                }
            }
            return EnsureRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified);
        }
    };
    if persist_verified_binding(
        db,
        input,
        fqdn,
        zone,
        &verified.line,
        &verified.record.record_id,
        stale_binding,
    )
    .await
    .is_err()
    {
        return EnsureRecordResult::MutationOutcomeUnknown;
    }
    if let Some(binding) = stale_binding {
        EnsureRecordResult::Recreated {
            old_record_id: binding.record_id.clone(),
            record_id: verified.record.record_id,
        }
    } else {
        EnsureRecordResult::Created {
            record_id: verified.record.record_id,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn update_provider_record_and_verify(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
    zone: &ResolvedZone,
    line: &ProviderLine,
    ttl: u32,
    binding: Option<&DnsRecordBinding>,
    record: &DiscoveredRecord,
) -> Result<(), EnsureRecordResult> {
    let mutation = mutation_request(input, zone, line, ttl);
    let write_result = client
        .update_record(zone.domain_id, &record.record.record_id, &mutation)
        .await;
    let ambiguous = match write_result {
        Ok(_) => false,
        Err(error) if error.is_ambiguous_write() => true,
        Err(error) => {
            if let Some(binding) = binding {
                if set_binding_state(db, binding.id, "ERROR", Some("UPSTREAM_FAILURE"))
                    .await
                    .is_err()
                {
                    return Err(EnsureRecordResult::Failed(EnsureRecordFailure::Database));
                }
            }
            return Err(EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(
                error,
            )));
        }
    };

    let expected_ip = validate_ip_family(input.record_type, &input.expected_value)
        .expect("ensure_record validated the IP family");
    let verified = discover_records(client, zone, input.record_type, line).await;
    let exact = match verified {
        RecordDiscovery::SingleMatchingRecord(record) => Some(record),
        RecordDiscovery::MultipleMatchingRecords(records) => records
            .into_iter()
            .find(|candidate| candidate.record.record_id == record.record.record_id),
        _ => None,
    };
    let Some(_exact) =
        exact.filter(|record| record_value_matches(&record.record.values, expected_ip))
    else {
        if let Some(binding) = binding {
            if set_binding_state(
                db,
                binding.id,
                "ERROR",
                Some(if ambiguous {
                    "MUTATION_UNKNOWN"
                } else {
                    "POST_WRITE_NOT_VERIFIED"
                }),
            )
            .await
            .is_err()
            {
                return Err(EnsureRecordResult::Failed(EnsureRecordFailure::Database));
            }
        }
        return Err(if ambiguous {
            EnsureRecordResult::MutationOutcomeUnknown
        } else {
            EnsureRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified)
        });
    };
    if ambiguous {
        Err(EnsureRecordResult::MutationOutcomeUnknown)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn persist_verified_binding(
    db: &dyn Repository,
    input: &EnsureRecordInput,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    record_id: &str,
    binding: Option<&DnsRecordBinding>,
) -> Result<(), ()> {
    let now = utc_now();
    let zone_id = i64::try_from(zone.domain_id).map_err(|_| ())?;
    let existing_provider_binding = db
        .find_dns_record_binding_by_record(zone_id, record_id)
        .await
        .map_err(|_| ())?;
    if let Some(binding) = binding {
        if existing_provider_binding
            .as_ref()
            .is_some_and(|existing| existing.id != binding.id)
        {
            return Ok(());
        }
        return match db
            .rebind_verified_dns_record(
                binding.id,
                record_id,
                &line.raw_id,
                &input.expected_value,
                &now,
                &now,
            )
            .await
        {
            Ok(1) => Ok(()),
            _ => Err(()),
        };
    }
    if existing_provider_binding.is_some() {
        return Ok(());
    }
    db.insert_dns_record_binding(&NewDnsRecordBinding {
        rule_id: Some(input.rule_id),
        fqdn: fqdn.as_str().to_string(),
        zone_id,
        zone_name: zone.zone_name.clone(),
        host: zone.host.clone(),
        record_type: input.record_type.as_str().to_string(),
        line: line.raw_id.clone(),
        line_key: line.key.clone(),
        record_id: record_id.to_string(),
        desired_value: input.expected_value.clone(),
        state: "BOUND".into(),
        last_observed_at: Some(now.clone()),
        created_at: now,
    })
    .await
    .map(|_| ())
    .map_err(|_| ())
}

fn mutation_request(
    input: &EnsureRecordInput,
    zone: &ResolvedZone,
    line: &ProviderLine,
    ttl: u32,
) -> DnsMgrRecordMutation {
    DnsMgrRecordMutation {
        host: zone.host.clone(),
        record_type: input.record_type.as_str().into(),
        value: input.expected_value.clone(),
        line: line.raw_id.clone(),
        ttl,
    }
}

/// The current SNI automation owns one A value per provider record identity.
/// Preserve every reported value and require an exact singleton match before
/// treating a record as converged; a multi-value record follows the existing
/// update-and-verify path instead of silently matching its first value.
fn record_value_matches(values: &[String], expected: IpAddr) -> bool {
    matches!(values, [value] if value.trim().parse::<IpAddr>().is_ok_and(|value| value == expected))
}

async fn binding_conflict(
    db: &dyn Repository,
    binding: Option<&DnsRecordBinding>,
    conflict: EnsureRecordConflict,
) -> EnsureRecordResult {
    if let Some(binding) = binding {
        if set_binding_state(db, binding.id, "CONFLICT", Some("DNS_CONFLICT"))
            .await
            .is_err()
        {
            return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
        }
    }
    EnsureRecordResult::Conflict(conflict)
}

async fn set_binding_state(
    db: &dyn Repository,
    binding_id: i64,
    state: &str,
    error: Option<&str>,
) -> Result<(), ()> {
    let now = utc_now();
    match db
        .update_dns_record_binding_observation(binding_id, state, Some(&now), error, &now)
        .await
    {
        Ok(1) => Ok(()),
        _ => Err(()),
    }
}

fn utc_now() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// The only automatic DNS target source in the single-active architecture.
/// Node observations and WS peer addresses are intentionally never consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsDesiredRecord {
    pub rule_id: i64,
    pub fqdn: String,
    pub record_type: DnsRecordType,
    pub expected_value: String,
    pub line: ProviderLine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsDesiredResolution {
    NotEligible,
    Frozen,
    Eligible(DnsDesiredRecord),
    ConfigurationError {
        desired: Option<DnsDesiredRecord>,
        category: &'static str,
    },
}

#[allow(dead_code)] // RC9-S3 foundation; consumed by the Carrier Policy stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LineDesiredError {
    Database,
    InvalidRule,
    InvalidLine,
    InvalidValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LineRecordSnapshot {
    Absent,
    PanelOwned { value: String, record_id: String },
}

#[derive(Debug)]
pub(crate) enum LineRecordSnapshotError {
    Database,
    InvalidRule,
    InvalidLine,
    NoMatchingZone,
    Provider(DnsMgrError),
    OwnershipUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicDnsObservation {
    ExpectedPresent,
    ExpectedPresentWithOtherAnswers,
    ExpectedAbsent,
    LookupFailed,
}

/// Resolve the desired DNS record without contacting DNSMgr. This keeps
/// eligibility and target selection deterministic and independently testable.
pub(crate) async fn derive_dns_desired(
    db: &dyn Repository,
    rule_id: i64,
) -> Result<DnsDesiredResolution, crate::db::error::DbError> {
    let Some(rule) =
        <dyn Repository as RuleRepository>::find_rule_by_id(db, rule_id, &ResourceScope::All)
            .await?
    else {
        return Ok(DnsDesiredResolution::NotEligible);
    };

    if matches!(
        crate::service::relay_preference::resolve_dns_target_for_rule(
            db,
            rule.device_group_in,
            Some(rule.id),
        )
        .await?,
        crate::service::relay_preference::RelayDnsTarget::Frozen
    ) {
        return Ok(DnsDesiredResolution::Frozen);
    }

    if rule.paused || (!rule.camouflage_enabled && rule.node_transport != "nginx_sni") {
        return Ok(DnsDesiredResolution::NotEligible);
    }
    if !rule.camouflage_enabled {
        return Ok(DnsDesiredResolution::NotEligible);
    }
    if rule.node_transport != "nginx_sni" {
        return Ok(DnsDesiredResolution::ConfigurationError {
            desired: None,
            category: "CAMOUFLAGE_TRANSPORT_INVALID",
        });
    }

    let line = ProviderLine::default();
    let sni = rule.sni.as_deref().unwrap_or_default().trim();
    let expected_value =
        match GroupRepository::find_by_id(db, rule.device_group_in, &ResourceScope::All).await? {
            Some(group) if group.group_type == "in" => {
                match crate::service::relay_preference::resolve_dns_target_for_rule(
                    db,
                    rule.device_group_in,
                    Some(rule.id),
                )
                .await?
                {
                    crate::service::relay_preference::RelayDnsTarget::Resolved(ip) => ip,
                    crate::service::relay_preference::RelayDnsTarget::NotSet => {
                        group.connect_host.trim().to_string()
                    }
                    crate::service::relay_preference::RelayDnsTarget::Frozen => {
                        return Ok(DnsDesiredResolution::Frozen)
                    }
                    crate::service::relay_preference::RelayDnsTarget::Invalid(category) => {
                        return Ok(DnsDesiredResolution::ConfigurationError {
                            desired: None,
                            category,
                        })
                    }
                }
            }
            Some(_) => {
                return Ok(DnsDesiredResolution::ConfigurationError {
                    desired: None,
                    category: "INBOUND_GROUP_INVALID",
                })
            }
            None => {
                return Ok(DnsDesiredResolution::ConfigurationError {
                    desired: None,
                    category: "INBOUND_GROUP_MISSING",
                })
            }
        };

    let desired = normalize_fqdn(sni).ok().map(|fqdn| DnsDesiredRecord {
        rule_id,
        fqdn: fqdn.as_str().to_string(),
        record_type: DnsRecordType::A,
        expected_value: expected_value.clone(),
        line: line.clone(),
    });
    let Some(desired) = desired else {
        return Ok(DnsDesiredResolution::ConfigurationError {
            desired: None,
            category: "INVALID_FQDN",
        });
    };

    let Ok(ip) = expected_value.parse::<IpAddr>() else {
        return Ok(DnsDesiredResolution::ConfigurationError {
            desired: Some(desired),
            category: "INVALID_RELAY_IPV4",
        });
    };
    if !ip.is_ipv4() || ip.is_loopback() || ip.is_unspecified() {
        return Ok(DnsDesiredResolution::ConfigurationError {
            desired: Some(desired),
            category: "INVALID_RELAY_IPV4",
        });
    }

    Ok(DnsDesiredResolution::Eligible(desired))
}

fn desired_matches_sync(desired: &DnsDesiredRecord, sync: &DnsRecordSync) -> bool {
    desired.rule_id == sync.rule_id
        && desired.fqdn == sync.fqdn
        && desired.record_type.as_str() == sync.record_type
        && sync.desired_action == "UPSERT"
        && sync.expected_value.as_deref() == Some(desired.expected_value.as_str())
        && desired.line.raw_id == sync.line
        && desired.line.key == sync.line_key
}

fn desired_timestamp(now: &str) -> Option<String> {
    Some(now.to_string())
}

async fn persist_desired(
    db: &dyn Repository,
    desired: &DnsDesiredRecord,
    force_schedule: bool,
) -> Result<(), crate::db::error::DbError> {
    let now = utc_now();
    let existing = db
        .find_dns_record_sync(desired.rule_id, &desired.line.key)
        .await?;
    match existing {
        None => {
            db.insert_dns_record_sync(&NewDnsRecordSync {
                rule_id: desired.rule_id,
                fqdn: desired.fqdn.clone(),
                record_type: desired.record_type.as_str().to_string(),
                expected_value: Some(desired.expected_value.clone()),
                line: desired.line.raw_id.clone(),
                line_key: desired.line.key.clone(),
                desired_action: "UPSERT".into(),
                state: "PENDING".into(),
                ownership: "UNKNOWN".into(),
                last_error_category: None,
                next_attempt_at: desired_timestamp(&now),
                created_at: now.clone(),
                updated_at: now,
            })
            .await?;
        }
        Some(sync) if !desired_matches_sync(desired, &sync) => {
            db.update_dns_record_sync_desired(
                desired.rule_id,
                &desired.fqdn,
                desired.record_type.as_str(),
                Some(&desired.expected_value),
                &desired.line.raw_id,
                &desired.line.key,
                "UPSERT",
                "PENDING",
                "UNKNOWN",
                None,
                Some(now.as_str()),
                &now,
            )
            .await?;
        }
        Some(sync) if force_schedule || sync.state == "DISABLED" => {
            db.schedule_dns_record_sync(
                desired.rule_id,
                &desired.line.key,
                "PENDING",
                "UNKNOWN",
                None,
                Some(now.as_str()),
                &now,
            )
            .await?;
        }
        Some(_) => {}
    }
    Ok(())
}

#[allow(dead_code)] // RC9-S3 foundation; consumed by the Carrier Policy stage.
pub(crate) async fn schedule_line_upsert(
    db: &dyn Repository,
    rule_id: i64,
    raw_line_id: &str,
    expected_value: &str,
) -> Result<(), LineDesiredError> {
    let line = canonical_provider_line(raw_line_id).ok_or(LineDesiredError::InvalidLine)?;
    if line.key == DEFAULT_LINE_KEY {
        return Err(LineDesiredError::InvalidLine);
    }
    let desired = line_desired_for_rule(db, rule_id, line, Some(expected_value)).await?;
    persist_line_desired(db, &desired, "UPSERT", Some(expected_value), true).await
}

#[allow(dead_code)] // RC9-S3 foundation; consumed by the Carrier Policy stage.
pub(crate) async fn schedule_line_delete(
    db: &dyn Repository,
    rule_id: i64,
    raw_line_id: &str,
) -> Result<(), LineDesiredError> {
    let line = canonical_provider_line(raw_line_id).ok_or(LineDesiredError::InvalidLine)?;
    if line.key == DEFAULT_LINE_KEY {
        return Err(LineDesiredError::InvalidLine);
    }
    let desired = line_desired_for_rule(db, rule_id, line, None).await?;
    persist_line_desired(db, &desired, "DELETE", None, true).await
}

pub(crate) async fn schedule_transaction_line(
    db: &dyn Repository,
    rule_id: i64,
    fqdn: &str,
    raw_line_id: &str,
    action: &str,
    value: Option<&str>,
) -> Result<(), LineDesiredError> {
    let line = canonical_provider_line(raw_line_id).ok_or(LineDesiredError::InvalidLine)?;
    if line.key == DEFAULT_LINE_KEY || !matches!(action, "UPSERT" | "DELETE") {
        return Err(LineDesiredError::InvalidLine);
    }
    let fqdn = normalize_fqdn(fqdn).map_err(|_| LineDesiredError::InvalidRule)?;
    if !crate::service::relay_preference::dns_transaction_authorizes(
        db,
        rule_id,
        fqdn.as_str(),
        &line.key,
        action,
        value,
    )
    .await
    .map_err(|_| LineDesiredError::Database)?
    {
        return Err(LineDesiredError::InvalidRule);
    }
    if action == "UPSERT" {
        let value = value.ok_or(LineDesiredError::InvalidValue)?;
        let ip = value
            .parse::<Ipv4Addr>()
            .map_err(|_| LineDesiredError::InvalidValue)?;
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(LineDesiredError::InvalidValue);
        }
    } else if value.is_some() {
        return Err(LineDesiredError::InvalidValue);
    }
    let desired = DnsDesiredRecord {
        rule_id,
        fqdn: fqdn.as_str().to_string(),
        record_type: DnsRecordType::A,
        expected_value: value.unwrap_or_default().to_string(),
        line,
    };
    persist_line_desired(db, &desired, action, value, true).await
}

pub(crate) async fn inspect_line_record(
    db: &dyn Repository,
    client: &DnsMgrClient,
    rule_id: i64,
    raw_line_id: &str,
) -> Result<LineRecordSnapshot, LineRecordSnapshotError> {
    let requested =
        canonical_provider_line(raw_line_id).ok_or(LineRecordSnapshotError::InvalidLine)?;
    if requested.key == DEFAULT_LINE_KEY {
        return Err(LineRecordSnapshotError::InvalidLine);
    }
    let rule = RuleRepository::find_rule_by_id(db, rule_id, &ResourceScope::All)
        .await
        .map_err(|_| LineRecordSnapshotError::Database)?
        .filter(rule_is_dns_eligible)
        .ok_or(LineRecordSnapshotError::InvalidRule)?;
    let fqdn = normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim())
        .map_err(|_| LineRecordSnapshotError::InvalidRule)?;
    let zone = match resolve_zone(client, &fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => return Err(LineRecordSnapshotError::NoMatchingZone),
        ZoneResolution::UpstreamFailure(error) => {
            return Err(LineRecordSnapshotError::Provider(error))
        }
    };
    let detail = client
        .get_domain(zone.domain_id)
        .await
        .map_err(LineRecordSnapshotError::Provider)?;
    let line = resolve_mutation_line(&requested, &detail).unwrap_or(requested);
    let binding = db
        .find_dns_record_binding_for_rule(rule_id, fqdn.as_str(), "A", &line.key)
        .await
        .map_err(|_| LineRecordSnapshotError::Database)?;
    match discover_records(client, &zone, DnsRecordType::A, &line).await {
        RecordDiscovery::NoRecord => Ok(LineRecordSnapshot::Absent),
        RecordDiscovery::SingleMatchingRecord(record)
            if binding_matches_record(
                binding.as_ref(),
                &fqdn,
                &zone,
                DnsRecordType::A,
                &record,
            ) =>
        {
            let [value] = record.record.values.as_slice() else {
                return Err(LineRecordSnapshotError::OwnershipUnverified);
            };
            let ip = value
                .parse::<Ipv4Addr>()
                .map_err(|_| LineRecordSnapshotError::OwnershipUnverified)?;
            if ip.is_loopback() || ip.is_unspecified() {
                return Err(LineRecordSnapshotError::OwnershipUnverified);
            }
            Ok(LineRecordSnapshot::PanelOwned {
                value: ip.to_string(),
                record_id: record.record.record_id,
            })
        }
        RecordDiscovery::SingleMatchingRecord(_)
        | RecordDiscovery::MultipleMatchingRecords(_)
        | RecordDiscovery::ConflictingRecordType(_) => {
            Err(LineRecordSnapshotError::OwnershipUnverified)
        }
        RecordDiscovery::UpstreamFailure(error) => Err(LineRecordSnapshotError::Provider(error)),
    }
}

#[allow(dead_code)]
async fn line_desired_for_rule(
    db: &dyn Repository,
    rule_id: i64,
    line: ProviderLine,
    expected_value: Option<&str>,
) -> Result<DnsDesiredRecord, LineDesiredError> {
    let rule = RuleRepository::find_rule_by_id(db, rule_id, &ResourceScope::All)
        .await
        .map_err(|_| LineDesiredError::Database)?
        .filter(rule_is_dns_eligible)
        .ok_or(LineDesiredError::InvalidRule)?;
    if let Some(value) = expected_value {
        let ip = value
            .parse::<Ipv4Addr>()
            .map_err(|_| LineDesiredError::InvalidValue)?;
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(LineDesiredError::InvalidValue);
        }
    }
    let fqdn = normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim())
        .map_err(|_| LineDesiredError::InvalidRule)?;
    Ok(DnsDesiredRecord {
        rule_id,
        fqdn: fqdn.as_str().to_string(),
        record_type: DnsRecordType::A,
        expected_value: expected_value.unwrap_or_default().to_string(),
        line,
    })
}

#[allow(dead_code)]
async fn persist_line_desired(
    db: &dyn Repository,
    desired: &DnsDesiredRecord,
    desired_action: &str,
    expected_value: Option<&str>,
    force_schedule: bool,
) -> Result<(), LineDesiredError> {
    let now = utc_now();
    let existing = db
        .find_dns_record_sync(desired.rule_id, &desired.line.key)
        .await
        .map_err(|_| LineDesiredError::Database)?;
    match existing {
        None => db
            .insert_dns_record_sync(&NewDnsRecordSync {
                rule_id: desired.rule_id,
                fqdn: desired.fqdn.clone(),
                record_type: desired.record_type.as_str().into(),
                expected_value: expected_value.map(str::to_string),
                line: desired.line.raw_id.clone(),
                line_key: desired.line.key.clone(),
                desired_action: desired_action.into(),
                state: "PENDING".into(),
                ownership: "UNKNOWN".into(),
                last_error_category: None,
                next_attempt_at: Some(now.clone()),
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .map_err(|_| LineDesiredError::Database),
        Some(sync)
            if sync.fqdn != desired.fqdn
                || sync.record_type != desired.record_type.as_str()
                || sync.expected_value.as_deref() != expected_value
                || sync.line != desired.line.raw_id
                || sync.line_key != desired.line.key
                || sync.desired_action != desired_action =>
        {
            db.update_dns_record_sync_desired(
                desired.rule_id,
                &desired.fqdn,
                desired.record_type.as_str(),
                expected_value,
                &desired.line.raw_id,
                &desired.line.key,
                desired_action,
                "PENDING",
                "UNKNOWN",
                None,
                Some(&now),
                &now,
            )
            .await
            .map_err(|_| LineDesiredError::Database)
            .and_then(|updated| {
                (updated == 1)
                    .then_some(())
                    .ok_or(LineDesiredError::Database)
            })
        }
        Some(sync)
            if force_schedule || matches!(sync.state.as_str(), "NOT_ELIGIBLE" | "DISABLED") =>
        {
            db.schedule_dns_record_sync(
                desired.rule_id,
                &desired.line.key,
                "PENDING",
                "UNKNOWN",
                None,
                Some(&now),
                &now,
            )
            .await
            .map_err(|_| LineDesiredError::Database)
            .and_then(|updated| {
                (updated == 1)
                    .then_some(())
                    .ok_or(LineDesiredError::Database)
            })
        }
        Some(_) => Ok(()),
    }
}

async fn persist_resolution(
    db: &dyn Repository,
    rule_id: i64,
    resolution: DnsDesiredResolution,
    force_schedule: bool,
) -> Result<(), crate::db::error::DbError> {
    match resolution {
        DnsDesiredResolution::Frozen => {}
        DnsDesiredResolution::NotEligible => {
            for sync in db.list_dns_record_syncs_for_rule(rule_id).await? {
                if sync.line_key != DEFAULT_LINE_KEY
                    && crate::service::relay_preference::dns_transaction_authorizes(
                        db,
                        sync.rule_id,
                        &sync.fqdn,
                        &sync.line_key,
                        &sync.desired_action,
                        sync.expected_value.as_deref(),
                    )
                    .await?
                {
                    continue;
                }
                let now = utc_now();
                db.schedule_dns_record_sync(
                    rule_id,
                    &sync.line_key,
                    "NOT_ELIGIBLE",
                    "UNKNOWN",
                    Some("RULE_NOT_ELIGIBLE"),
                    None,
                    &now,
                )
                .await?;
            }
        }
        DnsDesiredResolution::Eligible(desired) => {
            persist_desired(db, &desired, force_schedule).await?;
            persist_carrier_desired(db, rule_id).await?;
        }
        DnsDesiredResolution::ConfigurationError { desired, category } => {
            if let Some(desired) = desired {
                let now = utc_now();
                let existing = db.find_dns_record_sync(rule_id, &desired.line.key).await?;
                match existing {
                    None => {
                        db.insert_dns_record_sync(&NewDnsRecordSync {
                            rule_id,
                            fqdn: desired.fqdn,
                            record_type: desired.record_type.as_str().into(),
                            expected_value: Some(desired.expected_value),
                            line: desired.line.raw_id,
                            line_key: desired.line.key,
                            desired_action: "UPSERT".into(),
                            state: "FAILED".into(),
                            ownership: "UNKNOWN".into(),
                            last_error_category: Some(category.into()),
                            next_attempt_at: None,
                            created_at: now.clone(),
                            updated_at: now,
                        })
                        .await?;
                    }
                    Some(sync) if force_schedule || sync.state != "FAILED" => {
                        db.update_dns_record_sync_observation(
                            &sync,
                            &sync.state,
                            "FAILED",
                            "UNKNOWN",
                            None,
                            sync.last_observed_at.as_deref(),
                            None,
                            Some(category),
                            0,
                            None,
                            &now,
                        )
                        .await?;
                    }
                    Some(_) => {}
                }
            }
        }
    }
    Ok(())
}

async fn persist_carrier_desired(
    db: &dyn Repository,
    rule_id: i64,
) -> Result<(), crate::db::error::DbError> {
    for desired in
        crate::service::relay_preference::carrier_line_desired_for_rule(db, rule_id).await?
    {
        let result = match desired.action {
            crate::service::relay_preference::RelayDnsAction::Upsert => {
                let Some(value) = desired.value.as_deref() else {
                    return Err(crate::db::error::DbError::Other(sqlx::Error::Protocol(
                        "carrier UPSERT desired value is missing".into(),
                    )));
                };
                project_line_desired(db, rule_id, &desired.line_id, "UPSERT", Some(value)).await
            }
            crate::service::relay_preference::RelayDnsAction::Delete => {
                project_line_desired(db, rule_id, &desired.line_id, "DELETE", None).await
            }
        };
        result.map_err(|error| {
            crate::db::error::DbError::Other(sqlx::Error::Protocol(format!(
                "carrier line desired projection failed: {error:?}"
            )))
        })?;
    }
    Ok(())
}

async fn project_line_desired(
    db: &dyn Repository,
    rule_id: i64,
    raw_line_id: &str,
    action: &str,
    value: Option<&str>,
) -> Result<(), LineDesiredError> {
    let line = canonical_provider_line(raw_line_id).ok_or(LineDesiredError::InvalidLine)?;
    let desired = line_desired_for_rule(db, rule_id, line, value).await?;
    persist_line_desired(db, &desired, action, value, false).await
}

/// Schedule an eligible rule after its DB transaction has committed. Any
/// scheduling failure is deliberately returned to the caller for logging only;
/// it must never turn a successful Rule write into a failed Rule response.
pub async fn schedule_rule(
    db: &dyn Repository,
    rule_id: i64,
) -> Result<(), crate::db::error::DbError> {
    let resolution = derive_dns_desired(db, rule_id).await?;
    if matches!(resolution, DnsDesiredResolution::Frozen) {
        return Ok(());
    }
    persist_resolution(db, rule_id, resolution, true).await?;
    let settings = db
        .get(DNSMGR_CONFIG_KEY)
        .await?
        .map(|raw| DnsMgrSettings::from_json(Some(&raw)))
        .unwrap_or_default();
    if (!settings.enabled || !settings.configured())
        && db
            .find_dns_record_sync(rule_id, DEFAULT_LINE_KEY)
            .await?
            .is_some()
    {
        let now = utc_now();
        db.schedule_dns_record_sync(
            rule_id,
            DEFAULT_LINE_KEY,
            "DISABLED",
            "UNKNOWN",
            Some("DNSMGR_DISABLED"),
            None,
            &now,
        )
        .await?;
    }
    Ok(())
}

/// Record scheduling only when an eligible DNS desired-state row exists. This
/// is deliberately separate from scheduling so internal refresh ticks never
/// create audit noise.
pub async fn audit_sync_scheduled(state: &AppState, actor_id: Option<i64>, rule_id: i64) {
    let Ok(Some(sync)) = state
        .db
        .find_dns_record_sync(rule_id, DEFAULT_LINE_KEY)
        .await
    else {
        return;
    };
    if sync.state != "PENDING" {
        return;
    }
    crate::service::audit::record(
        state,
        actor_id,
        "DNS_SYNC_SCHEDULED",
        "rule",
        rule_id,
        &format!(
            "fqdn={} record_type={} expected_value={} state={}",
            sync.fqdn,
            sync.record_type,
            sync.expected_value.as_deref().unwrap_or("<absent>"),
            sync.state,
        ),
    )
    .await;
}

pub(crate) async fn refresh_all_desired(
    db: &dyn Repository,
) -> Result<(), crate::db::error::DbError> {
    for rule in db.list_rules(&ResourceScope::All).await? {
        let resolution = derive_dns_desired(db, rule.id).await?;
        persist_resolution(db, rule.id, resolution, false).await?;
    }
    Ok(())
}

pub async fn schedule_all_eligible(db: &dyn Repository) -> Result<(), crate::db::error::DbError> {
    for rule in db.list_rules(&ResourceScope::All).await? {
        schedule_rule(db, rule.id).await?;
    }
    Ok(())
}

pub(crate) fn rule_is_dns_eligible(rule: &relay_shared::models::ForwardRule) -> bool {
    !rule.paused
        && rule.camouflage_enabled
        && rule.node_transport == "nginx_sni"
        && normalize_fqdn(rule.sni.as_deref().unwrap_or_default().trim()).is_ok()
}

pub async fn eligible_rule_ids_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<Vec<i64>, crate::db::error::DbError> {
    let mut ids: Vec<i64> = db
        .list_rules(&ResourceScope::All)
        .await?
        .into_iter()
        .filter(|rule| rule.device_group_in == group_id && rule_is_dns_eligible(rule))
        .map(|rule| rule.id)
        .collect();
    ids.sort_unstable();
    Ok(ids)
}

/// Schedule only the eligible Reality records belonging to one inbound group.
/// `eligible_rule_ids` comes from the preflight performed under the preference
/// mutation lock, so another group can never be pulled into this transaction.
pub async fn schedule_group_eligible(
    db: &dyn Repository,
    group_id: i64,
    eligible_rule_ids: &[i64],
) -> Result<(), crate::db::error::DbError> {
    let current_ids = eligible_rule_ids_for_group(db, group_id).await?;
    for rule_id in eligible_rule_ids {
        if current_ids.binary_search(rule_id).is_ok() {
            schedule_rule(db, *rule_id).await?;
        }
    }
    Ok(())
}

pub async fn disable_all_syncs(db: &dyn Repository) -> Result<u64, crate::db::error::DbError> {
    let now = utc_now();
    let mut updated = 0;
    for rule in db.list_rules(&ResourceScope::All).await? {
        if matches!(
            crate::service::relay_preference::resolve_dns_target(db, rule.device_group_in).await?,
            crate::service::relay_preference::RelayDnsTarget::Frozen
        ) {
            continue;
        }
        for sync in db.list_dns_record_syncs_for_rule(rule.id).await? {
            updated += db
                .schedule_dns_record_sync(
                    rule.id,
                    &sync.line_key,
                    "DISABLED",
                    "UNKNOWN",
                    Some("DNSMGR_DISABLED"),
                    None,
                    &now,
                )
                .await?;
        }
    }
    Ok(updated)
}

async fn resume_unfrozen_syncs_on_startup(
    db: &dyn Repository,
) -> Result<u64, crate::db::error::DbError> {
    let now = utc_now();
    let mut updated = 0;
    for rule in db.list_rules(&ResourceScope::All).await? {
        if matches!(
            crate::service::relay_preference::resolve_dns_target(db, rule.device_group_in).await?,
            crate::service::relay_preference::RelayDnsTarget::Frozen
        ) {
            continue;
        }
        for sync in db.list_dns_record_syncs_for_rule(rule.id).await? {
            let resumed_state = match sync.state.as_str() {
                "MUTATION_VERIFIED" | "PROPAGATING" => Some("PROPAGATING"),
                "PENDING" | "SYNCING" => Some("PENDING"),
                "FAILED"
                    if matches!(
                        sync.last_error_category.as_deref(),
                        Some(
                            "DNSMGR_TRANSPORT" | "DNSMGR_TIMEOUT" | "DNSMGR_TEMPORARY" | "DATABASE"
                        )
                    ) =>
                {
                    Some("PENDING")
                }
                _ => None,
            };
            if let Some(resumed_state) = resumed_state {
                updated += db
                    .schedule_dns_record_sync(
                        rule.id,
                        &sync.line_key,
                        resumed_state,
                        &sync.ownership,
                        sync.last_error_category.as_deref(),
                        Some(&now),
                        &now,
                    )
                    .await?;
            }
        }
    }
    Ok(updated)
}

fn retry_delay(attempt: i32) -> Duration {
    let exponent = attempt.saturating_sub(1).clamp(0, 8) as u32;
    let seconds = DNS_SYNC_BASE_BACKOFF_SECS
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(DNS_SYNC_MAX_BACKOFF_SECS);
    Duration::from_secs(seconds)
}

fn retry_timestamp(attempt: i32) -> String {
    let when = chrono::Utc::now() + chrono::Duration::from_std(retry_delay(attempt)).unwrap();
    when.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn is_transient_failure(failure: &EnsureRecordFailure) -> bool {
    match failure {
        EnsureRecordFailure::Upstream(error) => matches!(
            error,
            DnsMgrError::Transport(_)
                | DnsMgrError::Timeout
                | DnsMgrError::RateLimitedOrTemporarilyUnavailable
        ),
        EnsureRecordFailure::Database => true,
        EnsureRecordFailure::InvalidInput(_)
        | EnsureRecordFailure::InvalidRule
        | EnsureRecordFailure::NoMatchingZone
        | EnsureRecordFailure::ProviderLineUnavailable
        | EnsureRecordFailure::TtlOutOfRange
        | EnsureRecordFailure::PostWriteNotVerified
        | EnsureRecordFailure::OwnershipUnverified => false,
    }
}

fn public_dns_state(answers: &[Ipv4Addr], expected: Ipv4Addr) -> PublicDnsObservation {
    if answers.contains(&expected) {
        if answers.iter().any(|answer| *answer != expected) {
            PublicDnsObservation::ExpectedPresentWithOtherAnswers
        } else {
            PublicDnsObservation::ExpectedPresent
        }
    } else {
        PublicDnsObservation::ExpectedAbsent
    }
}

async fn observe_public_dns(fqdn: &str, expected: Ipv4Addr) -> PublicDnsObservation {
    let lookup = tokio::time::timeout(
        PUBLIC_DNS_TIMEOUT,
        tokio::net::lookup_host((fqdn.to_string(), 0)),
    )
    .await;
    let Ok(Ok(addresses)) = lookup else {
        return PublicDnsObservation::LookupFailed;
    };
    let answers = addresses
        .filter_map(|address: SocketAddr| match address.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    public_dns_state(&answers, expected)
}

#[allow(clippy::too_many_arguments)] // 状态转移字段与持久化 CAS 参数一一对应，保持事务语义。
async fn update_sync(
    db: &dyn Repository,
    sync: &DnsRecordSync,
    expected_state: &str,
    state: &str,
    ownership: &str,
    mutation_verified_at: Option<&str>,
    last_observed_at: Option<&str>,
    propagated_at: Option<&str>,
    error: Option<&str>,
    attempts: i32,
    next_attempt_at: Option<&str>,
) -> bool {
    match db
        .update_dns_record_sync_observation(
            sync,
            expected_state,
            state,
            ownership,
            mutation_verified_at,
            last_observed_at,
            propagated_at,
            error,
            attempts,
            next_attempt_at,
            &utc_now(),
        )
        .await
    {
        Ok(1) => true,
        Ok(_) => false,
        Err(error) => {
            tracing::error!(
                "dns reconciliation rule {} state update failed: {}",
                sync.rule_id,
                error
            );
            false
        }
    }
}

async fn observe_and_store(
    db: &dyn Repository,
    sync: &DnsRecordSync,
    expected_state: &str,
    ownership: &str,
    mutation_verified_at: Option<&str>,
    attempts: i32,
) -> Option<DnsAuditTransition> {
    let Some(expected_value) = sync.expected_value.as_deref() else {
        return None;
    };
    let Ok(expected) = expected_value.parse::<Ipv4Addr>() else {
        let updated = update_sync(
            db,
            sync,
            expected_state,
            "FAILED",
            ownership,
            mutation_verified_at,
            None,
            None,
            Some("INVALID_RELAY_IPV4"),
            attempts,
            None,
        )
        .await;
        return updated.then(|| {
            DnsAuditTransition::from_sync(
                "DNS_SYNC_FAILED",
                sync,
                ownership,
                Some("INVALID_RELAY_IPV4"),
            )
        });
    };
    let observed_at = utc_now();
    let observation = observe_public_dns(&sync.fqdn, expected).await;
    match observation {
        PublicDnsObservation::ExpectedPresent => {
            let updated = update_sync(
                db,
                sync,
                expected_state,
                "PROPAGATED",
                ownership,
                mutation_verified_at,
                Some(&observed_at),
                Some(&observed_at),
                None,
                attempts,
                None,
            )
            .await;
            updated.then(|| DnsAuditTransition::from_sync("DNS_PROPAGATED", sync, ownership, None))
        }
        PublicDnsObservation::ExpectedPresentWithOtherAnswers => {
            let updated = update_sync(
                db,
                sync,
                expected_state,
                "PROPAGATED",
                ownership,
                mutation_verified_at,
                Some(&observed_at),
                Some(&observed_at),
                Some("PUBLIC_DNS_MULTIPLE_ANSWERS"),
                attempts,
                None,
            )
            .await;
            updated.then(|| {
                DnsAuditTransition::from_sync(
                    "DNS_PROPAGATED",
                    sync,
                    ownership,
                    Some("PUBLIC_DNS_MULTIPLE_ANSWERS"),
                )
            })
        }
        PublicDnsObservation::ExpectedAbsent | PublicDnsObservation::LookupFailed => {
            // Propagation observation is read-only and may legitimately take
            // longer than the bounded mutation retry window. Keep observing at
            // the capped interval until the expected answer appears.
            let next_attempt = retry_timestamp(attempts.max(1));
            let error = match observation {
                PublicDnsObservation::ExpectedAbsent => "PUBLIC_DNS_NOT_YET_PROPAGATED",
                PublicDnsObservation::LookupFailed => "PUBLIC_DNS_LOOKUP_FAILED",
                PublicDnsObservation::ExpectedPresent
                | PublicDnsObservation::ExpectedPresentWithOtherAnswers => unreachable!(),
            };
            update_sync(
                db,
                sync,
                expected_state,
                "PROPAGATING",
                ownership,
                mutation_verified_at,
                Some(&observed_at),
                None,
                Some(error),
                attempts.saturating_add(1),
                Some(&next_attempt),
            )
            .await;
            None
        }
    }
}

async fn reconcile_one(
    db: &dyn Repository,
    sync: DnsRecordSync,
    client: &DnsMgrClient,
) -> Vec<DnsAuditTransition> {
    if sync.desired_action == "DELETE" {
        return reconcile_delete(db, sync, client).await;
    }
    let mut audits = Vec::new();
    if sync.line_key == DEFAULT_LINE_KEY
        && matches!(sync.state.as_str(), "PROPAGATING" | "MUTATION_VERIFIED")
    {
        if let Some(audit) = observe_and_store(
            db,
            &sync,
            &sync.state,
            &sync.ownership,
            sync.mutation_verified_at.as_deref(),
            sync.attempt_count,
        )
        .await
        {
            audits.push(audit);
        }
        return audits;
    }

    let attempt = sync.attempt_count.saturating_add(1);
    let in_flight_recovery_at = retry_timestamp(attempt);
    if !update_sync(
        db,
        &sync,
        &sync.state,
        "SYNCING",
        &sync.ownership,
        sync.mutation_verified_at.as_deref(),
        sync.last_observed_at.as_deref(),
        sync.propagated_at.as_deref(),
        None,
        attempt,
        Some(&in_flight_recovery_at),
    )
    .await
    {
        return audits;
    }

    let input = EnsureRecordInput {
        rule_id: sync.rule_id,
        fqdn: sync.fqdn.clone(),
        record_type: DnsRecordType::A,
        expected_value: sync.expected_value.clone().unwrap_or_default(),
        line: ProviderLine::from_provider(&sync.line, None),
    };
    match ensure_record(db, client, &input).await {
        result @ (EnsureRecordResult::AlreadyCorrect { .. }
        | EnsureRecordResult::Created { .. }
        | EnsureRecordResult::Recreated { .. }
        | EnsureRecordResult::Updated { .. }) => {
            let verified_at = utc_now();
            let mutation_state_saved = update_sync(
                db,
                &sync,
                "SYNCING",
                "MUTATION_VERIFIED",
                "PANEL",
                Some(&verified_at),
                None,
                None,
                None,
                0,
                Some(&verified_at),
            )
            .await;
            if mutation_state_saved {
                let mutation_action = result.audit_outcome();
                if mutation_action != DnsMutationAuditOutcome::NoMutation {
                    audits.push(DnsAuditTransition::from_sync(
                        mutation_action.as_str(),
                        &sync,
                        "PANEL",
                        None,
                    ));
                }
                if sync.line_key == DEFAULT_LINE_KEY {
                    if let Some(audit) = observe_and_store(
                        db,
                        &sync,
                        "MUTATION_VERIFIED",
                        "PANEL",
                        Some(&verified_at),
                        0,
                    )
                    .await
                    {
                        audits.push(audit);
                    }
                } else if update_sync(
                    db,
                    &sync,
                    "MUTATION_VERIFIED",
                    "PROPAGATED",
                    "PANEL",
                    Some(&verified_at),
                    Some(&verified_at),
                    Some(&verified_at),
                    None,
                    0,
                    None,
                )
                .await
                {
                    audits.push(DnsAuditTransition::from_sync(
                        "DNS_PROPAGATED",
                        &sync,
                        "PANEL",
                        None,
                    ));
                }
            }
        }
        EnsureRecordResult::Conflict(_) => {
            if update_sync(
                db,
                &sync,
                "SYNCING",
                "CONFLICT",
                "UNKNOWN",
                None,
                None,
                None,
                Some("DNS_CONFLICT"),
                attempt,
                None,
            )
            .await
            {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_RECORD_CONFLICT",
                    &sync,
                    "UNKNOWN",
                    Some("DNS_CONFLICT"),
                ));
            }
        }
        EnsureRecordResult::MutationOutcomeUnknown => {
            if update_sync(
                db,
                &sync,
                "SYNCING",
                "MUTATION_OUTCOME_UNKNOWN",
                "UNKNOWN",
                None,
                None,
                None,
                Some("MUTATION_UNKNOWN"),
                attempt,
                None,
            )
            .await
            {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_MUTATION_OUTCOME_UNKNOWN",
                    &sync,
                    "UNKNOWN",
                    Some("MUTATION_UNKNOWN"),
                ));
            }
        }
        EnsureRecordResult::Failed(failure) => {
            if matches!(&failure, EnsureRecordFailure::PostWriteNotVerified) {
                if update_sync(
                    db,
                    &sync,
                    "SYNCING",
                    "MUTATION_OUTCOME_UNKNOWN",
                    "UNKNOWN",
                    None,
                    None,
                    None,
                    Some("POST_WRITE_NOT_VERIFIED"),
                    attempt,
                    None,
                )
                .await
                {
                    audits.push(DnsAuditTransition::from_sync(
                        "DNS_MUTATION_OUTCOME_UNKNOWN",
                        &sync,
                        "UNKNOWN",
                        Some("POST_WRITE_NOT_VERIFIED"),
                    ));
                }
                return audits;
            }
            let transient = is_transient_failure(&failure);
            let next_attempt = if transient && attempt < DNS_SYNC_MAX_ATTEMPTS {
                Some(retry_timestamp(attempt))
            } else {
                None
            };
            let category = match &failure {
                EnsureRecordFailure::InvalidInput(_) => "INVALID_INPUT",
                EnsureRecordFailure::InvalidRule => "INVALID_RULE",
                EnsureRecordFailure::NoMatchingZone => "NO_MATCHING_ZONE",
                EnsureRecordFailure::ProviderLineUnavailable => "PROVIDER_LINE_UNAVAILABLE",
                EnsureRecordFailure::TtlOutOfRange => "TTL_OUT_OF_RANGE",
                EnsureRecordFailure::Upstream(error) => match error {
                    DnsMgrError::Transport(_) => "DNSMGR_TRANSPORT",
                    DnsMgrError::Timeout => "DNSMGR_TIMEOUT",
                    DnsMgrError::RateLimitedOrTemporarilyUnavailable => "DNSMGR_TEMPORARY",
                    _ => "DNSMGR_UPSTREAM",
                },
                EnsureRecordFailure::Database => "DATABASE",
                EnsureRecordFailure::PostWriteNotVerified => "POST_WRITE_NOT_VERIFIED",
                EnsureRecordFailure::OwnershipUnverified => "DNS_OWNERSHIP_UNVERIFIED",
            };
            let updated = update_sync(
                db,
                &sync,
                "SYNCING",
                "FAILED",
                "UNKNOWN",
                None,
                None,
                None,
                Some(category),
                attempt,
                next_attempt.as_deref(),
            )
            .await;
            if updated && next_attempt.is_none() {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_SYNC_FAILED",
                    &sync,
                    "UNKNOWN",
                    Some(category),
                ));
            }
        }
    }
    audits
}

async fn reconcile_delete(
    db: &dyn Repository,
    sync: DnsRecordSync,
    client: &DnsMgrClient,
) -> Vec<DnsAuditTransition> {
    let mut audits = Vec::new();
    let attempt = sync.attempt_count.saturating_add(1);
    let recovery_at = retry_timestamp(attempt);
    if !update_sync(
        db,
        &sync,
        &sync.state,
        "SYNCING",
        &sync.ownership,
        sync.mutation_verified_at.as_deref(),
        sync.last_observed_at.as_deref(),
        sync.propagated_at.as_deref(),
        None,
        attempt,
        Some(&recovery_at),
    )
    .await
    {
        return audits;
    }

    let input = DeleteRecordInput {
        rule_id: sync.rule_id,
        fqdn: sync.fqdn.clone(),
        record_type: DnsRecordType::A,
        line: ProviderLine::from_provider(&sync.line, None),
    };
    match ensure_record_absent(db, client, &input).await {
        DeleteRecordResult::Deleted { .. } | DeleteRecordResult::AlreadyAbsent => {
            let verified_at = utc_now();
            if update_sync(
                db,
                &sync,
                "SYNCING",
                "PROPAGATED",
                "PANEL",
                Some(&verified_at),
                Some(&verified_at),
                Some(&verified_at),
                None,
                0,
                None,
            )
            .await
            {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_RECORD_DELETED",
                    &sync,
                    "PANEL",
                    None,
                ));
            }
        }
        DeleteRecordResult::MutationOutcomeUnknown => {
            if update_sync(
                db,
                &sync,
                "SYNCING",
                "MUTATION_OUTCOME_UNKNOWN",
                "UNKNOWN",
                None,
                None,
                None,
                Some("MUTATION_UNKNOWN"),
                attempt,
                None,
            )
            .await
            {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_MUTATION_OUTCOME_UNKNOWN",
                    &sync,
                    "UNKNOWN",
                    Some("MUTATION_UNKNOWN"),
                ));
            }
        }
        DeleteRecordResult::Failed(failure) => {
            let transient = is_transient_failure(&failure);
            let next_attempt =
                (transient && attempt < DNS_SYNC_MAX_ATTEMPTS).then(|| retry_timestamp(attempt));
            let category = match &failure {
                EnsureRecordFailure::InvalidInput(_) => "INVALID_INPUT",
                EnsureRecordFailure::InvalidRule => "INVALID_RULE",
                EnsureRecordFailure::NoMatchingZone => "NO_MATCHING_ZONE",
                EnsureRecordFailure::ProviderLineUnavailable => "PROVIDER_LINE_UNAVAILABLE",
                EnsureRecordFailure::TtlOutOfRange => "TTL_OUT_OF_RANGE",
                EnsureRecordFailure::Upstream(error) => match error {
                    DnsMgrError::Transport(_) => "DNSMGR_TRANSPORT",
                    DnsMgrError::Timeout => "DNSMGR_TIMEOUT",
                    DnsMgrError::RateLimitedOrTemporarilyUnavailable => "DNSMGR_TEMPORARY",
                    _ => "DNSMGR_UPSTREAM",
                },
                EnsureRecordFailure::Database => "DATABASE",
                EnsureRecordFailure::PostWriteNotVerified => "POST_WRITE_NOT_VERIFIED",
                EnsureRecordFailure::OwnershipUnverified => "DNS_OWNERSHIP_UNVERIFIED",
            };
            if update_sync(
                db,
                &sync,
                "SYNCING",
                "FAILED",
                "UNKNOWN",
                None,
                None,
                None,
                Some(category),
                attempt,
                next_attempt.as_deref(),
            )
            .await
                && next_attempt.is_none()
            {
                audits.push(DnsAuditTransition::from_sync(
                    "DNS_SYNC_FAILED",
                    &sync,
                    "UNKNOWN",
                    Some(category),
                ));
            }
        }
    }
    audits
}

pub(crate) async fn load_client(db: &dyn Repository) -> Result<Option<DnsMgrClient>, DnsMgrError> {
    let settings = db
        .get(DNSMGR_CONFIG_KEY)
        .await
        .map_err(|error| DnsMgrError::Transport(error.to_string()))?
        .map(|raw| DnsMgrSettings::from_json(Some(&raw)))
        .unwrap_or_default();
    if !settings.enabled || !settings.configured() {
        return Ok(None);
    }
    DnsMgrClientConfig::new(&settings.base_url, settings.uid, settings.api_key)
        .and_then(DnsMgrClient::new)
        .map(Some)
}

async fn reconciliation_tick(state: &AppState) {
    crate::service::acme_dns01::cleanup_expired(state.db.as_ref()).await;
    // Fail unsafe switching transactions before refresh/due processing so a
    // vanished target cannot receive one more automatic DNS mutation.
    crate::service::relay_preference::finalize_switching_preferences(state).await;
    let settings = match state.db.get(DNSMGR_CONFIG_KEY).await {
        Ok(raw) => DnsMgrSettings::from_json(raw.as_deref()),
        Err(error) => {
            tracing::error!("dns reconciliation: settings read failed: {}", error);
            return;
        }
    };
    if !settings.enabled || !settings.configured() {
        if let Err(error) = disable_all_syncs(state.db.as_ref()).await {
            tracing::error!("dns reconciliation: disabling sync state failed: {}", error);
        }
        crate::service::relay_preference::finalize_switching_preferences(state).await;
        return;
    }
    if let Err(error) = refresh_all_desired(state.db.as_ref()).await {
        tracing::error!(
            "dns reconciliation: desired-state refresh failed: {}",
            error
        );
    }
    let client = match load_client(state.db.as_ref()).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            crate::service::relay_preference::finalize_switching_preferences(state).await;
            return;
        }
        Err(error) => {
            tracing::error!("dns reconciliation: client configuration failed: {}", error);
            crate::service::relay_preference::finalize_switching_preferences(state).await;
            return;
        }
    };
    let now = utc_now();
    let due = match list_executable_due_syncs(state.db.as_ref(), &now).await {
        Ok(due) => due,
        Err(error) => {
            tracing::error!("dns reconciliation: due-state query failed: {}", error);
            crate::service::relay_preference::finalize_switching_preferences(state).await;
            return;
        }
    };
    // A single worker serializes provider writes. This is intentionally a
    // bounded concurrency of one because DNSMgr has no idempotency key.
    for sync in due {
        for audit in reconcile_one(state.db.as_ref(), sync, &client).await {
            audit.record(state).await;
        }
    }
    crate::service::relay_preference::finalize_switching_preferences(state).await;
}

async fn list_executable_due_syncs(
    db: &dyn Repository,
    now: &str,
) -> Result<Vec<DnsRecordSync>, crate::db::error::DbError> {
    // Read up to the persisted identity count so frozen lines cannot consume
    // the bounded executable slots now that a Rule may own multiple syncs.
    let due_limit = db.count_dns_record_syncs().await?.max(DNS_SYNC_MAX_BATCH);
    let due = db.list_due_dns_record_syncs(now, due_limit).await?;
    let mut executable = Vec::with_capacity(DNS_SYNC_MAX_BATCH as usize);

    for sync in due {
        if matches!(
            derive_dns_desired(db, sync.rule_id).await,
            Ok(DnsDesiredResolution::Frozen)
        ) {
            continue;
        }
        executable.push(sync);
        if executable.len() == DNS_SYNC_MAX_BATCH as usize {
            break;
        }
    }

    Ok(executable)
}

/// Start the Panel-only DNS reconciliation worker. It never touches Relay
/// runtime state and exits only when the Panel process exits.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        if let Err(error) = resume_unfrozen_syncs_on_startup(state.db.as_ref()).await {
            tracing::error!("dns reconciliation: startup recovery failed: {}", error);
        }
        let mut ticker = tokio::time::interval(DNS_SYNC_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            "dns reconciliation worker started (tick {}s)",
            DNS_SYNC_TICK.as_secs()
        );
        loop {
            ticker.tick().await;
            reconciliation_tick(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{DnsRecordBindingRepository, DnsRecordSyncRepository, KvsRepository};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::integrations::dnsmgr::{DnsMgrClientConfig, DnsMgrRecordLine};
    use axum::body::Body;
    use axum::extract::{Form, State};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashMap;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn public_projection_never_serializes_api_key() {
        let settings = DnsMgrSettings {
            enabled: true,
            base_url: "http://127.0.0.1:8080".into(),
            uid: 7,
            api_key: "private-api-key".into(),
        };
        let serialized = serde_json::to_string(&DnsMgrSettingsPublic::from(&settings)).unwrap();
        assert!(!serialized.contains(&settings.api_key));
        assert!(serialized.contains("has_api_key"));
        assert!(!format!("{settings:?}").contains(&settings.api_key));
    }

    #[test]
    fn fqdn_normalization_preserves_root_and_leftmost_wildcard_semantics() {
        assert_eq!(
            normalize_fqdn("OP1.Example.COM.").unwrap().as_str(),
            "op1.example.com"
        );
        assert_eq!(
            normalize_fqdn("example.com").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            normalize_fqdn("*.Example.com").unwrap().as_str(),
            "*.example.com"
        );

        for invalid in [
            "",
            ".",
            "bad..example.com",
            "-bad.example.com",
            "bad_.example.com",
            "a.*.example.com",
            " example.com",
        ] {
            assert_eq!(normalize_fqdn(invalid), Err(DnsDiscoveryError::InvalidFqdn));
        }
    }

    #[test]
    fn zone_resolution_uses_longest_configured_suffix_and_root_host() {
        let domains = vec![
            domain(10, "example.com"),
            domain(20, "sub.example.com"),
            domain(30, "example.co.uk"),
        ];

        let nested =
            resolve_zone_from_inventory(&normalize_fqdn("x.sub.example.com").unwrap(), &domains)
                .unwrap();
        assert_eq!(nested.domain_id, 20);
        assert_eq!(nested.zone_name, "sub.example.com");
        assert_eq!(nested.host, "x");

        let root =
            resolve_zone_from_inventory(&normalize_fqdn("example.com").unwrap(), &domains).unwrap();
        assert_eq!(root.host, "@");

        let public_suffix =
            resolve_zone_from_inventory(&normalize_fqdn("a.example.co.uk").unwrap(), &domains)
                .unwrap();
        assert_eq!(public_suffix.zone_name, "example.co.uk");
        assert_eq!(public_suffix.host, "a");

        let wildcard =
            resolve_zone_from_inventory(&normalize_fqdn("*.example.com").unwrap(), &domains)
                .unwrap();
        assert_eq!(wildcard.host, "*");
        assert!(
            resolve_zone_from_inventory(&normalize_fqdn("outside.test").unwrap(), &domains)
                .is_none()
        );
        assert!(
            resolve_zone_from_inventory(&normalize_fqdn("example.com").unwrap(), &[]).is_none()
        );
    }

    #[test]
    fn provider_default_lines_normalize_without_losing_raw_identity() {
        for raw in ["", "0", "default", "Default", "default_view"] {
            let line = ProviderLine::from_provider(raw, Some("General"));
            assert_eq!(line.key, "default");
            assert_eq!(line.raw_id, raw);
        }
        let custom = ProviderLine::from_provider("line-42", Some("Premium"));
        assert_eq!(custom.key, "dnsmgr:line-42");
        assert_eq!(custom.raw_id, "line-42");
        assert_eq!(custom.name.as_deref(), Some("Premium"));
    }

    #[test]
    fn provider_default_view_resolves_as_the_requested_default_line() {
        let detail = DnsMgrDomainDetail {
            domain: domain(7, "example.com"),
            min_ttl: Some(600),
            record_lines: vec![DnsMgrRecordLine {
                id: "default_view".into(),
                name: "Global default".into(),
                parent: None,
            }],
        };
        let resolved = resolve_mutation_line(&ProviderLine::default(), &detail).unwrap();
        assert_eq!(resolved.key, "default");
        assert_eq!(resolved.raw_id, "default_view");
    }

    #[test]
    fn record_value_matching_requires_exactly_one_expected_address() {
        let expected = "192.0.2.10".parse().unwrap();
        assert!(record_value_matches(&["192.0.2.10".into()], expected));
        assert!(!record_value_matches(&["192.0.2.11".into()], expected));
        assert!(!record_value_matches(
            &["192.0.2.1".into(), "192.0.2.10".into()],
            expected
        ));
    }

    #[test]
    fn record_discovery_distinguishes_zero_single_multiple_and_cname_conflict() {
        let zone = zone();
        let line = ProviderLine::default();
        assert_eq!(
            classify_records(&zone, DnsRecordType::A, &line, Vec::new()),
            RecordDiscovery::NoRecord
        );

        let one = record("r1", "A", "192.0.2.10", "default");
        assert!(matches!(
            classify_records(&zone, DnsRecordType::A, &line, vec![one.clone()]),
            RecordDiscovery::SingleMatchingRecord(_)
        ));
        match classify_records(
            &zone,
            DnsRecordType::A,
            &line,
            vec![one, record("r2", "A", "192.0.2.11", "0")],
        ) {
            RecordDiscovery::MultipleMatchingRecords(records) => assert_eq!(records.len(), 2),
            other => panic!("unexpected result: {other:?}"),
        }
        match classify_records(
            &zone,
            DnsRecordType::A,
            &line,
            vec![record("c1", "CNAME", "target.example.net", "Default")],
        ) {
            RecordDiscovery::ConflictingRecordType(records) => assert_eq!(records.len(), 1),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn record_discovery_reads_every_provider_array_page() {
        let router = Router::new().route(
            "/api/record/data/7",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                let offset = form
                    .get("offset")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or_default();
                let count = if offset == 0 {
                    100
                } else if offset == 100 {
                    1
                } else {
                    0
                };
                let rows = (0..count)
                    .map(|index| {
                        json!({
                            "RecordId": format!("r-{}", offset + index),
                            "Domain": "example.com", "Name": "op1", "Type": "A",
                            "Value": "192.0.2.10", "Line": "default", "TTL": 300,
                            "Status": "1", "MX": null, "Weight": null, "Remark": null,
                            "UpdateTime": null
                        })
                    })
                    .collect::<Vec<_>>();
                Json(json!(rows))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client =
            DnsMgrClient::new(DnsMgrClientConfig::new(&base_url, 7, "key").unwrap()).unwrap();

        let result =
            discover_records(&client, &zone(), DnsRecordType::A, &ProviderLine::default()).await;
        handle.abort();
        match result {
            RecordDiscovery::MultipleMatchingRecords(records) => assert_eq!(records.len(), 101),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn zone_resolution_reads_complete_authoritative_inventory() {
        let router = Router::new().route(
            "/api/domain",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                let offset = form
                    .get("offset")
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or_default();
                let row = if offset == 0 {
                    json!({"id": 10, "name": "example.com", "type": "provider"})
                } else {
                    json!({"id": 20, "name": "sub.example.com", "type": "provider"})
                };
                Json(json!({"total": 2, "rows": [row]}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client =
            DnsMgrClient::new(DnsMgrClientConfig::new(&base_url, 7, "key").unwrap()).unwrap();

        let result = resolve_zone(&client, &normalize_fqdn("x.sub.example.com").unwrap()).await;
        handle.abort();
        match result {
            ZoneResolution::ZoneResolved(zone) => {
                assert_eq!(zone.domain_id, 20);
                assert_eq!(zone.host, "x");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn record_value_family_is_validated_before_future_mutation() {
        assert!(validate_ip_family(DnsRecordType::A, "192.0.2.10").is_ok());
        assert!(validate_ip_family(DnsRecordType::Aaaa, "2001:db8::10").is_ok());
        assert!(validate_ip_family(DnsRecordType::A, "2001:db8::10").is_err());
        assert!(validate_ip_family(DnsRecordType::Aaaa, "192.0.2.10").is_err());
        assert_eq!(
            validate_ip_family(DnsRecordType::Cname, "target.example.com"),
            Err(DnsDiscoveryError::UnsupportedRecordType(
                DnsRecordType::Cname
            ))
        );
    }

    #[test]
    fn binding_identity_matching_remains_exact_bookkeeping() {
        let fqdn = normalize_fqdn("op1.example.com").unwrap();
        let zone = zone();
        let discovered = DiscoveredRecord {
            line: ProviderLine::default(),
            record: record("r1", "A", "192.0.2.10", "default"),
        };
        assert!(!binding_matches_record(
            None,
            &fqdn,
            &zone,
            DnsRecordType::A,
            &discovered
        ));

        let exact_binding = binding("r1");
        assert!(binding_matches_record(
            Some(&exact_binding),
            &fqdn,
            &zone,
            DnsRecordType::A,
            &discovered
        ));
        let wrong_record = binding("external-record");
        assert!(!binding_matches_record(
            Some(&wrong_record),
            &fqdn,
            &zone,
            DnsRecordType::A,
            &discovered
        ));
    }

    #[tokio::test]
    async fn ensure_create_is_verified_bound_and_then_a_true_noop() {
        let db = ensure_db().await;
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;

        let first = ensure_record(
            &db,
            &mock.client,
            &ensure_input(DnsRecordType::A, "192.0.2.10"),
        )
        .await;
        assert!(matches!(first, EnsureRecordResult::Created { .. }));
        assert_eq!(
            first.audit_outcome(),
            DnsMutationAuditOutcome::DnsRecordCreated
        );
        assert_eq!(first.audit_outcome().as_str(), "DNS_RECORD_CREATED");
        assert_eq!(mock.state.add_attempts.load(Ordering::SeqCst), 1);
        let form = mock.state.last_add_form.lock().unwrap().clone().unwrap();
        assert_eq!(form.get("line").map(String::as_str), Some("default_view"));
        assert_eq!(form.get("ttl").map(String::as_str), Some("1200"));

        let binding = db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.state, "BOUND");
        assert_eq!(binding.record_id, "created-1");
        db.update_dns_record_binding_observation(
            binding.id,
            "BOUND",
            Some("2000-01-01 00:00:00"),
            None,
            "2000-01-01 00:00:00",
        )
        .await
        .unwrap();
        let second = ensure_record(
            &db,
            &mock.client,
            &ensure_input(DnsRecordType::A, "192.0.2.10"),
        )
        .await;
        assert_eq!(
            second,
            EnsureRecordResult::AlreadyCorrect {
                record_id: "created-1".into()
            }
        );
        assert_eq!(mock.state.add_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(mock.state.update_attempts.load(Ordering::SeqCst), 0);
        let after = db
            .find_dns_record_binding_by_record(7, "created-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.updated_at, "2000-01-01 00:00:00",
            "no-op must not churn binding"
        );
    }

    #[tokio::test]
    async fn dynamic_line_upsert_uses_exact_raw_id_and_converges_by_provider_readback() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_line_upsert(&db, 100, "Dianxin_Shandong", "192.0.2.20")
            .await
            .unwrap();
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;

        let audits = reconcile_one(
            &db,
            db.find_dns_record_sync(100, "dnsmgr:Dianxin_Shandong")
                .await
                .unwrap()
                .unwrap(),
            &mock.client,
        )
        .await;
        let sync = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin_Shandong")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sync.state, "PROPAGATED");
        assert_eq!(sync.expected_value.as_deref(), Some("192.0.2.20"));
        assert_eq!(mock.state.add_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.state
                .last_add_form
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .get("line")
                .map(String::as_str),
            Some("Dianxin_Shandong")
        );
        assert!(audits.iter().any(|audit| audit.action == "DNS_PROPAGATED"));
        assert!(db
            .find_dns_record_binding_for_rule(
                100,
                "op1.example.com",
                "A",
                "dnsmgr:Dianxin_Shandong"
            )
            .await
            .unwrap()
            .is_some());

        let unavailable_db = ensure_db().await;
        configure_eligible_rule(&unavailable_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_upsert(&unavailable_db, 100, "Dianxin", "192.0.2.20")
            .await
            .unwrap();
        let unavailable =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        unavailable
            .state
            .record_lines
            .lock()
            .unwrap()
            .retain(|line| line.id != "Dianxin");
        assert_eq!(
            ensure_record(
                &unavailable_db,
                &unavailable.client,
                &EnsureRecordInput {
                    rule_id: 100,
                    fqdn: "op1.example.com".into(),
                    record_type: DnsRecordType::A,
                    expected_value: "192.0.2.20".into(),
                    line: ProviderLine::from_provider("Dianxin", None),
                },
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::ProviderLineUnavailable)
        );
        assert_eq!(unavailable.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn carrier_preflight_snapshots_only_absent_or_exact_panel_owned_records() {
        let absent_db = ensure_db().await;
        configure_eligible_rule(&absent_db, "op1.example.com", "192.0.2.10").await;
        let absent =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        assert_eq!(
            inspect_line_record(&absent_db, &absent.client, 100, "Dianxin")
                .await
                .unwrap(),
            LineRecordSnapshot::Absent
        );
        assert_eq!(absent.state.total_mutations(), 0);

        let owned_db = ensure_db().await;
        configure_eligible_rule(&owned_db, "op1.example.com", "192.0.2.10").await;
        insert_line_binding(&owned_db, "Dianxin", "owned", "192.0.2.20").await;
        let owned = spawn_ensure_mock(
            vec![record("owned", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            inspect_line_record(&owned_db, &owned.client, 100, "Dianxin")
                .await
                .unwrap(),
            LineRecordSnapshot::PanelOwned {
                value: "192.0.2.20".into(),
                record_id: "owned".into(),
            }
        );
        assert_eq!(owned.state.total_mutations(), 0);

        let external_db = ensure_db().await;
        configure_eligible_rule(&external_db, "op1.example.com", "192.0.2.10").await;
        let external = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.30", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert!(matches!(
            inspect_line_record(&external_db, &external.client, 100, "Dianxin").await,
            Err(LineRecordSnapshotError::OwnershipUnverified)
        ));
        assert_eq!(external.state.total_mutations(), 0);

        let duplicate_db = ensure_db().await;
        configure_eligible_rule(&duplicate_db, "op1.example.com", "192.0.2.10").await;
        insert_line_binding(&duplicate_db, "Dianxin", "owned", "192.0.2.20").await;
        let duplicate = spawn_ensure_mock(
            vec![
                record("owned", "A", "192.0.2.20", "Dianxin"),
                record("duplicate", "A", "192.0.2.20", "Dianxin"),
            ],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert!(matches!(
            inspect_line_record(&duplicate_db, &duplicate.client, 100, "Dianxin").await,
            Err(LineRecordSnapshotError::OwnershipUnverified)
        ));
        assert_eq!(duplicate.state.total_mutations(), 0);
    }

    async fn carrier_projection_db() -> SqliteRepository {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        db.set(
            "relay_preference:10",
            &serde_json::json!({
                "preferred_node_id": null,
                "pending_node_id": null,
                "state": "idle",
                "started_at": null,
                "last_error": null,
                "carrier_policy": {
                    "bindings": [{
                        "line_id": "Dianxin",
                        "mode": "follow_default",
                        "node_id": null
                    }]
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
        schedule_rule(&db, 100).await.unwrap();
        db
    }

    async fn set_carrier_sync_state(
        db: &SqliteRepository,
        state: &str,
        ownership: &str,
        error: Option<&str>,
        attempts: i32,
        next_attempt_at: Option<&str>,
    ) {
        let sync = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        db.update_dns_record_sync_observation(
            &sync,
            &sync.state,
            state,
            ownership,
            sync.mutation_verified_at.as_deref(),
            sync.last_observed_at.as_deref(),
            sync.propagated_at.as_deref(),
            error,
            attempts,
            next_attempt_at,
            "2026-08-31 12:00:00",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn carrier_background_refresh_preserves_identical_terminal_and_stable_syncs() {
        for (state, ownership, error, attempts, next_attempt_at) in [
            ("PROPAGATED", "PANEL", None, 0, None),
            (
                "MUTATION_OUTCOME_UNKNOWN",
                "UNKNOWN",
                Some("MUTATION_UNKNOWN"),
                1,
                None,
            ),
            (
                "FAILED",
                "UNKNOWN",
                Some("DNSMGR_TEMPORARY"),
                3,
                Some("2099-01-01 00:00:00"),
            ),
        ] {
            let db = carrier_projection_db().await;
            set_carrier_sync_state(&db, state, ownership, error, attempts, next_attempt_at).await;
            let before = db
                .find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap();
            refresh_all_desired(&db).await.unwrap();
            refresh_all_desired(&db).await.unwrap();
            let after = db
                .find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after, before, "background refresh changed {state}");
        }

        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        db.insert_dns_record_sync(&NewDnsRecordSync {
            rule_id: 100,
            fqdn: "op1.example.com".into(),
            record_type: "A".into(),
            expected_value: None,
            line: "Dianxin".into(),
            line_key: "dnsmgr:Dianxin".into(),
            desired_action: "DELETE".into(),
            state: "PROPAGATED".into(),
            ownership: "PANEL".into(),
            last_error_category: None,
            next_attempt_at: None,
            created_at: "2026-08-31 00:00:00".into(),
            updated_at: "2026-08-31 00:00:00".into(),
        })
        .await
        .unwrap();
        let before = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        refresh_all_desired(&db).await.unwrap();
        assert_eq!(
            db.find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap(),
            before,
            "DELETE tombstone must remain stable"
        );
    }

    #[tokio::test]
    async fn carrier_background_refresh_reactivates_only_lifecycle_states() {
        for state in ["NOT_ELIGIBLE", "DISABLED"] {
            let db = carrier_projection_db().await;
            set_carrier_sync_state(&db, state, "UNKNOWN", Some("LIFECYCLE"), 4, None).await;
            refresh_all_desired(&db).await.unwrap();
            let after = db
                .find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.state, "PENDING", "{state} did not reactivate");
            assert_eq!(after.attempt_count, 0);
            assert!(after.next_attempt_at.is_some());
        }
    }

    #[tokio::test]
    async fn ambiguous_carrier_write_is_not_retried_by_the_next_refresh_tick() {
        let db = carrier_projection_db().await;
        let mock = spawn_ensure_mock(
            Vec::new(),
            MutationBehavior::TransportWithoutApply,
            MutationBehavior::Apply,
        )
        .await;
        let sync = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        reconcile_one(&db, sync, &mock.client).await;
        assert_eq!(mock.state.total_mutations(), 1);
        assert_eq!(
            db.find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap()
                .state,
            "MUTATION_OUTCOME_UNKNOWN"
        );

        refresh_all_desired(&db).await.unwrap();
        let due = list_executable_due_syncs(&db, &utc_now()).await.unwrap();
        for sync in due
            .into_iter()
            .filter(|sync| sync.line_key == "dnsmgr:Dianxin")
        {
            reconcile_one(&db, sync, &mock.client).await;
        }
        assert_eq!(mock.state.total_mutations(), 1);
    }

    #[tokio::test]
    async fn dynamic_line_update_and_ambiguous_update_are_isolated_and_single_attempt() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_line_upsert(&db, 100, "Dianxin", "192.0.2.20")
            .await
            .unwrap();
        insert_line_binding(&db, "Dianxin", "line-record", "192.0.2.19").await;
        let updated = spawn_ensure_mock(
            vec![record("line-record", "A", "192.0.2.19", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        let result = ensure_record(
            &db,
            &updated.client,
            &EnsureRecordInput {
                rule_id: 100,
                fqdn: "op1.example.com".into(),
                record_type: DnsRecordType::A,
                expected_value: "192.0.2.20".into(),
                line: ProviderLine::from_provider("Dianxin", None),
            },
        )
        .await;
        assert_eq!(
            result,
            EnsureRecordResult::Updated {
                record_id: "line-record".into()
            }
        );
        assert_eq!(updated.state.update_attempts.load(Ordering::SeqCst), 1);
        assert!(db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .is_none());

        let ambiguous_db = ensure_db().await;
        configure_eligible_rule(&ambiguous_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_upsert(&ambiguous_db, 100, "Dianxin", "192.0.2.20")
            .await
            .unwrap();
        insert_line_binding(&ambiguous_db, "Dianxin", "line-record", "192.0.2.19").await;
        let ambiguous = spawn_ensure_mock(
            vec![record("line-record", "A", "192.0.2.19", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::TransportAfterApply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &ambiguous_db,
                &ambiguous.client,
                &EnsureRecordInput {
                    rule_id: 100,
                    fqdn: "op1.example.com".into(),
                    record_type: DnsRecordType::A,
                    expected_value: "192.0.2.20".into(),
                    line: ProviderLine::from_provider("Dianxin", None),
                },
            )
            .await,
            EnsureRecordResult::MutationOutcomeUnknown
        );
        assert_eq!(ambiguous.state.update_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            ambiguous.state.records.lock().unwrap()[0].values,
            ["192.0.2.20"]
        );

        let external_db = ensure_db().await;
        configure_eligible_rule(&external_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_upsert(&external_db, 100, "Dianxin", "192.0.2.20")
            .await
            .unwrap();
        let external = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.19", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &external_db,
                &external.client,
                &EnsureRecordInput {
                    rule_id: 100,
                    fqdn: "op1.example.com".into(),
                    record_type: DnsRecordType::A,
                    expected_value: "192.0.2.20".into(),
                    line: ProviderLine::from_provider("Dianxin", None),
                },
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        );
        assert_eq!(external.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn dynamic_line_failure_does_not_overwrite_default_status_or_retry() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_rule(&db, 100).await.unwrap();
        let default_before = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        schedule_line_upsert(&db, 100, "Dianxin", "192.0.2.20")
            .await
            .unwrap();
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        mock.state
            .record_lines
            .lock()
            .unwrap()
            .retain(|line| line.id != "Dianxin");

        reconcile_one(
            &db,
            db.find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap(),
            &mock.client,
        )
        .await;
        let carrier = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        let default = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(carrier.state, "FAILED");
        assert_eq!(
            carrier.last_error_category.as_deref(),
            Some("PROVIDER_LINE_UNAVAILABLE")
        );
        assert_eq!(carrier.next_attempt_at, None);
        assert_eq!(default, default_before);
    }

    #[tokio::test]
    async fn line_delete_removes_only_exact_owned_record_and_accepts_verified_absence() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&db, 100, "Dianxin").await.unwrap();
        insert_line_binding(&db, "Dianxin", "owned", "192.0.2.20").await;
        let mock = spawn_ensure_mock(
            vec![
                record("owned", "A", "192.0.2.20", "Dianxin"),
                record("other-line", "A", "192.0.2.30", "Dianxin_Shandong"),
            ],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;

        assert_eq!(
            ensure_record_absent(&db, &mock.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::Deleted {
                record_id: "owned".into()
            }
        );
        assert_eq!(mock.state.delete_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.state
                .records
                .lock()
                .unwrap()
                .iter()
                .map(|record| record.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["other-line"]
        );
        assert_eq!(
            ensure_record_absent(&db, &mock.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::AlreadyAbsent
        );
        assert_eq!(mock.state.delete_attempts.load(Ordering::SeqCst), 1);

        let stale_catalog_db = ensure_db().await;
        configure_eligible_rule(&stale_catalog_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&stale_catalog_db, 100, "Dianxin")
            .await
            .unwrap();
        insert_line_binding(&stale_catalog_db, "Dianxin", "stale-owned", "192.0.2.20").await;
        let stale_catalog = spawn_ensure_mock(
            vec![record("stale-owned", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        stale_catalog
            .state
            .record_lines
            .lock()
            .unwrap()
            .retain(|line| line.id != "Dianxin");
        assert_eq!(
            ensure_record_absent(
                &stale_catalog_db,
                &stale_catalog.client,
                &delete_input("Dianxin")
            )
            .await,
            DeleteRecordResult::Deleted {
                record_id: "stale-owned".into()
            }
        );
        assert_eq!(
            stale_catalog.state.delete_attempts.load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn line_delete_refuses_external_or_ambiguous_ownership_without_mutation() {
        let external_db = ensure_db().await;
        configure_eligible_rule(&external_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&external_db, 100, "Dianxin")
            .await
            .unwrap();
        let external = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record_absent(&external_db, &external.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        );
        assert_eq!(external.state.delete_attempts.load(Ordering::SeqCst), 0);

        let ambiguous_db = ensure_db().await;
        configure_eligible_rule(&ambiguous_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&ambiguous_db, 100, "Dianxin")
            .await
            .unwrap();
        insert_line_binding(&ambiguous_db, "Dianxin", "owned", "192.0.2.20").await;
        let ambiguous = spawn_ensure_mock(
            vec![
                record("owned", "A", "192.0.2.20", "Dianxin"),
                record("duplicate", "A", "192.0.2.21", "Dianxin"),
            ],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record_absent(&ambiguous_db, &ambiguous.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        );
        assert_eq!(ambiguous.state.delete_attempts.load(Ordering::SeqCst), 0);

        let drift_db = ensure_db().await;
        configure_eligible_rule(&drift_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&drift_db, 100, "Dianxin")
            .await
            .unwrap();
        insert_line_binding(&drift_db, "Dianxin", "old-owned", "192.0.2.20").await;
        let drift = spawn_ensure_mock(
            vec![record("replacement-external", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record_absent(&drift_db, &drift.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)
        );
        assert_eq!(drift.state.delete_attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_line_delete_uses_readback_and_is_never_blindly_retried() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&db, 100, "Dianxin").await.unwrap();
        insert_line_binding(&db, "Dianxin", "owned", "192.0.2.20").await;
        let mock = spawn_ensure_mock(
            vec![record("owned", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        *mock.state.delete_behavior.lock().unwrap() = MutationBehavior::TransportAfterApply;

        assert_eq!(
            ensure_record_absent(&db, &mock.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::Deleted {
                record_id: "owned".into()
            }
        );
        assert_eq!(mock.state.delete_attempts.load(Ordering::SeqCst), 1);

        let unknown_db = ensure_db().await;
        configure_eligible_rule(&unknown_db, "op1.example.com", "192.0.2.10").await;
        schedule_line_delete(&unknown_db, 100, "Dianxin")
            .await
            .unwrap();
        insert_line_binding(&unknown_db, "Dianxin", "still-owned", "192.0.2.20").await;
        let unknown = spawn_ensure_mock(
            vec![record("still-owned", "A", "192.0.2.20", "Dianxin")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        *unknown.state.delete_behavior.lock().unwrap() = MutationBehavior::TransportWithoutApply;
        assert_eq!(
            ensure_record_absent(&unknown_db, &unknown.client, &delete_input("Dianxin")).await,
            DeleteRecordResult::MutationOutcomeUnknown
        );
        assert_eq!(unknown.state.delete_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(unknown.state.records.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn eligible_rule_manages_existing_records_without_an_ownership_gate() {
        let correct_db = ensure_db().await;
        let correct = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.10", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &correct_db,
                &correct.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::AlreadyCorrect {
                record_id: "external".into()
            }
        );
        assert!(correct_db
            .find_dns_record_binding_by_record(7, "external")
            .await
            .unwrap()
            .is_some());
        assert_eq!(correct.state.total_mutations(), 0);

        let wrong_db = ensure_db().await;
        let wrong = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.99", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &wrong_db,
                &wrong.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Updated {
                record_id: "external".into()
            }
        );
        assert_eq!(wrong.state.update_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            wrong.state.records.lock().unwrap()[0].values,
            ["192.0.2.10"]
        );
        assert!(wrong_db
            .find_dns_record_binding_by_record(7, "external")
            .await
            .unwrap()
            .is_some());

        let historical_db = ensure_db().await;
        historical_db
            .insert_dns_record_binding(&NewDnsRecordBinding {
                rule_id: None,
                fqdn: "op1.example.com".into(),
                zone_id: 7,
                zone_name: "example.com".into(),
                host: "op1".into(),
                record_type: "A".into(),
                line: "0".into(),
                line_key: "default".into(),
                record_id: "historical".into(),
                desired_value: "192.0.2.99".into(),
                state: "BOUND".into(),
                last_observed_at: None,
                created_at: utc_now(),
            })
            .await
            .unwrap();
        let historical = spawn_ensure_mock(
            vec![record("historical", "A", "192.0.2.99", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &historical_db,
                &historical.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Updated {
                record_id: "historical".into()
            }
        );
        assert_eq!(historical.state.update_attempts.load(Ordering::SeqCst), 1);

        let multiple_db = ensure_db().await;
        let multiple = spawn_ensure_mock(
            vec![
                record("external-1", "A", "192.0.2.10", "0"),
                record("external-2", "A", "192.0.2.99", "0"),
            ],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &multiple_db,
                &multiple.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Updated {
                record_id: "external-1".into()
            }
        );
        assert_eq!(multiple.state.update_attempts.load(Ordering::SeqCst), 1);
        assert!(multiple
            .state
            .records
            .lock()
            .unwrap()
            .iter()
            .all(|record| record.values == ["192.0.2.10"]));
    }

    #[tokio::test]
    async fn ensure_treats_singleton_array_as_correct_and_converges_multi_value_records() {
        let expected = "192.0.2.10";
        let correct_db = ensure_db().await;
        let correct = spawn_ensure_mock(
            vec![record("correct", "A", expected, "default_view")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &correct_db,
                &correct.client,
                &ensure_input(DnsRecordType::A, expected),
            )
            .await,
            EnsureRecordResult::AlreadyCorrect {
                record_id: "correct".into()
            }
        );
        assert_eq!(correct.state.total_mutations(), 0);

        let multi_db = ensure_db().await;
        let mut multi = record("multi", "A", "192.0.2.1", "default_view");
        multi.values.push(expected.into());
        let multi = spawn_ensure_mock(
            vec![multi],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &multi_db,
                &multi.client,
                &ensure_input(DnsRecordType::A, expected),
            )
            .await,
            EnsureRecordResult::Updated {
                record_id: "multi".into()
            }
        );
        assert_eq!(multi.state.update_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(multi.state.records.lock().unwrap()[0].values, [expected]);
    }

    #[tokio::test]
    async fn ensure_converges_every_matching_provider_identity() {
        let db = ensure_db().await;
        insert_binding(&db, "owned", "192.0.2.1").await;
        let mock = spawn_ensure_mock(
            vec![
                record("owned", "A", "192.0.2.1", "0"),
                record("external", "A", "192.0.2.200", "0"),
            ],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;

        assert_eq!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10")
            )
            .await,
            EnsureRecordResult::Updated {
                record_id: "owned".into()
            }
        );
        assert_eq!(mock.state.update_attempts.load(Ordering::SeqCst), 2);
        let form = mock.state.last_update_form.lock().unwrap().clone().unwrap();
        assert_eq!(form.get("recordid").map(String::as_str), Some("external"));
        let records = mock.state.records.lock().unwrap();
        assert_eq!(
            records
                .iter()
                .find(|record| record.record_id == "owned")
                .unwrap()
                .values,
            ["192.0.2.10"]
        );
        assert_eq!(
            records
                .iter()
                .find(|record| record.record_id == "external")
                .unwrap()
                .values,
            ["192.0.2.10"]
        );
    }

    #[tokio::test]
    async fn ensure_conflicts_on_cname_but_rebinds_stale_metadata() {
        let cname_db = ensure_db().await;
        let cname = spawn_ensure_mock(
            vec![record("cname", "CNAME", "target.example.net", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &cname_db,
                &cname.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10")
            )
            .await,
            EnsureRecordResult::Conflict(EnsureRecordConflict::Cname)
        );
        assert_eq!(cname.state.total_mutations(), 0);

        let stale_db = ensure_db().await;
        insert_binding(&stale_db, "missing-owned", "192.0.2.1").await;
        let stale = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.10", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &stale_db,
                &stale.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10")
            )
            .await,
            EnsureRecordResult::AlreadyCorrect {
                record_id: "external".into()
            }
        );
        let binding = stale_db
            .find_dns_record_binding_by_record(7, "external")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.state, "BOUND");
        assert_eq!(stale.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn ensure_recreates_a_missing_bound_record_and_replaces_stale_identity() {
        let db = ensure_db().await;
        insert_binding(&db, "missing-owned", "192.0.2.1").await;
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;

        assert_eq!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10")
            )
            .await,
            EnsureRecordResult::Recreated {
                old_record_id: "missing-owned".into(),
                record_id: "created-1".into()
            }
        );
        assert!(db
            .find_dns_record_binding_by_record(7, "missing-owned")
            .await
            .unwrap()
            .is_none());
        let replacement = db
            .find_dns_record_binding_by_record(7, "created-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replacement.state, "BOUND");
        assert_eq!(replacement.desired_value, "192.0.2.10");
        assert_eq!(replacement.line, "default_view");
    }

    #[tokio::test]
    async fn ensure_requires_post_write_match_for_create_and_update() {
        let create_db = ensure_db().await;
        let create = spawn_ensure_mock(
            Vec::new(),
            MutationBehavior::AcceptWithoutApply,
            MutationBehavior::Apply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &create_db,
                &create.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified)
        );
        assert!(create_db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .is_none());

        let update_db = ensure_db().await;
        insert_binding(&update_db, "owned", "192.0.2.1").await;
        let update = spawn_ensure_mock(
            vec![record("owned", "A", "192.0.2.1", "0")],
            MutationBehavior::Apply,
            MutationBehavior::AcceptWithoutApply,
        )
        .await;
        assert_eq!(
            ensure_record(
                &update_db,
                &update.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified)
        );
        let binding = update_db
            .find_dns_record_binding_by_record(7, "owned")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.state, "ERROR");
    }

    #[tokio::test]
    async fn ambiguous_create_is_read_once_never_retried_or_claimed() {
        let db = ensure_db().await;
        let mock = spawn_ensure_mock(
            Vec::new(),
            MutationBehavior::TransportAfterApply,
            MutationBehavior::Apply,
        )
        .await;

        assert_eq!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::A, "192.0.2.10")
            )
            .await,
            EnsureRecordResult::MutationOutcomeUnknown
        );
        assert_eq!(mock.state.add_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(mock.state.list_attempts.load(Ordering::SeqCst), 2);
        assert!(db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .is_none());
        assert_eq!(mock.state.records.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn automatic_authority_is_limited_to_the_rule_derived_a_record() {
        let db = ensure_db().await;
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        assert!(matches!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::Aaaa, "2001:db8::10"),
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::InvalidRule)
        ));
        assert_eq!(mock.state.total_mutations(), 0);

        let before = mock.state.total_mutations();
        assert!(matches!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::A, "2001:db8::10"),
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::InvalidInput(_))
        ));
        assert!(matches!(
            ensure_record(
                &db,
                &mock.client,
                &ensure_input(DnsRecordType::Aaaa, "192.0.2.10"),
            )
            .await,
            EnsureRecordResult::Failed(EnsureRecordFailure::InvalidInput(_))
        ));
        assert_eq!(mock.state.total_mutations(), before);
    }

    #[derive(Clone, Copy)]
    enum MutationBehavior {
        Apply,
        AcceptWithoutApply,
        TransportAfterApply,
        TransportWithoutApply,
    }

    struct MockDnsState {
        records: Mutex<Vec<DnsMgrRecord>>,
        record_lines: Mutex<Vec<DnsMgrRecordLine>>,
        add_behavior: MutationBehavior,
        update_behavior: MutationBehavior,
        delete_behavior: Mutex<MutationBehavior>,
        add_attempts: AtomicUsize,
        update_attempts: AtomicUsize,
        delete_attempts: AtomicUsize,
        list_attempts: AtomicUsize,
        last_add_form: Mutex<Option<HashMap<String, String>>>,
        last_update_form: Mutex<Option<HashMap<String, String>>>,
    }

    impl MockDnsState {
        fn total_mutations(&self) -> usize {
            self.add_attempts.load(Ordering::SeqCst)
                + self.update_attempts.load(Ordering::SeqCst)
                + self.delete_attempts.load(Ordering::SeqCst)
        }
    }

    struct EnsureMock {
        client: DnsMgrClient,
        state: Arc<MockDnsState>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for EnsureMock {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_ensure_mock(
        records: Vec<DnsMgrRecord>,
        add_behavior: MutationBehavior,
        update_behavior: MutationBehavior,
    ) -> EnsureMock {
        let state = Arc::new(MockDnsState {
            records: Mutex::new(records),
            record_lines: Mutex::new(vec![
                DnsMgrRecordLine {
                    id: "default_view".into(),
                    name: "Global default".into(),
                    parent: None,
                },
                DnsMgrRecordLine {
                    id: "Dianxin".into(),
                    name: "电信".into(),
                    parent: None,
                },
                DnsMgrRecordLine {
                    id: "Dianxin_Shandong".into(),
                    name: "电信_山东".into(),
                    parent: Some("Dianxin".into()),
                },
            ]),
            add_behavior,
            update_behavior,
            delete_behavior: Mutex::new(MutationBehavior::Apply),
            add_attempts: AtomicUsize::new(0),
            update_attempts: AtomicUsize::new(0),
            delete_attempts: AtomicUsize::new(0),
            list_attempts: AtomicUsize::new(0),
            last_add_form: Mutex::new(None),
            last_update_form: Mutex::new(None),
        });
        let router = Router::new()
            .route("/api/domain", post(mock_domains))
            .route("/api/domain/7", post(mock_domain_detail))
            .route("/api/record/data/7", post(mock_records))
            .route("/api/record/add/7", post(mock_add_record))
            .route("/api/record/update/7", post(mock_update_record))
            .route("/api/record/delete/7", post(mock_delete_record))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client =
            DnsMgrClient::new(DnsMgrClientConfig::new(&base_url, 7, "key").unwrap()).unwrap();
        EnsureMock {
            client,
            state,
            handle,
        }
    }

    async fn mock_domains() -> Json<serde_json::Value> {
        Json(json!({
            "total": 1,
            "rows": [{"id": 7, "name": "example.com", "type": "provider"}]
        }))
    }

    async fn mock_domain_detail(State(state): State<Arc<MockDnsState>>) -> Json<serde_json::Value> {
        let record_lines = state
            .record_lines
            .lock()
            .unwrap()
            .iter()
            .map(|line| json!({"id": line.id, "name": line.name, "parent": line.parent}))
            .collect::<Vec<_>>();
        Json(json!({
            "code": 0,
            "data": {
                "id": 7,
                "name": "example.com",
                "type": "provider",
                "minTTL": 1200,
                "recordLine": record_lines
            }
        }))
    }

    async fn mock_records(State(state): State<Arc<MockDnsState>>) -> Json<serde_json::Value> {
        state.list_attempts.fetch_add(1, Ordering::SeqCst);
        let rows = state
            .records
            .lock()
            .unwrap()
            .iter()
            .map(record_json)
            .collect::<Vec<_>>();
        Json(json!({"total": rows.len(), "rows": rows}))
    }

    async fn mock_add_record(
        State(state): State<Arc<MockDnsState>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        let attempt = state.add_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        *state.last_add_form.lock().unwrap() = Some(form.clone());
        if matches!(
            state.add_behavior,
            MutationBehavior::Apply | MutationBehavior::TransportAfterApply
        ) {
            state
                .records
                .lock()
                .unwrap()
                .push(record_from_form(&format!("created-{attempt}"), &form));
        }
        mutation_response(state.add_behavior)
    }

    async fn mock_update_record(
        State(state): State<Arc<MockDnsState>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        state.update_attempts.fetch_add(1, Ordering::SeqCst);
        *state.last_update_form.lock().unwrap() = Some(form.clone());
        if matches!(
            state.update_behavior,
            MutationBehavior::Apply | MutationBehavior::TransportAfterApply
        ) {
            let record_id = form.get("recordid").unwrap();
            if let Some(record) = state
                .records
                .lock()
                .unwrap()
                .iter_mut()
                .find(|record| &record.record_id == record_id)
            {
                *record = record_from_form(record_id, &form);
            }
        }
        mutation_response(state.update_behavior)
    }

    async fn mock_delete_record(
        State(state): State<Arc<MockDnsState>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Response {
        state.delete_attempts.fetch_add(1, Ordering::SeqCst);
        let behavior = *state.delete_behavior.lock().unwrap();
        if matches!(
            behavior,
            MutationBehavior::Apply | MutationBehavior::TransportAfterApply
        ) {
            let record_id = form.get("recordid").unwrap();
            state
                .records
                .lock()
                .unwrap()
                .retain(|record| &record.record_id != record_id);
        }
        mutation_response(behavior)
    }

    fn mutation_response(behavior: MutationBehavior) -> Response {
        if matches!(
            behavior,
            MutationBehavior::TransportAfterApply | MutationBehavior::TransportWithoutApply
        ) {
            let stream = futures_util::stream::once(async {
                Err::<String, io::Error>(io::Error::other("injected response body failure"))
            });
            return Response::new(Body::from_stream(stream));
        }
        Json(json!({"code": 0, "msg": "accepted"})).into_response()
    }

    fn record_from_form(record_id: &str, form: &HashMap<String, String>) -> DnsMgrRecord {
        record(
            record_id,
            form.get("type").unwrap(),
            form.get("value").unwrap(),
            form.get("line").unwrap(),
        )
    }

    fn record_json(record: &DnsMgrRecord) -> serde_json::Value {
        json!({
            "RecordId": record.record_id,
            "Domain": record.domain,
            "Name": record.host,
            "Type": record.record_type,
            "Value": record.values,
            "Line": record.line,
            "LineName": record.line_name,
            "TTL": record.ttl,
            "Status": record.status,
            "MX": record.priority,
            "Weight": record.weight,
            "Remark": record.remark,
            "UpdateTime": record.updated_at
        })
    }

    #[test]
    fn public_dns_observation_accepts_expected_ip_with_other_answers() {
        assert_eq!(
            public_dns_state(
                &["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()],
                "192.0.2.10".parse().unwrap(),
            ),
            PublicDnsObservation::ExpectedPresentWithOtherAnswers
        );
        assert_eq!(
            public_dns_state(
                &["192.0.2.11".parse().unwrap()],
                "192.0.2.10".parse().unwrap(),
            ),
            PublicDnsObservation::ExpectedAbsent
        );
    }

    #[test]
    fn dns_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(retry_delay(1), Duration::from_secs(5));
        assert_eq!(retry_delay(2), Duration::from_secs(10));
        assert_eq!(retry_delay(6), Duration::from_secs(160));
        assert_eq!(retry_delay(20), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn desired_state_targets_only_camouflage_rules_and_group_connect_host() {
        let db = ensure_db().await;
        GroupRepository::update_group_fields(
            &db,
            10,
            &ResourceScope::All,
            None,
            None,
            Some("192.0.2.10"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            Some("nginx_sni"),
            Some("nginx_sni"),
            Some("nginx_sni"),
            None,
            None,
            Some(Some("op1.example.com")),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        match derive_dns_desired(&db, 100).await.unwrap() {
            DnsDesiredResolution::Eligible(desired) => {
                assert_eq!(desired.fqdn, "op1.example.com");
                assert_eq!(desired.record_type, DnsRecordType::A);
                assert_eq!(desired.expected_value, "192.0.2.10");
            }
            other => panic!("unexpected desired state: {other:?}"),
        }

        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            derive_dns_desired(&db, 100).await.unwrap(),
            DnsDesiredResolution::NotEligible
        );

        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            Some("raw"),
            Some("raw"),
            Some("raw"),
            None,
            None,
            None,
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            derive_dns_desired(&db, 100).await.unwrap(),
            DnsDesiredResolution::ConfigurationError {
                category: "CAMOUFLAGE_TRANSPORT_INVALID",
                ..
            }
        ));

        GroupRepository::update_group_fields(
            &db,
            10,
            &ResourceScope::All,
            None,
            None,
            Some("2001:db8::10"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            Some("nginx_sni"),
            Some("nginx_sni"),
            Some("nginx_sni"),
            None,
            None,
            None,
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            derive_dns_desired(&db, 100).await.unwrap(),
            DnsDesiredResolution::ConfigurationError {
                category: "INVALID_RELAY_IPV4",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn desired_state_prefers_pending_then_preferred_then_legacy_connect_host() {
        use crate::service::relay_preference::{
            RelayPreferencePhase, RelayPreferenceState, RELAY_PREFERENCE_KEY_PREFIX,
        };

        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        let desired_value = |resolution: DnsDesiredResolution| match resolution {
            DnsDesiredResolution::Eligible(desired) => desired.expected_value,
            other => panic!("unexpected desired state: {other:?}"),
        };
        assert_eq!(
            desired_value(derive_dns_desired(&db, 100).await.unwrap()),
            "192.0.2.10"
        );

        db.set("node_status:10:node-a", r#"{"public_ipv4":"192.0.2.20"}"#)
            .await
            .unwrap();
        db.set("node_status:10:node-b", r#"{"public_ipv4":"192.0.2.30"}"#)
            .await
            .unwrap();
        let key = format!("{RELAY_PREFERENCE_KEY_PREFIX}10");
        db.set(
            &key,
            &serde_json::to_string(&RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                ..RelayPreferenceState::default()
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            desired_value(derive_dns_desired(&db, 100).await.unwrap()),
            "192.0.2.20"
        );
        db.set("node_status:10:node-a", r#"{"public_ipv4":"192.0.2.21"}"#)
            .await
            .unwrap();
        assert_eq!(
            desired_value(derive_dns_desired(&db, 100).await.unwrap()),
            "192.0.2.21",
            "preferred IP must be read from current node telemetry"
        );
        db.set("node_status:10:node-a", r#"{"public_ipv4":"192.0.2.20"}"#)
            .await
            .unwrap();

        db.set(
            &key,
            &serde_json::to_string(&RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                pending_node_id: Some("node-b".into()),
                state: RelayPreferencePhase::Switching,
                started_at: Some("2026-08-29T00:00:00Z".into()),
                ..RelayPreferenceState::default()
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            desired_value(derive_dns_desired(&db, 100).await.unwrap()),
            "192.0.2.30"
        );
        schedule_rule(&db, 100).await.unwrap();
        let pending_b = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending_b.expected_value.as_deref(), Some("192.0.2.30"));

        db.set(
            &key,
            &serde_json::to_string(&RelayPreferenceState {
                preferred_node_id: Some("node-a".into()),
                pending_node_id: Some("node-b".into()),
                state: RelayPreferencePhase::Failed,
                started_at: Some("2026-08-29T00:00:00Z".into()),
                last_error: Some("DNS_RECORD_CONFLICT".into()),
                ..RelayPreferenceState::default()
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            derive_dns_desired(&db, 100).await.unwrap(),
            DnsDesiredResolution::Frozen
        );

        refresh_all_desired(&db).await.unwrap();
        schedule_all_eligible(&db).await.unwrap();
        disable_all_syncs(&db).await.unwrap();
        resume_unfrozen_syncs_on_startup(&db).await.unwrap();
        assert_eq!(
            db.find_dns_record_sync(100, DEFAULT_LINE_KEY)
                .await
                .unwrap()
                .unwrap(),
            pending_b,
            "failed Relay transactions must freeze desired value and sync state"
        );

        db.set("node_status:10:node-a", r#"{"public_ipv4":"192.0.2.21"}"#)
            .await
            .unwrap();
        assert_eq!(
            derive_dns_desired(&db, 100).await.unwrap(),
            DnsDesiredResolution::Frozen,
            "preferred telemetry changes must not thaw a failed transaction"
        );
    }

    #[tokio::test]
    async fn frozen_due_syncs_do_not_starve_executable_work() {
        let db = due_queue_db(DNS_SYNC_MAX_BATCH, 1).await;
        let frozen_before = frozen_sync_rows(&db, DNS_SYNC_MAX_BATCH).await;

        let executable = list_executable_due_syncs(&db, "2026-08-30 00:00:00")
            .await
            .unwrap();

        assert_eq!(
            executable
                .iter()
                .map(|sync| sync.rule_id)
                .collect::<Vec<_>>(),
            vec![1000],
            "a full leading batch of frozen rows must not starve later work"
        );
        assert_eq!(
            frozen_sync_rows(&db, DNS_SYNC_MAX_BATCH).await,
            frozen_before,
            "filtering frozen rows must not change their state or diagnostics"
        );
    }

    #[tokio::test]
    async fn executable_due_syncs_remain_bounded_after_frozen_filtering() {
        let db = due_queue_db(DNS_SYNC_MAX_BATCH - 1, DNS_SYNC_MAX_BATCH + 1).await;

        let executable = list_executable_due_syncs(&db, "2026-08-30 00:00:00")
            .await
            .unwrap();

        assert_eq!(executable.len(), DNS_SYNC_MAX_BATCH as usize);
        assert_eq!(executable.first().unwrap().rule_id, 1000);
        assert_eq!(executable.last().unwrap().rule_id, 1015);
        assert!(executable.iter().all(|sync| sync.rule_id >= 1000));
    }

    #[tokio::test]
    async fn scheduling_is_persisted_and_rule_edit_replaces_only_desired_state() {
        let db = ensure_db().await;
        db.set(
            DNSMGR_CONFIG_KEY,
            r#"{"enabled":true,"base_url":"http://127.0.0.1:9","uid":7,"api_key":"test-key"}"#,
        )
        .await
        .unwrap();
        GroupRepository::update_group_fields(
            &db,
            10,
            &ResourceScope::All,
            None,
            None,
            Some("192.0.2.10"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            Some("nginx_sni"),
            Some("nginx_sni"),
            Some("nginx_sni"),
            None,
            None,
            Some(Some("op1.example.com")),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        schedule_rule(&db, 100).await.unwrap();
        let first = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.state, "PENDING");
        assert_eq!(first.expected_value.as_deref(), Some("192.0.2.10"));

        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Some("op2.example.com")),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        schedule_rule(&db, 100).await.unwrap();
        let edited = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edited.fqdn, "op2.example.com");
        assert_eq!(edited.state, "PENDING");
        assert_eq!(edited.attempt_count, 0);
    }

    #[tokio::test]
    async fn ensure_rejects_a_hostname_not_authorized_by_the_eligible_rule() {
        let db = ensure_db().await;
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        let mut input = ensure_input(DnsRecordType::A, "192.0.2.10");
        input.fqdn = "www.example.com".into();

        assert_eq!(
            ensure_record(&db, &mock.client, &input).await,
            EnsureRecordResult::Failed(EnsureRecordFailure::InvalidRule)
        );
        assert_eq!(mock.state.list_attempts.load(Ordering::SeqCst), 0);
        assert_eq!(mock.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn connect_host_change_reschedules_and_updates_an_existing_sni_record() {
        let db = ensure_db().await;
        db.set(
            DNSMGR_CONFIG_KEY,
            r#"{"enabled":true,"base_url":"http://127.0.0.1:9","uid":7,"api_key":"test-key"}"#,
        )
        .await
        .unwrap();
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.5").await;
        schedule_rule(&db, 100).await.unwrap();
        assert_eq!(
            sync_row(&db).await.expected_value.as_deref(),
            Some("192.0.2.5")
        );

        GroupRepository::update_group_fields(
            &db,
            10,
            &ResourceScope::All,
            None,
            None,
            Some("192.0.2.10"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        schedule_all_eligible(&db).await.unwrap();
        let scheduled = sync_row(&db).await;
        assert_eq!(scheduled.expected_value.as_deref(), Some("192.0.2.10"));
        assert_eq!(scheduled.state, "PENDING");

        let mock = spawn_ensure_mock(
            vec![record("manual", "A", "192.0.2.5", "default_view")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        let audits = reconcile_one(&db, scheduled, &mock.client).await;
        assert_eq!(mock.state.update_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(mock.state.records.lock().unwrap()[0].values, ["192.0.2.10"]);
        assert!(audits
            .iter()
            .any(|audit| audit.action == "DNS_RECORD_UPDATED"));
        assert!(db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn making_a_rule_ineligible_does_not_delete_provider_metadata() {
        let db = ensure_db().await;
        db.set(
            DNSMGR_CONFIG_KEY,
            r#"{"enabled":true,"base_url":"http://127.0.0.1:9","uid":7,"api_key":"test-key"}"#,
        )
        .await
        .unwrap();
        insert_binding(&db, "manual", "192.0.2.10").await;
        insert_sync(&db).await;
        RuleRepository::update_rule_fields(
            &db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        schedule_rule(&db, 100).await.unwrap();
        assert_eq!(sync_row(&db).await.state, "NOT_ELIGIBLE");
        assert!(db
            .find_dns_record_binding_by_record(7, "manual")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn disabled_integration_leaves_eligible_work_disabled_and_not_due() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_rule(&db, 100).await.unwrap();
        let sync = db
            .find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sync.state, "DISABLED");
        assert_eq!(sync.last_error_category.as_deref(), Some("DNSMGR_DISABLED"));
        assert!(db
            .list_due_dns_record_syncs(&utc_now(), DNS_SYNC_MAX_BATCH)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn reconciliation_creates_or_manages_rule_authorized_records_without_blind_retry() {
        let created_db = ensure_db().await;
        configure_eligible_rule(&created_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&created_db).await;
        let created =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        let created_audits =
            reconcile_one(&created_db, sync_row(&created_db).await, &created.client).await;
        let created_state = sync_row(&created_db).await;
        assert_eq!(created_state.state, "PROPAGATING");
        assert_eq!(created_state.ownership, "PANEL");
        assert!(created_state.mutation_verified_at.is_some());
        assert_eq!(created.state.add_attempts.load(Ordering::SeqCst), 1);
        assert!(created_audits
            .iter()
            .any(|audit| audit.action == "DNS_RECORD_CREATED"));

        let external_db = ensure_db().await;
        configure_eligible_rule(&external_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&external_db).await;
        let external = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.10", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        let external_audits =
            reconcile_one(&external_db, sync_row(&external_db).await, &external.client).await;
        let external_state = sync_row(&external_db).await;
        assert_eq!(external_state.ownership, "PANEL");
        assert!(external_db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .is_some());
        assert_eq!(external.state.total_mutations(), 0);
        assert!(external_audits
            .iter()
            .all(|audit| audit.action != "DNS_RECORD_CREATED"));

        let conflict_db = ensure_db().await;
        configure_eligible_rule(&conflict_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&conflict_db).await;
        let now = utc_now();
        conflict_db
            .schedule_dns_record_sync(
                100,
                DEFAULT_LINE_KEY,
                "PENDING",
                "EXTERNAL",
                None,
                Some(&now),
                &now,
            )
            .await
            .unwrap();
        let conflict = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.99", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        let conflict_audits =
            reconcile_one(&conflict_db, sync_row(&conflict_db).await, &conflict.client).await;
        let conflict_state = sync_row(&conflict_db).await;
        assert_eq!(conflict_state.state, "PROPAGATING");
        assert_eq!(conflict_state.ownership, "PANEL");
        assert_eq!(conflict.state.update_attempts.load(Ordering::SeqCst), 1);
        assert!(conflict_audits
            .iter()
            .any(|audit| audit.action == "DNS_RECORD_UPDATED"));

        let unknown_db = ensure_db().await;
        configure_eligible_rule(&unknown_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&unknown_db).await;
        let unknown = spawn_ensure_mock(
            Vec::new(),
            MutationBehavior::TransportAfterApply,
            MutationBehavior::Apply,
        )
        .await;
        let unknown_audits =
            reconcile_one(&unknown_db, sync_row(&unknown_db).await, &unknown.client).await;
        let unknown_state = sync_row(&unknown_db).await;
        assert_eq!(unknown_state.state, "MUTATION_OUTCOME_UNKNOWN");
        assert_eq!(unknown_state.next_attempt_at, None);
        assert_eq!(unknown.state.add_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(unknown_audits[0].action, "DNS_MUTATION_OUTCOME_UNKNOWN");

        let unverified_db = ensure_db().await;
        configure_eligible_rule(&unverified_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&unverified_db).await;
        let unverified = spawn_ensure_mock(
            Vec::new(),
            MutationBehavior::AcceptWithoutApply,
            MutationBehavior::Apply,
        )
        .await;
        let unverified_audits = reconcile_one(
            &unverified_db,
            sync_row(&unverified_db).await,
            &unverified.client,
        )
        .await;
        let unverified_state = sync_row(&unverified_db).await;
        assert_eq!(unverified_state.state, "MUTATION_OUTCOME_UNKNOWN");
        assert_eq!(
            unverified_state.last_error_category.as_deref(),
            Some("POST_WRITE_NOT_VERIFIED")
        );
        assert_eq!(unverified_state.next_attempt_at, None);
        assert_eq!(unverified.state.add_attempts.load(Ordering::SeqCst), 1);
        assert!(unverified_db
            .list_due_dns_record_syncs(&utc_now(), DNS_SYNC_MAX_BATCH)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(unverified_audits[0].action, "DNS_MUTATION_OUTCOME_UNKNOWN");
    }

    #[tokio::test]
    async fn reconciliation_updates_owned_records_and_recognizes_owned_noops() {
        let updated_db = ensure_db().await;
        configure_eligible_rule(&updated_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&updated_db).await;
        insert_binding(&updated_db, "owned", "192.0.2.99").await;
        let updated = spawn_ensure_mock(
            vec![record("owned", "A", "192.0.2.99", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        reconcile_one(&updated_db, sync_row(&updated_db).await, &updated.client).await;
        let updated_state = sync_row(&updated_db).await;
        assert_eq!(updated_state.ownership, "PANEL");
        assert!(updated_state.mutation_verified_at.is_some());
        assert_eq!(updated.state.update_attempts.load(Ordering::SeqCst), 1);
        let updated_binding = updated_db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_binding.desired_value, "192.0.2.10");

        let noop_db = ensure_db().await;
        configure_eligible_rule(&noop_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&noop_db).await;
        insert_binding(&noop_db, "owned", "192.0.2.10").await;
        let noop = spawn_ensure_mock(
            vec![record("owned", "A", "192.0.2.10", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        reconcile_one(&noop_db, sync_row(&noop_db).await, &noop.client).await;
        let noop_state = sync_row(&noop_db).await;
        assert_eq!(noop_state.ownership, "PANEL");
        assert!(noop_state.mutation_verified_at.is_some());
        assert_eq!(noop.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn stale_worker_cannot_overwrite_edited_desired_state_or_mutate_dns() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&db).await;
        let stale = sync_row(&db).await;
        let now = utc_now();
        db.update_dns_record_sync_desired(
            100,
            "op2.example.com",
            "A",
            Some("192.0.2.11"),
            "default",
            "default",
            "UPSERT",
            "PENDING",
            "UNKNOWN",
            None,
            Some(&now),
            &now,
        )
        .await
        .unwrap();
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;

        reconcile_one(&db, stale, &mock.client).await;

        let current = sync_row(&db).await;
        assert_eq!(current.fqdn, "op2.example.com");
        assert_eq!(current.expected_value.as_deref(), Some("192.0.2.11"));
        assert_eq!(current.state, "PENDING");
        assert_eq!(mock.state.total_mutations(), 0);

        let disabled_db = ensure_db().await;
        configure_eligible_rule(&disabled_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&disabled_db).await;
        let stale_before_disable = sync_row(&disabled_db).await;
        disable_all_syncs(&disabled_db).await.unwrap();
        let disabled_mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;

        reconcile_one(&disabled_db, stale_before_disable, &disabled_mock.client).await;

        let disabled = sync_row(&disabled_db).await;
        assert_eq!(disabled.state, "DISABLED");
        assert_eq!(disabled_mock.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn propagation_observation_continues_after_mutation_retry_limit() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "localhost", "192.0.2.10").await;
        insert_sync(&db).await;
        let now = utc_now();
        db.update_dns_record_sync_desired(
            100,
            "localhost",
            "A",
            Some("192.0.2.10"),
            "default",
            "default",
            "UPSERT",
            "PROPAGATING",
            "PANEL",
            None,
            Some(&now),
            &now,
        )
        .await
        .unwrap();
        let sync = sync_row(&db).await;
        let audit = observe_and_store(
            &db,
            &sync,
            "PROPAGATING",
            "PANEL",
            Some(&now),
            DNS_SYNC_MAX_ATTEMPTS,
        )
        .await;
        assert_eq!(audit, None, "propagation polling must not emit audit spam");
        let observed = sync_row(&db).await;
        assert_eq!(observed.state, "PROPAGATING");
        assert_eq!(observed.attempt_count, DNS_SYNC_MAX_ATTEMPTS + 1);
        assert!(observed.next_attempt_at.is_some());
    }

    #[tokio::test]
    async fn transient_upstream_failure_is_backed_off_without_affecting_rule_state() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&db).await;
        let router = Router::new().route(
            "/api/domain",
            post(|| async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "unavailable") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client =
            DnsMgrClient::new(DnsMgrClientConfig::new(&base_url, 7, "key").unwrap()).unwrap();

        reconcile_one(&db, sync_row(&db).await, &client).await;
        handle.abort();
        let state = sync_row(&db).await;
        assert_eq!(state.state, "FAILED");
        assert_eq!(
            state.last_error_category.as_deref(),
            Some("DNSMGR_TEMPORARY")
        );
        assert_eq!(state.attempt_count, 1);
        assert!(state.next_attempt_at.is_some());
        assert!(db
            .find_rule_by_id(100, &ResourceScope::All)
            .await
            .unwrap()
            .is_some());
    }

    async fn configure_eligible_rule(db: &SqliteRepository, sni: &str, relay_ip: &str) {
        GroupRepository::update_group_fields(
            db,
            10,
            &ResourceScope::All,
            None,
            None,
            Some(relay_ip),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        RuleRepository::update_rule_fields(
            db,
            100,
            &ResourceScope::All,
            None,
            None,
            None,
            Some("nginx_sni"),
            Some("nginx_sni"),
            Some("nginx_sni"),
            None,
            None,
            Some(Some(sni)),
            Some(true),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }

    async fn insert_sync(db: &SqliteRepository) {
        db.insert_dns_record_sync(&NewDnsRecordSync {
            rule_id: 100,
            fqdn: "op1.example.com".into(),
            record_type: "A".into(),
            expected_value: Some("192.0.2.10".into()),
            line: "default".into(),
            line_key: "default".into(),
            desired_action: "UPSERT".into(),
            state: "PENDING".into(),
            ownership: "UNKNOWN".into(),
            last_error_category: None,
            next_attempt_at: Some(utc_now()),
            created_at: utc_now(),
            updated_at: utc_now(),
        })
        .await
        .unwrap();
    }

    async fn sync_row(db: &SqliteRepository) -> DnsRecordSync {
        db.find_dns_record_sync(100, DEFAULT_LINE_KEY)
            .await
            .unwrap()
            .unwrap()
    }

    async fn due_queue_db(frozen_count: i64, executable_count: i64) -> SqliteRepository {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'frozen-group', 'in', 'frozen-token', 1, '192.0.2.10'), \
                    (20, 'active-group', 'in', 'active-token', 1, '192.0.2.40')",
        )
        .execute(&pool)
        .await
        .unwrap();

        for offset in 0..frozen_count {
            sqlx::query(
                "INSERT INTO forward_rules \
                 (id, name, uid, listen_port, device_group_in, target_addr, target_port, \
                  public_transport, node_transport, protocol, sni, camouflage_enabled) \
                 VALUES (?, ?, 1, ?, 10, '127.0.0.1', 80, \
                         'nginx_sni', 'nginx_sni', 'tcp', ?, 1)",
            )
            .bind(100 + offset)
            .bind(format!("frozen-rule-{offset}"))
            .bind(21000 + offset)
            .bind(format!("frozen-{offset}.example.com"))
            .execute(&pool)
            .await
            .unwrap();
        }
        for offset in 0..executable_count {
            sqlx::query(
                "INSERT INTO forward_rules \
                 (id, name, uid, listen_port, device_group_in, target_addr, target_port, \
                  public_transport, node_transport, protocol, sni, camouflage_enabled) \
                 VALUES (?, ?, 1, ?, 20, '127.0.0.1', 80, \
                         'nginx_sni', 'nginx_sni', 'tcp', ?, 1)",
            )
            .bind(1000 + offset)
            .bind(format!("active-rule-{offset}"))
            .bind(22000 + offset)
            .bind(format!("active-{offset}.example.com"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let db = SqliteRepository::new(pool);
        db.set(
            "relay_preference:10",
            r#"{"preferred_node_id":"node-a","pending_node_id":"node-b","state":"failed","started_at":"2026-08-29T00:00:00Z","last_error":"DNS_RECORD_CONFLICT"}"#,
        )
        .await
        .unwrap();
        for offset in 0..frozen_count {
            db.insert_dns_record_sync(&NewDnsRecordSync {
                rule_id: 100 + offset,
                fqdn: format!("frozen-{offset}.example.com"),
                record_type: "A".into(),
                expected_value: Some("192.0.2.30".into()),
                line: "default".into(),
                line_key: "default".into(),
                desired_action: "UPSERT".into(),
                state: "FAILED".into(),
                ownership: "PANEL".into(),
                last_error_category: Some("DNS_RECORD_CONFLICT".into()),
                next_attempt_at: Some("2026-08-29 00:00:00".into()),
                created_at: "2026-08-29 00:00:00".into(),
                updated_at: "2026-08-29 00:00:00".into(),
            })
            .await
            .unwrap();
        }
        for offset in 0..executable_count {
            db.insert_dns_record_sync(&NewDnsRecordSync {
                rule_id: 1000 + offset,
                fqdn: format!("active-{offset}.example.com"),
                record_type: "A".into(),
                expected_value: Some("192.0.2.40".into()),
                line: "default".into(),
                line_key: "default".into(),
                desired_action: "UPSERT".into(),
                state: "PENDING".into(),
                ownership: "UNKNOWN".into(),
                last_error_category: None,
                next_attempt_at: Some("2026-08-29 00:00:00".into()),
                created_at: "2026-08-29 00:00:00".into(),
                updated_at: "2026-08-29 00:00:00".into(),
            })
            .await
            .unwrap();
        }
        db
    }

    async fn frozen_sync_rows(db: &SqliteRepository, count: i64) -> Vec<DnsRecordSync> {
        let mut rows = Vec::new();
        for offset in 0..count {
            rows.push(
                db.find_dns_record_sync(100 + offset, DEFAULT_LINE_KEY)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        rows
    }

    async fn ensure_db() -> SqliteRepository {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'dns-group', 'in', 'dns-token', 1, '192.0.2.10')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, \
              public_transport, node_transport, protocol, sni, camouflage_enabled) \
             VALUES (100, 'dns-rule', 1, 21000, 10, '127.0.0.1', 80, \
                     'nginx_sni', 'nginx_sni', 'tcp', 'op1.example.com', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        SqliteRepository::new(pool)
    }

    async fn insert_binding(db: &SqliteRepository, record_id: &str, desired_value: &str) {
        db.insert_dns_record_binding(&NewDnsRecordBinding {
            rule_id: Some(100),
            fqdn: "op1.example.com".into(),
            zone_id: 7,
            zone_name: "example.com".into(),
            host: "op1".into(),
            record_type: "A".into(),
            line: "0".into(),
            line_key: "default".into(),
            record_id: record_id.into(),
            desired_value: desired_value.into(),
            state: "BOUND".into(),
            last_observed_at: None,
            created_at: "2026-08-26 00:00:00".into(),
        })
        .await
        .unwrap();
    }

    fn ensure_input(record_type: DnsRecordType, expected_value: &str) -> EnsureRecordInput {
        EnsureRecordInput {
            rule_id: 100,
            fqdn: "op1.example.com".into(),
            record_type,
            expected_value: expected_value.into(),
            line: ProviderLine::default(),
        }
    }

    fn delete_input(raw_line_id: &str) -> DeleteRecordInput {
        DeleteRecordInput {
            rule_id: 100,
            fqdn: "op1.example.com".into(),
            record_type: DnsRecordType::A,
            line: ProviderLine::from_provider(raw_line_id, None),
        }
    }

    async fn insert_line_binding(
        db: &SqliteRepository,
        raw_line_id: &str,
        record_id: &str,
        desired_value: &str,
    ) {
        let line = ProviderLine::from_provider(raw_line_id, None);
        db.insert_dns_record_binding(&NewDnsRecordBinding {
            rule_id: Some(100),
            fqdn: "op1.example.com".into(),
            zone_id: 7,
            zone_name: "example.com".into(),
            host: "op1".into(),
            record_type: "A".into(),
            line: raw_line_id.into(),
            line_key: line.key,
            record_id: record_id.into(),
            desired_value: desired_value.into(),
            state: "BOUND".into(),
            last_observed_at: None,
            created_at: utc_now(),
        })
        .await
        .unwrap();
    }

    fn domain(domain_id: u64, zone_name: &str) -> DnsMgrDomain {
        DnsMgrDomain {
            domain_id,
            zone_name: zone_name.into(),
            provider_type: Some("provider".into()),
            record_count: None,
        }
    }

    fn zone() -> ResolvedZone {
        ResolvedZone {
            domain_id: 7,
            zone_name: "example.com".into(),
            host: "op1".into(),
            provider_type: Some("provider".into()),
        }
    }

    fn record(record_id: &str, record_type: &str, value: &str, line: &str) -> DnsMgrRecord {
        DnsMgrRecord {
            record_id: record_id.into(),
            domain: Some("example.com".into()),
            host: "op1".into(),
            record_type: record_type.into(),
            values: vec![value.into()],
            line: line.into(),
            line_name: Some("default".into()),
            ttl: 300,
            status: "1".into(),
            priority: None,
            weight: None,
            remark: None,
            updated_at: None,
        }
    }

    fn binding(record_id: &str) -> DnsRecordBinding {
        DnsRecordBinding {
            id: 1,
            rule_id: Some(1),
            fqdn: "op1.example.com".into(),
            zone_id: 7,
            zone_name: "example.com".into(),
            host: "op1".into(),
            record_type: "A".into(),
            line: "default".into(),
            line_key: "default".into(),
            record_id: record_id.into(),
            desired_value: "192.0.2.10".into(),
            state: "BOUND".into(),
            last_observed_at: None,
            last_error_category: None,
            created_at: "2026-08-26 00:00:00".into(),
            updated_at: "2026-08-26 00:00:00".into(),
        }
    }
}
