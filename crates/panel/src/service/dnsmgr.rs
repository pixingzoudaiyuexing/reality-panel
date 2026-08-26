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

/// KVS key holding the single Panel-wide DNSMgr integration configuration.
pub const DNSMGR_CONFIG_KEY: &str = "dns:dnsmgr";

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
        let key = if raw_id.is_empty() || raw_id == "0" || raw_id.eq_ignore_ascii_case("default") {
            "default".to_string()
        } else {
            format!("provider:{raw_id}")
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
#[allow(dead_code)] // Slice 3 foundation; consumed by Slice 4 ensure_record.
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
pub(crate) fn binding_owns_record(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnsureRecordConflict {
    Cname,
    ExternalWrongValue,
    MultipleUnmanagedRecords,
    StaleBindingCollidesWithExternalRecord,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnsureRecordResult {
    AlreadyCorrect {
        record_id: String,
    },
    AlreadyCorrectExternal {
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
            expected_value: sync.expected_value.clone(),
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
                "fqdn={} record_type={} expected_value={} ownership={} category={}",
                self.fqdn,
                self.record_type,
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
            Self::AlreadyCorrect { .. } | Self::AlreadyCorrectExternal { .. } => {
                DnsMutationAuditOutcome::NoMutation
            }
        }
    }
}

/// Ensure one A/AAAA record without deriving the desired address or coupling
/// DNS to Rule lifecycle. Only an exact persisted provider identity grants
/// mutation authority. DNSMgr writes are single-attempt and always followed by
/// read-back verification; public DNS propagation is intentionally separate.
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
    match <dyn Repository as RuleRepository>::find_rule_by_id(
        db,
        input.rule_id,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return EnsureRecordResult::Failed(EnsureRecordFailure::InvalidRule),
        Err(_) => return EnsureRecordResult::Failed(EnsureRecordFailure::Database),
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

fn resolve_mutation_line(
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

fn write_ttl(detail: &DnsMgrDomainDetail) -> Option<u32> {
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
    let owned = binding.and_then(|binding| {
        records.iter().find(|record| {
            binding_owns_record(Some(binding), fqdn, zone, input.record_type, record)
        })
    });
    if let (Some(binding), Some(record)) = (binding, owned) {
        if record_value_matches(&record.record.value, expected_ip) {
            return EnsureRecordResult::AlreadyCorrect {
                record_id: binding.record_id.clone(),
            };
        }
        return update_and_verify(db, client, input, fqdn, zone, line, ttl, binding, record).await;
    }

    if binding.is_some() {
        return binding_conflict(
            db,
            binding,
            EnsureRecordConflict::StaleBindingCollidesWithExternalRecord,
        )
        .await;
    }
    if records.len() == 1 && record_value_matches(&records[0].record.value, expected_ip) {
        return EnsureRecordResult::AlreadyCorrectExternal {
            record_id: records[0].record.record_id.clone(),
        };
    }
    let conflict = if records.len() > 1 {
        EnsureRecordConflict::MultipleUnmanagedRecords
    } else {
        EnsureRecordConflict::ExternalWrongValue
    };
    EnsureRecordResult::Conflict(conflict)
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
                &record.record.value,
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
    let now = utc_now();
    if let Some(binding) = stale_binding {
        match db
            .rebind_verified_dns_record(
                binding.id,
                &verified.record.record_id,
                &verified.line.raw_id,
                &input.expected_value,
                &now,
                &now,
            )
            .await
        {
            Ok(1) => EnsureRecordResult::Recreated {
                old_record_id: binding.record_id.clone(),
                record_id: verified.record.record_id,
            },
            _ => EnsureRecordResult::MutationOutcomeUnknown,
        }
    } else {
        let zone_id = match i64::try_from(zone.domain_id) {
            Ok(zone_id) => zone_id,
            Err(_) => return EnsureRecordResult::MutationOutcomeUnknown,
        };
        let binding = NewDnsRecordBinding {
            rule_id: Some(input.rule_id),
            fqdn: fqdn.as_str().to_string(),
            zone_id,
            zone_name: zone.zone_name.clone(),
            host: zone.host.clone(),
            record_type: input.record_type.as_str().to_string(),
            line: verified.line.raw_id.clone(),
            line_key: verified.line.key.clone(),
            record_id: verified.record.record_id.clone(),
            desired_value: input.expected_value.clone(),
            state: "BOUND".into(),
            last_observed_at: Some(now.clone()),
            created_at: now,
        };
        match db.insert_dns_record_binding(&binding).await {
            Ok(_) => EnsureRecordResult::Created {
                record_id: verified.record.record_id,
            },
            Err(_) => EnsureRecordResult::MutationOutcomeUnknown,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn update_and_verify(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
    _fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    ttl: u32,
    binding: &DnsRecordBinding,
    _record: &DiscoveredRecord,
) -> EnsureRecordResult {
    let mutation = mutation_request(input, zone, line, ttl);
    let write_result = client
        .update_record(zone.domain_id, &binding.record_id, &mutation)
        .await;
    let ambiguous = match write_result {
        Ok(_) => false,
        Err(error) if error.is_ambiguous_write() => true,
        Err(error) => {
            if set_binding_state(db, binding.id, "ERROR", Some("UPSTREAM_FAILURE"))
                .await
                .is_err()
            {
                return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
            }
            return EnsureRecordResult::Failed(EnsureRecordFailure::Upstream(error));
        }
    };

    let expected_ip = validate_ip_family(input.record_type, &input.expected_value)
        .expect("ensure_record validated the IP family");
    let verified = discover_records(client, zone, input.record_type, line).await;
    let exact = match verified {
        RecordDiscovery::SingleMatchingRecord(record) => Some(record),
        RecordDiscovery::MultipleMatchingRecords(records) => records
            .into_iter()
            .find(|record| record.record.record_id == binding.record_id),
        _ => None,
    };
    let Some(exact) =
        exact.filter(|record| record_value_matches(&record.record.value, expected_ip))
    else {
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
            return EnsureRecordResult::Failed(EnsureRecordFailure::Database);
        }
        return if ambiguous {
            EnsureRecordResult::MutationOutcomeUnknown
        } else {
            EnsureRecordResult::Failed(EnsureRecordFailure::PostWriteNotVerified)
        };
    };
    let now = utc_now();
    if db
        .rebind_verified_dns_record(
            binding.id,
            &exact.record.record_id,
            &exact.line.raw_id,
            &input.expected_value,
            &now,
            &now,
        )
        .await
        .ok()
        != Some(1)
    {
        return EnsureRecordResult::MutationOutcomeUnknown;
    }
    if ambiguous {
        EnsureRecordResult::MutationOutcomeUnknown
    } else {
        EnsureRecordResult::Updated {
            record_id: exact.record.record_id,
        }
    }
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

fn record_value_matches(value: &str, expected: IpAddr) -> bool {
    value
        .trim()
        .parse::<IpAddr>()
        .is_ok_and(|value| value == expected)
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
    Eligible(DnsDesiredRecord),
    ConfigurationError {
        desired: Option<DnsDesiredRecord>,
        category: &'static str,
    },
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
            Some(group) if group.group_type == "in" => group.connect_host.trim().to_string(),
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
        && desired.expected_value == sync.expected_value
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
    let existing = db.find_dns_record_sync(desired.rule_id).await?;
    match existing {
        None => {
            db.insert_dns_record_sync(&NewDnsRecordSync {
                rule_id: desired.rule_id,
                fqdn: desired.fqdn.clone(),
                record_type: desired.record_type.as_str().to_string(),
                expected_value: desired.expected_value.clone(),
                line: desired.line.raw_id.clone(),
                line_key: desired.line.key.clone(),
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
                &desired.expected_value,
                &desired.line.raw_id,
                &desired.line.key,
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

async fn persist_resolution(
    db: &dyn Repository,
    rule_id: i64,
    resolution: DnsDesiredResolution,
    force_schedule: bool,
) -> Result<(), crate::db::error::DbError> {
    match resolution {
        DnsDesiredResolution::NotEligible => {
            if db.find_dns_record_sync(rule_id).await?.is_some() {
                let now = utc_now();
                db.schedule_dns_record_sync(
                    rule_id,
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
        }
        DnsDesiredResolution::ConfigurationError { desired, category } => {
            if let Some(desired) = desired {
                let now = utc_now();
                let existing = db.find_dns_record_sync(rule_id).await?;
                match existing {
                    None => {
                        db.insert_dns_record_sync(&NewDnsRecordSync {
                            rule_id,
                            fqdn: desired.fqdn,
                            record_type: desired.record_type.as_str().into(),
                            expected_value: desired.expected_value,
                            line: desired.line.raw_id,
                            line_key: desired.line.key,
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

/// Schedule an eligible rule after its DB transaction has committed. Any
/// scheduling failure is deliberately returned to the caller for logging only;
/// it must never turn a successful Rule write into a failed Rule response.
pub async fn schedule_rule(
    db: &dyn Repository,
    rule_id: i64,
) -> Result<(), crate::db::error::DbError> {
    let resolution = derive_dns_desired(db, rule_id).await?;
    persist_resolution(db, rule_id, resolution, true).await?;
    let settings = db
        .get(DNSMGR_CONFIG_KEY)
        .await?
        .map(|raw| DnsMgrSettings::from_json(Some(&raw)))
        .unwrap_or_default();
    if (!settings.enabled || !settings.configured())
        && db.find_dns_record_sync(rule_id).await?.is_some()
    {
        let now = utc_now();
        db.schedule_dns_record_sync(
            rule_id,
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
    let Ok(Some(sync)) = state.db.find_dns_record_sync(rule_id).await else {
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
            sync.fqdn, sync.record_type, sync.expected_value, sync.state,
        ),
    )
    .await;
}

async fn refresh_all_desired(db: &dyn Repository) -> Result<(), crate::db::error::DbError> {
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

pub async fn disable_all_syncs(db: &dyn Repository) -> Result<u64, crate::db::error::DbError> {
    db.mark_all_dns_record_syncs_disabled(&utc_now(), "DNSMGR_DISABLED")
        .await
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
        | EnsureRecordFailure::PostWriteNotVerified => false,
    }
}

fn public_dns_state(answers: &[Ipv4Addr], expected: Ipv4Addr) -> PublicDnsObservation {
    if answers.iter().any(|answer| *answer == expected) {
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
    let Ok(expected) = sync.expected_value.parse::<Ipv4Addr>() else {
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
    let mut audits = Vec::new();
    if matches!(sync.state.as_str(), "PROPAGATING" | "MUTATION_VERIFIED") {
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
        expected_value: sync.expected_value.clone(),
        line: ProviderLine::from_provider(&sync.line, None),
    };
    match ensure_record(db, client, &input).await {
        EnsureRecordResult::AlreadyCorrectExternal { .. } => {
            if let Some(audit) = observe_and_store(db, &sync, "SYNCING", "EXTERNAL", None, 0).await
            {
                audits.push(audit);
            }
        }
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

async fn load_client(db: &dyn Repository) -> Result<Option<DnsMgrClient>, DnsMgrError> {
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
        Ok(None) => return,
        Err(error) => {
            tracing::error!("dns reconciliation: client configuration failed: {}", error);
            return;
        }
    };
    let now = utc_now();
    let due = match state
        .db
        .list_due_dns_record_syncs(&now, DNS_SYNC_MAX_BATCH)
        .await
    {
        Ok(due) => due,
        Err(error) => {
            tracing::error!("dns reconciliation: due-state query failed: {}", error);
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
}

/// Start the Panel-only DNS reconciliation worker. It never touches Relay
/// runtime state and exits only when the Panel process exits.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        if let Err(error) = state
            .db
            .resume_dns_record_syncs_on_startup(&utc_now())
            .await
        {
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
    use crate::integrations::dnsmgr::DnsMgrClientConfig;
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
        for raw in ["", "0", "default", "Default"] {
            let line = ProviderLine::from_provider(raw, Some("General"));
            assert_eq!(line.key, "default");
            assert_eq!(line.raw_id, raw);
        }
        let custom = ProviderLine::from_provider("line-42", Some("Premium"));
        assert_eq!(custom.key, "provider:line-42");
        assert_eq!(custom.raw_id, "line-42");
        assert_eq!(custom.name.as_deref(), Some("Premium"));
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
    fn ownership_requires_exact_persisted_provider_record_binding() {
        let fqdn = normalize_fqdn("op1.example.com").unwrap();
        let zone = zone();
        let discovered = DiscoveredRecord {
            line: ProviderLine::default(),
            record: record("r1", "A", "192.0.2.10", "default"),
        };
        assert!(!binding_owns_record(
            None,
            &fqdn,
            &zone,
            DnsRecordType::A,
            &discovered
        ));

        let exact_binding = binding("r1");
        assert!(binding_owns_record(
            Some(&exact_binding),
            &fqdn,
            &zone,
            DnsRecordType::A,
            &discovered
        ));
        let wrong_record = binding("external-record");
        assert!(!binding_owns_record(
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
        assert_eq!(form.get("line").map(String::as_str), Some("0"));
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
    async fn ensure_external_records_are_never_claimed_or_mutated() {
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
            EnsureRecordResult::AlreadyCorrectExternal {
                record_id: "external".into()
            }
        );
        assert!(correct_db
            .find_dns_record_binding_by_record(7, "external")
            .await
            .unwrap()
            .is_none());
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
            EnsureRecordResult::Conflict(EnsureRecordConflict::ExternalWrongValue)
        );
        assert_eq!(wrong.state.total_mutations(), 0);

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
            EnsureRecordResult::Conflict(EnsureRecordConflict::MultipleUnmanagedRecords)
        );
        assert_eq!(multiple.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn ensure_updates_only_the_exact_bound_identity_among_multiple_records() {
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
        assert_eq!(mock.state.update_attempts.load(Ordering::SeqCst), 1);
        let form = mock.state.last_update_form.lock().unwrap().clone().unwrap();
        assert_eq!(form.get("recordid").map(String::as_str), Some("owned"));
        let records = mock.state.records.lock().unwrap();
        assert_eq!(
            records
                .iter()
                .find(|record| record.record_id == "owned")
                .unwrap()
                .value,
            "192.0.2.10"
        );
        assert_eq!(
            records
                .iter()
                .find(|record| record.record_id == "external")
                .unwrap()
                .value,
            "192.0.2.200"
        );
    }

    #[tokio::test]
    async fn ensure_conflicts_on_cname_and_stale_binding_collision() {
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
            EnsureRecordResult::Conflict(
                EnsureRecordConflict::StaleBindingCollidesWithExternalRecord
            )
        );
        let binding = stale_db
            .find_dns_record_binding_by_record(7, "missing-owned")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.state, "CONFLICT");
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
        assert_eq!(replacement.line, "0");
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
    async fn ensure_supports_explicit_aaaa_but_rejects_cross_family_values() {
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
            EnsureRecordResult::Created { .. }
        ));
        assert_eq!(
            mock.state
                .last_add_form
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|form| form.get("type"))
                .map(String::as_str),
            Some("AAAA")
        );

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
    }

    struct MockDnsState {
        records: Mutex<Vec<DnsMgrRecord>>,
        add_behavior: MutationBehavior,
        update_behavior: MutationBehavior,
        add_attempts: AtomicUsize,
        update_attempts: AtomicUsize,
        list_attempts: AtomicUsize,
        last_add_form: Mutex<Option<HashMap<String, String>>>,
        last_update_form: Mutex<Option<HashMap<String, String>>>,
    }

    impl MockDnsState {
        fn total_mutations(&self) -> usize {
            self.add_attempts.load(Ordering::SeqCst) + self.update_attempts.load(Ordering::SeqCst)
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
            add_behavior,
            update_behavior,
            add_attempts: AtomicUsize::new(0),
            update_attempts: AtomicUsize::new(0),
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

    async fn mock_domain_detail() -> Json<serde_json::Value> {
        Json(json!({
            "code": 0,
            "data": {
                "id": 7,
                "name": "example.com",
                "type": "provider",
                "minTTL": 1200,
                "recordLine": [{"id": 0, "name": "General", "parent": null}]
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
        if matches!(state.update_behavior, MutationBehavior::Apply) {
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

    fn mutation_response(behavior: MutationBehavior) -> Response {
        if matches!(behavior, MutationBehavior::TransportAfterApply) {
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
            "Value": record.value,
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
        let first = db.find_dns_record_sync(100).await.unwrap().unwrap();
        assert_eq!(first.state, "PENDING");
        assert_eq!(first.expected_value, "192.0.2.10");

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
        let edited = db.find_dns_record_sync(100).await.unwrap().unwrap();
        assert_eq!(edited.fqdn, "op2.example.com");
        assert_eq!(edited.state, "PENDING");
        assert_eq!(edited.attempt_count, 0);
    }

    #[tokio::test]
    async fn disabled_integration_leaves_eligible_work_disabled_and_not_due() {
        let db = ensure_db().await;
        configure_eligible_rule(&db, "op1.example.com", "192.0.2.10").await;
        schedule_rule(&db, 100).await.unwrap();
        let sync = db.find_dns_record_sync(100).await.unwrap().unwrap();
        assert_eq!(sync.state, "DISABLED");
        assert_eq!(sync.last_error_category.as_deref(), Some("DNSMGR_DISABLED"));
        assert!(db
            .list_due_dns_record_syncs(&utc_now(), DNS_SYNC_MAX_BATCH)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn reconciliation_classifies_created_external_conflict_and_unknown_without_blind_retry() {
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
        assert_eq!(external_state.ownership, "EXTERNAL");
        assert!(external_db
            .find_dns_record_binding_for_rule(100, "op1.example.com", "A", "default")
            .await
            .unwrap()
            .is_none());
        assert_eq!(external.state.total_mutations(), 0);
        assert!(external_audits
            .iter()
            .all(|audit| audit.action != "DNS_RECORD_CREATED"));

        let conflict_db = ensure_db().await;
        configure_eligible_rule(&conflict_db, "op1.example.com", "192.0.2.10").await;
        insert_sync(&conflict_db).await;
        let conflict = spawn_ensure_mock(
            vec![record("external", "A", "192.0.2.99", "0")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        let conflict_audits =
            reconcile_one(&conflict_db, sync_row(&conflict_db).await, &conflict.client).await;
        let conflict_state = sync_row(&conflict_db).await;
        assert_eq!(conflict_state.state, "CONFLICT");
        assert_eq!(conflict_state.next_attempt_at, None);
        assert_eq!(conflict.state.total_mutations(), 0);
        assert_eq!(conflict_audits[0].action, "DNS_RECORD_CONFLICT");

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
            "192.0.2.11",
            "default",
            "default",
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
        assert_eq!(current.expected_value, "192.0.2.11");
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
            "192.0.2.10",
            "default",
            "default",
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
            expected_value: "192.0.2.10".into(),
            line: "default".into(),
            line_key: "default".into(),
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
        db.find_dns_record_sync(100).await.unwrap().unwrap()
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
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'dns-group', 'in', 'dns-token', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (100, 'dns-rule', 1, 21000, 10, '127.0.0.1', 80)",
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
            value: value.into(),
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
