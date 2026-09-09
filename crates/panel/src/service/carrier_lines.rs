use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use crate::integrations::dnsmgr::{
    DnsMgrClient, DnsMgrClientConfig, DnsMgrDomain, DnsMgrError, DnsMgrRecordLine, DomainListParams,
};
use crate::service::dnsmgr::{
    normalize_fqdn, resolve_zone_from_inventory, DnsMgrSettings, ProviderLine,
};
use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CATALOG_TTL: Duration = Duration::from_secs(300);
const DOMAIN_PAGE_LIMIT: u16 = 100;
const MAX_LINE_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CarrierLine {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CarrierLineCatalog {
    pub lines: Vec<CarrierLine>,
    pub stale: bool,
    pub issues: Vec<CarrierCatalogIssue>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CarrierCatalogIssue {
    NoEligibleRules,
    IncompatibleLineCatalogs {
        reason: String,
        actionable: Option<CarrierIssueAction>,
        zones: Vec<CarrierIssueZone>,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "level", rename_all = "snake_case")]
pub enum CarrierIssueAction {
    Rule { rule_id: i64 },
    Zone { domain_id: u64 },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CarrierIssueZone {
    pub domain_id: u64,
    pub zone: String,
    pub provider_type: Option<String>,
    pub line_count: usize,
    pub rules: Vec<CarrierIssueRule>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CarrierIssueRule {
    pub rule_id: i64,
    pub name: String,
    pub sni: String,
}

#[derive(Debug)]
pub enum CarrierLineCatalogError {
    Database(DbError),
    GroupNotFound,
    DnsMgrUnavailable,
    Provider(DnsMgrError),
    NoMatchingZone,
    InvalidProviderLine,
}

impl std::fmt::Display for CarrierLineCatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::GroupNotFound => formatter.write_str("inbound group not found"),
            Self::DnsMgrUnavailable => formatter.write_str("DNSMgr is disabled or not configured"),
            Self::Provider(error) => write!(formatter, "DNSMgr request failed: {error}"),
            Self::NoMatchingZone => formatter.write_str("eligible rule has no managed DNS zone"),
            Self::InvalidProviderLine => {
                formatter.write_str("DNSMgr returned an invalid record line")
            }
        }
    }
}

impl std::error::Error for CarrierLineCatalogError {}

impl From<DbError> for CarrierLineCatalogError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CatalogCacheKey {
    group_id: i64,
    settings_fingerprint: String,
    eligible_snis: Vec<String>,
}

#[derive(Debug, Clone)]
struct CachedCatalog {
    provider: ProviderCatalogSnapshot,
    fetched_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderCatalogSnapshot {
    sni_zones: BTreeMap<String, u64>,
    zones: BTreeMap<u64, ProviderZoneCatalog>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderZoneCatalog {
    domain_id: u64,
    zone: String,
    provider_type: Option<String>,
    lines: BTreeMap<String, CarrierLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EligibleRule {
    rule_id: i64,
    name: String,
    sni: String,
}

static CATALOG_CACHE: Lazy<Mutex<HashMap<CatalogCacheKey, CachedCatalog>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub async fn group_catalog(
    db: &dyn Repository,
    group_id: i64,
) -> Result<CarrierLineCatalog, CarrierLineCatalogError> {
    match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(group) if group.group_type == "in" => {}
        Some(_) | None => return Err(CarrierLineCatalogError::GroupNotFound),
    }

    let mut eligible_rules =
        eligible_rules_for_group(db.list_rules(&ResourceScope::All).await?, group_id);
    eligible_rules.sort_by_key(|rule| rule.rule_id);
    let mut eligible_snis = eligible_rules
        .iter()
        .map(|rule| rule.sni.clone())
        .collect::<Vec<_>>();
    eligible_snis.sort();
    eligible_snis.dedup();
    if eligible_snis.is_empty() {
        return Ok(CarrierLineCatalog {
            lines: vec![default_line()],
            stale: false,
            issues: vec![CarrierCatalogIssue::NoEligibleRules],
        });
    }

    let settings = db
        .get(crate::service::dnsmgr::DNSMGR_CONFIG_KEY)
        .await?
        .map(|raw| DnsMgrSettings::from_json(Some(&raw)))
        .unwrap_or_default();
    if !settings.enabled || !settings.configured() {
        return Err(CarrierLineCatalogError::DnsMgrUnavailable);
    }
    let key = CatalogCacheKey {
        group_id,
        settings_fingerprint: settings_fingerprint(&settings),
        eligible_snis: eligible_snis.clone(),
    };
    let client = DnsMgrClient::new(
        DnsMgrClientConfig::new(&settings.base_url, settings.uid, settings.api_key.clone())
            .map_err(CarrierLineCatalogError::Provider)?,
    )
    .map_err(CarrierLineCatalogError::Provider)?;

    let (provider, stale) =
        resolve_with_cache(&CATALOG_CACHE, key, Instant::now(), || async move {
            fetch_provider_catalog(&client, &eligible_snis).await
        })
        .await?;
    Ok(build_catalog(&eligible_rules, &provider, stale))
}

fn eligible_rules_for_group(
    rules: Vec<relay_shared::models::ForwardRule>,
    group_id: i64,
) -> Vec<EligibleRule> {
    rules
        .into_iter()
        .filter(|rule| {
            rule.device_group_in == group_id && crate::service::dnsmgr::rule_is_dns_eligible(rule)
        })
        .filter_map(|rule| {
            let sni = normalize_fqdn(rule.sni.as_deref()?.trim()).ok()?;
            Some(EligibleRule {
                rule_id: rule.id,
                name: rule.name,
                sni: sni.as_str().to_string(),
            })
        })
        .collect()
}

async fn resolve_with_cache<F, Fut>(
    cache: &Mutex<HashMap<CatalogCacheKey, CachedCatalog>>,
    key: CatalogCacheKey,
    now: Instant,
    fetch: F,
) -> Result<(ProviderCatalogSnapshot, bool), CarrierLineCatalogError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ProviderCatalogSnapshot, CarrierLineCatalogError>>,
{
    if let Some(entry) = cache.lock().await.get(&key).cloned() {
        if now.saturating_duration_since(entry.fetched_at) < CATALOG_TTL {
            return Ok((entry.provider, false));
        }
    }

    match fetch().await {
        Ok(provider) => {
            cache.lock().await.insert(
                key,
                CachedCatalog {
                    provider: provider.clone(),
                    fetched_at: now,
                },
            );
            Ok((provider, false))
        }
        Err(error) => match cache.lock().await.get(&key).cloned() {
            Some(entry) => Ok((entry.provider, true)),
            None => Err(error),
        },
    }
}

async fn fetch_provider_catalog(
    client: &DnsMgrClient,
    eligible_snis: &[String],
) -> Result<ProviderCatalogSnapshot, CarrierLineCatalogError> {
    let domains = list_domains(client).await?;
    let mut zones = BTreeSet::new();
    let mut sni_zones = BTreeMap::new();
    for sni in eligible_snis {
        let fqdn = normalize_fqdn(sni).map_err(|_| CarrierLineCatalogError::NoMatchingZone)?;
        let zone = resolve_zone_from_inventory(&fqdn, &domains)
            .ok_or(CarrierLineCatalogError::NoMatchingZone)?;
        zones.insert(zone.domain_id);
        sni_zones.insert(sni.clone(), zone.domain_id);
    }

    let mut provider_zones = BTreeMap::new();
    for zone_id in zones {
        let detail = client
            .get_domain(zone_id)
            .await
            .map_err(CarrierLineCatalogError::Provider)?;
        provider_zones.insert(
            zone_id,
            ProviderZoneCatalog {
                domain_id: zone_id,
                zone: detail.domain.zone_name,
                provider_type: detail.domain.provider_type,
                lines: normalize_lines(detail.record_lines)?,
            },
        );
    }
    Ok(ProviderCatalogSnapshot {
        sni_zones,
        zones: provider_zones,
    })
}

async fn list_domains(client: &DnsMgrClient) -> Result<Vec<DnsMgrDomain>, CarrierLineCatalogError> {
    let mut domains = Vec::new();
    let mut offset = 0_u32;
    loop {
        let page = client
            .list_domains(&DomainListParams {
                offset,
                limit: DOMAIN_PAGE_LIMIT,
                keyword: None,
            })
            .await
            .map_err(CarrierLineCatalogError::Provider)?;
        let count = page.rows.len();
        domains.extend(page.rows);
        if count == 0 || u64::from(offset).saturating_add(count as u64) >= page.total {
            break;
        }
        offset = offset
            .checked_add(count as u32)
            .ok_or(CarrierLineCatalogError::InvalidProviderLine)?;
    }
    Ok(domains)
}

fn default_line() -> CarrierLine {
    CarrierLine {
        id: crate::service::dnsmgr::DEFAULT_LINE_KEY.into(),
        name: "default".into(),
        parent: None,
    }
}

fn build_catalog(
    rules: &[EligibleRule],
    provider: &ProviderCatalogSnapshot,
    stale: bool,
) -> CarrierLineCatalog {
    // Preserve the existing catalog behavior exactly: intersect each unique
    // Zone once, in domain_id order. Rule-level duplicates are used only by the
    // diagnostic leave-one-out analysis below.
    let used_zone_ids = rules
        .iter()
        .filter_map(|rule| provider.sni_zones.get(&rule.sni).copied())
        .collect::<BTreeSet<_>>();
    let zone_catalogs = used_zone_ids
        .iter()
        .filter_map(|zone_id| provider.zones.get(zone_id).map(|zone| zone.lines.clone()))
        .collect::<Vec<_>>();
    let rule_catalogs = rules
        .iter()
        .filter_map(|rule| {
            provider
                .sni_zones
                .get(&rule.sni)
                .and_then(|zone_id| provider.zones.get(zone_id))
                .map(|zone| zone.lines.clone())
        })
        .collect::<Vec<_>>();
    let common_lines = intersect_catalogs(zone_catalogs);
    let mut lines = common_lines.clone();
    lines.insert(0, default_line());

    let issues = if rules.is_empty() {
        vec![CarrierCatalogIssue::NoEligibleRules]
    } else if rule_catalogs.len() == rules.len() && common_lines.is_empty() {
        vec![incompatible_issue(rules, provider)]
    } else {
        Vec::new()
    };

    CarrierLineCatalog {
        lines,
        stale,
        issues,
    }
}

fn incompatible_issue(
    rules: &[EligibleRule],
    provider: &ProviderCatalogSnapshot,
) -> CarrierCatalogIssue {
    let actionable_rules = (0..rules.len())
        .filter(|removed| {
            let remaining = rules
                .iter()
                .enumerate()
                .filter(|(index, _)| index != removed)
                .filter_map(|(_, rule)| rule_lines(rule, provider).cloned())
                .collect::<Vec<_>>();
            !remaining.is_empty() && !intersect_catalogs(remaining).is_empty()
        })
        .collect::<Vec<_>>();

    let actionable = if actionable_rules.len() == 1 {
        Some(CarrierIssueAction::Rule {
            rule_id: rules[actionable_rules[0]].rule_id,
        })
    } else {
        let zone_ids = rules
            .iter()
            .filter_map(|rule| provider.sni_zones.get(&rule.sni).copied())
            .collect::<BTreeSet<_>>();
        let actionable_zones = zone_ids
            .iter()
            .filter(|removed_zone| {
                let remaining = rules
                    .iter()
                    .filter(|rule| provider.sni_zones.get(&rule.sni) != Some(removed_zone))
                    .filter_map(|rule| rule_lines(rule, provider).cloned())
                    .collect::<Vec<_>>();
                !remaining.is_empty() && !intersect_catalogs(remaining).is_empty()
            })
            .copied()
            .collect::<Vec<_>>();
        (actionable_zones.len() == 1).then(|| CarrierIssueAction::Zone {
            domain_id: actionable_zones[0],
        })
    };

    let mut zones = BTreeMap::<u64, CarrierIssueZone>::new();
    for rule in rules {
        let Some(zone_id) = provider.sni_zones.get(&rule.sni) else {
            continue;
        };
        let Some(zone) = provider.zones.get(zone_id) else {
            continue;
        };
        zones
            .entry(*zone_id)
            .or_insert_with(|| CarrierIssueZone {
                domain_id: zone.domain_id,
                zone: zone.zone.clone(),
                provider_type: zone.provider_type.clone(),
                line_count: zone.lines.len(),
                rules: Vec::new(),
            })
            .rules
            .push(CarrierIssueRule {
                rule_id: rule.rule_id,
                name: rule.name.clone(),
                sni: rule.sni.clone(),
            });
    }

    CarrierCatalogIssue::IncompatibleLineCatalogs {
        reason: "no_common_line_ids".into(),
        actionable,
        zones: zones.into_values().collect(),
    }
}

fn rule_lines<'a>(
    rule: &EligibleRule,
    provider: &'a ProviderCatalogSnapshot,
) -> Option<&'a BTreeMap<String, CarrierLine>> {
    let zone_id = provider.sni_zones.get(&rule.sni)?;
    Some(&provider.zones.get(zone_id)?.lines)
}

fn normalize_lines(
    lines: Vec<DnsMgrRecordLine>,
) -> Result<BTreeMap<String, CarrierLine>, CarrierLineCatalogError> {
    let mut normalized = BTreeMap::new();
    for line in lines {
        validate_line_id(&line.id)?;
        if ProviderLine::from_provider(&line.id, Some(&line.name)).key == "default" {
            continue;
        }
        normalized.entry(line.id.clone()).or_insert(CarrierLine {
            id: line.id,
            name: line.name,
            parent: line.parent,
        });
    }
    Ok(normalized)
}

fn intersect_catalogs(catalogs: Vec<BTreeMap<String, CarrierLine>>) -> Vec<CarrierLine> {
    let mut catalogs = catalogs.into_iter();
    let Some(mut intersection) = catalogs.next() else {
        return Vec::new();
    };
    for catalog in catalogs {
        intersection.retain(|id, _| catalog.contains_key(id));
    }
    intersection.into_values().collect()
}

fn validate_line_id(line_id: &str) -> Result<(), CarrierLineCatalogError> {
    if line_id.is_empty()
        || line_id != line_id.trim()
        || line_id.len() > MAX_LINE_ID_BYTES
        || line_id.chars().any(char::is_control)
    {
        return Err(CarrierLineCatalogError::InvalidProviderLine);
    }
    Ok(())
}

fn settings_fingerprint(settings: &DnsMgrSettings) -> String {
    let mut digest = Sha256::new();
    digest.update([u8::from(settings.enabled)]);
    digest.update([0]);
    digest.update(settings.base_url.as_bytes());
    digest.update([0]);
    digest.update(settings.uid.to_be_bytes());
    digest.update([0]);
    digest.update(settings.api_key.as_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn line(id: &str, name: &str, parent: Option<&str>) -> DnsMgrRecordLine {
        DnsMgrRecordLine {
            id: id.into(),
            name: name.into(),
            parent: parent.map(str::to_string),
        }
    }

    fn catalog(ids: &[&str]) -> BTreeMap<String, CarrierLine> {
        ids.iter()
            .map(|id| {
                (
                    (*id).to_string(),
                    CarrierLine {
                        id: (*id).to_string(),
                        name: (*id).to_string(),
                        parent: None,
                    },
                )
            })
            .collect()
    }

    fn rule(id: i64, name: &str, zone_id: u64) -> EligibleRule {
        EligibleRule {
            rule_id: id,
            name: name.into(),
            sni: format!("rule{id}.zone{zone_id}.test"),
        }
    }

    fn provider(zones: &[(u64, &[&str])], rules: &[EligibleRule]) -> ProviderCatalogSnapshot {
        ProviderCatalogSnapshot {
            sni_zones: rules
                .iter()
                .map(|rule| {
                    let zone_id = rule
                        .sni
                        .split(".zone")
                        .nth(1)
                        .unwrap()
                        .split('.')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    (rule.sni.clone(), zone_id)
                })
                .collect(),
            zones: zones
                .iter()
                .map(|(zone_id, ids)| {
                    (
                        *zone_id,
                        ProviderZoneCatalog {
                            domain_id: *zone_id,
                            zone: format!("zone{zone_id}.test"),
                            provider_type: Some(format!("provider-{zone_id}")),
                            lines: catalog(ids),
                        },
                    )
                })
                .collect(),
        }
    }

    fn actionable(issue: &CarrierCatalogIssue) -> Option<&CarrierIssueAction> {
        match issue {
            CarrierCatalogIssue::IncompatibleLineCatalogs { actionable, .. } => actionable.as_ref(),
            CarrierCatalogIssue::NoEligibleRules => None,
        }
    }

    fn stored_rule(id: i64, paused: bool) -> relay_shared::models::ForwardRule {
        relay_shared::models::ForwardRule {
            id,
            name: format!("rule-{id}"),
            uid: 1,
            paused,
            listen_port: 443,
            protocol: "tcp".into(),
            public_transport: "nginx_sni".into(),
            node_transport: "nginx_sni".into(),
            route_mode: "direct".into(),
            device_group_in: 7,
            device_group_out: None,
            forward_mode: "direct".into(),
            tunnel_profile_id: None,
            domain: None,
            ws_path: None,
            ws_host: None,
            sni: Some(format!("rule{id}.example.com")),
            camouflage_enabled: true,
            send_proxy_protocol: false,
            target_addr: "127.0.0.1".into(),
            target_port: 443,
            targets: Vec::new(),
            load_balance_strategy: "first".into(),
            upload_limit_mbps: 0,
            download_limit_mbps: 0,
            max_connections: 0,
            auto_restart_minutes: 0,
            config: "{}".into(),
            traffic_used: 0,
            status: "active".into(),
            created_at: String::new(),
        }
    }

    #[test]
    fn opaque_ids_case_and_parent_are_preserved_while_default_is_filtered() {
        let lines = normalize_lines(vec![
            line("default_view", "全网默认", None),
            line("Dianxin", "电信", None),
            line("Dianxin_Shandong", "电信_山东", Some("Dianxin")),
        ])
        .unwrap();
        assert_eq!(
            lines.into_values().collect::<Vec<_>>(),
            vec![
                CarrierLine {
                    id: "Dianxin".into(),
                    name: "电信".into(),
                    parent: None,
                },
                CarrierLine {
                    id: "Dianxin_Shandong".into(),
                    name: "电信_山东".into(),
                    parent: Some("Dianxin".into()),
                },
            ]
        );
        assert!(normalize_lines(vec![line("bad\nline", "bad", None)]).is_err());
        assert!(normalize_lines(vec![line(" Dianxin", "bad", None)]).is_err());
    }

    #[test]
    fn multi_zone_catalog_is_an_id_intersection() {
        let first = normalize_lines(vec![
            line("X", "X", None),
            line("Y", "Y", Some("X")),
            line("Z", "Z", None),
        ])
        .unwrap();
        let second =
            normalize_lines(vec![line("X", "other X", None), line("Y", "other Y", None)]).unwrap();
        assert_eq!(
            intersect_catalogs(vec![first, second])
                .into_iter()
                .map(|line| line.id)
                .collect::<Vec<_>>(),
            vec!["X", "Y"]
        );
    }

    #[test]
    fn compatible_catalogs_keep_intersection_without_issue() {
        let rules = vec![rule(1, "one", 10), rule(2, "two", 20)];
        let result = build_catalog(
            &rules,
            &provider(&[(10, &["A", "COMMON"]), (20, &["B", "COMMON"])], &rules),
            false,
        );
        assert_eq!(
            result
                .lines
                .iter()
                .map(|line| line.id.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "COMMON"]
        );
        assert!(result.issues.is_empty());
    }

    #[test]
    fn repeated_good_zone_and_one_disjoint_rule_identifies_that_rule() {
        let rules = vec![
            rule(14, "Huawei A", 10),
            rule(16, "Huawei A again", 10),
            rule(15, "Cloudflare B", 20),
        ];
        let result = build_catalog(
            &rules,
            &provider(&[(10, &["A"]), (20, &["B"])], &rules),
            false,
        );
        assert_eq!(
            result
                .lines
                .iter()
                .map(|line| line.id.as_str())
                .collect::<Vec<_>>(),
            vec!["default"]
        );
        assert_eq!(
            actionable(&result.issues[0]),
            Some(&CarrierIssueAction::Rule { rule_id: 15 })
        );
    }

    #[test]
    fn two_disjoint_rules_are_ambiguous() {
        let rules = vec![rule(1, "A", 10), rule(2, "B", 20)];
        let result = build_catalog(
            &rules,
            &provider(&[(10, &["A"]), (20, &["B"])], &rules),
            false,
        );
        assert_eq!(actionable(&result.issues[0]), None);
    }

    #[test]
    fn two_rules_in_each_disjoint_zone_are_ambiguous() {
        let rules = vec![
            rule(1, "A1", 10),
            rule(2, "A2", 10),
            rule(3, "B1", 20),
            rule(4, "B2", 20),
        ];
        let result = build_catalog(
            &rules,
            &provider(&[(10, &["A"]), (20, &["B"])], &rules),
            false,
        );
        assert_eq!(actionable(&result.issues[0]), None);
    }

    #[test]
    fn zone_level_finds_unique_multi_rule_outlier() {
        let rules = vec![
            rule(1, "A", 10),
            rule(2, "B", 20),
            rule(3, "C1", 30),
            rule(4, "C2", 30),
        ];
        let result = build_catalog(
            &rules,
            &provider(
                &[(10, &["X", "A"]), (20, &["X", "B"]), (30, &["C"])],
                &rules,
            ),
            false,
        );
        assert_eq!(
            actionable(&result.issues[0]),
            Some(&CarrierIssueAction::Zone { domain_id: 30 })
        );
    }

    #[test]
    fn triangle_catalog_is_ambiguous() {
        let rules = vec![rule(1, "A", 10), rule(2, "B", 20), rule(3, "C", 30)];
        let result = build_catalog(
            &rules,
            &provider(
                &[(10, &["a", "b"]), (20, &["b", "c"]), (30, &["a", "c"])],
                &rules,
            ),
            false,
        );
        assert_eq!(actionable(&result.issues[0]), None);
    }

    #[test]
    fn no_eligible_rules_has_separate_issue() {
        let result = build_catalog(
            &[],
            &ProviderCatalogSnapshot {
                sni_zones: BTreeMap::new(),
                zones: BTreeMap::new(),
            },
            false,
        );
        assert_eq!(result.issues, vec![CarrierCatalogIssue::NoEligibleRules]);
        assert_eq!(result.lines, vec![default_line()]);
    }

    #[test]
    fn paused_and_other_group_rules_do_not_participate() {
        let mut other_group = stored_rule(3, false);
        other_group.device_group_in = 8;
        let rules = eligible_rules_for_group(
            vec![stored_rule(1, false), stored_rule(2, true), other_group],
            7,
        );
        assert_eq!(
            rules.iter().map(|rule| rule.rule_id).collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn cache_fingerprint_changes_with_every_dnsmgr_setting() {
        let base = DnsMgrSettings {
            enabled: true,
            base_url: "https://dns.example.test".into(),
            uid: 7,
            api_key: "key-a".into(),
        };
        let fingerprint = settings_fingerprint(&base);
        for changed in [
            DnsMgrSettings {
                enabled: false,
                ..base.clone()
            },
            DnsMgrSettings {
                base_url: "https://other.example.test".into(),
                ..base.clone()
            },
            DnsMgrSettings {
                uid: 8,
                ..base.clone()
            },
            DnsMgrSettings {
                api_key: "key-b".into(),
                ..base.clone()
            },
        ] {
            assert_ne!(settings_fingerprint(&changed), fingerprint);
        }
    }

    #[tokio::test]
    async fn cache_returns_fresh_then_stale_and_never_crosses_configuration_keys() {
        let cache = Mutex::new(HashMap::new());
        let now = Instant::now();
        let key = CatalogCacheKey {
            group_id: 7,
            settings_fingerprint: "config-a".into(),
            eligible_snis: vec!["op1.example.com".into()],
        };
        let calls = AtomicUsize::new(0);
        let rules = vec![rule(1, "old name", 10), rule(2, "second", 20)];
        let snapshot = provider(&[(10, &["A"]), (20, &["B"])], &rules);
        let fresh = resolve_with_cache(&cache, key.clone(), now, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(snapshot.clone())
        })
        .await
        .unwrap();
        assert!(!fresh.1);

        let first_view = build_catalog(&rules, &fresh.0, false);
        let mut renamed = rules.clone();
        renamed[0].name = "new name".into();

        let cached = resolve_with_cache(
            &cache,
            key.clone(),
            now + Duration::from_secs(1),
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(CarrierLineCatalogError::DnsMgrUnavailable)
            },
        )
        .await
        .unwrap();
        assert!(!cached.1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let renamed_view = build_catalog(&renamed, &cached.0, false);
        assert_ne!(first_view.issues, renamed_view.issues);
        let CarrierCatalogIssue::IncompatibleLineCatalogs { zones, .. } = &renamed_view.issues[0]
        else {
            panic!("expected incompatible issue");
        };
        assert!(zones
            .iter()
            .flat_map(|zone| &zone.rules)
            .any(|rule| rule.name == "new name"));

        let stale = resolve_with_cache(&cache, key, now + CATALOG_TTL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(CarrierLineCatalogError::DnsMgrUnavailable)
        })
        .await
        .unwrap();
        assert!(stale.1);
        let stale_view = build_catalog(&renamed, &stale.0, true);
        assert_eq!(stale_view.lines, renamed_view.lines);
        assert_eq!(stale_view.issues, renamed_view.issues);

        let other_key = CatalogCacheKey {
            group_id: 7,
            settings_fingerprint: "config-b".into(),
            eligible_snis: vec!["op1.example.com".into()],
        };
        assert!(resolve_with_cache(&cache, other_key, now, || async {
            Err(CarrierLineCatalogError::DnsMgrUnavailable)
        })
        .await
        .is_err());
    }
}
