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
    lines: Vec<CarrierLine>,
    fetched_at: Instant,
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

    let mut eligible_snis = db
        .list_rules(&ResourceScope::All)
        .await?
        .into_iter()
        .filter(|rule| {
            rule.device_group_in == group_id && crate::service::dnsmgr::rule_is_dns_eligible(rule)
        })
        .filter_map(|rule| normalize_fqdn(rule.sni.as_deref()?.trim()).ok())
        .map(|fqdn| fqdn.as_str().to_string())
        .collect::<Vec<_>>();
    eligible_snis.sort();
    eligible_snis.dedup();
    if eligible_snis.is_empty() {
        return Ok(CarrierLineCatalog {
            lines: Vec::new(),
            stale: false,
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

    resolve_with_cache(&CATALOG_CACHE, key, Instant::now(), || async move {
        fetch_catalog(&client, &eligible_snis).await
    })
    .await
}

async fn resolve_with_cache<F, Fut>(
    cache: &Mutex<HashMap<CatalogCacheKey, CachedCatalog>>,
    key: CatalogCacheKey,
    now: Instant,
    fetch: F,
) -> Result<CarrierLineCatalog, CarrierLineCatalogError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<CarrierLine>, CarrierLineCatalogError>>,
{
    if let Some(entry) = cache.lock().await.get(&key).cloned() {
        if now.saturating_duration_since(entry.fetched_at) < CATALOG_TTL {
            return Ok(CarrierLineCatalog {
                lines: entry.lines,
                stale: false,
            });
        }
    }

    match fetch().await {
        Ok(lines) => {
            cache.lock().await.insert(
                key,
                CachedCatalog {
                    lines: lines.clone(),
                    fetched_at: now,
                },
            );
            Ok(CarrierLineCatalog {
                lines,
                stale: false,
            })
        }
        Err(error) => match cache.lock().await.get(&key).cloned() {
            Some(entry) => Ok(CarrierLineCatalog {
                lines: entry.lines,
                stale: true,
            }),
            None => Err(error),
        },
    }
}

async fn fetch_catalog(
    client: &DnsMgrClient,
    eligible_snis: &[String],
) -> Result<Vec<CarrierLine>, CarrierLineCatalogError> {
    let domains = list_domains(client).await?;
    let mut zones = BTreeSet::new();
    for sni in eligible_snis {
        let fqdn = normalize_fqdn(sni).map_err(|_| CarrierLineCatalogError::NoMatchingZone)?;
        let zone = resolve_zone_from_inventory(&fqdn, &domains)
            .ok_or(CarrierLineCatalogError::NoMatchingZone)?;
        zones.insert(zone.domain_id);
    }

    let mut catalogs = Vec::with_capacity(zones.len());
    for zone_id in zones {
        let detail = client
            .get_domain(zone_id)
            .await
            .map_err(CarrierLineCatalogError::Provider)?;
        catalogs.push(normalize_lines(detail.record_lines)?);
    }
    Ok(intersect_catalogs(catalogs))
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
        let fresh = resolve_with_cache(&cache, key.clone(), now, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![CarrierLine {
                id: "Dianxin".into(),
                name: "电信".into(),
                parent: None,
            }])
        })
        .await
        .unwrap();
        assert!(!fresh.stale);

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
        assert!(!cached.stale);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let stale = resolve_with_cache(&cache, key, now + CATALOG_TTL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(CarrierLineCatalogError::DnsMgrUnavailable)
        })
        .await
        .unwrap();
        assert!(stale.stale);

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
