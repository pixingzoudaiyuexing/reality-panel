//! Short-lived provider observations for one apply/preflight or worker batch.
//! Only untouched record keys share the full-zone snapshot. Mutations dirty
//! their host/line before submission; readback always performs provider I/O.
use super::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

type ZoneKey = (String, u64);
type RecordKey = (String, String);

#[derive(Default)]
struct ZoneObservation {
    inventory: Option<Vec<DnsMgrRecord>>,
    epoch: u64,
    changes: BTreeMap<RecordKey, (u64, Option<Vec<DnsMgrRecord>>)>,
    fence: Option<Arc<ZoneFence>>,
    fresh_inventory: Option<(u64, std::time::Instant, Vec<DnsMgrRecord>)>,
}

#[derive(Default)]
struct Observations {
    domains: HashMap<String, Vec<DnsMgrDomain>>,
    details: HashMap<ZoneKey, DnsMgrDomainDetail>,
    zones: HashMap<ZoneKey, ZoneObservation>,
    drift: BTreeMap<i64, BTreeSet<String>>,
}

tokio::task_local! { static CURRENT: Arc<Mutex<Observations>>; }

pub(super) async fn scope<F: Future>(future: F) -> F::Output {
    CURRENT
        .scope(Arc::new(Mutex::new(Observations::default())), future)
        .await
}

fn current() -> Option<Arc<Mutex<Observations>>> {
    CURRENT.try_with(Arc::clone).ok()
}
pub(super) fn active() -> bool {
    current().is_some()
}

pub(super) async fn mark_drift(group_id: i64, line: &ProviderLine) {
    if let Some(context) = current() {
        context
            .lock()
            .await
            .drift
            .entry(group_id)
            .or_default()
            .insert(if line.key == DEFAULT_LINE_KEY {
                DEFAULT_LINE_KEY.into()
            } else {
                line.raw_id.clone()
            });
    }
}

pub(super) async fn drift_lines(group_id: i64) -> BTreeSet<String> {
    match current() {
        Some(context) => context
            .lock()
            .await
            .drift
            .get(&group_id)
            .cloned()
            .unwrap_or_default(),
        None => BTreeSet::new(),
    }
}

pub(super) async fn domains(client: &DnsMgrClient) -> Result<Vec<DnsMgrDomain>, DnsMgrError> {
    let Some(context) = current() else {
        return fetch_domain_inventory(client).await;
    };
    let mut context = context.lock().await;
    let key = client.observation_identity();
    if let Some(domains) = context.domains.get(&key) {
        return Ok(domains.clone());
    }
    let domains = fetch_domain_inventory(client).await?;
    context.domains.insert(key, domains.clone());
    Ok(domains)
}

pub(super) async fn detail(
    client: &DnsMgrClient,
    zone_id: u64,
) -> Result<DnsMgrDomainDetail, DnsMgrError> {
    let Some(context) = current() else {
        return client.get_domain(zone_id).await;
    };
    let mut context = context.lock().await;
    let key = (client.observation_identity(), zone_id);
    if let Some(detail) = context.details.get(&key) {
        return Ok(detail.clone());
    }
    let detail = client.get_domain(zone_id).await?;
    context.details.insert(key, detail.clone());
    Ok(detail)
}

fn record_key(host: &str, line: &ProviderLine) -> RecordKey {
    (host.trim().to_ascii_lowercase(), line.key.clone())
}

fn matching(records: &[DnsMgrRecord], key: &RecordKey) -> Vec<DnsMgrRecord> {
    records
        .iter()
        .filter(|r| {
            r.host.trim().eq_ignore_ascii_case(&key.0)
                && ProviderLine::from_provider(&r.line, r.line_name.as_deref()).key == key.1
        })
        .cloned()
        .collect()
}

pub(super) async fn prewrite_records(
    client: &DnsMgrClient,
    zone: &ResolvedZone,
    line: &ProviderLine,
) -> Result<Vec<DnsMgrRecord>, DnsMgrError> {
    let Some(context) = current() else {
        let inventory = fetch_record_inventory(client, zone, None).await?;
        if !inventory.complete {
            return Err(incomplete());
        }
        return Ok(matching(&inventory.records, &record_key(&zone.host, line)));
    };
    let zone_key = (client.observation_identity(), zone.domain_id);
    let key = record_key(&zone.host, line);
    let state = context.lock().await;
    if let Some(observed) = state.zones.get(&zone_key) {
        if let Some((_, records)) = observed.changes.get(&key) {
            if let Some(records) = records {
                return Ok(records.clone());
            }
            drop(state);
            return fresh_records(client, zone, line).await;
        }
        if let Some(records) = observed.inventory.as_ref() {
            return Ok(matching(records, &key));
        }
    }
    drop(state);
    let records = complete_zone_inventory(client, zone, None).await?;
    let mut state = context.lock().await;
    let observed = state.zones.entry(zone_key).or_default();
    observed.inventory = Some(records.clone());
    Ok(matching(&records, &key))
}

fn incomplete() -> DnsMgrError {
    DnsMgrError::ProtocolContractViolation("incomplete DNS record inventory".into())
}

/// A fresh filtered observation, with the existing full-zone absence gate.
/// Never return a cached snapshot as mutation success evidence.
pub(super) async fn fresh_records(
    client: &DnsMgrClient,
    zone: &ResolvedZone,
    line: &ProviderLine,
) -> Result<Vec<DnsMgrRecord>, DnsMgrError> {
    let zone_key = (client.observation_identity(), zone.domain_id);
    let key = record_key(&zone.host, line);
    let stamp = if let Some(context) = current() {
        let context = context.lock().await;
        context
            .zones
            .get(&zone_key)
            .map(|z| (z.epoch, z.changes.get(&key).map(|(v, _)| *v).unwrap_or(0)))
    } else {
        None
    };
    let filtered_started = std::time::Instant::now();
    let filtered = fetch_record_inventory(client, zone, Some(&zone.host)).await?;
    if !filtered.complete {
        return Err(incomplete());
    }
    let mut records = matching(&filtered.records, &key);
    if records.is_empty() {
        let full = complete_zone_inventory(client, zone, Some(filtered_started)).await?;
        records = matching(&full, &key);
    }
    if let (Some(context), Some(stamp)) = (current(), stamp) {
        let mut context = context.lock().await;
        if let Some(observed) = context.zones.get_mut(&zone_key) {
            let generation = observed.changes.get(&key).map(|(v, _)| *v).unwrap_or(0);
            if (observed.epoch, generation) == stamp {
                observed
                    .changes
                    .insert(key, (generation, Some(records.clone())));
            }
        }
    }
    Ok(records)
}

pub(super) async fn invalidate(
    client: &DnsMgrClient,
    zone_id: u64,
    mutation: Option<&DnsMgrRecordMutation>,
    record_id: Option<&str>,
) {
    let Some(context) = current() else {
        return;
    };
    let mut context = context.lock().await;
    let zone = context
        .zones
        .entry((client.observation_identity(), zone_id))
        .or_default();
    let key = mutation
        .map(|m| record_key(&m.host, &ProviderLine::from_provider(&m.line, None)))
        .or_else(|| {
            let records = zone
                .inventory
                .iter()
                .flatten()
                .chain(zone.changes.values().flat_map(|(_, r)| r.iter().flatten()));
            records
                .into_iter()
                .find(|r| Some(r.record_id.as_str()) == record_id)
                .map(|r| {
                    record_key(
                        &r.host,
                        &ProviderLine::from_provider(&r.line, r.line_name.as_deref()),
                    )
                })
        });
    if let Some(key) = key {
        let generation = zone.changes.get(&key).map(|(v, _)| *v).unwrap_or(0) + 1;
        zone.changes.insert(key, (generation, None));
    } else {
        // Never guess the affected RRset when a record ID is unknown.
        zone.epoch += 1;
        zone.inventory = None;
        zone.changes.clear();
    }
}

// A complete paginated inventory must not race this process's own writes.
// Writes take the shared side (up to four); only full-zone reads are exclusive.
#[derive(Default)]
struct ZoneFence {
    gate: RwLock<()>,
    generation: std::sync::atomic::AtomicU64,
}
type ZoneFences = HashMap<ZoneKey, Weak<ZoneFence>>;
static ZONE_FENCES: OnceLock<StdMutex<ZoneFences>> = OnceLock::new();

async fn zone_fence(client: &DnsMgrClient, zone_id: u64) -> Arc<ZoneFence> {
    let key = (client.observation_identity(), zone_id);
    let fence = {
        let mut fences = ZONE_FENCES
            .get_or_init(|| StdMutex::new(HashMap::new()))
            .lock()
            .unwrap();
        fences.retain(|_, weak| weak.strong_count() > 0);
        let fence = fences
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::new(ZoneFence::default()));
        fences.insert(key.clone(), Arc::downgrade(&fence));
        fence
    };
    if let Some(context) = current() {
        context.lock().await.zones.entry(key).or_default().fence = Some(fence.clone());
    }
    fence
}

/// Full snapshots coalesce only while no intervening mutation has occurred.
/// For an absence check they must have completed AFTER the filtered request
/// began, so a prewrite snapshot can never serve as post-mutation readback.
pub(super) async fn complete_zone_inventory(
    client: &DnsMgrClient,
    zone: &ResolvedZone,
    not_before: Option<std::time::Instant>,
) -> Result<Vec<DnsMgrRecord>, DnsMgrError> {
    let fence = zone_fence(client, zone.domain_id).await;
    let _inventory = fence.gate.write().await;
    let generation = fence.generation.load(std::sync::atomic::Ordering::SeqCst);
    let key = (client.observation_identity(), zone.domain_id);
    if let Some(context) = current() {
        let state = context.lock().await;
        if let Some(observed) = state.zones.get(&key) {
            if let Some((stamp, completed, records)) = &observed.fresh_inventory {
                if *stamp == generation && not_before.is_none_or(|start| *completed >= start) {
                    return Ok(records.clone());
                }
            }
        }
    }
    let inventory = fetch_record_inventory(client, zone, None).await?;
    if !inventory.complete {
        return Err(incomplete());
    }
    if let Some(context) = current() {
        context
            .lock()
            .await
            .zones
            .entry(key)
            .or_default()
            .fresh_inventory = Some((
            generation,
            std::time::Instant::now(),
            inventory.records.clone(),
        ));
    }
    Ok(inventory.records)
}

// Scope the guard across the mutation and account for both accepted and unknown outcomes.
pub(super) async fn mutation<F: Future>(
    client: &DnsMgrClient,
    zone_id: u64,
    future: F,
) -> F::Output {
    let fence = zone_fence(client, zone_id).await;
    let _mutation = fence.gate.read().await;
    fence
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let result = future.await;
    fence
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    result
}

static DESIRED_FENCE: RwLock<()> = RwLock::const_new(());
pub(super) async fn executing() -> tokio::sync::RwLockReadGuard<'static, ()> {
    DESIRED_FENCE.read().await
}
pub(super) async fn changing_desired() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    DESIRED_FENCE.write().await
}

type RecordLocks = HashMap<(String, String, String), Weak<Mutex<()>>>;
static RECORD_LOCKS: OnceLock<StdMutex<RecordLocks>> = OnceLock::new();
pub(super) fn execution_key(
    fqdn: &str,
    record_type: &str,
    line: &ProviderLine,
) -> (String, String, String) {
    (
        fqdn.trim().trim_end_matches('.').to_ascii_lowercase(),
        record_type.to_ascii_uppercase(),
        line.key.clone(),
    )
}

pub(super) async fn lock_record(
    fqdn: &str,
    record_type: &str,
    line: &ProviderLine,
) -> OwnedMutexGuard<()> {
    let key = execution_key(fqdn, record_type, line);
    let mutex = {
        let mut locks = RECORD_LOCKS
            .get_or_init(|| StdMutex::new(HashMap::new()))
            .lock()
            .unwrap();
        locks.retain(|_, weak| weak.strong_count() > 0);
        let mutex = locks
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| Arc::new(Mutex::new(())));
        locks.insert(key, Arc::downgrade(&mutex));
        mutex
    };
    mutex.lock_owned().await
}
