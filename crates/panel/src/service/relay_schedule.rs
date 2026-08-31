//! 持久化的 Relay 定时切换计划。
//!
//! S1 只负责持久化和校验。S2 的执行器只计算时间槽、领取计划并调用现有
//! Relay 切换入口；它不复制 Ready、DNS 或 rollback 状态机。

use crate::api::ws::NodeConnections;
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use crate::service::relay_preference::{StartRelaySwitchError, StartRelaySwitchOutcome};
use chrono::{DateTime, Datelike, FixedOffset, SecondsFormat, TimeZone, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

pub const RELAY_SWITCH_SCHEDULES_KEY: &str = "relay_switch_schedules:v1";
const RELAY_SCHEDULE_TICK: Duration = Duration::from_secs(30);
const RELAY_SCHEDULE_GRACE: chrono::Duration = chrono::Duration::seconds(120);

static RELAY_SCHEDULE_MUTATION_LOCK: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayScheduleType {
    OneTime,
    Daily,
    Weekly,
}

impl RelayScheduleType {
    fn parse(value: &str) -> Result<Self, RelayScheduleError> {
        match value.trim() {
            "one_time" => Ok(Self::OneTime),
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            _ => Err(RelayScheduleError::InvalidInput(
                "schedule_type must be one_time, daily, or weekly".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySchedule {
    pub id: String,
    pub group_id: i64,
    pub target_node_id: String,
    pub schedule_type: RelayScheduleType,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub execute_at: Option<String>,
    pub time: Option<String>,
    pub utc_offset_minutes: Option<i32>,
    pub weekdays: Vec<u8>,
    pub last_run_at: Option<String>,
    pub last_run_slot: Option<String>,
    pub last_result: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRelayScheduleRequest {
    pub group_id: i64,
    pub target_node_id: String,
    pub schedule_type: String,
    pub enabled: Option<bool>,
    pub execute_at: Option<String>,
    pub time: Option<String>,
    pub utc_offset_minutes: Option<i32>,
    pub weekdays: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRelayScheduleRequest {
    pub target_node_id: Option<String>,
    pub schedule_type: Option<String>,
    pub enabled: Option<bool>,
    pub execute_at: Option<String>,
    pub time: Option<String>,
    pub utc_offset_minutes: Option<i32>,
    pub weekdays: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum RelayScheduleError {
    Database(DbError),
    InvalidStoredData(String),
    InvalidInput(String),
    GroupNotFound,
    GroupNotRelayInbound,
    TargetNodeNotFound,
    ScheduleNotFound,
}

impl fmt::Display for RelayScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database error: {error}"),
            Self::InvalidStoredData(error) => write!(f, "stored schedule data is invalid: {error}"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::GroupNotFound => f.write_str("inbound group not found"),
            Self::GroupNotRelayInbound => f.write_str("group is not an inbound Relay group"),
            Self::TargetNodeNotFound => f.write_str("target Node is not known in this group"),
            Self::ScheduleNotFound => f.write_str("schedule not found"),
        }
    }
}

impl std::error::Error for RelayScheduleError {}

impl From<DbError> for RelayScheduleError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug)]
struct NormalizedFields {
    schedule_type: RelayScheduleType,
    execute_at: Option<String>,
    time: Option<String>,
    utc_offset_minutes: Option<i32>,
    weekdays: Vec<u8>,
}

fn normalize_fields(
    schedule_type: RelayScheduleType,
    execute_at: Option<&str>,
    time: Option<&str>,
    utc_offset_minutes: Option<i32>,
    weekdays: Option<&[u8]>,
) -> Result<NormalizedFields, RelayScheduleError> {
    match schedule_type {
        RelayScheduleType::OneTime => {
            let execute_at = execute_at
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    RelayScheduleError::InvalidInput(
                        "one_time requires an RFC3339 execute_at".into(),
                    )
                })?;
            DateTime::parse_from_rfc3339(execute_at).map_err(|_| {
                RelayScheduleError::InvalidInput("execute_at must be RFC3339".into())
            })?;
            Ok(NormalizedFields {
                schedule_type,
                execute_at: Some(execute_at.to_string()),
                time: None,
                utc_offset_minutes: None,
                weekdays: Vec::new(),
            })
        }
        RelayScheduleType::Daily | RelayScheduleType::Weekly => {
            let time = time
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    RelayScheduleError::InvalidInput(
                        "daily and weekly require time in HH:MM".into(),
                    )
                })?;
            validate_time(time)?;

            let utc_offset_minutes = utc_offset_minutes.ok_or_else(|| {
                RelayScheduleError::InvalidInput(
                    "daily and weekly require utc_offset_minutes".into(),
                )
            })?;
            if !(-14 * 60..=14 * 60).contains(&utc_offset_minutes) {
                return Err(RelayScheduleError::InvalidInput(
                    "utc_offset_minutes must be between -840 and 840".into(),
                ));
            }

            let normalized_weekdays = match schedule_type {
                RelayScheduleType::Daily => Vec::new(),
                RelayScheduleType::Weekly => {
                    let mut days = weekdays.map(|values| values.to_vec()).ok_or_else(|| {
                        RelayScheduleError::InvalidInput(
                            "weekly requires at least one weekday".into(),
                        )
                    })?;
                    if days.is_empty() || days.iter().any(|day| !(1..=7).contains(day)) {
                        return Err(RelayScheduleError::InvalidInput(
                            "weekly weekdays must contain values from 1 to 7".into(),
                        ));
                    }
                    days.sort_unstable();
                    days.dedup();
                    days
                }
                RelayScheduleType::OneTime => unreachable!(),
            };

            Ok(NormalizedFields {
                schedule_type,
                execute_at: None,
                time: Some(time.to_string()),
                utc_offset_minutes: Some(utc_offset_minutes),
                weekdays: normalized_weekdays,
            })
        }
    }
}

fn validate_time(value: &str) -> Result<(), RelayScheduleError> {
    let Some((hour, minute)) = value.split_once(':') else {
        return Err(RelayScheduleError::InvalidInput(
            "time must use HH:MM".into(),
        ));
    };
    if hour.len() != 2 || minute.len() != 2 {
        return Err(RelayScheduleError::InvalidInput(
            "time must use HH:MM".into(),
        ));
    }
    let hour = hour
        .parse::<u8>()
        .map_err(|_| RelayScheduleError::InvalidInput("time must use HH:MM".into()))?;
    let minute = minute
        .parse::<u8>()
        .map_err(|_| RelayScheduleError::InvalidInput("time must use HH:MM".into()))?;
    if hour > 23 || minute > 59 {
        return Err(RelayScheduleError::InvalidInput(
            "time must be between 00:00 and 23:59".into(),
        ));
    }
    Ok(())
}

async fn load_schedules(db: &dyn Repository) -> Result<Vec<RelaySchedule>, RelayScheduleError> {
    let Some(raw) = db.get(RELAY_SWITCH_SCHEDULES_KEY).await? else {
        return Ok(Vec::new());
    };
    serde_json::from_str(&raw)
        .map_err(|error| RelayScheduleError::InvalidStoredData(error.to_string()))
}

async fn save_schedules(
    db: &dyn Repository,
    schedules: &[RelaySchedule],
) -> Result<(), RelayScheduleError> {
    let raw = serde_json::to_string(schedules)
        .map_err(|error| RelayScheduleError::InvalidStoredData(error.to_string()))?;
    db.set(RELAY_SWITCH_SCHEDULES_KEY, &raw).await?;
    Ok(())
}

async fn validate_group_and_target(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    group_id: i64,
    target_node_id: &str,
) -> Result<String, RelayScheduleError> {
    let target_node_id = target_node_id.trim();
    if target_node_id.is_empty() {
        return Err(RelayScheduleError::InvalidInput(
            "target_node_id must not be empty".into(),
        ));
    }

    match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(group) if group.group_type == "in" => {}
        Some(_) => return Err(RelayScheduleError::GroupNotRelayInbound),
        None => return Err(RelayScheduleError::GroupNotFound),
    }

    let prefix = format!("node_status:{group_id}:");
    let has_status = db
        .scan_prefix(&prefix)
        .await?
        .iter()
        .any(|(key, _)| key.strip_prefix(&prefix) == Some(target_node_id));
    let online_nodes = node_connections.online_node_ids(group_id).await;
    if !has_status && !online_nodes.contains(target_node_id) {
        return Err(RelayScheduleError::TargetNodeNotFound);
    }
    Ok(target_node_id.to_string())
}

pub async fn list_schedules(db: &dyn Repository) -> Result<Vec<RelaySchedule>, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    load_schedules(db).await
}

pub async fn create_schedule(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    request: CreateRelayScheduleRequest,
) -> Result<RelaySchedule, RelayScheduleError> {
    let target_node_id = validate_group_and_target(
        db,
        node_connections,
        request.group_id,
        &request.target_node_id,
    )
    .await?;
    let fields = normalize_fields(
        RelayScheduleType::parse(&request.schedule_type)?,
        request.execute_at.as_deref(),
        request.time.as_deref(),
        request.utc_offset_minutes,
        request.weekdays.as_deref(),
    )?;

    let now = chrono::Utc::now().to_rfc3339();
    let schedule = RelaySchedule {
        id: uuid::Uuid::new_v4().to_string(),
        group_id: request.group_id,
        target_node_id,
        schedule_type: fields.schedule_type,
        enabled: request.enabled.unwrap_or(true),
        created_at: now.clone(),
        updated_at: now,
        execute_at: fields.execute_at,
        time: fields.time,
        utc_offset_minutes: fields.utc_offset_minutes,
        weekdays: fields.weekdays,
        last_run_at: None,
        last_run_slot: None,
        last_result: None,
        last_error: None,
    };

    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    schedules.push(schedule.clone());
    save_schedules(db, &schedules).await?;
    Ok(schedule)
}

pub async fn update_schedule(
    db: &dyn Repository,
    node_connections: &NodeConnections,
    id: &str,
    request: UpdateRelayScheduleRequest,
) -> Result<RelaySchedule, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let schedule = schedules
        .iter_mut()
        .find(|schedule| schedule.id == id)
        .ok_or(RelayScheduleError::ScheduleNotFound)?;

    let target_node_id = validate_group_and_target(
        db,
        node_connections,
        schedule.group_id,
        request
            .target_node_id
            .as_deref()
            .unwrap_or(&schedule.target_node_id),
    )
    .await?;
    let schedule_type = match request.schedule_type.as_deref() {
        Some(value) => RelayScheduleType::parse(value)?,
        None => schedule.schedule_type.clone(),
    };
    let fields = normalize_fields(
        schedule_type,
        request
            .execute_at
            .as_deref()
            .or(schedule.execute_at.as_deref()),
        request.time.as_deref().or(schedule.time.as_deref()),
        request.utc_offset_minutes.or(schedule.utc_offset_minutes),
        request
            .weekdays
            .as_deref()
            .or(Some(schedule.weekdays.as_slice())),
    )?;

    schedule.target_node_id = target_node_id;
    schedule.schedule_type = fields.schedule_type;
    if let Some(enabled) = request.enabled {
        schedule.enabled = enabled;
    }
    schedule.updated_at = chrono::Utc::now().to_rfc3339();
    schedule.execute_at = fields.execute_at;
    schedule.time = fields.time;
    schedule.utc_offset_minutes = fields.utc_offset_minutes;
    schedule.weekdays = fields.weekdays;

    let updated = schedule.clone();
    save_schedules(db, &schedules).await?;
    Ok(updated)
}

pub async fn delete_schedule(db: &dyn Repository, id: &str) -> Result<bool, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let original_len = schedules.len();
    schedules.retain(|schedule| schedule.id != id);
    if schedules.len() == original_len {
        return Ok(false);
    }
    save_schedules(db, &schedules).await?;
    Ok(true)
}

pub async fn delete_schedules_for_group(
    db: &dyn Repository,
    group_id: i64,
) -> Result<usize, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let original_len = schedules.len();
    schedules.retain(|schedule| schedule.group_id != group_id);
    let removed_count = original_len - schedules.len();
    if removed_count > 0 {
        save_schedules(db, &schedules).await?;
    }
    Ok(removed_count)
}

pub async fn set_schedule_enabled(
    db: &dyn Repository,
    id: &str,
    enabled: bool,
) -> Result<RelaySchedule, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let schedule = schedules
        .iter_mut()
        .find(|schedule| schedule.id == id)
        .ok_or(RelayScheduleError::ScheduleNotFound)?;
    schedule.enabled = enabled;
    schedule.updated_at = chrono::Utc::now().to_rfc3339();
    let updated = schedule.clone();
    save_schedules(db, &schedules).await?;
    Ok(updated)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OccurrenceDisposition {
    Due,
    Missed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduleOccurrence {
    slot: String,
    disposition: OccurrenceDisposition,
}

fn canonical_slot(prefix: &str, occurrence: DateTime<Utc>) -> String {
    format!(
        "{prefix}:{}",
        occurrence.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    )
}

fn parse_schedule_time(value: &str) -> Result<chrono::NaiveTime, RelayScheduleError> {
    validate_time(value)?;
    chrono::NaiveTime::parse_from_str(value, "%H:%M")
        .map_err(|_| RelayScheduleError::InvalidInput("time must use HH:MM".into()))
}

fn fixed_offset(minutes: i32) -> Result<FixedOffset, RelayScheduleError> {
    FixedOffset::east_opt(minutes * 60).ok_or_else(|| {
        RelayScheduleError::InvalidInput("utc_offset_minutes is outside the valid range".into())
    })
}

fn occurrence_for(
    schedule: &RelaySchedule,
    now: DateTime<Utc>,
) -> Result<Option<ScheduleOccurrence>, RelayScheduleError> {
    if !schedule.enabled {
        return Ok(None);
    }

    match schedule.schedule_type {
        RelayScheduleType::OneTime => {
            let execute_at = schedule.execute_at.as_deref().ok_or_else(|| {
                RelayScheduleError::InvalidStoredData("one_time has no execute_at".into())
            })?;
            let occurrence = DateTime::parse_from_rfc3339(execute_at)
                .map_err(|_| {
                    RelayScheduleError::InvalidStoredData(
                        "one_time execute_at is not RFC3339".into(),
                    )
                })?
                .with_timezone(&Utc);
            let slot = canonical_slot("one_time", occurrence);
            if now < occurrence {
                return Ok(None);
            }
            if now <= occurrence + RELAY_SCHEDULE_GRACE {
                return Ok(Some(ScheduleOccurrence {
                    slot,
                    disposition: OccurrenceDisposition::Due,
                }));
            }
            Ok(Some(ScheduleOccurrence {
                slot,
                disposition: OccurrenceDisposition::Missed,
            }))
        }
        RelayScheduleType::Daily | RelayScheduleType::Weekly => {
            let time = schedule.time.as_deref().ok_or_else(|| {
                RelayScheduleError::InvalidStoredData("recurring schedule has no time".into())
            })?;
            let local_time = parse_schedule_time(time)?;
            let offset_minutes = schedule.utc_offset_minutes.ok_or_else(|| {
                RelayScheduleError::InvalidStoredData(
                    "recurring schedule has no utc_offset_minutes".into(),
                )
            })?;
            let offset = fixed_offset(offset_minutes)?;
            let local_now = now.with_timezone(&offset);
            let local_date = local_now.date_naive();
            if schedule.schedule_type == RelayScheduleType::Weekly
                && !schedule
                    .weekdays
                    .contains(&(local_date.weekday().number_from_monday() as u8))
            {
                return Ok(None);
            }
            let local_occurrence = local_date.and_time(local_time);
            let occurrence = offset
                .from_local_datetime(&local_occurrence)
                .single()
                .expect("FixedOffset has one local datetime")
                .with_timezone(&Utc);
            if now < occurrence || now > occurrence + RELAY_SCHEDULE_GRACE {
                return Ok(None);
            }
            let prefix = if schedule.schedule_type == RelayScheduleType::Daily {
                "daily"
            } else {
                "weekly"
            };
            Ok(Some(ScheduleOccurrence {
                slot: canonical_slot(prefix, occurrence),
                disposition: OccurrenceDisposition::Due,
            }))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwitchResult {
    last_result: String,
    last_error: Option<String>,
}

type SwitchFuture = Pin<Box<dyn Future<Output = SwitchResult> + Send>>;
type SwitchStarter = Arc<dyn Fn(i64, String) -> SwitchFuture + Send + Sync>;

fn map_switch_result(
    result: Result<StartRelaySwitchOutcome, StartRelaySwitchError>,
) -> SwitchResult {
    match result {
        Ok(StartRelaySwitchOutcome::Started { .. }) => SwitchResult {
            last_result: "started".into(),
            last_error: None,
        },
        Ok(StartRelaySwitchOutcome::AlreadyPreferred) => SwitchResult {
            last_result: "already_preferred".into(),
            last_error: None,
        },
        Ok(StartRelaySwitchOutcome::AlreadySwitching) => SwitchResult {
            last_result: "busy".into(),
            last_error: None,
        },
        Err(error @ StartRelaySwitchError::SwitchInProgress { .. }) => SwitchResult {
            last_result: "busy".into(),
            last_error: Some(error.to_string()),
        },
        Err(error @ StartRelaySwitchError::TargetNotReady(_)) => SwitchResult {
            last_result: "target_not_ready".into(),
            last_error: Some(error.to_string()),
        },
        Err(error) => SwitchResult {
            last_result: "failed".into(),
            last_error: Some(error.to_string()),
        },
    }
}

fn production_switch_starter(
    db: Arc<dyn Repository>,
    node_connections: NodeConnections,
) -> SwitchStarter {
    Arc::new(move |group_id, target_node_id| {
        let db = db.clone();
        let node_connections = node_connections.clone();
        Box::pin(async move {
            map_switch_result(
                crate::service::relay_preference::start_relay_switch(
                    db.as_ref(),
                    &node_connections,
                    group_id,
                    &target_node_id,
                )
                .await,
            )
        })
    })
}

#[derive(Debug, Clone)]
struct ClaimedSchedule {
    id: String,
    group_id: i64,
    target_node_id: String,
    occurrence: ScheduleOccurrence,
    updated_at: String,
}

async fn claim_schedule(
    db: &dyn Repository,
    schedule_id: &str,
    occurrence: &ScheduleOccurrence,
    now: DateTime<Utc>,
) -> Result<Option<ClaimedSchedule>, RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let Some(schedule) = schedules
        .iter_mut()
        .find(|schedule| schedule.id == schedule_id)
    else {
        return Ok(None);
    };
    if !schedule.enabled || schedule.last_run_slot.as_deref() == Some(occurrence.slot.as_str()) {
        return Ok(None);
    }
    let Some(current_occurrence) = occurrence_for(schedule, now)? else {
        return Ok(None);
    };
    if current_occurrence != *occurrence {
        return Ok(None);
    }

    schedule.last_run_at = Some(now.to_rfc3339());
    schedule.last_run_slot = Some(occurrence.slot.clone());
    schedule.last_result = None;
    schedule.last_error = None;
    if schedule.schedule_type == RelayScheduleType::OneTime {
        schedule.enabled = false;
    }
    if occurrence.disposition == OccurrenceDisposition::Missed {
        schedule.enabled = false;
        schedule.last_result = Some("missed".into());
        schedule.last_error = Some("超过执行宽限窗口，未补执行".into());
    }
    schedule.updated_at = now.to_rfc3339();
    let claim = ClaimedSchedule {
        id: schedule.id.clone(),
        group_id: schedule.group_id,
        target_node_id: schedule.target_node_id.clone(),
        occurrence: occurrence.clone(),
        updated_at: schedule.updated_at.clone(),
    };
    save_schedules(db, &schedules).await?;
    Ok(Some(claim))
}

async fn finalize_claim(
    db: &dyn Repository,
    claim: &ClaimedSchedule,
    result: SwitchResult,
) -> Result<(), RelayScheduleError> {
    let _guard = RELAY_SCHEDULE_MUTATION_LOCK.lock().await;
    let mut schedules = load_schedules(db).await?;
    let Some(schedule) = schedules
        .iter_mut()
        .find(|schedule| schedule.id == claim.id)
    else {
        return Ok(());
    };
    if schedule.last_run_slot.as_deref() != Some(claim.occurrence.slot.as_str())
        || schedule.updated_at != claim.updated_at
    {
        return Ok(());
    }
    schedule.last_result = Some(result.last_result);
    schedule.last_error = result.last_error;
    schedule.updated_at = Utc::now().to_rfc3339();
    save_schedules(db, &schedules).await
}

async fn run_scheduler_once_with(
    db: &dyn Repository,
    now: DateTime<Utc>,
    starter: SwitchStarter,
) -> Result<(), RelayScheduleError> {
    let snapshot = list_schedules(db).await?;
    for schedule in snapshot {
        let Some(occurrence) = (match occurrence_for(&schedule, now) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(schedule_id = %schedule.id, "跳过无效 Relay 定时计划: {error}");
                continue;
            }
        }) else {
            continue;
        };
        let Some(claim) = claim_schedule(db, &schedule.id, &occurrence, now).await? else {
            continue;
        };
        if claim.occurrence.disposition == OccurrenceDisposition::Missed {
            continue;
        }
        let result = starter(claim.group_id, claim.target_node_id.clone()).await;
        if let Err(error) = finalize_claim(db, &claim, result).await {
            tracing::error!(schedule_id = %claim.id, "保存 Relay 定时计划执行结果失败: {error}");
        }
    }
    Ok(())
}

/// 启动 Panel 内部的定时 Relay 计划检查。首个 tick 立即执行，之后每 30 秒
/// 检查一次；执行本身始终复用现有 Relay Preference 切换入口。
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let starter = production_switch_starter(state.db.clone(), state.node_connections.clone());
        let mut ticker = tokio::time::interval(RELAY_SCHEDULE_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!("Relay schedule scheduler started (tick 30s)");
        ticker.tick().await;
        loop {
            if let Err(error) =
                run_scheduler_once_with(state.db.as_ref(), Utc::now(), starter.clone()).await
            {
                tracing::error!("Relay schedule scheduler tick failed: {error}");
            }
            ticker.tick().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ws::NodeConnections;
    use crate::db::repo::{GroupRepository, KvsRepository};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_repo() -> SqliteRepository {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let repo = SqliteRepository::new(pool);
        repo.insert_group("relay", "in", "token", 1, "", "1000-1001", 1.0, false)
            .await
            .unwrap();
        repo.set("node_status:1:node-a", "{}").await.unwrap();
        repo
    }

    fn one_time_request() -> CreateRelayScheduleRequest {
        CreateRelayScheduleRequest {
            group_id: 1,
            target_node_id: "node-a".into(),
            schedule_type: "one_time".into(),
            enabled: None,
            execute_at: Some("2026-09-01T12:00:00Z".into()),
            time: None,
            utc_offset_minutes: None,
            weekdays: None,
        }
    }

    fn utc(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn one_time_schedule(execute_at: &str) -> RelaySchedule {
        RelaySchedule {
            id: "schedule-1".into(),
            group_id: 1,
            target_node_id: "node-a".into(),
            schedule_type: RelayScheduleType::OneTime,
            enabled: true,
            created_at: "2026-08-30T00:00:00Z".into(),
            updated_at: "2026-08-30T00:00:00Z".into(),
            execute_at: Some(execute_at.into()),
            time: None,
            utc_offset_minutes: None,
            weekdays: Vec::new(),
            last_run_at: None,
            last_run_slot: None,
            last_result: None,
            last_error: None,
        }
    }

    fn recurring_schedule(
        schedule_type: RelayScheduleType,
        time: &str,
        utc_offset_minutes: i32,
        weekdays: Vec<u8>,
    ) -> RelaySchedule {
        RelaySchedule {
            id: "schedule-1".into(),
            group_id: 1,
            target_node_id: "node-a".into(),
            schedule_type,
            enabled: true,
            created_at: "2026-08-30T00:00:00Z".into(),
            updated_at: "2026-08-30T00:00:00Z".into(),
            execute_at: None,
            time: Some(time.into()),
            utc_offset_minutes: Some(utc_offset_minutes),
            weekdays,
            last_run_at: None,
            last_run_slot: None,
            last_result: None,
            last_error: None,
        }
    }

    async fn put_schedule(repo: &SqliteRepository, schedule: &RelaySchedule) {
        repo.set(
            RELAY_SWITCH_SCHEDULES_KEY,
            &serde_json::to_string(std::slice::from_ref(schedule)).unwrap(),
        )
        .await
        .unwrap();
    }

    async fn put_schedules(repo: &SqliteRepository, schedules: &[RelaySchedule]) {
        repo.set(
            RELAY_SWITCH_SCHEDULES_KEY,
            &serde_json::to_string(schedules).unwrap(),
        )
        .await
        .unwrap();
    }

    fn recording_starter(
        calls: std::sync::Arc<std::sync::Mutex<Vec<(i64, String)>>>,
        result: SwitchResult,
    ) -> SwitchStarter {
        std::sync::Arc::new(move |group_id, target_node_id| {
            let calls = calls.clone();
            let result = result.clone();
            Box::pin(async move {
                calls.lock().unwrap().push((group_id, target_node_id));
                result
            })
        })
    }

    #[test]
    fn one_time_occurrence_respects_before_due_grace_and_missed_windows() {
        let schedule = one_time_schedule("2026-08-30T12:00:00Z");
        assert!(occurrence_for(&schedule, utc("2026-08-30T11:59:59Z"))
            .unwrap()
            .is_none());
        assert_eq!(
            occurrence_for(&schedule, utc("2026-08-30T12:00:03Z"))
                .unwrap()
                .unwrap(),
            ScheduleOccurrence {
                slot: "one_time:2026-08-30T12:00:00Z".into(),
                disposition: OccurrenceDisposition::Due,
            }
        );
        assert_eq!(
            occurrence_for(&schedule, utc("2026-08-30T12:02:01Z"))
                .unwrap()
                .unwrap()
                .disposition,
            OccurrenceDisposition::Missed
        );
    }

    #[test]
    fn daily_occurrence_uses_positive_negative_offsets_and_utc_boundaries() {
        let utc_plus_eight = recurring_schedule(RelayScheduleType::Daily, "08:00", 480, vec![]);
        assert_eq!(
            occurrence_for(&utc_plus_eight, utc("2026-08-30T00:00:03Z"))
                .unwrap()
                .unwrap()
                .slot,
            "daily:2026-08-30T00:00:00Z"
        );

        let utc_minus_five = recurring_schedule(RelayScheduleType::Daily, "03:00", -300, vec![]);
        assert_eq!(
            occurrence_for(&utc_minus_five, utc("2026-08-30T08:00:30Z"))
                .unwrap()
                .unwrap()
                .slot,
            "daily:2026-08-30T08:00:00Z"
        );

        let boundary = recurring_schedule(RelayScheduleType::Daily, "01:30", 120, vec![]);
        assert_eq!(
            occurrence_for(&boundary, utc("2026-08-30T23:30:30Z"))
                .unwrap()
                .unwrap()
                .slot,
            "daily:2026-08-30T23:30:00Z"
        );
    }

    #[test]
    fn weekly_occurrence_requires_local_weekday_and_keeps_canonical_slot() {
        let schedule = recurring_schedule(RelayScheduleType::Weekly, "08:00", 0, vec![1]);
        let monday = utc("2026-08-31T08:00:03Z");
        let later_same_slot = utc("2026-08-31T08:01:01Z");
        assert_eq!(
            occurrence_for(&schedule, monday).unwrap().unwrap().slot,
            occurrence_for(&schedule, later_same_slot)
                .unwrap()
                .unwrap()
                .slot
        );
        assert!(occurrence_for(&schedule, utc("2026-09-01T08:00:03Z"))
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn scheduler_claims_once_persists_started_and_survives_restart() {
        let repo = test_repo().await;
        let schedule = one_time_schedule("2026-08-30T12:00:00Z");
        put_schedule(&repo, &schedule).await;
        let now = utc("2026-08-30T12:00:03Z");
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let starter = recording_starter(
            calls.clone(),
            SwitchResult {
                last_result: "started".into(),
                last_error: None,
            },
        );

        run_scheduler_once_with(&repo, now, starter).await.unwrap();
        assert_eq!(calls.lock().unwrap().as_slice(), &[(1, "node-a".into())]);
        let stored = list_schedules(&repo).await.unwrap();
        assert!(!stored[0].enabled);
        assert_eq!(
            stored[0].last_run_slot.as_deref(),
            Some("one_time:2026-08-30T12:00:00Z")
        );
        assert_eq!(stored[0].last_result.as_deref(), Some("started"));

        let restart_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        run_scheduler_once_with(
            &repo,
            now,
            recording_starter(
                restart_calls.clone(),
                SwitchResult {
                    last_result: "started".into(),
                    last_error: None,
                },
            ),
        )
        .await
        .unwrap();
        assert!(restart_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn disabled_schedule_is_not_executed() {
        let repo = test_repo().await;
        let mut schedule = one_time_schedule("2026-08-30T12:00:00Z");
        schedule.enabled = false;
        put_schedule(&repo, &schedule).await;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        run_scheduler_once_with(
            &repo,
            utc("2026-08-30T12:00:03Z"),
            recording_starter(
                calls.clone(),
                SwitchResult {
                    last_result: "started".into(),
                    last_error: None,
                },
            ),
        )
        .await
        .unwrap();
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missed_one_time_is_recorded_without_switch_and_recurring_stays_enabled() {
        let repo = test_repo().await;
        put_schedule(&repo, &one_time_schedule("2026-08-30T12:00:00Z")).await;
        let missed_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        run_scheduler_once_with(
            &repo,
            utc("2026-08-30T12:02:01Z"),
            recording_starter(
                missed_calls.clone(),
                SwitchResult {
                    last_result: "started".into(),
                    last_error: None,
                },
            ),
        )
        .await
        .unwrap();
        assert!(missed_calls.lock().unwrap().is_empty());
        let missed = list_schedules(&repo).await.unwrap().remove(0);
        assert!(!missed.enabled);
        assert_eq!(missed.last_result.as_deref(), Some("missed"));
        assert_eq!(
            missed.last_error.as_deref(),
            Some("超过执行宽限窗口，未补执行")
        );

        let recurring = recurring_schedule(RelayScheduleType::Daily, "08:00", 0, vec![]);
        put_schedule(&repo, &recurring).await;
        let recurring_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        run_scheduler_once_with(
            &repo,
            utc("2026-08-30T08:00:30Z"),
            recording_starter(
                recurring_calls,
                SwitchResult {
                    last_result: "already_preferred".into(),
                    last_error: None,
                },
            ),
        )
        .await
        .unwrap();
        assert!(list_schedules(&repo).await.unwrap()[0].enabled);
    }

    #[test]
    fn switch_results_map_to_stable_schedule_diagnostics() {
        assert_eq!(
            map_switch_result(Ok(StartRelaySwitchOutcome::AlreadyPreferred)),
            SwitchResult {
                last_result: "already_preferred".into(),
                last_error: None,
            }
        );
        assert_eq!(
            map_switch_result(Ok(StartRelaySwitchOutcome::AlreadySwitching)),
            SwitchResult {
                last_result: "busy".into(),
                last_error: None,
            }
        );
        assert_eq!(
            map_switch_result(Err(StartRelaySwitchError::SwitchInProgress {
                pending_node_id: Some("node-b".into()),
            }))
            .last_result,
            "busy"
        );
        assert_eq!(
            map_switch_result(Err(StartRelaySwitchError::TargetNotReady(vec![
                "STALE_STATUS".into(),
            ])))
            .last_result,
            "target_not_ready"
        );
        assert_eq!(
            map_switch_result(Err(StartRelaySwitchError::NoEligibleDnsRules)).last_result,
            "failed"
        );
    }

    #[tokio::test]
    async fn finalize_does_not_recreate_a_deleted_schedule() {
        let repo = test_repo().await;
        let schedule = one_time_schedule("2026-08-30T12:00:00Z");
        put_schedule(&repo, &schedule).await;
        let occurrence = occurrence_for(&schedule, utc("2026-08-30T12:00:03Z"))
            .unwrap()
            .unwrap();
        let claim = claim_schedule(
            &repo,
            &schedule.id,
            &occurrence,
            utc("2026-08-30T12:00:03Z"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(delete_schedule(&repo, &schedule.id).await.unwrap());
        finalize_claim(
            &repo,
            &claim,
            SwitchResult {
                last_result: "started".into(),
                last_error: None,
            },
        )
        .await
        .unwrap();
        assert!(list_schedules(&repo).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_group_schedules_keeps_other_groups() {
        let repo = test_repo().await;
        let mut first = one_time_schedule("2026-08-30T12:00:00Z");
        first.id = "group-10-a".into();
        first.group_id = 10;
        let mut second = one_time_schedule("2026-08-30T13:00:00Z");
        second.id = "group-10-b".into();
        second.group_id = 10;
        let mut other = one_time_schedule("2026-08-30T14:00:00Z");
        other.id = "group-20".into();
        other.group_id = 20;
        put_schedules(&repo, &[first, second, other.clone()]).await;

        assert_eq!(delete_schedules_for_group(&repo, 10).await.unwrap(), 2);
        assert_eq!(list_schedules(&repo).await.unwrap(), vec![other]);
    }

    #[tokio::test]
    async fn deleting_missing_group_schedules_does_not_rewrite_kvs() {
        let repo = test_repo().await;
        let schedule = one_time_schedule("2026-08-30T12:00:00Z");
        put_schedule(&repo, &schedule).await;
        let before = repo.get(RELAY_SWITCH_SCHEDULES_KEY).await.unwrap().unwrap();

        assert_eq!(delete_schedules_for_group(&repo, 999).await.unwrap(), 0);
        assert_eq!(
            repo.get(RELAY_SWITCH_SCHEDULES_KEY).await.unwrap(),
            Some(before)
        );
    }

    #[tokio::test]
    async fn crud_persists_schedule_without_executing_switch() {
        let repo = test_repo().await;
        let connections = NodeConnections::new();

        let created = create_schedule(&repo, &connections, one_time_request())
            .await
            .unwrap();
        assert!(created.enabled);
        assert_eq!(created.target_node_id, "node-a");
        assert!(created.last_run_at.is_none());
        assert_eq!(list_schedules(&repo).await.unwrap().len(), 1);

        let updated = update_schedule(
            &repo,
            &connections,
            &created.id,
            UpdateRelayScheduleRequest {
                target_node_id: None,
                schedule_type: Some("daily".into()),
                enabled: Some(false),
                execute_at: None,
                time: Some("08:30".into()),
                utc_offset_minutes: Some(480),
                weekdays: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(updated.schedule_type, RelayScheduleType::Daily);
        assert_eq!(updated.time.as_deref(), Some("08:30"));
        assert_eq!(updated.utc_offset_minutes, Some(480));
        assert!(!updated.enabled);
        assert!(updated.execute_at.is_none());

        let enabled = set_schedule_enabled(&repo, &created.id, true)
            .await
            .unwrap();
        assert!(enabled.enabled);
        assert!(delete_schedule(&repo, &created.id).await.unwrap());
        assert!(list_schedules(&repo).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn weekly_fields_are_sorted_and_deduplicated() {
        let repo = test_repo().await;
        let connections = NodeConnections::new();
        let mut request = one_time_request();
        request.schedule_type = "weekly".into();
        request.execute_at = None;
        request.time = Some("09:05".into());
        request.utc_offset_minutes = Some(-300);
        request.weekdays = Some(vec![7, 1, 7, 3]);

        let created = create_schedule(&repo, &connections, request).await.unwrap();
        assert_eq!(created.weekdays, vec![1, 3, 7]);
    }

    #[tokio::test]
    async fn invalid_schedule_and_unknown_target_are_rejected() {
        let repo = test_repo().await;
        let connections = NodeConnections::new();
        let mut invalid = one_time_request();
        invalid.schedule_type = "weekly".into();
        invalid.execute_at = None;
        invalid.time = Some("25:00".into());
        invalid.utc_offset_minutes = Some(0);
        invalid.weekdays = Some(vec![1]);
        assert!(matches!(
            create_schedule(&repo, &connections, invalid).await,
            Err(RelayScheduleError::InvalidInput(_))
        ));

        let mut unknown = one_time_request();
        unknown.target_node_id = "node-missing".into();
        assert!(matches!(
            create_schedule(&repo, &connections, unknown).await,
            Err(RelayScheduleError::TargetNodeNotFound)
        ));
    }

    #[tokio::test]
    async fn concurrent_creates_keep_both_kvs_rows() {
        let repo = std::sync::Arc::new(test_repo().await);
        let connections = NodeConnections::new();
        let first = create_schedule(&*repo, &connections, one_time_request());
        let mut second_request = one_time_request();
        second_request.execute_at = Some("2026-09-01T13:00:00Z".into());
        let second = create_schedule(&*repo, &connections, second_request);
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(list_schedules(&*repo).await.unwrap().len(), 2);
    }
}
