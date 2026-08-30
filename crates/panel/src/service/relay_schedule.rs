//! Persistent scheduled Relay switch definitions.
//!
//! S1 deliberately owns only persistence and validation. Execution belongs to
//! a later scheduler stage; creating or editing a schedule never starts a
//! Relay switch and never touches DNS.

use crate::api::ws::NodeConnections;
use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, Repository, ResourceScope};
use chrono::DateTime;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const RELAY_SWITCH_SCHEDULES_KEY: &str = "relay_switch_schedules:v1";

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
