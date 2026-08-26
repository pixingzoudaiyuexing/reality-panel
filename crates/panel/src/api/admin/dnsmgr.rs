use super::err;
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::integrations::dnsmgr::{
    normalize_base_url, DnsMgrClient, DnsMgrClientConfig, DnsMgrError, DomainListParams,
};
use crate::service::dnsmgr::{DnsMgrSettings, DnsMgrSettingsPublic, DNSMGR_CONFIG_KEY};
use axum::extract::{Path, State};
use axum::Json;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};

async fn load(state: &AppState) -> Result<DnsMgrSettings, ()> {
    state
        .db
        .get(DNSMGR_CONFIG_KEY)
        .await
        .map(|raw| DnsMgrSettings::from_json(raw.as_deref()))
        .map_err(|error| {
            tracing::error!("dnsmgr settings: database read failed: {error}");
        })
}

async fn save(state: &AppState, settings: &DnsMgrSettings) -> Result<(), ()> {
    let json = serde_json::to_string(settings).map_err(|error| {
        tracing::error!("dnsmgr settings: serialization failed: {error}");
    })?;
    state
        .db
        .set(DNSMGR_CONFIG_KEY, &json)
        .await
        .map_err(|error| {
            tracing::error!("dnsmgr settings: database write failed: {error}");
        })
}

/// GET /api/v1/admin/settings/dnsmgr
pub async fn get_dnsmgr_settings(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<DnsMgrSettingsPublic>> {
    match load(&state).await {
        Ok(settings) => Json(ApiResponse::success(DnsMgrSettingsPublic::from(&settings))),
        Err(()) => Json(err(500, "数据库错误")),
    }
}

#[derive(Deserialize)]
pub struct UpdateDnsMgrSettingsRequest {
    pub enabled: bool,
    pub base_url: String,
    pub uid: u64,
    /// Omitted or empty means retain the stored key. Clearing requires a
    /// future explicit action so a masked browser field can never erase it.
    #[serde(default)]
    pub api_key: Option<String>,
}

/// PUT /api/v1/admin/settings/dnsmgr
pub async fn update_dnsmgr_settings(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<UpdateDnsMgrSettingsRequest>,
) -> Json<ApiResponse<DnsMgrSettingsPublic>> {
    let existing = match load(&state).await {
        Ok(settings) => settings,
        Err(()) => return Json(err(500, "数据库错误")),
    };
    let (settings, key_replaced) = match merge_settings(
        existing,
        req.enabled,
        Some(req.base_url),
        Some(req.uid),
        req.api_key,
    ) {
        Ok(value) => value,
        Err(()) => return Json(err(400, "DNSMgr 配置无效")),
    };
    if save(&state, &settings).await.is_err() {
        return Json(err(500, "数据库错误"));
    }

    let sync_result = if settings.enabled && settings.configured() {
        crate::service::dnsmgr::schedule_all_eligible(state.db.as_ref()).await
    } else {
        crate::service::dnsmgr::disable_all_syncs(state.db.as_ref())
            .await
            .map(|_| ())
    };
    if let Err(error) = sync_result {
        tracing::error!("update_dnsmgr_settings: DNS reconciliation scheduling failed: {error}");
    }

    let origin = audit_origin(&settings.base_url);
    tracing::info!(
        action = "DNSMGR_SETTINGS_UPDATED",
        enabled = settings.enabled,
        uid = settings.uid,
        origin = %origin,
        "DNSMgr settings updated"
    );
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "DNSMGR_SETTINGS_UPDATED",
        "settings",
        "dnsmgr",
        &format!(
            "enabled={} origin={} uid={} api_key={}",
            settings.enabled,
            origin,
            settings.uid,
            if key_replaced {
                "replaced"
            } else {
                "preserved"
            },
        ),
    )
    .await;

    Json(ApiResponse::success(DnsMgrSettingsPublic::from(&settings)))
}

#[derive(Deserialize, Default)]
pub struct TestDnsMgrConnectionRequest {
    /// Optional unsaved overrides let an administrator validate a candidate
    /// endpoint without replacing the stored configuration.
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub uid: Option<u64>,
    /// Never echoed, logged, or persisted by this endpoint.
    #[serde(default)]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnsMgrConnectionCategory {
    Ok,
    TransportError,
    Timeout,
    AuthOrPermissionDenied,
    UpstreamRejected,
    MalformedResponse,
    ContractError,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsMgrConnectionTestResult {
    pub category: DnsMgrConnectionCategory,
    /// Present only after a semantically valid domain inventory response.
    pub domain_count: Option<u64>,
    /// An empty inventory proves reachability and signing, not ownership of a
    /// particular zone. Later binding logic must verify ownership separately.
    pub empty_domain_list: bool,
    pub zone_ownership_verified: bool,
}

/// POST /api/v1/admin/settings/dnsmgr/test
pub async fn test_dnsmgr_connection(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<TestDnsMgrConnectionRequest>,
) -> Json<ApiResponse<DnsMgrConnectionTestResult>> {
    let existing = match load(&state).await {
        Ok(settings) => settings,
        Err(()) => return Json(err(500, "数据库错误")),
    };
    let (settings, _) = match merge_settings(existing, false, req.base_url, req.uid, req.api_key) {
        Ok(value) => value,
        Err(()) => {
            return audited_test_result(
                &state,
                admin.user_id,
                "unconfigured",
                None,
                DnsMgrConnectionTestResult {
                    category: DnsMgrConnectionCategory::ContractError,
                    domain_count: None,
                    empty_domain_list: false,
                    zone_ownership_verified: false,
                },
            )
            .await;
        }
    };

    let client =
        match DnsMgrClientConfig::new(&settings.base_url, settings.uid, settings.api_key.clone())
            .and_then(DnsMgrClient::new)
        {
            Ok(client) => client,
            Err(_) => {
                return audited_test_result(
                    &state,
                    admin.user_id,
                    &audit_origin(&settings.base_url),
                    Some(settings.uid),
                    DnsMgrConnectionTestResult {
                        category: DnsMgrConnectionCategory::ContractError,
                        domain_count: None,
                        empty_domain_list: false,
                        zone_ownership_verified: false,
                    },
                )
                .await;
            }
        };

    let result = match client.list_domains(&DomainListParams::default()).await {
        Ok(page) => DnsMgrConnectionTestResult {
            category: DnsMgrConnectionCategory::Ok,
            domain_count: Some(page.total),
            empty_domain_list: page.rows.is_empty(),
            zone_ownership_verified: false,
        },
        Err(error) => DnsMgrConnectionTestResult {
            category: connection_category(&error),
            domain_count: None,
            empty_domain_list: false,
            zone_ownership_verified: false,
        },
    };
    audited_test_result(
        &state,
        admin.user_id,
        &audit_origin(&settings.base_url),
        Some(settings.uid),
        result,
    )
    .await
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleDnsStatus {
    pub rule_id: i64,
    pub eligible: bool,
    pub automation_enabled: bool,
    pub fqdn: Option<String>,
    pub record_type: Option<String>,
    pub expected_value: Option<String>,
    pub ownership: String,
    pub sync_state: String,
    pub last_observed_at: Option<String>,
    pub mutation_verified_at: Option<String>,
    pub propagated_at: Option<String>,
    pub last_error_category: Option<String>,
    pub warning_category: Option<String>,
}

fn status_from_sync(
    rule_id: i64,
    automation_enabled: bool,
    desired: &crate::service::dnsmgr::DnsDesiredRecord,
    sync: Option<crate::db::repo::DnsRecordSync>,
) -> RuleDnsStatus {
    let matching = sync.filter(|sync| {
        sync.fqdn == desired.fqdn
            && sync.record_type == desired.record_type.as_str()
            && sync.expected_value == desired.expected_value
            && sync.line_key == desired.line.key
    });
    let ownership = matching
        .as_ref()
        .map(|sync| match sync.ownership.as_str() {
            "PANEL" => "PANEL_MANAGED",
            "EXTERNAL" => "EXTERNAL",
            _ => "NONE",
        })
        .unwrap_or("NONE")
        .to_string();
    let warning_category = matching
        .as_ref()
        .and_then(|sync| sync.last_error_category.as_deref())
        .filter(|category| *category == "PUBLIC_DNS_MULTIPLE_ANSWERS")
        .map(str::to_string);
    let last_error_category = matching
        .as_ref()
        .and_then(|sync| sync.last_error_category.clone())
        .filter(|category| category != "PUBLIC_DNS_MULTIPLE_ANSWERS");

    RuleDnsStatus {
        rule_id,
        eligible: true,
        automation_enabled,
        fqdn: Some(desired.fqdn.clone()),
        record_type: Some(desired.record_type.as_str().into()),
        expected_value: Some(desired.expected_value.clone()),
        ownership,
        sync_state: if !automation_enabled {
            "DISABLED".into()
        } else {
            matching
                .as_ref()
                .map(|sync| sync.state.clone())
                .unwrap_or_else(|| "PENDING".into())
        },
        last_observed_at: matching
            .as_ref()
            .and_then(|sync| sync.last_observed_at.clone()),
        mutation_verified_at: matching
            .as_ref()
            .and_then(|sync| sync.mutation_verified_at.clone()),
        propagated_at: matching
            .as_ref()
            .and_then(|sync| sync.propagated_at.clone()),
        last_error_category,
        warning_category,
    }
}

async fn project_rule_dns_status(
    state: &AppState,
    settings: &DnsMgrSettings,
    rule_id: i64,
) -> Result<RuleDnsStatus, crate::db::error::DbError> {
    let automation_enabled = settings.enabled && settings.configured();
    match crate::service::dnsmgr::derive_dns_desired(state.db.as_ref(), rule_id).await? {
        crate::service::dnsmgr::DnsDesiredResolution::NotEligible => Ok(RuleDnsStatus {
            rule_id,
            eligible: false,
            automation_enabled,
            fqdn: None,
            record_type: None,
            expected_value: None,
            ownership: "NONE".into(),
            sync_state: "NOT_ELIGIBLE".into(),
            last_observed_at: None,
            mutation_verified_at: None,
            propagated_at: None,
            last_error_category: None,
            warning_category: None,
        }),
        crate::service::dnsmgr::DnsDesiredResolution::Eligible(desired) => {
            let sync = state.db.find_dns_record_sync(rule_id).await?;
            Ok(status_from_sync(
                rule_id,
                automation_enabled,
                &desired,
                sync,
            ))
        }
        crate::service::dnsmgr::DnsDesiredResolution::ConfigurationError { desired, category } => {
            Ok(RuleDnsStatus {
                rule_id,
                eligible: true,
                automation_enabled,
                fqdn: desired.as_ref().map(|desired| desired.fqdn.clone()),
                record_type: desired
                    .as_ref()
                    .map(|desired| desired.record_type.as_str().into()),
                expected_value: desired.map(|desired| desired.expected_value),
                ownership: "NONE".into(),
                sync_state: "INVALID_CONFIG".into(),
                last_observed_at: None,
                mutation_verified_at: None,
                propagated_at: None,
                last_error_category: Some(category.into()),
                warning_category: None,
            })
        }
    }
}

/// GET /api/v1/admin/rules/dns-status
pub async fn list_rule_dns_statuses(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<RuleDnsStatus>>> {
    let settings = match load(&state).await {
        Ok(settings) => settings,
        Err(()) => return Json(err(500, "数据库错误")),
    };
    let rules = match state
        .db
        .list_rules(&crate::db::repo::ResourceScope::All)
        .await
    {
        Ok(rules) => rules,
        Err(error) => {
            tracing::error!("list_rule_dns_statuses: rule query failed: {error}");
            return Json(err(500, "数据库错误"));
        }
    };
    let mut statuses = Vec::with_capacity(rules.len());
    for rule in rules {
        match project_rule_dns_status(&state, &settings, rule.id).await {
            Ok(status) => statuses.push(status),
            Err(error) => {
                tracing::error!(
                    "list_rule_dns_statuses: projection failed for rule {}: {}",
                    rule.id,
                    error
                );
                return Json(err(500, "数据库错误"));
            }
        }
    }
    Json(ApiResponse::success(statuses))
}

/// POST /api/v1/admin/rules/{id}/dns/retry
pub async fn retry_rule_dns_sync(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(rule_id): Path<i64>,
) -> Json<ApiResponse<RuleDnsStatus>> {
    let settings = match load(&state).await {
        Ok(settings) => settings,
        Err(()) => return Json(err(500, "数据库错误")),
    };
    if !settings.enabled || !settings.configured() {
        return Json(err(409, "DNSMgr 自动化未启用或配置不完整"));
    }
    match crate::service::dnsmgr::derive_dns_desired(state.db.as_ref(), rule_id).await {
        Ok(crate::service::dnsmgr::DnsDesiredResolution::Eligible(_)) => {}
        Ok(crate::service::dnsmgr::DnsDesiredResolution::NotEligible) => {
            return Json(err(409, "规则不符合 DNS 自动化条件"));
        }
        Ok(crate::service::dnsmgr::DnsDesiredResolution::ConfigurationError { .. }) => {
            return Json(err(409, "规则 DNS 配置无效"));
        }
        Err(error) => {
            tracing::error!("retry_rule_dns_sync: desired-state lookup failed: {error}");
            return Json(err(500, "数据库错误"));
        }
    }
    let existing = match state.db.find_dns_record_sync(rule_id).await {
        Ok(sync) => sync,
        Err(error) => {
            tracing::error!("retry_rule_dns_sync: sync lookup failed: {error}");
            return Json(err(500, "数据库错误"));
        }
    };
    if existing.as_ref().is_some_and(|sync| {
        sync.state == "MUTATION_OUTCOME_UNKNOWN"
            || matches!(
                sync.last_error_category.as_deref(),
                Some("MUTATION_UNKNOWN" | "POST_WRITE_NOT_VERIFIED")
            )
    }) {
        return Json(err(409, "上次 DNS 写入结果未知，必须先人工核对上游记录"));
    }
    if let Err(error) = crate::service::dnsmgr::schedule_rule(state.db.as_ref(), rule_id).await {
        tracing::error!("retry_rule_dns_sync: scheduling failed: {error}");
        return Json(err(500, "数据库错误"));
    }
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "DNS_SYNC_MANUAL_RETRY",
        "rule",
        rule_id,
        "scheduled=true direct_provider_write=false",
    )
    .await;
    crate::service::dnsmgr::audit_sync_scheduled(&state, Some(admin.user_id), rule_id).await;

    match project_rule_dns_status(&state, &settings, rule_id).await {
        Ok(status) => Json(ApiResponse::success(status)),
        Err(error) => {
            tracing::error!("retry_rule_dns_sync: status projection failed: {error}");
            Json(err(500, "数据库错误"))
        }
    }
}

async fn audited_test_result(
    state: &AppState,
    actor_id: i64,
    origin: &str,
    uid: Option<u64>,
    result: DnsMgrConnectionTestResult,
) -> Json<ApiResponse<DnsMgrConnectionTestResult>> {
    tracing::info!(
        action = "DNSMGR_CONNECTION_TEST",
        origin = %origin,
        uid = ?uid,
        category = ?result.category,
        "DNSMgr connection test completed"
    );
    crate::service::audit::record(
        state,
        Some(actor_id),
        "DNSMGR_CONNECTION_TEST",
        "settings",
        "dnsmgr",
        &format!(
            "origin={} uid={} category={:?}",
            origin,
            uid.map(|value| value.to_string())
                .as_deref()
                .unwrap_or("none"),
            result.category,
        ),
    )
    .await;
    Json(ApiResponse::success(result))
}

fn merge_settings(
    mut existing: DnsMgrSettings,
    enabled: bool,
    base_url: Option<String>,
    uid: Option<u64>,
    api_key: Option<String>,
) -> Result<(DnsMgrSettings, bool), ()> {
    if let Some(base_url) = base_url {
        existing.base_url = normalize_base_url(base_url.trim()).map_err(|_| ())?;
    }
    if let Some(uid) = uid {
        existing.uid = uid;
    }
    let key_replaced = matches!(api_key.as_deref(), Some(key) if !key.trim().is_empty());
    if key_replaced {
        existing.api_key = api_key.unwrap().trim().to_string();
    }
    existing.enabled = enabled;

    // Constructing the real client config keeps settings validation exactly in
    // step with the signed transport client used by the connection test.
    DnsMgrClientConfig::new(&existing.base_url, existing.uid, existing.api_key.clone())
        .map_err(|_| ())?;
    Ok((existing, key_replaced))
}

fn connection_category(error: &DnsMgrError) -> DnsMgrConnectionCategory {
    match error {
        DnsMgrError::Transport(_) => DnsMgrConnectionCategory::TransportError,
        DnsMgrError::Timeout => DnsMgrConnectionCategory::Timeout,
        // DNSMgr uses HTTP 403 for both authentication failures and some API
        // access denials. Expose the stable combined category rather than
        // interpreting its human-readable response message.
        DnsMgrError::Authentication | DnsMgrError::Permission => {
            DnsMgrConnectionCategory::AuthOrPermissionDenied
        }
        DnsMgrError::MalformedResponse(_) => DnsMgrConnectionCategory::MalformedResponse,
        DnsMgrError::InvalidBaseUrl
        | DnsMgrError::InvalidRequest(_)
        | DnsMgrError::ProtocolContractViolation(_) => DnsMgrConnectionCategory::ContractError,
        DnsMgrError::DomainNotFoundOrUnavailable
        | DnsMgrError::ProviderFailure(_)
        | DnsMgrError::RateLimitedOrTemporarilyUnavailable
        | DnsMgrError::UnknownUpstream(_) => DnsMgrConnectionCategory::UpstreamRejected,
    }
}

fn audit_origin(base_url: &str) -> String {
    reqwest::Url::parse(base_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| "unconfigured".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use relay_shared::protocol::LoginRequest;
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::sync::Arc;
    use tower::ServiceExt;

    const API_KEY: &str = "dns-test-api-key";

    async fn test_state() -> (AppState, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        };
        (state, pool)
    }

    async fn add_user(pool: &SqlitePool, id: i64, admin: bool) {
        let password = bcrypt::hash("password-for-test", 4).unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password, admin, balance, max_rules, traffic_used, traffic_limit, banned) \
             VALUES (?, ?, ?, ?, '0', 1, 0, 0, 0)",
        )
        .bind(id)
        .bind(format!("user-{id}"))
        .bind(password)
        .bind(admin)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn save_settings(state: &AppState, base_url: String, key: &str) {
        let Json(response) = update_dnsmgr_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(UpdateDnsMgrSettingsRequest {
                enabled: true,
                base_url,
                uid: 7,
                api_key: Some(key.into()),
            }),
        )
        .await;
        assert_eq!(response.code, 0);
    }

    #[tokio::test]
    async fn saves_http_and_https_without_exposing_or_overwriting_the_api_key() {
        let (state, _) = test_state().await;
        save_settings(&state, "http://127.0.0.1:8080/".into(), API_KEY).await;

        let Json(first) = get_dnsmgr_settings(AdminOnly { user_id: 1 }, State(state.clone())).await;
        let first_json = serde_json::to_string(&first).unwrap();
        assert_eq!(
            first.data.as_ref().unwrap().base_url,
            "http://127.0.0.1:8080"
        );
        assert!(first.data.as_ref().unwrap().has_api_key);
        assert!(!first_json.contains(API_KEY));

        let Json(preserved) = update_dnsmgr_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(UpdateDnsMgrSettingsRequest {
                enabled: false,
                base_url: "https://dns.example.test/".into(),
                uid: 8,
                api_key: None,
            }),
        )
        .await;
        assert_eq!(preserved.code, 0);
        let stored = state.db.get(DNSMGR_CONFIG_KEY).await.unwrap().unwrap();
        assert!(stored.contains(API_KEY));
        assert_eq!(preserved.data.unwrap().base_url, "https://dns.example.test");

        let Json(blank_key) = update_dnsmgr_settings(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(UpdateDnsMgrSettingsRequest {
                enabled: false,
                base_url: "https://dns.example.test".into(),
                uid: 8,
                api_key: Some("   ".into()),
            }),
        )
        .await;
        assert_eq!(blank_key.code, 0);
        assert!(state
            .db
            .get(DNSMGR_CONFIG_KEY)
            .await
            .unwrap()
            .unwrap()
            .contains(API_KEY));

        let replacement = "replacement-key";
        save_settings(&state, "https://dns.example.test".into(), replacement).await;
        let stored = state.db.get(DNSMGR_CONFIG_KEY).await.unwrap().unwrap();
        assert!(!stored.contains(API_KEY));
        assert!(stored.contains(replacement));

        let audit = state.db.query_audit_log(None, 20, 0).await.unwrap();
        let audit_json = serde_json::to_string(&audit).unwrap();
        assert!(!audit_json.contains(API_KEY));
        assert!(!audit_json.contains(replacement));
    }

    #[tokio::test]
    async fn rejects_invalid_urls_and_embedded_url_credentials() {
        let (state, _) = test_state().await;
        for base_url in [
            "file:///tmp/dns",
            "https://user:pass@dns.example.test",
            "https://dns.example.test/api?token=secret",
        ] {
            let Json(response) = update_dnsmgr_settings(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Json(UpdateDnsMgrSettingsRequest {
                    enabled: true,
                    base_url: base_url.into(),
                    uid: 7,
                    api_key: Some(API_KEY.into()),
                }),
            )
            .await;
            assert_eq!(response.code, 400);
        }
    }

    #[tokio::test]
    async fn non_admin_is_denied_by_the_real_admin_route() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, false).await;
        let Json(login) = crate::api::auth::login(
            State(state.clone()),
            Json(LoginRequest {
                username: "user-2".into(),
                password: "password-for-test".into(),
            }),
        )
        .await;
        let token = login.data.unwrap().token;
        let response = crate::api::routes()
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/admin/settings/dnsmgr")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn connection_test_uses_signed_client_and_keeps_empty_inventory_non_authoritative() {
        let router = Router::new().route(
            "/api/domain",
            post(|| async { Json(json!({"total": 0, "rows": []})) }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let (state, _) = test_state().await;
        save_settings(&state, base_url, API_KEY).await;

        let Json(response) = test_dnsmgr_connection(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(TestDnsMgrConnectionRequest::default()),
        )
        .await;
        handle.abort();
        let result = response.data.unwrap();
        let result_json = serde_json::to_string(&result).unwrap();
        assert_eq!(result.category, DnsMgrConnectionCategory::Ok);
        assert_eq!(result.domain_count, Some(0));
        assert!(result.empty_domain_list);
        assert!(!result.zone_ownership_verified);
        assert!(!result_json.contains(API_KEY));

        let audit = state
            .db
            .query_audit_log(Some("DNSMGR_CONNECTION_TEST"), 10, 0)
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert!(!serde_json::to_string(&audit).unwrap().contains(API_KEY));
    }

    #[tokio::test]
    async fn connection_test_maps_upstream_outcomes_without_reflecting_secrets() {
        let cases = [
            (
                Router::new().route(
                    "/api/domain",
                    post(|| async { (StatusCode::FORBIDDEN, "forbidden") }),
                ),
                DnsMgrConnectionCategory::AuthOrPermissionDenied,
            ),
            (
                Router::new().route(
                    "/api/domain",
                    post(|| async { Json(json!({"code": -1, "msg": "bad credential"})) }),
                ),
                DnsMgrConnectionCategory::UpstreamRejected,
            ),
            (
                Router::new().route(
                    "/api/domain",
                    post(|| async { (StatusCode::OK, "not json") }),
                ),
                DnsMgrConnectionCategory::MalformedResponse,
            ),
        ];

        for (router, expected) in cases {
            let (base_url, handle) = spawn_mock(router).await;
            let (state, _) = test_state().await;
            save_settings(&state, base_url, API_KEY).await;
            let Json(response) = test_dnsmgr_connection(
                AdminOnly { user_id: 1 },
                State(state),
                Json(TestDnsMgrConnectionRequest::default()),
            )
            .await;
            handle.abort();
            assert_eq!(response.data.unwrap().category, expected);
        }
    }

    #[test]
    fn local_error_categories_are_stable() {
        assert_eq!(
            connection_category(&DnsMgrError::Timeout),
            DnsMgrConnectionCategory::Timeout
        );
        assert_eq!(
            connection_category(&DnsMgrError::Transport("unreachable".into())),
            DnsMgrConnectionCategory::TransportError
        );
        assert_eq!(
            connection_category(&DnsMgrError::InvalidBaseUrl),
            DnsMgrConnectionCategory::ContractError
        );
    }

    async fn add_eligible_rule(pool: &SqlitePool, sni: &str) {
        sqlx::query(
            "INSERT INTO device_groups \
             (id, name, group_type, token, uid, connect_host) \
             VALUES (10, 'dns-group', 'in', 'dns-token', 1, '192.0.2.10')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, \
              public_transport, node_transport, entry_transport, sni, camouflage_enabled) \
             VALUES (100, 'dns-rule', 1, 443, 10, '198.51.100.2', 55443, \
                     'nginx_sni', 'nginx_sni', 'nginx_sni', ?, 1)",
        )
        .bind(sni)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rule_dns_status_is_safe_and_separates_warning_from_error() {
        let (state, pool) = test_state().await;
        add_eligible_rule(&pool, "op1.example.com").await;
        save_settings(&state, "https://dns.example.test".into(), API_KEY).await;
        sqlx::query(
            "UPDATE dns_record_syncs SET state = 'PROPAGATED', ownership = 'PANEL', \
             mutation_verified_at = '2026-08-26 01:00:00', \
             last_observed_at = '2026-08-26 01:01:00', \
             propagated_at = '2026-08-26 01:01:00', \
             last_error_category = 'PUBLIC_DNS_MULTIPLE_ANSWERS' WHERE rule_id = 100",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(response) = list_rule_dns_statuses(AdminOnly { user_id: 1 }, State(state)).await;
        assert_eq!(response.code, 0);
        let status = response.data.unwrap().remove(0);
        assert!(status.eligible);
        assert!(status.automation_enabled);
        assert_eq!(status.sync_state, "PROPAGATED");
        assert_eq!(status.ownership, "PANEL_MANAGED");
        assert_eq!(
            status.warning_category.as_deref(),
            Some("PUBLIC_DNS_MULTIPLE_ANSWERS")
        );
        assert_eq!(status.last_error_category, None);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains(API_KEY));
        assert!(!json.contains("sign"));
    }

    #[tokio::test]
    async fn disabled_automation_reports_separately_from_manual_dns_and_certificate_state() {
        let (state, pool) = test_state().await;
        add_eligible_rule(&pool, "op1.example.com").await;

        let status = project_rule_dns_status(&state, &DnsMgrSettings::default(), 100)
            .await
            .unwrap();
        assert!(status.eligible);
        assert!(!status.automation_enabled);
        assert_eq!(status.sync_state, "DISABLED");
        assert_eq!(status.fqdn.as_deref(), Some("op1.example.com"));
        assert_eq!(status.expected_value.as_deref(), Some("192.0.2.10"));
        assert_eq!(status.last_error_category, None);
    }

    #[tokio::test]
    async fn dns_status_and_retry_routes_are_admin_only() {
        let (state, pool) = test_state().await;
        add_user(&pool, 2, false).await;
        let Json(login) = crate::api::auth::login(
            State(state.clone()),
            Json(LoginRequest {
                username: "user-2".into(),
                password: "password-for-test".into(),
            }),
        )
        .await;
        let token = login.data.unwrap().token;
        for (method, uri) in [
            ("GET", "/admin/rules/dns-status"),
            ("POST", "/admin/rules/100/dns/retry"),
        ] {
            let response = crate::api::routes()
                .with_state(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn rule_dns_status_uses_fresh_rule_target_and_handles_invalid_history() {
        let (state, pool) = test_state().await;
        add_eligible_rule(&pool, "op1.example.com").await;
        save_settings(&state, "https://dns.example.test".into(), API_KEY).await;
        sqlx::query("UPDATE forward_rules SET sni = 'op2.example.com' WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let fresh = project_rule_dns_status(
            &state,
            &DnsMgrSettings::from_json(state.db.get(DNSMGR_CONFIG_KEY).await.unwrap().as_deref()),
            100,
        )
        .await
        .unwrap();
        assert_eq!(fresh.fqdn.as_deref(), Some("op2.example.com"));
        assert_eq!(fresh.sync_state, "PENDING");
        assert_eq!(fresh.ownership, "NONE");
        assert_eq!(fresh.propagated_at, None);

        sqlx::query("UPDATE forward_rules SET sni = 'not a fqdn' WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        let invalid = project_rule_dns_status(
            &state,
            &DnsMgrSettings::from_json(state.db.get(DNSMGR_CONFIG_KEY).await.unwrap().as_deref()),
            100,
        )
        .await
        .unwrap();
        assert_eq!(invalid.sync_state, "INVALID_CONFIG");
        assert_eq!(invalid.last_error_category.as_deref(), Some("INVALID_FQDN"));
    }

    #[tokio::test]
    async fn manual_retry_only_schedules_worker_and_rejects_unknown_mutations() {
        let (state, pool) = test_state().await;
        add_eligible_rule(&pool, "op1.example.com").await;
        save_settings(&state, "https://dns.example.test".into(), API_KEY).await;
        sqlx::query(
            "UPDATE dns_record_syncs SET state = 'FAILED', ownership = 'UNKNOWN', \
             last_error_category = 'DNSMGR_TIMEOUT', next_attempt_at = NULL WHERE rule_id = 100",
        )
        .execute(&pool)
        .await
        .unwrap();

        let Json(retried) =
            retry_rule_dns_sync(AdminOnly { user_id: 1 }, State(state.clone()), Path(100)).await;
        assert_eq!(retried.code, 0);
        assert_eq!(retried.data.unwrap().sync_state, "PENDING");
        let audit = state.db.query_audit_log(None, 20, 0).await.unwrap();
        assert!(audit
            .iter()
            .any(|entry| entry.action == "DNS_SYNC_MANUAL_RETRY"));
        assert!(audit
            .iter()
            .any(|entry| entry.action == "DNS_SYNC_SCHEDULED"));
        assert!(!serde_json::to_string(&audit).unwrap().contains(API_KEY));

        sqlx::query(
            "UPDATE dns_record_syncs SET state = 'MUTATION_OUTCOME_UNKNOWN', \
             last_error_category = 'POST_WRITE_NOT_VERIFIED', next_attempt_at = NULL \
             WHERE rule_id = 100",
        )
        .execute(&pool)
        .await
        .unwrap();
        let Json(rejected) =
            retry_rule_dns_sync(AdminOnly { user_id: 1 }, State(state.clone()), Path(100)).await;
        assert_eq!(rejected.code, 409);
        assert_eq!(
            state
                .db
                .find_dns_record_sync(100)
                .await
                .unwrap()
                .unwrap()
                .state,
            "MUTATION_OUTCOME_UNKNOWN"
        );
    }

    async fn spawn_mock(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (base_url, handle)
    }
}
