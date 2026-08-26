//! Typed client for the upstream DNSMgr signed form API.
//!
//! DNSMgr is a legacy, documented integration protocol rather than a REST API
//! with stable machine-readable error codes. This module keeps that protocol
//! behind typed Panel-local models and errors. It intentionally has no rule,
//! database, or Node dependencies. Read operations may retry transient errors;
//! record mutations are single-attempt because DNSMgr has no idempotency key.

use md5::{Digest, Md5};
use reqwest::{redirect::Policy, StatusCode, Url};
use serde_json::Value;
use std::fmt;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_READ_ATTEMPTS: usize = 2;
const DEFAULT_PAGE_LIMIT: u16 = 10;

#[derive(Clone)]
pub(crate) struct DnsMgrClientConfig {
    base_url: Url,
    uid: u64,
    api_key: String,
}

impl DnsMgrClientConfig {
    pub(crate) fn new(
        base_url: &str,
        uid: u64,
        api_key: impl Into<String>,
    ) -> Result<Self, DnsMgrError> {
        if uid == 0 {
            return Err(DnsMgrError::InvalidRequest("uid must be positive".into()));
        }
        let base_url = parse_base_url(base_url)?;

        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(DnsMgrError::InvalidRequest("API key is empty".into()));
        }

        Ok(Self {
            base_url,
            uid,
            api_key,
        })
    }
}

pub(crate) fn normalize_base_url(base_url: &str) -> Result<String, DnsMgrError> {
    let base_url = parse_base_url(base_url)?;
    Ok(base_url.as_str().trim_end_matches('/').to_string())
}

impl fmt::Debug for DnsMgrClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsMgrClientConfig")
            .field("base_url", &self.base_url)
            .field("uid", &self.uid)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct DnsMgrClient {
    config: DnsMgrClientConfig,
    http: reqwest::Client,
}

impl fmt::Debug for DnsMgrClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsMgrClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DnsMgrClient {
    pub(crate) fn new(config: DnsMgrClientConfig) -> Result<Self, DnsMgrError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(Policy::none())
            // Keep rustls' normal WebPKI verification. HTTP remains supported
            // because the product explicitly permits private/self-hosted HTTP
            // DNSMgr endpoints; HTTPS must never silently become insecure.
            .build()
            .map_err(|error| DnsMgrError::Transport(sanitize_message(&error.to_string(), "")))?;
        Ok(Self { config, http })
    }

    pub(crate) async fn list_domains(
        &self,
        params: &DomainListParams,
    ) -> Result<DnsMgrPage<DnsMgrDomain>, DnsMgrError> {
        params.validate()?;
        let mut fields = self.signed_fields(current_timestamp());
        fields.push(("offset".into(), params.offset.to_string()));
        fields.push(("limit".into(), params.limit.to_string()));
        if let Some(keyword) = params.keyword.as_deref() {
            fields.push(("kw".into(), keyword.to_string()));
        }

        let value = self.read_json(&["domain"], fields).await?;
        parse_page(&value, parse_domain)
    }

    pub(crate) async fn get_domain(
        &self,
        domain_id: u64,
    ) -> Result<DnsMgrDomainDetail, DnsMgrError> {
        validate_id(domain_id, "domain_id")?;
        let mut fields = self.signed_fields(current_timestamp());
        // Do not request DNSMgr's short-lived quick-login URL. It is unrelated
        // to RelayPanel and would create an avoidable secret-like response.
        fields.push(("loginurl".into(), "0".into()));
        let value = self
            .read_json(&["domain", &domain_id.to_string()], fields)
            .await?;
        parse_domain_detail(&value)
    }

    pub(crate) async fn list_records(
        &self,
        domain_id: u64,
        params: &RecordListParams,
    ) -> Result<DnsMgrPage<DnsMgrRecord>, DnsMgrError> {
        validate_id(domain_id, "domain_id")?;
        params.validate()?;
        let mut fields = self.signed_fields(current_timestamp());
        fields.push(("offset".into(), params.offset.to_string()));
        fields.push(("limit".into(), params.limit.to_string()));
        if let Some(value) = params.keyword.as_deref() {
            fields.push(("keyword".into(), value.to_string()));
        }
        if let Some(value) = params.subdomain.as_deref() {
            fields.push(("subdomain".into(), value.to_string()));
        }
        if let Some(value) = params.value.as_deref() {
            fields.push(("value".into(), value.to_string()));
        }
        if let Some(value) = params.record_type.as_deref() {
            fields.push(("type".into(), value.to_string()));
        }
        if let Some(value) = params.line.as_deref() {
            fields.push(("line".into(), value.to_string()));
        }
        if let Some(value) = params.status.as_deref() {
            fields.push(("status".into(), value.to_string()));
        }

        let value = self
            .read_json(&["record", "data", &domain_id.to_string()], fields)
            .await?;
        parse_record_page(&value)
    }

    /// Submit one record create mutation. DNSMgr has no idempotency key, so
    /// this deliberately bypasses the bounded retry used by read operations.
    /// The upstream controller returns only `code=0`, never a record identity;
    /// callers must establish the identity through post-write discovery.
    pub(crate) async fn create_record(
        &self,
        domain_id: u64,
        request: &DnsMgrRecordMutation,
    ) -> Result<DnsMgrMutationAccepted, DnsMgrError> {
        validate_id(domain_id, "domain_id")?;
        request.validate()?;
        let fields = self.mutation_fields(request, None);
        let endpoint = self.endpoint(&["record", "add", &domain_id.to_string()])?;
        let value = self.read_json_once(&endpoint, &fields).await?;
        parse_mutation_response(&value)
    }

    /// Update exactly one provider record identity. Like create, this is a
    /// single attempt; an ambiguous transport result is reconciled by reads.
    pub(crate) async fn update_record(
        &self,
        domain_id: u64,
        record_id: &str,
        request: &DnsMgrRecordMutation,
    ) -> Result<DnsMgrMutationAccepted, DnsMgrError> {
        validate_id(domain_id, "domain_id")?;
        if record_id.trim().is_empty() {
            return Err(DnsMgrError::InvalidRequest("record_id is empty".into()));
        }
        request.validate()?;
        let fields = self.mutation_fields(request, Some(record_id));
        let endpoint = self.endpoint(&["record", "update", &domain_id.to_string()])?;
        let value = self.read_json_once(&endpoint, &fields).await?;
        parse_mutation_response(&value)
    }

    fn mutation_fields(
        &self,
        request: &DnsMgrRecordMutation,
        record_id: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut fields = self.signed_fields(current_timestamp());
        if let Some(record_id) = record_id {
            fields.push(("recordid".into(), record_id.to_string()));
        }
        fields.extend([
            ("name".into(), request.host.clone()),
            ("type".into(), request.record_type.clone()),
            ("value".into(), request.value.clone()),
            ("line".into(), request.line.clone()),
            ("ttl".into(), request.ttl.to_string()),
        ]);
        fields
    }

    fn signed_fields(&self, timestamp: i64) -> Vec<(String, String)> {
        let timestamp = timestamp.to_string();
        vec![
            ("uid".into(), self.config.uid.to_string()),
            ("timestamp".into(), timestamp.clone()),
            (
                "sign".into(),
                sign_request(self.config.uid, &timestamp, &self.config.api_key),
            ),
        ]
    }

    async fn read_json(
        &self,
        path: &[&str],
        fields: Vec<(String, String)>,
    ) -> Result<Value, DnsMgrError> {
        let endpoint = self.endpoint(path)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.read_json_once(&endpoint, &fields).await {
                Ok(value) => return Ok(value),
                Err(error) if attempt < MAX_READ_ATTEMPTS && error.is_retryable() => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn read_json_once(
        &self,
        endpoint: &Url,
        fields: &[(String, String)],
    ) -> Result<Value, DnsMgrError> {
        let response = self
            .http
            .post(endpoint.clone())
            .form(fields)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    DnsMgrError::Timeout
                } else {
                    DnsMgrError::Transport(sanitize_message(
                        &error.to_string(),
                        &self.config.api_key,
                    ))
                }
            })?;

        let status = response.status();
        if status.is_redirection() {
            return Err(DnsMgrError::ProtocolContractViolation(
                "redirect response is not allowed".into(),
            ));
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(DnsMgrError::Authentication);
        }
        if status == StatusCode::FORBIDDEN {
            // DNSMgr uses 403 for missing, disabled, and invalid API access;
            // its protocol does not expose a stable subcategory.
            return Err(DnsMgrError::Permission);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(DnsMgrError::RateLimitedOrTemporarilyUnavailable);
        }
        if status.is_client_error() {
            return Err(DnsMgrError::InvalidRequest(format!(
                "HTTP {}",
                status.as_u16()
            )));
        }
        if status.is_server_error() {
            return Err(DnsMgrError::RateLimitedOrTemporarilyUnavailable);
        }
        if !status.is_success() {
            return Err(DnsMgrError::UnknownUpstream(format!(
                "HTTP {}",
                status.as_u16()
            )));
        }

        let body = read_limited_body(response).await?;
        serde_json::from_slice(&body).map_err(|error| {
            DnsMgrError::MalformedResponse(sanitize_message(&error.to_string(), ""))
        })
    }

    fn endpoint(&self, path: &[&str]) -> Result<Url, DnsMgrError> {
        let mut endpoint = self.config.base_url.clone();
        let base_path = endpoint.path().trim_end_matches('/');
        let suffix = path.join("/");
        endpoint.set_path(&format!("{base_path}/api/{suffix}"));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        Ok(endpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsMgrError {
    InvalidBaseUrl,
    InvalidRequest(String),
    Transport(String),
    Timeout,
    Authentication,
    Permission,
    #[allow(dead_code)]
    DomainNotFoundOrUnavailable,
    ProviderFailure(String),
    RateLimitedOrTemporarilyUnavailable,
    MalformedResponse(String),
    ProtocolContractViolation(String),
    UnknownUpstream(String),
}

impl DnsMgrError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport(_) | Self::Timeout | Self::RateLimitedOrTemporarilyUnavailable
        )
    }

    pub(crate) fn is_ambiguous_write(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Timeout)
    }
}

impl fmt::Display for DnsMgrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("invalid DNSMgr base URL"),
            Self::InvalidRequest(message) => write!(formatter, "invalid DNSMgr request: {message}"),
            Self::Transport(message) => write!(formatter, "DNSMgr transport error: {message}"),
            Self::Timeout => formatter.write_str("DNSMgr request timed out"),
            Self::Authentication => formatter.write_str("DNSMgr authentication failed"),
            Self::Permission => formatter.write_str("DNSMgr permission denied"),
            Self::DomainNotFoundOrUnavailable => {
                formatter.write_str("DNSMgr domain is unavailable")
            }
            Self::ProviderFailure(message) => {
                write!(formatter, "DNSMgr provider failure: {message}")
            }
            Self::RateLimitedOrTemporarilyUnavailable => {
                formatter.write_str("DNSMgr is temporarily unavailable or rate limited")
            }
            Self::MalformedResponse(message) => {
                write!(formatter, "malformed DNSMgr response: {message}")
            }
            Self::ProtocolContractViolation(message) => {
                write!(formatter, "DNSMgr protocol contract violation: {message}")
            }
            Self::UnknownUpstream(message) => {
                write!(formatter, "unknown DNSMgr upstream error: {message}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainListParams {
    pub offset: u32,
    pub limit: u16,
    pub keyword: Option<String>,
}

impl Default for DomainListParams {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_PAGE_LIMIT,
            keyword: None,
        }
    }
}

impl DomainListParams {
    fn validate(&self) -> Result<(), DnsMgrError> {
        validate_limit(self.limit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordListParams {
    pub offset: u32,
    pub limit: u16,
    pub keyword: Option<String>,
    pub subdomain: Option<String>,
    pub value: Option<String>,
    pub record_type: Option<String>,
    pub line: Option<String>,
    pub status: Option<String>,
}

impl Default for RecordListParams {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_PAGE_LIMIT,
            keyword: None,
            subdomain: None,
            value: None,
            record_type: None,
            line: None,
            status: None,
        }
    }
}

impl RecordListParams {
    fn validate(&self) -> Result<(), DnsMgrError> {
        validate_limit(self.limit)?;
        if let Some(status) = self.status.as_deref() {
            if status != "0" && status != "1" {
                return Err(DnsMgrError::InvalidRequest(
                    "record status must be 0 or 1".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrPage<T> {
    pub total: u64,
    pub rows: Vec<T>,
    pub authoritative_total: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrDomain {
    pub domain_id: u64,
    pub zone_name: String,
    pub provider_type: Option<String>,
    pub record_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrDomainDetail {
    pub domain: DnsMgrDomain,
    pub min_ttl: Option<u64>,
    pub record_lines: Vec<DnsMgrRecordLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrRecordLine {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrRecord {
    pub record_id: String,
    pub domain: Option<String>,
    pub host: String,
    pub record_type: String,
    pub value: String,
    pub line: String,
    pub line_name: Option<String>,
    pub ttl: u64,
    pub status: String,
    pub priority: Option<i64>,
    pub weight: Option<i64>,
    pub remark: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsMgrRecordMutation {
    pub host: String,
    pub record_type: String,
    pub value: String,
    pub line: String,
    pub ttl: u32,
}

impl DnsMgrRecordMutation {
    fn validate(&self) -> Result<(), DnsMgrError> {
        if self.host.trim().is_empty()
            || self.record_type.trim().is_empty()
            || self.value.trim().is_empty()
        {
            return Err(DnsMgrError::InvalidRequest(
                "record host, type, and value are required".into(),
            ));
        }
        if self.ttl == 0 {
            return Err(DnsMgrError::InvalidRequest(
                "record TTL must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DnsMgrMutationAccepted;

fn validate_base_url(url: &Url) -> Result<(), DnsMgrError> {
    if url.scheme() != "http" && url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DnsMgrError::InvalidBaseUrl);
    }
    Ok(())
}

fn parse_base_url(base_url: &str) -> Result<Url, DnsMgrError> {
    let mut url = Url::parse(base_url).map_err(|_| DnsMgrError::InvalidBaseUrl)?;
    validate_base_url(&url)?;
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url)
}

fn validate_limit(limit: u16) -> Result<(), DnsMgrError> {
    if !(1..=100).contains(&limit) {
        return Err(DnsMgrError::InvalidRequest(
            "limit must be between 1 and 100".into(),
        ));
    }
    Ok(())
}

fn validate_id(id: u64, name: &str) -> Result<(), DnsMgrError> {
    if id == 0 {
        return Err(DnsMgrError::InvalidRequest(format!(
            "{name} must be positive"
        )));
    }
    Ok(())
}

fn current_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

fn sign_request(uid: u64, timestamp: &str, api_key: &str) -> String {
    let mut digest = Md5::new();
    digest.update(uid.to_string());
    digest.update(timestamp.as_bytes());
    digest.update(api_key.as_bytes());
    format!("{:x}", digest.finalize())
}

async fn read_limited_body(mut response: reqwest::Response) -> Result<Vec<u8>, DnsMgrError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(DnsMgrError::MalformedResponse(
            "response exceeds the size limit".into(),
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            DnsMgrError::Timeout
        } else {
            DnsMgrError::Transport(sanitize_message(&error.to_string(), ""))
        }
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(DnsMgrError::MalformedResponse(
                "response exceeds the size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_page<T, F>(value: &Value, parser: F) -> Result<DnsMgrPage<T>, DnsMgrError>
where
    F: Fn(&Value) -> Result<T, DnsMgrError>,
{
    check_business_code(value)?;
    let object = value
        .as_object()
        .ok_or_else(|| DnsMgrError::MalformedResponse("response must be an object".into()))?;
    let total = required_u64(object.get("total"), "total")?;
    let rows = object
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| DnsMgrError::MalformedResponse("rows must be an array".into()))?;
    let rows = rows.iter().map(parser).collect::<Result<Vec<_>, _>>()?;
    Ok(DnsMgrPage {
        total,
        rows,
        authoritative_total: true,
    })
}

/// DNSMgr's record-list controller has two legitimate response branches: the
/// normal `{total, rows}` envelope and a provider-paginated bare record array.
/// No other endpoint accepts the array form. Every array element still passes
/// the same strict typed record parser as an enveloped row.
fn parse_record_page(value: &Value) -> Result<DnsMgrPage<DnsMgrRecord>, DnsMgrError> {
    if let Some(rows) = value.as_array() {
        let rows = rows
            .iter()
            .map(parse_record)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(DnsMgrPage {
            total: rows.len() as u64,
            rows,
            authoritative_total: false,
        });
    }
    parse_page(value, parse_record)
}

fn parse_domain(row: &Value) -> Result<DnsMgrDomain, DnsMgrError> {
    let object = required_object(row, "domain row")?;
    Ok(DnsMgrDomain {
        domain_id: required_u64(object.get("id"), "domain id")?,
        zone_name: normalize_zone_name(&required_string(object.get("name"), "domain name")?)?,
        provider_type: optional_string(object.get("type"), "domain type")?,
        record_count: optional_u64(object.get("recordcount"), "recordcount")?,
    })
}

fn parse_domain_detail(value: &Value) -> Result<DnsMgrDomainDetail, DnsMgrError> {
    check_business_code(value)?;
    let data = value
        .get("data")
        .ok_or_else(|| DnsMgrError::MalformedResponse("domain detail data is missing".into()))?;
    let object = required_object(data, "domain detail")?;
    let mut domain = parse_domain(data)?;
    if domain.provider_type.is_none() {
        domain.provider_type = match object.get("config") {
            None | Some(Value::Null) => None,
            Some(config) => {
                let config = required_object(config, "domain config")?;
                optional_string(config.get("type"), "domain config type")?
            }
        };
    }
    let min_ttl = optional_u64(object.get("minTTL"), "minTTL")?;
    let record_lines = match object.get("recordLine") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(lines)) => lines
            .iter()
            .map(parse_record_line)
            .collect::<Result<_, _>>()?,
        Some(_) => {
            return Err(DnsMgrError::MalformedResponse(
                "recordLine must be an array".into(),
            ))
        }
    };
    Ok(DnsMgrDomainDetail {
        domain,
        min_ttl,
        record_lines,
    })
}

fn parse_record(row: &Value) -> Result<DnsMgrRecord, DnsMgrError> {
    let object = required_object(row, "record row")?;
    Ok(DnsMgrRecord {
        record_id: required_string(object.get("RecordId"), "record id")?,
        domain: optional_string(object.get("Domain"), "record domain")?,
        host: required_string(object.get("Name"), "record host")?,
        record_type: required_string(object.get("Type"), "record type")?,
        value: required_string(object.get("Value"), "record value")?,
        line: scalar_string(object.get("Line"), "record line")?,
        line_name: optional_string(object.get("LineName"), "record line name")?,
        ttl: required_u64(object.get("TTL"), "record ttl")?,
        status: required_string(object.get("Status"), "record status")?,
        priority: optional_i64(object.get("MX"), "record MX")?,
        weight: optional_i64(object.get("Weight"), "record weight")?,
        remark: optional_string(object.get("Remark"), "record remark")?,
        updated_at: optional_string(object.get("UpdateTime"), "record update time")?,
    })
}

fn parse_record_line(value: &Value) -> Result<DnsMgrRecordLine, DnsMgrError> {
    let object = required_object(value, "record line")?;
    Ok(DnsMgrRecordLine {
        id: scalar_string(object.get("id"), "record line id")?,
        name: required_string(object.get("name"), "record line name")?,
        parent: optional_string(object.get("parent"), "record line parent")?,
    })
}

fn parse_mutation_response(value: &Value) -> Result<DnsMgrMutationAccepted, DnsMgrError> {
    let object = value.as_object().ok_or_else(|| {
        DnsMgrError::ProtocolContractViolation("mutation response must be an object".into())
    })?;
    let code = object.get("code").and_then(Value::as_i64).ok_or_else(|| {
        DnsMgrError::ProtocolContractViolation("mutation response code must be an integer".into())
    })?;
    if code != 0 {
        return Err(DnsMgrError::ProviderFailure(format!(
            "upstream returned code {code}"
        )));
    }
    if let Some(message) = object.get("msg") {
        required_string(Some(message), "mutation response msg")?;
    }
    Ok(DnsMgrMutationAccepted)
}

fn check_business_code(value: &Value) -> Result<(), DnsMgrError> {
    if let Some(code) = value.get("code") {
        let code = code.as_i64().ok_or_else(|| {
            DnsMgrError::MalformedResponse("response code must be an integer".into())
        })?;
        if code != 0 {
            // DNSMgr's msg is unstructured provider text and can include
            // reflected request data. Keep it out of errors and machine logic.
            return Err(DnsMgrError::ProviderFailure(format!(
                "upstream returned code {code}"
            )));
        }
    }
    Ok(())
}

fn normalize_zone_name(value: &str) -> Result<String, DnsMgrError> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(DnsMgrError::ProtocolContractViolation(
            "DNSMgr returned an invalid zone name".into(),
        ));
    }
    Ok(value)
}

fn required_object<'a>(
    value: &'a Value,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, DnsMgrError> {
    value
        .as_object()
        .ok_or_else(|| DnsMgrError::MalformedResponse(format!("{name} must be an object")))
}

fn required_string(value: Option<&Value>, name: &str) -> Result<String, DnsMgrError> {
    value
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| DnsMgrError::MalformedResponse(format!("{name} must be a string")))
}

fn optional_string(value: Option<&Value>, name: &str) -> Result<Option<String>, DnsMgrError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => required_string(Some(value), name).map(Some),
    }
}

fn required_u64(value: Option<&Value>, name: &str) -> Result<u64, DnsMgrError> {
    value.and_then(Value::as_u64).ok_or_else(|| {
        DnsMgrError::MalformedResponse(format!("{name} must be an unsigned integer"))
    })
}

fn optional_u64(value: Option<&Value>, name: &str) -> Result<Option<u64>, DnsMgrError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            DnsMgrError::MalformedResponse(format!("{name} must be an unsigned integer"))
        }),
        Some(Value::String(value)) => value.parse::<u64>().map(Some).map_err(|_| {
            DnsMgrError::MalformedResponse(format!("{name} must be a numeric string"))
        }),
        Some(_) => Err(DnsMgrError::MalformedResponse(format!(
            "{name} must be a number or numeric string"
        ))),
    }
}

fn optional_i64(value: Option<&Value>, name: &str) -> Result<Option<i64>, DnsMgrError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| DnsMgrError::MalformedResponse(format!("{name} must be an integer"))),
        Some(_) => Err(DnsMgrError::MalformedResponse(format!(
            "{name} must be an integer or null"
        ))),
    }
}

fn scalar_string(value: Option<&Value>, name: &str) -> Result<String, DnsMgrError> {
    match value {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.to_string()),
        _ => Err(DnsMgrError::MalformedResponse(format!(
            "{name} must be a string or number"
        ))),
    }
}

fn sanitize_message(message: &str, secret: &str) -> String {
    let message = if !secret.is_empty() {
        message.replace(secret, "[REDACTED]")
    } else {
        message.to_string()
    };
    let mut message = message;
    if message.len() > 160 {
        message.truncate(160);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Form;
    use axum::http::{header, HeaderValue, StatusCode as AxumStatusCode};
    use axum::response::Response;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    const UID: u64 = 123;
    const KEY: &str = "test-key";
    const TIMESTAMP: &str = "1712345678";
    const EXPECTED_SIGN: &str = "f267acc64a5026b605f8f1675b724d9c";

    #[test]
    fn signing_vector_is_exact_lowercase_md5() {
        assert_eq!(sign_request(UID, TIMESTAMP, KEY), EXPECTED_SIGN);
        assert_ne!(sign_request(UID, "1712345679", KEY), EXPECTED_SIGN);
        assert_ne!(sign_request(UID, TIMESTAMP, "other-key"), EXPECTED_SIGN);
    }

    #[test]
    fn list_params_have_valid_upstream_defaults() {
        assert_eq!(DomainListParams::default().limit, DEFAULT_PAGE_LIMIT);
        assert_eq!(RecordListParams::default().limit, DEFAULT_PAGE_LIMIT);
        assert!(DomainListParams::default().validate().is_ok());
        assert!(RecordListParams::default().validate().is_ok());
    }

    #[test]
    fn config_accepts_http_and_https_but_rejects_non_http_schemes() {
        assert!(DnsMgrClientConfig::new("http://127.0.0.1:8081", UID, KEY).is_ok());
        assert!(DnsMgrClientConfig::new("https://dns.example.test/base", UID, KEY).is_ok());
        assert_eq!(
            DnsMgrClientConfig::new("file:///tmp/dnsmgr", UID, KEY).unwrap_err(),
            DnsMgrError::InvalidBaseUrl
        );
        assert_eq!(
            DnsMgrClientConfig::new("https://user:pass@dns.example.test", UID, KEY).unwrap_err(),
            DnsMgrError::InvalidBaseUrl
        );
        assert_eq!(
            DnsMgrClientConfig::new("https://dns.example.test/api?token=secret", UID, KEY)
                .unwrap_err(),
            DnsMgrError::InvalidBaseUrl
        );
    }

    #[test]
    fn secret_is_redacted_from_debug_and_errors() {
        let config = DnsMgrClientConfig::new("http://127.0.0.1:8081", UID, KEY).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(KEY));
        let message = sanitize_message(&format!("upstream echoed {KEY}"), KEY);
        assert!(!message.contains(KEY));
        assert!(message.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn domain_list_validates_rows_envelope_and_signed_form() {
        let captured = Arc::new(Mutex::new(None));
        let captured_for_handler = captured.clone();
        let router = Router::new().route(
            "/api/domain",
            post(move |Form(form): Form<HashMap<String, String>>| {
                let captured = captured_for_handler.clone();
                async move {
                    *captured.lock().await = Some(form);
                    Json(json!({
                        "total": 1,
                        "rows": [{"id": 7, "name": "EXAMPLE.CO.UK.", "type": "dnsmgr", "recordcount": 3}]
                    }))
                }
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let client = client(&base_url);
        let page = client
            .list_domains(&DomainListParams {
                offset: 10,
                limit: 20,
                keyword: Some("example".into()),
            })
            .await
            .unwrap();
        handle.abort();

        assert_eq!(page.total, 1);
        assert_eq!(page.rows[0].domain_id, 7);
        assert_eq!(page.rows[0].zone_name, "example.co.uk");
        let form = captured.lock().await.clone().unwrap();
        assert_eq!(form.get("uid"), Some(&UID.to_string()));
        let timestamp = form.get("timestamp").unwrap();
        assert_eq!(timestamp.len(), 10);
        assert_eq!(form.get("offset"), Some(&"10".into()));
        assert_eq!(form.get("limit"), Some(&"20".into()));
        assert_eq!(form.get("kw"), Some(&"example".into()));
        assert_eq!(form.get("sign"), Some(&sign_request(UID, timestamp, KEY)));
    }

    #[tokio::test]
    async fn domain_detail_validates_code_data_envelope_and_record_lines() {
        let router = Router::new().route(
            "/api/domain/7",
            post(|| async {
                Json(json!({
                    "code": 0,
                    "data": {
                        "id": 7,
                        "name": "example.co.uk",
                        "config": {"type": "dnsmgr"},
                        "recordcount": 3,
                        "minTTL": "60",
                        "recordLine": [{"id": 0, "name": "default", "parent": null}]
                    }
                }))
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let detail = client(&base_url).get_domain(7).await.unwrap();
        handle.abort();
        assert_eq!(detail.domain.zone_name, "example.co.uk");
        assert_eq!(detail.domain.provider_type.as_deref(), Some("dnsmgr"));
        assert_eq!(detail.min_ttl, Some(60));
        assert_eq!(detail.record_lines[0].id, "0");
    }

    #[tokio::test]
    async fn record_list_supports_documented_filters_and_pagination() {
        let captured = Arc::new(Mutex::new(None));
        let captured_for_handler = captured.clone();
        let router = Router::new().route(
            "/api/record/data/7",
            post(move |Form(form): Form<HashMap<String, String>>| {
                let captured = captured_for_handler.clone();
                async move {
                    *captured.lock().await = Some(form);
                    Json(json!({
                        "total": 1,
                        "rows": [{
                            "RecordId": "r-1", "Domain": "example.co.uk", "Name": "op1",
                            "Type": "A", "Value": "192.0.2.10", "Line": "default",
                            "LineName": "default", "TTL": 300, "Status": "1", "MX": null,
                            "Weight": null, "Remark": null, "UpdateTime": "2026-08-26 00:00:00"
                        }]
                    }))
                }
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let page = client(&base_url)
            .list_records(
                7,
                &RecordListParams {
                    offset: 20,
                    limit: 10,
                    keyword: Some("op".into()),
                    subdomain: Some("op1".into()),
                    value: Some("192.0.2.10".into()),
                    record_type: Some("A".into()),
                    line: Some("default".into()),
                    status: Some("1".into()),
                },
            )
            .await
            .unwrap();
        handle.abort();

        assert_eq!(page.rows[0].record_id, "r-1");
        assert_eq!(page.rows[0].priority, None);
        let form = captured.lock().await.clone().unwrap();
        assert_eq!(form.get("subdomain"), Some(&"op1".into()));
        assert_eq!(form.get("type"), Some(&"A".into()));
        assert_eq!(form.get("status"), Some(&"1".into()));
    }

    #[tokio::test]
    async fn record_list_accepts_strict_provider_bare_array() {
        let router = Router::new().route(
            "/api/record/data/7",
            post(|| async {
                Json(json!([{
                    "RecordId": "r-array", "Domain": "example.co.uk", "Name": "op1",
                    "Type": "AAAA", "Value": "2001:db8::10", "Line": 0,
                    "LineName": "default", "TTL": 300, "Status": "1", "MX": null,
                    "Weight": null, "Remark": null, "UpdateTime": null
                }]))
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let page = client(&base_url)
            .list_records(7, &RecordListParams::default())
            .await
            .unwrap();
        handle.abort();

        assert_eq!(page.total, 1);
        assert!(!page.authoritative_total);
        assert_eq!(page.rows[0].record_id, "r-array");
        assert_eq!(page.rows[0].record_type, "AAAA");
        assert_eq!(page.rows[0].line, "0");
    }

    #[tokio::test]
    async fn record_list_rejects_malformed_provider_bare_array_row() {
        let router = Router::new().route(
            "/api/record/data/7",
            post(|| async {
                Json(json!([{
                    "RecordId": "r-array", "Name": "op1", "Type": "A",
                    "Value": "192.0.2.10", "Line": "default", "TTL": "wrong",
                    "Status": "1"
                }]))
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let result = client(&base_url)
            .list_records(7, &RecordListParams::default())
            .await;
        handle.abort();

        assert!(matches!(result, Err(DnsMgrError::MalformedResponse(_))));
    }

    #[tokio::test]
    async fn create_and_update_record_use_the_audited_signed_form_contract() {
        let captured = Arc::new(Mutex::new(Vec::<HashMap<String, String>>::new()));
        let add_capture = captured.clone();
        let update_capture = captured.clone();
        let router = Router::new()
            .route(
                "/api/record/add/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let captured = add_capture.clone();
                    async move {
                        captured.lock().await.push(form);
                        Json(json!({"code": 0, "msg": "accepted"}))
                    }
                }),
            )
            .route(
                "/api/record/update/7",
                post(move |Form(form): Form<HashMap<String, String>>| {
                    let captured = update_capture.clone();
                    async move {
                        captured.lock().await.push(form);
                        Json(json!({"code": 0, "msg": "accepted"}))
                    }
                }),
            );
        let (base_url, handle) = spawn_mock(router).await;
        let request = DnsMgrRecordMutation {
            host: "op1".into(),
            record_type: "A".into(),
            value: "192.0.2.10".into(),
            line: "default".into(),
            ttl: 600,
        };
        client(&base_url).create_record(7, &request).await.unwrap();
        client(&base_url)
            .update_record(7, "record-1", &request)
            .await
            .unwrap();
        handle.abort();

        let forms = captured.lock().await;
        assert_eq!(forms.len(), 2);
        for form in forms.iter() {
            assert_eq!(form.get("name").map(String::as_str), Some("op1"));
            assert_eq!(form.get("type").map(String::as_str), Some("A"));
            assert_eq!(form.get("value").map(String::as_str), Some("192.0.2.10"));
            assert_eq!(form.get("line").map(String::as_str), Some("default"));
            assert_eq!(form.get("ttl").map(String::as_str), Some("600"));
            assert!(form.contains_key("uid"));
            assert!(form.contains_key("timestamp"));
            assert!(form.contains_key("sign"));
            assert!(!form.contains_key("mx"));
            assert!(!form.contains_key("weight"));
            assert!(!form.contains_key("remark"));
        }
        assert!(!forms[0].contains_key("recordid"));
        assert_eq!(
            forms[1].get("recordid").map(String::as_str),
            Some("record-1")
        );
    }

    #[tokio::test]
    async fn record_mutation_is_single_attempt_and_failures_remain_typed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_handler = attempts.clone();
        let router = Router::new().route(
            "/api/record/add/7",
            post(move || {
                attempts_for_handler.fetch_add(1, Ordering::SeqCst);
                async { (AxumStatusCode::INTERNAL_SERVER_ERROR, "unavailable") }
            }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let result = client(&base_url).create_record(7, &mutation()).await;
        handle.abort();
        assert_eq!(
            result,
            Err(DnsMgrError::RateLimitedOrTemporarilyUnavailable)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "write must never retry");

        let forbidden = Router::new().route(
            "/api/record/add/7",
            post(|| async { (AxumStatusCode::FORBIDDEN, "forbidden") }),
        );
        let (base_url, handle) = spawn_mock(forbidden).await;
        assert_eq!(
            client(&base_url).create_record(7, &mutation()).await,
            Err(DnsMgrError::Permission)
        );
        handle.abort();

        let rejected = Router::new().route(
            "/api/record/add/7",
            post(|| async { Json(json!({"code": -1, "msg": "provider rejected"})) }),
        );
        let (base_url, handle) = spawn_mock(rejected).await;
        assert!(matches!(
            client(&base_url).create_record(7, &mutation()).await,
            Err(DnsMgrError::ProviderFailure(_))
        ));
        handle.abort();
    }

    #[tokio::test]
    async fn malformed_mutation_response_fails_closed() {
        for response in [json!([]), json!({}), json!({"code": "0"})] {
            let router = Router::new().route(
                "/api/record/add/7",
                post({
                    let response = response.clone();
                    move || async move { Json(response) }
                }),
            );
            let (base_url, handle) = spawn_mock(router).await;
            let result = client(&base_url).create_record(7, &mutation()).await;
            handle.abort();
            assert!(matches!(
                result,
                Err(DnsMgrError::ProtocolContractViolation(_))
            ));
        }
    }

    #[tokio::test]
    async fn empty_rows_are_valid_but_have_no_zone_validity_claim() {
        let router = Router::new().route(
            "/api/record/data/7",
            post(|| async { Json(json!({"total": 0, "rows": []})) }),
        );
        let (base_url, handle) = spawn_mock(router).await;
        let page = client(&base_url)
            .list_records(
                7,
                &RecordListParams {
                    limit: 10,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        handle.abort();
        assert_eq!(page.total, 0);
        assert!(page.rows.is_empty());
    }

    #[tokio::test]
    async fn error_statuses_and_business_failures_are_typed() {
        let forbidden = Router::new().route(
            "/api/domain",
            post(|| async { (AxumStatusCode::FORBIDDEN, "forbidden") }),
        );
        let (base_url, handle) = spawn_mock(forbidden).await;
        assert_eq!(
            client(&base_url)
                .list_domains(&DomainListParams {
                    limit: 10,
                    ..Default::default()
                })
                .await,
            Err(DnsMgrError::Permission)
        );
        handle.abort();

        let business_failure = Router::new().route(
            "/api/domain",
            post(|| async { Json(json!({"code": -1, "msg": "签名错误"})) }),
        );
        let (base_url, handle) = spawn_mock(business_failure).await;
        let error = client(&base_url)
            .list_domains(&DomainListParams {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap_err();
        handle.abort();
        assert!(matches!(error, DnsMgrError::ProviderFailure(_)));
        assert_eq!(
            error.to_string(),
            "DNSMgr provider failure: upstream returned code -1"
        );
        assert!(!error.to_string().contains(KEY));
    }

    #[tokio::test]
    async fn malformed_zone_names_fail_closed() {
        for zone in ["", ".", "bad..example", "-bad.example", "bad_.example"] {
            let router = Router::new().route(
                "/api/domain",
                post(move || async move {
                    Json(json!({"total": 1, "rows": [{"id": 7, "name": zone}]}))
                }),
            );
            let (base_url, handle) = spawn_mock(router).await;
            let result = client(&base_url)
                .list_domains(&DomainListParams::default())
                .await;
            handle.abort();
            assert!(matches!(
                result,
                Err(DnsMgrError::ProtocolContractViolation(_))
            ));
        }
    }

    #[tokio::test]
    async fn malformed_json_missing_fields_and_wrong_types_fail_closed() {
        let cases = [
            json!("not an object"),
            json!({"total": 1, "rows": [{}]}),
            json!({"total": 1, "rows": [{"id": "wrong", "name": "example.test"}]}),
        ];
        for body in cases {
            let router = Router::new().route(
                "/api/domain",
                post({
                    let body = body.clone();
                    move || async move { Json(body) }
                }),
            );
            let (base_url, handle) = spawn_mock(router).await;
            let result = client(&base_url)
                .list_domains(&DomainListParams {
                    limit: 10,
                    ..Default::default()
                })
                .await;
            handle.abort();
            assert!(matches!(result, Err(DnsMgrError::MalformedResponse(_))));
        }
    }

    #[tokio::test]
    async fn oversized_response_and_redirect_are_rejected() {
        let oversized = Router::new().route(
            "/api/domain",
            post(|| async {
                let mut response = Response::new("x".repeat(MAX_RESPONSE_BYTES + 1));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                response
            }),
        );
        let (base_url, handle) = spawn_mock(oversized).await;
        let result = client(&base_url)
            .list_domains(&DomainListParams {
                limit: 10,
                ..Default::default()
            })
            .await;
        handle.abort();
        assert!(matches!(result, Err(DnsMgrError::MalformedResponse(_))));

        let redirect = Router::new().route(
            "/api/domain",
            post(|| async {
                (
                    AxumStatusCode::FOUND,
                    [(header::LOCATION, "http://different-origin.test/api/domain")],
                    "redirect",
                )
            }),
        );
        let (base_url, handle) = spawn_mock(redirect).await;
        let result = client(&base_url)
            .list_domains(&DomainListParams {
                limit: 10,
                ..Default::default()
            })
            .await;
        handle.abort();
        assert_eq!(
            result,
            Err(DnsMgrError::ProtocolContractViolation(
                "redirect response is not allowed".into()
            ))
        );
    }

    #[tokio::test]
    async fn https_does_not_disable_certificate_verification() {
        let router = Router::new().route(
            "/api/domain",
            post(|| async { Json(json!({"total": 0, "rows": []})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config =
            DnsMgrClientConfig::new(format!("https://127.0.0.1:{port}").as_str(), UID, KEY)
                .unwrap();
        let result = DnsMgrClient::new(config)
            .unwrap()
            .list_domains(&DomainListParams {
                limit: 10,
                ..Default::default()
            })
            .await;
        handle.abort();
        assert!(matches!(
            result,
            Err(DnsMgrError::Transport(_)) | Err(DnsMgrError::Timeout)
        ));
    }

    async fn spawn_mock(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (base_url, handle)
    }

    fn client(base_url: &str) -> DnsMgrClient {
        let config = DnsMgrClientConfig::new(base_url, UID, KEY).unwrap();
        DnsMgrClient::new(config).unwrap()
    }

    fn mutation() -> DnsMgrRecordMutation {
        DnsMgrRecordMutation {
            host: "op1".into(),
            record_type: "A".into(),
            value: "192.0.2.10".into(),
            line: "default".into(),
            ttl: 600,
        }
    }
}
