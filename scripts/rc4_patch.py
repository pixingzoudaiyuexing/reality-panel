#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    file.write_text(text.replace(old, new, 1))


# 配置协议 v9：证书策略的 domain 允许为覆盖 SNI 的 DNS-01 通配符。
replace_once(
    "crates/shared/src/protocol.rs",
    '''/// v8 = Panel-selected ACME DNS-01. The gate prevents a v7 node from silently
/// ignoring DNS-01 hooks and the Panel-backed challenge lifecycle.
pub const CONFIG_PROTOCOL_VERSION: u32 = 8;''',
    '''/// v8 = Panel-selected ACME DNS-01. The gate prevents a v7 node from silently
/// ignoring DNS-01 hooks and the Panel-backed challenge lifecycle.
/// v9 = camouflage certificate `domain` may be a DNS-01 wildcard that covers
/// the concrete SNI. A v8 node rejects that semantic as an exact-domain
/// mismatch, so Panel and Node must upgrade together.
pub const CONFIG_PROTOCOL_VERSION: u32 = 9;''',
)

# Panel 配置生成：只有已有 Panel DNS ownership binding 的 SNI 才自动提升为通配符；
# 不猜公共后缀，且嵌套子域始终选择 SNI 的直接父域作为 wildcard scope。
replace_once(
    "crates/panel/src/service/node_config.rs",
    '''use crate::db::repo::{GroupRepository, ProfileScope, ResourceScope, TunnelProfileRepository};''',
    '''use crate::db::repo::{
    DnsRecordBindingRepository, DnsRecordSyncRepository, GroupRepository, ProfileScope,
    ResourceScope, TunnelProfileRepository,
};''',
)
replace_once(
    "crates/panel/src/service/node_config.rs",
    '''        if effective_rule.camouflage_enabled && effective_rule.node_transport == "nginx_sni" {
            if let Some(sni) = camouflage_sni {
                camouflage_by_sni
                    .entry(sni.clone())
                    .or_insert_with(|| CamouflageSiteDesired {
                        site_id: sni.replace('.', "_"),
                        sni: sni.clone(),
                        tls_listener_port: 8443,
                        local_backend: CamouflageLocalBackend::OpenList,
                        certificate: CamouflageCertificatePolicy {
                            domain: sni,
                            expected_public_ip: group.connect_host.trim().to_string(),
                            renew_before_days: 30,
                            // Reality Panel 的证书权威路径固定使用 Panel DNS-01。
                            // DNSMgr 未就绪时由依赖状态阻塞签发，不降级到 :80 HTTP-01。
                            challenge_method: AcmeChallengeMethod::Dns01,
                        },
                        enabled: true,
                    });
            }
        }''',
    '''        if effective_rule.camouflage_enabled && effective_rule.node_transport == "nginx_sni" {
            if let Some(sni) = camouflage_sni {
                let certificate_domain =
                    certificate_domain_for_rule(db, effective_rule.id, &sni).await?;
                camouflage_by_sni
                    .entry(sni.clone())
                    .or_insert_with(|| CamouflageSiteDesired {
                        site_id: sni.replace('.', "_"),
                        sni: sni.clone(),
                        tls_listener_port: 8443,
                        local_backend: CamouflageLocalBackend::OpenList,
                        certificate: CamouflageCertificatePolicy {
                            domain: certificate_domain,
                            expected_public_ip: group.connect_host.trim().to_string(),
                            renew_before_days: 30,
                            // Reality Panel 的证书权威路径固定使用 Panel DNS-01。
                            // DNSMgr 未就绪时由依赖状态阻塞签发，不降级到 :80 HTTP-01。
                            challenge_method: AcmeChallengeMethod::Dns01,
                        },
                        enabled: true,
                    });
            }
        }''',
)
replace_once(
    "crates/panel/src/service/node_config.rs",
    '''/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own''',
    '''/// 根据已经验证过的 Panel DNS ownership 计算证书作用域。
/// 没有 ownership binding 时保持单域名证书；绝不靠“最后两段域名”猜 zone。
async fn certificate_domain_for_rule(
    db: &dyn Repository,
    rule_id: i64,
    sni: &str,
) -> Result<String, DbError> {
    let exact = sni.trim_end_matches('.').to_ascii_lowercase();
    let Some(sync) = db.find_dns_record_sync(rule_id).await? else {
        return Ok(exact);
    };
    if !sync.fqdn.trim_end_matches('.').eq_ignore_ascii_case(&exact) {
        return Ok(exact);
    }
    let Some(binding) = db
        .find_dns_record_binding_for_rule(
            rule_id,
            &sync.fqdn,
            &sync.record_type,
            &sync.line_key,
        )
        .await?
    else {
        return Ok(exact);
    };
    Ok(wildcard_domain_for_managed_sni(&exact, &binding.zone_name)
        .unwrap_or(exact))
}

fn wildcard_domain_for_managed_sni(sni: &str, zone_name: &str) -> Option<String> {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone_name.trim_end_matches('.').to_ascii_lowercase();
    if sni == zone || zone.is_empty() {
        return None;
    }
    let zone_suffix = format!(".{zone}");
    if !sni.ends_with(&zone_suffix) {
        return None;
    }
    let (_, parent) = sni.split_once('.')?;
    if parent == zone || parent.ends_with(&zone_suffix) {
        Some(format!("*.{parent}"))
    } else {
        None
    }
}

/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own''',
)
# 在测试模块开头插入纯函数边界测试，避免公共后缀/多级域名回归。
replace_once(
    "crates/panel/src/service/node_config.rs",
    '''    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]''',
    '''    #[test]
    fn wildcard_scope_uses_direct_parent_inside_managed_zone() {
        assert_eq!(
            wildcard_domain_for_managed_sni("o1.13886.xyz", "13886.xyz").as_deref(),
            Some("*.13886.xyz")
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("a.b.example.com", "example.com").as_deref(),
            Some("*.b.example.com")
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("example.com", "example.com"),
            None
        );
        assert_eq!(
            wildcard_domain_for_managed_sni("evil-example.com", "example.com"),
            None
        );
    }

    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]''',
)

# Node ACME hook：Certbot 对 wildcard 会给出 *.example.com；Panel DNS challenge
# 的实际 owner 是 example.com，因此只剥离最前面的 wildcard 标签。
replace_once(
    "crates/node/src/acme_dns01.rs",
    '''    let sni = std::env::var("CERTBOT_DOMAIN").map_err(|_| "challenge domain is unavailable")?;
    let value =''',
    '''    let certbot_domain =
        std::env::var("CERTBOT_DOMAIN").map_err(|_| "challenge domain is unavailable")?;
    let sni = challenge_domain(&certbot_domain)?;
    let value =''',
)
replace_once(
    "crates/node/src/acme_dns01.rs",
    '''pub(crate) fn run_hook(args: &[String]) -> Result<(), String> {''',
    '''fn challenge_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    if domain.is_empty() || domain.contains('*') {
        return Err("challenge domain is invalid".into());
    }
    Ok(domain.to_ascii_lowercase())
}

pub(crate) fn run_hook(args: &[String]) -> Result<(), String> {''',
)
replace_once(
    "crates/node/src/acme_dns01.rs",
    '''    #[test]
    fn challenge_request_serializes_no_panel_credentials() {''',
    '''    #[test]
    fn wildcard_certbot_domain_maps_to_dns_challenge_base() {
        assert_eq!(
            challenge_domain("*.Example.COM.").unwrap(),
            "example.com"
        );
        assert_eq!(challenge_domain("op1.example.com").unwrap(), "op1.example.com");
        assert!(challenge_domain("foo.*.example.com").is_err());
    }

    #[test]
    fn challenge_request_serializes_no_panel_credentials() {''',
)

# Node certificate lifecycle：允许 exact 或单层 wildcard 覆盖 SNI；Certbot cert-name
# 使用安全目录名，但 -d 仍传真实 wildcard。SAN 校验也按 TLS wildcard 规则匹配。
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''    /// Must exactly match the local TLS camouflage SNI.
    pub domain: String,''',
    '''    /// Exact SNI or a one-label DNS-01 wildcard that covers the local SNI.
    pub domain: String,''',
)
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''    let mut args = vec![
        "certonly".into(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--cert-name".into(),
        policy.domain.clone(),
        "-d".into(),
        policy.domain.clone(),
    ];''',
    '''    let mut args = vec![
        "certonly".into(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--cert-name".into(),
        certbot_certificate_name(&policy.domain)?,
        "-d".into(),
        policy.domain.clone(),
    ];''',
)
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''fn validate_policy(
    site: &CamouflageSite,
    policy: &CertificateLifecyclePolicy,
) -> Result<(), String> {
    if policy.domain != site.sni || !is_valid_domain(&policy.domain) {
        return Err("certificate domain must exactly match camouflage SNI".into());
    }''',
    '''fn validate_policy(
    site: &CamouflageSite,
    policy: &CertificateLifecyclePolicy,
) -> Result<(), String> {
    if !is_valid_certificate_domain(&policy.domain)
        || !certificate_name_matches_host(&policy.domain, &site.sni)
    {
        return Err("certificate domain must cover camouflage SNI".into());
    }''',
)
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(value) if *value == domain))
    {''',
    '''        .iter()
        .any(|name| matches!(name, GeneralName::DNSName(value) if certificate_name_matches_host(value, domain)))
    {''',
)
# is_valid_domain 前增加 wildcard helpers。
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''fn is_valid_domain(value: &str) -> bool {''',
    '''fn is_valid_certificate_domain(value: &str) -> bool {
    match value.strip_prefix("*.") {
        Some(base) => is_valid_domain(base) && base.split('.').count() >= 2,
        None => is_valid_domain(value),
    }
}

fn certificate_name_matches_host(certificate_name: &str, host: &str) -> bool {
    if certificate_name.eq_ignore_ascii_case(host) {
        return true;
    }
    let Some(base) = certificate_name.strip_prefix("*.") else {
        return false;
    };
    let suffix = format!(".{base}");
    let Some(label) = host.strip_suffix(&suffix) else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

fn certbot_certificate_name(domain: &str) -> Result<String, String> {
    if !is_valid_certificate_domain(domain) {
        return Err("invalid certificate domain".into());
    }
    Ok(match domain.strip_prefix("*.") {
        Some(base) => format!("wildcard-{base}"),
        None => domain.to_string(),
    })
}

fn is_valid_domain(value: &str) -> bool {''',
)
# 在现有 certbot 测试前插入 wildcard 参数/匹配测试。
replace_once(
    "crates/node/src/forwarder/certificate_lifecycle.rs",
    '''    #[test]
    fn first_issuance_uses_certonly_without_a_renewal_record() {''',
    '''    #[test]
    fn wildcard_certificate_scope_covers_exactly_one_label() {
        assert!(certificate_name_matches_host("*.example.com", "op1.example.com"));
        assert!(!certificate_name_matches_host("*.example.com", "a.b.example.com"));
        assert!(!certificate_name_matches_host("*.example.com", "example.com"));
        assert!(is_valid_certificate_domain("*.example.com"));
        assert!(!is_valid_certificate_domain("*.com"));
    }

    #[test]
    fn wildcard_certbot_args_keep_wildcard_but_use_safe_cert_name() {
        let mut policy = policy("site.example.com");
        policy.domain = "*.example.com".into();
        policy.challenge_method = AcmeChallengeMethod::Dns01;
        let args = certbot_args(
            &policy,
            false,
            Path::new("/unused"),
            Path::new("/opt/relay-node/relay-node"),
        )
        .unwrap();
        assert!(args.windows(2).any(|pair| pair == ["-d", "*.example.com"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--cert-name", "wildcard-example.com"]));
    }

    #[test]
    fn first_issuance_uses_certonly_without_a_renewal_record() {''',
)

# Panel API：wildcard hook 只可请求配置中明确声明 wildcard 的 base domain；
# 同时把业务错误码写入日志，不记录 validation token。
replace_once(
    "crates/panel/src/api/node.rs",
    '''    let authorized = config.camouflage_sites.iter().any(|site| {
        site.enabled
            && site
                .sni
                .eq_ignore_ascii_case(request.sni.trim_end_matches('.'))
            && site.certificate.challenge_method == AcmeChallengeMethod::Dns01
    });''',
    '''    let requested_domain = request.sni.trim_end_matches('.');
    let authorized = config.camouflage_sites.iter().any(|site| {
        let certificate_domain = site.certificate.domain.trim_end_matches('.');
        let certificate_authorized = certificate_domain.eq_ignore_ascii_case(requested_domain)
            || certificate_domain
                .strip_prefix("*.")
                .is_some_and(|base| base.eq_ignore_ascii_case(requested_domain));
        site.enabled
            && certificate_authorized
            && site.certificate.challenge_method == AcmeChallengeMethod::Dns01
    });''',
)
replace_once(
    "crates/panel/src/api/node.rs",
    '''        Err(error) => {
            let status = match error {''',
    '''        Err(error) => {
            let code = error.code();
            tracing::warn!(
                operation = if present { "present" } else { "cleanup" },
                node_id = %request.node_id,
                domain = %request.sni,
                code,
                "ACME DNS-01 operation failed"
            );
            let status = match &error {''',
)
replace_once(
    "crates/panel/src/api/node.rs",
    '''            (status, Json(serde_json::json!({"code": error.code()}))).into_response()''',
    '''            (status, Json(serde_json::json!({"code": code}))).into_response()''',
)

# Panel DNS-01：真实 Provider 的多 TXT 模型不同。
# Huawei 一个 recordset 带 records[]；Cloudflare/默认模式是多个同名 TXT record。
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeState {''',
    '''#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
struct ChallengeState {''',
)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''    provider_record_id: Option<String>,
    value_sha256: String,''',
    '''    provider_record_id: Option<String>,
    /// rc.4 起持久化 Provider 的 TXT mutation 语义。旧 rc.3 状态没有此字段，
    /// cleanup 时会从 DNSMgr domain detail 重新推导，避免升级时误删 RRset。
    #[serde(default)]
    txt_mode: Option<TxtMutationMode>,
    value_sha256: String,''',
)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''    let ttl = write_ttl(&detail).ok_or(AcmeDns01Error::Provider)?;
    let challenge_host =''',
    '''    let ttl = write_ttl(&detail).ok_or(AcmeDns01Error::Provider)?;
    let txt_mode = txt_mutation_mode(detail.domain.provider_type.as_deref());
    let challenge_host =''',
)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''        provider_record_id: None,
        value_sha256: value_fingerprint(&request.value),''',
    '''        provider_record_id: None,
        txt_mode: Some(txt_mode),
        value_sha256: value_fingerprint(&request.value),''',
)
# 整体替换 provider present 函数。
old_present = '''async fn present_provider_value(
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

    let mutation = if records.is_empty() {
        DnsMgrRecordMutation {
            host: state.host.clone(),
            record_type: "TXT".into(),
            value: value.to_string(),
            line: state.line.clone(),
            ttl,
        }
    } else if records.len() == 1 {
        let mut values = records[0].values.clone();
        values.push(value.to_string());
        DnsMgrRecordMutation {
            host: state.host.clone(),
            record_type: "TXT".into(),
            value: encode_provider_values(&values)?,
            line: state.line.clone(),
            ttl,
        }
    } else {
        return Err(AcmeDns01Error::Conflict);
    };

    if records.is_empty() {
        client
            .create_record(state.zone_id, &mutation)
            .await
            .map_err(map_provider_error)?;
    } else {
        client
            .update_record(state.zone_id, &records[0].record_id, &mutation)
            .await
            .map_err(map_provider_error)?;
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
'''
new_present = '''async fn present_provider_value(
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
'''
replace_once("crates/panel/src/service/acme_dns01.rs", old_present, new_present)

old_cleanup = '''async fn cleanup_state(
    db: &dyn Repository,
    client: &DnsMgrClient,
    state: &mut ChallengeState,
) -> Result<(), AcmeDns01Error> {
    state.cleanup_state = "CLEANUP_PENDING".into();
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
        let remaining = record
            .values
            .iter()
            .filter(|value| value_fingerprint(&normalize_txt_value(value)) != state.value_sha256)
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
                value: encode_provider_values(&remaining)?,
                line: state.line.clone(),
                ttl: u32::try_from(record.ttl).map_err(|_| AcmeDns01Error::Provider)?,
            };
            client
                .update_record(state.zone_id, &record.record_id, &mutation)
                .await
                .map_err(map_provider_error)?;
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
'''
new_cleanup = '''async fn cleanup_state(
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
                        ttl: u32::try_from(record.ttl)
                            .map_err(|_| AcmeDns01Error::Provider)?,
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
'''
replace_once("crates/panel/src/service/acme_dns01.rs", old_cleanup, new_cleanup)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''fn encode_provider_values(values: &[String]) -> Result<String, AcmeDns01Error> {
    if values.is_empty() || values.iter().any(|value| value.contains(',')) {
        return Err(AcmeDns01Error::Conflict);
    }
    Ok(values.join(","))
}''',
    '''fn encode_huawei_recordset_values(values: &[String]) -> Result<String, AcmeDns01Error> {
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
                || value.contains('\\\\')
            {
                Err(AcmeDns01Error::Conflict)
            } else {
                Ok(format!("\\\"{value}\\\""))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}''',
)
# 测试 mock 按真实 DNSMgr Huawei wrapper 的规则解析 mutation，旧 A,B 写法会测试失败。
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''    fn request_for(node_id: &str, sni: &str, value: &str) -> AcmeDns01Request {''',
    '''    fn decode_huawei_mutation(value: &str) -> Vec<String> {
        let wrapped = if value.starts_with('"') {
            value.to_string()
        } else {
            format!("\\\"{value}\\\"")
        };
        wrapped
            .split(',')
            .map(normalize_txt_value)
            .collect::<Vec<_>>()
    }

    fn request_for(node_id: &str, sni: &str, value: &str) -> AcmeDns01Request {''',
)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''state.values = form["value"].split(',').map(str::to_string).collect();''',
    '''state.values = decode_huawei_mutation(&form["value"]);''',
)
# 上一替换在 add/update 两处，应为 2 次；replace_once 只能一次，因此第二处再替换。
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''state.values = form["value"].split(',').map(str::to_string).collect();''',
    '''state.values = decode_huawei_mutation(&form["value"]);''',
)
replace_once(
    "crates/panel/src/service/acme_dns01.rs",
    '''    fn provider_values_preserve_every_entry_and_fail_closed_on_commas() {
        assert_eq!(
            encode_provider_values(&["old".into(), "challenge".into()]).unwrap(),
            "old,challenge"
        );
        assert_eq!(
            encode_provider_values(&["unrelated,content".into(), "challenge".into()]),
            Err(AcmeDns01Error::Conflict)
        );
    }''',
    '''    fn huawei_recordset_values_quote_each_member_and_fail_closed() {
        assert_eq!(
            encode_huawei_recordset_values(&["old".into(), "challenge".into()]).unwrap(),
            "\\\"old\\\",\\\"challenge\\\""
        );
        assert_eq!(
            encode_huawei_recordset_values(&[
                "unrelated,content".into(),
                "challenge".into()
            ]),
            Err(AcmeDns01Error::Conflict)
        );
        assert_eq!(txt_mutation_mode(Some("huawei")), TxtMutationMode::HuaweiRecordSet);
        assert_eq!(
            txt_mutation_mode(Some("cloudflare")),
            TxtMutationMode::SeparateRecords
        );
    }''',
)

print("rc4 source patch applied")
