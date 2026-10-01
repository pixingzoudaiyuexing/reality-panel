//! Multi-A uses the existing binding/sync TEXT columns. A singleton remains
//! the legacy scalar; a set is a canonical JSON array. Provider record IDs use
//! the same scalar/array representation, so no schema migration is necessary.
use super::*;
use std::collections::BTreeSet;

pub(crate) fn encode_dns_values(values: BTreeSet<String>) -> String {
    if values.len() == 1 {
        values.into_iter().next().unwrap()
    } else {
        serde_json::to_string(&values).expect("string set serialization")
    }
}

fn decode_strings(value: &str) -> Result<BTreeSet<String>, ()> {
    if value.starts_with('[') {
        serde_json::from_str(value).map_err(|_| ())
    } else if !value.is_empty() {
        Ok(BTreeSet::from([value.to_owned()]))
    } else {
        Ok(BTreeSet::new())
    }
}

pub(crate) fn decode_dns_values(value: &str) -> Result<BTreeSet<Ipv4Addr>, ()> {
    decode_strings(value)?
        .into_iter()
        .map(|v| v.parse().map_err(|_| ()))
        .collect()
}

pub(crate) fn valid_dns_values(value: &str) -> bool {
    decode_dns_values(value).is_ok_and(|values| {
        !values.is_empty()
            && values
                .iter()
                .all(|ip| !ip.is_loopback() && !ip.is_unspecified())
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ObservedRecord {
    record_id: String,
    record_type: String,
    values: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DnsOverwriteConfirmation {
    pub rule_id: i64,
    pub zone_id: u64,
    pub fqdn: String,
    pub line_id: String,
    pub line_key: String,
    pub current: Vec<ObservedRecord>,
    pub desired: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfirmedOverwrite {
    confirmation: DnsOverwriteConfirmation,
    zone_id: u64,
}

fn override_key(rule_id: i64, line_key: &str) -> String {
    format!("dns_confirmed_overwrite:{rule_id}:{line_key}")
}

/// Preview is read-only. A confirmed retry grants replacement of the exact
/// observed scope/snapshot only, never permission to ignore a failed read.
pub(crate) async fn prepare_carrier_dns(
    db: &dyn Repository,
    group_id: i64,
    policy: &crate::service::relay_preference::CarrierPolicy,
    confirmed_snapshot: Option<&str>,
) -> Result<(Vec<DnsOverwriteConfirmation>, Vec<String>), String> {
    use crate::service::relay_preference::{self, CarrierLineMode, RelayDnsTarget};
    let rules = eligible_rule_ids_for_group(db, group_id)
        .await
        .map_err(|e| e.to_string())?;
    let mut lines: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let mut warnings = Vec::new();
    let old = relay_preference::load_preference(db, group_id)
        .await
        .map_err(|e| e.to_string())?;
    let default = policy
        .default_node_id
        .as_ref()
        .or(old.carrier_policy.default_node_id.as_ref())
        .or(old.preferred_node_id.as_ref());
    let selections =
        default
            .map(|id| ("default", Some(id)))
            .into_iter()
            .chain(policy.bindings.iter().map(|b| {
                (
                    b.line_id.as_str(),
                    match b.mode {
                        CarrierLineMode::Node => b.node_id.as_ref(),
                        CarrierLineMode::FollowDefault => default,
                    },
                )
            }));
    for (line, id) in selections {
        lines.entry(line.to_owned()).or_default();
        let value = match id {
            Some(id) => relay_preference::stored_node_public_ipv4(db, group_id, id)
                .await
                .map_err(|e| e.to_string())?,
            None => RelayDnsTarget::NotSet,
        };
        if let RelayDnsTarget::Resolved(ip) = value {
            lines.entry(line.to_owned()).or_default().insert(ip);
        } else {
            warnings.push(format!(
                "TARGET_IPV4_UNAVAILABLE:{line}:{}",
                id.map(String::as_str).unwrap_or("unconfigured")
            ));
        }
    }
    let configured = lines.keys().cloned().collect::<BTreeSet<_>>();
    for binding in &old.carrier_policy.bindings {
        if ProviderLine::from_provider(&binding.line_id, None).key == DEFAULT_LINE_KEY {
            continue;
        }
        if !configured.contains(&binding.line_id) {
            lines.entry(binding.line_id.clone()).or_default();
        }
    }
    if rules.is_empty() {
        return Ok((Vec::new(), warnings));
    }
    let Some(client) = load_client(db).await.map_err(|e| e.to_string())? else {
        return Ok((Vec::new(), warnings));
    };
    let mut conflicts = Vec::new();
    let mut approvals = Vec::new();
    for rule_id in rules {
        let rule = RuleRepository::find_rule_by_id(db, rule_id, &ResourceScope::All)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("rule disappeared")?;
        let fqdn = normalize_fqdn(rule.sni.as_deref().unwrap_or_default())
            .map_err(|_| "invalid DNS name")?;
        let zone = match resolve_zone(&client, &fqdn).await {
            ZoneResolution::ZoneResolved(zone) => zone,
            ZoneResolution::NoMatchingZone => return Err("no matching DNS zone".into()),
            ZoneResolution::UpstreamFailure(error) => return Err(error.to_string()),
        };
        // Read failures and unsupported lines are technical errors, not confirmations.
        let detail = client
            .get_domain(zone.domain_id)
            .await
            .map_err(|e| e.to_string())?;
        for (raw_line, desired) in &lines {
            if desired.is_empty() && configured.contains(raw_line) {
                continue;
            }
            let line = resolve_mutation_line(&ProviderLine::from_provider(raw_line, None), &detail)
                .ok_or("DNS carrier line unavailable")?;
            let current = read_set(&client, &zone, &line)
                .await
                .map_err(|e| e.to_string())?;
            let binding = db
                .find_dns_record_binding_for_rule(rule_id, fqdn.as_str(), "A", &line.key)
                .await
                .map_err(|e| e.to_string())?;
            if current.is_empty() || owns_set(binding.as_ref(), &fqdn, &zone, &line, &current) {
                continue;
            }
            let confirmation = DnsOverwriteConfirmation {
                rule_id,
                zone_id: zone.domain_id,
                fqdn: fqdn.as_str().into(),
                line_id: line.raw_id.clone(),
                line_key: line.key.clone(),
                current: observed(&current),
                desired: desired.clone(),
            };
            conflicts.push(confirmation.clone());
            approvals.push(ConfirmedOverwrite {
                confirmation,
                zone_id: zone.domain_id,
            });
        }
    }
    // A changed snapshot needs a new confirmation, even on a confirmed retry.
    if confirmed_snapshot != Some(confirmation_token(&conflicts).as_str()) {
        return Ok((conflicts, warnings));
    }
    // Complete all provider reads before writing any scoped approval.
    for approval in approvals {
        db.set(
            &override_key(
                approval.confirmation.rule_id,
                &approval.confirmation.line_key,
            ),
            &serde_json::to_string(&approval).map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    Ok((Vec::new(), warnings))
}

pub(crate) fn confirmation_token(conflicts: &[DnsOverwriteConfirmation]) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(conflicts).expect("DNS confirmation serialization"))
    )
}

fn observed(records: &[DnsMgrRecord]) -> Vec<ObservedRecord> {
    let mut result = records
        .iter()
        .map(|r| ObservedRecord {
            record_id: r.record_id.clone(),
            record_type: r.record_type.to_ascii_uppercase(),
            values: r.values.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| a.record_id.cmp(&b.record_id));
    result
}

async fn read_set(
    client: &DnsMgrClient,
    zone: &ResolvedZone,
    line: &ProviderLine,
) -> Result<Vec<DnsMgrRecord>, DnsMgrError> {
    let inventory = fetch_record_inventory(client, zone, None).await?;
    if !inventory.complete {
        return Err(DnsMgrError::ProtocolContractViolation(
            "incomplete DNS record inventory".into(),
        ));
    }
    Ok(inventory
        .records
        .into_iter()
        .filter(|r| {
            r.host.eq_ignore_ascii_case(&zone.host)
                && ProviderLine::from_provider(&r.line, None).key == line.key
                && (r.record_type.eq_ignore_ascii_case("A")
                    || r.record_type.eq_ignore_ascii_case("CNAME"))
        })
        .collect())
}

fn values_of(records: &[DnsMgrRecord]) -> Result<BTreeSet<Ipv4Addr>, ()> {
    if records
        .iter()
        .any(|r| !r.record_type.eq_ignore_ascii_case("A"))
    {
        return Err(());
    }
    records
        .iter()
        .flat_map(|r| &r.values)
        .map(|v| v.parse().map_err(|_| ()))
        .collect()
}

fn owns_set(
    binding: Option<&DnsRecordBinding>,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    records: &[DnsMgrRecord],
) -> bool {
    binding.is_some_and(|b| {
        b.state == "BOUND"
            && b.last_error_category.is_none()
            && b.fqdn == fqdn.as_str()
            && b.zone_id == zone.domain_id as i64
            && b.zone_name == zone.zone_name
            && b.host == zone.host
            && b.record_type == "A"
            && b.line_key == line.key
            && (line.key == DEFAULT_LINE_KEY || b.line == line.raw_id)
            && decode_strings(&b.record_id).ok()
                == Some(records.iter().map(|r| r.record_id.clone()).collect())
            && decode_dns_values(&b.desired_value).ok() == values_of(records).ok()
            && values_of(records).is_ok()
    })
}

async fn load_override(
    db: &dyn Repository,
    rule_id: i64,
    line: &ProviderLine,
) -> Result<Option<ConfirmedOverwrite>, EnsureRecordFailure> {
    db.get(&override_key(rule_id, &line.key))
        .await
        .map_err(|_| EnsureRecordFailure::Database)?
        .map(|raw| serde_json::from_str(&raw).map_err(|_| EnsureRecordFailure::OwnershipUnverified))
        .transpose()
}

fn override_matches(
    approval: &ConfirmedOverwrite,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
    records: &[DnsMgrRecord],
    desired: Option<&BTreeSet<String>>,
) -> bool {
    approval.zone_id == zone.domain_id
        && approval.confirmation.fqdn == fqdn.as_str()
        && approval.confirmation.line_key == line.key
        && approval.confirmation.current == observed(records)
        && desired.is_none_or(|values| values == &approval.confirmation.desired)
}

pub(super) async fn uses_set_reconciliation(
    db: &dyn Repository,
    input: &EnsureRecordInput,
) -> bool {
    if input.expected_value.starts_with('[') {
        return true;
    }
    if db
        .get(&override_key(input.rule_id, &input.line.key))
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return true;
    }
    db.find_dns_record_binding_for_rule(input.rule_id, &input.fqdn, "A", &input.line.key)
        .await
        .ok()
        .flatten()
        .is_some_and(|binding| {
            binding.record_id.starts_with('[') || binding.desired_value.starts_with('[')
        })
}

pub(super) async fn ensure_a_set(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
) -> EnsureRecordResult {
    match reconcile_set(db, client, input).await {
        Ok((record_id, changed)) => {
            if changed {
                EnsureRecordResult::Updated { record_id }
            } else {
                EnsureRecordResult::AlreadyCorrect { record_id }
            }
        }
        Err(EnsureRecordFailure::Upstream(error)) if error.is_ambiguous_write() => {
            EnsureRecordResult::MutationOutcomeUnknown
        }
        Err(failure) => EnsureRecordResult::Failed(failure),
    }
}

pub(super) async fn delete_a_set(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &DeleteRecordInput,
) -> DeleteRecordResult {
    match delete_set_inner(db, client, input).await {
        Ok(Some(record_id)) => DeleteRecordResult::Deleted { record_id },
        Ok(None) => DeleteRecordResult::AlreadyAbsent,
        Err(EnsureRecordFailure::Upstream(error)) if error.is_ambiguous_write() => {
            DeleteRecordResult::MutationOutcomeUnknown
        }
        Err(error) => DeleteRecordResult::Failed(error),
    }
}

async fn delete_set_inner(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &DeleteRecordInput,
) -> Result<Option<String>, EnsureRecordFailure> {
    let fqdn = normalize_fqdn(&input.fqdn).map_err(EnsureRecordFailure::InvalidInput)?;
    if !delete_is_authorized(db, input, &fqdn)
        .await
        .map_err(|_| EnsureRecordFailure::Database)?
    {
        return Err(EnsureRecordFailure::InvalidRule);
    }
    let zone = match resolve_zone(client, &fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => return Err(EnsureRecordFailure::NoMatchingZone),
        ZoneResolution::UpstreamFailure(error) => return Err(EnsureRecordFailure::Upstream(error)),
    };
    let detail = client
        .get_domain(zone.domain_id)
        .await
        .map_err(EnsureRecordFailure::Upstream)?;
    let line = resolve_mutation_line(&input.line, &detail)
        .ok_or(EnsureRecordFailure::ProviderLineUnavailable)?;
    let records = read_set(client, &zone, &line)
        .await
        .map_err(EnsureRecordFailure::Upstream)?;
    let binding = db
        .find_dns_record_binding_for_rule(input.rule_id, fqdn.as_str(), "A", &line.key)
        .await
        .map_err(|_| EnsureRecordFailure::Database)?;
    let approval = load_override(db, input.rule_id, &line).await?;
    if !records.is_empty()
        && !owns_set(binding.as_ref(), &fqdn, &zone, &line, &records)
        && !approval.as_ref().is_some_and(|a| {
            override_matches(a, &fqdn, &zone, &line, &records, Some(&BTreeSet::new()))
        })
    {
        return Err(EnsureRecordFailure::OwnershipUnverified);
    }
    for record in &records {
        client
            .delete_record(zone.domain_id, &record.record_id)
            .await
            .map_err(EnsureRecordFailure::Upstream)?;
    }
    if !read_set(client, &zone, &line)
        .await
        .map_err(EnsureRecordFailure::Upstream)?
        .is_empty()
    {
        return Err(EnsureRecordFailure::PostWriteNotVerified);
    }
    if let Some(binding) = binding {
        set_binding_state(db, binding.id, "MISSING", None)
            .await
            .map_err(|_| EnsureRecordFailure::Database)?;
    }
    db.delete(&override_key(input.rule_id, &line.key))
        .await
        .map_err(|_| EnsureRecordFailure::Database)?;
    Ok((!records.is_empty())
        .then(|| encode_dns_values(records.iter().map(|r| r.record_id.clone()).collect())))
}

async fn reconcile_set(
    db: &dyn Repository,
    client: &DnsMgrClient,
    input: &EnsureRecordInput,
) -> Result<(String, bool), EnsureRecordFailure> {
    let fqdn = normalize_fqdn(&input.fqdn).map_err(EnsureRecordFailure::InvalidInput)?;
    let desired =
        decode_dns_values(&input.expected_value).map_err(|_| EnsureRecordFailure::InvalidRule)?;
    if desired.is_empty()
        || desired
            .iter()
            .any(|ip| ip.is_loopback() || ip.is_unspecified())
        || !upsert_is_authorized(db, input, &fqdn)
            .await
            .map_err(|_| EnsureRecordFailure::Database)?
    {
        return Err(EnsureRecordFailure::InvalidRule);
    }
    let zone = match resolve_zone(client, &fqdn).await {
        ZoneResolution::ZoneResolved(zone) => zone,
        ZoneResolution::NoMatchingZone => return Err(EnsureRecordFailure::NoMatchingZone),
        ZoneResolution::UpstreamFailure(e) => return Err(EnsureRecordFailure::Upstream(e)),
    };
    let detail = client
        .get_domain(zone.domain_id)
        .await
        .map_err(EnsureRecordFailure::Upstream)?;
    let line = resolve_mutation_line(&input.line, &detail)
        .ok_or(EnsureRecordFailure::ProviderLineUnavailable)?;
    let ttl = write_ttl(&detail).ok_or(EnsureRecordFailure::TtlOutOfRange)?;
    let current = read_set(client, &zone, &line)
        .await
        .map_err(EnsureRecordFailure::Upstream)?;
    let binding = db
        .find_dns_record_binding_for_rule(input.rule_id, fqdn.as_str(), "A", &line.key)
        .await
        .map_err(|_| EnsureRecordFailure::Database)?;
    let approval = load_override(db, input.rule_id, &line).await?;
    let desired_strings = desired
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let owned = owns_set(binding.as_ref(), &fqdn, &zone, &line, &current);
    let confirmed = approval.as_ref().is_some_and(|a| {
        override_matches(a, &fqdn, &zone, &line, &current, Some(&desired_strings))
    });
    if !current.is_empty() && !owned && !confirmed {
        return Err(EnsureRecordFailure::OwnershipUnverified);
    }
    let changed = values_of(&current).ok().as_ref() != Some(&desired);
    if changed {
        if crate::integrations::dnsmgr::a_record_uses_rrset(zone.provider_type.as_deref()) {
            let reusable = current
                .iter()
                .find(|r| r.record_type.eq_ignore_ascii_case("A"));
            // A provider RRset has one identity. Preserve it when updating values;
            // confirmed CNAMEs must be removed before creating the A RRset.
            for record in &current {
                if reusable.is_none_or(|a| a.record_id != record.record_id) {
                    client
                        .delete_record(zone.domain_id, &record.record_id)
                        .await
                        .map_err(EnsureRecordFailure::Upstream)?;
                }
            }
            let mutation = DnsMgrRecordMutation {
                host: zone.host.clone(),
                record_type: "A".into(),
                value: crate::integrations::dnsmgr::a_record_mutation_value(&desired),
                line: line.raw_id.clone(),
                ttl,
            };
            if let Some(record) = reusable {
                client
                    .update_record(zone.domain_id, &record.record_id, &mutation)
                    .await
                    .map_err(EnsureRecordFailure::Upstream)?;
            } else {
                client
                    .create_record(zone.domain_id, &mutation)
                    .await
                    .map_err(EnsureRecordFailure::Upstream)?;
            }
        } else {
            // Retain only complete records whose values belong to the desired set.
            // An adapter read-back RRset may contain several values in one ID.
            let mut retained = BTreeSet::new();
            for record in &current {
                let values = values_of(std::slice::from_ref(record)).ok();
                let keep = values.as_ref().is_some_and(|v| {
                    !v.is_empty() && v.is_subset(&desired) && v.is_disjoint(&retained)
                });
                if keep {
                    retained.extend(values.unwrap());
                } else {
                    client
                        .delete_record(zone.domain_id, &record.record_id)
                        .await
                        .map_err(EnsureRecordFailure::Upstream)?;
                }
            }
            for value in desired.difference(&retained) {
                client
                    .create_record(
                        zone.domain_id,
                        &DnsMgrRecordMutation {
                            host: zone.host.clone(),
                            record_type: "A".into(),
                            value: value.to_string(),
                            line: line.raw_id.clone(),
                            ttl,
                        },
                    )
                    .await
                    .map_err(EnsureRecordFailure::Upstream)?;
            }
        }
    }
    let actual = read_set(client, &zone, &line)
        .await
        .map_err(EnsureRecordFailure::Upstream)?;
    if values_of(&actual).ok().as_ref() != Some(&desired) {
        return Err(EnsureRecordFailure::PostWriteNotVerified);
    }
    let ids = encode_dns_values(actual.iter().map(|r| r.record_id.clone()).collect());
    persist_verified_binding(db, input, &fqdn, &zone, &line, &ids, binding.as_ref(), true)
        .await
        .map_err(|e| match e {
            PersistVerifiedBindingError::Database => EnsureRecordFailure::Database,
            PersistVerifiedBindingError::OwnershipUnverified => {
                EnsureRecordFailure::OwnershipUnverified
            }
        })?;
    db.delete(&override_key(input.rule_id, &line.key))
        .await
        .map_err(|_| EnsureRecordFailure::Database)?;
    Ok((ids, changed))
}

pub(super) async fn inspect_set(
    db: &dyn Repository,
    client: &DnsMgrClient,
    rule_id: i64,
    fqdn: &NormalizedFqdn,
    zone: &ResolvedZone,
    line: &ProviderLine,
) -> Result<Option<LineRecordSnapshot>, LineRecordSnapshotError> {
    let records = read_set(client, zone, line)
        .await
        .map_err(LineRecordSnapshotError::Provider)?;
    if records.is_empty() {
        return Ok(Some(LineRecordSnapshot::Absent));
    }
    let binding = db
        .find_dns_record_binding_for_rule(rule_id, fqdn.as_str(), "A", &line.key)
        .await
        .map_err(|_| LineRecordSnapshotError::Database)?;
    let approved = load_override(db, rule_id, line)
        .await
        .map_err(|_| LineRecordSnapshotError::Database)?;
    if owns_set(binding.as_ref(), fqdn, zone, line, &records)
        || approved
            .as_ref()
            .is_some_and(|a| override_matches(a, fqdn, zone, line, &records, None))
    {
        let a_values = records
            .iter()
            .filter(|r| r.record_type.eq_ignore_ascii_case("A"))
            .flat_map(|r| r.values.iter().cloned())
            .collect::<BTreeSet<_>>();
        if a_values.is_empty() {
            return Ok(Some(LineRecordSnapshot::Absent));
        }
        return Ok(Some(LineRecordSnapshot::PanelOwned {
            value: encode_dns_values(a_values),
            record_id: encode_dns_values(
                records
                    .iter()
                    .filter(|r| r.record_type.eq_ignore_ascii_case("A"))
                    .map(|r| r.record_id.clone())
                    .collect(),
            ),
        }));
    }
    Ok(None)
}
