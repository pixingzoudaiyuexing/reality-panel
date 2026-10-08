#[tokio::test]
async fn fast_sync_preflight_and_rollback_snapshots_share_complete_zone_observation() {
    let f = fixture().await;
    let (status, result) = http(&f, "PUT", "/groups/10/routing-apply", json!({"mode":"carrier", "default_node_ids":["n1","n2"], "bindings":[{"line_id":"unicom", "mode":"follow_default"},{"line_id":"telecom", "mode":"node","node_id":"n2"}]})).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{result}");
    assert_eq!(result["code"], 0, "{result}");
    assert_eq!(f.mock.state.list_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(f.mock.state.detail_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(f.mock.state.total_mutations(), 0);
}

#[tokio::test]
async fn fast_sync_noop_still_observes_provider_drift_and_recreates_missing_owned_sets() {
    let f = fixture().await;
    apply_defaults(&f, &["n1", "n2"]).await;
    let body = json!({"mode":"carrier", "default_node_ids":["n1","n2"], "default_node_id":"n1", "bindings":[{"line_id":"unicom", "mode":"follow_default"}]});
    let before = f.mock.state.list_attempts.load(Ordering::SeqCst);
    let writes = f.mock.state.total_mutations();
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
    assert_eq!(response["code"], 0, "{response}");
    assert_eq!(f.mock.state.list_attempts.load(Ordering::SeqCst) - before, 1);
    assert_eq!(f.mock.state.total_mutations(), writes);
    f.mock.state.records.lock().unwrap().clear();
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", body).await;
    assert_eq!(response["code"], 0, "{response}");
    assert_eq!(preference::load_preference(f.db.as_ref(), 10).await.unwrap().state, preference::RelayPreferencePhase::Switching);
    reconcile_group(&f, 10).await;
    assert_eq!(actual_values(&f, "op1", "default"), expected(&["1.1.1.1","2.2.2.2"]));
    assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["1.1.1.1","2.2.2.2"]));
}

#[tokio::test]
async fn fast_sync_cached_ownership_cannot_overwrite_later_external_drift() {
    let f = fixture().await;
    apply_defaults(&f, &["n1","n2"]).await;
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", json!({"mode":"carrier", "default_node_ids":["n1","n6"], "bindings":[{"line_id":"unicom","mode":"follow_default"}]})).await;
    assert_eq!(response["code"], 0);
    let writes = f.mock.state.total_mutations();
    with_provider_observations(async {
        let zone = zone();
        let line = ProviderLine::default();
        let snapshot = observations::prewrite_records(&f.mock.client, &zone, &line).await.unwrap();
        assert!(!snapshot.is_empty());
        for record in f.mock.state.records.lock().unwrap().iter_mut().filter(|r| ProviderLine::from_provider(&r.line, None).key == DEFAULT_LINE_KEY) {
            record.values = vec!["9.9.9.9".into()];
        }
        let result = ensure_record(f.db.as_ref(), &f.mock.client, &EnsureRecordInput {rule_id:100, fqdn:"op1.example.com".into(), record_type:DnsRecordType::A, expected_value:encode_dns_values(expected(&["1.1.1.1","6.6.6.6"])), line}).await;
        assert!(matches!(result, EnsureRecordResult::Failed(EnsureRecordFailure::OwnershipUnverified)), "{result:?}");
    }).await;
    assert_eq!(f.mock.state.total_mutations(), writes);
    assert_eq!(actual_values(&f, "op1", "default"), expected(&["9.9.9.9"]));
}

#[tokio::test]
async fn fast_sync_worker_uses_four_independent_mutations_and_fresh_readback() {
    let f = fixture().await;
    f.mock.state.records.lock().unwrap().extend((0..110).map(|i| {
        let mut r = record(&format!("protected-{i}"), "A", "8.8.8.8", "default_view");
        r.host = format!("protected-{i}"); r
    }));
    for i in 1..=5 {
        sqlx::query("INSERT INTO forward_rules(id,name,uid,listen_port,device_group_in,target_addr,target_port,public_transport,node_transport,protocol,sni,camouflage_enabled) VALUES (?,?,1,?,10,'127.0.0.1',80,'nginx_sni','nginx_sni','tcp',?,1)")
            .bind(1000+i).bind(format!("perf-{i}")).bind(23000+i).bind(format!("perf-{i}.example.com")).execute(&f.pool).await.unwrap();
    }
    f.mock.state.mutation_delay_ms.store(80, Ordering::SeqCst);
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", json!({"mode":"carrier", "default_node_ids":["n1","n2"], "bindings":[{"line_id":"unicom","mode":"follow_default"}]})).await;
    assert_eq!(response["code"], 0, "{response}");
    let processed = reconciliation_tick(&app_state(&f)).await;
    assert!(processed >= 12, "{processed}");
    assert_eq!(f.mock.state.max_mutations.load(Ordering::SeqCst), 4);
    assert_eq!(f.mock.state.active_mutations.load(Ordering::SeqCst), 0);
    assert_eq!(preference::load_preference(f.db.as_ref(), 10).await.unwrap().state, preference::RelayPreferencePhase::Idle);
    for host in ["op1".to_string()].into_iter().chain((1..=5).map(|i| format!("perf-{i}"))) {
        assert_eq!(actual_values(&f, &host, "default"), expected(&["1.1.1.1","2.2.2.2"]));
        assert_eq!(actual_values(&f, &host, "unicom"), expected(&["1.1.1.1","2.2.2.2"]));
    }
    assert_eq!(f.mock.state.records.lock().unwrap().iter().filter(|r| r.host.starts_with("protected-")).count(), 110);
}

#[tokio::test]
async fn fast_sync_serializes_the_same_normalized_rrset() {
    let f = fixture().await;
    *f.mock.state.provider_type.lock().unwrap() = "huawei".into();
    apply_defaults(&f, &["n1", "n2"]).await;
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", json!({"mode":"carrier", "default_node_ids":["n1","n6"], "bindings":[{"line_id":"unicom","mode":"follow_default"}]})).await;
    assert_eq!(response["code"], 0, "{response}");
    let writes = f.mock.state.total_mutations();
    f.mock.state.mutation_delay_ms.store(50, Ordering::SeqCst);
    let input = EnsureRecordInput { rule_id: 100, fqdn: "op1.example.com".into(), record_type: DnsRecordType::A, expected_value: encode_dns_values(expected(&["1.1.1.1", "6.6.6.6"])), line: ProviderLine::default() };
    let alias = EnsureRecordInput { fqdn: "OP1.EXAMPLE.COM.".into(), line: ProviderLine::from_provider("default_view", None), ..input.clone() };
    let (first, second) = tokio::join!(ensure_record(f.db.as_ref(), &f.mock.client, &input), ensure_record(f.db.as_ref(), &f.mock.client, &alias));
    assert!(matches!(first, EnsureRecordResult::Updated { .. } | EnsureRecordResult::AlreadyCorrect { .. }), "{first:?}");
    assert!(matches!(second, EnsureRecordResult::Updated { .. } | EnsureRecordResult::AlreadyCorrect { .. }), "{second:?}");
    assert_eq!(f.mock.state.total_mutations() - writes, 1);
    assert_eq!(f.mock.state.max_mutations.load(Ordering::SeqCst), 1);
    assert_eq!(actual_values(&f, "op1", "default"), expected(&["1.1.1.1", "6.6.6.6"]));
}

#[tokio::test]
async fn fast_sync_new_desired_waits_for_inflight_write_and_remains_pending() {
    let f = fixture().await;
    let (_, response) = http(&f, "PUT", "/groups/10/routing-apply", json!({"mode":"carrier", "default_node_ids":["n1","n2"], "bindings":[]})).await;
    assert_eq!(response["code"], 0, "{response}");
    let sync = f.db.find_dns_record_sync(100, DEFAULT_LINE_KEY).await.unwrap().unwrap();
    f.mock.state.mutation_delay_ms.store(90, Ordering::SeqCst);
    let replacing = async {
        while f.mock.state.active_mutations.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; }
        persist_desired(f.db.as_ref(), &DnsDesiredRecord { rule_id:100, fqdn:"op1.example.com".into(), record_type:DnsRecordType::A, expected_value:"6.6.6.6".into(), line:ProviderLine::default() }, true).await.unwrap();
        let after = f.db.find_dns_record_sync(100, DEFAULT_LINE_KEY).await.unwrap().unwrap();
        assert_eq!(after.expected_value.as_deref(), Some("6.6.6.6"));
        assert_eq!(after.state, "PENDING");
        assert_eq!(f.mock.state.active_mutations.load(Ordering::SeqCst), 0);
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async { tokio::join!(reconcile_one(f.db.as_ref(), sync, &f.mock.client), replacing); }).await.unwrap();
    let latest = f.db.find_dns_record_sync(100, DEFAULT_LINE_KEY).await.unwrap().unwrap();
    assert_eq!(latest.expected_value.as_deref(), Some("6.6.6.6"));
    assert_eq!(latest.state, "PENDING");
}
