mod multi_a_acceptance {
    use super::*;
    use crate::db::repo::{NodeCredentialRepository, NodePoolRepository, NodeReuseRepository};
    use crate::service::relay_preference::{
        self as preference, CarrierLineBinding, CarrierLineMode, CarrierPolicy,
        RelayPreferenceState, RoutingMode,
    };

    struct Fixture {
        db: Arc<SqliteRepository>,
        pool: sqlx::SqlitePool,
        anchor: i64,
        mock: EnsureMock,
        connections: crate::api::ws::NodeConnections,
    }

    fn policy(default: &str, selections: &[(&str, &str)]) -> CarrierPolicy {
        CarrierPolicy {
            default_node_id: Some(default.into()),
            bindings: selections
                .iter()
                .map(|(line, id)| CarrierLineBinding {
                    line_id: (*line).into(),
                    mode: CarrierLineMode::Node,
                    node_id: Some((*id).into()),
                })
                .collect(),
        }
    }

    async fn fixture() -> Fixture {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query("UPDATE users SET admin=1,must_change_password=0 WHERE id=1")
            .execute(&pool)
            .await
            .unwrap();
        for (group, name, rule, host) in [
            (10, "z1", 100, "op1"),
            (20, "z2", 200, "op2"),
            (30, "z3", 300, "op3"),
        ] {
            sqlx::query("INSERT INTO device_groups(id,name,group_type,token,uid,connect_host) VALUES (?,?,'in',?,1,'')")
                .bind(group).bind(name).bind(format!("token-{group}")).execute(&pool).await.unwrap();
            sqlx::query("INSERT INTO forward_rules(id,name,uid,listen_port,device_group_in,target_addr,target_port,public_transport,node_transport,protocol,sni,camouflage_enabled) VALUES (?,?,1,?,?,'127.0.0.1',80,'nginx_sni','nginx_sni','tcp',?,1)")
                .bind(rule).bind(format!("rule-{rule}")).bind(21000+group).bind(group).bind(format!("{host}.example.com")).execute(&pool).await.unwrap();
        }
        let db = Arc::new(SqliteRepository::new(pool.clone()));
        let anchor = db
            .ensure_node_pool_system_group(1, "pool-test")
            .await
            .unwrap()
            .id;
        for n in 1..=6 {
            let id = format!("n{n}");
            sqlx::query("INSERT INTO node_credentials(credential_id,home_group_id,node_id,generation,verifier_format,verifier_version,verifier_data,activated_at) VALUES (?,?,?,1,'rp-node-sha256',1,?,datetime('now'))")
                .bind(format!("credential-{id}")).bind(anchor).bind(&id).bind(vec![7_u8;32]).execute(&pool).await.unwrap();
            db.register_node_pool_identity(anchor, &id).await.unwrap();
            db.set(&format!("node_status:{anchor}:{id}"),&json!({"node_id":id,"public_ipv4":format!("{n}.{n}.{n}.{n}"),"public_ipv4_reported":true,"last_seen":"2000-01-01T00:00:00Z"}).to_string()).await.unwrap();
        }
        for (group, members, default) in [
            (10, vec!["n1", "n2", "n6"], "n1"),
            (20, vec!["n2", "n3"], "n2"),
            (30, vec!["n1", "n4", "n5", "n6"], "n1"),
        ] {
            for id in members {
                db.insert_node_reuse_binding(group, anchor, id)
                    .await
                    .unwrap();
            }
            db.set(
                &format!("relay_preference:{group}"),
                &serde_json::to_string(&RelayPreferenceState {
                    active_routing_mode: Some(RoutingMode::Carrier),
                    preferred_node_id: Some(default.into()),
                    carrier_policy: policy(default, &[]),
                    ..Default::default()
                })
                .unwrap(),
            )
            .await
            .unwrap();
        }
        let mock =
            spawn_ensure_mock(Vec::new(), MutationBehavior::Apply, MutationBehavior::Apply).await;
        mock.state.record_lines.lock().unwrap().extend(
            [("mobile", "移动"), ("telecom", "电信"), ("unicom", "联通")].map(|(id, name)| {
                DnsMgrRecordLine {
                    id: id.into(),
                    name: name.into(),
                    parent: None,
                }
            }),
        );
        db.set(
            DNSMGR_CONFIG_KEY,
            &json!({"enabled":true,"base_url":mock.base_url,"uid":7,"api_key":"fixture-key"})
                .to_string(),
        )
        .await
        .unwrap();
        Fixture {
            db,
            pool,
            anchor,
            mock,
            connections: crate::api::ws::NodeConnections::new(),
        }
    }

    async fn reconcile_group(f: &Fixture, group: i64) {
        for rule in eligible_rule_ids_for_group(f.db.as_ref(), group)
            .await
            .unwrap()
        {
            for sync in f.db.list_dns_record_syncs_for_rule(rule).await.unwrap() {
                reconcile_one(f.db.as_ref(), sync, &f.mock.client).await;
            }
        }
        preference::finalize_switching_group_for_test(f.db.as_ref(), &f.connections, group)
            .await
            .unwrap();
    }

    fn actual_values(f: &Fixture, host: &str, line: &str) -> std::collections::BTreeSet<String> {
        f.mock
            .state
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                r.host == host
                    && ProviderLine::from_provider(&r.line, None).key
                        == ProviderLine::from_provider(line, None).key
            })
            .flat_map(|r| r.values.iter().cloned())
            .collect()
    }

    fn expected(values: &[&str]) -> std::collections::BTreeSet<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    fn app_state(f: &Fixture) -> AppState {
        AppState {
            db: f.db.clone(),
            config: crate::config::Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 60,
                node_reuse_runtime_enabled: true,
            },
            release_cache: crate::api::system::ReleaseCache::new(),
            node_connections: f.connections.clone(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(Default::default())),
        }
    }

    async fn http(
        f: &Fixture,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &crate::api::middleware::Claims {
                sub: 1,
                admin: true,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3600) as usize,
            },
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();
        let response = crate::api::routes()
            .with_state(app_state(f))
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn z1_z2_z3_multi_a_roundtrip_offline_remove_and_delete_failure() {
        let f = fixture().await;
        let before = crate::service::node_reuse::build_effective_config_candidate_for_node(
            f.db.as_ref(),
            f.anchor,
            "n2",
        )
        .await
        .unwrap()
        .config;
        let scenarios = [
            (
                10,
                policy(
                    "n1",
                    &[
                        ("mobile", "n1"),
                        ("telecom", "n2"),
                        ("unicom", "n2"),
                        ("unicom", "n6"),
                    ],
                ),
            ),
            (
                20,
                policy(
                    "n2",
                    &[("mobile", "n3"), ("telecom", "n2"), ("unicom", "n2")],
                ),
            ),
            (
                30,
                policy(
                    "n1",
                    &[
                        ("mobile", "n4"),
                        ("telecom", "n5"),
                        ("unicom", "n1"),
                        ("unicom", "n6"),
                    ],
                ),
            ),
        ];
        for (group, p) in &scenarios {
            assert_eq!(
                preference::start_carrier_policy_apply(
                    f.db.as_ref(),
                    &f.connections,
                    *group,
                    p.clone()
                )
                .await
                .unwrap(),
                preference::CarrierPolicyApplyOutcome::Started
            );
            reconcile_group(&f, *group).await;
            let saved = preference::load_preference(f.db.as_ref(), *group)
                .await
                .unwrap();
            assert_eq!(saved.state, preference::RelayPreferencePhase::Idle);
            assert_eq!(saved.carrier_policy, p.clone().normalize().unwrap());
        }
        for (host, line, values) in [
            ("op1", "default", vec!["1.1.1.1"]),
            ("op1", "mobile", vec!["1.1.1.1"]),
            ("op1", "telecom", vec!["2.2.2.2"]),
            ("op1", "unicom", vec!["2.2.2.2", "6.6.6.6"]),
            ("op2", "default", vec!["2.2.2.2"]),
            ("op2", "mobile", vec!["3.3.3.3"]),
            ("op2", "telecom", vec!["2.2.2.2"]),
            ("op2", "unicom", vec!["2.2.2.2"]),
            ("op3", "default", vec!["1.1.1.1"]),
            ("op3", "mobile", vec!["4.4.4.4"]),
            ("op3", "telecom", vec!["5.5.5.5"]),
            ("op3", "unicom", vec!["1.1.1.1", "6.6.6.6"]),
        ] {
            assert_eq!(
                actual_values(&f, host, line),
                expected(&values),
                "{host}/{line}"
            );
        }
        assert_eq!(
            serde_json::to_value(before.listeners).unwrap(),
            serde_json::to_value(
                crate::service::node_reuse::build_effective_config_candidate_for_node(
                    f.db.as_ref(),
                    f.anchor,
                    "n2"
                )
                .await
                .unwrap()
                .config
                .listeners
            )
            .unwrap(),
            "Carrier must not filter Group Rules"
        );
        // Every Node is Offline in this fixture; selected last-known addresses remain targets.
        assert!(crate::service::node_pool::list_nodes(f.db.as_ref())
            .await
            .unwrap()
            .iter()
            .all(|node| !node.online));
        crate::service::node_reuse::delete_binding(f.db.as_ref(), 10, f.anchor, "n6")
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
        assert_eq!(actual_values(&f, "op1", "telecom"), expected(&["2.2.2.2"]));
        assert_eq!(
            actual_values(&f, "op3", "unicom"),
            expected(&["1.1.1.1", "6.6.6.6"])
        );
        assert!(f
            .db
            .find_node_reuse_binding(30, f.anchor, "n6")
            .await
            .unwrap()
            .is_some());
        // Provider mutation failure occurs after local retirement and cannot undo Delete.
        *f.mock.state.delete_behavior.lock().unwrap() = MutationBehavior::TransportWithoutApply;
        let (status, result) = http(
            &f,
            "DELETE",
            &format!("/admin/node-pool/nodes/{}/n2", f.anchor),
            json!({}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(result["code"], 0);
        assert!(result["data"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "EXTERNAL_DNS_NEEDS_ATTENTION"));
        for group in [10, 20, 30] {
            let saved = preference::load_preference(f.db.as_ref(), group)
                .await
                .unwrap();
            assert_ne!(saved.carrier_policy.default_node_id.as_deref(), Some("n2"));
            assert!(saved
                .carrier_policy
                .bindings
                .iter()
                .all(|b| b.node_id.as_deref() != Some("n2")));
        }
        reconcile_group(&f, 10).await;
        assert!(f
            .db
            .list_node_pool_records()
            .await
            .unwrap()
            .iter()
            .all(|n| n.node_id != "n2"));
        assert!(f
            .db
            .find_active_node_credential_for_runtime("credential-n2")
            .await
            .unwrap()
            .is_none());
        let sync =
            f.db.find_dns_record_sync(100, "dnsmgr:unicom")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(sync.desired_action, "DELETE");
        assert_ne!(sync.state, "PROPAGATED");
        crate::service::node_pool::reconcile_metadata(f.db.as_ref())
            .await
            .unwrap();
        assert!(f
            .db
            .list_node_pool_records()
            .await
            .unwrap()
            .iter()
            .all(|n| n.node_id != "n2"));
    }

    #[tokio::test]
    async fn unknown_a_and_cname_require_http_confirmation_before_replacement() {
        for record_type in ["A", "CNAME"] {
            let f = fixture().await;
            let external = record(
                "external",
                record_type,
                if record_type == "A" {
                    "9.9.9.9"
                } else {
                    "external.example.net"
                },
                "unicom",
            );
            f.mock
                .state
                .records
                .lock()
                .unwrap()
                .extend([external, record("other-line", "A", "8.8.8.8", "telecom")]);
            let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
            let mut body = serde_json::to_value(&p).unwrap();
            body["mode"] = json!("carrier");
            let (status, preview) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
            assert_eq!(status, axum::http::StatusCode::CONFLICT);
            assert_eq!(preview["data"]["confirmation_required"], true);
            assert_eq!(
                preview["data"]["conflicts"][0]["current"][0]["record_type"],
                record_type
            );
            assert_eq!(f.mock.state.total_mutations(), 0);
            assert!(preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .carrier_policy
                .bindings
                .is_empty());
            body["dns_confirmation"] = preview["data"]["dns_confirmation"].clone();
            let (status, result) = http(&f, "PUT", "/groups/10/routing-apply", body).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{result}");
            reconcile_group(&f, 10).await;
            assert_eq!(
                actual_values(&f, "op1", "unicom"),
                expected(&["2.2.2.2", "6.6.6.6"])
            );
            assert_eq!(actual_values(&f, "op1", "telecom"), expected(&["8.8.8.8"]));
            assert!(f
                .mock
                .state
                .records
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.record_id != "external"));
            assert_eq!(
                preference::load_preference(f.db.as_ref(), 10)
                    .await
                    .unwrap()
                    .state,
                preference::RelayPreferencePhase::Idle
            );
        }
    }

    #[tokio::test]
    async fn provider_read_failure_never_turns_into_confirm_and_stale_confirmation_is_rejected() {
        let f = fixture().await;
        f.mock
            .state
            .records
            .lock()
            .unwrap()
            .push(record("external", "A", "9.9.9.9", "unicom"));
        let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        let mut body = serde_json::to_value(p).unwrap();
        body["mode"] = json!("carrier");
        let (_, preview) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
        body["dns_confirmation"] = preview["data"]["dns_confirmation"].clone();
        f.mock.state.read_failure.store(true, Ordering::SeqCst);
        let (status, failed) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
        assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
        assert!(failed["message"]
            .as_str()
            .unwrap()
            .starts_with("DNS_PROVIDER_READ_FAILED"));
        assert_eq!(f.mock.state.total_mutations(), 0);
        f.mock.state.read_failure.store(false, Ordering::SeqCst);
        f.mock.state.records.lock().unwrap()[0].values = vec!["7.7.7.7".into()];
        let (status, new_preview) = http(&f, "PUT", "/groups/10/routing-apply", body).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_ne!(
            new_preview["data"]["dns_confirmation"],
            preview["data"]["dns_confirmation"]
        );
        assert_eq!(f.mock.state.total_mutations(), 0);
    }

    #[tokio::test]
    async fn missing_and_duplicate_ips_save_membership_bound_policy_without_faking_dns_completeness(
    ) {
        let f = fixture().await;
        f.db.set(
            &format!("node_status:{}:n6", f.anchor),
            r#"{"last_seen":"2000-01-01T00:00:00Z"}"#,
        )
        .await
        .unwrap();
        let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        let mut body = serde_json::to_value(p.clone()).unwrap();
        body["mode"] = json!("carrier");
        let (status, result) = http(&f, "PUT", "/groups/10/routing-apply", body).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(result["data"]["config_saved"], true);
        assert_eq!(result["data"]["dns_complete"], false);
        reconcile_group(&f, 10).await;
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .carrier_policy,
            p.normalize().unwrap()
        );
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
        f.db.set(
            &format!("node_status:{}:n6", f.anchor),
            r#"{"public_ipv4":"2.2.2.2","public_ipv4_reported":true}"#,
        )
        .await
        .unwrap();
        schedule_group_after_membership_change(f.db.as_ref(), 10)
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
        assert_eq!(
            f.mock
                .state
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.host == "op1" && r.line == "unicom")
                .count(),
            1
        );
        let mut invalid = serde_json::to_value(policy("n1", &[("unicom", "n5")])).unwrap();
        invalid["mode"] = json!("carrier");
        assert_eq!(
            http(&f, "PUT", "/groups/10/routing-apply", invalid).await.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn owned_rrset_shrinks_and_removes_only_its_carrier_line() {
        let db = ensure_db().await;
        let mut rrset = record("rrset", "A", "2.2.2.2", "Dianxin");
        rrset.values.push("6.6.6.6".into());
        let mock = spawn_ensure_mock(
            vec![rrset, record("other", "A", "8.8.8.8", "default")],
            MutationBehavior::Apply,
            MutationBehavior::Apply,
        )
        .await;
        insert_line_binding(&db, "Dianxin", "rrset", r#"["2.2.2.2","6.6.6.6"]"#).await;
        schedule_line_upsert(&db, 100, "Dianxin", "2.2.2.2")
            .await
            .unwrap();
        let sync = db
            .find_dns_record_sync(100, "dnsmgr:Dianxin")
            .await
            .unwrap()
            .unwrap();
        reconcile_one(&db, sync, &mock.client).await;
        assert_eq!(
            db.find_dns_record_sync(100, "dnsmgr:Dianxin")
                .await
                .unwrap()
                .unwrap()
                .state,
            "PROPAGATED"
        );
        assert_eq!(
            mock.state
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.line == "Dianxin")
                .flat_map(|r| r.values.iter().cloned())
                .collect::<Vec<_>>(),
            vec!["2.2.2.2"]
        );
        assert!(mock
            .state
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.record_id == "other"));
    }

    #[tokio::test]
    async fn membership_and_carrier_cleanup_rollback_together_on_database_error() {
        let f = fixture().await;
        let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        let mut pref = preference::load_preference(f.db.as_ref(), 10)
            .await
            .unwrap();
        pref.carrier_policy = p.clone();
        f.db.set(
            "relay_preference:10",
            &serde_json::to_string(&pref).unwrap(),
        )
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_carrier_cleanup BEFORE UPDATE ON kvs WHEN NEW.key='relay_preference:10' BEGIN SELECT RAISE(FAIL,'injected'); END").execute(&f.pool).await.unwrap();
        assert!(
            crate::service::node_reuse::delete_binding(f.db.as_ref(), 10, f.anchor, "n6")
                .await
                .is_err()
        );
        assert!(f
            .db
            .find_node_reuse_binding(10, f.anchor, "n6")
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .carrier_policy,
            p
        );
    }
    #[tokio::test]
    async fn huawei_rrset_creates_all_values_once_and_updates_the_same_identity() {
        let f = fixture().await;
        *f.mock.state.provider_type.lock().unwrap() = "huawei".into();
        let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        preference::start_carrier_policy_apply(f.db.as_ref(), &f.connections, 10, p)
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert_eq!(
            actual_values(&f, "op1", "unicom"),
            expected(&["2.2.2.2", "6.6.6.6"])
        );
        let records = f.mock.state.records.lock().unwrap().clone();
        let line = records
            .iter()
            .filter(|r| r.line == "unicom")
            .collect::<Vec<_>>();
        assert_eq!(line.len(), 1);
        assert_eq!(line[0].values.len(), 2);
        let id = line[0].record_id.clone();
        let adds = f.mock.state.add_attempts.load(Ordering::SeqCst);
        assert_eq!(adds, 2, "one default RRset + one Carrier RRset");
        crate::service::node_reuse::delete_binding(f.db.as_ref(), 10, f.anchor, "n6")
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
        assert_eq!(f.mock.state.add_attempts.load(Ordering::SeqCst), adds);
        assert_eq!(f.mock.state.update_attempts.load(Ordering::SeqCst), 1);
        assert!(f
            .mock
            .state
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.record_id == id));
        crate::service::node_reuse::delete_binding(f.db.as_ref(), 10, f.anchor, "n2")
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert!(actual_values(&f, "op1", "unicom").is_empty());
        assert_eq!(actual_values(&f, "op1", "default"), expected(&["1.1.1.1"]));
    }

    #[tokio::test]
    async fn zero_available_ips_save_policy_with_actionable_incomplete_state_and_no_dns_write() {
        let f = fixture().await;
        for id in ["n1", "n2", "n6"] {
            f.db.set(
                &format!("node_status:{}:{id}", f.anchor),
                r#"{"last_seen":"2000-01-01T00:00:00Z"}"#,
            )
            .await
            .unwrap();
        }
        let p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        let mut body = serde_json::to_value(&p).unwrap();
        body["mode"] = json!("carrier");
        let (status, result) = http(&f, "PUT", "/groups/10/routing-apply", body).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(result["data"]["config_saved"], true);
        assert_eq!(result["data"]["dns_complete"], false);
        assert!(result["data"]["warnings"].as_array().unwrap().len() >= 3);
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .carrier_policy,
            p.normalize().unwrap()
        );
        let sync =
            f.db.find_dns_record_sync(100, "dnsmgr:unicom")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(sync.state, "FAILED");
        assert_eq!(
            sync.last_error_category.as_deref(),
            Some("CARRIER_TARGET_IPV4_UNAVAILABLE")
        );
        assert_eq!(f.mock.state.total_mutations(), 0);
        // Existing scheduler resumes this same row once a selected IP becomes available.
        f.db.set(
            &format!("node_status:{}:n2", f.anchor),
            r#"{"public_ipv4":"2.2.2.2","public_ipv4_reported":true}"#,
        )
        .await
        .unwrap();
        schedule_group_after_membership_change(f.db.as_ref(), 10)
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
    }

    #[tokio::test]
    async fn deleting_default_prunes_follow_default_and_dns_recovery_never_resurrects_node() {
        let f = fixture().await;
        let mut p = policy("n1", &[("unicom", "n2"), ("unicom", "n6")]);
        p.bindings.push(CarrierLineBinding {
            line_id: "mobile".into(),
            mode: CarrierLineMode::FollowDefault,
            node_id: None,
        });
        preference::start_carrier_policy_apply(f.db.as_ref(), &f.connections, 10, p)
            .await
            .unwrap();
        reconcile_group(&f, 10).await;
        *f.mock.state.delete_behavior.lock().unwrap() = MutationBehavior::TransportWithoutApply;
        let (status, _) = http(
            &f,
            "DELETE",
            &format!("/admin/node-pool/nodes/{}/n1", f.anchor),
            json!({}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let saved = preference::load_preference(f.db.as_ref(), 10)
            .await
            .unwrap();
        assert!(saved.carrier_policy.default_node_id.is_none());
        assert!(!saved
            .carrier_policy
            .bindings
            .iter()
            .any(|b| b.mode == CarrierLineMode::FollowDefault));
        reconcile_group(&f, 10).await;
        assert!(
            !actual_values(&f, "op1", "mobile").is_empty(),
            "failed external Delete retains last known provider state"
        );
        *f.mock.state.delete_behavior.lock().unwrap() = MutationBehavior::Apply;
        refresh_all_desired(f.db.as_ref()).await.unwrap();
        reconcile_group(&f, 10).await;
        assert!(actual_values(&f, "op1", "default").is_empty());
        assert!(actual_values(&f, "op1", "mobile").is_empty());
        assert_eq!(
            actual_values(&f, "op1", "unicom"),
            expected(&["2.2.2.2", "6.6.6.6"])
        );
        crate::service::node_pool::reconcile_metadata(f.db.as_ref())
            .await
            .unwrap();
        assert!(!f
            .db
            .list_node_pool_records()
            .await
            .unwrap()
            .iter()
            .any(|r| r.identity_group_id == f.anchor && r.node_id == "n1"));
    }
    #[tokio::test]
    async fn confirmed_cname_is_restored_if_a_later_carrier_line_fails() {
        for (partial_delete_failure, unknown_after_partial_delete) in
            [(false, false), (true, false), (true, true)]
        {
            let f = fixture().await;
            let original = record("external-cname", "CNAME", "original.example.net", "unicom");
            f.mock
                .state
                .records
                .lock()
                .unwrap()
                .extend([original.clone(), record("keep", "A", "8.8.8.8", "telecom")]);
            let p = policy(
                "n1",
                &[("mobile", "n1"), ("unicom", "n2"), ("unicom", "n6")],
            );
            let mut body = serde_json::to_value(&p).unwrap();
            body["mode"] = json!("carrier");
            let (_, preview) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
            body["dns_confirmation"] = preview["data"]["dns_confirmation"].clone();
            assert_eq!(
                http(&f, "PUT", "/groups/10/routing-apply", body).await.0,
                axum::http::StatusCode::OK
            );
            let sync =
                f.db.find_dns_record_sync(100, "dnsmgr:unicom")
                    .await
                    .unwrap()
                    .unwrap();
            reconcile_one(f.db.as_ref(), sync, &f.mock.client).await;
            assert_eq!(
                actual_values(&f, "op1", "unicom"),
                expected(&["2.2.2.2", "6.6.6.6"])
            );
            f.mock.state.reject_writes.store(true, Ordering::SeqCst);
            reconcile_group(&f, 10).await;
            assert_eq!(
                preference::load_preference(f.db.as_ref(), 10)
                    .await
                    .unwrap()
                    .state,
                preference::RelayPreferencePhase::RollingBack
            );
            f.mock.state.reject_writes.store(false, Ordering::SeqCst);
            if partial_delete_failure {
                f.mock.state.temporary_delete_at.store(
                    f.mock.state.delete_attempts.load(Ordering::SeqCst) + 2,
                    Ordering::SeqCst,
                );
            }
            reconcile_group(&f, 10).await;
            if partial_delete_failure {
                assert_eq!(
                    preference::load_preference(f.db.as_ref(), 10)
                        .await
                        .unwrap()
                        .state,
                    preference::RelayPreferencePhase::RollingBack
                );
                assert_eq!(
                    actual_values(&f, "op1", "unicom").len(),
                    1,
                    "one known A deletion succeeded before the transient failure"
                );
                if unknown_after_partial_delete {
                    f.mock.state.records.lock().unwrap().push(record(
                        "foreign-after-partial",
                        "A",
                        "9.9.9.9",
                        "unicom",
                    ));
                    let mutations = f.mock.state.total_mutations();
                    reconcile_group(&f, 10).await;
                    assert_eq!(
                        f.mock.state.total_mutations(),
                        mutations,
                        "rollback must not remove an unknown record"
                    );
                    assert!(f
                        .mock
                        .state
                        .records
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|r| r.record_id == "foreign-after-partial"));
                    assert_eq!(
                        preference::load_preference(f.db.as_ref(), 10)
                            .await
                            .unwrap()
                            .state,
                        preference::RelayPreferencePhase::FailedManualIntervention
                    );
                    continue;
                }
                reconcile_group(&f, 10).await;
            }
            let actual = f.mock.state.records.lock().unwrap().clone();
            let restored = actual
                .iter()
                .filter(|r| r.line == "unicom")
                .collect::<Vec<_>>();
            assert_eq!(
                restored.len(),
                1,
                "rollback must restore the confirmed original CNAME"
            );
            assert_eq!(restored[0].record_type, "CNAME");
            assert_eq!(restored[0].values, original.values);
            assert_eq!(restored[0].ttl, original.ttl);
            assert!(actual.iter().any(|r| r.record_id == "keep"));
            assert_eq!(
                preference::load_preference(f.db.as_ref(), 10)
                    .await
                    .unwrap()
                    .state,
                preference::RelayPreferencePhase::FailedRolledBack
            );
        }
    }

    #[tokio::test]
    async fn confirmed_overwrite_applies_even_when_carrier_policy_is_unchanged() {
        let f = fixture().await;
        f.mock.state.records.lock().unwrap().push(record(
            "external-default",
            "CNAME",
            "old.example.net",
            "default",
        ));
        let mut body = serde_json::to_value(policy("n1", &[])).unwrap();
        body["mode"] = json!("carrier");
        let (_, preview) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
        body["dns_confirmation"] = preview["data"]["dns_confirmation"].clone();
        assert_eq!(
            http(&f, "PUT", "/groups/10/routing-apply", body).await.0,
            axum::http::StatusCode::OK
        );
        reconcile_group(&f, 10).await;
        assert_eq!(actual_values(&f, "op1", "default"), expected(&["1.1.1.1"]));
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .state,
            preference::RelayPreferencePhase::Idle
        );
    }
    #[tokio::test]
    async fn confirmed_cname_restores_after_only_the_first_a_create_succeeds() {
        let f = fixture().await;
        let original = record("external-cname", "CNAME", "original.example.net", "unicom");
        f.mock.state.records.lock().unwrap().push(original.clone());
        let mut body =
            serde_json::to_value(policy("n1", &[("unicom", "n2"), ("unicom", "n6")])).unwrap();
        body["mode"] = json!("carrier");
        let (_, preview) = http(&f, "PUT", "/groups/10/routing-apply", body.clone()).await;
        body["dns_confirmation"] = preview["data"]["dns_confirmation"].clone();
        assert_eq!(
            http(&f, "PUT", "/groups/10/routing-apply", body).await.0,
            axum::http::StatusCode::OK
        );
        f.mock.state.reject_add_at.store(2, Ordering::SeqCst);
        let sync =
            f.db.find_dns_record_sync(100, "dnsmgr:unicom")
                .await
                .unwrap()
                .unwrap();
        reconcile_one(f.db.as_ref(), sync, &f.mock.client).await;
        assert_eq!(actual_values(&f, "op1", "unicom"), expected(&["2.2.2.2"]));
        preference::finalize_switching_group_for_test(f.db.as_ref(), &f.connections, 10)
            .await
            .unwrap();
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .state,
            preference::RelayPreferencePhase::RollingBack
        );
        reconcile_group(&f, 10).await;
        let actual = f.mock.state.records.lock().unwrap().clone();
        let restored = actual
            .iter()
            .filter(|r| r.line == "unicom")
            .collect::<Vec<_>>();
        assert_eq!(restored.len(), 1);
        assert_eq!(
            restored[0].record_type, "CNAME",
            "partial forward mutation must also restore original CNAME"
        );
        assert_eq!(restored[0].values, original.values);
        assert_eq!(restored[0].ttl, original.ttl);
        assert_eq!(
            preference::load_preference(f.db.as_ref(), 10)
                .await
                .unwrap()
                .state,
            preference::RelayPreferencePhase::FailedRolledBack
        );
    }
}
