//! The same replacement/rollback contract runs on both database backends.
use super::repo::*;

pub async fn replacement_contract(db: &dyn Repository) {
    let old = ConcreteNodeIdentity {
        home_group_id: 71,
        node_id: "LEGACY_OLD".into(),
    };
    let new = ConcreteNodeIdentity {
        home_group_id: 72,
        node_id: "STAGED_NEW".into(),
    };
    for group in [71, 73] {
        db.insert_node_reuse_binding(group, 72, "STAGED_NEW")
            .await
            .unwrap();
    }
    db.insert_node_reuse_binding(73, 71, "LEGACY_OLD")
        .await
        .unwrap();
    db.register_node_pool_identity(71, "LEGACY_OLD")
        .await
        .unwrap();
    db.register_node_pool_identity(72, "STAGED_NEW")
        .await
        .unwrap();
    db.set("node_status:71:LEGACY_OLD", "old status")
        .await
        .unwrap();
    db.set("node_config_revision:71:LEGACY_OLD", "42")
        .await
        .unwrap();
    db.set("node_metrics:71:LEGACY_OLD", "historical metrics")
        .await
        .unwrap();
    db.set("relay_preference:71", "old carrier").await.unwrap();
    let prepared = LegacyUpgradeCommit {
        expected_operation: None,
        operation_id: "migration-one".into(),
        operation: "PREPARED".into(),
        routing: vec![],
        replacement: None,
        rollback: None,
    };
    let (one, two) = tokio::join!(
        db.commit_legacy_upgrade(&prepared),
        db.commit_legacy_upgrade(&prepared)
    );
    assert_ne!(
        one.unwrap(),
        two.unwrap(),
        "only one concurrent start may win"
    );
    let mut finalize = LegacyUpgradeCommit {
        expected_operation: Some("PREPARED".into()),
        operation_id: "migration-one".into(),
        operation: "COMMITTED".into(),
        routing: vec![(
            "relay_preference:71".into(),
            "old carrier".into(),
            "new carrier".into(),
        )],
        replacement: Some(LegacyUpgradeReplacement {
            old: old.clone(),
            new: new.clone(),
            new_credential_id: "wrong-credential".into(),
            memberships: vec![71, 73],
        }),
        rollback: None,
    };
    assert!(!db.commit_legacy_upgrade(&finalize).await.unwrap());
    assert_eq!(
        db.get("relay_preference:71").await.unwrap().as_deref(),
        Some("old carrier"),
        "failed finalize must rollback prior writes"
    );
    assert!(db.get("node_status:71:LEGACY_OLD").await.unwrap().is_some());
    finalize.replacement.as_mut().unwrap().new_credential_id = "staged-credential".into();
    assert!(db.commit_legacy_upgrade(&finalize).await.unwrap());
    assert!(
        !db.commit_legacy_upgrade(&finalize).await.unwrap(),
        "replayed CAS cannot re-retire"
    );
    assert!(db.get("node_status:71:LEGACY_OLD").await.unwrap().is_none());
    assert!(db
        .get("node_config_revision:71:LEGACY_OLD")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.get("node_metrics:71:LEGACY_OLD")
            .await
            .unwrap()
            .as_deref(),
        Some("historical metrics")
    );
    assert!(db
        .find_active_node_credential_for_runtime("old-credential")
        .await
        .unwrap()
        .is_none());
    assert!(db
        .find_active_node_credential_for_runtime("staged-credential")
        .await
        .unwrap()
        .is_some());
    assert!(db
        .list_reusing_group_ids_for_node(71, "LEGACY_OLD")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        db.list_reusing_group_ids_for_node(72, "STAGED_NEW")
            .await
            .unwrap()
            .len(),
        2
    );
    // Late status must never recreate even a legacy Home identity.
    db.set("node_status:71:LEGACY_OLD", "late legacy report")
        .await
        .unwrap();
    crate::service::node_pool::reconcile_metadata(db)
        .await
        .unwrap();
    assert!(!db
        .list_node_pool_records()
        .await
        .unwrap()
        .iter()
        .any(|n| n.node_id == "LEGACY_OLD"));
    assert_eq!(
        db.get("legacy_v130_upgrade:operation:migration-one")
            .await
            .unwrap()
            .as_deref(),
        Some("COMMITTED")
    );
    let cleanup = LegacyUpgradeCommit {
        expected_operation: Some("COMMITTED".into()),
        operation_id: "migration-cleanup".into(),
        operation: "ROLLED_BACK".into(),
        routing: vec![],
        replacement: None,
        rollback: Some(new),
    };
    assert!(db.commit_legacy_upgrade(&cleanup).await.unwrap());
    assert!(db
        .find_active_node_credential_for_runtime("staged-credential")
        .await
        .unwrap()
        .is_none());
    assert!(db
        .list_reusing_group_ids_for_node(72, "STAGED_NEW")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        db.get("relay_preference:71").await.unwrap().as_deref(),
        Some("new carrier"),
        "staged cleanup does not prune Carrier"
    );
}
