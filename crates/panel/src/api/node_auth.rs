use crate::api::AppState;
use crate::db::repo::{GroupRepository, ResourceScope};
use crate::node_credential::{
    verify_active_node_credential, NodeCredentialSecret, StoredNodeCredentialVerifier,
};
use crate::node_identity::ReuseEligibleNodeId;
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use relay_shared::models::DeviceGroup;

pub const NODE_CREDENTIAL_AUTH_SCHEME: &str = "RelayNodeCredential";
pub const NODE_CREDENTIAL_ID_HEADER: &str = "X-Node-Credential-ID";
pub const NODE_ID_HEADER: &str = "X-Node-ID";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedConcreteNode {
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub credential_id: String,
    pub generation: i64,
}

#[derive(Debug)]
pub enum AuthenticatedNodeIdentity {
    LegacyHomeGroup {
        group: DeviceGroup,
        reported_node_id: Option<String>,
    },
    VerifiedConcreteNode {
        group: DeviceGroup,
        verified: VerifiedConcreteNode,
    },
}

impl AuthenticatedNodeIdentity {
    pub fn group(&self) -> &DeviceGroup {
        match self {
            Self::LegacyHomeGroup { group, .. } | Self::VerifiedConcreteNode { group, .. } => group,
        }
    }

    pub fn group_id(&self) -> i64 {
        self.group().id
    }

    pub fn node_id(&self) -> Option<&str> {
        match self {
            Self::LegacyHomeGroup {
                reported_node_id, ..
            } => reported_node_id.as_deref(),
            Self::VerifiedConcreteNode { verified, .. } => Some(verified.node_id.as_str()),
        }
    }

    pub fn verified(&self) -> Option<&VerifiedConcreteNode> {
        match self {
            Self::LegacyHomeGroup { .. } => None,
            Self::VerifiedConcreteNode { verified, .. } => Some(verified),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAuthError {
    Unauthorized,
    Forbidden,
    Unavailable,
}

impl NodeAuthError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, NodeAuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(NodeAuthError::Unauthorized);
    }
    first
        .to_str()
        .ok()
        .map(Some)
        .ok_or(NodeAuthError::Unauthorized)
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn reported_node_id(headers: &HeaderMap) -> Result<Option<String>, NodeAuthError> {
    Ok(unique_header(headers, NODE_ID_HEADER)?
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

pub async fn authenticate_node(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedNodeIdentity, NodeAuthError> {
    let authorization =
        unique_header(headers, AUTHORIZATION.as_str())?.ok_or(NodeAuthError::Unauthorized)?;
    let credential_id = unique_header(headers, NODE_CREDENTIAL_ID_HEADER)?;
    let node_id = reported_node_id(headers)?;

    if let Some(token) = authorization.strip_prefix("Bearer ") {
        if token.is_empty() || credential_id.is_some() {
            return Err(NodeAuthError::Unauthorized);
        }
        let group = state
            .db
            .find_by_token(token)
            .await
            .map_err(|_| NodeAuthError::Unavailable)?
            .ok_or(NodeAuthError::Unauthorized)?;
        if group.group_type != "in" {
            return Err(NodeAuthError::Forbidden);
        }
        return Ok(AuthenticatedNodeIdentity::LegacyHomeGroup {
            group,
            reported_node_id: node_id,
        });
    }

    let Some(secret_wire) = authorization
        .strip_prefix(NODE_CREDENTIAL_AUTH_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
    else {
        return Err(NodeAuthError::Unauthorized);
    };
    if secret_wire.is_empty() {
        return Err(NodeAuthError::Unauthorized);
    }
    let credential_id = credential_id
        .map(str::trim)
        .filter(|value| valid_credential_id(value))
        .ok_or(NodeAuthError::Unauthorized)?;
    let node_id = node_id
        .as_deref()
        .and_then(|value| ReuseEligibleNodeId::parse(value).ok())
        .ok_or(NodeAuthError::Unauthorized)?;
    let secret =
        NodeCredentialSecret::parse(secret_wire).map_err(|_| NodeAuthError::Unauthorized)?;

    let record = state
        .db
        .find_active_node_credential_for_runtime(credential_id)
        .await
        .map_err(|_| NodeAuthError::Unavailable)?
        .ok_or(NodeAuthError::Unauthorized)?;
    let stored = StoredNodeCredentialVerifier {
        credential_id: &record.credential_id,
        home_group_id: record.home_group_id,
        node_id: &record.node_id,
        verifier_format: &record.verifier_format,
        verifier_version: record.verifier_version,
        verifier_data: &record.verifier_data,
        activated_at: record.activated_at.as_deref(),
        revoked_at: record.revoked_at.as_deref(),
    };
    if !verify_active_node_credential(
        &stored,
        credential_id,
        record.home_group_id,
        &node_id,
        &secret,
    ) {
        return Err(NodeAuthError::Unauthorized);
    }

    let group =
        GroupRepository::find_by_id(state.db.as_ref(), record.home_group_id, &ResourceScope::All)
            .await
            .map_err(|_| NodeAuthError::Unavailable)?
            .ok_or(NodeAuthError::Unauthorized)?;
    if group.group_type != "in" {
        return Err(NodeAuthError::Forbidden);
    }
    Ok(AuthenticatedNodeIdentity::VerifiedConcreteNode {
        group,
        verified: VerifiedConcreteNode {
            home_group_id: record.home_group_id,
            node_id,
            credential_id: record.credential_id,
            generation: record.generation,
        },
    })
}

pub async fn verified_credential_still_active(
    state: &AppState,
    verified: &VerifiedConcreteNode,
) -> Result<bool, NodeAuthError> {
    let record = state
        .db
        .find_active_node_credential_for_runtime(&verified.credential_id)
        .await
        .map_err(|_| NodeAuthError::Unavailable)?;
    Ok(record.is_some_and(|record| {
        record.home_group_id == verified.home_group_id
            && record.node_id == verified.node_id.as_str()
            && record.generation == verified.generation
            && record.activated_at.is_some()
            && record.revoked_at.is_none()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::pg_repo::PgRepository;
    use crate::db::pg_schema::{apply_pg_schema, run_pg_migrations};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::node_credential::NodeCredentialVerifier;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    fn app_state(db: Arc<dyn crate::db::Repository>) -> AppState {
        AppState {
            db,
            config: Config {
                database_path: "test".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            node_operations: crate::api::node_ops::NodeOperationRegistry::new(),
            deployments: crate::api::node_deploy::DeploymentRegistry::default(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    async fn sqlite_state_with_active_credential() -> (AppState, NodeCredentialSecret) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'home', 'in', 'legacy-token', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let secret = NodeCredentialSecret::from_test_bytes([0x42; 32]);
        let verifier = NodeCredentialVerifier::derive("cred-active", 10, &node_id, &secret);
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data, activated_at) \
             VALUES ('cred-active', 10, 'Node_A', 3, 'rp-node-sha256', 1, ?, datetime('now'))",
        )
        .bind(verifier.data().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        (app_state(Arc::new(SqliteRepository::new(pool))), secret)
    }

    fn replace_db_in_url(url: &str, db_name: &str) -> String {
        let (base, query) = match url.split_once('?') {
            Some((base, query)) => (base, Some(query)),
            None => (url, None),
        };
        let head = base.rsplit_once('/').map(|(head, _)| head).unwrap_or(base);
        match query {
            Some(query) => format!("{head}/{db_name}?{query}"),
            None => format!("{head}/{db_name}"),
        }
    }

    async fn pg_state_with_active_credential() -> Option<(AppState, NodeCredentialSecret)> {
        let url = std::env::var("TEST_PG_URL")
            .ok()
            .filter(|value| !value.is_empty())?;
        let db_name = format!("test_s3_runtime_auth_{}", uuid::Uuid::new_v4().simple());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&replace_db_in_url(&url, "postgres"))
            .await
            .expect("connect PG admin DB");
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin)
            .await
            .expect("create S3 runtime-auth PG DB");
        admin.close().await;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&replace_db_in_url(&url, &db_name))
            .await
            .expect("connect S3 runtime-auth PG DB");
        apply_pg_schema(&pool).await.expect("apply PG schema");
        run_pg_migrations(&pool).await.expect("run PG migrations");
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES (10, 'home', 'in', 'legacy-token', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let secret = NodeCredentialSecret::from_test_bytes([0x42; 32]);
        let verifier = NodeCredentialVerifier::derive("cred-active", 10, &node_id, &secret);
        sqlx::query(
            "INSERT INTO node_credentials \
             (credential_id, home_group_id, node_id, generation, verifier_format, verifier_version, verifier_data, activated_at) \
             VALUES ('cred-active', 10, 'Node_A', 3, 'rp-node-sha256', 1, $1, \
                     to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'))",
        )
        .bind(verifier.data().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        Some((app_state(Arc::new(PgRepository::new(pool))), secret))
    }

    fn credential_headers(secret: &NodeCredentialSecret, node_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("RelayNodeCredential {}", secret.to_wire_value())
                .parse()
                .unwrap(),
        );
        headers.insert(NODE_CREDENTIAL_ID_HEADER, "cred-active".parse().unwrap());
        headers.insert(NODE_ID_HEADER, node_id.parse().unwrap());
        headers
    }

    #[test]
    fn credential_ids_use_bounded_ascii_runtime_grammar() {
        assert!(valid_credential_id("01234567-89ab-cdef_ABC"));
        assert!(!valid_credential_id(""));
        assert!(!valid_credential_id("bad credential"));
        assert!(!valid_credential_id(&"a".repeat(129)));
    }

    async fn exercise_runtime_auth_contract(state: AppState, secret: NodeCredentialSecret) {
        let mut legacy = HeaderMap::new();
        legacy.insert(AUTHORIZATION, "Bearer legacy-token".parse().unwrap());
        legacy.insert(NODE_ID_HEADER, "self-reported".parse().unwrap());
        match authenticate_node(&state, &legacy).await.unwrap() {
            AuthenticatedNodeIdentity::LegacyHomeGroup {
                group,
                reported_node_id,
            } => {
                assert_eq!(group.id, 10);
                assert_eq!(reported_node_id.as_deref(), Some("self-reported"));
            }
            _ => panic!("legacy token must not produce VerifiedConcreteNode"),
        }

        let verified = authenticate_node(&state, &credential_headers(&secret, "Node_A"))
            .await
            .unwrap();
        let verified = verified.verified().expect("credential must verify").clone();
        assert_eq!(verified.home_group_id, 10);
        assert_eq!(verified.node_id.as_str(), "Node_A");
        assert_eq!(verified.credential_id, "cred-active");
        assert_eq!(verified.generation, 3);
        assert!(verified_credential_still_active(&state, &verified)
            .await
            .unwrap());

        let wrong_secret = NodeCredentialSecret::from_test_bytes([0x55; 32]);
        assert_eq!(
            authenticate_node(&state, &credential_headers(&wrong_secret, "Node_A"))
                .await
                .unwrap_err(),
            NodeAuthError::Unauthorized
        );
        assert_eq!(
            authenticate_node(&state, &credential_headers(&secret, "Other_Node"))
                .await
                .unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let mut wrong_id = credential_headers(&secret, "Node_A");
        wrong_id.insert(
            NODE_CREDENTIAL_ID_HEADER,
            "missing-credential".parse().unwrap(),
        );
        assert_eq!(
            authenticate_node(&state, &wrong_id).await.unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let mut malformed_id = credential_headers(&secret, "Node_A");
        malformed_id.insert(
            NODE_CREDENTIAL_ID_HEADER,
            "bad credential id".parse().unwrap(),
        );
        assert_eq!(
            authenticate_node(&state, &malformed_id).await.unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let mut malformed_secret = credential_headers(&secret, "Node_A");
        malformed_secret.insert(
            AUTHORIZATION,
            "RelayNodeCredential rpn1_too-short".parse().unwrap(),
        );
        assert_eq!(
            authenticate_node(&state, &malformed_secret)
                .await
                .unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let mut missing_id = credential_headers(&secret, "Node_A");
        missing_id.remove(NODE_CREDENTIAL_ID_HEADER);
        assert_eq!(
            authenticate_node(&state, &missing_id).await.unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let mut mixed = legacy.clone();
        mixed.insert(NODE_CREDENTIAL_ID_HEADER, "cred-active".parse().unwrap());
        assert_eq!(
            authenticate_node(&state, &mixed).await.unwrap_err(),
            NodeAuthError::Unauthorized
        );

        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        assert_eq!(
            state
                .db
                .revoke_node_credential("cred-active", 10, &node_id, 3)
                .await
                .unwrap(),
            crate::db::repo::NodeCredentialMutationResult::Applied
        );
        assert!(!verified_credential_still_active(&state, &verified)
            .await
            .unwrap());
        assert_eq!(
            authenticate_node(&state, &credential_headers(&secret, "Node_A"))
                .await
                .unwrap_err(),
            NodeAuthError::Unauthorized
        );
    }

    #[tokio::test]
    async fn runtime_auth_contract_sqlite() {
        let (state, secret) = sqlite_state_with_active_credential().await;
        exercise_runtime_auth_contract(state, secret).await;
    }

    #[tokio::test]
    async fn runtime_auth_contract_real_postgres() {
        let Some((state, secret)) = pg_state_with_active_credential().await else {
            return;
        };
        println!("S3 REAL POSTGRES RUNTIME AUTH CONTRACT: EXECUTED");
        exercise_runtime_auth_contract(state, secret).await;
    }
}
