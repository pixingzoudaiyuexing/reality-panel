use relay_shared::protocol::{
    NodeMigrationBootstrap, NodeMigrationBootstrapAck, NodeMigrationBootstrapAuthorized,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ROOT: &str = "/var/lib/relay-panel/node-claims/automatic";
const BOOTSTRAP_FILE: &str = "bootstrap.json";
const SECRET_FILE: &str = "claim.secret";
const SCRIPT_FILE: &str = "migrate.py";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBootstrap {
    operation_id: String,
    identity_group_id: i64,
    node_id: String,
    claim_id: String,
    expires_at: String,
    authorized: bool,
    #[serde(default)]
    completed: bool,
}

fn check_private_directory(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "migration directory missing")?;
    if !meta.is_dir()
        || meta.is_symlink()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("migration directory permissions invalid".into());
    }
    Ok(())
}

fn create_safe_directory(child: &Path) -> Result<(), String> {
    let parent = child.parent().ok_or("credential parent missing")?;
    let meta = std::fs::symlink_metadata(parent).map_err(|_| "credential parent missing")?;
    if !meta.is_dir()
        || meta.is_symlink()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o022 != 0
    {
        return Err("credential parent unsafe".into());
    }
    match std::fs::symlink_metadata(child) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(child)
                .map_err(|_| "credential directory create failed")?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "credential directory commit failed")?;
        }
        Err(_) => return Err("credential directory inspection failed".into()),
    }
    let meta = std::fs::symlink_metadata(child).map_err(|_| "credential directory missing")?;
    if !meta.is_dir()
        || meta.is_symlink()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o022 != 0
    {
        return Err("credential directory unsafe".into());
    }
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("migration path missing parent")?;
    check_private_directory(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("state"),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|_| "migration private file create failed")?;
        file.write_all(bytes)
            .map_err(|_| "migration private file write failed")?;
        file.sync_all()
            .map_err(|_| "migration private file fsync failed")?;
        std::fs::rename(&temp, path).map_err(|_| "migration private file commit failed")?;
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "migration directory fsync failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

fn validate_message(message: &NodeMigrationBootstrap, node_id: &str) -> Result<(), String> {
    if message.msg_type != "node_migration_bootstrap"
        || message.node_id != node_id
        || message.identity_group_id <= 0
        || uuid::Uuid::parse_str(&message.operation_id).is_err()
        || uuid::Uuid::parse_str(&message.claim_id).is_err()
        || !message.claim_secret.starts_with("rpc1_")
        || message.claim_secret.len() > 128
        || !chrono::DateTime::parse_from_rfc3339(&message.expires_at)
            .is_ok_and(|expiry| expiry > chrono::Utc::now())
    {
        return Err("invalid migration bootstrap identity or lifetime".into());
    }
    Ok(())
}

fn persist_at(
    root: &Path,
    message: &NodeMigrationBootstrap,
    node_id: &str,
) -> Result<NodeMigrationBootstrapAck, String> {
    validate_message(message, node_id)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err("migration requires root".into());
    }
    let parent = root.parent().ok_or("migration root invalid")?;
    let grandparent = parent.parent().ok_or("credential root invalid")?;
    create_safe_directory(grandparent)?;
    create_safe_directory(parent)?;
    create_safe_directory(root)?;
    check_private_directory(root)?;
    let pending_path = root.join(BOOTSTRAP_FILE);
    if pending_path.exists() {
        let old: PendingBootstrap = serde_json::from_slice(
            &std::fs::read(&pending_path).map_err(|_| "migration pending read failed")?,
        )
        .map_err(|_| "migration pending state invalid")?;
        let same_attempt = old.operation_id == message.operation_id
            && old.claim_id == message.claim_id
            && old.node_id == node_id;
        let expired = chrono::DateTime::parse_from_rfc3339(&old.expires_at)
            .is_ok_and(|expiry| expiry <= chrono::Utc::now());
        if !(same_attempt
            || expired
                && !old.completed
                && crate::config::NodeRuntimeAuth::load_reload_descriptor(node_id).is_err())
        {
            return Err("another migration bootstrap is already durable".into());
        }
        let secret_path = root.join(SECRET_FILE);
        let meta =
            std::fs::symlink_metadata(&secret_path).map_err(|_| "migration secret missing")?;
        if !meta.is_file()
            || meta.is_symlink()
            || meta.uid() != 0
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err("migration secret permissions invalid".into());
        }
        let stored =
            std::fs::read_to_string(secret_path).map_err(|_| "migration secret missing")?;
        if same_attempt && stored != message.claim_secret {
            return Err("migration bootstrap secret mismatch".into());
        }
        if !same_attempt {
            atomic_private_write(
                &root.join(SECRET_FILE),
                message.claim_secret.as_bytes(),
                0o600,
            )?;
            let next = PendingBootstrap {
                operation_id: message.operation_id.clone(),
                identity_group_id: message.identity_group_id,
                node_id: node_id.into(),
                claim_id: message.claim_id.clone(),
                expires_at: message.expires_at.clone(),
                authorized: false,
                completed: false,
            };
            atomic_private_write(
                &pending_path,
                &serde_json::to_vec(&next).map_err(|_| "migration state encoding failed")?,
                0o600,
            )?;
        }
    } else {
        atomic_private_write(
            &root.join(SECRET_FILE),
            message.claim_secret.as_bytes(),
            0o600,
        )?;
        let pending = PendingBootstrap {
            operation_id: message.operation_id.clone(),
            identity_group_id: message.identity_group_id,
            node_id: node_id.into(),
            claim_id: message.claim_id.clone(),
            expires_at: message.expires_at.clone(),
            authorized: false,
            completed: false,
        };
        atomic_private_write(
            &pending_path,
            &serde_json::to_vec(&pending).map_err(|_| "migration state encoding failed")?,
            0o600,
        )?;
    }
    Ok(NodeMigrationBootstrapAck {
        msg_type: "node_migration_bootstrap_ack".into(),
        operation_id: message.operation_id.clone(),
        claim_id: message.claim_id.clone(),
        node_id: node_id.into(),
    })
}

pub fn persist(
    message: &NodeMigrationBootstrap,
    node_id: &str,
) -> Result<NodeMigrationBootstrapAck, String> {
    persist_at(Path::new(ROOT), message, node_id)
}

fn load_pending(root: &Path) -> Result<PendingBootstrap, String> {
    check_private_directory(root)?;
    let path = root.join(BOOTSTRAP_FILE);
    let meta = std::fs::symlink_metadata(&path).map_err(|_| "migration state missing")?;
    if !meta.is_file()
        || meta.is_symlink()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("migration state permissions invalid".into());
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|_| "migration state read failed")?)
        .map_err(|_| "migration state invalid".into())
}

pub fn authorize(message: &NodeMigrationBootstrapAuthorized, node_id: &str) -> Result<(), String> {
    if message.msg_type != "node_migration_bootstrap_authorized" || message.node_id != node_id {
        return Err("migration authorization identity mismatch".into());
    }
    let root = Path::new(ROOT);
    let mut pending = load_pending(root)?;
    if pending.operation_id != message.operation_id || pending.claim_id != message.claim_id {
        return Err("migration authorization operation mismatch".into());
    }
    pending.authorized = true;
    atomic_private_write(
        &root.join(BOOTSTRAP_FILE),
        &serde_json::to_vec(&pending).map_err(|_| "migration state encoding failed")?,
        0o600,
    )
}

async fn run_pending(node_id: &str) -> Result<(), String> {
    let root = PathBuf::from(ROOT);
    let mut pending = load_pending(&root)?;
    if pending.node_id != node_id || !pending.authorized {
        return Err("migration bootstrap identity mismatch".into());
    }
    if pending.completed {
        return Ok(());
    }
    let helper = include_str!("../../../scripts/relay-node-credential-state.py");
    let digest = format!("{:x}", Sha256::digest(helper.as_bytes()));
    let script = include_str!("../../../scripts/relay-node-pool-migrate.py")
        .replace("__STATE_HELPER_SHA256__", &digest);
    atomic_private_write(&root.join(SCRIPT_FILE), script.as_bytes(), 0o700)?;
    let status = tokio::process::Command::new("/usr/bin/python3")
        .arg(root.join(SCRIPT_FILE))
        .arg("--claim-id")
        .arg(&pending.claim_id)
        .arg("--identity-group-id")
        .arg(pending.identity_group_id.to_string())
        .arg("--node-id")
        .arg(node_id)
        .arg("--secret-file")
        .arg(root.join(SECRET_FILE))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|_| "migration worker unavailable")?;
    if status.success() {
        pending.completed = true;
        atomic_private_write(
            &root.join(BOOTSTRAP_FILE),
            &serde_json::to_vec(&pending).map_err(|_| "migration state encoding failed")?,
            0o600,
        )?;
        Ok(())
    } else {
        Err("migration worker did not complete".into())
    }
}

pub async fn retry_pending(node_id: &str) {
    let Ok(pending) = load_pending(Path::new(ROOT)) else {
        return;
    };
    if pending.node_id != node_id || !pending.authorized || pending.completed {
        return;
    }
    let expiry = chrono::DateTime::parse_from_rfc3339(&pending.expires_at).ok();
    while expiry.is_some_and(|until| until > chrono::Utc::now())
        || crate::config::NodeRuntimeAuth::load_reload_descriptor(node_id).is_ok()
    {
        if run_pending(node_id).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

pub async fn resume_authorized(node_id: &str) {
    if load_pending(Path::new(ROOT))
        .is_ok_and(|pending| pending.node_id == node_id && pending.authorized && !pending.completed)
    {
        let node_id = node_id.to_owned();
        tokio::spawn(async move { retry_pending(&node_id).await });
    }
}

fn requires_exact_auth_at(root: &Path, node_id: &str) -> bool {
    match std::fs::symlink_metadata(root.join(BOOTSTRAP_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
        Ok(_) => pending_requires_exact_auth(load_pending(root), node_id),
    }
}

fn pending_requires_exact_auth(pending: Result<PendingBootstrap, String>, node_id: &str) -> bool {
    match pending {
        Ok(pending) => pending.authorized || pending.completed || pending.node_id != node_id,
        Err(_) => true,
    }
}

pub fn requires_exact_auth(node_id: &str) -> bool {
    requires_exact_auth_at(Path::new(ROOT), node_id)
}

pub fn legacy_config_auth_blocked(node_id: &str, auth: &crate::config::NodeRuntimeAuth) -> bool {
    auth.credential_id().is_none() && requires_exact_auth(node_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_bootstrap_directory_creation_checks_parent_and_symlinks() {
        let root =
            std::env::temp_dir().join(format!("node-auto-directory-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let child = root.join("private");
        if unsafe { libc::geteuid() } == 0 {
            create_safe_directory(&child).unwrap();
            check_private_directory(&child).unwrap();
            let link = root.join("link");
            std::os::unix::fs::symlink(&child, &link).unwrap();
            assert!(create_safe_directory(&link).is_err());
        } else {
            assert!(create_safe_directory(&child).is_err());
            assert!(!child.exists());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authorized_or_unreadable_migration_never_falls_back_to_group_token() {
        let pending = PendingBootstrap {
            operation_id: "operation".into(),
            identity_group_id: 7,
            node_id: "Node_A".into(),
            claim_id: "claim".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
            authorized: false,
            completed: false,
        };
        assert!(!pending_requires_exact_auth(Ok(pending), "Node_A"));
        let pending = PendingBootstrap {
            operation_id: "operation".into(),
            identity_group_id: 7,
            node_id: "Node_A".into(),
            claim_id: "claim".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
            authorized: true,
            completed: false,
        };
        assert!(pending_requires_exact_auth(Ok(pending), "Node_A"));
        assert!(pending_requires_exact_auth(Err("corrupt".into()), "Node_A"));
    }

    #[test]
    fn bootstrap_requires_exact_node_expiry_and_redacts_secret_debug() {
        let message = NodeMigrationBootstrap {
            msg_type: "node_migration_bootstrap".into(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            identity_group_id: 10,
            node_id: "Node_A".into(),
            claim_id: uuid::Uuid::new_v4().to_string(),
            claim_secret: "rpc1_test-private-material".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        };
        assert!(validate_message(&message, "Node_A").is_ok());
        assert!(validate_message(&message, "Node_B").is_err());
        let debug = format!("{message:?}");
        assert!(!debug.contains(&message.claim_secret));
        let mut expired = message.clone();
        expired.expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        assert!(validate_message(&expired, "Node_A").is_err());
    }
}
