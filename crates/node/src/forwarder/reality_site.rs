//! Node-local REALITY site ownership.
//!
//! This deliberately has no shared-protocol representation. A site manifest,
//! certificate references, and the REALITY private key all remain root-owned on
//! the node. The Panel continues to own only ordinary forwarding listeners.

use super::manager::ForwarderManager;
use super::nginx_sni::{self, LocalSniRoute, NginxSniConfig};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealitySitesManifest {
    pub sites: Vec<RealitySite>,
}

impl std::fmt::Debug for RealitySitesManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealitySitesManifest")
            .field("sites", &self.sites)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealitySite {
    pub id: String,
    pub sni: String,
    pub public_port: u16,
    pub xray_inbound_port: u16,
    pub fallback_tls_port: u16,
    pub certificate: CertificateReference,
    pub reality: RealitySettings,
}

impl std::fmt::Debug for RealitySite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealitySite")
            .field("id", &self.id)
            .field("sni", &self.sni)
            .field("public_port", &self.public_port)
            .field("xray_inbound_port", &self.xray_inbound_port)
            .field("fallback_tls_port", &self.fallback_tls_port)
            .field("certificate", &self.certificate)
            .field("reality", &self.reality)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateReference {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealitySettings {
    pub uuid: String,
    pub flow: String,
    pub short_id: String,
    pub public_key: String,
    pub server_names: Vec<String>,
    /// Node-local root-owned file, never a Panel or shared-protocol field.
    pub private_key_path: PathBuf,
    pub target: LocalRealityTarget,
    #[serde(default = "default_outbound")]
    pub outbound: RealityOutbound,
}

impl std::fmt::Debug for RealitySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealitySettings")
            .field("uuid", &"[redacted]")
            .field("flow", &self.flow)
            .field("short_id", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("server_names", &self.server_names)
            .field("private_key_path", &"[redacted]")
            .field("target", &self.target)
            .field("outbound", &self.outbound)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalRealityTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RealityOutbound {
    Direct,
}

fn default_outbound() -> RealityOutbound {
    RealityOutbound::Direct
}

#[derive(Clone, Debug)]
pub struct RealitySiteConfig {
    pub enabled: bool,
    pub manifest_path: PathBuf,
    pub state_dir: PathBuf,
    pub xray_binary: PathBuf,
    pub expected_xray_version: String,
    pub nginx: NginxSniConfig,
    pub openlist_upstream: String,
}

#[derive(Debug)]
pub struct RealitySiteManager {
    config: RealitySiteConfig,
    active: Option<RealitySitesManifest>,
    xray: Option<Child>,
}

impl RealitySiteManager {
    pub fn new(config: RealitySiteConfig) -> Self {
        Self {
            config,
            active: None,
            xray: None,
        }
    }

    /// Restore a healthy site LKG before the control channel is started. This
    /// has no dependency on Panel availability.
    pub async fn restore_and_apply(&mut self, manager: &Arc<Mutex<ForwarderManager>>) -> bool {
        if !self.config.enabled {
            return true;
        }
        let recovered = self.load_lkg().ok();
        if let Some(manifest) = recovered.as_ref() {
            if !self.apply_candidate(manifest.clone(), manager).await {
                return false;
            }
        }
        match self.load_manifest() {
            Ok(manifest) if recovered.as_ref() != Some(&manifest) => {
                self.apply_candidate(manifest, manager).await
            }
            Ok(_) => true,
            Err(error) if recovered.is_some() => {
                tracing::warn!(
                    "Reality source manifest unavailable; retained site LKG: {}",
                    error
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    "Reality sites unavailable; keeping listener data plane: {}",
                    error
                );
                false
            }
        }
    }

    pub async fn apply_candidate(
        &mut self,
        candidate: RealitySitesManifest,
        manager: &Arc<Mutex<ForwarderManager>>,
    ) -> bool {
        if let Err(error) = validate_manifest(&candidate, &self.config.openlist_upstream) {
            tracing::warn!("Reality site candidate rejected: {}", error);
            return false;
        }
        if let Err(error) = self.verify_xray_binary() {
            tracing::error!("Reality Xray binary rejected: {}", error);
            return false;
        }

        let prepared = match self.prepare_for_apply(&candidate) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::error!("Reality site candidate preparation failed: {}", error);
                return false;
            }
        };
        if let Err(error) = self.validate_xray_config(&prepared.xray_config) {
            tracing::error!("Reality Xray candidate validation failed: {}", error);
            return false;
        }

        let old = self.active.clone();
        let previous_wrapper = fs::read(&self.config.nginx.conf_path).ok();
        // The wrapper is independent of the stream router, and has its own
        // disk/runtime rollback if Nginx rejects it.
        if let Err(error) = nginx_sni::apply_rendered(&prepared.wrapper_config, &self.config.nginx)
        {
            tracing::error!("Reality TLS wrapper apply failed: {}", error);
            return false;
        }
        if let Err(error) = self.restart_xray(&prepared.xray_config) {
            tracing::error!("Reality Xray runtime apply failed: {}", error);
            let _ = nginx_sni::restore_rendered(previous_wrapper.as_deref(), &self.config.nginx);
            self.restore_runtime(old.as_ref(), manager).await;
            return false;
        }
        if let Err(error) = self.validate_xray_listeners(&candidate) {
            tracing::error!("Reality Xray health validation failed: {}", error);
            let _ = nginx_sni::restore_rendered(previous_wrapper.as_deref(), &self.config.nginx);
            self.restore_runtime(old.as_ref(), manager).await;
            return false;
        }
        let routes = routes_for(&candidate);
        if !manager.lock().await.apply_reality_sni_routes(routes).await {
            tracing::error!("Reality stream route apply failed; restoring previous site runtime");
            let _ = nginx_sni::restore_rendered(previous_wrapper.as_deref(), &self.config.nginx);
            self.restore_runtime(old.as_ref(), manager).await;
            return false;
        }
        if let Err(error) = self.commit_lkg(&prepared.persisted_manifest, &prepared.xray_config) {
            tracing::error!(
                "Reality site apply succeeded but LKG commit failed: {}",
                error
            );
            self.restore_runtime(old.as_ref(), manager).await;
            return false;
        }
        self.active = Some(prepared.persisted_manifest);
        tracing::info!(
            sites = candidate.sites.len(),
            "Reality sites applied and committed as local LKG"
        );
        true
    }

    async fn restore_runtime(
        &mut self,
        old: Option<&RealitySitesManifest>,
        manager: &Arc<Mutex<ForwarderManager>>,
    ) {
        let Some(old) = old.cloned() else {
            let _ = self.stop_xray();
            let _ = manager
                .lock()
                .await
                .apply_reality_sni_routes(Vec::new())
                .await;
            return;
        };
        let Ok(prepared) = self.prepare_for_apply(&old) else {
            tracing::error!("unable to prepare old Reality LKG for rollback");
            return;
        };
        let _ = nginx_sni::apply_rendered(&prepared.wrapper_config, &self.config.nginx);
        let _ = self.restart_xray(&prepared.xray_config);
        let _ = manager
            .lock()
            .await
            .apply_reality_sni_routes(routes_for(&old))
            .await;
    }

    pub(crate) fn load_manifest(&self) -> Result<RealitySitesManifest, String> {
        read_manifest(&self.config.manifest_path)
    }

    fn load_lkg(&self) -> Result<RealitySitesManifest, String> {
        for path in [self.lkg_path(), self.lkg_backup_path()] {
            if let Ok(manifest) = read_manifest(&path) {
                validate_manifest(&manifest, &self.config.openlist_upstream)?;
                return Ok(manifest);
            }
        }
        Err("no valid Reality site LKG".to_string())
    }

    fn verify_xray_binary(&self) -> Result<(), String> {
        reject_symlink(&self.config.xray_binary)?;
        let metadata = fs::metadata(&self.config.xray_binary).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err("Xray binary is not executable".to_string());
        }
        let output = Command::new(&self.config.xray_binary)
            .arg("version")
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .contains(&format!("Xray {}", self.config.expected_xray_version))
        {
            return Err(format!(
                "expected fixed Xray {}",
                self.config.expected_xray_version
            ));
        }
        Ok(())
    }

    fn prepare_for_apply(
        &self,
        manifest: &RealitySitesManifest,
    ) -> Result<PreparedSiteFiles, String> {
        create_private_dir(&self.config.state_dir)?;
        let mut persisted = manifest.clone();
        let secret_dir = self.config.state_dir.join("secrets");
        create_private_dir(&secret_dir)?;
        let mut private_keys = Vec::with_capacity(manifest.sites.len());
        for (site, persisted_site) in manifest.sites.iter().zip(persisted.sites.iter_mut()) {
            let key = read_private_key(&site.reality.private_key_path)?;
            let target = secret_dir.join(format!("{}.reality-key", site.id));
            write_private_file(&target, key.as_bytes())?;
            persisted_site.reality.private_key_path = target;
            private_keys.push(key);
        }
        let xray_config = render_xray_config(&persisted, &private_keys)?;
        let wrapper_config = render_wrapper_config(&persisted, &self.config.openlist_upstream)?;
        Ok(PreparedSiteFiles {
            persisted_manifest: persisted,
            xray_config,
            wrapper_config,
        })
    }

    fn validate_xray_config(&self, config: &[u8]) -> Result<(), String> {
        let path = self.config.state_dir.join("xray.candidate.json");
        write_private_file(&path, config)?;
        let status = Command::new(&self.config.xray_binary)
            .args(["run", "-test", "-config"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        let _ = fs::remove_file(path);
        if status.success() {
            Ok(())
        } else {
            Err("Xray config test command failed".to_string())
        }
    }

    fn restart_xray(&mut self, config: &[u8]) -> Result<(), String> {
        let path = self.config.state_dir.join("xray.json");
        write_private_file(&path, config)?;
        self.stop_xray()?;
        let child = Command::new(&self.config.xray_binary)
            .args(["run", "-config"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(100));
        let mut child = child;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("Xray exited immediately with {}", status));
        }
        self.xray = Some(child);
        Ok(())
    }

    fn validate_xray_listeners(&self, manifest: &RealitySitesManifest) -> Result<(), String> {
        for site in &manifest.sites {
            let address = format!("127.0.0.1:{}", site.xray_inbound_port);
            std::net::TcpStream::connect_timeout(
                &address
                    .parse()
                    .map_err(|_| "invalid Xray loopback address")?,
                Duration::from_secs(1),
            )
            .map_err(|_| "Xray loopback listener did not become healthy")?;
        }
        Ok(())
    }

    fn stop_xray(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.xray.take() {
            child.kill().map_err(|e| e.to_string())?;
            let _ = child.wait();
        }
        Ok(())
    }

    fn commit_lkg(&self, manifest: &RealitySitesManifest, xray: &[u8]) -> Result<(), String> {
        let serialized = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
        let _: RealitySitesManifest =
            serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;
        write_private_file(&self.lkg_tmp_path(), &serialized)?;
        let _: RealitySitesManifest = read_manifest(&self.lkg_tmp_path())?;
        if self.lkg_path().exists() {
            let previous = fs::read(self.lkg_path()).map_err(|e| e.to_string())?;
            write_private_file(&self.lkg_backup_path(), &previous)?;
        }
        // Persist the runtime config before the manifest becomes the new LKG.
        // A write failure here must leave the old manifest authoritative.
        write_private_file(&self.config.state_dir.join("xray.json"), xray)?;
        fs::rename(self.lkg_tmp_path(), self.lkg_path()).map_err(|e| e.to_string())?;
        sync_parent(&self.lkg_path())?;
        Ok(())
    }

    fn lkg_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.json")
    }
    fn lkg_backup_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.backup.json")
    }
    fn lkg_tmp_path(&self) -> PathBuf {
        self.config.state_dir.join("site-manifest.json.tmp")
    }
}

impl Drop for RealitySiteManager {
    fn drop(&mut self) {
        let _ = self.stop_xray();
    }
}

struct PreparedSiteFiles {
    persisted_manifest: RealitySitesManifest,
    xray_config: Vec<u8>,
    wrapper_config: Vec<u8>,
}

fn routes_for(manifest: &RealitySitesManifest) -> Vec<LocalSniRoute> {
    manifest
        .sites
        .iter()
        .map(|site| LocalSniRoute {
            site_id: site.id.clone(),
            listen_port: site.public_port,
            sni: site.sni.clone(),
            backend: format!("127.0.0.1:{}", site.xray_inbound_port),
        })
        .collect()
}

pub fn validate_manifest(
    manifest: &RealitySitesManifest,
    openlist_upstream: &str,
) -> Result<(), String> {
    if manifest.sites.is_empty() {
        return Err("Reality site manifest is empty".to_string());
    }
    if !is_loopback_upstream(openlist_upstream) {
        return Err("OpenList upstream must be loopback".to_string());
    }
    let mut names = std::collections::HashSet::new();
    let mut routes = std::collections::HashSet::new();
    for site in &manifest.sites {
        validate_site(site)?;
        if !names.insert(site.id.clone()) {
            return Err("duplicate Reality site id".to_string());
        }
        if !routes.insert((site.public_port, site.sni.clone())) {
            return Err("duplicate Reality public SNI route".to_string());
        }
    }
    Ok(())
}

fn validate_site(site: &RealitySite) -> Result<(), String> {
    if !is_safe_id(&site.id) {
        return Err("invalid Reality site id".to_string());
    }
    if !is_valid_domain(&site.sni) {
        return Err("invalid Reality SNI".to_string());
    }
    if [
        site.public_port,
        site.xray_inbound_port,
        site.fallback_tls_port,
    ]
    .contains(&0)
        || site.xray_inbound_port == site.fallback_tls_port
        || site.public_port == site.fallback_tls_port
    {
        return Err("Reality ports conflict or are zero".to_string());
    }
    if site.reality.target.host != "127.0.0.1" || site.reality.target.port != site.fallback_tls_port
    {
        return Err("Reality target must be the site local TLS wrapper".to_string());
    }
    if !is_valid_uuid(&site.reality.uuid) {
        return Err("invalid Reality UUID".to_string());
    }
    if site.reality.flow != "xtls-rprx-vision" {
        return Err("unsupported Reality flow".to_string());
    }
    if !is_valid_short_id(&site.reality.short_id) {
        return Err("invalid Reality shortId".to_string());
    }
    if !is_x25519_public_key(&site.reality.public_key) {
        return Err("invalid Reality public key".to_string());
    }
    if site.reality.server_names != [site.sni.clone()] {
        return Err("Reality serverNames must contain exactly the site SNI".to_string());
    }
    validate_absolute_path(&site.certificate.cert_path, "certificate")?;
    validate_absolute_path(&site.certificate.key_path, "certificate key")?;
    validate_absolute_path(&site.reality.private_key_path, "Reality private key")?;
    Ok(())
}

fn render_xray_config(
    manifest: &RealitySitesManifest,
    private_keys: &[String],
) -> Result<Vec<u8>, String> {
    let inbounds: Vec<serde_json::Value> = manifest.sites.iter().zip(private_keys).map(|(site, key)| {
        serde_json::json!({
            "listen": "127.0.0.1", "port": site.xray_inbound_port, "protocol": "vless",
            "settings": {"clients": [{"id": site.reality.uuid, "flow": site.reality.flow}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": false, "dest": format!("127.0.0.1:{}", site.fallback_tls_port), "xver": 0,
                "serverNames": site.reality.server_names, "privateKey": key, "shortIds": [site.reality.short_id]
            }}
        })
    }).collect();
    serde_json::to_vec_pretty(&serde_json::json!({
        "log": {"loglevel": "warning"}, "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }))
    .map_err(|e| e.to_string())
}

fn render_wrapper_config(
    manifest: &RealitySitesManifest,
    upstream: &str,
) -> Result<Vec<u8>, String> {
    let mut rendered = String::from("# generated by relay-node; Reality local TLS wrappers\n");
    for site in &manifest.sites {
        rendered.push_str("server {\n");
        rendered.push_str(&format!(
            "    listen 127.0.0.1:{} ssl;\n",
            site.fallback_tls_port
        ));
        rendered.push_str(&format!("    server_name {};\n", quote_nginx(&site.sni)));
        rendered.push_str(&format!(
            "    ssl_certificate {};\n",
            quote_nginx_path(&site.certificate.cert_path)?
        ));
        rendered.push_str(&format!(
            "    ssl_certificate_key {};\n",
            quote_nginx_path(&site.certificate.key_path)?
        ));
        rendered.push_str(&format!(
            "    location / {{ proxy_pass http://{}; }}\n",
            upstream
        ));
        rendered.push_str("}\n\n");
    }
    Ok(rendered.into_bytes())
}

fn read_manifest(path: &Path) -> Result<RealitySitesManifest, String> {
    reject_symlink(path)?;
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn read_private_key(path: &Path) -> Result<String, String> {
    validate_absolute_path(path, "Reality private key")?;
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err("Reality private key must be root-owned mode 0600".to_string());
    }
    let key = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let key = key.trim().to_string();
    if !is_x25519_public_key(&key) {
        return Err("invalid Reality private key format".to_string());
    }
    Ok(key)
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    reject_symlink(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("file has no parent")?;
    create_private_dir(parent)?;
    let temp = path.with_extension("tmp");
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    file.write_all(contents).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temp, path).map_err(|e| e.to_string())?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path.parent().ok_or("file has no parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("refusing symlink {}", path.display()))
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

fn validate_absolute_path(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("{} path must be absolute without traversal", name));
    }
    Ok(())
}

fn is_loopback_upstream(value: &str) -> bool {
    value
        .strip_prefix("127.0.0.1:")
        .and_then(|p| p.parse::<u16>().ok())
        .is_some()
}

fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn is_valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

fn is_valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, c)| {
            if [8, 13, 18, 23].contains(&index) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn is_valid_short_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value.len() % 2 == 0
        && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_x25519_public_key(value: &str) -> bool {
    value.len() == 43
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn quote_nginx(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
fn quote_nginx_path(path: &Path) -> Result<String, String> {
    Ok(quote_nginx(path.to_str().ok_or("non-UTF8 path")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "relay-panel-reality-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn test_manager(dir: PathBuf) -> RealitySiteManager {
        RealitySiteManager::new(RealitySiteConfig {
            enabled: true,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("state"),
            xray_binary: "/bin/true".into(),
            expected_xray_version: "1.8.24".into(),
            nginx: NginxSniConfig {
                enabled: false,
                conf_path: dir.join("wrapper.conf"),
                test_cmd: "true".into(),
                reload_cmd: "true".into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("access.log").display().to_string(),
            },
            openlist_upstream: "127.0.0.1:5244".into(),
        })
    }

    fn site() -> RealitySite {
        RealitySite {
            id: "poc-site".into(),
            sni: "poc.example.com".into(),
            public_port: 443,
            xray_inbound_port: 24443,
            fallback_tls_port: 8443,
            certificate: CertificateReference {
                cert_path: "/etc/ssl/poc.crt".into(),
                key_path: "/etc/ssl/poc.key".into(),
            },
            reality: RealitySettings {
                uuid: "1178cda8-684b-41ac-9a6d-1ac8a2b1f1b0".into(),
                flow: "xtls-rprx-vision".into(),
                short_id: "e48b78bbc80088ed".into(),
                public_key: "jCJq2OuK1B_k1a8vCb18StSBmmh_5y-VmEd51ThWjns".into(),
                server_names: vec!["poc.example.com".into()],
                private_key_path: "/etc/relay-panel/private-secret.key".into(),
                target: LocalRealityTarget {
                    host: "127.0.0.1".into(),
                    port: 8443,
                },
                outbound: RealityOutbound::Direct,
            },
        }
    }

    #[test]
    fn valid_site_renders_loopback_xray_and_wrapper() {
        let manifest = RealitySitesManifest {
            sites: vec![site()],
        };
        validate_manifest(&manifest, "127.0.0.1:5244").unwrap();
        let xray = String::from_utf8(
            render_xray_config(
                &manifest,
                &["jCJq2OuK1B_k1a8vCb18StSBmmh_5y-VmEd51ThWjns".into()],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(xray.contains("\"listen\": \"127.0.0.1\""));
        assert!(xray.contains("127.0.0.1:8443"));
        assert!(!xray.contains("\"listen\": \"0.0.0.0\""));
        let wrapper =
            String::from_utf8(render_wrapper_config(&manifest, "127.0.0.1:5244").unwrap()).unwrap();
        assert!(wrapper.contains("listen 127.0.0.1:8443 ssl"));
        assert!(wrapper.contains("proxy_pass http://127.0.0.1:5244"));
    }

    #[test]
    fn recursion_and_invalid_identifiers_are_rejected() {
        let mut broken = site();
        broken.reality.target.port = 443;
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![broken]
            },
            "127.0.0.1:5244"
        )
        .is_err());
        let mut broken = site();
        broken.sni = "UPPER.example.com".into();
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![broken]
            },
            "127.0.0.1:5244"
        )
        .is_err());
        let mut broken = site();
        broken.reality.uuid = "not-a-uuid".into();
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![broken]
            },
            "127.0.0.1:5244"
        )
        .is_err());
        let mut broken = site();
        broken.reality.short_id = "not-hex".into();
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![broken]
            },
            "127.0.0.1:5244"
        )
        .is_err());
        let mut broken = site();
        broken.reality.server_names = vec!["other.example.com".into()];
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![broken]
            },
            "127.0.0.1:5244"
        )
        .is_err());
    }

    #[test]
    fn debug_and_public_manifest_do_not_expose_private_key_value() {
        let manifest = RealitySitesManifest {
            sites: vec![site()],
        };
        let debug = format!("{manifest:?}");
        assert!(!debug.contains("/etc/relay-panel/private-secret.key"));
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(
            !json.contains("privateKey"),
            "Xray-only key field leaked into manifest"
        );
        assert!(json.contains("public_key"));
    }

    #[test]
    fn local_route_uses_only_loopback_xray_port() {
        let manifest = RealitySitesManifest {
            sites: vec![site()],
        };
        assert_eq!(routes_for(&manifest)[0].backend, "127.0.0.1:24443");
    }

    #[test]
    fn failed_candidate_validation_does_not_overwrite_site_lkg() {
        let dir = unique_dir("preserve-lkg");
        let manager = test_manager(dir.clone());
        let healthy = RealitySitesManifest {
            sites: vec![site()],
        };
        manager.commit_lkg(&healthy, b"{}\n").unwrap();
        let before = fs::read(manager.lkg_path()).unwrap();

        let mut invalid = site();
        invalid.reality.target.port = 443;
        assert!(validate_manifest(
            &RealitySitesManifest {
                sites: vec![invalid]
            },
            "127.0.0.1:5244"
        )
        .is_err());
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before);
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_primary_recovers_from_site_lkg_backup() {
        let dir = unique_dir("backup-lkg");
        let manager = test_manager(dir.clone());
        let first = RealitySitesManifest {
            sites: vec![site()],
        };
        manager.commit_lkg(&first, b"first").unwrap();
        let mut changed_site = site();
        changed_site.xray_inbound_port = 24444;
        let second = RealitySitesManifest {
            sites: vec![changed_site],
        };
        manager.commit_lkg(&second, b"second").unwrap();
        fs::write(manager.lkg_path(), b"not-json").unwrap();
        assert_eq!(manager.load_lkg().unwrap(), first);
        let xray_mode = fs::metadata(manager.config.state_dir.join("xray.json"))
            .unwrap()
            .mode()
            & 0o777;
        assert_eq!(xray_mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }
}
pub const FIXED_XRAY_VERSION: &str = "1.8.24";
