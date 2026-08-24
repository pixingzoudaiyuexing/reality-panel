//! Relay-local TLS camouflage sites.
//!
//! Remote REALITY forwarding remains ordinary `ListenerConfig` state owned by
//! the Panel and listener LKG. This module owns only the public TLS wrapper
//! used by dedicated REALITY servers as their fallback target.

use super::nginx_sni::{self, NginxSniConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const CAMOUFLAGE_TLS_PORT: u16 = 8443;
pub const OPENLIST_BACKEND: &str = "127.0.0.1:5244";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CamouflageSitesManifest {
    pub sites: Vec<CamouflageSite>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CamouflageSite {
    pub id: String,
    pub sni: String,
    pub tls_listener_port: u16,
    pub local_backend: String,
    pub certificate: CertificateReference,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateReference {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CamouflageSiteConfig {
    pub enabled: bool,
    pub manifest_path: PathBuf,
    pub state_dir: PathBuf,
    pub nginx: NginxSniConfig,
}

#[derive(Debug)]
pub struct CamouflageSiteManager {
    config: CamouflageSiteConfig,
    active: Option<CamouflageSitesManifest>,
}

impl CamouflageSiteManager {
    pub fn new(config: CamouflageSiteConfig) -> Self {
        Self {
            config,
            active: None,
        }
    }

    /// Restore the camouflage LKG before the listener LKG is activated. This
    /// path has no dependency on Panel availability.
    pub fn restore_and_apply(&mut self) -> bool {
        if !self.config.enabled {
            return true;
        }

        let recovered = self.load_lkg().ok();
        let mut recovered_applied = false;
        if let Some(manifest) = recovered.as_ref() {
            match self.apply_runtime(manifest) {
                Ok(()) => {
                    self.active = Some(manifest.clone());
                    recovered_applied = true;
                }
                Err(error) => {
                    tracing::error!(
                        "camouflage site LKG runtime restore failed; trying source manifest: {}",
                        error
                    );
                }
            }
        }

        match self.load_manifest() {
            Ok(manifest) if !recovered_applied || recovered.as_ref() != Some(&manifest) => {
                if self.apply_candidate(manifest) {
                    true
                } else if recovered_applied {
                    tracing::warn!("camouflage source candidate failed; retained healthy site LKG");
                    true
                } else {
                    false
                }
            }
            Ok(_) => true,
            Err(error) if recovered_applied => {
                tracing::warn!(
                    "camouflage source manifest unavailable; retained site LKG: {}",
                    error
                );
                true
            }
            Err(error) => {
                tracing::warn!("camouflage sites unavailable: {}", error);
                false
            }
        }
    }

    pub fn apply_candidate(&mut self, candidate: CamouflageSitesManifest) -> bool {
        if let Err(error) = self.prepare_candidate(&candidate) {
            tracing::warn!("camouflage site candidate rejected: {}", error);
            return false;
        }
        let rendered = match render_camouflage_config(&candidate) {
            Ok(rendered) => rendered,
            Err(error) => {
                tracing::warn!("camouflage site render rejected: {}", error);
                return false;
            }
        };

        let previous_wrapper = match fs::read(&self.config.nginx.conf_path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::error!("cannot read current camouflage runtime: {}", error);
                return false;
            }
        };
        if let Err(error) = nginx_sni::apply_rendered(&rendered, &self.config.nginx) {
            tracing::error!("camouflage Nginx apply failed: {}", error);
            return false;
        }
        if let Err(error) = self.commit_lkg(&candidate) {
            tracing::error!("camouflage LKG commit failed; restoring runtime: {}", error);
            if let Err(restore_error) =
                nginx_sni::restore_rendered(previous_wrapper.as_deref(), &self.config.nginx)
            {
                tracing::error!(
                    "camouflage runtime restore failed after LKG error: {}",
                    restore_error
                );
            }
            return false;
        }

        self.active = Some(candidate.clone());
        tracing::info!(
            sites = candidate.sites.len(),
            "camouflage sites applied and committed as local LKG"
        );
        true
    }

    fn apply_runtime(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        self.prepare_candidate(manifest)?;
        let rendered = render_camouflage_config(manifest)?;
        nginx_sni::apply_rendered(&rendered, &self.config.nginx).map_err(|e| e.to_string())
    }

    fn prepare_candidate(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        validate_absolute_path(&self.config.manifest_path, "camouflage manifest")?;
        validate_absolute_path(&self.config.state_dir, "camouflage state")?;
        validate_absolute_path(&self.config.nginx.conf_path, "camouflage Nginx config")?;
        reject_symlink(&self.config.state_dir)?;
        reject_symlink(&self.config.nginx.conf_path)?;
        validate_manifest(manifest)?;
        for site in &manifest.sites {
            validate_certificate_reference(&site.certificate)?;
        }
        Ok(())
    }

    pub(crate) fn load_manifest(&self) -> Result<CamouflageSitesManifest, String> {
        read_manifest(&self.config.manifest_path)
    }

    fn load_lkg(&self) -> Result<CamouflageSitesManifest, String> {
        for path in [self.lkg_path(), self.lkg_backup_path()] {
            let Ok(manifest) = read_manifest(&path) else {
                continue;
            };
            if self.prepare_candidate(&manifest).is_ok() {
                return Ok(manifest);
            }
        }
        Err("no valid camouflage site LKG".to_string())
    }

    fn commit_lkg(&self, manifest: &CamouflageSitesManifest) -> Result<(), String> {
        validate_manifest(manifest)?;
        create_private_dir(&self.config.state_dir)?;
        let serialized = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
        let _: CamouflageSitesManifest =
            serde_json::from_slice(&serialized).map_err(|e| e.to_string())?;

        write_private_file(&self.lkg_tmp_path(), &serialized)?;
        let staged = read_manifest(&self.lkg_tmp_path())?;
        validate_manifest(&staged)?;

        if read_manifest(&self.lkg_path())
            .and_then(|current| {
                validate_manifest(&current)?;
                Ok(current)
            })
            .is_ok()
        {
            let previous = fs::read(self.lkg_path()).map_err(|e| e.to_string())?;
            write_private_file(&self.lkg_backup_path(), &previous)?;
        }
        if let Err(error) = fs::rename(self.lkg_tmp_path(), self.lkg_path())
            .and_then(|_| sync_parent(&self.lkg_path()))
        {
            let _ = fs::remove_file(self.lkg_tmp_path());
            return Err(error.to_string());
        }
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

pub fn validate_manifest(manifest: &CamouflageSitesManifest) -> Result<(), String> {
    if manifest.sites.is_empty() {
        return Err("camouflage site manifest is empty".to_string());
    }
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for site in &manifest.sites {
        if !is_safe_id(&site.id) {
            return Err("invalid camouflage site id".to_string());
        }
        if !is_valid_domain(&site.sni) {
            return Err("invalid camouflage SNI".to_string());
        }
        if site.tls_listener_port != CAMOUFLAGE_TLS_PORT {
            return Err("camouflage TLS listener must use port 8443".to_string());
        }
        if site.local_backend != OPENLIST_BACKEND {
            return Err("camouflage backend must be local OpenList".to_string());
        }
        if !ids.insert(site.id.clone()) {
            return Err("duplicate camouflage site id".to_string());
        }
        if !names.insert(site.sni.clone()) {
            return Err("duplicate camouflage SNI".to_string());
        }
        validate_absolute_path(&site.certificate.cert_path, "certificate")?;
        validate_absolute_path(&site.certificate.key_path, "certificate key")?;
        if site.certificate.cert_path == site.certificate.key_path {
            return Err("certificate and key paths must differ".to_string());
        }
    }
    Ok(())
}

pub fn render_camouflage_config(manifest: &CamouflageSitesManifest) -> Result<Vec<u8>, String> {
    validate_manifest(manifest)?;
    let mut sites = manifest.sites.clone();
    sites.sort_by(|a, b| (a.sni.as_str(), a.id.as_str()).cmp(&(b.sni.as_str(), b.id.as_str())));

    let mut out = String::from("# generated by relay-node; TLS camouflage sites\n");
    out.push_str("log_format relay_panel_camouflage '$msec|$remote_addr|$ssl_server_name|$status|$body_bytes_sent|$upstream_addr';\n\n");
    out.push_str("server {\n");
    out.push_str("    listen 8443 ssl default_server;\n");
    out.push_str("    listen [::]:8443 ssl default_server;\n");
    out.push_str("    ssl_reject_handshake on;\n");
    out.push_str("}\n\n");

    for site in sites {
        out.push_str("server {\n");
        out.push_str("    listen 8443 ssl;\n");
        out.push_str("    listen [::]:8443 ssl;\n");
        out.push_str(&format!("    server_name {};\n", quote_nginx(&site.sni)));
        out.push_str(&format!(
            "    ssl_certificate {};\n",
            quote_nginx_path(&site.certificate.cert_path)?
        ));
        out.push_str(&format!(
            "    ssl_certificate_key {};\n",
            quote_nginx_path(&site.certificate.key_path)?
        ));
        out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        out.push_str(
            "    access_log /var/log/nginx/relay-panel-camouflage.log relay_panel_camouflage;\n",
        );
        out.push_str("    location / {\n");
        out.push_str("        proxy_set_header Host $host;\n");
        out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
        out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
        out.push_str("        proxy_set_header X-Forwarded-Proto https;\n");
        out.push_str(&format!(
            "        proxy_pass http://{};\n",
            site.local_backend
        ));
        out.push_str("    }\n");
        out.push_str("}\n\n");
    }
    Ok(out.into_bytes())
}

fn validate_certificate_reference(reference: &CertificateReference) -> Result<(), String> {
    validate_certificate_file(&reference.cert_path, false)?;
    validate_certificate_file(&reference.key_path, true)
}

fn validate_certificate_file(path: &Path, private: bool) -> Result<(), String> {
    validate_absolute_path(
        path,
        if private {
            "certificate key"
        } else {
            "certificate"
        },
    )?;
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("certificate reference must be a regular file".to_string());
    }
    if private {
        if metadata.mode() & 0o077 != 0 {
            return Err("certificate key must not be group/world-readable".to_string());
        }
        if unsafe { libc::geteuid() } == 0 && metadata.uid() != 0 {
            return Err("certificate key must be root-owned".to_string());
        }
    }
    Ok(())
}

fn read_manifest(path: &Path) -> Result<CamouflageSitesManifest, String> {
    validate_absolute_path(path, "camouflage manifest")?;
    reject_symlink(path)?;
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    validate_absolute_path(path, "private directory")?;
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    reject_symlink(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    validate_absolute_path(path, "private file")?;
    reject_symlink(path)?;
    let parent = path.parent().ok_or("file has no parent")?;
    create_private_dir(parent)?;
    let temp = appended_temp_path(path);
    reject_symlink(&temp)?;
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path).and_then(|_| sync_parent(path)) {
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    Ok(())
}

fn appended_temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    PathBuf::from(value)
}

fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    File::open(path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file has no parent")
    })?)?
    .sync_all()
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
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("{} path must be absolute without traversal", name));
    }
    Ok(())
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
            "relay-panel-camouflage-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn certificate(dir: &Path, name: &str) -> CertificateReference {
        create_private_dir(dir).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        write_private_file(&cert_path, b"test certificate").unwrap();
        write_private_file(&key_path, b"test private key").unwrap();
        CertificateReference {
            cert_path,
            key_path,
        }
    }

    fn site(dir: &Path, id: &str, sni: &str) -> CamouflageSite {
        CamouflageSite {
            id: id.into(),
            sni: sni.into(),
            tls_listener_port: CAMOUFLAGE_TLS_PORT,
            local_backend: OPENLIST_BACKEND.into(),
            certificate: certificate(dir, id),
        }
    }

    fn manifest(dir: &Path) -> CamouflageSitesManifest {
        CamouflageSitesManifest {
            sites: vec![site(dir, "op1", "op1.example.com")],
        }
    }

    fn manager(dir: &Path, test_cmd: &str, reload_cmd: &str) -> CamouflageSiteManager {
        CamouflageSiteManager::new(CamouflageSiteConfig {
            enabled: true,
            manifest_path: dir.join("source.json"),
            state_dir: dir.join("state"),
            nginx: NginxSniConfig {
                enabled: true,
                conf_path: dir.join("camouflage.conf"),
                test_cmd: test_cmd.into(),
                reload_cmd: reload_cmd.into(),
                default_backend: "127.0.0.1:9".into(),
                access_log_path: dir.join("stream.log").display().to_string(),
            },
        })
    }

    #[test]
    fn renders_one_public_listener_with_deterministic_multi_vhosts() {
        let dir = unique_dir("render");
        let first = site(&dir, "op1", "op1.example.com");
        let second = site(&dir, "op2", "op2.example.com");
        let a = CamouflageSitesManifest {
            sites: vec![second.clone(), first.clone()],
        };
        let b = CamouflageSitesManifest {
            sites: vec![first, second],
        };
        let rendered_a = String::from_utf8(render_camouflage_config(&a).unwrap()).unwrap();
        let rendered_b = String::from_utf8(render_camouflage_config(&b).unwrap()).unwrap();
        assert_eq!(rendered_a, rendered_b);
        assert_eq!(
            rendered_a.matches("listen 8443 ssl default_server").count(),
            1
        );
        assert_eq!(rendered_a.matches("listen 8443 ssl;").count(), 2);
        assert!(rendered_a.contains("server_name \"op1.example.com\""));
        assert!(rendered_a.contains("op1.crt"));
        assert!(rendered_a.contains("server_name \"op2.example.com\""));
        assert!(rendered_a.contains("op2.crt"));
        assert!(rendered_a.contains("ssl_reject_handshake on"));
        assert_eq!(
            rendered_a
                .matches("proxy_pass http://127.0.0.1:5244")
                .count(),
            2
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn model_has_no_reality_or_route_authority() {
        let dir = unique_dir("ownership");
        let json = serde_json::to_string(&manifest(&dir)).unwrap();
        for forbidden in [
            "private_key",
            "public_key",
            "uuid",
            "short_id",
            "flow",
            "xray",
            "public_port",
            "remote_host",
            "remote_port",
            "targets",
        ] {
            assert!(!json.contains(forbidden), "unexpected field {forbidden}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_sni_port_backend_and_duplicates_are_rejected() {
        let dir = unique_dir("validation");
        let mut invalid = site(&dir, "op1", "UPPER.example.com");
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid.clone()]
        })
        .is_err());
        invalid.sni = "op1.example.com".into();
        invalid.tls_listener_port = 443;
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid.clone()]
        })
        .is_err());
        invalid.tls_listener_port = CAMOUFLAGE_TLS_PORT;
        invalid.local_backend = "127.0.0.1:443".into();
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![invalid]
        })
        .is_err());
        let duplicate = site(&dir, "op2", "op1.example.com");
        assert!(validate_manifest(&CamouflageSitesManifest {
            sites: vec![site(&dir, "op1", "op1.example.com"), duplicate]
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_candidate_validation_does_not_overwrite_lkg() {
        let dir = unique_dir("validation-lkg");
        let mut manager = manager(&dir, "true", "true");
        let healthy = manifest(&dir);
        assert!(manager.apply_candidate(healthy));
        let before = fs::read(manager.lkg_path()).unwrap();
        let mut invalid = manifest(&dir);
        invalid.sites[0].local_backend = "127.0.0.1:443".into();
        assert!(!manager.apply_candidate(invalid));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before);
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nginx_test_failure_restores_runtime_and_preserves_lkg() {
        let dir = unique_dir("nginx-test");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        let before_lkg = fs::read(manager.lkg_path()).unwrap();
        let before_runtime = fs::read(&manager.config.nginx.conf_path).unwrap();
        manager.config.nginx.test_cmd = "false".into();
        let changed = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(!manager.apply_candidate(changed));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before_lkg);
        assert_eq!(
            fs::read(&manager.config.nginx.conf_path).unwrap(),
            before_runtime
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reload_failure_restores_runtime_and_preserves_lkg() {
        let dir = unique_dir("reload");
        let mut manager = manager(&dir, "true", "true");
        assert!(manager.apply_candidate(manifest(&dir)));
        let before_lkg = fs::read(manager.lkg_path()).unwrap();
        let before_runtime = fs::read(&manager.config.nginx.conf_path).unwrap();
        let path = manager.config.nginx.conf_path.clone();
        manager.config.nginx.reload_cmd = format!(
            "if grep -q op2.example.com {}; then exit 1; else exit 0; fi",
            path.display()
        );
        let changed = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(!manager.apply_candidate(changed));
        assert_eq!(fs::read(manager.lkg_path()).unwrap(), before_lkg);
        assert_eq!(
            fs::read(&manager.config.nginx.conf_path).unwrap(),
            before_runtime
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn success_commits_lkg_and_corrupt_primary_recovers_backup() {
        let dir = unique_dir("backup");
        let mut manager = manager(&dir, "true", "true");
        let first = manifest(&dir);
        assert!(manager.apply_candidate(first.clone()));
        let second = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(manager.apply_candidate(second));
        fs::write(manager.lkg_path(), b"not-json").unwrap();
        assert_eq!(manager.load_lkg().unwrap(), first);
        assert!(!manager.lkg_tmp_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn semantically_invalid_primary_recovers_backup() {
        let dir = unique_dir("semantic-backup");
        let mut manager = manager(&dir, "true", "true");
        let first = manifest(&dir);
        assert!(manager.apply_candidate(first.clone()));
        let second = CamouflageSitesManifest {
            sites: vec![site(&dir, "op2", "op2.example.com")],
        };
        assert!(manager.apply_candidate(second));

        let mut invalid = manifest(&dir);
        invalid.sites[0].local_backend = "127.0.0.1:443".into();
        fs::write(
            manager.lkg_path(),
            serde_json::to_vec_pretty(&invalid).unwrap(),
        )
        .unwrap();

        assert_eq!(manager.load_lkg().unwrap(), first);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_restores_lkg_without_panel_or_source_manifest() {
        let dir = unique_dir("offline-restart");
        let mut first = manager(&dir, "true", "true");
        let expected = manifest(&dir);
        assert!(first.apply_candidate(expected.clone()));
        assert!(!first.config.manifest_path.exists());

        let mut restarted = manager(&dir, "true", "true");
        assert!(restarted.restore_and_apply());
        assert_eq!(restarted.active, Some(expected));
        let runtime = fs::read_to_string(&restarted.config.nginx.conf_path).unwrap();
        assert!(runtime.contains("op1.example.com"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn certificate_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let dir = unique_dir("symlink");
        let mut site = site(&dir, "op1", "op1.example.com");
        let link = dir.join("linked.key");
        symlink(&site.certificate.key_path, &link).unwrap();
        site.certificate.key_path = link;
        let mut manager = manager(&dir, "true", "true");
        assert!(!manager.apply_candidate(CamouflageSitesManifest { sites: vec![site] }));
        let _ = fs::remove_dir_all(dir);
    }
}
