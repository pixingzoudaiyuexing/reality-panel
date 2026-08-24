//! Installation-method detection shared by status reporting and lifecycle
//! preflight. Stage 2 upgrades use only Panel-managed local artifacts.

pub fn install_method() -> &'static str {
    if std::path::Path::new("/.dockerenv").exists() {
        "docker"
    } else if std::env::var_os("INVOCATION_ID").is_some() {
        "systemd"
    } else {
        "manual"
    }
}
