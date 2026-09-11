//! Installation-method detection shared by status reporting and lifecycle
//! preflight. Stage 2 upgrades use only Panel-managed local artifacts.

const LITE_MODE_MARKER: &str = "/etc/relay-panel/lite-mode";

pub fn install_method() -> &'static str {
    if std::path::Path::new("/.dockerenv").exists() {
        "docker"
    } else if std::env::var_os("INVOCATION_ID").is_some() {
        "systemd"
    } else {
        "manual"
    }
}

pub fn lite_mode() -> bool {
    lite_mode_at(std::path::Path::new(LITE_MODE_MARKER))
}

fn lite_mode_at(path: &std::path::Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_marker_is_legacy_standard_and_regular_marker_is_lite() {
        let root = std::env::temp_dir().join(format!(
            "relay-node-lite-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let marker = root.join("lite-mode");
        assert!(!lite_mode_at(&marker));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&marker, b"lite\n").unwrap();
        assert!(lite_mode_at(&marker));
        std::fs::remove_dir_all(root).unwrap();
    }
}
