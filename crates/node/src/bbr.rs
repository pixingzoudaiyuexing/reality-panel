use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONGESTION_PATH: &str = "/proc/sys/net/ipv4/tcp_congestion_control";
const AVAILABLE_CONGESTION_PATH: &str = "/proc/sys/net/ipv4/tcp_available_congestion_control";
const QDISC_PATH: &str = "/proc/sys/net/core/default_qdisc";
const SYSCTL_PATH: &str = "/etc/sysctl.d/99-reality-panel-bbr.conf";
const MODULES_PATH: &str = "/etc/modules-load.d/reality-panel-bbr.conf";
const MANAGED_HEADER: &str = "# managed by Reality Panel; do not edit\n";
const SYSCTL_CONTENT: &str = "# managed by Reality Panel; do not edit\nnet.ipv4.tcp_congestion_control=bbr\nnet.core.default_qdisc=fq\n";
const MODULES_CONTENT: &str = "# managed by Reality Panel; do not edit\ntcp_bbr\nsch_fq\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnsureOutcome {
    AlreadyEnabled,
    Enabled,
    Warning(String),
}

impl EnsureOutcome {
    pub fn message(&self) -> &str {
        match self {
            Self::AlreadyEnabled => "native BBR and fq are already enabled",
            Self::Enabled => "native BBR and fq were enabled",
            Self::Warning(message) => message,
        }
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning(_))
    }
}

trait BbrHost {
    fn read_value(&self, path: &str) -> Result<String, String>;
    fn module_loaded(&self, module: &str) -> bool;
    fn load_module(&mut self, module: &str) -> Result<(), String>;
    fn apply_value(&mut self, path: &str, value: &str) -> Result<(), String>;
    fn read_managed_file(&self, path: &str) -> Result<Option<String>, String>;
    fn write_managed_file(&mut self, path: &str, contents: &str) -> Result<(), String>;
}

struct SystemBbrHost;

impl BbrHost for SystemBbrHost {
    fn read_value(&self, path: &str) -> Result<String, String> {
        fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(|error| format!("read {path}: {error}"))
    }

    fn module_loaded(&self, module: &str) -> bool {
        Path::new("/sys/module").join(module).is_dir()
    }

    fn load_module(&mut self, module: &str) -> Result<(), String> {
        let output = Command::new("modprobe")
            .arg(module)
            .output()
            .map_err(|error| format!("execute modprobe {module}: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr)
            .replace(['\r', '\n'], " ")
            .chars()
            .take(240)
            .collect::<String>();
        Err(format!("modprobe {module} failed: {detail}"))
    }

    fn apply_value(&mut self, path: &str, value: &str) -> Result<(), String> {
        fs::write(path, value).map_err(|error| format!("write {path}: {error}"))
    }

    fn read_managed_file(&self, path: &str) -> Result<Option<String>, String> {
        let path = Path::new(path);
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => fs::read_to_string(path)
                .map(Some)
                .map_err(|error| format!("read {}: {error}", path.display())),
            Ok(_) => Err(format!("refusing non-file managed path {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect {}: {error}", path.display())),
        }
    }

    fn write_managed_file(&mut self, path: &str, contents: &str) -> Result<(), String> {
        write_managed_file(Path::new(path), contents.as_bytes())
    }
}

pub fn ensure() -> EnsureOutcome {
    ensure_with(&mut SystemBbrHost)
}

fn ensure_with<H: BbrHost>(host: &mut H) -> EnsureOutcome {
    match try_ensure(host) {
        Ok(outcome) => outcome,
        Err(error) => EnsureOutcome::Warning(format!(
            "native BBR/fq unavailable; continuing without acceleration: {error}"
        )),
    }
}

fn try_ensure<H: BbrHost>(host: &mut H) -> Result<EnsureOutcome, String> {
    let old_congestion = host.read_value(CONGESTION_PATH)?;
    let old_qdisc = host.read_value(QDISC_PATH)?;
    let already_enabled = old_congestion == "bbr" && old_qdisc == "fq";

    validate_managed_slot(
        SYSCTL_PATH,
        host.read_managed_file(SYSCTL_PATH)?.as_deref(),
        SYSCTL_CONTENT,
    )?;

    if already_enabled {
        persist_if_changed(host, SYSCTL_PATH, SYSCTL_CONTENT)?;
        return Ok(EnsureOutcome::AlreadyEnabled);
    }

    let mut loaded_module = false;
    let available = host.read_value(AVAILABLE_CONGESTION_PATH)?;
    if !available.split_whitespace().any(|value| value == "bbr") {
        if !host.module_loaded("tcp_bbr") {
            host.load_module("tcp_bbr")?;
            loaded_module = true;
        }
        let available = host.read_value(AVAILABLE_CONGESTION_PATH)?;
        if !available.split_whitespace().any(|value| value == "bbr") {
            return Err("the running kernel does not expose native BBR".into());
        }
    }
    if old_qdisc != "fq" && !host.module_loaded("sch_fq") {
        host.load_module("sch_fq")?;
        loaded_module = true;
    }

    if loaded_module {
        validate_managed_slot(
            MODULES_PATH,
            host.read_managed_file(MODULES_PATH)?.as_deref(),
            MODULES_CONTENT,
        )?;
    }

    if old_qdisc != "fq" {
        host.apply_value(QDISC_PATH, "fq")?;
    }
    if old_congestion != "bbr" {
        if let Err(error) = host.apply_value(CONGESTION_PATH, "bbr") {
            let _ = host.apply_value(QDISC_PATH, &old_qdisc);
            return Err(error);
        }
    }

    let read_back = (|| {
        Ok::<_, String>((
            host.read_value(CONGESTION_PATH)?,
            host.read_value(QDISC_PATH)?,
        ))
    })();
    let (current_congestion, current_qdisc) = match read_back {
        Ok(values) => values,
        Err(error) => {
            let _ = host.apply_value(CONGESTION_PATH, &old_congestion);
            let _ = host.apply_value(QDISC_PATH, &old_qdisc);
            return Err(error);
        }
    };
    if current_congestion != "bbr" || current_qdisc != "fq" {
        let _ = host.apply_value(CONGESTION_PATH, &old_congestion);
        let _ = host.apply_value(QDISC_PATH, &old_qdisc);
        return Err(format!(
            "read-back mismatch: congestion={current_congestion}, qdisc={current_qdisc}"
        ));
    }

    persist_if_changed(host, SYSCTL_PATH, SYSCTL_CONTENT)?;
    if loaded_module {
        persist_if_changed(host, MODULES_PATH, MODULES_CONTENT)?;
    }
    Ok(EnsureOutcome::Enabled)
}

fn validate_managed_slot(path: &str, current: Option<&str>, expected: &str) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    if current == expected || current.starts_with(MANAGED_HEADER) {
        return Ok(());
    }
    Err(format!(
        "refusing to replace non-RealityPanel configuration {path}"
    ))
}

fn persist_if_changed<H: BbrHost>(host: &mut H, path: &str, contents: &str) -> Result<(), String> {
    if host.read_managed_file(path)?.as_deref() == Some(contents) {
        return Ok(());
    }
    host.write_managed_file(path, contents)
}

fn write_managed_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            return Err(format!("refusing non-file managed path {}", path.display()));
        }
    }
    let parent = path.parent().ok_or("managed configuration has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let mut temp_name = path.as_os_str().to_os_string();
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = PathBuf::from(temp_name);
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("clear {}: {error}", temp.display())),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)
        .map_err(|error| format!("create {}: {error}", temp.display()))?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(format!("write {}: {error}", temp.display()));
    }
    drop(file);
    fs::rename(&temp, path)
        .and_then(|_| File::open(parent)?.sync_all())
        .map_err(|error| format!("commit {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    struct FakeHost {
        values: HashMap<String, String>,
        loaded: HashSet<String>,
        files: HashMap<String, String>,
        load_failures: HashSet<String>,
        applied: Vec<(String, String)>,
        writes: Vec<(String, String)>,
    }

    impl FakeHost {
        fn new(congestion: &str, qdisc: &str, available: &str) -> Self {
            Self {
                values: HashMap::from([
                    (CONGESTION_PATH.into(), congestion.into()),
                    (QDISC_PATH.into(), qdisc.into()),
                    (AVAILABLE_CONGESTION_PATH.into(), available.into()),
                ]),
                loaded: HashSet::new(),
                files: HashMap::new(),
                load_failures: HashSet::new(),
                applied: Vec::new(),
                writes: Vec::new(),
            }
        }
    }

    impl BbrHost for FakeHost {
        fn read_value(&self, path: &str) -> Result<String, String> {
            self.values
                .get(path)
                .cloned()
                .ok_or_else(|| format!("missing {path}"))
        }

        fn module_loaded(&self, module: &str) -> bool {
            self.loaded.contains(module)
        }

        fn load_module(&mut self, module: &str) -> Result<(), String> {
            if self.load_failures.contains(module) {
                return Err(format!("{module} unsupported"));
            }
            self.loaded.insert(module.into());
            if module == "tcp_bbr" {
                self.values
                    .insert(AVAILABLE_CONGESTION_PATH.into(), "reno cubic bbr".into());
            }
            Ok(())
        }

        fn apply_value(&mut self, path: &str, value: &str) -> Result<(), String> {
            self.values.insert(path.into(), value.into());
            self.applied.push((path.into(), value.into()));
            Ok(())
        }

        fn read_managed_file(&self, path: &str) -> Result<Option<String>, String> {
            Ok(self.files.get(path).cloned())
        }

        fn write_managed_file(&mut self, path: &str, contents: &str) -> Result<(), String> {
            self.files.insert(path.into(), contents.into());
            self.writes.push((path.into(), contents.into()));
            Ok(())
        }
    }

    #[test]
    fn already_enabled_is_idempotent_and_only_persists_missing_sysctl() {
        let mut host = FakeHost::new("bbr", "fq", "reno cubic bbr");
        assert_eq!(ensure_with(&mut host), EnsureOutcome::AlreadyEnabled);
        assert!(host.applied.is_empty());
        assert!(host.loaded.is_empty());
        assert_eq!(
            host.writes,
            vec![(SYSCTL_PATH.into(), SYSCTL_CONTENT.into())]
        );

        host.writes.clear();
        assert_eq!(ensure_with(&mut host), EnsureOutcome::AlreadyEnabled);
        assert!(host.writes.is_empty());
    }

    #[test]
    fn supported_native_bbr_and_fq_are_enabled_and_persisted() {
        let mut host = FakeHost::new("cubic", "fq_codel", "reno cubic");
        assert_eq!(ensure_with(&mut host), EnsureOutcome::Enabled);
        assert_eq!(host.values[CONGESTION_PATH], "bbr");
        assert_eq!(host.values[QDISC_PATH], "fq");
        assert_eq!(host.files[SYSCTL_PATH], SYSCTL_CONTENT);
        assert_eq!(host.files[MODULES_PATH], MODULES_CONTENT);
        assert_eq!(
            host.loaded,
            HashSet::from(["tcp_bbr".into(), "sch_fq".into()])
        );
    }

    #[test]
    fn persistence_contains_only_the_two_requested_settings() {
        let settings = SYSCTL_CONTENT
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        assert_eq!(
            settings,
            [
                "net.ipv4.tcp_congestion_control=bbr",
                "net.core.default_qdisc=fq"
            ]
        );
        assert_eq!(
            MODULES_CONTENT.lines().skip(1).collect::<Vec<_>>(),
            ["tcp_bbr", "sch_fq"]
        );
    }

    #[test]
    fn unsupported_kernel_is_a_non_fatal_warning() {
        let mut host = FakeHost::new("cubic", "fq_codel", "reno cubic");
        host.load_failures.insert("tcp_bbr".into());
        let outcome = ensure_with(&mut host);
        assert!(outcome.is_warning());
        assert_eq!(host.values[CONGESTION_PATH], "cubic");
        assert_eq!(host.values[QDISC_PATH], "fq_codel");
        assert!(host.writes.is_empty());
    }

    #[test]
    fn unknown_persistence_file_is_preserved_and_returns_warning() {
        let mut host = FakeHost::new("cubic", "fq_codel", "reno cubic bbr");
        host.files
            .insert(SYSCTL_PATH.into(), "operator configuration\n".into());
        let outcome = ensure_with(&mut host);
        assert!(outcome.is_warning());
        assert_eq!(host.files[SYSCTL_PATH], "operator configuration\n");
        assert!(host.applied.is_empty());
    }
}
