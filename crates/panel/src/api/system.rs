use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::config::app_version;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const REPO: &str = "pixingzoudaiyuexing/reality-panel";
const CACHE_TTL: Duration = Duration::from_secs(1800); // 30 minutes

/// Cached GitHub Release info. Shared across all requests via AppState.
#[derive(Clone)]
pub struct ReleaseCache {
    inner: Arc<RwLock<Option<CachedRelease>>>,
}

struct CachedRelease {
    fetched_at: Instant,
    data: CachedReleases,
}

/// Reality Panel releases ship matching Panel and Node binaries under one
/// `v*` tag. Both update projections therefore come from the same verified
/// GitHub Release.
#[derive(Clone)]
struct CachedReleases {
    panel: Option<GitHubRelease>,
    node: Option<GitHubRelease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    /// GitHub may return null for some fields on old or minimal releases
    /// (e.g. v0.2.0 / v0.1.9 have `"body": null`). Making them Option keeps
    /// the whole releases list deserializable instead of failing the entire
    /// update check.
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    /// Whether the release is a draft (never offered as an update).
    #[serde(default)]
    draft: bool,
    /// Whether the release is marked as a pre-release.
    #[serde(default)]
    prerelease: bool,
}

impl ReleaseCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    async fn get(&self) -> Option<CachedReleases> {
        let guard = self.inner.read().await;
        if let Some(ref cached) = *guard {
            if cached.fetched_at.elapsed() < CACHE_TTL {
                return Some(cached.data.clone());
            }
        }
        None
    }

    /// Force the next `get()` to miss the cache (so the next call will
    /// re-fetch from GitHub). Used by `?refresh=1` on the version endpoint.
    async fn invalidate(&self) {
        let mut guard = self.inner.write().await;
        *guard = None;
    }

    async fn set(&self, data: CachedReleases) {
        let mut guard = self.inner.write().await;
        *guard = Some(CachedRelease {
            fetched_at: Instant::now(),
            data,
        });
    }

    /// Resolve the matching Node version (bare, e.g. "1.0.0") from the latest
    /// stable Reality Panel release. Returns:
    /// - `Ok(Some(version))` — a node release was found.
    /// - `Ok(None)`           — the check succeeded but there is no node
    ///   release yet (caller should treat as "no upgrade target available").
    /// - `Err(message)`        — the version check failed (network/HTTP/parse).
    ///
    /// The directed-upgrade handler MUST use this and MUST NEVER fall back to
    /// the panel version: a panel-only release (e.g. v1.2.0 with no node
    /// binary) would otherwise command nodes to download a non-existent asset.
    pub async fn resolve_latest_node_version(&self) -> Result<Option<String>, String> {
        // Reuse the cache if fresh; otherwise fetch + repopulate. On fetch
        // failure, do NOT cache (so the next request retries).
        let releases = match self.get().await {
            Some(r) => r,
            None => {
                let fetched = fetch_github_releases().await?;
                self.set(fetched.clone()).await;
                fetched
            }
        };
        Ok(releases
            .node
            .as_ref()
            .and_then(|r| r.tag_name.strip_prefix('v'))
            .map(|s| s.to_string()))
    }
}

#[derive(Debug, Serialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub latest_version: String,
    pub has_update: bool,
    pub is_outdated: bool,
    pub release_url: String,
    pub release_notes: String,
    pub published_at: String,
    pub public_panel_url: String,
    /// True if the GitHub release check failed. Frontend should show a
    /// "update check failed" hint instead of just "no update available" —
    /// otherwise users may think they're up to date when the check itself
    /// silently failed.
    pub check_failed: bool,
    /// Short human-readable error message from the last failed check. Empty
    /// on success.
    pub error_message: String,
    /// The panel's config-protocol version (relay_shared::CONFIG_PROTOCOL_VERSION).
    /// The frontend compares each node's reported config_protocol_version against
    /// this to decide compatibility — previously the frontend hardcoded "1",
    /// which mislabeled healthy nodes after the constant was bumped to 2.
    pub config_protocol_version: u32,
    /// The Node version from the latest stable unified `v*` Release. Panel and
    /// Node artifacts are built together, so this projection intentionally
    /// matches the Panel release version. Empty when no release exists or the
    /// check failed.
    pub latest_node_version: String,
    /// v1.2: true if the node-version lookup failed. The frontend must show an
    /// "unknown / check failed" state (NOT a green "up to date" or an upgrade
    /// button) so a broken check can never silently drive a wrong upgrade.
    pub node_version_check_failed: bool,
}

/// Parse a version string like "v0.1.4" or "0.1.4" into a semver Version.
fn parse_version(s: &str) -> Option<semver::Version> {
    let cleaned = s.strip_prefix('v').unwrap_or(s);
    semver::Version::parse(cleaned).ok()
}

/// Accept only the unified Reality Panel release tag namespace.
fn release_version(tag: &str) -> Option<semver::Version> {
    semver::Version::parse(tag.strip_prefix('v')?).ok()
}

/// Whether pre-releases count as "latest" when looking for updates.
///
/// GitHub's `/releases/latest` endpoint ignores pre-releases entirely, which
/// would make the update check blind during the pre-release phase. We request
/// the full `/releases` list instead and pick the highest semver tag, allowing
/// pre-releases while this project is in pre-release. Flip to `false` once we
/// ship a stable 1.0 and only want to notify users about stable releases.
const ALLOW_PRERELEASE_UPDATES: bool = false;

/// Fetch releases from GitHub and pick the newest eligible unified release.
///
/// Why not `/releases/latest`: that endpoint only returns the latest
/// **non-prerelease** release, so during the pre-release phase it returns an
/// old (or no) release. Instead we list `/releases`, drop drafts (never
/// installable), classify each tag, and take the greatest semver PER TRACK.
/// Pre-releases are excluded from the default update channel. Operators may
/// still install a specific RC tag through the release installer.
///
/// Returns:
/// - `Ok(CachedReleases)`  - call succeeded; each track is Some if an eligible
///   release was found, None if that track had no eligible release.
/// - `Err(msg)`             - network/HTTP/parse error (logged, surfaced to
///   client). NOTE: a single shared error covers BOTH tracks because the
///   fetch is one HTTP call; the caller maps this to `check_failed` AND
///   `node_version_check_failed` both true.
///
/// Every error path logs a `tracing::warn!` with the URL, status, and body so
/// ops can diagnose a broken update check (this used to silently return None
/// and the user saw "no update available" forever).
async fn fetch_github_releases() -> Result<CachedReleases, String> {
    let url = format!("https://api.github.com/repos/{}/releases?per_page=30", REPO);
    let client = match reqwest::Client::builder()
        .user_agent("RelayPanel-Version-Check")
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "version-check: failed to build HTTP client");
            return Err(format!("build client: {}", e));
        }
    };

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "version-check: network error");
            return Err(format!("network: {}", e));
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(
            url = %url,
            status = %status,
            body = %body.chars().take(200).collect::<String>(),
            "version-check: GitHub returned non-2xx"
        );
        return Err(format!("HTTP {}", status.as_u16()));
    }

    let releases: Vec<GitHubRelease> = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            // GitHub occasionally returns null for body/html_url/published_at
            // on old or minimal releases; the GitHubRelease struct tolerates
            // that via Option fields now, but surface a clear message in case
            // the response shape changed in some other way.
            tracing::warn!(
                url = %url,
                error = %e,
                "version-check: GitHub release JSON parse failed; \
                 response shape may have changed or a field is incompatible"
            );
            return Err(format!(
                "GitHub release JSON parse failed; one or more fields may be null or incompatible ({})",
                e
            ));
        }
    };

    // Drop drafts and prereleases, then take the highest unified v* release.
    let eligible = releases
        .into_iter()
        .filter(|r| !r.draft)
        .filter(|r| ALLOW_PRERELEASE_UPDATES || !r.prerelease);

    let mut latest: Option<(semver::Version, GitHubRelease)> = None;
    for r in eligible {
        let Some(v) = release_version(&r.tag_name) else {
            continue;
        };
        match &latest {
            None => latest = Some((v, r)),
            Some((best, _)) if &v > best => latest = Some((v, r)),
            _ => {}
        }
    }

    let release = latest.map(|(_, release)| release);

    Ok(CachedReleases {
        panel: release.clone(),
        node: release,
    })
}

/// Query parameters for `get_version`. `refresh=true` (or `1`) bypasses the
/// 30-minute cache so the "check update" button on the dashboard can force a
/// fresh GitHub call.
///
/// Accepts `refresh=true|false|1|0` (case-insensitive). Any other value or
/// absence defaults to `false`. This is looser than `serde(bool)` so the
/// frontend can use either `refresh=1` (legacy) or `refresh=true`.
#[derive(Debug, Default, Deserialize)]
pub struct VersionQuery {
    #[serde(default)]
    pub refresh: Option<String>,
}

impl VersionQuery {
    /// Resolve the refresh flag to a bool. Truthy: "true", "1", "yes", "on"
    /// (case-insensitive). Everything else (including None) is falsy.
    fn want_refresh(&self) -> bool {
        match self.refresh.as_deref() {
            None => false,
            Some(v) => matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"),
        }
    }
}

/// Lightweight, UNAUTHENTICATED health endpoint for deployment probes
/// (deploy.sh) and external monitors. Deliberately exposes ONLY status + the
/// running version — never DB state, secrets, user info, or internal addresses.
///
/// This exists because `/system/version` requires admin auth, so deploy scripts
/// and uptime checkers had no real endpoint to hit — they fell back to the SPA
/// fallback (which returns index.html for any unknown path), making "200 OK"
/// meaningless. `/api/v1/health` returns a small, stable JSON instead.
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": app_version(),
    }))
}

pub async fn get_version(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Query(q): Query<VersionQuery>,
) -> Json<VersionInfo> {
    let current_ver_str = app_version();
    let current = parse_version(current_ver_str);

    // Try cache first, unless `?refresh=true` (manual "check update" button).
    let want_refresh = q.want_refresh();
    let cached = if want_refresh {
        // Invalidate the cache so the next get_version populates it fresh.
        // (We could also just skip cache below; invalidating prevents
        // concurrent requests from also serving stale data.)
        state.release_cache.invalidate().await;
        None
    } else {
        state.release_cache.get().await
    };

    // v1.2: a single fetch returns BOTH tracks (panel + node). A network/HTTP
    // failure is shared (one HTTP call), so it sets BOTH check_failed flags;
    // an empty track (e.g. no node release yet) sets only its own flag false
    // with an empty version string (NOT a failure — the check succeeded, there
    // just was nothing to find).
    let (releases, check_failed, error_message): (CachedReleases, bool, String) =
        if let Some(r) = cached {
            // Cached data — assume the cached fetch succeeded.
            (r, false, String::new())
        } else {
            match fetch_github_releases().await {
                Ok(got) => {
                    // Cache the successful result (even if a track is None — that
                    // means "succeeded but no eligible release on that track").
                    // Only Err (network failure) is NOT cached, so the next
                    // request retries.
                    state.release_cache.set(got.clone()).await;
                    (got, false, String::new())
                }
                Err(msg) => {
                    tracing::warn!("version-check: surfacing failure to client: {}", msg);
                    (
                        CachedReleases {
                            panel: None,
                            node: None,
                        },
                        true,
                        msg,
                    )
                }
            }
        };

    // ── Panel track ──
    let panel_release = releases.panel;
    // v1.2: the node check shares the same fetch, so a network failure marks
    // BOTH tracks failed. A successful fetch with no node release is NOT a
    // failure (node_version_check_failed stays false, latest_node_version is
    // just empty).
    let node_version_check_failed = check_failed;

    // The bare node version (e.g. "1.1.0") the frontend compares node_version
    // against. Empty when there's no node release or the fetch failed.
    let latest_node_version = releases
        .node
        .as_ref()
        .and_then(|r| r.tag_name.strip_prefix('v'))
        .map(|s| s.to_string())
        .unwrap_or_default();

    match panel_release {
        Some(release) => {
            let latest_ver = parse_version(&release.tag_name);

            let (has_update, is_outdated) = match (&current, &latest_ver) {
                (Some(c), Some(l)) => {
                    let update = l > c;
                    // "Outdated" = behind by 2+ minor versions, or any major gap.
                    let outdated = l.major > c.major || l.minor.saturating_sub(c.minor) >= 2;
                    (update, outdated)
                }
                _ => (false, false),
            };

            // Truncate release notes to first 10 lines for the API response.
            // body is Option<String> (GitHub may return null); treat None as
            // empty notes.
            let body = release.body.clone().unwrap_or_default();
            let notes = body.lines().take(10).collect::<Vec<_>>().join("\n");

            Json(VersionInfo {
                current_version: current_ver_str.to_string(),
                latest_version: release.tag_name.clone(),
                has_update,
                is_outdated,
                release_url: release.html_url.clone().unwrap_or_default(),
                release_notes: notes,
                published_at: release.published_at.clone().unwrap_or_default(),
                public_panel_url: state.config.public_panel_url.clone(),
                check_failed,
                error_message,
                config_protocol_version: relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
                latest_node_version,
                node_version_check_failed,
            })
        }
        // No eligible PANEL release (either fetch succeeded and found nothing,
        // or fetch failed and we synthesized empty tracks). check_failed /
        // error_message are set above and surfaced here.
        None => Json(VersionInfo {
            current_version: current_ver_str.to_string(),
            latest_version: current_ver_str.to_string(),
            has_update: false,
            is_outdated: false,
            release_url: String::new(),
            release_notes: String::new(),
            published_at: String::new(),
            public_panel_url: state.config.public_panel_url.clone(),
            check_failed,
            error_message,
            config_protocol_version: relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
            latest_node_version,
            node_version_check_failed,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_accepts_v_prefix_and_bare() {
        assert!(parse_version("0.2.1").is_some());
        assert!(parse_version("v0.2.1").is_some());
        assert!(parse_version("1.0.0").is_some());
        assert!(parse_version("not-a-version").is_none());
    }

    /// The public health endpoint must return status:"ok" + a non-empty version,
    /// and NOTHING else (no DB state, secrets, user info). This is the contract
    /// deploy.sh's strict check depends on (200 + json + status:ok + version).
    #[tokio::test]
    async fn health_returns_ok_and_version_only() {
        let Json(v) = health().await;
        let obj = v.as_object().expect("health returns a JSON object");
        assert_eq!(obj.get("status").and_then(|s| s.as_str()), Some("ok"));
        let ver = obj.get("version").and_then(|s| s.as_str());
        assert!(
            ver.is_some_and(|s| !s.is_empty()),
            "version must be non-empty"
        );
        // Must NOT leak anything beyond status + version.
        assert_eq!(
            obj.len(),
            2,
            "health must expose only status + version, got keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    /// Mimics the "has_update" comparison done inside get_version. This is
    /// the core user-visible logic; the surrounding HTTP plumbing is
    /// exercised by the e2e test.
    #[test]
    fn has_update_logic_from_release_payload() {
        let current = parse_version("0.2.1");
        let latest_v0_2_2 = parse_version("0.2.2");
        let latest_v0_2_1 = parse_version("0.2.1");
        let latest_v0_1_9 = parse_version("0.1.9");
        let latest_invalid = parse_version("not-a-version");

        // A strictly newer GitHub tag must be reported as has_update=true.
        assert!(latest_v0_2_2.unwrap() > current.clone().unwrap());
        // Same version: no update.
        assert_eq!(latest_v0_2_1.unwrap(), current.clone().unwrap());
        // Older tag: no update.
        assert!(latest_v0_1_9.unwrap() < current.clone().unwrap());
        // Unparseable tag: must not panic; treat as "unknown" -> no update.
        assert!(latest_invalid.is_none());
    }

    // ---- GitHubRelease null-field tolerance ----
    //
    // GitHub sometimes returns null for body/html_url/published_at on old
    // releases (e.g. v0.2.0, v0.1.9). The struct MUST accept these without
    // failing the entire releases list — otherwise no update is ever detected.

    #[test]
    fn github_release_parses_with_null_body() {
        // Real-world v0.2.0 shape: body is null
        let json = r#"{
            "tag_name": "v0.2.0",
            "html_url": "https://github.com/pixingzoudaiyuexing/reality-panel/releases/tag/v0.2.0",
            "body": null,
            "published_at": "2026-05-01T00:00:00Z",
            "draft": false,
            "prerelease": false
        }"#;
        let r: GitHubRelease = serde_json::from_str(json).expect("must parse null body");
        assert_eq!(r.tag_name, "v0.2.0");
        assert_eq!(r.body, None);
        assert_eq!(r.body.unwrap_or_default(), "");
    }

    #[test]
    fn github_release_parses_with_null_html_url() {
        let json = r#"{
            "tag_name": "v0.1.9",
            "html_url": null,
            "body": "notes",
            "published_at": "2026-04-01T00:00:00Z"
        }"#;
        let r: GitHubRelease = serde_json::from_str(json).expect("must parse null html_url");
        assert_eq!(r.tag_name, "v0.1.9");
        assert_eq!(r.html_url, None);
        assert_eq!(r.html_url.unwrap_or_default(), "");
    }

    #[test]
    fn github_release_parses_with_null_published_at() {
        let json = r#"{
            "tag_name": "v0.1.8",
            "html_url": "https://example.com",
            "body": null,
            "published_at": null
        }"#;
        let r: GitHubRelease = serde_json::from_str(json).expect("must parse null published_at");
        assert_eq!(r.tag_name, "v0.1.8");
        assert_eq!(r.published_at, None);
    }

    #[test]
    fn github_release_parses_with_all_optional_fields_absent() {
        // A minimal release object missing every optional field entirely
        // (the serde(default) annotations handle this).
        let json = r#"{ "tag_name": "v0.1.0" }"#;
        let r: GitHubRelease = serde_json::from_str(json).expect("must parse minimal");
        assert_eq!(r.tag_name, "v0.1.0");
        assert_eq!(r.html_url, None);
        assert_eq!(r.body, None);
        assert_eq!(r.published_at, None);
        assert!(!r.draft);
        assert!(!r.prerelease);
    }

    /// The bug that prompted v0.2.4: a releases list where one entry has
    /// body:null must NOT poison the whole Vec deserialization.
    #[test]
    fn releases_list_with_mixed_null_fields_parses() {
        let json = r#"[
            { "tag_name": "v0.2.3", "body": "real notes", "html_url": "https://a", "published_at": "2026-06-17T00:00:00Z" },
            { "tag_name": "v0.2.0", "body": null, "html_url": null, "published_at": null },
            { "tag_name": "v0.1.9", "body": null, "html_url": "https://b", "published_at": "2026-04-01T00:00:00Z" }
        ]"#;
        let list: Vec<GitHubRelease> =
            serde_json::from_str(json).expect("mixed null list must parse");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].body.as_deref(), Some("real notes"));
        assert_eq!(list[1].body, None);
        assert_eq!(list[1].html_url, None);
    }

    /// Semver selection must pick the highest tag even when some entries
    /// carry null fields. Mirrors the filter/max in fetch_github_release.
    #[test]
    fn picks_highest_semver_among_null_field_releases() {
        let json = r#"[
            { "tag_name": "v0.1.9", "body": null, "draft": false },
            { "tag_name": "v0.2.0", "body": null, "draft": false },
            { "tag_name": "v0.2.3", "body": "latest", "draft": false }
        ]"#;
        let releases: Vec<GitHubRelease> = serde_json::from_str(json).unwrap();
        let picked = releases
            .into_iter()
            .filter(|r| !r.draft)
            .filter_map(|r| parse_version(&r.tag_name).map(|v| (v, r)))
            .max_by(|(va, _), (vb, _)| va.cmp(vb))
            .map(|(_, r)| r);
        assert_eq!(picked.unwrap().tag_name, "v0.2.3");
    }

    // ---- VersionQuery refresh flag tolerance ----

    #[test]
    fn version_query_refresh_accepts_true() {
        let q: VersionQuery = serde_json::from_str(r#"{ "refresh": "true" }"#).unwrap();
        assert!(q.want_refresh());
    }

    #[test]
    fn version_query_refresh_accepts_one() {
        let q: VersionQuery = serde_json::from_str(r#"{ "refresh": "1" }"#).unwrap();
        assert!(q.want_refresh());
    }

    #[test]
    fn version_query_refresh_accepts_false() {
        let q: VersionQuery = serde_json::from_str(r#"{ "refresh": "false" }"#).unwrap();
        assert!(!q.want_refresh());
    }

    #[test]
    fn version_query_refresh_accepts_zero() {
        let q: VersionQuery = serde_json::from_str(r#"{ "refresh": "0" }"#).unwrap();
        assert!(!q.want_refresh());
    }

    #[test]
    fn version_query_refresh_defaults_to_false_when_absent() {
        let q: VersionQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(!q.want_refresh());
    }

    #[test]
    fn version_query_refresh_case_insensitive() {
        let q: VersionQuery = serde_json::from_str(r#"{ "refresh": "TRUE" }"#).unwrap();
        assert!(q.want_refresh());
    }

    // ---- Release cache behaviour (updated for v1.2 panel/node split) ----

    #[tokio::test]
    async fn release_cache_round_trip_and_invalidate() {
        let cache = ReleaseCache::new();
        // Empty -> get() returns None.
        assert!(cache.get().await.is_none());

        // After set(), get() returns Some and a second get() still returns Some
        // (within CACHE_TTL). Both projections point at one release.
        let release = GitHubRelease {
            tag_name: "v1.1.0".to_string(),
            html_url: Some("https://example.com/release".to_string()),
            body: Some("release notes".to_string()),
            published_at: Some("2026-07-02T00:00:00Z".to_string()),
            draft: false,
            prerelease: false,
        };
        cache
            .set(CachedReleases {
                panel: Some(release.clone()),
                node: Some(release),
            })
            .await;
        let got = cache.get().await;
        assert!(got.is_some(), "cache hit within TTL");
        let cached = got.unwrap();
        assert_eq!(cached.panel.as_ref().unwrap().tag_name, "v1.1.0");
        assert_eq!(cached.node.as_ref().unwrap().tag_name, "v1.1.0");

        // `?refresh=true` semantics: invalidate() empties the cache, the next
        // get() returns None (forcing a fresh GitHub fetch).
        cache.invalidate().await;
        assert!(cache.get().await.is_none());
    }

    /// A cached "successful fetch but no eligible release on a track" result
    /// is NOT a network failure. get() still returns the CachedReleases (so
    /// the caller serves the empty track with check_failed=false), distinct
    /// from a cache miss (None).
    #[tokio::test]
    async fn empty_cache_is_not_treated_as_failure() {
        let cache = ReleaseCache::new();
        // Both tracks empty (e.g. all drafts) — still a successful fetch.
        cache
            .set(CachedReleases {
                panel: None,
                node: None,
            })
            .await;
        // get() returns Some (cache populated), even though both tracks are
        // None. The caller maps this to check_failed=false with empty versions.
        let got = cache.get().await;
        assert!(got.is_some(), "empty-tracks cache is still a cache hit");
        let cached = got.unwrap();
        assert!(cached.panel.is_none());
        assert!(cached.node.is_none());
    }

    // ---- unified Reality Panel v* release classification ----

    #[test]
    fn release_version_accepts_stable_and_prerelease_v_tags() {
        let v = release_version("v1.1.0").expect("v* is a release tag");
        assert_eq!(v, semver::Version::new(1, 1, 0));
        assert_eq!(
            release_version("v1.0.0-rc.1").unwrap(),
            semver::Version::parse("1.0.0-rc.1").unwrap()
        );
    }

    #[test]
    fn release_version_ignores_other_namespaces() {
        assert!(release_version("main").is_none());
        assert!(release_version("sdk-v1.0.0").is_none());
        assert!(release_version("node-v1.1.0").is_none());
        assert!(release_version("not-a-version").is_none());
    }

    #[test]
    fn stable_selection_excludes_prerelease_and_other_tag_namespaces() {
        let json = r#"[
            { "tag_name": "v1.1.0", "draft": false },
            { "tag_name": "v1.0.9", "draft": false },
            { "tag_name": "v1.2.0-rc.1", "draft": false, "prerelease": true },
            { "tag_name": "node-v9.0.0", "draft": false }
        ]"#;
        let releases: Vec<GitHubRelease> = serde_json::from_str(json).unwrap();
        let picked = releases
            .into_iter()
            .filter(|release| !release.draft && !release.prerelease)
            .filter_map(|release| {
                release_version(&release.tag_name).map(|version| (version, release))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right));
        assert_eq!(picked.unwrap().1.tag_name, "v1.1.0");
    }
}
