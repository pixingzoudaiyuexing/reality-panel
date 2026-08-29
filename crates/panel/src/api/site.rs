//! v1.2.4: site identity endpoints.
//!
//! Split across THREE auth levels on purpose:
//!
//!   * `GET /site` is public, because the login page renders the brand before
//!     anyone has a token.
//!   * `GET /user/site-notice` requires auth, because the announcement and the
//!     support contact are for this operator's users — not for anyone who can
//!     reach the port. Not displaying them on the login page would be hollow if
//!     the API served them to the world anyway.
//!   * `PUT /admin/settings/site` is admin-only, like every other setting.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::middleware::{AdminOnly, AuthUser};
use super::provisioning::valid_public_panel_url;
use super::AppState;
use crate::service::site::{SiteConfig, MAX_PUBLIC_PANEL_URL, SITE_CONFIG_KEY};
use relay_shared::protocol::ApiResponse;

async fn load(state: &AppState) -> SiteConfig {
    let raw = state.db.get(SITE_CONFIG_KEY).await.ok().flatten();
    SiteConfig::from_json(raw.as_deref())
}

/// The public half: branding only. Deliberately does NOT carry `announcement`
/// or `contact` — see the module comment.
#[derive(Debug, Serialize)]
pub struct PublicSite {
    pub site_name: String,
    pub subtitle: String,
}

/// GET /api/v1/site — unauthenticated.
pub async fn get_public_site(State(state): State<AppState>) -> Json<ApiResponse<PublicSite>> {
    let cfg = load(&state).await;
    Json(ApiResponse::success(PublicSite {
        site_name: cfg.site_name,
        subtitle: cfg.subtitle,
    }))
}

/// The signed-in half.
///
/// v1.2.4: no longer carries the announcement. That moved to its own table
/// with history; the copy still sitting in site:config is frozen at whatever
/// Migration 44 carried over, and serving it would show stale text beside the
/// live banner.
#[derive(Debug, Serialize)]
pub struct SiteNotice {
    pub contact: String,
}

/// GET /api/v1/user/site-notice — any authenticated user.
pub async fn get_site_notice(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<ApiResponse<SiteNotice>> {
    let cfg = load(&state).await;
    Json(ApiResponse::success(SiteNotice {
        contact: cfg.contact,
    }))
}

/// GET /api/v1/admin/settings/site — the full row, for the edit form.
pub async fn get_site_settings(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<SiteConfig>> {
    Json(ApiResponse::success(load(&state).await))
}

#[derive(Debug, Deserialize)]
pub struct UpdateSiteRequest {
    #[serde(default)]
    pub site_name: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub announcement: String,
    #[serde(default)]
    pub announcement_type: String,
    #[serde(default)]
    pub contact: String,
    #[serde(default)]
    pub public_panel_url: String,
}

/// PUT /api/v1/admin/settings/site
pub async fn update_site_settings(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<UpdateSiteRequest>,
) -> Json<ApiResponse<SiteConfig>> {
    // 公网地址是连接配置，不能像普通展示文案一样静默截断；写入前必须完整校验。
    let public_panel_url = req.public_panel_url.trim();
    if public_panel_url.chars().count() > MAX_PUBLIC_PANEL_URL
        || (!public_panel_url.is_empty() && !valid_public_panel_url(public_panel_url))
    {
        return Json(ApiResponse {
            code: 400,
            message: "面板公网地址必须是有效的 http:// 或 https:// 根地址，且不能包含路径、查询参数或账号密码".into(),
            data: None,
        });
    }
    let public_panel_url = public_panel_url.trim_end_matches('/').to_string();

    // Trim + clamp before storing, so every reader (including the public
    // endpoint hit on every login page load) gets a bounded value.
    let cfg = SiteConfig {
        site_name: req.site_name,
        subtitle: req.subtitle,
        announcement: req.announcement,
        announcement_type: req.announcement_type,
        contact: req.contact,
        public_panel_url,
    }
    .sanitized();

    let json = match serde_json::to_string(&cfg) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("update_site_settings: serialize failed: {}", e);
            return Json(ApiResponse {
                code: 500,
                message: "配置序列化失败".into(),
                data: None,
            });
        }
    };
    if let Err(e) = state.db.set(SITE_CONFIG_KEY, &json).await {
        tracing::error!("update_site_settings: save failed: {}", e);
        return Json(ApiResponse {
            code: 500,
            message: "数据库错误".into(),
            data: None,
        });
    }

    tracing::info!(
        action = "update_site_settings",
        site_name = %cfg.site_name,
        "site settings updated"
    );
    // Records WHICH fields are now set, not their contents: the announcement can
    // be long, and the audit table is not the place to keep a copy of it.
    crate::service::audit::record(
        &state,
        Some(_admin.user_id),
        "update_site_settings",
        "settings",
        "site",
        &format!(
            "站点名称 {} / 公告 {} / 客服 {} / 公网地址 {}",
            cfg.site_name,
            if cfg.announcement.is_empty() {
                "已清空"
            } else {
                "已设置"
            },
            if cfg.contact.is_empty() {
                "已清空"
            } else {
                "已设置"
            },
            if cfg.public_panel_url.is_empty() {
                "已清空"
            } else {
                "已设置"
            },
        ),
    )
    .await;

    Json(ApiResponse::success(cfg))
}
