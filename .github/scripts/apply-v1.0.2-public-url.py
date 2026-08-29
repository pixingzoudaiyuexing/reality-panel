from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


def regex_once(path: str, pattern: str, repl: str) -> None:
    p = Path(path)
    text = p.read_text()
    new, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: expected one regex match, found {count}: {pattern[:120]!r}")
    p.write_text(new)


# 1) site:config 增加管理员可配置的面板公网地址；旧 JSON 因 serde(default) 自动兼容。
replace_once(
    "crates/panel/src/service/site.rs",
    "pub const MAX_CONTACT: usize = 256;\n",
    "pub const MAX_CONTACT: usize = 256;\npub const MAX_PUBLIC_PANEL_URL: usize = 2048;\n",
)
replace_once(
    "crates/panel/src/service/site.rs",
    "    /// How users reach the operator (Telegram handle, email, whatever).\n    pub contact: String,\n",
    "    /// How users reach the operator (Telegram handle, email, whatever).\n    pub contact: String,\n    /// 管理员配置的面板公网根地址。仅供 Panel 内部生成 Bootstrap / Enrollment 地址，\n    /// 不通过公开站点信息接口暴露。留空时继续使用部署环境的 PUBLIC_PANEL_URL。\n    pub public_panel_url: String,\n",
)
replace_once(
    "crates/panel/src/service/site.rs",
    "            contact: clamp(&self.contact, MAX_CONTACT),\n",
    "            contact: clamp(&self.contact, MAX_CONTACT),\n            public_panel_url: clamp(&self.public_panel_url, MAX_PUBLIC_PANEL_URL),\n",
)
regex_once(
    "crates/panel/src/service/site.rs",
    r'''    fn from_json_keeps_a_configured_name\(\) \{.*?    \}\n\n''',
    '''    fn from_json_keeps_a_configured_name() {
        let cfg = SiteConfig::from_json(Some(
            r#"{"site_name":"我的中转","contact":"tg","public_panel_url":"https://panel.example.com"}"#,
        ));
        assert_eq!(cfg.site_name, "我的中转");
        assert_eq!(cfg.contact, "tg");
        assert_eq!(cfg.public_panel_url, "https://panel.example.com");
    }

''',
)
replace_once(
    "crates/panel/src/service/site.rs",
    "    /// Truncation counts characters, not bytes. A byte slice at MAX_NAME would\n",
    '''    #[test]
    fn old_site_json_without_public_panel_url_remains_compatible() {
        let cfg = SiteConfig::from_json(Some(r#"{"site_name":"旧站点"}"#));
        assert_eq!(cfg.site_name, "旧站点");
        assert!(cfg.public_panel_url.is_empty());
    }

    /// Truncation counts characters, not bytes. A byte slice at MAX_NAME would
''',
)

# 2) 站点设置 API 保存时做严格 origin 校验并规范化末尾斜杠。
replace_once(
    "crates/panel/src/api/site.rs",
    "use crate::service::site::{SiteConfig, SITE_CONFIG_KEY};\n",
    "use crate::service::site::{SiteConfig, MAX_PUBLIC_PANEL_URL, SITE_CONFIG_KEY};\nuse super::provisioning::valid_public_panel_url;\n",
)
replace_once(
    "crates/panel/src/api/site.rs",
    "    #[serde(default)]\n    pub contact: String,\n",
    "    #[serde(default)]\n    pub contact: String,\n    #[serde(default)]\n    pub public_panel_url: String,\n",
)
replace_once(
    "crates/panel/src/api/site.rs",
    "    // Trim + clamp before storing, so every reader (including the public\n    // endpoint hit on every login page load) gets a bounded value.\n    let cfg = SiteConfig {\n",
    "    // 公网地址是连接配置，不能像普通展示文案一样静默截断；写入前必须完整校验。\n    let public_panel_url = req.public_panel_url.trim();\n    if public_panel_url.chars().count() > MAX_PUBLIC_PANEL_URL\n        || (!public_panel_url.is_empty() && !valid_public_panel_url(public_panel_url))\n    {\n        return Json(ApiResponse {\n            code: 400,\n            message: \"面板公网地址必须是有效的 http:// 或 https:// 根地址，且不能包含路径、查询参数或账号密码\".into(),\n            data: None,\n        });\n    }\n    let public_panel_url = public_panel_url.trim_end_matches('/').to_string();\n\n    // Trim + clamp before storing, so every reader (including the public\n    // endpoint hit on every login page load) gets a bounded value.\n    let cfg = SiteConfig {\n",
)
replace_once(
    "crates/panel/src/api/site.rs",
    "        contact: req.contact,\n",
    "        contact: req.contact,\n        public_panel_url,\n",
)
replace_once(
    "crates/panel/src/api/site.rs",
    "            \"站点名称 {} / 公告 {} / 客服 {}\",\n",
    "            \"站点名称 {} / 公告 {} / 客服 {} / 公网地址 {}\",\n",
)
replace_once(
    "crates/panel/src/api/site.rs",
    "            if cfg.contact.is_empty() {\n                \"已清空\"\n            } else {\n                \"已设置\"\n            },\n",
    "            if cfg.contact.is_empty() {\n                \"已清空\"\n            } else {\n                \"已设置\"\n            },\n            if cfg.public_panel_url.is_empty() {\n                \"已清空\"\n            } else {\n                \"已设置\"\n            },\n",
)

# 3) 所有节点部署入口统一解析“站点设置 > 环境变量”的有效公网地址。
replace_once(
    "crates/panel/src/api/provisioning.rs",
    "use relay_shared::protocol::ProvisioningCapabilities;\n",
    "use relay_shared::protocol::ProvisioningCapabilities;\nuse super::AppState;\nuse crate::service::site::{SiteConfig, SITE_CONFIG_KEY};\n",
)
replace_once(
    "crates/panel/src/api/provisioning.rs",
    "pub(crate) fn valid_public_panel_url(url: &str) -> bool {\n    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {\n        return false;\n    };\n    matches!(parsed.scheme(), \"http\" | \"https\")\n        && parsed.host_str().is_some()\n        && parsed.username().is_empty()\n        && parsed.password().is_none()\n        && parsed.query().is_none()\n        && parsed.fragment().is_none()\n        && (parsed.path().is_empty() || parsed.path() == \"/\")\n}\n",
    "pub(crate) fn valid_public_panel_url(url: &str) -> bool {\n    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {\n        return false;\n    };\n    matches!(parsed.scheme(), \"http\" | \"https\")\n        && parsed.host_str().is_some()\n        && parsed.username().is_empty()\n        && parsed.password().is_none()\n        && parsed.query().is_none()\n        && parsed.fragment().is_none()\n        && (parsed.path().is_empty() || parsed.path() == \"/\")\n}\n\nfn normalize_public_panel_url(url: &str) -> Option<String> {\n    let url = url.trim();\n    valid_public_panel_url(url).then(|| url.trim_end_matches('/').to_string())\n}\n\n/// 运行时公网地址优先使用管理员在站点设置中保存的值；留空或损坏时才回退\n/// 到部署环境的 PUBLIC_PANEL_URL。这样反代域名上线后无需重写容器环境变量。\npub(crate) fn select_public_panel_url(site_url: &str, env_url: &str) -> Option<String> {\n    normalize_public_panel_url(site_url).or_else(|| normalize_public_panel_url(env_url))\n}\n\npub(crate) async fn effective_public_panel_url(state: &AppState) -> Option<String> {\n    let raw = state.db.get(SITE_CONFIG_KEY).await.ok().flatten();\n    let site = SiteConfig::from_json(raw.as_deref());\n    select_public_panel_url(&site.public_panel_url, &state.config.public_panel_url)\n}\n",
)
replace_once(
    "crates/panel/src/api/provisioning.rs",
    "    #[test]\n    fn capability_helpers_require_all_five_typed_capabilities() {\n",
    "    #[test]\n    fn public_panel_url_prefers_site_setting_and_falls_back_to_environment() {\n        assert_eq!(\n            select_public_panel_url(\n                \" https://panel.example.com/ \",\n                \"http://203.0.113.10:18888\",\n            )\n            .as_deref(),\n            Some(\"https://panel.example.com\")\n        );\n        assert_eq!(\n            select_public_panel_url(\"\", \"http://203.0.113.10:18888/\").as_deref(),\n            Some(\"http://203.0.113.10:18888\")\n        );\n        assert_eq!(\n            select_public_panel_url(\"https://panel.example.com/path\", \"https://fallback.example.com\")\n                .as_deref(),\n            Some(\"https://fallback.example.com\")\n        );\n        assert!(select_public_panel_url(\"not-a-url\", \"\").is_none());\n    }\n\n    #[test]\n    fn capability_helpers_require_all_five_typed_capabilities() {\n",
)

# 4) SSH 一键部署使用运行时有效地址。
replace_once(
    "crates/panel/src/api/node_deploy.rs",
    "    capabilities_satisfy, load_artifact, normalize_architecture, reported_capabilities,\n    valid_public_panel_url, ProvisioningArtifact, ProvisioningBundle, ProvisioningProfile,\n",
    "    capabilities_satisfy, effective_public_panel_url, load_artifact, normalize_architecture,\n    reported_capabilities, ProvisioningArtifact, ProvisioningBundle, ProvisioningProfile,\n",
)
regex_once(
    "crates/panel/src/api/node_deploy.rs",
    r"    let panel_url = state\.config\.public_panel_url\.trim\(\)\.to_string\(\);\n    if !valid_public_panel_url\(&panel_url\) \{\n        return error\(\n            409,\n            \"PUBLIC_PANEL_URL must be a valid public http:// or https:// origin before node bootstrap\",\n        \);\n    \}\n",
    "    let Some(panel_url) = effective_public_panel_url(&state).await else {\n        return error(\n            409,\n            \"请先在站点设置中配置有效的面板公网地址，或设置 PUBLIC_PANEL_URL\",\n        );\n    };\n",
)

# 5) Manual Bootstrap / Enrollment 使用同一地址来源。
replace_once(
    "crates/panel/src/api/node_enrollment.rs",
    "    bootstrap_session_lifetime_secs, capabilities_satisfy, load_artifact, normalize_architecture,\n    valid_public_panel_url, ProvisioningBundle, ProvisioningProfile, ENROLLMENT_CLAIM_WINDOW_SECS,\n",
    "    bootstrap_session_lifetime_secs, capabilities_satisfy, effective_public_panel_url,\n    load_artifact, normalize_architecture, ProvisioningBundle, ProvisioningProfile,\n    ENROLLMENT_CLAIM_WINDOW_SECS,\n",
)
replace_once(
    "crates/panel/src/api/node_enrollment.rs",
    "    if !valid_public_panel_url(&state.config.public_panel_url) {\n        return api_error(\n            409,\n            \"PUBLIC_PANEL_URL must be a valid public http:// or https:// origin\",\n        );\n    }\n",
    "    let Some(panel_url) = effective_public_panel_url(&state).await else {\n        return api_error(\n            409,\n            \"请先在站点设置中配置有效的面板公网地址，或设置 PUBLIC_PANEL_URL\",\n        );\n    };\n",
)
replace_once(
    "crates/panel/src/api/node_enrollment.rs",
    "        launcher_command: launcher_command(&state.config.public_panel_url, &id),\n",
    "        launcher_command: launcher_command(&panel_url, &id),\n",
)
replace_once(
    "crates/panel/src/api/node_enrollment.rs",
    "    let bundle = ProvisioningBundle::new(&state.config.public_panel_url, &group.token, artifact);\n",
    "    let Some(panel_url) = effective_public_panel_url(&state).await else {\n        return bundle_error(\n            409,\n            \"请先在站点设置中配置有效的面板公网地址，或设置 PUBLIC_PANEL_URL\",\n        );\n    };\n    let bundle = ProvisioningBundle::new(&panel_url, &group.token, artifact);\n",
)

# 6) 前端类型、表单与双语文案。
replace_once(
    "frontend/src/api/types.ts",
    "export interface SiteConfig extends PublicSite, SiteNotice {}\n",
    "export interface SiteConfig extends PublicSite, SiteNotice {\n  /** 管理员配置的节点 Bootstrap / Enrollment 公网根地址。 */\n  public_panel_url: string;\n}\n",
)
replace_once(
    "frontend/src/pages/SiteSettings.tsx",
    "const MAX_CONTACT = 256;\n",
    "const MAX_CONTACT = 256;\nconst MAX_PUBLIC_PANEL_URL = 2048;\n",
)
site_name_block = '''        <Form.Item
          name="site_name"
          label={t('siteName')}
          extra={t('siteNameHint')}
          rules={[{ max: MAX_NAME, message: t('siteFieldTooLong') }]}
        >
          <Input placeholder="RealityPanel" showCount maxLength={MAX_NAME} />
        </Form.Item>
'''
public_url_block = site_name_block + '''        <Form.Item
          name="public_panel_url"
          label={t('panelPublicUrl')}
          extra={t('panelPublicUrlHint')}
          rules={[
            { max: MAX_PUBLIC_PANEL_URL, message: t('siteFieldTooLong') },
            {
              // 与后端 valid_public_panel_url 保持同样的“仅根 origin”语义。
              validator: async (_rule, value: string | undefined) => {
                const raw = (value ?? '').trim();
                if (!raw) return;
                try {
                  const parsed = new URL(raw);
                  const valid = (parsed.protocol === 'http:' || parsed.protocol === 'https:')
                    && !parsed.username
                    && !parsed.password
                    && !parsed.search
                    && !parsed.hash
                    && parsed.pathname === '/';
                  if (!valid) throw new Error('invalid');
                } catch {
                  throw new Error(t('panelPublicUrlInvalid'));
                }
              },
            },
          ]}
        >
          <Input placeholder="https://panel.example.com" showCount maxLength={MAX_PUBLIC_PANEL_URL} />
        </Form.Item>
'''
replace_once("frontend/src/pages/SiteSettings.tsx", site_name_block, public_url_block)
replace_once(
    "frontend/src/i18n/zh-CN.ts",
    "  siteNameHint: '显示在登录页、左侧边栏和浏览器标签标题。留空则使用 RealityPanel。',\n",
    "  siteNameHint: '显示在登录页、左侧边栏和浏览器标签标题。留空则使用 RealityPanel。',\n  panelPublicUrl: '面板公网地址',\n  panelPublicUrlHint: '用于节点 Bootstrap、Enrollment 及面板生成的对外访问链接。例如：https://panel.example.com。留空时继续使用部署环境中的 PUBLIC_PANEL_URL。',\n  panelPublicUrlInvalid: '请输入有效的 http:// 或 https:// 根地址，不能包含路径、查询参数或账号密码。',\n",
)
replace_once(
    "frontend/src/i18n/en-US.ts",
    "  siteNameHint: 'Shown on the login page, in the sidebar, and as the browser tab title. Empty falls back to RealityPanel.',\n",
    "  siteNameHint: 'Shown on the login page, in the sidebar, and as the browser tab title. Empty falls back to RealityPanel.',\n  panelPublicUrl: 'Panel public URL',\n  panelPublicUrlHint: 'Used for Node Bootstrap, Enrollment, and generated public links. Example: https://panel.example.com. Leave empty to keep using PUBLIC_PANEL_URL from the deployment environment.',\n  panelPublicUrlInvalid: 'Enter a valid http:// or https:// root URL without a path, query, credentials, or fragment.',\n",
)

print("v1.0.2 public URL patch applied")
