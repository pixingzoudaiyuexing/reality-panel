from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


admin = Path("crates/panel/src/api/admin/mod.rs")
text = admin.read_text()
if "public_panel_url: String::new()," not in text:
    replace_once(
        str(admin),
        '                contact: "tg:@someone".into(),\n',
        '                contact: "tg:@someone".into(),\n                public_panel_url: String::new(),\n',
    )

types = Path("frontend/src/api/types.ts")
text = types.read_text()
if "public_panel_url: string;" not in text:
    replace_once(
        str(types),
        "export interface SiteConfig extends PublicSite, SiteNotice {}\n",
        "export interface SiteConfig extends PublicSite, SiteNotice {\n  /** 管理员配置的节点 Bootstrap / Enrollment 公网根地址。 */\n  public_panel_url: string;\n}\n",
    )

en = Path("frontend/src/i18n/en-US.ts")
text = en.read_text()
if "panelPublicUrl: 'Panel public URL'" not in text:
    replace_once(
        str(en),
        "  siteNameHint: 'Shown on the login page, in the sidebar, and as the browser tab title. Empty falls back to RealityPanel.',\n",
        "  siteNameHint: 'Shown on the login page, in the sidebar, and as the browser tab title. Empty falls back to RealityPanel.',\n  panelPublicUrl: 'Panel public URL',\n  panelPublicUrlHint: 'Used for Node Bootstrap, Enrollment, and generated public links. Example: https://panel.example.com. Leave empty to keep using PUBLIC_PANEL_URL from the deployment environment.',\n  panelPublicUrlInvalid: 'Enter a valid http:// or https:// root URL without a path, query, credentials, or fragment.',\n",
    )

zh = Path("frontend/src/i18n/zh-CN.ts")
text = zh.read_text()
if "panelPublicUrl: '面板公网地址'" not in text:
    replace_once(
        str(zh),
        "  siteNameHint: '显示在登录页、左侧边栏和浏览器标签标题。留空则使用 RealityPanel。',\n",
        "  siteNameHint: '显示在登录页、左侧边栏和浏览器标签标题。留空则使用 RealityPanel。',\n  panelPublicUrl: '面板公网地址',\n  panelPublicUrlHint: '用于节点 Bootstrap、Enrollment 及面板生成的对外访问链接。例如：https://panel.example.com。留空时继续使用部署环境中的 PUBLIC_PANEL_URL。',\n  panelPublicUrlInvalid: '请输入有效的 http:// 或 https:// 根地址，不能包含路径、查询参数或账号密码。',\n",
    )
