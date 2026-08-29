from pathlib import Path

lifecycle = Path("crates/node/src/forwarder/certificate_lifecycle.rs")
text = lifecycle.read_text()
old = "fn certificate_name_matches_host(certificate_name: &str, host: &str) -> bool {"
new = "pub(crate) fn certificate_name_matches_host(certificate_name: &str, host: &str) -> bool {"
if old not in text:
    raise SystemExit("certificate matcher declaration not found")
lifecycle.write_text(text.replace(old, new, 1))

poller = Path("crates/node/src/poller.rs")
text = poller.read_text()
old = """            || site.tls_listener_port != 8443
            || site.certificate.domain != site.sni
            || site
"""
new = """            || site.tls_listener_port != 8443
            // wildcard 证书只要能覆盖当前 SNI 就是合法配置；这里必须和证书生命周期
            // 共用同一套匹配规则，避免“证书已签发但 desired 被拒绝”的分裂状态。
            || !crate::forwarder::certificate_lifecycle::certificate_name_matches_host(
                &site.certificate.domain,
                &site.sni,
            )
            || site
"""
if old not in text:
    raise SystemExit("old exact-domain validation not found")
text = text.replace(old, new, 1)

anchor = """    fn dependent_listener(
"""
tests = """    #[test]
    fn wildcard_certificate_domain_covering_sni_is_valid_config() {
        let mut site = camouflage_site("p1.13886.xyz");
        site.certificate.domain = "*.13886.xyz".into();
        let config = NodeConfigResponse {
            camouflage_sites: vec![site],
            listeners: vec![],
        };

        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn wildcard_certificate_domain_does_not_cover_nested_sni() {
        let mut site = camouflage_site("deep.p1.13886.xyz");
        site.certificate.domain = "*.13886.xyz".into();
        let config = NodeConfigResponse {
            camouflage_sites: vec![site],
            listeners: vec![],
        };

        assert_eq!(
            validate_config(&config).unwrap_err(),
            "invalid camouflage desired state"
        );
    }

"""
if anchor not in text:
    raise SystemExit("poller test anchor not found")
poller.write_text(text.replace(anchor, tests + anchor, 1))
