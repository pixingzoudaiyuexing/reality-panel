use crate::config::NodeConfig;
use crate::forwarder::camouflage_site::{install_panel_certificates_shared, CamouflageSiteManager};
use relay_shared::protocol::NodeCertificatesResponse;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const MAX_CERTIFICATE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct PanelCertificateSync {
    client: reqwest::Client,
    etag: Option<String>,
}

impl PanelCertificateSync {
    pub(crate) fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { client, etag: None })
    }

    pub(crate) async fn sync(
        &mut self,
        config: &NodeConfig,
        node_id: &str,
        camouflage: &Arc<Mutex<CamouflageSiteManager>>,
    ) -> Result<(), String> {
        let endpoint = format!(
            "{}/api/v1/node/certificates",
            config.panel_url.trim_end_matches('/')
        );
        let mut request = self
            .client
            .get(endpoint)
            .bearer_auth(&config.token)
            .header("X-Node-ID", node_id);
        let sources_complete =
            crate::forwarder::camouflage_site::panel_sources_complete_shared(camouflage).await;
        if sources_complete {
            if let Some(etag) = self.etag.as_deref() {
                request = request.header(reqwest::header::IF_NONE_MATCH, etag);
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "Panel certificate request failed")?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(());
        }
        if !response.status().is_success() {
            return Err(format!(
                "Panel certificate request returned HTTP {}",
                response.status().as_u16()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CERTIFICATE_RESPONSE_BYTES as u64)
        {
            return Err("Panel certificate response is too large".into());
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or("Panel certificate response has no ETag")?;
        if response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            != Some("no-store")
        {
            return Err("Panel certificate response is cacheable".into());
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Panel certificate response was interrupted")?
        {
            if body.len().saturating_add(chunk.len()) > MAX_CERTIFICATE_RESPONSE_BYTES {
                return Err("Panel certificate response is too large".into());
            }
            body.extend_from_slice(&chunk);
        }
        let response: NodeCertificatesResponse =
            serde_json::from_slice(&body).map_err(|_| "Panel certificate response is invalid")?;
        install_panel_certificates_shared(
            camouflage,
            response.certificates,
            response.missing_domains,
        )
        .await?;
        self.etag = Some(etag);
        Ok(())
    }
}
