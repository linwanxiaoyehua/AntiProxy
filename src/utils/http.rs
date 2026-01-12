use reqwest::{Client, Proxy};
use crate::modules::config::load_web_config;

/// Create a unified configured HTTP client
/// Automatically load global configuration and apply proxy
pub fn create_client(timeout_secs: u64) -> Client {
    if let Ok(config) = load_web_config() {
        create_client_with_proxy(timeout_secs, Some(config.upstream_proxy))
    } else {
        create_client_with_proxy(timeout_secs, None)
    }
}

/// Create an HTTP client with specified proxy configuration
pub fn create_client_with_proxy(
    timeout_secs: u64, 
    proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>
) -> Client {
    let mut builder = Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs));

    if let Some(config) = proxy_config {
        if config.enabled && !config.url.is_empty() {
            match Proxy::all(&config.url) {
                Ok(proxy) => {
                    builder = builder.proxy(proxy);
                    tracing::info!("HTTP client enabled upstream proxy: {}", config.url);
                }
                Err(e) => {
                    tracing::error!("Invalid proxy address: {}, error: {}", config.url, e);
                }
            }
        } else {
            builder = builder.no_proxy();
        }
    } else {
        builder = builder.no_proxy();
    }

    builder.build().unwrap_or_else(|_| Client::new())
}
