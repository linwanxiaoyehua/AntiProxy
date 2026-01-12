// Upstream client implementation
// High-performance HTTP client wrapper

use reqwest::{header, Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

// Cloud Code v1internal endpoints
// [FIX] daily endpoint preferred - sandbox endpoint returning 404 has been removed
const V1_INTERNAL_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const V1_INTERNAL_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";

pub struct UpstreamClient {
    http_client: Client,
    user_agent: String,
    // Dynamic endpoint priority list - successful fallback gets promoted
    endpoints: Arc<RwLock<Vec<String>>>,
}

impl UpstreamClient {
    pub fn new(proxy_config: Option<crate::proxy::config::UpstreamProxyConfig>) -> Self {
        let user_agent = proxy_config
            .as_ref()
            .map(|c| c.user_agent.clone())
            .filter(|ua| !ua.is_empty())
            .unwrap_or_else(|| "antigravity/1.13.3 darwin/arm64".to_string());

        let mut builder = Client::builder()
            // Connection settings (optimize connection reuse, reduce overhead)
            .connect_timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(16)                  // Max 16 idle connections per host
            .pool_idle_timeout(Duration::from_secs(90))  // Keep idle connections for 90s
            .tcp_keepalive(Duration::from_secs(60))      // TCP keepalive probe at 60s
            .timeout(Duration::from_secs(600))
            .user_agent(&user_agent);

        if let Some(config) = proxy_config {
            if config.enabled && !config.url.is_empty() {
                if let Ok(proxy) = reqwest::Proxy::all(&config.url) {
                    builder = builder.proxy(proxy);
                    tracing::info!("UpstreamClient enabled proxy: {}", config.url);
                }
            } else {
                builder = builder.no_proxy();
            }
        } else {
            builder = builder.no_proxy();
        }

        let http_client = builder.build().expect("Failed to create HTTP client");

        // Initialize with default endpoint priority
        // [FIX] daily endpoint preferred to avoid 429 rate limiting
        let endpoints = Arc::new(RwLock::new(vec![
            V1_INTERNAL_BASE_URL_DAILY.to_string(),
            V1_INTERNAL_BASE_URL_PROD.to_string(),
        ]));

        Self { http_client, user_agent, endpoints }
    }

    /// Promote a successful fallback endpoint to primary position
    async fn promote_endpoint(&self, successful_idx: usize) {
        if successful_idx == 0 {
            return; // Already primary
        }

        let mut endpoints = self.endpoints.write().await;
        if successful_idx < endpoints.len() {
            let endpoint = endpoints.remove(successful_idx);
            endpoints.insert(0, endpoint.clone());
            tracing::info!(
                "⚡ Endpoint promoted to primary: {} (was fallback #{})",
                endpoint,
                successful_idx
            );
        }
    }

    /// Build v1internal URL
    ///
    /// Build API request URL
    fn build_url(base_url: &str, method: &str, query_string: Option<&str>) -> String {
        if let Some(qs) = query_string {
            format!("{}:{}?{}", base_url, method, qs)
        } else {
            format!("{}:{}", base_url, method)
        }
    }

    /// Determine whether to try the next endpoint
    ///
    /// When encountering the following errors, try switching to a fallback endpoint:
    /// - 429 Too Many Requests (rate limiting)
    /// - 408 Request Timeout (timeout)
    /// - 404 Not Found (endpoint does not exist)
    /// - 5xx Server Error (server error)
    fn should_try_next_endpoint(status: StatusCode) -> bool {
        status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::NOT_FOUND
            || status.is_server_error()
    }

    /// Call v1internal API (base method)
    ///
    /// Make basic network request with multi-endpoint automatic fallback
    /// When a fallback endpoint succeeds, it will be automatically promoted to primary
    pub async fn call_v1_internal(
        &self,
        method: &str,
        access_token: &str,
        body: Value,
        query_string: Option<&str>,
    ) -> Result<Response, String> {
        // Build Headers (reused across all endpoints)
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| e.to_string())?,
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.user_agent)
                .unwrap_or_else(|_| header::HeaderValue::from_static("antigravity/1.11.9 windows/amd64")),
        );

        let mut last_err: Option<String> = None;

        // Read current endpoint priority (dynamic, may have been promoted)
        let endpoints = self.endpoints.read().await.clone();
        let endpoint_count = endpoints.len();

        // Iterate through all endpoints, automatically switch on failure
        for (idx, base_url) in endpoints.iter().enumerate() {
            let url = Self::build_url(base_url, method, query_string);
            let has_next = idx + 1 < endpoint_count;

            let response = self
                .http_client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "✓ Upstream fallback succeeded | Endpoint: {} | Status: {} | Attempt: {}/{}",
                                base_url,
                                status,
                                idx + 1,
                                endpoint_count
                            );
                            // Promote successful fallback to primary position
                            self.promote_endpoint(idx).await;
                        } else {
                            tracing::debug!("✓ Upstream request succeeded | Endpoint: {} | Status: {}", base_url, status);
                        }
                        return Ok(resp);
                    }

                    // If there is a next endpoint and current error is retryable, switch
                    if has_next && Self::should_try_next_endpoint(status) {
                        tracing::warn!(
                            "Upstream endpoint returned {} at {} (method={}), trying next endpoint",
                            status,
                            base_url,
                            method
                        );
                        last_err = Some(format!("Upstream {} returned {}", base_url, status));
                        continue;
                    }

                    // Non-retryable error or already the last endpoint, return directly
                    return Ok(resp);
                }
                Err(e) => {
                    let msg = format!("HTTP request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    last_err = Some(msg);

                    // If this is the last endpoint, exit the loop
                    if !has_next {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }

    /// Call v1internal API (with 429 retry, supports closures)
    ///
    /// Core request logic with fault tolerance and retry
    ///
    /// # Arguments
    /// * `method` - API method (e.g., "generateContent")
    /// * `query_string` - Optional query string (e.g., "?alt=sse")
    /// * `get_credentials` - Closure to get credentials (supports account rotation)
    /// * `build_body` - Closure that takes project_id to build request body
    /// * `max_attempts` - Maximum retry attempts
    ///
    /// # Returns
    /// HTTP Response
    // Deprecated retry method has been removed (call_v1_internal_with_retry)

    // Deprecated helper method has been removed (parse_retry_delay)

    // Deprecated helper method has been removed (parse_duration_ms)

    /// Get available models list
    ///
    /// Fetch remote model list with multi-endpoint automatic fallback
    /// When a fallback endpoint succeeds, it will be automatically promoted to primary
    pub async fn fetch_available_models(&self, access_token: &str) -> Result<Value, String> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", access_token))
                .map_err(|e| e.to_string())?,
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&self.user_agent)
                .unwrap_or_else(|_| header::HeaderValue::from_static("antigravity/1.11.9 windows/amd64")),
        );

        let mut last_err: Option<String> = None;

        // Read current endpoint priority (dynamic, may have been promoted)
        let endpoints = self.endpoints.read().await.clone();
        let endpoint_count = endpoints.len();

        // Iterate through all endpoints, automatically switch on failure
        for (idx, base_url) in endpoints.iter().enumerate() {
            let url = Self::build_url(base_url, "fetchAvailableModels", None);

            let response = self
                .http_client
                .post(&url)
                .headers(headers.clone())
                .json(&serde_json::json!({}))
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        if idx > 0 {
                            tracing::info!(
                                "✓ Upstream fallback succeeded for fetchAvailableModels | Endpoint: {} | Status: {}",
                                base_url,
                                status
                            );
                            // Promote successful fallback to primary position
                            self.promote_endpoint(idx).await;
                        } else {
                            tracing::debug!("✓ fetchAvailableModels succeeded | Endpoint: {}", base_url);
                        }
                        let json: Value = resp
                            .json()
                            .await
                            .map_err(|e| format!("Parse json failed: {}", e))?;
                        return Ok(json);
                    }

                    // If there is a next endpoint and current error is retryable, switch
                    let has_next = idx + 1 < endpoint_count;
                    if has_next && Self::should_try_next_endpoint(status) {
                        tracing::warn!(
                            "fetchAvailableModels returned {} at {}, trying next endpoint",
                            status,
                            base_url
                        );
                        last_err = Some(format!("Upstream error: {}", status));
                        continue;
                    }

                    // Non-retryable error or already the last endpoint
                    return Err(format!("Upstream error: {}", status));
                }
                Err(e) => {
                    let msg = format!("Request failed at {}: {}", base_url, e);
                    tracing::debug!("{}", msg);
                    last_err = Some(msg);

                    // If this is the last endpoint, exit the loop
                    if idx + 1 >= endpoint_count {
                        break;
                    }
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "All endpoints failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let base_url = "https://cloudcode-pa.googleapis.com/v1internal";
        
        let url1 = UpstreamClient::build_url(base_url, "generateContent", None);
        assert_eq!(
            url1,
            "https://cloudcode-pa.googleapis.com/v1internal:generateContent"
        );

        let url2 = UpstreamClient::build_url(base_url, "streamGenerateContent", Some("alt=sse"));
        assert_eq!(
            url2,
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
        );
    }

}
