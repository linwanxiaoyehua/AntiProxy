use serde::{Deserialize, Serialize};
// use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuthMode {
    Off,
    Strict,
    AllExceptHealth,
    Auto,
}

impl Default for ProxyAuthMode {
    fn default() -> Self {
        Self::Off
    }
}

/// Reverse proxy service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Whether to enable the reverse proxy service
    pub enabled: bool,

    /// Whether to allow LAN access
    /// - false: localhost only 127.0.0.1 (default, privacy-first)
    /// - true: allow LAN access 0.0.0.0
    #[serde(default)]
    pub allow_lan_access: bool,

    /// Authorization policy for the proxy.
    /// - off: no auth required
    /// - strict: auth required for all routes
    /// - all_except_health: auth required for all routes except `/healthz`
    /// - auto: recommended defaults (currently: allow_lan_access => all_except_health, else off)
    #[serde(default)]
    pub auth_mode: ProxyAuthMode,
    
    /// Listen port
    pub port: u16,
    
    /// API key
    pub api_key: String,
    

    /// Whether to auto-start
    pub auto_start: bool,

    /// Anthropic model mapping table (key: Claude model name, value: Gemini model name)
    #[serde(default)]
    pub anthropic_mapping: std::collections::HashMap<String, String>,

    /// OpenAI model mapping table (key: OpenAI model group, value: Gemini model name)
    #[serde(default)]
    pub openai_mapping: std::collections::HashMap<String, String>,

    /// Custom exact model mapping table (key: original model name, value: target model name)
    #[serde(default)]
    pub custom_mapping: std::collections::HashMap<String, String>,

    /// API request timeout (seconds)
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,

    /// Whether to enable request logging (monitoring)
    #[serde(default)]
    pub enable_logging: bool,

    /// Upstream proxy configuration
    #[serde(default)]
    pub upstream_proxy: UpstreamProxyConfig,

    /// Account scheduling configuration (sticky session/rate limit retry)
    #[serde(default)]
    pub scheduling: crate::proxy::sticky_config::StickySessionConfig,
}

/// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxyConfig {
    /// Whether enabled
    #[serde(default)]
    pub enabled: bool,
    /// Proxy URL (http://, https://, socks5://)
    #[serde(default)]
    pub url: String,
    /// Custom User-Agent string (for upstream requests)
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

fn default_user_agent() -> String {
    "antigravity/1.11.9 windows/amd64".to_string()
}

impl Default for UpstreamProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            user_agent: default_user_agent(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan_access: false, // Default localhost only, privacy-first
            auth_mode: ProxyAuthMode::default(),
            port: 8045,
            api_key: format!("sk-{}", uuid::Uuid::new_v4().simple()),
            auto_start: false,
            anthropic_mapping: std::collections::HashMap::new(),
            openai_mapping: std::collections::HashMap::new(),
            custom_mapping: std::collections::HashMap::new(),
            request_timeout: default_request_timeout(),
            enable_logging: false, // Default off, save performance
            upstream_proxy: UpstreamProxyConfig::default(),
            scheduling: crate::proxy::sticky_config::StickySessionConfig::default(),
        }
    }
}

fn default_request_timeout() -> u64 {
    120  // Default 120 seconds, original 60 seconds was too short
}

impl ProxyConfig {
    /// Get the actual bind address
    /// - allow_lan_access = false: returns "127.0.0.1" (default, privacy-first)
    /// - allow_lan_access = true: returns "0.0.0.0" (allow LAN access)
    pub fn get_bind_address(&self) -> &str {
        if self.allow_lan_access {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }
}
