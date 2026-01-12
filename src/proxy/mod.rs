// proxy module - API reverse proxy service

// Existing modules (retained)
pub mod config;
pub mod token_manager;
pub mod project_resolver;
pub mod server;
pub mod security;

// New architecture modules
pub mod mappers;           // Protocol converters
pub mod handlers;          // API endpoint handlers
pub mod middleware;        // Axum middleware
pub mod upstream;          // Upstream client
pub mod common;            // Common utilities
pub mod monitor;           // Monitoring
pub mod rate_limit;        // Rate limit tracking
pub mod sticky_config;     // Sticky scheduling configuration
pub mod session_manager;   // Session fingerprint management


pub use config::ProxyConfig;
pub use config::ProxyAuthMode;
pub use token_manager::TokenManager;
pub use server::AxumServer;
pub use security::ProxySecurityConfig;
