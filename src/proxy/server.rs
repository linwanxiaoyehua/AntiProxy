use crate::proxy::TokenManager;
use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tower_http::services::ServeDir;
use tracing::{debug, error};
use tokio::sync::RwLock;
use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct OAuthStatus {
    pub status: String,
    pub message: Option<String>,
    pub email: Option<String>,
    pub auth_url: Option<String>,
}

/// Axum application state
#[derive(Clone)]
pub struct AppState {
    pub token_manager: Arc<TokenManager>,
    pub anthropic_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    pub openai_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    pub custom_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    #[allow(dead_code)]
    pub request_timeout: u64, // API request timeout (seconds)
    pub bind_port: u16,
    pub oauth_state: Arc<tokio::sync::Mutex<OAuthStatus>>,
    #[allow(dead_code)]
    pub thought_signature_map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>, // Chain-of-thought signature mapping (ID -> Signature)
    #[allow(dead_code)]
    pub upstream_proxy: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    pub upstream: Arc<crate::proxy::upstream::client::UpstreamClient>,
    pub monitor: Arc<crate::proxy::monitor::ProxyMonitor>,
    /// WebAuthn (Passkey) manager
    pub webauthn_manager: Arc<crate::modules::webauthn::WebAuthnManager>,
    /// Session manager
    pub session_manager: Arc<crate::modules::webauthn::SessionManager>,
}

/// Axum server instance
pub struct AxumServer {
    shutdown_tx: Option<oneshot::Sender<()>>,
    anthropic_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    openai_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    custom_mapping: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
    proxy_state: Arc<tokio::sync::RwLock<crate::proxy::config::UpstreamProxyConfig>>,
    security_state: Arc<RwLock<crate::proxy::ProxySecurityConfig>>,
}

impl AxumServer {
    pub async fn update_mapping(&self, config: &crate::proxy::config::ProxyConfig) {
        {
            let mut m = self.anthropic_mapping.write().await;
            *m = config.anthropic_mapping.clone();
        }
        {
            let mut m = self.openai_mapping.write().await;
            *m = config.openai_mapping.clone();
        }
        {
            let mut m = self.custom_mapping.write().await;
            *m = config.custom_mapping.clone();
        }
        tracing::debug!("Model mappings (Anthropic/OpenAI/Custom) fully hot-reloaded");
    }

    /// Update proxy configuration
    pub async fn update_proxy(&self, new_config: crate::proxy::config::UpstreamProxyConfig) {
        let mut proxy = self.proxy_state.write().await;
        *proxy = new_config;
        tracing::info!("Upstream proxy configuration hot-reloaded");
    }

    pub async fn update_security(&self, config: &crate::proxy::config::ProxyConfig) {
        let mut sec = self.security_state.write().await;
        *sec = crate::proxy::ProxySecurityConfig::from_proxy_config(config);
        tracing::info!("Reverse proxy security configuration hot-reloaded");
    }

    /// Start Axum server
    pub async fn start(
        host: String,
        port: u16,
        token_manager: Arc<TokenManager>,
        anthropic_mapping: std::collections::HashMap<String, String>,
        openai_mapping: std::collections::HashMap<String, String>,
        custom_mapping: std::collections::HashMap<String, String>,
        _request_timeout: u64,
        upstream_proxy: crate::proxy::config::UpstreamProxyConfig,
        security_config: crate::proxy::ProxySecurityConfig,
        monitor: Arc<crate::proxy::monitor::ProxyMonitor>,

    ) -> Result<(Self, tokio::task::JoinHandle<()>), String> {
        let mapping_state = Arc::new(tokio::sync::RwLock::new(anthropic_mapping));
        let openai_mapping_state = Arc::new(tokio::sync::RwLock::new(openai_mapping));
        let custom_mapping_state = Arc::new(tokio::sync::RwLock::new(custom_mapping));
        let proxy_state = Arc::new(tokio::sync::RwLock::new(upstream_proxy.clone()));
        let security_state = Arc::new(RwLock::new(security_config));
        let oauth_state = Arc::new(tokio::sync::Mutex::new(OAuthStatus {
            status: "idle".to_string(),
            message: None,
            email: None,
            auth_url: None,
        }));

        // Initialize WebAuthn manager
        let data_dir = crate::modules::account::get_data_dir()
            .map_err(|e| format!("Failed to get data dir: {}", e))?;
        let webauthn_manager = Arc::new(crate::modules::webauthn::WebAuthnManager::new(data_dir));
        webauthn_manager.load_credentials().await
            .map_err(|e| format!("Failed to load passkeys: {}", e))?;
        webauthn_manager.load_auth_config().await
            .map_err(|e| format!("Failed to load auth config: {}", e))?;

        // Initialize Session manager (7-day validity)
        let session_manager = Arc::new(crate::modules::webauthn::SessionManager::new(24 * 7));

        let state = AppState {
            token_manager: token_manager.clone(),
            anthropic_mapping: mapping_state.clone(),
            openai_mapping: openai_mapping_state.clone(),
            custom_mapping: custom_mapping_state.clone(),
            request_timeout: 300, // 5-minute timeout
            bind_port: port,
            oauth_state: oauth_state.clone(),
            thought_signature_map: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            upstream_proxy: proxy_state.clone(),
            upstream: Arc::new(crate::proxy::upstream::client::UpstreamClient::new(Some(
                upstream_proxy.clone(),
            ))),
            monitor: monitor.clone(),
            webauthn_manager,
            session_manager,
        };


        // Build routes - using new architecture handlers!
        use crate::proxy::handlers;
        // Build routes
        let static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("web");

        let app = Router::new()
            // WebAuthn (Passkey) Authentication APIs
            .route("/api/auth/status", get(handlers::webauthn::get_auth_status))
            .route("/api/auth/register/start", post(handlers::webauthn::start_registration))
            .route("/api/auth/register/finish", post(handlers::webauthn::finish_registration))
            .route("/api/auth/login/start", post(handlers::webauthn::start_authentication))
            .route("/api/auth/login/finish", post(handlers::webauthn::finish_authentication))
            .route("/api/auth/logout", post(handlers::webauthn::logout))
            .route("/api/auth/credentials", get(handlers::webauthn::list_credentials))
            .route("/api/auth/credentials/delete", post(handlers::webauthn::delete_credential))
            // Password Authentication APIs
            .route("/api/auth/password/setup", post(handlers::webauthn::setup_password))
            .route("/api/auth/password/login", post(handlers::webauthn::password_login))
            .route("/api/auth/password/change", post(handlers::webauthn::change_password))
            .route("/api/auth/reset", post(handlers::webauthn::reset_auth))
            // API Keys Management
            .route("/api/keys", get(handlers::api_keys::list_api_keys).post(handlers::api_keys::create_api_key))
            .route("/api/keys/usage", get(handlers::api_keys::get_total_usage))
            .route(
                "/api/keys/:id",
                get(handlers::api_keys::get_api_key)
                    .put(handlers::api_keys::update_api_key)
                    .delete(handlers::api_keys::delete_api_key),
            )
            .route("/api/keys/:id/regenerate", post(handlers::api_keys::regenerate_api_key))
            .route("/api/keys/:id/reset_usage", post(handlers::api_keys::reset_api_key_usage))
            // Management APIs
            .route("/api/accounts", get(handlers::manage::list_accounts).post(handlers::manage::create_account))
            .route(
                "/api/accounts/current",
                get(handlers::manage::get_current_account).put(handlers::manage::set_current_account),
            )
            .route(
                "/api/accounts/refresh_quotas",
                post(handlers::manage::refresh_all_quotas),
            )
            .route(
                "/api/accounts/:id",
                get(handlers::manage::get_account).delete(handlers::manage::delete_account),
            )
            .route(
                "/api/accounts/:id/refresh_quota",
                post(handlers::manage::refresh_account_quota),
            )
            .route("/api/oauth/prepare", get(handlers::manage::prepare_oauth))
            .route("/api/oauth/status", get(handlers::manage::oauth_status))
            .route("/api/oauth/cancel", post(handlers::manage::cancel_oauth))
            .route("/api/oauth/callback", post(handlers::manage::submit_oauth_callback))
            .route("/oauth-callback", get(handlers::manage::oauth_callback))
            .route(
                "/api/proxy/mappings",
                get(handlers::manage::get_mappings).put(handlers::manage::update_mappings),
            )
            // OpenAI Protocol
            .route("/v1/models", get(handlers::openai::handle_list_models))
            .route(
                "/v1/chat/completions",
                post(handlers::openai::handle_chat_completions),
            )
            .route(
                "/v1/completions",
                post(handlers::openai::handle_completions),
            )
            .route("/v1/responses", post(handlers::openai::handle_completions)) // Compatible with Codex CLI
            .route(
                "/v1/images/generations",
                post(handlers::openai::handle_images_generations),
            ) // Image generation API
            .route(
                "/v1/images/edits",
                post(handlers::openai::handle_images_edits),
            ) // Image editing API
            // Claude Protocol
            .route("/v1/messages", post(handlers::claude::handle_messages))
            .route(
                "/v1/messages/count_tokens",
                post(handlers::claude::handle_count_tokens),
            )
            .route(
                "/v1/models/claude",
                get(handlers::claude::handle_list_models),
            )
	            // Gemini Protocol (Native)
	            .route("/v1beta/models", get(handlers::gemini::handle_list_models))
            // Handle both GET (get info) and POST (generateContent with colon) at the same route
            .route(
                "/v1beta/models/:model",
                get(handlers::gemini::handle_get_model).post(handlers::gemini::handle_generate),
            )
            .route(
                "/v1beta/models/:model/countTokens",
                post(handlers::gemini::handle_count_tokens),
            ) // Specific route priority
            .route("/v1/models/detect", post(handlers::common::handle_detect_model))
            .route("/v1/api/event_logging/batch", post(silent_ok_handler))
            .route("/v1/api/event_logging", post(silent_ok_handler))
            .route("/healthz", get(health_check_handler))
            .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
            .layer(axum::middleware::from_fn_with_state(state.clone(), crate::proxy::middleware::web_auth_middleware))
            .layer(crate::proxy::middleware::cors_layer())
            // monitor_middleware must execute after auth_middleware (i.e., placed above it in the layer stack)
            // so that AuthenticatedKey can be accessed in monitor_middleware
            .layer(axum::middleware::from_fn_with_state(state.clone(), crate::proxy::middleware::monitor::monitor_middleware))
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn_with_state(
                security_state.clone(),
                crate::proxy::middleware::auth_middleware,
            ))
            .with_state(state)
            .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true));

        // Bind address
        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("Failed to bind address {}: {}", addr, e))?;

        tracing::info!("Reverse proxy server started at http://{}", addr);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let server_instance = Self {
            shutdown_tx: Some(shutdown_tx),
            anthropic_mapping: mapping_state.clone(),
            openai_mapping: openai_mapping_state.clone(),
            custom_mapping: custom_mapping_state.clone(),
            proxy_state,
            security_state,
        };

        // Start server in a new task
        let handle = tokio::spawn(async move {
            use hyper::server::conn::http1;
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;

            loop {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, _)) => {
                                let io = TokioIo::new(stream);
                                let service = TowerToHyperService::new(app.clone());

                                tokio::task::spawn(async move {
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .with_upgrades() // Support WebSocket (if needed in the future)
                                        .await
                                    {
                                        debug!("Connection handling ended or error: {:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {:?}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!("Reverse proxy server stopped listening");
                        break;
                    }
                }
            }
        });

        Ok((server_instance, handle))
    }

    /// Stop the server
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ===== API handlers (legacy code removed, now handled by src/proxy/handlers/*) =====

/// Health check handler
async fn health_check_handler() -> Response {
    Json(serde_json::json!({
        "status": "ok"
    }))
    .into_response()
}

/// Silent success handler (used for intercepting telemetry logs, etc.)
async fn silent_ok_handler() -> Response {
    StatusCode::OK.into_response()
}
