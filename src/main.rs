use std::sync::Arc;

use anti_proxy::modules;
use anti_proxy::proxy;

#[tokio::main]
async fn main() -> Result<(), String> {
    modules::logger::init_logger();

    let mut proxy_config = match modules::config::load_web_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::warn!("failed to load web config: {}. using defaults", err);
            let cfg = proxy::ProxyConfig::default();
            let _ = modules::config::save_web_config(&cfg);
            cfg
        }
    };

    if let Ok(value) = std::env::var("ANTI_PROXY_ALLOW_LAN") {
        let enabled = matches!(value.as_str(), "1" | "true" | "yes" | "on");
        if enabled {
            proxy_config.allow_lan_access = true;
        }
    }

    if let Ok(value) = std::env::var("ANTI_PROXY_ENABLED") {
        let enabled = matches!(value.as_str(), "1" | "true" | "yes" | "on");
        if enabled {
            proxy_config.enabled = true;
        }
    }

    let bind_address = if let Ok(addr) = std::env::var("ANTI_PROXY_BIND") {
        if addr != "127.0.0.1" && addr != "localhost" {
            proxy_config.allow_lan_access = true;
        }
        addr
    } else {
        proxy_config.get_bind_address().to_string()
    };

    let data_dir = modules::account::get_data_dir()?;
    let _ = modules::account::get_accounts_dir()?;

    let token_manager = Arc::new(proxy::TokenManager::new(data_dir));
    token_manager
        .update_sticky_config(proxy_config.scheduling.clone())
        .await;

    let active_accounts = token_manager
        .load_accounts()
        .await
        .map_err(|e| format!("failed to load accounts: {}", e))?;

    if active_accounts == 0 {
        tracing::warn!("no active accounts found; open the web console to add accounts");
    }

    let monitor = Arc::new(proxy::monitor::ProxyMonitor::new(1000));
    monitor.set_enabled(proxy_config.enable_logging);

    let (server, handle) = proxy::AxumServer::start(
        bind_address.clone(),
        proxy_config.port,
        token_manager,
        proxy_config.anthropic_mapping.clone(),
        proxy_config.openai_mapping.clone(),
        proxy_config.custom_mapping.clone(),
        proxy_config.request_timeout,
        proxy_config.upstream_proxy.clone(),
        proxy::ProxySecurityConfig::from_proxy_config(&proxy_config),
        monitor,
    )
    .await
    .map_err(|e| format!("failed to start proxy server: {}", e))?;

    tracing::info!(
        "anti-proxy listening on http://{}:{}",
        bind_address,
        proxy_config.port
    );

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("failed to listen for shutdown signal: {}", e))?;

    tracing::info!("shutdown requested, stopping server...");
    server.stop();
    let _ = handle.await;

    Ok(())
}
