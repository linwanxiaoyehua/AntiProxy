//! Web UI 认证中间件
//!
//! 保护 Web UI 路由，需要 Passkey 认证才能访问

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use crate::proxy::server::AppState;

const SESSION_COOKIE_NAME: &str = "antiproxy_session";

/// 需要保护的路径前缀
fn is_protected_path(path: &str) -> bool {
    // 管理 API 需要认证
    if path.starts_with("/api/") {
        // 认证相关的 API 不需要保护
        if path.starts_with("/api/auth/") {
            return false;
        }
        // OAuth 回调不需要保护 (在设置 passkey 之前需要添加账号)
        if path.starts_with("/api/oauth/") {
            return false;
        }
        return true;
    }

    // 静态资源不需要保护
    if is_static_asset(path) {
        return false;
    }

    // 登录页面不需要保护
    if path == "/login.html" || path == "/login" {
        return false;
    }

    // OAuth 回调页面
    if path == "/oauth-callback" {
        return false;
    }

    // 健康检查
    if path == "/healthz" {
        return false;
    }

    // API 协议端点不需要 Web UI 认证 (它们有自己的 API Key 认证)
    if path.starts_with("/v1/") || path.starts_with("/v1beta/") {
        return false;
    }

    // 其他路径 (主页等) 需要认证
    true
}

/// 检查是否是静态资源
fn is_static_asset(path: &str) -> bool {
    // HTML 文件不是静态资源 - 它们需要认证保护
    if path.ends_with(".html") {
        return false;
    }

    if path == "/favicon.ico" {
        return true;
    }

    if path.starts_with("/assets/") {
        return true;
    }

    matches!(
        path.rsplit('.').next(),
        Some("css") | Some("js") | Some("png") | Some("svg") | Some("jpg") | Some("jpeg") | Some("webp") | Some("ico") | Some("woff") | Some("woff2") | Some("ttf")
    )
}

/// 从 Cookie 中提取 session token
fn extract_session_token(request: &Request) -> Option<String> {
    let cookie_header = request.headers().get(header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;

    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)) {
            return Some(value.to_string());
        }
    }

    None
}

/// Web UI 认证中间件
pub async fn web_auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    tracing::debug!("web_auth_middleware: checking path = {}", path);

    // 检查是否需要保护
    if !is_protected_path(&path) {
        tracing::debug!("web_auth_middleware: path {} is not protected, allowing", path);
        return next.run(request).await;
    }

    tracing::debug!("web_auth_middleware: path {} is protected, checking session", path);

    let session_manager = &state.session_manager;

    // 检查 session
    if let Some(token) = extract_session_token(&request) {
        if session_manager.validate_session(&token).await {
            // Session 有效，刷新并继续
            session_manager.refresh_session(&token).await;
            tracing::debug!("web_auth_middleware: valid session for {}", path);
            return next.run(request).await;
        }
        tracing::debug!("web_auth_middleware: invalid session token for {}", path);
    } else {
        tracing::debug!("web_auth_middleware: no session cookie for {}", path);
    }

    // 未认证 - 需要登录或设置 Passkey
    tracing::info!("web_auth_middleware: unauthenticated access to {}, redirecting to login", path);
    // API 请求返回 401
    if path.starts_with("/api/") {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "application/json")],
            r#"{"error": "Authentication required"}"#,
        )
            .into_response();
    }

    // Web 页面重定向到登录页
    Redirect::to("/login.html").into_response()
}
