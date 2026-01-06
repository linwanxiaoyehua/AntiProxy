//! WebAuthn API 处理程序
//!
//! 提供 Passkey 和密码认证的 REST API

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::modules::webauthn::AuthMode;
use crate::proxy::server::AppState;

const SESSION_COOKIE_NAME: &str = "antiproxy_session";

fn resolve_webauthn_config(headers: &HeaderMap, state: &AppState) -> crate::modules::webauthn::WebAuthnConfig {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let port = if host.starts_with('[') {
        let end = host.find(']').unwrap_or(0);
        host.get(end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(state.bind_port)
    } else {
        host.rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(state.bind_port)
    };

    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let forwarded = headers
        .get("forwarded")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_https = proto.eq_ignore_ascii_case("https")
        || forwarded.to_ascii_lowercase().contains("proto=https");

    crate::modules::webauthn::WebAuthnConfig::from_host(host, port, is_https)
        .unwrap_or_else(|_| crate::modules::webauthn::WebAuthnConfig::localhost(state.bind_port))
}

/// 检查认证状态
#[derive(Serialize)]
pub struct AuthStatusResponse {
    /// 是否已认证
    pub authenticated: bool,
    /// 是否需要设置 (首次使用)
    pub needs_setup: bool,
    /// 认证模式: "none", "password", "passkey"
    pub auth_mode: String,
    /// 已注册的凭据数量 (仅 passkey 模式)
    pub credential_count: usize,
}

/// 获取认证状态
pub async fn get_auth_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    let webauthn = &state.webauthn_manager;
    let sessions = &state.session_manager;

    // 检查 session cookie
    let authenticated = if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        sessions.validate_session(cookie.value()).await
    } else {
        false
    };

    let auth_mode = webauthn.get_auth_mode().await;
    let credential_count = webauthn.credential_count().await;
    let needs_setup = auth_mode == AuthMode::None;

    let auth_mode_str = match auth_mode {
        AuthMode::None => "none",
        AuthMode::Password => "password",
        AuthMode::Passkey => "passkey",
    };

    Json(AuthStatusResponse {
        authenticated,
        needs_setup,
        auth_mode: auth_mode_str.to_string(),
        credential_count,
    })
}

// ===== Password Authentication =====

/// 设置密码请求
#[derive(Deserialize)]
pub struct SetupPasswordRequest {
    pub password: String,
}

/// 设置密码认证
pub async fn setup_password(
    State(state): State<AppState>,
    Json(req): Json<SetupPasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    match webauthn.setup_password(&req.password).await {
        Ok(()) => {
            tracing::info!("Password authentication configured");
            Ok(Json(json!({ "success": true })))
        }
        Err(e) => {
            tracing::error!("Failed to setup password: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 密码登录请求
#[derive(Deserialize)]
pub struct PasswordLoginRequest {
    pub password: String,
}

/// 密码登录
pub async fn password_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<PasswordLoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;
    let sessions = &state.session_manager;

    // 检查认证模式
    let auth_mode = webauthn.get_auth_mode().await;
    if auth_mode != AuthMode::Password {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Password authentication is not configured" })),
        ));
    }

    // 验证密码
    if !webauthn.verify_password(&req.password).await {
        tracing::warn!("Failed password login attempt");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid password" })),
        ));
    }

    // 创建 session
    let session_token = sessions.create_session().await;

    // 设置 cookie
    let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, session_token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build();

    let jar = jar.add(cookie);

    tracing::info!("Password authentication successful");
    Ok((jar, Json(json!({ "success": true }))))
}

/// 更改密码请求
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// 更改密码
pub async fn change_password(
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    match webauthn.change_password(&req.old_password, &req.new_password).await {
        Ok(()) => {
            tracing::info!("Password changed successfully");
            Ok(Json(json!({ "success": true })))
        }
        Err(e) => {
            tracing::error!("Failed to change password: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 重置认证 (需要当前已认证)
pub async fn reset_auth(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;
    let sessions = &state.session_manager;

    // 验证当前已认证
    let authenticated = if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        sessions.validate_session(cookie.value()).await
    } else {
        false
    };

    if !authenticated {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Must be authenticated to reset" })),
        ));
    }

    match webauthn.reset_auth().await {
        Ok(()) => {
            // 清除当前 session
            if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
                sessions.delete_session(cookie.value()).await;
            }

            let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, ""))
                .path("/")
                .max_age(time::Duration::ZERO)
                .build();

            let jar = jar.add(cookie);

            tracing::info!("Authentication reset");
            Ok((jar, Json(json!({ "success": true }))))
        }
        Err(e) => {
            tracing::error!("Failed to reset auth: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            ))
        }
    }
}

// ===== Passkey Authentication =====

/// 开始注册请求
#[derive(Deserialize)]
pub struct StartRegistrationRequest {
    /// 用户名/设备名称
    pub name: String,
}

/// 开始注册 - 返回 WebAuthn challenge
pub async fn start_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StartRegistrationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    let config = resolve_webauthn_config(&headers, &state);

    match webauthn.start_registration(&config, &req.name).await {
        Ok((ccr, challenge)) => {
            Ok(Json(json!({
                "challenge": challenge,
                "options": ccr
            })))
        }
        Err(e) => {
            tracing::error!("Failed to start registration: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 完成注册请求
#[derive(Deserialize)]
pub struct FinishRegistrationRequest {
    /// Challenge (from start_registration)
    pub challenge: String,
    /// 用户名
    pub name: String,
    /// WebAuthn 响应
    pub response: Value,
}

/// 完成注册
pub async fn finish_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    let config = resolve_webauthn_config(&headers, &state);

    // 解析 WebAuthn 响应
    let credential: webauthn_rs::prelude::RegisterPublicKeyCredential =
        serde_json::from_value(req.response).map_err(|e| {
            tracing::error!("Failed to parse registration response: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid response: {}", e) })),
            )
        })?;

    match webauthn
        .finish_registration(&config, &req.challenge, credential, &req.name)
        .await
    {
        Ok(()) => {
            tracing::info!("Passkey registered successfully: {}", req.name);
            Ok(Json(json!({ "success": true })))
        }
        Err(e) => {
            tracing::error!("Failed to finish registration: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 开始认证 - 返回 WebAuthn challenge
pub async fn start_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    let config = resolve_webauthn_config(&headers, &state);

    match webauthn.start_authentication(&config).await {
        Ok((rcr, challenge)) => {
            Ok(Json(json!({
                "challenge": challenge,
                "options": rcr
            })))
        }
        Err(e) => {
            tracing::error!("Failed to start authentication: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 完成认证请求
#[derive(Deserialize)]
pub struct FinishAuthenticationRequest {
    /// Challenge (from start_authentication)
    pub challenge: String,
    /// WebAuthn 响应
    pub response: Value,
}

/// 完成认证
pub async fn finish_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<FinishAuthenticationRequest>,
) -> Result<(CookieJar, impl IntoResponse), (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;
    let sessions = &state.session_manager;

    let config = resolve_webauthn_config(&headers, &state);

    // 解析 WebAuthn 响应
    let credential: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(req.response).map_err(|e| {
            tracing::error!("Failed to parse authentication response: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid response: {}", e) })),
            )
        })?;

    match webauthn
        .finish_authentication(&config, &req.challenge, credential)
        .await
    {
        Ok(_) => {
            // 创建 session
            let session_token = sessions.create_session().await;

            // 设置 cookie (HttpOnly, 7天有效)
            let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, session_token))
                .path("/")
                .http_only(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax)
                .max_age(time::Duration::days(7))
                .build();

            let jar = jar.add(cookie);

            tracing::info!("Passkey authentication successful");
            Ok((jar, Json(json!({ "success": true }))))
        }
        Err(e) => {
            tracing::error!("Failed to finish authentication: {}", e);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": e })),
            ))
        }
    }
}

/// 登出
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    let sessions = &state.session_manager;

    // 删除 session
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        sessions.delete_session(cookie.value()).await;
    }

    // 清除 cookie
    let cookie = axum_extra::extract::cookie::Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .max_age(time::Duration::ZERO)
        .build();

    let jar = jar.add(cookie);

    (jar, Json(json!({ "success": true })))
}

/// 列出已注册的凭据
pub async fn list_credentials(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let webauthn = &state.webauthn_manager;
    let credentials = webauthn.list_credentials().await;

    Json(json!({ "credentials": credentials }))
}

/// 删除凭据请求
#[derive(Deserialize)]
pub struct DeleteCredentialRequest {
    pub credential_id: String,
}

/// 删除凭据
pub async fn delete_credential(
    State(state): State<AppState>,
    Json(req): Json<DeleteCredentialRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let webauthn = &state.webauthn_manager;

    // 确保至少保留一个凭据
    if webauthn.credential_count().await <= 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Cannot delete the last credential" })),
        ));
    }

    match webauthn.delete_credential(&req.credential_id).await {
        Ok(()) => Ok(Json(json!({ "success": true }))),
        Err(e) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": e })),
        )),
    }
}
