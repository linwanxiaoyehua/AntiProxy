use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use url::{form_urlencoded, Url};

use crate::models::{Account, QuotaData, TokenData};
use crate::proxy::server::AppState;
use crate::proxy::server::OAuthStatus;
use crate::modules::config as config_store;

#[derive(Serialize)]
struct AccountsResponse {
    current_account_id: Option<String>,
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct SetCurrentAccountRequest {
    account_id: String,
}

#[derive(Serialize)]
struct RefreshQuotaResponse {
    account: Account,
    quota: QuotaData,
}

#[derive(Serialize)]
struct BatchRefreshResult {
    account_id: String,
    email: String,
    ok: bool,
    quota: Option<QuotaData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct MappingResponse {
    anthropic_mapping: HashMap<String, String>,
    openai_mapping: HashMap<String, String>,
    custom_mapping: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct MappingUpdateRequest {
    anthropic_mapping: Option<HashMap<String, String>>,
    openai_mapping: Option<HashMap<String, String>>,
    custom_mapping: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    code: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct OAuthCallbackPayload {
    callback_url: Option<String>,
    code: Option<String>,
}

#[derive(Serialize)]
struct OAuthStatusResponse {
    status: String,
    message: Option<String>,
    email: Option<String>,
    auth_url: Option<String>,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

pub async fn list_accounts(State(_state): State<AppState>) -> Response {
    let current_account_id = match crate::modules::account::get_current_account_id() {
        Ok(id) => id,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    match crate::modules::account::list_accounts() {
        Ok(accounts) => Json(AccountsResponse {
            current_account_id,
            accounts,
        })
        .into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn get_account(Path(account_id): Path<String>) -> Response {
    match crate::modules::account::load_account(&account_id) {
        Ok(account) => Json(account).into_response(),
        Err(e) => error_response(StatusCode::NOT_FOUND, e),
    }
}

pub async fn get_current_account() -> Response {
    match crate::modules::account::get_current_account() {
        Ok(account) => Json(account).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn set_current_account(
    State(_state): State<AppState>,
    Json(payload): Json<SetCurrentAccountRequest>,
) -> Response {
    if payload.account_id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "account_id is required");
    }

    match crate::modules::account::set_current_account_id(&payload.account_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<CreateAccountRequest>,
) -> Response {
    if payload.refresh_token.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "refresh_token is required");
    }

    let token_res = match crate::modules::oauth::refresh_access_token(&payload.refresh_token).await
    {
        Ok(token) => token,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };

    let user_info = match crate::modules::oauth::get_user_info(&token_res.access_token).await {
        Ok(info) => info,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };

    let token = TokenData::new(
        token_res.access_token,
        payload.refresh_token,
        token_res.expires_in,
        Some(user_info.email.clone()),
        None,
        None,
    );

    let account = match crate::modules::account::upsert_account(
        user_info.email.clone(),
        user_info.get_display_name(),
        token,
    ) {
        Ok(account) => account,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let _ = state.token_manager.load_accounts().await;

    Json(account).into_response()
}

pub async fn delete_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Response {
    match crate::modules::account::delete_account(&account_id) {
        Ok(()) => {
            let _ = state.token_manager.load_accounts().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn refresh_account_quota(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Response {
    let mut account = match crate::modules::account::load_account(&account_id) {
        Ok(account) => account,
        Err(e) => return error_response(StatusCode::NOT_FOUND, e),
    };

    let token = match crate::modules::oauth::ensure_fresh_token(&account.token).await {
        Ok(token) => token,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };

    if token.access_token != account.token.access_token {
        account.token = token.clone();
    }

    let (quota, project_id) =
        match crate::modules::quota::fetch_quota(&token.access_token, &account.email).await {
            Ok(data) => data,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, e.to_string()),
        };

    if let Some(pid) = project_id {
        if account.token.project_id.as_deref() != Some(pid.as_str()) {
            account.token.project_id = Some(pid);
        }
    }

    account.update_quota(quota.clone());

    if let Err(e) = crate::modules::account::save_account(&account) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }

    let _ = state.token_manager.load_accounts().await;

    Json(RefreshQuotaResponse { account, quota }).into_response()
}

pub async fn refresh_all_quotas(State(state): State<AppState>) -> Response {
    let accounts = match crate::modules::account::list_accounts() {
        Ok(accounts) => accounts,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    let mut results = Vec::new();

    for mut account in accounts {
        let result = match crate::modules::oauth::ensure_fresh_token(&account.token).await {
            Ok(token) => {
                if token.access_token != account.token.access_token {
                    account.token = token.clone();
                }
                match crate::modules::quota::fetch_quota(&token.access_token, &account.email).await {
                    Ok((quota, project_id)) => {
                        if let Some(pid) = project_id {
                            if account.token.project_id.as_deref() != Some(pid.as_str()) {
                                account.token.project_id = Some(pid);
                            }
                        }
                        account.update_quota(quota.clone());
                        if let Err(e) = crate::modules::account::save_account(&account) {
                            Err(e)
                        } else {
                            Ok(quota)
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(quota) => results.push(BatchRefreshResult {
                account_id: account.id.clone(),
                email: account.email.clone(),
                ok: true,
                quota: Some(quota),
                error: None,
            }),
            Err(err) => results.push(BatchRefreshResult {
                account_id: account.id.clone(),
                email: account.email.clone(),
                ok: false,
                quota: None,
                error: Some(err),
            }),
        }
    }

    let _ = state.token_manager.load_accounts().await;

    Json(results).into_response()
}

fn oauth_success_html() -> &'static str {
    "<html>\
    <body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
        <h1 style='color: green;'>✅ Authorization successful!</h1>\
        <p>Account added. You can close this window and return to the console.</p>\
        <script>setTimeout(function() { window.close(); }, 2000);</script>\
    </body>\
    </html>"
}

fn oauth_fail_html() -> &'static str {
    "<html>\
    <body style='font-family: sans-serif; text-align: center; padding: 50px;'>\
        <h1 style='color: red;'>❌ Authorization failed</h1>\
        <p>Authorization could not be completed. Please return to the console and try again.</p>\
    </body>\
    </html>"
}

fn oauth_missing_refresh_message() -> String {
    "Refresh token missing.\n\n\
     Possible reasons:\n\
     1. You previously authorized this app; Google will not return refresh_token again\n\n\
     How to fix:\n\
     1. Visit https://myaccount.google.com/permissions\n\
     2. Revoke access for 'Antigravity Tools'\n\
     3. Re-run OAuth authorization\n\n\
     Or use 'Refresh Token' to add the account manually"
        .to_string()
}

fn parse_oauth_query(query: &str) -> OAuthCallbackQuery {
    let mut code = None;
    let mut error = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    OAuthCallbackQuery { code, error }
}

fn parse_oauth_callback_input(raw: &str) -> Result<OAuthCallbackQuery, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Callback URL cannot be empty".to_string());
    }

    if trimmed.contains("://") {
        let url = Url::parse(trimmed).map_err(|_| "Invalid callback URL".to_string())?;
        return Ok(parse_oauth_query(url.query().unwrap_or("")));
    }

    if trimmed.contains('?') || trimmed.contains('/') {
        if let Ok(url) = Url::parse(&format!("http://{}", trimmed)) {
            return Ok(parse_oauth_query(url.query().unwrap_or("")));
        }
    }

    if trimmed.contains("code=") || trimmed.contains("error=") {
        let query = trimmed.splitn(2, '?').nth(1).unwrap_or(trimmed);
        return Ok(parse_oauth_query(query));
    }

    Ok(OAuthCallbackQuery {
        code: Some(trimmed.to_string()),
        error: None,
    })
}

async fn process_oauth_code(state: &AppState, code: &str) -> Result<String, String> {
    let redirect_uri = if let Ok(value) = std::env::var("ANTI_PROXY_PUBLIC_URL") {
        format!("{}/oauth-callback", value.trim_end_matches('/'))
    } else {
        format!("http://127.0.0.1:{}/oauth-callback", state.bind_port)
    };
    let token_res = crate::modules::oauth::exchange_code(code, &redirect_uri).await?;

    let refresh_token = token_res
        .refresh_token
        .ok_or_else(oauth_missing_refresh_message)?;

    let user_info = crate::modules::oauth::get_user_info(&token_res.access_token).await?;

    let project_id = crate::proxy::project_resolver::fetch_project_id(&token_res.access_token)
        .await
        .ok();

    let token_data = TokenData::new(
        token_res.access_token,
        refresh_token,
        token_res.expires_in,
        Some(user_info.email.clone()),
        project_id,
        None,
    );

    let account = crate::modules::account::upsert_account(
        user_info.email.clone(),
        user_info.get_display_name(),
        token_data,
    )?;

    let _ = state.token_manager.load_accounts().await;
    Ok(account.email)
}

async fn update_oauth_state(
    state: &AppState,
    status: &str,
    message: Option<String>,
    email: Option<String>,
    auth_url: Option<String>,
) {
    let mut lock = state.oauth_state.lock().await;
    *lock = OAuthStatus {
        status: status.to_string(),
        message,
        email,
        auth_url,
    };
}

pub async fn prepare_oauth(State(state): State<AppState>) -> Response {
    let redirect_uri = if let Ok(value) = std::env::var("ANTI_PROXY_PUBLIC_URL") {
        format!("{}/oauth-callback", value.trim_end_matches('/'))
    } else {
        format!("http://127.0.0.1:{}/oauth-callback", state.bind_port)
    };
    let auth_url = crate::modules::oauth::get_auth_url(&redirect_uri);
    update_oauth_state(
        &state,
        "waiting",
        Some("Waiting for authorization callback".to_string()),
        None,
        Some(auth_url.clone()),
    )
    .await;

    Json(json!({
        "auth_url": auth_url,
        "redirect_uri": redirect_uri
    }))
    .into_response()
}

pub async fn oauth_status(State(state): State<AppState>) -> Response {
    let lock = state.oauth_state.lock().await.clone();
    let status = if lock.status.is_empty() {
        "idle".to_string()
    } else {
        lock.status
    };
    Json(OAuthStatusResponse {
        status,
        message: lock.message,
        email: lock.email,
        auth_url: lock.auth_url,
    })
    .into_response()
}

pub async fn cancel_oauth(State(state): State<AppState>) -> Response {
    update_oauth_state(&state, "idle", None, None, None).await;
    StatusCode::NO_CONTENT.into_response()
}

pub async fn submit_oauth_callback(
    State(state): State<AppState>,
    Json(payload): Json<OAuthCallbackPayload>,
) -> Response {
    let query = if let Some(code) = payload.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        OAuthCallbackQuery {
            code: Some(code.to_string()),
            error: None,
        }
    } else {
        let input = payload.callback_url.as_deref().unwrap_or("");
        match parse_oauth_callback_input(input) {
            Ok(query) => query,
            Err(message) => {
                update_oauth_state(&state, "error", Some(message.clone()), None, None).await;
                return error_response(StatusCode::BAD_REQUEST, message);
            }
        }
    };

    if let Some(error) = query.error {
        let message = format!("Authorization failed: {}", error);
        update_oauth_state(&state, "error", Some(message.clone()), None, None).await;
        return error_response(StatusCode::BAD_REQUEST, message);
    }

    let code = match query.code {
        Some(code) => code,
        None => {
            let message = "Unable to parse authorization code from callback URL".to_string();
            update_oauth_state(&state, "error", Some(message.clone()), None, None).await;
            return error_response(StatusCode::BAD_REQUEST, message);
        }
    };

    match process_oauth_code(&state, &code).await {
        Ok(email) => {
            let message = "Account added".to_string();
            update_oauth_state(&state, "success", Some(message.clone()), Some(email.clone()), None)
                .await;
            Json(OAuthStatusResponse {
                status: "success".to_string(),
                message: Some(message),
                email: Some(email),
                auth_url: None,
            })
            .into_response()
        }
        Err(message) => {
            update_oauth_state(&state, "error", Some(message.clone()), None, None).await;
            error_response(StatusCode::BAD_REQUEST, message)
        }
    }
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Response {
    if let Some(error) = query.error {
        update_oauth_state(
            &state,
            "error",
            Some(format!("Authorization failed: {}", error)),
            None,
            None,
        )
        .await;
        return Html(oauth_fail_html().to_string()).into_response();
    }

    let code = match query.code {
        Some(code) => code,
        None => {
            update_oauth_state(
                &state,
                "error",
                Some("Authorization code missing in callback".to_string()),
                None,
                None,
            )
            .await;
            return Html(oauth_fail_html().to_string()).into_response();
        }
    };

    match process_oauth_code(&state, &code).await {
        Ok(email) => {
            update_oauth_state(
                &state,
                "success",
                Some("Account added".to_string()),
                Some(email),
                None,
            )
            .await;
            Html(oauth_success_html().to_string()).into_response()
        }
        Err(message) => {
            update_oauth_state(&state, "error", Some(message), None, None).await;
            Html(oauth_fail_html().to_string()).into_response()
        }
    }
}

pub async fn get_mappings() -> Response {
    match config_store::load_web_config() {
        Ok(config) => Json(MappingResponse {
            anthropic_mapping: config.anthropic_mapping,
            openai_mapping: config.openai_mapping,
            custom_mapping: config.custom_mapping,
        })
        .into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub async fn update_mappings(
    State(state): State<AppState>,
    Json(payload): Json<MappingUpdateRequest>,
) -> Response {
    let mut config = match config_store::load_web_config() {
        Ok(config) => config,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    if let Some(mapping) = payload.anthropic_mapping {
        config.anthropic_mapping = mapping;
    }
    if let Some(mapping) = payload.openai_mapping {
        config.openai_mapping = mapping;
    }
    if let Some(mapping) = payload.custom_mapping {
        config.custom_mapping = mapping;
    }

    if let Err(e) = config_store::save_web_config(&config) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e);
    }

    {
        let mut m = state.anthropic_mapping.write().await;
        *m = config.anthropic_mapping.clone();
    }
    {
        let mut m = state.openai_mapping.write().await;
        *m = config.openai_mapping.clone();
    }
    {
        let mut m = state.custom_mapping.write().await;
        *m = config.custom_mapping.clone();
    }

    Json(MappingResponse {
        anthropic_mapping: config.anthropic_mapping,
        openai_mapping: config.openai_mapping,
        custom_mapping: config.custom_mapping,
    })
    .into_response()
}
