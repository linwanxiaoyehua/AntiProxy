//! API Keys management endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::modules::api_keys::{
    self, ApiKeyResponse, CreateApiKeyRequest,
};
use crate::proxy::server::AppState;

/// List all API Keys
pub async fn list_api_keys(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    match api_keys::list_api_keys() {
        Ok(keys) => {
            let responses: Vec<ApiKeyResponse> = keys.into_iter().map(|k| k.into()).collect();
            Ok(Json(responses))
        }
        Err(e) => {
            tracing::error!("Failed to list API keys: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create a new API Key
pub async fn create_api_key(
    State(_state): State<AppState>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if req.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match api_keys::create_api_key(&req.name) {
        Ok(key) => {
            // Return the full key on creation (this is the only chance to see the full key)
            Ok((StatusCode::CREATED, Json(CreatedApiKeyResponse {
                id: key.id,
                name: key.name,
                key: key.key, // Full key, only returned on creation
                created_at: key.created_at,
            })))
        }
        Err(e) => {
            tracing::error!("Failed to create API key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize)]
pub struct CreatedApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String,
    pub created_at: i64,
}

/// Get a single API Key
pub async fn get_api_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match api_keys::get_api_key(&id) {
        Ok(Some(key)) => Ok(Json(ApiKeyResponse::from(key))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get API key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Update API Key request
#[derive(Deserialize)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

/// Update API Key
pub async fn update_api_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateApiKeyRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if key exists
    match api_keys::get_api_key(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get API key: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // Update name
    if let Some(name) = req.name {
        if !name.trim().is_empty() {
            if let Err(e) = api_keys::update_api_key_name(&id, &name) {
                tracing::error!("Failed to update API key name: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    // Update enabled state
    if let Some(enabled) = req.enabled {
        if let Err(e) = api_keys::set_api_key_enabled(&id, enabled) {
            tracing::error!("Failed to update API key enabled state: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // Return the updated key
    match api_keys::get_api_key(&id) {
        Ok(Some(key)) => Ok(Json(ApiKeyResponse::from(key))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get updated API key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete API Key
pub async fn delete_api_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if key exists
    match api_keys::get_api_key(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get API key: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    match api_keys::delete_api_key(&id) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            tracing::error!("Failed to delete API key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Regenerate API Key
pub async fn regenerate_api_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if key exists
    match api_keys::get_api_key(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get API key: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    match api_keys::regenerate_api_key(&id) {
        Ok(new_key) => Ok(Json(RegeneratedKeyResponse { key: new_key })),
        Err(e) => {
            tracing::error!("Failed to regenerate API key: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize)]
pub struct RegeneratedKeyResponse {
    pub key: String,
}

/// Reset API Key usage statistics
pub async fn reset_api_key_usage(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check if key exists
    match api_keys::get_api_key(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get API key: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    match api_keys::reset_usage(&id) {
        Ok(()) => {
            // Return the updated key
            match api_keys::get_api_key(&id) {
                Ok(Some(key)) => Ok(Json(ApiKeyResponse::from(key))),
                Ok(None) => Err(StatusCode::NOT_FOUND),
                Err(e) => {
                    tracing::error!("Failed to get API key after reset: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to reset API key usage: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get total usage statistics
pub async fn get_total_usage(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    match api_keys::get_total_usage() {
        Ok(usage) => Ok(Json(usage)),
        Err(e) => {
            tracing::error!("Failed to get total usage: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
