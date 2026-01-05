// 错误处理
use thiserror::Error;
use axum::{http::StatusCode, Json, response::IntoResponse};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Upstream API error: {0}")]
    UpstreamError(String),

    #[error("Transform error: {0}")]
    TransformError(String),

    #[error("Account error: {0}")]
    AccountError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            ProxyError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            ProxyError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ProxyError::AccountError(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::json!({
            "error": {
                "message": self.to_string(),
                "type": format!("{:?}", self)
            }
        });

        (status, Json(body)).into_response()
    }
}
