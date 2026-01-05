// Gemini v1internal 数据模型
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1InternalRequest {
    pub project: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub request: serde_json::Value,
    pub model: String,
    #[serde(rename = "userAgent")]
    pub user_agent: String,
    #[serde(rename = "requestType")]
    pub request_type: String,
}
