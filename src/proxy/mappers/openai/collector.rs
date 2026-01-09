use bytes::Bytes;
use futures::Stream;
use serde_json::{json, Map, Value};
use std::pin::Pin;

use crate::proxy::mappers::sse_collector::{
    collect_sse_payloads, DEFAULT_COLLECTOR_TIMEOUT_SECS, DEFAULT_MAX_COLLECTED_PARTS,
};

/// Collects Gemini SSE into a single JSON response for non-stream OpenAI clients.
pub async fn collect_openai_sse_response(
    gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
) -> Result<Value, String> {
    let collected = collect_sse_payloads(
        gemini_stream,
        DEFAULT_COLLECTOR_TIMEOUT_SECS,
        DEFAULT_MAX_COLLECTED_PARTS,
    )
    .await?;

    let mut candidate = Map::new();
    candidate.insert(
        "content".to_string(),
        json!({
            "role": "model",
            "parts": collected.parts
        }),
    );
    if let Some(reason) = collected.finish_reason {
        candidate.insert("finishReason".to_string(), Value::String(reason));
    }
    candidate.insert("index".to_string(), Value::Number(serde_json::Number::from(0)));
    if let Some(grounding) = collected.grounding_metadata {
        candidate.insert("groundingMetadata".to_string(), grounding);
    }

    let mut response = Map::new();
    response.insert(
        "candidates".to_string(),
        Value::Array(vec![Value::Object(candidate)]),
    );
    if let Some(usage) = collected.usage_metadata {
        response.insert("usageMetadata".to_string(), usage);
    }
    if let Some(model) = collected.model_version {
        response.insert("modelVersion".to_string(), Value::String(model));
    }
    if let Some(id) = collected.response_id {
        response.insert("responseId".to_string(), Value::String(id));
    }

    Ok(Value::Object(response))
}
