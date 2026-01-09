use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;

use super::models::{
    Candidate, GeminiContent, GeminiPart, GeminiResponse, GroundingMetadata, UsageMetadata,
};
use crate::proxy::mappers::sse_collector::{
    collect_sse_payloads, DEFAULT_COLLECTOR_TIMEOUT_SECS, DEFAULT_MAX_COLLECTED_PARTS,
};

/// Collects Gemini SSE into a typed response for non-stream Claude clients.
pub async fn collect_claude_sse_response(
    gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
) -> Result<GeminiResponse, String> {
    let collected = collect_sse_payloads(
        gemini_stream,
        DEFAULT_COLLECTOR_TIMEOUT_SECS,
        DEFAULT_MAX_COLLECTED_PARTS,
    )
    .await?;

    let mut parts: Vec<GeminiPart> = Vec::with_capacity(collected.parts.len());
    for part in collected.parts {
        if let Ok(parsed) = serde_json::from_value::<GeminiPart>(part) {
            parts.push(parsed);
        }
    }

    let usage_metadata = collected
        .usage_metadata
        .and_then(|v| serde_json::from_value::<UsageMetadata>(v).ok());
    let grounding_metadata = collected
        .grounding_metadata
        .and_then(|v| serde_json::from_value::<GroundingMetadata>(v).ok());

    let candidate = Candidate {
        content: Some(GeminiContent {
            role: "model".to_string(),
            parts,
        }),
        finish_reason: collected.finish_reason,
        index: Some(0),
        grounding_metadata,
    };

    Ok(GeminiResponse {
        candidates: Some(vec![candidate]),
        usage_metadata,
        model_version: collected.model_version,
        response_id: collected.response_id,
    })
}
