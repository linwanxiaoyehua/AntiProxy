use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use serde_json::Value;
use std::pin::Pin;
use tokio::time::{timeout, Duration};

pub const DEFAULT_COLLECTOR_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MAX_COLLECTED_PARTS: usize = 10_000;

#[derive(Debug)]
pub struct CollectedSse {
    pub parts: Vec<Value>,
    pub finish_reason: Option<String>,
    pub usage_metadata: Option<Value>,
    pub model_version: Option<String>,
    pub response_id: Option<String>,
    pub grounding_metadata: Option<Value>,
}

impl CollectedSse {
    fn new() -> Self {
        Self {
            parts: Vec::new(),
            finish_reason: None,
            usage_metadata: None,
            model_version: None,
            response_id: None,
            grounding_metadata: None,
        }
    }
}

fn ingest_payload(payload: &Value, collected: &mut CollectedSse) {
    let raw = payload.get("response").unwrap_or(payload);

    if let Some(usage) = raw.get("usageMetadata") {
        collected.usage_metadata = Some(usage.clone());
    }

    if let Some(model) = raw.get("modelVersion").and_then(|v| v.as_str()) {
        collected.model_version = Some(model.to_string());
    }

    if let Some(id) = raw.get("responseId").and_then(|v| v.as_str()) {
        collected.response_id = Some(id.to_string());
    }

    // NOTE: Gemini typically returns a single candidate; we only collect index 0.
    if let Some(candidate) = raw.get("candidates").and_then(|c| c.get(0)) {
        if let Some(reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
            collected.finish_reason = Some(reason.to_string());
        }

        if let Some(grounding) = candidate.get("groundingMetadata") {
            collected.grounding_metadata = Some(grounding.clone());
        }

        if let Some(parts_list) = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
        {
            for part in parts_list {
                collected.parts.push(part.clone());
            }
        }
    }
}

pub async fn collect_sse_payloads(
    mut gemini_stream: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    timeout_secs: u64,
    max_parts: usize,
) -> Result<CollectedSse, String> {
    let collection = async {
        let mut buffer = BytesMut::new();
        let mut collected = CollectedSse::new();

        while let Some(item) = gemini_stream.next().await {
            match item {
                Ok(bytes) => {
                    buffer.extend_from_slice(&bytes);
                    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                        let line_raw = buffer.split_to(pos + 1);
                        let line = match std::str::from_utf8(&line_raw) {
                            Ok(s) => s.trim(),
                            Err(_) => continue,
                        };
                        let payload = match line.strip_prefix("data: ") {
                            Some(rest) => rest.trim(),
                            None => continue,
                        };
                        if payload.is_empty() || payload == "[DONE]" {
                            continue;
                        }
                        if let Ok(json) = serde_json::from_str::<Value>(payload) {
                            ingest_payload(&json, &mut collected);
                            if collected.parts.len() > max_parts {
                                return Err(format!(
                                    "Stream too large: {} parts exceeds limit of {}",
                                    collected.parts.len(),
                                    max_parts
                                ));
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("Stream error: {}", e)),
            }
        }

        if !buffer.is_empty() {
            if let Ok(line) = std::str::from_utf8(&buffer) {
                let line = line.trim();
                if let Some(payload) = line.strip_prefix("data: ") {
                    let payload = payload.trim();
                    if !payload.is_empty() && payload != "[DONE]" {
                        if let Ok(json) = serde_json::from_str::<Value>(payload) {
                            ingest_payload(&json, &mut collected);
                            if collected.parts.len() > max_parts {
                                return Err(format!(
                                    "Stream too large: {} parts exceeds limit of {}",
                                    collected.parts.len(),
                                    max_parts
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(collected)
    };

    match timeout(Duration::from_secs(timeout_secs), collection).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "Stream collection timed out after {}s",
            timeout_secs
        )),
    }
}
