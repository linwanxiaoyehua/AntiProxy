// Claude Protocol Handler

use axum::{
    body::Body,
    extract::{Json, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};

use crate::proxy::mappers::claude::{
    collect_claude_sse_response, create_claude_sse_stream, transform_claude_request_in,
    transform_response, ClaudeRequest,
};
use crate::proxy::session_manager::SessionManager;
use crate::proxy::server::AppState;
use axum::http::HeaderMap;

const MAX_RETRY_ATTEMPTS: usize = 3;
const MIN_SIGNATURE_LENGTH: usize = 10;  // Minimum valid signature length

// ===== Model Constants for Background Tasks =====
// These can be adjusted for performance/cost optimization
const BACKGROUND_MODEL_LITE: &str = "gemini-2.5-flash-lite";  // For simple/lightweight tasks
const BACKGROUND_MODEL_STANDARD: &str = "gemini-2.5-flash";   // For complex background tasks

// ===== Jitter Configuration =====
// Jitter helps prevent thundering herd problem in retry scenarios
const JITTER_FACTOR: f64 = 0.2;  // ±20% jitter

// ===== Thinking Block Processing Helper Functions =====

use crate::proxy::mappers::claude::models::{ContentBlock, Message, MessageContent, SystemPrompt, UsageMetadata};

/// Check if thinking block has a valid signature
fn has_valid_signature(block: &ContentBlock) -> bool {
    match block {
        ContentBlock::Thinking { signature, thinking, .. } => {
            // Empty thinking + any signature = valid (trailing signature case)
            if thinking.is_empty() && signature.is_some() {
                return true;
            }
            // Has content + signature with sufficient length = valid
            signature.as_ref().map_or(false, |s| s.len() >= MIN_SIGNATURE_LENGTH)
        }
        _ => true  // Non-thinking blocks are valid by default
    }
}

/// Sanitize thinking block, keep only necessary fields (remove cache_control etc.)
fn sanitize_thinking_block(block: ContentBlock) -> ContentBlock {
    match block {
        ContentBlock::Thinking { thinking, signature, .. } => {
            // Rebuild block, remove cache_control and other extra fields
            ContentBlock::Thinking {
                thinking,
                signature,
                cache_control: None,
            }
        }
        _ => block
    }
}

/// Filter invalid thinking blocks from messages
fn filter_invalid_thinking_blocks(messages: &mut Vec<Message>) {
    let mut total_filtered = 0;
    
    for msg in messages.iter_mut() {
        // Only process assistant messages
        // [CRITICAL FIX] Handle 'model' role too (Google history usage)
        if msg.role != "assistant" && msg.role != "model" {
            continue;
        }
        tracing::error!("[DEBUG-FILTER] Inspecting msg with role: {}", msg.role);
        
        if let MessageContent::Array(blocks) = &mut msg.content {
            let original_len = blocks.len();
            
            // Filter and sanitize
            let mut new_blocks = Vec::new();
            for block in blocks.drain(..) {
                if matches!(block, ContentBlock::Thinking { .. }) {
                    // [DEBUG] Force output log
                    if let ContentBlock::Thinking { ref signature, .. } = block {
                         tracing::error!("[DEBUG-FILTER] Found thinking block. Sig len: {:?}", signature.as_ref().map(|s| s.len()));
                    }

                    // [CRITICAL FIX] Vertex AI doesn't recognize skip_thought_signature_validator
                    // Must directly delete invalid thinking blocks
                    if has_valid_signature(&block) {
                        new_blocks.push(sanitize_thinking_block(block));
                    } else {
                        // [IMPROVED] Preserve content by converting to text, instead of discarding directly
                        if let ContentBlock::Thinking { thinking, .. } = &block {
                            if !thinking.is_empty() {
                                tracing::info!(
                                    "[Claude-Handler] Converting thinking block with invalid signature to text. \
                                     Content length: {} chars",
                                    thinking.len()
                                );
                                new_blocks.push(ContentBlock::Text { text: thinking.clone() });
                            } else {
                                tracing::debug!("[Claude-Handler] Dropping empty thinking block with invalid signature");
                            }
                        }
                    }
                } else {
                    new_blocks.push(block);
                }
            }
            
            *blocks = new_blocks;
            let filtered_count = original_len - blocks.len();
            total_filtered += filtered_count;
            
            // If empty after filtering, add an empty text block to keep message valid
            if blocks.is_empty() {
                blocks.push(ContentBlock::Text { 
                    text: String::new() 
                });
            }
        }
    }
    
    if total_filtered > 0 {
        debug!("Filtered {} invalid thinking block(s) from history", total_filtered);
    }
}

/// Remove trailing unsigned thinking blocks
fn remove_trailing_unsigned_thinking(blocks: &mut Vec<ContentBlock>) {
    if blocks.is_empty() {
        return;
    }
    
    // Scan from back to front
    let mut end_index = blocks.len();
    for i in (0..blocks.len()).rev() {
        match &blocks[i] {
            ContentBlock::Thinking { .. } => {
                if !has_valid_signature(&blocks[i]) {
                    end_index = i;
                } else {
                    break;  // Stop when encountering thinking block with valid signature
                }
            }
            _ => break  // Stop when encountering non-thinking block
        }
    }
    
    if end_index < blocks.len() {
        let removed = blocks.len() - end_index;
        blocks.truncate(end_index);
        debug!("Removed {} trailing unsigned thinking block(s)", removed);
    }
}

// ===== Unified Backoff Strategy Module =====

/// Apply jitter to a delay value to prevent thundering herd
/// Returns delay ± JITTER_FACTOR (e.g., 1000ms ± 20% = 800-1200ms)
fn apply_jitter(delay_ms: u64) -> u64 {
    use rand::Rng;
    let jitter_range = (delay_ms as f64 * JITTER_FACTOR) as i64;
    let jitter: i64 = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
    ((delay_ms as i64) + jitter).max(1) as u64
}

/// Retry strategy enum
#[derive(Debug, Clone)]
enum RetryStrategy {
    /// Don't retry, return error directly
    NoRetry,
    /// Fixed delay
    FixedDelay(Duration),
    /// Linear backoff: base_ms * (attempt + 1)
    LinearBackoff { base_ms: u64 },
    /// Exponential backoff: base_ms * 2^attempt, capped at max_ms
    ExponentialBackoff { base_ms: u64, max_ms: u64 },
}

/// Determine retry strategy based on error status code and error message
fn determine_retry_strategy(
    status_code: u16,
    error_text: &str,
    retried_without_thinking: bool,
) -> RetryStrategy {
    match status_code {
        // 400 error: Thinking signature failure
        400 if !retried_without_thinking
            && (error_text.contains("Invalid `signature`")
                || error_text.contains("thinking.signature")
                || error_text.contains("thinking.thinking")) =>
        {
            // Fixed 200ms delay before retry
            RetryStrategy::FixedDelay(Duration::from_millis(200))
        }

        // 429 rate limit error
        429 => {
            // Prefer using server-returned Retry-After
            if let Some(delay_ms) = crate::proxy::upstream::retry::parse_retry_delay(error_text) {
                let actual_delay = delay_ms.saturating_add(200).min(10_000);
                RetryStrategy::FixedDelay(Duration::from_millis(actual_delay))
            } else {
                // Otherwise use linear backoff: 1s, 2s, 3s
                RetryStrategy::LinearBackoff { base_ms: 1000 }
            }
        }

        // 503 service unavailable / 529 server overload
        503 | 529 => {
            // Exponential backoff: 1s, 2s, 4s, 8s
            RetryStrategy::ExponentialBackoff {
                base_ms: 1000,
                max_ms: 8000,
            }
        }

        // 500 internal server error
        500 => {
            // Linear backoff: 500ms, 1s, 1.5s
            RetryStrategy::LinearBackoff { base_ms: 500 }
        }

        // 401/403 authentication/permission error: retryable (rotate account)
        401 | 403 => RetryStrategy::FixedDelay(Duration::from_millis(100)),

        // Other errors: don't retry
        _ => RetryStrategy::NoRetry,
    }
}

/// Execute backoff strategy and return whether to continue retry
async fn apply_retry_strategy(
    strategy: RetryStrategy,
    attempt: usize,
    status_code: u16,
    trace_id: &str,
) -> bool {
    match strategy {
        RetryStrategy::NoRetry => {
            debug!("[{}] Non-retryable error {}, stopping", trace_id, status_code);
            false
        }

        RetryStrategy::FixedDelay(duration) => {
            // Apply jitter to fixed delays to prevent synchronized retries
            let base_ms = duration.as_millis() as u64;
            let jittered_ms = apply_jitter(base_ms);
            info!(
                "[{}] ⏱️  Retry with fixed delay: status={}, attempt={}/{}, base={}ms, actual={}ms (jitter applied)",
                trace_id,
                status_code,
                attempt + 1,
                MAX_RETRY_ATTEMPTS,
                base_ms,
                jittered_ms
            );
            sleep(Duration::from_millis(jittered_ms)).await;
            true
        }

        RetryStrategy::LinearBackoff { base_ms } => {
            let calculated_ms = base_ms * (attempt as u64 + 1);
            let jittered_ms = apply_jitter(calculated_ms);
            info!(
                "[{}] ⏱️  Retry with linear backoff: status={}, attempt={}/{}, base={}ms, actual={}ms (jitter applied)",
                trace_id,
                status_code,
                attempt + 1,
                MAX_RETRY_ATTEMPTS,
                calculated_ms,
                jittered_ms
            );
            sleep(Duration::from_millis(jittered_ms)).await;
            true
        }

        RetryStrategy::ExponentialBackoff { base_ms, max_ms } => {
            let calculated_ms = (base_ms * 2_u64.pow(attempt as u32)).min(max_ms);
            let jittered_ms = apply_jitter(calculated_ms);
            info!(
                "[{}] ⏱️  Retry with exponential backoff: status={}, attempt={}/{}, base={}ms, actual={}ms (jitter applied)",
                trace_id,
                status_code,
                attempt + 1,
                MAX_RETRY_ATTEMPTS,
                calculated_ms,
                jittered_ms
            );
            sleep(Duration::from_millis(jittered_ms)).await;
            true
        }
    }
}

/// Determine whether to rotate account
fn should_rotate_account(status_code: u16) -> bool {
    match status_code {
        // These errors are account-level, require rotation
        429 | 401 | 403 | 500 => true,
        // These errors are server-level, rotating account is meaningless
        400 | 503 | 529 => false,
        // Other errors default to no rotation
        _ => false,
    }
}

// ===== End of Backoff Strategy Module =====

/// Handle Claude messages request
///
/// Process Chat message request flow
pub async fn handle_messages(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    tracing::error!(">>> [RED ALERT] handle_messages called! Body JSON len: {}", body.to_string().len());
    
    // Generate random Trace ID for tracking
    let trace_id: String = rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>().to_lowercase();
        
    // [CRITICAL REFACTOR] Parse and filter Thinking blocks first to ensure request body consistency
    let mut request: crate::proxy::mappers::claude::models::ClaudeRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "message": format!("Invalid request body: {}", e)
                    }
                }))
            ).into_response();
        }
    };

    // [CRITICAL FIX] Filter and fix Thinking block signatures
    filter_invalid_thinking_blocks(&mut request.messages);
    
    // Google Flow continues using request object
    // (subsequent code doesn't need to call filter_invalid_thinking_blocks again)

    // Get the latest "meaningful" message content (for logging and background task detection)
    // Strategy: Iterate in reverse, first filter all messages with role "user", then find the first non-"Warmup" and non-empty text message
    // Get the latest "meaningful" message content (for logging and background task detection)
    // Strategy: Iterate in reverse, first filter all user-related messages (role="user")
    // Then extract their text content, skip "Warmup" or system preset reminders
    let meaningful_msg = request.messages.iter().rev()
        .filter(|m| m.role == "user")
        .find_map(|m| {
            let content = match &m.content {
                crate::proxy::mappers::claude::models::MessageContent::String(s) => s.to_string(),
                crate::proxy::mappers::claude::models::MessageContent::Array(arr) => {
                    // For arrays, extract all Text blocks and join, ignore ToolResult
                    arr.iter()
                        .filter_map(|block| match block {
                            crate::proxy::mappers::claude::models::ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            };
            
            // Filter rules:
            // 1. Ignore empty messages
            // 2. Ignore "Warmup" messages
            // 3. Ignore messages with <system-reminder> tags
            if content.trim().is_empty() 
                || content.starts_with("Warmup") 
                || content.contains("<system-reminder>") 
            {
                None 
            } else {
                Some(content)
            }
        });

    // If still not found after filtering (e.g., pure tool calls), fall back to last message's raw display
    let latest_msg = meaningful_msg.unwrap_or_else(|| {
        request.messages.last().map(|m| {
            match &m.content {
                crate::proxy::mappers::claude::models::MessageContent::String(s) => s.clone(),
                crate::proxy::mappers::claude::models::MessageContent::Array(_) => "[Complex/Tool Message]".to_string()
            }
        }).unwrap_or_else(|| "[No Messages]".to_string())
    });
    
    
    // INFO level: Concise one-line summary
    info!(
        "[{}] Claude Request | Model: {} | Stream: {} | Messages: {} | Tools: {}",
        trace_id,
        request.model,
        request.stream,
        request.messages.len(),
        request.tools.is_some()
    );
    
    // DEBUG level: Detailed debug information
    debug!("========== [{}] CLAUDE REQUEST DEBUG START ==========", trace_id);
    debug!("[{}] Model: {}", trace_id, request.model);
    debug!("[{}] Stream: {}", trace_id, request.stream);
    debug!("[{}] Max Tokens: {:?}", trace_id, request.max_tokens);
    debug!("[{}] Temperature: {:?}", trace_id, request.temperature);
    debug!("[{}] Message Count: {}", trace_id, request.messages.len());
    debug!("[{}] Has Tools: {}", trace_id, request.tools.is_some());
    debug!("[{}] Has Thinking Config: {}", trace_id, request.thinking.is_some());
    debug!("[{}] Content Preview: {:.100}...", trace_id, latest_msg);
    
    // Output detailed info for each message
    for (idx, msg) in request.messages.iter().enumerate() {
        let content_preview = match &msg.content {
            crate::proxy::mappers::claude::models::MessageContent::String(s) => {
                // Use chars() for safe truncation, avoiding UTF-8 boundary panic
                let preview: String = s.chars().take(200).collect();
                if s.chars().count() > 200 {
                    format!("{}... (total {} chars)", preview, s.chars().count())
                } else {
                    s.clone()
                }
            },
            crate::proxy::mappers::claude::models::MessageContent::Array(arr) => {
                format!("[Array with {} blocks]", arr.len())
            }
        };
        debug!("[{}] Message[{}] - Role: {}, Content: {}",
            trace_id, idx, msg.role, content_preview);
    }
    
    debug!("[{}] Full Claude Request JSON: {}", trace_id, serde_json::to_string_pretty(&request).unwrap_or_default());
    debug!("========== [{}] CLAUDE REQUEST DEBUG END ==========", trace_id);

    // 2. Get UpstreamClient
    let upstream = state.upstream.clone();

    // 3. Prepare closure
    let mut request_for_body = request.clone();
    let token_manager = state.token_manager;

    // 1. Pre-calculate session_id (outside the loop, to avoid session_id changes due to request_for_body modification)
    // This ensures all retries for the same request use the same account
    let stable_session_id = crate::proxy::session_manager::SessionManager::extract_session_id(&request);
    
    let pool_size = token_manager.len();
    let max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size).max(1);

    let mut last_error = String::new();
    let mut retried_without_thinking = false;
    let mut force_rotate_next = false;  // New: control whether to rotate account in next iteration

    for attempt in 0..max_attempts {
        // 2. Model routing and config parsing (parse early to determine request type)
        // First without family mapping to get initial mapped_model
        let initial_mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
            &request_for_body.model,
            &*state.custom_mapping.read().await,
            &*state.openai_mapping.read().await,
            &*state.anthropic_mapping.read().await,
            false,  // Don't apply family mapping first
        );

        // Convert Claude tools to Value array for web search detection
        let tools_val: Option<Vec<Value>> = request_for_body.tools.as_ref().map(|list| {
            list.iter().map(|t| serde_json::to_value(t).unwrap_or(json!({}))).collect()
        });

        let config = crate::proxy::mappers::common_utils::resolve_request_config(&request_for_body.model, &initial_mapped_model, &tools_val);

        // 3. Decide whether to apply Claude family mapping based on request_type
        // request_type == "agent" indicates CLI request, should apply family mapping
        // Other types (web_search, image_gen) don't apply family mapping
        let is_cli_request = config.request_type == "agent";

        let mut mapped_model = if is_cli_request {
            // CLI request: re-call resolve_model_route with family mapping
            crate::proxy::common::model_mapping::resolve_model_route(
                &request_for_body.model,
                &*state.custom_mapping.read().await,
                &*state.openai_mapping.read().await,
                &*state.anthropic_mapping.read().await,
                true,  // CLI request applies family mapping
            )
        } else {
            // Non-CLI request: use initial mapped_model (family mapping skipped)
            initial_mapped_model
        };

        // 0. Use pre-calculated session_id (calculated outside loop, ensures no change on retry)
        let session_id = Some(stable_session_id.as_str());

        let quota_group = "claude";
        // Use force_rotate_next instead of attempt > 0, only rotate when confirmed necessary
        let force_rotate_token = force_rotate_next;
        let selected = match token_manager
            .get_token(quota_group, &config.request_type, force_rotate_token, session_id)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                let safe_message = if e.contains("invalid_grant") {
                    "OAuth refresh failed (invalid_grant): refresh_token likely revoked/expired; reauthorize account(s) to restore service.".to_string()
                } else {
                    e
                };
                 return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "type": "error",
                        "error": {
                            "type": "overloaded_error",
                            "message": format!("No available accounts: {}", safe_message)
                        }
                    }))
                ).into_response();
            }
        };

        let access_token = selected.access_token;
        let project_id = selected.project_id;
        let email = selected.email;
        let account_id = selected.account_id;

        info!("✓ Using account: {} (type: {})", email, config.request_type);
        
        
        // ===== [OPTIMIZATION] Background task smart detection and downgrade =====
        // Use new detection system, supports 5 categories of keywords and multi Flash model strategy
        let background_task_type = detect_background_task_type(&request_for_body);

        // Pass mapped model name
        let mut request_with_mapped = request_for_body.clone();

        if let Some(task_type) = background_task_type {
            // Background task detected, force downgrade to Flash model
            let downgrade_model = select_background_model(task_type);

            info!(
                "[{}][AUTO] Background task detected (type: {:?}), force downgrade: {} -> {}",
                trace_id,
                task_type,
                mapped_model,
                downgrade_model
            );

            // Override user-defined mapping
            mapped_model = downgrade_model.to_string();

            // Background task cleanup:
            // 1. Remove tool definitions (background tasks don't need tools)
            request_with_mapped.tools = None;

            // 2. Remove Thinking config (Flash models don't support it)
            request_with_mapped.thinking = None;

            // 3. Clean Thinking Blocks from history messages, prevent Invalid Argument
            for msg in request_with_mapped.messages.iter_mut() {
                if let crate::proxy::mappers::claude::models::MessageContent::Array(blocks) = &mut msg.content {
                    blocks.retain(|b| !matches!(b,
                        crate::proxy::mappers::claude::models::ContentBlock::Thinking { .. } |
                        crate::proxy::mappers::claude::models::ContentBlock::RedactedThinking { .. }
                    ));
                }
            }
        } else {
            // Real user request, keep original mapping
            debug!(
                "[{}][USER] User interaction request, keeping mapping: {}",
                trace_id,
                mapped_model
            );

            // Apply extra cleanup for real requests: remove trailing unsigned thinking blocks
            for msg in request_with_mapped.messages.iter_mut() {
                if msg.role == "assistant" || msg.role == "model" {
                    if let crate::proxy::mappers::claude::models::MessageContent::Array(blocks) = &mut msg.content {
                        remove_trailing_unsigned_thinking(blocks);
                    }
                }
            }
        }

        
        request_with_mapped.model = mapped_model;

        // Generate Trace ID (simple timestamp suffix)
        // let _trace_id = format!("req_{}", chrono::Utc::now().timestamp_subsec_millis());

        let gemini_body = match transform_claude_request_in(&request_with_mapped, &project_id) {
            Ok(b) => {
                debug!("[{}] Transformed Gemini Body: {}", trace_id, serde_json::to_string_pretty(&b).unwrap_or_default());
                b
            },
            Err(e) => {
                 return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "type": "error",
                        "error": {
                            "type": "api_error",
                            "message": format!("Transform error: {}", e)
                        }
                    }))
                ).into_response();
            }
        };
        
    // 4. Upstream call
    let method = "streamGenerateContent";
    let query = Some("alt=sse");

    let response = match upstream.call_v1_internal(
        method,
        &access_token,
        gemini_body,
        query
    ).await {
            Ok(r) => r,
            Err(e) => {
                last_error = e.clone();
                debug!("Request failed on attempt {}/{}: {}", attempt + 1, max_attempts, e);
                continue;
            }
        };
        
        let status = response.status();

        // Success
        if status.is_success() {
            // Handle streaming response
            if request.stream {
                let stream = response.bytes_stream();
                let gemini_stream = Box::pin(stream);
                let claude_stream = create_claude_sse_stream(gemini_stream, trace_id, email);

                // Convert to Bytes stream
                let sse_stream = claude_stream.map(|result| -> Result<Bytes, std::io::Error> {
                    match result {
                        Ok(bytes) => Ok(bytes),
                        Err(e) => Ok(Bytes::from(format!("data: {{\"error\":\"{}\"}}\n\n", e))),
                    }
                });

                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .header(header::CONNECTION, "keep-alive")
                    .body(Body::from_stream(sse_stream))
                    .unwrap();
            } else {
                // Handle non-streaming response
                let stream = response.bytes_stream();
                let gemini_response = match collect_claude_sse_response(Box::pin(stream)).await {
                    Ok(r) => r,
                    Err(e) => {
                        return (StatusCode::BAD_GATEWAY, format!("Stream collect error: {}", e))
                            .into_response();
                    }
                };

                let claude_response = match transform_response(&gemini_response) {
                    Ok(r) => r,
                    Err(e) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Transform error: {}", e))
                            .into_response();
                    }
                };

                // [Optimization] Log closed-loop: consumption info
                let cache_info = if let Some(cached) = claude_response.usage.cache_read_input_tokens {
                    format!(", Cached: {}", cached)
                } else {
                    String::new()
                };

                tracing::info!(
                    "[{}] ✓ Stream collected and converted to JSON | Model: {}, Tokens: In {}, Out {}{}",
                    trace_id,
                    request_with_mapped.model,
                    claude_response.usage.input_tokens,
                    claude_response.usage.output_tokens,
                    cache_info
                );

                return Json(claude_response).into_response();
            }
        }
        
        // 1. Extract status code and headers immediately (prevent response from being moved)
        let status_code = status.as_u16();
        let retry_after = response.headers().get("Retry-After").and_then(|h| h.to_str().ok()).map(|s| s.to_string());

        // 2. Get error text and transfer Response ownership
        let error_text = response.text().await.unwrap_or_else(|_| format!("HTTP {}", status));
        last_error = format!("HTTP {}: {}", status_code, error_text);
        debug!("[{}] Upstream Error Response: {}", trace_id, error_text);

        // 3. Mark rate limit status (for UI display)
        if status_code == 429 || status_code == 529 || status_code == 503 || status_code == 500 {
            token_manager.mark_rate_limited(
                quota_group,
                &config.request_type,
                &account_id,
                status_code,
                retry_after.as_deref(),
                &error_text,
            );
        }

        // 4. Handle 400 error (Thinking signature failure)
        // Since already proactively filtered, this error should rarely occur
        if status_code == 400
            && !retried_without_thinking
            && (error_text.contains("Invalid `signature`")
                || error_text.contains("thinking.signature: Field required")
                || error_text.contains("thinking.thinking: Field required")
                || error_text.contains("thinking.signature")
                || error_text.contains("thinking.thinking"))
        {
            retried_without_thinking = true;

            // Use WARN level since this shouldn't happen often (already proactively filtered)
            tracing::warn!(
                "[{}] Unexpected thinking signature error (should have been filtered). \
                 Retrying with all thinking blocks removed.",
                trace_id
            );

            // Completely remove all thinking-related content
            request_for_body.thinking = None;

            // Clean all Thinking Blocks from history messages
            for msg in request_for_body.messages.iter_mut() {
                if let crate::proxy::mappers::claude::models::MessageContent::Array(blocks) = &mut msg.content {
                    blocks.retain(|b| !matches!(b, 
                        crate::proxy::mappers::claude::models::ContentBlock::Thinking { .. } |
                        crate::proxy::mappers::claude::models::ContentBlock::RedactedThinking { .. }
                    ));
                }
            }

            // Clean -thinking suffix from model name
            if request_for_body.model.contains("claude-") {
                let mut m = request_for_body.model.clone();
                m = m.replace("-thinking", "");
                if m.contains("claude-sonnet-4-5-") {
                    m = "claude-sonnet-4-5".to_string();
                } else if m.contains("claude-opus-4-5-") || m.contains("claude-opus-4-") {
                    m = "claude-opus-4-5".to_string();
                }
                request_for_body.model = m;
            }

            // Use unified backoff strategy
            let strategy = determine_retry_strategy(status_code, &error_text, retried_without_thinking);
            if apply_retry_strategy(strategy, attempt, status_code, &trace_id).await {
                continue;
            }
        }

        // 5. Unified handling of all retryable errors
        // [REMOVED] No longer special-handling QUOTA_EXHAUSTED, allow account rotation
        // Original logic would return directly when first account exhausted, preventing "balance" mode from switching accounts


        // Determine retry strategy
        let strategy = determine_retry_strategy(status_code, &error_text, retried_without_thinking);

        // Execute backoff
        if apply_retry_strategy(strategy, attempt, status_code, &trace_id).await {
            // Determine whether to rotate account and set rotation flag for next iteration
            if should_rotate_account(status_code) {
                force_rotate_next = true;
                debug!("[{}] Will rotate account for status {} (account-level issue)", trace_id, status_code);
            } else {
                force_rotate_next = false;
                debug!("[{}] Keeping same account for status {} (server-side issue)", trace_id, status_code);
            }
            continue;
        } else {
            // Non-retryable error, return directly
            error!("[{}] Non-retryable error {}: {}", trace_id, status_code, error_text);
            return (status, error_text).into_response();
        }
    }
    
    (StatusCode::TOO_MANY_REQUESTS, Json(json!({
        "type": "error",
        "error": {
            "type": "overloaded_error",
            "message": format!("All {} attempts failed. Last error: {}", max_attempts, last_error)
        }
    }))).into_response()
}

/// List available models
pub async fn handle_list_models(State(state): State<AppState>) -> impl IntoResponse {
    use crate::proxy::common::model_mapping::get_all_dynamic_models;

    let model_ids = get_all_dynamic_models(
        &state.openai_mapping,
        &state.custom_mapping,
        &state.anthropic_mapping,
    ).await;

    let data: Vec<_> = model_ids.into_iter().map(|id| {
        json!({
            "id": id,
            "object": "model",
            "created": 1706745600,
            "owned_by": "antigravity"
        })
    }).collect();

    Json(json!({
        "object": "list",
        "data": data
    }))
}

const MESSAGE_OVERHEAD_TOKENS: u32 = 3;
const IMAGE_BLOCK_TOKENS: u32 = 256;
const DOCUMENT_BLOCK_TOKENS: u32 = 1024;

fn estimate_tokens_from_text(text: &str) -> u32 {
    let mut ascii_chars = 0u32;
    let mut non_ascii_chars = 0u32;

    for ch in text.chars() {
        if ch.is_ascii() {
            ascii_chars += 1;
        } else {
            non_ascii_chars += 1;
        }
    }

    let ascii_tokens = (ascii_chars + 3) / 4;
    ascii_tokens + non_ascii_chars
}

fn estimate_tokens_from_value(value: &Value) -> u32 {
    estimate_tokens_from_text(&value.to_string())
}

fn estimate_tokens_from_content_block(block: &ContentBlock) -> u32 {
    match block {
        ContentBlock::Text { text } => estimate_tokens_from_text(text),
        ContentBlock::Thinking { thinking, .. } => estimate_tokens_from_text(thinking),
        ContentBlock::ToolUse { name, input, .. } => {
            estimate_tokens_from_text(name) + estimate_tokens_from_value(input)
        }
        ContentBlock::ToolResult { content, .. } => estimate_tokens_from_value(content),
        ContentBlock::ServerToolUse { name, input, .. } => {
            estimate_tokens_from_text(name) + estimate_tokens_from_value(input)
        }
        ContentBlock::WebSearchToolResult { content, .. } => estimate_tokens_from_value(content),
        ContentBlock::RedactedThinking { data } => estimate_tokens_from_text(data),
        ContentBlock::Image { .. } => IMAGE_BLOCK_TOKENS,
        ContentBlock::Document { .. } => DOCUMENT_BLOCK_TOKENS,
    }
}

fn estimate_tokens_from_message_content(content: &MessageContent) -> u32 {
    match content {
        MessageContent::String(text) => estimate_tokens_from_text(text),
        MessageContent::Array(blocks) => blocks
            .iter()
            .map(estimate_tokens_from_content_block)
            .sum(),
    }
}

fn estimate_tokens_from_request(request: &ClaudeRequest) -> u32 {
    let mut total = 0u32;

    if let Some(system) = &request.system {
        match system {
            SystemPrompt::String(text) => {
                total += estimate_tokens_from_text(text);
            }
            SystemPrompt::Array(blocks) => {
                for block in blocks {
                    total += estimate_tokens_from_text(&block.text);
                }
            }
        }
    }

    if let Some(tools) = &request.tools {
        if let Ok(value) = serde_json::to_value(tools) {
            total += estimate_tokens_from_value(&value);
        }
    }

    for msg in &request.messages {
        total += MESSAGE_OVERHEAD_TOKENS;
        total += estimate_tokens_from_message_content(&msg.content);
    }

    total
}

fn estimate_tokens_from_gemini_body(body: &Value) -> u32 {
    if let Some(request) = body.get("request") {
        estimate_tokens_from_value(request)
    } else {
        estimate_tokens_from_value(body)
    }
}

fn extract_total_tokens(value: &Value) -> Option<u32> {
    let raw = value.get("response").unwrap_or(value);

    let total = raw
        .get("totalTokens")
        .or_else(|| raw.get("total_tokens"))
        .or_else(|| raw.get("tokenCount"))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());

    if total.is_some() {
        return total;
    }

    let usage = raw
        .get("usageMetadata")
        .and_then(|u| serde_json::from_value::<UsageMetadata>(u.clone()).ok());

    usage
        .and_then(|u| u.prompt_token_count.or(u.total_token_count))
}

/// Count tokens
pub async fn handle_count_tokens(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let request: ClaudeRequest = match serde_json::from_value(body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "message": format!("Invalid request body: {}", e)
                    }
                })),
            )
                .into_response();
        }
    };

    let estimated_tokens = estimate_tokens_from_request(&request);

    let stable_session_id = SessionManager::extract_session_id(&request);
    let initial_mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
        &request.model,
        &*state.custom_mapping.read().await,
        &*state.openai_mapping.read().await,
        &*state.anthropic_mapping.read().await,
        false,
    );

    let tools_val: Option<Vec<Value>> = request.tools.as_ref().map(|list| {
        list.iter()
            .map(|t| serde_json::to_value(t).unwrap_or(json!({})))
            .collect()
    });

    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        &request.model,
        &initial_mapped_model,
        &tools_val,
    );

    let is_cli_request = config.request_type == "agent";
    let mapped_model = if is_cli_request {
        crate::proxy::common::model_mapping::resolve_model_route(
            &request.model,
            &*state.custom_mapping.read().await,
            &*state.openai_mapping.read().await,
            &*state.anthropic_mapping.read().await,
            true,
        )
    } else {
        initial_mapped_model
    };

    let mut request_with_mapped = request.clone();
    request_with_mapped.model = mapped_model;

    let input_tokens = match state
        .token_manager
        .get_token("claude", &config.request_type, false, Some(&stable_session_id))
        .await
    {
        Ok(selected) => match transform_claude_request_in(&request_with_mapped, &selected.project_id) {
            Ok(gemini_body) => {
                let transformed_estimate =
                    estimate_tokens_from_gemini_body(&gemini_body).max(estimated_tokens);
                let upstream = state.upstream.clone();
                match upstream
                    .call_v1_internal("countTokens", &selected.access_token, gemini_body, None)
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status();
                        if !status.is_success() {
                            tracing::warn!(
                                "[Claude-CountTokens] Upstream error {}. Falling back to estimate.",
                                status
                            );
                            transformed_estimate
                        } else {
                            match resp.json::<Value>().await {
                                Ok(value) => {
                                    extract_total_tokens(&value).unwrap_or(transformed_estimate)
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "[Claude-CountTokens] Parse error: {}. Falling back to estimate.",
                                        e
                                    );
                                    transformed_estimate
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[Claude-CountTokens] Upstream call failed: {}. Falling back to estimate.",
                            e
                        );
                        transformed_estimate
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[Claude-CountTokens] Transform error: {}. Falling back to estimate.",
                    e
                );
                estimated_tokens
            }
        },
        Err(e) => {
            tracing::warn!(
                "[Claude-CountTokens] Token error: {}. Falling back to estimate.",
                e
            );
            estimated_tokens
        }
    };

    Json(json!({
        "input_tokens": input_tokens,
        "output_tokens": 0
    }))
    .into_response()
}

// Removed obsolete simple unit tests, complete integration tests to be added later
/*
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handle_list_models() {
        // handle_list_models now requires AppState, skip old unit test here
    }
}
*/

// ===== Background Task Detection Helper Functions =====

/// Background task type
#[derive(Debug, Clone, Copy, PartialEq)]
enum BackgroundTaskType {
    TitleGeneration,      // Title generation
    SimpleSummary,        // Simple summary
    ContextCompression,   // Context compression
    PromptSuggestion,     // Prompt suggestion
    SystemMessage,        // System message
    EnvironmentProbe,     // Environment probe
}

/// Title generation keywords
const TITLE_KEYWORDS: &[&str] = &[
    "write a 5-10 word title",
    "Please write a 5-10 word title",
    "Respond with the title",
    "Generate a title for",
    "Create a brief title",
    "title for the conversation",
    "conversation title",
];

/// Summary generation keywords
const SUMMARY_KEYWORDS: &[&str] = &[
    "Summarize this coding conversation",
    "Summarize the conversation",
    "Concise summary",
    "in under 50 characters",
    "compress the context",
    "Provide a concise summary",
    "condense the previous messages",
    "shorten the conversation history",
    "extract key points from",
];

/// Suggestion generation keywords
const SUGGESTION_KEYWORDS: &[&str] = &[
    "prompt suggestion generator",
    "suggest next prompts",
    "what should I ask next",
    "generate follow-up questions",
    "recommend next steps",
    "possible next actions",
];

/// System message keywords
const SYSTEM_KEYWORDS: &[&str] = &[
    "Warmup",
    "<system-reminder>",
    // Removed: "Caveat: The messages below were generated" - this is a normal Claude Desktop system prompt
    "This is a system message",
];

/// Environment probe keywords
const PROBE_KEYWORDS: &[&str] = &[
    "check current directory",
    "list available tools",
    "verify environment",
    "test connection",
];

/// Detect background task and return task type
fn detect_background_task_type(request: &ClaudeRequest) -> Option<BackgroundTaskType> {
    let last_user_msg = extract_last_user_message_for_detection(request)?;
    let preview = last_user_msg.chars().take(500).collect::<String>();

    // Length filter: background tasks usually don't exceed 800 characters
    if last_user_msg.len() > 800 {
        return None;
    }

    // Match by priority
    if matches_keywords(&preview, SYSTEM_KEYWORDS) {
        return Some(BackgroundTaskType::SystemMessage);
    }
    
    if matches_keywords(&preview, TITLE_KEYWORDS) {
        return Some(BackgroundTaskType::TitleGeneration);
    }
    
    if matches_keywords(&preview, SUMMARY_KEYWORDS) {
        if preview.contains("in under 50 characters") {
            return Some(BackgroundTaskType::SimpleSummary);
        }
        return Some(BackgroundTaskType::ContextCompression);
    }
    
    if matches_keywords(&preview, SUGGESTION_KEYWORDS) {
        return Some(BackgroundTaskType::PromptSuggestion);
    }
    
    if matches_keywords(&preview, PROBE_KEYWORDS) {
        return Some(BackgroundTaskType::EnvironmentProbe);
    }
    
    None
}

/// Helper function: keyword matching
fn matches_keywords(text: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|kw| text.contains(kw))
}

/// Helper function: extract last user message (for detection)
fn extract_last_user_message_for_detection(request: &ClaudeRequest) -> Option<String> {
    request.messages.iter().rev()
        .filter(|m| m.role == "user")
        .find_map(|m| {
            let content = match &m.content {
                crate::proxy::mappers::claude::models::MessageContent::String(s) => s.to_string(),
                crate::proxy::mappers::claude::models::MessageContent::Array(arr) => {
                    arr.iter()
                        .filter_map(|block| match block {
                            crate::proxy::mappers::claude::models::ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            };
            
            if content.trim().is_empty() 
                || content.starts_with("Warmup") 
                || content.contains("<system-reminder>") 
            {
                None 
            } else {
                Some(content)
            }
        })
}

/// Select appropriate model based on background task type
fn select_background_model(task_type: BackgroundTaskType) -> &'static str {
    match task_type {
        BackgroundTaskType::TitleGeneration => BACKGROUND_MODEL_LITE,     // Minimal task
        BackgroundTaskType::SimpleSummary => BACKGROUND_MODEL_LITE,       // Simple summary
        BackgroundTaskType::SystemMessage => BACKGROUND_MODEL_LITE,       // System message
        BackgroundTaskType::PromptSuggestion => BACKGROUND_MODEL_LITE,    // Suggestion generation
        BackgroundTaskType::EnvironmentProbe => BACKGROUND_MODEL_LITE,    // Environment probe
        BackgroundTaskType::ContextCompression => BACKGROUND_MODEL_STANDARD, // Complex compression
    }
}
