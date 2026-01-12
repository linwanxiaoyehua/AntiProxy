// OpenAI Handler
use axum::{extract::Json, extract::State, http::StatusCode, response::IntoResponse};
use axum::body::Body;
use axum::response::Response;
use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info}; // Import Engine trait for encode method

use crate::proxy::mappers::openai::{
    collect_openai_sse_response, transform_openai_request, transform_openai_response, OpenAIRequest,
};
use crate::proxy::server::AppState;
use crate::proxy::TokenManager;
use crate::proxy::upstream::client::UpstreamClient;

const MAX_RETRY_ATTEMPTS: usize = 3;
use crate::proxy::session_manager::SessionManager;

/// Response format type
#[derive(Clone, Copy)]
enum ResponseFormat {
    /// Standard OpenAI Chat format
    Chat,
    /// Legacy Completions format
    LegacyCompletion,
    /// Codex style format
    Codex,
}

/// Core request execution result
enum ExecuteResult {
    /// Successful streaming response
    StreamResponse(Response),
    /// Successful non-streaming response (Gemini raw JSON)
    JsonResponse(Value),
    /// Needs retry
    Retry { error: String, should_rotate: bool },
    /// Non-retryable error
    FatalError { status: StatusCode, message: String },
}

fn extract_u32(value: &Value, path: &[&str]) -> u32 {
    let mut current = value;
    for key in path {
        current = match current.get(*key) {
            Some(v) => v,
            None => return 0,
        };
    }
    current
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

/// Core request execution function V2 - accepts pre-calculated session_id and force_rotate parameters
/// Fixes the issue in original version where session_id calculated inside function caused account switching on retry
async fn execute_openai_request_v2(
    state: &AppState,
    openai_req: &OpenAIRequest,
    upstream: Arc<UpstreamClient>,
    token_manager: Arc<TokenManager>,
    force_rotate: bool,
    session_id: &str,
    response_format: ResponseFormat,
) -> ExecuteResult {
    // 1. Model routing and config parsing
    let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
        &openai_req.model,
        &*state.custom_mapping.read().await,
        &*state.openai_mapping.read().await,
        &*state.anthropic_mapping.read().await,
        false, // OpenAI requests don't apply Claude family mapping
    );

    // Convert OpenAI tools to Value array for web search detection
    let tools_val: Option<Vec<Value>> = openai_req
        .tools
        .as_ref()
        .map(|list| list.iter().cloned().collect());
    let config = crate::proxy::mappers::common_utils::resolve_request_config(
        &openai_req.model,
        &mapped_model,
        &tools_val,
    );
    let quota_group = if openai_req.model.to_ascii_lowercase().contains("claude")
        || mapped_model.to_ascii_lowercase().contains("claude")
    {
        "claude"
    } else {
        "gemini"
    };

    // 2. Get Token (using passed session_id and force_rotate)
    let selected = match token_manager
        .get_token(quota_group, &config.request_type, force_rotate, Some(session_id))
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return ExecuteResult::FatalError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: format!("Token error: {}", e),
            };
        }
    };

    let access_token = selected.access_token;
    let project_id = selected.project_id;
    let email = selected.email;
    let account_id = selected.account_id;

    info!("✓ Using account: {} (type: {})", email, config.request_type);

    // 3. Transform request
    let gemini_body = transform_openai_request(openai_req, &project_id, &mapped_model);

    if let Ok(body_json) = serde_json::to_string_pretty(&gemini_body) {
        debug!("[OpenAI-Request] Transformed Gemini Body:\n{}", body_json);
    }

    // 4. Send request
    let method = "streamGenerateContent";
    let query_string = Some("alt=sse");

    let response = match upstream
        .call_v1_internal(method, &access_token, gemini_body, query_string)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!("OpenAI Request failed: {}", e);
            // Network error doesn't need account rotation, might be temporary issue
            return ExecuteResult::Retry { error: e, should_rotate: false };
        }
    };

    let status = response.status();

    // 5. Handle successful response
    if status.is_success() {
        let gemini_stream = response.bytes_stream();
        let model_clone = openai_req.model.clone();

        // Select different SSE stream transformer based on response format
        if openai_req.stream {
            let body = match response_format {
                ResponseFormat::Chat => {
                    use crate::proxy::mappers::openai::streaming::create_openai_sse_stream;
                    let stream = create_openai_sse_stream(Box::pin(gemini_stream), model_clone);
                    Body::from_stream(stream)
                }
                ResponseFormat::Codex => {
                    use crate::proxy::mappers::openai::streaming::create_codex_sse_stream;
                    let stream = create_codex_sse_stream(Box::pin(gemini_stream), model_clone);
                    Body::from_stream(stream)
                }
                ResponseFormat::LegacyCompletion => {
                    use crate::proxy::mappers::openai::streaming::create_legacy_sse_stream;
                    let stream = create_legacy_sse_stream(Box::pin(gemini_stream), model_clone);
                    Body::from_stream(stream)
                }
            };

            let resp = Response::builder()
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .body(body)
                .unwrap();

            return ExecuteResult::StreamResponse(resp);
        }

        let gemini_resp = match collect_openai_sse_response(Box::pin(gemini_stream)).await {
            Ok(value) => value,
            Err(e) => {
                return ExecuteResult::FatalError {
                    status: StatusCode::BAD_GATEWAY,
                    message: format!("Stream collect error: {}", e),
                };
            }
        };

        return ExecuteResult::JsonResponse(gemini_resp);
    }

    // 6. Handle error response
    let status_code = status.as_u16();
    let retry_after = response
        .headers()
        .get("Retry-After")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let error_text = response
        .text()
        .await
        .unwrap_or_else(|_| format!("HTTP {}", status_code));

    tracing::error!(
        "[OpenAI-Upstream] Error Response {}: {}",
        status_code,
        error_text
    );

    // Determine whether to rotate account
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

    // 429/529/503/500 smart handling
    if status_code == 429 || status_code == 529 || status_code == 503 || status_code == 500 {
        token_manager.mark_rate_limited(
            quota_group,
            &config.request_type,
            &account_id,
            status_code,
            retry_after.as_deref(),
            &error_text,
        );

        if let Some(delay_ms) = crate::proxy::upstream::retry::parse_retry_delay(&error_text) {
            let actual_delay = delay_ms.saturating_add(200).min(10_000);
            tracing::warn!(
                "OpenAI Upstream {} on {}, waiting {}ms then retrying",
                status_code,
                email,
                actual_delay
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(actual_delay)).await;
            return ExecuteResult::Retry {
                error: format!("HTTP {}: {}", status_code, error_text),
                should_rotate: should_rotate_account(status_code),
            };
        }

        tracing::warn!(
            "OpenAI Upstream {} on {}, will rotate: {}",
            status_code,
            email,
            should_rotate_account(status_code)
        );
        return ExecuteResult::Retry {
            error: format!("HTTP {}: {}", status_code, error_text),
            should_rotate: should_rotate_account(status_code),
        };
    }

    // 401/403 triggers account rotation
    if status_code == 403 || status_code == 401 {
        tracing::warn!(
            "OpenAI Upstream {} on account {}, rotating account",
            status_code,
            email
        );
        return ExecuteResult::Retry {
            error: format!("HTTP {}: {}", status_code, error_text),
            should_rotate: true,
        };
    }

    // Other errors are not retryable
    error!(
        "OpenAI Upstream non-retryable error {} on account {}: {}",
        status_code, email, error_text
    );
    ExecuteResult::FatalError {
        status,
        message: error_text,
    }
}

/// Core request execution function - kept for backward compatibility (deprecated, use execute_openai_request_v2)
#[allow(dead_code)]
async fn execute_openai_request(
    state: &AppState,
    openai_req: &OpenAIRequest,
    upstream: Arc<UpstreamClient>,
    token_manager: Arc<TokenManager>,
    attempt: usize,
    _max_attempts: usize,
    response_format: ResponseFormat,
) -> ExecuteResult {
    // Backward compatible with old calls: force rotate when attempt > 0
    let session_id = SessionManager::extract_openai_session_id(openai_req);
    execute_openai_request_v2(
        state,
        openai_req,
        upstream,
        token_manager,
        attempt > 0,
        &session_id,
        response_format,
    ).await
}

/// Execute request loop with retry
async fn execute_with_retry(
    state: &AppState,
    openai_req: &OpenAIRequest,
    response_format: ResponseFormat,
) -> Result<Response, (StatusCode, String)> {
    let upstream = state.upstream.clone();
    let token_manager = state.token_manager.clone();
    let pool_size = token_manager.len();
    let max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size).max(1);

    // [CRITICAL FIX] Pre-calculate session_id, ensure it doesn't change on retry
    let stable_session_id = SessionManager::extract_openai_session_id(openai_req);

    let mut last_error = String::new();
    let mut force_rotate_next = false;  // Control whether to rotate account in next iteration

    for _attempt in 0..max_attempts {
        match execute_openai_request_v2(
            state,
            openai_req,
            upstream.clone(),
            token_manager.clone(),
            force_rotate_next,
            &stable_session_id,
            response_format,
        )
        .await
        {
            ExecuteResult::StreamResponse(resp) => {
                // Streaming response already processed by format in execute_openai_request
                return Ok(resp);
            }
            ExecuteResult::JsonResponse(gemini_resp) => {
                // Non-streaming response - transform based on format
                if !openai_req.stream {
                    let cached_tokens = extract_u32(
                        &gemini_resp,
                        &["usageMetadata", "cachedContentTokenCount"],
                    );
                    let cache_info = if cached_tokens > 0 {
                        format!(", Cached: {}", cached_tokens)
                    } else {
                        String::new()
                    };
                    let prompt_tokens =
                        extract_u32(&gemini_resp, &["usageMetadata", "promptTokenCount"]);
                    let completion_tokens =
                        extract_u32(&gemini_resp, &["usageMetadata", "candidatesTokenCount"]);
                    let model_version = gemini_resp
                        .get("modelVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&openai_req.model);

                    info!(
                        "[OpenAI][{}] ✓ Stream collected and converted to JSON | Model: {}, Tokens: In {}, Out {}{}",
                        stable_session_id,
                        model_version,
                        prompt_tokens.saturating_sub(cached_tokens),
                        completion_tokens,
                        cache_info
                    );
                }

                let response = match response_format {
                    ResponseFormat::Chat => {
                        let openai_response = transform_openai_response(&gemini_resp);
                        Json(openai_response).into_response()
                    }
                    ResponseFormat::LegacyCompletion | ResponseFormat::Codex => {
                        let chat_resp = transform_openai_response(&gemini_resp);
                        let choices: Vec<_> = chat_resp
                            .choices
                            .iter()
                            .map(|c| {
                                json!({
                                    "text": match &c.message.content {
                                        Some(crate::proxy::mappers::openai::OpenAIContent::String(s)) => s.clone(),
                                        _ => "".to_string()
                                    },
                                    "index": c.index,
                                    "logprobs": null,
                                    "finish_reason": c.finish_reason
                                })
                            })
                            .collect();

                        let legacy_resp = json!({
                            "id": chat_resp.id,
                            "object": "text_completion",
                            "created": chat_resp.created,
                            "model": chat_resp.model,
                            "choices": choices
                        });
                        Json(legacy_resp).into_response()
                    }
                };
                return Ok(response);
            }
            ExecuteResult::Retry { error, should_rotate } => {
                last_error = error;
                force_rotate_next = should_rotate;
                continue;
            }
            ExecuteResult::FatalError { status, message } => {
                return Err((status, message));
            }
        }
    }

    Err((
        StatusCode::TOO_MANY_REQUESTS,
        format!("All accounts exhausted. Last error: {}", last_error),
    ))
}

pub async fn handle_chat_completions(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut openai_req: OpenAIRequest = serde_json::from_value(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)))?;

    // Safety: Ensure messages is not empty
    if openai_req.messages.is_empty() {
        debug!("Received request with empty messages, injecting fallback...");
        openai_req
            .messages
            .push(crate::proxy::mappers::openai::OpenAIMessage {
                role: "user".to_string(),
                content: Some(crate::proxy::mappers::openai::OpenAIContent::String(
                    " ".to_string(),
                )),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            });
    }

    debug!("Received OpenAI request for model: {}", openai_req.model);

    // Use shared execution function
    execute_with_retry(&state, &openai_req, ResponseFormat::Chat).await
}

/// Handle Legacy Completions API (/v1/completions)
/// Convert Prompt to Chat Message format, reuse handle_chat_completions
pub async fn handle_completions(
    State(state): State<AppState>,
    Json(mut body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!(
        "Received /v1/completions or /v1/responses payload: {:?}",
        body
    );

    let is_codex_style = body.get("input").is_some() && body.get("instructions").is_some();

    // 1. Convert Payload to Messages (Shared Chat Format)
    if is_codex_style {
        let instructions = body
            .get("instructions")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let input_items = body.get("input").and_then(|v| v.as_array());

        let mut messages = Vec::new();

        // System Instructions
        if !instructions.is_empty() {
            messages.push(json!({ "role": "system", "content": instructions }));
        }

        let mut call_id_to_name = std::collections::HashMap::new();

        // Pass 1: Build Call ID to Name Map
        if let Some(items) = input_items {
            for item in items {
                let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match item_type {
                    "function_call" | "local_shell_call" | "web_search_call" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.get("id").and_then(|v| v.as_str()))
                            .unwrap_or("unknown");

                        let name = if item_type == "local_shell_call" {
                            "shell"
                        } else if item_type == "web_search_call" {
                            "google_search"
                        } else {
                            item.get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        };

                        call_id_to_name.insert(call_id.to_string(), name.to_string());
                        tracing::debug!("Mapped call_id {} to name {}", call_id, name);
                    }
                    _ => {}
                }
            }
        }

        // Pass 2: Map Input Items to Messages
        if let Some(items) = input_items {
            for item in items {
                let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match item_type {
                    "message" => {
                        let role = item.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                        let content = item.get("content").and_then(|v| v.as_array());
                        let mut text_parts = Vec::new();
                        let mut image_parts: Vec<Value> = Vec::new();

                        if let Some(parts) = content {
                            for part in parts {
                                // Handle text blocks
                                if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                    text_parts.push(text.to_string());
                                }
                                // [NEW] Handle image blocks (Codex input_image format)
                                else if part.get("type").and_then(|v| v.as_str())
                                    == Some("input_image")
                                {
                                    if let Some(image_url) =
                                        part.get("image_url").and_then(|v| v.as_str())
                                    {
                                        image_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": { "url": image_url }
                                        }));
                                        debug!("[Codex] Found input_image: {}", image_url);
                                    }
                                }
                                // [NEW] Compatible with standard OpenAI image_url format
                                else if part.get("type").and_then(|v| v.as_str())
                                    == Some("image_url")
                                {
                                    if let Some(url_obj) = part.get("image_url") {
                                        image_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": url_obj.clone()
                                        }));
                                    }
                                }
                            }
                        }

                        // Build message content: use array format if there are images
                        if image_parts.is_empty() {
                            messages.push(json!({
                                "role": role,
                                "content": text_parts.join("\n")
                            }));
                        } else {
                            let mut content_blocks: Vec<Value> = Vec::new();
                            if !text_parts.is_empty() {
                                content_blocks.push(json!({
                                    "type": "text",
                                    "text": text_parts.join("\n")
                                }));
                            }
                            content_blocks.extend(image_parts);
                            messages.push(json!({
                                "role": role,
                                "content": content_blocks
                            }));
                        }
                    }
                    "function_call" | "local_shell_call" | "web_search_call" => {
                        let mut name = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let mut args_str = item
                            .get("arguments")
                            .and_then(|v| v.as_str())
                            .unwrap_or("{}")
                            .to_string();
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.get("id").and_then(|v| v.as_str()))
                            .unwrap_or("unknown");

                        // Handle native shell calls
                        if item_type == "local_shell_call" {
                            name = "shell";
                            if let Some(action) = item.get("action") {
                                if let Some(exec) = action.get("exec") {
                                    // Map to ShellCommandToolCallParams (string command) or ShellToolCallParams (array command)
                                    // Most LLMs prefer a single string for shell
                                    let mut args_obj = serde_json::Map::new();
                                    if let Some(cmd) = exec.get("command") {
                                        // CRITICAL FIX: The 'shell' tool schema defines 'command' as an ARRAY of strings.
                                        // We MUST pass it as an array, not a joined string, otherwise Gemini rejects with 400 INVALID_ARGUMENT.
                                        let cmd_val = if cmd.is_string() {
                                            json!([cmd]) // Wrap in array
                                        } else {
                                            cmd.clone() // Assume already array
                                        };
                                        args_obj.insert("command".to_string(), cmd_val);
                                    }
                                    if let Some(wd) =
                                        exec.get("working_directory").or(exec.get("workdir"))
                                    {
                                        args_obj.insert("workdir".to_string(), wd.clone());
                                    }
                                    args_str = serde_json::to_string(&args_obj)
                                        .unwrap_or("{}".to_string());
                                }
                            }
                        } else if item_type == "web_search_call" {
                            name = "google_search";
                            if let Some(action) = item.get("action") {
                                let mut args_obj = serde_json::Map::new();
                                if let Some(q) = action.get("query") {
                                    args_obj.insert("query".to_string(), q.clone());
                                }
                                args_str =
                                    serde_json::to_string(&args_obj).unwrap_or("{}".to_string());
                            }
                        }

                        messages.push(json!({
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": args_str
                                    }
                                }
                            ]
                        }));
                    }
                    "function_call_output" | "custom_tool_call_output" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let output = item.get("output");
                        let output_str = if let Some(o) = output {
                            if o.is_string() {
                                o.as_str().unwrap().to_string()
                            } else if let Some(content) = o.get("content").and_then(|v| v.as_str())
                            {
                                content.to_string()
                            } else {
                                o.to_string()
                            }
                        } else {
                            "".to_string()
                        };

                        let name = call_id_to_name.get(call_id).cloned().unwrap_or_else(|| {
                            // Fallback: if unknown and we see function_call_output, it's likely "shell" in this context
                            tracing::warn!(
                                "Unknown tool name for call_id {}, defaulting to 'shell'",
                                call_id
                            );
                            "shell".to_string()
                        });

                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": name,
                            "content": output_str
                        }));
                    }
                    _ => {}
                }
            }
        }

        if let Some(obj) = body.as_object_mut() {
            obj.insert("messages".to_string(), json!(messages));
        }
    } else if let Some(prompt_val) = body.get("prompt") {
        // Legacy OpenAI Style: prompt -> Chat
        let prompt_str = match prompt_val {
            Value::String(s) => s.clone(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            _ => prompt_val.to_string(),
        };
        let messages = json!([ { "role": "user", "content": prompt_str } ]);
        if let Some(obj) = body.as_object_mut() {
            obj.remove("prompt");
            obj.insert("messages".to_string(), messages);
        }
    }

    // 2. Parse request and use shared execution function
    let mut openai_req: OpenAIRequest = serde_json::from_value(body.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)))?;

    // Safety: Inject empty message if needed
    if openai_req.messages.is_empty() {
        openai_req
            .messages
            .push(crate::proxy::mappers::openai::OpenAIMessage {
                role: "user".to_string(),
                content: Some(crate::proxy::mappers::openai::OpenAIContent::String(
                    " ".to_string(),
                )),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            });
    }

    debug!("Received Completions request for model: {}", openai_req.model);

    // Select response format based on request type
    let response_format = if is_codex_style {
        ResponseFormat::Codex
    } else {
        ResponseFormat::LegacyCompletion
    };

    // Use shared execution function
    execute_with_retry(&state, &openai_req, response_format).await
}

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

/// OpenAI Images API: POST /v1/images/generations
/// Handle image generation request, transform to Gemini API format
pub async fn handle_images_generations(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Parse request parameters
    let prompt = body.get("prompt").and_then(|v| v.as_str()).ok_or((
        StatusCode::BAD_REQUEST,
        "Missing 'prompt' field".to_string(),
    ))?;

    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("gemini-3-pro-image");

    let n = body.get("n").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

    let size = body
        .get("size")
        .and_then(|v| v.as_str())
        .unwrap_or("1024x1024");

    let response_format = body
        .get("response_format")
        .and_then(|v| v.as_str())
        .unwrap_or("b64_json");

    let quality = body
        .get("quality")
        .and_then(|v| v.as_str())
        .unwrap_or("standard");
    let style = body
        .get("style")
        .and_then(|v| v.as_str())
        .unwrap_or("vivid");

    info!(
        "[Images] Received request: model={}, prompt={:.50}..., n={}, size={}, quality={}, style={}",
        model,
        prompt,
        n,
        size,
        quality,
        style
    );

    // 2. Parse size to aspect ratio
    let aspect_ratio = match size {
        "1792x768" | "2560x1080" => "21:9", // Ultra-wide
        "1792x1024" | "1920x1080" => "16:9",
        "1024x1792" | "1080x1920" => "9:16",
        "1024x768" | "1280x960" => "4:3",
        "768x1024" | "960x1280" => "3:4",
        _ => "1:1", // Default 1024x1024
    };

    // Prompt Enhancement
    let mut final_prompt = prompt.to_string();
    if quality == "hd" {
        final_prompt.push_str(", (high quality, highly detailed, 4k resolution, hdr)");
    }
    match style {
        "vivid" => final_prompt.push_str(", (vivid colors, dramatic lighting, rich details)"),
        "natural" => final_prompt.push_str(", (natural lighting, realistic, photorealistic)"),
        _ => {}
    }

    // 3. Get Token
    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;

    let selected = match token_manager
        .get_token("gemini", "image_gen", false, None)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Token error: {}", e),
            ))
        }
    };

    let access_token = selected.access_token;
    let project_id = selected.project_id;
    let email = selected.email;

    info!("✓ Using account: {} for image generation", email);

    // 4. Send concurrent requests (solve candidateCount > 1 not supported issue)
    let mut tasks = Vec::new();

    for _ in 0..n {
        let upstream = upstream.clone();
        let access_token = access_token.clone();
        let project_id = project_id.clone();
        let final_prompt = final_prompt.clone();
        let aspect_ratio = aspect_ratio.to_string();
        let _response_format = response_format.to_string();

        tasks.push(tokio::spawn(async move {
            let gemini_body = json!({
                "project": project_id,
                "requestId": format!("img-{}", uuid::Uuid::new_v4()),
                "model": "gemini-3-pro-image",
                "userAgent": "antigravity",
                "requestType": "image_gen",
                "request": {
                    "contents": [{
                        "role": "user",
                        "parts": [{"text": final_prompt}]
                    }],
                    "generationConfig": {
                        "candidateCount": 1, // Force single image
                        "imageConfig": {
                            "aspectRatio": aspect_ratio
                        }
                    },
                    "safetySettings": [
                        { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF" },
                        { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF" },
                        { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF" },
                        { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF" },
                        { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "OFF" },
                    ]
                }
            });

            match upstream
                .call_v1_internal("generateContent", &access_token, gemini_body, None)
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if !status.is_success() {
                        let err_text = response.text().await.unwrap_or_default();
                        return Err(format!("Upstream error {}: {}", status, err_text));
                    }
                    match response.json::<Value>().await {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("Parse error: {}", e)),
                    }
                }
                Err(e) => Err(format!("Network error: {}", e)),
            }
        }));
    }

    // 5. Collect results
    let mut images: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (idx, task) in tasks.into_iter().enumerate() {
        match task.await {
            Ok(result) => match result {
                Ok(gemini_resp) => {
                    let raw = gemini_resp.get("response").unwrap_or(&gemini_resp);
                    if let Some(parts) = raw
                        .get("candidates")
                        .and_then(|c| c.get(0))
                        .and_then(|cand| cand.get("content"))
                        .and_then(|content| content.get("parts"))
                        .and_then(|p| p.as_array())
                    {
                        for part in parts {
                            if let Some(img) = part.get("inlineData") {
                                let data = img.get("data").and_then(|v| v.as_str()).unwrap_or("");
                                if !data.is_empty() {
                                    if response_format == "url" {
                                        let mime_type = img
                                            .get("mimeType")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("image/png");
                                        images.push(json!({
                                            "url": format!("data:{};base64,{}", mime_type, data)
                                        }));
                                    } else {
                                        images.push(json!({
                                            "b64_json": data
                                        }));
                                    }
                                    tracing::debug!("[Images] Task {} succeeded", idx);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("[Images] Task {} failed: {}", idx, e);
                    errors.push(e);
                }
            },
            Err(e) => {
                let err_msg = format!("Task join error: {}", e);
                tracing::error!("[Images] Task {} join error: {}", idx, e);
                errors.push(err_msg);
            }
        }
    }

    if images.is_empty() {
        let error_msg = if !errors.is_empty() {
            errors.join("; ")
        } else {
            "No images generated".to_string()
        };
        tracing::error!("[Images] All {} requests failed. Errors: {}", n, error_msg);
        return Err((StatusCode::BAD_GATEWAY, error_msg));
    }

    // Log warning on partial success
    if !errors.is_empty() {
        tracing::warn!(
            "[Images] Partial success: {} out of {} requests succeeded. Errors: {}",
            images.len(),
            n,
            errors.join("; ")
        );
    }

    tracing::info!(
        "[Images] Successfully generated {} out of {} requested image(s)",
        images.len(),
        n
    );

    // 6. Build OpenAI format response
    let openai_response = json!({
        "created": chrono::Utc::now().timestamp(),
        "data": images
    });

    Ok(Json(openai_response))
}

pub async fn handle_images_edits(
    State(state): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("[Images] Received edit request");

    let mut image_data = None;
    let mut mask_data = None;
    let mut prompt = String::new();
    let mut n = 1;
    let mut size = "1024x1024".to_string();
    let mut response_format = "b64_json".to_string(); // Default to b64_json for better compatibility with tools handling edits
    let mut model = "gemini-3-pro-image".to_string();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        if name == "image" {
            let data = field
                .bytes()
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Image read error: {}", e)))?;
            image_data = Some(base64::engine::general_purpose::STANDARD.encode(data));
        } else if name == "mask" {
            let data = field
                .bytes()
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Mask read error: {}", e)))?;
            mask_data = Some(base64::engine::general_purpose::STANDARD.encode(data));
        } else if name == "prompt" {
            prompt = field
                .text()
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Prompt read error: {}", e)))?;
        } else if name == "n" {
            if let Ok(val) = field.text().await {
                n = val.parse().unwrap_or(1);
            }
        } else if name == "size" {
            if let Ok(val) = field.text().await {
                size = val;
            }
        } else if name == "response_format" {
            if let Ok(val) = field.text().await {
                response_format = val;
            }
        } else if name == "model" {
            if let Ok(val) = field.text().await {
                if !val.is_empty() {
                    model = val;
                }
            }
        }
    }

    if image_data.is_none() {
        return Err((StatusCode::BAD_REQUEST, "Missing image".to_string()));
    }
    if prompt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Missing prompt".to_string()));
    }

    tracing::info!(
        "[Images] Edit Request: model={}, prompt={}, n={}, size={}, mask={}, response_format={}",
        model,
        prompt,
        n,
        size,
        mask_data.is_some(),
        response_format
    );

    // FIX: Client Display Issue
    // Cherry Studio (and potentially others) might accept Data URI for generations but display raw text for edits
    // if 'url' format is used with a data-uri.
    // If request asks for 'url' but we are a local proxy, returning b64_json is often safer for correct rendering if the client supports it.
    // However, strictly following spec means 'url' should be 'url'.
    // Let's rely on client requesting the right thing, BUT allow a server-side heuristic:
    // If we simply return b64_json structure even if url was requested? No, that breaks spec.
    // Instead, let's assume successful clients request b64_json.
    // But if users see raw text, it means client defaulted to 'url' or we defaulted to 'url'.
    // Let's keep the log to confirm.

    // 1. Get Upstream
    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;
    // Fix: Proper get_token call with correct signature and unwrap (using image_gen quota)
    let selected = match token_manager
        .get_token("gemini", "image_gen", false, None)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Token error: {}", e),
            ))
        }
    };
    let access_token = selected.access_token;
    let project_id = selected.project_id;

    // 2. Map configuration
    let mut contents_parts = Vec::new();

    contents_parts.push(json!({
        "text": format!("Edit this image: {}", prompt)
    }));

    if let Some(data) = image_data {
        contents_parts.push(json!({
            "inlineData": {
                "mimeType": "image/png",
                "data": data
            }
        }));
    }

    if let Some(data) = mask_data {
        contents_parts.push(json!({
            "inlineData": {
                "mimeType": "image/png",
                "data": data
            }
        }));
    }

    // Build Gemini internal API Body (Envelope Structure)
    let gemini_body = json!({
        "project": project_id,
        "requestId": format!("img-edit-{}", uuid::Uuid::new_v4()),
        "model": model,
        "userAgent": "antigravity",
        "requestType": "image_gen",
        "request": {
            "contents": [{
                "role": "user",
                "parts": contents_parts
            }],
            "generationConfig": {
                "candidateCount": 1,
                "maxOutputTokens": 8192,
                "stopSequences": [],
                "temperature": 1.0,
                "topP": 0.95,
                "topK": 40
            },
            "safetySettings": [
                { "category": "HARM_CATEGORY_HARASSMENT", "threshold": "OFF" },
                { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "OFF" },
                { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "OFF" },
                { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "OFF" },
                { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "OFF" },
            ]
        }
    });

    let mut tasks = Vec::new();
    for _ in 0..n {
        let upstream = upstream.clone();
        let access_token = access_token.clone();
        let body = gemini_body.clone();

        tasks.push(tokio::spawn(async move {
            match upstream
                .call_v1_internal("generateContent", &access_token, body, None)
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if !status.is_success() {
                        let err_text = response.text().await.unwrap_or_default();
                        return Err(format!("Upstream error {}: {}", status, err_text));
                    }
                    match response.json::<Value>().await {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("Parse error: {}", e)),
                    }
                }
                Err(e) => Err(format!("Network error: {}", e)),
            }
        }));
    }

    let mut images: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (idx, task) in tasks.into_iter().enumerate() {
        match task.await {
            Ok(result) => match result {
                Ok(gemini_resp) => {
                    let raw = gemini_resp.get("response").unwrap_or(&gemini_resp);
                    if let Some(parts) = raw
                        .get("candidates")
                        .and_then(|c| c.get(0))
                        .and_then(|cand| cand.get("content"))
                        .and_then(|content| content.get("parts"))
                        .and_then(|p| p.as_array())
                    {
                        for part in parts {
                            if let Some(img) = part.get("inlineData") {
                                let data = img.get("data").and_then(|v| v.as_str()).unwrap_or("");
                                if !data.is_empty() {
                                    if response_format == "url" {
                                        let mime_type = img
                                            .get("mimeType")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("image/png");
                                        images.push(json!({
                                            "url": format!("data:{};base64,{}", mime_type, data)
                                        }));
                                    } else {
                                        images.push(json!({
                                            "b64_json": data
                                        }));
                                    }
                                    tracing::debug!("[Images] Task {} succeeded", idx);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("[Images] Task {} failed: {}", idx, e);
                    errors.push(e);
                }
            },
            Err(e) => {
                let err_msg = format!("Task join error: {}", e);
                tracing::error!("[Images] Task {} join error: {}", idx, e);
                errors.push(err_msg);
            }
        }
    }

    if images.is_empty() {
        let error_msg = if !errors.is_empty() {
            errors.join("; ")
        } else {
            "No images generated".to_string()
        };
        tracing::error!(
            "[Images] All {} edit requests failed. Errors: {}",
            n,
            error_msg
        );
        return Err((StatusCode::BAD_GATEWAY, error_msg));
    }

    if !errors.is_empty() {
        tracing::warn!(
            "[Images] Partial success: {} out of {} requests succeeded. Errors: {}",
            images.len(),
            n,
            errors.join("; ")
        );
    }

    tracing::info!(
        "[Images] Successfully generated {} out of {} requested edited image(s)",
        images.len(),
        n
    );

    let openai_response = json!({
        "created": chrono::Utc::now().timestamp(),
        "data": images
    });

    Ok(Json(openai_response))
}
