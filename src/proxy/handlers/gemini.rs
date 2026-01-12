// Gemini Handler
use axum::{extract::State, extract::{Json, Path}, http::StatusCode, response::IntoResponse};
use serde_json::{json, Value};
use tracing::{debug, error, info};

use crate::proxy::mappers::gemini::{wrap_request, unwrap_response};
use crate::proxy::server::AppState;
use crate::proxy::session_manager::SessionManager;
 
const MAX_RETRY_ATTEMPTS: usize = 3;
 
/// Handle generateContent and streamGenerateContent
/// Path parameters: model_name, method (e.g. "gemini-pro", "generateContent")
pub async fn handle_generate(
    State(state): State<AppState>,
    Path(model_action): Path<String>,
    Json(body): Json<Value>
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Parse model:method
    let (model_name, method) = if let Some((m, action)) = model_action.rsplit_once(':') {
        (m.to_string(), action.to_string())
    } else {
        (model_action, "generateContent".to_string())
    };

    crate::modules::logger::log_info(&format!("Received Gemini request: {}/{}", model_name, method));

    // 1. Validate method
    if method != "generateContent" && method != "streamGenerateContent" {
        return Err((StatusCode::BAD_REQUEST, format!("Unsupported method: {}", method)));
    }
    let is_stream = method == "streamGenerateContent";

    // 2. Get UpstreamClient and TokenManager
    let upstream = state.upstream.clone();
    let token_manager = state.token_manager;
    let pool_size = token_manager.len();
    let max_attempts = MAX_RETRY_ATTEMPTS.min(pool_size).max(1);

    // [CRITICAL FIX] Pre-calculate session_id to ensure it doesn't change on retry
    let stable_session_id = SessionManager::extract_gemini_session_id(&body, &model_name);

    let mut last_error = String::new();
    let mut force_rotate_next = false;  // Control whether to rotate account on next iteration

    for attempt in 0..max_attempts {
        // 3. Model routing and configuration parsing
        let mapped_model = crate::proxy::common::model_mapping::resolve_model_route(
            &model_name,
            &*state.custom_mapping.read().await,
            &*state.openai_mapping.read().await,
            &*state.anthropic_mapping.read().await,
            false,  // Gemini requests don't apply Claude family mapping
        );
        // Extract tools list for web search detection (Gemini style may be nested)
        let tools_val: Option<Vec<Value>> = body.get("tools").and_then(|t| t.as_array()).map(|arr| {
            let mut flattened = Vec::new();
            for tool_entry in arr {
                if let Some(decls) = tool_entry.get("functionDeclarations").and_then(|v| v.as_array()) {
                    flattened.extend(decls.iter().cloned());
                } else {
                    flattened.push(tool_entry.clone());
                }
            }
            flattened
        });

        let config = crate::proxy::mappers::common_utils::resolve_request_config(&model_name, &mapped_model, &tools_val);

        // 4. Get Token (using pre-calculated session_id and force_rotate_next)
        let quota_group = "gemini";
        let selected = match token_manager
            .get_token(quota_group, &config.request_type, force_rotate_next, Some(&stable_session_id))
            .await
        {
            Ok(t) => t,
            Err(e) => {
                return Err((StatusCode::SERVICE_UNAVAILABLE, format!("Token error: {}", e)));
            }
        };

        let access_token = selected.access_token;
        let project_id = selected.project_id;
        let email = selected.email;
        let account_id = selected.account_id;

        info!("✓ Using account: {} (type: {})", email, config.request_type);

        // 5. Wrap request (project injection)
        let wrapped_body = wrap_request(&body, &project_id, &mapped_model);

        // 5. Upstream call
        let query_string = if is_stream { Some("alt=sse") } else { None };
        let upstream_method = if is_stream { "streamGenerateContent" } else { "generateContent" };

        let response = match upstream
            .call_v1_internal(upstream_method, &access_token, wrapped_body, query_string)
            .await {
                Ok(r) => r,
                Err(e) => {
                    last_error = e.clone();
                    debug!("Gemini Request failed on attempt {}/{}: {}", attempt + 1, max_attempts, e);
                    continue;
                }
            };

        let status = response.status();
        if status.is_success() {
            // 6. Response handling
            if is_stream {
                use axum::body::Body;
                use axum::response::Response;
                use bytes::{Bytes, BytesMut};
                use futures::StreamExt;
                
                let mut response_stream = response.bytes_stream();
                let mut buffer = BytesMut::new();

                let stream = async_stream::stream! {
                    while let Some(item) = response_stream.next().await {
                        match item {
                            Ok(bytes) => {
                                debug!("[Gemini-SSE] Received chunk: {} bytes", bytes.len());
                                buffer.extend_from_slice(&bytes);
                                while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                                    let line_raw = buffer.split_to(pos + 1);
                                    if let Ok(line_str) = std::str::from_utf8(&line_raw) {
                                        let line = line_str.trim();
                                        if line.is_empty() { continue; }
                                        
                                        if line.starts_with("data: ") {
                                            let json_part = line.trim_start_matches("data: ").trim();
                                            if json_part == "[DONE]" {
                                                yield Ok::<Bytes, String>(Bytes::from("data: [DONE]\n\n"));
                                                continue;
                                            }
                                            
                                            match serde_json::from_str::<Value>(json_part) {
                                                Ok(mut json) => {
                                                    // Unwrap v1internal response wrapper
                                                    if let Some(inner) = json.get_mut("response").map(|v| v.take()) {
                                                        let new_line = format!("data: {}\n\n", serde_json::to_string(&inner).unwrap_or_default());
                                                        yield Ok::<Bytes, String>(Bytes::from(new_line));
                                                    } else {
                                                        yield Ok::<Bytes, String>(Bytes::from(format!("data: {}\n\n", serde_json::to_string(&json).unwrap_or_default())));
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!("[Gemini-SSE] JSON parse error: {}, passing raw line", e);
                                                    yield Ok::<Bytes, String>(Bytes::from(format!("{}\n\n", line)));
                                                }
                                            }
                                        } else {
                                            // Non-data lines (comments, etc.)
                                            yield Ok::<Bytes, String>(Bytes::from(format!("{}\n\n", line)));
                                        }
                                    } else {
                                        // Non-UTF8 data? Just pass it through or skip
                                        debug!("[Gemini-SSE] Non-UTF8 line encountered");
                                        yield Ok::<Bytes, String>(line_raw.freeze());
                                    }
                                }
                            }
                            Err(e) => {
                                error!("[Gemini-SSE] Connection error: {}", e);
                                yield Err(format!("Stream error: {}", e));
                            }
                        }
                    }
                };
                
                let body = Body::from_stream(stream);
                return Ok(Response::builder()
                    .header("Content-Type", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                    .header("Connection", "keep-alive")
                    .body(body)
                    .unwrap()
                    .into_response());
            }

            let gemini_resp: Value = response
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {}", e)))?;

            let unwrapped = unwrap_response(&gemini_resp);
            return Ok(Json(unwrapped).into_response());
        }

        // Handle error and retry
        let status_code = status.as_u16();
        let retry_after = response.headers().get("Retry-After").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
        let error_text = response.text().await.unwrap_or_else(|_| format!("HTTP {}", status_code));
        last_error = format!("HTTP {}: {}", status_code, error_text);

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

        // Only 429 (rate limit), 529 (overload), 503, 403 (permission) and 401 (auth failure) trigger retry
        if status_code == 429 || status_code == 529 || status_code == 503 || status_code == 500 || status_code == 403 || status_code == 401 {
            // Record rate limit info (global sync)
            token_manager.mark_rate_limited(
                quota_group,
                &config.request_type,
                &account_id,
                status_code,
                retry_after.as_deref(),
                &error_text,
            );

            // Determine whether to rotate account based on error type
            force_rotate_next = should_rotate_account(status_code);
            tracing::warn!(
                "Gemini Upstream {} on account {}, will rotate: {}",
                status_code, email, force_rotate_next
            );
            continue;
        }

        // 404 etc. HTTP errors due to model config or path errors, return error directly without invalid rotation
        error!("Gemini Upstream non-retryable error {}: {}", status_code, error_text);
        return Err((status, error_text));
    }

    Ok((StatusCode::TOO_MANY_REQUESTS, format!("All accounts exhausted. Last error: {}", last_error)).into_response())
}

pub async fn handle_list_models(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    use crate::proxy::common::model_mapping::get_all_dynamic_models;

    // Get all dynamic model list (consistent with /v1/models)
    let model_ids = get_all_dynamic_models(
        &state.openai_mapping,
        &state.custom_mapping,
        &state.anthropic_mapping,
    ).await;

    // Convert to Gemini API format
    let models: Vec<_> = model_ids.into_iter().map(|id| {
        json!({
            "name": format!("models/{}", id),
            "version": "001",
            "displayName": id.clone(),
            "description": "",
            "inputTokenLimit": 128000,
            "outputTokenLimit": 8192,
            "supportedGenerationMethods": ["generateContent", "countTokens"],
            "temperature": 1.0,
            "topP": 0.95,
            "topK": 64
        })
    }).collect();

    Ok(Json(json!({ "models": models })))
}

pub async fn handle_get_model(Path(model_name): Path<String>) -> impl IntoResponse {
    Json(json!({
        "name": format!("models/{}", model_name),
        "displayName": model_name
    }))
}

pub async fn handle_count_tokens(State(state): State<AppState>, Path(_model_name): Path<String>, Json(_body): Json<Value>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = state
        .token_manager
        .get_token("gemini", "agent", false, None)
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, format!("Token error: {}", e)))?;
    
    Ok(Json(json!({"totalTokens": 0})))
}
