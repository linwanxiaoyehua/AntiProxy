// Claude request transformation (Claude → Gemini v1internal)
// Corresponds to transformClaudeRequestIn

use super::models::*;
use crate::proxy::mappers::signature_store::get_thought_signature;
use serde_json::{json, Value};
use std::collections::HashMap;

// ===== Safety Settings Configuration =====

/// Safety threshold levels for Gemini API
/// Can be configured via GEMINI_SAFETY_THRESHOLD environment variable
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SafetyThreshold {
    /// Disable all safety filters (default for proxy compatibility)
    Off,
    /// Block low probability and above
    BlockLowAndAbove,
    /// Block medium probability and above
    BlockMediumAndAbove,
    /// Only block high probability content
    BlockOnlyHigh,
    /// Don't block anything (BLOCK_NONE)
    BlockNone,
}

impl SafetyThreshold {
    /// Get threshold from environment variable or default to Off
    pub fn from_env() -> Self {
        match std::env::var("GEMINI_SAFETY_THRESHOLD").as_deref() {
            Ok("OFF") | Ok("off") => SafetyThreshold::Off,
            Ok("LOW") | Ok("low") => SafetyThreshold::BlockLowAndAbove,
            Ok("MEDIUM") | Ok("medium") => SafetyThreshold::BlockMediumAndAbove,
            Ok("HIGH") | Ok("high") => SafetyThreshold::BlockOnlyHigh,
            Ok("NONE") | Ok("none") => SafetyThreshold::BlockNone,
            _ => SafetyThreshold::Off, // Default: maintain current behavior
        }
    }

    /// Convert to Gemini API threshold string
    pub fn to_gemini_threshold(&self) -> &'static str {
        match self {
            SafetyThreshold::Off => "OFF",
            SafetyThreshold::BlockLowAndAbove => "BLOCK_LOW_AND_ABOVE",
            SafetyThreshold::BlockMediumAndAbove => "BLOCK_MEDIUM_AND_ABOVE",
            SafetyThreshold::BlockOnlyHigh => "BLOCK_ONLY_HIGH",
            SafetyThreshold::BlockNone => "BLOCK_NONE",
        }
    }
}

/// Build safety settings based on configuration
fn build_safety_settings() -> Value {
    let threshold = SafetyThreshold::from_env();
    let threshold_str = threshold.to_gemini_threshold();

    json!([
        { "category": "HARM_CATEGORY_HARASSMENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_HATE_SPEECH", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": threshold_str },
        { "category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": threshold_str },
    ])
}

/// Clean cache_control fields from messages
///
/// This function deeply traverses all message content blocks and removes cache_control fields.
/// This is necessary because:
/// 1. Clients like VS Code send back historical messages (containing cache_control) unchanged
/// 2. Anthropic API does not accept cache_control fields in requests
/// 3. Even when forwarding to Gemini, cleaning is needed to maintain protocol purity
fn clean_cache_control_from_messages(messages: &mut [Message]) {
    for msg in messages.iter_mut() {
        if let MessageContent::Array(blocks) = &mut msg.content {
            for block in blocks.iter_mut() {
                match block {
                    ContentBlock::Thinking { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!("[Cache-Control-Cleaner] Removed cache_control from Thinking block");
                            *cache_control = None;
                        }
                    }
                    ContentBlock::Image { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!("[Cache-Control-Cleaner] Removed cache_control from Image block");
                            *cache_control = None;
                        }
                    }
                    ContentBlock::Document { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!("[Cache-Control-Cleaner] Removed cache_control from Document block");
                            *cache_control = None;
                        }
                    }
                    ContentBlock::ToolUse { cache_control, .. } => {
                        if cache_control.is_some() {
                            tracing::debug!("[Cache-Control-Cleaner] Removed cache_control from ToolUse block");
                            *cache_control = None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Transform Claude request to Gemini v1internal format
pub fn transform_claude_request_in(
    claude_req: &ClaudeRequest,
    project_id: &str,
) -> Result<Value, String> {
    // [CRITICAL FIX] Pre-clean all cache_control fields from messages
    // This fixes the "Extra inputs are not permitted" error caused by clients like VS Code
    // sending back historical messages with cache_control fields unchanged in multi-turn conversations
    let mut cleaned_req = claude_req.clone();
    clean_cache_control_from_messages(&mut cleaned_req.messages);
    let claude_req = &cleaned_req; // Use the cleaned request going forward

    // Detect if there's a web search tool (server tool or built-in tool)
    let has_web_search_tool = claude_req
        .tools
        .as_ref()
        .map(|tools| {
            tools.iter().any(|t| {
                t.is_web_search() 
                    || t.name.as_deref() == Some("google_search")
                    || t.type_.as_deref() == Some("web_search_20250305")
            })
        })
        .unwrap_or(false);

    // Store tool_use id -> name mapping
    let mut tool_id_to_name: HashMap<String, String> = HashMap::new();

    // 1. System Instruction (inject dynamic identity protection)
    let system_instruction = build_system_instruction(&claude_req.system, &claude_req.model);

    //  Map model name (Use standard mapping)
    // [IMPROVED] Extract web search model as constant for easier maintenance
    const WEB_SEARCH_FALLBACK_MODEL: &str = "gemini-2.5-flash";

    let mapped_model = if has_web_search_tool {
        tracing::debug!(
            "[Claude-Request] Web search tool detected, using fallback model: {}",
            WEB_SEARCH_FALLBACK_MODEL
        );
        WEB_SEARCH_FALLBACK_MODEL.to_string()
    } else {
        crate::proxy::common::model_mapping::map_claude_model_to_gemini(&claude_req.model)
    };
    
    // Convert Claude tools to Value array for web search detection
    let tools_val: Option<Vec<Value>> = claude_req.tools.as_ref().map(|list| {
        list.iter().map(|t| serde_json::to_value(t).unwrap_or(json!({}))).collect()
    });


    // Resolve grounding config
    let config = crate::proxy::mappers::common_utils::resolve_request_config(&claude_req.model, &mapped_model, &tools_val);
    
    // [CRITICAL FIX] Disable dummy thought injection for Vertex AI
    // [CRITICAL FIX] Disable dummy thought injection for Vertex AI
    // Vertex AI rejects thinking blocks without valid signatures
    // Even if thinking is enabled, we should NOT inject dummy blocks for historical messages
    let allow_dummy_thought = false;
    
    // Check if thinking is enabled in the request
    let mut is_thinking_enabled = claude_req
        .thinking
        .as_ref()
        .map(|t| t.type_ == "enabled")
        .unwrap_or_else(|| {
            // [Claude Code v2.0.67+] Default thinking enabled for Opus 4.5
            // If no thinking config is provided, enable by default for Opus models
            should_enable_thinking_by_default(&claude_req.model)
        });

    // [NEW FIX] Check if target model supports thinking
    // Only models with "-thinking" suffix or Claude models support thinking
    // Regular Gemini models (gemini-2.5-flash, gemini-2.5-pro) do NOT support thinking
    let target_model_supports_thinking = mapped_model.contains("-thinking") 
        || mapped_model.starts_with("claude-");
    
    if is_thinking_enabled && !target_model_supports_thinking {
        tracing::warn!(
            "[Thinking-Mode] Target model '{}' does not support thinking. Force disabling thinking mode.",
            mapped_model
        );
        is_thinking_enabled = false;
    }

    // [New Strategy] Smart downgrade: Check if history messages are compatible with Thinking mode
    // If in a tool call chain without Thinking, must temporarily disable Thinking
    if is_thinking_enabled {
        let should_disable = should_disable_thinking_due_to_history(&claude_req.messages);
        if should_disable {
             tracing::warn!("[Thinking-Mode] Automatically disabling thinking checks due to incompatible tool-use history (mixed application)");
             is_thinking_enabled = false;
        }
    }

    // [FIX #295 & #298] If thinking enabled but no signature available,
    // disable thinking to prevent Gemini 3 Pro rejection
    if is_thinking_enabled {
        let global_sig = get_thought_signature();
        
        // Check if there are any thinking blocks in message history
        let has_thinking_history = claude_req.messages.iter().any(|m| {
            if m.role == "assistant" {
                if let MessageContent::Array(blocks) = &m.content {
                    return blocks.iter().any(|b| matches!(b, ContentBlock::Thinking { .. }));
                }
            }
            false
        });
        
        // Check if there are function calls in the request
        let has_function_calls = claude_req.messages.iter().any(|m| {
            if let MessageContent::Array(blocks) = &m.content {
                blocks
                    .iter()
                    .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
            } else {
                false
            }
        });

        // [FIX #298] For first-time thinking requests (no thinking history),
        // always check for valid signature to prevent API rejection
        // [FIX #295] For requests with function calls, also require valid signature
        let needs_signature_check = !has_thinking_history || has_function_calls;
        
        if needs_signature_check
            && !has_valid_signature_for_function_calls(&claude_req.messages, &global_sig)
        {
            if !has_thinking_history {
                tracing::warn!(
                    "[Thinking-Mode] [FIX #298] First thinking request without valid signature. \
                     Disabling thinking to prevent API rejection."
                );
            } else {
                tracing::warn!(
                    "[Thinking-Mode] [FIX #295] No valid signature found for function calls. \
                     Disabling thinking to prevent Gemini 3 Pro rejection."
                );
            }
            is_thinking_enabled = false;
        }
    }

    // 4. Generation Config & Thinking (pass final is_thinking_enabled)
    let generation_config = build_generation_config(claude_req, has_web_search_tool, is_thinking_enabled);

    // 2. Contents (Messages)
    let contents = build_contents(
        &claude_req.messages,
        &mut tool_id_to_name,
        is_thinking_enabled,
        allow_dummy_thought,
    )?;

    // 3. Tools
    let tools = build_tools(&claude_req.tools, has_web_search_tool)?;

    // 5. Safety Settings (configurable via GEMINI_SAFETY_THRESHOLD env var)
    let safety_settings = build_safety_settings();

    // Build inner request
    let mut inner_request = json!({
        "contents": contents,
        "safetySettings": safety_settings,
    });

    // Deep clean [undefined] strings (common injection from clients like Cherry Studio)
    crate::proxy::mappers::common_utils::deep_clean_undefined(&mut inner_request);

    if let Some(sys_inst) = system_instruction {
        inner_request["systemInstruction"] = sys_inst;
    }

    if !generation_config.is_null() {
        inner_request["generationConfig"] = generation_config;
    }

    if let Some(tools_val) = tools {
        inner_request["tools"] = tools_val;
        // Explicitly set tool config mode to VALIDATED
        inner_request["toolConfig"] = json!({
            "functionCallingConfig": {
                "mode": "VALIDATED"
            }
        });
    }

    // Inject googleSearch tool if needed (and not already done by build_tools)
    if config.inject_google_search && !has_web_search_tool {
        crate::proxy::mappers::common_utils::inject_google_search_tool(&mut inner_request);
    }

    // Inject imageConfig if present (for image generation models)
    if let Some(image_config) = config.image_config {
        if let Some(obj) = inner_request.as_object_mut() {
            // 1. Remove tools (image generation does not support tools)
            obj.remove("tools");

            // 2. Remove systemInstruction (image generation does not support system prompts)
            obj.remove("systemInstruction");

            // 3. Clean generationConfig (remove thinkingConfig, responseMimeType, responseModalities etc.)
            let gen_config = obj.entry("generationConfig").or_insert_with(|| json!({}));
            if let Some(gen_obj) = gen_config.as_object_mut() {
                gen_obj.remove("thinkingConfig");
                gen_obj.remove("responseMimeType");
                gen_obj.remove("responseModalities");
                gen_obj.insert("imageConfig".to_string(), image_config);
            }
        }
    }

    // Generate requestId
    let request_id = format!("agent-{}", uuid::Uuid::new_v4());

    // Build final request body
    let mut body = json!({
        "project": project_id,
        "requestId": request_id,
        "request": inner_request,
        "model": config.final_model,
        "userAgent": "antigravity",
        "requestType": config.request_type,
    });

    // If metadata.user_id is provided, reuse it as sessionId
    if let Some(metadata) = &claude_req.metadata {
        if let Some(user_id) = &metadata.user_id {
            body["request"]["sessionId"] = json!(user_id);
        }
    }


    Ok(body)
}

/// Check if Thinking should be disabled due to history messages
///
/// Scenario: If the last Assistant message is in a Tool Use flow but has no Thinking block,
/// it indicates this flow was initiated by a non-Thinking model. Forcing Thinking on would cause:
/// "final assistant message must start with a thinking block" error.
/// We cannot forge legitimate Thinking (due to signature issues), so the only solution is to temporarily disable Thinking for this request.
fn should_disable_thinking_due_to_history(messages: &[Message]) -> bool {
    // Find the last Assistant message in reverse order
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                let has_tool_use = blocks.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. }));
                let has_thinking = blocks.iter().any(|b| matches!(b, ContentBlock::Thinking { .. }));
                
                // If there's tool use but no Thinking block -> incompatible
                if has_tool_use && !has_thinking {
                    tracing::info!("[Thinking-Mode] Detected ToolUse without Thinking in history. Requesting disable.");
                    return true;
                }
            }
            // End check once we find the most recent Assistant message
            // because validation rules mainly target the current closed-loop state
            return false;
        }
    }
    false
}

/// Check if thinking mode should be enabled by default for a given model
///
/// Claude Code v2.0.67+ enables thinking by default for Opus 4.5 models.
/// This function determines if the model should have thinking enabled
/// when no explicit thinking configuration is provided.
fn should_enable_thinking_by_default(model: &str) -> bool {
    let model_lower = model.to_lowercase();

    // Enable thinking by default for Opus 4.5 variants
    if model_lower.contains("opus-4-5") || model_lower.contains("opus-4.5") {
        tracing::debug!(
            "[Thinking-Mode] Auto-enabling thinking for Opus 4.5 model: {}",
            model
        );
        return true;
    }

    // Also enable for explicit thinking model variants
    if model_lower.contains("-thinking") {
        return true;
    }

    false
}

/// Minimum length for a valid thought_signature
const MIN_SIGNATURE_LENGTH: usize = 10;

/// [FIX #295] Check if we have any valid signature available for function calls
/// This prevents Gemini 3 Pro from rejecting requests due to missing thought_signature
fn has_valid_signature_for_function_calls(
    messages: &[Message],
    global_sig: &Option<String>,
) -> bool {
    // 1. Check global store
    if let Some(sig) = global_sig {
        if sig.len() >= MIN_SIGNATURE_LENGTH {
            return true;
        }
    }

    // 2. Check if any message has a thinking block with valid signature
    for msg in messages.iter().rev() {
        if msg.role == "assistant" {
            if let MessageContent::Array(blocks) = &msg.content {
                for block in blocks {
                    if let ContentBlock::Thinking {
                        signature: Some(sig),
                        ..
                    } = block
                    {
                        if sig.len() >= MIN_SIGNATURE_LENGTH {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Build System Instruction
/// [FIX] Following CLIProxyAPI fix: use fixed Antigravity identity text
fn build_system_instruction(_system: &Option<SystemPrompt>, _model_name: &str) -> Option<Value> {
    // [CRITICAL FIX] CLIProxyAPI uses fixed identity text to replace the entire systemInstruction
    // This is key to resolving 429 errors!
    let antigravity_identity = r#"<identity>
You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.
You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.
The USER will send you requests, which you must always prioritize addressing. Along with each USER request, we will attach additional metadata about their current state, such as what files they have open and where their cursor is.
This information may or may not be relevant to the coding task, it is up for you to decide.
</identity>

<tool_calling>
Call tools as you normally would. The following list provides additional guidance to help you avoid errors:
  - **Absolute paths only**. When using tools that accept file path arguments, ALWAYS use the absolute file path.
</tool_calling>

<communication_style>
- **Formatting**. Format your responses in github-style markdown to make your responses easier for the USER to parse. For example, use headers to organize your responses and bolded or italicized text to highlight important keywords. Use backticks to format file, directory, function, and class names. If providing a URL to the user, format this in markdown as well, for example `[label](example.com)`.
- **Proactiveness**. As an agent, you are allowed to be proactive, but only in the course of completing the user's task. For example, if the user asks you to add a new component, you can edit the code, verify build and test statuses, and take any other obvious follow-up actions, such as performing additional research. However, avoid surprising the user. For example, if the user asks HOW to approach something, you should answer their question and instead of jumping into editing a file.
- **Helpfulness**. Respond like a helpful software engineer who is explaining your work to a friendly collaborator on the project. Acknowledge mistakes or any backtracking you do as a result of new information.
- **Ask for clarification**. If you are unsure about the USER's intent, always ask for clarification rather than making assumptions.
</communication_style>"#;

    Some(json!({
        "role": "user",
        "parts": [{"text": antigravity_identity}]
    }))
}

/// Build Contents (Messages)
fn build_contents(
    messages: &[Message],
    tool_id_to_name: &mut HashMap<String, String>,
    is_thinking_enabled: bool,
    allow_dummy_thought: bool,
) -> Result<Value, String> {
    let mut contents = Vec::new();
    let mut last_thought_signature: Option<String> = None;

    let _msg_count = messages.len();
    for (_i, msg) in messages.iter().enumerate() {
        let role = if msg.role == "assistant" {
            "model"
        } else {
            &msg.role
        };

        let mut parts = Vec::new();

        match &msg.content {
            MessageContent::String(text) => {
                if text != "(no content)" {
                    if !text.trim().is_empty() {
                        parts.push(json!({"text": text.trim()}));
                    }
                }
            }
            MessageContent::Array(blocks) => {
                for item in blocks {
                    match item {
                        ContentBlock::Text { text } => {
                            if text != "(no content)" {
                                parts.push(json!({"text": text}));
                            }
                        }
                        ContentBlock::Thinking { thinking, signature, .. } => {
                            tracing::error!("[DEBUG-TRANSFORM] Processing thinking block. Sig: {:?}", signature);
                            
                            // [FIX] If thinking is disabled (smart downgrade), convert ALL thinking blocks to text
                            // to avoid "thinking is disabled but message contains thinking" error
                            if !is_thinking_enabled {
                                tracing::warn!("[Claude-Request] Thinking disabled. Downgrading thinking block to text.");
                                if !thinking.is_empty() {
                                    parts.push(json!({
                                        "text": thinking
                                    }));
                                }
                                continue;
                            }
                            
                            // [FIX] Empty thinking blocks cause "Field required" errors.
                            // We downgrade them to Text to avoid structural errors and signature mismatch.
                            if thinking.is_empty() {
                                tracing::warn!("[Claude-Request] Empty thinking block detected. Downgrading to Text.");
                                parts.push(json!({
                                    "text": "..."
                                }));
                                continue;
                            }

                            let mut part = json!({
                                "text": thinking,
                                "thought": true, // [CRITICAL FIX] Vertex AI v1internal requires thought: true to distinguish from text
                            });
                            // [New] Recursively clean blacklisted fields (e.g., cache_control)
                            crate::proxy::common::json_schema::clean_json_schema(&mut part);

                            // [CRITICAL FIX] Do NOT add skip_thought_signature_validator for Vertex AI
                            // If no signature, the block should have been filtered out
                            if signature.is_none() {
                                tracing::warn!("[Claude-Request] Thinking block without signature (should have been filtered!)");
                            }

                            if let Some(sig) = signature {
                                last_thought_signature = Some(sig.clone());
                                part["thoughtSignature"] = json!(sig);
                            }
                            parts.push(part);
                        }
                        ContentBlock::Image { source, .. } => {
                            if source.source_type == "base64" {
                                parts.push(json!({
                                    "inlineData": {
                                        "mimeType": source.media_type,
                                        "data": source.data
                                    }
                                }));
                            }
                        }
                        ContentBlock::Document { source, .. } => {
                            if source.source_type == "base64" {
                                parts.push(json!({
                                    "inlineData": {
                                        "mimeType": source.media_type,
                                        "data": source.data
                                    }
                                }));
                            }
                        }
                        ContentBlock::ToolUse { id, name, input, signature, .. } => {
                            let mut part = json!({
                                "functionCall": {
                                    "name": name,
                                    "args": input,
                                    "id": id
                                }
                            });
                            
                            // [New] Recursively clean potentially invalid validation fields in parameters
                            crate::proxy::common::json_schema::clean_json_schema(&mut part);

                            // Store id -> name mapping
                            tool_id_to_name.insert(id.clone(), name.clone());

                            // Signature resolution logic (Priority: Client -> Context -> Global Store)
                            // [CRITICAL FIX] Do NOT use skip_thought_signature_validator for Vertex AI
                            // Vertex AI rejects this sentinel value, so we only add thoughtSignature if we have a real one
                            let final_sig = signature.as_ref()
                                .or(last_thought_signature.as_ref())
                                .cloned()
                                .or_else(|| {
                                    let global_sig = get_thought_signature();
                                    if global_sig.is_some() {
                                        tracing::info!("[Claude-Request] Using global thought_signature fallback (length: {})", 
                                            global_sig.as_ref().unwrap().len());
                                    }
                                    global_sig
                                });
                            // Only add thoughtSignature if we have a valid one
                            // Do NOT add skip_thought_signature_validator - Vertex AI rejects it

                            if let Some(sig) = final_sig {
                                part["thoughtSignature"] = json!(sig);
                            }
                            parts.push(part);
                        }
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                            ..
                        } => {
                            // Prefer previously recorded name, otherwise use tool_use_id
                            let func_name = tool_id_to_name
                                .get(tool_use_id)
                                .cloned()
                                .unwrap_or_else(|| tool_use_id.clone());

                            // Process content: may be an array of content blocks or a single string
                            let mut merged_content = match content {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Array(arr) => arr
                                    .iter()
                                    .filter_map(|block| {
                                        if let Some(text) =
                                            block.get("text").and_then(|v| v.as_str())
                                        {
                                            Some(text)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                _ => content.to_string(),
                            };

                            // [Optimization] If result is empty, inject explicit confirmation signal to prevent model hallucination
                            if merged_content.trim().is_empty() {
                                if is_error.unwrap_or(false) {
                                    merged_content =
                                        "Tool execution failed with no output.".to_string();
                                } else {
                                    merged_content = "Command executed successfully.".to_string();
                                }
                            }

                            let mut part = json!({
                                "functionResponse": {
                                    "name": func_name,
                                    "response": {"result": merged_content},
                                    "id": tool_use_id
                                }
                            });

                            // [Fix] Tool Result also needs signature backfill (if available in context)
                            if let Some(sig) = last_thought_signature.as_ref() {
                                part["thoughtSignature"] = json!(sig);
                            }

                            parts.push(part);
                        }
                        ContentBlock::ServerToolUse { .. } | ContentBlock::WebSearchToolResult { .. } => {
                            // Search result blocks should not be sent back to upstream by client (replaced by tool_result)
                            continue;
                        }
                        ContentBlock::RedactedThinking { data } => {
                            // [FIX] Process RedactedThinking as plain text
                            // because it has no signature, marking it as thought: true would cause API rejection (Corrupted signature)
                            parts.push(json!({
                                "text": format!("[Redacted Thinking: {}]", data),
                            }));
                        }
                    }
                }
            }
        }

        // Fix for "Thinking enabled, assistant message must start with thinking block" 400 error
        // [Optimization] Apply this to ALL assistant messages in history, not just the last one.
        // Vertex AI requires every assistant message to start with a thinking block when thinking is enabled.
        if allow_dummy_thought && role == "model" && is_thinking_enabled {
            let has_thought_part = parts
                .iter()
                .any(|p| {
                    p.get("thought").and_then(|v| v.as_bool()).unwrap_or(false)
                        || p.get("thoughtSignature").is_some()
                        || p.get("thought").and_then(|v| v.as_str()).is_some() // In some cases it may be a combination of text + thought: true
                });

            if !has_thought_part {
                // Prepend a dummy thinking block to satisfy Gemini v1internal requirements
                parts.insert(
                    0,
                    json!({
                        "text": "Thinking...",
                        "thought": true
                    }),
                );
                tracing::debug!("Injected dummy thought block for historical assistant message at index {}", contents.len());
            } else {
                // [Crucial Check] Even with a thought block, it must be at the first position (Index 0) in parts
                // and must contain the thought: true marker
                let first_is_thought = parts.get(0).map_or(false, |p| {
                    (p.get("thought").is_some() || p.get("thoughtSignature").is_some())
                    && p.get("text").is_some() // For v1internal, typically text + thought: true is the compliant thinking block
                });

                if !first_is_thought {
                    // If the first item doesn't match thinking block characteristics, force prepend one
                    parts.insert(
                        0,
                        json!({
                            "text": "...",
                            "thought": true
                        }),
                    );
                    tracing::debug!("First part of model message at {} is not a valid thought block. Prepending dummy.", contents.len());
                } else {
                    // Ensure first item contains thought: true (prevent cases with only signature)
                    if let Some(p0) = parts.get_mut(0) {
                        if p0.get("thought").is_none() {
                             p0.as_object_mut().map(|obj| obj.insert("thought".to_string(), json!(true)));
                        }
                    }
                }
            }
        }

        if parts.is_empty() {
            continue;
        }

        contents.push(json!({
            "role": role,
            "parts": parts
        }));
    }



    // [Removed] ensure_last_assistant_has_thinking 
    // Corrupted signature issues proved we cannot fake thinking blocks.
    // Instead we rely on should_disable_thinking_due_to_history to prevent this state.

    Ok(json!(contents))
}

/// Build Tools
fn build_tools(tools: &Option<Vec<Tool>>, has_web_search: bool) -> Result<Option<Value>, String> {
    if let Some(tools_list) = tools {
        let mut function_declarations: Vec<Value> = Vec::new();
        let mut has_google_search = has_web_search;

        for tool in tools_list {
            // 1. Detect server tools / built-in tools like web_search
            if tool.is_web_search() {
                has_google_search = true;
                continue;
            }

            if let Some(t_type) = &tool.type_ {
                if t_type == "web_search_20250305" {
                    has_google_search = true;
                    continue;
                }
            }

            // 2. Detect by name
            if let Some(name) = &tool.name {
                if name == "web_search" || name == "google_search" {
                    has_google_search = true;
                    continue;
                }

                // 3. Client tools require input_schema
                let mut input_schema = tool.input_schema.clone().unwrap_or(json!({
                    "type": "object",
                    "properties": {}
                }));
                crate::proxy::common::json_schema::clean_json_schema(&mut input_schema);

                function_declarations.push(json!({
                    "name": name,
                    "description": tool.description,
                    "parameters": input_schema
                }));
            }
        }

        let mut tool_obj = serde_json::Map::new();

        // [Fix] Resolve "Multiple tools are supported only when they are all search tools" 400 error
        // Principle: Gemini v1internal API is very picky, usually doesn't allow mixing Google Search and Function Declarations in the same tool definition.
        // For clients like Claude CLI that carry MCP tools, must prioritize ensuring Function Declarations work properly.
        if !function_declarations.is_empty() {
            // If there are local tools, only use local tools and skip Google Search injection
            tool_obj.insert("functionDeclarations".to_string(), json!(function_declarations));

            // [IMPROVED] Log reason for skipping googleSearch injection
            if has_google_search {
                tracing::info!(
                    "[Claude-Request] Skipping googleSearch injection due to {} existing function declarations. \
                     Gemini v1internal does not support mixed tool types.",
                    function_declarations.len()
                );
            }
        } else if has_google_search {
            // Only allow Google Search injection when there are no local tools
            tool_obj.insert("googleSearch".to_string(), json!({}));
        }

        if !tool_obj.is_empty() {
            return Ok(Some(json!([tool_obj])));
        }
    }

    Ok(None)
}

/// Build Generation Config
fn build_generation_config(
    claude_req: &ClaudeRequest,
    has_web_search: bool,
    is_thinking_enabled: bool
) -> Value {
    let mut config = json!({});

    // Thinking configuration
    if let Some(thinking) = &claude_req.thinking {
        // [New Check] Only generate thinkingConfig if is_thinking_enabled is true
        if thinking.type_ == "enabled" && is_thinking_enabled {
            let mut thinking_config = json!({"includeThoughts": true});

            if let Some(budget_tokens) = thinking.budget_tokens {
                let mut budget = budget_tokens;
                // gemini-2.5-flash has a limit of 24576
                let is_flash_model =
                    has_web_search || claude_req.model.contains("gemini-2.5-flash");
                if is_flash_model {
                    budget = budget.min(24576);
                }
                thinking_config["thinkingBudget"] = json!(budget);
            }

            config["thinkingConfig"] = thinking_config;
        }
    }

    // Other parameters
    if let Some(temp) = claude_req.temperature {
        config["temperature"] = json!(temp);
    }
    if let Some(top_p) = claude_req.top_p {
        config["topP"] = json!(top_p);
    }
    if let Some(top_k) = claude_req.top_k {
        config["topK"] = json!(top_k);
    }

    // Effort level mapping (Claude API v2.0.67+)
    // Maps Claude's output_config.effort to Gemini's effortLevel
    if let Some(output_config) = &claude_req.output_config {
        if let Some(effort) = &output_config.effort {
            config["effortLevel"] = json!(match effort.to_lowercase().as_str() {
                "high" => "HIGH",
                "medium" => "MEDIUM",
                "low" => "LOW",
                _ => "HIGH" // Default to HIGH for unknown values
            });
            tracing::debug!(
                "[Generation-Config] Effort level set: {} -> {}",
                effort,
                config["effortLevel"]
            );
        }
    }

    // web_search forces candidateCount=1
    /*if has_web_search {
        config["candidateCount"] = json!(1);
    }*/

    // max_tokens maps to maxOutputTokens
    config["maxOutputTokens"] = json!(64000);

    // [Optimization] Set global stop sequences to prevent redundant streaming output (reference: done-hub)
    config["stopSequences"] = json!([
        "<|user|>",
        "<|endoftext|>",
        "<|end_of_turn|>",
        "[DONE]",
        "\n\nHuman:"
    ]);

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::common::json_schema::clean_json_schema;

    #[test]
    fn test_simple_request() {
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::String("Hello".to_string()),
            }],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());

        let body = result.unwrap();
        assert_eq!(body["project"], "test-project");
        assert!(body["requestId"].as_str().unwrap().starts_with("agent-"));
    }

    #[test]
    fn test_clean_json_schema() {
        let mut schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city and state, e.g. San Francisco, CA",
                    "minLength": 1,
                    "exclusiveMinimum": 0
                },
                "unit": {
                    "type": ["string", "null"],
                    "enum": ["celsius", "fahrenheit"],
                    "default": "celsius"
                },
                "date": {
                    "type": "string",
                    "format": "date"
                }
            },
            "required": ["location"]
        });

        clean_json_schema(&mut schema);

        // Check removed fields
        assert!(schema.get("$schema").is_none());
        assert!(schema.get("additionalProperties").is_none());
        assert!(schema["properties"]["location"].get("minLength").is_none());
        assert!(schema["properties"]["unit"].get("default").is_none());
        assert!(schema["properties"]["date"].get("format").is_none());

        // Check union type handling ["string", "null"] -> "string"
        assert_eq!(schema["properties"]["unit"]["type"], "string");

        // Check types are lowercased
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["location"]["type"], "string");
        assert_eq!(schema["properties"]["date"]["type"], "string");
    }

    #[test]
    fn test_complex_tool_result() {
        let req = ClaudeRequest {
            model: "claude-3-5-sonnet-20241022".to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Run command".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::ToolUse {
                            id: "call_1".to_string(),
                            name: "run_command".to_string(),
                            input: json!({"command": "ls"}),
                            signature: None,
                            cache_control: None,
                        }
                    ]),
                },
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![ContentBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: json!([
                            {"type": "text", "text": "file1.txt\n"},
                            {"type": "text", "text": "file2.txt"}
                        ]),
                        is_error: Some(false),
                    }]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());

        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();

        // Check the tool result message (last message)
        let tool_resp_msg = &contents[2];
        let parts = tool_resp_msg["parts"].as_array().unwrap();
        let func_resp = &parts[0]["functionResponse"];

        assert_eq!(func_resp["name"], "run_command");
        assert_eq!(func_resp["id"], "call_1");

        // Verify merged content
        let resp_text = func_resp["response"]["result"].as_str().unwrap();
        assert!(resp_text.contains("file1.txt"));
        assert!(resp_text.contains("file2.txt"));
        assert!(resp_text.contains("\n"));
    }

    #[test]
    fn test_cache_control_cleanup() {
        // Simulate historical messages with cache_control sent by VS Code plugin
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Hello".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Thinking {
                            thinking: "Let me think...".to_string(),
                            signature: Some("sig123".to_string()),
                            cache_control: Some(json!({"type": "ephemeral"})), // This should be cleaned
                        },
                        ContentBlock::Text {
                            text: "Here is my response".to_string(),
                        },
                    ]),
                },
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Image {
                            source: ImageSource {
                                source_type: "base64".to_string(),
                                media_type: "image/png".to_string(),
                                data: "iVBORw0KGgo=".to_string(),
                            },
                            cache_control: Some(json!({"type": "ephemeral"})), // This should also be cleaned
                        },
                    ]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());

        // Verify successful request transformation
        let body = result.unwrap();
        assert_eq!(body["project"], "test-project");
        
        // Note: cache_control cleaning happens internally, we cannot verify directly from JSON output
        // But if not cleaned, sending to Anthropic API would cause errors
        // This test mainly ensures the cleaning logic doesn't cause transformation failure
    }

    #[test]
    fn test_thinking_mode_auto_disable_on_tool_use_history() {
        // [Scenario] History messages have a tool call chain, and Assistant message has no Thinking block
        // Expected: System auto-downgrades, disables Thinking mode to avoid 400 error
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Check files".to_string()),
                },
                // Assistant uses tools, but in non-Thinking mode
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Text {
                            text: "Checking...".to_string(),
                        },
                        ContentBlock::ToolUse {
                            id: "tool_1".to_string(),
                            name: "list_files".to_string(),
                            input: json!({}),
                            cache_control: None, 
                            signature: None 
                        },
                    ]),
                },
                // User returns tool result
                Message {
                    role: "user".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::ToolResult {
                            tool_use_id: "tool_1".to_string(),
                            content: serde_json::Value::String("file1.txt\nfile2.txt".to_string()),
                            is_error: Some(false),
                            // cache_control: None, // removed
                        },
                    ]),
                },
            ],
            system: None,
            tools: Some(vec![
                Tool {
                    name: Some("list_files".to_string()),
                    description: Some("List files".to_string()),
                    input_schema: Some(json!({"type": "object"})),
                    type_: None,
                    // cache_control: None, // removed
                }
            ]),
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(1024),
            }),
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());

        let body = result.unwrap();
        let request = &body["request"];

        // Verify: generationConfig should not contain thinkingConfig (because it was downgraded)
        // Even though thinking was explicitly enabled in the request
        if let Some(gen_config) = request.get("generationConfig") {
             assert!(gen_config.get("thinkingConfig").is_none(), "thinkingConfig should be removed due to downgrade");
        }
        
        // Verify: can still generate valid request body
        assert!(request.get("contents").is_some());
    }



    #[test]
    fn test_thinking_block_not_prepend_when_disabled() {
        // Verify that when thinking is not enabled, thinking blocks are not prepended
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: MessageContent::String("Hello".to_string()),
                },
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Text {
                            text: "Response".to_string(),
                        },
                    ]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None, // thinking not enabled
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());

        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();

        let last_model_msg = contents
            .iter()
            .rev()
            .find(|c| c["role"] == "model")
            .unwrap();

        let parts = last_model_msg["parts"].as_array().unwrap();
        
        // Verify no thinking block was prepended
        assert_eq!(parts.len(), 1, "Should only have the original text block");
        assert_eq!(parts[0]["text"], "Response");
    }

    #[test]
    fn test_thinking_block_empty_content_fix() {
        // [Scenario] Client sends a thinking block with empty content
        // Expected: Auto-fill with "..."
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::Thinking {
                            thinking: "".to_string(), // Empty content
                            signature: Some("sig".to_string()),
                            cache_control: None,
                        },
                        ContentBlock::Text { text: "Hi".to_string() }
                    ]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: Some(ThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: Some(1024),
            }),
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok(), "Transformation failed");
        let body = result.unwrap();
        let contents = body["request"]["contents"].as_array().unwrap();
        let parts = contents[0]["parts"].as_array().unwrap();
        
        // Verify thinking block
        assert_eq!(parts[0]["text"], "...", "Empty thinking should be filled with ...");
        assert!(parts[0].get("thought").is_none(), "Empty thinking should be downgraded to text");
    }

    #[test]
    fn test_redacted_thinking_degradation() {
        // [Scenario] Client contains RedactedThinking
        // Expected: Downgrade to plain text, without thought: true
        let req = ClaudeRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![
                Message {
                    role: "assistant".to_string(),
                    content: MessageContent::Array(vec![
                        ContentBlock::RedactedThinking {
                            data: "some data".to_string(),
                        },
                         ContentBlock::Text { text: "Hi".to_string() }
                    ]),
                },
            ],
            system: None,
            tools: None,
            stream: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            thinking: None,
            metadata: None,
            output_config: None,
        };

        let result = transform_claude_request_in(&req, "test-project");
        assert!(result.is_ok());
        let body = result.unwrap();
        let parts = body["request"]["contents"][0]["parts"].as_array().unwrap();

        // Verify RedactedThinking -> Text
        let text = parts[0]["text"].as_str().unwrap();
        assert!(text.contains("[Redacted Thinking: some data]"));
        assert!(parts[0].get("thought").is_none(), "Redacted thinking should NOT have thought: true");
    }
}
