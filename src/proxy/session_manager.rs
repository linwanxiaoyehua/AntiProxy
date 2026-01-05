use sha2::{Sha256, Digest};
use crate::proxy::mappers::claude::models::{ClaudeRequest, MessageContent};
use crate::proxy::mappers::openai::models::{OpenAIRequest, OpenAIContent};
use serde_json::Value;

/// 会话管理器工具
pub struct SessionManager;

impl SessionManager {
    /// 根据 Claude 请求生成稳定的会话指纹 (Session Fingerprint)
    pub fn extract_session_id(request: &ClaudeRequest) -> String {
        // 1. 优先使用 metadata 中的 user_id
        if let Some(metadata) = &request.metadata {
            if let Some(user_id) = &metadata.user_id {
                if !user_id.is_empty() && !user_id.contains("session-") {
                    return user_id.clone();
                }
            }
        }

        // 2. 备选方案：智能内容指纹 (SHA256)
        // 策略：提取第一条核心用户消息，移除空白和系统干扰项
        let mut hasher = Sha256::new();
        
        // 混入模型名称增加区分度
        hasher.update(request.model.as_bytes());

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" { continue; }
            
            let text = match &msg.content {
                MessageContent::String(s) => s.clone(),
                MessageContent::Array(blocks) => {
                    blocks.iter()
                        .filter_map(|block| match block {
                            crate::proxy::mappers::claude::models::ContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            };

            let clean_text = text.trim();
            // 跳过过短的消息 (可能是 CLI 的探测消息) 或含有系统标签的消息
            if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                hasher.update(clean_text.as_bytes());
                content_found = true;
                break; // 只取第一条关键消息作为锚点
            }
        }

        if !content_found {
            // 如果没找到有意义的内容，退化为对最后一条消息进行哈希
            if let Some(last_msg) = request.messages.last() {
                hasher.update(format!("{:?}", last_msg.content).as_bytes());
            }
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);
        
        tracing::debug!("[SessionManager] Generated fingerprint: {} for model {}", sid, request.model);
        sid
    }

    /// 根据 OpenAI 请求生成稳定的会话指纹
    pub fn extract_openai_session_id(request: &OpenAIRequest) -> String {
        let mut hasher = Sha256::new();
        hasher.update(request.model.as_bytes());

        let mut content_found = false;
        for msg in &request.messages {
            if msg.role != "user" { continue; }
            if let Some(content) = &msg.content {
                let text = match content {
                    OpenAIContent::String(s) => s.clone(),
                    OpenAIContent::Array(blocks) => {
                        blocks.iter()
                            .filter_map(|block| match block {
                                crate::proxy::mappers::openai::models::OpenAIContentBlock::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    }
                };

                let clean_text = text.trim();
                if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                    hasher.update(clean_text.as_bytes());
                    content_found = true;
                    break;
                }
            }
        }

        if !content_found {
            if let Some(last_msg) = request.messages.last() {
                hasher.update(format!("{:?}", last_msg.content).as_bytes());
            }
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);
        tracing::debug!("[SessionManager-OpenAI] Generated fingerprint: {}", sid);
        sid
    }

    /// 根据 Gemini 原生请求 (JSON) 生成稳定的会话指纹
    pub fn extract_gemini_session_id(request: &Value, model_name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(model_name.as_bytes());

        let mut content_found = false;
        if let Some(contents) = request.get("contents").and_then(|v| v.as_array()) {
            for content in contents {
                if content.get("role").and_then(|v| v.as_str()) != Some("user") { continue; }
                
                if let Some(parts) = content.get("parts").and_then(|v| v.as_array()) {
                    let mut text_parts = Vec::new();
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                            text_parts.push(text);
                        }
                    }
                    
                    let combined_text = text_parts.join(" ");
                    let clean_text = combined_text.trim();
                    if clean_text.len() > 10 && !clean_text.contains("<system-reminder>") {
                        hasher.update(clean_text.as_bytes());
                        content_found = true;
                        break;
                    }
                }
            }
        }

        if !content_found {
             // 兜底：对整个 Body 的首个 user part 进行摘要
             hasher.update(request.to_string().as_bytes());
        }

        let hash = format!("{:x}", hasher.finalize());
        let sid = format!("sid-{}", &hash[..16]);
        tracing::debug!("[SessionManager-Gemini] Generated fingerprint: {}", sid);
        sid
    }
}
