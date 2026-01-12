// Model name mapping
use std::collections::HashMap;
use once_cell::sync::Lazy;

static CLAUDE_TO_GEMINI: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Directly supported models
    m.insert("claude-opus-4-5-thinking", "claude-opus-4-5-thinking");
    m.insert("claude-sonnet-4-5", "claude-sonnet-4-5");
    m.insert("claude-sonnet-4-5-thinking", "claude-sonnet-4-5-thinking");

    // Alias mapping
    m.insert("claude-sonnet-4-5-20250929", "claude-sonnet-4-5-thinking");
    m.insert("claude-3-5-sonnet-20241022", "claude-sonnet-4-5");
    m.insert("claude-3-5-sonnet-20240620", "claude-sonnet-4-5");
    m.insert("claude-opus-4", "claude-opus-4-5-thinking");
    m.insert("claude-opus-4-5-20251101", "claude-opus-4-5-thinking");
    m.insert("claude-haiku-4", "claude-sonnet-4-5");
    m.insert("claude-3-haiku-20240307", "claude-sonnet-4-5");
    m.insert("claude-haiku-4-5-20251001", "claude-sonnet-4-5");
    // OpenAI protocol mapping table
    m.insert("gpt-4", "gemini-2.5-pro");
    m.insert("gpt-4-turbo", "gemini-2.5-pro");
    m.insert("gpt-4-turbo-preview", "gemini-2.5-pro");
    m.insert("gpt-4-0125-preview", "gemini-2.5-pro");
    m.insert("gpt-4-1106-preview", "gemini-2.5-pro");
    m.insert("gpt-4-0613", "gemini-2.5-pro");

    m.insert("gpt-4o", "gemini-2.5-pro");
    m.insert("gpt-4o-2024-05-13", "gemini-2.5-pro");
    m.insert("gpt-4o-2024-08-06", "gemini-2.5-pro");

    m.insert("gpt-4o-mini", "gemini-2.5-flash");
    m.insert("gpt-4o-mini-2024-07-18", "gemini-2.5-flash");

    m.insert("gpt-3.5-turbo", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-16k", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-0125", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-1106", "gemini-2.5-flash");
    m.insert("gpt-3.5-turbo-0613", "gemini-2.5-flash");

    // Gemini protocol mapping table
    m.insert("gemini-2.5-flash-lite", "gemini-2.5-flash-lite");
    m.insert("gemini-2.5-flash-thinking", "gemini-2.5-flash-thinking");
    m.insert("gemini-3-pro-low", "gemini-3-pro-low");
    m.insert("gemini-3-pro-high", "gemini-3-pro-high");
    m.insert("gemini-3-pro-preview", "gemini-3-pro-preview");
    m.insert("gemini-2.5-flash", "gemini-2.5-flash");
    m.insert("gemini-3-flash", "gemini-3-flash");
    m.insert("gemini-3-pro-image", "gemini-3-pro-image");

    m
});

pub fn map_claude_model_to_gemini(input: &str) -> String {
    // 1. Check exact match in map
    if let Some(mapped) = CLAUDE_TO_GEMINI.get(input) {
        return mapped.to_string();
    }

    // 2. Pass-through known prefixes (gemini-, -thinking) to support dynamic suffixes
    if input.starts_with("gemini-") || input.contains("thinking") {
        return input.to_string();
    }

    // 3. Fallback to default
    "claude-sonnet-4-5".to_string()
}

/// Get all built-in supported model list keywords
pub fn get_supported_models() -> Vec<String> {
    CLAUDE_TO_GEMINI.keys().map(|s| s.to_string()).collect()
}

/// Dynamically get all available model list (including built-in and user-defined)
///
/// Only returns core available models, excluding aliases and redundant variants
pub async fn get_all_dynamic_models(
    openai_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    custom_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    anthropic_mapping: &tokio::sync::RwLock<std::collections::HashMap<String, String>>,
) -> Vec<String> {
    use std::collections::HashSet;
    let mut model_ids = HashSet::new();

    // 1. Core Claude models (only native supported, no aliases)
    model_ids.insert("claude-opus-4-5-thinking".to_string());
    model_ids.insert("claude-sonnet-4-5".to_string());
    model_ids.insert("claude-sonnet-4-5-thinking".to_string());

    // 2. Core Gemini models
    model_ids.insert("gemini-2.5-flash".to_string());
    model_ids.insert("gemini-2.5-flash-lite".to_string());
    model_ids.insert("gemini-2.5-flash-thinking".to_string());
    model_ids.insert("gemini-2.5-pro".to_string());
    model_ids.insert("gemini-3-flash".to_string());
    model_ids.insert("gemini-3-pro-low".to_string());
    model_ids.insert("gemini-3-pro-high".to_string());
    model_ids.insert("gemini-3-pro-preview".to_string());
    model_ids.insert("gemini-3-pro-image".to_string());

    // 3. Core OpenAI models (for compatibility)
    model_ids.insert("gpt-4".to_string());
    model_ids.insert("gpt-4o".to_string());
    model_ids.insert("gpt-4o-mini".to_string());
    model_ids.insert("gpt-3.5-turbo".to_string());

    // 4. Add custom mapping models (OpenAI)
    {
        let mapping = openai_mapping.read().await;
        for key in mapping.keys() {
            if !key.ends_with("-series") {
                 model_ids.insert(key.clone());
            }
        }
    }

    // 5. Add custom mapping models (Custom)
    {
        let mapping = custom_mapping.read().await;
        for key in mapping.keys() {
            model_ids.insert(key.clone());
        }
    }

    // 6. Add Anthropic mapping models
    {
        let mapping = anthropic_mapping.read().await;
        for key in mapping.keys() {
            if !key.ends_with("-series") && key != "claude-default" {
                model_ids.insert(key.clone());
            }
        }
    }

    let mut sorted_ids: Vec<_> = model_ids.into_iter().collect();
    sorted_ids.sort();
    sorted_ids
}

/// Core model routing resolution engine
/// Priority: Custom Mapping (exact) > Group Mapping (family) > System Mapping (built-in plugins)
///
/// # Parameters
/// - `apply_claude_family_mapping`: Whether to apply family mapping for Claude models
///   - `true`: CLI request, apply family mapping (e.g., claude-sonnet-4-5 -> gemini-3-pro-high)
///   - `false`: Non-CLI request (e.g., Cherry Studio), skip family mapping, pass through directly
pub fn resolve_model_route(
    original_model: &str,
    custom_mapping: &std::collections::HashMap<String, String>,
    openai_mapping: &std::collections::HashMap<String, String>,
    anthropic_mapping: &std::collections::HashMap<String, String>,
    apply_claude_family_mapping: bool,
) -> String {
    // 1. Check custom exact mapping (highest priority)
    if let Some(target) = custom_mapping.get(original_model) {
        crate::modules::logger::log_info(&format!("[Router] Using custom exact mapping: {} -> {}", original_model, target));
        return target.clone();
    }

    let lower_model = original_model.to_lowercase();

    // 2. Check family group mapping (OpenAI series)
    // GPT-4 series (including GPT-4 classic, o1, o3, etc., excluding 4o/mini/turbo)
    if (lower_model.starts_with("gpt-4") && !lower_model.contains("o") && !lower_model.contains("mini") && !lower_model.contains("turbo")) ||
       lower_model.starts_with("o1-") || lower_model.starts_with("o3-") || lower_model == "gpt-4" {
        if let Some(target) = openai_mapping.get("gpt-4-series") {
            crate::modules::logger::log_info(&format!("[Router] Using GPT-4 series mapping: {} -> {}", original_model, target));
            return target.clone();
        }
    }

    // GPT-4o / 3.5 series (balanced and lightweight, including 4o, mini, turbo)
    if lower_model.contains("4o") || lower_model.starts_with("gpt-3.5") || (lower_model.contains("mini") && !lower_model.contains("gemini")) || lower_model.contains("turbo") {
        if let Some(target) = openai_mapping.get("gpt-4o-series") {
            crate::modules::logger::log_info(&format!("[Router] Using GPT-4o/3.5 series mapping: {} -> {}", original_model, target));
            return target.clone();
        }
    }

    // GPT-5 series (gpt-5, gpt-5.1, gpt-5.2, etc.)
    if lower_model.starts_with("gpt-5") {
        // Prefer gpt-5-series mapping, fallback to gpt-4-series if not available
        if let Some(target) = openai_mapping.get("gpt-5-series") {
            crate::modules::logger::log_info(&format!("[Router] Using GPT-5 series mapping: {} -> {}", original_model, target));
            return target.clone();
        }
        if let Some(target) = openai_mapping.get("gpt-4-series") {
            crate::modules::logger::log_info(&format!("[Router] Using GPT-4 series mapping (GPT-5 fallback): {} -> {}", original_model, target));
            return target.clone();
        }
    }

    // 3. Check family group mapping (Anthropic series)
    if lower_model.starts_with("claude-") {
        // [CRITICAL] Check whether to apply Claude family mapping
        // If non-CLI request (e.g., Cherry Studio), first check if it's a natively supported pass-through model
        if !apply_claude_family_mapping {
            if let Some(mapped) = CLAUDE_TO_GEMINI.get(original_model) {
                if *mapped == original_model {
                    // Natively supported pass-through model, skip family mapping
                    crate::modules::logger::log_info(&format!("[Router] Non-CLI request, skipping family mapping: {}", original_model));
                    return original_model.to_string();
                }
            }
        }

        // [NEW] Haiku smart downgrade strategy
        // Automatically downgrade all Haiku models to gemini-2.5-flash-lite (lightest/cheapest model)
        // [FIX] Only effective in CLI mode (apply_claude_family_mapping == true)
        if apply_claude_family_mapping && lower_model.contains("haiku") {
            crate::modules::logger::log_info(&format!("[Router] Haiku smart downgrade (CLI): {} -> gemini-2.5-flash-lite", original_model));
            return "gemini-2.5-flash-lite".to_string();
        }

        let family_key = if lower_model.contains("4-5") || lower_model.contains("4.5") {
            "claude-4.5-series"
        } else if lower_model.contains("3-5") || lower_model.contains("3.5") {
            "claude-3.5-series"
        } else {
            "claude-default"
        };

        if let Some(target) = anthropic_mapping.get(family_key) {
            crate::modules::logger::log_warn(&format!("[Router] Using Anthropic series mapping: {} -> {}", original_model, target));
            return target.clone();
        }

        // Fallback to legacy exact mapping for compatibility
        if let Some(target) = anthropic_mapping.get(original_model) {
             return target.clone();
        }
    }

    // 4. Fall through to system default mapping logic
    map_claude_model_to_gemini(original_model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_mapping() {
        assert_eq!(
            map_claude_model_to_gemini("claude-3-5-sonnet-20241022"),
            "claude-sonnet-4-5"
        );
        assert_eq!(
            map_claude_model_to_gemini("claude-opus-4"),
            "claude-opus-4-5-thinking"
        );
        // Test gemini pass-through (should not be caught by "mini" rule)
        assert_eq!(
            map_claude_model_to_gemini("gemini-2.5-flash-mini-test"),
            "gemini-2.5-flash-mini-test"
        );
        assert_eq!(
            map_claude_model_to_gemini("unknown-model"),
            "claude-sonnet-4-5"
        );
    }
}
