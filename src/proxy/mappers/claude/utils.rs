// Claude utility functions
// JSON Schema cleanup, signature handling, etc.

// Removed unused Value import

/// Convert type names in JSON Schema to uppercase (required by Gemini)
/// Example: "string" -> "STRING", "integer" -> "INTEGER"
// Removed unused uppercase_schema_types function

/// Convert Gemini UsageMetadata to Claude Usage
pub fn to_claude_usage(usage_metadata: &super::models::UsageMetadata) -> super::models::Usage {
    let prompt_tokens = usage_metadata.prompt_token_count.unwrap_or(0);
    let cached_tokens = usage_metadata.cached_content_token_count.unwrap_or(0);
    
    super::models::Usage {
        // input_tokens should include cached portion for accurate context usage display
        input_tokens: prompt_tokens,
        output_tokens: usage_metadata.candidates_token_count.unwrap_or(0),
        // Cache statistics
        cache_read_input_tokens: if cached_tokens > 0 { Some(cached_tokens) } else { None },
        cache_creation_input_tokens: Some(0),  // Gemini doesn't provide this field, set to 0
        server_tool_use: None,
    }
}

/// Extract thoughtSignature
// Removed unused extract_thought_signature function

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused serde_json::json

    // Removed obsolete uppercase_schema_types test

    #[test]
    fn test_to_claude_usage() {
        use super::super::models::UsageMetadata;

        let usage = UsageMetadata {
            prompt_token_count: Some(100),
            candidates_token_count: Some(50),
            total_token_count: Some(150),
            cached_content_token_count: None,
        };

        let claude_usage = to_claude_usage(&usage);
        assert_eq!(claude_usage.input_tokens, 100);
        assert_eq!(claude_usage.output_tokens, 50);
    }
}
