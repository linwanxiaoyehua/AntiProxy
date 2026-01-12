use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use regex::Regex;

/// Rate limit reason type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitReason {
    /// Quota exhausted (QUOTA_EXHAUSTED)
    QuotaExhausted,
    /// Rate limit exceeded (RATE_LIMIT_EXCEEDED)
    RateLimitExceeded,
    /// Server error (5xx)
    ServerError,
    /// Unknown reason
    Unknown,
}

/// Rate limit information
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Rate limit reset time
    pub reset_time: SystemTime,
    /// Retry interval (seconds)
    #[allow(dead_code)]
    pub retry_after_sec: u64,
    /// Detection time
    #[allow(dead_code)]
    pub detected_at: SystemTime,
    /// Rate limit reason
    pub reason: RateLimitReason,
}

/// Rate limit tracker
pub struct RateLimitTracker {
    limits: DashMap<String, RateLimitInfo>,
}

impl RateLimitTracker {
    pub fn new() -> Self {
        Self {
            limits: DashMap::new(),
        }
    }
    
    fn make_key(&self, quota_group: &str, account_id: &str) -> String {
        format!("{}::{}", quota_group, account_id)
    }

    /// Get the remaining wait time for an account (in seconds)
    pub fn get_remaining_wait(&self, quota_group: &str, account_id: &str) -> u64 {
        let key = self.make_key(quota_group, account_id);
        if let Some(info) = self.limits.get(&key) {
            let now = SystemTime::now();
            if info.reset_time > now {
                return info.reset_time.duration_since(now).unwrap_or(Duration::from_secs(0)).as_secs();
            }
        }
        0
    }
    
    /// Parse rate limit information from error response
    ///
    /// # Arguments
    /// * `quota_group` - Quota group (e.g. "gemini", "claude")
    /// * `account_id` - Account ID
    /// * `status` - HTTP status code
    /// * `retry_after_header` - Retry-After header value
    /// * `body` - Error response body
    pub fn parse_from_error(
        &self,
        quota_group: &str,
        account_id: &str,
        status: u16,
        retry_after_header: Option<&str>,
        body: &str,
    ) -> Option<RateLimitInfo> {
        // Support 429 (rate limit) and 500/503/529 (backend failure soft backoff)
        if status != 429 && status != 500 && status != 503 && status != 529 {
            return None;
        }

        // 1. Parse rate limit reason type
        let reason = if status == 429 {
            self.parse_rate_limit_reason(body)
        } else {
            RateLimitReason::ServerError
        };
        
        let mut retry_after_sec = None;

        // 2. Extract from Retry-After header
        if let Some(retry_after) = retry_after_header {
            if let Ok(seconds) = retry_after.parse::<u64>() {
                retry_after_sec = Some(seconds);
            }
        }
        
        // 3. Extract from error message (try JSON parsing first, then regex)
        if retry_after_sec.is_none() {
            retry_after_sec = self.parse_retry_time_from_body(body);
        }

        // 4. Handle default values and soft backoff logic (set different defaults based on rate limit type)
        let retry_sec = match retry_after_sec {
            Some(s) => {
                // Introduce PR #28's safety buffer: minimum 2 seconds to prevent extremely high-frequency invalid retries
                if s < 2 { 2 } else { s }
            },
            None => {
                match reason {
                    RateLimitReason::QuotaExhausted => {
                        // Quota exhausted: use a longer default (1 hour) to avoid frequent retries
                        tracing::warn!("Detected quota exhausted (QUOTA_EXHAUSTED), using default 3600s (1 hour)");
                        3600
                    },
                    RateLimitReason::RateLimitExceeded => {
                        // Rate limit: use a shorter default (30 seconds) for faster recovery
                        tracing::debug!("Detected rate limit (RATE_LIMIT_EXCEEDED), using default 30s");
                        30
                    },
                    RateLimitReason::ServerError => {
                        // Server error: perform "soft backoff", default lock for 20 seconds
                        tracing::warn!("Detected 5xx error ({}), performing 20s soft backoff...", status);
                        20
                    },
                    RateLimitReason::Unknown => {
                        // Unknown reason: use medium default (60 seconds)
                        tracing::debug!("Unable to parse 429 rate limit reason, using default 60s");
                        60
                    }
                }
            }
        };
        
        let info = RateLimitInfo {
            reset_time: SystemTime::now() + Duration::from_secs(retry_sec),
            retry_after_sec: retry_sec,
            detected_at: SystemTime::now(),
            reason,
        };
        
        // Store
        let key = self.make_key(quota_group, account_id);
        self.limits.insert(key, info.clone());

        tracing::warn!(
            "Account {} (group {}) [{}] rate limit type: {:?}, reset delay: {}s",
            account_id,
            quota_group,
            status,
            reason,
            retry_sec
        );
        
        Some(info)
    }
    
    /// Parse rate limit reason type
    fn parse_rate_limit_reason(&self, body: &str) -> RateLimitReason {
        // Try to extract reason field from JSON
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(reason_str) = json.get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.get(0))
                    .and_then(|o| o.get("reason"))
                    .and_then(|v| v.as_str()) {
                    
                    return match reason_str {
                        "QUOTA_EXHAUSTED" => RateLimitReason::QuotaExhausted,
                        "RATE_LIMIT_EXCEEDED" => RateLimitReason::RateLimitExceeded,
                        _ => RateLimitReason::Unknown,
                    };
                }
            }
        }
        
        // If unable to parse from JSON, try to determine from message text
        if body.contains("exhausted") || body.contains("quota") {
            RateLimitReason::QuotaExhausted
        } else if body.contains("rate limit") || body.contains("too many requests") {
            RateLimitReason::RateLimitExceeded
        } else {
            RateLimitReason::Unknown
        }
    }
    
    /// Generic time parsing function: supports all format combinations like "2h1m1s"
    fn parse_duration_string(&self, s: &str) -> Option<u64> {
        tracing::debug!("[Time parsing] Attempting to parse: '{}'", s);

        // Use regex to extract hours, minutes, seconds, milliseconds
        // Supported formats: "2h1m1s", "1h30m", "5m", "30s", "500ms", etc.
        let re = Regex::new(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?(?:(\d+)ms)?").ok()?;
        let caps = match re.captures(s) {
            Some(c) => c,
            None => {
                tracing::warn!("[Time parsing] Regex did not match: '{}'", s);
                return None;
            }
        };
        
        let hours = caps.get(1)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let minutes = caps.get(2)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        let seconds = caps.get(3)
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .unwrap_or(0.0);
        let milliseconds = caps.get(4)
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .unwrap_or(0);
        
        tracing::debug!("[Time parsing] Extracted: {}h {}m {:.3}s {}ms", hours, minutes, seconds, milliseconds);

        // Calculate total seconds
        let total_seconds = hours * 3600 + minutes * 60 + seconds.ceil() as u64 + (milliseconds + 999) / 1000;

        // If total seconds is 0, parsing failed
        if total_seconds == 0 {
            tracing::warn!("[Time parsing] Failed: '{}' (total seconds is 0)", s);
            None
        } else {
            tracing::info!("[Time parsing] Success: '{}' => {}s ({}h {}m {:.1}s)",
                s, total_seconds, hours, minutes, seconds);
            Some(total_seconds)
        }
    }
    
    /// Parse reset time from error message body
    fn parse_retry_time_from_body(&self, body: &str) -> Option<u64> {
        // A. Prioritize JSON precise parsing (borrowed from PR #28)
        let trimmed = body.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                // 1. Google's common quotaResetDelay format (supports all formats: "2h1m1s", "1h30m", "42s", "500ms", etc.)
                // Path: error.details[0].metadata.quotaResetDelay
                if let Some(delay_str) = json.get("error")
                    .and_then(|e| e.get("details"))
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.get(0))
                    .and_then(|o| o.get("metadata"))  // Add metadata level
                    .and_then(|m| m.get("quotaResetDelay"))
                    .and_then(|v| v.as_str()) {
                    
                    tracing::debug!("[JSON parsing] Found quotaResetDelay: '{}'", delay_str);

                    // Use generic time parsing function
                    if let Some(seconds) = self.parse_duration_string(delay_str) {
                        return Some(seconds);
                    }
                }
                
                // 2. OpenAI's common retry_after field (numeric)
                if let Some(retry) = json.get("error")
                    .and_then(|e| e.get("retry_after"))
                    .and_then(|v| v.as_u64()) {
                    return Some(retry);
                }
            }
        }

        // B. Regex matching patterns (fallback)
        // Pattern 1: "Try again in 2m 30s"
        if let Ok(re) = Regex::new(r"(?i)try again in (\d+)m\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let (Ok(m), Ok(s)) = (caps[1].parse::<u64>(), caps[2].parse::<u64>()) {
                    return Some(m * 60 + s);
                }
            }
        }
        
        // Pattern 2: "Try again in 30s" or "backoff for 42s"
        if let Ok(re) = Regex::new(r"(?i)(?:try again in|backoff for|wait)\s*(\d+)s") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        // Pattern 3: "quota will reset in X seconds"
        if let Ok(re) = Regex::new(r"(?i)quota will reset in (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        // Pattern 4: OpenAI style "Retry after (\d+) seconds"
        if let Ok(re) = Regex::new(r"(?i)retry after (\d+) second") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }

        // Pattern 5: Parenthesis form "(wait (\d+)s)"
        if let Ok(re) = Regex::new(r"\(wait (\d+)s\)") {
            if let Some(caps) = re.captures(body) {
                if let Ok(s) = caps[1].parse::<u64>() {
                    return Some(s);
                }
            }
        }
        
        None
    }
    
    /// Get rate limit information for an account
    pub fn get(&self, quota_group: &str, account_id: &str) -> Option<RateLimitInfo> {
        let key = self.make_key(quota_group, account_id);
        self.limits.get(&key).map(|r| r.clone())
    }
    
    /// Check if account is still rate limited
    pub fn is_rate_limited(&self, quota_group: &str, account_id: &str) -> bool {
        if let Some(info) = self.get(quota_group, account_id) {
            info.reset_time > SystemTime::now()
        } else {
            false
        }
    }
    
    /// Get seconds until rate limit reset
    pub fn get_reset_seconds(&self, quota_group: &str, account_id: &str) -> Option<u64> {
        if let Some(info) = self.get(quota_group, account_id) {
            info.reset_time
                .duration_since(SystemTime::now())
                .ok()
                .map(|d| d.as_secs())
        } else {
            None
        }
    }
    
    /// Clear expired rate limit records
    #[allow(dead_code)]
    pub fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now();
        let mut count = 0;

        self.limits.retain(|_k, v| {
            if v.reset_time <= now {
                count += 1;
                false
            } else {
                true
            }
        });

        if count > 0 {
            tracing::debug!("Cleared {} expired rate limit records", count);
        }

        count
    }
    
    /// Clear rate limit record for a specific account
    #[allow(dead_code)]
    pub fn clear(&self, quota_group: &str, account_id: &str) -> bool {
        let key = self.make_key(quota_group, account_id);
        self.limits.remove(&key).is_some()
    }
    
    /// Clear all rate limit records
    #[allow(dead_code)]
    pub fn clear_all(&self) {
        let count = self.limits.len();
        self.limits.clear();
        tracing::debug!("Cleared all {} rate limit records", count);
    }
}

impl Default for RateLimitTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_retry_time_minutes_seconds() {
        let tracker = RateLimitTracker::new();
        let body = "Rate limit exceeded. Try again in 2m 30s";
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(150)); 
    }
    
    #[test]
    fn test_parse_google_json_delay() {
        let tracker = RateLimitTracker::new();
        // Update test data to match code logic (needs to include metadata)
        let body = r#"{
            "error": {
                "details": [
                    {
                        "metadata": {
                            "quotaResetDelay": "42s"
                        }
                    }
                ]
            }
        }"#;
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(42));
    }

    #[test]
    fn test_parse_retry_after_ignore_case() {
        let tracker = RateLimitTracker::new();
        let body = "Quota limit hit. Retry After 99 Seconds";
        let time = tracker.parse_retry_time_from_body(body);
        assert_eq!(time, Some(99));
    }

    #[test]
    fn test_get_remaining_wait() {
        let tracker = RateLimitTracker::new();
        tracker.parse_from_error("gemini", "acc1", 429, Some("30"), "");
        let wait = tracker.get_remaining_wait("gemini", "acc1");
        assert!(wait > 25 && wait <= 30);
    }

    #[test]
    fn test_safety_buffer() {
        let tracker = RateLimitTracker::new();
        // If API returns 1s, we force it to 2s
        tracker.parse_from_error("gemini", "acc1", 429, Some("1"), "");
        let wait = tracker.get_remaining_wait("gemini", "acc1");
        // Due to time elapsed, remaining time may be 1s or 2s
        assert!(wait >= 1 && wait <= 2);
    }
}
