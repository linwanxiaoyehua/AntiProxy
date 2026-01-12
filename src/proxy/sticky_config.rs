use serde::{Deserialize, Serialize};

/// Scheduling mode enumeration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SchedulingMode {
    /// Cache-first: Lock to the same account as much as possible, prefer to wait when rate limited, greatly improves Prompt Caching hit rate
    CacheFirst,
    /// Balance: Lock to the same account, immediately switch to backup account when rate limited, balancing success rate and performance
    Balance,
    /// Performance-first: Pure round-robin mode, most balanced account load, but doesn't utilize cache
    PerformanceFirst,
}

impl Default for SchedulingMode {
    fn default() -> Self {
        Self::Balance
    }
}

/// Sticky session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickySessionConfig {
    /// Current scheduling mode
    pub mode: SchedulingMode,
    /// Maximum wait time in cache-first mode (seconds)
    pub max_wait_seconds: u64,
}

impl Default for StickySessionConfig {
    fn default() -> Self {
        Self {
            // Default to CacheFirst mode to avoid multi-account consumption within a single session
            // When account is rate limited, will wait (up to max_wait_seconds) instead of switching accounts
            mode: SchedulingMode::CacheFirst,
            max_wait_seconds: 120,  // Maximum wait 2 minutes
        }
    }
}
