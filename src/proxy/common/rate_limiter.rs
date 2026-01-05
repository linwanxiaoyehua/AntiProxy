// Rate Limiter
// 确保 API 调用间隔 ≥ 500ms

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

pub struct RateLimiter {
    min_interval: Duration,
    last_call: Arc<Mutex<Option<Instant>>>,
}

impl RateLimiter {
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval: Duration::from_millis(min_interval_ms),
            last_call: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn wait(&self) {
        let mut last = self.last_call.lock().await;
        if let Some(last_time) = *last {
            let elapsed = last_time.elapsed();
            if elapsed < self.min_interval {
                sleep(self.min_interval - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(500);
        let start = Instant::now();

        limiter.wait().await; // 第一次调用，立即返回
        let elapsed1 = start.elapsed().as_millis();
        assert!(elapsed1 < 50);

        limiter.wait().await; // 第二次调用，等待 500ms
        let elapsed2 = start.elapsed().as_millis();
        assert!(elapsed2 >= 500 && elapsed2 < 600);
    }
}
