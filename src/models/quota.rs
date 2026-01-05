use serde::{Deserialize, Serialize};

/// 模型配额信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelQuota {
    pub name: String,
    pub percentage: i32,  // 剩余百分比 0-100
    pub reset_time: String,
}

/// 配额数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaData {
    pub models: Vec<ModelQuota>,
    pub last_updated: i64,
    #[serde(default)]
    pub is_forbidden: bool,
    /// 订阅等级 (FREE/PRO/ULTRA)
    #[serde(default)]
    pub subscription_tier: Option<String>,
}

impl QuotaData {
    pub fn new() -> Self {
        Self {
            models: Vec::new(),
            last_updated: chrono::Utc::now().timestamp(),
            is_forbidden: false,
            subscription_tier: None,
        }
    }

    pub fn add_model(&mut self, name: String, percentage: i32, reset_time: String) {
        self.models.push(ModelQuota {
            name,
            percentage,
            reset_time,
        });
    }
}

impl Default for QuotaData {
    fn default() -> Self {
        Self::new()
    }
}
