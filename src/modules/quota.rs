use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::models::QuotaData;

const QUOTA_API_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels";
const USER_AGENT: &str = "antigravity/1.11.3 Darwin/arm64";

#[derive(Debug, Serialize, Deserialize)]
struct QuotaResponse {
    models: std::collections::HashMap<String, ModelInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModelInfo {
    #[serde(rename = "quotaInfo")]
    quota_info: Option<QuotaInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuotaInfo {
    #[serde(rename = "remainingFraction")]
    remaining_fraction: Option<f64>,
    #[serde(rename = "resetTime")]
    reset_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoadProjectResponse {
    #[serde(rename = "cloudaicompanionProject")]
    project_id: Option<String>,
    #[serde(rename = "currentTier")]
    current_tier: Option<Tier>,
    #[serde(rename = "paidTier")]
    paid_tier: Option<Tier>,
}

#[derive(Debug, Deserialize)]
struct Tier {
    id: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "quotaTier")]
    quota_tier: Option<String>,
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    slug: Option<String>,
}

fn create_client() -> reqwest::Client {
    crate::utils::http::create_client(15)
}

const CLOUD_CODE_BASE_URL: &str = "https://cloudcode-pa.googleapis.com";

async fn fetch_project_id(access_token: &str, email: &str) -> (Option<String>, Option<String>) {
    let client = create_client();
    let meta = json!({"metadata": {"ideType": "ANTIGRAVITY"}});

    let res = client
        .post(format!("{}/v1internal:loadCodeAssist", CLOUD_CODE_BASE_URL))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", access_token))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, "antigravity/windows/amd64")
        .json(&meta)
        .send()
        .await;

    match res {
        Ok(res) => {
            if res.status().is_success() {
                if let Ok(data) = res.json::<LoadProjectResponse>().await {
                    let project_id = data.project_id.clone();
                    let subscription_tier = data
                        .paid_tier
                        .and_then(|t| t.id)
                        .or_else(|| data.current_tier.and_then(|t| t.id));

                    if let Some(ref tier) = subscription_tier {
                        crate::modules::logger::log_info(&format!(
                            "📊 [{}] 订阅识别成功: {}",
                            email, tier
                        ));
                    }

                    return (project_id, subscription_tier);
                }
            } else {
                crate::modules::logger::log_warn(&format!(
                    "⚠️  [{}] loadCodeAssist 失败: Status: {}",
                    email,
                    res.status()
                ));
            }
        }
        Err(e) => {
            crate::modules::logger::log_error(&format!(
                "❌ [{}] loadCodeAssist 网络错误: {}",
                email, e
            ));
        }
    }

    (None, None)
}

pub async fn fetch_quota(
    access_token: &str,
    email: &str,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    fetch_quota_inner(access_token, email).await
}

pub async fn fetch_quota_inner(
    access_token: &str,
    email: &str,
) -> crate::error::AppResult<(QuotaData, Option<String>)> {
    use crate::error::AppError;

    let (project_id, subscription_tier) = fetch_project_id(access_token, email).await;
    let final_project_id = project_id.as_deref().unwrap_or("bamboo-precept-lgxtn");

    let client = create_client();
    let payload = json!({
        "project": final_project_id
    });

    let url = QUOTA_API_URL;
    let max_retries = 3;
    let mut last_error: Option<AppError> = None;

    for attempt in 1..=max_retries {
        match client
            .post(url)
            .bearer_auth(access_token)
            .header("User-Agent", USER_AGENT)
            .json(&json!(payload))
            .send()
            .await
        {
            Ok(response) => {
                if let Err(_) = response.error_for_status_ref() {
                    let status = response.status();

                    if status == reqwest::StatusCode::FORBIDDEN {
                        crate::modules::logger::log_warn(
                            "账号无权限 (403 Forbidden),标记为 forbidden 状态",
                        );
                        let mut q = QuotaData::new();
                        q.is_forbidden = true;
                        q.subscription_tier = subscription_tier.clone();
                        return Ok((q, project_id.clone()));
                    }

                    if attempt < max_retries {
                        let text = response.text().await.unwrap_or_default();
                        crate::modules::logger::log_warn(&format!(
                            "API 错误: {} - {} (尝试 {}/{})",
                            status, text, attempt, max_retries
                        ));
                        last_error = Some(AppError::Unknown(format!(
                            "HTTP {} - {}",
                            status, text
                        )));
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    } else {
                        let text = response.text().await.unwrap_or_default();
                        return Err(AppError::Unknown(format!(
                            "API 错误: {} - {}",
                            status, text
                        )));
                    }
                }

                let quota_response: QuotaResponse =
                    response.json().await.map_err(AppError::Network)?;

                let mut quota_data = QuotaData::new();

                tracing::debug!("Quota API 返回了 {} 个模型", quota_response.models.len());

                for (name, info) in quota_response.models {
                    if let Some(quota_info) = info.quota_info {
                        let percentage = quota_info
                            .remaining_fraction
                            .map(|f| (f * 100.0) as i32)
                            .unwrap_or(0);

                        let reset_time = quota_info.reset_time.unwrap_or_default();

                        if name.contains("gemini") || name.contains("claude") {
                            quota_data.add_model(name, percentage, reset_time);
                        }
                    }
                }

                quota_data.subscription_tier = subscription_tier.clone();

                return Ok((quota_data, project_id.clone()));
            }
            Err(e) => {
                crate::modules::logger::log_warn(&format!(
                    "请求失败: {} (尝试 {}/{})",
                    e, attempt, max_retries
                ));
                last_error = Some(AppError::Network(e));
                if attempt < max_retries {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| AppError::Unknown("配额查询失败".to_string())))
}

#[allow(dead_code)]
pub async fn fetch_all_quotas(
    accounts: Vec<(String, String)>,
) -> Vec<(String, crate::error::AppResult<QuotaData>)> {
    let mut results = Vec::new();

    for (account_id, access_token) in accounts {
        let result = fetch_quota(&access_token, &account_id)
            .await
            .map(|(q, _)| q);
        results.push((account_id, result));
    }

    results
}
