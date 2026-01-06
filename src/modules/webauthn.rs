//! WebAuthn (Passkey) 认证模块
//!
//! 实现 FIDO2/WebAuthn 标准的 Passkey 认证流程
//! 支持密码和 Passkey 二选一模式

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

/// 认证模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// 未设置 (首次使用)
    None,
    /// 密码认证
    Password,
    /// Passkey 认证
    Passkey,
}

impl Default for AuthMode {
    fn default() -> Self {
        Self::None
    }
}

/// 认证配置存储
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// 认证模式
    pub mode: AuthMode,
    /// 密码哈希 (仅密码模式)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

impl AuthConfig {
    /// 创建密码认证配置
    pub fn with_password(password: &str) -> Result<Self, String> {
        let hash = hash_password(password)?;
        Ok(Self {
            mode: AuthMode::Password,
            password_hash: Some(hash),
        })
    }

    /// 验证密码
    pub fn verify_password(&self, password: &str) -> bool {
        if self.mode != AuthMode::Password {
            return false;
        }
        match &self.password_hash {
            Some(hash) => verify_password(password, hash),
            None => false,
        }
    }
}

/// 使用 argon2 哈希密码
fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// 验证密码
fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// WebAuthn 配置
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying Party ID (通常是域名)
    pub rp_id: String,
    /// Relying Party 名称
    pub rp_name: String,
    /// Relying Party Origin (完整 URL)
    pub rp_origin: Url,
}

impl WebAuthnConfig {
    /// 从请求 Host 头动态创建配置
    pub fn from_host(host: &str, port: u16, is_https: bool) -> Result<Self, String> {
        let scheme = if is_https { "https" } else { "http" };

        // 解析 host，可能包含端口
        let (hostname, _) = host.split_once(':').unwrap_or((host, ""));
        let hostname = if hostname.is_empty() { "localhost" } else { hostname };

        let origin_str = if (is_https && port == 443) || (!is_https && port == 80) {
            format!("{}://{}", scheme, hostname)
        } else {
            format!("{}://{}:{}", scheme, hostname, port)
        };

        let rp_origin = Url::parse(&origin_str)
            .map_err(|e| format!("Invalid origin URL: {}", e))?;

        Ok(Self {
            rp_id: hostname.to_string(),
            rp_name: "AntiProxy".to_string(),
            rp_origin,
        })
    }

    /// 默认本地配置
    pub fn localhost(port: u16) -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "AntiProxy".to_string(),
            rp_origin: Url::parse(&format!("http://localhost:{}", port)).unwrap(),
        }
    }
}

/// 存储的 Passkey 凭据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// 凭据 ID
    pub credential_id: String,
    /// 用户 ID
    pub user_id: String,
    /// 用户显示名称
    pub user_name: String,
    /// 序列化的 Passkey 数据
    pub passkey_json: String,
    /// 创建时间
    pub created_at: i64,
    /// 最后使用时间
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct AuthStateEntry {
    state_json: String,
    created_at: i64,
}

/// WebAuthn 管理器
pub struct WebAuthnManager {
    /// 凭据存储路径
    credentials_path: PathBuf,
    /// 认证配置路径
    auth_config_path: PathBuf,
    /// 缓存的凭据列表
    credentials: Arc<RwLock<Vec<StoredCredential>>>,
    /// 认证配置
    auth_config: Arc<RwLock<AuthConfig>>,
    /// 注册状态缓存 (challenge -> state, with TTL)
    reg_states: Arc<RwLock<std::collections::HashMap<String, AuthStateEntry>>>,
    /// 认证状态缓存 (challenge -> state, with TTL)
    auth_states: Arc<RwLock<std::collections::HashMap<String, AuthStateEntry>>>,
}

impl WebAuthnManager {
    /// 创建新的 WebAuthn 管理器
    pub fn new(data_dir: PathBuf) -> Self {
        let credentials_path = data_dir.join("passkeys.json");
        let auth_config_path = data_dir.join("auth_config.json");

        Self {
            credentials_path,
            auth_config_path,
            credentials: Arc::new(RwLock::new(Vec::new())),
            auth_config: Arc::new(RwLock::new(AuthConfig::default())),
            reg_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            auth_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// 加载认证配置
    pub async fn load_auth_config(&self) -> Result<(), String> {
        if !self.auth_config_path.exists() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&self.auth_config_path)
            .await
            .map_err(|e| format!("Failed to read auth config: {}", e))?;

        let config: AuthConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse auth config: {}", e))?;

        let mut auth_config = self.auth_config.write().await;
        *auth_config = config;

        Ok(())
    }

    /// 保存认证配置
    async fn save_auth_config(&self) -> Result<(), String> {
        let config = self.auth_config.read().await;
        let content = serde_json::to_string_pretty(&*config)
            .map_err(|e| format!("Failed to serialize auth config: {}", e))?;

        // 确保目录存在
        if let Some(parent) = self.auth_config_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        tokio::fs::write(&self.auth_config_path, content)
            .await
            .map_err(|e| format!("Failed to write auth config: {}", e))?;

        Ok(())
    }

    /// 获取当前认证模式
    pub async fn get_auth_mode(&self) -> AuthMode {
        let config = self.auth_config.read().await;
        config.mode.clone()
    }

    /// 设置密码认证
    pub async fn setup_password(&self, password: &str) -> Result<(), String> {
        // 检查是否已有认证模式
        let current_mode = self.get_auth_mode().await;
        if current_mode != AuthMode::None {
            return Err("Authentication is already configured. Reset first to change mode.".to_string());
        }

        // 验证密码强度
        if password.len() < 6 {
            return Err("Password must be at least 6 characters".to_string());
        }

        let config = AuthConfig::with_password(password)?;

        {
            let mut auth_config = self.auth_config.write().await;
            *auth_config = config;
        }

        self.save_auth_config().await?;
        tracing::info!("Password authentication configured");

        Ok(())
    }

    /// 验证密码
    pub async fn verify_password(&self, password: &str) -> bool {
        let config = self.auth_config.read().await;
        config.verify_password(password)
    }

    /// 更改密码
    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<(), String> {
        // 验证旧密码
        if !self.verify_password(old_password).await {
            return Err("Current password is incorrect".to_string());
        }

        // 验证新密码强度
        if new_password.len() < 6 {
            return Err("New password must be at least 6 characters".to_string());
        }

        let new_config = AuthConfig::with_password(new_password)?;

        {
            let mut auth_config = self.auth_config.write().await;
            *auth_config = new_config;
        }

        self.save_auth_config().await?;
        tracing::info!("Password changed successfully");

        Ok(())
    }

    /// 重置认证 (危险操作，需要当前认证)
    pub async fn reset_auth(&self) -> Result<(), String> {
        // 清除 passkeys
        {
            let mut credentials = self.credentials.write().await;
            credentials.clear();
        }
        if self.credentials_path.exists() {
            tokio::fs::remove_file(&self.credentials_path)
                .await
                .map_err(|e| format!("Failed to remove credentials file: {}", e))?;
        }

        // 重置配置
        {
            let mut auth_config = self.auth_config.write().await;
            *auth_config = AuthConfig::default();
        }
        self.save_auth_config().await?;

        tracing::info!("Authentication reset");
        Ok(())
    }

    /// 加载凭据
    pub async fn load_credentials(&self) -> Result<(), String> {
        if !self.credentials_path.exists() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&self.credentials_path)
            .await
            .map_err(|e| format!("Failed to read credentials: {}", e))?;

        let creds: Vec<StoredCredential> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse credentials: {}", e))?;

        let mut credentials = self.credentials.write().await;
        *credentials = creds;

        Ok(())
    }

    /// 保存凭据
    async fn save_credentials(&self) -> Result<(), String> {
        let credentials = self.credentials.read().await;
        let content = serde_json::to_string_pretty(&*credentials)
            .map_err(|e| format!("Failed to serialize credentials: {}", e))?;

        tokio::fs::write(&self.credentials_path, content)
            .await
            .map_err(|e| format!("Failed to write credentials: {}", e))?;

        Ok(())
    }

    /// 检查是否有已注册的凭据
    pub async fn has_credentials(&self) -> bool {
        let credentials = self.credentials.read().await;
        !credentials.is_empty()
    }

    /// 获取凭据数量
    pub async fn credential_count(&self) -> usize {
        let credentials = self.credentials.read().await;
        credentials.len()
    }

    /// 开始注册流程
    pub async fn start_registration(
        &self,
        config: &WebAuthnConfig,
        user_name: &str,
    ) -> Result<(CreationChallengeResponse, String), String> {
        // 检查认证模式
        let current_mode = self.get_auth_mode().await;
        if current_mode == AuthMode::Password {
            return Err("Password authentication is configured. Reset to switch to Passkey.".to_string());
        }

        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        // 生成用户 ID
        let user_id = uuid::Uuid::new_v4();

        // 获取现有凭据以排除
        let credentials = self.credentials.read().await;
        let exclude_credentials: Vec<CredentialID> = credentials
            .iter()
            .filter_map(|c| {
                let passkey: Passkey = serde_json::from_str(&c.passkey_json).ok()?;
                Some(passkey.cred_id().clone())
            })
            .collect();
        drop(credentials);

        let (ccr, reg_state) = webauthn
            .start_passkey_registration(user_id, user_name, user_name, Some(exclude_credentials))
            .map_err(|e| format!("Failed to start registration: {}", e))?;

        // 序列化状态并存储
        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| format!("Failed to serialize reg state: {}", e))?;

        let challenge_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_string(&ccr.public_key.challenge)
                .unwrap_or_default()
                .as_bytes(),
        );

        let mut reg_states = self.reg_states.write().await;
        reg_states.insert(
            challenge_b64.clone(),
            AuthStateEntry {
                state_json,
                created_at: chrono::Utc::now().timestamp(),
            },
        );

        Ok((ccr, challenge_b64))
    }

    /// 完成注册流程
    pub async fn finish_registration(
        &self,
        config: &WebAuthnConfig,
        challenge: &str,
        response: RegisterPublicKeyCredential,
        user_name: &str,
    ) -> Result<(), String> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        // 获取并移除注册状态
        let state_entry = {
            let mut reg_states = self.reg_states.write().await;
            reg_states.remove(challenge)
                .ok_or("Registration challenge not found or expired")?
        };

        let now = chrono::Utc::now().timestamp();
        if now - state_entry.created_at > 300 {
            return Err("Registration challenge expired".to_string());
        }

        let reg_state: PasskeyRegistration = serde_json::from_str(&state_entry.state_json)
            .map_err(|e| format!("Failed to deserialize reg state: {}", e))?;

        // 完成注册
        let passkey = webauthn
            .finish_passkey_registration(&response, &reg_state)
            .map_err(|e| format!("Failed to finish registration: {}", e))?;

        // 存储凭据
        let passkey_json = serde_json::to_string(&passkey)
            .map_err(|e| format!("Failed to serialize passkey: {}", e))?;

        let credential_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            passkey.cred_id().as_ref(),
        );

        let stored = StoredCredential {
            credential_id,
            user_id: uuid::Uuid::new_v4().to_string(),
            user_name: user_name.to_string(),
            passkey_json,
            created_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
        };

        {
            let mut credentials = self.credentials.write().await;
            credentials.push(stored);
        }

        self.save_credentials().await?;

        // 设置认证模式为 Passkey (如果是首次注册)
        let current_mode = self.get_auth_mode().await;
        if current_mode == AuthMode::None {
            let mut auth_config = self.auth_config.write().await;
            auth_config.mode = AuthMode::Passkey;
            drop(auth_config);
            self.save_auth_config().await?;
            tracing::info!("Authentication mode set to Passkey");
        }

        Ok(())
    }

    /// 开始认证流程
    pub async fn start_authentication(
        &self,
        config: &WebAuthnConfig,
    ) -> Result<(RequestChallengeResponse, String), String> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        // 获取所有已注册的 passkeys
        let credentials = self.credentials.read().await;
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter_map(|c| serde_json::from_str(&c.passkey_json).ok())
            .collect();
        drop(credentials);

        if passkeys.is_empty() {
            return Err("No registered passkeys".to_string());
        }

        let (rcr, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| format!("Failed to start authentication: {}", e))?;

        // 序列化状态并存储
        let state_json = serde_json::to_string(&auth_state)
            .map_err(|e| format!("Failed to serialize auth state: {}", e))?;

        let challenge_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_string(&rcr.public_key.challenge)
                .unwrap_or_default()
                .as_bytes(),
        );

        let mut auth_states = self.auth_states.write().await;
        auth_states.insert(
            challenge_b64.clone(),
            AuthStateEntry {
                state_json,
                created_at: chrono::Utc::now().timestamp(),
            },
        );

        Ok((rcr, challenge_b64))
    }

    /// 完成认证流程
    pub async fn finish_authentication(
        &self,
        config: &WebAuthnConfig,
        challenge: &str,
        response: PublicKeyCredential,
    ) -> Result<String, String> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        // 获取并移除认证状态
        let state_entry = {
            let mut auth_states = self.auth_states.write().await;
            auth_states.remove(challenge)
                .ok_or("Authentication challenge not found or expired")?
        };

        let now = chrono::Utc::now().timestamp();
        if now - state_entry.created_at > 300 {
            return Err("Authentication challenge expired".to_string());
        }

        let auth_state: PasskeyAuthentication = serde_json::from_str(&state_entry.state_json)
            .map_err(|e| format!("Failed to deserialize auth state: {}", e))?;

        // 完成认证
        let auth_result = webauthn
            .finish_passkey_authentication(&response, &auth_state)
            .map_err(|e| format!("Failed to finish authentication: {}", e))?;

        // 更新凭据的最后使用时间
        let cred_id_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            auth_result.cred_id().as_ref(),
        );

        {
            let mut credentials = self.credentials.write().await;
            if let Some(cred) = credentials.iter_mut().find(|c| c.credential_id == cred_id_b64) {
                cred.last_used_at = Some(chrono::Utc::now().timestamp());

                // 更新 passkey 的计数器
                if let Ok(mut passkey) = serde_json::from_str::<Passkey>(&cred.passkey_json) {
                    passkey.update_credential(&auth_result);
                    if let Ok(updated_json) = serde_json::to_string(&passkey) {
                        cred.passkey_json = updated_json;
                    }
                }
            }
        }

        self.save_credentials().await?;

        // 生成 session token
        let session_token = uuid::Uuid::new_v4().to_string();

        Ok(session_token)
    }

    /// 删除凭据
    pub async fn delete_credential(&self, credential_id: &str) -> Result<(), String> {
        {
            let mut credentials = self.credentials.write().await;
            let original_len = credentials.len();
            credentials.retain(|c| c.credential_id != credential_id);

            if credentials.len() == original_len {
                return Err("Credential not found".to_string());
            }
        }

        self.save_credentials().await
    }

    /// 列出所有凭据 (不包含敏感数据)
    pub async fn list_credentials(&self) -> Vec<CredentialInfo> {
        let credentials = self.credentials.read().await;
        credentials
            .iter()
            .map(|c| CredentialInfo {
                credential_id: c.credential_id.clone(),
                user_name: c.user_name.clone(),
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect()
    }

    /// 清理过期的注册/认证状态 (5分钟过期)
    pub async fn cleanup_expired_states(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut reg_states = self.reg_states.write().await;
        reg_states.retain(|_, entry| now - entry.created_at <= 300);

        let mut auth_states = self.auth_states.write().await;
        auth_states.retain(|_, entry| now - entry.created_at <= 300);
    }
}

/// 凭据信息 (公开)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub credential_id: String,
    pub user_name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// Session 管理器
pub struct SessionManager {
    /// 活跃的 sessions (token -> expiry timestamp)
    sessions: Arc<RwLock<std::collections::HashMap<String, i64>>>,
    /// Session 有效期 (秒)
    session_ttl: i64,
}

impl SessionManager {
    pub fn new(session_ttl_hours: i64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            session_ttl: session_ttl_hours * 3600,
        }
    }

    /// 创建新 session
    pub async fn create_session(&self) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let expiry = chrono::Utc::now().timestamp() + self.session_ttl;

        let mut sessions = self.sessions.write().await;
        sessions.insert(token.clone(), expiry);

        token
    }

    /// 验证 session
    pub async fn validate_session(&self, token: &str) -> bool {
        let sessions = self.sessions.read().await;

        if let Some(&expiry) = sessions.get(token) {
            let now = chrono::Utc::now().timestamp();
            expiry > now
        } else {
            false
        }
    }

    /// 刷新 session
    pub async fn refresh_session(&self, token: &str) -> bool {
        let mut sessions = self.sessions.write().await;

        if sessions.contains_key(token) {
            let expiry = chrono::Utc::now().timestamp() + self.session_ttl;
            sessions.insert(token.to_string(), expiry);
            true
        } else {
            false
        }
    }

    /// 删除 session
    pub async fn delete_session(&self, token: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(token);
    }

    /// 清理过期 sessions
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, &mut expiry| expiry > now);
    }
}
