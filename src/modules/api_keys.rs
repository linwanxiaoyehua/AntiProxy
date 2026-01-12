//! API Keys management module
//! Supports multi-key isolation and usage tracking

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// API Key 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key: String,
    pub enabled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub success_count: u64,
    /// Failed requests
    pub error_count: u64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
}

/// API Key usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiKeyUsage {
    pub total_requests: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

/// Create API Key request
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

/// API Key response (hides full key)
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key_preview: String,
    pub enabled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub usage: ApiKeyUsage,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        let key_preview = if key.key.len() > 12 {
            format!("{}...{}", &key.key[..8], &key.key[key.key.len()-4..])
        } else {
            key.key.clone()
        };

        Self {
            id: key.id,
            name: key.name,
            key_preview,
            enabled: key.enabled,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            usage: ApiKeyUsage {
                total_requests: key.total_requests,
                success_count: key.success_count,
                error_count: key.error_count,
                total_input_tokens: key.total_input_tokens,
                total_output_tokens: key.total_output_tokens,
            },
        }
    }
}

fn get_db_path() -> Result<PathBuf, String> {
    let data_dir = crate::modules::account::get_data_dir()?;
    Ok(data_dir.join("api_keys.db"))
}

/// Initialize database
pub fn init_db() -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            key TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            total_requests INTEGER NOT NULL DEFAULT 0,
            success_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            total_input_tokens INTEGER NOT NULL DEFAULT 0,
            total_output_tokens INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Create key index for fast lookup
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys (key)",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Generate new API Key
pub fn generate_key() -> String {
    format!("sk-{}", uuid::Uuid::new_v4().simple())
}

/// Create new API Key
pub fn create_api_key(name: &str) -> Result<ApiKey, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let id = uuid::Uuid::new_v4().to_string();
    let key = generate_key();
    let created_at = chrono::Utc::now().timestamp();

    conn.execute(
        "INSERT INTO api_keys (id, name, key, enabled, created_at, total_requests, success_count, error_count, total_input_tokens, total_output_tokens)
         VALUES (?1, ?2, ?3, 1, ?4, 0, 0, 0, 0, 0)",
        params![id, name, key, created_at],
    )
    .map_err(|e| e.to_string())?;

    Ok(ApiKey {
        id,
        name: name.to_string(),
        key,
        enabled: true,
        created_at,
        last_used_at: None,
        total_requests: 0,
        success_count: 0,
        error_count: 0,
        total_input_tokens: 0,
        total_output_tokens: 0,
    })
}

/// Get all API Keys
pub fn list_api_keys() -> Result<Vec<ApiKey>, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, key, enabled, created_at, last_used_at,
                    total_requests, success_count, error_count,
                    total_input_tokens, total_output_tokens
             FROM api_keys ORDER BY created_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let keys_iter = stmt
        .query_map([], |row| {
            Ok(ApiKey {
                id: row.get(0)?,
                name: row.get(1)?,
                key: row.get(2)?,
                enabled: row.get::<_, i32>(3)? == 1,
                created_at: row.get(4)?,
                last_used_at: row.get(5)?,
                total_requests: row.get::<_, i64>(6)? as u64,
                success_count: row.get::<_, i64>(7)? as u64,
                error_count: row.get::<_, i64>(8)? as u64,
                total_input_tokens: row.get::<_, i64>(9)? as u64,
                total_output_tokens: row.get::<_, i64>(10)? as u64,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut keys = Vec::new();
    for key in keys_iter {
        keys.push(key.map_err(|e| e.to_string())?);
    }
    Ok(keys)
}

/// Find API Key by key string (for authentication)
pub fn find_by_key(key_str: &str) -> Result<Option<ApiKey>, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, key, enabled, created_at, last_used_at,
                    total_requests, success_count, error_count,
                    total_input_tokens, total_output_tokens
             FROM api_keys WHERE key = ?1",
        )
        .map_err(|e| e.to_string())?;

    let result = stmt.query_row([key_str], |row| {
        Ok(ApiKey {
            id: row.get(0)?,
            name: row.get(1)?,
            key: row.get(2)?,
            enabled: row.get::<_, i32>(3)? == 1,
            created_at: row.get(4)?,
            last_used_at: row.get(5)?,
            total_requests: row.get::<_, i64>(6)? as u64,
            success_count: row.get::<_, i64>(7)? as u64,
            error_count: row.get::<_, i64>(8)? as u64,
            total_input_tokens: row.get::<_, i64>(9)? as u64,
            total_output_tokens: row.get::<_, i64>(10)? as u64,
        })
    });

    match result {
        Ok(key) => Ok(Some(key)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Get single API Key
pub fn get_api_key(id: &str) -> Result<Option<ApiKey>, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT id, name, key, enabled, created_at, last_used_at,
                    total_requests, success_count, error_count,
                    total_input_tokens, total_output_tokens
             FROM api_keys WHERE id = ?1",
        )
        .map_err(|e| e.to_string())?;

    let result = stmt.query_row([id], |row| {
        Ok(ApiKey {
            id: row.get(0)?,
            name: row.get(1)?,
            key: row.get(2)?,
            enabled: row.get::<_, i32>(3)? == 1,
            created_at: row.get(4)?,
            last_used_at: row.get(5)?,
            total_requests: row.get::<_, i64>(6)? as u64,
            success_count: row.get::<_, i64>(7)? as u64,
            error_count: row.get::<_, i64>(8)? as u64,
            total_input_tokens: row.get::<_, i64>(9)? as u64,
            total_output_tokens: row.get::<_, i64>(10)? as u64,
        })
    });

    match result {
        Ok(key) => Ok(Some(key)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Update API Key name
pub fn update_api_key_name(id: &str, name: &str) -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE api_keys SET name = ?1 WHERE id = ?2",
        params![name, id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Enable/disable API Key
pub fn set_api_key_enabled(id: &str, enabled: bool) -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE api_keys SET enabled = ?1 WHERE id = ?2",
        params![if enabled { 1 } else { 0 }, id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Delete API Key
pub fn delete_api_key(id: &str) -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Regenerate API Key
pub fn regenerate_api_key(id: &str) -> Result<String, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let new_key = generate_key();

    conn.execute(
        "UPDATE api_keys SET key = ?1 WHERE id = ?2",
        params![new_key, id],
    )
    .map_err(|e| e.to_string())?;

    Ok(new_key)
}

/// Record API Key usage (for statistics)
pub fn record_usage(
    key_str: &str,
    success: bool,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
) -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let now = chrono::Utc::now().timestamp();
    let input = input_tokens.unwrap_or(0) as i64;
    let output = output_tokens.unwrap_or(0) as i64;

    if success {
        conn.execute(
            "UPDATE api_keys SET
                last_used_at = ?1,
                total_requests = total_requests + 1,
                success_count = success_count + 1,
                total_input_tokens = total_input_tokens + ?2,
                total_output_tokens = total_output_tokens + ?3
             WHERE key = ?4",
            params![now, input, output, key_str],
        )
        .map_err(|e| e.to_string())?;
    } else {
        conn.execute(
            "UPDATE api_keys SET
                last_used_at = ?1,
                total_requests = total_requests + 1,
                error_count = error_count + 1
             WHERE key = ?2",
            params![now, key_str],
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Reset API Key usage statistics
pub fn reset_usage(id: &str) -> Result<(), String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE api_keys SET
            total_requests = 0,
            success_count = 0,
            error_count = 0,
            total_input_tokens = 0,
            total_output_tokens = 0
         WHERE id = ?1",
        params![id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Get total usage of all API Keys
pub fn get_total_usage() -> Result<ApiKeyUsage, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let result = conn.query_row(
        "SELECT
            COALESCE(SUM(total_requests), 0),
            COALESCE(SUM(success_count), 0),
            COALESCE(SUM(error_count), 0),
            COALESCE(SUM(total_input_tokens), 0),
            COALESCE(SUM(total_output_tokens), 0)
         FROM api_keys",
        [],
        |row| {
            Ok(ApiKeyUsage {
                total_requests: row.get::<_, i64>(0)? as u64,
                success_count: row.get::<_, i64>(1)? as u64,
                error_count: row.get::<_, i64>(2)? as u64,
                total_input_tokens: row.get::<_, i64>(3)? as u64,
                total_output_tokens: row.get::<_, i64>(4)? as u64,
            })
        },
    );

    match result {
        Ok(usage) => Ok(usage),
        Err(_) => Ok(ApiKeyUsage::default()),
    }
}

/// Check if any API Key exists
pub fn has_any_keys() -> Result<bool, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM api_keys", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    Ok(count > 0)
}

/// Migrate old single API Key to new multi-key system
pub fn migrate_legacy_key(legacy_key: &str) -> Result<(), String> {
    if legacy_key.is_empty() {
        return Ok(());
    }

    // Check if this key already exists
    if let Ok(Some(_)) = find_by_key(legacy_key) {
        return Ok(()); // Already exists, no migration needed
    }

    // Check if any keys already exist
    if has_any_keys()? {
        return Ok(()); // Keys already exist, no migration needed
    }

    // Create the migrated key
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    let id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().timestamp();

    conn.execute(
        "INSERT INTO api_keys (id, name, key, enabled, created_at, total_requests, success_count, error_count, total_input_tokens, total_output_tokens)
         VALUES (?1, ?2, ?3, 1, ?4, 0, 0, 0, 0, 0)",
        params![id, "Default (Migrated)", legacy_key, created_at],
    )
    .map_err(|e| e.to_string())?;

    tracing::info!("Migrated legacy API key to new multi-key system");
    Ok(())
}
