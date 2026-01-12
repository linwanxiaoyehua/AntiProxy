use std::fs;
use std::path::PathBuf;
use serde_json;
use uuid::Uuid;

use crate::models::{Account, AccountIndex, AccountSummary, TokenData, QuotaData};
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global account write lock to prevent concurrent operations from corrupting the index file
static ACCOUNT_INDEX_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// ... existing constants ...
const DATA_DIR: &str = ".AntiProxy";
const LEGACY_DATA_DIR: &str = ".antigravity_proxy";
const ACCOUNTS_INDEX: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";

// ... existing functions get_data_dir, get_accounts_dir, load_account_index, save_account_index ...
/// Get data directory path
pub fn get_data_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Failed to get user home directory")?;
    let data_dir = home.join(DATA_DIR);
    let legacy_dir = home.join(LEGACY_DATA_DIR);

    if !data_dir.exists() && legacy_dir.exists() {
        return Ok(legacy_dir);
    }
    
    // Ensure directory exists
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;
    }
    
    Ok(data_dir)
}

/// Get accounts directory path
pub fn get_accounts_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let accounts_dir = data_dir.join(ACCOUNTS_DIR);

    if !accounts_dir.exists() {
        fs::create_dir_all(&accounts_dir)
            .map_err(|e| format!("Failed to create accounts directory: {}", e))?;
    }
    
    Ok(accounts_dir)
}

/// Load account index
pub fn load_account_index() -> Result<AccountIndex, String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);
    // modules::logger::log_info(&format!("Loading account index: {:?}", index_path)); // Optional: reduce noise

    if !index_path.exists() {
        crate::modules::logger::log_warn("Account index file does not exist");
        return Ok(AccountIndex::new());
    }

    let content = fs::read_to_string(&index_path)
        .map_err(|e| format!("Failed to read account index: {}", e))?;

    let index: AccountIndex = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse account index: {}", e))?;

    crate::modules::logger::log_info(&format!("Successfully loaded index with {} accounts", index.accounts.len()));
    Ok(index)
}

/// Save account index (atomic write)
pub fn save_account_index(index: &AccountIndex) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);
    let temp_path = data_dir.join(format!("{}.tmp", ACCOUNTS_INDEX));

    let content = serde_json::to_string_pretty(index)
        .map_err(|e| format!("Failed to serialize account index: {}", e))?;

    // Write to temporary file
    fs::write(&temp_path, content)
        .map_err(|e| format!("Failed to write temporary index file: {}", e))?;

    // Atomic rename
    fs::rename(temp_path, index_path)
        .map_err(|e| format!("Failed to replace index file: {}", e))
}

/// Load account data
pub fn load_account(account_id: &str) -> Result<Account, String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));

    if !account_path.exists() {
        return Err(format!("Account does not exist: {}", account_id));
    }

    let content = fs::read_to_string(&account_path)
        .map_err(|e| format!("Failed to read account data: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse account data: {}", e))
}

/// Save account data
pub fn save_account(account: &Account) -> Result<(), String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account.id));

    let content = serde_json::to_string_pretty(account)
        .map_err(|e| format!("Failed to serialize account data: {}", e))?;

    fs::write(&account_path, content)
        .map_err(|e| format!("Failed to save account data: {}", e))
}

/// List all accounts
/// List all accounts
pub fn list_accounts() -> Result<Vec<Account>, String> {
    crate::modules::logger::log_info("Started listing accounts...");
    let mut index = load_account_index()?;
    let mut accounts = Vec::new();
    let mut invalid_ids = Vec::new();

    for summary in &index.accounts {
        match load_account(&summary.id) {
            Ok(account) => accounts.push(account),
            Err(e) => {
                crate::modules::logger::log_error(&format!("Failed to load account {}: {}", summary.id, e));
                // If the error is due to file not existing, mark as invalid ID
                // load_account returns "Account does not exist: id" or underlying io error
                if e.contains("Account does not exist") || e.contains("Os { code: 2,") || e.contains("No such file") {
                    invalid_ids.push(summary.id.clone());
                }
            },
        }
    }

    // Auto-repair index: remove invalid account IDs
    if !invalid_ids.is_empty() {
        crate::modules::logger::log_warn(&format!("Found {} invalid account indexes, auto-cleaning...", invalid_ids.len()));

        index.accounts.retain(|s| !invalid_ids.contains(&s.id));

        // If the currently selected account is also invalid, reset to the first available account
        if let Some(current_id) = &index.current_account_id {
            if invalid_ids.contains(current_id) {
                index.current_account_id = index.accounts.first().map(|s| s.id.clone());
            }
        }

        if let Err(e) = save_account_index(&index) {
            crate::modules::logger::log_error(&format!("Failed to auto-clean index: {}", e));
        } else {
            crate::modules::logger::log_info("Index auto-cleanup completed");
        }
    }

    // modules::logger::log_info(&format!("Found {} valid accounts", accounts.len()));
    Ok(accounts)
}

/// Add account
pub fn add_account(email: String, name: Option<String>, token: TokenData) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;

    // Check if already exists
    if index.accounts.iter().any(|s| s.email == email) {
        return Err(format!("Account already exists: {}", email));
    }

    // Create new account
    let account_id = Uuid::new_v4().to_string();
    let mut account = Account::new(account_id.clone(), email.clone(), token);
    account.name = name.clone();

    // Save account data
    save_account(&account)?;

    // Update index
    index.accounts.push(AccountSummary {
        id: account_id.clone(),
        email: email.clone(),
        name: name.clone(),
        created_at: account.created_at,
        last_used: account.last_used,
    });

    // If this is the first account, set as current account
    if index.current_account_id.is_none() {
        index.current_account_id = Some(account_id);
    }

    save_account_index(&index)?;

    Ok(account)
}

/// Add or update account
pub fn upsert_account(email: String, name: Option<String>, token: TokenData) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;

    // First find the account ID (if exists)
    let existing_account_id = index.accounts.iter()
        .find(|s| s.email == email)
        .map(|s| s.id.clone());

    if let Some(account_id) = existing_account_id {
        // Update existing account
        match load_account(&account_id) {
            Ok(mut account) => {
                let old_access_token = account.token.access_token.clone();
                let old_refresh_token = account.token.refresh_token.clone();
                account.token = token;
                account.name = name.clone();
                // If an account was previously disabled (e.g. invalid_grant), any explicit token upsert
                // should re-enable it (user manually updated credentials in the UI).
                if account.disabled
                    && (account.token.refresh_token != old_refresh_token
                        || account.token.access_token != old_access_token)
                {
                    account.disabled = false;
                    account.disabled_reason = None;
                    account.disabled_at = None;
                }
                account.update_last_used();
                save_account(&account)?;

                // Sync update name in index
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.name = name;
                    save_account_index(&index)?;
                }

                return Ok(account);
            },
            Err(e) => {
                crate::modules::logger::log_warn(&format!("Account {} file missing ({}), recreating...", account_id, e));
                // Index exists but file is missing, recreate
                let mut account = Account::new(account_id.clone(), email.clone(), token);
                account.name = name.clone();
                save_account(&account)?;

                // Sync update name in index
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.name = name;
                    save_account_index(&index)?;
                }

                return Ok(account);
            }
        }
    }

    // Does not exist, add new account
    // Note: Here we manually call add_account, which also tries to acquire the lock,
    // but due to Mutex library limitations it would deadlock.
    // So we need an internal version without lock, or refactor. For simplicity, we expand the add logic or avoid re-locking

    // Release lock, let add_account handle it
    drop(_lock);
    add_account(email, name, token)
}

/// Delete account
pub fn delete_account(account_id: &str) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;

    // Remove from index
    let original_len = index.accounts.len();
    index.accounts.retain(|s| s.id != account_id);

    if index.accounts.len() == original_len {
        return Err(format!("Account ID not found: {}", account_id));
    }

    // If it's the current account, clear current account
    if index.current_account_id.as_deref() == Some(account_id) {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }

    save_account_index(&index)?;

    // Delete account file
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));

    if account_path.exists() {
        fs::remove_file(&account_path)
            .map_err(|e| format!("Failed to delete account file: {}", e))?;
    }

    Ok(())
}

/// Batch delete accounts (atomic index operation)
pub fn delete_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;

    let accounts_dir = get_accounts_dir()?;

    for account_id in account_ids {
        // Remove from index
        index.accounts.retain(|s| &s.id != account_id);

        // If it's the current account, clear current account
        if index.current_account_id.as_deref() == Some(account_id) {
            index.current_account_id = None;
        }

        // Delete account file
        let account_path = accounts_dir.join(format!("{}.json", account_id));
        if account_path.exists() {
            let _ = fs::remove_file(&account_path);
        }
    }

    // If current account is empty, try to select the first one as default
    if index.current_account_id.is_none() {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }

    save_account_index(&index)
}

/// Reorder accounts list
/// Update account order in index file based on the provided account ID order
pub fn reorder_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;

    // Create a mapping of account ID to summary information
    let id_to_summary: std::collections::HashMap<_, _> = index.accounts
        .iter()
        .map(|s| (s.id.clone(), s.clone()))
        .collect();

    // Rebuild account list according to new order
    let mut new_accounts = Vec::new();
    for id in account_ids {
        if let Some(summary) = id_to_summary.get(id) {
            new_accounts.push(summary.clone());
        }
    }

    // Add accounts not in the new order (append at the end maintaining original order)
    for summary in &index.accounts {
        if !account_ids.contains(&summary.id) {
            new_accounts.push(summary.clone());
        }
    }

    index.accounts = new_accounts;

    crate::modules::logger::log_info(&format!("Account order updated, {} accounts total", index.accounts.len()));

    save_account_index(&index)
}

/// Get current account ID
pub fn get_current_account_id() -> Result<Option<String>, String> {
    let index = load_account_index()?;
    Ok(index.current_account_id)
}

/// Get current active account details
pub fn get_current_account() -> Result<Option<Account>, String> {
    if let Some(id) = get_current_account_id()? {
        Ok(Some(load_account(&id)?))
    } else {
        Ok(None)
    }
}

/// Set current active account ID
pub fn set_current_account_id(account_id: &str) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
    let mut index = load_account_index()?;
    index.current_account_id = Some(account_id.to_string());
    save_account_index(&index)
}

/// Update account quota
pub fn update_account_quota(account_id: &str, quota: QuotaData) -> Result<(), String> {
    let mut account = load_account(account_id)?;
    account.update_quota(quota);
    save_account(&account)
}

/// Export all accounts' refresh_token
#[allow(dead_code)]
pub fn export_accounts() -> Result<Vec<(String, String)>, String> {
    let accounts = list_accounts()?;
    let mut exports = Vec::new();
    
    for account in accounts {
        exports.push((account.email, account.token.refresh_token));
    }
    
    Ok(exports)
}
