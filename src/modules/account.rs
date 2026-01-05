use std::fs;
use std::path::PathBuf;
use serde_json;
use uuid::Uuid;

use crate::models::{Account, AccountIndex, AccountSummary, TokenData, QuotaData};
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// 全局账号写入锁，防止并发操作导致索引文件损坏
static ACCOUNT_INDEX_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// ... existing constants ...
const DATA_DIR: &str = ".AntiProxy";
const LEGACY_DATA_DIR: &str = ".antigravity_proxy";
const ACCOUNTS_INDEX: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";

// ... existing functions get_data_dir, get_accounts_dir, load_account_index, save_account_index ...
/// 获取数据目录路径
pub fn get_data_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("无法获取用户主目录")?;
    let data_dir = home.join(DATA_DIR);
    let legacy_dir = home.join(LEGACY_DATA_DIR);

    if !data_dir.exists() && legacy_dir.exists() {
        return Ok(legacy_dir);
    }
    
    // 确保目录存在
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)
            .map_err(|e| format!("创建数据目录失败: {}", e))?;
    }
    
    Ok(data_dir)
}

/// 获取账号目录路径
pub fn get_accounts_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let accounts_dir = data_dir.join(ACCOUNTS_DIR);
    
    if !accounts_dir.exists() {
        fs::create_dir_all(&accounts_dir)
            .map_err(|e| format!("创建账号目录失败: {}", e))?;
    }
    
    Ok(accounts_dir)
}

/// 加载账号索引
pub fn load_account_index() -> Result<AccountIndex, String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);
    // modules::logger::log_info(&format!("正在加载账号索引: {:?}", index_path)); // Optional: reduce noise
    
    if !index_path.exists() {
        crate::modules::logger::log_warn("账号索引文件不存在");
        return Ok(AccountIndex::new());
    }
    
    let content = fs::read_to_string(&index_path)
        .map_err(|e| format!("读取账号索引失败: {}", e))?;
    
    let index: AccountIndex = serde_json::from_str(&content)
        .map_err(|e| format!("解析账号索引失败: {}", e))?;
        
    crate::modules::logger::log_info(&format!("成功加载索引，包含 {} 个账号", index.accounts.len()));
    Ok(index)
}

/// 保存账号索引 (原子化写入)
pub fn save_account_index(index: &AccountIndex) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let index_path = data_dir.join(ACCOUNTS_INDEX);
    let temp_path = data_dir.join(format!("{}.tmp", ACCOUNTS_INDEX));
    
    let content = serde_json::to_string_pretty(index)
        .map_err(|e| format!("序列化账号索引失败: {}", e))?;
    
    // 写入临时文件
    fs::write(&temp_path, content)
        .map_err(|e| format!("写入临时索引文件失败: {}", e))?;
        
    // 原子重命名
    fs::rename(temp_path, index_path)
        .map_err(|e| format!("替换索引文件失败: {}", e))
}

/// 加载账号数据
pub fn load_account(account_id: &str) -> Result<Account, String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));
    
    if !account_path.exists() {
        return Err(format!("账号不存在: {}", account_id));
    }
    
    let content = fs::read_to_string(&account_path)
        .map_err(|e| format!("读取账号数据失败: {}", e))?;
    
    serde_json::from_str(&content)
        .map_err(|e| format!("解析账号数据失败: {}", e))
}

/// 保存账号数据
pub fn save_account(account: &Account) -> Result<(), String> {
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account.id));
    
    let content = serde_json::to_string_pretty(account)
        .map_err(|e| format!("序列化账号数据失败: {}", e))?;
    
    fs::write(&account_path, content)
        .map_err(|e| format!("保存账号数据失败: {}", e))
}

/// 列出所有账号
/// 列出所有账号
pub fn list_accounts() -> Result<Vec<Account>, String> {
    crate::modules::logger::log_info("已开始列出账号...");
    let mut index = load_account_index()?;
    let mut accounts = Vec::new();
    let mut invalid_ids = Vec::new();
    
    for summary in &index.accounts {
        match load_account(&summary.id) {
            Ok(account) => accounts.push(account),
            Err(e) => {
                crate::modules::logger::log_error(&format!("加载账号 {} 失败: {}", summary.id, e));
                // 如果是文件不存在导致的错误，标记为无效 ID
                // load_account 返回 "账号不存在: id" 或者底层 io error
                if e.contains("账号不存在") || e.contains("Os { code: 2,") || e.contains("No such file") {
                    invalid_ids.push(summary.id.clone());
                }
            },
        }
    }
    
    // 自动修复索引：移除无效的账号 ID
    if !invalid_ids.is_empty() {
        crate::modules::logger::log_warn(&format!("发现 {} 个无效的账号索引，正在自动清理...", invalid_ids.len()));
        
        index.accounts.retain(|s| !invalid_ids.contains(&s.id));
        
        // 如果当前选中的账号也是无效的，重置为第一个可用账号
        if let Some(current_id) = &index.current_account_id {
            if invalid_ids.contains(current_id) {
                index.current_account_id = index.accounts.first().map(|s| s.id.clone());
            }
        }
        
        if let Err(e) = save_account_index(&index) {
            crate::modules::logger::log_error(&format!("自动清理索引失败: {}", e));
        } else {
            crate::modules::logger::log_info("索引自动清理完成");
        }
    }
    
    // modules::logger::log_info(&format!("共找到 {} 个有效账号", accounts.len()));
    Ok(accounts)
}

/// 添加账号
pub fn add_account(email: String, name: Option<String>, token: TokenData) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    
    // 检查是否已存在
    if index.accounts.iter().any(|s| s.email == email) {
        return Err(format!("账号已存在: {}", email));
    }
    
    // 创建新账号
    let account_id = Uuid::new_v4().to_string();
    let mut account = Account::new(account_id.clone(), email.clone(), token);
    account.name = name.clone();
    
    // 保存账号数据
    save_account(&account)?;
    
    // 更新索引
    index.accounts.push(AccountSummary {
        id: account_id.clone(),
        email: email.clone(),
        name: name.clone(),
        created_at: account.created_at,
        last_used: account.last_used,
    });
    
    // 如果是第一个账号，设为当前账号
    if index.current_account_id.is_none() {
        index.current_account_id = Some(account_id);
    }
    
    save_account_index(&index)?;
    
    Ok(account)
}

/// 添加或更新账号
pub fn upsert_account(email: String, name: Option<String>, token: TokenData) -> Result<Account, String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    
    // 先找到账号 ID（如果存在）
    let existing_account_id = index.accounts.iter()
        .find(|s| s.email == email)
        .map(|s| s.id.clone());
    
    if let Some(account_id) = existing_account_id {
        // 更新现有账号
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
                
                // 同步更新索引中的 name
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.name = name;
                    save_account_index(&index)?;
                }
                
                return Ok(account);
            },
            Err(e) => {
                crate::modules::logger::log_warn(&format!("Account {} file missing ({}), recreating...", account_id, e));
                // 索引存在但文件丢失，重新创建
                let mut account = Account::new(account_id.clone(), email.clone(), token);
                account.name = name.clone();
                save_account(&account)?;
                
                // 同步更新索引中的 name
                if let Some(idx_summary) = index.accounts.iter_mut().find(|s| s.id == account_id) {
                    idx_summary.name = name;
                    save_account_index(&index)?;
                }
                
                return Ok(account);
            }
        }
    }
    
    // 不存在则添加
    // 注意：这里手动调用 add_account，它也会尝试获取锁，但因为 Mutex 库限制会死锁
    // 所以我们需要一个不带锁的内部版本，或者重构。简单起见，这里直接展开添加逻辑或不重复加锁
    
    // 释放锁，让 add_account 处理
    drop(_lock);
    add_account(email, name, token)
}

/// 删除账号
pub fn delete_account(account_id: &str) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    
    // 从索引中移除
    let original_len = index.accounts.len();
    index.accounts.retain(|s| s.id != account_id);
    
    if index.accounts.len() == original_len {
        return Err(format!("找不到账号 ID: {}", account_id));
    }
    
    // 如果是当前账号，清除当前账号
    if index.current_account_id.as_deref() == Some(account_id) {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }
    
    save_account_index(&index)?;
    
    // 删除账号文件
    let accounts_dir = get_accounts_dir()?;
    let account_path = accounts_dir.join(format!("{}.json", account_id));
    
    if account_path.exists() {
        fs::remove_file(&account_path)
            .map_err(|e| format!("删除账号文件失败: {}", e))?;
    }
    
    Ok(())
}

/// 批量删除账号 (原子性操作索引)
pub fn delete_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    
    let accounts_dir = get_accounts_dir()?;
    
    for account_id in account_ids {
        // 从索引中移除
        index.accounts.retain(|s| &s.id != account_id);
        
        // 如果是当前账号，清除当前账号
        if index.current_account_id.as_deref() == Some(account_id) {
            index.current_account_id = None;
        }
        
        // 删除账号文件
        let account_path = accounts_dir.join(format!("{}.json", account_id));
        if account_path.exists() {
            let _ = fs::remove_file(&account_path);
        }
    }
    
    // 如果当前账号为空，尝试选取第一个作为默认
    if index.current_account_id.is_none() {
        index.current_account_id = index.accounts.first().map(|s| s.id.clone());
    }
    
    save_account_index(&index)
}

/// 重新排序账号列表
/// 根据传入的账号ID顺序更新索引文件中的账号排列顺序
pub fn reorder_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    
    // 创建一个映射，记录每个账号ID对应的摘要信息
    let id_to_summary: std::collections::HashMap<_, _> = index.accounts
        .iter()
        .map(|s| (s.id.clone(), s.clone()))
        .collect();
    
    // 按照新顺序重建账号列表
    let mut new_accounts = Vec::new();
    for id in account_ids {
        if let Some(summary) = id_to_summary.get(id) {
            new_accounts.push(summary.clone());
        }
    }
    
    // 添加未在新顺序中出现的账号（保持原有顺序追加到末尾）
    for summary in &index.accounts {
        if !account_ids.contains(&summary.id) {
            new_accounts.push(summary.clone());
        }
    }
    
    index.accounts = new_accounts;
    
    crate::modules::logger::log_info(&format!("账号顺序已更新，共 {} 个账号", index.accounts.len()));
    
    save_account_index(&index)
}

/// 获取当前账号 ID
pub fn get_current_account_id() -> Result<Option<String>, String> {
    let index = load_account_index()?;
    Ok(index.current_account_id)
}

/// 获取当前激活账号的具体信息
pub fn get_current_account() -> Result<Option<Account>, String> {
    if let Some(id) = get_current_account_id()? {
        Ok(Some(load_account(&id)?))
    } else {
        Ok(None)
    }
}

/// 设置当前激活账号 ID
pub fn set_current_account_id(account_id: &str) -> Result<(), String> {
    let _lock = ACCOUNT_INDEX_LOCK.lock().map_err(|e| format!("获取锁失败: {}", e))?;
    let mut index = load_account_index()?;
    index.current_account_id = Some(account_id.to_string());
    save_account_index(&index)
}

/// 更新账号配额
pub fn update_account_quota(account_id: &str, quota: QuotaData) -> Result<(), String> {
    let mut account = load_account(account_id)?;
    account.update_quota(quota);
    save_account(&account)
}

/// 导出所有账号的 refresh_token
#[allow(dead_code)]
pub fn export_accounts() -> Result<Vec<(String, String)>, String> {
    let accounts = list_accounts()?;
    let mut exports = Vec::new();
    
    for account in accounts {
        exports.push((account.email, account.token.refresh_token));
    }
    
    Ok(exports)
}
