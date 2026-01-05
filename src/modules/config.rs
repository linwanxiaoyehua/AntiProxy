use std::fs;
use serde_json;

use crate::proxy::ProxyConfig;
use super::account::get_data_dir;

const CONFIG_FILE: &str = "web_config.json";

/// 加载 Web 服务配置
pub fn load_web_config() -> Result<ProxyConfig, String> {
    let data_dir = get_data_dir()?;
    let config_path = data_dir.join(CONFIG_FILE);
    
    if !config_path.exists() {
        let config = ProxyConfig::default();
        let _ = save_web_config(&config);
        return Ok(config);
    }
    
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("读取配置文件失败: {}", e))?;
    
    serde_json::from_str(&content)
        .map_err(|e| format!("解析配置文件失败: {}", e))
}

/// 保存 Web 服务配置
pub fn save_web_config(config: &ProxyConfig) -> Result<(), String> {
    let data_dir = get_data_dir()?;
    let config_path = data_dir.join(CONFIG_FILE);
    
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("序列化配置失败: {}", e))?;
    
    fs::write(&config_path, content)
        .map_err(|e| format!("保存配置失败: {}", e))
}
