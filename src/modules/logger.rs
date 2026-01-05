use tracing::{info, warn, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::modules::account::get_data_dir;

// 自定义本地时区时间格式化器
struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.to_rfc3339())
    }
}

pub fn get_log_dir() -> Result<PathBuf, String> {
    let data_dir = get_data_dir()?;
    let log_dir = data_dir.join("logs");
    
    if !log_dir.exists() {
        fs::create_dir_all(&log_dir).map_err(|e| format!("创建日志目录失败: {}", e))?;
    }
    
    Ok(log_dir)
}

/// 初始化日志系统
pub fn init_logger() {
    // 捕获 log 宏日志
    let _ = tracing_log::LogTracer::init();

    let log_dir = match get_log_dir() {
        Ok(dir) => Some(dir),
        Err(e) => {
            eprintln!("无法初始化日志目录: {}", e);
            None
        }
    };

    let mut file_guard: Option<tracing_appender::non_blocking::WorkerGuard> = None;
    let mut file_layer = None;

    if let Some(dir) = log_dir {
        if is_log_dir_writable(&dir) {
            let file_appender = tracing_appender::rolling::daily(dir, "app.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            file_guard = Some(guard);
            file_layer = Some(
                fmt::Layer::new()
                    .with_writer(non_blocking)
                    .with_ansi(false)
                    .with_target(true)
                    .with_level(true)
                    .with_timer(LocalTimer),
            );
        } else {
            eprintln!("日志目录不可写，已降级为控制台输出");
        }
    }

    let console_layer = fmt::Layer::new()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .with_timer(LocalTimer);

    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(console_layer)
        .with(file_layer)
        .try_init();

    if let Some(guard) = file_guard {
        std::mem::forget(guard);
        info!("日志系统已完成初始化 (终端控制台 + 文件持久化)");
    } else {
        info!("日志系统已完成初始化 (终端控制台)");
    }
}

fn is_log_dir_writable(dir: &PathBuf) -> bool {
    let probe = dir.join(".write_test");
    let result = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&probe)
        .and_then(|mut f| f.write_all(b"ok"));

    if result.is_ok() {
        let _ = fs::remove_file(probe);
        true
    } else {
        false
    }
}

/// 清理日志缓存 (采用截断模式以保持文件句柄有效)
pub fn clear_logs() -> Result<(), String> {
    let log_dir = get_log_dir()?;
    if log_dir.exists() {
        // 遍历目录下的所有文件并截断，而不是删除目录
        let entries = fs::read_dir(&log_dir).map_err(|e| format!("读取日志目录失败: {}", e))?;
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    // 使用截断模式打开文件，将大小设为 0
                    let _ = fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(path);
                }
            }
        }
    }
    Ok(())
}

/// 记录信息日志 (向后兼容接口)
pub fn log_info(message: &str) {
    info!("{}", message);
}

/// 记录警告日志 (向后兼容接口)
pub fn log_warn(message: &str) {
    warn!("{}", message);
}

/// 记录错误日志 (向后兼容接口)
pub fn log_error(message: &str) {
    error!("{}", message);
}
