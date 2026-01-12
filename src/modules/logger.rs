use tracing::{info, warn, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::modules::account::get_data_dir;

// Custom local timezone time formatter
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
        fs::create_dir_all(&log_dir).map_err(|e| format!("Failed to create log directory: {}", e))?;
    }
    
    Ok(log_dir)
}

/// Initialize logger system
pub fn init_logger() {
    // Capture log macro logs
    let _ = tracing_log::LogTracer::init();

    let log_dir = match get_log_dir() {
        Ok(dir) => Some(dir),
        Err(e) => {
            eprintln!("Failed to initialize log directory: {}", e);
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
            eprintln!("Log directory not writable, downgrading to console output");
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
        info!("Logger system initialized (console + file persistence)");
    } else {
        info!("Logger system initialized (console only)");
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

/// Clear log cache (uses truncation mode to keep file handles valid)
pub fn clear_logs() -> Result<(), String> {
    let log_dir = get_log_dir()?;
    if log_dir.exists() {
        // Iterate all files in directory and truncate, instead of deleting directory
        let entries = fs::read_dir(&log_dir).map_err(|e| format!("Failed to read log directory: {}", e))?;
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    // Open file in truncate mode, set size to 0
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

/// Log info message (backward compatible interface)
pub fn log_info(message: &str) {
    info!("{}", message);
}

/// Log warning message (backward compatible interface)
pub fn log_warn(message: &str) {
    warn!("{}", message);
}

/// Log error message (backward compatible interface)
pub fn log_error(message: &str) {
    error!("{}", message);
}
