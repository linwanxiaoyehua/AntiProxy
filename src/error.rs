use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Account error: {0}")]
    Account(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

pub type AppResult<T> = Result<T, AppError>;
