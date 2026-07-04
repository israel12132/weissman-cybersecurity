use thiserror::Error;

#[derive(Debug, Error)]
pub enum JobBusError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis: {0}")]
    Redis(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("signature mismatch: {0}")]
    SignatureMismatch(String),
    #[error("lease denied: {0}")]
    LeaseDenied(String),
    #[error("forensic: {0}")]
    Forensic(String),
    #[error("configuration: {0}")]
    Config(String),
}

impl From<redis::RedisError> for JobBusError {
    fn from(e: redis::RedisError) -> Self {
        Self::Redis(e.to_string())
    }
}
