use thiserror::Error;

#[derive(Debug, Error)]
pub enum FleetShapingError {
    #[error("redis unavailable: {0}")]
    Redis(String),
    #[error("rate limit denied — retry after {retry_after_ms}ms")]
    Denied { retry_after_ms: u64 },
    #[error("configuration error: {0}")]
    Config(String),
}
