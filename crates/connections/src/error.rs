use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConnectionsError {
    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("encryption error")]
    Encryption,

    #[error("invalid encryption key: {0}")]
    InvalidKey(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("data integrity error: {0}")]
    DataIntegrity(String),

    /// A capability operation was requested that the connection never declared,
    /// or that is not independently grantable.
    #[error("invalid capability: {0}")]
    InvalidCapability(String),
}

pub type ConnectionsResult<T> = Result<T, ConnectionsError>;
