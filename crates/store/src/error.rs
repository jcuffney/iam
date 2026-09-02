use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,

    /// A uniqueness constraint was violated (duplicate handle, credential, …).
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("dynamodb error: {0}")]
    Dynamo(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A stored value could not be mapped back to a domain type — e.g. an
    /// unknown permission string. Fails loudly rather than silently dropping.
    #[error("data integrity error: {0}")]
    DataIntegrity(String),
}

pub type StoreResult<T> = Result<T, StoreError>;
