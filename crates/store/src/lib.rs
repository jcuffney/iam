//! Persistence for the iam identity tree and ephemeral state.
//!
//! Everything sits behind the traits in [`traits`]: durable identity data in
//! Postgres ([`PgStore`]), ephemeral challenges and sessions in DynamoDB
//! ([`DynamoStore`]), and in-memory implementations of all four traits for
//! tests. Callers depend on the traits, never the concrete stores.

mod dynamo;
mod error;
mod memory;
mod postgres;
mod records;
mod traits;

pub use dynamo::{CHALLENGES_TABLE, DynamoStore, SESSIONS_TABLE};
pub use error::{StoreError, StoreResult};
pub use memory::{MemoryAuditStore, MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
pub use postgres::PgStore;
pub use records::{
    AuditFilter, ChallengeMode, ChallengeRecord, CodePurpose, SessionRecord, SessionScope,
    StoredCode,
};
pub use traits::{AuditStore, ChallengeStore, IdentityStore, SessionStore};

use sqlx::postgres::PgPoolOptions;

/// Connect to Postgres and return a pool.
///
/// Lazy: connections open on first acquire, so process startup (and health
/// checks) never touch — or wake — a scale-to-zero database. The cost is that a
/// bad URL/credential surfaces at the first query instead of at boot.
pub async fn connect_postgres(
    database_url: &str,
    max_connections: u32,
) -> StoreResult<sqlx::PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_lazy(database_url)?;
    Ok(pool)
}

/// Run the identity-database migrations embedded at compile time.
pub async fn run_identity_migrations(pool: &sqlx::PgPool) -> StoreResult<()> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| StoreError::Database(sqlx::Error::Migrate(Box::new(e))))?;
    Ok(())
}

/// Build a DynamoDB client, honoring a local endpoint override when set
/// (`endpoint_url`), otherwise the ambient AWS configuration.
pub async fn connect_dynamo(endpoint_url: Option<&str>) -> aws_sdk_dynamodb::Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(url) = endpoint_url {
        loader = loader.endpoint_url(url);
    }
    let config = loader.load().await;
    aws_sdk_dynamodb::Client::new(&config)
}
