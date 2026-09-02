//! Outbound-credential store for the iam service: OAuth grants, API keys, MCP
//! server credentials.
//!
//! Store-isolated from `iam-store` by design — its own database, pool,
//! credentials, and encryption key — because it holds live bearer secrets that
//! can act against third-party systems right now, whereas the identity store
//! holds only public keys. One SQL injection must not expose both.
//!
//! Authorization for using a connection or invoking a capability goes through
//! the same `iam-policy` functions as everything else. This crate gets no
//! special authorization path.

mod crypto;
mod error;
mod memory;
mod postgres;
mod refresh;
mod store;

pub use crypto::{EncryptionKey, Sealed};
pub use error::{ConnectionsError, ConnectionsResult};
pub use memory::MemoryConnectionsStore;
pub use postgres::PgConnectionsStore;
pub use refresh::{
    LoggingRefreshProvider, RefreshConfig, RefreshOutcome, RefreshProvider, run_refresh_loop, tick,
};
pub use store::{ConnectionsStore, GrantForAuthorization, NewConnection};

use sqlx::postgres::PgPoolOptions;

/// Connect to the connections database with its own pool.
///
/// Lazy for the same reason as the identity pool: startup must not open (or
/// wake) database connections; errors surface at first use instead.
pub async fn connect(database_url: &str, max_connections: u32) -> ConnectionsResult<sqlx::PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_lazy(database_url)?;
    Ok(pool)
}

/// Run the connections-database migrations embedded at compile time.
pub async fn run_migrations(pool: &sqlx::PgPool) -> ConnectionsResult<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| ConnectionsError::Database(sqlx::Error::Migrate(Box::new(e))))?;
    Ok(())
}
