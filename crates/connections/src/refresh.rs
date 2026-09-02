//! Token refresh loop.
//!
//! This is deliberately a standalone async task with no dependency on the HTTP
//! handlers or the api crate. The rest of the service is request-response; this
//! is the one background timer. Keeping it separable means the eventual split
//! of `iam-connections` into its own deployable (the trigger for which is
//! operational, not security) stays cheap: move this file and its store, done.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use iam_core::Connection;
use time::OffsetDateTime;

use crate::error::ConnectionsResult;
use crate::store::ConnectionsStore;

/// Performs the provider-specific work of refreshing a connection's secret.
///
/// The real OAuth refresh (exchanging a refresh token at the provider) is out
/// of scope for this build; the dev implementation records the attempt so the
/// loop's plumbing is exercisable end to end.
#[async_trait]
pub trait RefreshProvider: Send + Sync {
    /// Attempt to refresh; return the new expiry on success.
    async fn refresh(&self, connection: &Connection) -> ConnectionsResult<RefreshOutcome>;
}

pub struct RefreshOutcome {
    pub status: String,
    pub new_expires_at: Option<OffsetDateTime>,
}

/// Dev provider: logs and marks the attempt without contacting any provider.
pub struct LoggingRefreshProvider;

#[async_trait]
impl RefreshProvider for LoggingRefreshProvider {
    async fn refresh(&self, connection: &Connection) -> ConnectionsResult<RefreshOutcome> {
        tracing::info!(connection_id = %connection.id, provider = %connection.provider, "refresh (dev no-op)");
        // Push expiry out an hour so the connection stops appearing in the work
        // list; a real provider would return the provider-issued expiry.
        Ok(RefreshOutcome {
            status: "dev_noop".into(),
            new_expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
        })
    }
}

/// Configuration for the loop.
#[derive(Clone, Copy)]
pub struct RefreshConfig {
    /// How often to scan for due connections.
    pub interval: Duration,
    /// Refresh connections expiring within this many seconds.
    pub lead_secs: i64,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            lead_secs: 300,
        }
    }
}

/// Run the refresh loop until the process ends. Spawn with `tokio::spawn`.
pub async fn run_refresh_loop(
    store: Arc<dyn ConnectionsStore>,
    provider: Arc<dyn RefreshProvider>,
    config: RefreshConfig,
) {
    let mut ticker = tokio::time::interval(config.interval);
    loop {
        ticker.tick().await;
        if let Err(e) = tick(store.as_ref(), provider.as_ref(), config.lead_secs).await {
            tracing::warn!(error = %e, "refresh loop tick failed");
        }
    }
}

/// One scan-and-refresh pass. Extracted so it can be unit-tested without a timer.
pub async fn tick(
    store: &dyn ConnectionsStore,
    provider: &dyn RefreshProvider,
    lead_secs: i64,
) -> ConnectionsResult<usize> {
    let now = OffsetDateTime::now_utc();
    let due = store.list_refresh_due(now, lead_secs).await?;
    let count = due.len();
    for connection in due {
        match provider.refresh(&connection).await {
            Ok(outcome) => {
                store
                    .record_refresh(
                        connection.id,
                        &outcome.status,
                        OffsetDateTime::now_utc(),
                        outcome.new_expires_at,
                    )
                    .await?;
            }
            Err(e) => {
                tracing::warn!(connection_id = %connection.id, error = %e, "refresh attempt failed");
                store
                    .record_refresh(connection.id, "error", OffsetDateTime::now_utc(), None)
                    .await?;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptionKey;
    use crate::memory::MemoryConnectionsStore;
    use crate::store::NewConnection;
    use iam_core::{Connection, ConnectionId, ConnectionKind, OrgId, PrincipalId, RefreshState};

    #[tokio::test]
    async fn tick_refreshes_due_connections_and_clears_them() {
        let key = EncryptionKey::from_bytes(&[1u8; 32]).unwrap();
        let store = MemoryConnectionsStore::new(key.clone());

        let conn = Connection {
            id: ConnectionId::new(),
            principal_id: PrincipalId::new(),
            org_id: OrgId::new(),
            provider: "google".into(),
            kind: ConnectionKind::OAuth,
            scopes_held: vec![],
            // Already expired → due now.
            expires_at: Some(OffsetDateTime::now_utc() - time::Duration::minutes(1)),
            refresh: RefreshState::Refreshable {
                last_refreshed_at: None,
                status: None,
            },
            created_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        };
        store
            .create_connection(NewConnection {
                connection: &conn,
                secret: b"tok",
                refresh: Some(b"refresh"),
                capabilities: &[],
            })
            .await
            .unwrap();

        let refreshed = tick(&store, &LoggingRefreshProvider, 300).await.unwrap();
        assert_eq!(refreshed, 1);

        // After refresh the expiry moved out, so it is no longer due.
        let refreshed_again = tick(&store, &LoggingRefreshProvider, 300).await.unwrap();
        assert_eq!(refreshed_again, 0);
    }
}
