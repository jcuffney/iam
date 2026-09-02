//! Postgres implementation of the connections store, over its OWN pool and
//! database credentials — never the identity pool.

use std::str::FromStr;

use async_trait::async_trait;
use iam_core::{
    Capability, CapabilityOperation, CapabilityRef, Connection, ConnectionId, ConnectionKind,
    Constraint, Grant, GrantId, PrincipalId, RefreshState,
};
use sqlx::PgPool;

use crate::crypto::{EncryptionKey, Sealed};
use crate::error::{ConnectionsError, ConnectionsResult};
use crate::store::{ConnectionsStore, GrantForAuthorization, NewConnection};

/// Postgres-backed connections store. Owns the encryption key and a pool that
/// connects with the `iam_connections` role.
#[derive(Clone)]
pub struct PgConnectionsStore {
    pool: PgPool,
    key: EncryptionKey,
}

impl PgConnectionsStore {
    pub fn new(pool: PgPool, key: EncryptionKey) -> Self {
        Self { pool, key }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn integrity<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> ConnectionsError {
    move |e| ConnectionsError::DataIntegrity(format!("{what}: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn row_to_connection(
    id: uuid::Uuid,
    principal_id: uuid::Uuid,
    org_id: uuid::Uuid,
    provider: String,
    kind: String,
    scopes_held: Vec<String>,
    refresh_status: Option<String>,
    last_refreshed_at: Option<time::OffsetDateTime>,
    expires_at: Option<time::OffsetDateTime>,
    created_at: time::OffsetDateTime,
    revoked_at: Option<time::OffsetDateTime>,
) -> ConnectionsResult<Connection> {
    let refresh = match (refresh_status.clone(), last_refreshed_at) {
        (None, None) => RefreshState::None,
        (status, last) => RefreshState::Refreshable {
            last_refreshed_at: last,
            status,
        },
    };
    Ok(Connection {
        id: ConnectionId(id),
        principal_id: PrincipalId(principal_id),
        org_id: org_id.into(),
        provider,
        kind: ConnectionKind::from_str(&kind).map_err(integrity("connection kind"))?,
        scopes_held,
        expires_at,
        refresh,
        created_at,
        revoked_at,
    })
}

#[async_trait]
impl ConnectionsStore for PgConnectionsStore {
    async fn create_connection(&self, new: NewConnection<'_>) -> ConnectionsResult<()> {
        let c = new.connection;
        // Seal with this store's own key; plaintext never reaches the database.
        let secret = self.key.seal(new.secret)?;
        let (refresh_ct, refresh_nonce) = match new.refresh {
            Some(r) => {
                let sealed = self.key.seal(r)?;
                (Some(sealed.ciphertext), Some(sealed.nonce))
            }
            None => (None, None),
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "INSERT INTO connections \
             (id, principal_id, org_id, provider, kind, scopes_held, secret_ciphertext, secret_nonce, \
              refresh_ciphertext, refresh_nonce, expires_at, created_at, revoked_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            c.id.0,
            c.principal_id.0,
            c.org_id.0,
            c.provider,
            c.kind.to_string(),
            &c.scopes_held,
            secret.ciphertext,
            secret.nonce,
            refresh_ct,
            refresh_nonce,
            c.expires_at,
            c.created_at,
            c.revoked_at,
        )
        .execute(&mut *tx)
        .await?;

        for cap in new.capabilities {
            sqlx::query!(
                "INSERT INTO capabilities (connection_id, operation, scopable) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                c.id.0,
                cap.operation.to_string(),
                cap.operation.independently_scopable(),
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_connection(&self, id: ConnectionId) -> ConnectionsResult<Connection> {
        let r = sqlx::query!(
            "SELECT id, principal_id, org_id, provider, kind, scopes_held, refresh_status, last_refreshed_at, \
             expires_at, created_at, revoked_at FROM connections WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ConnectionsError::NotFound)?;
        row_to_connection(
            r.id,
            r.principal_id,
            r.org_id,
            r.provider,
            r.kind,
            r.scopes_held,
            r.refresh_status,
            r.last_refreshed_at,
            r.expires_at,
            r.created_at,
            r.revoked_at,
        )
    }

    async fn list_connections(
        &self,
        principal_id: PrincipalId,
    ) -> ConnectionsResult<Vec<Connection>> {
        let rows = sqlx::query!(
            "SELECT id, principal_id, org_id, provider, kind, scopes_held, refresh_status, last_refreshed_at, \
             expires_at, created_at, revoked_at FROM connections \
             WHERE principal_id = $1 AND revoked_at IS NULL ORDER BY created_at",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                row_to_connection(
                    r.id,
                    r.principal_id,
                    r.org_id,
                    r.provider,
                    r.kind,
                    r.scopes_held,
                    r.refresh_status,
                    r.last_refreshed_at,
                    r.expires_at,
                    r.created_at,
                    r.revoked_at,
                )
            })
            .collect()
    }

    async fn revoke_connection(
        &self,
        id: ConnectionId,
        at: time::OffsetDateTime,
    ) -> ConnectionsResult<()> {
        let res = sqlx::query!(
            "UPDATE connections SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
            id.0,
            at
        )
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(ConnectionsError::NotFound);
        }
        Ok(())
    }

    async fn reveal_secret(&self, id: ConnectionId) -> ConnectionsResult<Vec<u8>> {
        let r = sqlx::query!(
            "SELECT secret_ciphertext, secret_nonce FROM connections WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ConnectionsError::NotFound)?;
        self.key.open(&Sealed {
            ciphertext: r.secret_ciphertext,
            nonce: r.secret_nonce,
        })
    }

    async fn list_capabilities(
        &self,
        connection_id: ConnectionId,
    ) -> ConnectionsResult<Vec<Capability>> {
        let rows = sqlx::query!(
            "SELECT operation FROM capabilities WHERE connection_id = $1",
            connection_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(Capability {
                    connection_id,
                    operation: CapabilityOperation::from_str(&r.operation)
                        .map_err(integrity("capability operation"))?,
                })
            })
            .collect()
    }

    async fn create_grant(&self, grant: &Grant) -> ConnectionsResult<()> {
        let constraints = serde_json::to_value(&grant.constraints)?;
        sqlx::query!(
            "INSERT INTO grants (id, principal_id, granted_by, connection_id, operation, constraints, expires_at, created_at, revoked_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            grant.id.0,
            grant.principal.0,
            grant.granted_by.0,
            grant.capability.connection_id.0,
            grant.capability.operation.to_string(),
            constraints,
            grant.expires_at,
            grant.created_at,
            grant.revoked_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_grant(&self, id: GrantId) -> ConnectionsResult<Grant> {
        let r = sqlx::query!(
            "SELECT id, principal_id, granted_by, connection_id, operation, constraints, expires_at, created_at, revoked_at \
             FROM grants WHERE id = $1",
            id.0
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ConnectionsError::NotFound)?;
        grant_from_row(
            r.id,
            r.principal_id,
            r.granted_by,
            r.connection_id,
            r.operation,
            r.constraints,
            r.expires_at,
            r.created_at,
            r.revoked_at,
        )
    }

    async fn list_grants(&self, principal_id: PrincipalId) -> ConnectionsResult<Vec<Grant>> {
        let rows = sqlx::query!(
            "SELECT id, principal_id, granted_by, connection_id, operation, constraints, expires_at, created_at, revoked_at \
             FROM grants WHERE principal_id = $1 AND revoked_at IS NULL ORDER BY created_at",
            principal_id.0
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                grant_from_row(
                    r.id,
                    r.principal_id,
                    r.granted_by,
                    r.connection_id,
                    r.operation,
                    r.constraints,
                    r.expires_at,
                    r.created_at,
                    r.revoked_at,
                )
            })
            .collect()
    }

    async fn revoke_grant(&self, id: GrantId, at: time::OffsetDateTime) -> ConnectionsResult<()> {
        let res = sqlx::query!(
            "UPDATE grants SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
            id.0,
            at
        )
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(ConnectionsError::NotFound);
        }
        Ok(())
    }

    async fn find_grant_for_authorization(
        &self,
        principal_id: PrincipalId,
        capability: &CapabilityRef,
    ) -> ConnectionsResult<Option<GrantForAuthorization>> {
        // The joint read: grant matched by principal + connection + operation,
        // unrevoked, plus the connection's active state so a revoked connection
        // kills the grant at read time.
        let r = sqlx::query!(
            "SELECT g.id, g.principal_id, g.granted_by, g.connection_id, g.operation, g.constraints, \
                    g.expires_at, g.created_at, g.revoked_at, \
                    (c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > now())) AS connection_active \
             FROM grants g JOIN connections c ON c.id = g.connection_id \
             WHERE g.principal_id = $1 AND g.connection_id = $2 AND g.operation = $3 AND g.revoked_at IS NULL \
             ORDER BY g.created_at DESC LIMIT 1",
            principal_id.0,
            capability.connection_id.0,
            capability.operation.to_string(),
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = r else { return Ok(None) };
        let grant = grant_from_row(
            r.id,
            r.principal_id,
            r.granted_by,
            r.connection_id,
            r.operation,
            r.constraints,
            r.expires_at,
            r.created_at,
            r.revoked_at,
        )?;
        Ok(Some(GrantForAuthorization {
            grant,
            connection_active: r.connection_active.unwrap_or(false),
        }))
    }

    async fn list_refresh_due(
        &self,
        now: time::OffsetDateTime,
        within_secs: i64,
    ) -> ConnectionsResult<Vec<Connection>> {
        let horizon = now + time::Duration::seconds(within_secs);
        let rows = sqlx::query!(
            "SELECT id, principal_id, org_id, provider, kind, scopes_held, refresh_status, last_refreshed_at, \
             expires_at, created_at, revoked_at FROM connections \
             WHERE revoked_at IS NULL AND kind = 'oauth' AND expires_at IS NOT NULL AND expires_at <= $1",
            horizon
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                row_to_connection(
                    r.id,
                    r.principal_id,
                    r.org_id,
                    r.provider,
                    r.kind,
                    r.scopes_held,
                    r.refresh_status,
                    r.last_refreshed_at,
                    r.expires_at,
                    r.created_at,
                    r.revoked_at,
                )
            })
            .collect()
    }

    async fn record_refresh(
        &self,
        id: ConnectionId,
        status: &str,
        at: time::OffsetDateTime,
        new_expires_at: Option<time::OffsetDateTime>,
    ) -> ConnectionsResult<()> {
        sqlx::query!(
            "UPDATE connections SET refresh_status = $2, last_refreshed_at = $3, \
             expires_at = COALESCE($4, expires_at) WHERE id = $1",
            id.0,
            status,
            at,
            new_expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn grant_from_row(
    id: uuid::Uuid,
    principal_id: uuid::Uuid,
    granted_by: uuid::Uuid,
    connection_id: uuid::Uuid,
    operation: String,
    constraints: serde_json::Value,
    expires_at: Option<time::OffsetDateTime>,
    created_at: time::OffsetDateTime,
    revoked_at: Option<time::OffsetDateTime>,
) -> ConnectionsResult<Grant> {
    let constraints: Vec<Constraint> = serde_json::from_value(constraints)?;
    let operation =
        CapabilityOperation::from_str(&operation).map_err(integrity("grant operation"))?;
    Ok(Grant {
        id: GrantId(id),
        principal: PrincipalId(principal_id),
        capability: CapabilityRef {
            connection_id: ConnectionId(connection_id),
            operation,
        },
        constraints,
        expires_at,
        granted_by: PrincipalId(granted_by),
        created_at,
        revoked_at,
    })
}
