//! In-memory connections store for tests. Mirrors the Postgres semantics,
//! especially the joint grant+connection validity read.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use iam_core::{
    Capability, CapabilityRef, Connection, ConnectionId, Grant, GrantId, PrincipalId, RefreshState,
};
use time::OffsetDateTime;

use crate::crypto::{EncryptionKey, Sealed};
use crate::error::{ConnectionsError, ConnectionsResult};
use crate::store::{ConnectionsStore, GrantForAuthorization, NewConnection};

struct ConnRow {
    connection: Connection,
    secret: Sealed,
    #[allow(dead_code)]
    refresh: Option<Sealed>,
    capabilities: Vec<Capability>,
}

#[derive(Default)]
struct Data {
    connections: HashMap<ConnectionId, ConnRow>,
    grants: HashMap<GrantId, Grant>,
}

/// In-memory [`ConnectionsStore`]. Holds its own key, never shared with the
/// identity store.
pub struct MemoryConnectionsStore {
    key: EncryptionKey,
    data: Mutex<Data>,
}

impl MemoryConnectionsStore {
    pub fn new(key: EncryptionKey) -> Self {
        Self {
            key,
            data: Mutex::new(Data::default()),
        }
    }
}

#[async_trait]
impl ConnectionsStore for MemoryConnectionsStore {
    async fn create_connection(&self, new: NewConnection<'_>) -> ConnectionsResult<()> {
        // Seal with this store's own key; plaintext never persists.
        let secret = self.key.seal(new.secret)?;
        let refresh = match new.refresh {
            Some(r) => Some(self.key.seal(r)?),
            None => None,
        };
        let mut d = self.data.lock().unwrap();
        d.connections.insert(
            new.connection.id,
            ConnRow {
                connection: new.connection.clone(),
                secret,
                refresh,
                capabilities: new.capabilities.to_vec(),
            },
        );
        Ok(())
    }

    async fn get_connection(&self, id: ConnectionId) -> ConnectionsResult<Connection> {
        self.data
            .lock()
            .unwrap()
            .connections
            .get(&id)
            .map(|r| r.connection.clone())
            .ok_or(ConnectionsError::NotFound)
    }

    async fn list_connections(
        &self,
        principal_id: PrincipalId,
    ) -> ConnectionsResult<Vec<Connection>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .connections
            .values()
            .filter(|r| {
                r.connection.principal_id == principal_id && r.connection.revoked_at.is_none()
            })
            .map(|r| r.connection.clone())
            .collect())
    }

    async fn revoke_connection(
        &self,
        id: ConnectionId,
        at: OffsetDateTime,
    ) -> ConnectionsResult<()> {
        let mut d = self.data.lock().unwrap();
        let row = d
            .connections
            .get_mut(&id)
            .ok_or(ConnectionsError::NotFound)?;
        row.connection.revoked_at = Some(at);
        Ok(())
    }

    async fn reveal_secret(&self, id: ConnectionId) -> ConnectionsResult<Vec<u8>> {
        let d = self.data.lock().unwrap();
        let row = d.connections.get(&id).ok_or(ConnectionsError::NotFound)?;
        self.key.open(&row.secret)
    }

    async fn list_capabilities(
        &self,
        connection_id: ConnectionId,
    ) -> ConnectionsResult<Vec<Capability>> {
        let d = self.data.lock().unwrap();
        let row = d
            .connections
            .get(&connection_id)
            .ok_or(ConnectionsError::NotFound)?;
        Ok(row.capabilities.clone())
    }

    async fn create_grant(&self, grant: &Grant) -> ConnectionsResult<()> {
        let mut d = self.data.lock().unwrap();
        if !d.connections.contains_key(&grant.capability.connection_id) {
            return Err(ConnectionsError::NotFound);
        }
        d.grants.insert(grant.id, grant.clone());
        Ok(())
    }

    async fn get_grant(&self, id: GrantId) -> ConnectionsResult<Grant> {
        self.data
            .lock()
            .unwrap()
            .grants
            .get(&id)
            .cloned()
            .ok_or(ConnectionsError::NotFound)
    }

    async fn list_grants(&self, principal_id: PrincipalId) -> ConnectionsResult<Vec<Grant>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .grants
            .values()
            .filter(|g| g.principal == principal_id && g.revoked_at.is_none())
            .cloned()
            .collect())
    }

    async fn revoke_grant(&self, id: GrantId, at: OffsetDateTime) -> ConnectionsResult<()> {
        let mut d = self.data.lock().unwrap();
        let g = d.grants.get_mut(&id).ok_or(ConnectionsError::NotFound)?;
        g.revoked_at = Some(at);
        Ok(())
    }

    async fn find_grant_for_authorization(
        &self,
        principal_id: PrincipalId,
        capability: &CapabilityRef,
    ) -> ConnectionsResult<Option<GrantForAuthorization>> {
        let d = self.data.lock().unwrap();
        let grant = d
            .grants
            .values()
            .find(|g| {
                g.principal == principal_id && g.revoked_at.is_none() && &g.capability == capability
            })
            .cloned();

        let Some(grant) = grant else { return Ok(None) };
        // Report the connection's active state; policy decides the reason. Must
        // match the Postgres query, which checks revocation AND expiry — hence
        // `is_active(now)`, not just `revoked_at`.
        let connection_active = d
            .connections
            .get(&capability.connection_id)
            .map(|r| r.connection.is_active(OffsetDateTime::now_utc()))
            .unwrap_or(false);
        Ok(Some(GrantForAuthorization {
            grant,
            connection_active,
        }))
    }

    async fn list_refresh_due(
        &self,
        now: OffsetDateTime,
        within_secs: i64,
    ) -> ConnectionsResult<Vec<Connection>> {
        let horizon = now + time::Duration::seconds(within_secs);
        Ok(self
            .data
            .lock()
            .unwrap()
            .connections
            .values()
            .filter(|r| r.connection.revoked_at.is_none())
            .filter(|r| matches!(r.connection.refresh, RefreshState::Refreshable { .. }))
            .filter(|r| r.connection.expires_at.is_some_and(|e| e <= horizon))
            .map(|r| r.connection.clone())
            .collect())
    }

    async fn record_refresh(
        &self,
        id: ConnectionId,
        status: &str,
        at: OffsetDateTime,
        new_expires_at: Option<OffsetDateTime>,
    ) -> ConnectionsResult<()> {
        let mut d = self.data.lock().unwrap();
        let row = d
            .connections
            .get_mut(&id)
            .ok_or(ConnectionsError::NotFound)?;
        row.connection.refresh = RefreshState::Refreshable {
            last_refreshed_at: Some(at),
            status: Some(status.to_string()),
        };
        if let Some(exp) = new_expires_at {
            row.connection.expires_at = Some(exp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iam_core::{CapabilityOperation, ConnectionKind, GrantId, OrgId};

    fn store() -> MemoryConnectionsStore {
        MemoryConnectionsStore::new(EncryptionKey::from_bytes(&[3u8; 32]).unwrap())
    }

    fn a_connection(principal: PrincipalId) -> Connection {
        Connection {
            id: ConnectionId::new(),
            principal_id: principal,
            org_id: OrgId::new(),
            provider: "google".into(),
            kind: ConnectionKind::OAuth,
            scopes_held: vec!["calendar".into()],
            expires_at: None,
            refresh: RefreshState::None,
            created_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn revoking_a_connection_makes_its_grant_non_live() {
        let s = store();
        let principal = PrincipalId::new();
        let conn = a_connection(principal);
        let cap = CapabilityRef {
            connection_id: conn.id,
            operation: CapabilityOperation::McpTool {
                name: "fs.read".into(),
            },
        };
        s.create_connection(NewConnection {
            connection: &conn,
            secret: b"tok",
            refresh: None,
            capabilities: &[Capability {
                connection_id: conn.id,
                operation: cap.operation.clone(),
            }],
        })
        .await
        .unwrap();

        let grant = Grant {
            id: GrantId::new(),
            principal,
            capability: cap.clone(),
            constraints: vec![],
            expires_at: None,
            granted_by: principal,
            created_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        };
        s.create_grant(&grant).await.unwrap();

        // Before revocation: found and connection active.
        let found = s
            .find_grant_for_authorization(principal, &cap)
            .await
            .unwrap()
            .unwrap();
        assert!(found.connection_active);

        // After revoking the connection: grant still found, but connection
        // reported inactive — policy will deny with ConnectionInactive.
        s.revoke_connection(conn.id, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let found = s
            .find_grant_for_authorization(principal, &cap)
            .await
            .unwrap()
            .unwrap();
        assert!(!found.connection_active);
    }

    #[tokio::test]
    async fn revoked_grant_is_not_returned() {
        let s = store();
        let principal = PrincipalId::new();
        let conn = a_connection(principal);
        let cap = CapabilityRef {
            connection_id: conn.id,
            operation: CapabilityOperation::Opaque,
        };
        s.create_connection(NewConnection {
            connection: &conn,
            secret: b"tok",
            refresh: None,
            capabilities: &[Capability {
                connection_id: conn.id,
                operation: CapabilityOperation::Opaque,
            }],
        })
        .await
        .unwrap();
        let grant = Grant {
            id: GrantId::new(),
            principal,
            capability: cap.clone(),
            constraints: vec![],
            expires_at: None,
            granted_by: principal,
            created_at: OffsetDateTime::now_utc(),
            revoked_at: None,
        };
        s.create_grant(&grant).await.unwrap();
        s.revoke_grant(grant.id, OffsetDateTime::now_utc())
            .await
            .unwrap();
        assert!(
            s.find_grant_for_authorization(principal, &cap)
                .await
                .unwrap()
                .is_none()
        );
    }
}
