//! The store-isolated outbound-credential persistence contract.
//!
//! This trait is deliberately separate from `iam_store`'s traits and is
//! implemented over its own pool/database/credentials. Grant validity is
//! evaluated jointly with connection state so revoking a connection kills every
//! dependent grant at read time.

use async_trait::async_trait;
use iam_core::{Capability, CapabilityRef, Connection, ConnectionId, Grant, GrantId, PrincipalId};
use time::OffsetDateTime;

use crate::error::ConnectionsResult;

/// A grant plus whether the connection behind it is currently active. This is
/// exactly the pair `iam_policy::authorize_capability_invocation` consumes, so
/// the "revoking a connection invalidates its grants" rule is enforced at the
/// read, never cached.
#[derive(Debug, Clone)]
pub struct GrantForAuthorization {
    pub grant: Grant,
    pub connection_active: bool,
}

/// Everything needed to create a connection: the metadata, the plaintext
/// secret, an optional plaintext refresh token, and the declared capabilities.
///
/// Secrets are passed in the clear and sealed by the store with its own key —
/// the key never leaves this crate, which is the whole point of the isolation.
pub struct NewConnection<'a> {
    pub connection: &'a Connection,
    pub secret: &'a [u8],
    pub refresh: Option<&'a [u8]>,
    pub capabilities: &'a [Capability],
}

#[async_trait]
pub trait ConnectionsStore: Send + Sync {
    async fn create_connection(&self, new: NewConnection<'_>) -> ConnectionsResult<()>;
    async fn get_connection(&self, id: ConnectionId) -> ConnectionsResult<Connection>;
    async fn list_connections(
        &self,
        principal_id: PrincipalId,
    ) -> ConnectionsResult<Vec<Connection>>;
    /// Revoke a connection. Every grant referencing it becomes non-live
    /// immediately (validity is evaluated jointly at read time).
    async fn revoke_connection(
        &self,
        id: ConnectionId,
        at: OffsetDateTime,
    ) -> ConnectionsResult<()>;

    /// Decrypt and return the bearer secret. The only method that yields
    /// plaintext; used by the (future) invocation proxy after authorization.
    async fn reveal_secret(&self, id: ConnectionId) -> ConnectionsResult<Vec<u8>>;

    async fn list_capabilities(
        &self,
        connection_id: ConnectionId,
    ) -> ConnectionsResult<Vec<Capability>>;

    async fn create_grant(&self, grant: &Grant) -> ConnectionsResult<()>;
    async fn get_grant(&self, id: GrantId) -> ConnectionsResult<Grant>;
    async fn list_grants(&self, principal_id: PrincipalId) -> ConnectionsResult<Vec<Grant>>;
    async fn revoke_grant(&self, id: GrantId, at: OffsetDateTime) -> ConnectionsResult<()>;

    /// Find the unrevoked grant (if any) for this principal and capability,
    /// together with its connection's active state. Expiry and connection
    /// state are reported, not filtered, so policy can produce a precise reason.
    async fn find_grant_for_authorization(
        &self,
        principal_id: PrincipalId,
        capability: &CapabilityRef,
    ) -> ConnectionsResult<Option<GrantForAuthorization>>;

    // --- refresh loop support ---

    /// Connections whose secret is refreshable and whose expiry is within
    /// `within_secs` of `now` (or already past). The refresh loop's work list.
    async fn list_refresh_due(
        &self,
        now: OffsetDateTime,
        within_secs: i64,
    ) -> ConnectionsResult<Vec<Connection>>;
    /// Record the outcome of a refresh attempt.
    async fn record_refresh(
        &self,
        id: ConnectionId,
        status: &str,
        at: OffsetDateTime,
        new_expires_at: Option<OffsetDateTime>,
    ) -> ConnectionsResult<()>;
}
