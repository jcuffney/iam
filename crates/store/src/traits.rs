//! Persistence behind traits, split by access pattern so tests can run against
//! in-memory implementations and neither store is forced to do the other's job.
//!
//! Durable identity data (Postgres) sits behind [`IdentityStore`] and
//! [`AuditStore`]; ephemeral ceremony/session state (DynamoDB) sits behind
//! [`ChallengeStore`] and [`SessionStore`].

use async_trait::async_trait;
use iam_core::{
    AuditEvent, Credential, Org, OrgId, PasskeyCredential, Permission, PermissionSet, Principal,
    PrincipalId, Role, RoleId,
};
use time::OffsetDateTime;

use crate::error::StoreResult;
use crate::records::{AuditFilter, ChallengeRecord, CodePurpose, SessionRecord, StoredCode};

/// The durable identity tree: orgs, principals, credentials, roles, role
/// assignments, and one-time codes.
#[async_trait]
pub trait IdentityStore: Send + Sync {
    // --- orgs ---
    async fn create_org(&self, org: &Org) -> StoreResult<()>;
    async fn get_org(&self, id: OrgId) -> StoreResult<Org>;
    async fn get_org_by_slug(&self, slug: &str) -> StoreResult<Org>;

    // --- principals ---
    async fn create_principal(&self, principal: &Principal) -> StoreResult<()>;
    async fn get_principal(&self, id: PrincipalId) -> StoreResult<Principal>;
    async fn get_principal_by_handle(&self, org_id: OrgId, handle: &str) -> StoreResult<Principal>;
    /// Set or clear the disabled timestamp. Clearing re-enables.
    async fn set_principal_disabled(
        &self,
        id: PrincipalId,
        disabled_at: Option<OffsetDateTime>,
    ) -> StoreResult<()>;

    // --- credentials ---
    /// Insert a credential idempotently. Returns `true` if newly inserted,
    /// `false` if a credential with this id already existed for this principal
    /// (a retried registration finish). Errors with `Conflict` if the id
    /// belongs to a *different* principal.
    async fn insert_credential(&self, credential: &Credential) -> StoreResult<bool>;
    async fn get_credential(&self, credential_id: &[u8]) -> StoreResult<Credential>;
    async fn list_credentials(&self, principal_id: PrincipalId) -> StoreResult<Vec<Credential>>;
    /// Persist the post-assertion blob, counter, and last-used timestamp.
    async fn update_credential_after_auth(&self, updated: &PasskeyCredential) -> StoreResult<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> StoreResult<()>;

    // --- roles ---
    async fn create_role(&self, role: &Role) -> StoreResult<()>;
    async fn get_role_by_name(&self, org_id: OrgId, name: &str) -> StoreResult<Role>;
    async fn set_role_permissions(
        &self,
        role_id: RoleId,
        permissions: &[Permission],
    ) -> StoreResult<()>;

    // --- role assignments ---
    async fn assign_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()>;
    async fn revoke_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()>;
    async fn roles_for_principal(&self, principal_id: PrincipalId) -> StoreResult<Vec<Role>>;
    /// The union of permissions across all of the principal's roles — the input
    /// to policy::authorize.
    async fn permissions_for_principal(
        &self,
        principal_id: PrincipalId,
    ) -> StoreResult<PermissionSet>;

    // --- one-time codes (recovery + registration) ---
    async fn insert_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
        hashes: &[String],
    ) -> StoreResult<()>;
    /// Unused codes for a principal+purpose; the caller argon2-verifies each.
    async fn list_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<Vec<StoredCode>>;
    /// Atomically mark a code used. Returns `true` if this call consumed it,
    /// `false` if it was already used (lost the race).
    async fn mark_code_used(&self, code_id: uuid::Uuid) -> StoreResult<bool>;
    /// Delete all unused codes for a principal+purpose (used when reissuing).
    async fn delete_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<()>;
}

/// Append-only audit trail. No update, no delete — by shape here and by trigger
/// in the database.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, event: &AuditEvent) -> StoreResult<()>;
    async fn query(&self, filter: &AuditFilter) -> StoreResult<Vec<AuditEvent>>;
}

/// Ephemeral WebAuthn ceremony state, consumed exactly once.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn put_challenge(&self, record: &ChallengeRecord) -> StoreResult<()>;
    /// Consume a challenge: remove and return it, but only if it exists and has
    /// not expired. A second take of the same id returns `None`, which is what
    /// makes replay impossible.
    async fn take_challenge(
        &self,
        challenge_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<ChallengeRecord>>;
}

/// Active sessions with TTL. The token layer defers to this for revocation.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn put_session(&self, record: &SessionRecord) -> StoreResult<()>;
    /// Fetch a session if it exists and has not expired.
    async fn get_session(
        &self,
        session_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<SessionRecord>>;
    async fn revoke_session(&self, session_id: &str) -> StoreResult<()>;
}
