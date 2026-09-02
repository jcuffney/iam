//! In-memory store implementations for tests and local experimentation.
//!
//! These are the reference semantics: the Postgres and DynamoDB implementations
//! must behave identically from the caller's point of view. Kept deliberately
//! simple (a mutex around some maps); correctness, not throughput, is the goal.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use iam_core::{
    AuditEvent, Credential, Org, OrgId, PasskeyCredential, Permission, PermissionSet, Principal,
    PrincipalId, Role, RoleId,
};
use time::OffsetDateTime;

use crate::error::{StoreError, StoreResult};
use crate::records::{AuditFilter, ChallengeRecord, CodePurpose, SessionRecord, StoredCode};
use crate::traits::{AuditStore, ChallengeStore, IdentityStore, SessionStore};

#[derive(Default)]
struct IdentityData {
    orgs: HashMap<OrgId, Org>,
    principals: HashMap<PrincipalId, Principal>,
    credentials: HashMap<Vec<u8>, Credential>,
    roles: HashMap<RoleId, Role>,
    role_permissions: HashMap<RoleId, PermissionSet>,
    principal_roles: HashMap<PrincipalId, Vec<RoleId>>,
    codes: HashMap<uuid::Uuid, CodeRow>,
}

#[derive(Clone)]
struct CodeRow {
    principal_id: PrincipalId,
    purpose: CodePurpose,
    hash: String,
    used: bool,
}

/// In-memory [`IdentityStore`].
#[derive(Default)]
pub struct MemoryIdentityStore {
    data: Mutex<IdentityData>,
}

impl MemoryIdentityStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn create_org(&self, org: &Org) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if d.orgs.values().any(|o| o.slug == org.slug) {
            return Err(StoreError::Conflict(format!("org slug {}", org.slug)));
        }
        d.orgs.insert(org.id, org.clone());
        Ok(())
    }

    async fn get_org(&self, id: OrgId) -> StoreResult<Org> {
        self.data
            .lock()
            .unwrap()
            .orgs
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn get_org_by_slug(&self, slug: &str) -> StoreResult<Org> {
        self.data
            .lock()
            .unwrap()
            .orgs
            .values()
            .find(|o| o.slug == slug)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn create_principal(&self, principal: &Principal) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if d.principals
            .values()
            .any(|p| p.org_id == principal.org_id && p.handle == principal.handle)
        {
            return Err(StoreError::Conflict(format!("handle {}", principal.handle)));
        }
        d.principals.insert(principal.id, principal.clone());
        Ok(())
    }

    async fn get_principal(&self, id: PrincipalId) -> StoreResult<Principal> {
        self.data
            .lock()
            .unwrap()
            .principals
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn get_principal_by_handle(&self, org_id: OrgId, handle: &str) -> StoreResult<Principal> {
        self.data
            .lock()
            .unwrap()
            .principals
            .values()
            .find(|p| p.org_id == org_id && p.handle == handle)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn set_principal_disabled(
        &self,
        id: PrincipalId,
        disabled_at: Option<OffsetDateTime>,
    ) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        let p = d.principals.get_mut(&id).ok_or(StoreError::NotFound)?;
        p.disabled_at = disabled_at;
        Ok(())
    }

    async fn insert_credential(&self, credential: &Credential) -> StoreResult<bool> {
        let mut d = self.data.lock().unwrap();
        let id = credential.credential_id().to_vec();
        if let Some(existing) = d.credentials.get(&id) {
            // Idempotent for the same principal; a conflict for a different one.
            if existing.principal_id() == credential.principal_id() {
                return Ok(false);
            }
            return Err(StoreError::Conflict(
                "credential id belongs to another principal".into(),
            ));
        }
        d.credentials.insert(id, credential.clone());
        Ok(true)
    }

    async fn get_credential(&self, credential_id: &[u8]) -> StoreResult<Credential> {
        self.data
            .lock()
            .unwrap()
            .credentials
            .get(credential_id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn list_credentials(&self, principal_id: PrincipalId) -> StoreResult<Vec<Credential>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .credentials
            .values()
            .filter(|c| c.principal_id() == principal_id)
            .cloned()
            .collect())
    }

    async fn update_credential_after_auth(&self, updated: &PasskeyCredential) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        let entry = d
            .credentials
            .get_mut(&updated.credential_id)
            .ok_or(StoreError::NotFound)?;
        *entry = Credential::Passkey(updated.clone());
        Ok(())
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        d.credentials
            .remove(credential_id)
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }

    async fn create_role(&self, role: &Role) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if d.roles
            .values()
            .any(|r| r.org_id == role.org_id && r.name == role.name)
        {
            return Err(StoreError::Conflict(format!("role {}", role.name)));
        }
        d.roles.insert(role.id, role.clone());
        Ok(())
    }

    async fn get_role_by_name(&self, org_id: OrgId, name: &str) -> StoreResult<Role> {
        self.data
            .lock()
            .unwrap()
            .roles
            .values()
            .find(|r| r.org_id == org_id && r.name == name)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn set_role_permissions(
        &self,
        role_id: RoleId,
        permissions: &[Permission],
    ) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if !d.roles.contains_key(&role_id) {
            return Err(StoreError::NotFound);
        }
        d.role_permissions
            .insert(role_id, permissions.iter().copied().collect());
        Ok(())
    }

    async fn assign_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if !d.principals.contains_key(&principal_id) || !d.roles.contains_key(&role_id) {
            return Err(StoreError::NotFound);
        }
        let entry = d.principal_roles.entry(principal_id).or_default();
        if !entry.contains(&role_id) {
            entry.push(role_id);
        }
        Ok(())
    }

    async fn revoke_role(&self, principal_id: PrincipalId, role_id: RoleId) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        if let Some(entry) = d.principal_roles.get_mut(&principal_id) {
            entry.retain(|r| *r != role_id);
        }
        Ok(())
    }

    async fn roles_for_principal(&self, principal_id: PrincipalId) -> StoreResult<Vec<Role>> {
        let d = self.data.lock().unwrap();
        let ids = d
            .principal_roles
            .get(&principal_id)
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| d.roles.get(id).cloned())
            .collect())
    }

    async fn permissions_for_principal(
        &self,
        principal_id: PrincipalId,
    ) -> StoreResult<PermissionSet> {
        let d = self.data.lock().unwrap();
        let ids = d
            .principal_roles
            .get(&principal_id)
            .cloned()
            .unwrap_or_default();
        let mut perms = PermissionSet::new();
        for id in ids {
            if let Some(role_perms) = d.role_permissions.get(&id) {
                perms.extend(role_perms.iter().copied());
            }
        }
        Ok(perms)
    }

    async fn insert_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
        hashes: &[String],
    ) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        for hash in hashes {
            d.codes.insert(
                uuid::Uuid::new_v4(),
                CodeRow {
                    principal_id,
                    purpose,
                    hash: hash.clone(),
                    used: false,
                },
            );
        }
        Ok(())
    }

    async fn list_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<Vec<StoredCode>> {
        let d = self.data.lock().unwrap();
        Ok(d.codes
            .iter()
            .filter(|(_, c)| c.principal_id == principal_id && c.purpose == purpose && !c.used)
            .map(|(id, c)| StoredCode {
                id: *id,
                code_hash: c.hash.clone(),
            })
            .collect())
    }

    async fn mark_code_used(&self, code_id: uuid::Uuid) -> StoreResult<bool> {
        let mut d = self.data.lock().unwrap();
        match d.codes.get_mut(&code_id) {
            Some(c) if !c.used => {
                c.used = true;
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err(StoreError::NotFound),
        }
    }

    async fn delete_unused_codes(
        &self,
        principal_id: PrincipalId,
        purpose: CodePurpose,
    ) -> StoreResult<()> {
        let mut d = self.data.lock().unwrap();
        d.codes
            .retain(|_, c| !(c.principal_id == principal_id && c.purpose == purpose && !c.used));
        Ok(())
    }
}

/// In-memory [`AuditStore`].
#[derive(Default)]
pub struct MemoryAuditStore {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn append(&self, event: &AuditEvent) -> StoreResult<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn query(&self, filter: &AuditFilter) -> StoreResult<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let mut out: Vec<AuditEvent> = events
            .iter()
            .filter(|e| filter.org_id.is_none_or(|o| e.org_id == o))
            .filter(|e| filter.actor_id.is_none_or(|a| e.actor_id == a))
            .filter(|e| filter.action.as_ref().is_none_or(|a| &e.action == a))
            .filter(|e| filter.decision.is_none_or(|d| e.decision == d))
            .filter(|e| filter.from.is_none_or(|f| e.occurred_at >= f))
            .filter(|e| filter.to.is_none_or(|t| e.occurred_at <= t))
            .cloned()
            .collect();
        // Newest first, matching the Postgres query's ORDER BY.
        out.sort_by_key(|e| std::cmp::Reverse(e.occurred_at));
        out.truncate(filter.limit.max(0) as usize);
        Ok(out)
    }
}

/// In-memory [`ChallengeStore`].
#[derive(Default)]
pub struct MemoryChallengeStore {
    challenges: Mutex<HashMap<String, ChallengeRecord>>,
}

impl MemoryChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChallengeStore for MemoryChallengeStore {
    async fn put_challenge(&self, record: &ChallengeRecord) -> StoreResult<()> {
        self.challenges
            .lock()
            .unwrap()
            .insert(record.challenge_id.clone(), record.clone());
        Ok(())
    }

    async fn take_challenge(
        &self,
        challenge_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<ChallengeRecord>> {
        let mut c = self.challenges.lock().unwrap();
        match c.remove(challenge_id) {
            // Expiry is enforced here, not left to a TTL sweep.
            Some(rec) if rec.expires_at > now => Ok(Some(rec)),
            _ => Ok(None),
        }
    }
}

/// In-memory [`SessionStore`].
#[derive(Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, SessionRecord>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn put_session(&self, record: &SessionRecord) -> StoreResult<()> {
        self.sessions
            .lock()
            .unwrap()
            .insert(record.session_id.clone(), record.clone());
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
        now: OffsetDateTime,
    ) -> StoreResult<Option<SessionRecord>> {
        let s = self.sessions.lock().unwrap();
        match s.get(session_id) {
            Some(rec) if !rec.is_expired(now) => Ok(Some(rec.clone())),
            _ => Ok(None),
        }
    }

    async fn revoke_session(&self, session_id: &str) -> StoreResult<()> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }
}
